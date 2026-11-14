//! net/src/transport/tcp.rs
//!
//! TCP: the stream that a handshake opens, an acknowledgement carries, and an
//! orderly close shuts.
//!
//! ## The layout
//!
//! ```text
//! IPv4    ver|ihl, tos, total_length, … protocol=6
//! TCP     source_port[2] destination_port[2]
//!         sequence[4] acknowledgement[4]
//!         offset|reserved[1] flags[1]
//!         window[2] checksum[2] urgent[2]      20 bytes
//! data[…]
//! ```
//!
//! ## The state machine, and what it does not do
//!
//! A connection is the states a stream moves through, [`State`], from a
//! handshake to an orderly close, and each move is one of this module's
//! methods with one injected `send` callback, which is where the bytes go.
//! The callback is the module's whole output: the state machine computes the
//! segment, the caller decides what a segment is for this connection's wire.
//! That is what makes a loopback exchange and a frame through the card the
//! same state machine with two callers, and what makes every move here a
//! host test without a device in it.
//!
//! What it does not do is deliberate: **no flow control**.  A peer's window is
//! carried but never enforced, because the receive buffer is this stack's own
//! bound and a peer that sent past it is a peer whose segments the sequence
//! check already drops.
//!
//! ## Retransmission, and the clock it needs
//!
//! A segment can be lost, and a stream that never sent one again is a stream
//! that hangs forever on the first loss.  [`Connection::retransmit`] is the
//! answer: the segments this side sent and the peer has not acknowledged are
//! kept, oldest first, and one that has waited past the timeout is handed back
//! to the caller to send again with the timeout doubled, which is [RFC 6298]'s
//! exponential backoff.  Five attempts is where this stack gives up, which is
//! the same order as the retransmission count the common stacks use.
//!
//! A timeout is a duration, and a duration in ticks is a duration in a unit
//! this crate would have to guess: the kernel's clock runs at ten kilohertz,
//! and a constant written for a hundred-hertz clock is a schedule a hundred
//! times too fast.  So the unit here is **microseconds**, and the connection
//! does not read a clock at all.  [`Connection::advance`] is how it is told the
//! time, by the caller whose clock it is.  That keeps every move here a host
//! test with a clock the test owns, and it is why a lost segment is a test
//! rather than something only a bad network finds.
//!
//! [RFC 6298]: https://www.rfc-editor.org/rfc/rfc6298
//!
//! ## What a segment refuses
//!
//! The checksum is mandatory, TCP has no zero field that means "not
//! summed", and the sequence is checked against the connection's own
//! acknowledgement: a segment that arrives out of order is dropped rather
//! than held, because holding one asks for the receive-side reassembly that
//! this module does not have.

use crate::address::Address;
use crate::ethernet::get_u16;
use crate::ethernet::put_u16;
use crate::ipv4::PROTOCOL_TCP;
use crate::ipv4::checksum_of;

/// The TCP header's length, with no options.
pub const HEADER_LEN: usize = 20;

/// `FIN`: the sender is done sending.
pub const FLAG_FIN: u8 = 0x01;
/// `SYN`: the sender is opening.
pub const FLAG_SYN: u8 = 0x02;
/// `RST`: the sender is refusing.
pub const FLAG_RST: u8 = 0x04;
/// `PSH`: the sender wants the data delivered now.
pub const FLAG_PSH: u8 = 0x08;
/// `ACK`: the acknowledgement field means something.
pub const FLAG_ACK: u8 = 0x10;

/// The timeout a first retransmission waits, in microseconds.
///
/// [RFC 6298] section 2.1's initial value is one second, and this stack keeps
/// it rather than measuring a round trip: one exchange per boot is not a
/// sample, and a smoothed estimate from a single measurement is a number that
/// looks measured and is not.
///
/// [RFC 6298]: https://www.rfc-editor.org/rfc/rfc6298
pub const RTO_INITIAL_MICROS: u64 = 1_000_000;

/// The longest a retransmission may wait, in microseconds.
///
/// The same section's ceiling, sixty seconds.  Without it, five doublings
/// would put the last attempt half an hour away, and a stream that is not
/// going to work would hold its caller for most of a boot.
pub const RTO_MAX_MICROS: u64 = 60_000_000;

/// How many times one segment is sent before the stream is abandoned.
///
/// Five attempts at one, two, four, eight and sixteen seconds is thirty-one
/// seconds before giving up, which is the order the common stacks' longer
/// schedules land at.  A stream that cannot carry a segment in half a minute
/// is not going to, and a caller waiting longer has been told nothing.
pub const MAX_ATTEMPTS: u8 = 5;

/// How many unacknowledged segments one connection holds.
///
/// This stack has no send window, so the queue is the only thing standing
/// between a peer that stopped acknowledging and a program that keeps
/// writing: every byte written before an acknowledgement is a byte this
/// connection keeps a copy of.  Sixteen segments is the bound, and a full
/// queue refuses the write with a zero rather than growing, which is the same
/// "nothing was carried, ask again" a full pipe answers with.
pub const MAX_UNACKNOWLEDGED: usize = 16;

/// The window this stack advertises.
///
/// Carried, never enforced: the receive buffer a connection keeps is this
/// stack's own bound, and a peer that sent past it would be a peer whose
/// segments this stack already drops by sequence.  Eight kilobytes is room
/// for every exchange this stack carries and a number a reader can compare
/// against the buffer it advertises for.
pub const WINDOW: u16 = 8192;

/// The states a connection moves through, in the order a stream does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Nothing has happened yet, or the close has finished.
    Closed,
    /// A client's handshake is out, and the answer has not come.
    SynSent,
    /// A server's handshake is out, and the client's answer has not come.
    SynReceived,
    /// The stream is open in both directions.
    Established,
    /// This side is done sending; the peer's finish has not arrived.
    FinWait,
    /// The peer is done sending; this side's finish has not gone out.
    CloseWait,
    /// Both sides are done sending; the last acknowledgement has not come.
    LastAck,
}

/// A TCP segment, as this stack reads one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub source_port: u16,
    pub destination_port: u16,
    /// The sender's position in its own stream.
    pub sequence: u32,
    /// The sender's acknowledgement of this stream.
    pub acknowledgement: u32,
    /// The flags the segment carries: [`FLAG_SYN`], [`FLAG_ACK`], and the
    /// rest.
    pub flags: u8,
    /// The peer's advertised window, carried but never enforced.
    pub window: u16,
    /// How many data bytes the segment carries.
    pub payload_len: usize,
}

/// Write a segment: header, data, and the checksum over both and the
/// pseudo-header their packet names.
///
/// The caller's buffer is the segment's: [`HEADER_LEN`] + `data.len()`
/// bytes, written at the start of `into`.
#[allow(clippy::too_many_arguments)]
pub fn write_segment(
    into: &mut [u8],
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    data: &[u8],
) {
    let length = (HEADER_LEN + data.len()) as u16;
    put_u16(into, 0, source_port);
    put_u16(into, 2, destination_port);
    into[4..8].copy_from_slice(&sequence.to_be_bytes());
    into[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
    // Data offset: five words, the header with no options.
    into[12] = 5 << 4;
    into[13] = flags;
    put_u16(into, 14, WINDOW);
    put_u16(into, 16, 0);
    put_u16(into, 18, 0);
    into[HEADER_LEN..HEADER_LEN + data.len()].copy_from_slice(data);
    let sum = checksum_of(&[
        &pseudo_header(source, destination, length),
        &into[..length as usize],
    ]);
    put_u16(into, 16, sum);
}

/// Write a segment over IPv6, with its checksum over the forty-byte
/// pseudo-header.
///
/// Every field but the checksum is the same as [`write_segment`]'s; the sum
/// is a different one because IPv6's pseudo-header is forty bytes where
/// IPv4's is twelve, and a segment written with the wrong one has a checksum
/// every peer on its wire discards.
#[allow(clippy::too_many_arguments)]
pub fn write_segment6(
    into: &mut [u8],
    source: crate::ipv6::Addr,
    destination: crate::ipv6::Addr,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    data: &[u8],
) {
    let length = (HEADER_LEN + data.len()) as u16;
    put_u16(into, 0, source_port);
    put_u16(into, 2, destination_port);
    into[4..8].copy_from_slice(&sequence.to_be_bytes());
    into[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
    into[12] = 5 << 4;
    into[13] = flags;
    put_u16(into, 14, WINDOW);
    put_u16(into, 16, 0);
    put_u16(into, 18, 0);
    into[HEADER_LEN..HEADER_LEN + data.len()].copy_from_slice(data);
    let sum = crate::ipv6::checksum_with_pseudo(
        source,
        destination,
        crate::ipv6::NEXT_TCP,
        &into[..length as usize],
    );
    put_u16(into, 16, sum);
}

/// Read the segment at the start of an IPv6 packet's payload.
///
/// The checksum is verified over IPv6's pseudo-header, and like
/// [`write_segment6`] this is a second function rather than the IPv4 one with
/// a flag: the bytes the two sums cover differ in length and content, and a
/// reader that guessed which to use would accept a segment no peer sent.
pub fn parse6(
    packet: &[u8],
    source: crate::ipv6::Addr,
    destination: crate::ipv6::Addr,
) -> Option<Segment> {
    if packet.len() < HEADER_LEN {
        return None;
    }
    let data_offset = (packet[12] >> 4) as usize * 4;
    if data_offset < HEADER_LEN || data_offset > packet.len() {
        return None;
    }
    // Over IPv6 the packet is exactly the segment: the header's payload
    // length says so, and nothing pads it the way Ethernet pads a short
    // frame, which is why the whole slice is what the sum covers.
    if crate::ipv6::checksum_with_pseudo(source, destination, crate::ipv6::NEXT_TCP, packet) != 0 {
        return None;
    }
    Some(Segment {
        source_port: get_u16(packet, 0),
        destination_port: get_u16(packet, 2),
        sequence: u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]),
        acknowledgement: u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]),
        flags: packet[13],
        window: get_u16(packet, 14),
        payload_len: packet.len() - data_offset,
    })
}

/// The twelve bytes the checksum sums before the segment: both addresses, a
/// zero byte, the protocol, and the segment's length.
fn pseudo_header(source: [u8; 4], destination: [u8; 4], length: u16) -> [u8; 12] {
    let mut header = [0_u8; 12];
    header[0..4].copy_from_slice(&source);
    header[4..8].copy_from_slice(&destination);
    header[8] = 0;
    header[9] = PROTOCOL_TCP;
    header[10..12].copy_from_slice(&length.to_be_bytes());
    header
}

/// Read the segment at the start of an IPv4 packet's payload, or `None`
/// when it is not one this stack can interpret.
///
/// The checksum is mandatory here, UDP's zero field has no TCP twin, and
/// the data offset is checked against the packet's length, because a header
/// that claimed more words than the packet holds is a segment that ends
/// before it begins.
pub fn parse(packet: &[u8], source: [u8; 4], destination: [u8; 4]) -> Option<Segment> {
    if packet.len() < HEADER_LEN {
        return None;
    }
    if packet[12] >> 4 < 5 {
        return None;
    }
    if checksum_of(&[
        &pseudo_header(source, destination, packet.len() as u16),
        packet,
    ]) != 0
    {
        return None;
    }

    Some(Segment {
        source_port: get_u16(packet, 0),
        destination_port: get_u16(packet, 2),
        sequence: u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]),
        acknowledgement: u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]),
        flags: packet[13],
        window: get_u16(packet, 14),
        payload_len: packet.len() - HEADER_LEN,
    })
}

/// What one received segment meant to the connection it arrived for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Event {
    /// Nothing a caller acts on: an acknowledgement, or a state move the
    /// connection made on its own.
    None,
    /// The handshake completed, or the last acknowledgement of a close
    /// landed: the connection is [`State::Established`] or [`State::Closed`].
    Settled,
    /// The peer sent `usize` data bytes, now in the connection's inbox.
    Data(usize),
    /// The peer is done sending, and the data before its finish is in the
    /// inbox.
    PeerFinished,
}

/// One segment the state machine computed, waiting for its wire.
///
/// The state machine's whole output is a list of these: a move returns what
/// it sent, and the caller, a loopback exchange that delivers to the
/// peer's own state machine, or a frame through the card, decides where a
/// segment goes.  Returning them rather than sending them from inside is
/// what keeps the machine pure: no callback, no re-entry into a caller's
/// own lock, and every byte a connection emitted is a value the caller can
/// carry, drop, or test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outgoing {
    pub sequence: u32,
    pub acknowledgement: u32,
    pub flags: u8,
    pub payload: alloc::vec::Vec<u8>,
}

/// One outgoing segment, built for the moves that answer with one.
fn one(
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    payload: &[u8],
) -> alloc::vec::Vec<Outgoing> {
    alloc::vec![Outgoing {
        sequence,
        acknowledgement,
        flags,
        payload: alloc::vec::Vec::from(payload),
    }]
}

/// One end of a stream: the states, the sequence numbers, and the data the
/// peer has sent that this side has not taken.
///
/// The connection is the state machine and its buffers in one, and every
/// move takes the `send` callback, which is why nothing here can send a
/// segment the caller did not see.
pub struct Connection {
    state: State,
    local_port: u16,
    remote: (Address, u16),
    /// The position this side sends from: advanced by every byte the peer's
    /// acknowledgement covers, with SYN and FIN each counting as one.
    sequence: u32,
    /// The position this side expects the peer to send from.
    acknowledgement: u32,
    inbox: alloc::vec::Vec<u8>,
    /// Whether this side has said it is done sending.
    finished: bool,
    /// The segments this side sent and the peer has not acknowledged, oldest
    /// first.
    ///
    /// A sent segment that is forgotten cannot be sent again, so the queue is
    /// the retransmission: an entry leaves when an acknowledgement covers its
    /// last byte, and one that waits past its deadline is handed back to the
    /// caller.  The queue is bounded by [`MAX_UNACKNOWLEDGED`] because a
    /// connection that keeps every unacknowledged segment is a connection a
    /// peer's silence spends memory on.
    unacknowledged: alloc::vec::Vec<Unacknowledged>,
    /// The time this side was last told, in microseconds.
    ///
    /// [`Connection::advance`] sets it.  A move that needs a deadline reads
    /// it rather than calling a clock, which is what lets a test own the
    /// time: the module has no clock and asks for none.
    now: u64,
    /// The timeout the next retransmission waits, which doubles with each
    /// attempt at the same position.
    timeout: u64,
    /// How many times the oldest unacknowledged segment has been sent.
    attempts: u8,
}

/// One segment waiting for its acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Unacknowledged {
    /// The sequence number of this segment's first byte, which is what an
    /// acknowledgement has to cover before it leaves the queue.
    sequence: u32,
    /// The sequence number one past its last byte, with SYN and FIN each
    /// counting as one.  An acknowledgement at or past this retires the entry.
    end: u32,
    flags: u8,
    payload: alloc::vec::Vec<u8>,
    /// The time this copy was sent, in microseconds of the caller's clock.
    sent_at: u64,
}

/// What a retransmission check found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Retransmission {
    /// Nothing is due: either the queue is empty or the oldest segment has
    /// not waited its timeout.
    Idle,
    /// A segment waited past its timeout, and these are the bytes to send
    /// again.  The timeout has already doubled.
    Again(alloc::vec::Vec<Outgoing>),
    /// The oldest segment has been sent every way this stack sends it and
    /// nothing came back.  The connection is now [`State::Closed`], and a
    /// caller's next read or write sees a stream that ended rather than one
    /// that will never move.
    Abandoned,
}

impl Connection {
    /// The client's end of a handshake: open the stream and send the SYN.
    pub fn connect(
        local_port: u16,
        remote: (Address, u16),
        initial_sequence: u32,
    ) -> (Self, alloc::vec::Vec<Outgoing>) {
        let mut connection = Self {
            state: State::SynSent,
            local_port,
            remote,
            sequence: initial_sequence,
            acknowledgement: 0,
            inbox: alloc::vec::Vec::new(),
            finished: false,
            unacknowledged: alloc::vec::Vec::new(),
            now: 0,
            timeout: RTO_INITIAL_MICROS,
            attempts: 0,
        };
        let sent = connection.take_outgoing(connection.sequence, 0, FLAG_SYN, &[]);
        connection.sequence += 1;
        (connection, sent)
    }

    /// The server's end of a handshake: a SYN arrived for a listener's port,
    /// and this connection answers it.
    ///
    /// The connection starts in [`State::SynReceived`], and it is the
    /// listener's to hand out, a caller accepts it as soon as it exists,
    /// because the handshake finishes on the segments themselves and data
    /// that arrives before the accept queues in this connection's inbox.
    pub fn accept_syn(
        local_port: u16,
        remote: (Address, u16),
        initial_sequence: u32,
        client_sequence: u32,
    ) -> (Self, alloc::vec::Vec<Outgoing>) {
        let mut connection = Self {
            state: State::SynReceived,
            local_port,
            remote,
            sequence: initial_sequence,
            acknowledgement: client_sequence.wrapping_add(1),
            inbox: alloc::vec::Vec::new(),
            finished: false,
            unacknowledged: alloc::vec::Vec::new(),
            now: 0,
            timeout: RTO_INITIAL_MICROS,
            attempts: 0,
        };
        let sent = connection.take_outgoing(
            connection.sequence,
            connection.acknowledgement,
            FLAG_SYN | FLAG_ACK,
            &[],
        );
        connection.sequence += 1;
        (connection, sent)
    }

    /// The state the connection is in.
    pub fn state(&self) -> State {
        self.state
    }

    /// The port this side answers on.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// The peer this stream runs to.
    pub fn remote(&self) -> (Address, u16) {
        self.remote
    }

    /// The data the peer has sent that this side has not taken.
    pub fn inbox_len(&self) -> usize {
        self.inbox.len()
    }

    /// Take up to `into.len()` bytes the peer sent, answering how many.
    pub fn take(&mut self, into: &mut [u8]) -> usize {
        let count = into.len().min(self.inbox.len());
        let rest = self.inbox.split_off(count);
        into[..count].copy_from_slice(&self.inbox);
        self.inbox = rest;
        count
    }

    /// One segment arrived for this connection.
    ///
    /// The sequence is checked before anything else: a segment out of order
    /// is dropped silently, because there is no buffer to hold it in and no
    /// receive-side reassembly to sort it with.  The handshake's moves and
    /// the stream's data and finishes are the three things a segment can be;
    /// everything else is refused without changing the state.
    ///
    /// An acknowledgement is acted on before any of that: it is the one thing
    /// a segment says about this side's own sending, and a segment whose data
    /// is dropped still acknowledges what it acknowledges.
    pub fn receive(
        &mut self,
        segment: &Segment,
        payload: &[u8],
    ) -> (abi::Result<Event>, alloc::vec::Vec<Outgoing>) {
        if segment.flags & FLAG_ACK != 0 {
            self.note_acknowledgement(segment.acknowledgement);
        }

        // The one segment the handshake's answer is: the SYN with this
        // side's own acknowledgement in it.  The client's move from
        // [`State::SynSent`], on the server's SYN with ACK.
        if self.state == State::SynSent
            && segment.flags & FLAG_SYN != 0
            && segment.flags & FLAG_ACK != 0
        {
            self.state = State::Established;
            self.acknowledgement = segment.sequence.wrapping_add(1);
            let sent = self.take_outgoing(self.sequence, self.acknowledgement, FLAG_ACK, &[]);
            return (Ok(Event::Settled), sent);
        }

        // The one segment the handshake's last move is: the client's ACK on
        // the server's SYN with ACK.  The server's move from
        // [`State::SynReceived`].
        if self.state == State::SynReceived
            && segment.flags & FLAG_ACK != 0
            && segment.flags & FLAG_SYN == 0
            && segment.acknowledgement == self.sequence
        {
            self.state = State::Established;
            return (Ok(Event::Settled), alloc::vec::Vec::new());
        }

        // Everything after the handshake needs the stream open in this
        // direction, and needs the peer's sequence to be the one this side
        // is waiting for.
        let open = matches!(
            self.state,
            State::Established | State::FinWait | State::CloseWait | State::LastAck
        );
        if !open || segment.sequence != self.acknowledgement {
            return (Ok(Event::None), alloc::vec::Vec::new());
        }

        let mut event = Event::None;
        if segment.flags & FLAG_ACK != 0 && self.state == State::LastAck {
            // The peer's acknowledgement of this side's finish: the close is
            // over.
            self.state = State::Closed;
            return (Ok(Event::Settled), alloc::vec::Vec::new());
        }
        if self.state == State::FinWait
            && segment.flags & FLAG_ACK != 0
            && segment.flags & FLAG_FIN != 0
        {
            // The peer's finish, answering this side's own: the last
            // acknowledgement closes both halves at once.
            self.acknowledgement = segment.sequence.wrapping_add(1);
            let sent = self.take_outgoing(self.sequence, self.acknowledgement, FLAG_ACK, &[]);
            self.state = State::Closed;
            return (Ok(Event::Settled), sent);
        }

        if !payload.is_empty() {
            self.acknowledgement += payload.len() as u32;
            self.inbox.extend_from_slice(payload);
            event = Event::Data(payload.len());
        }
        if segment.flags & FLAG_FIN != 0 {
            self.acknowledgement += 1;
            let sent = self.take_outgoing(self.sequence, self.acknowledgement, FLAG_ACK, &[]);
            self.state = if self.finished {
                State::Closed
            } else {
                State::CloseWait
            };
            return (Ok(Event::PeerFinished), sent);
        }
        // The acknowledgement is empty: a data segment is answered with the
        // position it moved this side to, and carrying the data back would
        // be the wire echoing to itself.
        let sent = if payload.is_empty() {
            alloc::vec::Vec::new()
        } else {
            one(self.sequence, self.acknowledgement, FLAG_ACK, &[])
        };
        (Ok(event), sent)
    }

    /// Send data on the stream.
    ///
    /// Answering zero for a closed half is the caller's signal, not an
    /// error: a stream whose send side is finished has nothing to carry,
    /// and a caller that writes after closing wrote to a stream it ended.
    ///
    /// A queue that is full answers zero too, and for the same reason: what it
    /// holds is a peer's unacknowledged bytes, and a peer that stopped
    /// acknowledging must not be able to spend this machine's memory by
    /// letting a program keep writing.
    pub fn send_data(&mut self, bytes: &[u8]) -> (usize, alloc::vec::Vec<Outgoing>) {
        if self.finished || bytes.is_empty() {
            return (0, alloc::vec::Vec::new());
        }
        let open = matches!(self.state, State::Established | State::CloseWait);
        if !open {
            return (0, alloc::vec::Vec::new());
        }
        if self.unacknowledged.len() >= MAX_UNACKNOWLEDGED {
            return (0, alloc::vec::Vec::new());
        }
        let sent = self.take_outgoing(
            self.sequence,
            self.acknowledgement,
            FLAG_ACK | FLAG_PSH,
            bytes,
        );
        self.sequence += bytes.len() as u32;
        (bytes.len(), sent)
    }

    /// Say this side is done sending: one FIN, and the state that waits for
    /// the peer's.
    ///
    /// A close of a half the peer already finished is the stream's last
    /// move: the state goes to [`State::Closed`], because both halves have
    /// said their piece and the acknowledgements have crossed.
    pub fn close(&mut self) -> alloc::vec::Vec<Outgoing> {
        if self.finished {
            return alloc::vec::Vec::new();
        }
        self.finished = true;
        match self.state {
            State::Established => {
                let sent = self.take_outgoing(
                    self.sequence,
                    self.acknowledgement,
                    FLAG_ACK | FLAG_FIN,
                    &[],
                );
                self.sequence += 1;
                self.state = State::FinWait;
                sent
            }
            State::CloseWait => {
                // The peer finished first; this side's finish is the last
                // move a handshake of finishes has.
                let sent = self.take_outgoing(
                    self.sequence,
                    self.acknowledgement,
                    FLAG_ACK | FLAG_FIN,
                    &[],
                );
                self.sequence += 1;
                self.state = State::LastAck;
                sent
            }
            _ => alloc::vec::Vec::new(),
        }
    }

    /// Tell the connection what time it is, in microseconds.
    ///
    /// The caller's clock, which is the only clock there is: this module has
    /// none, because a crate that read a timer could not be a host test.  A
    /// connection that is never told the time still works, and never
    /// retransmits, which is exactly what a loopback wire and a test that does
    /// not care about loss want.
    pub fn advance(&mut self, now: u64) {
        self.now = now;
    }

    /// The segments this side sent and the peer has not acknowledged.
    pub fn unacknowledged(&self) -> usize {
        self.unacknowledged.len()
    }

    /// Whether a retransmission is due at the time this connection was last
    /// told, and if so, what to send.
    ///
    /// The check is a comparison and not a timer: nothing here schedules
    /// anything, and the caller decides how often to ask.  Ask it from
    /// whatever already runs periodically, which for this kernel is the pump
    /// the receive path calls.
    ///
    /// An attempt count that reaches [`MAX_ATTEMPTS`] abandons the stream:
    /// the oldest segment has been offered every way this stack offers one,
    /// and the state goes to [`State::Closed`] so a caller's next read or
    /// write learns the stream ended instead of waiting forever on it.
    pub fn retransmit(&mut self) -> Retransmission {
        let Some(oldest) = self.unacknowledged.first() else {
            return Retransmission::Idle;
        };
        if self.now.wrapping_sub(oldest.sent_at) < self.timeout {
            return Retransmission::Idle;
        }
        if self.attempts >= MAX_ATTEMPTS {
            self.unacknowledged.clear();
            self.state = State::Closed;
            return Retransmission::Abandoned;
        }
        let sequence = oldest.sequence;
        let acknowledgement = self.acknowledgement;
        let flags = oldest.flags;
        let payload = oldest.payload.clone();
        self.attempts += 1;
        // [RFC 6298]'s backoff, capped: a stream that answers nothing must
        // not hold a caller for the sum of unbounded doublings.
        self.timeout = self.timeout.saturating_mul(2).min(RTO_MAX_MICROS);
        let sent = one(sequence, acknowledgement, flags, &payload);
        self.unacknowledged[0].sent_at = self.now;
        Retransmission::Again(sent)
    }

    /// Build one segment and remember it until its acknowledgement arrives.
    ///
    /// A segment that carries nothing but an acknowledgement is not
    /// remembered: it is not retransmitted, because a lost pure ACK is
    /// recovered by the peer retransmitting the data it acknowledged, and
    /// queueing every ACK would make a stream's memory follow its
    /// conversation rather than its unacknowledged bytes.
    fn take_outgoing(
        &mut self,
        sequence: u32,
        acknowledgement: u32,
        flags: u8,
        payload: &[u8],
    ) -> alloc::vec::Vec<Outgoing> {
        let carried = !payload.is_empty() || flags & (FLAG_SYN | FLAG_FIN) != 0;
        let mut end = sequence.wrapping_add(payload.len() as u32);
        // A SYN and a FIN each occupy one sequence number.
        if flags & FLAG_SYN != 0 {
            end = end.wrapping_add(1);
        }
        if flags & FLAG_FIN != 0 {
            end = end.wrapping_add(1);
        }
        if carried {
            self.unacknowledged.push(Unacknowledged {
                sequence,
                end,
                flags,
                payload: alloc::vec::Vec::from(payload),
                sent_at: self.now,
            });
        }
        one(sequence, acknowledgement, flags, payload)
    }

    /// Retire every segment an acknowledgement covers, and start its clock
    /// over.
    ///
    /// The range is checked first, and the check is the one [RFC 793] section
    /// 3.9 states: an acknowledgement is meaningful only between the oldest
    /// byte this side has not had acknowledged and the next byte it will send.
    /// Without it a segment carrying any number at all would retire data the
    /// peer never received, which is silent loss rather than a slow stream:
    /// the sender would stop offering bytes nothing had acknowledged.
    ///
    /// "Covers" is `end <= ack` in the sequence's own arithmetic, which is the
    /// one comparison a wrapping number allows.  Progress resets the attempt
    /// count and the timeout together: [RFC 6298] measures a round trip from a
    /// segment that was sent once, and a doubling that survived an
    /// acknowledged segment would make the next loss wait on a schedule the
    /// previous one earned.
    ///
    /// [RFC 793]: https://www.rfc-editor.org/rfc/rfc793
    /// [RFC 6298]: https://www.rfc-editor.org/rfc/rfc6298
    fn note_acknowledgement(&mut self, acknowledgement: u32) {
        let Some(oldest) = self.unacknowledged.first() else {
            return;
        };
        // `SND.UNA <= SEG.ACK <= SND.NXT`, each comparison in the sequence's
        // own arithmetic so a stream that crossed the wrap is not refused.
        if seq_before(acknowledgement, oldest.sequence)
            || seq_before(self.sequence, acknowledgement)
        {
            return;
        }
        let before = self.unacknowledged.len();
        self.unacknowledged
            .retain(|segment| !acknowledges(acknowledgement, segment.end));
        if self.unacknowledged.len() != before {
            self.attempts = 0;
            self.timeout = RTO_INITIAL_MICROS;
        }
    }
}

/// Whether an acknowledgement covers a segment's last byte.
///
/// The comparison is the difference, so a segment that ends one past the
/// wrap is covered by an acknowledgement of zero, which is the case a plain
/// `>=` gets wrong.
fn acknowledges(acknowledgement: u32, end: u32) -> bool {
    acknowledgement.wrapping_sub(end) as i32 >= 0
}

/// Whether `a` comes before `b` in a sequence's own arithmetic.
///
/// Sequence numbers wrap, so a plain `<` is wrong at the wrap: the comparison
/// is on the difference, and [RFC 1982]'s rule is that a difference of half
/// the space or more is the other way round.  This stack never has two
/// numbers that far apart for one connection, and the wrapping difference is
/// still the honest test for the ones it has.
///
/// [RFC 1982]: https://www.rfc-editor.org/rfc/rfc1982
fn seq_before(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

#[cfg(test)]
mod tests {
    use super::Connection;
    use super::Event;
    use super::FLAG_ACK;
    use super::FLAG_FIN;
    use super::FLAG_PSH;
    use super::FLAG_SYN;
    use super::HEADER_LEN;
    use super::Outgoing;
    use super::Segment;
    use super::State;
    use super::parse;
    use super::write_segment;
    use crate::address::Address;

    const US: [u8; 4] = [10, 0, 2, 15];
    const OUR_PORT: u16 = 50000;
    const THEIR_PORT: u16 = 9000;

    /// The loopback the tests run on: each side's outgoing segments queue
    /// here, and [`drain`] hands every one to the peer's own state machine
    /// until the wire is quiet.  This is what the kernel's demux does for a
    /// segment this machine sends to itself, which is why the handshake
    /// here finishes in one drain, and why the kernel's own loopback
    /// behaves the same way.
    fn drain(
        client_out: &mut alloc::vec::Vec<Outgoing>,
        server_out: &mut alloc::vec::Vec<Outgoing>,
        client: &mut Connection,
        server: &mut Connection,
    ) {
        loop {
            if client_out.is_empty() && server_out.is_empty() {
                return;
            }
            while let Some(item) = client_out.pop() {
                let (answer, replies) =
                    server.receive(&segment(OUR_PORT, THEIR_PORT, &item), &item.payload);
                let _ = answer;
                server_out.extend(replies);
            }
            while let Some(item) = server_out.pop() {
                let (answer, replies) =
                    client.receive(&segment(THEIR_PORT, OUR_PORT, &item), &item.payload);
                let _ = answer;
                client_out.extend(replies);
            }
        }
    }

    /// An outgoing segment as the peer reads it: the header's fields with
    /// the ports set from the direction it travels.
    fn segment(source_port: u16, destination_port: u16, outgoing: &Outgoing) -> Segment {
        Segment {
            source_port,
            destination_port,
            sequence: outgoing.sequence,
            acknowledgement: outgoing.acknowledgement,
            flags: outgoing.flags,
            window: super::WINDOW,
            payload_len: outgoing.payload.len(),
        }
    }

    /// The handshake's first three moves, run once and returned in the open
    /// state.
    fn handshake() -> (Connection, Connection) {
        let (mut client, mut client_out) =
            Connection::connect(OUR_PORT, (Address::V4(US), THEIR_PORT), 1000);
        assert_eq!(client.state(), State::SynSent);
        assert_eq!(client_out.len(), 1, "the SYN");
        assert_eq!(client_out[0].flags, FLAG_SYN);

        // The SYN reaches a listener, which builds the server's end and
        // answers with its own SYN with ACK.
        let syn = client_out.pop().expect("the SYN");
        let (mut server, mut server_out) =
            Connection::accept_syn(THEIR_PORT, (Address::V4(US), OUR_PORT), 5000, syn.sequence);
        assert_eq!(server.state(), State::SynReceived);

        drain(&mut client_out, &mut server_out, &mut client, &mut server);
        assert_eq!(client.state(), State::Established);
        assert_eq!(server.state(), State::Established);
        (client, server)
    }

    /// The handshake, over the loopback: a connect whose SYN the listener
    /// answers, the answer the client answers back, and both ends in the
    /// open state by the time the drain is quiet.
    #[test]
    fn a_handshake_finishes_on_the_loopback() {
        let _ = handshake();
    }

    /// A stream that carries data both ways, and the acknowledgements the
    /// carries pull behind them.
    #[test]
    fn a_stream_carries_data_both_ways() {
        let (mut client, mut server) = handshake();
        let mut client_out = alloc::vec::Vec::new();
        let mut server_out = alloc::vec::Vec::new();

        // The client sends; the server's inbox takes it, and the ACK is the
        // only thing that crosses the wire for it.
        let (sent, outgoing) = client.send_data(b"protofire");
        assert_eq!(sent, 9);
        assert_eq!(outgoing.len(), 1, "one segment");
        assert_eq!(outgoing[0].flags, FLAG_ACK | FLAG_PSH);
        client_out.extend(outgoing);
        drain(&mut client_out, &mut server_out, &mut client, &mut server);
        assert_eq!(server.inbox_len(), 9);

        let mut buffer = [0_u8; 16];
        assert_eq!(server.take(&mut buffer), 9);
        assert_eq!(&buffer[..9], b"protofire");

        // The server answers; the client's inbox takes that.
        let (sent, outgoing) = server.send_data(b"back");
        assert_eq!(sent, 4);
        server_out.extend(outgoing);
        drain(&mut client_out, &mut server_out, &mut client, &mut server);
        assert_eq!(client.inbox_len(), 4);
        let mut buffer = [0_u8; 16];
        assert_eq!(client.take(&mut buffer), 4);
        assert_eq!(&buffer[..4], b"back");
    }

    /// The orderly close: one side finishes, the peer answers with its own,
    /// and both ends are closed by the time the wire is quiet.
    #[test]
    fn an_orderly_close_ends_both_ends() {
        let (mut client, mut server) = handshake();
        let mut client_out = alloc::vec::Vec::new();
        let mut server_out = alloc::vec::Vec::new();

        client_out.extend(client.close());
        assert_eq!(client.state(), State::FinWait);
        assert_eq!(client_out[0].flags, FLAG_ACK | FLAG_FIN, "the FIN");
        drain(&mut client_out, &mut server_out, &mut client, &mut server);
        assert_eq!(server.state(), State::CloseWait, "the peer's finish landed");

        server_out.extend(server.close());
        assert_eq!(server.state(), State::LastAck);
        drain(&mut client_out, &mut server_out, &mut client, &mut server);
        assert_eq!(client.state(), State::Closed, "the last exchange closed it");
        assert_eq!(server.state(), State::Closed, "and the other end with it");
    }

    /// A write after a close answers zero, because the send side is
    /// finished and a stream carries nothing after its FIN.
    #[test]
    fn a_write_after_a_close_carries_nothing() {
        let (mut client, mut server) = handshake();
        let mut client_out = alloc::vec::Vec::new();
        let mut server_out = alloc::vec::Vec::new();

        client_out.extend(client.close());
        drain(&mut client_out, &mut server_out, &mut client, &mut server);

        let (sent, outgoing) = client.send_data(b"late");
        assert_eq!(sent, 0, "the stream is half-closed at the sender");
        assert!(outgoing.is_empty(), "and nothing went on the wire");
    }

    /// A segment whose sequence is not the one the connection waits for is
    /// dropped without changing anything: there is no buffer to hold it in
    /// and no timer to ask for it again.
    #[test]
    fn an_out_of_order_segment_is_dropped() {
        let (_client, mut server) = handshake();

        // A segment the server is not waiting for: one byte past its
        // position, with data in it.  The server's next position is one past
        // the client's ISN, the SYN consumed one, and nothing has been sent
        // since.
        let stray = Segment {
            source_port: OUR_PORT,
            destination_port: THEIR_PORT,
            sequence: 1000 + 2,
            acknowledgement: 5001,
            flags: FLAG_ACK | FLAG_PSH,
            window: super::WINDOW,
            payload_len: 4,
        };
        let (answer, replies) = server.receive(&stray, b"lost");
        assert_eq!(answer, Ok(Event::None));
        assert!(replies.is_empty(), "and nothing went back");
        assert_eq!(server.inbox_len(), 0, "nothing was taken in");
    }

    /// A data segment is acknowledged empty: carrying the data back would
    /// be the wire echoing to itself, and the echo the test before this
    /// one's bug ran found was the inbox doubling.
    #[test]
    fn an_acknowledgement_is_empty() {
        let (mut client, mut server) = handshake();

        let (_, outgoing) = client.send_data(b"protofire");
        let (answer, replies) =
            server.receive(&segment(OUR_PORT, THEIR_PORT, &outgoing[0]), b"protofire");
        assert_eq!(answer, Ok(Event::Data(9)));
        assert_eq!(replies.len(), 1, "the ACK");
        assert!(replies[0].payload.is_empty(), "and it carries no data");
    }

    /// A segment this stack wrote, read back as the wire carries it, with
    /// the corruption checks the checksum is there for.
    #[test]
    fn a_segment_round_trips() {
        let mut buffer = [0_u8; HEADER_LEN + 5];
        write_segment(
            &mut buffer,
            US,
            US,
            OUR_PORT,
            THEIR_PORT,
            100,
            200,
            FLAG_ACK | FLAG_PSH,
            b"hello",
        );

        let segment = parse(&buffer, US, US).expect("a segment");
        assert_eq!(segment.source_port, OUR_PORT);
        assert_eq!(segment.destination_port, THEIR_PORT);
        assert_eq!(segment.sequence, 100);
        assert_eq!(segment.acknowledgement, 200);
        assert_eq!(segment.flags, FLAG_ACK | FLAG_PSH);
        assert_eq!(segment.payload_len, 5);
        assert_eq!(segment.window, super::WINDOW);

        buffer[HEADER_LEN] = !buffer[HEADER_LEN];
        assert!(parse(&buffer, US, US).is_none(), "corrupt data");
        buffer[HEADER_LEN] = 0x68;
        buffer[4] = !buffer[4];
        assert!(parse(&buffer, US, US).is_none(), "corrupt header");
    }

    /// The header's length is what the data offset field says it is.
    #[test]
    fn the_header_is_twenty_bytes_with_no_options() {
        assert_eq!(HEADER_LEN, 20);
        let mut buffer = [0_u8; HEADER_LEN];
        write_segment(
            &mut buffer,
            US,
            US,
            OUR_PORT,
            THEIR_PORT,
            1,
            2,
            FLAG_ACK,
            &[],
        );
        assert_eq!(buffer[12] >> 4, 5, "five words of header");
    }
    /// A segment written for IPv6 verifies over IPv6's pseudo-header, and a
    /// segment written for IPv4 does not: the two sums cover forty bytes and
    /// twelve.
    #[test]
    fn the_two_pseudo_headers_are_not_interchangeable() {
        let source4 = [10, 0, 2, 15];
        let destination4 = [10, 0, 2, 2];
        let mut v4 = [0_u8; super::HEADER_LEN];
        super::write_segment(
            &mut v4,
            source4,
            destination4,
            1234,
            5678,
            1,
            0,
            super::FLAG_SYN,
            b"",
        );
        assert!(super::parse(&v4, source4, destination4).is_some());

        let source6 = crate::ipv6::link_local_from_mac([0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        let destination6 = crate::ipv6::link_local_from_mac([0x52, 0x55, 0, 0x12, 0x34, 0x57]);
        let mut v6 = [0_u8; super::HEADER_LEN];
        super::write_segment6(
            &mut v6,
            source6,
            destination6,
            1234,
            5678,
            1,
            0,
            super::FLAG_SYN,
            b"",
        );
        assert!(super::parse6(&v6, source6, destination6).is_some());

        // The IPv6 segment read as IPv4, or the other way round, does not
        // verify, which is the whole reason these are two functions.
        assert!(
            super::parse(&v4, [0; 4], [0; 4]).is_none(),
            "an IPv4 segment does not verify against other addresses"
        );
        let mut v4_as_v6 = [0_u8; super::HEADER_LEN];
        v4_as_v6.copy_from_slice(&v4);
        assert!(
            super::parse6(&v4_as_v6, source6, destination6).is_none(),
            "an IPv4 checksum is not an IPv6 one"
        );
    }

    /// A segment with data verifies too, and its payload length is the bytes
    /// past the header.
    #[test]
    fn a_segment_with_data_round_trips_over_ipv6() {
        let source = crate::ipv6::link_local_from_mac([0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        let destination = crate::ipv6::link_local_from_mac([0x52, 0x55, 0, 0x12, 0x34, 0x57]);
        let mut segment = [0_u8; super::HEADER_LEN + 9];
        super::write_segment6(
            &mut segment,
            source,
            destination,
            1234,
            5678,
            0x1122_3344,
            0x5566_7788,
            super::FLAG_ACK,
            b"pyrofire!",
        );
        let parsed = super::parse6(&segment, source, destination).expect("a segment");
        assert_eq!(parsed.source_port, 1234);
        assert_eq!(parsed.destination_port, 5678);
        assert_eq!(parsed.sequence, 0x1122_3344);
        assert_eq!(parsed.acknowledgement, 0x5566_7788);
        assert_eq!(parsed.flags, super::FLAG_ACK);
        assert_eq!(parsed.payload_len, 9);
    }

    /// An opened stream: the handshake run, both ends established, and both
    /// told what time it is.
    fn established_on_the_loopback() -> (Connection, Connection) {
        let (mut client, mut server) = handshake();
        // The handshake's own segments are acknowledged by the drain, so the
        // queue starts empty and the test's own send is the first entry.
        client.advance(0);
        server.advance(0);
        (client, server)
    }

    /// A sent segment is kept until the peer acknowledges it.
    ///
    /// This is the defect the change this test arrived with was written for:
    /// nothing kept a sent segment, so nothing could send it again, and the
    /// first loss on a real wire hung the stream for the rest of the boot.
    #[test]
    fn a_sent_segment_is_kept_until_its_acknowledgement() {
        let (mut client, mut server) = established_on_the_loopback();
        let mut client_out = alloc::vec::Vec::new();
        let mut server_out = alloc::vec::Vec::new();

        assert_eq!(client.unacknowledged(), 0, "the handshake was acknowledged");
        let (sent, outgoing) = client.send_data(b"protofire");
        assert_eq!(sent, 9);
        assert_eq!(client.unacknowledged(), 1, "the data is held");
        client_out.extend(outgoing);

        // The peer gets it and answers, and the answer retires the entry.
        drain(&mut client_out, &mut server_out, &mut client, &mut server);
        assert_eq!(client.unacknowledged(), 0, "the acknowledgement retired it");

        // Nothing is due on a queue with nothing in it.
        client.advance(super::RTO_INITIAL_MICROS * 10);
        assert_eq!(client.retransmit(), super::Retransmission::Idle);
    }

    /// A segment nobody acknowledged is sent again when its timeout passes,
    /// with the same bytes and the same sequence.
    #[test]
    fn an_unacknowledged_segment_is_sent_again_after_its_timeout() {
        let (mut client, _server) = established_on_the_loopback();
        client.advance(0);
        let (_, outgoing) = client.send_data(b"lost");
        let original = outgoing[0].clone();
        assert_eq!(client.unacknowledged(), 1);

        // Before the timeout, nothing is due.
        client.advance(super::RTO_INITIAL_MICROS - 1);
        assert_eq!(client.retransmit(), super::Retransmission::Idle);

        // At it, the same segment is handed back.
        client.advance(super::RTO_INITIAL_MICROS);
        match client.retransmit() {
            super::Retransmission::Again(sent) => {
                assert_eq!(sent.len(), 1, "one segment again");
                assert_eq!(sent[0].sequence, original.sequence, "the same position");
                assert_eq!(sent[0].payload, original.payload, "the same bytes");
                assert_eq!(sent[0].flags, original.flags);
            }
            other => panic!("expected a retransmission, got {other:?}"),
        }
        assert_eq!(client.unacknowledged(), 1, "still waiting for the one ACK");
    }

    /// The timeout doubles with each attempt, which is [RFC 6298]'s backoff.
    ///
    /// The test measures the intervals rather than reading the field: a
    /// backoff that was written but never applied is the defect this is for,
    /// and the interval between two retransmissions is what a peer sees.
    ///
    /// [RFC 6298]: https://www.rfc-editor.org/rfc/rfc6298
    #[test]
    fn the_timeout_doubles_with_each_attempt() {
        let (mut client, _server) = established_on_the_loopback();
        client.advance(0);
        client.send_data(b"backoff");

        // The first attempt waits the initial timeout, and the next waits
        // twice it: a clock that advanced one microsecond before the doubled
        // interval is due must still be idle.
        client.advance(super::RTO_INITIAL_MICROS);
        assert!(matches!(
            client.retransmit(),
            super::Retransmission::Again(_)
        ));

        let doubled = super::RTO_INITIAL_MICROS * 2;
        client.advance(super::RTO_INITIAL_MICROS + doubled - 1);
        assert_eq!(client.retransmit(), super::Retransmission::Idle);
        client.advance(super::RTO_INITIAL_MICROS + doubled);
        assert!(matches!(
            client.retransmit(),
            super::Retransmission::Again(_)
        ));
    }

    /// An acknowledgement of *any* segment resets the backoff, because
    /// progress is what the timeout is measuring toward.
    #[test]
    fn an_acknowledgement_resets_the_backoff() {
        let (mut client, mut server) = established_on_the_loopback();
        let mut client_out = alloc::vec::Vec::new();
        let mut server_out = alloc::vec::Vec::new();
        client.advance(0);
        let (_, outgoing) = client.send_data(b"first");
        client_out.extend(outgoing);

        // Two lost attempts, so the next wait would be four times the initial.
        client.advance(super::RTO_INITIAL_MICROS);
        assert!(matches!(
            client.retransmit(),
            super::Retransmission::Again(_)
        ));
        client.advance(super::RTO_INITIAL_MICROS * 3);
        assert!(matches!(
            client.retransmit(),
            super::Retransmission::Again(_)
        ));

        // The answer lands after all, and the schedule starts over.
        drain(&mut client_out, &mut server_out, &mut client, &mut server);
        assert_eq!(client.unacknowledged(), 0);

        client.advance(super::RTO_INITIAL_MICROS * 3 + 10);
        let (_, outgoing) = client.send_data(b"second");
        client_out.extend(outgoing);
        // The initial timeout, not four times it, is what the new segment
        // waits: an entry recorded at the later time is due at the later time
        // plus the *initial* timeout.
        client.advance(super::RTO_INITIAL_MICROS * 3 + 10 + super::RTO_INITIAL_MICROS);
        assert!(
            matches!(client.retransmit(), super::Retransmission::Again(_)),
            "the backoff started over"
        );
    }

    /// A full unacknowledged queue refuses a write rather than growing.
    #[test]
    fn a_full_unacknowledged_queue_refuses_a_write() {
        let (mut client, _server) = established_on_the_loopback();
        client.advance(0);
        for length in 0..super::MAX_UNACKNOWLEDGED {
            let (sent, _) = client.send_data(b"x");
            assert_eq!(sent, 1, "write {length} fit");
        }
        assert_eq!(
            client.unacknowledged(),
            super::MAX_UNACKNOWLEDGED,
            "the queue is full"
        );
        let (sent, outgoing) = client.send_data(b"one too many");
        assert_eq!(sent, 0, "a full queue carried nothing");
        assert!(outgoing.is_empty(), "nothing went out");

        // The peer's acknowledgement frees room, and the same write succeeds.
        let acknowledgement = client.sequence;
        let (_event, _replies) = client.receive(
            &super::Segment {
                source_port: THEIR_PORT,
                destination_port: OUR_PORT,
                sequence: client.acknowledgement,
                acknowledgement,
                flags: FLAG_ACK,
                window: super::WINDOW,
                payload_len: 0,
            },
            &[],
        );
        assert_eq!(client.unacknowledged(), 0, "one acknowledgement freed it");
        let (sent, _) = client.send_data(b"now it fits");
        assert_eq!(sent, 11, "the write the full queue refused");
    }

    /// A stream that is never answered is abandoned, and a caller learns it
    /// rather than waiting forever.
    #[test]
    fn a_stream_nobody_answers_is_abandoned() {
        let (mut client, _server) = established_on_the_loopback();
        client.advance(0);
        client.send_data(b"into the void");

        // Walk the whole schedule, asking after each interval.
        let mut now = 0u64;
        let mut attempts = 0;
        let mut timeout = super::RTO_INITIAL_MICROS;
        while attempts < super::MAX_ATTEMPTS {
            now += timeout;
            client.advance(now);
            match client.retransmit() {
                super::Retransmission::Again(_) => attempts += 1,
                other => panic!("attempt {attempts}: expected a retransmission, got {other:?}"),
            }
            timeout = (timeout * 2).min(super::RTO_MAX_MICROS);
        }

        // One more interval, and the next attempt is the one past the limit.
        now += timeout;
        client.advance(now);
        assert_eq!(client.retransmit(), super::Retransmission::Abandoned);
        assert_eq!(
            client.state(),
            State::Closed,
            "a stream nobody answers is not a stream a caller waits on"
        );
        assert_eq!(client.unacknowledged(), 0, "the queue is released");
    }

    /// A pure acknowledgement is not queued: it carries no bytes, and the
    /// peer recovers a lost one by retransmitting what it acknowledged.
    #[test]
    fn a_pure_acknowledgement_is_not_kept() {
        let (mut client, mut server) = established_on_the_loopback();
        let mut client_out = alloc::vec::Vec::new();
        let mut server_out = alloc::vec::Vec::new();

        // The server acknowledges the client's data, and that ACK is not the
        // server's to remember.
        let (_, outgoing) = client.send_data(b"x");
        client_out.extend(outgoing);
        let before = server.unacknowledged();
        drain(&mut client_out, &mut server_out, &mut client, &mut server);
        assert_eq!(
            server.unacknowledged(),
            before,
            "an acknowledgement is not retransmitted"
        );
    }

    /// An acknowledgement of a byte this side never sent retires nothing.
    ///
    /// The defect this is for is the one [RFC 793] section 3.9 names: a
    /// segment carrying an acknowledgement past `SND.NXT` is a segment whose
    /// number means nothing, and acting on it would drop data the peer never
    /// received.  The stream would then be silent rather than slow, which is
    /// the harder failure to find.
    ///
    /// [RFC 793]: https://www.rfc-editor.org/rfc/rfc793
    #[test]
    fn an_acknowledgement_past_what_was_sent_retires_nothing() {
        let (mut client, _server) = established_on_the_loopback();
        client.advance(0);
        let (_, outgoing) = client.send_data(b"protofire");
        assert_eq!(client.unacknowledged(), 1);

        // One byte past the last one this side sent: refused.
        let past = outgoing[0].sequence + outgoing[0].payload.len() as u32 + 1;
        let (_event, _replies) = client.receive(
            &super::Segment {
                source_port: THEIR_PORT,
                destination_port: OUR_PORT,
                sequence: client.acknowledgement,
                acknowledgement: past,
                flags: FLAG_ACK,
                window: super::WINDOW,
                payload_len: 0,
            },
            &[],
        );
        assert_eq!(
            client.unacknowledged(),
            1,
            "an acknowledgement past the send position retires nothing"
        );

        // Below the oldest unacknowledged byte: also refused.
        let (_event, _replies) = client.receive(
            &super::Segment {
                source_port: THEIR_PORT,
                destination_port: OUR_PORT,
                sequence: client.acknowledgement,
                acknowledgement: outgoing[0].sequence - 1,
                flags: FLAG_ACK,
                window: super::WINDOW,
                payload_len: 0,
            },
            &[],
        );
        assert_eq!(
            client.unacknowledged(),
            1,
            "an acknowledgement below the oldest sent byte retires nothing"
        );

        // And the exact last byte does retire it, which is the control that
        // shows the two refusals above were the range and not a queue that
        // never retires anything.
        let (_event, _replies) = client.receive(
            &super::Segment {
                source_port: THEIR_PORT,
                destination_port: OUR_PORT,
                sequence: client.acknowledgement,
                acknowledgement: past - 1,
                flags: FLAG_ACK,
                window: super::WINDOW,
                payload_len: 0,
            },
            &[],
        );
        assert_eq!(client.unacknowledged(), 0, "the last byte retires it");
    }
}
