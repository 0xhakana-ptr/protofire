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
//! The checksum is mandatory, and TCP has no zero field that means "not
//! summed".
//!
//! ## Out of order, and why it is held rather than dropped
//!
//! A wire may reorder, and a stack that dropped every segment that arrived
//! early would ask the peer to send it again and again until the gap filled,
//! which is a stream whose speed is the round trip's.  So a segment ahead of
//! the expected position is held in [`Connection::out_of_order`], answered
//! with the duplicate acknowledgement that names the hole, and the moment the
//! gap closes, every held segment that now fits is appended in sequence
//! order.  The inbox is therefore always a prefix of the peer's stream, which
//! is what lets a reader take bytes without learning that anything was
//! reordered at all.
//!
//! A segment that starts *before* the expected position and runs past it is
//! trimmed rather than dropped: that is what a peer's retransmission after a
//! partial loss looks like, and the bytes past the expected position are new.
//!
//! The bound is [`MAX_OUT_OF_ORDER`], and a full cache drops the newest
//! segment rather than growing: what fills it is a peer's word, and a peer
//! that opened sixty-four holes has already offered this stack more than a
//! stream it intends to finish.

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

/// The congestion window a stream starts with, in bytes.
///
/// [RFC 6928] raises the initial window to ten segments, which is what a
/// modern sender uses: it is large enough that a short transfer finishes
/// without waiting for an acknowledgement to grow it, and small enough that ten
/// segments of a link are not a burst a router notices.  Ten of [`MSS_DEFAULT`]
/// is what this is written as, because the number the RFC states is segments
/// and the number this stack counts in is bytes.
///
/// [RFC 6928]: https://www.rfc-editor.org/rfc/rfc6928
pub const INITIAL_CWND: usize = 10 * MSS_DEFAULT;

/// The largest congestion window this stack grows to, in bytes.
///
/// A window is a sender's estimate of a path's capacity, and this stack's
/// exchanges are a loopback and a user-mode network: without a ceiling, a long
/// transfer to a peer that acknowledges everything would grow the window to a
/// number that describes nothing.  Sixty-four kilobytes is past any exchange
/// this tree carries and inside what the receive side can hold.
pub const MAX_CWND: usize = 64 * 1024;

/// How many duplicate acknowledgements a loss is assumed at.
///
/// [RFC 5681]'s three: a peer that has received a segment past a gap sends the
/// same acknowledgement again, and three of them is what a single lost segment
/// produces while a reordered pair produces two.
///
/// [RFC 5681]: https://www.rfc-editor.org/rfc/rfc5681
pub const DUPLICATE_ACKS: u8 = 3;

/// How many segments ahead of the expected position one connection holds.
///
/// A peer that opens holes in its own stream is choosing how much of this
/// machine's memory to spend, so the number is this stack's and not the
/// peer's.  Sixty-four is far more than any window this stack advertises can
/// produce on a wire that reorders a little, and a cache that is full drops
/// the newest segment, which the peer will send again when its own
/// retransmission timer fires.
pub const MAX_OUT_OF_ORDER: usize = 64;

/// The window this stack advertises.
///
/// Carried, never enforced: the receive buffer a connection keeps is this
/// stack's own bound, and a peer that sent past it would be a peer whose
/// segments this stack already drops by sequence.  Eight kilobytes is room
/// for every exchange this stack carries and a number a reader can compare
/// against the buffer it advertises for.
pub const WINDOW: u16 = 8192;

/// The default largest payload one segment carries.
///
/// A segment is not a frame, and a stream is not a datagram: what a write
/// bytes becomes is a run of segments whose payloads fit the path, and this is
/// the payload that fits a fifteen-hundred-byte Ethernet frame with both
/// headers and no options, `1500 - 20 - 20`.  A sender that wrote a segment
/// longer than this produced a frame the card could not carry, which is the
/// defect this constant exists for: the first version sent every write as
/// **one** segment, so a hundred-kilobyte write built a hundred-kilobyte frame
/// and the driver's ring refused it with no stream-level answer at all.
pub const MSS_DEFAULT: usize = 1460;

/// The smallest segment this stack will build.
///
/// Below this the headers dominate and a stream of tiny segments is a stream
/// paying a header per few bytes.  A path that claims to carry less than this
/// is a path a peer stated wrongly, and [RFC 1122] says a host may refuse to
/// shrink past it rather than fragment into uselessness.
///
/// [RFC 1122]: https://www.rfc-editor.org/rfc/rfc1122
pub const MIN_MSS: usize = 128;

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
    window: u16,
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
    put_u16(into, 14, window);
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
    window: u16,
    data: &[u8],
) {
    let length = (HEADER_LEN + data.len()) as u16;
    put_u16(into, 0, source_port);
    put_u16(into, 2, destination_port);
    into[4..8].copy_from_slice(&sequence.to_be_bytes());
    into[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
    into[12] = 5 << 4;
    into[13] = flags;
    put_u16(into, 14, window);
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
    /// The receive window this side advertised in the segment.
    ///
    /// Carried rather than restated by the writer, because the number is a
    /// fact about this connection's buffers at the moment the segment was
    /// built: a writer that put a constant there would advertise room it may
    /// not have, and the peer would fill it.
    pub window: u16,
    pub payload: alloc::vec::Vec<u8>,
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
    /// The segments the peer sent ahead of the position this side expects,
    /// held until the gap before them fills.
    ///
    /// Sorted by sequence and never overlapping the inbox: an entry here is a
    /// run of the peer's stream that starts after the gap.  When the gap
    /// fills, [`Connection::deliver_in_order`] moves every entry that now
    /// touches the inbox into it, so the inbox stays a prefix of the peer's
    /// stream and a reader never learns that anything was reordered.
    out_of_order: alloc::vec::Vec<Held>,
    /// The congestion window: how many bytes this side may have in flight.
    ///
    /// This side's estimate of the path's capacity, in bytes, which is the
    /// number [`Connection::in_flight`] is compared against.  It starts at
    /// [`INITIAL_CWND`] and moves on the two events a sender learns from: an
    /// acknowledgement, which says the path carried what was sent, and a loss,
    /// which says it did not.
    cwnd: usize,
    /// The window slow start grows to before it switches to congestion
    /// avoidance.
    ///
    /// [RFC 5681]'s `ssthresh`: below it the window doubles per round trip,
    /// because a path that has not lost anything yet is one with room to
    /// spare; above it the window grows by one segment per round trip, because
    /// the only evidence of more room is a slow trickle of acknowledgements.
    ///
    /// [RFC 5681]: https://www.rfc-editor.org/rfc/rfc5681
    ssthresh: usize,
    /// How many acknowledgements in a row named the same position.
    ///
    /// Three of them without new data is a gap the peer has counted, which is
    /// [RFC 5681]'s fast retransmit: the sender knows a segment is lost without
    /// waiting for its timer, and retransmits at once.
    ///
    /// [RFC 5681]: https://www.rfc-editor.org/rfc/rfc5681
    duplicates: u8,
    /// The largest payload the path is known to carry, in bytes.
    ///
    /// Path-MTU discovery's answer, and [`MSS_DEFAULT`] until something says
    /// otherwise.  It lives on the connection rather than on the table
    /// because a path is a property of one four-tuple: a stream to one peer
    /// may cross a link a stream to another does not.
    path_mss: usize,
    /// How many bytes the peer says its receive buffer has room for.
    ///
    /// The window its segments advertise, kept because it is a bound on this
    /// side's sending and not a fact about this side's buffers.  The two
    /// numbers were one constant for a while, [`WINDOW`] carried out and
    /// never read in, and a sender that ignores this one sends past what the
    /// peer said it would take.
    peer_window: usize,
    /// What a program changed about this socket, by `SetSockOpt`.
    ///
    /// Two of the four options act on a stream and two on a bind; the two that
    /// act here are [`crate::options::Options::receive_buffer`], which is the
    /// window every segment advertises, and
    /// [`crate::options::Options::send_buffer`], which is the congestion
    /// window a write starts with.  Held on the connection and not on the
    /// table because a socket is one connection: two streams to two peers may
    /// be told different buffer sizes by the same program.
    options: crate::options::Options,
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

/// One segment held ahead of the gap.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Held {
    /// Where this run starts in the peer's stream.
    sequence: u32,
    data: alloc::vec::Vec<u8>,
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
            out_of_order: alloc::vec::Vec::new(),
            path_mss: MSS_DEFAULT,
            peer_window: WINDOW as usize,
            // The congestion window a write starts with, which `SO_SNDBUF`
            // may have changed: the option's value is a ceiling and this is
            // the start, so the smaller of the two is what slow start begins
            // at.  A program that named a larger send buffer than
            // `INITIAL_CWND` keeps the RFC 6928 initial window, because slow
            // start is a rule about the path and not about the buffer.
            cwnd: INITIAL_CWND,
            options: crate::options::Options::new(),
            ssthresh: MAX_CWND,
            duplicates: 0,
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
            out_of_order: alloc::vec::Vec::new(),
            path_mss: MSS_DEFAULT,
            peer_window: WINDOW as usize,
            // The congestion window a write starts with, which `SO_SNDBUF`
            // may have changed: the option's value is a ceiling and this is
            // the start, so the smaller of the two is what slow start begins
            // at.  A program that named a larger send buffer than
            // `INITIAL_CWND` keeps the RFC 6928 initial window, because slow
            // start is a rule about the path and not about the buffer.
            cwnd: INITIAL_CWND,
            options: crate::options::Options::new(),
            ssthresh: MAX_CWND,
            duplicates: 0,
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
        // An acknowledgement may be the third duplicate that says a segment
        // was lost, in which case the answer is that segment sent again, and
        // it goes out before anything this call does with the segment's own
        // data: the gap is ahead of whatever the peer just sent.
        let fast = if segment.flags & FLAG_ACK != 0 {
            self.note_acknowledgement(segment.acknowledgement)
                .unwrap_or_default()
        } else {
            alloc::vec::Vec::new()
        };
        // The peer's own room, taken from the segment that stated it.  After
        // the acknowledgement and not before, because a fast retransmission is
        // composed from the queue the acknowledgement inspected, and the
        // window bounds what is sent *next*.
        self.note_window(segment);
        let (event, mut replies) = self.receive_body(segment, payload);
        // The fast retransmission goes first: it is the segment at a gap the
        // peer has already counted, and the reply this call composed is about
        // bytes that arrived after it.
        let mut all = fast;
        all.append(&mut replies);
        (event, all)
    }

    /// The receive path proper, with the fast retransmission already decided.
    fn receive_body(
        &mut self,
        segment: &Segment,
        payload: &[u8],
    ) -> (abi::Result<Event>, alloc::vec::Vec<Outgoing>) {
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
        // direction.
        let open = matches!(
            self.state,
            State::Established | State::FinWait | State::CloseWait | State::LastAck
        );
        if !open {
            return (Ok(Event::None), alloc::vec::Vec::new());
        }

        let mut event = Event::None;
        if segment.flags & FLAG_ACK != 0 && self.state == State::LastAck {
            // The peer's acknowledgement of this side's finish: the close is
            // over.
            self.state = State::Closed;
            return (Ok(Event::Settled), alloc::vec::Vec::new());
        }

        // A segment ahead of the position this side expects is held rather
        // than dropped: a wire may reorder, and a stack that dropped every
        // early segment would ask the peer to send it again until the gap
        // filled, which is a stream whose speed is the round trip's.  The
        // answer is the duplicate acknowledgement that names the hole.
        //
        // The test is the segment's **start**, not its end: a segment whose
        // first byte is past the gap begins a run that cannot be delivered
        // until the gap closes, whether or not the run is longer than the
        // gap.  Comparing the gap against the segment's length instead reads
        // a short run just past the gap as a retransmission of the bytes
        // before it, which is how a probe's second half became nine bytes of
        // "already seen" and reached the inbox as the first half.
        //
        // The direction is `seq_before`'s and not a subtraction, because a
        // segment that starts before the expected position makes
        // `sequence - acknowledgement` wrap to a huge number.
        if !payload.is_empty() && seq_before(self.acknowledgement, segment.sequence) {
            self.hold(segment.sequence, payload);
            // Through `take_outgoing` rather than `one`, because the window
            // this acknowledgement advertises is the room the buffers have,
            // and only the connection knows it.  A pure ACK is not queued for
            // retransmission either way.
            let sent = self.take_outgoing(self.sequence, self.acknowledgement, FLAG_ACK, &[]);
            return (Ok(Event::None), sent);
        }

        if self.state == State::FinWait
            && segment.flags & FLAG_ACK != 0
            && segment.flags & FLAG_FIN != 0
            && segment.sequence == self.acknowledgement
        {
            // The peer's finish, answering this side's own: the last
            // acknowledgement closes both halves at once.
            self.acknowledgement = segment.sequence.wrapping_add(1);
            let sent = self.take_outgoing(self.sequence, self.acknowledgement, FLAG_ACK, &[]);
            self.state = State::Closed;
            return (Ok(Event::Settled), sent);
        }

        if payload.is_empty() && segment.flags & FLAG_FIN == 0 {
            // An empty segment carries nothing to sequence; its
            // acknowledgement was acted on above.
            return (Ok(Event::None), alloc::vec::Vec::new());
        }
        if seq_before(segment.sequence, self.acknowledgement) {
            // Behind the expected position.  Any bytes past it are new, and
            // the rest is a retransmission of what is already here: the trim
            // is `accept_payload`'s, which is also the path an early segment
            // takes once the gap closes.
            let seen = self.acknowledgement.wrapping_sub(segment.sequence) as usize;
            if seen >= payload.len() {
                return (Ok(Event::None), alloc::vec::Vec::new());
            }
        }

        if !payload.is_empty() {
            let growth = self.accept_payload(segment.sequence, payload);
            if growth > 0 {
                event = Event::Data(growth);
            }
        }
        if segment.flags & FLAG_FIN != 0 && segment.sequence == self.acknowledgement {
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
            self.take_outgoing(self.sequence, self.acknowledgement, FLAG_ACK, &[])
        };
        (Ok(event), sent)
    }

    /// Take one segment's data, answering how many bytes reached the inbox.
    ///
    /// The return value is what a caller reports as [`Event::Data`], and it
    /// counts everything this call put in the inbox: the segment's own bytes
    /// plus whatever held segments the gap closing released.  A caller that
    /// was told only the segment's length would take fewer bytes than it was
    /// promised.
    ///
    /// The caller has already refused a segment that is entirely ahead of the
    /// gap, so the segment here starts at or before the expected position.
    /// That is what makes `seen` a real count and not a wrapped one: the
    /// caller's `seq_before` test is the guarantee, and this function's
    /// arithmetic depends on it.
    fn accept_payload(&mut self, sequence: u32, payload: &[u8]) -> usize {
        // A peer may send no more than the window this side advertised.  The
        // check is on what the connection would **hold** after taking the
        // bytes, not on the segment's length: a stream that accepted whatever
        // arrived would let a peer choose this machine's memory use, which is
        // the whole reason a window exists.
        //
        // The bytes past the window are dropped rather than the whole segment:
        // at the edge the segment's first bytes may be exactly what fits, and
        // a sender that learns nothing would send the same segment again.
        let room = self.window_room();
        let payload = if payload.len() > room {
            &payload[..room]
        } else {
            payload
        };
        if payload.is_empty() {
            return 0;
        }
        let before = self.inbox.len();
        let seen = self.acknowledgement.wrapping_sub(sequence) as usize;
        let fresh = if seen >= payload.len() {
            // Everything it carries is already in the inbox.
            &payload[..0]
        } else {
            // The bytes before the expected position are a retransmission of
            // what is already here; only the rest is new.
            &payload[seen..]
        };
        if fresh.is_empty() {
            return 0;
        }
        self.inbox.extend_from_slice(fresh);
        self.acknowledgement = self.acknowledgement.wrapping_add(fresh.len() as u32);
        self.deliver_in_order();
        self.inbox.len() - before
    }

    /// Hold a segment that starts after the position this side expects.
    ///
    /// A duplicate of something already held is dropped rather than stored
    /// twice, and a full cache refuses the newest: what fills it is a peer's
    /// word, and a peer that opened sixty-four holes has already offered this
    /// stack more than a stream it intends to finish.
    fn hold(&mut self, sequence: u32, payload: &[u8]) {
        if self.out_of_order.len() >= MAX_OUT_OF_ORDER {
            return;
        }
        // A run held ahead of a gap is memory this side is spending on the
        // peer's word, so it is bounded by the same room the inbox is: a peer
        // that opened a hole and then sent past the window would otherwise
        // hold two buffers' worth.
        if payload.len() > self.window_room() {
            return;
        }
        if self
            .out_of_order
            .iter()
            .any(|held| held.sequence == sequence && held.data == payload)
        {
            return;
        }
        self.out_of_order.push(Held {
            sequence,
            data: alloc::vec::Vec::from(payload),
        });
    }

    /// Move every held segment that now fits into the inbox, in order.
    ///
    /// The loop repeats because each append may make the next held segment
    /// fit: a cache filled from the far end backwards becomes a whole stream
    /// the moment the first hole closes.
    fn deliver_in_order(&mut self) {
        loop {
            let Some(index) = self
                .out_of_order
                .iter()
                .position(|held| held.sequence == self.acknowledgement)
            else {
                return;
            };
            let held = self.out_of_order.remove(index);
            self.acknowledgement = self.acknowledgement.wrapping_add(held.data.len() as u32);
            self.inbox.extend_from_slice(&held.data);
            // A held segment the inbox has caught up with is trimmed or
            // dropped rather than stored twice, which a peer's retransmission
            // may produce.
            self.trim_held();
        }
    }

    /// Drop or trim held segments the inbox has caught up with.
    ///
    /// The comparison is the sequence's own and not a subtraction cast to
    /// `usize`: a held segment that starts *after* the inbox makes
    /// `inbox_end - sequence` wrap to a huge number, and a subtraction would
    /// read that as "entirely covered" and delete a segment that has not been
    /// delivered at all.  That defect cost a test four bytes of a sixteen
    /// byte run, and it is why this is `seq_before` and not arithmetic.
    fn trim_held(&mut self) {
        let inbox_end = self.acknowledgement;
        self.out_of_order.retain_mut(|held| {
            if seq_before(held.sequence, inbox_end) {
                let covered = inbox_end.wrapping_sub(held.sequence) as usize;
                if covered >= held.data.len() {
                    return false;
                }
                held.data.drain(..covered);
                held.sequence = inbox_end;
            }
            true
        });
    }

    /// How many segments are held ahead of a gap.
    pub fn out_of_order(&self) -> usize {
        self.out_of_order.len()
    }

    /// How many bytes this side has room for.
    ///
    /// The window a segment advertises.  It is [`WINDOW`] less everything the
    /// connection is holding that a reader has not taken: the inbox, and the
    /// runs held ahead of a gap, because both are bytes the peer has already
    /// sent and this side is spending memory on.  Counting only the inbox
    /// would advertise room a reordered stream would fill, which is how a
    /// window becomes a number that means nothing.
    ///
    /// The floor is zero rather than a wrapped subtraction: a peer that sent
    /// past the window is refused at `accept_payload`, so the arithmetic
    /// should not reach this, and a window that wrapped would advertise sixty
    /// kilobytes of room that does not exist.
    ///
    /// The total is `SO_RCVBUF`'s, which is [`WINDOW`] until a program sets
    /// it: a program that asked for a smaller receive buffer asks the peer to
    /// send less, and the number it read back from `GetSockOpt` is the number
    /// its peer is looking at.
    pub fn advertised_window(&self) -> u16 {
        let held = self.held();
        let total = self.options.receive_buffer().min(u16::MAX as usize);
        (total.saturating_sub(held)).min(total) as u16
    }

    /// The options a program may read and change.
    pub fn options(&self) -> crate::options::Options {
        self.options
    }

    /// Set one option, answering the value's width.
    ///
    /// The value goes through [`crate::options::Options::set`], which is where
    /// the four options and their widths live; what this adds is the one thing
    /// only the connection can do, which is to apply a size to the state it
    /// governs.  `SO_RCVBUF` needs nothing applied, because
    /// [`Connection::advertised_window`] reads it every time a segment is
    /// built; `SO_SNDBUF` is applied here, and it shrinks the congestion
    /// window when it names something smaller than what slow start has already
    /// grown to.
    pub fn set_option(&mut self, level: u32, name: u32, value: &[u8]) -> abi::Result<()> {
        self.options.set(level, name, value)?;
        // A send buffer smaller than the window already open is a ceiling the
        // sender has already passed: the acknowledgement that grew it is
        // history, and the next write must respect the new number rather than
        // the one that was in force when it was sent.
        self.cwnd = self.cwnd.min(self.options.send_buffer());
        Ok(())
    }

    /// Read one option into `into`, answering how many bytes were written.
    pub fn get_option(&self, level: u32, name: u32, into: &mut [u8]) -> abi::Result<usize> {
        self.options.get(level, name, into)
    }

    /// How many bytes this side has sent and the peer has not acknowledged.
    ///
    /// The number the congestion window bounds.  It is the queue's payload,
    /// not its segment count: a window in bytes and a queue in segments would
    /// be two units for one question, and the segment count is already bounded
    /// separately by [`MAX_UNACKNOWLEDGED`].
    pub fn in_flight(&self) -> usize {
        self.unacknowledged
            .iter()
            .map(|segment| segment.end.wrapping_sub(segment.sequence) as usize)
            .sum()
    }

    /// The congestion window, in bytes.
    pub fn congestion_window(&self) -> usize {
        self.cwnd
    }

    /// The window slow start grows to.
    pub fn slow_start_threshold(&self) -> usize {
        self.ssthresh
    }

    /// How many bytes this side may put in flight right now.
    ///
    /// The smallest of three bounds: the congestion window, the peer's
    /// advertised window, and what the unacknowledged queue has room for.  A
    /// sender may send when `in_flight < min(cwnd, peer, room)`, which is
    /// [RFC 5681]'s rule with the three bounds it names: the congestion window
    /// is this side's estimate of the path, the peer's window is the peer's
    /// statement about its own buffers, and the queue is this side's copy of
    /// what the peer has not taken, bounded by [`MAX_UNACKNOWLEDGED`].
    ///
    /// The peer's window was carried and ignored until this bound existed: a
    /// segment's `window` field was parsed into [`Segment`] and every sender
    /// treated the queue's size as the whole answer.  A peer that advertised
    /// fewer bytes than `MAX_UNACKNOWLEDGED` segments were worth therefore
    /// received more than it said it had room for, which is loss it reported
    /// as a gap rather than as the window it had already named.
    ///
    /// [RFC 5681]: https://www.rfc-editor.org/rfc/rfc5681
    pub fn send_budget(&self) -> usize {
        let room = MAX_UNACKNOWLEDGED
            .saturating_sub(self.unacknowledged.len())
            .saturating_mul(self.mss());
        self.cwnd
            .min(self.peer_window)
            .saturating_sub(self.in_flight())
            .min(room)
    }

    /// The bytes the peer says its receive buffer has room for.
    ///
    /// The number its segments advertise, which [RFC 793] section 3.9 calls
    /// `SND.WND`: a receive buffer's free room, as the peer last measured it.
    /// It is kept as a number of bytes and never as a segment count, because a
    /// segment's `window` field is a byte count and the two units this stack
    /// counts in are bytes and segments, which would otherwise be confused
    /// here.
    ///
    /// It starts at the full window because a handshake that has not yet
    /// carried an ACK has not been told anything: a connection that started at
    /// zero would wait for a statement the peer makes in the same SYN that
    /// opens the stream.
    pub fn peer_window(&self) -> usize {
        self.peer_window
    }

    /// Open the window on an acknowledgement that carried new data.
    ///
    /// Two rules, and which one applies is `ssthresh`'s.  Below it the window
    /// grows by the acknowledged bytes, which doubles it per round trip: slow
    /// start is exponential because nothing has yet said the path is full.
    /// Above it the window grows by `mss * acked / cwnd`, which is one segment
    /// per round trip: congestion avoidance, because the only evidence of more
    /// room is a trickle of acknowledgements.
    ///
    /// `acked` is what this acknowledgement newly covered, not the whole of
    /// what the peer has received: counting a duplicate would make a stalled
    /// stream grow a window for repeating itself.
    fn open_window(&mut self, acked: usize) {
        if acked == 0 {
            return;
        }
        if self.cwnd < self.ssthresh {
            self.cwnd = self.cwnd.saturating_add(acked).min(MAX_CWND);
        } else {
            // `mss * acked / cwnd`, in that order, so the multiply does not
            // lose the fraction a small acknowledgement is: a division first
            // would round a segment per round trip down to nothing.
            let growth = self.mss().saturating_mul(acked) / self.cwnd.max(1);
            self.cwnd = self.cwnd.saturating_add(growth.max(1)).min(MAX_CWND);
        }
    }

    /// Shrink the window because the path dropped something.
    ///
    /// [RFC 5681]'s two halves: a timeout is the harder evidence, so the window
    /// goes to one segment and slow start begins again; three duplicate
    /// acknowledgements are the softer one, so the window halves and the
    /// threshold is set to it, which is fast recovery.  A path that dropped
    /// nothing should not shrink, which is why this is called from the two
    /// places that know something was lost and not from an acknowledgement.
    ///
    /// [RFC 5681]: https://www.rfc-editor.org/rfc/rfc5681
    fn close_window(&mut self, timeout: bool) {
        let flight = self.in_flight();
        // The threshold never goes below the protocol's floor: a path that
        // repeatedly collapses to two segments is a path this stack cannot
        // use, and [RFC 5681] says the threshold holds at least two segments.
        self.ssthresh = (flight / 2).max(2 * self.mss());
        if timeout {
            self.cwnd = self.mss();
            self.duplicates = 0;
        } else {
            self.cwnd = self.ssthresh;
        }
    }

    /// Note the room the peer's segment says its receive buffer has.
    ///
    /// The peer states a window in every segment it sends, including the ones
    /// that carry data and the bare acknowledgements, so this reads the field
    /// and does not wait for an acknowledgement to carry new bytes: a peer
    /// whose buffer is full says so on the acknowledgement that emptied its
    /// inbox, which is exactly the segment this needs to read.
    ///
    /// The statement is taken only from a segment whose acknowledgement is in
    /// the range [RFC 793] section 3.9 calls acceptable, `SND.UNA <= SEG.ACK
    /// <= SND.NXT`.  A duplicate acknowledgement sits at the low end of that
    /// range and its window **is** read, which is the case that matters: a
    /// peer filling its buffer answers three times with the same position and a
    /// window that shrinks with each one, and a sender that skipped duplicate
    /// acknowledgements would keep the largest number it had ever seen.  A
    /// segment acknowledging something already acknowledged carries a window
    /// from before the last update, and that is the one this refuses.
    ///
    /// A zero is a real value and not a refusal: [RFC 793]'s `SND.WND` may be
    /// zero, and a sender that treated zero as "nothing was said" would ignore
    /// the one statement that matters.  What a zero produces is a budget of
    /// zero, which is the sender waiting for the peer to reopen, and the reopen
    /// arrives as a later segment with a larger number in the same field.
    fn note_window(&mut self, segment: &Segment) {
        // A SYN has no acknowledgement to compare, and its window is the
        // peer's statement about a stream that has carried nothing.
        if segment.flags & FLAG_ACK != 0 {
            // The low end of the range is the oldest queued segment's first
            // byte, and with an empty queue the two ends of the range are one
            // position, which only an acknowledgement of exactly that position
            // is current at.
            let oldest = self
                .unacknowledged
                .first()
                .map(|segment| segment.sequence)
                .unwrap_or(self.sequence);
            if seq_before(segment.acknowledgement, oldest)
                || seq_before(self.sequence, segment.acknowledgement)
            {
                return;
            }
        }
        self.peer_window = segment.window as usize;
    }

    /// Note an acknowledgement that covered nothing new.
    ///
    /// Three in a row is [RFC 5681]'s fast retransmit: the peer has received
    /// something past a gap, so the segment at the gap is lost and waiting for
    /// its timer would wait a second for news this acknowledgement already
    /// carries.  The answer is the segment at the gap, sent at once.
    ///
    /// [RFC 5681]: https://www.rfc-editor.org/rfc/rfc5681
    fn note_duplicate(&mut self) -> Option<alloc::vec::Vec<Outgoing>> {
        self.duplicates = self.duplicates.saturating_add(1);
        if self.duplicates != DUPLICATE_ACKS {
            return None;
        }
        // Read what the retransmission needs before anything borrows the queue
        // mutably: the position, the flags and the bytes.
        let (sequence, flags, payload) = {
            let oldest = self.unacknowledged.first()?;
            (oldest.sequence, oldest.flags, oldest.payload.clone())
        };
        // Fast recovery: the window halves before the retransmission, because
        // the path has just said it dropped something and sending the whole
        // window again would offer it the same burst.
        self.close_window(false);
        let segment = Outgoing {
            sequence,
            acknowledgement: self.acknowledgement,
            flags,
            window: self.advertised_window(),
            payload,
        };
        self.unacknowledged[0].sent_at = self.now;
        Some(alloc::vec![segment])
    }

    /// The room this side has left for the peer's bytes.
    ///
    /// The total is `SO_RCVBUF`'s, the same number
    /// [`Connection::advertised_window`] states to the peer.  The two agreeing
    /// is the property that makes the option real: a window a connection
    /// advertises and a room it enforces that came from two different numbers
    /// would let a peer send exactly what it was told it could and have it
    /// refused.
    fn window_room(&self) -> usize {
        self.options.receive_buffer().saturating_sub(self.held())
    }

    /// The position this side expects the peer's next byte at.
    ///
    /// The sequence number an acknowledgement of this stream would carry, which
    /// is what a caller needs to place a segment it is building itself.
    pub fn expected_position(&self) -> u32 {
        self.acknowledgement
    }

    /// The position this side will send its next byte from.
    ///
    /// [RFC 793] section 3.9's `SND.NXT`, which is the high end of the range an
    /// incoming acknowledgement has to fall inside to be current.  A caller
    /// that composes a segment on this side's behalf needs it, and so does a
    /// test that hands this connection an acknowledgement it has to accept.
    pub fn send_position(&self) -> u32 {
        self.sequence
    }

    /// How many bytes the peer has sent that a reader has not taken.
    pub fn held(&self) -> usize {
        self.inbox.len()
            + self
                .out_of_order
                .iter()
                .map(|run| run.data.len())
                .sum::<usize>()
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

        // A write becomes a run of segments, each no larger than the path's
        // payload, and as many of them as the queue has room for.  A write
        // that cannot be split into what fits is a partial write: the count
        // answers how much was carried, which is the same answer a pipe gives
        // when its buffer fills, and the caller writes the rest.
        //
        // The loop stops on the queue's bound for the reason that bound
        // exists: what is queued is bytes nobody has acknowledged, and a peer
        // that stopped acknowledging must not be able to make one write cost
        // unbounded memory.
        // The congestion window bounds this write as well as the queue does:
        // a sender may have only `min(cwnd, peer window, queue room)` in
        // flight, so a write that would exceed it is a partial write.  This is
        // the rule that makes slow start mean something: an empty stream
        // starts with ten segments of room and earns the rest.
        let budget = self.send_budget();
        if budget == 0 {
            return (0, alloc::vec::Vec::new());
        }
        let mss = self.mss();
        let mut carried = 0;
        let mut segments = alloc::vec::Vec::new();
        while carried < bytes.len()
            && carried < budget
            && self.unacknowledged.len() < MAX_UNACKNOWLEDGED
        {
            // The segment is clamped to what the budget has left, not just to
            // what the bytes have.  A budget is a number of bytes and an MSS is
            // a number of bytes, and the two are only equal when the budget is
            // a whole number of segments: a first version tested `carried <
            // budget` and then appended a whole MSS, which put up to one
            // segment more in flight than the window allows.  A window of 8192
            // against segments of 1460 carried 8760, and the test that names
            // the number is the one that found it.
            let allowance = (budget - carried).min(mss);
            let end = (carried + allowance).min(bytes.len());
            let chunk = &bytes[carried..end];
            segments.extend(self.take_outgoing(
                self.sequence,
                self.acknowledgement,
                FLAG_ACK | FLAG_PSH,
                chunk,
            ));
            self.sequence = self.sequence.wrapping_add(chunk.len() as u32);
            carried = end;
        }
        (carried, segments)
    }

    /// The largest payload one segment may carry on this connection.
    ///
    /// The path's own limit when discovery has found one, and [`MSS_DEFAULT`]
    /// otherwise.  A connection that learns the path is smaller never sends a
    /// larger segment again, which is what makes one lost oversized segment
    /// enough to fix every later write.
    ///
    /// The floor is [`MIN_MSS`]: a report claiming less than that is a path a
    /// peer stated wrongly, and a stream that shrank to a handful of bytes per
    /// segment would be a header per handful.
    fn mss(&self) -> usize {
        self.path_mss.clamp(MIN_MSS, MSS_DEFAULT)
    }

    /// Tell this connection the largest payload the path carries.
    ///
    /// The caller learns it from a packet-too-big report or from its own
    /// interface, and the number is a payload rather than an MTU so the
    /// headers do not have to be subtracted twice.  It only ever shrinks: a
    /// path that was found small does not become large again because a later
    /// measurement says so, and a connection that grew its segment size would
    /// repeat the loss that taught it.
    pub fn limit_segment(&mut self, payload: usize) {
        self.path_mss = self.path_mss.min(payload);
    }

    /// The largest payload this connection may put in one segment.
    pub fn segment_limit(&self) -> usize {
        self.mss()
    }

    /// End the stream because the wire said it is over.
    ///
    /// This is what an ICMP error acts on, and it is not a close: a close is
    /// two ends agreeing, and this is a third party reporting that the path
    /// does not exist.  The state goes straight to [`State::Closed`] with no
    /// segment sent, because sending a FIN to a peer a router could not reach
    /// is a segment asking for the same error again.
    ///
    /// The two states an error may end are the handshake and an open stream.
    /// [RFC 1122] says a host must not abort a connection whose segments are
    /// merely being lost, and an error is different: it is a report about
    /// this four-tuple, from a party on the path, and the only two things a
    /// stack can do with it are abort or ignore.  This aborts.
    ///
    /// [RFC 1122]: https://www.rfc-editor.org/rfc/rfc1122
    pub fn abort(&mut self) {
        self.state = State::Closed;
        self.finished = true;
        self.unacknowledged.clear();
        self.out_of_order.clear();
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
        // The queue is read once, into values: what follows borrows the
        // connection mutably, and a borrow of the queue would be a second one.
        let (sequence, flags, payload) = {
            let Some(oldest) = self.unacknowledged.first() else {
                return Retransmission::Idle;
            };
            if self.now.wrapping_sub(oldest.sent_at) < self.timeout {
                return Retransmission::Idle;
            }
            (oldest.sequence, oldest.flags, oldest.payload.clone())
        };
        if self.attempts >= MAX_ATTEMPTS {
            self.unacknowledged.clear();
            self.state = State::Closed;
            return Retransmission::Abandoned;
        }
        // A timer that fired is the harder evidence of loss, so the window
        // goes back to one segment and slow start begins again.
        self.close_window(true);
        let acknowledgement = self.acknowledgement;
        self.attempts += 1;
        // [RFC 6298]'s backoff, capped: a stream that answers nothing must
        // not hold a caller for the sum of unbounded doublings.
        self.timeout = self.timeout.saturating_mul(2).min(RTO_MAX_MICROS);
        let sent = alloc::vec![Outgoing {
            sequence,
            acknowledgement,
            flags,
            window: self.advertised_window(),
            payload,
        }];
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
        // The window this side advertises is the room its buffers still have,
        // read **here**, where the connection knows what it is holding.  A
        // writer that restated a constant would advertise room the inbox has
        // already filled.
        alloc::vec![Outgoing {
            sequence,
            acknowledgement,
            flags,
            window: self.advertised_window(),
            payload: alloc::vec::Vec::from(payload),
        }]
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
    fn note_acknowledgement(&mut self, acknowledgement: u32) -> Option<alloc::vec::Vec<Outgoing>> {
        let oldest = self.unacknowledged.first()?;
        // `SND.UNA <= SEG.ACK <= SND.NXT`, each comparison in the sequence's
        // own arithmetic so a stream that crossed the wrap is not refused.
        if seq_before(acknowledgement, oldest.sequence)
            || seq_before(self.sequence, acknowledgement)
        {
            return None;
        }
        // What this acknowledgement newly covers, which is what the congestion
        // window grows by: counting the whole of what the peer has received
        // would grow it again for a segment already counted.
        //
        // Only the **data** counts.  A SYN and a FIN each occupy one sequence
        // number and neither occupies a link, so a window that grew by them
        // would be measuring the handshake rather than the path: the first
        // version of this added one byte for the SYN and left the initial
        // window at ten segments and one byte, which is a number no rule
        // produces and a test that compared against ten segments found.
        let covered: usize = self
            .unacknowledged
            .iter()
            .filter(|segment| acknowledges(acknowledgement, segment.end))
            .map(|segment| segment.payload.len())
            .sum();
        // Whether this acknowledgement covers any segment at all.  A segment
        // that carries only a SYN or a FIN occupies no link but does leave the
        // queue, so the test is on coverage and not on the byte count: a
        // connection that kept a handshake's SYN because it carried no data
        // would hold it until the stream was abandoned.
        let retires = self
            .unacknowledged
            .iter()
            .any(|segment| acknowledges(acknowledgement, segment.end));
        if !retires {
            // Nothing covered: a duplicate, which says the peer is waiting at
            // a gap.  Three of them is a lost segment, and the answer is the
            // segment at the gap.
            return self.note_duplicate();
        }
        self.unacknowledged
            .retain(|segment| !acknowledges(acknowledgement, segment.end));
        self.attempts = 0;
        self.timeout = RTO_INITIAL_MICROS;
        self.duplicates = 0;
        self.open_window(covered);
        None
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

    /// A segment ahead of the expected position is held, and the moment the
    /// gap fills it reaches the inbox in sequence order.
    ///
    /// This used to be a drop test, and what it asserted was the defect: a
    /// wire may reorder, and a stack that dropped every early segment asked
    /// the peer to send it again and again until the gap filled, which is a
    /// stream whose speed is the round trip's.
    #[test]
    fn a_segment_ahead_of_the_gap_is_held_until_it_fills() {
        let (_client, mut server) = handshake();
        let base = server.acknowledgement;

        // Four bytes past the hole.
        let second = Segment {
            source_port: OUR_PORT,
            destination_port: THEIR_PORT,
            sequence: base + 4,
            acknowledgement: 5001,
            flags: FLAG_ACK | FLAG_PSH,
            window: super::WINDOW,
            payload_len: 4,
        };
        let (answer, replies) = server.receive(&second, b"wxyz");
        assert_eq!(answer, Ok(Event::None), "nothing reached a reader yet");
        assert_eq!(replies.len(), 1, "the duplicate ACK that names the hole");
        assert_eq!(
            replies[0].acknowledgement, base,
            "the position the peer should fill, not the one it sent past"
        );
        assert_eq!(server.inbox_len(), 0);
        assert_eq!(server.out_of_order(), 1, "the segment is held");

        // The hole fills, and both runs land in order.
        let first = Segment {
            source_port: OUR_PORT,
            destination_port: THEIR_PORT,
            sequence: base,
            acknowledgement: 5001,
            flags: FLAG_ACK | FLAG_PSH,
            window: super::WINDOW,
            payload_len: 4,
        };
        let (answer, _) = server.receive(&first, b"abcd");
        assert_eq!(answer, Ok(Event::Data(8)), "both runs reached the inbox");
        assert_eq!(server.out_of_order(), 0, "the held segment was taken");
        assert_eq!(server.inbox_len(), 8);

        let mut buffer = [0_u8; 8];
        assert_eq!(server.take(&mut buffer), 8);
        assert_eq!(&buffer, b"abcdwxyz", "sequence order, not arrival order");
    }

    /// The far end of a hole may arrive first, and the walk keeps going: a
    /// cache filled backwards becomes a whole stream the moment the first
    /// hole closes.
    #[test]
    fn several_held_segments_all_land_when_the_gap_closes() {
        let (_client, mut server) = handshake();
        let base = server.acknowledgement;

        for (offset, data) in [(12u32, &b"mnop"[..]), (8, b"ijkl"), (4, b"efgh")] {
            let segment = Segment {
                source_port: OUR_PORT,
                destination_port: THEIR_PORT,
                sequence: base + offset,
                acknowledgement: 5001,
                flags: FLAG_ACK | FLAG_PSH,
                window: super::WINDOW,
                payload_len: 4,
            };
            let (answer, _) = server.receive(&segment, data);
            assert_eq!(answer, Ok(Event::None));
        }
        assert_eq!(server.out_of_order(), 3);

        let first = Segment {
            source_port: OUR_PORT,
            destination_port: THEIR_PORT,
            sequence: base,
            acknowledgement: 5001,
            flags: FLAG_ACK | FLAG_PSH,
            window: super::WINDOW,
            payload_len: 4,
        };
        let (answer, _) = server.receive(&first, b"abcd");
        assert_eq!(answer, Ok(Event::Data(16)), "every held byte arrived");
        assert_eq!(server.out_of_order(), 0);

        let mut buffer = [0_u8; 16];
        assert_eq!(server.take(&mut buffer), 16);
        assert_eq!(&buffer, b"abcdefghijklmnop");
    }

    /// A segment that starts before the expected position and runs past it is
    /// trimmed to the bytes that are new.
    ///
    /// This is what a peer's retransmission after a partial loss looks like,
    /// and a stack that dropped the whole segment would lose the new half.
    #[test]
    fn a_straddling_segment_contributes_only_its_new_half() {
        let (_client, mut server) = handshake();
        let base = server.acknowledgement;

        let whole = Segment {
            source_port: OUR_PORT,
            destination_port: THEIR_PORT,
            sequence: base,
            acknowledgement: 5001,
            flags: FLAG_ACK | FLAG_PSH,
            window: super::WINDOW,
            payload_len: 4,
        };
        let (answer, _) = server.receive(&whole, b"abcd");
        assert_eq!(answer, Ok(Event::Data(4)));

        // A segment that begins at the position this side has already passed
        // and runs past it: four bytes that are already in the inbox and four
        // that are not.  Only the new four count, which is what a peer's
        // retransmission after a partial loss looks like: a stack that
        // dropped the whole segment would lose the new half.
        let straddling = Segment {
            source_port: OUR_PORT,
            destination_port: THEIR_PORT,
            sequence: base,
            acknowledgement: 5001,
            flags: FLAG_ACK | FLAG_PSH,
            window: super::WINDOW,
            payload_len: 8,
        };
        let (answer, _) = server.receive(&straddling, b"abcdefgh");
        assert_eq!(answer, Ok(Event::Data(4)), "only the new half");
        assert_eq!(server.inbox_len(), 8);

        let mut buffer = [0_u8; 8];
        assert_eq!(server.take(&mut buffer), 8);
        assert_eq!(&buffer, b"abcdefgh");
    }

    /// A duplicate of what the inbox already holds adds nothing.
    #[test]
    fn a_repeated_segment_adds_nothing() {
        let (_client, mut server) = handshake();
        let base = server.acknowledgement;
        let segment = Segment {
            source_port: OUR_PORT,
            destination_port: THEIR_PORT,
            sequence: base,
            acknowledgement: 5001,
            flags: FLAG_ACK | FLAG_PSH,
            window: super::WINDOW,
            payload_len: 8,
        };
        let (answer, _) = server.receive(&segment, b"abcdefgh");
        assert_eq!(answer, Ok(Event::Data(8)));

        let (answer, _) = server.receive(&segment, b"abcdefgh");
        assert_eq!(answer, Ok(Event::None), "a duplicate is not data");
        assert_eq!(server.inbox_len(), 8, "and does not double the inbox");
    }

    /// A short run just past the gap is held, not trimmed into the gap.
    ///
    /// This is the defect the boot's probe found after the tests were green:
    /// the hold test compared the *gap* against the segment's length, so a
    /// run nine bytes past the gap and ten bytes long read as "one byte new,
    /// nine already seen" and was delivered as the wrong bytes.  The test's
    /// numbers are the probe's, which is why it is here with them.
    #[test]
    fn a_short_run_just_past_the_gap_is_held_not_trimmed() {
        let (_client, mut server) = handshake();
        let base = server.acknowledgement;

        // Nine bytes past the gap, ten bytes long: its start is past the
        // position this side expects, so it is a run to hold.
        let second = Segment {
            source_port: OUR_PORT,
            destination_port: THEIR_PORT,
            sequence: base + 9,
            acknowledgement: 5001,
            flags: FLAG_ACK | FLAG_PSH,
            window: super::WINDOW,
            payload_len: 10,
        };
        let (answer, _) = server.receive(&second, b"secondhalf");
        assert_eq!(answer, Ok(Event::None), "held, not delivered");
        assert_eq!(server.out_of_order(), 1, "the run is held");
        assert_eq!(server.inbox_len(), 0, "and nothing reached the inbox");

        // The first nine bytes, and the whole run lands in order.
        let first = Segment {
            source_port: OUR_PORT,
            destination_port: THEIR_PORT,
            sequence: base,
            acknowledgement: 5001,
            flags: FLAG_ACK | FLAG_PSH,
            window: super::WINDOW,
            payload_len: 9,
        };
        let (answer, _) = server.receive(&first, b"firsthalf");
        assert_eq!(answer, Ok(Event::Data(19)), "both runs");
        let mut buffer = [0_u8; 19];
        assert_eq!(server.take(&mut buffer), 19);
        assert_eq!(&buffer, b"firsthalfsecondhalf");
    }

    /// The window a segment advertises is the room this side has left, and
    /// bytes past it are dropped.
    ///
    /// This is the difference between a window that is carried and one that is
    /// enforced.  Before this change the field was a constant: this stack told
    /// every peer it had eight kilobytes of room however full its inbox was, so
    /// a peer that filled it was entitled to send more, and what stopped it was
    /// the connection's own memory growing without bound.
    #[test]
    fn the_window_shrinks_as_the_peer_fills_it() {
        let (mut client, mut server) = handshake();
        // The handshake's answers are built before any data, so the first one
        // advertises the whole buffer.
        let base = server.acknowledgement;
        assert_eq!(
            server.advertised_window(),
            super::WINDOW,
            "an empty connection has all of it"
        );

        // Half the buffer arrives, and the next segment says so.
        let half = (super::WINDOW as usize) / 2;
        let full = Segment {
            source_port: OUR_PORT,
            destination_port: THEIR_PORT,
            sequence: base,
            acknowledgement: 5001,
            flags: FLAG_ACK | FLAG_PSH,
            window: super::WINDOW,
            payload_len: half,
        };
        let (answer, replies) = server.receive(&full, &alloc::vec![0x41_u8; half]);
        assert_eq!(answer, Ok(Event::Data(half)));
        assert_eq!(
            server.advertised_window(),
            super::WINDOW - half as u16,
            "the acknowledgement says what is left"
        );
        assert_eq!(
            replies[0].window,
            super::WINDOW - half as u16,
            "and the segment carrying it says the same"
        );

        // A reader takes everything, and the window reopens: a window that
        // only ever shrank would close the stream for good.
        let mut buffer = alloc::vec![0_u8; half];
        assert_eq!(server.take(&mut buffer), half);
        assert_eq!(server.advertised_window(), super::WINDOW, "reopened");
        let _ = &mut client;
    }

    /// Bytes past the advertised window are dropped rather than grown into.
    ///
    /// The peer chooses how much of this machine's memory to spend only up to
    /// the window; past it, the answer is "no", and the sender learns by
    /// retransmitting rather than by this stack's allocation growing.
    #[test]
    fn bytes_past_the_window_are_dropped() {
        let (_client, mut server) = handshake();
        let base = server.acknowledgement;

        // One segment fills the whole window.
        let window = super::WINDOW as usize;
        let filling = Segment {
            source_port: OUR_PORT,
            destination_port: THEIR_PORT,
            sequence: base,
            acknowledgement: 5001,
            flags: FLAG_ACK | FLAG_PSH,
            window: super::WINDOW,
            payload_len: window,
        };
        let (answer, _) = server.receive(&filling, &alloc::vec![0x42_u8; window]);
        assert_eq!(answer, Ok(Event::Data(window)));
        assert_eq!(server.advertised_window(), 0, "nothing left");
        assert_eq!(server.held(), window);

        // One more byte arrives, and there is nowhere for it.
        let extra = Segment {
            source_port: OUR_PORT,
            destination_port: THEIR_PORT,
            sequence: base + window as u32,
            acknowledgement: 5001,
            flags: FLAG_ACK | FLAG_PSH,
            window: super::WINDOW,
            payload_len: 1,
        };
        let (answer, _) = server.receive(&extra, b"x");
        assert_eq!(answer, Ok(Event::None), "past the window");
        assert_eq!(server.held(), window, "the buffer did not grow");
    }

    /// A run held ahead of a gap is bounded by the same window the inbox is.
    ///
    /// A peer that opens a hole and then sends past the window would otherwise
    /// hold two buffers' worth of this machine's memory: the inbox is full and
    /// the out-of-order cache is a second place the same bytes live.
    #[test]
    fn a_held_run_is_bounded_by_the_window() {
        let (_client, mut server) = handshake();
        let base = server.acknowledgement;

        // A run more than the whole window, entirely ahead of the gap.
        let too_much = super::WINDOW as usize + 1;
        let segment = Segment {
            source_port: OUR_PORT,
            destination_port: THEIR_PORT,
            sequence: base + 4,
            acknowledgement: 5001,
            flags: FLAG_ACK | FLAG_PSH,
            window: super::WINDOW,
            payload_len: too_much,
        };
        let (answer, _) = server.receive(&segment, &alloc::vec![0x43_u8; too_much]);
        assert_eq!(answer, Ok(Event::None));
        assert_eq!(
            server.out_of_order(),
            0,
            "a run larger than the window is not held"
        );
        assert_eq!(server.held(), 0);
    }

    /// A full out-of-order cache keeps what it has and drops the newest, so a
    /// peer that opens more holes than this stack holds cannot grow it.
    #[test]
    fn a_full_out_of_order_cache_drops_the_newest() {
        let (_client, mut server) = handshake();
        let base = server.acknowledgement;

        // Every held segment starts a hole of its own: one byte, two apart.
        for index in 0..super::MAX_OUT_OF_ORDER {
            let segment = Segment {
                source_port: OUR_PORT,
                destination_port: THEIR_PORT,
                sequence: base + 2 + (index as u32 * 2),
                acknowledgement: 5001,
                flags: FLAG_ACK | FLAG_PSH,
                window: super::WINDOW,
                payload_len: 1,
            };
            let (answer, _) = server.receive(&segment, b"x");
            assert_eq!(answer, Ok(Event::None));
        }
        assert_eq!(server.out_of_order(), super::MAX_OUT_OF_ORDER);

        let overflow = Segment {
            source_port: OUR_PORT,
            destination_port: THEIR_PORT,
            sequence: base + 2 + (super::MAX_OUT_OF_ORDER as u32 * 2),
            acknowledgement: 5001,
            flags: FLAG_ACK | FLAG_PSH,
            window: super::WINDOW,
            payload_len: 1,
        };
        let (_, _) = server.receive(&overflow, b"y");
        assert_eq!(
            server.out_of_order(),
            super::MAX_OUT_OF_ORDER,
            "the cache did not grow"
        );
        assert_eq!(server.inbox_len(), 0);
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
            super::WINDOW,
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
            super::WINDOW,
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
            super::WINDOW,
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
            super::WINDOW,
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
            super::WINDOW,
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

    /// A write larger than one segment becomes a run of segments, each no
    /// larger than the path's payload.
    ///
    /// This is the defect a stream this stack could not have carried: every
    /// write went out as **one** segment, so a write larger than a frame built
    /// a frame the card could not carry.  The assertion is the segment sizes
    /// and the byte count, because a stack that split the write but lost a
    /// byte would satisfy neither.
    #[test]
    fn a_large_write_becomes_a_run_of_segments() {
        let (mut client, _server) = established_on_the_loopback();
        let mut bytes = alloc::vec![0_u8; 5000];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }

        let (carried, outgoing) = client.send_data(&bytes);
        assert_eq!(carried, 5000, "the whole write was carried");
        assert!(outgoing.len() > 1, "and in more than one segment");
        assert_eq!(
            client.segment_limit(),
            super::MSS_DEFAULT,
            "the default path payload"
        );

        let mut total = 0;
        for segment in &outgoing {
            assert!(
                segment.payload.len() <= super::MSS_DEFAULT,
                "a segment of {} bytes is larger than the path carries",
                segment.payload.len()
            );
            assert!(!segment.payload.is_empty(), "no empty segments");
            total += segment.payload.len();
        }
        assert_eq!(total, 5000, "and every byte once");

        // Concatenated back together, the segments are the write.
        let rebuilt: alloc::vec::Vec<u8> = outgoing
            .iter()
            .flat_map(|segment| segment.payload.iter().copied())
            .collect();
        assert_eq!(rebuilt, bytes, "the bytes, in order");
    }

    /// A path that says it carries less makes the next write use less.
    #[test]
    fn a_smaller_path_shrinks_every_later_segment() {
        let (mut client, _server) = established_on_the_loopback();
        assert_eq!(client.segment_limit(), super::MSS_DEFAULT);

        client.limit_segment(512);
        assert_eq!(client.segment_limit(), 512, "the path's own payload");

        let (carried, outgoing) = client.send_data(&alloc::vec![0xAB_u8; 1500]);
        assert_eq!(carried, 1500);
        for segment in &outgoing {
            assert!(
                segment.payload.len() <= 512,
                "a segment of {} bytes after the path shrank",
                segment.payload.len()
            );
        }

        // A later report that claims more does not grow it back: a path that
        // was found small does not become large because a later measurement
        // says so, and growing would repeat the loss that taught it.
        client.limit_segment(9000);
        assert_eq!(client.segment_limit(), 512, "it only ever shrinks");

        // And a report below the floor is the floor, because a stream of
        // handfuls is a header per handful.
        client.limit_segment(1);
        assert_eq!(client.segment_limit(), super::MIN_MSS);
    }

    /// A write past what may be in flight is partly carried, and the count
    /// says how much.
    ///
    /// The count is what a caller writes again from, so a write that answered
    /// the whole length and queued part of it would lose the rest silently.
    /// The bound that stops it is the **smallest** of the three a sender
    /// respects, and on a fresh loopback stream that is the peer's advertised
    /// window: the congestion window starts at ten segments (14600 bytes) and
    /// the peer advertises [`super::WINDOW`] (8192), which is the tighter of
    /// the two.  Asserting the exact number is what says which bound worked;
    /// asserting only "less than the write" would pass with the queue's bound,
    /// the congestion window's, or the peer's, and this test has been all three
    /// as the stack grew.
    #[test]
    fn a_write_stops_where_the_window_is_full() {
        let (mut client, _server) = established_on_the_loopback();
        client.advance(0);
        assert_eq!(client.unacknowledged(), 0);
        assert_eq!(client.in_flight(), 0);
        let bound = client.send_budget();
        assert_eq!(
            bound,
            super::WINDOW as usize,
            "the peer's window is the tighter bound on a fresh stream"
        );
        assert_eq!(bound, client.peer_window());

        // Enough segments to fill the window and then some.
        let bytes = alloc::vec![0x5A_u8; bound + super::MSS_DEFAULT * 4];
        let (carried, outgoing) = client.send_data(&bytes);
        assert_eq!(carried, bound, "exactly the budget, not a segment past it");
        assert_eq!(client.in_flight(), bound);
        assert!(outgoing.len() > 1, "and more than one segment");
        assert!(carried < bytes.len(), "the rest is the caller's to write");

        // The next write carries nothing until an acknowledgement opens room.
        let (again, none) = client.send_data(b"more");
        assert_eq!(again, 0, "the window is full");
        assert!(none.is_empty());
    }

    /// A budget that is not a whole number of segments carries a short last
    /// segment rather than overshooting.
    ///
    /// The defect this pins: the send loop tested `carried < budget` and then
    /// appended a whole MSS, so a budget of 8192 against segments of 1460 put
    /// 8760 bytes in flight, 568 past what the window allows.  No test saw it
    /// while the congestion window was the only bound, because that one is ten
    /// whole segments; the peer's window is an arbitrary number and made it
    /// reachable on the first write.
    #[test]
    fn a_budget_that_is_not_whole_segments_carries_a_short_last_segment() {
        let (mut client, _server) = established_on_the_loopback();
        // A peer that states a window one byte past two segments.
        let narrow = 2 * super::MSS_DEFAULT + 1;
        let ack = super::Segment {
            source_port: THEIR_PORT,
            destination_port: OUR_PORT,
            sequence: client.expected_position(),
            acknowledgement: client.send_position(),
            flags: FLAG_ACK,
            window: narrow as u16,
            payload_len: 0,
        };
        let (_, replies) = client.receive(&ack, b"");
        assert!(replies.is_empty(), "a bare acknowledgement answers nothing");
        assert_eq!(client.peer_window(), narrow);

        let bytes = alloc::vec![0x33_u8; narrow * 2];
        let (carried, outgoing) = client.send_data(&bytes);
        assert_eq!(carried, narrow, "the budget, to the byte");
        assert_eq!(
            client.in_flight(),
            narrow,
            "in flight is what the peer said it would take"
        );
        assert_eq!(
            outgoing.last().map(|segment| segment.payload.len()),
            Some(1),
            "the last segment carries the odd byte and not a whole MSS"
        );
        assert!(
            outgoing
                .iter()
                .map(|segment| segment.payload.len())
                .sum::<usize>()
                == narrow,
            "the segments add up to the budget exactly"
        );
    }

    /// The peer's window is a bound on sending, separate from this side's.
    ///
    /// The field was parsed into every [`Segment`] and read by nothing: a
    /// sender compared the congestion window and the queue's size and treated
    /// the peer's statement as information it had already accounted for.  A
    /// peer that shrank its window to zero said "send nothing" and was sent to
    /// anyway.  This test is the one that would fail with the field ignored,
    /// because a zero window and a full congestion window are different facts
    /// that produce the same count only if one of them is not read.
    #[test]
    fn a_zero_peer_window_stops_the_sender() {
        let (mut client, _server) = established_on_the_loopback();
        let ack = super::Segment {
            source_port: THEIR_PORT,
            destination_port: OUR_PORT,
            sequence: client.expected_position(),
            acknowledgement: client.send_position(),
            flags: FLAG_ACK,
            window: 0,
            payload_len: 0,
        };
        let _ = client.receive(&ack, b"");
        assert_eq!(client.peer_window(), 0, "the peer said its buffer is full");
        assert!(
            client.congestion_window() > 0,
            "and the path said nothing, so the two bounds disagree"
        );

        let (carried, outgoing) = client.send_data(b"blocked");
        assert_eq!(carried, 0, "a zero window carries nothing");
        assert!(outgoing.is_empty());

        // The peer reopens, and the same write now goes.
        let reopen = super::Segment {
            source_port: THEIR_PORT,
            destination_port: OUR_PORT,
            sequence: client.expected_position(),
            acknowledgement: client.send_position(),
            flags: FLAG_ACK,
            window: super::WINDOW,
            payload_len: 0,
        };
        let _ = client.receive(&reopen, b"");
        let (carried, outgoing) = client.send_data(b"blocked");
        assert_eq!(carried, 7, "the reopen is what let it through");
        assert_eq!(outgoing.len(), 1);
    }

    /// A stream starts with ten segments of window, whatever the handshake
    /// A receive buffer a program set is the window its peer sees, and the
    /// room it enforces.
    ///
    /// The option is only real if both halves move together: a connection that
    /// advertised the smaller window and enforced the old room would accept
    /// more than it said it would, and one that enforced the smaller room and
    /// advertised the old one would drop bytes a peer was told to send.  The
    /// test asserts both numbers, which is what distinguishes an option that
    /// works from a field that is stored and read by one path.
    #[test]
    fn a_receive_buffer_option_moves_the_window_and_the_room() {
        let (mut client, _server) = established_on_the_loopback();
        assert_eq!(
            client.advertised_window(),
            super::WINDOW,
            "the default before anything is set"
        );

        let narrowed = 1000_usize;
        client
            .set_option(
                abi::network::SOL_SOCKET,
                abi::network::SO_RCVBUF,
                &narrowed.to_le_bytes(),
            )
            .expect("a receive buffer");
        assert_eq!(
            client.advertised_window(),
            narrowed as u16,
            "the peer sees it"
        );

        // The peer sends exactly the advertised number and it fits; one byte
        // more does not.  The second segment starts past the gap the first
        // filled, so it is refused by the window and not by the sequence.
        let base = client.expected_position();
        let filling = super::Segment {
            source_port: THEIR_PORT,
            destination_port: OUR_PORT,
            sequence: base,
            acknowledgement: client.send_position(),
            flags: FLAG_ACK | FLAG_PSH,
            window: super::WINDOW,
            payload_len: narrowed,
        };
        let (_, replies) = client.receive(&filling, &alloc::vec![0x41_u8; narrowed]);
        assert!(!replies.is_empty(), "the segment is acknowledged");
        assert_eq!(client.held(), narrowed, "all of it is held");
        assert_eq!(client.advertised_window(), 0, "and the window is closed");

        // A byte past the window, at the position the peer would send it.
        let extra = super::Segment {
            source_port: THEIR_PORT,
            destination_port: OUR_PORT,
            sequence: base + narrowed as u32,
            acknowledgement: client.send_position(),
            flags: FLAG_ACK | FLAG_PSH,
            window: super::WINDOW,
            payload_len: 1,
        };
        let _ = client.receive(&extra, b"x");
        assert_eq!(
            client.held(),
            narrowed,
            "the byte past the window was refused, and by the option's number"
        );
    }

    /// A send buffer a program set caps the congestion window.
    ///
    /// `SO_SNDBUF` is the ceiling this side may have in flight, and slow
    /// start's growth stops at it.  The test sets a buffer smaller than the
    /// window slow start had already reached: the ceiling has to apply to what
    /// is already open, not only to what a fresh connection would start with,
    /// because an acknowledgement that grew the window is history and the next
    /// write has to respect the number the program set after it.
    #[test]
    fn a_send_buffer_option_caps_the_congestion_window() {
        let (mut client, _server) = established_on_the_loopback();
        assert_eq!(client.congestion_window(), super::INITIAL_CWND);
        let ceiling = 3 * super::MSS_DEFAULT;
        assert!(
            ceiling < super::INITIAL_CWND,
            "the test needs a tighter cap"
        );

        client
            .set_option(
                abi::network::SOL_SOCKET,
                abi::network::SO_SNDBUF,
                &ceiling.to_le_bytes(),
            )
            .expect("a send buffer");
        assert_eq!(
            client.congestion_window(),
            ceiling,
            "the window already open is capped, not only a fresh one"
        );
        // And the budget follows it, which is what a write reads.
        assert_eq!(client.send_budget(), ceiling);

        // Reading it back answers the number that was set.
        let mut buffer = [0_u8; 8];
        let written = client
            .get_option(
                abi::network::SOL_SOCKET,
                abi::network::SO_SNDBUF,
                &mut buffer,
            )
            .expect("a send buffer");
        assert_eq!(written, core::mem::size_of::<usize>());
        assert_eq!(
            usize::from_le_bytes(buffer[..written].try_into().unwrap()),
            ceiling
        );
    }

    /// A stream's option calls refuse a number nothing in this stack serves.
    ///
    /// The refusal reaches through the connection, so a program's `SetSockOpt`
    /// on a stream is refused by the same `match` a datagram socket's is, and
    /// the stream's own state is unchanged by the attempt.
    #[test]
    fn a_stream_refuses_an_option_it_does_not_serve() {
        let (mut client, _server) = established_on_the_loopback();
        let before = client.options();
        assert_eq!(
            client.set_option(abi::network::SOL_SOCKET, 1, &[1]),
            Err(abi::Error::InvalidArgument)
        );
        assert_eq!(client.options(), before, "a refusal changes nothing");
        let mut buffer = [0_u8; 8];
        assert_eq!(
            client.get_option(abi::network::IPPROTO_TCP, 9, &mut buffer),
            Err(abi::Error::InvalidArgument)
        );
    }

    /// occupied, and its first acknowledgements double it.
    ///
    /// Slow start's rule is that an acknowledged byte adds a byte of window, so
    /// a round trip of acknowledgements doubles what may be in flight.  The
    /// initial number is [RFC 6928]'s ten segments exactly: the first version
    /// of this counted the handshake's SYN as a byte, which left the window at
    /// ten segments and one, a number no rule produces.
    ///
    /// [RFC 6928]: https://www.rfc-editor.org/rfc/rfc6928
    #[test]
    fn a_stream_starts_with_ten_segments_and_doubles_on_acknowledgement() {
        let (mut client, mut server) = established_on_the_loopback();
        assert_eq!(
            client.congestion_window(),
            super::INITIAL_CWND,
            "ten segments, and not ten segments plus the SYN"
        );
        assert_eq!(super::INITIAL_CWND, 10 * super::MSS_DEFAULT);

        // One segment's worth of acknowledgements, and the window grows by
        // exactly that much.
        let before = client.congestion_window();
        let (_, outgoing) = client.send_data(&alloc::vec![0x11_u8; super::MSS_DEFAULT]);
        let mut client_out = outgoing;
        let mut server_out = alloc::vec::Vec::new();
        drain(&mut client_out, &mut server_out, &mut client, &mut server);
        assert_eq!(
            client.congestion_window(),
            before + super::MSS_DEFAULT,
            "one acknowledged segment opens the window by one"
        );

        // And once ssthresh is reached the growth is one segment per round
        // trip rather than one per acknowledgement.  The threshold is pushed
        // down to the current window so the next acknowledgement takes the
        // avoidance branch.
        client.ssthresh = client.congestion_window();
        let before = client.congestion_window();
        let (_, outgoing) = client.send_data(&alloc::vec![0x22_u8; super::MSS_DEFAULT]);
        let mut client_out = outgoing;
        drain(&mut client_out, &mut server_out, &mut client, &mut server);
        let grown = client.congestion_window() - before;
        assert!(
            grown < super::MSS_DEFAULT,
            "congestion avoidance grew by {grown}, which is a full segment per              acknowledgement rather than per round trip"
        );
        assert!(grown > 0, "and it still grew");
    }

    /// A timeout collapses the window to one segment and lowers the threshold.
    #[test]
    fn a_timeout_collapses_the_congestion_window() {
        let (mut client, _server) = established_on_the_loopback();
        client.advance(0);
        let before = client.congestion_window();
        let (_, outgoing) = client.send_data(&alloc::vec![0x33_u8; 4 * super::MSS_DEFAULT]);
        assert!(outgoing.len() >= 4);

        // Nothing answers, and the timer fires.
        client.advance(super::RTO_INITIAL_MICROS);
        assert!(matches!(
            client.retransmit(),
            super::Retransmission::Again(_)
        ));

        assert_eq!(
            client.congestion_window(),
            client.segment_limit(),
            "one segment: the path just said it dropped something"
        );
        assert!(
            client.slow_start_threshold() <= before / 2,
            "and the threshold halved from {}",
            before
        );
        assert!(
            client.slow_start_threshold() >= 2 * client.segment_limit(),
            "but never below two segments"
        );
    }

    /// Three duplicate acknowledgements send the segment at the gap at once,
    /// without waiting for its timer.
    ///
    /// This is fast retransmit, and it is the half of congestion control a
    /// timer cannot do: the peer is saying it received something past a gap, so
    /// the sender knows which segment was lost before a second has passed.
    #[test]
    fn three_duplicate_acknowledgements_retransmit_at_once() {
        let (mut client, _server) = established_on_the_loopback();
        client.advance(0);
        let (_, outgoing) = client.send_data(&alloc::vec![0x44_u8; 3 * super::MSS_DEFAULT]);
        assert_eq!(outgoing.len(), 3);
        let first = outgoing[0].clone();
        let window_before = client.congestion_window();

        // The peer's position, which is what a duplicate acknowledgement
        // repeats: it has the first segment missing and the rest held.
        let position = client.expected_position();
        let duplicate = Segment {
            source_port: THEIR_PORT,
            destination_port: OUR_PORT,
            sequence: position,
            acknowledgement: first.sequence,
            flags: FLAG_ACK,
            window: super::WINDOW,
            payload_len: 0,
        };

        // The first two say nothing new.
        for expected in 1..super::DUPLICATE_ACKS {
            let (_event, replies) = client.receive(&duplicate, &[]);
            assert!(replies.is_empty(), "duplicate {expected} is not yet a loss");
        }
        // The third is.
        let (_event, replies) = client.receive(&duplicate, &[]);
        assert_eq!(replies.len(), 1, "the segment at the gap, sent again");
        assert_eq!(
            replies[0].sequence, first.sequence,
            "the same position it first carried"
        );
        assert_eq!(replies[0].payload, first.payload, "and the same bytes");
        assert!(
            client.congestion_window() < window_before,
            "fast recovery halved the window"
        );
    }

    /// A reordered pair is not a loss: two duplicate acknowledgements leave
    /// the window alone.
    ///
    /// This is the reason the threshold is three rather than one.  A wire that
    /// swaps two segments produces two duplicates and no loss, and a sender
    /// that halved its window for each would shrink for a path that carried
    /// everything.
    #[test]
    fn two_duplicate_acknowledgements_are_not_a_loss() {
        let (mut client, _server) = established_on_the_loopback();
        client.advance(0);
        let (_, outgoing) = client.send_data(&alloc::vec![0x55_u8; 2 * super::MSS_DEFAULT]);
        let first = outgoing[0].clone();
        let window_before = client.congestion_window();

        let duplicate = Segment {
            source_port: THEIR_PORT,
            destination_port: OUR_PORT,
            sequence: client.expected_position(),
            acknowledgement: first.sequence,
            flags: FLAG_ACK,
            window: super::WINDOW,
            payload_len: 0,
        };
        for _ in 0..2 {
            let (_event, replies) = client.receive(&duplicate, &[]);
            assert!(replies.is_empty());
        }
        assert_eq!(
            client.congestion_window(),
            window_before,
            "two duplicates are a reordering, not a loss"
        );
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
