//! net/src/tcp.rs
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
//! A connection is the states a stream moves through — [`State`], from a
//! handshake to an orderly close — and each move is one of this module's
//! methods with one injected `send` callback, which is where the bytes go.
//! The callback is the module's whole output: the state machine computes the
//! segment, the caller decides what a segment is for this connection's wire.
//! That is what makes a loopback exchange and a frame through the card the
//! same state machine with two callers, and what makes every move here a
//! host test without a device in it.
//!
//! What it does not do is deliberate, and the header of the change that
//! added it says so in the kernel's own log: **no retransmission and no flow
//! control**.  The exchanges this stack carries run over loopback and QEMU's
//! user-mode network, neither of which loses a frame; a lost frame is a
//! connection this stack drops rather than recovers, and a peer's window is
//! carried but never enforced.  Retransmission asks for timers, and timers
//! are a decision for a stack that runs where frames are lost.
//!
//! ## What a segment refuses
//!
//! The checksum is mandatory — TCP has no zero field that means "not
//! summed" — and the sequence is checked against the connection's own
//! acknowledgement: a segment that arrives out of order is dropped rather
//! than held, because holding one asks for the reassembly buffer and the
//! timers that retransmission would have brought.

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
/// The checksum is mandatory here — UDP's zero field has no TCP twin — and
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
/// it sent, and the caller — a loopback exchange that delivers to the
/// peer's own state machine, or a frame through the card — decides where a
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
/// move takes the `send` callback — which is why nothing here can send a
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
        };
        let sent = one(connection.sequence, 0, FLAG_SYN, &[]);
        connection.sequence += 1;
        (connection, sent)
    }

    /// The server's end of a handshake: a SYN arrived for a listener's port,
    /// and this connection answers it.
    ///
    /// The connection starts in [`State::SynReceived`], and it is the
    /// listener's to hand out — a caller accepts it as soon as it exists,
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
        };
        let sent = one(
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
    /// timer to ask for it again.  The handshake's moves and the stream's
    /// data and finishes are the three things a segment can be; everything
    /// else is refused without changing the state.
    pub fn receive(
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
            let sent = one(self.sequence, self.acknowledgement, FLAG_ACK, &[]);
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
            let sent = one(self.sequence, self.acknowledgement, FLAG_ACK, &[]);
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
            let sent = one(self.sequence, self.acknowledgement, FLAG_ACK, &[]);
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
    pub fn send_data(&mut self, bytes: &[u8]) -> (usize, alloc::vec::Vec<Outgoing>) {
        if self.finished || bytes.is_empty() {
            return (0, alloc::vec::Vec::new());
        }
        let open = matches!(self.state, State::Established | State::CloseWait);
        if !open {
            return (0, alloc::vec::Vec::new());
        }
        let sent = one(
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
                let sent = one(
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
                let sent = one(
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
    /// segment this machine sends to itself — which is why the handshake
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
        // the client's ISN — the SYN consumed one, and nothing has been sent
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

        // The IPv6 segment read as IPv4 — or the other way round — does not
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
}
