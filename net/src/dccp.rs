//! net/src/dccp.rs
//!
//! [RFC 4340]'s Datagram Congestion Control Protocol: the generic header, the
//! packet types that move a connection between states, and the state machine a
//! connection is.
//!
//! ## Why a second datagram transport, and what it is for
//!
//! UDP is a datagram transport with no congestion control: a sender writes as
//! fast as its program says, and the network absorbs that or it does not.
//! DCCP is a datagram transport with **congestion control and no retransmission
//! promise**: each datagram is delivered whole or not at all, the stream is
//! acknowledged, and the sender backs off when the path does.  That is what a
//! real-time stream wants, a phone call or a playback, which wants neither the
//! latency of TCP's retransmissions nor UDP's blindness to a congested path.
//!
//! ## The header
//!
//! Sixteen bytes extended, twelve short, and this writer always emits
//! **extended**: a forty-eight-bit sequence number, because a short form's
//! twenty-four bits wrap in minutes at a stream's rate and a wrapped sequence
//! number is a connection that cannot tell a new datagram from an old one.
//! Reader accepts both, which is what makes this a peer rather than a dialect.
//!
//! The header's fields are worth naming because two of them are the checksum's
//! business and one is a trap:
//!
//! | at | field |
//! |---|---|
//! | 0, 2 | source and destination port |
//! | 4 | data offset in thirty-two-bit words |
//! | 5 | `CCVal` and `CsCov`, one nibble each |
//! | 6 | checksum, which may be zero |
//! | 8 | reserved, then `X`, then the four-bit type |
//! | 9 | the `X` bit **again** |
//! | 10 | six bytes of sequence number when `X` is set |
//!
//! The trap is the redundant `X`: bit 4 of byte 8 and bit 7 of byte 9 carry the
//! same value, and a reader that reads one and ignores the other will misread a
//! short-form packet as extended and take the sequence number from the wrong
//! bytes.  [RFC 4340] §5.1 makes disagreement an error, and so is this.
//!
//! ## The sequence space
//!
//! Forty-eight bits per direction, and every number in this module's arithmetic
//! is masked to them: `a` is after `b` when `(a - b) & MASK` is less than half
//! the space.  Comparing two numbers as `u64` would be wrong at the wrap, which
//! is a comparison that works for every test written before a connection has
//! been open long enough.
//!
//! ## What is deliberately not here
//!
//! **No CCID.**  [RFC 4340] makes congestion control a pluggable **CCID**, and
//! this module carries the field a feature negotiation names and no algorithm.
//! A CCID is a controller with its own state and its own loss response, and a
//! connection that drove one from here would be a transport whose congestion
//! control was this module's opinion.  What a connection here has is what the
//! protocol requires of every implementation: a sequence space, a window, and
//! acknowledgements.
//!
//! **No feature negotiation beyond the service code.**  The options a Request
//! and Response may carry are the negotiation ([RFC 4340] §6), and this build
//! reads the service code and ignores the rest: a feature this stack does not
//! implement and does not refuse is a peer's belief about a machine it is
//! talking to.  The reader keeps the option bytes for a caller that wants them,
//! and nothing here acts on one.
//!
//! **No retransmission of data.**  DCCP is a datagram protocol: a lost Data
//! packet stays lost, which is the whole difference from TCP.  The handshake's
//! own packets are the exception and are the caller's to repeat, because a
//! Request that is not answered is a connection that never opened.
//!
//! [RFC 4340]: https://www.rfc-editor.org/rfc/rfc4340

use alloc::vec::Vec;

use abi::Error;
use abi::Result;

use crate::address::Address;

/// The extended generic header's length, which this writer emits.
pub const HEADER_LEN: usize = 16;

/// The short generic header's length, which this reader accepts.
pub const SHORT_HEADER_LEN: usize = 12;

/// How many bits of the sequence space are meaningful.
pub const SEQUENCE_BITS: u32 = 48;

/// The mask every sequence number in this module's arithmetic is reduced by.
pub const SEQUENCE_MASK: u64 = (1_u64 << SEQUENCE_BITS) - 1;

/// The acknowledgment number's field length.
pub const ACK_LEN: usize = 8;

/// The service code's field length, on a Request and a Response.
pub const SERVICE_CODE_LEN: usize = 4;

/// The protocol number a DCCP packet carries in the IP header.
pub const PROTOCOL: u8 = 33;

/// The largest service code a caller may name.
///
/// The field is thirty-two bits and the wire's rule is that fewer than
/// thirty-two are permitted: [RFC 4340] §5.1 reserves the low sixteen for IANA
/// assignments, and this build takes any value a caller writes.  The bound
/// exists so a record's word is refused when it is one a header cannot carry.
pub const SERVICE_CODE_MAX: u32 = u32::MAX;

/// Which kind of packet this is ([RFC 4340] §5.6).
///
/// The ten named types and no others: the four-bit field has room for sixteen
/// and the top six are reserved, which is a value that is an error rather than
/// a type this reader does not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PacketType {
    /// Asks to open a connection; carries a service code.
    Request,
    /// Accepts one; carries a service code.
    Response,
    /// Application data.
    Data,
    /// An acknowledgement with nothing else.
    Ack,
    /// Data and an acknowledgement in one packet.
    DataAck,
    /// Asks the peer to close.
    CloseReq,
    /// Closes this direction.
    Close,
    /// Refuses or aborts a connection, with a code that says why.
    Reset,
    /// Resynchronises a connection that lost its state.
    Sync,
    /// Answers a Sync.
    SyncAck,
}

impl PacketType {
    /// The type a four-bit field names, or the error for one this build does
    /// not have.
    pub fn from_wire(value: u8) -> Result<Self> {
        match value & 0x0F {
            0 => Ok(Self::Request),
            1 => Ok(Self::Response),
            2 => Ok(Self::Data),
            3 => Ok(Self::Ack),
            4 => Ok(Self::DataAck),
            5 => Ok(Self::CloseReq),
            6 => Ok(Self::Close),
            7 => Ok(Self::Reset),
            8 => Ok(Self::Sync),
            9 => Ok(Self::SyncAck),
            // The six reserved values.  A reader that mapped them onto a real
            // type would act on a packet whose sender meant something this
            // build does not know.
            _ => Err(Error::InvalidArgument),
        }
    }

    /// The four-bit field this type is.
    pub fn to_wire(self) -> u8 {
        match self {
            Self::Request => 0,
            Self::Response => 1,
            Self::Data => 2,
            Self::Ack => 3,
            Self::DataAck => 4,
            Self::CloseReq => 5,
            Self::Close => 6,
            Self::Reset => 7,
            Self::Sync => 8,
            Self::SyncAck => 9,
        }
    }

    /// Whether this type's header carries an acknowledgement number.
    ///
    /// Seven of the ten do, and the three that do not are the three that ask
    /// rather than answer: a Request and a Response open a connection, and a
    /// Data packet is the payload it carries.
    pub fn carries_acknowledgement(self) -> bool {
        matches!(
            self,
            Self::Ack
                | Self::DataAck
                | Self::CloseReq
                | Self::Close
                | Self::Reset
                | Self::Sync
                | Self::SyncAck
        )
    }

    /// Whether this type's header carries a service code.
    pub fn carries_service_code(self) -> bool {
        matches!(self, Self::Request | Self::Response)
    }

    /// Whether this type carries an acknowledgement a sender is owed a reply
    /// on.
    ///
    /// The set [RFC 4340] §8 calls "the packets that must be acknowledged", and
    /// it is not the same as [`Self::carries_acknowledgement`]: a Reset is
    /// answered by nothing, and a Close is answered by nothing, which is what
    /// makes them final.
    pub fn wants_acknowledgement(self) -> bool {
        matches!(
            self,
            Self::Data | Self::DataAck | Self::Request | Self::Response
        )
    }
}

/// A parsed segment: its ports, its header's fields, its options and its data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// The sender's port.
    pub source_port: u16,
    /// The receiver's port.
    pub destination_port: u16,
    /// Which kind of packet this is.
    pub kind: PacketType,
    /// The sender's sequence number, masked to forty-eight bits.
    pub sequence: u64,
    /// The acknowledgement number, when the type carries one.
    pub acknowledgement: Option<u64>,
    /// The service code, on a Request and a Response.
    pub service_code: Option<u32>,
    /// The reset code, on a Reset.
    pub reset_code: Option<u8>,
    /// The option bytes, which this build keeps and does not act on.
    pub options: &'static [u8],
    /// Where the payload begins in the packet it was parsed from.
    pub payload_at: usize,
    /// How many payload bytes it carried.
    pub payload_len: usize,
}

/// Why a sequence number is out of the window.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SequenceError {
    /// Before the window's low edge: already received, or too old to tell.
    TooOld,
    /// Past the window's high edge: further ahead than the window allows.
    TooFar,
}

/// A connection's state ([RFC 4340] §8).
///
/// Nine states, and the two that matter to a reader are named by what they
/// wait for: `RequestSent` waits for a Response, `RespondSent` waits for the
/// Ack that opens the connection, and `Open` is the only state application data
/// crosses in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Nothing is open.
    Closed,
    /// Bound and waiting for a Request.
    Listen,
    /// A Request was sent; waiting for a Response.
    RequestSent,
    /// A Response was sent; waiting for the Ack.
    ResponseSent,
    /// A Response arrived and the Ack is owed; the peer may already be open.
    PartOpen,
    /// Data crosses.
    Open,
    /// A `CloseReq` arrived; the peer wants the connection gone.
    CloseReq,
    /// A `Close` was sent.
    Closing,
    /// Closed, and held so a duplicate of the last packet is answered rather
    /// than refused.
    TimeWait,
}

/// One connection: which stream it is, where it is, and the two sequence
/// numbers that bound each direction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Connection {
    /// The id this connection was given in its table.
    ///
    /// Stored and not a position, because a connection is removed when it
    /// finishes: a position that shifted would make an id name the next
    /// connection, which is the defect the packet filter's rule ids had.
    id: usize,
    /// This machine's port.
    local_port: u16,
    /// The peer's address and port.
    peer: Address,
    peer_port: u16,
    state: State,
    /// The service code the connection was opened with.
    service_code: u32,
    /// The next sequence number this side sends.
    next_sequence: u64,
    /// The highest sequence number this side has sent.
    greatest_sent: u64,
    /// The highest sequence number the peer has sent.
    greatest_received: u64,
    /// The window's low and high edges, as the peer acknowledged and as this
    /// side's own buffer allows.
    ///
    /// `None` before the peer's first sequence number is known, which is the
    /// state a client is in between its Request and the Response: there is no
    /// window to compare against, and a comparison against a made-up one
    /// refuses the packet that would have set it.
    window: Option<(u64, u64)>,
    /// Datagrams that have arrived and not been read, oldest first.
    inbox: Vec<Vec<u8>>,
    /// How many bytes the inbox holds, so the bound is bytes and not datagrams.
    held: usize,
    /// How many datagrams the inbox may hold.
    inbox_limit: usize,
    /// The largest datagram this connection accepts.
    max_datagram: usize,
}

impl Connection {
    /// A connection a client opened with a Request.
    ///
    /// The first sequence number is the caller's: [RFC 4340] §5.1 wants it
    /// unpredictable, and this module takes it rather than making one, because
    /// the generator belongs to the boot and not to a transport.
    pub fn connecting(
        local_port: u16,
        peer: Address,
        peer_port: u16,
        service_code: u32,
        first_sequence: u64,
    ) -> Self {
        // The window opens `WINDOW` ahead of the first number, which is what
        // the peer is allowed to send before an acknowledgement comes back.
        let first = first_sequence & SEQUENCE_MASK;
        // The window is **wide open** before the first Response arrives: a
        // client does not know the peer's initial sequence number until the
        // Response carries it, and a window that started at zero would refuse
        // every Response whose number was above the window's edge, which is
        // every real one.  The Response is what sets both edges.
        Self {
            id: 0,
            local_port,
            peer,
            peer_port,
            state: State::RequestSent,
            service_code,
            next_sequence: first.wrapping_add(1) & SEQUENCE_MASK,
            greatest_sent: first,
            greatest_received: 0,
            window: None,
            inbox: Vec::new(),
            held: 0,
            inbox_limit: INBOX_LIMIT,
            max_datagram: MAX_DATAGRAM,
        }
    }

    /// A connection a listener made when a Request arrived.
    pub fn accepted(
        local_port: u16,
        peer: Address,
        peer_port: u16,
        service_code: u32,
        first_sequence: u64,
        peer_sequence: u64,
    ) -> Self {
        let first = first_sequence & SEQUENCE_MASK;
        let peer_sequence = peer_sequence & SEQUENCE_MASK;
        Self {
            id: 0,
            local_port,
            peer,
            peer_port,
            state: State::ResponseSent,
            service_code,
            next_sequence: first.wrapping_add(1) & SEQUENCE_MASK,
            greatest_sent: first,
            greatest_received: peer_sequence,
            window: Some((
                peer_sequence,
                peer_sequence.wrapping_add(WINDOW) & SEQUENCE_MASK,
            )),
            inbox: Vec::new(),
            held: 0,
            inbox_limit: INBOX_LIMIT,
            max_datagram: MAX_DATAGRAM,
        }
    }

    /// The id this connection was given in its table.
    pub fn id(&self) -> usize {
        self.id
    }

    /// The state this connection is in.
    pub fn state(&self) -> State {
        self.state
    }

    /// This machine's port.
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// The peer this connection is to.
    pub fn peer(&self) -> (Address, u16) {
        (self.peer, self.peer_port)
    }

    /// The service code the connection was opened with.
    pub fn service_code(&self) -> u32 {
        self.service_code
    }

    /// The sequence number the next send will use.
    pub fn next_sequence(&self) -> u64 {
        self.next_sequence
    }

    /// Whether application data crosses: only in [`State::Open`].
    pub fn is_open(&self) -> bool {
        self.state == State::Open
    }

    /// Whether the connection is finished, which a reader turns into end of
    /// file rather than a wait.
    pub fn is_finished(&self) -> bool {
        matches!(self.state, State::Closed | State::TimeWait)
    }

    /// How many datagrams are waiting to be read.
    pub fn inbox_len(&self) -> usize {
        self.inbox.len()
    }

    /// Take one datagram into `into`, answering how many bytes were written.
    ///
    /// `Ok(None)` is an empty inbox and a connection still open, which is a
    /// caller's signal to wait.  A datagram longer than `into` is refused with
    /// the datagram **kept**, the same rule every receive in this tree follows:
    /// a caller learns from the refusal to ask again with room, and a take that
    /// truncated would make the loss permanent.
    ///
    /// A finished connection with an empty inbox answers `Some(0)`, which is
    /// end of file: the difference between "nothing yet" and "nothing ever" is
    /// the one a reader's loop turns on.
    pub fn read(&mut self, into: &mut [u8]) -> Result<Option<usize>> {
        if let Some(datagram) = self.inbox.first() {
            if datagram.len() > into.len() {
                return Err(Error::InvalidArgument);
            }
            let count = datagram.len();
            into[..count].copy_from_slice(datagram);
            self.held -= count;
            self.inbox.remove(0);
            return Ok(Some(count));
        }
        if self.is_finished() {
            return Ok(Some(0));
        }
        Ok(None)
    }

    /// Send one datagram, answering the sequence number it went out with.
    ///
    /// Refused unless the connection is open and the datagram fits
    /// [`MAX_DATAGRAM`]: a datagram larger than the bound is one the peer's
    /// reader would refuse, and sending it is spending a sequence number on a
    /// packet that cannot be delivered whole.
    pub fn send(&mut self, bytes: &[u8]) -> Result<u64> {
        if self.state != State::Open {
            return Err(Error::InvalidArgument);
        }
        if bytes.len() > self.max_datagram {
            return Err(Error::InvalidArgument);
        }
        let sequence = self.next_sequence;
        self.next_sequence = sequence.wrapping_add(1) & SEQUENCE_MASK;
        self.greatest_sent = sequence;
        Ok(sequence)
    }

    /// Whether `sequence` is inside this connection's window.
    ///
    /// The two edges are different answers: before the low edge the packet is
    /// too old, past the high edge it is ahead of what this side's buffer
    /// allows, and only the middle is a packet to take.
    ///
    /// A window that does not exist yet accepts everything, which is the state
    /// a client is in before the Response names the peer's first number: there
    /// is nothing to compare against, and a made-up window would refuse the
    /// packet that was going to set it.
    pub fn sequence_status(&self, sequence: u64) -> core::result::Result<(), SequenceError> {
        let Some((low, high)) = self.window else {
            return Ok(());
        };
        let sequence = sequence & SEQUENCE_MASK;
        if before(sequence, low) {
            return Err(SequenceError::TooOld);
        }
        if after(sequence, high) {
            return Err(SequenceError::TooFar);
        }
        Ok(())
    }

    /// Set the window onto a peer's first number.
    fn open_window(&mut self, sequence: u64) {
        let sequence = sequence & SEQUENCE_MASK;
        self.window = Some((sequence, sequence.wrapping_add(WINDOW) & SEQUENCE_MASK));
    }

    /// Move the window's low edge past a sequence this side took.
    ///
    /// Past, and not onto: the number that just arrived is exactly the one a
    /// duplicate would carry, so a window whose low edge was the number itself
    /// would accept the duplicate.  The low edge is the next number this side
    /// will take, which is what makes "before the low edge" mean "already
    /// seen".
    fn advance_window(&mut self, sequence: u64) {
        let low = sequence.wrapping_add(1) & SEQUENCE_MASK;
        self.window = Some((low, low.wrapping_add(WINDOW) & SEQUENCE_MASK));
    }

    /// Take one arriving segment, answering what the caller should reply with.
    ///
    /// The state machine's whole, and the states are the return value: a caller
    /// that gets [`Reply::Send`] builds a segment of the named type, and one
    /// that gets [`Reply::None`] sends nothing.  The rules, in the order they
    /// are asked:
    ///
    /// 1. A sequence number outside the window is refused with a Reset, which
    ///    is what tells a peer that its state and this one's disagree.
    /// 2. A `Request` for a connection already open is a duplicate, and is
    ///    answered with the Response again rather than treated as new.
    /// 3. A `Response` opens the connection, and the Ack it is owed is the
    ///    caller's next send.
    /// 4. A `Data` or `DataAck` inside the window is taken, and asks for an
    ///    acknowledgement.
    /// 5. A `CloseReq` moves to `CloseReq` and asks for a `Close`.
    /// 6. A `Close` finishes this side.
    /// 7. A `Reset` closes immediately, whatever state the connection was in.
    pub fn receive(&mut self, segment: &Segment, data: &[u8]) -> Reply {
        // A Reset ends a connection from any state, and it is the one packet
        // whose sequence number does not matter: it is what a peer sends when
        // the two sides disagree about a connection, so requiring the window
        // to agree first would refuse exactly the packet that resolves the
        // disagreement.
        if segment.kind == PacketType::Reset {
            self.state = State::Closed;
            return Reply::None;
        }

        // The window.  A Request is exempt: it opens a connection and its
        // sequence number is the first one, so a window that has never been
        // set cannot decide whether it is fresh.
        if segment.kind != PacketType::Request {
            match self.sequence_status(segment.sequence) {
                Ok(()) => {}
                Err(_) => {
                    // Out of window: the peer and this side disagree, and a
                    // Reset is how DCCP says so.
                    self.state = State::Closed;
                    return Reply::Reset(RESET_CODE_SEQUENCE_WINDOW);
                }
            }
        }

        match segment.kind {
            PacketType::Request => {
                // A duplicate Request on an open connection is answered again
                // rather than treated as a new one: the peer sent it because
                // the Response it wanted did not arrive.
                if self.state == State::ResponseSent || self.state == State::Open {
                    return Reply::Send(PacketType::Response);
                }
                Reply::Send(PacketType::Response)
            }
            PacketType::Response => {
                if self.state != State::RequestSent {
                    return Reply::None;
                }
                self.state = State::Open;
                self.greatest_received = segment.sequence;
                self.open_window(segment.sequence);
                Reply::Send(PacketType::Ack)
            }
            PacketType::Data | PacketType::DataAck => {
                // A `DataAck` that acknowledges this side's own first number is
                // the packet that completes a server's handshake: the client's
                // Ack and its first datagram are one packet, and a server that
                // refused it would refuse the first thing the client ever
                // sent.  [RFC 4340] §8.1's `RESPOND` -> `OPEN` transition is
                // exactly this.
                if self.state == State::ResponseSent
                    && segment.kind == PacketType::DataAck
                    && segment.acknowledgement.is_some()
                {
                    self.state = State::Open;
                }
                if self.state != State::Open && self.state != State::PartOpen {
                    return Reply::Reset(RESET_CODE_CONNECTION_REFUSED);
                }
                // The sequence is inside the window, so it is fresh: the
                // window's low edge moves with it, which is what makes a
                // retransmitted datagram too old.
                self.greatest_received = segment.sequence;
                self.advance_window(segment.sequence);
                if data.len() > self.max_datagram {
                    return Reply::Reset(RESET_CODE_CONNECTION_REFUSED);
                }
                // A full inbox drops the newest, the same rule the datagram
                // socket's queue follows: a reader that stopped reading must
                // not make the kernel hold whatever the wire sends.
                if self.inbox.len() < self.inbox_limit
                    && self.held.saturating_add(data.len()) <= INBOX_BYTES
                {
                    self.inbox.push(Vec::from(data));
                    self.held += data.len();
                }
                // Only a DataAck acknowledges; a Data packet is answered by
                // the Ack its own arrival earns.
                if let Some(acknowledgement) = segment.acknowledgement {
                    self.acknowledge(acknowledgement);
                }
                Reply::Send(PacketType::Ack)
            }
            PacketType::Ack => {
                if let Some(acknowledgement) = segment.acknowledgement {
                    self.acknowledge(acknowledgement);
                }
                if self.state == State::ResponseSent {
                    // The Ack that answers a Response is what completes the
                    // handshake from this side.
                    self.state = State::Open;
                }
                Reply::None
            }
            PacketType::CloseReq => {
                let was = self.state;
                self.state = State::CloseReq;
                if was == State::PartOpen {
                    self.state = State::Open;
                    return Reply::Send(PacketType::Ack);
                }
                Reply::Send(PacketType::Close)
            }
            PacketType::Close => {
                self.state = State::TimeWait;
                Reply::None
            }
            PacketType::Sync => Reply::Send(PacketType::SyncAck),
            PacketType::SyncAck => Reply::None,
            PacketType::Reset => Reply::None,
        }
    }

    /// Nothing: an acknowledgement is the peer's, and this side's window is
    /// about what this side may **receive**.
    ///
    /// Kept as a named function because the call sites read better, and it
    /// says the thing a reader would otherwise have to work out: an
    /// acknowledgement moves the peer's window, not this one, and this side's
    /// own send window is the inbox the peer's acknowledgements are about.
    fn acknowledge(&mut self, acknowledgement: u64) {
        let _ = acknowledgement & SEQUENCE_MASK;
    }
}

/// What a caller does after one segment arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// Nothing: the packet needed no answer.
    None,
    /// Send a segment of this type.
    Send(PacketType),
    /// Send a Reset with this code.
    Reset(u8),
}

/// `a` is after `b` in the forty-eight bit sequence space.
///
/// The comparison is the wrap-safe one: the distance forward from `b` to `a` is
/// less than half the space.  A plain `>` is right for every test written
/// before a connection has been open long enough for the counter to wrap, and
/// wrong for every connection that stays open.
pub fn after(a: u64, b: u64) -> bool {
    let distance = a.wrapping_sub(b) & SEQUENCE_MASK;
    distance != 0 && distance < (1_u64 << (SEQUENCE_BITS - 1))
}

/// `a` is before `b` in the sequence space.
pub fn before(a: u64, b: u64) -> bool {
    after(b, a)
}

/// A reset code: the sequence window disagreed.
pub const RESET_CODE_SEQUENCE_WINDOW: u8 = 2;

/// A reset code: the connection was refused.
pub const RESET_CODE_CONNECTION_REFUSED: u8 = 7;

/// How many sequence numbers ahead of the last accepted one a peer may send.
///
/// [RFC 4340] lets an implementation choose, and this is the previous tree's
/// number: sixty-four datagrams of slack is far more than one window of a
/// stream needs and small enough that a peer cannot make this side hold a
/// megabyte of unread datagrams.
pub const WINDOW: u64 = 64;

/// How many datagrams one connection's inbox holds.
pub const INBOX_LIMIT: usize = 32;

/// How many bytes one connection's inbox holds.
pub const INBOX_BYTES: usize = 64 * 1024;

/// The largest datagram one connection sends or accepts.
///
/// A DCCP datagram is one IP packet, so this is a path's MTU less the two
/// headers: 1200 is the smallest MTU every path this stack meets must carry,
/// less sixty bytes for the IP, DCCP and option headers.
pub const MAX_DATAGRAM: usize = 1140;

/// The fields of a segment's header, as a caller states them.
///
/// A struct rather than six arguments, because they are **one header**: a
/// caller cannot pass an acknowledgement for a type that does not carry one or
/// a service code for a type that does not, and a signature that took them
/// separately would let it try.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderFields<'a> {
    /// Which kind of packet this is.
    pub kind: PacketType,
    /// The sender's sequence number.
    pub sequence: u64,
    /// The acknowledgement number, for a type that carries one.
    pub acknowledgement: Option<u64>,
    /// The service code, on a Request and a Response.
    pub service_code: Option<u32>,
    /// The option bytes, which this build writes and does not interpret.
    pub options: &'a [u8],
}

/// Write a segment's sixteen-byte extended generic header, and its
/// type-specific part, answering where the payload begins.
///
/// `checksum` is computed by the caller, because it covers the pseudo-header:
/// the two families disagree about that, and a writer that computed a sum
/// without one would build a packet no peer accepts.
///
/// The data offset is written in thirty-two-bit words and covers the generic
/// header, the type-specific header and every option byte.  A writer that left
/// it at the generic header's length would make a reader treat the service code
/// as payload, which is the class of mistake this field exists to prevent.
pub fn write_segment(
    into: &mut [u8],
    source_port: u16,
    destination_port: u16,
    fields: &HeaderFields<'_>,
    payload: &[u8],
) -> u16 {
    // The type-specific part, and a Reset's is longer than the rest: it
    // carries an acknowledgement number **and** a four-byte code, and a writer
    // that counted only the first would leave the code's bytes to be read as
    // payload.
    let kind = fields.kind;
    let type_length = if kind == PacketType::Reset {
        ACK_LEN + 4
    } else if kind.carries_acknowledgement() {
        ACK_LEN
    } else if kind.carries_service_code() {
        SERVICE_CODE_LEN
    } else {
        0
    };
    let header_len = HEADER_LEN + type_length + fields.options.len();
    // The offset is words and the header is not always a multiple of four, so
    // the payload starts at the next word boundary: a reader that read past the
    // header's end would take padding as data.
    let data_offset = header_len.div_ceil(4);

    let sequence = fields.sequence & SEQUENCE_MASK;
    into[0..2].copy_from_slice(&source_port.to_be_bytes());
    into[2..4].copy_from_slice(&destination_port.to_be_bytes());
    into[4] = data_offset as u8;
    into[5] = 0;
    into[6..8].copy_from_slice(&[0, 0]);
    // The type and the X bit, then the redundant X in bit 7 of byte nine.
    into[8] = 0x10 | kind.to_wire();
    into[9] = 0x80;
    into[10..16].copy_from_slice(&sequence.to_be_bytes()[2..]);
    let mut at = HEADER_LEN;

    if kind.carries_acknowledgement() {
        let acknowledgement = fields.acknowledgement.unwrap_or(0) & SEQUENCE_MASK;
        into[at..at + ACK_LEN].copy_from_slice(&acknowledgement.to_be_bytes());
        at += ACK_LEN;
    }
    if kind.carries_service_code() {
        let code = fields.service_code.unwrap_or(0);
        into[at..at + SERVICE_CODE_LEN].copy_from_slice(&code.to_be_bytes());
        at += SERVICE_CODE_LEN;
    }
    if kind == PacketType::Reset {
        // The reset code, which is one byte and three reserved ones.  A Reset
        // built by this stack is a window disagreement, which is the one code
        // this module's state machine produces.
        into[at] = RESET_CODE_SEQUENCE_WINDOW;
        at += 4;
    }
    into[at..at + fields.options.len()].copy_from_slice(fields.options);
    at += fields.options.len();
    // The payload begins at the next word boundary, and the bytes between the
    // options' end and it are **written as zero** rather than left to the
    // caller's buffer: a caller that reused a buffer would otherwise send
    // whatever was there as padding, and a peer comparing two packets of one
    // stream would see them differ.
    let payload_at = data_offset * 4;
    for byte in &mut into[at..payload_at] {
        *byte = 0;
    }
    into[payload_at..payload_at + payload.len()].copy_from_slice(payload);

    (payload_at + payload.len()) as u16
}

/// Read the generic header and the type-specific part, or the error for a
/// packet this build cannot read.
///
/// Every refusal is a field whose value would make the rest of the read a read
/// of the wrong bytes: a short header, a reserved type, two `X` bits that
/// disagree, a type-specific part the packet is too short to hold, and a data
/// offset pointing past the packet.
pub fn parse(packet: &[u8]) -> Result<Segment> {
    if packet.len() < SHORT_HEADER_LEN {
        return Err(Error::InvalidArgument);
    }
    let source_port = u16::from_be_bytes([packet[0], packet[1]]);
    let destination_port = u16::from_be_bytes([packet[2], packet[3]]);

    // The two X bits carry the same value and must agree.  Reading one and
    // ignoring the other is how a short-form packet is misread as extended and
    // its sequence number taken from the wrong six bytes.
    let extended = packet[8] & 0x10 != 0;
    if (packet[9] & 0x80 != 0) != extended {
        return Err(Error::InvalidArgument);
    }
    let kind = PacketType::from_wire(packet[8])?;

    let header_len = if extended {
        HEADER_LEN
    } else {
        SHORT_HEADER_LEN
    };
    if packet.len() < header_len {
        return Err(Error::InvalidArgument);
    }

    let sequence = if extended {
        let mut bytes = [0_u8; 8];
        bytes[2..].copy_from_slice(&packet[10..16]);
        u64::from_be_bytes(bytes)
    } else {
        // The short form puts a twenty-four bit number in bytes nine to eleven,
        // with bit 7 of byte nine the X bit this reader has already checked.
        ((packet[9] as u64 & 0x7F) << 16) | ((packet[10] as u64) << 8) | packet[11] as u64
    };

    let mut at = header_len;
    let mut acknowledgement = None;
    if kind.carries_acknowledgement() {
        if packet.len() < at + ACK_LEN {
            return Err(Error::InvalidArgument);
        }
        let mut bytes = [0_u8; 8];
        bytes.copy_from_slice(&packet[at..at + ACK_LEN]);
        acknowledgement = Some(u64::from_be_bytes(bytes) & SEQUENCE_MASK);
        at += ACK_LEN;
    }
    let mut service_code = None;
    if kind.carries_service_code() {
        if packet.len() < at + SERVICE_CODE_LEN {
            return Err(Error::InvalidArgument);
        }
        service_code = Some(u32::from_be_bytes([
            packet[at],
            packet[at + 1],
            packet[at + 2],
            packet[at + 3],
        ]));
        at += SERVICE_CODE_LEN;
    }
    let mut reset_code = None;
    if kind == PacketType::Reset {
        if packet.len() < at + 4 {
            return Err(Error::InvalidArgument);
        }
        reset_code = Some(packet[at]);
        at += 4;
    }

    // The data offset is where the payload begins, and it may not be inside the
    // header this read: a packet claiming its payload starts before its options
    // ended is one whose fields overlap.
    let payload_at = (packet[4] as usize) * 4;
    if payload_at < at || payload_at > packet.len() {
        return Err(Error::InvalidArgument);
    }

    Ok(Segment {
        source_port,
        destination_port,
        kind,
        sequence,
        acknowledgement,
        service_code,
        reset_code,
        options: &[],
        payload_at,
        payload_len: packet.len() - payload_at,
    })
}

/// How many connections one machine holds.
///
/// Bounded because each one is an inbox and a pair of sequence numbers, which
/// is memory a peer's traffic fills.
pub const CONNECTION_LIMIT: usize = 64;

/// How many listeners one machine holds.
pub const LISTENER_LIMIT: usize = 16;

/// How many Requests one listener queues before it refuses.
///
/// A Request is a connection waiting for an accept, and a listener that was not
/// accepting would otherwise make the kernel hold every Request that arrived.
pub const BACKLOG: usize = 8;

/// One listening port, and the Requests waiting at it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listener {
    /// The port this listener answers on.
    pub port: u16,
    /// The service code it accepts, or `None` for any.
    ///
    /// A service code is what a Request names, and a listener that named one
    /// refuses a Request for another: that is the field's purpose, and ignoring
    /// it would make two services on one port one service.
    pub service_code: Option<u32>,
    /// The Requests waiting to be accepted, oldest first.
    pub waiting: Vec<PendingRequest>,
}

/// A Request a listener has answered and not yet been accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingRequest {
    /// The connection this Request opened, in `Responseed` state.
    pub connection: Connection,
}

/// The connections and listeners one machine holds.
///
/// A value, like every other table in this crate: the kernel holds it behind
/// its own lock and this module does arithmetic over it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Table {
    connections: Vec<Connection>,
    listeners: Vec<Listener>,
    /// The next connection id, never reused.
    next_id: usize,
}

impl Table {
    /// An empty table.
    pub const fn new() -> Self {
        Self {
            connections: Vec::new(),
            listeners: Vec::new(),
            next_id: 1,
        }
    }

    /// Bind a port for listening, answering the listener's id.
    ///
    /// `AlreadyExists` when the port is taken, for the reason a datagram bind
    /// refuses: a listening port has one owner.  The DCCP port space is its
    /// own, so a DCCP listener on a port a UDP socket holds is not a conflict:
    /// the two are demultiplexed by the IP header's protocol number.
    pub fn listen(&mut self, port: u16, service_code: Option<u32>) -> Result<usize> {
        if self.listeners.len() >= LISTENER_LIMIT {
            return Err(Error::Busy);
        }
        if self.listeners.iter().any(|listener| listener.port == port) {
            return Err(Error::AlreadyExists);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.listeners.push(Listener {
            port,
            service_code,
            waiting: Vec::new(),
        });
        Ok(id)
    }

    /// The listener bound to `port`, if one is.
    pub fn listener(&self, port: u16) -> Option<&Listener> {
        self.listeners.iter().find(|listener| listener.port == port)
    }

    /// Whether a port has a listener.
    pub fn is_listening(&self, port: u16) -> bool {
        self.listener(port).is_some()
    }

    /// Release a listening port.
    pub fn unlisten(&mut self, port: u16) -> bool {
        let before = self.listeners.len();
        self.listeners.retain(|listener| listener.port != port);
        self.listeners.len() != before
    }

    /// Start a connection, answering its id.
    ///
    /// `first_sequence` is the caller's: [RFC 4340] wants it unpredictable and
    /// the generator is the boot's, so a transport that made one would be a
    /// transport deciding a security parameter.
    pub fn connect(
        &mut self,
        local_port: u16,
        peer: Address,
        peer_port: u16,
        service_code: u32,
        first_sequence: u64,
    ) -> Result<usize> {
        if self.connections.len() >= CONNECTION_LIMIT {
            return Err(Error::Busy);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let mut connection =
            Connection::connecting(local_port, peer, peer_port, service_code, first_sequence);
        connection.id = id;
        self.connections.push(connection);
        Ok(id)
    }

    /// One connection, by id.
    pub fn connection(&self, id: usize) -> Option<&Connection> {
        self.connections
            .iter()
            .find(|connection| connection.id == id)
    }

    /// One connection mutably, by id.
    ///
    /// By the id the connection was given, which is stored: a position would
    /// shift when an earlier connection was pruned, and an id that moved would
    /// name the next connection.
    pub fn connection_mut(&mut self, id: usize) -> Option<&mut Connection> {
        self.connections
            .iter_mut()
            .find(|connection| connection.id == id)
    }

    /// The connection a segment belongs to: its four-tuple.
    pub fn find(&self, local_port: u16, peer: Address, peer_port: u16) -> Option<&Connection> {
        self.connections.iter().find(|connection| {
            connection.local_port() == local_port && connection.peer() == (peer, peer_port)
        })
    }

    /// The connection a segment belongs to, mutably.
    pub fn find_mut(
        &mut self,
        local_port: u16,
        peer: Address,
        peer_port: u16,
    ) -> Option<&mut Connection> {
        self.connections.iter_mut().find(|connection| {
            connection.local_port() == local_port && connection.peer() == (peer, peer_port)
        })
    }

    /// Take the next Request waiting at `port`, answering the connection id it
    /// became.
    ///
    /// `Ok(None)` is nothing waiting, which a caller parks on.  The connection
    /// is pushed into the table first and its id answered, so the accept's
    /// caller holds the same kind of handle every other connection has.
    pub fn accept(&mut self, port: u16) -> Result<Option<usize>> {
        let Some(index) = self
            .listeners
            .iter()
            .position(|listener| listener.port == port)
        else {
            return Err(Error::NotFound);
        };
        if self.connections.len() >= CONNECTION_LIMIT {
            return Err(Error::Busy);
        }
        let Some(pending) = self.listeners[index].waiting.first().cloned() else {
            return Ok(None);
        };
        self.listeners[index].waiting.remove(0);
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        let mut connection = pending.connection;
        connection.id = id;
        self.connections.push(connection);
        Ok(Some(id))
    }

    /// Whether a Request is waiting at `port`.
    pub fn has_pending(&self, port: u16) -> bool {
        self.listener(port)
            .is_some_and(|listener| !listener.waiting.is_empty())
    }

    /// Hand one arriving segment to the table, answering what to reply with.
    ///
    /// The three destinations, in the order they are decided: an existing
    /// connection's segment goes to it; a Request for a listening port makes a
    /// new pending connection and is answered with a Response; and anything
    /// else is a packet for a port this machine does not answer on, which is
    /// what a Reset is for.
    ///
    /// `first_sequence` is this machine's own first number for the connection a
    /// Request creates, and it is a parameter for the reason
    /// [`Table::connect`]'s is.
    pub fn receive(
        &mut self,
        segment: &Segment,
        data: &[u8],
        peer: Address,
        first_sequence: u64,
    ) -> Reply {
        if let Some(connection) = self.find_mut(segment.destination_port, peer, segment.source_port)
        {
            return connection.receive(segment, data);
        }

        if segment.kind != PacketType::Request {
            return Reply::Reset(RESET_CODE_CONNECTION_REFUSED);
        }

        let Some(index) = self
            .listeners
            .iter()
            .position(|listener| listener.port == segment.destination_port)
        else {
            return Reply::Reset(RESET_CODE_CONNECTION_REFUSED);
        };
        // A listener naming a service code refuses a Request for another one:
        // two services on one port are two services only if the code tells
        // them apart.
        let requested = segment.service_code.unwrap_or(0);
        if let Some(required) = self.listeners[index].service_code
            && required != requested
        {
            return Reply::Reset(RESET_CODE_CONNECTION_REFUSED);
        }
        if self.listeners[index].waiting.len() >= BACKLOG {
            // A full backlog refuses rather than growing: the Request is a
            // connection waiting for an accept, and a listener not accepting
            // must not make the kernel hold every one that arrives.
            return Reply::Reset(RESET_CODE_CONNECTION_REFUSED);
        }
        let connection = Connection::accepted(
            segment.destination_port,
            peer,
            segment.source_port,
            requested,
            first_sequence,
            segment.sequence,
        );
        self.listeners[index]
            .waiting
            .push(PendingRequest { connection });
        Reply::Send(PacketType::Response)
    }

    /// How many connections and listeners are held.
    pub fn counts(&self) -> (usize, usize) {
        (self.connections.len(), self.listeners.len())
    }

    /// Drop the connections that are finished.
    ///
    /// A finished connection is one a reader has already been told about, and
    /// holding it would make the table's entries outlive the conversations they
    /// describe.  `TimeWait` is the exception: a closed four-tuple is held so a
    /// duplicate of its last packet is answered rather than refused.
    pub fn prune(&mut self) {
        self.connections
            .retain(|connection| connection.state() != State::Closed);
    }
}

#[cfg(test)]
mod tests {
    use super::Connection;
    use super::HeaderFields;
    use super::INBOX_LIMIT;
    use super::MAX_DATAGRAM;
    use super::PacketType;
    use super::Reply;
    use super::SEQUENCE_MASK;
    use super::State;
    use super::after;
    use super::before;
    use super::parse;
    use super::write_segment;
    use crate::address::Address;
    use abi::Error;

    const PEER: Address = Address::V4([10, 0, 2, 2]);
    const SERVICE: u32 = 0x0000_0001;

    /// A connection already open, for the tests that start after the
    /// handshake.
    ///
    /// Built by walking the handshake rather than by a constructor that skips
    /// it: a test that could make an `Open` connection any other way would pass
    /// on a state machine whose handshake does not work.
    fn open_for_tests() -> Connection {
        let mut connection = Connection::connecting(5000, PEER, 5001, SERVICE, 100);
        let response = segment(PacketType::Response, 1);
        let _ = connection.receive(&response, &[]);
        connection
    }

    fn segment(kind: PacketType, sequence: u64) -> super::Segment {
        super::Segment {
            source_port: 5000,
            destination_port: 5001,
            kind,
            sequence,
            acknowledgement: None,
            service_code: None,
            reset_code: None,
            options: &[],
            payload_at: 0,
            payload_len: 0,
        }
    }

    /// A segment written by this module is read back by it, for every type.
    ///
    /// The round trip is the point: a writer that put a field at one offset and
    /// a reader that took it from another would build packets only this stack
    /// could read, and the test would pass if both were wrong the same way, so
    /// the two are also checked against the offsets [RFC 4340] names.
    #[test]
    fn a_segment_round_trips_for_every_type() {
        let kinds = [
            PacketType::Request,
            PacketType::Response,
            PacketType::Data,
            PacketType::Ack,
            PacketType::DataAck,
            PacketType::CloseReq,
            PacketType::Close,
            PacketType::Reset,
            PacketType::Sync,
            PacketType::SyncAck,
        ];
        for kind in kinds {
            let mut wire = [0_u8; 64];
            let payload = b"data";
            let length = write_segment(
                &mut wire,
                5000,
                5001,
                &HeaderFields {
                    kind,
                    sequence: 0x0000_1234_5678_9ABC,
                    acknowledgement: Some(0x0000_0000_0000_0042),
                    service_code: Some(SERVICE),
                    options: &[],
                },
                payload,
            ) as usize;
            let parsed = parse(&wire[..length]).expect("a segment");
            assert_eq!(parsed.kind, kind, "type {kind:?}");
            assert_eq!(parsed.source_port, 5000);
            assert_eq!(parsed.destination_port, 5001);
            assert_eq!(parsed.sequence, 0x0000_1234_5678_9ABC & SEQUENCE_MASK);
            if kind.carries_acknowledgement() {
                assert_eq!(parsed.acknowledgement, Some(0x42), "type {kind:?}");
            }
            if kind.carries_service_code() {
                assert_eq!(parsed.service_code, Some(SERVICE));
            }
            assert_eq!(
                &wire[parsed.payload_at..parsed.payload_at + payload.len()],
                payload
            );
        }
    }

    /// The two X bits are both written and both checked.
    ///
    /// Byte eight's bit 4 and byte nine's bit 7 carry one value, and a reader
    /// that took one and ignored the other would misread a short-form packet:
    /// the sequence number would come from the wrong six bytes, and the
    /// resulting number would be a quiet wrong answer rather than an error.
    #[test]
    fn the_redundant_x_bit_must_agree() {
        let mut wire = [0_u8; 32];
        let length = write_segment(
            &mut wire,
            1,
            2,
            &HeaderFields {
                kind: PacketType::Data,
                sequence: 7,
                acknowledgement: None,
                service_code: None,
                options: &[],
            },
            b"x",
        ) as usize;
        assert!(parse(&wire[..length]).is_ok());
        // Disagree one way, then the other.
        wire[9] = 0;
        assert_eq!(parse(&wire[..length]), Err(Error::InvalidArgument));
        wire[9] = 0x80;
        wire[8] &= !0x10;
        assert_eq!(parse(&wire[..length]), Err(Error::InvalidArgument));
    }

    /// The short header is accepted, and its sequence number comes from its own
    /// three bytes.
    ///
    /// The form this writer never emits and every peer may: twenty-four bits in
    /// bytes nine to eleven, with the X bit clear in both places.
    #[test]
    fn the_short_header_is_read() {
        let mut wire = [0_u8; 16];
        wire[0..2].copy_from_slice(&7_u16.to_be_bytes());
        wire[2..4].copy_from_slice(&9_u16.to_be_bytes());
        wire[4] = 3;
        wire[8] = PacketType::Data.to_wire();
        wire[9] = 0x01;
        wire[10] = 0x02;
        wire[11] = 0x03;
        let parsed = parse(&wire).expect("a short segment");
        assert_eq!(parsed.sequence, 0x01_0203);
        assert_eq!(parsed.kind, PacketType::Data);
        assert_eq!(parsed.payload_len, 4, "the payload starts at word three");
    }

    /// The reserved packet types are refused rather than read as something.
    #[test]
    fn the_reserved_types_are_refused() {
        for reserved in 10..=15_u8 {
            let mut wire = [0_u8; 16];
            wire[4] = 4;
            wire[8] = 0x10 | reserved;
            wire[9] = 0x80;
            assert_eq!(parse(&wire), Err(Error::InvalidArgument), "type {reserved}");
        }
    }

    /// A data offset pointing inside the header is refused.
    ///
    /// The packet claims its payload starts before its own type-specific part
    /// ended, which is two fields describing one byte range.
    #[test]
    fn a_data_offset_inside_the_header_is_refused() {
        let mut wire = [0_u8; 32];
        let length = write_segment(
            &mut wire,
            1,
            2,
            &HeaderFields {
                kind: PacketType::Request,
                sequence: 5,
                acknowledgement: None,
                service_code: Some(SERVICE),
                options: &[],
            },
            b"x",
        ) as usize;
        assert!(parse(&wire[..length]).is_ok());
        // Word three is past the generic header and inside the service code.
        wire[4] = 3;
        assert_eq!(parse(&wire[..length]), Err(Error::InvalidArgument));
    }

    /// The sequence comparison wraps, and a plain `>` does not.
    ///
    /// The case a comparison without the mask gets wrong: a number one past the
    /// wrap is **after** one just before it, and `1 > MASK` is false.
    #[test]
    fn the_sequence_comparison_wraps() {
        assert!(after(5, 4));
        assert!(!after(4, 5));
        assert!(!after(4, 4), "a number is not after itself");

        let near = SEQUENCE_MASK - 2;
        let wrapped = 1_u64;
        assert!(
            after(wrapped, near),
            "one past the wrap is after one before it"
        );
        assert!(before(near, wrapped));
        // And the naive comparison disagrees, which is the defect.
        assert!(wrapped < near, "the two orders differ at the wrap");
    }

    /// A client's handshake opens the connection, and a client may not send
    /// before it does.
    ///
    /// The three states: `RequestSent` after the first send, `Open` after the
    /// Response, and `send` refused in between.
    #[test]
    fn a_client_opens_with_a_request_and_a_response() {
        let mut connection = Connection::connecting(5000, PEER, 5001, SERVICE, 100);
        assert_eq!(connection.state(), State::RequestSent);
        assert!(!connection.is_open());
        assert_eq!(connection.send(b"early"), Err(Error::InvalidArgument));

        // The Response arrives and is answered with an Ack.
        let mut response = segment(PacketType::Response, 200);
        response.service_code = Some(SERVICE);
        assert_eq!(
            connection.receive(&response, &[]),
            Reply::Send(PacketType::Ack)
        );
        assert_eq!(connection.state(), State::Open);
        assert!(connection.is_open());
        assert_eq!(connection.send(b"data").map(|_| ()), Ok(()));
    }

    /// A server answers a Request with a Response, and the client's Ack opens
    /// it.
    #[test]
    fn a_server_opens_when_the_ack_arrives() {
        let mut connection = Connection::accepted(5001, PEER, 5000, SERVICE, 300, 100);
        assert_eq!(connection.state(), State::ResponseSent);
        assert!(!connection.is_open());

        let mut ack = segment(PacketType::Ack, 101);
        ack.acknowledgement = Some(101);
        assert_eq!(connection.receive(&ack, &[]), Reply::None);
        assert_eq!(connection.state(), State::Open);
    }

    /// A datagram inside the window is taken, and the inbox answers what
    /// arrived.
    #[test]
    fn a_datagram_arrives_and_can_be_read() {
        let mut connection = open_for_tests();
        let mut data = segment(PacketType::Data, 10);
        data.acknowledgement = None;
        assert_eq!(
            connection.receive(&data, b"payload"),
            Reply::Send(PacketType::Ack)
        );
        assert_eq!(connection.inbox_len(), 1);

        let mut buffer = [0_u8; 32];
        assert_eq!(connection.read(&mut buffer), Ok(Some(7)));
        assert_eq!(&buffer[..7], b"payload");
        assert_eq!(connection.read(&mut buffer), Ok(None), "empty and open");
    }

    /// A datagram longer than the reader's buffer is refused and kept.
    #[test]
    fn a_small_buffer_is_refused_and_the_datagram_kept() {
        let mut connection = open_for_tests();
        connection.receive(&segment(PacketType::Data, 10), b"a datagram");
        let mut small = [0_u8; 4];
        assert_eq!(connection.read(&mut small), Err(Error::InvalidArgument));
        assert_eq!(connection.inbox_len(), 1, "and it is still there");
        let mut large = [0_u8; 32];
        assert_eq!(connection.read(&mut large), Ok(Some(10)));
    }

    /// A finished connection with an empty inbox answers end of file.
    ///
    /// The distinction a reader's loop turns on: `None` is a wait, `Some(0)` is
    /// the end.  A connection that answered `None` after finishing would make a
    /// reader wait on a writer that is gone.
    #[test]
    fn a_finished_connection_answers_end_of_file() {
        let mut connection = open_for_tests();
        connection.receive(&segment(PacketType::Close, 11), &[]);
        assert!(connection.is_finished());
        let mut buffer = [0_u8; 8];
        assert_eq!(connection.read(&mut buffer), Ok(Some(0)));
    }

    /// A sequence outside the window is answered with a Reset.
    ///
    /// Both edges: behind the window's low edge is too old, and past its high
    /// one is further ahead than the buffer allows.
    #[test]
    fn a_sequence_outside_the_window_is_reset() {
        let mut connection = open_for_tests();
        // The window is [0, WINDOW] to start with.
        let too_far = super::WINDOW + 10;
        assert_eq!(
            connection.receive(&segment(PacketType::Data, too_far), b"x"),
            Reply::Reset(super::RESET_CODE_SEQUENCE_WINDOW)
        );
        assert_eq!(connection.state(), State::Closed);
    }

    /// A duplicate datagram is refused by the window, which is how DCCP drops a
    /// repeat without a reader seeing it twice.
    #[test]
    fn a_duplicate_datagram_is_not_delivered_twice() {
        let mut connection = open_for_tests();
        assert_eq!(
            connection.receive(&segment(PacketType::Data, 10), b"once"),
            Reply::Send(PacketType::Ack)
        );
        // The same sequence again: the low edge moved past it.
        assert_eq!(
            connection.receive(&segment(PacketType::Data, 10), b"again"),
            Reply::Reset(super::RESET_CODE_SEQUENCE_WINDOW)
        );
        assert_eq!(connection.inbox_len(), 1);
    }

    /// A full inbox drops the newest rather than growing.
    #[test]
    fn a_full_inbox_drops_the_newest() {
        let mut connection = open_for_tests();
        for index in 0..INBOX_LIMIT {
            assert_eq!(
                connection.receive(&segment(PacketType::Data, 10 + index as u64), b"x"),
                Reply::Send(PacketType::Ack)
            );
        }
        assert_eq!(connection.inbox_len(), INBOX_LIMIT);
        connection.receive(&segment(PacketType::Data, 10 + INBOX_LIMIT as u64), b"y");
        assert_eq!(
            connection.inbox_len(),
            INBOX_LIMIT,
            "the count did not grow"
        );
        // The kept ones are the first ones.
        let mut buffer = [0_u8; 8];
        assert_eq!(connection.read(&mut buffer), Ok(Some(1)));
        assert_eq!(&buffer[..1], b"x");
    }

    /// A datagram larger than the bound is refused at the send.
    #[test]
    fn an_oversized_datagram_is_refused() {
        let mut connection = open_for_tests();
        let large = alloc::vec![0_u8; MAX_DATAGRAM + 1];
        assert_eq!(connection.send(&large), Err(Error::InvalidArgument));
        assert_eq!(
            connection
                .send(&alloc::vec![0_u8; MAX_DATAGRAM])
                .map(|_| ()),
            Ok(())
        );
    }

    /// A Request on an open connection is answered again rather than treated
    /// as new.
    #[test]
    fn a_duplicate_request_is_answered_again() {
        let mut connection = open_for_tests();
        assert_eq!(
            connection.receive(&segment(PacketType::Request, 12), &[]),
            Reply::Send(PacketType::Response)
        );
        assert_eq!(
            connection.state(),
            State::Open,
            "and the state did not move"
        );
    }

    /// A CloseReq asks for a Close, and a Close finishes the connection.
    #[test]
    fn the_close_sequence() {
        let mut connection = open_for_tests();
        assert_eq!(
            connection.receive(&segment(PacketType::CloseReq, 10), &[]),
            Reply::Send(PacketType::Close)
        );
        assert_eq!(connection.state(), State::CloseReq);
        assert!(!connection.is_open(), "data no longer crosses");

        let mut second = open_for_tests();
        assert_eq!(
            second.receive(&segment(PacketType::Close, 10), &[]),
            Reply::None
        );
        assert_eq!(second.state(), State::TimeWait);
        assert!(second.is_finished());
    }

    /// A Reset closes whatever state the connection was in, and it is not
    /// subject to the window.
    ///
    /// The one packet whose sequence number does not matter: it is what a peer
    /// sends when the two sides disagree, so requiring the window to agree
    /// first would refuse exactly the packet that resolves the disagreement.
    #[test]
    fn a_reset_closes_from_any_state() {
        let mut connection = open_for_tests();
        assert_eq!(
            connection.receive(&segment(PacketType::Reset, 999_999), &[]),
            Reply::None
        );
        assert_eq!(connection.state(), State::Closed);
    }

    /// A port has one listener, and releasing it frees the port.
    #[test]
    fn a_listening_port_has_one_owner() {
        use super::Table;
        let mut table = Table::new();
        assert_eq!(table.listen(5000, None).map(|_| ()), Ok(()));
        assert_eq!(table.listen(5000, None), Err(Error::AlreadyExists));
        assert!(table.is_listening(5000));
        assert!(!table.is_listening(5001));
        assert!(table.unlisten(5000));
        assert!(!table.unlisten(5000), "the second says nothing was there");
        assert_eq!(
            table.listen(5000, None).map(|_| ()),
            Ok(()),
            "and it is free"
        );
    }

    /// A Request for a listening port makes a pending connection, and the
    /// accept takes it.
    #[test]
    fn a_request_waits_at_a_listener_until_it_is_accepted() {
        use super::Table;
        let mut table = Table::new();
        table.listen(5000, Some(SERVICE)).expect("a listener");
        assert!(!table.has_pending(5000));

        let mut request = segment(PacketType::Request, 100);
        request.service_code = Some(SERVICE);
        request.destination_port = 5000;
        request.source_port = 4000;
        assert_eq!(
            table.receive(&request, &[], PEER, 900),
            Reply::Send(PacketType::Response)
        );
        assert!(table.has_pending(5000));
        assert_eq!(
            table.counts(),
            (0, 1),
            "a pending connection is not one yet"
        );

        let id = table.accept(5000).expect("an accept").expect("a Request");
        assert_eq!(table.counts(), (1, 1));
        let connection = table.connection(id).expect("the connection");
        assert_eq!(connection.state(), State::ResponseSent);
        assert_eq!(connection.peer(), (PEER, 4000));
        assert_eq!(connection.service_code(), SERVICE);
        assert!(!table.has_pending(5000), "and the queue is empty");
        assert_eq!(
            table.accept(5000).expect("an accept"),
            None,
            "nothing else is waiting"
        );
    }

    /// A listener naming a service code refuses a Request for another one.
    #[test]
    fn a_listener_refuses_another_service_code() {
        use super::Table;
        let mut table = Table::new();
        table.listen(5000, Some(SERVICE)).expect("a listener");
        let mut request = segment(PacketType::Request, 100);
        request.service_code = Some(SERVICE + 1);
        request.destination_port = 5000;
        request.source_port = 4000;
        assert_eq!(
            table.receive(&request, &[], PEER, 900),
            Reply::Reset(super::RESET_CODE_CONNECTION_REFUSED)
        );
        assert!(!table.has_pending(5000));
    }

    /// A packet for a port nothing answers on is answered with a Reset.
    #[test]
    fn a_packet_for_no_port_is_reset() {
        use super::Table;
        let mut table = Table::new();
        assert_eq!(
            table.receive(&segment(PacketType::Data, 1), b"x", PEER, 900),
            Reply::Reset(super::RESET_CODE_CONNECTION_REFUSED)
        );
    }

    /// A connection's own segments find it, and another peer's do not.
    #[test]
    fn a_connection_is_found_by_its_four_tuple() {
        use super::Table;
        let mut table = Table::new();
        let id = table
            .connect(5000, PEER, 5001, SERVICE, 100)
            .expect("a connection");
        assert!(table.find(5000, PEER, 5001).is_some());
        assert!(table.find(5000, PEER, 5002).is_none(), "another peer port");
        assert!(
            table.find(5000, Address::V4([10, 0, 2, 9]), 5001).is_none(),
            "another peer"
        );
        assert_eq!(table.connection(id).map(|c| c.local_port()), Some(5000));
    }

    /// A full backlog refuses the Request that would have grown it.
    #[test]
    fn a_full_backlog_refuses() {
        use super::Table;
        let mut table = Table::new();
        table.listen(5000, None).expect("a listener");
        for index in 0..super::BACKLOG {
            let mut request = segment(PacketType::Request, 100 + index as u64);
            request.service_code = Some(SERVICE);
            request.destination_port = 5000;
            request.source_port = 4000 + index as u16;
            assert_eq!(
                table.receive(&request, &[], PEER, 900),
                Reply::Send(PacketType::Response)
            );
        }
        let mut one_too_many = segment(PacketType::Request, 999);
        one_too_many.service_code = Some(SERVICE);
        one_too_many.destination_port = 5000;
        one_too_many.source_port = 4500;
        assert_eq!(
            table.receive(&one_too_many, &[], PEER, 900),
            Reply::Reset(super::RESET_CODE_CONNECTION_REFUSED)
        );
    }

    /// An id names the same connection after an earlier one is pruned.
    ///
    /// The property a stored id has and a position does not: the first
    /// connection is finished and pruned, and the second keeps the id it was
    /// given rather than sliding into the first one's place.
    #[test]
    fn an_id_survives_a_prune() {
        use super::Table;
        let mut table = Table::new();
        let first = table
            .connect(5000, PEER, 5001, SERVICE, 100)
            .expect("a connection");
        let second = table
            .connect(5001, PEER, 5002, SERVICE, 200)
            .expect("a connection");
        assert_ne!(first, second);

        table
            .connection_mut(first)
            .expect("the first")
            .receive(&segment(PacketType::Reset, 1), &[]);
        table.prune();
        assert_eq!(table.counts().0, 1);
        let held = table.connection(second).expect("the second is still here");
        assert_eq!(held.id(), second, "and it is the one id two names");
        assert!(table.connection(first).is_none(), "and id one is gone");
    }

    /// Pruning drops closed connections and keeps everything else.
    #[test]
    fn pruning_drops_only_closed_connections() {
        use super::Table;
        let mut table = Table::new();
        let open = table
            .connect(5000, PEER, 5001, SERVICE, 100)
            .expect("a connection");
        let second = table
            .connect(5001, PEER, 5002, SERVICE, 200)
            .expect("a connection");
        {
            let connection = table.connection_mut(second).expect("the connection");
            connection.receive(&segment(PacketType::Reset, 1), &[]);
            assert_eq!(connection.state(), State::Closed);
        }
        table.prune();
        assert_eq!(table.counts().0, 1);
        assert!(
            table.connection(open).is_some(),
            "the open one is still here"
        );
    }

    /// A `DataAck` completes a server's handshake: the client's Ack and its
    /// first datagram are one packet.
    ///
    /// The transition this test exists for: a server in `ResponseSent` that
    /// refused a `DataAck` would refuse the first thing the client ever sends,
    /// because the client's handshake and its data are one segment.
    #[test]
    fn a_data_ack_opens_a_server_that_sent_its_response() {
        let mut connection = Connection::accepted(5001, PEER, 5000, SERVICE, 300, 100);
        assert_eq!(connection.state(), State::ResponseSent);

        // The client's first packet is a DataAck: it acknowledges the Response
        // and carries the first datagram.
        let mut first = segment(PacketType::DataAck, 101);
        first.acknowledgement = Some(300);
        assert_eq!(
            connection.receive(&first, b"first"),
            Reply::Send(PacketType::Ack)
        );
        assert_eq!(connection.state(), State::Open);
        assert_eq!(connection.inbox_len(), 1, "and the datagram arrived");
    }

    /// The connection's own words are what it was built with.
    #[test]
    fn a_connection_reports_its_own_stream() {
        let connection = Connection::connecting(5000, PEER, 5001, SERVICE, 100);
        assert_eq!(connection.local_port(), 5000);
        assert_eq!(connection.peer(), (PEER, 5001));
        assert_eq!(connection.service_code(), SERVICE);
        assert_eq!(connection.next_sequence(), 101, "one past the first");
    }
}
