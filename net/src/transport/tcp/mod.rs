//! net/src/transport/tcp/mod.rs
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

/// The floor a measured round trip may set the timeout to, in microseconds.
///
/// [RFC 6298] section 2.4's: a measured round trip is at least a millisecond,
/// because a smaller number is a measurement of the clock rather than of the
/// path and would make the timeout so short that every segment is
/// retransmitted before its acknowledgement could arrive.
///
/// [RFC 6298]: https://www.rfc-editor.org/rfc/rfc6298
pub const RTO_FLOOR_MICROS: u64 = 1_000;

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

/// How long a closed four-tuple is held, in microseconds.
///
/// [RFC 793]'s `2 * MSL`, and this stack's MSL is thirty seconds, which is the
/// value [RFC 1122] states as the floor a host must assume when it does not
/// know the path.  The state exists so that a peer's retransmitted finish,
/// arriving after the close, lands on a stream that answers it instead of on a
/// port nothing owns, which this stack answers with a reset.
///
/// [RFC 793]: https://www.rfc-editor.org/rfc/rfc793
/// [RFC 1122]: https://www.rfc-editor.org/rfc/rfc1122
pub const TIME_WAIT_MICROS: u64 = 60_000_000;

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
    /// This side sent its finish and the peer has not acknowledged it yet.
    ///
    /// The half of the close this stack used to fold into one state: a FIN
    /// that is still unacknowledged has to be retransmitted, and one the peer
    /// has acknowledged does not, so the two are different jobs and
    /// [RFC 793] gives them different names.
    FinWait,
    /// The peer acknowledged this side's finish, and its own has not arrived.
    ///
    /// Nothing is sent from here and nothing is retransmitted: this side is
    /// done, and what it waits for is the peer saying the same.  A stream in
    /// this state can wait indefinitely and that is correct, which is why the
    /// table's ``a stream that never moves again`` reading has to treat it as
    /// alive.
    FinWait2,
    /// The peer is done sending; this side's finish has not gone out.
    CloseWait,
    /// Both sides sent a finish, and this side's has not been acknowledged.
    ///
    /// The crossing case: the peer's finish arrived before this side's was
    /// acknowledged, so both are in flight and the stream is not done until
    /// this side's own is.  [RFC 793] calls it `CLOSING`; a stack without it
    /// treated the crossing as an ordinary [`State::FinWait`] and lost the
    /// acknowledgement it was still owed.
    Closing,
    /// Both sides are done and this side's finish is the last unacknowledged
    /// one.
    LastAck,
    /// The close is over, and the four-tuple is held so a duplicate finish is
    /// answered rather than refused.
    ///
    /// Two times the longest segment lifetime, [RFC 793]'s rule.  A stream
    /// that went straight to [`State::Closed`] would let the table forget the
    /// four-tuple, and a peer's retransmitted FIN, arriving afterwards, would
    /// be a segment for a port nothing owns: this stack answers those with a
    /// reset, which is a close the peer did not ask for.
    TimeWait,
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
    /// The peer's advertised window, which bounds what this side may send.
    pub window: u16,
    /// How many data bytes the segment carries.
    ///
    /// The bytes **past the header**, which is not the packet's length less
    /// [`HEADER_LEN`]: a segment may carry options, and a reader that took the
    /// whole packet for data would count them as the peer's bytes and deliver
    /// a stream's first segment twenty bytes too long.  The header's own
    /// length is `data offset`, and [`parse`] subtracts it.
    pub payload_len: usize,
    /// Where the data starts in the packet, in bytes.
    ///
    /// `data offset` times four, and [`HEADER_LEN`] for a segment with no
    /// options.  A caller that hands the whole packet to
    /// [`Connection::receive`] needs this: that function's `payload` is the
    /// segment's data and not its header, and passing the packet is the defect
    /// this field exists to make visible at the call site.
    pub payload_at: usize,
    /// The largest segment the sender says it can receive, if it said.
    ///
    /// The MSS option's value from a SYN, and `None` from any segment that did
    /// not carry one.  A SYN without the option is a peer using [RFC 1122]'s
    /// default of 536 bytes for an address it does not know, which is the
    /// number a stream that learned nothing has to assume.
    ///
    /// [RFC 1122]: https://www.rfc-editor.org/rfc/rfc1122
    pub mss: Option<u16>,
}

impl Segment {
    /// A segment built from the fields a caller has, with the rest at their
    /// defaults.
    ///
    /// The defaults are the ones a segment with **no options** has: the data
    /// starts at [`HEADER_LEN`], nothing is stated about a receive buffer, and
    /// the payload is whatever the caller says it carried.  A caller that has
    /// a real packet should use [`parse`], which reads all of it; this exists
    /// for the caller that is composing or simulating a segment and should not
    /// have to restate four fields every time the struct grows one.
    pub const fn new(
        source_port: u16,
        destination_port: u16,
        sequence: u32,
        acknowledgement: u32,
        flags: u8,
        window: u16,
        payload_len: usize,
    ) -> Self {
        Self {
            source_port,
            destination_port,
            sequence,
            acknowledgement,
            flags,
            window,
            payload_len,
            payload_at: HEADER_LEN,
            mss: None,
        }
    }
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
    write_segment_with_mss(
        into,
        source,
        destination,
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        flags,
        window,
        data,
        // A SYN states this side's largest segment, and only a SYN: the
        // option is a handshake's, and a peer that saw one on a data segment
        // would be a peer reading a header it did not expect.
        (flags & FLAG_SYN != 0).then_some(MSS_DEFAULT as u16),
    );
}

/// Write a segment, stating `mss` in the option field when it is given.
///
/// [`write_segment`] is this with the SYN's own rule; this exists so a caller
/// that is building a **fault** can put an option on a segment whose flags do
/// not say SYN, which is what a probe needs to tell "the data offset is read"
/// from "the flags happen to make the header longer".
#[allow(clippy::too_many_arguments)]
pub fn write_segment_with_mss(
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
    mss: Option<u16>,
) {
    let header = match mss {
        Some(mss) => write_mss_option(into, mss),
        None => HEADER_LEN,
    };
    let length = fill_segment(
        into,
        header,
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        flags,
        window,
        data,
    );
    let sum = checksum_of(&[
        &pseudo_header(source, destination, length),
        &into[..length as usize],
    ]);
    put_u16(into, 16, sum);
}

/// Write the MSS option into the header's option field, answering the header's
/// length.
///
/// Four bytes, which keeps the header a whole number of words: a kind, a
/// length of four, and the value.  The header then occupies six words rather
/// than five, which is why every writer takes its length from this and not
/// from [`HEADER_LEN`].
fn write_mss_option(into: &mut [u8], mss: u16) -> usize {
    into[HEADER_LEN] = OPTION_MSS;
    into[HEADER_LEN + 1] = 4;
    put_u16(into, HEADER_LEN + 2, mss);
    HEADER_LEN + 4
}

/// Fill in every field of a segment whose options have already been written,
/// answering the segment's length.
///
/// The checksum is **not** computed here: the two families' pseudo-headers
/// differ in length and content, so a body that summed one of them would be a
/// body that silently wrote an IPv4 sum into an IPv6 segment.  It leaves the
/// field zero, which is what the computation reads it as, and each writer sums
/// its own.
#[allow(clippy::too_many_arguments)]
fn fill_segment(
    into: &mut [u8],
    header: usize,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    window: u16,
    data: &[u8],
) -> u16 {
    let length = (header + data.len()) as u16;
    put_u16(into, 0, source_port);
    put_u16(into, 2, destination_port);
    into[4..8].copy_from_slice(&sequence.to_be_bytes());
    into[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
    // The data offset is the header's length in four-byte words, which is what
    // lets a reader find the data past an option.
    into[12] = ((header / 4) as u8) << 4;
    into[13] = flags;
    put_u16(into, 14, window);
    put_u16(into, 16, 0);
    put_u16(into, 18, 0);
    into[header..header + data.len()].copy_from_slice(data);
    length
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
    let header = if flags & FLAG_SYN != 0 {
        write_mss_option(into, MSS_DEFAULT as u16)
    } else {
        HEADER_LEN
    };
    let length = fill_segment(
        into,
        header,
        source_port,
        destination_port,
        sequence,
        acknowledgement,
        flags,
        window,
        data,
    );
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
    let data_offset = header_len(packet)?;
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
        payload_at: data_offset,
        mss: mss_option(&packet[HEADER_LEN..data_offset]),
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
/// How many bytes a SYN's header occupies, MSS option included.
///
/// A SYN carries the option and every other segment does not, so a caller that
/// reserves room for a **segment** has to know which it is building.  The
/// number is [`HEADER_LEN`] plus the option's four bytes, and it is a constant
/// rather than arithmetic at each call site because a buffer one byte short is
/// an out-of-bounds write and not a short segment.
pub const SYN_HEADER_LEN: usize = HEADER_LEN + 4;

/// The kind number of the MSS option, [RFC 9293]'s.
///
/// Two bytes of kind and length, then the value: the peer's receive buffer's
/// largest segment, which is what a sender's segment size must not exceed.
///
/// [RFC 9293]: https://www.rfc-editor.org/rfc/rfc9293
pub const OPTION_MSS: u8 = 2;

/// How many bytes a segment's header occupies, from the data offset.
///
/// The `data offset` field is the high nibble of byte twelve, counted in
/// **four-byte words**, so the header's length in bytes is that number times
/// four.  A value below five is a header shorter than the fixed part, which is
/// a segment no peer sent; a value past the packet is a header that claims
/// bytes the packet does not have.  Both are refused, because a reader that
/// took either would index past what it was given.
fn header_len(packet: &[u8]) -> Option<usize> {
    if packet.len() < HEADER_LEN {
        return None;
    }
    let words = (packet[12] >> 4) as usize;
    let length = words * 4;
    if length < HEADER_LEN || length > packet.len() {
        return None;
    }
    Some(length)
}

/// The MSS option's value, if `options` carries one.
///
/// Every option is a kind byte alone (end, no-op) or a kind, a length and the
/// bytes between; a length below two would make the walk step nowhere and a
/// kind of zero ends the list.  Both are [RFC 9293]'s rules, and both are why
/// this cannot be a search for the byte `2`: a value byte of an earlier option
/// may be `2` itself, and reading it as the kind would report a segment size
/// from a number that means something else entirely.
///
/// [RFC 9293]: https://www.rfc-editor.org/rfc/rfc9293
fn mss_option(options: &[u8]) -> Option<u16> {
    let mut at = 0;
    while at < options.len() {
        match options[at] {
            // End of the option list, and the no-op that pads an alignment.
            0 => return None,
            1 => {
                at += 1;
                continue;
            }
            kind => {
                let length = *options.get(at + 1)? as usize;
                // A length below two is a walk that never advances; one past
                // the buffer is an option the sender did not finish.
                if length < 2 || at + length > options.len() {
                    return None;
                }
                if kind == OPTION_MSS && length == 4 {
                    return Some(get_u16(options, at + 2));
                }
                at += length;
            }
        }
    }
    None
}

/// Read the segment at the start of an IPv4 packet's payload.
pub fn parse(packet: &[u8], source: [u8; 4], destination: [u8; 4]) -> Option<Segment> {
    let data_offset = header_len(packet)?;
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
        // The bytes past the **header**, which is not the packet less
        // [`HEADER_LEN`]: a segment that carried options would otherwise count
        // them as the peer's data, and the first segment of a stream would
        // arrive with a header's worth of bytes in front of its payload.
        payload_len: packet.len() - data_offset,
        payload_at: data_offset,
        mss: mss_option(&packet[HEADER_LEN..data_offset]),
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
    /// The smoothed round trip, in microseconds.
    ///
    /// [RFC 6298] section 2's `SRTT`: an exponential moving average whose
    /// weight is seven eighths, so one slow round trip moves the estimate a
    /// little and a path that changed moves it within a few.  `None` until a
    /// measurement exists, because the first one is the estimate rather than a
    /// sample to average.
    ///
    /// [RFC 6298]: https://www.rfc-editor.org/rfc/rfc6298
    srtt: Option<u64>,
    /// The smoothed round trip's variance, in microseconds.
    ///
    /// Section 2's `RTTVAR`, the mean deviation.  The timeout is `SRTT + 4 *
    /// RTTVAR` with a floor, which is what makes it track a path that got
    /// noisier rather than only one that got slower.
    rttvar: u64,
    /// How many times the oldest unacknowledged segment has been sent.
    attempts: u8,
    /// When the [`State::TimeWait`] hold began, in the caller's clock.
    ///
    /// `None` everywhere else, and the one place a connection's deadline is
    /// about a state rather than about a segment: the close is over, and the
    /// entry stays so a late finish is answered.
    time_wait_since: Option<u64>,
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
    /// Whether this copy has been sent more than once.
    ///
    /// [RFC 6298] section 3's Karn rule: an acknowledgement of a segment that
    /// was retransmitted cannot say **which** copy it acknowledges, so the
    /// round trip it appears to measure may be one that never happened.  Such
    /// a segment contributes no sample, and the timeout keeps its backoff.
    ///
    /// [RFC 6298]: https://www.rfc-editor.org/rfc/rfc6298
    retransmitted: bool,
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
            srtt: None,
            rttvar: 0,
            time_wait_since: None,
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
            srtt: None,
            rttvar: 0,
            time_wait_since: None,
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
        self.note_send_move(segment);
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

        // A stream in `TimeWait` answers a retransmitted finish and nothing
        // else.  This is the whole reason the state exists: the peer sent a
        // FIN, this side acknowledged it, and the acknowledgement was lost, so
        // the peer sends the same FIN again.  Answering it again is the
        // protocol; a `Closed` entry would have been pruned and the segment
        // would reach a port nothing owns, which this stack answers with a
        // reset.
        if self.state == State::TimeWait {
            if segment.flags & FLAG_FIN != 0
                && segment.sequence.wrapping_add(1) == self.acknowledgement
            {
                let sent = self.take_outgoing(self.sequence, self.acknowledgement, FLAG_ACK, &[]);
                return (Ok(Event::None), sent);
            }
            // Anything else is a peer that did not hear the close: a segment
            // after both sides finished is answered with the acknowledgement
            // that says so, which is what ends the peer's retransmissions.
            if segment.flags & FLAG_ACK != 0 {
                return (Ok(Event::None), alloc::vec::Vec::new());
            }
            return (Ok(Event::None), alloc::vec::Vec::new());
        }

        // Everything after the handshake needs the stream open in this
        // direction.
        // Every state from `Established` to `LastAck` accepts segments: a
        // half-closed stream still reads, and a stream waiting for a finish
        // still has to acknowledge what arrives.  `TimeWait` is deliberately
        // **not** here: it answers the peer's finish and nothing else, which
        // the arm below does.
        let open = matches!(
            self.state,
            State::Established
                | State::FinWait
                | State::FinWait2
                | State::CloseWait
                | State::Closing
                | State::LastAck
        );
        if !open {
            return (Ok(Event::None), alloc::vec::Vec::new());
        }

        let mut event = Event::None;

        // The peer's acknowledgement of this side's finish.  What it means
        // depends on whether the peer has said its own finish:
        //
        // * In `FinWait` this side is done and the peer has not said it is, so
        //   the stream waits, which is `FinWait2`.
        // * In `Closing` both finishes were sent and crossed, so the
        //   acknowledgement is the moment both are done, which is `TimeWait`.
        // * In `LastAck` the peer's finish came first and this side's is the
        //   last unacknowledged one, so the close is over and the entry enters
        //   `TimeWait` with the others.
        //
        // The three used to be one arm that went straight to `Closed`, which
        // was right for `LastAck` and wrong for the other two: a stream whose
        // peer had not finished was forgotten, and the peer's own finish, when
        // it came, found no connection and was answered with a reset.
        if segment.flags & FLAG_ACK != 0 {
            match self.state {
                State::FinWait => {
                    self.state = State::FinWait2;
                    return (Ok(Event::Settled), alloc::vec::Vec::new());
                }
                State::Closing | State::LastAck => {
                    self.enter_time_wait();
                    return (Ok(Event::Settled), alloc::vec::Vec::new());
                }
                _ => {}
            }
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

        if (self.state == State::FinWait2 || self.state == State::Closing)
            && segment.flags & FLAG_FIN != 0
            && segment.sequence == self.acknowledgement
        {
            // The peer's finish, answering this side's own acknowledging one:
            // both halves are done, and the entry stays in `TimeWait` so a
            // retransmitted finish is answered rather than reset.
            self.acknowledgement = segment.sequence.wrapping_add(1);
            let sent = self.take_outgoing(self.sequence, self.acknowledgement, FLAG_ACK, &[]);
            self.enter_time_wait();
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
                // This side's finish is out and the peer's has just arrived.
                // Whether the peer has acknowledged this side's is the
                // difference between `Closing` (it has not, so an
                // acknowledgement is still owed) and `TimeWait` (it has, so
                // only the hold is left).
                match self.state {
                    State::FinWait2 => {
                        self.enter_time_wait();
                        State::TimeWait
                    }
                    _ => State::Closing,
                }
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
    /// Take the move the segment makes to this side's **sending**, which is
    /// two statements: the room the peer's buffer has, and the largest segment
    /// it can receive.
    ///
    /// A SYN states the second and a segment without the option states
    /// nothing, so an absent option leaves the limit where it was rather than
    /// resetting it to a default: a data segment that carried no option is a
    /// peer repeating no news, not a peer retracting what its handshake said.
    fn note_send_move(&mut self, segment: &Segment) {
        self.note_window(segment);
        if let Some(mss) = segment.mss {
            self.limit_segment(mss as usize);
        }
    }

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

        // Nagle's rule, and `TCP_NODELAY` is what turns it off.  A small write
        // with bytes already in flight is **held**, not sent: the first small
        // segment goes out at once and the ones after it wait for the
        // acknowledgement, so a program that writes a byte at a time costs one
        // segment per round trip rather than one per byte.  [RFC 1122] section
        // 4.2.3.4 states it, and the option is the caller's way out: `some
        // writes are late and want to be` is a real property, which is why the
        // standard has the switch at all.
        //
        // A write at least a segment long is sent whatever the rule says: the
        // rule is about small writes, and holding a full segment would be
        // holding data the path is waiting for.
        //
        // [RFC 1122]: https://www.rfc-editor.org/rfc/rfc1122
        if !self.options.no_delay() && bytes.len() < self.mss() && !self.unacknowledged.is_empty() {
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

    /// Enter [`State::TimeWait`], recording when the hold began.
    ///
    /// The one move that takes two fields at once, which is why it is a
    /// function: a state set without its deadline would be a hold that never
    /// ends, and a deadline set without the state would be a timer on an open
    /// stream.
    fn enter_time_wait(&mut self) {
        self.state = State::TimeWait;
        self.time_wait_since = Some(self.now);
        // Nothing is owed from here: the queue is what a closed stream would
        // otherwise retransmit at a peer that has already finished.
        self.unacknowledged.clear();
    }

    /// Whether the hold has run out at the time this connection was last told.
    ///
    /// The caller's clock, the same one `retransmit` reads, and the answer a
    /// table needs before it drops an entry: a four-tuple is held for
    /// [`TIME_WAIT_MICROS`] and not for ever.
    pub fn time_wait_elapsed(&self) -> bool {
        self.state == State::TimeWait
            && self
                .time_wait_since
                .is_some_and(|since| self.now.wrapping_sub(since) >= TIME_WAIT_MICROS)
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
        // Karn's rule: this copy cannot measure a round trip, so any
        // acknowledgement that retires it contributes no sample.
        self.unacknowledged[0].retransmitted = true;
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
                retransmitted: false,
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
        // The round trip this acknowledgement measures, if it can measure
        // one.  The newest segment it retires is the one whose send time is
        // the sample's: an acknowledgement covering several segments says the
        // peer received all of them, and the one that was sent last is the
        // round trip that just ended.  A segment that was retransmitted is
        // skipped, because its acknowledgement cannot say which copy it means
        // and a sample from the wrong copy is a measurement of the timeout
        // rather than of the path.
        let sample = self
            .unacknowledged
            .iter()
            .filter(|segment| acknowledges(acknowledgement, segment.end) && !segment.retransmitted)
            .max_by_key(|segment| segment.sent_at)
            .map(|segment| self.now.saturating_sub(segment.sent_at));

        self.unacknowledged
            .retain(|segment| !acknowledges(acknowledgement, segment.end));
        self.attempts = 0;
        self.duplicates = 0;
        match sample {
            // A measurement replaces the backoff: the path has just answered,
            // and the timeout it earned by answering is the one the next
            // segment waits, not the doubled one a silence produced.
            Some(measured) => {
                self.measure(measured);
                self.timeout = self.rto();
            }
            // Nothing measured, so the backoff survives: an acknowledgement of
            // a retransmitted segment says the peer is alive and says nothing
            // about how long the path takes.
            None => {
                if self.attempts == 0 {
                    self.timeout = self.rto();
                }
            }
        }
        self.open_window(covered);
        None
    }

    /// Fold one round-trip measurement into the estimate.
    ///
    /// [RFC 6298]'s section on the estimator, and its two cases.  The
    /// **first** measurement is the estimate itself: `SRTT = R` and `RTTVAR =
    /// R / 2`.  That case exists because there is nothing to average a first
    /// sample against, and a formula that assumed a zero estimate would spend
    /// several round trips recovering from it.
    ///
    /// After that the deviation moves a quarter of the way toward how far the
    /// sample was from the estimate, and then the estimate moves an eighth of
    /// the way toward the sample.  The order is the standard's and it matters:
    /// the deviation is measured against the estimate **before** this sample
    /// moved it, which makes it a measure of how far the sample was from what
    /// was expected rather than of how far the estimate had already moved.
    ///
    /// The shifts are exact because the weights are powers of two: a division
    /// would round a small change to nothing on a path whose round trip is
    /// tens of microseconds.
    ///
    /// [RFC 6298]: https://www.rfc-editor.org/rfc/rfc6298
    fn measure(&mut self, round_trip: u64) {
        match self.srtt {
            None => {
                self.srtt = Some(round_trip);
                self.rttvar = round_trip / 2;
            }
            Some(srtt) => {
                let difference = srtt.abs_diff(round_trip);
                self.rttvar = (self.rttvar * 3 + difference) / 4;
                self.srtt = Some((srtt * 7 + round_trip) / 8);
            }
        }
    }

    /// The timeout the estimate calls for, in microseconds.
    ///
    /// [RFC 6298] section 2.3's `SRTT + 4 * RTTVAR`, floored and capped.
    /// Before any measurement it is [`RTO_INITIAL_MICROS`], which is what the
    /// stack used for every stream until this existed.
    ///
    /// [RFC 6298]: https://www.rfc-editor.org/rfc/rfc6298
    pub fn rto(&self) -> u64 {
        match self.srtt {
            None => RTO_INITIAL_MICROS,
            Some(srtt) => (srtt + 4 * self.rttvar).clamp(RTO_FLOOR_MICROS, RTO_MAX_MICROS),
        }
    }

    /// The smoothed round trip, if anything has been measured.
    ///
    /// `None` is a stream that has not had an acknowledgement worth
    /// measuring, which is a real state and not a zero: a zero would be a
    /// measurement of no time at all.
    pub fn smoothed_round_trip(&self) -> Option<u64> {
        self.srtt
    }

    /// The smoothed round trip's variance, in microseconds.
    pub fn round_trip_variance(&self) -> u64 {
        self.rttvar
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
mod tests;
