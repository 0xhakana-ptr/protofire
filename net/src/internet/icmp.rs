//! net/src/internet/icmp.rs
//!
//! ICMP: the control messages the wire sends about itself, as far as this
//! stack needs them, an echo request out, an echo reply back.
//!
//! ## The layout
//!
//! ```text
//! IPv4     ver|ihl, tos, total_length, … protocol=1
//! ICMP     type[1] code[1] checksum[2]
//! echo     identifier[2] sequence[2] data[…]   8 bytes + data
//! ```
//!
//! ## Why a ping is the proof for this layer
//!
//! An echo exchange is the smallest round trip IPv4 can carry: the reply that
//! comes back names the identifier and sequence the request sent and holds the
//! bytes it carried, so a boot that matches all three has parsed a packet
//! another machine built, not its own output read back through its own
//! parser.  QEMU's user-mode network answers a ping for its gateway without
//! being asked to, which is what makes the exchange a real one on every
//! machine this tree boots.
//!
//! ## The errors, and why a stack must send them
//!
//! A datagram for a port nothing owns is the one error a sender is guaranteed
//! to be able to provoke, and a stack that parses port-unreachable but never
//! sends it is a stack whose peers wait forever.
//! [`write_destination_unreachable`] is that message: the sender's own header
//! and the first eight bytes of its payload, quoted back, which is what lets
//! the sender match the report to the datagram it sent.
//!
//! [RFC 1812] is the rule for how much to quote, as much of the original
//! packet as fits without making the message larger than the smallest MTU a
//! path may have, and it is here rather than at the caller because the
//! arithmetic is the message's own layout.
//!
//! [RFC 1812]: https://www.rfc-editor.org/rfc/rfc1812

use crate::ethernet::get_u16;
use crate::ethernet::put_u16;
use crate::ipv4::checksum;

/// The ICMP message's length before its data: type, code, checksum, and the
/// echo pair.
pub const HEADER_LEN: usize = 8;

/// `type` value 8: an echo request, a ping.
pub const ECHO_REQUEST: u8 = 8;

/// `type` value 0: an echo reply, the answer to one.
pub const ECHO_REPLY: u8 = 0;

/// `type` value 3: destination unreachable, the datagram did not get where
/// it was going, and the message says why in its code.
pub const DESTINATION_UNREACHABLE: u8 = 3;

/// `code` value 3 under [`DESTINATION_UNREACHABLE`]: the port nothing owns.
///
/// This is the one error a UDP sender is guaranteed to be able to provoke
/// send a datagram to a port nothing listens on, and the peer answers with
/// it, which is what makes it the proof a datagram left and a peer parsed
/// it.
pub const PORT_UNREACHABLE: u8 = 3;

/// `code` value 1 under [`DESTINATION_UNREACHABLE`]: the host does not answer.
///
/// A router says this when it has no route to the host, and a host says it
/// when it cannot reach one.  For a stream it is the same news as a closed
/// port: the path this four-tuple names does not exist, and a stack that kept
/// retransmitting into it would be retransmitting for thirty-one seconds to
/// learn what the report already said.
pub const HOST_UNREACHABLE: u8 = 1;

/// `code` value 4 under [`DESTINATION_UNREACHABLE`]: fragmentation is needed
/// and the packet said not to fragment it.
///
/// This is path-MTU discovery's whole signal on IPv4.  A router on a link
/// narrower than the packet drops it and says so, and the message carries the
/// next hop's MTU in its header's unused word, which is what tells a sender
/// what to shrink to.  Without it a sender whose packets are too large learns
/// nothing: every packet is dropped in silence and the only evidence is that
/// nothing ever answers.
pub const FRAGMENTATION_NEEDED: u8 = 4;

/// Where a fragmentation-needed message holds the next hop's MTU.
///
/// The four bytes every ICMP error leaves unused hold the MTU in that one
/// code, which is [RFC 1191]'s layout and the only place a sender can learn a
/// path's size on IPv4.
///
/// [RFC 1191]: https://www.rfc-editor.org/rfc/rfc1191
pub const NEXT_HOP_MTU_AT: usize = 4;

/// Where an error message holds the original datagram it is about: after the
/// eight bytes every ICMP message begins with, four of which an error leaves
/// unused.
pub const ORIGINAL_DATAGRAM_AT: usize = 8;

/// How long an echo message is, header and data.
pub const fn echo_len(data_len: usize) -> usize {
    HEADER_LEN + data_len
}

/// Write an echo request: `identifier` and `sequence` name the exchange, and
/// `data` is what the reply must hold.
///
/// The caller's buffer is the message's: `HEADER_LEN + data.len()` bytes,
/// which is what [`echo_len`] answers.  The checksum is computed over the
/// whole message, type and code included, which is why the field is zeroed
/// before the sum and written after it.
pub fn write_echo_request(into: &mut [u8], identifier: u16, sequence: u16, data: &[u8]) {
    write_echo(into, ECHO_REQUEST, identifier, sequence, data);
}

/// How many bytes of the original datagram an error quotes back.
///
/// [RFC 792] requires the internet header plus the first sixty-four bits of
/// the original datagram's payload, which is what lets the sender match the
/// report to a socket.  Eight is also all a UDP or TCP header's first fields
/// need, the ports, which is the part a caller acts on.
///
/// [RFC 792]: https://www.rfc-editor.org/rfc/rfc792
pub const QUOTED_PAYLOAD: usize = 8;

/// The length an error message has when it quotes `payload_quoted` bytes of
/// the original payload after `header_quoted` bytes of its header.
pub const fn error_len(header_quoted: usize, payload_quoted: usize) -> usize {
    HEADER_LEN + header_quoted + payload_quoted
}

/// Write a destination-unreachable message, quoting the datagram that caused
/// it.
///
/// `into` is the message's bytes and must be at least
/// `error_len(header_quoted, payload_quoted)`.  The writer fills the eight
/// fixed bytes, then the quoted header, then the quoted payload, which is
/// [RFC 792]'s layout, and the order a sender's own header has to come back
/// in for it to recognise its datagram.
///
/// The four bytes an error leaves unused between the checksum and the quote
/// are written as zero: the RFC says they must be, and a peer that compared
/// them would otherwise be comparing whatever the buffer held.
///
/// [RFC 792]: https://www.rfc-editor.org/rfc/rfc792
pub fn write_destination_unreachable(
    into: &mut [u8],
    code: u8,
    original_header: &[u8],
    original_payload: &[u8],
) {
    write_unreachable_with_mtu(into, code, 0, original_header, original_payload);
}

/// Write a destination-unreachable message, with the next hop's MTU when the
/// code is the one that carries it.
///
/// The four-byte word after the checksum is unused in every error but
/// [`FRAGMENTATION_NEEDED`], and zero in all of them, because [RFC 792] says
/// an unused field is zero and a buffer is not.  The one code that gives it a
/// meaning is [RFC 1191]'s: the MTU of the next hop, which is the only way a
/// sender whose packets are too large can learn what to shrink to.
///
/// [RFC 792]: https://www.rfc-editor.org/rfc/rfc792
/// [RFC 1191]: https://www.rfc-editor.org/rfc/rfc1191
pub fn write_unreachable_with_mtu(
    into: &mut [u8],
    code: u8,
    next_hop_mtu: u16,
    original_header: &[u8],
    original_payload: &[u8],
) {
    let quoted_payload = original_payload.len().min(QUOTED_PAYLOAD);
    let total = error_len(original_header.len(), quoted_payload);
    if into.len() < total {
        return;
    }
    into[0] = DESTINATION_UNREACHABLE;
    into[1] = code;
    put_u16(into, 2, 0);
    // The word after the checksum: the MTU in the one code that gives it a
    // meaning, and zero everywhere else, which is what an unused field is.
    put_u16(into, NEXT_HOP_MTU_AT, next_hop_mtu);
    put_u16(into, 6, 0);
    into[HEADER_LEN..HEADER_LEN + original_header.len()].copy_from_slice(original_header);
    let payload_at = HEADER_LEN + original_header.len();
    into[payload_at..payload_at + quoted_payload]
        .copy_from_slice(&original_payload[..quoted_payload]);
    put_u16(into, 2, checksum(&into[..total]));
}

/// An error message, as this stack reads one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Error {
    /// The message's `type`: [`DESTINATION_UNREACHABLE`] for the one this
    /// stack acts on.
    pub kind: u8,
    /// The `code` that says why, such as [`PORT_UNREACHABLE`] or
    /// [`FRAGMENTATION_NEEDED`].
    pub code: u8,
    /// The next hop's MTU, when this message is the one that states it.
    ///
    /// `None` for every code but [`FRAGMENTATION_NEEDED`], because the four
    /// bytes that hold it are unused in every other error and a value read
    /// from them would be whatever the sender left there.
    pub next_hop_mtu: Option<u16>,
    /// Where the quoted original packet begins.
    pub quoted_at: usize,
    /// How many bytes of the original this message carries.
    pub quoted_len: usize,
}

/// Read an error message, or `None` when the bytes are not one this stack
/// can interpret.
///
/// The checksum is verified: an error about a datagram that is itself corrupt
/// is not an error a sender can act on, and a stack that acted on one would
/// close a connection because a stranger said so.
pub fn parse_error(message: &[u8]) -> Option<Error> {
    if message.len() < HEADER_LEN {
        return None;
    }
    if checksum(message) != 0 {
        return None;
    }
    // The MTU is read only from the one code that states one: the four bytes
    // are unused in every other error, and a value read from an unused field
    // is the sender's leftovers, not a measurement.
    let next_hop_mtu =
        if message[0] == DESTINATION_UNREACHABLE && message[1] == FRAGMENTATION_NEEDED {
            Some(get_u16(message, NEXT_HOP_MTU_AT))
        } else {
            None
        };
    Some(Error {
        kind: message[0],
        code: message[1],
        next_hop_mtu,
        quoted_at: ORIGINAL_DATAGRAM_AT,
        quoted_len: message.len() - ORIGINAL_DATAGRAM_AT,
    })
}

/// The writer both echo kinds share, so a reply this stack answers with is
/// the same bytes a request is, with the type changed.
///
/// Not `pub` yet: nothing answers a stranger's ping, and an item nothing
/// names is one a reader has to wonder about.  The socket layer's demux is
/// the change that publishes it.
fn write_echo(into: &mut [u8], kind: u8, identifier: u16, sequence: u16, data: &[u8]) {
    into[0] = kind;
    into[1] = 0;
    put_u16(into, 2, 0);
    put_u16(into, 4, identifier);
    put_u16(into, 6, sequence);
    into[HEADER_LEN..HEADER_LEN + data.len()].copy_from_slice(data);
    put_u16(into, 2, checksum(&into[..HEADER_LEN + data.len()]));
}

/// An ICMP message, as this stack reads one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Echo {
    /// `type`: [`ECHO_REQUEST`] or [`ECHO_REPLY`], for the messages this
    /// stack names.
    pub kind: u8,
    /// `code`: zero for an echo, whatever the sender meant for the rest.
    pub code: u8,
    /// The number the request chose, which the reply must carry back.
    pub identifier: u16,
    /// The exchange's position in the sender's sequence, carried back too.
    pub sequence: u16,
}

/// Read the ICMP message at the start of an IPv4 packet's payload, or `None`
/// when it is not one this stack can interpret.
///
/// The checksum is verified over the whole message, data included, the one
/// check that makes the bytes a packet claims to be the bytes they are.  The
/// data after the header is the caller's to compare: this function cannot
/// know what the sender was asked to echo, and a comparison against the
/// request it came from is the caller's own fact.
pub fn parse(message: &[u8]) -> Option<Echo> {
    if message.len() < HEADER_LEN {
        return None;
    }
    if checksum(message) != 0 {
        return None;
    }
    Some(Echo {
        kind: message[0],
        code: message[1],
        identifier: get_u16(message, 4),
        sequence: get_u16(message, 6),
    })
}

#[cfg(test)]
mod tests {
    use super::DESTINATION_UNREACHABLE;
    use super::ECHO_REPLY;
    use super::ECHO_REQUEST;
    use super::HEADER_LEN;
    use super::ORIGINAL_DATAGRAM_AT;
    use super::PORT_UNREACHABLE;
    use super::echo_len;
    use super::parse;
    use super::write_echo_request;

    /// An echo request for "protofire", exactly as the wire carries it: the
    /// same seventeen bytes the IPv4 layer's vector ends with, so the two
    /// layers agree on what one packet holds.
    ///
    /// The checksum is `0xda3d` by hand, the words `0x0800 + 0x0001 + …`
    /// sum to `0x25c2`, and the complement is the field the vector carries.
    const REQUEST: [u8; 17] = [
        0x08, 0x00, 0xda, 0x3d, // type 8, code 0, checksum
        0x00, 0x01, 0x00, 0x01, // identifier 1, sequence 1
        0x70, 0x72, 0x6f, 0x74, 0x6f, 0x66, 0x69, 0x72, 0x65, // "protofire"
    ];

    /// The reply a peer writes for that request, built by hand rather than by
    /// this module's writer, so the parser is checked against the layout and
    /// not against itself.  The type is the only field that changes, and the
    /// checksum changes with it: `0x25c2 - 0x0800 = 0x1dc2`, complemented.
    const REPLY: [u8; 17] = [
        0x00, 0x00, 0xe2, 0x3d, // type 0, code 0, checksum
        0x00, 0x01, 0x00, 0x01, // identifier 1, sequence 1
        0x70, 0x72, 0x6f, 0x74, 0x6f, 0x66, 0x69, 0x72, 0x65, // "protofire"
    ];

    /// The writer produces the request the vector holds, byte for byte.
    #[test]
    fn the_request_is_the_bytes_the_wire_carries() {
        let mut message = [0_u8; REQUEST.len()];
        write_echo_request(&mut message, 1, 1, b"protofire");
        assert_eq!(message, REQUEST);
    }

    /// A written request parses back as the echo it is, checksum and all.
    #[test]
    fn a_request_parses_back() {
        let echo = parse(&REQUEST).expect("an echo request");
        assert_eq!(echo.kind, ECHO_REQUEST);
        assert_eq!(echo.code, 0);
        assert_eq!(echo.identifier, 1);
        assert_eq!(echo.sequence, 1);
    }

    /// A peer's reply parses with its own kind, and the bytes after the
    /// header are the data the request sent.
    #[test]
    fn a_reply_parses_with_its_own_kind() {
        let echo = parse(&REPLY).expect("an echo reply");
        assert_eq!(echo.kind, ECHO_REPLY);
        assert_eq!(echo.identifier, REQUEST_ID);
        assert_eq!(echo.sequence, REQUEST_SEQUENCE);
        assert_eq!(&REPLY[HEADER_LEN..], b"protofire", "the data is echoed");
    }

    /// The message's length is its header plus its data, and the vectors
    /// agree with the arithmetic.
    #[test]
    fn the_length_is_header_plus_data() {
        assert_eq!(HEADER_LEN, 8);
        assert_eq!(echo_len(9), 17);
        assert_eq!(REQUEST.len(), echo_len(9));
        assert_eq!(REPLY.len(), echo_len(9));
    }

    /// A destination-unreachable message about the datagram `udp.rs`'s
    /// vector holds, exactly as a peer writes it: type 3, code 3, four
    /// unused bytes, and the original datagram, its IPv4 header and its
    /// UDP header, after them.
    ///
    /// The checksum is `0x32f0` by hand over the message and its embedded
    /// original together; the embedded header carries its own checksum,
    /// which this layer does not verify, the error's message is what is
    /// read here, and the embedded bytes are what the caller slices.
    const UNREACHABLE: [u8; 36] = [
        0x03, 0x03, 0x32, 0xf0, // type 3, code 3, checksum
        0x00, 0x00, 0x00, 0x00, // unused
        // The original datagram: an IPv4 header to this stack, then the
        // refused datagram's own header, source port 40000.
        0x45, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00, 0x00, 0x40, 0x11, 0x62, 0xb8, 0x0a, 0x00, 0x02,
        0x02, 0x0a, 0x00, 0x02, 0x0f, 0x9c, 0x40, 0x21, 0xa4, 0x00, 0x11, 0x0c, 0x17,
    ];

    /// An error message parses with its own kind and code, and the original
    /// datagram sits where every error message holds it.
    #[test]
    fn an_unreachable_names_the_datagram_it_is_about() {
        let message = parse(&UNREACHABLE).expect("an error message");
        assert_eq!(message.kind, DESTINATION_UNREACHABLE);
        assert_eq!(message.code, PORT_UNREACHABLE);

        // The embedded UDP header's source port is what tells the caller
        // which of its datagrams was refused; the slice is the caller's to
        // read, and the port is the one `udp.rs`'s vector was written with.
        let original = &UNREACHABLE[ORIGINAL_DATAGRAM_AT + 20..ORIGINAL_DATAGRAM_AT + 22];
        assert_eq!(original, &[0x9c, 0x40], "source port 40000, big-endian");
    }

    /// A corrupted byte refuses the message: the checksum is over the data
    /// too, so a flipped bit in the echoed bytes is not an echo this stack
    /// believes.
    #[test]
    fn a_corrupted_message_is_refused() {
        assert!(parse(&REQUEST[..HEADER_LEN - 1]).is_none(), "short");

        let mut corrupt = REQUEST;
        corrupt[HEADER_LEN] = !corrupt[HEADER_LEN];
        assert!(parse(&corrupt).is_none(), "a flipped data bit");

        let mut field = REQUEST;
        field[2] = !field[2];
        assert!(parse(&field).is_none(), "a flipped checksum bit");
    }

    /// The request's own constants, spelled once for the two tests above.
    const REQUEST_ID: u16 = 1;
    const REQUEST_SEQUENCE: u16 = 1;

    /// An error message quotes the original's header and the first eight
    /// bytes of its payload, and a sender can read its own ports back out of
    /// the quote, which is the whole reason the RFC requires it.
    #[test]
    fn an_error_quotes_the_datagram_it_is_about() {
        // A minimal original: a twenty-byte IPv4 header and a UDP header.
        let mut original_header = [0_u8; 20];
        original_header[0] = 0x45;
        original_header[9] = crate::ipv4::PROTOCOL_UDP;
        original_header[12..16].copy_from_slice(&[10, 0, 2, 15]);
        original_header[16..20].copy_from_slice(&[10, 0, 2, 2]);
        let mut original_payload = [0_u8; 12];
        original_payload[0..2].copy_from_slice(&40000u16.to_be_bytes());
        original_payload[2..4].copy_from_slice(&9u16.to_be_bytes());

        let total = super::error_len(original_header.len(), super::QUOTED_PAYLOAD);
        let mut message = [0_u8; 64];
        super::write_destination_unreachable(
            &mut message,
            super::PORT_UNREACHABLE,
            &original_header,
            &original_payload,
        );

        // The message verifies: its checksum covers the quote too.
        assert_eq!(crate::ipv4::checksum(&message[..total]), 0);
        let parsed = super::parse_error(&message[..total]).expect("an error");
        assert_eq!(parsed.kind, super::DESTINATION_UNREACHABLE);
        assert_eq!(parsed.code, super::PORT_UNREACHABLE);
        assert_eq!(parsed.quoted_len, original_header.len() + 8);

        // The ports are readable at the offset a sender knows: eight bytes of
        // quoted IP header, then the UDP header's first field.
        let quote = &message[parsed.quoted_at..parsed.quoted_at + parsed.quoted_len];
        assert_eq!(&quote[..20], &original_header, "the header came back");
        assert_eq!(&quote[20..22], &40000u16.to_be_bytes(), "the source port");
        assert_eq!(&quote[22..24], &9u16.to_be_bytes(), "the destination port");

        // The unused word is zero, which is what a peer comparing it needs.
        assert_eq!(&message[4..8], &[0, 0, 0, 0]);
    }

    /// A quote is truncated to what the RFC requires and no more, so an
    /// error about a large datagram stays small.
    #[test]
    fn an_error_quotes_only_eight_payload_bytes() {
        let header = [0_u8; 20];
        let payload = [0xAB_u8; 1500];
        let mut message = [0_u8; 1600];
        super::write_destination_unreachable(
            &mut message,
            super::PORT_UNREACHABLE,
            &header,
            &payload,
        );
        let total = super::error_len(header.len(), super::QUOTED_PAYLOAD);
        assert_eq!(total, 8 + 20 + 8);
        let parsed = super::parse_error(&message[..total]).expect("an error");
        assert_eq!(parsed.quoted_len, 28);
    }

    /// A fragmentation-needed message states the next hop's MTU, and no other
    /// code's message does.
    ///
    /// The MTU is path-MTU discovery's whole signal: a sender whose packets
    /// are too large learns nothing else, because the router's only other
    /// evidence is silence.  The test reads it back out of the bytes the
    /// sender wrote, and then asserts the negative case, which is what keeps
    /// a value from being read out of a field every other code leaves unused.
    #[test]
    fn a_fragmentation_needed_message_states_the_next_hops_mtu() {
        let header = [0x45_u8; 20];
        let payload = [0x02_u8; 8];
        let total = super::error_len(header.len(), 8);
        let mut message = [0_u8; 64];

        super::write_unreachable_with_mtu(
            &mut message,
            super::FRAGMENTATION_NEEDED,
            1_400,
            &header,
            &payload,
        );
        assert_eq!(
            crate::ipv4::checksum(&message[..total]),
            0,
            "the checksum covers the MTU field"
        );
        let parsed = super::parse_error(&message[..total]).expect("an error");
        assert_eq!(parsed.kind, super::DESTINATION_UNREACHABLE);
        assert_eq!(parsed.code, super::FRAGMENTATION_NEEDED);
        assert_eq!(parsed.next_hop_mtu, Some(1_400));

        // The same message under a code that has no meaning for those four
        // bytes reports none, whatever the sender wrote there.
        let mut other = [0_u8; 64];
        super::write_unreachable_with_mtu(
            &mut other,
            super::PORT_UNREACHABLE,
            1_400,
            &header,
            &payload,
        );
        let parsed = super::parse_error(&other[..total]).expect("an error");
        assert_eq!(
            parsed.next_hop_mtu, None,
            "an unused field is not a measurement"
        );

        // And the plain writer leaves those bytes zero, which is what the RFC
        // says an unused field is.
        let mut plain = [0_u8; 64];
        super::write_destination_unreachable(
            &mut plain,
            super::FRAGMENTATION_NEEDED,
            &header,
            &payload,
        );
        assert_eq!(
            u16::from_be_bytes([
                plain[super::NEXT_HOP_MTU_AT],
                plain[super::NEXT_HOP_MTU_AT + 1]
            ]),
            0,
            "the writer that states no MTU writes none"
        );
    }

    /// A corrupted error message is refused: a stack that acted on one would
    /// close a connection because a stranger said so.
    #[test]
    fn a_corrupted_error_is_refused() {
        let header = [0_u8; 20];
        let payload = [0x01_u8; 8];
        let mut message = [0_u8; 40];
        super::write_destination_unreachable(
            &mut message,
            super::PORT_UNREACHABLE,
            &header,
            &payload,
        );
        let total = super::error_len(header.len(), 8);
        assert!(super::parse_error(&message[..total]).is_some());

        let mut corrupt = message;
        corrupt[total - 1] ^= 0xFF;
        assert!(
            super::parse_error(&corrupt[..total]).is_none(),
            "a flipped quote byte fails the checksum"
        );
        assert!(
            super::parse_error(&message[..HEADER_LEN - 1]).is_none(),
            "short"
        );
    }
}
