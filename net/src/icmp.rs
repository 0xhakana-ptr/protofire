//! net/src/icmp.rs
//!
//! ICMP: the control messages the wire sends about itself, as far as this
//! stack needs them — an echo request out, an echo reply back.
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
//! another machine built — not its own output read back through its own
//! parser.  QEMU's user-mode network answers a ping for its gateway without
//! being asked to, which is what makes the exchange a real one on every
//! machine this tree boots.
//!
//! ## What is not here yet
//!
//! The error messages a stack is asked about — destination unreachable, time
//! exceeded — and the answer to a stranger's ping.  The first arrives with the
//! UDP layer, which is the protocol that makes an unbound port a thing to
//! report; the second needs a demux that answers, which is the socket layer's
//! shape and not this module's.

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

/// How long an echo message is, header and data.
pub const fn echo_len(data_len: usize) -> usize {
    HEADER_LEN + data_len
}

/// Write an echo request: `identifier` and `sequence` name the exchange, and
/// `data` is what the reply must hold.
///
/// The caller's buffer is the message's: `HEADER_LEN + data.len()` bytes,
/// which is what [`echo_len`] answers.  The checksum is computed over the
/// whole message — type and code included — which is why the field is zeroed
/// before the sum and written after it.
pub fn write_echo_request(into: &mut [u8], identifier: u16, sequence: u16, data: &[u8]) {
    write_echo(into, ECHO_REQUEST, identifier, sequence, data);
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
/// The checksum is verified over the whole message, data included — the one
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
    use super::ECHO_REPLY;
    use super::ECHO_REQUEST;
    use super::HEADER_LEN;
    use super::echo_len;
    use super::parse;
    use super::write_echo_request;

    /// An echo request for "protofire", exactly as the wire carries it: the
    /// same seventeen bytes the IPv4 layer's vector ends with, so the two
    /// layers agree on what one packet holds.
    ///
    /// The checksum is `0xda3d` by hand — the words `0x0800 + 0x0001 + …`
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
}
