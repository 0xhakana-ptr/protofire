//! net/src/udp.rs
//!
//! UDP: a datagram from a port to a port, with no connection and no delivery
//! promise.
//!
//! ## The layout
//!
//! ```text
//! IPv4    ver|ihl, tos, total_length, … protocol=17
//! UDP     source_port[2] destination_port[2] length[2] checksum[2]
//!         data[…]                                          8 bytes + data
//! ```
//!
//! ## The checksum, and why it may be zero
//!
//! The Internet checksum again, but over more than the message: a
//! pseudo-header — both IPv4 addresses, the protocol, the UDP length — goes
//! into the sum with it, which is what binds a datagram to the packet it rode
//! in on.  A datagram delivered to the wrong machine would fail a checksum
//! the message alone would pass, which is why the verification takes the
//! packet's own addresses and not the datagram alone.
//!
//! Zero is special twice, and both are RFC 768's own rule: a computed
//! checksum of zero is transmitted as all ones, because a zero field would
//! read as "no checksum"; and a zero field received means the sender chose
//! not to checksum, which this stack accepts rather than refuses — a
//! datagram's delivery was never promised, and a sender who skipped the sum
//! said so.  [`Datagram::checksummed`] is how a caller knows which it got.
//!
//! ## What is deliberately not here
//!
//! Ports this stack refuses, port unreachables it answers, and anything that
//! remembers a peer: those are the socket layer's, which is where a bound
//! port and its queue live.  This module is the datagram's shape and its
//! arithmetic.

use crate::ethernet::get_u16;
use crate::ethernet::put_u16;
use crate::ipv4::PROTOCOL_UDP;
use crate::ipv4::checksum_of;

/// The UDP header's length, before the datagram's data.
pub const HEADER_LEN: usize = 8;

/// How long a datagram is, header and data.
pub const fn datagram_len(data_len: usize) -> usize {
    HEADER_LEN + data_len
}

/// A UDP datagram, as this stack reads one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Datagram {
    /// The port the datagram claims to come from.
    pub source_port: u16,
    /// The port the datagram is going to.
    pub destination_port: u16,
    /// How many data bytes the datagram carries.
    pub payload_len: usize,
    /// Whether the sender checksummed the datagram: a zero field means it
    /// did not, and a caller that relies on the sum should know that.
    pub checksummed: bool,
}

/// Write a datagram: header, data, and the checksum over both and the
/// pseudo-header their packet names.
///
/// The caller's buffer is the datagram's: [`datagram_len`] bytes, written at
/// the start of `into` — the offset in an IPv4 packet's payload a sender
/// hands this.  A computed checksum of zero goes on the wire as all ones,
/// which is the rule that keeps a zero field meaning "not computed".
pub fn write_datagram(
    into: &mut [u8],
    source: [u8; 4],
    destination: [u8; 4],
    source_port: u16,
    destination_port: u16,
    data: &[u8],
) {
    let length = datagram_len(data.len()) as u16;
    put_u16(into, 0, source_port);
    put_u16(into, 2, destination_port);
    put_u16(into, 4, length);
    put_u16(into, 6, 0);
    into[HEADER_LEN..HEADER_LEN + data.len()].copy_from_slice(data);
    let sum = checksum_of(&[
        &pseudo_header(source, destination, length),
        &into[..length as usize],
    ]);
    // Zero means "no checksum" on the wire, so a sum that came out zero is
    // sent as all ones, which verifies to zero like any other honest sum.
    put_u16(into, 6, if sum == 0 { 0xFFFF } else { sum });
}

/// The twelve bytes the checksum sums before the datagram: both addresses, a
/// zero byte, the protocol, and the UDP length.
fn pseudo_header(source: [u8; 4], destination: [u8; 4], length: u16) -> [u8; 12] {
    let mut header = [0_u8; 12];
    header[0..4].copy_from_slice(&source);
    header[4..8].copy_from_slice(&destination);
    header[8] = 0;
    header[9] = PROTOCOL_UDP;
    header[10..12].copy_from_slice(&length.to_be_bytes());
    header
}

/// Read the datagram at the start of an IPv4 packet's payload, or `None`
/// when it is not one this stack can interpret.
///
/// `source` and `destination` are the packet's own addresses, which the
/// checksum's pseudo-header needs.  The datagram's own length field sizes
/// the sum, because a packet may carry padding past it; a length that
/// disagrees with the packet — shorter than the header, longer than the
/// bytes the packet holds — is a datagram this stack refuses rather than
/// reads at offsets that mean something else.
pub fn parse(packet: &[u8], source: [u8; 4], destination: [u8; 4]) -> Option<Datagram> {
    if packet.len() < HEADER_LEN {
        return None;
    }
    let length = get_u16(packet, 4) as usize;
    if length < HEADER_LEN || length > packet.len() {
        return None;
    }
    let field = get_u16(packet, 6);
    let checksummed = field != 0;
    if checksummed
        && checksum_of(&[
            &pseudo_header(source, destination, length as u16),
            &packet[..length],
        ]) != 0
    {
        return None;
    }

    Some(Datagram {
        source_port: get_u16(packet, 0),
        destination_port: get_u16(packet, 2),
        payload_len: length - HEADER_LEN,
        checksummed,
    })
}

#[cfg(test)]
mod tests {
    use super::HEADER_LEN;
    use super::datagram_len;
    use super::parse;
    use super::write_datagram;

    const US: [u8; 4] = [10, 0, 2, 15];
    const GATEWAY: [u8; 4] = [10, 0, 2, 2];
    const OUR_PORT: u16 = 40000;
    const THEIR_PORT: u16 = 8612;

    /// A datagram from this stack's port to a port nothing owns, exactly as
    /// the wire carries it: the datagram the boot's own probe sends.
    ///
    /// The checksum is `0x0c17` by hand — the pseudo-header's words
    /// `0x0a00 + 0x020f + 0x0a00 + 0x0202 + 0x0011 + 0x0011` and the
    /// datagram's own sum to `0xf3e8`, and the complement is the field.
    const DATAGRAM: [u8; 17] = [
        0x9c, 0x40, 0x21, 0xa4, // source port 40000, destination port 8612
        0x00, 0x11, 0x0c, 0x17, // length 17, checksum
        0x70, 0x72, 0x6f, 0x74, 0x6f, 0x66, 0x69, 0x72, 0x65, // "protofire"
    ];

    /// The writer produces the datagram the vector holds, byte for byte.
    #[test]
    fn the_datagram_is_the_bytes_the_vector_carries() {
        let mut datagram = [0_u8; DATAGRAM.len()];
        write_datagram(
            &mut datagram,
            US,
            GATEWAY,
            OUR_PORT,
            THEIR_PORT,
            b"protofire",
        );
        assert_eq!(datagram, DATAGRAM);
    }

    /// A written datagram parses back as the datagram it is, checksum and
    /// all, bound to the packet's own addresses.
    #[test]
    fn a_datagram_parses_back() {
        let parsed = parse(&DATAGRAM, US, GATEWAY).expect("a datagram");
        assert_eq!(parsed.source_port, OUR_PORT);
        assert_eq!(parsed.destination_port, THEIR_PORT);
        assert_eq!(parsed.payload_len, 9);
        assert!(parsed.checksummed, "the writer checksummed it");
    }

    /// The same datagram verified against a stranger's packet is refused:
    /// the pseudo-header binds the datagram to the addresses it rode in
    /// with, which is the protection the message's own checksum could not
    /// give.
    ///
    /// The one miss is a swapped pair, and it is the algorithm's own blind
    /// spot rather than this parser's: the sum is additive, so `a → b` and
    /// `b → a` sum identically and a swap is invisible to the checksum.
    /// Keeping a datagram out of the wrong conversation is the demux's job —
    /// the layer that reads the packet's addresses and hands the datagram to
    /// the port it was sent to.
    #[test]
    fn a_datagram_verified_against_the_wrong_packet_is_refused() {
        assert!(
            parse(&DATAGRAM, US, [10, 0, 2, 3]).is_none(),
            "a stranger's address"
        );
        assert!(
            parse(&DATAGRAM, US, GATEWAY).is_some(),
            "and the right one still verifies"
        );
    }

    /// A zero checksum field is the sender's declared choice, and the
    /// datagram parses without a sum.
    #[test]
    fn a_zero_checksum_is_accepted_as_a_choice() {
        let mut unchecked = DATAGRAM;
        unchecked[6] = 0;
        unchecked[7] = 0;
        let parsed = parse(&unchecked, US, GATEWAY).expect("a datagram");
        assert!(!parsed.checksummed, "the sender said it did not sum");
    }

    /// A corrupted datagram is refused, and a corrupted unchecked one is
    /// not — which is exactly the protection the zero field says is absent.
    #[test]
    fn a_checksum_refuses_corruption_and_zero_does_not() {
        let mut corrupt = DATAGRAM;
        corrupt[HEADER_LEN] = !corrupt[HEADER_LEN];
        assert!(parse(&corrupt, US, GATEWAY).is_none(), "corrupt data");

        let mut unchecked = corrupt;
        unchecked[6] = 0;
        unchecked[7] = 0;
        assert!(
            parse(&unchecked, US, GATEWAY).is_some(),
            "no sum, no refusal"
        );
    }

    /// The datagram's length is its header plus its data, and a length field
    /// that disagrees with the packet is refused rather than read past.
    #[test]
    fn a_length_field_past_the_packet_is_refused() {
        assert_eq!(datagram_len(9), 17);
        assert_eq!(DATAGRAM.len(), datagram_len(9));

        let mut overlong = DATAGRAM;
        overlong[4] = 0x40;
        assert!(parse(&overlong, US, GATEWAY).is_none(), "past the packet");

        let mut underlength = DATAGRAM;
        underlength[5] = 0x00;
        assert!(
            parse(&underlength, US, GATEWAY).is_none(),
            "under the header"
        );

        assert!(
            parse(&DATAGRAM[..HEADER_LEN - 1], US, GATEWAY).is_none(),
            "short"
        );
    }

    /// A datagram the packet holds more of parses to the length the sender
    /// claimed: a packet may carry padding past the datagram, and the
    /// padding is not data.
    #[test]
    fn the_padding_past_the_datagram_is_not_data() {
        let mut packet = [0xEE_u8; 32];
        packet[..DATAGRAM.len()].copy_from_slice(&DATAGRAM);
        let parsed = parse(&packet, US, GATEWAY).expect("a datagram");
        assert_eq!(parsed.payload_len, 9, "the sender's claim, not the packet");
    }
}
