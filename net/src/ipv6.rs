//! net/src/ipv6.rs
//!
//! IPv6: the packet every protocol above the frame rides in, the extension
//! headers a sender may stack between its header and its payload, and the
//! pseudo-header checksum its upper layers carry.
//!
//! ## The layout
//!
//! ```text
//! Ethernet  dst[6] src[6] ethertype=0x86DD        14 bytes
//! IPv6      ver|tc|flow[4] payload_length[2]
//!           next_header[1] hop_limit[1]
//!           source[16] destination[16]           40 bytes
//! payload                                        what next_header names
//! ```
//!
//! ## No checksum in the header, and where the checksum went
//!
//! IPv6 has no header checksum: the link layer and the transports each check
//! their own bytes, and a router no longer rewrites a field that has to be
//! summed again.  What IPv6 *did* keep is the **pseudo-header**, which its
//! upper layers sum in front of their own bytes — the source, the
//! destination, the upper-layer length and the next-header value.  It is
//! forty bytes and it exists so that a datagram delivered to the wrong
//! address fails its checksum rather than being read as someone else's.
//!
//! [`checksum_with_pseudo`] is that sum.  A caller appends its own bytes to
//! the pseudo-header and takes the complement, which is exactly what
//! [`crate::udp`] and [`crate::tcp`]'s checksum functions do for IPv4 with a
//! twelve-byte preamble instead.
//!
//! ## Extension headers are a chain, and this walks it
//!
//! `next_header` 0, 43, 44, 51 and 60 all mean "another header follows, and
//! the first byte of *that* header is the next hop in the chain".  A reader
//! that stopped at the base header would hand a transport the extension
//! header's bytes as its payload — a TCP segment whose ports are a hop-by-hop
//! header is a segment this stack would answer with nonsense.  [`walk`]
//! follows the chain to the first header that is not one of them, and answers
//! where the real payload starts.
//!
//! What this driver does *not* interpret is the content of those headers: a
//! routing header's segments, an authentication header's SPI, a
//! destination-options header's options.  It skips them by their own length
//! fields, which is what a host that is not a router and not an endpoint's
//! policy engine has any business doing.
//!
//! ## Fragmentation
//!
//! A fragment header is one the chain carries, and a fragment is a packet
//! this stack reads only when it is whole: [`walk`] answers [`Next::Fragment`]
//! with the fragment's own fields so a caller can decide, and this crate has
//! no reassembly buffer.  The reason is the one IPv4's module gives — nothing
//! above this layer has asked for one, and a reassembly buffer is a
//! per-sender table with a timer, not a parse.
//!
//! ## Addresses
//!
//! Sixteen bytes, and the three shapes a stack that has not been given a
//! global address needs: the unspecified address, the all-nodes multicast
//! group every interface joins, and the link-local address a MAC address
//! derives by EUI-64.  The last is what makes a machine reachable on its own
//! wire before a router has said anything, and it is the address this stack's
//! own boot uses.

use crate::ethernet::get_u16;
use crate::ethernet::put_u16;

/// An IPv6 address: sixteen octets (RFC 8200 §2.5).
pub type Addr = [u8; 16];

/// The IPv6 header's length, with no extension headers.
pub const HEADER_LEN: usize = 40;

/// The smallest MTU every IPv6 link must carry (RFC 8200 §5).
///
/// A packet larger than this is the sender's to fragment; one smaller than it
/// is a link IPv6 does not allow, and this stack writes nothing smaller.
pub const MIN_MTU: usize = 1280;

/// The hop limit a sender with no opinion writes.
///
/// 64 is what a host uses; a router decrements it and a packet whose hop
/// limit reaches zero is dropped with an ICMPv6 time-exceeded.
pub const HOP_LIMIT: u8 = 64;

/// The `next_header` value for a fragment header.
pub const NEXT_FRAGMENT: u8 = 44;
/// The `next_header` value for ICMPv6.
pub const NEXT_ICMPV6: u8 = 58;
/// The `next_header` value for TCP.
pub const NEXT_TCP: u8 = 6;
/// The `next_header` value for UDP.
pub const NEXT_UDP: u8 = 17;

/// Whether `next_header` names a header the chain walks through rather than
/// a protocol that consumes the payload.
///
/// Hop-by-hop (0), routing (43), fragment (44), authentication (51),
/// destination options (60) and mobility (135) all carry a next-header byte
/// of their own.  ESP (50) does not: its payload is encrypted and its length
/// is the packet's, so there is nothing left for a reader to walk.
pub const fn is_extension(next_header: u8) -> bool {
    matches!(next_header, 0 | 43 | 44 | 51 | 60 | 135)
}

/// An IPv6 header, as this stack reads one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub source: Addr,
    pub destination: Addr,
    /// The value the base header carries; an extension header may have
    /// replaced it by the time a transport sees it, which is what [`walk`]
    /// answers.
    pub next_header: u8,
    pub hop_limit: u8,
    /// The traffic class, eight bits: the six-bit DSCP and the two-bit ECN
    /// field as the format packs them.
    pub traffic_class: u8,
    /// The flow label, twenty bits.
    pub flow_label: u32,
}

/// A parsed packet: the header's fields, and where the payload the base
/// header names begins.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet {
    pub header: Header,
    /// Where bytes the base header calls "payload" begin: always
    /// [`HEADER_LEN`], because the base header is fixed and every other
    /// header is *inside* the payload it counts.
    pub payload_at: usize,
    /// How many payload bytes `payload_length` claimed, extension headers
    /// included.
    pub payload_len: usize,
}

/// What the chain of extension headers leads to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// A protocol that consumes the payload, at this offset with these many
    /// bytes left.  `next_header` is the value that named it.
    Payload {
        next_header: u8,
        at: usize,
        len: usize,
    },
    /// A fragment header, and the fragment it describes.
    ///
    /// The chain stops here: what follows is a piece of a packet, and reading
    /// a piece as a whole is how a stack answers with a truncated segment
    /// that looks complete.  `at` and `len` are the *fragment's* bytes, which
    /// is what a reassembly buffer would collect.
    Fragment {
        /// The value the fragment header's own `next_header` byte carries,
        /// which is the header of the whole packet this is a piece of.
        next_header: u8,
        /// The offset of this piece in the original packet, in eight-octet
        /// units, already multiplied by eight.
        offset: u32,
        /// Whether more pieces follow; the last one is the only one that can
        /// be read alone.
        more: bool,
        /// The identification every piece of one packet shares.
        identification: u32,
        at: usize,
        len: usize,
    },
}

/// Write the forty bytes that carry `payload_len` bytes from `source` to
/// `destination`.
///
/// The payload is not written: a caller that already has its bytes wants the
/// header in front of what it is about to write, the same arrangement the
/// IPv4 and Ethernet header writers make.  No checksum is computed because
/// the header has none.
pub fn write_header(
    packet: &mut [u8],
    source: Addr,
    destination: Addr,
    next_header: u8,
    payload_len: usize,
) {
    write_header_classified(packet, source, destination, next_header, payload_len, 0, 0);
}

/// The same header, with a traffic class and a flow label.
///
/// The two are packed into the first four bytes — version in the top four
/// bits, then the class's high four, then the class's low four and the flow
/// label's high four, then the label's low sixteen — which is the format's
/// arrangement and not a choice.
pub fn write_header_classified(
    packet: &mut [u8],
    source: Addr,
    destination: Addr,
    next_header: u8,
    payload_len: usize,
    traffic_class: u8,
    flow_label: u32,
) {
    let flow = flow_label & 0x000F_FFFF;
    packet[0] = 0x60 | (traffic_class >> 4);
    packet[1] = ((traffic_class & 0x0F) << 4) | ((flow >> 16) as u8 & 0x0F);
    packet[2] = (flow >> 8) as u8;
    packet[3] = flow as u8;
    put_u16(packet, 4, payload_len as u16);
    packet[6] = next_header;
    packet[7] = HOP_LIMIT;
    packet[8..24].copy_from_slice(&source);
    packet[24..40].copy_from_slice(&destination);
}

/// Read the packet at the start of a frame, or `None` when it is not one this
/// stack can interpret.
///
/// Four things are refused, each because reading past it would be reading
/// bytes that mean something else: a frame shorter than a header, a version
/// that is not 6, a payload length larger than the frame, and a destination
/// this stack does not answer for ([`is_for`] is the caller's check, because
/// only the caller knows the addresses this machine holds).
pub fn parse(frame: &[u8]) -> Option<Packet> {
    if frame.len() < HEADER_LEN {
        return None;
    }
    if frame[0] >> 4 != 6 {
        return None;
    }
    let payload_len = get_u16(frame, 4) as usize;
    if HEADER_LEN + payload_len > frame.len() {
        return None;
    }

    let flow_label = ((frame[1] as u32 & 0x0F) << 16) | ((frame[2] as u32) << 8) | frame[3] as u32;
    let traffic_class = ((frame[0] & 0x0F) << 4) | (frame[1] >> 4);

    let mut source = [0_u8; 16];
    source.copy_from_slice(&frame[8..24]);
    let mut destination = [0_u8; 16];
    destination.copy_from_slice(&frame[24..40]);

    Some(Packet {
        header: Header {
            source,
            destination,
            next_header: frame[6],
            hop_limit: frame[7],
            traffic_class,
            flow_label,
        },
        payload_at: HEADER_LEN,
        payload_len,
    })
}

/// Follow the extension-header chain from a parsed packet to what consumes
/// its payload.
///
/// Each header in the chain starts with a next-header byte, and each except
/// the fragment header holds its own length.  The two length encodings in the
/// chain are the format's: hop-by-hop, routing and destination-options count
/// **eight-octet units past the first eight bytes**, so a length byte of 0 is
/// eight bytes and 1 is sixteen; the authentication header counts
/// **four-octet units past the first eight**, and the fragment header is
/// eight bytes always.
///
/// `None` is a chain this parser cannot follow: a header running past the
/// packet, a header shorter than its own header is, or a chain longer than
/// [`MAX_CHAIN`] headers.  A truncated chain is refused rather than guessed
/// at, because the bytes after it are not reachable by arithmetic.
pub fn walk(frame: &[u8], packet: &Packet) -> Option<Next> {
    let mut next_header = packet.header.next_header;
    let mut at = packet.payload_at;
    let end = packet.payload_at + packet.payload_len;

    for _ in 0..MAX_CHAIN {
        if !is_extension(next_header) {
            return Some(Next::Payload {
                next_header,
                at,
                len: end.checked_sub(at)?,
            });
        }
        if at + 2 > end {
            return None;
        }
        let header_next = frame[at];

        if next_header == NEXT_FRAGMENT {
            // Always eight bytes: next_header, a reserved byte, the offset and
            // the more-fragments bit, then the identification.
            if at + FRAGMENT_HEADER_LEN > end {
                return None;
            }
            let offset_field = get_u16(frame, at + 2);
            return Some(Next::Fragment {
                next_header: header_next,
                offset: u32::from((offset_field >> 3) & 0x1FFF) * 8,
                more: offset_field & 1 != 0,
                identification: u32::from_be_bytes([
                    frame[at + 4],
                    frame[at + 5],
                    frame[at + 6],
                    frame[at + 7],
                ]),
                at: at + FRAGMENT_HEADER_LEN,
                len: end - (at + FRAGMENT_HEADER_LEN),
            });
        }

        // The authentication header counts four-octet units past its first
        // eight bytes; everything else in the chain counts eight-octet units.
        let units = frame[at + 1] as usize;
        let header_len = if next_header == 51 {
            (units + 2) * 4
        } else {
            (units + 1) * 8
        };
        if header_len < 8 || at + header_len > end {
            return None;
        }
        at += header_len;
        next_header = header_next;
    }

    None
}

/// How many extension headers a chain may hold before this reader stops.
///
/// A chain is a linked list with no bound of its own, and a packet whose
/// headers point at each other is a reader that never returns.  Eight is more
/// than any sender writes — RFC 8200's own examples use two — and few enough
/// that the walk is bounded by arithmetic rather than by trust.
pub const MAX_CHAIN: usize = 8;

/// The fragment header's fixed length.
pub const FRAGMENT_HEADER_LEN: usize = 8;

/// Write an eight-byte fragment header in front of a piece of a packet.
///
/// `offset` is in bytes and must be a multiple of eight; `more` says whether
/// another piece follows, which is what makes every piece but the last
/// unreadable alone.
pub fn write_fragment_header(
    into: &mut [u8],
    next_header: u8,
    offset: u32,
    more: bool,
    identification: u32,
) {
    into[0] = next_header;
    into[1] = 0; // reserved
    let offset_field = (((offset / 8) & 0x1FFF) as u16) << 3 | u16::from(more);
    put_u16(into, 2, offset_field);
    into[4..8].copy_from_slice(&identification.to_be_bytes());
}

/// The pseudo-header checksum over an upper-layer protocol's bytes.
///
/// The forty bytes IPv6 sums instead of a header checksum: the source, the
/// destination, the upper-layer length and the next-header value, then the
/// protocol's own bytes.  The answer is already complemented and ready to
/// write into the protocol's checksum field — the same contract
/// [`crate::ipv4::checksum`] has.
///
/// The length in the pseudo-header is `bytes.len()`, which is why this takes
/// the whole buffer: a caller that summed its header and payload as separate
/// pieces would still need the one total, and handing the total in beside
/// pieces is how the wrong one gets used.
pub fn checksum_with_pseudo(source: Addr, destination: Addr, next_header: u8, bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    sum = add_bytes(sum, &source);
    sum = add_bytes(sum, &destination);
    sum = add_bytes(sum, &(bytes.len() as u32).to_be_bytes());
    sum = add_bytes(sum, &[0, 0, 0, next_header]);
    sum = add_bytes(sum, bytes);
    finish(sum)
}

/// Add a whole number of bytes to a running checksum sum.
///
/// This is the primitive, and it is deliberately the *only* one: a checksum
/// is a sum of sixteen-bit words over one buffer, so **the buffer's length
/// decides where its last word ends**.  A function that let a caller hand in
/// pieces would have to know whether a piece's trailing byte is the high half
/// of a word continued in the next piece or the padded end of the last one —
/// a fact no piece carries.
///
/// So a caller with several pieces concatenates them, or calls this on each
/// in a way that keeps every piece an even number of bytes except the last.
/// The pseudo-header this module writes is forty bytes and every protocol
/// header it sums is even, so the only odd length is at the very end, where
/// the pad is what the format means.
pub fn add_bytes(mut sum: u32, bytes: &[u8]) -> u32 {
    let (words, rest) = bytes.as_chunks::<2>();
    for word in words {
        sum += u32::from(u16::from_be_bytes(*word));
    }
    if let [last] = rest {
        // The final odd byte is the high half of a word whose low half is
        // zero, which is the format's padding and not a mistake.
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    sum
}

/// Fold the carries and take the one's complement.
pub fn finish(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Whether a packet was sent to `address`, to a multicast group this
/// interface joined, or to the all-nodes group every interface is in.
///
/// `joined` is the multicast groups a caller holds, which this module has no
/// opinion about: a boot's own interface joins the all-nodes group and the
/// solicited-node group of each address it takes, and the caller is what
/// knows which.
pub fn is_for(packet: &Packet, address: Addr, joined: &[Addr]) -> bool {
    if packet.header.destination == address
        || packet.header.destination == ALL_NODES_MULTICAST
        || packet.header.destination == ALL_ROUTERS_MULTICAST
    {
        return true;
    }
    joined.contains(&packet.header.destination)
}

// ── addresses ────────────────────────────────────────────────────────────

/// The unspecified address, `::`.
pub const UNSPECIFIED: Addr = [0_u8; 16];

/// `ff02::1`, every node on the link.
pub const ALL_NODES_MULTICAST: Addr = [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01];

/// `ff02::2`, every router on the link.
pub const ALL_ROUTERS_MULTICAST: Addr = [0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02];

/// `fe80::/10`'s first two bytes: a link-local address.
pub const LINK_LOCAL_TOP: [u8; 2] = [0xFE, 0x80];

/// `ff02::1:ff00::/104`'s first twelve bytes, then a target's low three.
///
/// The solicited-node multicast address a host listens on for the neighbour
/// solicitation of one of its own addresses, which is how a link with a
/// hundred hosts answers one solicitation without a hundred nodes reading it.
pub fn solicited_node(target: Addr) -> Addr {
    let mut group = [0_u8; 16];
    group[0] = 0xFF;
    group[1] = 0x02;
    group[11] = 0x01;
    group[12] = 0xFF;
    group[13..16].copy_from_slice(&target[13..16]);
    group
}

/// The link-local address a MAC address derives by EUI-64 (RFC 4291's
/// modified EUI-64, as RFC 2464 applies it to Ethernet).
///
/// The interface identifier is the MAC's three bytes, `FF:FE`, the MAC's last
/// three — and the universal/local bit of the first byte **inverted**, which
/// is what tells a reader that the address was derived from a hardware
/// address rather than assigned by an administrator.  The answer is
/// `fe80::` plus that identifier.
pub fn link_local_from_mac(mac: [u8; 6]) -> Addr {
    let mut address = [0_u8; 16];
    address[0] = LINK_LOCAL_TOP[0];
    address[1] = LINK_LOCAL_TOP[1];
    // The 64-bit interface identifier: 00..00 in the top half of the address
    // is where the subnet prefix ends, so the identifier starts at byte 8.
    address[8] = mac[0] ^ 0x02;
    address[9] = mac[1];
    address[10] = mac[2];
    address[11] = 0xFF;
    address[12] = 0xFE;
    address[13] = mac[3];
    address[14] = mac[4];
    address[15] = mac[5];
    address
}

/// Whether an address is one of the link's own: `fe80::/10`.
pub fn is_link_local(address: Addr) -> bool {
    address[0] == LINK_LOCAL_TOP[0] && (address[1] & 0xC0) == LINK_LOCAL_TOP[1]
}

/// Whether an address is multicast: `ff00::/8`.
pub fn is_multicast(address: Addr) -> bool {
    address[0] == 0xFF
}

/// The Ethernet address a multicast IPv6 address maps to (RFC 2464 §7).
///
/// The first two bytes are `33:33`, and the last four are the group's last
/// four — a mapping that drops the group's middle eight bytes, which is why
/// only thirty-two bits of a multicast group reach the wire.
pub fn multicast_mac(address: Addr) -> [u8; 6] {
    [
        0x33,
        0x33,
        address[12],
        address[13],
        address[14],
        address[15],
    ]
}

#[cfg(test)]
mod tests {
    //! The tests for this module.
    //!
    //! IPv6's header, the extension-header chain, the pseudo-header checksum,
    //! and the addresses a stack derives rather than asks for.
    //!
    //! Everything is built by hand from the field offsets the format gives: a
    //! parser that read the wrong offset would read a number the builder did
    //! not write, which is the whole point of writing the bytes here.

    use super::ALL_NODES_MULTICAST;
    use super::FRAGMENT_HEADER_LEN;
    use super::HEADER_LEN;
    use super::HOP_LIMIT;
    use super::MIN_MTU;
    use super::NEXT_FRAGMENT;
    use super::NEXT_ICMPV6;
    use super::NEXT_TCP;
    use super::NEXT_UDP;
    use super::Next;
    use super::checksum_with_pseudo;
    use super::is_extension;
    use super::is_for;
    use super::is_link_local;
    use super::is_multicast;
    use super::link_local_from_mac;
    use super::multicast_mac;
    use super::parse;
    use super::solicited_node;
    use super::walk;
    use super::write_fragment_header;
    use super::write_header;
    use alloc::vec;
    use alloc::vec::Vec;

    /// A frame holding an IPv6 header and `payload`, with the source and
    /// destination a test names.
    fn frame(source: [u8; 16], destination: [u8; 16], next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0_u8; HEADER_LEN + payload.len()];
        write_header(&mut bytes, source, destination, next_header, payload.len());
        bytes[HEADER_LEN..].copy_from_slice(payload);
        bytes
    }

    /// The header's fields are the ones the builder wrote, in the offsets the
    /// format names.
    #[test]
    fn a_header_is_decoded_from_its_fields() {
        let source = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8];
        let destination = super::ALL_NODES_MULTICAST;
        let bytes = frame(source, destination, NEXT_ICMPV6, b"hello");
        let packet = parse(&bytes).expect("a header this stack wrote");

        assert_eq!(packet.header.source, source);
        assert_eq!(packet.header.destination, destination);
        assert_eq!(packet.header.next_header, NEXT_ICMPV6);
        assert_eq!(packet.header.hop_limit, HOP_LIMIT);
        assert_eq!(packet.payload_at, HEADER_LEN);
        assert_eq!(packet.payload_len, 5);
        assert_eq!(&bytes[packet.payload_at..][..packet.payload_len], b"hello");
    }

    /// Version 4's frame is not this parser's, and neither is one that ends
    /// before the payload length says it does.
    #[test]
    fn a_frame_that_is_not_this_protocol_is_refused() {
        let mut bytes = frame([0; 16], [0; 16], NEXT_UDP, b"x");
        bytes[0] = 0x45; // version 4
        assert_eq!(parse(&bytes), None);

        let bytes = frame([0; 16], [0; 16], NEXT_UDP, b"xy");
        assert_eq!(parse(&bytes[..HEADER_LEN + 1]), None, "a short frame");
        assert_eq!(parse(&bytes[..HEADER_LEN - 1]), None, "a short header");
    }

    /// The traffic class and the flow label share the first four bytes, and
    /// a caller that writes them gets them back.
    #[test]
    fn the_traffic_class_and_flow_label_round_trip() {
        let mut bytes = [0_u8; HEADER_LEN];
        super::write_header_classified(&mut bytes, [0; 16], [0; 16], NEXT_TCP, 0, 0xB8, 0x12345);
        let packet = parse(&bytes).expect("a header");
        assert_eq!(packet.header.traffic_class, 0xB8);
        assert_eq!(packet.header.flow_label, 0x12345);
    }

    /// A packet with no extension header reaches its payload on the first
    /// step of the walk.
    #[test]
    fn a_bare_packet_reaches_its_payload_at_once() {
        let bytes = frame([0; 16], [0; 16], NEXT_UDP, b"datagram");
        let packet = parse(&bytes).expect("a header");
        assert_eq!(
            walk(&bytes, &packet),
            Some(Next::Payload {
                next_header: NEXT_UDP,
                at: HEADER_LEN,
                len: 8,
            })
        );
    }

    /// A hop-by-hop header is eight bytes when its length byte is zero, and
    /// sixteen when it is one — the unit is eight octets past the first
    /// eight, which is the format's own arithmetic and the one an off-by-one
    /// gets wrong.
    #[test]
    fn a_hop_by_hop_header_is_skipped_by_its_own_length() {
        // Next header UDP, length byte 0: eight bytes total.
        let mut payload = vec![NEXT_UDP, 0, 1, 4, 0, 0, 0, 0];
        payload.extend_from_slice(b"data");
        let bytes = frame([0; 16], [0; 16], 0, &payload);
        let packet = parse(&bytes).expect("a header");
        assert_eq!(
            walk(&bytes, &packet),
            Some(Next::Payload {
                next_header: NEXT_UDP,
                at: HEADER_LEN + 8,
                len: 4,
            })
        );

        // Length byte 1: sixteen bytes total, so the payload starts later.
        let mut payload = vec![NEXT_UDP, 1];
        payload.extend_from_slice(&[0; 14]);
        payload.extend_from_slice(b"data");
        let bytes = frame([0; 16], [0; 16], 0, &payload);
        let packet = parse(&bytes).expect("a header");
        assert_eq!(
            walk(&bytes, &packet),
            Some(Next::Payload {
                next_header: NEXT_UDP,
                at: HEADER_LEN + 16,
                len: 4,
            })
        );
    }

    /// The authentication header counts four-octet units instead, and a
    /// reader that used the eight-octet rule on it would walk sixteen bytes
    /// into a header that is twelve.
    #[test]
    fn the_authentication_header_counts_four_octet_units() {
        // Length byte 1: (1 + 2) * 4 = twelve bytes.
        let mut payload = vec![NEXT_UDP, 1];
        payload.extend_from_slice(&[0; 10]);
        payload.extend_from_slice(b"data");
        let bytes = frame([0; 16], [0; 16], 51, &payload);
        let packet = parse(&bytes).expect("a header");
        assert_eq!(
            walk(&bytes, &packet),
            Some(Next::Payload {
                next_header: NEXT_UDP,
                at: HEADER_LEN + 12,
                len: 4,
            })
        );
    }

    /// Two extension headers in a row are both walked, and the second one's
    /// own next-header byte is what names the payload.
    #[test]
    fn two_extension_headers_are_both_walked() {
        // Hop-by-hop (8 bytes) naming a destination-options header (8 bytes),
        // naming UDP.
        let mut payload = vec![60, 0];
        payload.extend_from_slice(&[0; 6]);
        payload.extend_from_slice(&[NEXT_UDP, 0]);
        payload.extend_from_slice(&[0; 6]);
        payload.extend_from_slice(b"data");
        let bytes = frame([0; 16], [0; 16], 0, &payload);
        let packet = parse(&bytes).expect("a header");
        assert_eq!(
            walk(&bytes, &packet),
            Some(Next::Payload {
                next_header: NEXT_UDP,
                at: HEADER_LEN + 16,
                len: 4,
            })
        );
    }

    /// A fragment header stops the walk and answers the piece's own fields:
    /// the offset in **bytes**, the more-fragments bit, and the
    /// identification every piece of one packet shares.
    #[test]
    fn a_fragment_header_stops_the_walk_with_its_own_fields() {
        let mut payload = vec![0_u8; FRAGMENT_HEADER_LEN];
        // The fragment's next header is UDP; offset 2 (sixteen bytes); more.
        write_fragment_header(&mut payload, NEXT_UDP, 16, true, 0xDEAD_BEEF);
        payload.extend_from_slice(b"piece");
        let bytes = frame([0; 16], [0; 16], NEXT_FRAGMENT, &payload);
        let packet = parse(&bytes).expect("a header");
        assert_eq!(
            walk(&bytes, &packet),
            Some(Next::Fragment {
                next_header: NEXT_UDP,
                offset: 16,
                more: true,
                identification: 0xDEAD_BEEF,
                at: HEADER_LEN + FRAGMENT_HEADER_LEN,
                len: 5,
            })
        );
    }

    /// A chain that runs past the packet is refused rather than read, and a
    /// chain longer than the bound stops.
    #[test]
    fn a_chain_that_does_not_fit_is_refused() {
        // A hop-by-hop header claiming sixteen bytes in a packet holding
        // eight.
        let mut payload = vec![NEXT_UDP, 1];
        payload.extend_from_slice(&[0; 6]);
        let bytes = frame([0; 16], [0; 16], 0, &payload);
        let packet = parse(&bytes).expect("a header");
        assert_eq!(
            walk(&bytes, &packet),
            None,
            "the header runs past the packet"
        );

        // Eight headers, each naming another: the ninth is past the bound.
        let mut payload = vec![0_u8; 0];
        for _ in 0..super::MAX_CHAIN + 1 {
            payload.extend_from_slice(&[0, 0]);
            payload.extend_from_slice(&[0; 6]);
        }
        let bytes = frame([0; 16], [0; 16], 0, &payload);
        let packet = parse(&bytes).expect("a header");
        assert_eq!(walk(&bytes, &packet), None, "a chain past the bound");
    }

    /// The extension set is the one the format names, and ESP is not in it:
    /// its payload is encrypted, so there is nothing for a reader to walk.
    #[test]
    fn the_extension_set_is_the_formats() {
        for header in [0_u8, 43, 44, 51, 60, 135] {
            assert!(is_extension(header), "{header} walks");
        }
        for header in [NEXT_TCP, NEXT_UDP, NEXT_ICMPV6, 50, 59] {
            assert!(!is_extension(header), "{header} consumes");
        }
    }

    /// The pseudo-header checksum verifies over what it summed: a correct sum
    /// of the same bytes including the field is zero.
    #[test]
    fn the_pseudo_header_checksum_verifies() {
        let source = super::link_local_from_mac([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        let destination = super::link_local_from_mac([0x52, 0x55, 0x0A, 0x00, 0x02, 0x02]);
        let mut udp = vec![0_u8; 8];
        // Source port 8612, destination 8613, length 8, checksum zero for now.
        udp[0..2].copy_from_slice(&8612_u16.to_be_bytes());
        udp[2..4].copy_from_slice(&8613_u16.to_be_bytes());
        udp[4..6].copy_from_slice(&8_u16.to_be_bytes());

        let checksum = checksum_with_pseudo(source, destination, NEXT_UDP, &udp);
        assert_ne!(checksum, 0, "a real datagram's checksum is not zero");
        udp[6..8].copy_from_slice(&checksum.to_be_bytes());

        // The receiver's sum over the same bytes, checksum included, is zero.
        assert_eq!(checksum_with_pseudo(source, destination, NEXT_UDP, &udp), 0);
    }

    /// An odd length is padded at its end, and only there: the sum of a
    /// buffer with a trailing byte is the sum of that buffer with a zero
    /// appended.
    #[test]
    fn an_odd_length_is_padded_at_the_end() {
        let odd = super::finish(super::add_bytes(0, b"abc"));
        let padded = super::finish(super::add_bytes(0, b"abc\0"));
        assert_eq!(odd, padded, "the pad is a zero byte, which adds nothing");
    }

    /// The sum is the same computed in one pass and in several, when every
    /// piece but the last is a whole number of words.
    #[test]
    fn the_sum_is_the_same_in_pieces() {
        let bytes = b"a datagram with an odd length";
        let whole = super::finish(super::add_bytes(0, bytes));

        let mut sum = 0_u32;
        let (head, tail) = bytes.split_at(12);
        sum = super::add_bytes(sum, head);
        sum = super::add_bytes(sum, tail);
        assert_eq!(super::finish(sum), whole);

        // Three pieces, the last one odd: still the same total.
        let mut sum = 0_u32;
        sum = super::add_bytes(sum, &bytes[..6]);
        sum = super::add_bytes(sum, &bytes[6..20]);
        sum = super::add_bytes(sum, &bytes[20..]);
        assert_eq!(super::finish(sum), whole);
    }

    /// An address this machine holds, the all-nodes group, and a group it
    /// joined are all for it; another machine's unicast address is not.
    #[test]
    fn a_packet_is_for_this_machine_or_a_group_it_joined() {
        let mine = link_local_from_mac([0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        let other = link_local_from_mac([0x52, 0x55, 0, 0x12, 0x34, 0x56]);

        let for_me = parse(&frame(other, mine, NEXT_UDP, b"")).expect("a header");
        assert!(is_for(&for_me, mine, &[]));

        let for_all = parse(&frame(other, ALL_NODES_MULTICAST, NEXT_UDP, b"")).expect("a header");
        assert!(
            is_for(&for_all, mine, &[]),
            "the all-nodes group is every node's"
        );

        let joined = solicited_node(mine);
        let for_group = parse(&frame(other, joined, NEXT_UDP, b"")).expect("a header");
        assert!(is_for(&for_group, mine, &[joined]));
        assert!(!is_for(&for_group, mine, &[]), "a group nobody joined");

        let for_other = parse(&frame(mine, other, NEXT_UDP, b"")).expect("a header");
        assert!(!is_for(&for_other, mine, &[]));
    }

    /// The link-local address is `fe80::` plus the modified EUI-64, with the
    /// universal/local bit inverted — the one bit that says the identifier
    /// came from hardware rather than an administrator.
    #[test]
    fn the_link_local_address_is_the_modified_eui_64() {
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let address = link_local_from_mac(mac);
        assert_eq!(
            address,
            [
                0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x54, 0x00, 0xFF, 0xFE, 0x12, 0x34, 0x56
            ]
        );
        assert!(is_link_local(address));
        // A global unicast address is not link-local.
        assert!(!is_link_local([
            0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
        ]));
    }

    /// The solicited-node group keeps the target's low three bytes and
    /// nothing else of it.
    #[test]
    fn the_solicited_node_group_keeps_the_low_three_bytes() {
        let target = [
            0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x54, 0, 0xFF, 0xFE, 0x12, 0x34, 0x56,
        ];
        let group = solicited_node(target);
        assert_eq!(
            group,
            [
                0xFF, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xFF, 0x12, 0x34, 0x56
            ]
        );
        assert!(is_multicast(group));
    }

    /// A multicast address's Ethernet mapping is `33:33` and the group's last
    /// four bytes, and nothing of its middle.
    #[test]
    fn the_multicast_mac_is_the_low_thirty_two_bits() {
        assert_eq!(multicast_mac(ALL_NODES_MULTICAST), [0x33, 0x33, 0, 0, 0, 1]);
        let group = solicited_node([
            0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x54, 0, 0, 0, 0x12, 0x34, 0x56,
        ]);
        assert_eq!(multicast_mac(group), [0x33, 0x33, 0xFF, 0x12, 0x34, 0x56]);
    }

    /// The minimum MTU is the format's 1280, and a header this stack writes
    /// for a packet that size is a packet a link must carry.
    #[test]
    fn the_minimum_mtu_is_what_the_format_requires() {
        assert_eq!(MIN_MTU, 1280);
        // The header is 40 and the MTU 1280, so a packet of the minimum size
        // carries 1240 bytes of payload — which is what a sender with no
        // larger MTU may write.
        assert_eq!(MIN_MTU - HEADER_LEN, 1240);
    }
}
