//! net/src/internet/ipv4.rs
//!
//! IPv4: the packet every protocol above the frame rides in, and the checksum
//! that says its bytes survived the wire.
//!
//! ## The layout
//!
//! ```text
//! Ethernet  dst[6] src[6] ethertype=0x0800        14 bytes
//! IPv4      ver|ihl[1] tos[1] total_length[2]
//!           identification[2] flags|fragment[2]
//!           ttl[1] protocol[1] checksum[2]
//!           source[4] destination[4]              20 bytes
//! payload                                        what the protocol names
//! ```
//!
//! ## Why the checksum is here and not beside each protocol
//!
//! It is one algorithm, sum the sixteen-bit words, fold the carries, take the
//! one's complement, and three protocols use it: this header over itself, and
//! UDP's and TCP's over a pseudo-header plus their own bytes.  One function in
//! one file is what keeps three protocols from carrying three copies that
//! drift, and a test vector here is a test vector for all of them.
//!
//! ## Why the reader trusts `total_length` and not the frame
//!
//! Ethernet pads short frames to sixty bytes, so the bytes after an IPv4 packet
//! are usually the sender's padding and never its payload.  A parser that sized
//! the payload from the frame would hand a protocol bytes that mean nothing,
//! and a parser that sized it from `total_length` hands it exactly what was
//! sent, which is why [`parse`] answers a payload length and leaves the
//! reading to the protocol that knows what its own bytes mean.
//!
//! ## What is deliberately not here
//!
//! Fragmentation.  Every packet this stack sends fits one frame, and a packet
//! that arrives in pieces is one this stack drops rather than reassembles
//! a fragmented packet asks for a reassembly buffer keyed on a sender's
//! identification field, and nothing above this layer has asked yet.  The
//! flags word is written with the don't-fragment bit set so a sender downstream
//! refuses with an ICMP message rather than delivering a packet this stack
//! would not reassemble.

use crate::ethernet::get_u16;
use crate::ethernet::put_u16;

/// The IPv4 header's length, with no options.
pub const HEADER_LEN: usize = 20;

/// `protocol` value 1: ICMP.
pub const PROTOCOL_ICMP: u8 = 1;

/// `protocol` value 6: TCP.
pub const PROTOCOL_TCP: u8 = 6;

/// `protocol` value 17: UDP.
pub const PROTOCOL_UDP: u8 = 17;

/// The don't-fragment flag, set on every packet this stack sends.
///
/// A packet this stack sends fits one frame, so nothing it emits ever needs
/// splitting; the bit is still the right one to set, because a path router
/// that had to split such a packet would be splitting something this stack
/// says it does not want split.
pub const FLAGS_DONT_FRAGMENT: u16 = 0x4000;

/// The more-fragments flag: this packet is a piece, and more follow.
pub const FLAGS_MORE_FRAGMENTS: u16 = 0x2000;

/// The time-to-live this stack sends with.
///
/// Sixty-four hops is the convention every general-purpose stack shares; a
/// packet this stack sends crosses at most one, the gateway, so any value
/// above one would do, and the conventional one is the one a peer's log reads
/// without surprise.
const TIME_TO_LIVE: u8 = 64;

/// The Internet checksum over `bytes`: the sum of its sixteen-bit words with
/// end-around carry, one's-complemented.
///
/// An odd length is padded with a zero byte on the right, which is the rule
/// RFC 1071 states: the last lone byte counts as the high byte of the final
/// word.  The checksum of a message with its own checksum included is zero,
/// which is how a reader verifies without recomputing what the writer wrote.
pub fn checksum(bytes: &[u8]) -> u16 {
    checksum_of(&[bytes])
}

/// The Internet checksum over pieces summed as one message.
///
/// UDP's checksum runs over a pseudo-header and the datagram after it, which
/// live in different buffers, and summing them separately is not the same as
/// summing their concatenation when a piece's length is odd, because the
/// lone byte at a boundary is the high half of a word that spans the two.
/// So the words run across the pieces here, in order, with one padding rule
/// at the very end.
pub fn checksum_of(slices: &[&[u8]]) -> u16 {
    let mut sum = 0_u32;
    let mut high: Option<u8> = None;
    for slice in slices {
        let mut index = 0;
        // A lone byte left over from the piece before pairs with this one's
        // first byte, which is the word that spans the boundary.
        if let Some(pending) = high
            && let Some(&byte) = slice.first()
        {
            sum += u16::from_be_bytes([pending, byte]) as u32;
            high = None;
            index = 1;
        }
        while index + 1 < slice.len() {
            sum += u16::from_be_bytes([slice[index], slice[index + 1]]) as u32;
            index += 2;
        }
        if index < slice.len() {
            high = Some(slice[index]);
        }
    }
    if let Some(pending) = high {
        sum += (pending as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// An IPv4 header, as this stack reads one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// The address the packet claims to come from.
    pub source: [u8; 4],
    /// The address the packet is going to.
    pub destination: [u8; 4],
    /// The protocol the payload speaks: [`PROTOCOL_ICMP`], [`PROTOCOL_TCP`],
    /// [`PROTOCOL_UDP`].
    pub protocol: u8,
    /// How many hops the packet may still cross.
    ///
    /// Kept because a **forwarder** reads it and a receiver does not: this
    /// stack sent every packet with `TIME_TO_LIVE` and never looked at an
    /// arriving one's, which is right for a host and wrong for the one place a
    /// packet is passed on.  A forwarder decrements this and drops the packet
    /// at zero rather than sending it with the count it arrived with, which is
    /// what stops a routing loop from being a loop of frames.
    pub time_to_live: u8,
}

/// A parsed packet: the header's fields, and where the payload starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet {
    pub header: Header,
    /// Where the payload begins: past the header, including its options when
    /// the sender wrote any.
    pub payload_at: usize,
    /// How many payload bytes the sender claimed.  The frame may hold more
    /// Ethernet's padding, and the claim is the one to trust.
    pub payload_len: usize,
    /// The number the sender chose to tell this packet's pieces apart, which
    /// only an unfragmented packet and a fragment's first piece agree on.
    pub identification: u16,
    /// Whether more pieces of this datagram follow.
    pub more_fragments: bool,
    /// Where this piece's payload starts in the whole datagram's payload, in
    /// bytes.  Zero for an unfragmented packet and for a datagram's first
    /// piece.
    pub fragment_offset: usize,
}

impl Packet {
    /// The header's own bytes, as the sender wrote them, from the frame this
    /// packet was parsed out of.
    ///
    /// The fields `parse` keeps are the ones every caller reads; the bytes are
    /// what an ICMP error has to quote back, and [RFC 792] requires the quote
    /// to be the *sender's* header rather than a header rebuilt from fields.
    /// The difference is every field `parse` does not keep: the time-to-live,
    /// the type of service, the don't-fragment bit, and the header's options
    /// when it has any.
    ///
    /// `None` when `frame` is not the slice this packet was parsed from, which
    /// a caller detects by the length check rather than by a tag: the header
    /// must start at zero and end where `payload_at` says.
    ///
    /// [RFC 792]: https://www.rfc-editor.org/rfc/rfc792
    pub fn header_bytes<'a>(&self, frame: &'a [u8]) -> Option<&'a [u8]> {
        frame.get(..self.payload_at)
    }

    /// The first bytes of the payload, which an error quotes after the header.
    ///
    /// [RFC 792] asks for the original datagram's internet header plus the
    /// first sixty-four bits of its payload; a caller that wants those bytes
    /// rather than a rebuilt header asks here.
    ///
    /// [RFC 792]: https://www.rfc-editor.org/rfc/rfc792
    pub fn payload_bytes<'a>(&self, frame: &'a [u8]) -> Option<&'a [u8]> {
        let start = self.payload_at;
        let end = start.checked_add(self.payload_len)?;
        frame.get(start..end)
    }

    /// Whether this packet is one piece of a larger one.
    ///
    /// The two fields that decide it are the fragment header's: a packet with
    /// more pieces following, or with a piece that does not start at zero, is
    /// a piece.  A packet with neither is the whole of what it claims, the
    /// common case, and the one every unfragmented sender produces.
    pub fn is_fragment(&self) -> bool {
        self.more_fragments || self.fragment_offset != 0
    }
}

/// Write the twenty bytes that carry `payload_len` bytes of `protocol` from
/// `source` to `destination`.
///
/// The payload is not written: a caller that already has its bytes wants the
/// header in front of what it is about to write, the same arrangement the
/// Ethernet header's writer makes.  The checksum is computed here, over the
/// header this call just wrote, because the two facts it depends on, the
/// total length and a zeroed checksum field, are both settled by the time
/// the last field lands.
pub fn write_header(
    packet: &mut [u8],
    source: [u8; 4],
    destination: [u8; 4],
    protocol: u8,
    payload_len: usize,
) {
    let total_len = (HEADER_LEN + payload_len) as u16;
    // Version 4, header length five words: twenty bytes, no options.
    packet[0] = 0x45;
    packet[1] = 0;
    put_u16(packet, 2, total_len);
    // One sender, one packet: this stack sends nothing fragmented, so nothing
    // here needs to tell two packets of one datagram apart.
    put_u16(packet, 4, 0);
    put_u16(packet, 6, FLAGS_DONT_FRAGMENT);
    packet[8] = TIME_TO_LIVE;
    packet[9] = protocol;
    // The checksum field reads zero while it is being computed, which is the
    // definition of the computation.
    put_u16(packet, 10, 0);
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    put_u16(packet, 10, checksum(&packet[..HEADER_LEN]));
}

/// Read the packet at the start of a frame, or `None` when it is not one this
/// stack can interpret.
///
/// Four things are refused, each because reading past it would be reading
/// bytes that mean something else: a frame shorter than a header, a version
/// that is not 4, a header shorter than five words, and a checksum that does
/// not verify.  The length fields are cross-checked against the frame, a
/// `total_length` larger than the frame names bytes the sender never put on
/// the wire, and one smaller than the header names a packet that overlaps
/// itself.
pub fn parse(frame: &[u8]) -> Option<Packet> {
    if frame.len() < HEADER_LEN {
        return None;
    }
    if frame[0] >> 4 != 4 {
        return None;
    }
    let header_len = (frame[0] & 0x0F) as usize * 4;
    if header_len < HEADER_LEN || header_len > frame.len() {
        return None;
    }
    let total_len = get_u16(frame, 2) as usize;
    if total_len < header_len || total_len > frame.len() {
        return None;
    }
    // The checksum verifies over the header with its own field included: a
    // correct header sums to all ones, which is zero after the complement.
    if checksum(&frame[..header_len]) != 0 {
        return None;
    }

    let mut source = [0_u8; 4];
    source.copy_from_slice(&frame[12..16]);
    let mut destination = [0_u8; 4];
    destination.copy_from_slice(&frame[16..20]);

    // The fragment fields: bit 0x2000 is "more fragments", the low thirteen
    // bits are the offset in eight-byte units, and the offset is multiplied
    // here so every caller sees bytes.
    let flags_and_offset = get_u16(frame, 6);
    Some(Packet {
        header: Header {
            source,
            destination,
            protocol: frame[9],
            time_to_live: frame[8],
        },
        payload_at: header_len,
        payload_len: total_len - header_len,
        identification: get_u16(frame, 4),
        more_fragments: flags_and_offset & FLAGS_MORE_FRAGMENTS != 0,
        fragment_offset: (flags_and_offset as usize & 0x1FFF) * 8,
    })
}

/// Whether the packet was sent to `address`, to everyone on the wire, or to a
/// group this machine joined.
///
/// The two broadcast forms are both accepted because both are real: the
/// limited broadcast (`255.255.255.255`) is what a sender uses before it knows
/// its own network, and the directed form (`10.0.2.255`) names this one.  A
/// packet addressed to another machine is another machine's conversation.
///
/// A **group** is accepted only when it is in `joined`, which is the same rule
/// [`crate::ipv6::is_for`] applies and for the same reason: a multicast address
/// names every member of a group, and a host that read every group's traffic
/// would be a host that had joined all of them.  The list is the caller's,
/// because which groups this machine is in is a fact about its boot.
pub fn is_for(packet: &Packet, address: [u8; 4], joined: &[[u8; 4]]) -> bool {
    if packet.header.destination == address
        || packet.header.destination == [255, 255, 255, 255]
        || packet.header.destination == [address[0], address[1], address[2], 255]
    {
        return true;
    }
    joined.contains(&packet.header.destination)
}

/// Whether `address` names a group: `224.0.0.0/4`.
///
/// The range is the four high bits, which eight addresses short of half of the
/// space: `224.0.0.0` through `239.255.255.255`, and everything from `240`
/// up is reserved for a future use this stack does not have.
pub fn is_multicast(address: [u8; 4]) -> bool {
    address[0] & 0xF0 == 0xE0
}

/// The Ethernet address a multicast IPv4 address maps to ([RFC 1112] §6.4).
///
/// `01:00:5e`, then the group's low twenty-three bits.  The mapping is
/// **lossy on purpose**: thirty-two group addresses share each hardware
/// address, because the frame's address field has twenty-three bits to spend
/// and the group has twenty-eight.  That is the standard's choice and not an
/// error to correct here, which is why the group is still checked in software
/// after the frame's address matches.
///
/// [RFC 1112]: https://www.rfc-editor.org/rfc/rfc1112
pub fn multicast_mac(address: [u8; 4]) -> [u8; 6] {
    [0x01, 0x00, 0x5E, address[1] & 0x7F, address[2], address[3]]
}

#[cfg(test)]
mod tests {
    use super::HEADER_LEN;
    use super::PROTOCOL_ICMP;
    use super::PROTOCOL_UDP;
    use super::Packet;
    use super::checksum;
    use super::checksum_of;
    use super::is_for;
    use super::is_multicast;
    use super::multicast_mac;
    use super::parse;
    use super::write_header;

    const US: [u8; 4] = [10, 0, 2, 15];
    const GATEWAY: [u8; 4] = [10, 0, 2, 2];

    /// An ICMP echo request to the gateway, header and payload, exactly as
    /// the wire carries it.
    ///
    /// Both checksums were computed by hand and are compared whole: a writer
    /// that summed in the host's order produces a frame whose checksum
    /// verifies against itself and still says nothing to a peer.  The payload
    /// is nine bytes, an odd length, so the vector also pins the padding
    /// rule the checksum's last lone byte follows.
    const ECHO_REQUEST: [u8; 37] = [
        0x45, 0x00, 0x00, 0x25, // version|ihl, tos, total length = 37
        0x00, 0x00, 0x40, 0x00, // identification, flags: don't fragment
        0x40, 0x01, 0x22, 0xc8, // ttl 64, protocol ICMP, checksum
        0x0a, 0x00, 0x02, 0x0f, // source 10.0.2.15
        0x0a, 0x00, 0x02, 0x02, // destination 10.0.2.2
        // The payload: an ICMP echo request, "protofire", seventeen bytes.
        0x08, 0x00, 0xda, 0x3d, 0x00, 0x01, 0x00, 0x01, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x66, 0x69,
        0x72, 0x65,
    ];

    /// The checksum's arithmetic is the one's-complement sum, on a vector with
    /// its carries known by hand.
    ///
    /// The words are `0x4500 + 0x0025 + 0x4000 + … = 0xdd37`, and the
    /// complement is `0x22c8`; a fold that lost a carry would answer `0x22c9`,
    /// which is one bit off and verifies against nothing.  The field reads
    /// zero here, because that is the input the writer's own call computes
    /// over.
    #[test]
    fn the_checksum_of_the_echo_request_header_is_the_hand_computed_one() {
        let mut zeroed = ECHO_REQUEST;
        zeroed[10] = 0;
        zeroed[11] = 0;
        assert_eq!(checksum(&zeroed[..HEADER_LEN]), 0x22c8);
    }

    /// A message with its own checksum included sums to zero, which is how a
    /// reader verifies.
    ///
    /// The payload's checksum is on the vector too, so this is the claim for
    /// both halves of the packet and for the odd-length padding in one.
    #[test]
    fn a_checksum_included_sums_to_zero() {
        assert_eq!(checksum(&ECHO_REQUEST[..HEADER_LEN]), 0, "the header");
        assert_eq!(checksum(&ECHO_REQUEST[HEADER_LEN..]), 0, "the payload");
    }

    /// Every single-byte corruption of the header changes the checksum.
    ///
    /// A sum that ignored a field would agree with the corrupt frame, and the
    /// field it ignored would be a field the wire could flip unseen.  The one
    /// exception the algorithm allows, corrupting two bytes so their errors
    /// cancel, is not reachable by changing one byte.
    #[test]
    fn any_single_corrupted_byte_changes_the_checksum() {
        for index in 0..HEADER_LEN {
            let mut corrupt = ECHO_REQUEST;
            corrupt[index] = !corrupt[index];
            assert_ne!(
                checksum(&corrupt[..HEADER_LEN]),
                checksum(&ECHO_REQUEST[..HEADER_LEN]),
                "byte {index} is invisible to the checksum"
            );
        }
    }

    /// An odd-length message is checksummed as if padded with one zero byte:
    /// the lone last byte counts as the high byte of its final word.
    ///
    /// Checked against the value the padded form gives, which is the rule
    /// stated rather than assumed.
    #[test]
    fn an_odd_length_pads_with_a_zero_byte() {
        const PAYLOAD_LEN: usize = ECHO_REQUEST.len() - HEADER_LEN;
        let mut padded = [0_u8; PAYLOAD_LEN + 1];
        padded[..PAYLOAD_LEN].copy_from_slice(&ECHO_REQUEST[HEADER_LEN..]);
        assert_eq!(
            checksum(&ECHO_REQUEST[HEADER_LEN..]),
            checksum(&padded),
            "the pad changes nothing"
        );
    }

    /// Pieces summed as one message give the same answer as their
    /// concatenation, at every split point.
    ///
    /// The odd split is the one that matters: a lone byte at the boundary is
    /// the high half of a word that spans the two pieces, and a caller that
    /// summed them separately would lose that word's pairing.  UDP's
    /// checksum is the caller, its pseudo-header and its datagram are
    /// summed across exactly this kind of boundary.
    #[test]
    fn pieces_sum_as_one_message_at_every_split() {
        let message = &ECHO_REQUEST[..];
        for split in 0..=message.len() {
            assert_eq!(
                checksum_of(&[&message[..split], &message[split..]]),
                checksum(message),
                "the split at {split} changed the sum"
            );
        }
    }

    /// The writer produces the bytes the wire carries, payload excluded.
    #[test]
    fn the_writer_produces_the_frame_the_vector_carries() {
        let mut packet = [0_u8; ECHO_REQUEST.len()];
        write_header(&mut packet, US, GATEWAY, PROTOCOL_ICMP, 17);
        assert_eq!(&packet[..HEADER_LEN], &ECHO_REQUEST[..HEADER_LEN]);
        // The payload is not the writer's: the caller's bytes, untouched.
        packet[HEADER_LEN..].copy_from_slice(&ECHO_REQUEST[HEADER_LEN..]);
        assert_eq!(packet, ECHO_REQUEST);
    }

    /// A written packet reads back as the fields it was written with.
    #[test]
    fn a_written_packet_round_trips() {
        let mut packet = [0_u8; 40];
        write_header(&mut packet, US, GATEWAY, PROTOCOL_UDP, 20);

        let parsed = parse(&packet).expect("a packet");
        assert_eq!(parsed.header.source, US);
        assert_eq!(parsed.header.destination, GATEWAY);
        assert_eq!(parsed.header.protocol, PROTOCOL_UDP);
        assert_eq!(parsed.payload_at, HEADER_LEN, "no options");
        assert_eq!(parsed.payload_len, 20);
    }

    /// A packet the frame holds more of parses to the length the sender
    /// claimed: Ethernet pads, and the padding is not payload.
    #[test]
    fn the_padding_past_total_length_is_not_payload() {
        let mut frame = [0xEE_u8; 60];
        frame[..ECHO_REQUEST.len()].copy_from_slice(&ECHO_REQUEST);

        let parsed = parse(&frame).expect("a packet");
        assert_eq!(parsed.payload_len, 17, "the sender's claim, not the frame");
        assert_eq!(parsed.payload_at, HEADER_LEN);
    }

    /// A packet this stack cannot interpret is refused rather than read at
    /// the wrong offsets.
    #[test]
    fn a_packet_that_is_not_ours_is_refused() {
        assert!(parse(&[]).is_none(), "empty");
        assert!(parse(&ECHO_REQUEST[..HEADER_LEN - 1]).is_none(), "short");

        let mut wrong_version = ECHO_REQUEST;
        wrong_version[0] = 0x65;
        assert!(parse(&wrong_version).is_none(), "not IPv4");

        let mut short_header = ECHO_REQUEST;
        short_header[0] = 0x43;
        assert!(parse(&short_header).is_none(), "a header below five words");

        let mut bad_checksum = ECHO_REQUEST;
        bad_checksum[10] = !bad_checksum[10];
        assert!(parse(&bad_checksum).is_none(), "the sum does not verify");

        let mut overlong = ECHO_REQUEST;
        overlong[2] = 0x40;
        assert!(
            parse(&overlong).is_none(),
            "a total length past the frame's end"
        );

        let mut underlength = ECHO_REQUEST;
        underlength[3] = 0x10;
        assert!(
            parse(&underlength).is_none(),
            "a total length shorter than the header"
        );
    }

    /// A packet addressed to this stack, or to everyone, is for it; one
    /// addressed to another machine is not.
    #[test]
    fn a_packet_is_for_this_stack_when_addressed_to_it_or_to_everyone() {
        let mut packet = [0_u8; HEADER_LEN];
        write_header(&mut packet, GATEWAY, US, PROTOCOL_ICMP, 0);
        assert!(is_for(&parse(&packet).expect("a packet"), US, &[]));

        // The limited broadcast, and the directed broadcast for this network.
        for broadcast in [[255, 255, 255, 255], [10, 0, 2, 255]] {
            write_header(&mut packet, GATEWAY, broadcast, PROTOCOL_ICMP, 0);
            let parsed = parse(&packet).expect("a packet");
            assert!(is_for(&parsed, US, &[]), "broadcast is for everyone");
        }

        write_header(&mut packet, GATEWAY, [10, 0, 2, 3], PROTOCOL_ICMP, 0);
        let parsed: Packet = parse(&packet).expect("a packet");
        assert!(!is_for(&parsed, US, &[]), "another machine's conversation");

        // A group this machine joined is for it, and one it did not is not.
        // The distinction is the whole difference between a host and a
        // promiscuous listener: `224.0.0.1` is every host on the link, and a
        // group nobody joined is another machine's conversation.
        let mut packet = [0_u8; 20 + 8];
        write_header(&mut packet, US, [224, 0, 0, 1], PROTOCOL_UDP, 8);
        let group = parse(&packet).expect("a packet");
        assert!(!is_for(&group, US, &[]), "not joined, so not ours");
        assert!(is_for(&group, US, &[[224, 0, 0, 1]]), "joined, so ours");
        assert!(
            !is_for(&group, US, &[[239, 255, 255, 250]]),
            "another group's packet"
        );
    }

    /// The multicast range is the high four bits, and its MAC mapping keeps
    /// twenty-three of the group's twenty-eight.
    ///
    /// The mapping is lossy and the test says so by naming two groups that
    /// share an address: `224.0.1.1` and `224.128.1.1` both map to
    /// `01:00:5e:00:01:01`, because the group's fourth byte has its high bit
    /// cleared and the second byte's low seven are all that survive.  That is
    /// [RFC 1112]'s rule, and a test that asserted a one-to-one mapping would
    /// be asserting something the standard does not promise.
    #[test]
    fn the_multicast_range_and_its_mac_mapping() {
        assert!(is_multicast([224, 0, 0, 1]));
        assert!(is_multicast([239, 255, 255, 255]));
        assert!(!is_multicast([223, 255, 255, 255]), "just below");
        assert!(!is_multicast([240, 0, 0, 1]), "just above");

        assert_eq!(
            multicast_mac([224, 0, 1, 1]),
            [0x01, 0x00, 0x5E, 0x00, 0x01, 0x01]
        );
        assert_eq!(
            multicast_mac([239, 255, 255, 255]),
            [0x01, 0x00, 0x5E, 0x7F, 0xFF, 0xFF],
            "the second byte keeps its low seven bits"
        );
        assert_eq!(
            multicast_mac([224, 128, 1, 1]),
            multicast_mac([224, 0, 1, 1]),
            "thirty-two groups share one hardware address"
        );
    }

    /// The header an error quotes is the sender's own bytes, which is the
    /// difference between a quote and a rebuild: every field `parse` does not
    /// keep comes back exactly as it arrived.
    #[test]
    fn a_packet_can_quote_its_own_header() {
        // A header with a time-to-live and a type of service this stack never
        // sends, so a rebuilt one would differ.
        let mut wire = [0_u8; 28];
        wire[0] = 0x45;
        wire[1] = 0xB8;
        wire[2..4].copy_from_slice(&28u16.to_be_bytes());
        wire[6..8].copy_from_slice(&crate::ipv4::FLAGS_DONT_FRAGMENT.to_be_bytes());
        wire[8] = 3;
        wire[9] = crate::ipv4::PROTOCOL_UDP;
        wire[12..16].copy_from_slice(&[10, 0, 2, 2]);
        wire[16..20].copy_from_slice(&[10, 0, 2, 15]);
        let sum = crate::ipv4::checksum(&wire[..20]);
        wire[10..12].copy_from_slice(&sum.to_be_bytes());
        for (index, byte) in wire.iter_mut().enumerate().skip(20) {
            *byte = index as u8;
        }

        let packet = crate::ipv4::parse(&wire).expect("a packet");
        let header = packet.header_bytes(&wire).expect("its own header");
        assert_eq!(header, &wire[..20], "byte for byte, not a rebuild");
        assert_eq!(header[8], 3, "the ttl the sender chose");
        assert_eq!(header[1], 0xB8, "the type of service");
        let payload = packet.payload_bytes(&wire).expect("its own payload");
        assert_eq!(payload, &wire[20..28]);
    }
}
