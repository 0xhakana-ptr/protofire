//! net/src/ethernet.rs
//!
//! An Ethernet frame: two addresses, a type, and what follows.
//!
//! ## The layout
//!
//! ```text
//! dst[6] src[6] ethertype[2]                       14 bytes
//! payload                                          what the type names
//! ```
//!
//! Every multi-byte field is big-endian on the wire, which is the opposite of
//! what a device's own configuration registers use.  That is not a curiosity: a
//! request written with little-endian fields asks for the address of
//! `0x01000000` instead of `10.0.0.1`, and a network that answers nothing looks
//! exactly like a card that does not send.
//!
//! ## Why the header length lives in `link`
//!
//! [`link::ETHERNET_HEADER_LEN`] is there because a receive buffer is sized
//! from it and because the ethertype reader is the one function both crates
//! use. What is here is the frame's own vocabulary: the type numbers, the
//! broadcast address, and the two writers a protocol needs.

use link::ETHERNET_HEADER_LEN;

/// `0x0806`: ARP.
pub const ETHERTYPE_ARP: u16 = 0x0806;

/// `0x0800`: IPv4.
pub const ETHERTYPE_IPV4: u16 = 0x0800;

/// The broadcast address, which is who a question with no known answer is sent
/// to.
pub const BROADCAST: [u8; 6] = [0xFF; 6];

/// Write a `u16` in the byte order the wire uses.
///
/// Public because every protocol above this one writes fields: ARP's `oper`,
/// IPv4's total length and checksum, UDP's ports.  A `copy_from_slice` of
/// `to_be_bytes` at each of those is the same four words written eight times,
/// and the one that is written as a cast is the one that works on a
/// little-endian host and fails on a big-endian machine.
pub fn put_u16(frame: &mut [u8], at: usize, value: u16) {
    frame[at..at + 2].copy_from_slice(&value.to_be_bytes());
}

/// Read a `u16` from the byte order the wire uses.
pub fn get_u16(frame: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([frame[at], frame[at + 1]])
}

/// Build the fourteen bytes that carry `payload` to `destination`.
///
/// The payload is not written: a caller that already has its bytes at the right
/// place would copy them twice, and one that is building into a buffer wants
/// the header in front of what it is about to write.
pub fn write_header(frame: &mut [u8], destination: [u8; 6], source: [u8; 6], ethertype: u16) {
    frame[0..6].copy_from_slice(&destination);
    frame[6..12].copy_from_slice(&source);
    put_u16(frame, 12, ethertype);
}

/// The header's three fields, as a reader sees them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub destination: [u8; 6],
    pub source: [u8; 6],
    pub ethertype: u16,
}

/// Read the header at the start of a frame, or `None` when it is too short.
///
/// A frame shorter than the header is refused rather than padded: there is no
/// ethertype to dispatch on, and a caller that read one from a shorter buffer
/// would be reading whatever followed it in memory.
pub fn parse_header(frame: &[u8]) -> Option<Header> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return None;
    }
    let mut destination = [0_u8; 6];
    destination.copy_from_slice(&frame[0..6]);
    let mut source = [0_u8; 6];
    source.copy_from_slice(&frame[6..12]);
    Some(Header {
        destination,
        source,
        ethertype: get_u16(frame, 12),
    })
}

/// Whether a frame was sent to `address`, or to everyone.
///
/// The check a stack makes before it answers: a device promiscuously receives
/// frames addressed to other machines, and answering one is talking to a
/// conversation that is not ours.
pub fn is_for(frame: &[u8], address: [u8; 6]) -> bool {
    match frame.get(0..6) {
        Some(destination) => destination == address || destination == BROADCAST,
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::BROADCAST;
    use super::ETHERTYPE_ARP;
    use super::ETHERTYPE_IPV4;
    use super::Header;
    use super::get_u16;
    use super::is_for;
    use super::parse_header;
    use super::put_u16;
    use super::write_header;
    use link::ETHERNET_HEADER_LEN;

    const CARD: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    const PEER: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    /// A `u16` goes on the wire big-endian and comes back.
    ///
    /// The round trip alone would pass for a reader and writer that agreed on
    /// the host's order, which is why the bytes are checked too.
    #[test]
    fn a_u16_is_big_endian_on_the_wire() {
        let mut frame = [0_u8; 2];
        put_u16(&mut frame, 0, 0x0806);
        assert_eq!(frame, [0x08, 0x06], "high byte first");
        assert_eq!(get_u16(&frame, 0), 0x0806);
    }

    /// The header is written where the structure puts its fields.
    #[test]
    fn a_header_lands_at_its_offsets() {
        let mut frame = [0_u8; ETHERNET_HEADER_LEN];
        write_header(&mut frame, PEER, CARD, ETHERTYPE_IPV4);

        assert_eq!(&frame[0..6], &PEER, "destination first");
        assert_eq!(&frame[6..12], &CARD, "then the source");
        assert_eq!(&frame[12..14], &[0x08, 0x00], "then the type, big-endian");
    }

    /// A header written reads back as the same three values.
    #[test]
    fn a_header_round_trips() {
        let mut frame = [0_u8; ETHERNET_HEADER_LEN + 4];
        write_header(&mut frame, PEER, CARD, ETHERTYPE_ARP);

        let header = parse_header(&frame).expect("a header");
        assert_eq!(
            header,
            Header {
                destination: PEER,
                source: CARD,
                ethertype: ETHERTYPE_ARP,
            }
        );
    }

    /// A frame shorter than a header has none, rather than a partial one.
    #[test]
    fn a_short_frame_has_no_header() {
        for length in 0..ETHERNET_HEADER_LEN {
            assert!(
                parse_header(&[0_u8; 13][..length]).is_none(),
                "{length} bytes is not a header"
            );
        }
    }

    /// A frame addressed to this card, or to everyone, is for it.
    ///
    /// The broadcast case is not a convenience: an ARP request is sent to
    /// `ff:ff:ff:ff:ff:ff`, so a stack that only accepted its own address
    /// would never see one.
    #[test]
    fn a_frame_is_for_this_card_when_addressed_to_it_or_to_everyone() {
        let mut frame = [0_u8; ETHERNET_HEADER_LEN];
        write_header(&mut frame, CARD, PEER, ETHERTYPE_ARP);
        assert!(is_for(&frame, CARD));

        write_header(&mut frame, BROADCAST, PEER, ETHERTYPE_ARP);
        assert!(is_for(&frame, CARD), "broadcast is for everyone");

        write_header(&mut frame, PEER, CARD, ETHERTYPE_ARP);
        assert!(!is_for(&frame, CARD), "someone else's conversation");

        assert!(!is_for(&[], CARD), "a short frame is for nobody");
    }
}
