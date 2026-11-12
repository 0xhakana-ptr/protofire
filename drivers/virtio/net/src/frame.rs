//! drivers/virtio/net/src/frame.rs
//!
//! An Ethernet frame and the one ARP message this driver sends and reads.
//!
//! ## Why ARP is the first frame
//!
//! It is the smallest exchange that proves both queues.  An ARP request is 42
//! bytes, needs no configuration, no address assignment and no stack above it,
//! and QEMU's user-mode network answers one for its gateway without being asked
//! to.  So a boot that sends one and reads the reply has exercised the
//! transmit chain, the device's own send path, the receive chain and the
//! device's receive path — four things a bring-up test cannot reach.
//!
//! ## The layout is the protocol's, not this tree's
//!
//! ```text
//! Ethernet  dst[6] src[6] ethertype[2]             14 bytes
//! ARP       htype[2] ptype[2] hlen[1] plen[1]
//!           oper[2] sha[6] spa[4] tha[6] tpa[4]    28 bytes
//! ```
//!
//! Every multi-byte field is big-endian on the wire, which is the opposite of
//! the device's own configuration registers.  That is not a curiosity: a driver
//! that wrote an ARP request with little-endian fields asks for the address of
//! `0x0100000a` instead of `10.0.0.1`, and a network that answers nothing looks
//! exactly like a card that does not send.

/// The Ethernet header's length: two addresses and a type.
pub const ETHERNET_HEADER_LEN: usize = 14;

/// `0x0806`: ARP, as the ethertype field carries it.
pub const ETHERTYPE_ARP: u16 = 0x0806;

/// `0x0800`: IPv4, the protocol address type an ARP message names.
pub const ETHERTYPE_IPV4: u16 = 0x0800;

/// The ARP message's length, for an Ethernet and IPv4 pair.
pub const ARP_LEN: usize = 28;

/// The length of a complete ARP frame for Ethernet over IPv4.
pub const ARP_FRAME_LEN: usize = ETHERNET_HEADER_LEN + ARP_LEN;

/// The broadcast address, which is who an ARP request is sent to.
pub const BROADCAST: [u8; 6] = [0xFF; 6];

/// `oper` value 1: a request.
pub const OPER_REQUEST: u16 = 1;

/// `oper` value 2: a reply.
pub const OPER_REPLY: u16 = 2;

/// Write a `u16` in the byte order the wire uses.
fn put_u16(frame: &mut [u8], at: usize, value: u16) {
    frame[at..at + 2].copy_from_slice(&value.to_be_bytes());
}

/// Read a `u16` from the byte order the wire uses.
fn get_u16(frame: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([frame[at], frame[at + 1]])
}

/// An ARP message, as this driver reads one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arp {
    /// `oper`: 1 for a request, 2 for a reply.
    pub operation: u16,
    /// `sha`: the sender's hardware address.
    pub sender_hardware: [u8; 6],
    /// `spa`: the sender's protocol address, four bytes as the wire carries it.
    pub sender_protocol: [u8; 4],
    /// `tha`: the target's hardware address.
    pub target_hardware: [u8; 6],
    /// `tpa`: the target's protocol address.
    pub target_protocol: [u8; 4],
}

/// Build an ARP request asking who holds `target_protocol`.
///
/// `source` is the card's address, which the device published; the request is a
/// broadcast because the answer is what the driver does not have.  The sender's
/// hardware field carries `source` so the reply is addressed back to it.
pub fn arp_request(
    source: [u8; 6],
    sender_protocol: [u8; 4],
    target_protocol: [u8; 4],
) -> [u8; ARP_FRAME_LEN] {
    let mut frame = [0_u8; ARP_FRAME_LEN];

    // Ethernet: to everyone, from the card, and it is an ARP.
    frame[0..6].copy_from_slice(&BROADCAST);
    frame[6..12].copy_from_slice(&source);
    put_u16(&mut frame, 12, ETHERTYPE_ARP);

    let arp = ETHERNET_HEADER_LEN;
    // htype = 1 (Ethernet), ptype = IPv4, hlen = 6, plen = 4.
    put_u16(&mut frame, arp, 1);
    put_u16(&mut frame, arp + 2, ETHERTYPE_IPV4);
    frame[arp + 4] = 6;
    frame[arp + 5] = 4;
    put_u16(&mut frame, arp + 6, OPER_REQUEST);
    frame[arp + 8..arp + 14].copy_from_slice(&source);
    frame[arp + 14..arp + 18].copy_from_slice(&sender_protocol);
    // The target's hardware address is unknown, which is the question.
    frame[arp + 18..arp + 24].copy_from_slice(&[0; 6]);
    frame[arp + 24..arp + 28].copy_from_slice(&target_protocol);

    frame
}

/// Read the ARP message at the start of an Ethernet frame.
///
/// `None` for anything that is not an Ethernet ARP frame this driver can
/// interpret: a frame shorter than the message, a different ethertype, or an
/// ARP whose own field sizes say it is not Ethernet over IPv4.  Each of those
/// would otherwise be read from offsets that mean something else, and the
/// fields after the mistake would look plausible.
pub fn parse_arp(frame: &[u8]) -> Option<Arp> {
    if frame.len() < ARP_FRAME_LEN {
        return None;
    }
    if get_u16(frame, 12) != ETHERTYPE_ARP {
        return None;
    }
    let arp = ETHERNET_HEADER_LEN;
    if get_u16(frame, arp) != 1 {
        return None;
    }
    if get_u16(frame, arp + 2) != ETHERTYPE_IPV4 {
        return None;
    }
    if frame[arp + 4] != 6 || frame[arp + 5] != 4 {
        return None;
    }

    let mut sender_hardware = [0_u8; 6];
    sender_hardware.copy_from_slice(&frame[arp + 8..arp + 14]);
    let mut sender_protocol = [0_u8; 4];
    sender_protocol.copy_from_slice(&frame[arp + 14..arp + 18]);
    let mut target_hardware = [0_u8; 6];
    target_hardware.copy_from_slice(&frame[arp + 18..arp + 24]);
    let mut target_protocol = [0_u8; 4];
    target_protocol.copy_from_slice(&frame[arp + 24..arp + 28]);

    Some(Arp {
        operation: get_u16(frame, arp + 6),
        sender_hardware,
        sender_protocol,
        target_hardware,
        target_protocol,
    })
}

#[cfg(test)]
mod tests {
    use super::ARP_FRAME_LEN;
    use super::ARP_LEN;
    use super::BROADCAST;
    use super::ETHERNET_HEADER_LEN;
    use super::OPER_REPLY;
    use super::OPER_REQUEST;
    use super::arp_request;
    use super::parse_arp;

    const CARD: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    const US: [u8; 4] = [10, 0, 2, 15];
    const GATEWAY: [u8; 4] = [10, 0, 2, 2];

    /// The request is the bytes an ARP for the gateway is, at every offset a
    /// reader would check.
    ///
    /// The frame is compared whole rather than field by field because that is
    /// what the wire carries: a driver that wrote one field with the host's
    /// byte order produces a frame that is wrong in a way a per-field read
    /// back through the same wrong order would agree with.
    #[test]
    fn the_request_is_the_frame_the_wire_carries() {
        let request = arp_request(CARD, US, GATEWAY);
        assert_eq!(request.len(), 42, "the smallest ARP frame");
        assert_eq!(
            request,
            [
                // dst: everyone.
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // src
                0x02, 0x11, 0x22, 0x33, 0x44, 0x55, // ethertype: ARP, big-endian.
                0x08, 0x06, // htype = 1, big-endian.
                0x00, 0x01, // ptype = IPv4, big-endian.
                0x08, 0x00, // hlen = 6, plen = 4.
                0x06, 0x04, // oper = 1 (request), big-endian.
                0x00, 0x01, // sha
                0x02, 0x11, 0x22, 0x33, 0x44, 0x55, // spa = 10.0.2.15, in wire order.
                0x0A, 0x00, 0x02, 0x0F, // tha: unknown
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // tpa = 10.0.2.2
                0x0A, 0x00, 0x02, 0x02,
            ]
        );
    }

    /// The offsets the structure puts each field at are the ones used.
    #[test]
    fn the_offsets_are_the_structures() {
        assert_eq!(ETHERNET_HEADER_LEN, 14);
        assert_eq!(ARP_LEN, 28);
        assert_eq!(ARP_FRAME_LEN, 42);
        assert_eq!(BROADCAST, [0xFF; 6]);
    }

    /// The request parses back as the message it is.
    #[test]
    fn a_request_parses_back() {
        let parsed = parse_arp(&arp_request(CARD, US, GATEWAY)).expect("an ARP frame");
        assert_eq!(parsed.operation, OPER_REQUEST);
        assert_eq!(parsed.sender_hardware, CARD);
        assert_eq!(parsed.sender_protocol, US);
        assert_eq!(parsed.target_hardware, [0; 6], "the question is the target");
        assert_eq!(parsed.target_protocol, GATEWAY);
    }

    /// A reply's fields land where the structure says.
    ///
    /// Written here as a device would, rather than by the driver's own builder,
    /// so the parser is checked against the layout rather than against itself.
    #[test]
    fn a_reply_parses() {
        let mut frame = arp_request(CARD, US, GATEWAY);
        // Turn it into the answer: from the gateway, to the card, oper 2.
        frame[0..6].copy_from_slice(&CARD);
        frame[6..12].copy_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        frame[20..22].copy_from_slice(&OPER_REPLY.to_be_bytes());
        frame[22..28].copy_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        frame[28..32].copy_from_slice(&GATEWAY);
        frame[32..38].copy_from_slice(&CARD);
        frame[38..42].copy_from_slice(&US);

        let parsed = parse_arp(&frame).expect("an ARP frame");
        assert_eq!(parsed.operation, OPER_REPLY);
        assert_eq!(
            parsed.sender_hardware,
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
            "the gateway's address is what the request asked for"
        );
        assert_eq!(parsed.sender_protocol, GATEWAY);
        assert_eq!(parsed.target_hardware, CARD);
        assert_eq!(parsed.target_protocol, US);
    }

    /// A frame this driver cannot interpret is refused rather than read at the
    /// wrong offsets.
    #[test]
    fn a_frame_that_is_not_ethernet_over_ipv4_arp_is_refused() {
        let request = arp_request(CARD, US, GATEWAY);

        assert!(parse_arp(&request[..ARP_FRAME_LEN - 1]).is_none(), "short");

        let mut wrong_type = request;
        wrong_type[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        assert!(parse_arp(&wrong_type).is_none(), "not an ARP");

        let mut wrong_hardware = request;
        wrong_hardware[18] = 8;
        assert!(
            parse_arp(&wrong_hardware).is_none(),
            "not an Ethernet address"
        );

        let mut wrong_protocol = request;
        wrong_protocol[19] = 16;
        assert!(parse_arp(&wrong_protocol).is_none(), "not an IPv4 address");

        let mut wrong_htype = request;
        wrong_htype[14..16].copy_from_slice(&6u16.to_be_bytes());
        assert!(parse_arp(&wrong_htype).is_none(), "not Ethernet hardware");

        let mut wrong_ptype = request;
        wrong_ptype[16..18].copy_from_slice(&0x86DDu16.to_be_bytes());
        assert!(parse_arp(&wrong_ptype).is_none(), "not an IPv4 protocol");
    }

    /// A buffer longer than the frame parses from its start, which is what a
    /// receive buffer holds: the device's header, then the frame, then
    /// whatever else the buffer had.
    #[test]
    fn a_longer_buffer_parses_from_the_start() {
        let mut buffer = [0xAA_u8; 128];
        buffer[..ARP_FRAME_LEN].copy_from_slice(&arp_request(CARD, US, GATEWAY));
        let parsed = parse_arp(&buffer).expect("the frame is at the start");
        assert_eq!(parsed.sender_protocol, US);
    }
}
