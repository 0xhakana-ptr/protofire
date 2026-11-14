//! net/src/reply.rs
//!
//! The two frames a host answers on its own: an echo reply and a neighbour
//! advertisement.  Both are composed here, byte for byte, from addresses and
//! link-layer facts, no card, no state, and a buffer the caller supplies.
//!
//! ## Why the composition is here
//!
//! The kernel knows which address is its own and which hardware address a
//! frame goes to; it does not know where the ICMPv6 header begins inside a
//! frame, and it should not have to.  A reply is three headers stacked, the
//! Ethernet frame, the IPv6 packet, the ICMPv6 message, and each of them is
//! this crate's layout.
//!
//! The reason to insist on that is not tidiness.  The neighbour advertisement
//! carries a checksum over a pseudo-header built from the *addresses the
//! answer is sent from and to*, and a composer that got either one wrong
//! produced a frame that parsed and then failed verification, which is
//! exactly the defect the first IPv6 round found, eight phantom bytes of a
//! solicitation's length inside a checksum.  A builder that a host test can
//! run and verify is what makes that class of mistake visible before a boot.
//!
//! ## What is not here
//!
//! Which address is ours, whether the target was one of them, and whether the
//! message is one this host should answer at all: those are the kernel's, and
//! it decides them before calling here.  These functions take a decision and
//! write it.

use crate::ethernet;
use crate::icmpv6;
use crate::ipv6;
use netdev::ETHERNET_HEADER_LEN;

/// The Ethernet header plus the IPv6 header: where a payload begins.
pub const PAYLOAD_AT: usize = ETHERNET_HEADER_LEN + ipv6::HEADER_LEN;

/// Compose an echo reply into `frame`, answering how many bytes it wrote.
///
/// The reply carries the request's identifier, sequence and data back
/// unchanged: that is the whole promise of an echo, and a reply that altered
/// the data would be a reply a sender could not match to its request.
///
/// `frame` must be long enough for the reply; a caller sizes it from the
/// card's maximum frame length, and the answer is the frame's true length
/// because the last writer's message is shorter than the buffer it sat in.
///
/// `None` when the frame or the data cannot hold what was asked for, which is
/// a caller that sized its buffer wrong rather than a wire that refused
/// anything.
// Eight: the frame, the two addresses, the two hardware addresses, the echo
// to answer and the data it carried.  A struct grouping the addresses would
// be a second place a frame's source and destination are named, and the
// mistake this signature exists to make impossible is naming the wrong pair.
#[allow(clippy::too_many_arguments)]
pub fn echo_reply(
    frame: &mut [u8],
    local: ipv6::Addr,
    local_hardware: [u8; 6],
    destination: ipv6::Addr,
    destination_hardware: [u8; 6],
    echo: &icmpv6::Echo,
    data: &[u8],
) -> Option<usize> {
    let message_len = icmpv6::echo_len(data.len());
    let total = PAYLOAD_AT + message_len;
    if frame.len() < total {
        return None;
    }
    ethernet::write_header(
        frame,
        destination_hardware,
        local_hardware,
        ethernet::ETHERTYPE_IPV6,
    );
    ipv6::write_header(
        &mut frame[ETHERNET_HEADER_LEN..],
        local,
        destination,
        ipv6::NEXT_ICMPV6,
        message_len,
    );
    icmpv6::write_echo(
        &mut frame[PAYLOAD_AT..],
        local,
        destination,
        icmpv6::ECHO_REPLY,
        echo.identifier,
        echo.sequence,
        data,
    );
    Some(total)
}

/// The fixed part plus the target link-layer option: what an advertisement
/// always carries, because the option is the answer.
pub const ADVERTISEMENT_LEN: usize = icmpv6::HEADER_LEN + icmpv6::NEIGHBOR_LEN + 8;

/// Compose a solicited neighbour advertisement into `frame`.
///
/// `target` is the address that was asked about and `local` is the address the
/// answer is sent **from**, the same one, which is what makes the asker's
/// cache and checksum agree with it.  `destination` is the asker, which is why
/// the solicited flag is set: an advertisement that answered a solicitation
/// goes to the one node that asked rather than to a group.
///
/// `None` when the frame cannot hold the message; the advertisement's length
/// is fixed, so the only way to fail is a buffer too small for a reply this
/// crate builds.
pub fn neighbor_advertisement(
    frame: &mut [u8],
    local: ipv6::Addr,
    local_hardware: [u8; 6],
    destination: ipv6::Addr,
    destination_hardware: [u8; 6],
    target: ipv6::Addr,
) -> Option<usize> {
    let total = PAYLOAD_AT + ADVERTISEMENT_LEN;
    if frame.len() < total {
        return None;
    }
    ethernet::write_header(
        frame,
        destination_hardware,
        local_hardware,
        ethernet::ETHERTYPE_IPV6,
    );
    ipv6::write_header(
        &mut frame[ETHERNET_HEADER_LEN..],
        local,
        destination,
        ipv6::NEXT_ICMPV6,
        ADVERTISEMENT_LEN,
    );
    icmpv6::write_neighbor_advertisement(
        &mut frame[PAYLOAD_AT..],
        local,
        destination,
        target,
        local_hardware,
        false,
        true,
    );
    Some(total)
}

/// Compose an echo **request** into `frame`, answering how many bytes it wrote.
///
/// The request's twin, and here for the same reason: an exchange a boot runs
/// to prove its answer path has to write the request through the same three
/// headers a real one carries, and a probe that hand-built its own would be
/// proving a layout no other code uses.
///
/// `None` when the frame cannot hold the message.
// Eight: the same parameter list as the reply, plus the identifier and
// sequence a request names and a reply echoes.  A struct would be a second
// type for a message `icmpv6` already has an `Echo` for, and the two writers
// are one field apart on purpose.
#[allow(clippy::too_many_arguments)]
pub fn echo_request(
    frame: &mut [u8],
    local: ipv6::Addr,
    local_hardware: [u8; 6],
    destination: ipv6::Addr,
    destination_hardware: [u8; 6],
    identifier: u16,
    sequence: u16,
    data: &[u8],
) -> Option<usize> {
    let message_len = icmpv6::echo_len(data.len());
    let total = PAYLOAD_AT + message_len;
    if frame.len() < total {
        return None;
    }
    ethernet::write_header(
        frame,
        destination_hardware,
        local_hardware,
        ethernet::ETHERTYPE_IPV6,
    );
    ipv6::write_header(
        &mut frame[ETHERNET_HEADER_LEN..],
        local,
        destination,
        ipv6::NEXT_ICMPV6,
        message_len,
    );
    icmpv6::write_echo(
        &mut frame[PAYLOAD_AT..],
        local,
        destination,
        icmpv6::ECHO_REQUEST,
        identifier,
        sequence,
        data,
    );
    Some(total)
}

/// Compose a neighbour solicitation into `frame`, answering how many bytes it
/// wrote.
///
/// `source_link_layer` is the option a solicitation carries when its source is
/// a real address; `None` is the duplicate-address form, whose source is `::`
/// and whose length is the message's fixed part alone, the difference the
/// first IPv6 round got wrong, by counting eight bytes of an option the
/// message did not contain.
///
/// `destination` is normally the target's solicited-node group, and
/// `destination_hardware` the group's multicast MAC.
///
/// `None` when the frame cannot hold the message.
pub fn neighbor_solicitation(
    frame: &mut [u8],
    local: ipv6::Addr,
    local_hardware: [u8; 6],
    destination: ipv6::Addr,
    destination_hardware: [u8; 6],
    target: ipv6::Addr,
    source_link_layer: Option<[u8; 6]>,
) -> Option<usize> {
    let message_len =
        icmpv6::HEADER_LEN + icmpv6::NEIGHBOR_LEN + if source_link_layer.is_some() { 8 } else { 0 };
    let total = PAYLOAD_AT + message_len;
    if frame.len() < total {
        return None;
    }
    ethernet::write_header(
        frame,
        destination_hardware,
        local_hardware,
        ethernet::ETHERTYPE_IPV6,
    );
    ipv6::write_header(
        &mut frame[ETHERNET_HEADER_LEN..],
        local,
        destination,
        ipv6::NEXT_ICMPV6,
        message_len,
    );
    icmpv6::write_neighbor_solicitation(&mut frame[PAYLOAD_AT..], local, target, source_link_layer);
    Some(total)
}

#[cfg(test)]
mod tests {
    use super::ADVERTISEMENT_LEN;
    use super::PAYLOAD_AT;
    use super::echo_reply;
    use super::echo_request;
    use super::neighbor_advertisement;
    use super::neighbor_solicitation;
    use crate::icmpv6;
    use crate::ipv6;

    const LOCAL: ipv6::Addr = [
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x54, 0x00, 0xff, 0xfe, 0x12, 0x34, 0x56,
    ];
    const PEER: ipv6::Addr = [
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x55, 0x0a, 0xff, 0xfe, 0x00, 0x02, 0x02,
    ];
    const LOCAL_HARDWARE: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    const PEER_HARDWARE: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
    const FRAME_LIMIT: usize = 1514;

    /// An echo reply is a frame the sender's own verifier accepts, which is
    /// the only property that matters: a checksum built wrong parses and is
    /// then thrown away, and the boot sees an exchange that never happened.
    #[test]
    fn an_echo_reply_verifies() {
        let mut frame = [0_u8; FRAME_LIMIT];
        let echo = icmpv6::Echo {
            identifier: 7,
            sequence: 1,
            data_at: 0,
            data_len: 8,
        };
        let data = b"protofir";
        let total = echo_reply(
            &mut frame,
            LOCAL,
            LOCAL_HARDWARE,
            PEER,
            PEER_HARDWARE,
            &echo,
            data,
        )
        .expect("a reply");
        assert_eq!(total, PAYLOAD_AT + icmpv6::echo_len(8));

        // The Ethernet header names the asker's hardware address and ours.
        assert_eq!(&frame[0..6], &PEER_HARDWARE);
        assert_eq!(&frame[6..12], &LOCAL_HARDWARE);

        let packet = ipv6::parse(&frame[netdev::ETHERNET_HEADER_LEN..]).expect("a packet");
        assert_eq!(packet.header.source, LOCAL);
        assert_eq!(packet.header.destination, PEER);
        assert_eq!(packet.header.next_header, ipv6::NEXT_ICMPV6);
        assert_eq!(packet.payload_len, icmpv6::echo_len(8));

        // The checksum, over the message and the addresses it rode between:
        // this is the assertion the boot could only make by succeeding.
        let message = &frame[PAYLOAD_AT..total];
        assert!(
            icmpv6::verify(message, LOCAL, PEER),
            "the reply's own checksum must verify against the ends it names"
        );
        let parsed = icmpv6::parse(message).expect("a message");
        assert_eq!(parsed.icmp_type, icmpv6::ECHO_REPLY);
        let back = icmpv6::parse_echo(&parsed, message).expect("an echo");
        assert_eq!(back.identifier, 7);
        assert_eq!(back.sequence, 1);
        assert_eq!(back.data_len, 8);
        assert_eq!(&message[back.data_at..back.data_at + 8], data);
    }

    /// A reply whose addresses were swapped does not verify, which is what
    /// makes the assertion above mean something: the checksum binds the
    /// message to the ends, and a composer that named the wrong pair would be
    /// caught rather than passing on a checksum of the same bytes.
    #[test]
    fn the_checksum_binds_the_reply_to_its_ends() {
        let mut frame = [0_u8; FRAME_LIMIT];
        let echo = icmpv6::Echo {
            identifier: 7,
            sequence: 1,
            data_at: 0,
            data_len: 4,
        };
        let total = echo_reply(
            &mut frame,
            LOCAL,
            LOCAL_HARDWARE,
            PEER,
            PEER_HARDWARE,
            &echo,
            b"data",
        )
        .expect("a reply");
        let message = &frame[PAYLOAD_AT..total];
        assert!(icmpv6::verify(message, LOCAL, PEER));
        // A different destination is a different pseudo-header.
        let mut elsewhere = PEER;
        elsewhere[15] = elsewhere[15].wrapping_add(1);
        assert!(
            !icmpv6::verify(message, LOCAL, elsewhere),
            "a reply for one node must not verify for another"
        );
    }

    /// An advertisement is a frame the asker's verifier accepts, and it
    /// carries its own hardware address as the target option, the whole
    /// answer to the question it is answering.
    #[test]
    fn a_neighbour_advertisement_verifies_and_carries_the_option() {
        let mut frame = [0_u8; FRAME_LIMIT];
        let total = neighbor_advertisement(
            &mut frame,
            LOCAL,
            LOCAL_HARDWARE,
            PEER,
            PEER_HARDWARE,
            LOCAL,
        )
        .expect("an advertisement");
        assert_eq!(total, PAYLOAD_AT + ADVERTISEMENT_LEN);

        let packet = ipv6::parse(&frame[netdev::ETHERNET_HEADER_LEN..]).expect("a packet");
        assert_eq!(
            packet.header.source, LOCAL,
            "answered from the address asked about"
        );
        assert_eq!(
            packet.header.destination, PEER,
            "to the asker, not to a group"
        );

        let message = &frame[PAYLOAD_AT..total];
        assert!(
            icmpv6::verify(message, LOCAL, PEER),
            "the advertisement's own checksum must verify"
        );
        let parsed = icmpv6::parse(message).expect("a message");
        assert_eq!(parsed.icmp_type, icmpv6::NEIGHBOR_ADVERTISEMENT);
        let advertisement =
            icmpv6::parse_neighbor_advertisement(&parsed, message).expect("an advertisement");
        assert_eq!(advertisement.target, LOCAL);
        // The solicited flag is set; the router flag is not, because this
        // host forwards nothing.
        assert!(advertisement.solicited);
        assert!(!advertisement.router);
        assert!(
            advertisement.override_existing,
            "the override flag is always set"
        );

        let option = icmpv6::link_layer_option(
            message,
            parsed.body_at + icmpv6::NEIGHBOR_LEN,
            message.len(),
            icmpv6::OPTION_TARGET_LINK_LAYER,
        )
        .expect("the target link-layer option");
        assert_eq!(option, LOCAL_HARDWARE);
    }

    /// A solicitation's length is the fixed part alone when it carries no
    /// option, and the option's eight bytes when it does, the difference
    /// that a first attempt got wrong by counting them in both cases, which
    /// made the checksum cover eight zeros nobody wrote.
    #[test]
    fn a_solicitations_length_follows_its_option() {
        let mut frame = [0_u8; FRAME_LIMIT];
        let group = ipv6::solicited_node(LOCAL);
        let group_hardware = ipv6::multicast_mac(group);

        let without = neighbor_solicitation(
            &mut frame,
            ipv6::UNSPECIFIED,
            LOCAL_HARDWARE,
            group,
            group_hardware,
            LOCAL,
            None,
        )
        .expect("a solicitation");
        assert_eq!(
            without - PAYLOAD_AT,
            icmpv6::HEADER_LEN + icmpv6::NEIGHBOR_LEN,
            "no option, no option bytes"
        );
        let message = &frame[PAYLOAD_AT..without];
        assert!(
            icmpv6::verify(message, ipv6::UNSPECIFIED, group),
            "the duplicate-address form's checksum covers what was written"
        );

        let with = neighbor_solicitation(
            &mut frame,
            PEER,
            LOCAL_HARDWARE,
            group,
            group_hardware,
            LOCAL,
            Some(PEER_HARDWARE),
        )
        .expect("a solicitation");
        assert_eq!(
            with - PAYLOAD_AT,
            icmpv6::HEADER_LEN + icmpv6::NEIGHBOR_LEN + 8,
            "the option is eight bytes"
        );
        assert_eq!(
            with - without,
            8,
            "and exactly the option's, which is the whole point"
        );
        let message = &frame[PAYLOAD_AT..with];
        assert!(icmpv6::verify(message, PEER, group));
        let parsed = icmpv6::parse(message).expect("a message");
        let solicitation =
            icmpv6::parse_neighbor_solicitation(&parsed, message).expect("a solicitation");
        assert_eq!(solicitation.target, LOCAL);
        let option = icmpv6::link_layer_option(
            message,
            parsed.body_at + icmpv6::NEIGHBOR_LEN,
            message.len(),
            icmpv6::OPTION_SOURCE_LINK_LAYER,
        )
        .expect("the source link-layer option");
        assert_eq!(option, PEER_HARDWARE);
    }

    /// An echo request verifies and carries the identifier and sequence a
    /// sender compares its reply against.
    #[test]
    fn an_echo_request_verifies() {
        let mut frame = [0_u8; FRAME_LIMIT];
        let total = echo_request(
            &mut frame,
            PEER,
            PEER_HARDWARE,
            LOCAL,
            LOCAL_HARDWARE,
            7,
            1,
            b"pyrofire",
        )
        .expect("a request");
        assert_eq!(total, PAYLOAD_AT + icmpv6::echo_len(8));

        let packet = ipv6::parse(&frame[netdev::ETHERNET_HEADER_LEN..]).expect("a packet");
        assert_eq!(packet.header.source, PEER);
        assert_eq!(packet.header.destination, LOCAL);

        let message = &frame[PAYLOAD_AT..total];
        assert!(icmpv6::verify(message, PEER, LOCAL));
        let parsed = icmpv6::parse(message).expect("a message");
        assert_eq!(parsed.icmp_type, icmpv6::ECHO_REQUEST);
        let echo = icmpv6::parse_echo(&parsed, message).expect("an echo");
        assert_eq!(echo.identifier, 7);
        assert_eq!(echo.sequence, 1);
        assert_eq!(echo.data_len, 8);
        assert_eq!(&message[echo.data_at..echo.data_at + 8], b"pyrofire");
    }

    /// A buffer too small answers none rather than writing past its end,
    /// which is the one failure a caller that sized its frame wrong can have.
    #[test]
    fn a_small_frame_is_refused() {
        let mut frame = [0_u8; PAYLOAD_AT];
        let echo = icmpv6::Echo {
            identifier: 1,
            sequence: 1,
            data_at: 0,
            data_len: 8,
        };
        assert_eq!(
            echo_reply(
                &mut frame,
                LOCAL,
                LOCAL_HARDWARE,
                PEER,
                PEER_HARDWARE,
                &echo,
                b"12345678"
            ),
            None
        );
        let mut frame = [0_u8; PAYLOAD_AT + ADVERTISEMENT_LEN - 1];
        assert_eq!(
            neighbor_advertisement(
                &mut frame,
                LOCAL,
                LOCAL_HARDWARE,
                PEER,
                PEER_HARDWARE,
                LOCAL
            ),
            None
        );
    }
}
