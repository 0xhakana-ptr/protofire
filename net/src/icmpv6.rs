//! net/src/icmpv6.rs
//!
//! ICMPv6 and the Neighbor Discovery messages IPv6 cannot work without.
//!
//! ## Why this is not "ICMP with a different number"
//!
//! ICMPv6 carries more than a ping.  IPv6 has no ARP: the protocol that
//! turns a neighbour's address into a link-layer address is **Neighbor
//! Solicitation** and **Neighbor Advertisement**, two ICMPv6 message types.
//! A router says it exists and what prefix it serves with **Router
//! Solicitation** and **Router Advertisement**, two more.  So a stack with
//! ICMPv6 echo and no NDP is a stack that can answer a ping from nowhere and
//! send to nowhere: there is no other way to learn a MAC address.
//!
//! That is why this module holds both, and why the tests pin the NDP message
//! layouts byte for byte rather than only the echo.
//!
//! ## The checksum is the pseudo-header's
//!
//! ICMPv6's checksum covers the IPv6 pseudo-header, the source and
//! destination addresses, the length and the next-header value 58, and then
//! the message.  It is **mandatory**: unlike UDP over IPv4 there is no zero
//! that means "not computed", so a receiver verifies every message.  That
//! makes the addresses part of the checksum's input, which is why
//! [`write_message`] takes them rather than only its own bytes.
//!
//! ## The layout
//!
//! ```text
//! ICMPv6   type[1] code[1] checksum[2]               4 bytes
//! echo     identifier[2] sequence[2] data[…]
//! NS       reserved[4] target[16] options[…]
//! NA       flags[4] target[16] options[…]
//! RS       reserved[4] options[…]
//! RA       cur_hop_limit[1] flags[1] lifetime[2]
//!          reachable[4] retransmit[4] options[…]
//! ```
//!
//! ## Options
//!
//! An NDP message carries options after its fixed part, each a type byte, a
//! length **in eight-octet units** (which includes the type and length
//! bytes), and its value.  Two matter to a host: the source link-layer
//! address an advertisement carries, the MAC the asker wanted, and the
//! prefix information a router advertisement carries, which is what makes an
//! address auto-configurable.

use crate::ethernet::get_u16;
use crate::ethernet::put_u16;
use crate::ipv6;
use crate::ipv6::Addr;

/// ICMPv6's next-header value.
pub const NEXT_HEADER: u8 = 58;

/// The fixed part of every ICMPv6 message: type, code, checksum.
pub const HEADER_LEN: usize = 4;

/// Echo reply.
pub const ECHO_REPLY: u8 = 129;
/// Echo request.
pub const ECHO_REQUEST: u8 = 128;
/// Destination unreachable.
pub const DESTINATION_UNREACHABLE: u8 = 1;
/// Packet too big.
pub const PACKET_TOO_BIG: u8 = 2;
/// Time exceeded.
pub const TIME_EXCEEDED: u8 = 3;
/// Parameter problem.
pub const PARAMETER_PROBLEM: u8 = 4;

/// Router solicitation.
pub const ROUTER_SOLICITATION: u8 = 133;
/// Router advertisement.
pub const ROUTER_ADVERTISEMENT: u8 = 134;
/// Neighbor solicitation.
pub const NEIGHBOR_SOLICITATION: u8 = 135;
/// Neighbor advertisement.
pub const NEIGHBOR_ADVERTISEMENT: u8 = 136;

/// The code a `DESTINATION_UNREACHABLE` carries for a closed port.
pub const PORT_UNREACHABLE: u8 = 4;

/// The fixed parts of the NDP messages that carry one, in bytes.
pub const NEIGHBOR_LEN: usize = 20;
/// Router solicitation's fixed part: four reserved bytes.
pub const ROUTER_SOLICITATION_LEN: usize = 4;
/// Router advertisement's fixed part.
pub const ROUTER_ADVERTISEMENT_LEN: usize = 12;

/// The source link-layer address option's type.
pub const OPTION_SOURCE_LINK_LAYER: u8 = 1;
/// The target link-layer address option's type.
pub const OPTION_TARGET_LINK_LAYER: u8 = 2;
/// The prefix information option's type.
pub const OPTION_PREFIX_INFORMATION: u8 = 3;
/// The MTU option's type.
pub const OPTION_MTU: u8 = 5;

/// A parsed ICMPv6 message: its type and code, and where its body starts.
///
/// The checksum is not part of this: [`verify`] is a separate answer because
/// a caller that built the message itself does not need to check it, and one
/// that received it always does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Message {
    pub icmp_type: u8,
    pub code: u8,
    /// Where the type-specific body begins, past the four fixed bytes.
    pub body_at: usize,
    /// How many body bytes the message holds.
    pub body_len: usize,
}

/// Read the ICMPv6 message at the start of `bytes`, or `None` when it is too
/// short to be one.
pub fn parse(bytes: &[u8]) -> Option<Message> {
    if bytes.len() < HEADER_LEN {
        return None;
    }
    Some(Message {
        icmp_type: bytes[0],
        code: bytes[1],
        body_at: HEADER_LEN,
        body_len: bytes.len() - HEADER_LEN,
    })
}

/// Whether a message's checksum verifies against the addresses it travelled
/// between.
///
/// The check is the sender's computation run again: a message whose checksum
/// is correct sums, with its own checksum field included, to zero.
pub fn verify(bytes: &[u8], source: Addr, destination: Addr) -> bool {
    ipv6::checksum_with_pseudo(source, destination, NEXT_HEADER, bytes) == 0
}

/// Write an ICMPv6 message with `body` after its four fixed bytes, and
/// compute the checksum the pseudo-header needs.
///
/// The addresses are the message's own, the source and destination the IPv6
/// header will carry, because they are the checksum's input.
pub fn write_message(
    message: &mut [u8],
    source: Addr,
    destination: Addr,
    icmp_type: u8,
    code: u8,
    body: &[u8],
) {
    message[0] = icmp_type;
    message[1] = code;
    // The checksum field reads zero while it is computed, which is the
    // definition of the computation.
    put_u16(message, 2, 0);
    message[HEADER_LEN..HEADER_LEN + body.len()].copy_from_slice(body);
    let total = HEADER_LEN + body.len();
    let checksum = ipv6::checksum_with_pseudo(source, destination, NEXT_HEADER, &message[..total]);
    put_u16(message, 2, checksum);
}

// echo

/// The fixed part of an echo message: identifier and sequence.
pub const ECHO_LEN: usize = 4;

/// An echo request or reply, as this stack reads one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Echo {
    pub identifier: u16,
    pub sequence: u16,
    /// Where the data the sender included begins, and how much of it there
    /// is.  A reply must carry the request's data back unchanged, which is
    /// what makes the exchange proof the path both ways.
    pub data_at: usize,
    pub data_len: usize,
}

/// How many bytes an echo message of `data_len` data bytes takes.
pub const fn echo_len(data_len: usize) -> usize {
    HEADER_LEN + ECHO_LEN + data_len
}

/// Write an echo message of `kind` with `data` after its identifier and
/// sequence.
///
/// `kind` is [`ECHO_REQUEST`] or [`ECHO_REPLY`]; the two differ in that byte
/// and nothing else, which is why one writer makes both, a reply this stack
/// builds is its request with the type changed and the checksum recomputed.
pub fn write_echo(
    message: &mut [u8],
    source: Addr,
    destination: Addr,
    kind: u8,
    identifier: u16,
    sequence: u16,
    data: &[u8],
) {
    let mut body = [0_u8; ECHO_LEN + 8];
    debug_assert!(data.len() <= 8, "the boot's echo data is eight bytes");
    put_u16(&mut body, 0, identifier);
    put_u16(&mut body, 2, sequence);
    let take = data.len().min(8);
    body[ECHO_LEN..ECHO_LEN + take].copy_from_slice(&data[..take]);
    write_message(
        message,
        source,
        destination,
        kind,
        0,
        &body[..ECHO_LEN + take],
    );
}

/// Read an echo message, or `None` when it is not one or is too short for
/// its own fixed part.
pub fn parse_echo(message: &Message, bytes: &[u8]) -> Option<Echo> {
    if message.icmp_type != ECHO_REQUEST && message.icmp_type != ECHO_REPLY {
        return None;
    }
    if message.body_len < ECHO_LEN {
        return None;
    }
    Some(Echo {
        identifier: get_u16(bytes, message.body_at),
        sequence: get_u16(bytes, message.body_at + 2),
        data_at: message.body_at + ECHO_LEN,
        data_len: message.body_len - ECHO_LEN,
    })
}

// neighbour discovery

/// The flags a neighbour advertisement carries, in its first four bytes.
pub const NEIGHBOR_FLAG_ROUTER: u32 = 0x8000_0000;
pub const NEIGHBOR_FLAG_SOLICITED: u32 = 0x4000_0000;
pub const NEIGHBOR_FLAG_OVERRIDE: u32 = 0x2000_0000;

/// A neighbour solicitation: who has `target`, as this stack writes one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeighborSolicitation {
    pub target: Addr,
}

/// Write a neighbour solicitation asking who holds `target`.
///
/// `source_link_layer` is the asker's MAC, which the advertisement answers to
/// and which the target learns from the option rather than from a separate
/// exchange.  `None` is the solicitation a duplicate-address check sends: it
/// comes from the unspecified address, and a message from `::` must not name
/// a source link-layer address, because the address it would name is the one
/// being questioned.
pub fn write_neighbor_solicitation(
    message: &mut [u8],
    source: Addr,
    target: Addr,
    source_link_layer: Option<[u8; 6]>,
) {
    // The destination is the target's solicited-node group when the asker
    // knows it, which is the whole point of the group: the solicitation wakes
    // one node rather than every node on the link.
    let destination = ipv6::solicited_node(target);
    let mut body = [0_u8; 4 + 16 + 8];
    body[4..20].copy_from_slice(&target);
    let mut body_len = 20;
    if let Some(mac) = source_link_layer {
        body[20] = OPTION_SOURCE_LINK_LAYER;
        // Length in eight-octet units, including the type and length bytes:
        // eight bytes is one unit.
        body[21] = 1;
        body[22..28].copy_from_slice(&mac);
        body_len = 28;
    }
    write_message(
        message,
        source,
        destination,
        NEIGHBOR_SOLICITATION,
        0,
        &body[..body_len],
    );
}

/// A neighbour advertisement: this node holds `target`, and here is its MAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeighborAdvertisement {
    pub target: Addr,
    pub router: bool,
    pub solicited: bool,
    pub override_existing: bool,
    /// Where the target link-layer address option begins, when there is one.
    pub target_link_layer_at: Option<usize>,
}

/// Write a neighbour advertisement answering for `target`.
///
/// `destination` is the asker's address, the solicitation's source, and not
/// a multicast group: an advertisement that answers a solicitation goes to
/// the one node that asked, which is what the solicited flag promises.  The
/// target link-layer address option is mandatory in an advertisement, because
/// it is the whole answer.
pub fn write_neighbor_advertisement(
    message: &mut [u8],
    source: Addr,
    destination: Addr,
    target: Addr,
    target_link_layer: [u8; 6],
    router: bool,
    solicited: bool,
) {
    let mut body = [0_u8; 4 + 16 + 8];
    let mut flags = NEIGHBOR_FLAG_OVERRIDE;
    if router {
        flags |= NEIGHBOR_FLAG_ROUTER;
    }
    if solicited {
        flags |= NEIGHBOR_FLAG_SOLICITED;
    }
    body[..4].copy_from_slice(&flags.to_be_bytes());
    body[4..20].copy_from_slice(&target);
    body[20] = OPTION_TARGET_LINK_LAYER;
    body[21] = 1;
    body[22..28].copy_from_slice(&target_link_layer);
    write_message(
        message,
        source,
        destination,
        NEIGHBOR_ADVERTISEMENT,
        0,
        &body,
    );
}

/// Read a neighbour solicitation's target.
pub fn parse_neighbor_solicitation(
    message: &Message,
    bytes: &[u8],
) -> Option<NeighborSolicitation> {
    if message.icmp_type != NEIGHBOR_SOLICITATION || message.body_len < NEIGHBOR_LEN {
        return None;
    }
    let mut target = [0_u8; 16];
    target.copy_from_slice(&bytes[message.body_at + 4..message.body_at + 20]);
    Some(NeighborSolicitation { target })
}

/// Read a neighbour advertisement's target and flags.
pub fn parse_neighbor_advertisement(
    message: &Message,
    bytes: &[u8],
) -> Option<NeighborAdvertisement> {
    if message.icmp_type != NEIGHBOR_ADVERTISEMENT || message.body_len < NEIGHBOR_LEN {
        return None;
    }
    let flags = u32::from_be_bytes([
        bytes[message.body_at],
        bytes[message.body_at + 1],
        bytes[message.body_at + 2],
        bytes[message.body_at + 3],
    ]);
    let mut target = [0_u8; 16];
    target.copy_from_slice(&bytes[message.body_at + 4..message.body_at + 20]);

    Some(NeighborAdvertisement {
        target,
        router: flags & NEIGHBOR_FLAG_ROUTER != 0,
        solicited: flags & NEIGHBOR_FLAG_SOLICITED != 0,
        override_existing: flags & NEIGHBOR_FLAG_OVERRIDE != 0,
        target_link_layer_at: None,
    })
}

// router discovery

/// The length of an advertisement carrying one prefix option: the fixed part
/// plus the option's thirty-two bytes.
pub const ROUTER_ADVERTISEMENT_WITH_PREFIX_LEN: usize = HEADER_LEN + ROUTER_ADVERTISEMENT_LEN + 32;

/// Write a router advertisement carrying one prefix.
///
/// An advertisement is what a router sends on its own schedule, and a stack
/// that has no router to hear one from still has to prove it can act on one:
/// this writer is for the boot's own probe, and its output goes through the
/// same receive path a real advertisement does.
///
/// The prefix option's fields are the ones [RFC 4861] defines: the length, the
/// on-link and autonomous flags, the two lifetimes, and sixteen bytes of
/// prefix.  The reserved halves are written as zero, which is what a router
/// writes and what a comparison of two advertisements expects.
///
/// [RFC 4861]: https://www.rfc-editor.org/rfc/rfc4861
#[allow(clippy::too_many_arguments)]
pub fn write_router_advertisement(
    message: &mut [u8],
    source: Addr,
    destination: Addr,
    current_hop_limit: u8,
    router_lifetime: u16,
    reachable_time: u32,
    retransmit_timer: u32,
    prefix: Addr,
    prefix_len: u8,
    autonomous: bool,
    valid_lifetime: u32,
    preferred_lifetime: u32,
) {
    let mut body = [0_u8; ROUTER_ADVERTISEMENT_LEN + 32];
    body[0] = current_hop_limit;
    // The reserved flag bits stay zero; the autonomous one is the caller's.
    if autonomous {
        body[1] |= 0x40;
    }
    body[2..4].copy_from_slice(&router_lifetime.to_be_bytes());
    body[4..8].copy_from_slice(&reachable_time.to_be_bytes());
    body[8..12].copy_from_slice(&retransmit_timer.to_be_bytes());

    // The prefix option, after the advertisement's fixed part.
    let option = ROUTER_ADVERTISEMENT_LEN;
    body[option] = OPTION_PREFIX_INFORMATION;
    body[option + 1] = 4; // thirty-two bytes, in eight-octet units
    body[option + 2] = prefix_len;
    // The option's own flag byte: on-link and autonomous.
    body[option + 3] = 0x80 | if autonomous { 0x40 } else { 0 };
    body[option + 4..option + 8].copy_from_slice(&valid_lifetime.to_be_bytes());
    body[option + 8..option + 12].copy_from_slice(&preferred_lifetime.to_be_bytes());
    body[option + 12..option + 14].copy_from_slice(&0u16.to_be_bytes()); // reserved
    body[option + 16..option + 32].copy_from_slice(&prefix);

    write_message(message, source, destination, ROUTER_ADVERTISEMENT, 0, &body);
}

/// Write a router solicitation, which asks the link's routers to answer with
/// an advertisement.
///
/// The destination is the all-routers group, because the asker does not know
/// any router's address, that is the question.
pub fn write_router_solicitation(message: &mut [u8], source: Addr, source_link_layer: [u8; 6]) {
    let mut body = [0_u8; 4 + 8];
    body[4] = OPTION_SOURCE_LINK_LAYER;
    body[5] = 1;
    body[6..12].copy_from_slice(&source_link_layer);
    write_message(
        message,
        source,
        ipv6::ALL_ROUTERS_MULTICAST,
        ROUTER_SOLICITATION,
        0,
        &body,
    );
}

/// A router advertisement's fixed part, and where its options begin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouterAdvertisement {
    pub current_hop_limit: u8,
    pub managed: bool,
    pub other_config: bool,
    /// The router's lifetime in seconds; zero means it is not a default
    /// router and its prefix is only for on-link addressing.
    pub router_lifetime: u16,
    pub reachable_time: u32,
    pub retransmit_timer: u32,
    /// Where the options begin, and how many bytes of them there are.
    pub options_at: usize,
    pub options_len: usize,
}

/// Read a router advertisement's fixed part.
pub fn parse_router_advertisement(message: &Message, bytes: &[u8]) -> Option<RouterAdvertisement> {
    if message.icmp_type != ROUTER_ADVERTISEMENT || message.body_len < ROUTER_ADVERTISEMENT_LEN {
        return None;
    }
    let at = message.body_at;
    let flags = bytes[at + 1];
    Some(RouterAdvertisement {
        current_hop_limit: bytes[at],
        managed: flags & 0x80 != 0,
        other_config: flags & 0x40 != 0,
        router_lifetime: get_u16(bytes, at + 2),
        reachable_time: u32::from_be_bytes([
            bytes[at + 4],
            bytes[at + 5],
            bytes[at + 6],
            bytes[at + 7],
        ]),
        retransmit_timer: u32::from_be_bytes([
            bytes[at + 8],
            bytes[at + 9],
            bytes[at + 10],
            bytes[at + 11],
        ]),
        options_at: at + ROUTER_ADVERTISEMENT_LEN,
        options_len: message.body_len - ROUTER_ADVERTISEMENT_LEN,
    })
}

// options

/// One NDP option: its type, and where its value begins and how long it is.
///
/// The length byte counts eight-octet units **including the type and length**
/// themselves, so the smallest option is eight bytes and the value is six of
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NdpOption {
    pub option_type: u8,
    /// Where the option's value begins.
    pub value_at: usize,
    /// How many value bytes it holds.
    pub value_len: usize,
}

/// The options an NDP message carries, as an iterator-shaped walk.
///
/// A malformed option, one whose length byte is zero, or one that runs past
/// the message, ends the walk rather than being skipped: stepping by a
/// length that is zero is a loop that never ends, and stepping past the end
/// is a read of bytes that belong to something else.
pub fn option_at(bytes: &[u8], at: usize, end: usize) -> Option<(NdpOption, usize)> {
    if at + 2 > end {
        return None;
    }
    let units = bytes[at + 1] as usize;
    if units == 0 {
        return None;
    }
    let option_len = units * 8;
    if at + option_len > end {
        return None;
    }
    Some((
        NdpOption {
            option_type: bytes[at],
            value_at: at + 2,
            value_len: option_len - 2,
        },
        at + option_len,
    ))
}

/// The link-layer address a message's source or target option carries, if it
/// has one.
///
/// `option_type` is [`OPTION_SOURCE_LINK_LAYER`] for a solicitation or a
/// router advertisement's source, or [`OPTION_TARGET_LINK_LAYER`] for an
/// advertisement's answer.
pub fn link_layer_option(bytes: &[u8], at: usize, end: usize, option_type: u8) -> Option<[u8; 6]> {
    let mut cursor = at;
    while let Some((option, next)) = option_at(bytes, cursor, end) {
        if option.option_type == option_type && option.value_len >= 6 {
            let mut mac = [0_u8; 6];
            mac.copy_from_slice(&bytes[option.value_at..option.value_at + 6]);
            return Some(mac);
        }
        cursor = next;
    }
    None
}

/// A prefix information option's fields, and where its prefix starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixInformation {
    pub prefix_len: u8,
    pub on_link: bool,
    pub autonomous: bool,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    pub prefix_at: usize,
}

/// The prefix information a router advertisement carries, if it carries one.
///
/// `autonomous` is the flag that says the prefix may be used for stateless
/// address configuration, the router saying "append an interface identifier
/// to this and you have an address", and it is the one this stack needs.
pub fn prefix_information(bytes: &[u8], at: usize, end: usize) -> Option<PrefixInformation> {
    let mut cursor = at;
    while let Some((option, next)) = option_at(bytes, cursor, end) {
        if option.option_type == OPTION_PREFIX_INFORMATION && option.value_len >= 30 {
            let flags = bytes[option.value_at + 1];
            return Some(PrefixInformation {
                prefix_len: bytes[option.value_at],
                on_link: flags & 0x80 != 0,
                autonomous: flags & 0x40 != 0,
                valid_lifetime: u32::from_be_bytes([
                    bytes[option.value_at + 2],
                    bytes[option.value_at + 3],
                    bytes[option.value_at + 4],
                    bytes[option.value_at + 5],
                ]),
                preferred_lifetime: u32::from_be_bytes([
                    bytes[option.value_at + 6],
                    bytes[option.value_at + 7],
                    bytes[option.value_at + 8],
                    bytes[option.value_at + 9],
                ]),
                prefix_at: option.value_at + 14,
            });
        }
        cursor = next;
    }
    None
}

#[cfg(test)]
mod tests {
    //! The tests for this module.
    //!
    //! ICMPv6's checksum over the pseudo-header, the echo exchange, and the
    //! NDP messages, because IPv6 has no ARP, and a stack that could not
    //! write a neighbour solicitation could not send to a neighbour at all.
    //!
    //! The NDP tests pin the layout byte for byte: a solicitation whose
    //! target is one byte off is a question about a different address, and
    //! the answer it gets would be an advertisement for a node that is not
    //! there.

    use super::*;
    use alloc::vec;

    fn link_local(last: u8) -> Addr {
        let mut address = [0_u8; 16];
        address[0] = 0xFE;
        address[1] = 0x80;
        address[15] = last;
        address
    }

    /// The echo exchange: a request this stack writes parses back, its
    /// checksum verifies over the pseudo-header, and a reply is the request
    /// with the type byte changed.
    #[test]
    fn an_echo_request_round_trips_and_verifies() {
        let source = link_local(1);
        let destination = link_local(2);
        let mut request = vec![0_u8; echo_len(8)];
        write_echo(
            &mut request,
            source,
            destination,
            ECHO_REQUEST,
            0x1234,
            7,
            b"pyrofire",
        );

        assert!(
            verify(&request, source, destination),
            "the checksum verifies"
        );
        let message = parse(&request).expect("a message");
        assert_eq!(message.icmp_type, ECHO_REQUEST);
        let echo = parse_echo(&message, &request).expect("an echo");
        assert_eq!(echo.identifier, 0x1234);
        assert_eq!(echo.sequence, 7);
        assert_eq!(&request[echo.data_at..][..echo.data_len], b"pyrofire");

        // The reply carries the request's data back, which is the point.
        let mut reply = vec![0_u8; echo_len(8)];
        write_echo(
            &mut reply,
            destination,
            source,
            ECHO_REPLY,
            echo.identifier,
            echo.sequence,
            b"pyrofire",
        );
        assert!(verify(&reply, destination, source));
        assert_ne!(request[0], reply[0], "the type byte is what differs");
    }

    /// A message whose checksum was computed for other addresses does not
    /// verify, which is why the addresses are the writer's arguments.
    #[test]
    fn the_checksum_is_bound_to_the_addresses() {
        let source = link_local(1);
        let destination = link_local(2);
        let other = link_local(3);
        let mut request = vec![0_u8; echo_len(0)];
        write_echo(&mut request, source, destination, ECHO_REQUEST, 1, 1, b"");

        assert!(verify(&request, source, destination));
        assert!(!verify(&request, source, other), "a different destination");
        assert!(!verify(&request, other, destination), "a different source");
    }

    /// A neighbour solicitation asks about its target at the target's
    /// solicited-node group, and carries the asker's MAC so the answer needs
    /// no second question.
    #[test]
    fn a_neighbor_solicitation_asks_the_solicited_node_group() {
        let asker = link_local(1);
        let target = link_local(2);
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let mut message = vec![0_u8; HEADER_LEN + 20 + 8];
        write_neighbor_solicitation(&mut message, asker, target, Some(mac));

        let parsed = parse(&message).expect("a message");
        assert_eq!(parsed.icmp_type, NEIGHBOR_SOLICITATION);
        let solicitation = parse_neighbor_solicitation(&parsed, &message).expect("a solicitation");
        assert_eq!(solicitation.target, target, "the target is the question");

        // The source link-layer option is the asker's MAC.
        assert_eq!(
            link_layer_option(
                &message,
                parsed.body_at + NEIGHBOR_LEN,
                message.len(),
                OPTION_SOURCE_LINK_LAYER
            ),
            Some(mac)
        );

        // The IPv6 destination the message was written for is the target's
        // solicited-node group, and its Ethernet mapping is 33:33 and the
        // group's low four.
        let destination = ipv6::solicited_node(target);
        assert!(ipv6::is_multicast(destination));
        assert_eq!(
            ipv6::multicast_mac(destination),
            [0x33, 0x33, 0xFF, 0x00, 0x00, 0x02]
        );
    }

    /// A duplicate-address check asks from the unspecified address and names
    /// no source link-layer option, because the address it would name is the
    /// one being questioned.
    #[test]
    fn a_dad_solicitation_names_no_source_link_layer() {
        let target = link_local(2);
        let mut message = vec![0_u8; HEADER_LEN + NEIGHBOR_LEN];
        write_neighbor_solicitation(&mut message, ipv6::UNSPECIFIED, target, None);

        let parsed = parse(&message).expect("a message");
        assert_eq!(
            link_layer_option(
                &message,
                parsed.body_at + NEIGHBOR_LEN,
                message.len(),
                OPTION_SOURCE_LINK_LAYER
            ),
            None
        );
        assert!(
            verify(&message, ipv6::UNSPECIFIED, ipv6::solicited_node(target)),
            "a message from :: checksums against ::"
        );
    }

    /// A neighbour advertisement answers with the target's MAC, the whole
    /// answer, and its flags say whether a router sent it and whether it
    /// answers a solicitation.
    #[test]
    fn a_neighbor_advertisement_carries_the_target_mac() {
        let responder = link_local(2);
        let asker = link_local(1);
        let target = responder;
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x57];
        let mut message = vec![0_u8; HEADER_LEN + NEIGHBOR_LEN + 8];
        write_neighbor_advertisement(&mut message, responder, asker, target, mac, false, true);

        let parsed = parse(&message).expect("a message");
        let advertisement =
            parse_neighbor_advertisement(&parsed, &message).expect("an advertisement");
        assert_eq!(advertisement.target, target);
        assert!(advertisement.solicited, "it answers a question");
        assert!(!advertisement.router, "this node is not a router");
        assert!(advertisement.override_existing);

        assert_eq!(
            link_layer_option(
                &message,
                parsed.body_at + NEIGHBOR_LEN,
                message.len(),
                OPTION_TARGET_LINK_LAYER
            ),
            Some(mac),
            "the MAC is the answer"
        );
    }

    /// A router solicitation goes to every router on the link and names the
    /// asker's MAC.
    #[test]
    fn a_router_solicitation_reaches_the_routers_group() {
        let asker = link_local(1);
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let mut message = vec![0_u8; HEADER_LEN + ROUTER_SOLICITATION_LEN + 8];
        write_router_solicitation(&mut message, asker, mac);

        let parsed = parse(&message).expect("a message");
        assert_eq!(parsed.icmp_type, ROUTER_SOLICITATION);
        assert_eq!(
            link_layer_option(
                &message,
                parsed.body_at + ROUTER_SOLICITATION_LEN,
                message.len(),
                OPTION_SOURCE_LINK_LAYER
            ),
            Some(mac)
        );
        assert!(verify(&message, asker, ipv6::ALL_ROUTERS_MULTICAST));
    }

    /// A router advertisement's fixed part parses, and its prefix option is
    /// what makes an address auto-configurable.
    #[test]
    fn a_router_advertisement_carries_a_prefix() {
        let router = link_local(1);
        let everyone = ipv6::ALL_NODES_MULTICAST;

        // The fixed part, then a prefix information option (32 bytes).
        let mut body = vec![0_u8; ROUTER_ADVERTISEMENT_LEN + 32];
        body[0] = 64; // current hop limit
        body[1] = 0; // no managed, no other-config
        body[2..4].copy_from_slice(&1800_u16.to_be_bytes()); // router lifetime
        body[4..8].copy_from_slice(&30_000_u32.to_be_bytes()); // reachable
        body[8..12].copy_from_slice(&1_000_u32.to_be_bytes()); // retransmit

        let option = ROUTER_ADVERTISEMENT_LEN;
        body[option] = OPTION_PREFIX_INFORMATION;
        body[option + 1] = 4; // 32 bytes
        body[option + 2] = 64; // prefix length
        body[option + 3] = 0xC0; // on-link and autonomous
        body[option + 4..option + 8].copy_from_slice(&86_400_u32.to_be_bytes());
        body[option + 8..option + 12].copy_from_slice(&14_400_u32.to_be_bytes());
        // Prefix bytes at option + 16, sixteen of them.
        body[option + 16] = 0x20;
        body[option + 17] = 0x01;
        body[option + 18] = 0x0D;
        body[option + 19] = 0xB8;

        let mut message = vec![0_u8; HEADER_LEN + body.len()];
        write_message(
            &mut message,
            router,
            everyone,
            ROUTER_ADVERTISEMENT,
            0,
            &body,
        );

        let parsed = parse(&message).expect("a message");
        let advertisement =
            parse_router_advertisement(&parsed, &message).expect("an advertisement");
        assert_eq!(advertisement.current_hop_limit, 64);
        assert_eq!(advertisement.router_lifetime, 1800);
        assert_eq!(advertisement.reachable_time, 30_000);
        assert!(!advertisement.managed);

        let prefix = prefix_information(
            &message,
            advertisement.options_at,
            advertisement.options_at + advertisement.options_len,
        )
        .expect("a prefix");
        assert_eq!(prefix.prefix_len, 64);
        assert!(prefix.autonomous, "the prefix may configure an address");
        assert!(prefix.on_link);
        assert_eq!(prefix.valid_lifetime, 86_400);
        assert_eq!(
            &message[prefix.prefix_at..prefix.prefix_at + 4],
            &[0x20, 0x01, 0x0D, 0xB8]
        );
    }

    /// An option whose length byte is zero ends the walk rather than looping
    /// on it, and one that runs past the message is refused.
    #[test]
    fn a_malformed_option_ends_the_walk() {
        // A length of zero would step nowhere forever.
        let bytes = [OPTION_SOURCE_LINK_LAYER, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(option_at(&bytes, 0, bytes.len()), None);

        // A length of two (sixteen bytes) in an eight-byte message.
        let bytes = [OPTION_SOURCE_LINK_LAYER, 2, 0, 0, 0, 0, 0, 0];
        assert_eq!(option_at(&bytes, 0, bytes.len()), None);

        // A well-formed one is eight bytes and its value is six.
        let bytes = [OPTION_TARGET_LINK_LAYER, 1, 1, 2, 3, 4, 5, 6];
        let (option, next) = option_at(&bytes, 0, bytes.len()).expect("an option");
        assert_eq!(option.option_type, OPTION_TARGET_LINK_LAYER);
        assert_eq!(option.value_at, 2);
        assert_eq!(option.value_len, 6);
        assert_eq!(next, 8);
    }

    /// The error types this module answers are the ones a stack reacts to:
    /// port unreachable makes a sender's datagram fail, and packet too big
    /// makes it shrink.
    #[test]
    fn the_error_types_are_the_ones_a_sender_reacts_to() {
        assert_eq!(DESTINATION_UNREACHABLE, 1);
        assert_eq!(PACKET_TOO_BIG, 2);
        assert_eq!(TIME_EXCEEDED, 3);
        assert_eq!(PORT_UNREACHABLE, 4);

        // A port-unreachable message verifies like any other.
        let target = link_local(2);
        let sender = link_local(1);
        let mut body = vec![0_u8; 4 + 8];
        body[4..].copy_from_slice(b"\x21\x94\x21\x95\x00\x08\x00\x00");
        let mut message = vec![0_u8; HEADER_LEN + body.len()];
        write_message(
            &mut message,
            target,
            sender,
            DESTINATION_UNREACHABLE,
            PORT_UNREACHABLE,
            &body,
        );
        let parsed = parse(&message).expect("a message");
        assert_eq!(parsed.icmp_type, DESTINATION_UNREACHABLE);
        assert_eq!(parsed.code, PORT_UNREACHABLE);
        assert!(verify(&message, target, sender));
    }
}
