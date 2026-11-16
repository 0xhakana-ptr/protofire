//! kernel/src/net/demux6.rs
//!
//! The same for IPv6: the demux, ICMPv6, neighbour discovery, the router
//! advertisement's route, and the fragment cache.
//!
//! One section of `kernel/src/net/mod.rs`.  The sections call each other in
//! both directions: the demux reaches every protocol's delivery and a protocol
//! reaches the interface, so each names what it needs through `super::`.  What
//! the split buys is that a reader looking for one protocol opens one file.

use super::core::FRAGMENTS;
use super::core::INTERFACE;
use super::core::TCP;
use super::core::deliver_udp;
use super::core::fragment_now;
use super::demux4::Report;
use super::demux4::quoted_segment;
use super::filter::filter_inbound;
use super::tcp::route_stream6;

/// What one received IPv6 packet means, and where it goes.
///
/// The chain is walked before anything else: a packet with an extension
/// header that this stack read as a transport header would deliver a
/// solicitation's bytes to a socket's port.  A fragment is dropped rather
/// than reassembled, this stack has no reassembly buffer, and the
/// alternative is to read the first piece as the whole packet, which is a
/// wrong answer that looks like a right one.
///
/// The three things a host does with what it reads here: learn a neighbour's
/// MAC from an advertisement, answer a solicitation for an address it holds,
/// and answer a neighbor's echo.
pub(crate) fn demux_ipv6(frame: &[u8]) {
    let Some(packet) = net::ipv6::parse(frame) else {
        return;
    };
    {
        let interface = INTERFACE.lock();
        let Some(interface) = interface.as_ref() else {
            return;
        };
        // A packet for another machine on the wire is not ours to read.  The
        // check is against the fixed group array plus a global address's own
        // solicited-node group, computed rather than stored: the receive path
        // runs in interrupt context and must not allocate.
        let joined = interface.ipv6_groups;
        let mut for_us = net::ipv6::is_for(&packet, interface.ipv6, &joined);
        if let Some(global) = interface.ipv6_global {
            for_us = for_us
                || packet.header.destination == global
                || packet.header.destination == net::ipv6::solicited_node(global);
        }
        if !for_us {
            return;
        }
    }

    let Some(next) = net::ipv6::walk(frame, &packet) else {
        return;
    };
    // The filter, at the same point in the other family: after the packet is
    // known to be this machine's and before a piece of it is held or a
    // transport reads it.  A first fragment carries the transport header and
    // so has its ports; a later one does not, and is matched as a packet whose
    // protocol has no ports, which is the same answer IPv4's path gives.
    let (filtered_header, filtered_at, filtered_len) = match next {
        net::ipv6::Next::Payload {
            next_header,
            at,
            len,
        } => (next_header, at, len),
        net::ipv6::Next::Fragment {
            next_header,
            at,
            len,
            ..
        } => (next_header, at, len),
    };
    if !filter_inbound(&net::filter::Packet::v6(
        packet.header.source,
        packet.header.destination,
        filtered_header,
        &frame[filtered_at..filtered_at + filtered_len],
    )) {
        return;
    }
    // A piece of a larger packet is held rather than read as the whole: the
    // bytes at an offset are not a segment, and parsing them as one is how a
    // stack answers with a truncated segment that looks complete.  The piece
    // that says no more follow, plus every byte before it, is the datagram.
    let assembled: alloc::vec::Vec<u8>;
    let (next_header, payload) = match next {
        net::ipv6::Next::Payload {
            next_header,
            at,
            len,
        } => (next_header, &frame[at..at + len]),
        net::ipv6::Next::Fragment {
            next_header,
            offset,
            more,
            identification,
            at,
            len,
        } => {
            let key = net::reassembly::Key {
                family: 6,
                source: net::address::Address::V6(packet.header.source),
                destination: net::address::Address::V6(packet.header.destination),
                identification,
                next_header,
            };
            let piece = net::reassembly::Piece {
                data: &frame[at..at + len],
                offset: offset as usize,
                more,
            };
            match FRAGMENTS.lock().accept(key, piece, fragment_now()) {
                net::reassembly::Outcome::Complete(bytes) => {
                    // The transport header is at the front of the assembled
                    // payload, which is exactly what a whole packet's payload
                    // would be.  The bytes move into a binding that outlives
                    // this arm, because the match's own binding would not.
                    assembled = bytes;
                    (next_header, &assembled[..])
                }
                net::reassembly::Outcome::Collected => return,
                net::reassembly::Outcome::Refused(_) => return,
            }
        }
    };

    match next_header {
        net::ipv6::NEXT_ICMPV6 => handle_icmpv6(&packet, payload),
        net::ipv6::NEXT_UDP => {
            // The pseudo-header a datagram's checksum covers over IPv6 is
            // forty bytes of addresses, so the parse takes them: a datagram
            // is accepted only if it was built for this pair.
            if let Some(datagram) =
                net::udp::parse6(payload, packet.header.source, packet.header.destination)
            {
                let at = net::udp::HEADER_LEN;
                let _ = deliver_udp(
                    net::address::Address::V6(packet.header.destination),
                    datagram.destination_port,
                    net::address::Address::V6(packet.header.source),
                    datagram.source_port,
                    &payload[at..at + datagram.payload_len],
                );
            }
        }
        net::ipv6::NEXT_TCP => route_stream6(&packet, payload),
        _ => {}
    }
}

/// What an ICMPv6 message means to this host.
///
/// Three answers and nothing else: an advertisement fills the neighbour
/// cache, a solicitation for one of this host's addresses is answered, and
/// an echo request is replied to.  A message that is none of those is read
/// for nothing, this stack has no error path above it yet, and pretending
/// to react to a packet-too-big would be a reaction with no shrunken send.
fn handle_icmpv6(packet: &net::ipv6::Packet, payload: &[u8]) {
    let Some(message) = net::icmpv6::parse(payload) else {
        return;
    };
    // The checksum is over the message and the addresses its header carried,
    // which is why the packet is an argument.
    if !net::icmpv6::verify(payload, packet.header.source, packet.header.destination) {
        return;
    }

    match message.icmp_type {
        net::icmpv6::NEIGHBOR_ADVERTISEMENT => {
            if let Some(advertisement) =
                net::icmpv6::parse_neighbor_advertisement(&message, payload)
                && let Some(mac) = net::icmpv6::link_layer_option(
                    payload,
                    message.body_at + net::icmpv6::NEIGHBOR_LEN,
                    payload.len(),
                    net::icmpv6::OPTION_TARGET_LINK_LAYER,
                )
            {
                let mut interface = INTERFACE.lock();
                if let Some(interface) = interface.as_mut() {
                    interface.ndp.learn(advertisement.target, mac, 0);
                }
            }
        }
        net::icmpv6::NEIGHBOR_SOLICITATION => {
            answer_neighbor_solicitation(packet, &message, payload);
        }
        net::icmpv6::ECHO_REQUEST => {
            answer_echo_request(packet, &message, payload);
        }
        net::icmpv6::ROUTER_ADVERTISEMENT => {
            learn_from_router(packet, &message, payload);
        }
        // A packet-too-big or a destination-unreachable report names one of
        // this machine's packets by quoting it, and the two messages whose
        // answer is a stream are handled together because the reading is the
        // same: where the quotation starts, which four-tuple it names, and
        // whether the packet it quotes left from this machine.
        net::icmpv6::PACKET_TOO_BIG
        | net::icmpv6::DESTINATION_UNREACHABLE
        | net::icmpv6::TIME_EXCEEDED
        | net::icmpv6::PARAMETER_PROBLEM => {
            handle_icmpv6_error(packet, payload);
        }
        _ => {}
    }
}

/// What one received ICMPv6 error means to this stack.
///
/// The same two answers the IPv4 side gives: a **packet-too-big** report is
/// the path's size and shrinks every stream its quotation names, and a
/// **destination unreachable** ends the stream it names.  Time-exceeded and
/// parameter-problem are read and dropped: the first is a loop or a hop limit
/// the path could not cross, and this stack has no route to look for a loop
/// on; the second names a header field, and this stack writes no option a
/// router could refuse.
///
/// The quotation starts eight bytes in, not four: this message's MTU word
/// occupies the space an IPv4 error leaves unused, which is the layout
/// difference that makes this a second function rather than the IPv4 one with
/// a flag.
fn handle_icmpv6_error(packet: &net::ipv6::Packet, payload: &[u8]) {
    let Some(error) = net::icmpv6::parse_error(payload) else {
        return;
    };
    let Some(report) = quoted_report6(packet.header.destination, &error, payload) else {
        return;
    };
    match error.kind {
        net::icmpv6::PACKET_TOO_BIG => {
            // IPv6 has no router fragmentation, so this report is the only
            // way a sender learns a path is smaller than what it sent, and
            // the MTU it states is a whole packet's.  A report with no usable
            // number falls back to the protocol's floor, which [RFC 8200]
            // guarantees every link carries.
            //
            // [RFC 8200]: https://www.rfc-editor.org/rfc/rfc8200
            let mtu = error
                .mtu
                .map(|mtu| mtu as usize)
                .filter(|mtu| *mtu >= net::ipv6::HEADER_LEN + net::tcp::HEADER_LEN)
                .unwrap_or(net::ipv6::MIN_MTU);
            let limit = mtu
                .saturating_sub(net::ipv6::HEADER_LEN)
                .saturating_sub(net::tcp::HEADER_LEN);
            let _ = TCP
                .lock()
                .limit_path(report.remote, report.local_port, limit);
        }
        net::icmpv6::DESTINATION_UNREACHABLE => {
            let aborted = TCP.lock().abort_path(report.remote, report.local_port);
            #[cfg(target_os = "none")]
            if aborted {
                arch::serial::write_str("protofire: an icmpv6 error ended a stream\n");
            }
            #[cfg(not(target_os = "none"))]
            let _ = aborted;
        }
        _ => {}
    }
}

/// What an ICMPv6 report says about one of this machine's streams.
///
/// The same reading the IPv4 side does, over a different quotation offset and
/// a different header: the quoted packet is one this machine **sent**, so the
/// port it names first is ours, and the address it was sent to is the peer's.
fn quoted_report6(
    our_address: net::ipv6::Addr,
    error: &net::icmpv6::Error,
    payload: &[u8],
) -> Option<Report> {
    let quoted = payload.get(error.quoted_at..error.quoted_at + error.quoted_len)?;
    let original = net::ipv6::parse(quoted)?;
    // The same check the IPv4 side makes, and for the same reason: the quoted
    // packet must have left from this machine, or the report is a stranger's
    // claim about somebody else's packet.
    if original.header.source != our_address {
        return None;
    }
    // The chain is walked, because a quotation may carry an extension header
    // between the fixed header and the transport: a report about a packet with
    // one would otherwise have its ports read out of the extension, and the
    // base header's `next_header` names the extension rather than the
    // transport.
    let next = net::ipv6::walk(quoted, &original)?;
    let (protocol, transport_at) = match next {
        net::ipv6::Next::Payload {
            next_header, at, ..
        } => (next_header, at),
        // A quotation that stops inside its own extension chain names no
        // transport, and a report about it names no stream this stack can
        // match.
        net::ipv6::Next::Fragment { .. } => return None,
    };
    let transport = quoted.get(transport_at..)?;
    let ports = quoted_segment(protocol, transport)?;
    Some(Report {
        remote: (
            net::address::Address::V6(original.header.destination),
            ports.destination_port,
        ),
        local_port: ports.source_port,
    })
}

/// Configure a global address from a router's advertisement.
///
/// The advertisement's prefix option is what says a network exists and whether
/// this host may make an address in it.  [`net::ndp::configure_from`] is the
/// decision, the autonomous flag and the prefix length and the valid
/// lifetime, and this function is the state it changes: the address goes on the
/// interface, joins its solicited-node group, and remembers the router's own
/// link-layer address so later unicast needs no second solicitation.
///
/// An advertisement is not solicited by this stack: nothing here sends a
/// router solicitation, because a router broadcasts one on its own schedule
/// and a boot that waited for an answer it asked for would wait for a machine
/// that may not be there.  An advertisement that arrives is used; one that
/// never arrives leaves the interface with its link-local address, which is
/// the state this stack can guarantee.
fn learn_from_router(packet: &net::ipv6::Packet, message: &net::icmpv6::Message, payload: &[u8]) {
    let Some(advertisement) = net::icmpv6::parse_router_advertisement(message, payload) else {
        return;
    };
    let mut interface = INTERFACE.lock();
    let Some(interface) = interface.as_mut() else {
        return;
    };
    // The router itself, learned whether or not the advertisement carries a
    // prefix.  The address is the message's **source**, which is what a router
    // sends from and what a host sends off-link traffic to; the lifetime is
    // what says whether it is willing to be one, and zero is a router saying
    // it is not.  A prefix and a default route are two separate facts and an
    // advertisement may carry either, which is why the first version of this
    // learned neither when the prefix was absent: it returned before reading
    // the lifetime.
    //
    // Only a **link-local** source is taken: a router that advertises from a
    // global address is one a host would have to route to reach, which is the
    // question this field answers.  A lifetime of zero withdraws the route the
    // same router may have offered before, which is how a router says it is
    // going away.
    interface.ipv6_router = (advertisement.router_lifetime > 0
        && net::ipv6::is_link_local(packet.header.source))
    .then_some(packet.header.source);

    let Some(prefix) = net::icmpv6::prefix_information(
        payload,
        advertisement.options_at,
        advertisement.options_at + advertisement.options_len,
    ) else {
        // No prefix: the advertisement's whole content was the default route,
        // and that is already recorded.
        return;
    };
    let Some(configuration) = net::ndp::configure_from(&prefix, payload, interface.hardware) else {
        return;
    };
    interface.ipv6_global = Some(configuration.address);
    // The group the new address answers on.  A fixed array has room for the
    // one a link-local-only interface holds, and the global's takes the slot
    // the all-routers group used: a host that has a global address still
    // answers solicitations for it, and the all-routers group is the one a
    // solicitation is *sent* to rather than one this interface receives on.
    let group = net::ipv6::solicited_node(configuration.address);
    if let Some(slot) = interface
        .ipv6_groups
        .iter_mut()
        .find(|existing| **existing == net::ipv6::ALL_ROUTERS_MULTICAST)
    {
        *slot = group;
    }
}

/// Answer an echo request: the reply carries the request's identifier,
/// sequence and data back unchanged, which is what makes the round trip proof
/// of the path both ways.
fn answer_echo_request(packet: &net::ipv6::Packet, message: &net::icmpv6::Message, payload: &[u8]) {
    let Some(echo) = net::icmpv6::parse_echo(message, payload) else {
        return;
    };
    // Only a request is answered: a reply that drew a reply is a loop, and
    // this stack's own request is answered by whoever it was sent to.
    if message.icmp_type != net::icmpv6::ECHO_REQUEST {
        return;
    }
    let (card, mac, local) = {
        let interface = INTERFACE.lock();
        let Some(interface) = interface.as_ref() else {
            return;
        };
        (interface.card.clone(), interface.hardware, interface.ipv6)
    };
    // The reply goes back to the sender, from the address it asked: the two
    // are the checksum's input, so using anything else would make the reply
    // fail the asker's verification.
    let destination = packet.header.source;

    let mut frame = alloc::vec![0_u8; card.maximum_frame_len()];
    let data = &payload[echo.data_at..echo.data_at + echo.data_len.min(8)];
    let Some(total) = net::reply::echo_reply(
        &mut frame,
        local,
        mac,
        destination,
        peer_hardware(destination),
        &echo,
        data,
    ) else {
        return;
    };
    let _ = card.submit_frame(&frame[..total]);

    // The line that says the exchange happened, and what it carried: the
    // identifier and sequence are the request's, which is what a sender
    // compares to know the reply is its own.
    #[cfg(target_os = "none")]
    {
        arch::serial::write_str("protofire: ipv6 echo reply to ");
        write_ipv6(destination);
        arch::serial::write_str(", identifier ");
        arch::serial::write_u32(echo.identifier as u32);
        arch::serial::write_str(", sequence ");
        arch::serial::write_u32(echo.sequence as u32);
        arch::serial::write_str(", ");
        arch::serial::write_u32(echo.data_len as u32);
        arch::serial::write_str(" byte(s)\n");
    }
}

/// The hardware address a unicast IPv6 destination's frame is sent to.
///
/// The neighbour cache's answer when the wire gave one, and the solicited-node
/// group's mapping when it did not, a reply to a node this stack has not
/// resolved goes to a group that node joined, which is what makes an
/// advertisement's answer reach a host whose cache is empty.
pub(crate) fn peer_hardware(destination: net::ipv6::Addr) -> [u8; 6] {
    let interface = INTERFACE.lock();
    let interface = match interface.as_ref() {
        Some(interface) => interface,
        // No interface: nothing has an answer, and a solicited-node group is
        // the frame's best chance of reaching whoever holds the address.
        None => return net::ipv6::multicast_mac(net::ipv6::solicited_node(destination)),
    };
    // A multicast destination goes to the group's own hardware address, which
    // is arithmetic rather than discovery.
    if net::ipv6::is_multicast(destination) {
        return net::ipv6::multicast_mac(destination);
    }
    // A neighbour the cache knows.
    if let Some(mac) = interface.ndp.lookup(destination) {
        return mac;
    }
    // A neighbour on this link that the cache does not know: the solicitation
    // for its own address is the frame that will teach it, and the Mac is the
    // solicited-node group's.
    if interface.is_on_link(destination) {
        return net::ipv6::multicast_mac(net::ipv6::solicited_node(destination));
    }
    // Off this link: the default router, and the cache's answer for **it**.
    // This is the routing decision IPv6 has and the one this stack was
    // missing: without it an off-link destination resolved to a solicited-node
    // group on this link, which is a frame no machine answers because the
    // machine that holds it is not here.
    match interface
        .ipv6_router
        .and_then(|router| interface.ndp.lookup(router))
    {
        Some(mac) => mac,
        // The router's hardware address is not known yet, so the frame goes to
        // the solicited-node group of the **router's** address: its own answer
        // is what fills the cache, and the next frame takes the branch above.
        None => interface
            .ipv6_router
            .map(|router| net::ipv6::multicast_mac(net::ipv6::solicited_node(router)))
            .unwrap_or_else(|| net::ipv6::multicast_mac(net::ipv6::solicited_node(destination))),
    }
}

/// Answer a solicitation for an address this host holds.
///
/// The answer is the advertisement the asker wanted, sent to the asker's own
/// address rather than to a group, which is what the solicited flag means
/// and it is sent only when the target is one of ours: answering for another
/// node's address is how two hosts claim one address.
fn answer_neighbor_solicitation(
    packet: &net::ipv6::Packet,
    message: &net::icmpv6::Message,
    payload: &[u8],
) {
    let Some(solicitation) = net::icmpv6::parse_neighbor_solicitation(message, payload) else {
        return;
    };

    let (ours, mac, card) = {
        let interface = INTERFACE.lock();
        let Some(interface) = interface.as_ref() else {
            return;
        };
        let ours = solicitation.target == interface.ipv6
            || interface.ipv6_global == Some(solicitation.target);
        (ours, interface.hardware, interface.card.clone())
    };
    if !ours {
        return;
    }

    // The solicitation's source is the asker's address; `::` is the
    // duplicate-address check, and an advertisement sent to `::` would go
    // nowhere, a check that hears an advertisement answers it later, at its
    // real address, and this stack's own check is the boot's probe.
    let destination = packet.header.source;
    if destination == net::ipv6::UNSPECIFIED {
        return;
    }
    // The asker's MAC, from the solicitation's source link-layer option: the
    // Ethernet frame needs it, and the option is why a solicitation carries
    // one.
    let Some(asker_mac) = net::icmpv6::link_layer_option(
        payload,
        message.body_at + net::icmpv6::NEIGHBOR_LEN,
        payload.len(),
        net::icmpv6::OPTION_SOURCE_LINK_LAYER,
    ) else {
        return;
    };

    let mut frame = alloc::vec![0_u8; card.maximum_frame_len()];
    // Answered from the address that was asked about: a host holding both a
    // link-local and a global address replies from the one the asker's own
    // cache and checksum are keyed on.
    let Some(total) = net::reply::neighbor_advertisement(
        &mut frame,
        solicitation.target,
        mac,
        destination,
        asker_mac,
        solicitation.target,
    ) else {
        return;
    };
    // The asker's address is a neighbour this host now knows, and recording
    // it is what makes the exchange's answer observable through a path that
    // does not depend on the frame coming back: a solicitation carries the
    // asker's MAC precisely so the two ends do not have to ask each other
    // twice, and keeping it is that promise.
    {
        let mut interface = INTERFACE.lock();
        if let Some(interface) = interface.as_mut() {
            interface.ndp.learn(destination, asker_mac, 0);
        }
    }

    let _ = card.submit_frame(&frame[..total]);
}

/// Write an IPv6 address in its compressed hex form.
///
/// Sixteen bytes as eight four-hex-digit groups is the full form, and it is
/// what this prints: a compression that elides the longest zero run is a
/// reader convenience and a writer's bug surface, and a line a gate compares
/// wants one spelling.
#[cfg(target_os = "none")]
pub(crate) fn write_ipv6(address: net::ipv6::Addr) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for (index, pair) in address.as_chunks::<2>().0.iter().enumerate() {
        if index > 0 {
            arch::serial::write_str(":");
        }
        for byte in pair {
            let digits = [
                DIGITS[(byte >> 4) as usize] as char,
                DIGITS[(byte & 0x0F) as usize] as char,
            ];
            arch::serial::write_str(digits.iter().collect::<alloc::string::String>().as_str());
        }
    }
}
