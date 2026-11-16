//! kernel/src/net/probes.rs
//!
//! The boot-time exchanges that prove the stack on a machine: one per layer,
//! each over a path that is real rather than simulated.
//!
//! ## Why these are their own file
//!
//! They were part of `net.rs` and they outgrew the mechanism they prove.  The
//! line between them is the one the module already drew: a probe drives the
//! stack through a recording card and reads the frames back, while everything
//! in `net/mod.rs` is the state a boot installs.  Nothing in that mechanism
//! calls a probe, the boot does, which is why this file can name `super::` and
//! `net/mod.rs` cannot name this one.
//!
//! Every probe is `#[cfg(target_os = "none")]`: a host has no card to record a
//! frame on, and the arithmetic a host can check lives in the `net` crate's
//! own tests.

use alloc::sync::Arc;
use alloc::vec::Vec;
use netdev::LinkDevice;
use sync::Mutex;

use super::core::DCCP;
use super::core::INTERFACE;
use super::core::TCP;
use super::core::bind_udp;
use super::core::create_raw_socket;
use super::core::deliver_udp;
use super::core::hardware_for_v4;
use super::core::send_datagram;
use super::core::send_raw_packet;
use super::dccp::dccp_accept;
use super::dccp::dccp_close;
use super::dccp::dccp_listen;
use super::dccp::dccp_read;
use super::dccp::deliver_dccp;
use super::demux4::demux;
use super::demux6::demux_ipv6;
use super::demux6::peer_hardware;
use super::demux6::write_ipv6;
use super::dhcp::apply_lease;
use super::dhcp::rebind_lease;
use super::dhcp::resolve;
use super::filter::filter_add;
use super::filter::filter_remove;
use super::filter::filter_status;
use super::filter::submit_filtered;
use super::ipsec::ipsec_add_sa;
use super::ipsec::ipsec_add_sp;
use super::ipsec::ipsec_del_sa;
use super::ipsec::ipsec_del_sp;
use super::ipsec::ipsec_open;
use super::ipsec::ipsec_status;
use super::multicast::MULTICAST;
use super::multicast::multicast_add_mfc;
use super::multicast::multicast_done;
use super::multicast::multicast_init;
use super::tcp::tcp_accept;
use super::tcp::tcp_close;
use super::tcp::tcp_connect;
use super::tcp::tcp_exchange;
use super::tcp::tcp_listen;
use super::tcp::tcp_read;
use super::tcp::tcp_write;

/// Prove the IPv6 side of the stack on the boot's own machine.
///
/// Three exchanges, each over a path that is real rather than simulated: a
/// neighbour solicitation this stack sends is parsed by [`demux_ipv6`] as the
/// frame comes back through the receive path, answered by
/// [`answer_neighbor_solicitation`], and the advertisement is parsed again
/// into the cache; an echo request sent to the interface's own link-local
/// address comes back through the same demux.  A loopback over the wire is
/// the one exchange QEMU's user-mode network cannot fake, because it never
/// leaves the machine.
///
/// The alternative, sending to a QEMU gateway, was measured and refused:
/// slirp forwards IPv6 datagrams but does not implement NDP, so a solicitation
/// for its address goes unanswered and the boot would have no advertisement
/// to learn from.  A probe that printed a line for an exchange that never
/// happened is the shape this tree's gates exist to catch.
pub fn ipv6_probe() -> bool {
    let (card, mac, local) = {
        let interface = INTERFACE.lock();
        let Some(interface) = interface.as_ref() else {
            return false;
        };
        (interface.card.clone(), interface.hardware, interface.ipv6)
    };

    // the neighbour solicitation, answered by this stack itself
    //
    // Sent to the address's own solicited-node group, which is a group this
    // interface joined, so the receive path's `is_for` accepts it.  The
    // `::` source is the duplicate-address form, which is what a host with
    // an address it has not yet heard about sends.
    // A solicitation with no source link-layer option is its fixed part
    // only; the eight bytes an option takes are **not** part of a message
    // that does not carry one, and a length that counted them would make the
    // checksum cover eight zeros nobody wrote.
    let group = net::ipv6::solicited_node(local);
    let mut frame = alloc::vec![0_u8; card.maximum_frame_len()];
    let Some(total) = net::reply::neighbor_solicitation(
        &mut frame,
        net::ipv6::UNSPECIFIED,
        mac,
        group,
        net::ipv6::multicast_mac(group),
        local,
        None,
    ) else {
        arch::serial::write_str("protofire: the ipv6 probe's frame is too small\n");
        return false;
    };

    // The frame goes through the demux the receive path uses, not a private
    // copy of its logic: what this proves is the path a real frame takes.
    // The slice is the frame's true length, a buffer's trailing zeros parse
    // only because the header carries the length, and a probe that relied on
    // that would be hiding a wrong length behind a right one.
    demux_ipv6(&frame[netdev::ETHERNET_HEADER_LEN..total]);

    // A solicitation from `::` is not answerable, an advertisement sent to
    // `::` goes nowhere, so this stack learns nothing from that one, and
    // the line says so rather than claiming a cache entry it does not have.
    let learned_from_dad = {
        let interface = INTERFACE.lock();
        interface
            .as_ref()
            .and_then(|interface| interface.ndp.state(local))
            .is_some()
    };
    if learned_from_dad {
        arch::serial::write_str(
            "protofire: ipv6 neighbour cache learned an address the check never proved\n",
        );
        return false;
    }

    // and the solicitation a host answers
    //
    // From the gateway-shaped peer: a link-local address built from another
    // MAC, asking for ours.  This one names a source link-layer address, so
    // the answer has somewhere to go, and it goes through the same write
    // helper a real advertisement uses.
    let peer = net::ipv6::link_local_from_mac([0x52, 0x55, 0x0A, 0x00, 0x02, 0x02]);
    let peer_mac = [0x52, 0x55, 0x0A, 0x00, 0x02, 0x02];
    // This one names its MAC, so its length includes the option's eight
    // bytes: the two lengths differ by exactly that, and a probe that used
    // one for both would fail exactly one of its checksums.
    let mut frame = alloc::vec![0_u8; card.maximum_frame_len()];
    let Some(total) = net::reply::neighbor_solicitation(
        &mut frame,
        peer,
        peer_mac,
        group,
        net::ipv6::multicast_mac(group),
        local,
        Some(peer_mac),
    ) else {
        arch::serial::write_str("protofire: the ipv6 probe's frame is too small\n");
        return false;
    };
    // The receive path's own demux, with the diagnostic that says what it
    // made of the frame when it made nothing: a probe whose failure is
    // silent is a probe that cannot tell "the demux refused it" from "the
    // answer was lost", and this boot has one chance to say which.
    demux_ipv6(&frame[netdev::ETHERNET_HEADER_LEN..total]);

    // What the exchange proved: the solicitation was parsed, the target was
    // an address this host holds, and the asker's MAC came out of the
    // solicitation's own option and into the cache.  The cache is what a
    // later send to `peer` resolves through, so an entry for `peer` is the
    // exchange having happened.
    let neighbour = {
        let interface = INTERFACE.lock();
        interface
            .as_ref()
            .and_then(|interface| interface.ndp.lookup(peer))
    };
    let Some(neighbour) = neighbour else {
        arch::serial::write_str("protofire: ipv6 neighbour solicitation went unanswered\n");
        return false;
    };
    arch::serial::write_str("protofire: ipv6 neighbour answered for ");
    write_ipv6(local);
    arch::serial::write_str(", peer ");
    write_ipv6(peer);
    arch::serial::write_str(" is ");
    {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        for (index, byte) in neighbour.iter().enumerate() {
            if index != 0 {
                arch::serial::write_str(":");
            }
            let digits = [
                DIGITS[(byte >> 4) as usize] as char,
                DIGITS[(byte & 0x0F) as usize] as char,
            ];
            arch::serial::write_str(digits.iter().collect::<alloc::string::String>().as_str());
        }
    }
    arch::serial::write_str("\n");

    // and the echo a host answers
    //
    // An echo request from the peer to our link-local address, through the
    // demux: the reply is built by the same path a real ICMPv6 answering
    // takes, and this asserts the request reached it.
    let mut frame = alloc::vec![0_u8; card.maximum_frame_len()];
    let Some(total) =
        net::reply::echo_request(&mut frame, peer, peer_mac, local, mac, 7, 1, b"pyrofire")
    else {
        arch::serial::write_str("protofire: the ipv6 probe's frame is too small\n");
        return false;
    };
    demux_ipv6(&frame[netdev::ETHERNET_HEADER_LEN..total]);

    // The echo's evidence is the line `answer_echo_request` prints: the
    // request reached the answer path, which is the same path a frame from
    // the wire takes.  What this checks is that the demux did not drop it
    // a request no handler saw prints no line, and the boot's gate requires
    // one.
    true
}

/// The boot's name exchange: one lookup through the server a lease named.
///
/// QEMU's user-mode network carries a name server that answers for the names
/// its own resolver knows, and the boot asks it for one.  The lookup is the
/// whole path: a query this stack built, a datagram through the card, the
/// server's answer parsed back, and the address the answer carried.
///
/// A network with no name server answers the probe with a line and no
/// address, which is not a failure of the stack: the line says which of the
/// two happened.
pub fn dns_probe() -> bool {
    // The name QEMU's resolver answers for on every user-mode network: the
    // host's own name for the guest's gateway.  Asking a name that does not
    // exist would prove the parser's refusal rather than the exchange.
    const NAME: &str = "example.com";

    match resolve(NAME, net::dns::TYPE_A) {
        Some(net::address::Address::V4(address)) => {
            arch::serial::write_str("protofire: dns resolved ");
            arch::serial::write_str(NAME);
            arch::serial::write_str(" to ");
            arch::serial::write_u32(address[0] as u32);
            arch::serial::write_str(".");
            arch::serial::write_u32(address[1] as u32);
            arch::serial::write_str(".");
            arch::serial::write_u32(address[2] as u32);
            arch::serial::write_str(".");
            arch::serial::write_u32(address[3] as u32);
            arch::serial::write_str("\n");
            true
        }
        Some(net::address::Address::V6(_)) => {
            arch::serial::write_str("protofire: dns answered the wrong family\n");
            false
        }
        None => {
            arch::serial::write_str("protofire: dns got no answer\n");
            false
        }
    }
}

/// The boot's stateless-configuration exchange: a router advertisement put
/// through the receive path, and the global address it configures.
///
/// No router on a machine this tree boots sends one, so the boot writes the
/// advertisement itself and sends it through `demux_ipv6`, the function a real
/// one arrives at.  What that proves is everything after the wire: the
/// advertisement parses, its prefix option is read, the autonomous flag and
/// the prefix length are checked, the address is built from the prefix and the
/// hardware address, and it joins the group it answers on.  A router
/// appearing later needs no code that is not here.
///
/// The line names the address and the prefix it came from, which is what a
/// reader compares against the Mac's own identifier.
pub fn slaac_probe() -> bool {
    let hardware = {
        let interface = INTERFACE.lock();
        let Some(interface) = interface.as_ref() else {
            return false;
        };
        interface.hardware
    };

    // A router's own link-local address and a global prefix in it.
    let router = net::ipv6::link_local_from_mac([0x52, 0x55, 0x0A, 0x00, 0x02, 0x02]);
    let prefix: net::ipv6::Addr = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    let message_len = net::icmpv6::ROUTER_ADVERTISEMENT_WITH_PREFIX_LEN;
    let mut frame =
        alloc::vec![0_u8; netdev::ETHERNET_HEADER_LEN + net::ipv6::HEADER_LEN + message_len];
    net::ethernet::write_header(
        &mut frame,
        hardware,
        [0x52, 0x55, 0x0A, 0x00, 0x02, 0x02],
        net::ethernet::ETHERTYPE_IPV6,
    );
    net::ipv6::write_header(
        &mut frame[netdev::ETHERNET_HEADER_LEN..],
        router,
        net::ipv6::ALL_NODES_MULTICAST,
        net::ipv6::NEXT_ICMPV6,
        message_len,
    );
    net::icmpv6::write_router_advertisement(
        &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv6::HEADER_LEN..],
        router,
        net::ipv6::ALL_NODES_MULTICAST,
        64,
        1_800,
        30_000,
        1_000,
        prefix,
        64,
        true,
        86_400,
        14_400,
    );
    demux_ipv6(&frame[netdev::ETHERNET_HEADER_LEN..]);

    let configured = {
        let interface = INTERFACE.lock();
        interface
            .as_ref()
            .and_then(|interface| interface.ipv6_global)
    };
    let Some(configured) = configured else {
        arch::serial::write_str("protofire: slaac configured nothing\n");
        return false;
    };
    // The address must be the router's prefix with this interface's own
    // identifier, which is the whole of what a host may conclude on its own.
    let identifier = net::ndp::interface_identifier(hardware);
    let mut expected = prefix;
    expected[8..16].copy_from_slice(&identifier);
    let correct = configured == expected;
    arch::serial::write_str("protofire: slaac configured ");
    write_ipv6(configured);
    arch::serial::write_str(if correct {
        " from its router's prefix\n"
    } else {
        ", which is not the identifier this mac makes\n"
    });

    // The default route, and the next hop a destination off this link gets.
    //
    // This is the half of a router advertisement that has nothing to do with
    // the address: the advertisement's **source** is a router willing to be a
    // default, and a destination outside this link is a frame sent to it.  The
    // probe asks for the hardware address of an address no machine on this
    // link holds, and asserts that the answer is derived from the **router's**
    // solicited-node group rather than the destination's: a stack with no
    // default route answers with the latter, which is a frame the router never
    // receives.
    let off_link: net::ipv6::Addr = [
        0x20, 0x01, 0x0d, 0xb8, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99,
    ];
    // The router is read and the lock released before the next hop is asked
    // for: `peer_hardware` takes the same lock, and one lock taken twice in
    // one thread is a deadlock rather than a second read.
    let learned_router = {
        let interface = INTERFACE.lock();
        match interface.as_ref() {
            Some(interface) => interface.ipv6_router,
            None => return false,
        }
    };
    let next_hop = peer_hardware(off_link);
    let router_learned = learned_router == Some(router);
    // Two answers are both "through the router": its own hardware address when
    // the neighbour cache holds it, and the solicited-node group of its
    // address when it does not, which is the frame that asks for it.  What
    // this rejects is the stack with no route, which answers with the
    // **destination's** group and sends the frame to a machine that is not on
    // this link.
    let via_router_mac = learned_router
        .and_then(|router| {
            INTERFACE
                .lock()
                .as_ref()
                .and_then(|interface| interface.ndp.lookup(router))
        })
        .is_some_and(|mac| next_hop == mac);
    let via_router_group = learned_router.is_some_and(|router| {
        next_hop == net::ipv6::multicast_mac(net::ipv6::solicited_node(router))
    });
    let goes_to_router = via_router_mac || via_router_group;
    let routed = correct && router_learned && goes_to_router;
    arch::serial::write_str("protofire: ipv6 route via ");
    match learned_router {
        Some(router) => write_ipv6(router),
        None => arch::serial::write_str("none"),
    }
    arch::serial::write_str(if routed {
        ", and an off-link address is asked for through it\n"
    } else {
        ", MISMATCH\n"
    });
    routed
}

/// The boot's reassembly exchange: a datagram split into pieces, delivered to
/// this machine's own socket, and the payload read back whole.
///
/// The split is the one a shrinking path forces, the first piece carries the
/// transport header and some data with more to follow, the second carries the
/// rest and says it is the last, and the delivery goes through the same
/// `demux` a frame from the wire takes, so the reassembly under test is the
/// one a real fragment meets.  What the line names is the payload's length and
/// its first and last byte, which only a correctly reassembled datagram could
/// produce.
pub fn reassembly_probe() -> bool {
    const PORT: u16 = 9200;
    const PAYLOAD: &[u8] = b"protofire-fragmented";
    // Eight-byte alignment, because the wire's offset field counts in
    // eight-octet units and a sender that ignored that would be sending a
    // datagram no receiver could place.
    const SPLIT: usize = 16;

    let protocol = {
        let interface = INTERFACE.lock();
        let Some(interface) = interface.as_ref() else {
            return false;
        };
        interface.protocol
    };
    let socket = match bind_udp(PORT) {
        Ok(socket) => socket,
        Err(_) => {
            arch::serial::write_str("protofire: fragments could not bind a port\n");
            return false;
        }
    };

    // Each piece is a UDP datagram's bytes at an offset, framed the way a
    // router that split the original would have framed them.
    let udp_len = net::udp::datagram_len(PAYLOAD.len());
    let mut datagram = alloc::vec![0_u8; udp_len];
    net::udp::write_datagram(&mut datagram, protocol, protocol, 9300, PORT, PAYLOAD);
    let pieces: [(usize, usize, bool); 2] = [(0, SPLIT, true), (SPLIT, udp_len - SPLIT, false)];
    for (offset, length, more) in pieces {
        let mut frame =
            alloc::vec![0_u8; netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + length];
        net::ethernet::write_header(
            &mut frame,
            [0x02; 6],
            [0x02; 6],
            net::ethernet::ETHERTYPE_IPV4,
        );
        net::ipv4::write_header(
            &mut frame[netdev::ETHERNET_HEADER_LEN..],
            protocol,
            protocol,
            net::ipv4::PROTOCOL_UDP,
            length,
        );
        // The fragment fields are the point, so they are written here rather
        // than by `write_header`: an unfragmented header is exactly what a
        // reassembly test must not send.
        let identification: u16 = 0x51A7;
        let flags = if more { 0x2000u16 } else { 0 };
        net::ethernet::put_u16(&mut frame[netdev::ETHERNET_HEADER_LEN..], 4, identification);
        net::ethernet::put_u16(
            &mut frame[netdev::ETHERNET_HEADER_LEN..],
            6,
            flags | (offset as u16 / 8),
        );
        // The IPv4 checksum covers the header, and these two fields just
        // changed inside it.
        let header = &mut frame
            [netdev::ETHERNET_HEADER_LEN..netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN];
        net::ethernet::put_u16(header, 10, 0);
        let sum = net::ipv4::checksum(header);
        net::ethernet::put_u16(header, 10, sum);
        frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..]
            .copy_from_slice(&datagram[offset..offset + length]);
        demux(&frame, protocol);
    }

    let mut buffer = [0_u8; 64];
    let count = match socket.try_recv(&mut buffer) {
        Ok(Some((_, _, count))) => count,
        _ => {
            arch::serial::write_str("protofire: fragments did not reassemble\n");
            return false;
        }
    };
    let intact = count == PAYLOAD.len() && buffer[..count] == *PAYLOAD;
    arch::serial::write_str("protofire: fragments reassembled ");
    arch::serial::write_u32(count as u32);
    arch::serial::write_str(" byte(s), ");
    arch::serial::write_str(if intact { "intact\n" } else { "MISMATCH\n" });
    intact
}

/// The boot's IPv6 exchange: a datagram and a stream, both to this machine's
/// own link-local address, both through the receive path the wire uses.
///
/// What this proves is the part a loopback cannot fake: a datagram and a
/// segment written by [`send_datagram`] and [`tcp_connect`] with an IPv6
/// address, framed for the card's ethertype, parsed back by [`demux_ipv6`] and
/// routed to the socket or the connection the address names.  The exchange
/// never touches the card, QEMU's user-mode network forwards IPv6 but does
/// not answer NDP, so a probe aimed at its gateway would ask a question
/// nothing answers.
///
/// The IPv4 side's own probe answers the same question for the other family,
/// which is why the two lines are asserted separately by a gate: one family
/// working says nothing about the other.
pub fn ipv6_transport_probe() -> bool {
    let (local, card) = {
        let interface = INTERFACE.lock();
        let Some(interface) = interface.as_ref() else {
            return false;
        };
        (interface.ipv6, interface.card.clone())
    };
    let _ = &card;

    // a datagram to this machine, through the demux
    let socket = match bind_udp(9100) {
        Ok(socket) => socket,
        Err(_) => {
            arch::serial::write_str("protofire: ipv6 udp could not bind port 9100\n");
            return false;
        }
    };
    if send_datagram(net::address::Address::V6(local), 9100, 9101, b"protofire6").is_err() {
        arch::serial::write_str("protofire: ipv6 udp could not send\n");
        return false;
    }
    let mut buffer = [0_u8; 32];
    let (source, source_port, count) = match socket.try_recv(&mut buffer) {
        Ok(Some((source, port, count))) => (source, port, count),
        _ => {
            arch::serial::write_str("protofire: ipv6 udp went unanswered\n");
            return false;
        }
    };
    // The sender the record names is this machine, over IPv6: a record that
    // said something else would mean the demux routed by the wrong address.
    let expected = net::address::Address::V6(local);
    let sender_is_this_machine = source == expected && source_port == 9101;
    arch::serial::write_str("protofire: ipv6 udp received ");
    arch::serial::write_u32(count as u32);
    arch::serial::write_str(" byte(s) from ");
    arch::serial::write_str(if sender_is_this_machine {
        "this machine\n"
    } else {
        "an address the send did not name\n"
    });
    if !sender_is_this_machine || count != 10 {
        return false;
    }

    // a stream to this machine, through the demux
    let listener = match tcp_listen(9102) {
        Ok(id) => id,
        Err(_) => {
            arch::serial::write_str("protofire: ipv6 tcp could not listen\n");
            return false;
        }
    };
    let client = match tcp_connect(net::address::Address::V6(local), 9102) {
        Ok(id) => id,
        Err(_) => {
            arch::serial::write_str("protofire: ipv6 tcp could not connect\n");
            return false;
        }
    };
    let accepted = match tcp_accept(listener) {
        Ok(Some(id)) => id,
        _ => {
            arch::serial::write_str("protofire: ipv6 tcp accepted nothing\n");
            return false;
        }
    };
    let sent = tcp_write(client, b"v6").unwrap_or_default();
    let mut stream_buffer = [0_u8; 8];
    let echoed = match tcp_read(accepted, &mut stream_buffer) {
        Ok(Some(count)) => count,
        _ => 0,
    };
    let back = tcp_write(accepted, &stream_buffer[..echoed]).unwrap_or_default();
    let received = match tcp_read(client, &mut stream_buffer) {
        Ok(Some(count)) => count,
        _ => 0,
    };
    let _ = tcp_close(client);
    let _ = tcp_close(accepted);
    let round_trip = sent == 2 && echoed == 2 && back == 2 && received == 2;
    arch::serial::write_str("protofire: ipv6 tcp echoed ");
    arch::serial::write_u32(received as u32);
    arch::serial::write_str(" byte(s) of ");
    arch::serial::write_u32(sent as u32);
    arch::serial::write_str(if round_trip {
        ", round trip\n"
    } else {
        ", MISMATCH\n"
    });
    round_trip
}

/// Prove that the timeout is measured rather than assumed.
///
/// The constant it replaced was a second for every stream on every path, which
/// is right for no path: a machine on a fast wire retransmits a segment that
/// was merely in flight, and one on a slow one gives up on a segment that was
/// still coming.  The two numbers on the line are the estimate's two halves,
/// and what makes them evidence is that the second response is deliberately
/// **later** than the first: a stack that measured one round trip and reused it
/// would print the same number twice.
pub fn round_trip_probe() -> bool {
    let listener = match tcp_listen(9110) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let protocol = match INTERFACE.lock().as_ref() {
        Some(interface) => interface.protocol,
        None => return false,
    };
    let client = match tcp_connect(net::address::Address::V4(protocol), 9110) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let accepted = match tcp_accept(listener) {
        Ok(Some(id)) => id,
        _ => return false,
    };
    let source_port = match TCP.lock().local_port_of(client) {
        Some(port) => port,
        None => return false,
    };

    // Two exchanges, the second slower than the first, and the estimate read
    // after each.  The time is the kernel's own clock advanced by the probe,
    // because the value under test is what a **peer's** answer does to the
    // estimate and not what the boot's traffic happens to be.
    let mut estimates = alloc::vec::Vec::new();
    for delay in [4_000_u64, 40_000] {
        let (sequence, acknowledgement, payload) = {
            let mut table = TCP.lock();
            let Some(connection) = table.connection_mut(client) else {
                return false;
            };
            let (sent, outgoing) = connection.send_data(b"probe");
            if sent != 5 {
                return false;
            }
            let Some(segment) = outgoing.into_iter().next() else {
                return false;
            };
            (segment.sequence, segment.acknowledgement, segment.payload)
        };
        // The peer's own state machine, reached the way a wire reaches it: a
        // segment built from what this side sent.
        let replies = {
            let mut table = TCP.lock();
            let Some(peer) = table.connection_mut(accepted) else {
                return false;
            };
            let segment = net::tcp::Segment::new(
                source_port,
                9110,
                sequence,
                acknowledgement,
                net::tcp::FLAG_ACK | net::tcp::FLAG_PSH,
                net::tcp::WINDOW,
                payload.len(),
            );
            peer.receive(&segment, &payload).1
        };
        let mut table = TCP.lock();
        let Some(connection) = table.connection_mut(client) else {
            return false;
        };
        connection.advance(crate::net::micros_since_boot() + delay);
        for reply in replies {
            let segment = net::tcp::Segment::new(
                9110,
                source_port,
                connection.expected_position(),
                reply.acknowledgement,
                reply.flags,
                reply.window,
                reply.payload.len(),
            );
            let _ = connection.receive(&segment, &reply.payload);
        }
        match connection.smoothed_round_trip() {
            Some(estimate) => estimates.push(estimate),
            None => return false,
        }
    }

    let _ = tcp_close(client);
    let _ = tcp_close(accepted);

    // The second estimate is above the first and below it plus the second
    // sample: an eighth of a delay moves the average, so a stack that took the
    // new sample as the estimate would land at the delay and a stack that
    // ignored it would not move at all.
    let first = estimates[0];
    let second = estimates[1];
    let correct = second > first && second < first + 40_000;
    // Two lines rather than one: the numbers are the clock's and change every
    // boot, and the gate can require a prefix but not a suffix.  So the numbers
    // are their own line, read by a human, and the verdict is the line the gate
    // requires.
    arch::serial::write_str("protofire: round trip ");
    arch::serial::write_u32(first as u32);
    arch::serial::write_str(" then ");
    arch::serial::write_u32(second as u32);
    arch::serial::write_str(" microseconds\n");
    arch::serial::write_str(if correct {
        "protofire: the estimate moved with the measurement\n"
    } else {
        "protofire: round trip MISMATCH\n"
    });
    correct
}

/// Prove that a stream fed from a frame carries the frame's **data**.
///
/// Every exchange above runs on the loopback, and a loopback hands a
/// connection the payload it built: no frame, no header, no data offset.  The
/// frame path is the other half, and it had a defect no loopback could show:
/// the demux handed `receive` the whole packet, so a stream fed by a real card
/// carried its peer's TCP header as the first twenty bytes of data.
///
/// The probe builds a frame the way the card would carry one, sends it through
/// `demux`, and reads the stream's inbox.  Two segments go in, one with the
/// MSS option and one without, so the two readings of "where does the data
/// start" differ: a reader that used a constant header length would take four
/// option bytes from the first segment and be right about the second.
///
/// The line's number is the inbox's length, which is the data and not the
/// headers: eight bytes sent, eight held.
pub fn frame_data_probe() -> bool {
    const PORT: u16 = 9109;
    const FIRST: &[u8] = b"four";
    const SECOND: &[u8] = b"more";

    let (protocol, hardware) = {
        let interface = INTERFACE.lock();
        let Some(interface) = interface.as_ref() else {
            return false;
        };
        (interface.protocol, interface.hardware)
    };
    // The listener and a client, so the table has a connection whose sequence
    // numbers the probe can build segments from: the segment's own numbers are
    // the connection's, and a probe that invented them would be read as a
    // retransmission of something it never sent.
    let listener = match tcp_listen(PORT) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let client = match tcp_connect(net::address::Address::V4(protocol), PORT) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let accepted = match tcp_accept(listener) {
        Ok(Some(id)) => id,
        _ => return false,
    };
    let source_port = match TCP.lock().local_port_of(client) {
        Some(port) => port,
        None => return false,
    };

    // The two segments, written with the stack's own writer so the frame is
    // exactly what this stack would put on a wire.
    let mut carried = 0;
    for (index, payload) in [FIRST, SECOND].iter().enumerate() {
        let header = if index == 0 {
            net::tcp::SYN_HEADER_LEN
        } else {
            net::tcp::HEADER_LEN
        };
        let tcp_len = header + payload.len();
        let frame_len = netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + tcp_len;
        let mut frame = alloc::vec![0; frame_len];
        net::ethernet::write_header(
            &mut frame,
            hardware,
            hardware,
            net::ethernet::ETHERTYPE_IPV4,
        );
        net::ipv4::write_header(
            &mut frame[netdev::ETHERNET_HEADER_LEN..],
            protocol,
            protocol,
            net::ipv4::PROTOCOL_TCP,
            tcp_len,
        );
        // Both are data segments and neither opens a connection: a SYN would
        // be delivered to the listener as a **second** stream, and the probe
        // would be measuring a connection it never read.  The difference the
        // probe needs is the option, and it puts that in by hand below.
        let flags = net::tcp::FLAG_PSH | net::tcp::FLAG_ACK;
        // Each segment starts where the stream's inbox now ends, read **at
        // this moment** and not from a base captured before the first one:
        // the first segment's arrival advances the expected position, so a
        // base plus a running count would put the second segment four bytes
        // past where the stream is and it would be held for a gap that does
        // not exist.
        let (sequence, acknowledgement) = {
            let table = TCP.lock();
            let Some(connection) = table.connection(accepted) else {
                return false;
            };
            (connection.expected_position(), connection.send_position())
        };
        // The first segment states an MSS and the second does not, so the two
        // data offsets differ: a reader that used a constant header length
        // would take the option's four bytes as the first segment's data and
        // be right about the second, which is exactly the defect this probe is
        // for.
        net::tcp::write_segment_with_mss(
            &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..],
            protocol,
            protocol,
            source_port,
            PORT,
            sequence,
            acknowledgement,
            flags,
            net::tcp::WINDOW,
            payload,
            if index == 0 { Some(1460) } else { None },
        );
        // Through the demux, which is the path a frame from a card takes.  A
        // SYN for a port the table already listens on would open a *second*
        // connection, so only the second segment is delivered as data; the
        // first is delivered to the same connection by handing the demux a
        // segment whose flags do not open.  What is measured is the inbox
        // after both, so the first must be data too.
        demux(&frame, protocol);
        carried += payload.len();
    }

    let held = {
        let mut table = TCP.lock();
        let Some(connection) = table.connection_mut(accepted) else {
            return false;
        };
        connection.inbox_len()
    };

    let _ = tcp_close(client);
    let _ = tcp_close(accepted);

    let correct = held == carried;
    arch::serial::write_str("protofire: frame data ");
    arch::serial::write_u32(carried as u32);
    arch::serial::write_str(" byte(s) sent, ");
    arch::serial::write_u32(held as u32);
    arch::serial::write_str(if correct {
        " held, the headers stayed out of the stream\n"
    } else {
        " held, MISMATCH\n"
    });
    correct
}

/// Prove that the longest match decides where a frame goes.
///
/// The stack had one gateway and every off-link frame went to it, which is a
/// table with one entry.  A table is only worth having if a **second** entry
/// wins where it should, so the probe adds a route to a prefix that contains a
/// destination the default route also covers, and reads which hardware address
/// the frame is addressed to.
///
/// The two hardware addresses are both in the ARP cache and both are fake: the
/// cache is this stack's own table, and what is under test is which entry a
/// lookup picks, not whether a wire answers.
///
/// The line names how many routes exist and which address the frame went to,
/// and the second number is the assertion: the specific route's hardware
/// address and not the default's.
pub fn route_probe() -> bool {
    // A destination the default route covers and the specific one does not
    // have to win for.
    const DESTINATION: [u8; 4] = [203, 0, 113, 7];
    const DEFAULT_HARDWARE: [u8; 6] = [0x02, 0, 0, 0, 0, 0x01];
    const SPECIFIC_HARDWARE: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];
    const SPECIFIC_GATEWAY: [u8; 4] = [192, 0, 2, 1];

    let before = {
        let mut interface = INTERFACE.lock();
        let Some(interface) = interface.as_mut() else {
            return false;
        };
        // The default route's gateway, resolved to a hardware address the
        // probe made up: what a send to DESTINATION would look like without
        // the specific route.
        let gateway = interface.gateway;
        let count = interface.routes.len();
        interface.arp.learn(gateway, DEFAULT_HARDWARE);
        // The specific route, and the gateway it names.
        interface.routes.add(net::route::Route {
            prefix: net::address::Address::V4([203, 0, 113, 0]),
            length: 24,
            gateway: Some(net::address::Address::V4(SPECIFIC_GATEWAY)),
        });
        interface.arp.learn(SPECIFIC_GATEWAY, SPECIFIC_HARDWARE);
        (count, interface.routes.len())
    };

    let chosen = {
        let interface = INTERFACE.lock();
        let Some(interface) = interface.as_ref() else {
            return false;
        };
        hardware_for_v4(interface, DESTINATION)
    };

    // Put the table back the way the boot found it, so the rest of the boot's
    // exchanges route as they did before this probe ran.
    let restored = {
        let mut interface = INTERFACE.lock();
        let Some(interface) = interface.as_mut() else {
            return false;
        };
        interface
            .routes
            .remove(net::address::Address::V4([203, 0, 113, 0]), 24)
            && interface.routes.len() == before.0
    };

    let correct = chosen == Ok(SPECIFIC_HARDWARE) && restored && before.1 == before.0 + 1;
    arch::serial::write_str("protofire: routes ");
    arch::serial::write_u32(before.0 as u32);
    arch::serial::write_str(" -> ");
    arch::serial::write_u32(before.1 as u32);
    arch::serial::write_str(", and the longer prefix chose ");
    match chosen {
        Ok(hardware) => {
            arch::serial::write_u32(hardware[5] as u32);
        }
        Err(_) => arch::serial::write_str("nothing"),
    }
    arch::serial::write_str(if correct { "\n" } else { ", MISMATCH\n" });
    correct
}

/// A card that records the frames it was given, for the forwarding probe.
///
/// The question is not "did the call report a forward" but "what did the card
/// receive": a forwarding path that composed a frame and then lost it would
/// look like a forward from every counter the tables keep, and a frame with the
/// wrong hop count looks like a forward from a count alone.  So the probe reads
/// the bytes.
struct RecordingCard {
    frames: Mutex<Vec<Vec<u8>>>,
}

impl RecordingCard {
    fn new() -> Self {
        Self {
            frames: Mutex::new(Vec::new()),
        }
    }

    fn frames(&self) -> Vec<Vec<u8>> {
        self.frames.lock().clone()
    }
}

impl LinkDevice for RecordingCard {
    fn hardware_address(&self) -> [u8; 6] {
        [0x02; 6]
    }

    fn submit_frame(&self, frame: &[u8]) -> abi::Result<()> {
        self.frames.lock().push(Vec::from(frame));
        Ok(())
    }

    fn receive_frame(&self, _into: &mut [u8]) -> abi::Result<Option<usize>> {
        Ok(None)
    }

    fn maximum_frame_len(&self) -> usize {
        1514
    }
}

/// A card that records how many frames reached it, for the filter's outbound
/// half.
///
/// The question that half asks is not "did the call report a refusal" but "did
/// the frame reach the card", and the two are different: a send that submitted
/// the frame and then returned an error looks like a refusal from the caller's
/// side and is a packet on the wire.  So the probe needs a card whose only job
/// is to count.
struct CountingCard {
    frames: core::sync::atomic::AtomicUsize,
}

impl CountingCard {
    fn new() -> Self {
        Self {
            frames: core::sync::atomic::AtomicUsize::new(0),
        }
    }

    fn count(&self) -> usize {
        self.frames.load(core::sync::atomic::Ordering::Relaxed)
    }
}

impl LinkDevice for CountingCard {
    fn hardware_address(&self) -> [u8; 6] {
        [0x02; 6]
    }

    fn submit_frame(&self, _frame: &[u8]) -> abi::Result<()> {
        self.frames
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    fn receive_frame(&self, _into: &mut [u8]) -> abi::Result<Option<usize>> {
        Ok(None)
    }

    fn maximum_frame_len(&self) -> usize {
        1514
    }
}

/// Prove that DCCP opens a connection, carries a datagram, and closes it.
///
/// The exchange is two endpoints on this machine, which is the one path that
/// exercises the whole protocol without a peer: a listener, a client that sends
/// its Request through the demux, the server's accept, the data, and the close.
/// A DCCP implementation that stored headers and had no state machine would
/// print a table of ports and pass nothing here.
///
/// The three numbers are the state the client reached, whether the server read
/// the datagram the client sent, and whether the client finished on a close.
pub fn dccp_probe() -> bool {
    const PORT: u16 = 9_109;
    const CLIENT_PORT: u16 = 9_110;
    const SERVICE: u32 = 0x0000_1234;

    let local = {
        let interface = INTERFACE.lock();
        interface
            .as_ref()
            .map(|interface| interface.protocol)
            .unwrap_or([10, 0, 2, 15])
    };
    let peer = net::address::Address::V4(local);

    if dccp_listen(PORT, Some(SERVICE)).is_err() {
        return false;
    }

    // The client's Request, handed to the same function the demux calls.  The
    // probe drives both directions itself rather than sending through the card:
    // a frame this machine addresses to itself comes back through QEMU's
    // network ring, and a probe that depended on that would be measuring the
    // emulator's reflection rule.  What is proven here is the state machine and
    // the table, which is what the four call groups are about; the frame's
    // bytes are `net::dccp`'s own round trip.
    let request = {
        let mut wire = alloc::vec![0; net::dccp::HEADER_LEN + 4 + 8];
        let length = net::dccp::write_segment(
            &mut wire,
            CLIENT_PORT,
            PORT,
            &net::dccp::HeaderFields {
                kind: net::dccp::PacketType::Request,
                sequence: 100,
                acknowledgement: None,
                service_code: Some(SERVICE),
                options: &[],
            },
            &[],
        ) as usize;
        wire.truncate(length);
        wire
    };
    if deliver_dccp(&request, peer, local).is_err() {
        let _ = DCCP.lock().unlisten(PORT);
        return false;
    }
    let Some(server) = dccp_accept(PORT).ok().flatten() else {
        let _ = DCCP.lock().unlisten(PORT);
        return false;
    };

    // The client end, made from the Request's own numbers so the four-tuple
    // the server holds is the one this side answers on.
    let Ok(client) = DCCP.lock().connect(CLIENT_PORT, peer, PORT, SERVICE, 200) else {
        let _ = DCCP.lock().unlisten(PORT);
        return false;
    };

    // The server's Response, which is what opens the client.
    let response = {
        let mut wire = alloc::vec![0; net::dccp::HEADER_LEN + 4 + 8];
        let length = net::dccp::write_segment(
            &mut wire,
            PORT,
            CLIENT_PORT,
            &net::dccp::HeaderFields {
                kind: net::dccp::PacketType::Response,
                sequence: 300,
                acknowledgement: None,
                service_code: Some(SERVICE),
                options: &[],
            },
            &[],
        ) as usize;
        wire.truncate(length);
        wire
    };
    let _ = deliver_dccp(&response, peer, local);

    // The server has not been told the client accepted, so its own state is
    // `ResponseSent`; the client is `Open`, and that is the state data crosses
    // in.
    let client_state = DCCP.lock().connection(client).map(|c| c.state());

    // One datagram, from the client to the server, through the demux function.
    let payload = b"dccp";
    let data_segment = {
        let mut wire = alloc::vec![0; net::dccp::HEADER_LEN + 8 + payload.len() + 8];
        let length = net::dccp::write_segment(
            &mut wire,
            CLIENT_PORT,
            PORT,
            &net::dccp::HeaderFields {
                kind: net::dccp::PacketType::DataAck,
                sequence: 101,
                acknowledgement: Some(300),
                service_code: None,
                options: &[],
            },
            payload,
        ) as usize;
        wire.truncate(length);
        wire
    };
    let _ = deliver_dccp(&data_segment, peer, local);

    let mut buffer = [0_u8; 32];
    let received = dccp_read(server, &mut buffer).unwrap_or(None).unwrap_or(0);
    let intact = received == payload.len() && &buffer[..received] == payload;

    let closed = dccp_close(client).is_ok();
    let _ = DCCP.lock().unlisten(PORT);
    DCCP.lock().prune();

    let correct = intact
        && closed
        && client_state == Some(net::dccp::State::Open)
        && received == payload.len();
    arch::serial::write_str("protofire: dccp client ");
    arch::serial::write_str(if client_state == Some(net::dccp::State::Open) {
        "open"
    } else {
        "CLOSED"
    });
    arch::serial::write_str(", carried ");
    arch::serial::write_u32(received as u32);
    arch::serial::write_str(" byte(s)");
    arch::serial::write_str(if correct { "\n" } else { ", MISMATCH\n" });
    correct
}

/// Prove that ESP encrypts what leaves and recovers it on arrival, and that a
/// repeat of one packet does not arrive twice.
///
/// Three facts, because ESP is broken three ways and each looks like a working
/// tunnel through a different window.  The frame the card is given must not
/// **contain** the plaintext: a stack that set the protocol number to ESP and
/// sent the datagram unchanged is a stack whose peer decrypts garbage, and a
/// counter saying "encrypted 1" would not show it.  The demux must **recover**
/// the exact bytes: a round trip through the seal and open is a host test, and
/// through the demux is the wiring.  And the same frame delivered twice must
/// produce **one** delivery: the replay window is what makes ESP a protocol and
/// not a cipher.
pub fn ipsec_probe() -> bool {
    const PORT: u16 = 9_108;
    const SPI: u32 = 0x0000_2A2A;
    const PAYLOAD: &[u8] = b"secret";

    let local = {
        let interface = INTERFACE.lock();
        let Some(interface) = interface.as_ref() else {
            return false;
        };
        interface.protocol
    };
    // A destination that is **not** this machine, so the frame reaches the card
    // the probe reads.  A send to the loopback is a send the stack delivers
    // itself, and the sealed bytes it would produce are never composed into a
    // frame: ESP is proven on the wire or not at all.
    let peer = [10, 0, 2, 2];

    // An association and a policy that protects every packet leaving this
    // machine for the peer.
    let mut sa = abi::network::IpsecSaDef {
        flags: 0,
        spi: SPI,
        mode: abi::network::IPSEC_MODE_TRANSPORT,
        proto: abi::network::IPSEC_PROTO_ESP,
        aead_algo: abi::network::IPSEC_AEAD_AES128_GCM,
        auth_algo: 0,
        enc_key_len: 16,
        auth_key_len: 0,
        enc_key: [0; 32],
        auth_key: [0; 32],
        salt: [0; 12],
        src_addr: [0; 4],
        dst_addr: [0; 4],
        tunnel_src: [0; 4],
        tunnel_dst: [0; 4],
        lifetime_bytes: 0,
        lifetime_ticks: 0,
    };
    for (index, byte) in sa.enc_key[..16].iter_mut().enumerate() {
        *byte = (index as u8).wrapping_mul(7).wrapping_add(3);
    }
    sa.salt[..4].copy_from_slice(&[0x5A, 0x5B, 0x5C, 0x5D]);
    let Ok(association) = ipsec_add_sa(&sa) else {
        return false;
    };
    let policy = abi::network::IpsecSpDef {
        flags: 0,
        action: abi::network::IPSEC_ACTION_PROTECT,
        direction: abi::network::IPSEC_DIR_BOTH,
        protocol: u32::from(net::ipv4::PROTOCOL_UDP),
        src_addr: [0; 4],
        src_prefix: 0,
        dst_addr: [0; 4],
        dst_prefix: 0,
        src_port: 0,
        dst_port: PORT as u32,
        sa_id: association,
        reserved: 0,
    };
    if ipsec_add_sp(&policy).is_err() {
        let _ = ipsec_del_sa(SPI);
        return false;
    }

    // A bound port to receive what the demux recovers.
    let Ok(socket) = bind_udp(PORT) else {
        let _ = ipsec_del_sa(SPI);
        return false;
    };

    // The sending half, through the real send path but against a card that
    // records: what the wire would carry is what this reads.
    let recorded = Arc::new(RecordingCard::new());
    let original = {
        let mut interface = INTERFACE.lock();
        let Some(interface) = interface.as_mut() else {
            let _ = ipsec_del_sa(SPI);
            return false;
        };
        let original = interface.card.clone();
        interface.card = recorded.clone();
        original
    };
    // The route to `peer` goes through the gateway, and a frame with no
    // hardware address is a frame the card cannot carry: the cache entry is
    // made up, exactly as the route probe's is.
    {
        let mut interface = INTERFACE.lock();
        if let Some(interface) = interface.as_mut() {
            interface
                .arp
                .learn(interface.gateway, [0x02, 0, 0, 0, 0, 0x03]);
        }
    }
    let sent = send_datagram(net::address::Address::V4(peer), PORT, PORT, PAYLOAD).is_ok();
    {
        let mut interface = INTERFACE.lock();
        if let Some(interface) = interface.as_mut() {
            interface.card = original;
        }
    }

    let frames = recorded.frames();
    let frame = frames.first();
    let protocol = frame.map(|frame| frame[netdev::ETHERNET_HEADER_LEN + 9]);
    let carries_plaintext = frame
        .map(|frame| frame.windows(PAYLOAD.len()).any(|window| window == PAYLOAD))
        .unwrap_or(true);

    // The receiving half: the ESP payload the card was given goes through
    // `ipsec_open` and then through `deliver_udp`, which is what the demux does
    // with a packet that is this machine's.  The demux's own entry point is not
    // used because its first check is `is_for`, and the frame was addressed to
    // the peer on purpose: what a receiver does with a protected packet is
    // decapsulate it, and the address check happened before the packet was this
    // machine's to read.
    let mut first_delivery = 0;
    let mut second_delivery = 0;
    if let Some(frame) = frame {
        let payload = &frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..];
        if let Some((inner, next_header)) = ipsec_open(payload)
            && next_header == net::ipv4::PROTOCOL_UDP
            && inner.len() >= net::udp::HEADER_LEN
        {
            let data = &inner[net::udp::HEADER_LEN..];
            let _ = deliver_udp(
                net::address::Address::V4(local),
                PORT,
                net::address::Address::V4(peer),
                PORT,
                data,
            );
        }
        first_delivery = socket
            .try_recv(&mut [0_u8; 32])
            .ok()
            .flatten()
            .map(|(_, _, count)| count)
            .unwrap_or(0);
        // The same payload again: the replay window must refuse it, and the
        // queue must stay empty.
        let _ = ipsec_open(payload);
        second_delivery = socket
            .try_recv(&mut [0_u8; 32])
            .ok()
            .flatten()
            .map(|(_, _, count)| count)
            .unwrap_or(0);
    }

    let statistics = ipsec_status();
    let _ = ipsec_del_sa(SPI);
    let _ = ipsec_del_sp(1);

    // `statistics` is `(policies, associations, sealed, opened, integrity,
    // replay)`.
    let correct = sent
        && protocol == Some(net::ipv4::PROTOCOL_ESP)
        && !carries_plaintext
        && first_delivery == PAYLOAD.len()
        && second_delivery == 0
        && statistics.2 >= 1
        && statistics.3 >= 1
        && statistics.5 >= 1;
    arch::serial::write_str("protofire: esp sealed ");
    arch::serial::write_u32(statistics.2 as u32);
    arch::serial::write_str(", opened ");
    arch::serial::write_u32(statistics.3 as u32);
    arch::serial::write_str(", the wire carried ");
    arch::serial::write_str(if carries_plaintext {
        "PLAINTEXT"
    } else {
        "ciphertext"
    });
    arch::serial::write_str(", and the replay ");
    arch::serial::write_u32(second_delivery as u32);
    arch::serial::write_str(if correct {
        " byte(s)\n"
    } else {
        ", MISMATCH\n"
    });
    correct
}

/// Prove that TLS 1.3's protocol half runs: a handshake between two endpoints
/// in this machine, and a record each way afterwards.
///
/// There is no TLS peer here and there cannot be one: QEMU's user-mode network
/// answers ARP, ICMP and UDP, and it does not terminate TLS.  So this probe
/// does the one thing that is available and honest: it runs **both sides** of a
/// TLS 1.3 handshake against each other, with a real X25519 exchange, the
/// ladder of RFC 8446 §7.1, and each side verifying the other's Finished.
///
/// What that proves is that the two sides **agree**: one schedule derived
/// twice from one exchange and one transcript, a Finished each side accepts,
/// and records both ways.  What it cannot prove is that a wrong side is
/// **refused**, because both sides here are right: the rejection half is
/// `a_forged_finished_does_not_verify` and the record layer's tag tests, which
/// are host tests, and a boot that printed a rejection line would be a boot
/// whose rejection path ran only under a mutation.  And it does not prove the
/// syscall's connection to a server, because there is none.  `docs/status.md`
/// says all three.
pub fn tls_probe() -> bool {
    use net::tls;

    // Two offers, one each, and the hello both sides hash.
    let (client_offer, client_secret) = tls::Offer::generate([1_u8; 32]);
    let (server_offer, server_secret) = tls::Offer::generate([2_u8; 32]);
    let client_hello = tls::write_handshake(
        tls::HANDSHAKE_CLIENT_HELLO,
        &tls::client_hello_body(&client_offer, Some("example.test")),
    );
    let server_hello = {
        let mut body = alloc::vec![0; 35 + 2 + 1 + 2 + 40];
        body[..2].copy_from_slice(&tls::LEGACY_VERSION.to_be_bytes());
        body[2..34].copy_from_slice(&server_offer.random);
        body[34] = 0;
        body[35..37].copy_from_slice(&tls::Suite::Aes128GcmSha256.code().to_be_bytes());
        body[37] = 0;
        body[38..40].copy_from_slice(&40_u16.to_be_bytes());
        body[40..42].copy_from_slice(&0x0033_u16.to_be_bytes());
        body[42..44].copy_from_slice(&36_u16.to_be_bytes());
        body[44..46].copy_from_slice(&tls::GROUP_X25519.to_be_bytes());
        body[46..48].copy_from_slice(&32_u16.to_be_bytes());
        body[48..80].copy_from_slice(&server_offer.key);
        tls::write_handshake(tls::HANDSHAKE_SERVER_HELLO, &body)
    };

    let mut transcript = tls::Transcript::new();
    transcript.add(&client_hello);
    transcript.add(&server_hello);

    let Ok(client_shared) = tls::shared_secret(&client_secret, &server_offer.key) else {
        return false;
    };
    let Ok(server_shared) = tls::shared_secret(&server_secret, &client_offer.key) else {
        return false;
    };
    if client_shared != server_shared {
        return false;
    }

    let client_schedule = tls::Schedule::new(client_shared, transcript.hash(), [0; 32]);
    let server_schedule = tls::Schedule::new(server_shared, transcript.hash(), [0; 32]);

    // The server's Finished, sealed under its handshake keys and opened by the
    // client.
    let mut server_write = tls::Keys::from_secret(
        &server_schedule.server_handshake(),
        tls::Suite::Aes128GcmSha256,
    );
    let mut client_read = tls::Keys::from_secret(
        &server_schedule.server_handshake(),
        tls::Suite::Aes128GcmSha256,
    );
    let server_finished = tls::write_handshake(
        tls::HANDSHAKE_FINISHED,
        &tls::finished_value(&server_schedule.finished_key(true), &transcript.hash()),
    );
    let Ok(record) = tls::write_record(tls::CONTENT_HANDSHAKE, &mut server_write, &server_finished)
    else {
        return false;
    };
    let Ok((plaintext, content_type, _)) = tls::read_record(&mut client_read, &record) else {
        return false;
    };
    let Ok((messages, _)) = tls::read_handshakes(&plaintext) else {
        return false;
    };
    // The Finished check is its own value, and it is the one the line reports:
    // a `verified` that also carried the content type would be true when the
    // record parsed and the MAC was never compared.
    let finished_ok = messages.len() == 1
        && messages[0].kind == tls::HANDSHAKE_FINISHED
        && tls::verify_finished(
            &client_schedule.finished_key(true),
            &transcript.hash(),
            &messages[0].body,
        );
    let verified = content_type == tls::CONTENT_HANDSHAKE && finished_ok;

    // The application keys, and one record each way under them.
    transcript.add(&server_finished);
    let client_app = tls::Schedule::new(client_shared, transcript.hash(), transcript.hash());
    let server_app = tls::Schedule::new(server_shared, transcript.hash(), transcript.hash());
    let mut client_write = tls::Keys::from_secret(
        &client_app.client_application(),
        tls::Suite::Aes128GcmSha256,
    );
    let mut server_read = tls::Keys::from_secret(
        &server_app.client_application(),
        tls::Suite::Aes128GcmSha256,
    );
    let carried = tls::write_record(tls::CONTENT_APPLICATION_DATA, &mut client_write, b"hello")
        .ok()
        .and_then(|record| tls::read_record(&mut server_read, &record).ok())
        .map(|(plaintext, _, _)| plaintext)
        .unwrap_or_default();

    let correct = verified && carried == b"hello";
    arch::serial::write_str("protofire: tls handshake finished verified ");
    arch::serial::write_str(if verified { "yes" } else { "no" });
    arch::serial::write_str(", and carried ");
    arch::serial::write_u32(carried.len() as u32);
    arch::serial::write_str(" byte(s) under the application keys");
    arch::serial::write_str(if correct { "\n" } else { ", MISMATCH\n" });
    correct
}

/// Prove that a multicast packet is forwarded, with its hop count spent.
///
/// The claim multicast routing has to earn is not "the entry was stored": it is
/// "a packet the entry names was sent on".  Forwarding state with no caller in
/// the data path describes a stream nothing reads, which is the same shape the
/// packet filter's `enabled` flag had.
///
/// The exchange is a frame this machine hands the demux, carrying a multicast
/// destination and an entry that forwards it, and the assertion is what the
/// **card** was told: QEMU's user-mode network is not what this is about, so
/// the frame's TTL and its destination are read from the outgoing frame the
/// interface recorded rather than from a counter.
///
/// Three things are measured, and each fails a different broken forwarding:
/// the packet was forwarded at all (a table nothing reads sends nothing), the
/// copy left with one hop fewer (a forwarder that did not decrement would loop
/// forever), and its payload is the sender's (a copy that rebuilt the payload
/// would forward bytes nobody sent).
pub fn multicast_probe() -> bool {
    const GROUP: [u8; 4] = [239, 1, 2, 3];
    const SENDER: [u8; 4] = [10, 0, 2, 2];
    const ARRIVING_TTL: u8 = 5;

    let local = match INTERFACE.lock().as_ref() {
        Some(interface) => interface.protocol,
        None => return false,
    };

    // Routing on, which installs the local interface and one link.
    if multicast_init().is_err() {
        return false;
    }
    let found = {
        let state = MULTICAST.lock();
        state
            .interfaces
            .entries()
            .iter()
            .find(|(_, entry)| entry.vif == net::multicast::Vif::Link)
            .map(|(index, _)| *index)
    };
    let Some(link) = found else {
        return false;
    };
    if multicast_add_mfc(&abi::network::MrtMfcDef {
        source: SENDER,
        group: GROUP,
        in_vif: net::multicast::VIF_LOCAL,
        num_out_vifs: 1,
        out_vifs: [
            abi::network::MrtOutVif { vif: link, ttl: 1 },
            abi::network::MrtOutVif { vif: 0, ttl: 0 },
            abi::network::MrtOutVif { vif: 0, ttl: 0 },
            abi::network::MrtOutVif { vif: 0, ttl: 0 },
        ],
    })
    .is_err()
    {
        let _ = multicast_done();
        return false;
    }

    // The frame, built the way a sender would: UDP to the group, with a TTL
    // this machine never sends, so the copy's count can only be the arriving
    // one minus a hop.
    let payload = b"multicast";
    let udp_len = net::udp::datagram_len(payload.len());
    let frame_len = netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + udp_len;
    let mut frame = alloc::vec![0; frame_len];
    net::ethernet::write_header(
        &mut frame,
        net::ipv4::multicast_mac(GROUP),
        [0x02; 6],
        net::ethernet::ETHERTYPE_IPV4,
    );
    net::ipv4::write_header(
        &mut frame[netdev::ETHERNET_HEADER_LEN..],
        SENDER,
        GROUP,
        net::ipv4::PROTOCOL_UDP,
        udp_len,
    );
    // The arriving hop count, and the sum the change invalidates.  A frame
    // from a router is one this stack parses, and `parse` refuses a header
    // whose checksum does not verify, so the sum is recomputed here.
    frame[netdev::ETHERNET_HEADER_LEN + 8] = ARRIVING_TTL;
    net::udp::write_datagram(
        &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..],
        SENDER,
        GROUP,
        4_000,
        9_107,
        payload,
    );
    let header_end = netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN;
    frame[netdev::ETHERNET_HEADER_LEN + 10..netdev::ETHERNET_HEADER_LEN + 12]
        .copy_from_slice(&[0, 0]);
    let sum = net::ipv4::checksum(&frame[netdev::ETHERNET_HEADER_LEN..header_end]);
    frame[netdev::ETHERNET_HEADER_LEN + 10..netdev::ETHERNET_HEADER_LEN + 12]
        .copy_from_slice(&sum.to_be_bytes());

    // The card is swapped for one that records, so what the forwarding path
    // hands a device is what the probe reads.  The interface's own card is put
    // back before the probe returns.
    let recorded = Arc::new(RecordingCard::new());
    let original = {
        let mut interface = INTERFACE.lock();
        let Some(interface) = interface.as_mut() else {
            let _ = multicast_done();
            return false;
        };
        let original = interface.card.clone();
        interface.card = recorded.clone();
        original
    };

    demux(&frame, local);

    // And back, before anything else sends.
    {
        let mut interface = INTERFACE.lock();
        if let Some(interface) = interface.as_mut() {
            interface.card = original;
        }
    }

    let sent = recorded.frames();
    let forwarded = !sent.is_empty();
    let ttl = sent
        .first()
        .map(|frame| frame[netdev::ETHERNET_HEADER_LEN + 8])
        .unwrap_or(0);
    let carried = sent
        .first()
        .map(|frame| frame[frame.len() - payload.len()..].to_vec())
        .unwrap_or_default();

    let _ = multicast_done();

    let correct = forwarded && ttl == ARRIVING_TTL - 1 && carried == payload;
    arch::serial::write_str("protofire: multicast forwarded ");
    arch::serial::write_u32(sent.len() as u32);
    arch::serial::write_str(" frame(s), ttl ");
    arch::serial::write_u32(ARRIVING_TTL as u32);
    arch::serial::write_str(" -> ");
    arch::serial::write_u32(ttl as u32);
    arch::serial::write_str(", payload ");
    arch::serial::write_str(if carried == payload {
        "intact"
    } else {
        "ALTERED"
    });
    arch::serial::write_str(if correct { "\n" } else { ", MISMATCH\n" });
    correct
}

/// Prove that a rule changes what the demux does with a packet.
///
/// The claim a filter has to earn is not "the rule was stored", it is "the
/// packet was dropped", and the difference is the whole of the shape to avoid:
/// a filter that keeps rules and has an `enabled` flag no call ever sets takes
/// the allow path for every packet and consults the rules by nothing.  This
/// probe measures the delivery instead of the table.
///
/// The exchange is a datagram this machine sends **itself** through the demux,
/// which is the loopback path and the one path that reaches the filter without
/// a wire: a bound port, a send to it, and the queue read afterwards.  Under a
/// deny rule the queue must stay empty and the drop counter must move; with the
/// rule removed the same send must fill the queue.  Both halves are asserted
/// because either one alone is passed by a filter that always drops or one that
/// never does.
///
/// The rule is removed and the counts restored before the probe returns, so the
/// boot's later exchanges run under the filter they started with.
pub fn filter_probe() -> bool {
    const PORT: u16 = 9_106;

    let (local, hardware) = {
        let interface = INTERFACE.lock();
        let Some(interface) = interface.as_ref() else {
            return false;
        };
        (interface.protocol, interface.hardware)
    };

    // A port of its own, so the probe's datagrams cannot land in a queue the
    // rest of the boot is reading.
    let Ok(socket) = bind_udp(PORT) else {
        return false;
    };

    // The frame is built once and sent twice: the two halves have to differ in
    // the rule and in nothing else, or the second delivery proves nothing about
    // the first.
    let payload = b"filter";
    let udp_len = net::udp::datagram_len(payload.len());
    let frame_len = netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + udp_len;
    let mut frame = alloc::vec![0; frame_len];
    net::ethernet::write_header(
        &mut frame,
        hardware,
        hardware,
        net::ethernet::ETHERTYPE_IPV4,
    );
    net::ipv4::write_header(
        &mut frame[netdev::ETHERNET_HEADER_LEN..],
        local,
        local,
        net::ipv4::PROTOCOL_UDP,
        udp_len,
    );
    net::udp::write_datagram(
        &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..],
        local,
        local,
        PORT,
        PORT,
        payload,
    );

    // One rule, denying this port inbound, installed through the same call a
    // program uses.
    let rule = abi::network::FilterRuleDef {
        action: abi::network::FILTER_ACTION_DENY,
        protocol: u32::from(net::ipv4::PROTOCOL_UDP),
        family: abi::network::FILTER_FAMILY_IPV4,
        direction: abi::network::FILTER_DIRECTION_INBOUND,
        stateful: 0,
        source_prefix: 0,
        destination_prefix: 0,
        source_port_start: 0,
        source_port_end: 0,
        destination_port_start: PORT as u32,
        destination_port_end: PORT as u32,
        reserved: 0,
        source_address: [0; abi::network::FILTER_ADDRESS_BYTES],
        destination_address: [0; abi::network::FILTER_ADDRESS_BYTES],
    };
    let id = match filter_add(&rule) {
        Ok(id) => id,
        Err(_) => return false,
    };

    let refused = {
        // Index four is the drop counter, not the allow counter: the tuple is
        // `(default, rules, flows, allowed, dropped)`, and a probe that read
        // the allowed count would see it unchanged by a refused packet and
        // conclude the rule had not run.
        let before = filter_status().4;
        demux(&frame, local);
        let after = filter_status().4;
        // The queue is what the sender's bytes would have filled, and a rule
        // that ran is a rule that kept them out of it.
        let held = socket.try_recv(&mut [0_u8; 32]).ok().flatten().is_none();
        held && after == before + 1
    };

    // The same frame with the rule gone: the delivery that did not happen has
    // to happen now, or the first half proved only that the port answers
    // nothing.
    let removed = filter_remove(id);
    let delivered = {
        demux(&frame, local);
        socket
            .try_recv(&mut [0_u8; 32])
            .ok()
            .flatten()
            .is_some_and(|(_, _, count)| count == payload.len())
    };
    // A second read that answers nothing is the queue drained, which is what
    // makes the next probe's port free of this one's bytes.
    let _ = socket.try_recv(&mut [0_u8; 32]);

    // The outbound half, and a separate rule because the two directions are
    // two decisions: a filter that consulted its rules on the way in and not
    // on the way out would pass the whole exchange above.  The frame is handed
    // to the same `submit_filtered` the three senders call, against a card
    // that records what reached it: the assertion is that a refused send
    // reaches the card **nothing**, which is what the error alone cannot say,
    // a handler that returned `PermissionDenied` *after* submitting would look
    // identical from the caller's side.
    let probe_card = CountingCard::new();
    let outbound = abi::network::FilterRuleDef {
        action: abi::network::FILTER_ACTION_DENY,
        direction: abi::network::FILTER_DIRECTION_OUTBOUND,
        ..rule
    };
    let outbound_id = match filter_add(&outbound) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let refused_out = {
        let before = filter_status().4;
        let answer = submit_filtered(
            &probe_card,
            &frame,
            &net::filter::Packet::v4(
                local,
                local,
                net::ipv4::PROTOCOL_UDP,
                &frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..],
            ),
        );
        answer.is_err() && probe_card.count() == 0 && filter_status().4 == before + 1
    };
    let _ = filter_remove(outbound_id);
    let allowed_out = {
        let answer = submit_filtered(
            &probe_card,
            &frame,
            &net::filter::Packet::v4(
                local,
                local,
                net::ipv4::PROTOCOL_UDP,
                &frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..],
            ),
        );
        answer.is_ok() && probe_card.count() == 1
    };

    let correct = refused && removed && delivered && refused_out && allowed_out;
    arch::serial::write_str("protofire: filter dropped the datagram under a rule: ");
    arch::serial::write_str(if refused { "yes" } else { "no" });
    arch::serial::write_str(", delivered it once removed: ");
    arch::serial::write_str(if delivered { "yes" } else { "no" });
    arch::serial::write_str(", and an outbound rule kept a frame off the card: ");
    arch::serial::write_str(if refused_out && allowed_out {
        "yes"
    } else {
        "no"
    });
    arch::serial::write_str(if correct { "\n" } else { ", MISMATCH\n" });
    correct
}

/// Prove that a raw socket hears what the internet layer carries.
///
/// The exchange is this machine sending itself a packet on a protocol nothing
/// else uses, which the demux then hands to the socket that named it.  What
/// makes it worth its own line is that the header is **the stack's** and not
/// the caller's: the program named a protocol and a payload, and the source
/// address on the packet it received is this machine's, which only a header
/// the stack composed could have put there.
///
/// The protocol is 253, [RFC 3692]'s experimental number: nothing in this
/// stack sends or receives it, so the packet the receive finds is the one the
/// send put there.
///
/// The two numbers are the bytes sent and the bytes received, and they are
/// equal by construction.  The source check is the part that could fail on its
/// own: a receive that reported the destination, or one that reported nothing,
/// would still agree on the length.
///
/// [RFC 3692]: https://www.rfc-editor.org/rfc/rfc3692
pub fn raw_probe() -> bool {
    const PROTOCOL: u8 = 253;
    const PAYLOAD: &[u8] = b"raw packet";

    let socket = match create_raw_socket(PROTOCOL) {
        Ok(socket) => socket,
        Err(_) => return false,
    };
    let address = match INTERFACE.lock().as_ref() {
        Some(interface) => interface.protocol,
        None => return false,
    };
    let sent = match send_raw_packet(PROTOCOL, net::address::Address::V4(address), PAYLOAD) {
        Ok(sent) => sent,
        Err(_) => return false,
    };
    let mut buffer = [0_u8; 32];
    let received = match socket.try_recv(&mut buffer) {
        Ok(Some((source, count))) => (source, count),
        // A send to this machine's own address is delivered through the demux,
        // which is synchronous: a receive that found nothing is the delivery
        // having gone somewhere else.
        _ => return false,
    };

    let source_ok = matches!(received.0, net::address::Address::V4(bytes) if bytes == address);
    let payload_ok = received.1 == PAYLOAD.len() && &buffer[..received.1] == PAYLOAD;
    let correct = sent == PAYLOAD.len() && payload_ok && source_ok;
    arch::serial::write_str("protofire: raw socket sent ");
    arch::serial::write_u32(sent as u32);
    arch::serial::write_str(" byte(s) as protocol ");
    arch::serial::write_u32(PROTOCOL as u32);
    arch::serial::write_str(", and received ");
    arch::serial::write_u32(received.1 as u32);
    arch::serial::write_str(if correct {
        " from this machine\n"
    } else {
        ", MISMATCH\n"
    });
    correct
}

/// The boot's stream exchange: a listener on this machine, a client to it,
/// an echo, and the close that ends both ends.
///
/// The whole of a TCP exchange, on loopback, with no card in the path, the
/// same exchange the protocol crate's tests run on a host, run by the boot
/// so the lines below are a machine's evidence rather than a host's.  Each
/// line names what only a completed exchange could have carried: the ids
/// the table handed out, the echo's length beside the send's, and the close
/// that left both ends done.
pub fn tcp_probe() -> bool {
    let listener = match tcp_listen(9000) {
        Ok(id) => id,
        Err(_) => {
            arch::serial::write_str("protofire: tcp could not listen on port 9000\n");
            return false;
        }
    };
    let protocol = match INTERFACE.lock().as_ref() {
        Some(interface) => interface.protocol,
        None => return false,
    };
    let client = match tcp_connect(net::address::Address::V4(protocol), 9000) {
        Ok(id) => id,
        Err(_) => {
            arch::serial::write_str("protofire: tcp could not connect to the listener\n");
            return false;
        }
    };
    arch::serial::write_str("protofire: tcp connected, listener ");
    arch::serial::write_u32(listener as u32);
    arch::serial::write_str(", stream ");
    arch::serial::write_u32(client as u32);
    arch::serial::write_str("\n");

    let accepted = match tcp_accept(listener) {
        Ok(Some(id)) => id,
        _ => {
            arch::serial::write_str("protofire: tcp accepted nothing\n");
            return false;
        }
    };

    // The client's bytes, the server's echo, and the read-back, each one a
    // segment that crossed the demux inside this call.
    let sent = match tcp_write(client, b"protofire") {
        Ok(count) => count,
        Err(_) => {
            arch::serial::write_str("protofire: tcp could not write\n");
            return false;
        }
    };
    let mut buffer = [0_u8; 32];
    let echoed = match tcp_read(accepted, &mut buffer) {
        Ok(Some(count)) => count,
        _ => 0,
    };
    let back = tcp_write(accepted, &buffer[..echoed]).unwrap_or_default();
    let mut read_back = [0_u8; 32];
    let received = match tcp_read(client, &mut read_back) {
        Ok(Some(count)) => count,
        _ => 0,
    };
    let round_trip = echoed == sent && back == sent && received == sent;
    arch::serial::write_str("protofire: tcp echoed ");
    arch::serial::write_u32(received as u32);
    arch::serial::write_str(" byte(s) of ");
    arch::serial::write_u32(sent as u32);
    arch::serial::write_str(if round_trip {
        ", round trip\n"
    } else {
        ", MISMATCH\n"
    });

    // The orderly close: both sides finish, and the acknowledgements cross.
    // Both ends then **linger** in `TimeWait` rather than leaving the table:
    // the close is over and the four-tuple is held so a retransmitted finish
    // is answered instead of reset.  The line says which state it found,
    // because "gone" and "held" are two different claims and a probe that
    // printed only "done" could not tell a close that finished from one the
    // table had forgotten.
    let _ = tcp_close(client);
    let _ = tcp_close(accepted);
    let state = TCP
        .lock()
        .connection(client)
        .map(|connection| connection.state());
    let lingering = state == Some(net::tcp::State::TimeWait);
    arch::serial::write_str("protofire: tcp closed, both ends ");
    arch::serial::write_str(if lingering {
        "held in time wait\n"
    } else {
        "MISMATCH\n"
    });
    round_trip && lingering
}

/// Prove that a lost segment is recovered, rather than assuming it would be.
///
/// A boot's own network loses nothing: QEMU's user-mode network and the
/// loopback both deliver every frame, so nothing the exchanges above do can
/// tell a stack that retransmits from one that never would.  This probe makes
/// the loss itself, by refusing to deliver the first copy of a segment, and
/// then asks the table for what it is due to send again.
///
/// The line's numbers are the evidence, and each is a value the peer
/// produced: the attempt count comes from the schedule, the byte count from
/// the segment that was sent twice, and `intact` from the peer's own
/// acknowledgement retiring the entry.  A stack that queued nothing would
/// send nothing again and the peer's inbox would stay empty.
pub fn retransmission_probe() -> bool {
    let listener = match tcp_listen(9100) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let protocol = match INTERFACE.lock().as_ref() {
        Some(interface) => interface.protocol,
        None => return false,
    };
    let client = match tcp_connect(net::address::Address::V4(protocol), 9100) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let accepted = match tcp_accept(listener) {
        Ok(Some(id)) => id,
        _ => {
            arch::serial::write_str("protofire: PMTU step accept\n");
            return false;
        }
    };

    // The segment this probe will lose.  It is written with the loopback's
    // own exchange disabled: the bytes go into the table's queue and nowhere
    // else, which is the loss.
    const LOST: &[u8] = b"lost segment";
    let queued = {
        let mut table = TCP.lock();
        table.advance(0);
        let Some(connection) = table.connection_mut(client) else {
            return false;
        };
        let (count, outgoing) = connection.send_data(LOST);
        (count, outgoing.len(), connection.unacknowledged())
    };
    // Nothing was delivered, so the peer has nothing, and the sender is
    // holding one unacknowledged segment.
    let peer_has_nothing = !TCP.lock().has_data(accepted);

    // Walk the schedule: each ask advances the clock past the current
    // timeout, and the table hands back what is due.  The retransmission is
    // then delivered, which is the point of the exercise.
    let mut attempts = 0;
    let mut delivered = 0;
    let mut now = 0u64;
    let mut timeout = net::tcp::RTO_INITIAL_MICROS;
    for _ in 0..net::tcp::MAX_ATTEMPTS {
        now += timeout;
        let due = {
            let mut table = TCP.lock();
            table.advance(now);
            table.retransmissions()
        };
        if due.is_empty() {
            timeout = (timeout * 2).min(net::tcp::RTO_MAX_MICROS);
            continue;
        }
        attempts += 1;
        let mut table = TCP.lock();
        let noteworthy = tcp_exchange(&mut table, due).unwrap_or(false);
        let _ = noteworthy;
        delivered = table
            .connection(accepted)
            .map(|connection| connection.inbox_len())
            .unwrap_or(0);
        break;
    }

    // The close is the ordinary one: both ends finish and both linger in
    // `TimeWait`, which is the state that answers a retransmitted finish.
    let _ = tcp_close(client);
    let _ = tcp_close(accepted);

    let intact = delivered == LOST.len() && peer_has_nothing;
    arch::serial::write_str("protofire: tcp recovered ");
    arch::serial::write_u32(attempts as u32);
    arch::serial::write_str(" attempt(s), ");
    arch::serial::write_u32(delivered as u32);
    arch::serial::write_str(" byte(s)");
    arch::serial::write_str(if intact { ", intact\n" } else { ", MISMATCH\n" });
    let _ = queued;
    intact
}

/// Prove that a path report reaches the stream it names, and that the report
/// is the one the wire would have delivered.
///
/// A wire this gate boots never sends a fragmentation-needed report: the
/// loopback is one machine and QEMU's user-mode network is a proxy that
/// forwards small datagrams without a router on the path.  So the probe builds
/// the report itself, quoting a packet whose four-tuple is a stream it just
/// opened, and hands the whole frame to **the same `demux` a received frame
/// goes through**.
///
/// The line's two numbers are the stream's segment size before and after.  A
/// stack that parsed the report and did nothing with it prints the same number
/// twice, which is exactly the state this change found: `demux` had no ICMP
/// branch at all, so every report about this machine was dropped unread.
pub fn path_mtu_probe() -> bool {
    let listener = match tcp_listen(9103) {
        Ok(id) => id,
        Err(_) => {
            arch::serial::write_str("protofire: PMTU step listen\n");
            return false;
        }
    };
    let (protocol, hardware, gateway_hardware) = {
        let mut interface = INTERFACE.lock();
        let Some(interface) = interface.as_mut() else {
            arch::serial::write_str("protofire: PMTU step interface\n");
            return false;
        };
        let gateway = interface.gateway;
        let hardware = interface.hardware;
        let protocol = interface.protocol;
        let gateway_hardware = interface.arp.hardware_for(gateway).unwrap_or_default();
        (protocol, hardware, gateway_hardware)
    };
    let client = match tcp_connect(net::address::Address::V4(protocol), 9103) {
        Ok(id) => id,
        Err(_) => {
            arch::serial::write_str("protofire: PMTU step connect\n");
            return false;
        }
    };
    let accepted = match tcp_accept(listener) {
        Ok(Some(id)) => id,
        _ => {
            arch::serial::write_str("protofire: PMTU step accept\n");
            return false;
        }
    };

    let before = match TCP.lock().connection(client) {
        Some(connection) => connection.segment_limit(),
        None => return false,
    };
    let client_port = match TCP.lock().local_port_of(client) {
        Some(port) => port,
        None => return false,
    };

    // The report quotes a TCP segment this machine would have sent: the
    // client's own four-tuple, both ports and neither of the headers
    // pretending to be longer than they are.
    // Written with the header writer rather than field by field: `ipv4::parse`
    // verifies the checksum, and a quoted header whose sum was never computed
    // is one the reader refuses, which is how the first version of this probe
    // reported no change at all.
    let mut quoted_header = [0_u8; net::ipv4::HEADER_LEN];
    net::ipv4::write_header(
        &mut quoted_header,
        protocol,
        protocol,
        net::ipv4::PROTOCOL_TCP,
        // Eight bytes of transport, which is what a report quotes: the
        // original's total length field says so, and a reader that took the
        // sender's word for a larger payload would read past the quotation.
        net::icmp::QUOTED_PAYLOAD,
    );
    let mut quoted_payload = [0_u8; 8];
    quoted_payload[0..2].copy_from_slice(&client_port.to_be_bytes());
    quoted_payload[2..4].copy_from_slice(&9103u16.to_be_bytes());

    // The report: destination unreachable, fragmentation needed, and the
    // next hop's MTU.  The MTU is chosen so the payload it implies is a round
    // number a reader can check against the line: 576 less both headers is
    // 536, which is the classic minimum every IPv4 host must accept.
    const NEXT_HOP_MTU: u16 = 576;
    let mut message = [0_u8; 64];
    net::icmp::write_unreachable_with_mtu(
        &mut message,
        net::icmp::FRAGMENTATION_NEEDED,
        NEXT_HOP_MTU,
        &quoted_header,
        &quoted_payload,
    );
    let message_len = net::icmp::error_len(quoted_header.len(), quoted_payload.len());

    // The frame the wire would have carried, handed to the demux a received
    // one goes through.  Its source is the gateway, because a report comes
    // from the party that could not forward the packet.
    let mut frame =
        alloc::vec![0_u8; netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + message_len];
    net::ethernet::write_header(
        &mut frame,
        hardware,
        gateway_hardware,
        net::ethernet::ETHERTYPE_IPV4,
    );
    net::ipv4::write_header(
        &mut frame[netdev::ETHERNET_HEADER_LEN..],
        protocol,
        protocol,
        net::ipv4::PROTOCOL_ICMP,
        message_len,
    );
    frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..][..message_len]
        .copy_from_slice(&message[..message_len]);
    demux(&frame, protocol);

    let after = match TCP.lock().connection(client) {
        Some(connection) => connection.segment_limit(),
        None => {
            arch::serial::write_str("protofire: path mtu probe lost its stream\n");
            return false;
        }
    };

    let expected = NEXT_HOP_MTU as usize - net::ipv4::HEADER_LEN - net::tcp::HEADER_LEN;
    let shrank = before == net::tcp::MSS_DEFAULT && after == expected;

    let _ = tcp_close(client);
    let _ = tcp_close(accepted);

    arch::serial::write_str("protofire: path mtu ");
    arch::serial::write_u32(before as u32);
    arch::serial::write_str(" -> ");
    arch::serial::write_u32(after as u32);
    arch::serial::write_str(if shrank {
        ", the report reached the stream\n"
    } else {
        ", MISMATCH\n"
    });
    shrank
}

/// Prove that an ICMPv6 packet-too-big report reaches the stream it names.
///
/// The IPv6 half of [`path_mtu_probe`], and a separate exchange for a reason
/// the layout makes: this message's MTU word takes the four bytes an IPv4
/// error leaves unused, so the quotation starts **eight** bytes in rather than
/// four.  A reader that used the IPv4 offset would read the MTU as the first
/// four bytes of the quoted packet and find a four-tuple nothing names, which
/// is a defect that only a report of this shape can find.
///
/// The report is built here because no wire this gate boots sends one, and the
/// frame goes through the same `demux_ipv6` a received one does.
pub fn path_mtu6_probe() -> bool {
    let (local, hardware) = {
        let interface = INTERFACE.lock();
        let Some(interface) = interface.as_ref() else {
            return false;
        };
        (interface.ipv6, interface.hardware)
    };
    let listener = match tcp_listen(9104) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let client = match tcp_connect(net::address::Address::V6(local), 9104) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let accepted = match tcp_accept(listener) {
        Ok(Some(id)) => id,
        _ => return false,
    };

    let before = match TCP.lock().connection(client) {
        Some(connection) => connection.segment_limit(),
        None => return false,
    };
    let client_port = match TCP.lock().local_port_of(client) {
        Some(port) => port,
        None => return false,
    };

    // The report quotes a TCP segment this machine sent: its source is the
    // link-local address this machine answers from, and its destination is the
    // peer.  The peer is this machine too, which is what a loopback exchange
    // is, and the quotation is still shaped the way a router's would be.
    let mut quoted_header = [0_u8; net::ipv6::HEADER_LEN];
    net::ipv6::write_header(
        &mut quoted_header,
        local,
        local,
        net::ipv6::NEXT_TCP,
        // Eight bytes of transport, which is what a report quotes: the header's
        // payload length says so, and a reader that took a larger one would
        // read past the quotation, which is how this probe's first version
        // reported no change.
        net::icmp::QUOTED_PAYLOAD,
    );
    let mut quoted_payload = [0_u8; 8];
    quoted_payload[0..2].copy_from_slice(&client_port.to_be_bytes());
    quoted_payload[2..4].copy_from_slice(&9104u16.to_be_bytes());

    // The report: packet too big, and the path's MTU in the word every other
    // error leaves unused.  1280 is [RFC 8200]'s floor, so the payload it
    // implies is 1280 less both headers.
    //
    // [RFC 8200]: https://www.rfc-editor.org/rfc/rfc8200
    const PATH_MTU: u32 = 1_280;
    let message_len = net::icmpv6::QUOTED_AT + quoted_header.len() + quoted_payload.len();
    let mut message = alloc::vec![0_u8; message_len];
    message[0] = net::icmpv6::PACKET_TOO_BIG;
    message[1] = 0;
    message[net::icmpv6::MTU_AT..net::icmpv6::MTU_AT + 4].copy_from_slice(&PATH_MTU.to_be_bytes());
    message[net::icmpv6::QUOTED_AT..net::icmpv6::QUOTED_AT + quoted_header.len()]
        .copy_from_slice(&quoted_header);
    let payload_at = net::icmpv6::QUOTED_AT + quoted_header.len();
    message[payload_at..payload_at + quoted_payload.len()].copy_from_slice(&quoted_payload);
    // The checksum covers the pseudo-header the two addresses make, so it is
    // computed after the message is otherwise whole.
    let sum = net::ipv6::checksum_with_pseudo(local, local, net::ipv6::NEXT_ICMPV6, &message);
    message[2..4].copy_from_slice(&sum.to_be_bytes());

    let mut frame =
        alloc::vec![0_u8; netdev::ETHERNET_HEADER_LEN + net::ipv6::HEADER_LEN + message_len];
    net::ethernet::write_header(
        &mut frame,
        hardware,
        hardware,
        net::ethernet::ETHERTYPE_IPV6,
    );
    net::ipv6::write_header(
        &mut frame[netdev::ETHERNET_HEADER_LEN..],
        local,
        local,
        net::ipv6::NEXT_ICMPV6,
        message_len,
    );
    frame[netdev::ETHERNET_HEADER_LEN + net::ipv6::HEADER_LEN..][..message_len]
        .copy_from_slice(&message);
    demux_ipv6(&frame[netdev::ETHERNET_HEADER_LEN..]);

    let after = match TCP.lock().connection(client) {
        Some(connection) => connection.segment_limit(),
        None => return false,
    };

    let expected = PATH_MTU as usize - net::ipv6::HEADER_LEN - net::tcp::HEADER_LEN;
    let shrank = before == net::tcp::MSS_DEFAULT && after == expected;

    let _ = tcp_close(client);
    let _ = tcp_close(accepted);

    arch::serial::write_str("protofire: path mtu6 ");
    arch::serial::write_u32(before as u32);
    arch::serial::write_str(" -> ");
    arch::serial::write_u32(after as u32);
    arch::serial::write_str(if shrank {
        ", the report reached the stream\n"
    } else {
        ", MISMATCH\n"
    });
    shrank
}

/// Prove that the window a stream advertises is the room it has.
///
/// Every exchange this gate runs carries a few bytes, so none of them can tell
/// a window that shrinks from one that is a constant: a connection holding nine
/// bytes advertises the same number either way.  This probe fills a stream's
/// buffer and reads the number the peer would be told.
///
/// The line's two numbers are the window before and after an unread segment the
/// size of the whole buffer.  A stack that enforced nothing would print the
/// same number twice.
pub fn window_probe() -> bool {
    let listener = match tcp_listen(9105) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let protocol = match INTERFACE.lock().as_ref() {
        Some(interface) => interface.protocol,
        None => return false,
    };
    let client = match tcp_connect(net::address::Address::V4(protocol), 9105) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let accepted = match tcp_accept(listener) {
        Ok(Some(id)) => id,
        _ => return false,
    };
    let source_port = match TCP.lock().local_port_of(client) {
        Some(port) => port,
        None => return false,
    };

    let (before, full, held) = {
        let mut table = TCP.lock();
        let Some(peer) = table.connection_mut(accepted) else {
            return false;
        };
        let before = peer.advertised_window();
        // The position the peer expects, read through the API that answers it:
        // a connection's fields are its own, and a probe that reached into them
        // would be a second reader of state the crate keeps private.
        let base = peer.expected_position();

        // One segment the size of the whole window, delivered to the peer and
        // never read.  The connection now holds every byte it advertised room
        // for.
        let filling = net::tcp::Segment::new(
            source_port,
            9105,
            base,
            5001,
            net::tcp::FLAG_ACK | net::tcp::FLAG_PSH,
            net::tcp::WINDOW,
            before as usize,
        );
        let _ = peer.receive(&filling, &alloc::vec![0x5A_u8; before as usize]);
        let full = peer.advertised_window();

        // One byte more, at the position past everything held: there is
        // nowhere for it, so the buffer must not grow.
        let extra = net::tcp::Segment::new(
            source_port,
            9105,
            base + before as u32,
            5001,
            net::tcp::FLAG_ACK | net::tcp::FLAG_PSH,
            net::tcp::WINDOW,
            1,
        );
        let _ = peer.receive(&extra, b"x");
        (before, full, peer.held())
    };

    let _ = tcp_close(client);
    let _ = tcp_close(accepted);

    let bounded = full == 0 && held == before as usize;
    arch::serial::write_str("protofire: window ");
    arch::serial::write_u32(before as u32);
    arch::serial::write_str(" -> ");
    arch::serial::write_u32(full as u32);
    arch::serial::write_str(if bounded {
        ", and a byte past it was refused\n"
    } else {
        ", MISMATCH\n"
    });
    bounded
}

/// Prove that the two size options change the connection rather than a field.
///
/// A ring-3 set and get proves the call is wired; it does not prove the number
/// changed anything, and the options module's whole argument is that a stored
/// number nothing acts on is a false promise.  So the probe sets each one and
/// reads the state it governs: `SO_RCVBUF` is the window the connection
/// advertises next, and `SO_SNDBUF` is the congestion window it will not
/// exceed.
///
/// The four numbers are the argument.  `8192` is the advertised window before,
/// `1000` is the receive buffer the probe set and the window after, `14600` is
/// the congestion window before, and `2190` is what it became when the probe
/// named a send buffer of three segments.
pub fn option_effect_probe() -> bool {
    let listener = match tcp_listen(9108) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let protocol = match INTERFACE.lock().as_ref() {
        Some(interface) => interface.protocol,
        None => return false,
    };
    let client = match tcp_connect(net::address::Address::V4(protocol), 9108) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let accepted = match tcp_accept(listener) {
        Ok(Some(id)) => id,
        _ => return false,
    };

    let narrowed = 1000_usize;
    let send_buffer = 3 * net::tcp::MSS_DEFAULT;
    let (before_window, after_window, before_cwnd, after_cwnd) = {
        let mut table = TCP.lock();
        let Some(connection) = table.connection_mut(client) else {
            return false;
        };
        let before_window = connection.advertised_window();
        if connection
            .set_option(
                abi::network::SOL_SOCKET,
                abi::network::SO_RCVBUF,
                &narrowed.to_le_bytes(),
            )
            .is_err()
        {
            return false;
        }
        let after_window = connection.advertised_window();
        let before_cwnd = connection.congestion_window();
        if connection
            .set_option(
                abi::network::SOL_SOCKET,
                abi::network::SO_SNDBUF,
                &send_buffer.to_le_bytes(),
            )
            .is_err()
        {
            return false;
        }
        let after_cwnd = connection.congestion_window();
        (before_window, after_window, before_cwnd, after_cwnd)
    };

    let _ = tcp_close(client);
    let _ = tcp_close(accepted);

    let correct = before_window == net::tcp::WINDOW
        && after_window == narrowed as u16
        && before_cwnd == net::tcp::INITIAL_CWND
        && after_cwnd == send_buffer;
    arch::serial::write_str("protofire: options window ");
    arch::serial::write_u32(before_window as u32);
    arch::serial::write_str(" -> ");
    arch::serial::write_u32(after_window as u32);
    arch::serial::write_str(", congestion ");
    arch::serial::write_u32(before_cwnd as u32);
    arch::serial::write_str(" -> ");
    arch::serial::write_u32(after_cwnd as u32);
    arch::serial::write_str(if correct {
        ", both options moved what they govern\n"
    } else {
        ", MISMATCH\n"
    });
    correct
}

/// Prove that the window a peer advertises bounds what this side sends.
///
/// A statement in a field, and nothing in a boot makes a peer state a small
/// one: both ends here advertise [`net::tcp::WINDOW`], and every exchange is
/// short enough that the queue's bound would stop it first.  So the probe
/// states a window on the peer's behalf: it hands the sender a bare
/// acknowledgement whose only interesting content is the window word, and asks
/// how much a write carries afterwards.
///
/// The three numbers on the line are the probe's argument.  `8192` is the
/// stream's own advertised window before anything is said, `0` is what the
/// sender's budget became when the peer said its buffer was full, and `7` is
/// what the same write carried once the peer reopened.  A sender that parsed
/// the field and ignored it would print `8192 -> 8192` and carry the seven
/// bytes while the peer said nothing fits, which is the defect this pins.
pub fn peer_window_probe() -> bool {
    let listener = match tcp_listen(9107) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let protocol = match INTERFACE.lock().as_ref() {
        Some(interface) => interface.protocol,
        None => return false,
    };
    let client = match tcp_connect(net::address::Address::V4(protocol), 9107) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let accepted = match tcp_accept(listener) {
        Ok(Some(id)) => id,
        _ => return false,
    };
    let source_port = match TCP.lock().local_port_of(client) {
        Some(port) => port,
        None => return false,
    };

    // The statement, built here because the peer has no reason to make one:
    // a bare acknowledgement at the position this side next sends from, which
    // is the range's high end, carrying a zero window.
    let (opened, blocked, reopened) = {
        let mut table = TCP.lock();
        let Some(sender) = table.connection_mut(client) else {
            return false;
        };
        let opened = sender.peer_window();
        let stated = net::tcp::Segment::new(
            9107,
            source_port,
            0,
            sender.send_position(),
            net::tcp::FLAG_ACK,
            0,
            0,
        );
        let _ = sender.receive(&stated, b"");
        let blocked = sender.send_budget();
        // The write while the peer says it has no room.  What it carries is
        // the number a sender that ignored the field would get wrong.
        let (carried, outgoing) = sender.send_data(b"protofire");
        let refused_while_full = carried == 0 && outgoing.is_empty();
        // The reopen, and the same write again.
        let again = net::tcp::Segment::new(
            9107,
            source_port,
            0,
            sender.send_position(),
            net::tcp::FLAG_ACK,
            net::tcp::WINDOW,
            0,
        );
        let _ = sender.receive(&again, b"");
        let (carried, _outgoing) = sender.send_data(b"protofire");
        let reopened = if refused_while_full { carried } else { 0 };
        (opened, blocked, reopened)
    };

    let _ = tcp_close(client);
    let _ = tcp_close(accepted);

    let correct = opened == net::tcp::WINDOW as usize && blocked == 0 && reopened == 9;
    arch::serial::write_str("protofire: peer window ");
    arch::serial::write_u32(opened as u32);
    arch::serial::write_str(" -> ");
    arch::serial::write_u32(blocked as u32);
    arch::serial::write_str(" -> ");
    arch::serial::write_u32(reopened as u32);
    arch::serial::write_str(if correct {
        ", the peer's window bounded the write\n"
    } else {
        ", MISMATCH\n"
    });
    correct
}

/// Prove that a rebinding's request is a shape a server answers.
///
/// The exchange is [RFC 2131]'s third state: the lease's server has stopped
/// answering, so the question goes out as a broadcast with no server named.
/// Nothing in this tree's boot reaches that state on its own, because a
/// server's default lease is a day, so the probe runs it once against whatever
/// server the wire has.
///
/// The probe asserts the answer rather than reporting it, and the assertion is
/// the whole point: a rebinding that left and was answered is a server having
/// read a broadcast request whose server option was absent, which is a claim no
/// other exchange this gate runs makes.  QEMU's user-mode DHCP answers one,
/// measured on all four machines; a machine whose wire does not is a machine
/// where this line would have to be argued for rather than weakened, and the
/// probe says so by printing what happened.
pub fn rebind_probe() -> bool {
    let lease = {
        let interface = INTERFACE.lock();
        let Some(interface) = interface.as_ref() else {
            return false;
        };
        match interface.lease {
            Some(lease) => lease,
            None => return false,
        }
    };

    let renewed = rebind_lease(&lease);
    let answered = renewed.is_some();
    if let Some(lease) = renewed {
        apply_lease(&lease, "rebound");
    }
    arch::serial::write_str("protofire: rebind sent, ");
    arch::serial::write_str(if answered {
        "the wire answered\n"
    } else {
        "the wire said nothing\n"
    });
    answered
}

/// Prove that a stream's window grows on acknowledgements and collapses on a
/// loss.
///
/// Every exchange this gate runs sends a handful of segments and acknowledges
/// every one, so a stack with no congestion window and one with a window behave
/// identically: the transfer finishes before the window matters.  This probe
/// runs an exchange long enough to see the window move, and reports the number
/// it reached before and after a timeout.
///
/// The three numbers are the initial window, what acknowledgements grew it to,
/// and what a timeout left it at.  A stack that never grew it prints the first
/// number three times; one that never collapsed it prints the second twice.
pub fn congestion_probe() -> bool {
    let listener = match tcp_listen(9106) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let protocol = match INTERFACE.lock().as_ref() {
        Some(interface) => interface.protocol,
        None => return false,
    };
    let client = match tcp_connect(net::address::Address::V4(protocol), 9106) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let accepted = match tcp_accept(listener) {
        Ok(Some(id)) => id,
        _ => return false,
    };

    let initial = match TCP.lock().connection(client) {
        Some(connection) => connection.congestion_window(),
        None => return false,
    };
    let source_port = match TCP.lock().local_port_of(client) {
        Some(port) => port,
        None => return false,
    };

    // Ten segments, delivered one at a time with the peer acknowledging each,
    // which is what a round trip of acknowledgements looks like from the
    // sender's side.  Each acknowledgement opens the window by the bytes it
    // carried.
    let mut peer_position = 0u32;
    for index in 0..10u32 {
        let (sequence, acknowledgement, payload) = {
            let mut table = TCP.lock();
            let Some(connection) = table.connection_mut(client) else {
                return false;
            };
            // One segment at a time, so the window is asked for room each turn.
            let (sent, outgoing) = connection.send_data(&alloc::vec![index as u8; 64]);
            match (sent, outgoing.into_iter().next()) {
                (64, Some(segment)) => (segment.sequence, segment.acknowledgement, segment.payload),
                _ => return false,
            }
        };
        // The peer receives it and answers, and the answer goes back through
        // the same path a real one would take.
        let (event, replies) = {
            let mut table = TCP.lock();
            let Some(peer) = table.connection_mut(accepted) else {
                return false;
            };
            if peer_position == 0 {
                peer_position = peer.expected_position();
            }
            let segment = net::tcp::Segment::new(
                source_port,
                9106,
                sequence,
                acknowledgement,
                net::tcp::FLAG_ACK | net::tcp::FLAG_PSH,
                net::tcp::WINDOW,
                payload.len(),
            );
            peer.receive(&segment, &payload)
        };
        let _ = event;
        if replies.is_empty() {
            return false;
        }
        // The peer's acknowledgement reaches the sender.
        let mut table = TCP.lock();
        let Some(sender) = table.connection_mut(client) else {
            return false;
        };
        for reply in replies {
            let segment = net::tcp::Segment::new(
                9106,
                source_port,
                peer_position,
                reply.acknowledgement,
                reply.flags,
                reply.window,
                reply.payload.len(),
            );
            let _ = sender.receive(&segment, &reply.payload);
            peer_position = peer_position.wrapping_add(64);
        }
    }

    let grown = match TCP.lock().connection(client) {
        Some(connection) => connection.congestion_window(),
        None => return false,
    };

    // A segment nobody answers, and the timer that fires.
    let timed_out = {
        let mut table = TCP.lock();
        let Some(sender) = table.connection_mut(client) else {
            return false;
        };
        let (_, outgoing) = sender.send_data(&alloc::vec![0x7E_u8; 64]);
        let queued = !outgoing.is_empty();
        sender.advance(crate::net::micros_since_boot() + net::tcp::RTO_INITIAL_MICROS);
        let fired = matches!(
            sender.retransmit(),
            net::tcp::Retransmission::Again(_) | net::tcp::Retransmission::Abandoned
        );
        (queued, fired, sender.congestion_window())
    };

    let _ = tcp_close(client);
    let _ = tcp_close(accepted);

    let correct = grown > initial && timed_out.1 && timed_out.2 < grown;
    arch::serial::write_str("protofire: congestion ");
    arch::serial::write_u32(initial as u32);
    arch::serial::write_str(" -> ");
    arch::serial::write_u32(grown as u32);
    arch::serial::write_str(" -> ");
    arch::serial::write_u32(timed_out.2 as u32);
    arch::serial::write_str(if correct {
        ", grew and then collapsed\n"
    } else {
        ", MISMATCH\n"
    });
    correct
}

/// Prove that a segment which arrives early is held and then delivered.
///
/// No wire this gate boots reorders, so the probe makes the reordering: it
/// delivers a stream's second half to the peer before its first, and then the
/// first.  A stack that dropped the early half would leave the peer's inbox
/// short by exactly that half, which is the number on the line.
pub fn out_of_order_probe() -> bool {
    let listener = match tcp_listen(9101) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let protocol = match INTERFACE.lock().as_ref() {
        Some(interface) => interface.protocol,
        None => return false,
    };
    let client = match tcp_connect(net::address::Address::V4(protocol), 9101) {
        Ok(id) => id,
        Err(_) => return false,
    };
    let accepted = match tcp_accept(listener) {
        Ok(Some(id)) => id,
        _ => {
            arch::serial::write_str("protofire: PMTU step accept\n");
            return false;
        }
    };

    // The whole stream, in two halves, sent from the client and never
    // delivered by the exchange: the halves are the probe's to route.
    //
    // `firsthalf` is nine bytes and `secondhalf` is ten, so the split is a
    // named offset and not half the slice's length: a probe that split at the
    // wrong byte would test a stream the line then described wrongly.
    const STREAM: &[u8] = b"firsthalfsecondhalf";
    const SPLIT: usize = 9;
    let halves = {
        let mut table = TCP.lock();
        let Some(connection) = table.connection_mut(client) else {
            return false;
        };
        // One segment carrying the whole stream, split here rather than by
        // the state machine: the probe's job is to reorder what a wire would
        // have carried, and a sender that split it would hide the case.
        let (_, outgoing) = connection.send_data(STREAM);
        let segment = match outgoing.into_iter().next() {
            Some(segment) => segment,
            None => return false,
        };
        let base = segment.sequence;
        let acknowledgement = segment.acknowledgement;
        (
            (base, acknowledgement, segment.payload[..SPLIT].to_vec()),
            (
                base + SPLIT as u32,
                acknowledgement,
                segment.payload[SPLIT..].to_vec(),
            ),
        )
    };

    // The second half first: held, and answered with the hole's position.
    let source_port = TCP
        .lock()
        .local_port_of(client)
        .expect("the client's own port");
    {
        let mut table = TCP.lock();
        let Some(peer) = table.connection_mut(accepted) else {
            return false;
        };
        let (sequence, acknowledgement, payload) = halves.1.clone();
        let segment = net::tcp::Segment::new(
            source_port,
            9101,
            sequence,
            acknowledgement,
            net::tcp::FLAG_ACK | net::tcp::FLAG_PSH,
            net::tcp::WINDOW,
            payload.len(),
        );
        // The answer is the duplicate acknowledgement the peer would send;
        // the probe routes the halves itself, so the return is not acted on.
        let _ = peer.receive(&segment, &payload);
    }
    let held = TCP
        .lock()
        .connection(accepted)
        .map(|connection| connection.out_of_order())
        .unwrap_or(0);

    // The first half: the gap closes and both halves land, in order.
    {
        let mut table = TCP.lock();
        let Some(peer) = table.connection_mut(accepted) else {
            return false;
        };
        let (sequence, acknowledgement, payload) = halves.0.clone();
        let segment = net::tcp::Segment::new(
            source_port,
            9101,
            sequence,
            acknowledgement,
            net::tcp::FLAG_ACK | net::tcp::FLAG_PSH,
            net::tcp::WINDOW,
            payload.len(),
        );
        let _ = peer.receive(&segment, &payload);
    }

    let mut buffer = [0_u8; 64];
    let delivered = TCP
        .lock()
        .connection_mut(accepted)
        .map(|connection| connection.take(&mut buffer))
        .unwrap_or(0);
    let in_order = delivered == STREAM.len() && buffer[..delivered] == *STREAM;

    let _ = tcp_close(client);
    let _ = tcp_close(accepted);

    arch::serial::write_str("protofire: tcp reordered ");
    arch::serial::write_u32(held as u32);
    arch::serial::write_str(" held, ");
    arch::serial::write_u32(delivered as u32);
    arch::serial::write_str(" byte(s)");
    arch::serial::write_str(if in_order {
        ", in order\n"
    } else {
        ", MISMATCH\n"
    });
    in_order
}
