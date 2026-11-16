//! kernel/src/net/demux4.rs
//!
//! What a received IPv4 frame means: the demux itself, ICMP, and the port
//! unreachable report a datagram to a closed port earns.
//!
//! One section of `kernel/src/net/mod.rs`.  The sections call each other in
//! both directions: the demux reaches every protocol's delivery and a protocol
//! reaches the interface, so each names what it needs through `super::`.  What
//! the split buys is that a reader looking for one protocol opens one file.

use alloc::vec::Vec;

use super::core::Delivery;
use super::core::FRAGMENTS;
use super::core::INTERFACE;
use super::core::TCP;
use super::core::arp_learn;
use super::core::deliver_raw;
use super::core::deliver_udp;
use super::core::fragment_now;
use super::dccp::deliver_dccp;
use super::demux6::demux_ipv6;
use super::filter::filter_inbound;
use super::ipsec::ipsec_open;
use super::multicast::forward_multicast;
use super::multicast::forwarded_groups;
use super::multicast::multicast_forward;
use super::tcp::demux_tcp;

/// What one received frame means, and where it goes.
pub(crate) fn demux(frame: &[u8], protocol: [u8; 4]) {
    if netdev::ethertype(frame) == Some(net::ethernet::ETHERTYPE_ARP) {
        if let Some(arp) = net::arp::parse(frame)
            && arp.operation == net::arp::OPER_REPLY
        {
            arp_learn(arp.sender_protocol, arp.sender_hardware);
        }
        return;
    }
    if netdev::ethertype(frame) == Some(net::ethernet::ETHERTYPE_IPV6) {
        demux_ipv6(&frame[netdev::ETHERNET_HEADER_LEN..]);
        return;
    }
    if netdev::ethertype(frame) != Some(net::ethernet::ETHERTYPE_IPV4) {
        return;
    }
    let Some(packet) = net::ipv4::parse(&frame[netdev::ETHERNET_HEADER_LEN..]) else {
        return;
    };
    // A group this machine forwards for is a group it receives, and one it
    // neither addresses nor forwards is another machine's conversation.  The
    // joined set is read from the multicast tables rather than a fixed array:
    // an interface's groups are what a forwarding entry added, which is why
    // this is a question the tables answer and not a constant.
    let joined = forwarded_groups();
    if !net::ipv4::is_for(&packet, protocol, &joined) {
        return;
    }
    let at = netdev::ETHERNET_HEADER_LEN + packet.payload_at;
    let payload = &frame[at..at + packet.payload_len];

    // Multicast forwarding, which is the one thing this stack does with a
    // packet that is not its own.  The rule is the RFC 1112 one and it is
    // ordered: a packet bound for a group is **received** if a forwarding entry
    // names it, and then forwarded to the interfaces that entry names, with a
    // copy never going back out of the interface it arrived on.
    //
    // The arriving interface is the local one: this machine has one card, so a
    // packet that reached the demux arrived on the link interface and is being
    // read by the host, which is `VIF_LOCAL`'s own traffic.  A cache entry
    // installed for the host's own stream therefore names `VIF_LOCAL` as its
    // input, and the copy leaves by the link.
    if net::ipv4::is_multicast(packet.header.destination)
        && let Some(forwarding) = multicast_forward(
            packet.header.source,
            packet.header.destination,
            net::multicast::VIF_LOCAL,
            packet.header.time_to_live,
            payload.len(),
        )
    {
        forward_multicast(&packet, payload, &forwarding);
    }

    // The filter's opinion, before any transport reads a byte.  Before, and
    // not after: a packet a rule drops has not reached the stream table, so a
    // dropped SYN makes no stream, a dropped datagram fills no queue, and a
    // dropped fragment does not spend the reassembly cache's memory.  A filter
    // asked after the demux would be a filter that decided whether a program
    // learned something it had already been told.
    //
    // A **later fragment** is matched with no ports, because its transport
    // header is in the first piece: the filter sees the ports that arrived
    // with this packet and nothing the sender put in another one.
    if !filter_inbound(&net::filter::Packet::v4(
        packet.header.source,
        packet.header.destination,
        packet.header.protocol,
        payload,
    )) {
        return;
    }

    // ESP is decapsulated here, before any transport reads a byte, and it is
    // the one arriving protocol whose payload is **not** what the header
    // claims: the IP header says 50 and the bytes inside are a UDP or TCP
    // header this machine has to be told about.  A stack that demultiplexed on
    // the outer number would deliver every protected packet to a protocol
    // nothing listens on.
    //
    // A packet that fails its tag, or whose sequence the window refuses, is
    // **dropped here**: the checks that would have run on the plaintext are
    // checks on bytes an attacker chose, and running them is the defect ESP
    // exists to prevent.
    // ESP is decapsulated here, before any transport reads a byte, and it is
    // the one arriving protocol whose payload is **not** what the header
    // claims: the IP header says 50 and the bytes inside are a UDP or TCP
    // header this machine has to be told about.  A stack that demultiplexed on
    // the outer number would deliver every protected packet to a protocol
    // nothing listens on.
    //
    // A packet that fails its tag, or whose sequence the window refuses, is
    // **dropped here**: the checks that would have run on the plaintext are
    // checks on bytes an attacker chose, and running them is the defect ESP
    // exists to prevent.
    let decapsulated: alloc::vec::Vec<u8>;
    let (protocol_number, payload): (u8, &[u8]) =
        if packet.header.protocol == net::ipv4::PROTOCOL_ESP {
            let Some((inner, next_header)) = ipsec_open(payload) else {
                return;
            };
            decapsulated = inner;
            (next_header, &decapsulated[..])
        } else {
            (packet.header.protocol, payload)
        };

    // A piece of a larger packet is held rather than read as the whole: the
    // bytes at an offset are not a segment, and parsing them as one is how a
    // stack answers with a truncated segment that looks complete.  The last
    // piece completes the datagram, and what comes back is the payload as the
    // sender wrote it, which then takes the same path an unfragmented
    // packet's payload takes.
    let whole;
    let payload = if packet.is_fragment() {
        let key = net::reassembly::Key {
            family: 4,
            source: net::address::Address::V4(packet.header.source),
            destination: net::address::Address::V4(packet.header.destination),
            identification: packet.identification as u32,
            next_header: packet.header.protocol,
        };
        let piece = net::reassembly::Piece {
            data: payload,
            offset: packet.fragment_offset,
            more: packet.more_fragments,
        };
        let outcome = FRAGMENTS.lock().accept(key, piece, fragment_now());
        match outcome {
            net::reassembly::Outcome::Complete(assembled) => {
                whole = assembled;
                &whole[..]
            }
            net::reassembly::Outcome::Collected => return,
            net::reassembly::Outcome::Refused(_) => return,
        }
    } else {
        payload
    };

    if protocol_number == net::ipv4::PROTOCOL_UDP
        && let Some(datagram) =
            net::udp::parse(payload, packet.header.source, packet.header.destination)
    {
        let data_at = net::udp::HEADER_LEN;
        let data = &payload[data_at..data_at + datagram.payload_len];
        let delivered = deliver_udp(
            net::address::Address::V4(packet.header.destination),
            datagram.destination_port,
            net::address::Address::V4(packet.header.source),
            datagram.source_port,
            data,
        );
        // A datagram for a port nothing owns is the one error this stack can
        // be sure a sender can act on: the report says which port and quotes
        // the datagram, and the sender's own call is what failed.
        if matches!(delivered, Ok(Delivery::Unbound)) {
            // The header the report quotes is the sender's own bytes, not a
            // header rebuilt from the fields `parse` keeps: [RFC 792] says
            // the original internet header, and every field this stack does
            // not read (the ttl, the type of service, the options) is part of
            // what came back.
            //
            // [RFC 792]: https://www.rfc-editor.org/rfc/rfc792
            let original_header = packet
                .header_bytes(&frame[netdev::ETHERNET_HEADER_LEN..])
                .unwrap_or_default();
            answer_port_unreachable(&packet, original_header, &payload[data_at..]);
        }
    }
    if protocol_number == net::ipv4::PROTOCOL_TCP && demux_tcp(packet, payload) {
        // The same wake a datagram delivery makes, from the same kind of
        // context: the table's lock is down, the scheduler's is next.
        let woken = crate::scheduler::wake_blocked();
        #[cfg(target_os = "none")]
        if woken > 0 {
            // The woken task may be held by another CPU parked in a wait
            // whose own clock may never move, and only the IPI ends that
            // wait.  SAFETY: the boot's own IPI path, installed before any
            // program ran.
            unsafe { arch::send_ipi_to_others() };
        }
        #[cfg(not(target_os = "none"))]
        let _ = woken;
    }
    // DCCP, which is a transport of its own: the segment is the payload, and
    // the reply its state machine makes is sent from inside the call.
    if protocol_number == net::dccp::PROTOCOL {
        let _ = deliver_dccp(
            payload,
            net::address::Address::V4(packet.header.source),
            packet.header.destination,
        );
    }
    if protocol_number == net::ipv4::PROTOCOL_ICMP {
        handle_icmp(&packet, payload);
    }

    // A raw socket is a **reader of the internet layer** and not a second
    // transport: it is handed the payload of every packet this machine
    // accepts, whatever the protocol, after the stack's own handling of it has
    // run.  After, and not instead: an ICMP error a stream acted on is still a
    // message a program watching ICMP may want to see, and a stack that
    // deflected a packet to a raw socket would be a stack whose own protocols
    // changed meaning when a program opened a socket.
    let kept = deliver_raw(
        protocol_number,
        net::address::Address::V4(packet.header.source),
        payload,
    );
    if kept > 0 {
        // The same wake a datagram delivery makes: a program parked on a raw
        // receive is waiting for exactly this.
        let woken = crate::scheduler::wake_blocked();
        #[cfg(target_os = "none")]
        if woken > 0 {
            // The woken task may be held by another CPU parked in a wait whose
            // own clock may never move.  SAFETY: the boot's own IPI path,
            // installed before any program ran.
            unsafe { arch::send_ipi_to_others() };
        }
        #[cfg(not(target_os = "none"))]
        let _ = woken;
    }
}

/// What one received ICMP message means to this stack.
///
/// Two codes change anything, and both are about a stream this machine holds.
/// A **fragmentation-needed** report is the path's size, and every stream the
/// quoted four-tuple names shrinks to it: without that, a sender whose packets
/// are too large has no evidence at all, because the router's only other
/// answer is silence and the sender's own retransmissions produce the same
/// silence every time.  A **port** or **host unreachable** report ends the
/// stream it names, because a third party on the path has said the path does
/// not exist.
///
/// Every other message is dropped, and the silence is deliberate: this stack
/// sends no echo request it is waiting on outside the boot's own probe, and
/// acting on a report about a packet it did not send would let a stranger end
/// a connection by quoting it.
fn handle_icmp(packet: &net::ipv4::Packet, payload: &[u8]) {
    let Some(error) = net::icmp::parse_error(payload) else {
        return;
    };
    if error.kind != net::icmp::DESTINATION_UNREACHABLE {
        return;
    }
    // The quoted original packet: its header, then the transport's first
    // eight bytes, which is what a report must carry.  Nothing is acted on
    // unless the original was **this machine's**, a report about a packet
    // that was not ours is a stranger's claim, and a four-tuple match without
    // the address check would let one end a connection by guessing a port.
    let Some(report) = quoted_report(packet.header.source, &error, payload) else {
        return;
    };
    match error.code {
        net::icmp::FRAGMENTATION_NEEDED => {
            // The MTU is the next hop's, and the payload one segment can carry
            // is it less this stack's own headers.  A report with no MTU (a
            // sender that left the field zero, which [RFC 1191] says to read as
            // "no number") is acted on with the protocol's own floor instead,
            // so the stream does not keep sending a size that was just refused.
            //
            // [RFC 1191]: https://www.rfc-editor.org/rfc/rfc1191
            let mtu = error
                .next_hop_mtu
                .filter(|mtu| *mtu as usize >= net::ipv4::HEADER_LEN + net::tcp::HEADER_LEN)
                .map(usize::from)
                .unwrap_or(net::ipv4::HEADER_LEN + net::tcp::MIN_MSS);
            let _ = report;
            let _ = TCP
                .lock()
                .limit_path(report.remote, report.local_port, payload_for(mtu));
        }
        net::icmp::PORT_UNREACHABLE | net::icmp::HOST_UNREACHABLE => {
            let aborted = TCP.lock().abort_path(report.remote, report.local_port);
            #[cfg(target_os = "none")]
            if aborted {
                arch::serial::write_str("protofire: an icmp error ended a stream\n");
            }
            #[cfg(not(target_os = "none"))]
            let _ = aborted;
        }
        _ => {}
    }
}

/// The payload one segment carries when the path's MTU is `mtu`.
///
/// The path's size less both headers this stack puts in front of a segment.
/// `saturating_sub` because an MTU a peer states wrongly is the peer's number
/// and a subtraction that wrapped would be a limit of nearly four gigabytes.
pub(crate) fn payload_for(mtu: usize) -> usize {
    mtu.saturating_sub(net::ipv4::HEADER_LEN)
        .saturating_sub(net::tcp::HEADER_LEN)
}

/// What a report says about one of this machine's streams.
///
/// The four-tuple a report names, read out of the packet it quotes.  The
/// quoted packet is one **this machine sent**, so the port it names first is
/// ours and the one it names second is the peer's: the two are returned in
/// the order the table is keyed on, and swapping them finds the peer's own end
/// of a loopback exchange and shrinks the wrong stream.  That swap was a real
/// defect, and the boot's probe is what found it.
///
/// `None` for every report that names nothing this machine can act on: one
/// about somebody else's packet, one whose quotation does not parse, and one
/// whose protocol has no ports.
///
/// `our_address` is checked against the quoted packet's **source**, not its
/// destination.  A report is about a packet that was not delivered, and the
/// quoted packet is one this machine *sent*: its destination is the peer whose
/// path was too narrow, and its source is the address it left from.  The check
/// this stack first had compared destinations, which is the answer for a
/// report about a packet sent *to* us, and that is not what an error quotes.
pub(crate) fn quoted_report(
    our_address: [u8; 4],
    error: &net::icmp::Error,
    payload: &[u8],
) -> Option<Report> {
    let quoted = payload.get(error.quoted_at..error.quoted_at + error.quoted_len)?;
    let original = net::ipv4::parse(quoted)?;
    // The quoted packet must have left from this machine: a report about a
    // packet that was not ours is a stranger's claim, and a four-tuple match
    // without this check would let one end a connection by guessing a port.
    if original.header.source != our_address {
        return None;
    }
    let transport = quoted.get(original.payload_at..)?;
    let ports = quoted_segment(original.header.protocol, transport)?;
    Some(Report {
        remote: (
            net::address::Address::V4(original.header.destination),
            ports.destination_port,
        ),
        local_port: ports.source_port,
    })
}

/// One of this machine's streams, as a report names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Report {
    /// The peer's address and port.
    pub(crate) remote: (net::address::Address, u16),
    /// This machine's own port.
    pub(crate) local_port: u16,
}

/// The ports a report's quoted transport header names.
///
/// A report must quote the original's header and the first eight bytes of its
/// payload, and for both transports those eight bytes begin with the two
/// ports, which is what makes a four-tuple readable from a quotation.  The
/// ports are read here rather than through `udp::parse` or `tcp::parse`
/// because the quote has no checksum to verify: it is a fragment of a packet
/// by construction, and a parser that demanded one would refuse every report.
pub(crate) fn quoted_segment(protocol: u8, transport: &[u8]) -> Option<Ports> {
    if transport.len() < 4 {
        return None;
    }
    if protocol != net::ipv4::PROTOCOL_TCP && protocol != net::ipv4::PROTOCOL_UDP {
        return None;
    }
    Some(Ports {
        source_port: u16::from_be_bytes([transport[0], transport[1]]),
        destination_port: u16::from_be_bytes([transport[2], transport[3]]),
    })
}

/// The two ports a quotation names.
pub(crate) struct Ports {
    pub(crate) source_port: u16,
    pub(crate) destination_port: u16,
}

/// Tell a sender that the port its datagram named has nothing bound.
///
/// [RFC 792]'s message, and the only ICMP error this stack sends: a datagram
/// for a port nothing owns is the case a sender provokes by dialling a port
/// that is closed, and silence would leave it waiting.  The original's header
/// and the first eight payload bytes are quoted back so the sender can match
/// the report to its socket.
///
/// Nothing is sent for a datagram that was itself addressed to a group or to
/// the broadcast address, which is [RFC 1122]'s rule: a report about a
/// broadcast would be a report to everyone, and every one of them would be
/// entitled to answer it.
///
/// [RFC 792]: https://www.rfc-editor.org/rfc/rfc792
/// [RFC 1122]: https://www.rfc-editor.org/rfc/rfc1122
fn answer_port_unreachable(packet: &net::ipv4::Packet, original_header: &[u8], payload: &[u8]) {
    let destination = packet.header.destination;
    // A group or broadcast destination is not a socket's, so a report about
    // one would go to everyone who could answer it.
    if destination[0] & 0xF0 == 0xE0 || destination[3] == 0xFF {
        return;
    }
    // The sender's own hardware address, which the ARP cache holds because
    // this machine answered or asked it: a report with no address to send to
    // is a report this stack cannot deliver.
    let Some(sender_hardware) = peer_hardware_v4(packet.header.source) else {
        return;
    };
    let (card, our_protocol, our_hardware) = {
        let interface = INTERFACE.lock();
        let Some(interface) = interface.as_ref() else {
            return;
        };
        (
            interface.card.clone(),
            interface.protocol,
            interface.hardware,
        )
    };

    let frame = port_unreachable_frame(
        original_header,
        packet,
        payload,
        our_protocol,
        our_hardware,
        sender_hardware,
    );
    let _ = card.submit_frame(&frame);
}

/// Build the port-unreachable report for a datagram, as the frame that carries
/// it.
///
/// Apart from the send so a host test can read what it built: a report whose
/// quote a sender cannot match is a report that changed nothing, and the only
/// way to check the quote is to compare it against the datagram it is about.
pub(crate) fn port_unreachable_frame(
    original_header: &[u8],
    packet: &net::ipv4::Packet,
    payload: &[u8],
    our_protocol: [u8; 4],
    our_hardware: [u8; 6],
    sender_hardware: [u8; 6],
) -> Vec<u8> {
    let quoted_payload = payload.len().min(net::icmp::QUOTED_PAYLOAD);
    let message_len = net::icmp::HEADER_LEN + original_header.len() + quoted_payload;
    let mut message = alloc::vec![0_u8; message_len];
    net::icmp::write_destination_unreachable(
        &mut message,
        net::icmp::PORT_UNREACHABLE,
        original_header,
        payload,
    );

    // The report goes back to the sender, from this machine: the addresses
    // are the original packet's, swapped.
    let frame_len = netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + message_len;
    let mut frame = alloc::vec![0_u8; frame_len];
    net::ethernet::write_header(
        &mut frame,
        sender_hardware,
        our_hardware,
        net::ethernet::ETHERTYPE_IPV4,
    );
    net::ipv4::write_header(
        &mut frame[netdev::ETHERNET_HEADER_LEN..],
        our_protocol,
        packet.header.source,
        net::ipv4::PROTOCOL_ICMP,
        message_len,
    );
    frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..].copy_from_slice(&message);
    frame
}

/// The hardware address a peer's IPv4 address resolves to, if the ARP cache
/// holds one.
fn peer_hardware_v4(address: [u8; 4]) -> Option<[u8; 6]> {
    let mut interface = INTERFACE.lock();
    interface
        .as_mut()
        .and_then(|interface| interface.arp.hardware_for(address))
}
