//! kernel/src/net/dhcp.rs
//!
//! The lease: its probe, its renewals, and the stub resolver that reads the
//! name server a lease named.
//!
//! One section of `kernel/src/net/mod.rs`.  The sections call each other in
//! both directions: the demux reaches every protocol's delivery and a protocol
//! reaches the interface, so each names what it needs through `super::`.  What
//! the split buys is that a reader looking for one protocol opens one file.

#[cfg(target_os = "none")]
use super::core::INTERFACE;
#[cfg(target_os = "none")]
use super::core::MICROS_PER_SECOND;
#[cfg(target_os = "none")]
use super::core::arp_hardware_for;
#[cfg(target_os = "none")]
use super::core::bind_udp;
#[cfg(target_os = "none")]
#[cfg(target_os = "none")]
use super::core::micros_since_boot;
#[cfg(target_os = "none")]
use super::core::pump;
#[cfg(target_os = "none")]
use super::core::send_datagram;

/// Resolve `name` through the name server a lease named.
///
/// One query, one datagram, one wait: the whole of what a stub resolver does
/// when it has a server and no cache.  The lookup binds a port of its own so
/// an answer for one lookup cannot be read by another, draws a transaction id
/// from the generator for the same reason, and refuses any reply whose id or
/// source does not match, because a datagram from a stranger on the port is
/// not this
/// lookup's answer.
///
/// `None` when no server was configured, when the send failed, or when no
/// answer arrived inside the wait.  A name the server says does not exist is
/// also `None`, because both are "this stack cannot give you an address" and
/// the caller's next step is the same.
///
/// [`resolve_why`] is the same exchange with the reason kept, for the boot
/// probe: a resolver that answers `None` for six different reasons and one
/// line for all of them is a probe that cannot say what it saw.
#[cfg(target_os = "none")]
pub fn resolve(name: &str, kind: u16) -> Option<net::address::Address> {
    resolve_why(name, kind).ok()
}

/// Why a lookup answered what it did, so the boot can say which happened.
///
/// The six answers are the six things that can go wrong between this stack
/// and the address, and each is a different diagnosis: no server is a
/// configuration answer, a send failure is the card or the route, no reply at
/// all is the wire or the wait, a reply that did not parse is the parser, and
/// a name the server refused is the answer.
#[cfg(target_os = "none")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Why {
    /// No name server was configured, so nothing was asked.
    NoServer,
    /// The socket for the lookup's own port did not bind.
    NoPort,
    /// The query could not be built or sent.
    NotSent,
    /// Nothing arrived before the wait ran out.
    NoReply,
    /// Datagrams arrived on the port and none of them parsed as this lookup's
    /// answer.
    Unreadable,
    /// The server answered that the name does not exist.
    NoSuchName,
}

#[cfg(target_os = "none")]
pub(crate) fn resolve_why(
    name: &str,
    kind: u16,
) -> core::result::Result<net::address::Address, Why> {
    let server = {
        let interface = INTERFACE.lock();
        interface.as_ref().and_then(|interface| interface.dns())
    };
    let Some(server) = server else {
        return Err(Why::NoServer);
    };

    // A port for this lookup, taken from the ephemeral range the TCP side
    // uses and never reused while the socket is alive.  The socket owns the
    // queue the answer arrives in.
    let port = {
        static NEXT: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(53_000);
        NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
    };
    let Ok(socket) = bind_udp(port) else {
        return Err(Why::NoPort);
    };

    let mut id_bytes = [0_u8; 2];
    if crate::random::fill(&mut id_bytes).is_err() {
        return Err(Why::NotSent);
    }
    let id = u16::from_be_bytes(id_bytes);

    let mut query = [0_u8; 300];
    let Some(length) = net::dns::write_query(&mut query, id, name, kind) else {
        return Err(Why::NotSent);
    };
    if send_datagram(
        net::address::Address::V4(server),
        53,
        port,
        &query[..length],
    )
    .is_err()
    {
        return Err(Why::NotSent);
    }

    // One wait, and the unit is microseconds rather than ticks for the reason
    // the stream's timeouts are: a tick is a duration this file would have to
    // guess, and the guess it carried said a hundred-hertz clock while the
    // machine's slice is a hundred microseconds.  A server on this link
    // answers in microseconds, so twenty milliseconds is generous by orders
    // of magnitude and a boot with no server ends with an answer rather than a
    // hang.
    let deadline = micros_since_boot().saturating_add(LEASE_WAIT_MICROS);
    let mut buffer = [0_u8; 512];
    while micros_since_boot() < deadline {
        // The card's ring first, because the answer is on it before the
        // socket's queue is: a receive that asked its queue alone would see
        // nothing until the next pump.
        pump();
        match socket.try_recv(&mut buffer) {
            Ok(Some((source, _, count))) => {
                if source != net::address::Address::V4(server) {
                    continue;
                }
                match net::dns::parse_answer(&buffer[..count], id, kind) {
                    Ok(net::dns::Answer::Address { address, .. }) => return Ok(address),
                    Ok(net::dns::Answer::NoSuchName) => return Err(Why::NoSuchName),
                    Err(_) => return Err(Why::Unreadable),
                }
            }
            _ => continue,
        }
    }
    Err(Why::NoReply)
}

/// Ask the network what this machine is, and configure the interface with the
/// answer.
///
/// The four-message exchange of [RFC 2131], run before the interface has an
/// address: a broadcast DISCOVER, a server's OFFER, a broadcast REQUEST naming
/// that offer, and the ACK that makes the address usable.  The frames are
/// broadcast at the link layer because there is no address to resolve yet, and
/// their source address is zero because that is what a client without a lease
/// puts there.
///
/// Answers the lease, or `None` when no server answered.  A boot that gets
/// `None` keeps whatever the caller installed, which is why this is a probe
/// the boot reports rather than a step it depends on: QEMU's user-mode network
/// answers, and a machine with no server is a machine this must not die on.
///
/// [RFC 2131]: https://www.rfc-editor.org/rfc/rfc2131
#[cfg(target_os = "none")]
pub fn dhcp_probe() -> Option<net::dhcp::Lease> {
    let (card, hardware) = {
        let interface = INTERFACE.lock();
        let interface = interface.as_ref()?;
        (interface.card.clone(), interface.hardware)
    };

    let mut bytes = [0_u8; 2];
    if crate::random::fill(&mut bytes).is_err() {
        return None;
    }
    let transaction = net::dhcp::Transaction {
        id: u32::from_be_bytes([bytes[0], bytes[1], bytes[0], bytes[1]]),
        hardware,
    };

    // One UDP datagram, broadcast to the server port, from the client port.
    // The frame's addresses are the broadcast ones: a client with no address
    // has nothing else to put there, and the server answers to the client's
    // hardware address for the same reason.
    let send = |payload: &[u8]| -> bool {
        let udp_len = net::udp::datagram_len(payload.len());
        let packet_len = netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + udp_len;
        let mut frame = alloc::vec![0_u8; packet_len];
        net::ethernet::write_header(
            &mut frame,
            net::ethernet::BROADCAST,
            hardware,
            net::ethernet::ETHERTYPE_IPV4,
        );
        net::ipv4::write_header(
            &mut frame[netdev::ETHERNET_HEADER_LEN..],
            [0, 0, 0, 0],
            [255, 255, 255, 255],
            net::ipv4::PROTOCOL_UDP,
            udp_len,
        );
        net::udp::write_datagram(
            &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..],
            [0, 0, 0, 0],
            [255, 255, 255, 255],
            net::dhcp::CLIENT_PORT,
            net::dhcp::SERVER_PORT,
            payload,
        );
        card.submit_frame(&frame).is_ok()
    };

    // Wait for a reply of `kind`, draining the card's ring.
    let await_reply = |kind: u8| -> Option<net::dhcp::Reply> {
        let limit = card.maximum_frame_len();
        let mut frame = alloc::vec![0_u8; limit];
        let deadline = micros_since_boot().saturating_add(WAIT_MICROS);
        while micros_since_boot() < deadline {
            let Ok(Some(length)) = card.receive_frame(&mut frame) else {
                continue;
            };
            if netdev::ethertype(&frame[..length]) != Some(net::ethernet::ETHERTYPE_IPV4) {
                continue;
            }
            let Some(packet) = net::ipv4::parse(&frame[netdev::ETHERNET_HEADER_LEN..length]) else {
                continue;
            };
            if packet.header.protocol != net::ipv4::PROTOCOL_UDP {
                continue;
            }
            let at = netdev::ETHERNET_HEADER_LEN + packet.payload_at;
            let Some(datagram) = net::udp::parse(
                &frame[at..length],
                packet.header.source,
                packet.header.destination,
            ) else {
                continue;
            };
            if datagram.destination_port != net::dhcp::CLIENT_PORT {
                continue;
            }
            let data =
                &frame[at + net::udp::HEADER_LEN..at + net::udp::HEADER_LEN + datagram.payload_len];
            if let Some(reply) = net::dhcp::parse_reply(data, transaction)
                && reply.kind == kind
            {
                return Some(reply);
            }
        }
        None
    };

    let mut message = [0_u8; 512];
    let region = net::dhcp::write_discover(&mut message, transaction)?;
    if !send(region.as_slice()) {
        return None;
    }
    let offer = await_reply(net::dhcp::MESSAGE_OFFER)?;

    let region = net::dhcp::write_request(&mut message, transaction, offer.address, offer.server)?;
    if !send(region.as_slice()) {
        return None;
    }
    let ack = await_reply(net::dhcp::MESSAGE_ACK)?;
    // The clock is the caller's, and this caller's is microseconds: the
    // scale is how many of them a second is, which is what makes a lease the
    // server granted for an hour last an hour instead of eighty-six
    // milliseconds.
    net::dhcp::lease_from(&ack, micros_since_boot(), MICROS_PER_SECOND).ok()
}

/// Ask the server that granted this address to grant it again.
///
/// [RFC 2131]'s renewal is a unicast `REQUEST` to the granting server, not a
/// broadcast `DISCOVER`: the machine still holds the address, so it can name
/// itself, and a broadcast would offer the renewal to every server on the
/// link.  The reply is the same `ACK` a grant is, and applying it is the same
/// act, which is why this answers a lease rather than changing the interface
/// itself.
///
/// `None` is "the server did not answer", and it is not a failure the caller
/// should undo anything for: the lease it holds is still valid until the
/// clock says otherwise, and `Lease::duty` is what says when the next attempt
/// is due.  A renewal that tore down the address it was renewing would turn a
/// late reply into an outage.
///
/// [RFC 2131]: https://www.rfc-editor.org/rfc/rfc2131
#[cfg(target_os = "none")]
fn renew_lease(lease: &net::dhcp::Lease) -> Option<net::dhcp::Lease> {
    let (card, hardware, address, router) = {
        let interface = INTERFACE.lock();
        let interface = interface.as_ref()?;
        (
            interface.card.clone(),
            interface.hardware,
            interface.protocol,
            interface.gateway,
        )
    };
    // The renewal asks the server that granted the lease.  A lease that named
    // none cannot be renewed by unicast, and the caller's next step is
    // rebinding, which the clocks decide.
    let server = lease.server?;

    let mut bytes = [0_u8; 2];
    if crate::random::fill(&mut bytes).is_err() {
        return None;
    }
    let transaction = net::dhcp::Transaction {
        id: u32::from_be_bytes([bytes[0], bytes[1], bytes[0], bytes[1]]),
        hardware,
    };

    // The gateway's hardware address, because a unicast frame to a server off
    // this link goes through it; a server on this link is in the ARP cache
    // under its own address, and the fallback is the router for the reason
    // every other send in this file uses it.
    let destination_hardware = arp_hardware_for(server).or_else(|| arp_hardware_for(router))?;

    let mut message = [0_u8; 512];
    let region = net::dhcp::write_request(&mut message, transaction, address, Some(server))?;
    let payload = region.as_slice();
    let udp_len = net::udp::datagram_len(payload.len());
    let packet_len = netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + udp_len;
    let mut frame = alloc::vec![0_u8; packet_len];
    net::ethernet::write_header(
        &mut frame,
        destination_hardware,
        hardware,
        net::ethernet::ETHERTYPE_IPV4,
    );
    net::ipv4::write_header(
        &mut frame[netdev::ETHERNET_HEADER_LEN..],
        address,
        server,
        net::ipv4::PROTOCOL_UDP,
        udp_len,
    );
    net::udp::write_datagram(
        &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..],
        address,
        server,
        net::dhcp::CLIENT_PORT,
        net::dhcp::SERVER_PORT,
        payload,
    );
    if card.submit_frame(&frame).is_err() {
        return None;
    }

    // The answer, on the same bounded wait a grant uses: a server that does
    // not answer leaves the lease as it was, and the clock moves the caller to
    // rebinding.
    let limit = card.maximum_frame_len();
    let mut reply_frame = alloc::vec![0_u8; limit];
    let deadline = micros_since_boot().saturating_add(WAIT_MICROS);
    while micros_since_boot() < deadline {
        let Ok(Some(length)) = card.receive_frame(&mut reply_frame) else {
            continue;
        };
        if netdev::ethertype(&reply_frame[..length]) != Some(net::ethernet::ETHERTYPE_IPV4) {
            continue;
        }
        let Some(packet) = net::ipv4::parse(&reply_frame[netdev::ETHERNET_HEADER_LEN..length])
        else {
            continue;
        };
        if packet.header.protocol != net::ipv4::PROTOCOL_UDP {
            continue;
        }
        let at = packet.payload_at;
        let Some(datagram) = net::udp::parse(
            &reply_frame[netdev::ETHERNET_HEADER_LEN + at..length],
            packet.header.source,
            packet.header.destination,
        ) else {
            continue;
        };
        if datagram.destination_port != net::dhcp::CLIENT_PORT {
            continue;
        }
        let data = &reply_frame[netdev::ETHERNET_HEADER_LEN + at + net::udp::HEADER_LEN..]
            [..datagram.payload_len];
        if let Some(reply) = net::dhcp::parse_reply(data, transaction)
            && reply.kind == net::dhcp::MESSAGE_ACK
        {
            return net::dhcp::lease_from(&reply, micros_since_boot(), MICROS_PER_SECOND).ok();
        }
    }
    None
}

/// Ask any server on the link to take over this address.
///
/// [RFC 2131]'s rebinding is the third of the three states a lease moves
/// through: the machine still holds its address, the server that granted it has
/// stopped answering, and the question goes out as a **broadcast** `REQUEST`
/// with no server named, which is the shape any server may answer.  The
/// difference from a renewal is exactly that: a unicast frame to one server
/// becomes a broadcast to all of them, and the option that names a server is
/// absent.
///
/// The source address is this machine's, because it still holds one: a client
/// with no address sends from zero, which is the state before the first grant
/// and not this one.
///
/// [RFC 2131]: https://www.rfc-editor.org/rfc/rfc2131
#[cfg(target_os = "none")]
pub(crate) fn rebind_lease(lease: &net::dhcp::Lease) -> Option<net::dhcp::Lease> {
    let (card, hardware, address) = {
        let interface = INTERFACE.lock();
        let interface = interface.as_ref()?;
        (
            interface.card.clone(),
            interface.hardware,
            interface.protocol,
        )
    };

    let mut bytes = [0_u8; 2];
    if crate::random::fill(&mut bytes).is_err() {
        return None;
    }
    let transaction = net::dhcp::Transaction {
        id: u32::from_be_bytes([bytes[0], bytes[1], bytes[0], bytes[1]]),
        hardware,
    };

    let mut message = [0_u8; 512];
    // No server named: that absence is what makes this a rebinding rather than
    // a renewal, and any server that holds a record of this machine may answer.
    let region = net::dhcp::write_request(&mut message, transaction, lease.address, None)?;
    let payload = region.as_slice();
    let udp_len = net::udp::datagram_len(payload.len());
    let packet_len = netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + udp_len;
    let mut frame = alloc::vec![0_u8; packet_len];
    net::ethernet::write_header(
        &mut frame,
        net::ethernet::BROADCAST,
        hardware,
        net::ethernet::ETHERTYPE_IPV4,
    );
    net::ipv4::write_header(
        &mut frame[netdev::ETHERNET_HEADER_LEN..],
        address,
        [255, 255, 255, 255],
        net::ipv4::PROTOCOL_UDP,
        udp_len,
    );
    net::udp::write_datagram(
        &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..],
        address,
        [255, 255, 255, 255],
        net::dhcp::CLIENT_PORT,
        net::dhcp::SERVER_PORT,
        payload,
    );
    if card.submit_frame(&frame).is_err() {
        return None;
    }

    // The answer, on the same bounded wait a grant uses.
    let limit = card.maximum_frame_len();
    let mut reply_frame = alloc::vec![0_u8; limit];
    let deadline = micros_since_boot().saturating_add(WAIT_MICROS);
    while micros_since_boot() < deadline {
        let Ok(Some(length)) = card.receive_frame(&mut reply_frame) else {
            continue;
        };
        if netdev::ethertype(&reply_frame[..length]) != Some(net::ethernet::ETHERTYPE_IPV4) {
            continue;
        }
        let Some(packet) = net::ipv4::parse(&reply_frame[netdev::ETHERNET_HEADER_LEN..length])
        else {
            continue;
        };
        if packet.header.protocol != net::ipv4::PROTOCOL_UDP {
            continue;
        }
        let at = packet.payload_at;
        let Some(datagram) = net::udp::parse(
            &reply_frame[netdev::ETHERNET_HEADER_LEN + at..length],
            packet.header.source,
            packet.header.destination,
        ) else {
            continue;
        };
        if datagram.destination_port != net::dhcp::CLIENT_PORT {
            continue;
        }
        let data = &reply_frame[netdev::ETHERNET_HEADER_LEN + at + net::udp::HEADER_LEN..]
            [..datagram.payload_len];
        if let Some(reply) = net::dhcp::parse_reply(data, transaction)
            && reply.kind == net::dhcp::MESSAGE_ACK
        {
            return net::dhcp::lease_from(&reply, micros_since_boot(), MICROS_PER_SECOND).ok();
        }
    }
    None
}

/// Apply a lease a server granted and say so on the console.
///
/// One function for the two exchanges because applying a lease is the same act
/// whether it arrived as a unicast acknowledgement or a broadcast one: the
/// address, the router and the name server are one decision, and a caller that
/// took two of the three would be a machine sending half its traffic to a
/// router it is not attached to.
#[cfg(target_os = "none")]
pub(crate) fn apply_lease(lease: &net::dhcp::Lease, how: &str) {
    if let Some(interface) = INTERFACE.lock().as_mut() {
        interface.configure(lease);
    }
    arch::serial::write_str("protofire: dhcp ");
    arch::serial::write_str(how);
    arch::serial::write_str(" ");
    for (index, byte) in lease.address.iter().enumerate() {
        if index > 0 {
            arch::serial::write_str(".");
        }
        arch::serial::write_u32(*byte as u32);
    }
    arch::serial::write_str(" for ");
    arch::serial::write_u32((lease.lifetime / MICROS_PER_SECOND) as u32);
    arch::serial::write_str(" second(s) more\n");
}

/// Renew the interface's lease when its clock says to.
///
/// Called from the pump, which is the one path that already runs while a
/// program waits: a machine whose only activity is a parked reader still has a
/// lease running out, and a lease renewed only when a call happened to arrive
/// would expire between calls.
///
/// The three duties are `Lease::duty`'s, which is [RFC 2131]'s clocks:
/// `Renew` asks the granting server, `Rebind` is a broadcast that any server
/// may answer and is not written here, and `Expired` clears the address
/// because it is no longer this machine's.  A renewal that fails leaves the
/// lease in place: the clock is what says the address is gone, not one
/// unanswered datagram.
///
/// [RFC 2131]: https://www.rfc-editor.org/rfc/rfc2131
#[cfg(target_os = "none")]
pub(crate) fn renew_lease_if_due() {
    let (lease, due) = {
        let interface = INTERFACE.lock();
        let Some(interface) = interface.as_ref() else {
            return;
        };
        let Some(lease) = interface.lease.as_ref() else {
            return;
        };
        (*lease, lease.duty(micros_since_boot()))
    };

    match due {
        net::dhcp::Duty::Bound => {}
        // The two are different exchanges, which is why `duty` names them
        // separately: a renewal asks the one server that granted the lease and
        // a rebinding asks every server on the link, because the one that
        // granted it has stopped answering.
        net::dhcp::Duty::Renew => {
            if let Some(renewed) = renew_lease(&lease) {
                apply_lease(&renewed, "renewed");
            }
        }
        net::dhcp::Duty::Rebind => {
            if let Some(renewed) = rebind_lease(&lease) {
                apply_lease(&renewed, "rebound");
            }
        }
        net::dhcp::Duty::Expired => {
            // The address is no longer this machine's.  Keeping it would put
            // two machines on one address, so the interface gives it up and
            // the machine becomes one with a card and no address, which is
            // what the first boot's state was.
            if let Some(interface) = INTERFACE.lock().as_mut() {
                interface.lease = None;
            }
            arch::serial::write_str("protofire: dhcp lease expired, the address is released\n");
        }
    }
}

/// How long one DHCP reply is waited for.
///
/// A duration, and microseconds rather than ticks because a tick is a duration
/// this file would have to guess.  It guessed, and the guess was wrong by a
/// factor of a hundred: the constant said "two seconds on a hundred-hertz
/// clock" while the machine's slice is `TIME_SLICE_US`, a hundred
/// microseconds, so two hundred ticks was twenty milliseconds.  The DHCP
/// server on a boot's own link still answered inside that, which is why only
/// the resolver below it ever failed, and only sometimes.
///
/// Twenty milliseconds is what this wait has always been, once the unit is
/// the right one: two hundred ticks of a hundred-microsecond slice.  It is
/// kept rather than chosen again because a window widened without a
/// measurement is a window that hides the failure it was widened for.
#[cfg(target_os = "none")]
const WAIT_MICROS: u64 = 20_000;

/// How long the resolver waits for the name server's answer.
///
/// The DHCP wait's twenty milliseconds, and the reasoning is the same: the
/// exchange is one query and one datagram, and a server on the same link
/// answers in microseconds.  The measured answer on this machine is three
/// hundred microseconds, so the window is what the old constant meant and not
/// a change to it.
#[cfg(target_os = "none")]
const LEASE_WAIT_MICROS: u64 = 20_000;
