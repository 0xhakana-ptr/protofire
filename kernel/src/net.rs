//! kernel/src/net.rs
//!
//! The kernel's network half: the interface the boot brought up, the answers
//! the network calls give, and the sockets a program holds.
//!
//! ## Where `net` ends and this file begins
//!
//! The `net` crate computes what a frame means: it parses a header, builds a
//! request, checks a sum, and every one of its functions is a pure call over a
//! byte slice.  The one piece of state it does hold —
//! [`net::tcp_table::Table`], the streams a machine owns — it holds as a
//! **value** its caller owns, with no lock and no `static`, which is what lets
//! that arithmetic be a host test as well.
//!
//! This file holds everything `net` deliberately does not: **which** address
//! this machine answers for, **which** neighbours the wire has answered about,
//! **which** ports a program has bound, **who** holds the table's lock, and
//! **when** a waiting task wakes.  Those are facts about a boot rather than
//! about a protocol, and each one is a `static` behind a `Mutex` for that
//! reason.
//!
//! The line is what makes a second card a second `Interface` rather than a
//! second stack: `net` never learns which card carried a frame, and this file
//! never reads a field of one.  It is also what keeps this module's size from
//! following the protocol count: a protocol added to `net` adds nothing here,
//! and the one thing that had grown here — the connection table — moved out.
//!
//! ## Why this is a module and not a field of the boot
//!
//! The probes in `devices.rs` prove the wire; this module holds what the
//! probes found, so a call made after the boot has finished answers from
//! state rather than from constants a caller would have to guess.  The
//! interface is installed once, when the card comes up, and every network
//! call reads through it — which is what makes `NetworkStatus` a fact about
//! this boot's machine rather than about the QEMU defaults a reader could
//! have looked up.
//!
//! ## The sockets, and the one table that knows their ports
//!
//! A datagram socket is a bound port and a queue of what arrived for it.  It
//! lives behind an `Arc` a descriptor holds, and the port table beside this
//! file's interface holds a `Weak` — so a socket's port is routable for
//! exactly as long as some descriptor holds the socket, and a process that
//! exits releases its descriptors the way it releases its files and pipes,
//! with the port going with the last of them.  The demux prunes the dead
//! entries on the way past rather than keeping a second count.
//!
//! ## Loopback, and why a datagram to this machine never touches the card
//!
//! A datagram addressed to this interface's own address is delivered through
//! the demux directly: the port table answers, the queue takes it, the
//! waiter wakes.  Sending it to the card would ask the wire to hand this
//! machine its own frame back, which no card promises to do, and the
//! exchanges a program makes with itself are the ones this build can prove
//! on every machine it boots.  A datagram for anyone else goes out through
//! the gateway, whose hardware address the ARP cache holds.

use alloc::sync::Arc;
use alloc::sync::Weak;
use alloc::vec::Vec;

use netdev::LinkDevice;
use sync::Mutex;

use abi::Error;
use abi::Result;
use abi::network::NETWORK_STATUS_UP;
use abi::network::NetworkStatusRecord;

/// The most bytes one datagram carries.
///
/// One IPv4 packet's payload on this interface: a frame is fifteen hundred
/// bytes, and the IP and UDP headers take twenty-eight of them.  A send
/// larger than this is refused before the frame is built, because a frame
/// the card cannot carry is a send that failed twice — once in the build
/// and once on the wire.
pub const MAX_DATAGRAM_BYTES: usize = 1472;

/// How many datagrams one socket's queue holds.
///
/// A queue a sender could grow is a queue a sender could fill, and the
/// answer to a full queue is the same one the wire gives a full card:
/// `Busy`, which a sender can act on.
const QUEUE_LIMIT: usize = 16;

/// An interface: the card the boot drives, the addresses it answers for,
/// the ARP cache its wire exchanges filled, and the IPv6 state beside them.
pub struct Interface {
    card: Arc<dyn LinkDevice>,
    hardware: [u8; 6],
    protocol: [u8; 4],
    gateway: [u8; 4],
    arp: net::arp::Cache,
    /// The link-local IPv6 address this interface derives from its own MAC.
    ///
    /// Every IPv6 interface has one before it has said anything to anyone:
    /// it is the address a neighbour solicitation is sent *from* while the
    /// interface waits for a router, and the address an agent puts in a
    /// reply.  It is derived rather than configured, which is why it can be
    /// set at install and never moved.
    ipv6: net::ipv6::Addr,
    /// The multicast groups this interface joined: the all-nodes group, the
    /// all-routers group a solicitation is sent to, and the solicited-node
    /// group of each address it holds.
    ///
    /// A fixed array and not a `Vec`: `install` runs before the heap is
    /// certain, and an allocation there took the whole network bring-up with
    /// it when this was first written — the ARP exchange's lines disappeared
    /// and the boot still exited zero.  Three is all a link-local-only
    /// interface has; a global address adds its own group at the point a
    /// router configures it.
    ipv6_groups: [net::ipv6::Addr; 3],
    /// What the wire has answered about its IPv6 neighbours.
    ndp: net::ndp::Cache,
    /// A global address a router's advertisement configured, if one has.
    ipv6_global: Option<net::ipv6::Addr>,
}

impl Interface {
    /// The interface a boot installed, from the facts its card and its wire
    /// gave it.
    pub fn new(
        card: Arc<dyn LinkDevice>,
        hardware: [u8; 6],
        protocol: [u8; 4],
        gateway: [u8; 4],
    ) -> Self {
        // The IPv6 side needs nothing the boot did not already have: the
        // link-local address is the MAC's by EUI-64, and the two groups are
        // that address's solicited-node group and the all-nodes group every
        // interface is in.
        let ipv6 = net::ipv6::link_local_from_mac(hardware);
        let ipv6_groups = [
            net::ipv6::ALL_NODES_MULTICAST,
            net::ipv6::ALL_ROUTERS_MULTICAST,
            net::ipv6::solicited_node(ipv6),
        ];
        Self {
            card,
            hardware,
            protocol,
            gateway,
            arp: net::arp::Cache::new(),
            ipv6,
            ipv6_groups,
            ndp: net::ndp::Cache::new(),
            ipv6_global: None,
        }
    }

    /// The protocol address this interface answers for.
    pub fn protocol(&self) -> [u8; 4] {
        self.protocol
    }

    /// The link-local IPv6 address this interface answers for.
    pub fn ipv6(&self) -> net::ipv6::Addr {
        self.ipv6
    }

    /// The global IPv6 address a router configured, if one has.
    pub fn ipv6_global(&self) -> Option<net::ipv6::Addr> {
        self.ipv6_global
    }
}

/// The interface this boot drives, installed once by the network exercise
/// and read by every network call after.
///
/// A `Mutex<Option<_>>` for the reason the registry is: the boot writes it
/// before any program exists, and every reader after is a call that arrived
/// without a context to be handed one.
static INTERFACE: Mutex<Option<Interface>> = Mutex::new(None);

/// Install the interface the boot brought up.
///
/// Called once.  A second call replaces it, which is a second boot's
/// exercise in one address space, and this kernel has one boot.
pub fn install(interface: Interface) {
    *INTERFACE.lock() = Some(interface);
}

/// What the network answers about itself: the record `NetworkStatus` fills,
/// or `None` when this boot has no interface.
pub fn status() -> Option<NetworkStatusRecord> {
    let interface = INTERFACE.lock();
    interface.as_ref().map(|interface| {
        NetworkStatusRecord::new(
            NETWORK_STATUS_UP,
            interface.hardware,
            interface.protocol,
            interface.gateway,
        )
    })
}

/// What the interface's IPv6 side answers: the record `Ipv6Status` fills, or
/// `None` when this boot has no interface.
pub fn ipv6_status() -> Option<abi::network::Ipv6StatusRecord> {
    let interface = INTERFACE.lock();
    interface.as_ref().map(|interface| {
        abi::network::Ipv6StatusRecord::new(
            interface.ipv6,
            interface.ipv6_global,
            interface.ndp.len(),
        )
    })
}

/// The hardware address the ARP cache holds for `protocol`, if the wire
/// answered for it.
pub fn arp_hardware_for(protocol: [u8; 4]) -> Option<[u8; 6]> {
    let mut interface = INTERFACE.lock();
    interface
        .as_mut()
        .and_then(|interface| interface.arp.hardware_for(protocol))
}

/// Record an answer the wire gave, so the wire is not asked again.
pub fn arp_learn(protocol: [u8; 4], hardware: [u8; 6]) {
    let mut interface = INTERFACE.lock();
    if let Some(interface) = interface.as_mut() {
        interface.arp.learn(protocol, hardware);
    }
}

/// A datagram that arrived for a socket, held until the socket's caller
/// takes it.
struct Received {
    source: [u8; 4],
    source_port: u16,
    bytes: Vec<u8>,
}

/// One datagram socket: a bound port and the queue of what arrived for it.
///
/// The `Arc` is the socket's life: the descriptor table holds one, the port
/// table holds a `Weak`, and the socket lives while either is alive — which
/// is what makes a fork's copy of a descriptor keep the bound port
/// routable, and the last close take it off the wire.
pub struct UdpSocket {
    port: u16,
    queue: Mutex<Vec<Received>>,
}

impl UdpSocket {
    /// The port the socket is bound to.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Take the next datagram the queue holds, answering where it came from
    /// and how many bytes of it fit in `into`.
    ///
    /// `None` is "nothing arrived, ask again" — the answer a caller parks on.
    /// A datagram longer than `into` is refused with the datagram **kept**:
    /// a caller whose buffer is small learns that from the error and asks
    /// again with a larger one, and a take that discarded the bytes would
    /// make the loss permanent.
    pub fn try_recv(&self, into: &mut [u8]) -> Result<Option<([u8; 4], u16, usize)>> {
        let mut queue = self.queue.lock();
        let Some(received) = queue.first() else {
            return Ok(None);
        };
        if received.bytes.len() > into.len() {
            return Err(Error::InvalidArgument);
        }
        let received = queue.remove(0);
        into[..received.bytes.len()].copy_from_slice(&received.bytes);
        Ok(Some((
            received.source,
            received.source_port,
            received.bytes.len(),
        )))
    }

    /// Put one datagram in the queue, or refuse when it is full.
    fn push(&self, source: [u8; 4], source_port: u16, bytes: &[u8]) -> Result<()> {
        let mut queue = self.queue.lock();
        if queue.len() >= QUEUE_LIMIT {
            return Err(Error::Busy);
        }
        queue.push(Received {
            source,
            source_port,
            bytes: Vec::from(bytes),
        });
        Ok(())
    }
}

/// The bound ports, as the demux routes to them.
///
/// A `Weak` per entry, for the reason the module header gives: the socket's
/// life is its descriptors', and a port whose last descriptor went is a port
/// nothing can answer for.
static UDP_SOCKETS: Mutex<Vec<(u16, Weak<UdpSocket>)>> = Mutex::new(Vec::new());

/// Drop every entry whose socket no longer has a descriptor.
///
/// Called wherever the table is walked, so a closed socket's port is free
/// again by the time the next bind looks — and never as its own pass,
/// because a sweep nothing else needed would be a sweep nothing would run.
fn prune_sockets(sockets: &mut Vec<(u16, Weak<UdpSocket>)>) {
    sockets.retain(|(_, socket)| socket.upgrade().is_some());
}

/// Bind a datagram socket to `port`, answering the socket.
///
/// `AlreadyExists` when the port is taken: two sockets on one port would
/// make one datagram two callers' answer, and the wire's rule is that a
/// bound port has one owner.  Port zero is refused at the handler, before
/// this is reached, because it is the wire's "any port" and this stack has
/// no port allocator to answer it with.
pub fn bind_udp(port: u16) -> Result<Arc<UdpSocket>> {
    let mut sockets = UDP_SOCKETS.lock();
    prune_sockets(&mut sockets);
    if sockets.iter().any(|(bound, _)| *bound == port) {
        return Err(Error::AlreadyExists);
    }
    let socket = Arc::new(UdpSocket {
        port,
        queue: Mutex::new(Vec::new()),
    });
    sockets.push((port, Arc::downgrade(&socket)));
    Ok(socket)
}

/// Whether `destination` names this machine, and the datagram is delivered
/// through the demux rather than the card.
///
/// The interface's own address, and the loopback network every IP stack
/// shares: a datagram to either is this machine's conversation with itself.
fn is_loopback(destination: [u8; 4]) -> bool {
    let interface = INTERFACE.lock();
    let Some(interface) = interface.as_ref() else {
        return false;
    };
    destination == interface.protocol || destination[0] == 127
}

/// Deliver one datagram to the socket bound for it, and wake what waits.
///
/// The source is the wire's answer to "who sent this", and the return is
/// how many tasks the delivery woke — zero when nobody was parked on the
/// socket, which is a fact and not a failure.  A datagram for a port
/// nothing owns is dropped, because UDP promised nothing: the sender's
/// answer for a silent port is the wire's port-unreachable, not an error
/// from this call.
pub fn deliver_udp(
    destination: [u8; 4],
    destination_port: u16,
    source: [u8; 4],
    source_port: u16,
    bytes: &[u8],
) -> Result<usize> {
    let socket = {
        let mut sockets = UDP_SOCKETS.lock();
        prune_sockets(&mut sockets);
        sockets
            .iter()
            .find(|(bound, _)| *bound == destination_port)
            .and_then(|(_, socket)| socket.upgrade())
    };
    let Some(socket) = socket else {
        let _ = destination;
        return Ok(0);
    };
    socket.push(source, source_port, bytes)?;

    // A datagram in a queue is what a parked receive was waiting for, so
    // this is where the wake belongs — the same one a pipe's write makes,
    // with the same discipline on the waiter's side.
    let woken = crate::scheduler::wake_blocked();
    #[cfg(target_os = "none")]
    {
        arch::serial::write_str("protofire: a datagram for port ");
        arch::serial::write_u32(destination_port as u32);
        arch::serial::write_str(" woke ");
        arch::serial::write_u32(woken as u32);
        arch::serial::write_str(" blocked task(s)\n");
        if woken > 0 {
            // The woken task may be held by another CPU parked in a wait
            // whose own clock may never move, and only the IPI ends that
            // wait.  SAFETY: the boot's own IPI path, installed before any
            // program ran.
            unsafe { arch::send_ipi_to_others() };
        }
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = destination_port;
    }
    Ok(woken)
}

/// Send one datagram out through the interface, to `destination`'s port.
///
/// A datagram addressed to this machine is delivered through the demux
/// instead, which is what loopback is: the sender's call and the receiver's
/// answer meet at the port table, not on the wire.  For anyone else, the
/// gateway's hardware address comes from the ARP cache, which is this
/// build's whole routing decision — one interface, one gateway, and every
/// datagram for another machine leaves by it.  A cache with no answer is
/// `NotFound`, because a frame with no destination address is a frame the
/// card cannot carry.
pub fn send_datagram(
    destination: [u8; 4],
    destination_port: u16,
    source_port: u16,
    bytes: &[u8],
) -> Result<()> {
    if is_loopback(destination) {
        let protocol = {
            let interface = INTERFACE.lock();
            let Some(interface) = interface.as_ref() else {
                return Err(Error::NotFound);
            };
            interface.protocol
        };
        // The sender the datagram names is this machine: the wire would have
        // seen the frame leave with this address, and the receiver's answer
        // says the same thing.
        return deliver_udp(destination, destination_port, protocol, source_port, bytes)
            .map(|_| ());
    }

    let interface = INTERFACE.lock();
    let Some(interface) = interface.as_ref() else {
        return Err(Error::NotFound);
    };
    let Some(gateway_hardware) = interface.arp.hardware_for(interface.gateway) else {
        return Err(Error::NotFound);
    };
    let (hardware, protocol) = (interface.hardware, interface.protocol);
    let card = interface.card.clone();

    let udp_len = net::udp::datagram_len(bytes.len());
    let packet_len = netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + udp_len;
    let mut frame = alloc::vec![0; packet_len];
    net::ethernet::write_header(
        &mut frame,
        gateway_hardware,
        hardware,
        net::ethernet::ETHERTYPE_IPV4,
    );
    net::ipv4::write_header(
        &mut frame[netdev::ETHERNET_HEADER_LEN..],
        protocol,
        destination,
        net::ipv4::PROTOCOL_UDP,
        udp_len,
    );
    net::udp::write_datagram(
        &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..],
        protocol,
        destination,
        source_port,
        destination_port,
        bytes,
    );
    card.submit_frame(&frame)
}

/// Drain the card's receive ring into the demux, answering how many frames
/// the card had.
///
/// Called by the receive path before it asks its own question, so a frame
/// the card is holding is a datagram in a queue rather than a wait that
/// answers nothing.  A frame that is not a datagram for this machine's
/// sockets is demuxed as far as it goes and dropped: an ARP reply is the
/// cache's, an ICMP message is nothing's yet, and a datagram for an unbound
/// port is nobody's.
pub fn pump() -> usize {
    let (card, protocol) = {
        let interface = INTERFACE.lock();
        let Some(interface) = interface.as_ref() else {
            return 0;
        };
        (interface.card.clone(), interface.protocol)
    };

    let length_limit = card.maximum_frame_len();
    let mut frame = alloc::vec![0; length_limit];
    let mut taken = 0;
    loop {
        let length = match card.receive_frame(&mut frame) {
            Ok(Some(length)) => length,
            Ok(None) => return taken,
            Err(_) => return taken,
        };
        taken += 1;
        demux(&frame[..length], protocol);
    }
}

/// What one received frame means, and where it goes.
fn demux(frame: &[u8], protocol: [u8; 4]) {
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
    if !net::ipv4::is_for(&packet, protocol) {
        return;
    }
    let at = netdev::ETHERNET_HEADER_LEN + packet.payload_at;
    let payload = &frame[at..at + packet.payload_len];
    if packet.header.protocol == net::ipv4::PROTOCOL_UDP
        && let Some(datagram) =
            net::udp::parse(payload, packet.header.source, packet.header.destination)
    {
        let data_at = net::udp::HEADER_LEN;
        let _ = deliver_udp(
            packet.header.destination,
            datagram.destination_port,
            packet.header.source,
            datagram.source_port,
            &payload[data_at..data_at + datagram.payload_len],
        );
    }
    if packet.header.protocol == net::ipv4::PROTOCOL_TCP && demux_tcp(packet, payload) {
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
}

/// What one received IPv6 packet means, and where it goes.
///
/// The chain is walked before anything else: a packet with an extension
/// header that this stack read as a transport header would deliver a
/// solicitation's bytes to a socket's port.  A fragment is dropped rather
/// than reassembled — this stack has no reassembly buffer, and the
/// alternative is to read the first piece as the whole packet, which is a
/// wrong answer that looks like a right one.
///
/// The three things a host does with what it reads here: learn a neighbour's
/// MAC from an advertisement, answer a solicitation for an address it holds,
/// and answer a neighbor's echo.
fn demux_ipv6(frame: &[u8]) {
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
    let (next_header, at, len) = match next {
        net::ipv6::Next::Payload {
            next_header,
            at,
            len,
        } => (next_header, at, len),
        // A fragment: this stack does not reassemble, and reading a piece as
        // the whole is the wrong answer this refusal avoids.
        net::ipv6::Next::Fragment { .. } => return,
    };

    let payload = &frame[at..at + len];
    if next_header == net::ipv6::NEXT_ICMPV6 {
        handle_icmpv6(&packet, payload);
    }
}

/// What an ICMPv6 message means to this host.
///
/// Three answers and nothing else: an advertisement fills the neighbour
/// cache, a solicitation for one of this host's addresses is answered, and
/// an echo request is replied to.  A message that is none of those is read
/// for nothing — this stack has no error path above it yet, and pretending
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
        _ => {}
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

    let reply_len = net::icmpv6::echo_len(echo.data_len);
    let mut frame = alloc::vec![0_u8; card.maximum_frame_len()];
    net::ethernet::write_header(
        &mut frame,
        peer_hardware(destination),
        mac,
        net::ethernet::ETHERTYPE_IPV6,
    );
    net::ipv6::write_header(
        &mut frame[netdev::ETHERNET_HEADER_LEN..],
        local,
        destination,
        net::ipv6::NEXT_ICMPV6,
        reply_len,
    );
    net::icmpv6::write_echo(
        &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv6::HEADER_LEN..],
        local,
        destination,
        net::icmpv6::ECHO_REPLY,
        echo.identifier,
        echo.sequence,
        &payload[echo.data_at..echo.data_at + echo.data_len.min(8)],
    );
    let total = netdev::ETHERNET_HEADER_LEN + net::ipv6::HEADER_LEN + reply_len;
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
/// group's mapping when it did not — a reply to a node this stack has not
/// resolved goes to a group that node joined, which is what makes an
/// advertisement's answer reach a host whose cache is empty.
fn peer_hardware(destination: net::ipv6::Addr) -> [u8; 6] {
    let interface = INTERFACE.lock();
    interface
        .as_ref()
        .and_then(|interface| interface.ndp.lookup(destination))
        .or_else(|| {
            net::ipv6::is_multicast(destination).then(|| net::ipv6::multicast_mac(destination))
        })
        .unwrap_or_else(|| net::ipv6::multicast_mac(net::ipv6::solicited_node(destination)))
}

/// Answer a solicitation for an address this host holds.
///
/// The answer is the advertisement the asker wanted, sent to the asker's own
/// address rather than to a group — which is what the solicited flag means —
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
    // nowhere — a check that hears an advertisement answers it later, at its
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
    // The advertisement's fixed part plus its target link-layer option: the
    // two-hop length of the body the message writer produces.
    let advertisement_len = net::icmpv6::HEADER_LEN + net::icmpv6::NEIGHBOR_LEN + 8;
    net::ethernet::write_header(&mut frame, asker_mac, mac, net::ethernet::ETHERTYPE_IPV6);
    // Answered from the address that was asked about: a host holding both a
    // link-local and a global address replies from the one the asker's own
    // cache and checksum are keyed on.
    net::ipv6::write_header(
        &mut frame[netdev::ETHERNET_HEADER_LEN..],
        solicitation.target,
        destination,
        net::ipv6::NEXT_ICMPV6,
        advertisement_len,
    );
    net::icmpv6::write_neighbor_advertisement(
        &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv6::HEADER_LEN..],
        solicitation.target,
        destination,
        solicitation.target,
        mac,
        false,
        true,
    );
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

    let total = netdev::ETHERNET_HEADER_LEN + net::ipv6::HEADER_LEN + advertisement_len;
    let _ = card.submit_frame(&frame[..total]);
}

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
/// The alternative — sending to a QEMU gateway — was measured and refused:
/// slirp forwards IPv6 datagrams but does not implement NDP, so a solicitation
/// for its address goes unanswered and the boot would have no advertisement
/// to learn from.  A probe that printed a line for an exchange that never
/// happened is the shape this tree's gates exist to catch.
#[cfg(target_os = "none")]
pub fn ipv6_probe() -> bool {
    let (card, mac, local) = {
        let interface = INTERFACE.lock();
        let Some(interface) = interface.as_ref() else {
            return false;
        };
        (interface.card.clone(), interface.hardware, interface.ipv6)
    };

    // ── the neighbour solicitation, answered by this stack itself ────────
    //
    // Sent to the address's own solicited-node group, which is a group this
    // interface joined, so the receive path's `is_for` accepts it.  The
    // `::` source is the duplicate-address form, which is what a host with
    // an address it has not yet heard about sends.
    // A solicitation with no source link-layer option is its fixed part
    // only; the eight bytes an option takes are **not** part of a message
    // that does not carry one, and a length that counted them would make the
    // checksum cover eight zeros nobody wrote.
    let solicitation_len = net::icmpv6::HEADER_LEN + net::icmpv6::NEIGHBOR_LEN;
    let mut frame = alloc::vec![0_u8; card.maximum_frame_len()];
    net::ethernet::write_header(
        &mut frame,
        net::ipv6::multicast_mac(net::ipv6::solicited_node(local)),
        mac,
        net::ethernet::ETHERTYPE_IPV6,
    );
    net::ipv6::write_header(
        &mut frame[netdev::ETHERNET_HEADER_LEN..],
        net::ipv6::UNSPECIFIED,
        net::ipv6::solicited_node(local),
        net::ipv6::NEXT_ICMPV6,
        solicitation_len,
    );
    net::icmpv6::write_neighbor_solicitation(
        &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv6::HEADER_LEN..],
        net::ipv6::UNSPECIFIED,
        local,
        None,
    );

    // The frame goes through the demux the receive path uses, not a private
    // copy of its logic: what this proves is the path a real frame takes.
    demux_ipv6(&frame[netdev::ETHERNET_HEADER_LEN..]);

    // A solicitation from `::` is not answerable — an advertisement sent to
    // `::` goes nowhere — so this stack learns nothing from that one, and
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

    // ── and the solicitation a host answers ─────────────────────────────
    //
    // From the gateway-shaped peer: a link-local address built from another
    // MAC, asking for ours.  This one names a source link-layer address, so
    // the answer has somewhere to go — and it goes through the same write
    // helper a real advertisement uses.
    let peer = net::ipv6::link_local_from_mac([0x52, 0x55, 0x0A, 0x00, 0x02, 0x02]);
    let peer_mac = [0x52, 0x55, 0x0A, 0x00, 0x02, 0x02];
    // This one names its MAC, so its length includes the option's eight
    // bytes: the two lengths differ by exactly that, and a probe that used
    // one for both would fail exactly one of its checksums.
    let with_option_len = net::icmpv6::HEADER_LEN + net::icmpv6::NEIGHBOR_LEN + 8;
    let mut frame = alloc::vec![0_u8; card.maximum_frame_len()];
    net::ethernet::write_header(
        &mut frame,
        net::ipv6::multicast_mac(net::ipv6::solicited_node(local)),
        peer_mac,
        net::ethernet::ETHERTYPE_IPV6,
    );
    net::ipv6::write_header(
        &mut frame[netdev::ETHERNET_HEADER_LEN..],
        peer,
        net::ipv6::solicited_node(local),
        net::ipv6::NEXT_ICMPV6,
        with_option_len,
    );
    net::icmpv6::write_neighbor_solicitation(
        &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv6::HEADER_LEN..],
        peer,
        local,
        Some(peer_mac),
    );
    // The receive path's own demux, with the diagnostic that says what it
    // made of the frame when it made nothing: a probe whose failure is
    // silent is a probe that cannot tell "the demux refused it" from "the
    // answer was lost", and this boot has one chance to say which.
    demux_ipv6(&frame[netdev::ETHERNET_HEADER_LEN..]);

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

    // ── and the echo a host answers ─────────────────────────────────────
    //
    // An echo request from the peer to our link-local address, through the
    // demux: the reply is built by the same path a real ICMPv6 answering
    // takes, and this asserts the request reached it.
    let echo_len = net::icmpv6::echo_len(8);
    let mut frame = alloc::vec![0_u8; card.maximum_frame_len()];
    net::ethernet::write_header(&mut frame, mac, peer_mac, net::ethernet::ETHERTYPE_IPV6);
    net::ipv6::write_header(
        &mut frame[netdev::ETHERNET_HEADER_LEN..],
        peer,
        local,
        net::ipv6::NEXT_ICMPV6,
        echo_len,
    );
    net::icmpv6::write_echo(
        &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv6::HEADER_LEN..],
        peer,
        local,
        net::icmpv6::ECHO_REQUEST,
        7,
        1,
        b"pyrofire",
    );
    demux_ipv6(&frame[netdev::ETHERNET_HEADER_LEN..]);

    // The echo's evidence is the line `answer_echo_request` prints: the
    // request reached the answer path, which is the same path a frame from
    // the wire takes.  What this checks is that the demux did not drop it —
    // a request no handler saw prints no line, and the boot's gate requires
    // one.
    true
}

/// Write an IPv6 address in its compressed hex form.
///
/// Sixteen bytes as eight four-hex-digit groups is the full form, and it is
/// what this prints: a compression that elides the longest zero run is a
/// reader convenience and a writer's bug surface, and a line a gate compares
/// wants one spelling.
#[cfg(target_os = "none")]
fn write_ipv6(address: net::ipv6::Addr) {
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

/// The streams this machine holds, behind one lock.
///
/// The table itself is `net`'s: the ids, the ports, the listening queue and
/// the counters are protocol state, and that crate keeps them so a host can
/// test them.  What is here is the **lock** and the **wire**: every move the
/// crate's table makes is a value, and this module is what carries those
/// values to a card, decides whether an address is this machine, and wakes a
/// task that parked on the answer.
///
/// One lock and not one per connection, because the loopback exchange is
/// re-entrant — a segment delivered to a peer's state machine is answered
/// inside the same call — and a per-connection lock is a deadlock the first
/// full-duplex exchange would find.
static TCP: Mutex<net::tcp_table::Table> = Mutex::new(net::tcp_table::Table::new());

/// Open a listening port, answering the listener's id.
///
/// `AlreadyExists` when the port is taken, for the reason a bound datagram
/// port is: two listeners on one port would make one SYN two streams.
pub fn tcp_listen(port: u16) -> Result<usize> {
    TCP.lock().listen(port)
}

/// Whether a listener has a connection waiting to be accepted.
pub fn tcp_has_pending(listener: usize) -> bool {
    TCP.lock().has_pending(listener)
}

/// Take the connection a listener has been holding, answering its id.
///
/// `NotFound` for an id that names no listener, and `Ok(None)` when the
/// listener holds nothing — which is the caller's signal to park, the same
/// shape a datagram receive is.
pub fn tcp_accept(listener: usize) -> Result<Option<usize>> {
    TCP.lock().accept(listener)
}

/// Open a stream to `destination`'s port, answering the connection's id.
///
/// The handshake runs here, synchronously: the SYN goes out, the listener's
/// answer comes back through the demux, the client's acknowledgement goes
/// back, and by the time this returns both ends hold an open stream.  A
/// connect to another machine would have to wait for its answer on the
/// wire, which is a wait this build does not make a call do — the answer
/// for a destination that is not this machine is `Unsupported`, and the
/// exchange that proves the layer runs where the proof is, on loopback.
pub fn tcp_connect(destination: [u8; 4], destination_port: u16) -> Result<usize> {
    if !is_loopback(destination) {
        return Err(Error::Unsupported);
    }
    if !INTERFACE.lock().as_ref().is_some() {
        return Err(Error::NotFound);
    }

    let (id, noteworthy) = {
        let mut table = TCP.lock();
        let (id, outgoing) = table.connect((destination, destination_port));
        let queued = outgoing.into_iter().map(|segment| (id, segment)).collect();
        let noteworthy = tcp_exchange(&mut table, queued)?;
        (id, noteworthy)
    };
    // The handshake a connect starts is what a parked accept was waiting
    // for, and the wake is here because the table's lock is down.
    note_stream_wake(noteworthy);
    Ok(id)
}

/// Write bytes onto a stream, answering how many were carried.
///
/// The count is the whole write: a stream carries what it is given in one
/// segment, and a partial write on a stream this size would be a caller
/// re-writing bytes the first write already took.
pub fn tcp_write(id: usize, bytes: &[u8]) -> Result<usize> {
    let (count, noteworthy) = {
        let mut table = TCP.lock();
        let Some(connection) = table.connection_mut(id) else {
            return Err(Error::InvalidArgument);
        };
        let (count, outgoing) = connection.send_data(bytes);
        let queued = outgoing.into_iter().map(|segment| (id, segment)).collect();
        let noteworthy = tcp_exchange(&mut table, queued)?;
        (count, noteworthy)
    };
    // The bytes a stream carried are what a parked reader was waiting for.
    note_stream_wake(noteworthy);
    Ok(count)
}

/// Whether a stream has bytes its reader has not taken.
pub fn tcp_has_data(id: usize) -> bool {
    TCP.lock().has_data(id)
}

/// Read bytes off a stream, answering how many.
///
/// `None` is "nothing arrived, ask again" — the answer a caller parks on,
/// the same shape a datagram receive is.  A stream whose connection is gone
/// reached its close, and answers zero: end of file, which is what a reader
/// whose writer finished reads.  A read that never answered zero would be a
/// reader parked on a writer that said it was done.
pub fn tcp_read(id: usize, into: &mut [u8]) -> Result<Option<usize>> {
    let mut table = TCP.lock();
    let Some(connection) = table.connection_mut(id) else {
        return Ok(Some(0));
    };
    if connection.inbox_len() == 0 {
        return Ok(None);
    }
    Ok(Some(connection.take(into)))
}

/// Close a stream: the FIN, the peer's, and the acknowledgements that cross
/// between them.
///
/// A close of an id that names nothing is `Ok`, because the close already
/// happened — the orderly one this call ran, or the abrupt one a process's
/// exit ran when it released its descriptors.
pub fn tcp_close(id: usize) -> Result<()> {
    let noteworthy = {
        let mut table = TCP.lock();
        let Some(connection) = table.connection_mut(id) else {
            return Ok(());
        };
        let outgoing = connection.close();
        let queued = outgoing.into_iter().map(|segment| (id, segment)).collect();
        let noteworthy = tcp_exchange(&mut table, queued)?;
        table.prune();
        noteworthy
    };
    // The finish a close sends is what a parked reader's end of file is.
    note_stream_wake(noteworthy);
    Ok(())
}

/// Wake what a stream event parked, from a context that holds no lock.
///
/// The count is printed when it is not zero, because the wake is the fact
/// the parked caller's retry answers — and the IPI, for the reason every
/// wake here carries one: the woken task may be held by another CPU parked
/// in a wait whose own clock may never move.
fn note_stream_wake(noteworthy: bool) {
    if !noteworthy {
        return;
    }
    let woken = crate::scheduler::wake_blocked();
    if woken > 0 {
        #[cfg(target_os = "none")]
        {
            arch::serial::write_str("protofire: a stream event woke ");
            arch::serial::write_u32(woken as u32);
            arch::serial::write_str(" blocked task(s)\n");
            // SAFETY: the boot's own IPI path, installed before any program
            // ran.
            unsafe { arch::send_ipi_to_others() };
        }
        #[cfg(not(target_os = "none"))]
        let _ = woken;
    }
}

/// Carry one connection's outgoing segments to their peers, and everything
/// the peers answer back, until the wire is quiet.
///
/// This is the loopback the protocol crate's tests run on, in the kernel:
/// a segment for this machine is delivered to the peer's own state machine
/// inside the same locked region, whose replies queue behind it, and the
/// loop runs until nothing is left.  A segment for another machine goes out
/// through the card in an IPv4 packet, which is the whole of the
/// difference between the two wires — the state machine never learns which
/// one carried its bytes.
fn tcp_exchange(
    table: &mut net::tcp_table::Table,
    queue: Vec<(usize, net::tcp::Outgoing)>,
) -> Result<bool> {
    // Whether anything happened that a parked caller was waiting for: a
    // connection a SYN opened, bytes that landed in a stream's inbox, a
    // finish that ends a read.  The answer comes back to the caller, which
    // wakes **after** this function returns — the table's lock is its
    // caller's, and the scheduler's is never taken inside it.
    let mut noteworthy = false;
    let mut queue = queue;
    while let Some((sender_id, outgoing)) = queue.pop() {
        // The sender's own facts, read before anything is delivered: where
        // the segment goes, and what port it names itself from.
        let Some((address, destination_port)) = table.remote_of(sender_id) else {
            // The sender's close finished while its last segment was in
            // flight; the segment has nowhere to name itself from, and a
            // wire that carried it would be a wire answering a closed
            // stream.
            continue;
        };
        let Some(sender_port) = table.local_port_of(sender_id) else {
            continue;
        };

        if is_loopback(address) {
            let protocol = {
                let interface = INTERFACE.lock();
                interface.as_ref().map(|interface| interface.protocol)
            };
            let Some(protocol) = protocol else {
                return Err(Error::NotFound);
            };
            // A SYN for a listening port opens a connection right here: the
            // listener answers inside the same exchange, whose SYN with ACK
            // queues behind this one, and the connection waits in the
            // listener's pending list for the accept that takes it.
            if outgoing.flags & net::tcp::FLAG_SYN != 0
                && outgoing.flags & net::tcp::FLAG_ACK == 0
                && table
                    .connection_for(destination_port, protocol, sender_port)
                    .is_none()
            {
                let Some((id, replies)) = table.accept_syn(
                    &net::tcp::Segment {
                        source_port: sender_port,
                        destination_port,
                        sequence: outgoing.sequence,
                        acknowledgement: outgoing.acknowledgement,
                        flags: outgoing.flags,
                        window: net::tcp::WINDOW,
                        payload_len: outgoing.payload.len(),
                    },
                    (protocol, sender_port),
                ) else {
                    // A SYN for a port nothing listens on: dropped, the way
                    // a datagram for an unbound port is.
                    continue;
                };
                noteworthy = true;
                queue.extend(replies.into_iter().map(|reply| (id, reply)));
                continue;
            }
            let Some(peer_id) = table.connection_for(destination_port, protocol, sender_port)
            else {
                // A segment for a stream this table does not hold: the peer
                // is gone, and a wire that carried the segment would be a
                // wire talking to nobody.  Dropped, the way a segment to a
                // closed port is.
                continue;
            };
            let segment = net::tcp::Segment {
                source_port: sender_port,
                destination_port,
                sequence: outgoing.sequence,
                acknowledgement: outgoing.acknowledgement,
                flags: outgoing.flags,
                window: net::tcp::WINDOW,
                payload_len: outgoing.payload.len(),
            };
            let connection = table
                .connection_mut(peer_id)
                .expect("the id came from this table");
            let (answer, replies) = connection.receive(&segment, &outgoing.payload);
            answer?;
            noteworthy |= matches!(
                answer,
                Ok(net::tcp::Event::Data(_)) | Ok(net::tcp::Event::PeerFinished)
            );
            queue.extend(replies.into_iter().map(|reply| (peer_id, reply)));
        } else {
            tcp_send_on_wire(table, sender_port, address, destination_port, &outgoing)?;
        }
    }
    Ok(noteworthy)
}

/// Put one segment in an IPv4 packet and give it to the card.
fn tcp_send_on_wire(
    table: &mut net::tcp_table::Table,
    sender_port: u16,
    address: [u8; 4],
    destination_port: u16,
    outgoing: &net::tcp::Outgoing,
) -> Result<()> {
    let _ = table;
    let interface = INTERFACE.lock();
    let Some(interface) = interface.as_ref() else {
        return Err(Error::NotFound);
    };
    let Some(gateway_hardware) = interface.arp.hardware_for(interface.gateway) else {
        return Err(Error::NotFound);
    };
    let (our_protocol, our_hardware) = (interface.protocol, interface.hardware);
    let tcp_len = net::tcp::HEADER_LEN + outgoing.payload.len();
    let packet_len = netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + tcp_len;
    let mut frame = alloc::vec![0; packet_len];
    net::ethernet::write_header(
        &mut frame,
        gateway_hardware,
        our_hardware,
        net::ethernet::ETHERTYPE_IPV4,
    );
    net::ipv4::write_header(
        &mut frame[netdev::ETHERNET_HEADER_LEN..],
        our_protocol,
        address,
        net::ipv4::PROTOCOL_TCP,
        tcp_len,
    );
    net::tcp::write_segment(
        &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..],
        our_protocol,
        address,
        sender_port,
        destination_port,
        outgoing.sequence,
        outgoing.acknowledgement,
        outgoing.flags,
        &outgoing.payload,
    );
    interface.card.submit_frame(&frame)
}

/// What the pump does with a TCP segment: route it to the connection it
/// names, or open one for it on a listener.
///
/// The SYN's connection is created here, with the listener's answer sent
/// before the accept ever runs — which is why a client's connect completes
/// against a listener nothing has accepted from yet, and why the data
/// before an accept is in the connection's own inbox when the accept
/// returns it.
fn demux_tcp(packet: net::ipv4::Packet, payload: &[u8]) -> bool {
    let Some(segment) = net::tcp::parse(payload, packet.header.source, packet.header.destination)
    else {
        return false;
    };
    let mut table = TCP.lock();
    table.prune();

    // A SYN for a listening port opens a connection.
    if net::tcp_table::Table::is_opening(&segment) {
        let Some((id, outgoing)) =
            table.accept_syn(&segment, (packet.header.source, segment.source_port))
        else {
            return false;
        };
        let queued = outgoing.into_iter().map(|segment| (id, segment)).collect();
        let _ = tcp_exchange(&mut table, queued);
        // A connection opened is what a parked accept was waiting for.
        return true;
    }

    let Some(id) = table.connection_for(
        segment.destination_port,
        packet.header.source,
        segment.source_port,
    ) else {
        return false;
    };
    let noteworthy = table.has_data(id) || segment.flags & net::tcp::FLAG_FIN != 0;
    let connection = table
        .connection_mut(id)
        .expect("the id came from this table");
    let (answer, replies) = connection.receive(&segment, payload);
    let _ = answer;
    if !replies.is_empty() {
        let queued = replies.into_iter().map(|segment| (id, segment)).collect();
        let _ = tcp_exchange(&mut table, queued);
    }
    // Anything the peer has waiting is what a parked reader was waiting
    // for — but the wake takes the scheduler's lock, and this function
    // holds the table's, so the answer is returned and the wake happens
    // where the lock is no longer held.
    noteworthy
}

/// The boot's stream exchange: a listener on this machine, a client to it,
/// an echo, and the close that ends both ends.
///
/// The whole of a TCP exchange, on loopback, with no card in the path — the
/// same exchange the protocol crate's tests run on a host, run by the boot
/// so the lines below are a machine's evidence rather than a host's.  Each
/// line names what only a completed exchange could have carried: the ids
/// the table handed out, the echo's length beside the send's, and the close
/// that left both ends done.
#[cfg(target_os = "none")]
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
    let client = match tcp_connect(protocol, 9000) {
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

    // The client's bytes, the server's echo, and the read-back — each one a
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
    let _ = tcp_close(client);
    let _ = tcp_close(accepted);
    let closed = table_state(client);
    arch::serial::write_str("protofire: tcp closed, both ends ");
    arch::serial::write_str(if closed { "done\n" } else { "lingering\n" });
    round_trip
}

/// Whether an id's connection is gone from the table, which an orderly
/// close leaves behind.
#[cfg(target_os = "none")]
fn table_state(id: usize) -> bool {
    TCP.lock().is_gone(id)
}

#[cfg(test)]
mod tests {
    use super::Interface;
    use super::QUEUE_LIMIT;
    use super::bind_udp;
    use super::deliver_udp;
    use super::install;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use netdev::LinkDevice;
    use sync::Mutex;

    /// A card that records what it was asked to send, and hands back the
    /// frames a test queues for it — the same shape a driver has, without a
    /// machine behind it.
    struct FakeCard {
        sent: Mutex<Vec<Vec<u8>>>,
        incoming: Mutex<Vec<Vec<u8>>>,
    }

    impl FakeCard {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                sent: Mutex::new(Vec::new()),
                incoming: Mutex::new(Vec::new()),
            })
        }

        /// Queue a frame the card has "received", for the pump to drain.
        fn receive(&self, frame: &[u8]) {
            self.incoming.lock().push(Vec::from(frame));
        }
    }

    impl LinkDevice for FakeCard {
        fn hardware_address(&self) -> [u8; 6] {
            [0x02; 6]
        }

        fn submit_frame(&self, frame: &[u8]) -> abi::Result<()> {
            self.sent.lock().push(Vec::from(frame));
            Ok(())
        }

        fn receive_frame(&self, into: &mut [u8]) -> abi::Result<Option<usize>> {
            let mut incoming = self.incoming.lock();
            let Some(frame) = incoming.first() else {
                return Ok(None);
            };
            if frame.len() > into.len() {
                return Err(abi::Error::InvalidArgument);
            }
            let length = frame.len();
            into[..length].copy_from_slice(frame);
            incoming.remove(0);
            Ok(Some(length))
        }

        fn maximum_frame_len(&self) -> usize {
            1514
        }
    }

    /// Each test binds its own ports, because the port table is one boot's
    /// state and the tests run beside each other.
    const PORT_A: u16 = 40001;
    const PORT_B: u16 = 40002;
    const PORT_C: u16 = 40003;
    const PORT_D: u16 = 40004;
    const PORT_E: u16 = 40005;
    const PORT_F: u16 = 40006;

    /// A bound port answers, and binding it again is the wire's refusal.
    #[test]
    fn a_bound_port_has_one_owner() {
        let socket = bind_udp(PORT_A).expect("a bind");
        assert_eq!(socket.port(), PORT_A);
        assert!(
            matches!(bind_udp(PORT_A), Err(abi::Error::AlreadyExists)),
            "the second bind on one port is the wire's refusal"
        );
    }

    /// A datagram delivered to a bound port is what the socket's next
    /// receive answers, with the source the delivery was given.
    #[test]
    fn a_delivered_datagram_is_what_the_receive_answers() {
        let socket = bind_udp(PORT_B).expect("a bind");
        let _ = deliver_udp([10, 0, 2, 2], PORT_B, [10, 0, 2, 9], 77, b"protofire")
            .expect("a delivery");

        let mut buffer = [0_u8; 16];
        let (source, source_port, count) = socket
            .try_recv(&mut buffer)
            .expect("a receive")
            .expect("a datagram");
        assert_eq!(source, [10, 0, 2, 9]);
        assert_eq!(source_port, 77);
        assert_eq!(count, 9);
        assert_eq!(&buffer[..count], b"protofire");
    }

    /// A datagram for a port nothing owns is dropped, because UDP promised
    /// nothing; the receive that follows answers nothing.
    #[test]
    fn a_datagram_for_an_unbound_port_is_dropped() {
        let woken =
            deliver_udp([10, 0, 2, 15], PORT_E, [10, 0, 2, 9], 77, b"nobody").expect("a delivery");
        assert_eq!(woken, 0, "and nobody was waiting");
        let socket = bind_udp(PORT_E).expect("a bind after the drop");
        let mut buffer = [0_u8; 16];
        assert_eq!(socket.try_recv(&mut buffer), Ok(None), "nothing arrived");
    }

    /// A receive with nothing in the queue answers none, and one whose
    /// datagram does not fit is refused with the datagram kept.
    #[test]
    fn a_receive_refuses_a_datagram_that_does_not_fit_and_keeps_it() {
        let socket = bind_udp(PORT_C).expect("a bind");
        let mut buffer = [0_u8; 16];
        assert_eq!(socket.try_recv(&mut buffer), Ok(None), "nothing yet");

        deliver_udp(
            [10, 0, 2, 2],
            PORT_C,
            [10, 0, 2, 9],
            77,
            b"way too long for this buffer",
        )
        .expect("a delivery");
        let mut small = [0_u8; 4];
        assert_eq!(
            socket.try_recv(&mut small).unwrap_err(),
            abi::Error::InvalidArgument,
            "the buffer, not the datagram, is the problem"
        );
        // The datagram is still there, and a buffer that fits takes it.
        let mut whole = [0_u8; 32];
        let (source, _, count) = socket
            .try_recv(&mut whole)
            .expect("a receive")
            .expect("the datagram was kept");
        assert_eq!(count, 28);
        assert_eq!(source, [10, 0, 2, 9]);
    }

    /// A full queue refuses the next datagram with `Busy`, which is what a
    /// sender can act on.
    #[test]
    fn a_full_queue_refuses_with_busy() {
        let _socket = bind_udp(PORT_D).expect("a bind");
        for index in 0..QUEUE_LIMIT {
            deliver_udp([10, 0, 2, 2], PORT_D, [10, 0, 2, 9], 77, &[index as u8; 4])
                .expect("a delivery");
        }
        assert_eq!(
            deliver_udp([10, 0, 2, 2], PORT_D, [10, 0, 2, 9], 77, b"one more").unwrap_err(),
            abi::Error::Busy
        );
    }

    /// The interface's whole day, as one test, because the interface is one
    /// static and the tests run beside each other: a datagram to this
    /// machine goes through the demux and never touches the card, one for
    /// another machine leaves through the gateway, a frame the card
    /// received is a datagram in a socket's queue after the pump, a stream
    /// opens, carries and closes on loopback, and a closed stream reads as
    /// end of file.
    #[test]
    fn the_interface_runs_the_whole_of_the_stack() {
        let card = FakeCard::new();
        let hardware = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let protocol = [10, 9, 9, 15];
        let gateway = [10, 9, 9, 2];
        install(Interface::new(card.clone(), hardware, protocol, gateway));
        super::arp_learn(gateway, [0x52; 6]);

        // Loopback, as a datagram: to this machine's own address.
        let socket = bind_udp(PORT_F).expect("a bind");
        super::send_datagram(protocol, PORT_F, 50000, b"self").expect("a loopback send");
        assert!(
            card.sent.lock().is_empty(),
            "a datagram to this machine does not touch the card"
        );
        let mut buffer = [0_u8; 8];
        let (source, _, count) = socket
            .try_recv(&mut buffer)
            .expect("a receive")
            .expect("the loopback datagram");
        assert_eq!(source, protocol, "the sender is this machine");
        assert_eq!(&buffer[..count], b"self");

        // The wire, as a datagram: the frame names the gateway's hardware
        // address and the destination's protocol address, which is the
        // whole of this build's routing.
        super::send_datagram([10, 9, 9, 7], 9004, 50000, b"out").expect("a send");
        {
            let sent = card.sent.lock();
            assert_eq!(sent.len(), 1);
            let frame = &sent[0];
            assert_eq!(&frame[0..6], &[0x52; 6], "to the gateway's address");
            assert_eq!(
                netdev::ethertype(frame),
                Some(net::ethernet::ETHERTYPE_IPV4)
            );
            let packet = net::ipv4::parse(&frame[netdev::ETHERNET_HEADER_LEN..]).expect("a packet");
            assert_eq!(packet.header.destination, [10, 9, 9, 7]);
            assert_eq!(packet.header.source, protocol);
        }

        // The pump: a real frame in the card's ring, a datagram in a
        // socket's queue after it — built by the same writers the send path
        // uses, so the pump is tested against the wire's own bytes.
        let datagram_socket = bind_udp(40008).expect("a bind");
        let udp_len = net::udp::datagram_len(5);
        let packet_len = netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + udp_len;
        let mut frame = alloc::vec![0; packet_len];
        net::ethernet::write_header(
            &mut frame,
            [0x02; 6],
            [0x02; 6],
            net::ethernet::ETHERTYPE_IPV4,
        );
        net::ipv4::write_header(
            &mut frame[netdev::ETHERNET_HEADER_LEN..],
            [10, 9, 9, 9],
            protocol,
            net::ipv4::PROTOCOL_UDP,
            udp_len,
        );
        net::udp::write_datagram(
            &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..],
            [10, 9, 9, 9],
            protocol,
            77,
            40008,
            b"hello",
        );
        card.receive(&frame);
        assert_eq!(super::pump(), 1, "the pump took the frame the card held");
        let mut buffer = [0_u8; 8];
        let (source, source_port, count) = datagram_socket
            .try_recv(&mut buffer)
            .expect("a receive")
            .expect("the datagram the frame carried");
        assert_eq!(source, [10, 9, 9, 9]);
        assert_eq!(source_port, 77);
        assert_eq!(&buffer[..count], b"hello");

        // The stream: the boot's own probe, as a host test.  The same
        // calls, the same demux, and a card that records nothing, because a
        // loopback stream touches none of it.
        let listener = super::tcp_listen(9002).expect("a listen");
        let client = super::tcp_connect(protocol, 9002).expect("a connect");
        assert_eq!(
            card.sent.lock().len(),
            1,
            "the handshake never touched the card: the wire datagram's frame is still the only one"
        );
        assert!(super::tcp_has_pending(listener), "the SYN opened a stream");
        let accepted = super::tcp_accept(listener)
            .expect("an accept")
            .expect("a pending stream");

        let sent = super::tcp_write(client, b"protofire").expect("a write");
        assert_eq!(sent, 9);
        assert!(super::tcp_has_data(accepted), "the stream carried it");
        let mut stream_buffer = [0_u8; 32];
        let echoed = super::tcp_read(accepted, &mut stream_buffer)
            .expect("a read")
            .expect("the bytes");
        assert_eq!(echoed, 9);
        assert_eq!(&stream_buffer[..9], b"protofire");

        let back = super::tcp_write(accepted, &stream_buffer[..echoed]).expect("a write");
        assert_eq!(back, 9);
        let received = super::tcp_read(client, &mut stream_buffer)
            .expect("a read")
            .expect("the echo");
        assert_eq!(received, 9);
        assert_eq!(&stream_buffer[..9], b"protofire");

        // The orderly close, and the end of file it leaves behind.
        super::tcp_close(client).expect("a close");
        super::tcp_close(accepted).expect("a close");
        {
            let table = super::TCP.lock();
            assert!(table.is_gone(client), "the client's end is done");
            assert!(table.is_gone(accepted), "and the accepted end with it");
        }
        assert_eq!(
            super::tcp_read(client, &mut stream_buffer),
            Ok(Some(0)),
            "a stream that is gone reads as end of file"
        );
        // The stream never touched the card, and the wire datagram's frame
        // is still the only thing the card carries.
        assert_eq!(card.sent.lock().len(), 1, "loopback is not the wire");
    }

    /// A frame the card received is a datagram in a socket's queue after the
    /// pump, which is the receive path's own shape.
    #[test]
    fn a_frame_the_card_received_is_a_datagram_after_the_pump() {
        let card = FakeCard::new();
        let protocol = [10, 9, 9, 15];
        install(Interface::new(
            card.clone(),
            [0x02; 6],
            protocol,
            [10, 9, 9, 2],
        ));

        let socket = bind_udp(40007).expect("a bind");
        // A real frame: Ethernet to this machine, IPv4 to its address, and
        // the datagram in the payload — built by the same writers the send
        // path uses, so the pump is tested against the wire's own bytes.
        let udp_len = net::udp::datagram_len(5);
        let packet_len = netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + udp_len;
        let mut frame = alloc::vec![0; packet_len];
        net::ethernet::write_header(
            &mut frame,
            [0x02; 6],
            [0x02; 6],
            net::ethernet::ETHERTYPE_IPV4,
        );
        net::ipv4::write_header(
            &mut frame[netdev::ETHERNET_HEADER_LEN..],
            [10, 9, 9, 9],
            protocol,
            net::ipv4::PROTOCOL_UDP,
            udp_len,
        );
        net::udp::write_datagram(
            &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..],
            [10, 9, 9, 9],
            protocol,
            77,
            40007,
            b"hello",
        );
        card.receive(&frame);

        let taken = super::pump();
        assert_eq!(taken, 1, "the pump took the frame the card held");

        let mut buffer = [0_u8; 8];
        let (source, source_port, count) = socket
            .try_recv(&mut buffer)
            .expect("a receive")
            .expect("the datagram the frame carried");
        assert_eq!(source, [10, 9, 9, 9]);
        assert_eq!(source_port, 77);
        assert_eq!(&buffer[..count], b"hello");
    }
}
