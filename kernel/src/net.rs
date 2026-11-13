//! kernel/src/net.rs
//!
//! The kernel's network half: the interface the boot brought up, the answers
//! the network calls give, and the datagram sockets a program holds.
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
/// and the ARP cache its wire exchanges filled.
pub struct Interface {
    card: Arc<dyn LinkDevice>,
    hardware: [u8; 6],
    protocol: [u8; 4],
    gateway: [u8; 4],
    arp: net::arp::Cache,
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
        Self {
            card,
            hardware,
            protocol,
            gateway,
            arp: net::arp::Cache::new(),
        }
    }

    /// The protocol address this interface answers for.
    pub fn protocol(&self) -> [u8; 4] {
        self.protocol
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

    /// A datagram addressed to this interface is delivered through the demux
    /// and never reaches the card; one addressed elsewhere leaves through
    /// the gateway, addressed to its hardware address.
    #[test]
    fn loopback_is_the_demux_and_the_wire_is_the_gateway() {
        let card = FakeCard::new();
        let hardware = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let protocol = [10, 9, 9, 15];
        let gateway = [10, 9, 9, 2];
        install(Interface::new(card.clone(), hardware, protocol, gateway));
        // The cache learns the gateway the way the boot's exchange does.
        super::arp_learn(gateway, [0x52; 6]);

        let socket = bind_udp(PORT_F).expect("a bind");
        // Loopback: to this machine's own address.
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

        // The wire: to another machine.  The frame the card was given names
        // the gateway's hardware address and the destination's protocol
        // address, which is the whole of this build's routing.
        super::send_datagram([10, 9, 9, 7], 9000, 50000, b"out").expect("a send");
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
