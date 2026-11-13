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
    if packet.header.protocol == net::ipv4::PROTOCOL_TCP {
        demux_tcp(packet, payload);
    }
}

/// The initial sequence numbers, drawn from a counter.
///
/// A counter rather than a constant, because two connections whose
/// handshakes used the same numbers would be two streams one segment could
/// confuse for the other; a counter is not a secret, and this stack does
/// not pretend the wire is one that needs it to be.
static TCP_SEQUENCE: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(1000);

/// The next initial sequence number.
fn tcp_isn() -> u32 {
    TCP_SEQUENCE.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
}

/// One end of a stream, as the kernel holds it: the state machine the
/// protocol crate computes, keyed by an id a descriptor carries.
struct TcpEntry {
    id: usize,
    connection: net::tcp::Connection,
}

/// One listening port, with the connections its SYNs opened.
struct TcpListenerEntry {
    id: usize,
    port: u16,
    pending: Vec<usize>,
}

/// The whole of the kernel's TCP state, behind one lock.
///
/// One lock rather than one per connection, because the loopback exchange
/// is synchronous — a segment delivered to a peer's state machine comes
/// back as that machine's answer inside the same call — and a re-entrant
/// lock is a deadlock the first full-duplex exchange would find.  Holding
/// the table for the length of an exchange is holding it for
/// microseconds: the exchanges are loopback-sized, and the lock is the
/// same one a parked reader releases before it sleeps.
struct TcpTable {
    listeners: Vec<TcpListenerEntry>,
    connections: Vec<TcpEntry>,
    next_id: usize,
}

impl TcpTable {
    const fn new() -> Self {
        Self {
            listeners: Vec::new(),
            connections: Vec::new(),
            next_id: 1,
        }
    }

    /// The id of the connection a segment answers, by its own four fields:
    /// the port it names and the peer it names them for.
    fn connection_for(
        &self,
        destination_port: u16,
        source: [u8; 4],
        source_port: u16,
    ) -> Option<usize> {
        self.connections
            .iter()
            .find(|entry| {
                entry.connection.local_port() == destination_port
                    && entry.connection.remote() == (source, source_port)
            })
            .map(|entry| entry.id)
    }

    /// Drop every connection whose close finished: its id is nobody's, and
    /// the descriptors that named it are closed or closing.
    fn prune(&mut self) {
        self.connections
            .retain(|entry| entry.connection.state() != net::tcp::State::Closed);
    }
}

static TCP: Mutex<TcpTable> = Mutex::new(TcpTable::new());

/// Open a listening port, answering the listener's id.
///
/// `AlreadyExists` when the port is taken, for the reason a bound datagram
/// port is: two listeners on one port would make one SYN two streams.
pub fn tcp_listen(port: u16) -> Result<usize> {
    let mut table = TCP.lock();
    if table.listeners.iter().any(|entry| entry.port == port) {
        return Err(Error::AlreadyExists);
    }
    let id = table.next_id;
    table.next_id += 1;
    table.listeners.push(TcpListenerEntry {
        id,
        port,
        pending: Vec::new(),
    });
    Ok(id)
}

/// Whether a listener has a connection waiting to be accepted.
pub fn tcp_has_pending(listener: usize) -> bool {
    let table = TCP.lock();
    table
        .listeners
        .iter()
        .find(|entry| entry.id == listener)
        .is_some_and(|entry| !entry.pending.is_empty())
}

/// Take the connection a listener has been holding, answering its id.
///
/// `NotFound` for an id that names no listener, and `None` when the
/// listener holds nothing — which is the caller's signal to park, the same
/// shape a datagram receive is.
pub fn tcp_accept(listener: usize) -> Result<Option<usize>> {
    let mut table = TCP.lock();
    let Some(entry) = table
        .listeners
        .iter_mut()
        .find(|entry| entry.id == listener)
    else {
        return Err(Error::NotFound);
    };
    Ok(entry.pending.pop())
}

/// The next ephemeral port a client's end of a stream uses.
///
/// From the range the wire's own convention reserves for clients; a counter
/// rather than a search, because the connections a boot makes are a
/// handful and the range is thirty thousand wide.
static TCP_EPHEMERAL: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(49152);

fn tcp_ephemeral() -> u16 {
    TCP_EPHEMERAL.fetch_add(1, core::sync::atomic::Ordering::Relaxed) as u16
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

    let mut table = TCP.lock();
    let (connection, outgoing) =
        net::tcp::Connection::connect(tcp_ephemeral(), (destination, destination_port), tcp_isn());
    let id = table.next_id;
    table.next_id += 1;
    table.connections.push(TcpEntry { id, connection });
    let queued = outgoing.into_iter().map(|segment| (id, segment)).collect();
    tcp_exchange(&mut table, queued)?;
    Ok(id)
}

/// Write bytes onto a stream, answering how many were carried.
///
/// The count is the whole write: a stream carries what it is given in one
/// segment, and a partial write on a stream this size would be a caller
/// re-writing bytes the first write already took.
pub fn tcp_write(id: usize, bytes: &[u8]) -> Result<usize> {
    let mut table = TCP.lock();
    let Some(index) = table.connections.iter().position(|entry| entry.id == id) else {
        return Err(Error::InvalidArgument);
    };
    let (count, outgoing) = table.connections[index].connection.send_data(bytes);
    let queued = outgoing.into_iter().map(|segment| (id, segment)).collect();
    tcp_exchange(&mut table, queued)?;
    Ok(count)
}

/// Whether a stream has bytes its reader has not taken.
pub fn tcp_has_data(id: usize) -> bool {
    let table = TCP.lock();
    table
        .connections
        .iter()
        .find(|entry| entry.id == id)
        .is_some_and(|entry| entry.connection.inbox_len() > 0)
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
    let Some(entry) = table.connections.iter_mut().find(|entry| entry.id == id) else {
        return Ok(Some(0));
    };
    if entry.connection.inbox_len() == 0 {
        return Ok(None);
    }
    Ok(Some(entry.connection.take(into)))
}

/// Close a stream: the FIN, the peer's, and the acknowledgements that cross
/// between them.
///
/// A close of an id that names nothing is `Ok`, because the close already
/// happened — the orderly one this call ran, or the abrupt one a process's
/// exit ran when it released its descriptors.
pub fn tcp_close(id: usize) -> Result<()> {
    let mut table = TCP.lock();
    let Some(index) = table.connections.iter().position(|entry| entry.id == id) else {
        return Ok(());
    };
    let outgoing = table.connections[index].connection.close();
    let queued = outgoing.into_iter().map(|segment| (id, segment)).collect();
    tcp_exchange(&mut table, queued)?;
    table.prune();
    Ok(())
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
fn tcp_exchange(table: &mut TcpTable, queue: Vec<(usize, net::tcp::Outgoing)>) -> Result<()> {
    let mut queue = queue;
    while let Some((sender_id, outgoing)) = queue.pop() {
        // The sender's own facts, read before anything is delivered: where
        // the segment goes, and what port it names itself from.
        let Some(sender_index) = table
            .connections
            .iter()
            .position(|entry| entry.id == sender_id)
        else {
            // The sender's close finished while its last segment was in
            // flight; the segment has nowhere to name itself from, and a
            // wire that carried it would be a wire answering a closed
            // stream.
            continue;
        };
        let (address, destination_port) = table.connections[sender_index].connection.remote();
        let sender_port = table.connections[sender_index].connection.local_port();

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
                let Some(listener_index) = table
                    .listeners
                    .iter()
                    .position(|entry| entry.port == destination_port)
                else {
                    // A SYN for a port nothing listens on: dropped, the way
                    // a datagram for an unbound port is.
                    continue;
                };
                let (connection, replies) = net::tcp::Connection::accept_syn(
                    destination_port,
                    (protocol, sender_port),
                    tcp_isn(),
                    outgoing.sequence,
                );
                let id = table.next_id;
                table.next_id += 1;
                table.connections.push(TcpEntry { id, connection });
                table.listeners[listener_index].pending.push(id);
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
            let peer_index = table
                .connections
                .iter()
                .position(|entry| entry.id == peer_id)
                .expect("the id came from this table");
            let segment = net::tcp::Segment {
                source_port: sender_port,
                destination_port,
                sequence: outgoing.sequence,
                acknowledgement: outgoing.acknowledgement,
                flags: outgoing.flags,
                window: net::tcp::WINDOW,
                payload_len: outgoing.payload.len(),
            };
            let (answer, replies) = table.connections[peer_index]
                .connection
                .receive(&segment, &outgoing.payload);
            answer?;
            queue.extend(replies.into_iter().map(|reply| (peer_id, reply)));
        } else {
            tcp_send_on_wire(table, sender_port, address, destination_port, &outgoing)?;
        }
    }
    Ok(())
}

/// Put one segment in an IPv4 packet and give it to the card.
fn tcp_send_on_wire(
    table: &mut TcpTable,
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
fn demux_tcp(packet: net::ipv4::Packet, payload: &[u8]) {
    let Some(segment) = net::tcp::parse(payload, packet.header.source, packet.header.destination)
    else {
        return;
    };
    let mut table = TCP.lock();
    table.prune();

    // A SYN for a listening port opens a connection.
    if segment.flags & net::tcp::FLAG_SYN != 0 && segment.flags & net::tcp::FLAG_ACK == 0 {
        let Some(listener_index) = table
            .listeners
            .iter()
            .position(|entry| entry.port == segment.destination_port)
        else {
            return;
        };
        let (connection, outgoing) = net::tcp::Connection::accept_syn(
            segment.destination_port,
            (packet.header.source, segment.source_port),
            tcp_isn(),
            segment.sequence,
        );
        let id = table.next_id;
        table.next_id += 1;
        table.connections.push(TcpEntry { id, connection });
        table.listeners[listener_index].pending.push(id);
        let queued = outgoing.into_iter().map(|segment| (id, segment)).collect();
        let _ = tcp_exchange(&mut table, queued);
        return;
    }

    let Some(id) = table.connection_for(
        segment.destination_port,
        packet.header.source,
        segment.source_port,
    ) else {
        return;
    };
    let index = table
        .connections
        .iter()
        .position(|entry| entry.id == id)
        .expect("the id came from this table");
    let (answer, replies) = table.connections[index]
        .connection
        .receive(&segment, payload);
    let _ = answer;
    if !replies.is_empty() {
        let queued = replies.into_iter().map(|segment| (id, segment)).collect();
        let _ = tcp_exchange(&mut table, queued);
    }
    // Anything the peer has waiting is what a parked reader was waiting
    // for, so this is where the wake belongs.
    let _ = crate::scheduler::wake_blocked();
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
    let table = TCP.lock();
    table.connections.iter().all(|entry| entry.id != id)
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
            assert!(
                table.connections.iter().all(|entry| entry.id != client),
                "the client's end is done"
            );
            assert!(
                table.connections.iter().all(|entry| entry.id != accepted),
                "and the accepted end with it"
            );
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
