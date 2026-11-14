//! kernel/src/net.rs
//!
//! The kernel's network half: the interface the boot brought up, the answers
//! the network calls give, and the sockets a program holds.
//!
//! ## Where `net` ends and this file begins
//!
//! The `net` crate computes what a frame means: it parses a header, builds a
//! request, checks a sum, and every one of its functions is a pure call over a
//! byte slice.  The state it does hold, [`net::tcp_table::Table`], the streams
//! a machine owns, and [`net::udp_socket::Queue`], what arrived for one bound
//! port, it holds as **values** its caller owns, with no lock and no
//! `static`, which is what lets that arithmetic be a host test as well.  So
//! does the writing of a reply frame: [`net::reply`] composes one from
//! addresses, and this file decides **whose** addresses and when.
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
//! and the one thing that had grown here, the connection table, moved out.
//!
//! ## Why this is a module and not a field of the boot
//!
//! The probes in `devices.rs` prove the wire; this module holds what the
//! probes found, so a call made after the boot has finished answers from
//! state rather than from constants a caller would have to guess.  The
//! interface is installed once, when the card comes up, and every network
//! call reads through it, which is what makes `NetworkStatus` a fact about
//! this boot's machine rather than about the QEMU defaults a reader could
//! have looked up.
//!
//! ## The sockets, and the one table that knows their ports
//!
//! A datagram socket is a bound port and a queue of what arrived for it.  It
//! lives behind an `Arc` a descriptor holds, and the port table beside this
//! file's interface holds a `Weak`, so a socket's port is routable for
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
/// the card cannot carry is a send that failed twice, once in the build
/// and once on the wire.
pub const MAX_DATAGRAM_BYTES: usize = 1472;

/// How many datagrams one socket's queue holds, from the crate that owns the
/// rule.
///
/// Re-exported rather than restated: a queue a sender could grow is a queue a
/// sender could fill, and the bound and the refusal for it are one decision
/// that `net::udp_socket` makes.
pub use net::udp_socket::QUEUE_LIMIT;

/// An interface: the card the boot drives, the addresses it answers for,
/// the ARP cache its wire exchanges filled, and the IPv6 state beside them.
pub struct Interface {
    card: Arc<dyn LinkDevice>,
    hardware: [u8; 6],
    protocol: [u8; 4],
    gateway: [u8; 4],
    /// The routes this machine knows, of both families.
    ///
    /// `gateway` above is the one route DHCP names, kept because the boot's
    /// lines report it and because a lease's renewal compares it; the table is
    /// what a **send** asks.  Two facts rather than one because they answer
    /// different questions: the gateway is what a lease said, and the table is
    /// what this machine will do, and a route added by another advertisement
    /// or by a program does not change the lease.
    routes: net::route::Table,
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
    /// it when this was first written, the ARP exchange's lines disappeared
    /// and the boot still exited zero.  Three is all a link-local-only
    /// interface has; a global address adds its own group at the point a
    /// router configures it.
    ipv6_groups: [net::ipv6::Addr; 3],
    /// What the wire has answered about its IPv6 neighbours.
    ndp: net::ndp::Cache,
    /// A global address a router's advertisement configured, if one has.
    ipv6_global: Option<net::ipv6::Addr>,
    /// The name server a lease named, if one did.
    ///
    /// Kept here rather than in a socket because it is a fact about this
    /// machine's network, and a lookup asks it once per name.
    dns: Option<[u8; 4]>,
    /// The default router a router advertisement named, if one has.
    ///
    /// IPv6 has no configured default route the way IPv4's DHCP hands one out:
    /// a router says it exists with an advertisement, and the source address of
    /// that advertisement is the address a host sends off-link traffic to.
    /// Zero lifetime is a router saying it is **not** a default router, which
    /// is why the lifetime is checked rather than the message's arrival.
    ipv6_router: Option<net::ipv6::Addr>,
    /// The lease this interface is running under, if the address came from
    /// one.
    ///
    /// Kept because an address a server granted is the server's to take back:
    /// without the lease, a boot's address would outlive the grant that made
    /// it, and a second machine granted the same address would find it in
    /// use.  The lease's clocks are in the caller's unit, microseconds here,
    /// and [`net::dhcp::Lease::duty`] is what reads them.
    lease: Option<net::dhcp::Lease>,
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
        // The one route a boot has: everything goes to the gateway.  A
        // **connected** subnet is deliberately not seeded from the address's
        // class, which the first version of this did: classful addressing is
        // not what any network this stack meets uses, and a `/8` guessed from
        // `10.x` would make every host in a private cloud "on the link" and
        // send frames to addresses no neighbour answers for.  What adds a
        // connected route is a lease that carries a subnet mask, or an
        // advertisement that carries a prefix, and both state the length
        // rather than guessing it.
        let mut routes = net::route::Table::new();
        routes.add(net::route::default_via(net::address::Address::V4(gateway)));

        Self {
            card,
            hardware,
            protocol,
            gateway,
            routes,
            arp: net::arp::Cache::new(),
            ipv6,
            ipv6_groups,
            ndp: net::ndp::Cache::new(),
            ipv6_global: None,
            ipv6_router: None,
            dns: None,
            lease: None,
        }
    }

    /// The protocol address this interface answers for.
    pub fn protocol(&self) -> [u8; 4] {
        self.protocol
    }

    /// Take the address, the gateway and the name server a lease granted.
    ///
    /// The three arrive together because a lease is one decision: an address
    /// with the old gateway is a machine that sends half its traffic to a
    /// router it is not attached to.  The name server is stored beside them
    /// because it is what the resolver asks, and a boot whose server is not on
    /// this link has no way to reach one.
    pub fn configure(&mut self, lease: &net::dhcp::Lease) {
        self.protocol = lease.address;
        if let Some(router) = lease.router {
            self.gateway = router;
        }
        self.dns = lease.dns;
        // The lease itself is kept, because its clocks are what say when this
        // address has to be asked for again.
        self.lease = Some(*lease);
    }

    /// Whether an IPv6 destination is on this link.
    ///
    /// Two answers, and both are facts the interface already holds.  A
    /// link-local address is by definition here, on the link the interface's
    /// own link-local address is on.  A global address is here when it shares
    /// its first sixty-four bits with the one a router configured: IPv6's
    /// subnet boundary is sixty-four bits for every address this stack is
    /// given, which is what a router advertisement's prefix is.
    ///
    /// An interface with no global address yet has only its link: nothing else
    /// can be reached without a router, and an off-link destination is one the
    /// router has to answer for.
    fn is_on_link(&self, destination: net::ipv6::Addr) -> bool {
        if net::ipv6::is_link_local(destination) {
            return true;
        }
        match self.ipv6_global {
            Some(global) => net::ndp::same_prefix(global, destination, 64),
            None => false,
        }
    }

    /// The link-local IPv6 address this interface answers for.
    pub fn ipv6(&self) -> net::ipv6::Addr {
        self.ipv6
    }

    /// The global IPv6 address a router configured, if one has.
    pub fn ipv6_global(&self) -> Option<net::ipv6::Addr> {
        self.ipv6_global
    }

    /// The name server a lease named, if one did.
    pub fn dns(&self) -> Option<[u8; 4]> {
        self.dns
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

/// Take the address, the gateway and the name server a lease granted.
///
/// A no-op on a machine with no interface, which is the same answer every
/// other call here gives: nothing was installed, so there is nothing to
/// configure.
pub fn configure(lease: &net::dhcp::Lease) {
    if let Some(interface) = INTERFACE.lock().as_mut() {
        interface.configure(lease);
    }
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

/// This machine's name, if a program set one.
///
/// A fixed array behind the same lock the interface uses, and for the same
/// reason: a name is a fact about this boot's machine, and the one place that
/// answers questions about the machine is here.  An empty length is "no name",
/// which `GetHostName` reports as an empty string rather than an error: a
/// machine that was never named is not a machine whose name is missing, and a
/// caller that treated the two the same would fail to start on a machine that
/// simply had not been told.
static HOST_NAME: Mutex<HostName> = Mutex::new(HostName::new());

/// The name a program set, or none.
struct HostName {
    bytes: [u8; abi::network::HOST_NAME_MAX],
    len: usize,
}

impl HostName {
    const fn new() -> Self {
        Self {
            bytes: [0; abi::network::HOST_NAME_MAX],
            len: 0,
        }
    }
}

/// Set this machine's name.
///
/// The name is copied rather than borrowed: a caller's buffer is the caller's,
/// and a stored pointer into it would outlive the call that passed it.  A name
/// too long for the ABI's bound is refused rather than truncated, because a
/// truncated name is a different name.
pub fn set_host_name(name: &[u8]) -> Result<()> {
    if name.len() > abi::network::HOST_NAME_MAX {
        return Err(Error::InvalidArgument);
    }
    // A name is text a program will print, so the bytes are checked here
    // rather than at every reader: a name with a control character in it is a
    // program's output being rewritten by the name it set.
    if !name
        .iter()
        .all(|byte| byte.is_ascii_graphic() || *byte == b'-' || *byte == b'.')
    {
        return Err(Error::InvalidArgument);
    }
    let mut stored = HOST_NAME.lock();
    stored.bytes[..name.len()].copy_from_slice(name);
    stored.bytes[name.len()..].fill(0);
    stored.len = name.len();
    Ok(())
}

/// This machine's name, as many bytes as it has.
pub fn host_name(into: &mut [u8]) -> Result<usize> {
    let stored = HOST_NAME.lock();
    if into.len() < stored.len {
        return Err(Error::InvalidArgument);
    }
    into[..stored.len].copy_from_slice(&stored.bytes[..stored.len]);
    Ok(stored.len)
}

/// Where a stream of this caller's is, which end is asked for.
pub enum SocketEnd {
    /// The address this machine's end answers on.
    Local,
    /// The address the peer is.
    Peer,
}

/// Ask a stream or a datagram socket where one of its ends is.
///
/// The answer is a [`abi::network::SockAddrIn`], and only a four-byte address
/// fits it: a socket over IPv6 answers `Unsupported`, which is what this ABI's
/// call has always meant for an address its record cannot hold.  The port is
/// the caller's own for [`SocketEnd::Local`] and the peer's for
/// [`SocketEnd::Peer`], and a datagram socket has no peer at all because it
/// never connected to one.
pub fn socket_address(
    port: u16,
    peer: Option<(net::address::Address, u16)>,
    end: SocketEnd,
) -> Result<abi::network::SockAddrIn> {
    let interface = INTERFACE.lock();
    let interface = interface.as_ref().ok_or(Error::NotFound)?;
    let (address, port) = match end {
        SocketEnd::Local => (interface.protocol, port),
        SocketEnd::Peer => match peer {
            Some((net::address::Address::V4(address), port)) => (address, port),
            // A datagram socket has no peer, and a stream over IPv6 has one
            // this record cannot hold.
            _ => return Err(Error::Unsupported),
        },
    };
    Ok(abi::network::SockAddrIn {
        family: abi::network::SOCKADDR_IN_FAMILY,
        port: port.to_be_bytes(),
        address,
        padding: [0; 8],
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

/// One datagram socket: a bound port and the queue of what arrived for it.
///
/// The `Arc` is the socket's life: the descriptor table holds one, the port
/// table holds a `Weak`, and the socket lives while either is alive, which
/// is what makes a fork's copy of a descriptor keep the bound port
/// routable, and the last close take it off the wire.
///
/// The queue itself is [`net::udp_socket::Queue`]: the ordering, the bound
/// and the too-small-buffer rule are the wire's, and a host test can run them
/// without a card.  What is here is the lock two callers share and the port
/// the demux routes by.
pub struct UdpSocket {
    port: u16,
    queue: Mutex<net::udp_socket::Queue>,
    /// What a program changed about this socket, by `SetSockOpt`.
    ///
    /// A datagram socket acts on one of the four: `SO_REUSEADDR`, whose effect
    /// is at the bind and so is spent by the time the socket exists.  The
    /// options are kept anyway, because `GetSockOpt` has to answer what the
    /// program set and a socket that remembered only the one it acted on would
    /// answer the default for the rest.
    options: Mutex<net::options::Options>,
}

impl UdpSocket {
    /// The port the socket is bound to.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// The options a program may read and change.
    pub fn set_option(&self, level: u32, name: u32, value: &[u8]) -> Result<()> {
        self.options.lock().set(level, name, value)
    }

    /// Read one option into `into`, answering how many bytes were written.
    pub fn get_option(&self, level: u32, name: u32, into: &mut [u8]) -> Result<usize> {
        self.options.lock().get(level, name, into)
    }

    /// Take the next datagram the queue holds, answering where it came from
    /// and how many bytes of it fit in `into`.
    ///
    /// `None` is "nothing arrived, ask again", the answer a caller parks on.
    /// A datagram longer than `into` is refused with the datagram **kept**:
    /// a caller whose buffer is small learns that from the error and asks
    /// again with a larger one, and a take that discarded the bytes would
    /// make the loss permanent.
    pub fn try_recv(&self, into: &mut [u8]) -> Result<Option<(net::address::Address, u16, usize)>> {
        Ok(self
            .queue
            .lock()
            .take(into)?
            .map(|taken| (taken.source, taken.source_port, taken.count)))
    }

    /// Put one datagram in the queue, or refuse when it is full.
    fn push(&self, source: net::address::Address, source_port: u16, bytes: &[u8]) -> Result<()> {
        self.queue.lock().push(source, source_port, bytes)
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
/// again by the time the next bind looks, and never as its own pass,
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
        queue: Mutex::new(net::udp_socket::Queue::new()),
        options: Mutex::new(net::options::Options::new()),
    });
    sockets.push((port, Arc::downgrade(&socket)));
    Ok(socket)
}

/// The raw sockets a machine holds, keyed by the protocol number each names.
///
/// A `Weak` per entry, for the reason the datagram table's is: a socket's life
/// is its descriptors', and a protocol nothing holds a socket for is a protocol
/// the demux delivers nothing for.  Several sockets may name one protocol,
/// which is not the rule a bound port has: a raw socket is a **reader** of the
/// internet layer, and two programs watching ICMP are two readers of one stream
/// rather than two owners of one port.
static RAW_SOCKETS: Mutex<Vec<(u8, Weak<RawSocket>)>> = Mutex::new(Vec::new());

/// One raw socket, as a program holds it: its protocol and its queue.
///
/// The queue is behind a lock of its own because two contexts reach it, the
/// demux on one CPU and the program's receive call on another, and the
/// registry's lock is held only for the length of a lookup.  A per-socket lock
/// is also what keeps two programs watching one protocol from serialising on
/// the table: they share the lookup and not the queue.
pub struct RawSocket {
    protocol: u8,
    queue: Mutex<net::raw::Socket>,
}

impl RawSocket {
    /// The protocol number this socket answers for.
    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    /// Queue one packet, answering whether it was kept.
    fn deliver(&self, source: net::address::Address, payload: &[u8]) -> bool {
        self.queue.lock().deliver(source, payload)
    }

    /// Take the oldest packet into `into`.
    pub fn try_recv(&self, into: &mut [u8]) -> Result<Option<(net::address::Address, usize)>> {
        self.queue.lock().take(into)
    }
}

/// Create a raw socket for `protocol`, answering it.
///
/// Protocol zero is refused before this is reached, at the handler: it is the
/// IP header's "no protocol", and a socket bound to it would receive every
/// packet this machine accepts.
pub fn create_raw_socket(protocol: u8) -> Result<Arc<RawSocket>> {
    let mut sockets = RAW_SOCKETS.lock();
    sockets.retain(|(_, socket)| socket.upgrade().is_some());
    let socket = Arc::new(RawSocket {
        protocol,
        queue: Mutex::new(net::raw::Socket::new(protocol)),
    });
    sockets.push((protocol, Arc::downgrade(&socket)));
    Ok(socket)
}

/// Hand one packet to every raw socket bound to its protocol.
///
/// Answers how many sockets kept it, which is what the demux reports: a packet
/// whose protocol a program is watching was delivered, and one nothing watches
/// was not.  A socket whose queue is full drops it and is not counted, because
/// a delivery count that included a drop would overstate what a program can
/// read.
fn deliver_raw(protocol: u8, source: net::address::Address, payload: &[u8]) -> usize {
    let mut sockets = RAW_SOCKETS.lock();
    sockets.retain(|(_, socket)| socket.upgrade().is_some());
    let mut kept = 0;
    for (bound, socket) in sockets.iter() {
        if *bound != protocol {
            continue;
        }
        let Some(socket) = socket.upgrade() else {
            continue;
        };
        if socket.deliver(source, payload) {
            kept += 1;
        }
    }
    kept
}

/// Send `payload` as `protocol` to `destination`, answering the bytes sent.
///
/// The header is written here and not by the caller, which is the decision this
/// whole mechanism turns on: a program that wrote its own header would choose
/// its own source address and its own length, and every field the stack is
/// responsible for would become a program's.  What the program chooses is the
/// **protocol number** and the payload.
///
/// A destination that is this machine is delivered through the demux, the same
/// loopback a datagram send takes, so a program's raw send and its own raw
/// receive meet without the card.
pub fn send_raw_packet(
    protocol: u8,
    destination: net::address::Address,
    payload: &[u8],
) -> Result<usize> {
    if is_loopback(destination) {
        // The frame is built and handed to the **demux**, not to the socket:
        // a loopback that delivered straight to the queue would exercise
        // nothing but the queue, and the header this stack composes would be
        // the one thing a raw send must get right.  Building it and parsing it
        // back is the same path a frame from the card takes, which is what
        // makes this a loopback rather than a shortcut.
        // The two fields are read and the lock released **before** the demux
        // runs: the demux takes the socket table and the scheduler's lock, and
        // a raw receive it wakes would otherwise re-enter this one.
        let (hardware, local) = {
            let interface = INTERFACE.lock();
            let Some(interface) = interface.as_ref() else {
                return Err(Error::NotFound);
            };
            (interface.hardware, interface.protocol)
        };
        match destination {
            net::address::Address::V4(destination) => {
                let packet_len =
                    netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + payload.len();
                let mut frame = alloc::vec![0; packet_len];
                net::ethernet::write_header(
                    &mut frame,
                    hardware,
                    hardware,
                    net::ethernet::ETHERTYPE_IPV4,
                );
                net::ipv4::write_header(
                    &mut frame[netdev::ETHERNET_HEADER_LEN..],
                    local,
                    destination,
                    protocol,
                    // The payload **after** the header: the writer adds the
                    // header's own length to this, and passing the total made
                    // the packet claim forty bytes it did not have, which
                    // `parse` refused for a length mismatch and the receive
                    // saw as a packet that never arrived.
                    payload.len(),
                );
                frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..]
                    .copy_from_slice(payload);
                demux(&frame, local);
                Ok(payload.len())
            }
            // A raw send over IPv6 would have to write the extension-header
            // chain, which this stack's IPv6 sender does not do for any of its
            // own transports either.
            net::address::Address::V6(_) => Err(Error::Unsupported),
        }
    } else {
        let interface = INTERFACE.lock();
        let Some(interface) = interface.as_ref() else {
            return Err(Error::NotFound);
        };
        let (hardware, local) = (interface.hardware, interface.protocol);
        let card = interface.card.clone();
        match destination {
            net::address::Address::V4(destination) => {
                let gateway_hardware = hardware_for_v4(interface, destination)?;
                let packet_len =
                    netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + payload.len();
                let mut frame = alloc::vec![0; packet_len];
                net::ethernet::write_header(
                    &mut frame,
                    gateway_hardware,
                    hardware,
                    net::ethernet::ETHERTYPE_IPV4,
                );
                net::ipv4::write_header(
                    &mut frame[netdev::ETHERNET_HEADER_LEN..],
                    local,
                    destination,
                    protocol,
                    payload.len(),
                );
                frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..]
                    .copy_from_slice(payload);
                card.submit_frame(&frame)?;
                Ok(payload.len())
            }
            // A raw socket over IPv6 would have to write the extension-header
            // chain, which this stack's IPv6 sender does not do for any of its
            // own transports either.  The refusal is `Unsupported` and not a
            // silent IPv4-shaped packet.
            net::address::Address::V6(_) => Err(Error::Unsupported),
        }
    }
}

/// The hardware address a frame for `destination` goes to, IPv4.
///
/// The route table decides, and the answer has three shapes a caller must not
/// confuse:
///
/// * a route with a gateway, whose hardware address the ARP cache holds, is
///   "send it to the router";
/// * a route with **no** gateway is a destination on this link, and the frame
///   goes to the destination's own hardware address;
/// * no route at all is a destination this machine cannot reach, which is
///   `NotFound` and not a guess.
///
/// The version before this asked the ARP cache for the interface's one
/// gateway and nothing else, which is the same answer for every destination
/// and wrong for every one on the link.
fn hardware_for_v4(interface: &Interface, destination: [u8; 4]) -> Result<[u8; 6]> {
    let next_hop = interface
        .routes
        .next_hop(net::address::Address::V4(destination))
        .ok_or(Error::NotFound)?;
    // A gateway the machine has not resolved yet is a frame with nowhere to
    // go, which is the same answer as a destination with no route: the caller
    // retries, and the ARP exchange the send itself starts fills the cache.
    let target = match next_hop {
        Some(net::address::Address::V4(gateway)) => gateway,
        Some(net::address::Address::V6(_)) => return Err(Error::Unsupported),
        None => destination,
    };
    interface.arp.hardware_for(target).ok_or(Error::NotFound)
}

/// Whether an IPv4 `destination` names this machine, and the packet is
/// delivered through the demux rather than the card.
///
/// The interface's own address, and the loopback network every IP stack
/// shares: a datagram to either is this machine's conversation with itself.
fn is_loopback_v4(destination: [u8; 4]) -> bool {
    let interface = INTERFACE.lock();
    let Some(interface) = interface.as_ref() else {
        return false;
    };
    destination == interface.protocol || destination[0] == 127
}

/// Whether an address of either family names this machine.
///
/// The IPv6 side has no `127`-shaped range to inherit: a link-local or global
/// address this interface holds is the only thing that makes it this machine,
/// and a global one a router configured counts for the same reason.
fn is_loopback(destination: net::address::Address) -> bool {
    match destination {
        net::address::Address::V4(bytes) => is_loopback_v4(bytes),
        net::address::Address::V6(bytes) => {
            let interface = INTERFACE.lock();
            let Some(interface) = interface.as_ref() else {
                return false;
            };
            bytes == interface.ipv6 || interface.ipv6_global == Some(bytes)
        }
    }
}

/// What a delivery did, which is three different facts the caller acts on
/// differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// A socket took it, and this many tasks were woken by it, zero when
    /// nobody was parked on the socket, which is a fact and not a failure.
    Queued(usize),
    /// No socket owns the port, which is the one case a sender can be told
    /// about: [RFC 792]'s port-unreachable names a port that does not exist,
    /// and this is how a caller learns the port does not exist.
    ///
    /// [RFC 792]: https://www.rfc-editor.org/rfc/rfc792
    Unbound,
}

/// Deliver one datagram to the socket bound for it, and wake what waits.
///
/// The source is the wire's answer to "who sent this".  A datagram for a
/// port nothing owns answers [`Delivery::Unbound`] rather than an error:
/// delivering it is not this call's failure, and the answer is what a caller
/// turns into the report the sender is owed.
pub fn deliver_udp(
    destination: net::address::Address,
    destination_port: u16,
    source: net::address::Address,
    source_port: u16,
    bytes: &[u8],
) -> Result<Delivery> {
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
        return Ok(Delivery::Unbound);
    };
    socket.push(source, source_port, bytes)?;

    // A datagram in a queue is what a parked receive was waiting for, so
    // this is where the wake belongs, the same one a pipe's write makes,
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
    Ok(Delivery::Queued(woken))
}

/// Send one datagram out through the interface, to `destination`'s port.
///
/// A datagram addressed to this machine is delivered through the demux
/// instead, which is what loopback is: the sender's call and the receiver's
/// answer meet at the port table, not on the wire.  For anyone else, the
/// gateway's hardware address comes from the ARP cache, which is this
/// build's whole routing decision, one interface, one gateway, and every
/// datagram for another machine leaves by it.  A cache with no answer is
/// `NotFound`, because a frame with no destination address is a frame the
/// card cannot carry.
pub fn send_datagram(
    destination: net::address::Address,
    destination_port: u16,
    source_port: u16,
    bytes: &[u8],
) -> Result<()> {
    if is_loopback(destination) {
        let local = {
            let interface = INTERFACE.lock();
            let Some(interface) = interface.as_ref() else {
                return Err(Error::NotFound);
            };
            match destination {
                net::address::Address::V4(_) => net::address::Address::V4(interface.protocol),
                net::address::Address::V6(_) => net::address::Address::V6(interface.ipv6),
            }
        };
        // The sender the datagram names is this machine: the wire would have
        // seen the frame leave with this address, and the receiver's answer
        // says the same thing.
        return deliver_udp(destination, destination_port, local, source_port, bytes).map(|_| ());
    }

    let interface = INTERFACE.lock();
    let Some(interface) = interface.as_ref() else {
        return Err(Error::NotFound);
    };
    let (hardware, protocol) = (interface.hardware, interface.protocol);
    let card = interface.card.clone();

    let udp_len = net::udp::datagram_len(bytes.len());
    match destination {
        net::address::Address::V4(destination) => {
            let gateway_hardware = hardware_for_v4(interface, destination)?;
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
        net::address::Address::V6(destination) => {
            let destination_hardware = peer_hardware(destination);
            let local = interface.ipv6;
            let packet_len = netdev::ETHERNET_HEADER_LEN + net::ipv6::HEADER_LEN + udp_len;
            let mut frame = alloc::vec![0; packet_len];
            net::ethernet::write_header(
                &mut frame,
                destination_hardware,
                hardware,
                net::ethernet::ETHERTYPE_IPV6,
            );
            net::ipv6::write_header(
                &mut frame[netdev::ETHERNET_HEADER_LEN..],
                local,
                destination,
                net::ipv6::NEXT_UDP,
                udp_len,
            );
            net::udp::write_datagram6(
                &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv6::HEADER_LEN..],
                local,
                destination,
                source_port,
                destination_port,
                bytes,
            );
            card.submit_frame(&frame)
        }
    }
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

    // Time first, because what a stream is due to send again is measured
    // against it, and a pump that drained the card before telling the table
    // the time would retransmit one pump late.  The tick is a hundred
    // microseconds, which is `TIME_SLICE_US`, so a count of ticks times a
    // hundred is microseconds, saturating rather than wrapping at the
    // counter's own thirty-six-hour wrap.
    let now = micros_since_boot();
    retransmit_due(now);
    // The lease's clock, checked on the path that already runs while a
    // program waits: a machine whose only activity is a parked reader still
    // has a lease running out.
    #[cfg(target_os = "none")]
    renew_lease_if_due();

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

/// The boot's clock in microseconds, for a protocol that measures durations.
///
/// The conversion is [`micros_of_ticks`]'s, so this and the fragment cache's
/// clock are one arithmetic rather than two: they disagreed once, one
/// measuring ticks and one a duration, and the disagreement was a timeout a
/// hundred times shorter than the constant describing it.
fn micros_since_boot() -> u64 {
    #[cfg(target_os = "none")]
    {
        let ticks = crate::tick::TIMER_TICKS.load(core::sync::atomic::Ordering::Relaxed) as u64;
        micros_of_ticks(ticks)
    }
    // A host test has no timer, and a connection that is never told the time
    // never retransmits, which is what a loopback wire wants.
    #[cfg(not(target_os = "none"))]
    {
        0
    }
}

/// A count of timer interrupts, as elapsed microseconds.
///
/// `saturating_mul` and not `*`: the product is the one a `u64` would wrap at
/// an uptime long enough that the wrap is not the interesting number.
///
/// A free function rather than three lines inside the two callers, because the
/// arithmetic is the thing that was wrong once: the caller handed the fragment
/// cache raw ticks and the cache's constant was a duration, and no test could
/// see the join because the cache's tests measured against a clock they
/// supplied.  This is the join.
#[cfg(any(test, target_os = "none"))]
fn micros_of_ticks(ticks: u64) -> u64 {
    ticks.saturating_mul(MICROS_PER_TICK)
}

/// How long one timer interrupt is, in microseconds.
///
/// The same value [`crate::tick::TIME_SLICE_US`] carries on a machine, and
/// deliberately a second name: a host test compiles `tick` with no timer and
/// no slice, so the assertion that the two agree is a test's.
#[cfg(any(test, target_os = "none"))]
const MICROS_PER_TICK: u64 = 100;

/// How many microseconds a second is, which is the scale a lease's seconds
/// are converted into this kernel's clock with.
///
/// A DHCP reply states its lifetime in seconds and `Lease::duty` compares it
/// against the caller's clock, so the conversion has to be the caller's own
/// unit or the lease expires at the wrong time.  The first version passed `1`
/// here, which left the lease in seconds while the clock counted
/// microseconds: a lease an hour long would have been read as expired
/// eighty-six milliseconds after it was granted.
#[cfg(any(test, target_os = "none"))]
const MICROS_PER_SECOND: u64 = 1_000_000;

/// Send again every segment whose stream is due to.
///
/// Runs inside [`pump`], before the card is drained: a stream whose segment
/// was lost is exactly a stream whose answer is not on the card, so the only
/// thing that moves it forward is this call.
///
/// The lock discipline is `tcp_exchange`'s, and for its reason: the table's
/// lock is taken, the segments are queued, the exchange delivers them and
/// collects the answers, and every wake happens after the lock is down.
fn retransmit_due(now: u64) {
    let noteworthy = {
        let mut table = TCP.lock();
        table.advance(now);
        let queue = table.retransmissions();
        let sent = !queue.is_empty();
        let found = if queue.is_empty() {
            false
        } else {
            tcp_exchange(&mut table, queue).unwrap_or(false)
        };
        // A stream that was abandoned has nothing left to send and its entry
        // is `Closed`; the prune is what makes the next read answer end of
        // file rather than a stream that will never move again.
        table.prune();
        sent | found
    };
    note_stream_wake(noteworthy);
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

    if packet.header.protocol == net::ipv4::PROTOCOL_UDP
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
    if packet.header.protocol == net::ipv4::PROTOCOL_ICMP {
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
        packet.header.protocol,
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
fn payload_for(mtu: usize) -> usize {
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
fn quoted_report(our_address: [u8; 4], error: &net::icmp::Error, payload: &[u8]) -> Option<Report> {
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
struct Report {
    /// The peer's address and port.
    remote: (net::address::Address, u16),
    /// This machine's own port.
    local_port: u16,
}

/// The ports a report's quoted transport header names.
///
/// A report must quote the original's header and the first eight bytes of its
/// payload, and for both transports those eight bytes begin with the two
/// ports, which is what makes a four-tuple readable from a quotation.  The
/// ports are read here rather than through `udp::parse` or `tcp::parse`
/// because the quote has no checksum to verify: it is a fragment of a packet
/// by construction, and a parser that demanded one would refuse every report.
fn quoted_segment(protocol: u8, transport: &[u8]) -> Option<Ports> {
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
struct Ports {
    source_port: u16,
    destination_port: u16,
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
fn port_unreachable_frame(
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
fn peer_hardware(destination: net::ipv6::Addr) -> [u8; 6] {
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
#[cfg(target_os = "none")]
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
/// re-entrant, a segment delivered to a peer's state machine is answered
/// inside the same call, and a per-connection lock is a deadlock the first
/// full-duplex exchange would find.
/// The pieces of fragmented datagrams this machine is holding, and the clock
/// they expire on.
///
/// The cache is `net`'s, the bounds, the overlap rule and the completion
/// test are the wire's, and what is here is the lock and the tick it is
/// given.  A piece is memory a peer spends by sending, which is why the
/// bound lives beside the arithmetic rather than at this call site.
static FRAGMENTS: Mutex<net::reassembly::Cache> = Mutex::new(net::reassembly::Cache::new());

/// The clock the fragment cache expires against.
///
/// The same clock the retransmission schedule uses, and deliberately the same
/// function rather than a second conversion: the two used to disagree, one
/// measuring ticks and one measuring a duration, and the disagreement was a
/// timeout a hundred times shorter than the constant describing it.  A cache
/// with no clock could not expire anything, and a peer that never sent its
/// last piece would hold its entry for the rest of the boot.
fn fragment_now() -> u64 {
    micros_since_boot()
}

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
/// listener holds nothing, which is the caller's signal to park, the same
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
/// wire, which is a wait this build does not make a call do, the answer
/// for a destination that is not this machine is `Unsupported`, and the
/// exchange that proves the layer runs where the proof is, on loopback.
pub fn tcp_connect(destination: net::address::Address, destination_port: u16) -> Result<usize> {
    // A connect whose peer is not this machine would have to wait for its
    // answer on the wire, which is a wait this build does not make a call do.
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

/// Where a stream's two ends are: this machine's own port and the peer.
///
/// One call rather than two because the two are a single fact about one
/// connection and a caller asking for both would otherwise take the lock twice.
pub fn stream_ends(id: usize) -> Option<(u16, (net::address::Address, u16))> {
    let table = TCP.lock();
    let connection = table.connection(id)?;
    Some((connection.local_port(), connection.remote()))
}

/// Set one option on a stream, answering what the connection answered.
///
/// The table's lock is taken once and released before the caller returns: a
/// setter does not send, so nothing here re-enters the demux, and the option's
/// effect is on the next segment the connection builds rather than on one in
/// flight.
pub fn set_stream_option(id: usize, level: u32, name: u32, value: &[u8]) -> Result<()> {
    let mut table = TCP.lock();
    let connection = table.connection_mut(id).ok_or(Error::NotFound)?;
    connection.set_option(level, name, value)
}

/// Read one option from a stream, answering the bytes written.
pub fn stream_option(id: usize, level: u32, name: u32, into: &mut [u8]) -> Result<usize> {
    let table = TCP.lock();
    let connection = table.connection(id).ok_or(Error::NotFound)?;
    connection.get_option(level, name, into)
}

/// Whether a stream has bytes its reader has not taken.
pub fn tcp_has_data(id: usize) -> bool {
    TCP.lock().has_data(id)
}

/// Read bytes off a stream, answering how many.
///
/// `None` is "nothing arrived, ask again", the answer a caller parks on,
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
        // An empty inbox is "ask again" only while a peer could still fill
        // it.  A stream whose close is over cannot, so its empty read is
        // end-of-file: `TimeWait` is the state that made this distinction
        // necessary, because the entry is still in the table and a reader
        // parked on it would otherwise wait for a writer that has finished.
        return Ok(match connection.state() {
            net::tcp::State::TimeWait | net::tcp::State::Closed => Some(0),
            _ => None,
        });
    }
    Ok(Some(connection.take(into)))
}

/// Close a stream: the FIN, the peer's, and the acknowledgements that cross
/// between them.
///
/// A close of an id that names nothing is `Ok`, because the close already
/// happened, the orderly one this call ran, or the abrupt one a process's
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
/// the parked caller's retry answers, and the IPI, for the reason every
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
/// difference between the two wires, the state machine never learns which
/// one carried its bytes.
fn tcp_exchange(
    table: &mut net::tcp_table::Table,
    queue: Vec<(usize, net::tcp::Outgoing)>,
) -> Result<bool> {
    // Whether anything happened that a parked caller was waiting for: a
    // connection a SYN opened, bytes that landed in a stream's inbox, a
    // finish that ends a read.  The answer comes back to the caller, which
    // wakes **after** this function returns, the table's lock is its
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
            let interface = INTERFACE.lock();
            let Some(interface) = interface.as_ref() else {
                return Err(Error::NotFound);
            };
            // The address this machine's own end of a loopback exchange is
            // known by: the protocol address for IPv4, the link-local one for
            // IPv6, which is the address a solicitation is answered from.
            let local = match address {
                net::address::Address::V4(_) => net::address::Address::V4(interface.protocol),
                net::address::Address::V6(_) => net::address::Address::V6(interface.ipv6),
            };
            // A SYN for a listening port opens a connection right here: the
            // listener answers inside the same exchange, whose SYN with ACK
            // queues behind this one, and the connection waits in the
            // listener's pending list for the accept that takes it.
            if outgoing.flags & net::tcp::FLAG_SYN != 0
                && outgoing.flags & net::tcp::FLAG_ACK == 0
                && table
                    .connection_for(destination_port, local, sender_port)
                    .is_none()
            {
                let Some((id, replies)) = table.accept_syn(
                    &net::tcp::Segment::new(
                        sender_port,
                        destination_port,
                        outgoing.sequence,
                        outgoing.acknowledgement,
                        outgoing.flags,
                        outgoing.window,
                        outgoing.payload.len(),
                    ),
                    (local, sender_port),
                ) else {
                    // A SYN for a port nothing listens on: dropped, the way
                    // a datagram for an unbound port is.
                    continue;
                };
                noteworthy = true;
                queue.extend(replies.into_iter().map(|reply| (id, reply)));
                continue;
            }
            let Some(peer_id) = table.connection_for(destination_port, local, sender_port) else {
                // A segment for a stream this table does not hold: the peer
                // is gone, and a wire that carried the segment would be a
                // wire talking to nobody.  Dropped, the way a segment to a
                // closed port is.
                continue;
            };
            // The window the segment advertises, read from the segment rather
            // than restated: it is what the sender's own buffers had room for
            // at the moment it was built.  A segment the loopback carries
            // states no receive buffer, so `Segment::new`'s "nothing said" is
            // right for it: the option is a handshake's and the connection
            // learned this side's MSS when the SYN that opened it arrived.
            let segment = net::tcp::Segment::new(
                sender_port,
                destination_port,
                outgoing.sequence,
                outgoing.acknowledgement,
                outgoing.flags,
                outgoing.window,
                outgoing.payload.len(),
            );
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
    address: net::address::Address,
    destination_port: u16,
    outgoing: &net::tcp::Outgoing,
) -> Result<()> {
    let _ = table;
    let interface = INTERFACE.lock();
    let Some(interface) = interface.as_ref() else {
        return Err(Error::NotFound);
    };
    let (our_hardware, our_protocol) = (interface.hardware, interface.protocol);
    // A SYN carries the MSS option and every other segment does not, so the
    // header's length is the segment's and not a constant: a frame sized by
    // `HEADER_LEN` for a SYN is four bytes short, and the writer's option
    // would run past it.
    let header = if outgoing.flags & net::tcp::FLAG_SYN != 0 {
        net::tcp::SYN_HEADER_LEN
    } else {
        net::tcp::HEADER_LEN
    };
    let tcp_len = header + outgoing.payload.len();
    match address {
        net::address::Address::V4(destination) => {
            // The gateway's hardware address is this build's whole routing
            // decision for IPv4: one interface, one gateway.
            let gateway_hardware = hardware_for_v4(interface, destination)?;
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
                destination,
                net::ipv4::PROTOCOL_TCP,
                tcp_len,
            );
            net::tcp::write_segment(
                &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..],
                our_protocol,
                destination,
                sender_port,
                destination_port,
                outgoing.sequence,
                outgoing.acknowledgement,
                outgoing.flags,
                outgoing.window,
                &outgoing.payload,
            );
            interface.card.submit_frame(&frame)
        }
        net::address::Address::V6(destination) => {
            // No router address to route by yet: an IPv6 packet for another
            // machine goes to the neighbour cache's answer for its own
            // address, which is the neighbour discovery this stack has.
            let destination_hardware = peer_hardware(destination);
            let local = interface.ipv6;
            let packet_len = netdev::ETHERNET_HEADER_LEN + net::ipv6::HEADER_LEN + tcp_len;
            let mut frame = alloc::vec![0; packet_len];
            net::ethernet::write_header(
                &mut frame,
                destination_hardware,
                our_hardware,
                net::ethernet::ETHERTYPE_IPV6,
            );
            net::ipv6::write_header(
                &mut frame[netdev::ETHERNET_HEADER_LEN..],
                local,
                destination,
                net::ipv6::NEXT_TCP,
                tcp_len,
            );
            net::tcp::write_segment6(
                &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv6::HEADER_LEN..],
                local,
                destination,
                sender_port,
                destination_port,
                outgoing.sequence,
                outgoing.acknowledgement,
                outgoing.flags,
                outgoing.window,
                &outgoing.payload,
            );
            interface.card.submit_frame(&frame)
        }
    }
}

/// What the pump does with a TCP segment: route it to the connection it
/// names, or open one for it on a listener.
///
/// The SYN's connection is created here, with the listener's answer sent
/// before the accept ever runs, which is why a client's connect completes
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
        let Some((id, outgoing)) = table.accept_syn(
            &segment,
            (
                net::address::Address::V4(packet.header.source),
                segment.source_port,
            ),
        ) else {
            return false;
        };
        let queued = outgoing.into_iter().map(|segment| (id, segment)).collect();
        let _ = tcp_exchange(&mut table, queued);
        // A connection opened is what a parked accept was waiting for.
        return true;
    }

    let Some(id) = table.connection_for(
        segment.destination_port,
        net::address::Address::V4(packet.header.source),
        segment.source_port,
    ) else {
        return false;
    };
    let noteworthy = table.has_data(id) || segment.flags & net::tcp::FLAG_FIN != 0;
    let connection = table
        .connection_mut(id)
        .expect("the id came from this table");
    // The segment's **data**, not the packet: `receive`'s second argument is
    // the peer's bytes, and handing it the whole packet put the segment's own
    // header at the front of the stream.  The offset is the parser's, and it is
    // why `Segment` carries one: a segment with options has its data past them,
    // and only the data offset knows where.  Both demux paths had this defect,
    // which no loopback exchange could show: the loopback hands a connection
    // the payload it built, never a frame.
    let data = &payload[segment.payload_at..segment.payload_at + segment.payload_len];
    let (answer, replies) = connection.receive(&segment, data);
    let _ = answer;
    if !replies.is_empty() {
        let queued = replies.into_iter().map(|segment| (id, segment)).collect();
        let _ = tcp_exchange(&mut table, queued);
    }
    // Anything the peer has waiting is what a parked reader was waiting
    // for, but the wake takes the scheduler's lock, and this function
    // holds the table's, so the answer is returned and the wake happens
    // where the lock is no longer held.
    noteworthy
}

/// Route one IPv6 segment, and wake what a parked reader was waiting for.
///
/// The wake is here rather than inside [`demux_tcp6`] because that function
/// holds the connection table's lock, and the scheduler's is never taken while
/// it is held: the routing answers whether anything a parked caller cares
/// about happened, the table's lock drops when that function returns, and this
/// one wakes after it.
fn route_stream6(packet: &net::ipv6::Packet, payload: &[u8]) {
    if !demux_tcp6(packet, payload) {
        return;
    }
    let woken = crate::scheduler::wake_blocked();
    #[cfg(target_os = "none")]
    if woken > 0 {
        // SAFETY: the boot's own IPI path, installed before any program ran.
        unsafe { arch::send_ipi_to_others() };
    }
    #[cfg(not(target_os = "none"))]
    let _ = woken;
}

/// What the pump does with a TCP segment that arrived over IPv6.
///
/// The same routing the IPv4 demux does, against the same table: a connection
/// is keyed by the port it answers on and the peer it answers for, and the
/// family is part of the peer because [`net::address::Address`] carries it.
/// A SYN for a listening port opens a connection; anything else joins one, and
/// a segment for a stream this table does not hold is dropped.
fn demux_tcp6(packet: &net::ipv6::Packet, payload: &[u8]) -> bool {
    let Some(segment) = net::tcp::parse6(payload, packet.header.source, packet.header.destination)
    else {
        return false;
    };
    let peer = net::address::Address::V6(packet.header.source);
    let mut table = TCP.lock();
    table.prune();

    if net::tcp_table::Table::is_opening(&segment) {
        let Some((id, outgoing)) = table.accept_syn(&segment, (peer, segment.source_port)) else {
            return false;
        };
        let queued = outgoing.into_iter().map(|segment| (id, segment)).collect();
        let _ = tcp_exchange(&mut table, queued);
        return true;
    }

    let Some(id) = table.connection_for(segment.destination_port, peer, segment.source_port) else {
        return false;
    };
    let noteworthy = table.has_data(id) || segment.flags & net::tcp::FLAG_FIN != 0;
    let connection = table
        .connection_mut(id)
        .expect("the id came from this table");
    // The same defect the IPv4 path had, and the same fix: the connection is
    // handed the segment's data, whose start only the data offset knows.
    let data = &payload[segment.payload_at..segment.payload_at + segment.payload_len];
    let (answer, replies) = connection.receive(&segment, data);
    let _ = answer;
    if !replies.is_empty() {
        let queued = replies.into_iter().map(|segment| (id, segment)).collect();
        let _ = tcp_exchange(&mut table, queued);
    }
    noteworthy
}

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
#[cfg(target_os = "none")]
pub fn resolve(name: &str, kind: u16) -> Option<net::address::Address> {
    let server = {
        let interface = INTERFACE.lock();
        interface.as_ref()?.dns()?
    };

    // A port for this lookup, taken from the ephemeral range the TCP side
    // uses and never reused while the socket is alive.  The socket owns the
    // queue the answer arrives in.
    let port = {
        static NEXT: core::sync::atomic::AtomicU16 = core::sync::atomic::AtomicU16::new(53_000);
        NEXT.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
    };
    let Ok(socket) = bind_udp(port) else {
        return None;
    };

    let mut id_bytes = [0_u8; 2];
    if crate::random::fill(&mut id_bytes).is_err() {
        return None;
    }
    let id = u16::from_be_bytes(id_bytes);

    let mut query = [0_u8; 300];
    let length = net::dns::write_query(&mut query, id, name, kind)?;
    send_datagram(
        net::address::Address::V4(server),
        53,
        port,
        &query[..length],
    )
    .ok()?;

    // One wait, bounded by the timer: a server on this link answers in
    // microseconds, so a second is generous and a boot with no server ends
    // with an answer rather than a hang.
    let deadline = crate::tick::TIMER_TICKS
        .load(core::sync::atomic::Ordering::Relaxed)
        .saturating_add(DHCP_WAIT_TICKS);
    let mut buffer = [0_u8; 512];
    while (crate::tick::TIMER_TICKS.load(core::sync::atomic::Ordering::Relaxed) as u64)
        < deadline as u64
    {
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
                    Ok(net::dns::Answer::Address { address, .. }) => return Some(address),
                    Ok(net::dns::Answer::NoSuchName) => return None,
                    Err(_) => continue,
                }
            }
            _ => continue,
        }
    }
    None
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
        let deadline = crate::tick::TIMER_TICKS
            .load(core::sync::atomic::Ordering::Relaxed)
            .saturating_add(DHCP_WAIT_TICKS);
        while (crate::tick::TIMER_TICKS.load(core::sync::atomic::Ordering::Relaxed) as u64)
            < deadline as u64
        {
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
    let deadline = crate::tick::TIMER_TICKS
        .load(core::sync::atomic::Ordering::Relaxed)
        .saturating_add(DHCP_WAIT_TICKS);
    while (crate::tick::TIMER_TICKS.load(core::sync::atomic::Ordering::Relaxed) as u64)
        < deadline as u64
    {
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
fn rebind_lease(lease: &net::dhcp::Lease) -> Option<net::dhcp::Lease> {
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
    let deadline = crate::tick::TIMER_TICKS
        .load(core::sync::atomic::Ordering::Relaxed)
        .saturating_add(DHCP_WAIT_TICKS);
    while (crate::tick::TIMER_TICKS.load(core::sync::atomic::Ordering::Relaxed) as u64)
        < deadline as u64
    {
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
fn apply_lease(lease: &net::dhcp::Lease, how: &str) {
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
fn renew_lease_if_due() {
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

/// How long one DHCP reply is waited for, in timer ticks.
///
/// Two seconds on a hundred-hertz clock.  A server on the same link answers in
/// microseconds, so this is generous by orders of magnitude; it exists so a
/// boot with no server ends with a line rather than a hung machine.
#[cfg(target_os = "none")]
const DHCP_WAIT_TICKS: usize = 200;

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
#[cfg(target_os = "none")]
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
#[cfg(target_os = "none")]
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
#[cfg(target_os = "none")]
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
#[cfg(target_os = "none")]
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
#[cfg(target_os = "none")]
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
#[cfg(target_os = "none")]
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
#[cfg(target_os = "none")]
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
#[cfg(target_os = "none")]
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
#[cfg(target_os = "none")]
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
#[cfg(target_os = "none")]
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
#[cfg(target_os = "none")]
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
#[cfg(target_os = "none")]
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
#[cfg(target_os = "none")]
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
#[cfg(target_os = "none")]
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
#[cfg(target_os = "none")]
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
#[cfg(target_os = "none")]
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
#[cfg(target_os = "none")]
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
    /// frames a test queues for it, the same shape a driver has, without a
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
    /// The two protocol addresses these tests speak between.
    const OUR_PROTOCOL: [u8; 4] = [10, 9, 9, 15];
    const PEER_PROTOCOL: [u8; 4] = [10, 9, 9, 2];

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
        let _ = deliver_udp(
            net::address::Address::V4([10, 0, 2, 2]),
            PORT_B,
            net::address::Address::V4([10, 0, 2, 9]),
            77,
            b"protofire",
        )
        .expect("a delivery");

        let mut buffer = [0_u8; 16];
        let (source, source_port, count) = socket
            .try_recv(&mut buffer)
            .expect("a receive")
            .expect("a datagram");
        assert_eq!(source, net::address::Address::V4([10, 0, 2, 9]));
        assert_eq!(source_port, 77);
        assert_eq!(count, 9);
        assert_eq!(&buffer[..count], b"protofire");
    }

    /// A datagram for a port nothing owns is dropped, because UDP promised
    /// nothing; the receive that follows answers nothing.
    #[test]
    fn a_datagram_for_an_unbound_port_is_dropped() {
        let woken = deliver_udp(
            net::address::Address::V4([10, 0, 2, 15]),
            PORT_E,
            net::address::Address::V4([10, 0, 2, 9]),
            77,
            b"nobody",
        )
        .expect("a delivery");
        assert_eq!(
            woken,
            super::Delivery::Unbound,
            "and no socket owned the port"
        );
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
            net::address::Address::V4([10, 0, 2, 2]),
            PORT_C,
            net::address::Address::V4([10, 0, 2, 9]),
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
        assert_eq!(source, net::address::Address::V4([10, 0, 2, 9]));
    }

    /// A full queue refuses the next datagram with `Busy`, which is what a
    /// sender can act on.
    #[test]
    fn a_full_queue_refuses_with_busy() {
        let _socket = bind_udp(PORT_D).expect("a bind");
        for index in 0..QUEUE_LIMIT {
            deliver_udp(
                net::address::Address::V4([10, 0, 2, 2]),
                PORT_D,
                net::address::Address::V4([10, 0, 2, 9]),
                77,
                &[index as u8; 4],
            )
            .expect("a delivery");
        }
        assert_eq!(
            deliver_udp(
                net::address::Address::V4([10, 0, 2, 2]),
                PORT_D,
                net::address::Address::V4([10, 0, 2, 9]),
                77,
                b"one more",
            )
            .unwrap_err(),
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
        super::send_datagram(net::address::Address::V4(protocol), PORT_F, 50000, b"self")
            .expect("a loopback send");
        assert!(
            card.sent.lock().is_empty(),
            "a datagram to this machine does not touch the card"
        );
        let mut buffer = [0_u8; 8];
        let (source, _, count) = socket
            .try_recv(&mut buffer)
            .expect("a receive")
            .expect("the loopback datagram");
        assert_eq!(
            source,
            net::address::Address::V4(protocol),
            "the sender is this machine"
        );
        assert_eq!(&buffer[..count], b"self");

        // The wire, as a datagram: the frame names the gateway's hardware
        // address and the destination's protocol address, which is the
        // whole of this build's routing.
        super::send_datagram(
            net::address::Address::V4([10, 9, 9, 7]),
            9004,
            50000,
            b"out",
        )
        .expect("a send");
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
        // socket's queue after it, built by the same writers the send path
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
        assert_eq!(source, net::address::Address::V4([10, 9, 9, 9]));
        assert_eq!(source_port, 77);
        assert_eq!(&buffer[..count], b"hello");

        // The stream: the boot's own probe, as a host test.  The same
        // calls, the same demux, and a card that records nothing, because a
        // loopback stream touches none of it.
        let listener = super::tcp_listen(9002).expect("a listen");
        let client =
            super::tcp_connect(net::address::Address::V4(protocol), 9002).expect("a connect");
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
            // Both ends finished, and both **hold** the four-tuple: the close
            // is over and the entry stays in `TimeWait` so a retransmitted
            // finish is answered rather than reset.  The read below is the
            // part that matters to a program, and it is end-of-file either
            // way: a stream whose inbox is drained and whose peer finished
            // reads zero.
            assert_eq!(
                table.connection(client).map(|c| c.state()),
                Some(net::tcp::State::TimeWait),
                "the client's end finished and its four-tuple is held"
            );
            assert_eq!(
                table.connection(accepted).map(|c| c.state()),
                Some(net::tcp::State::TimeWait),
                "and the accepted end with it"
            );
        }
        assert_eq!(
            super::tcp_read(client, &mut stream_buffer),
            Ok(Some(0)),
            "a stream whose close is over reads as end of file, and not as \
             `None`: the entry is held in `TimeWait`, so a reader that treated \
             an empty inbox as `ask again` would wait for a writer that has \
             finished"
        );
        // The stream never touched the card, and the wire datagram's frame
        // is still the only thing the card carries.
        assert_eq!(card.sent.lock().len(), 1, "loopback is not the wire");
    }

    /// A datagram for a port nothing owns is answered with a report that
    /// quotes the datagram, and the sender can read its own ports back out of
    /// the quote.
    ///
    /// This is the assertion a boot cannot make: the boot sees no report,
    /// because a report only goes to a sender that sent something.  What the
    /// test can do is build the report the kernel would send and check the
    /// bytes a sender acts on, its own source port and destination port, at
    /// the offsets its own header layout puts them.
    #[test]
    fn a_port_unreachable_report_quotes_the_datagram_it_answers() {
        // A datagram from a peer to a port on this machine, with a UDP header
        // whose ports the test can read back.
        const SOURCE_PORT: u16 = 9300;
        const DESTINATION_PORT: u16 = 9400;
        const PAYLOAD: &[u8] = b"nobody";
        let udp_len = net::udp::datagram_len(PAYLOAD.len());
        let mut datagram = alloc::vec![0_u8; udp_len];
        net::udp::write_datagram(
            &mut datagram,
            PEER_PROTOCOL,
            OUR_PROTOCOL,
            SOURCE_PORT,
            DESTINATION_PORT,
            PAYLOAD,
        );

        // The header carries a type of service and a time-to-live this stack
        // never sends, so a quote rebuilt from the fields `parse` keeps would
        // differ from the bytes: the assertions below tell a quote from a
        // rebuild.
        let mut header = [0_u8; net::ipv4::HEADER_LEN];
        header[0] = 0x45;
        header[1] = 0xB8;
        header[2..4].copy_from_slice(&((net::ipv4::HEADER_LEN + udp_len) as u16).to_be_bytes());
        header[8] = 3;
        header[9] = net::ipv4::PROTOCOL_UDP;
        header[12..16].copy_from_slice(&PEER_PROTOCOL);
        header[16..20].copy_from_slice(&OUR_PROTOCOL);
        let sum = net::ipv4::checksum(&header);
        header[10..12].copy_from_slice(&sum.to_be_bytes());
        // `parse` cross-checks the total length against the bytes it was
        // given, so the header has to arrive with the payload it claims.
        let mut wire = alloc::vec![0_u8; net::ipv4::HEADER_LEN + udp_len];
        wire[..net::ipv4::HEADER_LEN].copy_from_slice(&header);
        wire[net::ipv4::HEADER_LEN..].copy_from_slice(&datagram);
        let packet = net::ipv4::parse(&wire).expect("the packet a peer wrote");
        let original_header = packet.header_bytes(&wire).expect("its own header");

        let frame = super::port_unreachable_frame(
            original_header,
            &packet,
            &datagram,
            OUR_PROTOCOL,
            [0x02; 6],
            [0x54; 6],
        );

        // The frame is addressed to the sender, from this machine.
        assert_eq!(&frame[0..6], &[0x54; 6], "to the sender's own address");
        assert_eq!(&frame[6..12], &[0x02; 6]);
        let answer = net::ipv4::parse(&frame[netdev::ETHERNET_HEADER_LEN..])
            .expect("the report's own header");
        assert_eq!(answer.header.protocol, net::ipv4::PROTOCOL_ICMP);
        assert_eq!(answer.header.source, OUR_PROTOCOL, "from this machine");
        assert_eq!(answer.header.destination, PEER_PROTOCOL, "to the sender");

        // The message is a port-unreachable, verifies, and quotes the
        // datagram's ports where the sender looks for them: eight fixed
        // bytes, then the quoted twenty-byte header, then the UDP header.
        let message = &frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..];
        let error = net::icmp::parse_error(message).expect("an error message");
        assert_eq!(error.kind, net::icmp::DESTINATION_UNREACHABLE);
        assert_eq!(error.code, net::icmp::PORT_UNREACHABLE);
        let quote = &message[error.quoted_at..error.quoted_at + error.quoted_len];
        assert_eq!(quote[0] >> 4, 4, "the quoted packet is IPv4");
        // The quote is the sender's own bytes, not a header rebuilt from the
        // fields this stack reads: the ttl and the type of service are the
        // ones the test wrote and this stack never sends.
        assert_eq!(
            &quote[..20],
            &header[..],
            "the sender's header, byte for byte"
        );
        assert_eq!(quote[8], 3, "the ttl the sender chose");
        assert_eq!(quote[1], 0xB8, "the type of service the sender chose");
        assert_eq!(quote[9], net::ipv4::PROTOCOL_UDP);
        assert_eq!(
            &quote[12..16],
            &PEER_PROTOCOL,
            "the sender's address came back"
        );
        assert_eq!(
            &quote[20..22],
            &SOURCE_PORT.to_be_bytes(),
            "its source port, where its own UDP header puts it"
        );
        assert_eq!(
            &quote[22..24],
            &DESTINATION_PORT.to_be_bytes(),
            "and the port nothing owned"
        );
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
        // the datagram in the payload, built by the same writers the send
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
        assert_eq!(source, net::address::Address::V4([10, 9, 9, 9]));
        assert_eq!(source_port, 77);
        assert_eq!(&buffer[..count], b"hello");
    }

    /// The clock the fragment cache is given is a duration, and the cache's
    /// constant is the same duration.
    ///
    /// This is the join no test could see before: the cache's own tests
    /// measure against a clock they supply, so a caller that handed it raw
    /// ticks satisfied every one of them while the window it actually offered
    /// was a hundred times shorter than the constant describing it.
    #[test]
    fn the_tick_is_a_duration_and_the_timeout_is_measured_in_one() {
        // The machine's slice and this file's copy are the same number.  On a
        // host only one of them compiles, so the comparison is made where the
        // machine's exists; what this test can always check is that the cache
        // holds a duration and that the conversion is a duration too.
        #[cfg(target_os = "none")]
        assert_eq!(
            super::crate::tick::TIME_SLICE_US,
            super::MICROS_PER_TICK,
            "the boot's slice and the conversion's copy are one number"
        );

        assert_eq!(
            super::micros_of_ticks(1),
            super::MICROS_PER_TICK,
            "one timer interrupt is one slice"
        );

        // The reassembly timeout, converted back to seconds, is RFC 1122's
        // thirty.  A factor of a hundred wrong either way fails here: too
        // small and the window is 0.3 s, too large and it is fifty minutes.
        let timeout_seconds = net::reassembly::TIMEOUT_MICROS / 1_000_000;
        assert_eq!(
            timeout_seconds, 30,
            "RFC 1122's floor for reassembly is thirty seconds"
        );

        // And the count of interrupts that thirty seconds is, which is what a
        // caller passing ticks instead of a duration would have got wrong.
        let ticks_in_the_window = net::reassembly::TIMEOUT_MICROS / super::MICROS_PER_TICK;
        assert_eq!(
            super::micros_of_ticks(ticks_in_the_window),
            net::reassembly::TIMEOUT_MICROS,
            "the window, measured in ticks and converted back, is itself"
        );
        assert_eq!(
            ticks_in_the_window, 300_000,
            "ten kilohertz for thirty seconds"
        );
    }

    /// A DHCP lease's seconds are converted into the clock its duty is
    /// measured by, and the two agree.
    ///
    /// This is the second place the same class of defect lived: `lease_from`
    /// takes the caller's unit, and the caller passed `1` while its clock
    /// counted microseconds, so an hour's lease was read as expired
    /// eighty-six milliseconds after it was granted.  The test goes through
    /// `lease_from` for exactly that reason: a test that built a `Lease` by
    /// hand would pass whatever scale the caller used, which is what the
    /// first version of this test did.
    #[test]
    fn a_lease_is_measured_in_the_clock_its_duty_reads() {
        let reply = net::dhcp::Reply {
            kind: net::dhcp::MESSAGE_ACK,
            address: [10, 0, 2, 15],
            server: Some([10, 0, 2, 2]),
            router: Some([10, 0, 2, 2]),
            dns: Some([10, 0, 2, 3]),
            subnet_mask: Some([255, 255, 255, 0]),
            lease_seconds: 3_600,
            renewal_seconds: 1_800,
            rebinding_seconds: 3_150,
        };

        // The conversion this kernel makes: a second is `MICROS_PER_SECOND`
        // of its clock.
        let lease =
            net::dhcp::lease_from(&reply, 0, super::MICROS_PER_SECOND).expect("an ACK is a lease");
        assert_eq!(
            lease.lifetime,
            3_600 * super::MICROS_PER_SECOND,
            "an hour, in this kernel's unit"
        );
        assert_eq!(lease.duty(0), net::dhcp::Duty::Bound, "fresh at the grant");
        assert_eq!(
            lease.duty(lease.lifetime / 2),
            net::dhcp::Duty::Renew,
            "renewal at half the lease"
        );
        assert_eq!(
            lease.duty(lease.lifetime / 8 * 7),
            net::dhcp::Duty::Rebind,
            "rebinding at seven eighths"
        );
        assert_eq!(
            lease.duty(lease.lifetime),
            net::dhcp::Duty::Expired,
            "and the address is gone at the end"
        );

        // The scale the caller used before this fix, for contrast: the same
        // reply becomes a lease whose thirty-six hundred seconds are read as
        // thirty-six hundred *microseconds*, so a boot three and a half
        // milliseconds old is already past it.
        let wrong = net::dhcp::lease_from(&reply, 0, 1).expect("an ACK is a lease");
        assert_eq!(wrong.lifetime, 3_600, "an hour read as 3600 units");
        assert_eq!(
            wrong.duty(3_600),
            net::dhcp::Duty::Expired,
            "expired 3.6 milliseconds into a boot"
        );
        assert!(
            super::micros_of_ticks(36) == 3_600,
            "which is thirty-six timer interrupts, not an hour"
        );
    }

    /// A report about this machine's own packet names the stream by this
    /// machine's port first and the peer's second.
    ///
    /// The port order is the whole test.  The quoted packet is one this
    /// machine sent, so its source port is ours; a reader that handed the
    /// table the pair the other way round found the peer's own end of a
    /// loopback exchange and shrank the wrong stream, which is the defect the
    /// boot's probe found after this test's subject was already written.
    #[test]
    fn a_report_names_our_port_first_and_the_peers_second() {
        const OURS: u16 = 49152;
        const THEIRS: u16 = 9000;
        let us = [10, 0, 2, 15];

        // The report: the bytes a router sends about a segment this machine
        // sent to a peer, which is why the original's source is this machine's
        // address and its destination is the peer's.
        let mut quoted_header = [0_u8; 20];
        net::ipv4::write_header(
            &mut quoted_header,
            us,
            [10, 0, 2, 2],
            net::ipv4::PROTOCOL_TCP,
            net::icmp::QUOTED_PAYLOAD,
        );
        let mut quoted_payload = [0_u8; 8];
        quoted_payload[0..2].copy_from_slice(&THEIRS.to_be_bytes());
        quoted_payload[2..4].copy_from_slice(&OURS.to_be_bytes());

        let mut message = [0_u8; 64];
        net::icmp::write_unreachable_with_mtu(
            &mut message,
            net::icmp::FRAGMENTATION_NEEDED,
            1_400,
            &quoted_header,
            &quoted_payload,
        );
        let length = net::icmp::error_len(quoted_header.len(), quoted_payload.len());
        let error = net::icmp::parse_error(&message[..length]).expect("an error");

        let report = super::quoted_report(us, &error, &message[..length]).expect("a report");
        assert_eq!(
            report.local_port, THEIRS,
            "the port the quoted packet named first is ours"
        );
        assert_eq!(
            report.remote.1, OURS,
            "and the second is the peer it went to"
        );
        assert_eq!(report.remote.0, net::address::Address::V4([10, 0, 2, 2]));
    }

    /// A report about a packet that was not this machine's is refused.
    ///
    /// The quoted packet is one whose destination is somebody else, so no
    /// stream of ours could be the subject: acting on it would let a stranger
    /// shrink or end a connection by guessing a port.
    #[test]
    fn a_report_about_someone_elses_packet_is_refused() {
        let us = [10, 0, 2, 15];
        let mut quoted_header = [0_u8; 20];
        net::ipv4::write_header(
            &mut quoted_header,
            [10, 0, 2, 9],
            [10, 0, 2, 2],
            net::ipv4::PROTOCOL_TCP,
            net::icmp::QUOTED_PAYLOAD,
        );
        let mut quoted_payload = [0_u8; 8];
        quoted_payload[0..2].copy_from_slice(&9000u16.to_be_bytes());
        quoted_payload[2..4].copy_from_slice(&49152u16.to_be_bytes());

        let mut message = [0_u8; 64];
        net::icmp::write_unreachable_with_mtu(
            &mut message,
            net::icmp::FRAGMENTATION_NEEDED,
            1_400,
            &quoted_header,
            &quoted_payload,
        );
        let length = net::icmp::error_len(quoted_header.len(), quoted_payload.len());
        let error = net::icmp::parse_error(&message[..length]).expect("an error");

        assert_eq!(
            super::quoted_report(us, &error, &message[..length]),
            None,
            "the quoted packet was not addressed to this machine"
        );
    }

    /// The payload a path's MTU leaves is the MTU less both headers, and a
    /// wrongly small one is not a wrapped number.
    #[test]
    fn a_paths_mtu_leaves_room_for_the_headers() {
        assert_eq!(
            super::payload_for(1_500),
            1_500 - net::ipv4::HEADER_LEN - net::tcp::HEADER_LEN
        );
        // A path that claims less than the headers is a peer's mistake, and
        // the subtraction must not wrap into four gigabytes.
        assert_eq!(super::payload_for(10), 0);
        assert_eq!(super::payload_for(0), 0);
    }
}
