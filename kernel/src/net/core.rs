//! kernel/src/net/core.rs
//!
//! The interface, the sockets, the datagram path and the clock: what a boot
//! installs and what every call below reads.
//!
//! One section of `kernel/src/net/mod.rs`.  The sections call each other in
//! both directions: the demux reaches every protocol's delivery and a protocol
//! reaches the interface, so each names what it needs through `super::`.  What
//! the split buys is that a reader looking for one protocol opens one file.

use alloc::sync::Arc;
use alloc::sync::Weak;
use alloc::vec::Vec;

use netdev::LinkDevice;
use sync::Mutex;

use abi::Error;
use abi::Result;
use abi::network::NETWORK_STATUS_UP;
use abi::network::NetworkStatusRecord;

use super::demux4::demux;
use super::demux6::peer_hardware;
#[cfg(target_os = "none")]
use super::dhcp::renew_lease_if_due;
use super::filter::submit_filtered;
use super::ipsec::ipsec_open;
use super::ipsec::ipsec_seal;
use super::tcp::note_stream_wake;
use super::tcp::tcp_exchange;

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
    pub(crate) card: Arc<dyn LinkDevice>,
    pub(crate) hardware: [u8; 6],
    pub(crate) protocol: [u8; 4],
    pub(crate) gateway: [u8; 4],
    /// The routes this machine knows, of both families.
    ///
    /// `gateway` above is the one route DHCP names, kept because the boot's
    /// lines report it and because a lease's renewal compares it; the table is
    /// what a **send** asks.  Two facts rather than one because they answer
    /// different questions: the gateway is what a lease said, and the table is
    /// what this machine will do, and a route added by another advertisement
    /// or by a program does not change the lease.
    pub(crate) routes: net::route::Table,
    pub(crate) arp: net::arp::Cache,
    /// The link-local IPv6 address this interface derives from its own MAC.
    ///
    /// Every IPv6 interface has one before it has said anything to anyone:
    /// it is the address a neighbour solicitation is sent *from* while the
    /// interface waits for a router, and the address an agent puts in a
    /// reply.  It is derived rather than configured, which is why it can be
    /// set at install and never moved.
    pub(crate) ipv6: net::ipv6::Addr,
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
    pub(crate) ipv6_groups: [net::ipv6::Addr; 3],
    /// What the wire has answered about its IPv6 neighbours.
    pub(crate) ndp: net::ndp::Cache,
    /// A global address a router's advertisement configured, if one has.
    pub(crate) ipv6_global: Option<net::ipv6::Addr>,
    /// The name server a lease named, if one did.
    ///
    /// Kept here rather than in a socket because it is a fact about this
    /// machine's network, and a lookup asks it once per name.
    pub(crate) dns: Option<[u8; 4]>,
    /// The default router a router advertisement named, if one has.
    ///
    /// IPv6 has no configured default route the way IPv4's DHCP hands one out:
    /// a router says it exists with an advertisement, and the source address of
    /// that advertisement is the address a host sends off-link traffic to.
    /// Zero lifetime is a router saying it is **not** a default router, which
    /// is why the lifetime is checked rather than the message's arrival.
    pub(crate) ipv6_router: Option<net::ipv6::Addr>,
    /// The lease this interface is running under, if the address came from
    /// one.
    ///
    /// Kept because an address a server granted is the server's to take back:
    /// without the lease, a boot's address would outlive the grant that made
    /// it, and a second machine granted the same address would find it in
    /// use.  The lease's clocks are in the caller's unit, microseconds here,
    /// and [`net::dhcp::Lease::duty`] is what reads them.
    pub(crate) lease: Option<net::dhcp::Lease>,
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
    pub(crate) fn is_on_link(&self, destination: net::ipv6::Addr) -> bool {
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
pub(crate) static INTERFACE: Mutex<Option<Interface>> = Mutex::new(None);

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
pub(crate) fn deliver_raw(protocol: u8, source: net::address::Address, payload: &[u8]) -> usize {
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
                submit_filtered(
                    card.as_ref(),
                    &frame,
                    &net::filter::Packet::v4(local, destination, protocol, payload),
                )?;
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
pub(crate) fn hardware_for_v4(interface: &Interface, destination: [u8; 4]) -> Result<[u8; 6]> {
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
pub(crate) fn is_loopback_v4(destination: [u8; 4]) -> bool {
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
pub(crate) fn is_loopback(destination: net::address::Address) -> bool {
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
        let (local, protocol_number) = {
            let interface = INTERFACE.lock();
            let Some(interface) = interface.as_ref() else {
                return Err(Error::NotFound);
            };
            (
                match destination {
                    net::address::Address::V4(_) => net::address::Address::V4(interface.protocol),
                    net::address::Address::V6(_) => net::address::Address::V6(interface.ipv6),
                },
                interface.protocol,
            )
        };
        // The sender the datagram names is this machine: the wire would have
        // seen the frame leave with this address, and the receiver's answer
        // says the same thing.
        //
        // **A policy still applies.**  The shortcut is about the card and not
        // about the protocol: a datagram this machine sends itself is a
        // datagram that would have left under a policy and arrived under one,
        // and a loopback that skipped both would be a machine where a protected
        // service was reachable in plaintext by naming its own address.  So the
        // datagram is sealed when a policy says so, opened again on the way in
        // (which is what spends a sequence number and advances the window, and
        // so is what a replay would be checked against), and only then
        // delivered.
        let mut datagram = alloc::vec![0; net::udp::datagram_len(bytes.len())];
        net::udp::write_datagram(
            &mut datagram,
            protocol_number,
            match destination {
                net::address::Address::V4(bytes) => bytes,
                net::address::Address::V6(_) => protocol_number,
            },
            source_port,
            destination_port,
            bytes,
        );
        let sealed = ipsec_seal(
            protocol_number,
            match destination {
                net::address::Address::V4(bytes) => bytes,
                net::address::Address::V6(_) => protocol_number,
            },
            net::ipv4::PROTOCOL_UDP,
            Some((source_port, destination_port)),
            &datagram,
        )?;
        let payload = match sealed {
            Some(esp) => {
                // Opened by the same demux path a frame from the card takes, so
                // what is delivered is what a peer would have recovered.
                let Some((inner, _)) = ipsec_open(&esp) else {
                    return Err(Error::PermissionDenied);
                };
                inner
            }
            None => datagram,
        };
        // The UDP header inside is this machine's own, and the datagram the
        // queue wants is what follows it.
        if payload.len() < net::udp::HEADER_LEN {
            return Err(Error::InvalidArgument);
        }
        let data = &payload[net::udp::HEADER_LEN..];
        return deliver_udp(destination, destination_port, local, source_port, data).map(|_| ());
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

            // The datagram is built first and encapsulated second, because the
            // policy the encapsulation follows is about the datagram: the ports
            // a selector names are in the UDP header, and a lookup that ran
            // before the header existed would have no ports to ask about.
            let mut datagram = alloc::vec![0; udp_len];
            net::udp::write_datagram(
                &mut datagram,
                protocol,
                destination,
                source_port,
                destination_port,
                bytes,
            );

            // ESP, when a policy says so.  The protocol number the IP header
            // carries becomes ESP's, and the payload becomes the encapsulated
            // one: what the peer reads as a transport is the peer's own
            // decapsulation, not this machine's UDP.
            let (ip_protocol, payload_len, sealed) = match ipsec_seal(
                protocol,
                destination,
                net::ipv4::PROTOCOL_UDP,
                Some((source_port, destination_port)),
                &datagram,
            )? {
                Some(esp) => {
                    let length = esp.len();
                    (net::ipv4::PROTOCOL_ESP, length, Some(esp))
                }
                None => (net::ipv4::PROTOCOL_UDP, udp_len, None),
            };
            let payload: &[u8] = match &sealed {
                Some(esp) => esp,
                None => &datagram,
            };

            let packet_len = netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + payload_len;
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
                ip_protocol,
                payload_len,
            );
            frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..].copy_from_slice(payload);
            submit_filtered(
                card.as_ref(),
                &frame,
                &net::filter::Packet::v4(
                    protocol,
                    destination,
                    ip_protocol,
                    &frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..],
                ),
            )
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
            submit_filtered(
                card.as_ref(),
                &frame,
                &net::filter::Packet::v6(
                    local,
                    destination,
                    net::ipv6::NEXT_UDP,
                    &frame[netdev::ETHERNET_HEADER_LEN + net::ipv6::HEADER_LEN..],
                ),
            )
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
pub(crate) fn micros_since_boot() -> u64 {
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
pub(crate) fn micros_of_ticks(ticks: u64) -> u64 {
    ticks.saturating_mul(MICROS_PER_TICK)
}

/// How long one timer interrupt is, in microseconds.
///
/// The same value [`crate::tick::TIME_SLICE_US`] carries on a machine, and
/// deliberately a second name: a host test compiles `tick` with no timer and
/// no slice, so the assertion that the two agree is a test's.
#[cfg(any(test, target_os = "none"))]
pub(crate) const MICROS_PER_TICK: u64 = 100;

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
pub(crate) const MICROS_PER_SECOND: u64 = 1_000_000;

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
pub(crate) static FRAGMENTS: Mutex<net::reassembly::Cache> =
    Mutex::new(net::reassembly::Cache::new());

/// The clock the fragment cache expires against.
///
/// The same clock the retransmission schedule uses, and deliberately the same
/// function rather than a second conversion: the two used to disagree, one
/// measuring ticks and one measuring a duration, and the disagreement was a
/// timeout a hundred times shorter than the constant describing it.  A cache
/// with no clock could not expire anything, and a peer that never sent its
/// last piece would hold its entry for the rest of the boot.
pub(crate) fn fragment_now() -> u64 {
    micros_since_boot()
}

pub(crate) static TCP: Mutex<net::tcp_table::Table> = Mutex::new(net::tcp_table::Table::new());

/// The DCCP connections and listeners.
///
/// `net::dccp` owns the headers and the state machine; this file owns the lock,
/// the wire, and the sequence numbers the state machine is given.  The last of
/// those is here rather than in the protocol crate because a first sequence
/// number must be **unpredictable**, and the generator belongs to the boot.
pub(crate) static DCCP: Mutex<net::dccp::Table> = Mutex::new(net::dccp::Table::new());

/// A first sequence number for a connection this machine opens.
///
/// [RFC 4340] §5.1 wants it unpredictable, and the boot's generator is what
/// makes one: `crate::random` is seeded before any program runs, and a
/// transport that derived one from a counter would make a connection's sequence
/// numbers guessable from any other connection's.
///
/// [RFC 4340]: https://www.rfc-editor.org/rfc/rfc4340
pub(crate) fn dccp_first_sequence() -> u64 {
    let mut bytes = [0_u8; 6];
    if crate::random::fill(&mut bytes).is_err() {
        // A machine whose generator is not seeded still has to open a
        // connection: the clock is worse than the generator and better than a
        // constant, and the value is masked to the sequence space by the
        // protocol crate.
        return micros_since_boot();
    }
    let mut wide = [0_u8; 8];
    wide[2..].copy_from_slice(&bytes);
    u64::from_be_bytes(wide) & net::dccp::SEQUENCE_MASK
}
