//! net/src/lib.rs
//!
//! The protocol stack above the frame: what the bytes a card carries mean.
//!
//! ## What this crate is, and what it is not
//!
//! It is the layer that reads and writes the protocols a network runs on.  It
//! is not a driver: it sends and receives frames through [`netdev::LinkDevice`]
//! and never names a card, which is why a second network device is a second
//! implementation of that trait and not a second stack.
//!
//! This is the same division `block` makes for disks.  `virtio_block`
//! implements `QueuedBlockDevice`; `fs` reads through it and knows nothing
//! about virtio. Here `virtio_net` implements `LinkDevice`; this crate sends
//! through it.
//!
//! ## What is here, today
//!
//! Both address families, and one module per thing the wire carries: the
//! Ethernet frame, ARP and its cache, IPv4, ICMP, UDP and TCP on the one side;
//! IPv6, its extension-header chain, ICMPv6, neighbour discovery and the
//! solicitation and advertisement a router answers on the other.  Each is a
//! pure reader and writer, bytes in, a value out, no allocation in the
//! parsers and no lock anywhere, which is what lets every one of them be a
//! host test without a card.
//!
//! ## The three directories, and what each is for
//!
//! Seventeen flat files read as a list rather than as a stack, so they sit in
//! three directories, by the layer of the frame each one reads:
//!
//! | directory | what it holds |
//! |---|---|
//! | [`link`] | the frame a card carries, and its type numbers |
//! | [`internet`] | what a packet means before a transport reads it, the control messages about it, and the neighbour state a host keeps |
//! | [`transport`] | the two ways a program's bytes cross, and the table or queue each one needs |
//!
//! [`address`], [`dhcp`] and [`dns`] stay at the root because they are not a
//! layer: an address is what every layer names, and the other two configure a
//! machine rather than carry its traffic.
//!
//! The directories are the reader's; the paths are not.  Every module below is
//! re-exported at the crate root, so a caller spells `net::ipv4::parse` and
//! never learns which directory the module is in, which is what keeps this
//! grouping from becoming an interface the day a file moves again.
//!
//! Two modules hold state rather than reading a byte slice, and both hold it
//! as a **value** a caller owns rather than as a `static`: [`tcp_table`] is
//! which streams exist, the port a listener reserved, the queue a finished
//! handshake waits in, and the counters that name them; [`udp_socket`] is one
//! bound port's queue, its bound, and the rule that a too-small receive is
//! refused with the datagram kept.  Neither takes a lock, how a value is
//! shared is the caller's decision about its own concurrency, which is why
//! their arithmetic is a host test too.
//!
//! [`reply`] is the other direction from the parsers: it **writes** the two
//! frames a host sends on its own, an echo reply and a neighbour
//! advertisement, plus the request and solicitation a boot's probe sends to
//! exercise them.  It is here because a reply is three headers stacked, and a
//! kernel composing one would be a kernel that knew where an ICMPv6 header
//! begins inside a frame.  Its checksums are verified in its own tests against
//! the ends the frames name, because that is the class of mistake a boot can
//! only find by failing.
//!
//! The transports are the same code for both families: [`udp::write_datagram6`]
//! and [`tcp::write_segment6`] differ from their IPv4 twins only in the
//! pseudo-header, which is the one place the two versions of a checksum
//! disagree.
//!
//! ## What this crate does not decide
//!
//! Which address a machine has, which neighbours it can reach, and when a task
//! waiting on a socket wakes.  Those are choices about a boot's state, and they
//! live in `kernel/src/net.rs`: this crate computes what a frame means and
//! keeps the table a caller hands it, and the kernel keeps what the machine
//! knows.
//!
//! [`reassembly`] is the other place a peer's word costs memory: the pieces
//! of a fragmented datagram, held until the last one arrives, bounded in every
//! direction a sender controls, a fixed payload budget, a fixed entry count,
//! an expiry on the caller's clock, and [RFC 5722]'s rule that an overlapping
//! piece takes the whole datagram with it.  A piece that is *the same bytes*
//! again is a retransmission and changes nothing, which is the distinction
//! coverage alone cannot make.
//!
//! [RFC 5722]: https://www.rfc-editor.org/rfc/rfc5722
//!
//! ## Configuring the machine, as opposed to carrying its traffic
//!
//! [`dhcp`] is the four messages that turn a machine with a card into a
//! machine with an address, a router and a name server.  [`dns`] is the query
//! that turns a name into an address through that server.  Both are the
//! protocol's arithmetic only: the socket, the clock and the retry schedule
//! are the caller's, which is what lets a reply with a bad cookie or a
//! compression pointer that loops be a host test rather than a boot.
//!
//! ## What is not here yet
//!
//! Path-MTU discovery and ICMP errors beyond the one a closed port produces.
//! Each is a documented refusal in the module it belongs to.
//!
//! Congestion control is the one refusal that has no module: a stream
//! retransmits, with [`tcp::RTO_INITIAL_MICROS`]'s backoff, and receives out
//! of order, but what it does not do is slow down before a loss tells it to.
//! A receiver's window is carried and never enforced either, so the only bound
//! on what a peer may send is the sequence check.  Both are decisions a stack
//! needs a path with a round trip on it to make, and this one's exchanges are a
//! loopback and a user-mode network.

#![no_std]

extern crate alloc;

pub mod address;
pub mod dhcp;
pub mod dns;
pub mod internet;
pub mod link;
pub mod transport;

/// The internet layer's modules, at the crate root so a caller names the
/// protocol and not its shelf.
///
/// A `pub use` of a module, not of the items in it: `net::ipv4::Packet` is the
/// path a caller spells, and re-exporting the module keeps its own docs and
/// its own name attached.  The directories exist for a reader browsing the
/// tree, which is the only reader a directory helps.
pub use internet::arp;
pub use internet::icmp;
pub use internet::icmpv6;
pub use internet::ipv4;
pub use internet::ipv6;
pub use internet::ndp;
pub use internet::reassembly;
pub use internet::reply;

pub use link::ethernet;

pub use transport::tcp;
pub use transport::tcp_table;
pub use transport::udp;
pub use transport::udp_socket;
