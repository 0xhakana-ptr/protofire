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
//! [`address`], [`dhcp`], [`dns`] and [`route`] stay at the root because they
//! are not a layer: an address is what every layer names, the other two
//! configure a machine rather than carry its traffic, and a route is the
//! question of which link a destination is on, asked before any layer reads a
//! byte.
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
//! ## What the stream does, and what it does not
//!
//! A stream's close is [RFC 793]'s, all of it: `FinWait`, `FinWait2`,
//! `Closing` and `TimeWait` are four states because the close is four
//! situations, and a closed four-tuple is held for `2 * MSL` so a
//! retransmitted finish is answered rather than reset.
//!
//! [RFC 793]: https://www.rfc-editor.org/rfc/rfc793
//!
//! What a stream states is what it can take: a SYN carries the MSS option, and
//! the peer's answer to it bounds every segment this side builds.  A stream
//! holds a small write while anything is in flight unless
//! [`options::Options::no_delay`] says otherwise, which is [RFC 1122]'s rule
//! and the one behaviour `TCP_NODELAY` was written for.
//!
//! [RFC 1122]: https://www.rfc-editor.org/rfc/rfc1122
//!
//! What a stream **does** is measure: its timeout is [RFC 6298]'s estimate,
//! `SRTT + 4 * RTTVAR` over the acknowledgements that carried no
//! retransmission, rather than a constant.  The first measurement is the
//! estimate and each later one moves it an eighth of the way, which is what
//! makes a path that changed visible within a few round trips and a path that
//! did not unbothered.  Congestion control is [RFC 5681]'s two halves, slow
//! start and congestion avoidance, with fast retransmit on three duplicate
//! acknowledgements.
//!
//! [RFC 6298]: https://www.rfc-editor.org/rfc/rfc6298
//!
//! [RFC 5681]: https://www.rfc-editor.org/rfc/rfc5681
//!
//! What a stream **respects** is the window its peer advertises:
//! [`tcp::Connection::send_budget`] is the smallest of the congestion window,
//! that window, and the unacknowledged queue's room, so a peer whose buffer is
//! full stops this side rather than being sent past what it said it would
//! take.
//!
//! Path-MTU discovery is both families': [`icmp::FRAGMENTATION_NEEDED`] states
//! a path's size on IPv4 and [`icmpv6::PACKET_TOO_BIG`] on IPv6, and
//! [`tcp::Connection::limit_segment`] only ever shrinks.  The two readers are
//! separate functions because the messages differ in where the quotation
//! starts: IPv6's MTU word takes the four bytes an IPv4 error leaves unused.
//!
//! ## What is not here yet
//!
//! A **metric**.  [`route`] holds a table and the longest match decides, but
//! two routes to one prefix replace rather than compete: this machine has one
//! interface and one address per family, and a cost that chooses between routes
//! a single interface cannot have would be a field nothing reads.  The day
//! there are two interfaces, the route gains one field and the lookup one
//! comparison.
//!
//! What is also absent is every protocol this crate does not name: DCCP,
//! IPsec, TLS, multicast routing.  Those are numbers above the frozen range
//! and each is its own stack, which is why `docs/roadmap.md` lists them as
//! work rather than as gaps in this one.
//!
//! [`multicast`] is the other, and its shape is different from a protocol's:
//! two tables, one from virtual interface to what it does with a frame and one
//! from a `(source, group)` to where it goes, plus the one function that reads
//! both to answer where a packet leaves.  What makes it a **forwarder** rather
//! than a receiver is that a decision can name an interface that sends, and the
//! kernel's demux acts on it: the entry's group is what the receive test
//! accepts, and the copy leaves with the hop count spent.
//!
//! [`filter`] is here and is one of them no longer: an ordered rule list, the
//! first match deciding, prefixes and port ranges in both families, and the
//! flow table a stateful rule fills so a reply finds what its request was
//! allowed to do.  It is a **policy about a packet**, which is why it is not
//! under `transport`: it is asked at two points the frame crosses, and neither
//! of them is a transport.  There is no `enabled` flag, deliberately: a rule
//! set that a call could switch off is a rule set that can be installed and
//! never consulted, which is the state the previous tree shipped.
//! What a program **may change** about a socket is [`options`]: three numbers,
//! each of which moves the thing it names.  The module is short because an
//! option nothing acts on is a field, and this crate would rather refuse one
//! than keep it.
//!
//! [`raw`] is the one socket keyed on a protocol number rather than a port, so
//! a program can implement a protocol this crate does not have.  What it does
//! not take is a header: the stack composes the one the machine is responsible
//! for, and the program chooses the protocol and the payload.
//!
//! [`local`] is the one transport whose bytes are not on a wire: a name a
//! listener binds, the connections waiting at it, and the rule that a full
//! backlog refuses.  The pipes behind a connection are the kernel's, because a
//! pipe parks a reader and parking is the scheduler's act; what is here is the
//! naming, which is arithmetic over values and so a host test.

#![no_std]

extern crate alloc;

pub mod address;
pub mod dhcp;
pub mod dns;
pub mod filter;
pub mod internet;
pub mod link;
pub mod multicast;
pub mod route;
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

pub use filter::Action;
pub use filter::Filter;
pub use filter::Packet;
pub use filter::Rule;

pub use multicast::Cache;
pub use multicast::Forwarding;
pub use multicast::Interfaces;
pub use multicast::Vif;

pub use transport::local;
pub use transport::options;
pub use transport::raw;
pub use transport::tcp;
pub use transport::tcp_table;
pub use transport::udp;
pub use transport::udp_socket;
