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
//! pure reader and writer — bytes in, a value out, no allocation in the
//! parsers and no lock anywhere — which is what lets every one of them be a
//! host test without a card.
//!
//! Two modules hold state rather than reading a byte slice, and both hold it
//! as a **value** a caller owns rather than as a `static`: [`tcp_table`] is
//! which streams exist, the port a listener reserved, the queue a finished
//! handshake waits in, and the counters that name them; [`udp_socket`] is one
//! bound port's queue, its bound, and the rule that a too-small receive is
//! refused with the datagram kept.  Neither takes a lock — how a value is
//! shared is the caller's decision about its own concurrency — which is why
//! their arithmetic is a host test too.
//!
//! [`reply`] is the other direction from the parsers: it **writes** the two
//! frames a host sends on its own — an echo reply and a neighbour
//! advertisement — plus the request and solicitation a boot's probe sends to
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
//! ## What is not here yet
//!
//! Fragmentation and reassembly, path-MTU discovery, and the ICMP error
//! messages a stack **sends** rather than parses.  Each is a documented
//! refusal in the module it belongs to, with the reason beside it.

#![no_std]

extern crate alloc;

pub mod address;
pub mod arp;
pub mod ethernet;
pub mod icmp;
pub mod icmpv6;
pub mod ipv4;
pub mod ipv6;
pub mod ndp;
pub mod reply;
pub mod tcp;
pub mod tcp_table;
pub mod udp;
pub mod udp_socket;
