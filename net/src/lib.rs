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
//! The transports are the same code for both families: [`udp::write_datagram6`]
//! and [`tcp::write_segment6`] differ from their IPv4 twins only in the
//! pseudo-header, which is the one place the two versions of a checksum
//! disagree.
//!
//! ## What this crate does not decide
//!
//! Which address a machine has, which neighbours it can reach, which sockets
//! exist, and when a task waiting on one wakes.  Those are choices about a
//! boot's state, and they live in `kernel/src/net.rs`: this crate computes
//! what a frame means, the kernel keeps what the machine knows.
//!
//! ## What is not here yet
//!
//! Fragmentation and reassembly, path-MTU discovery, and the ICMP error
//! messages a stack **sends** rather than parses.  Each is a documented
//! refusal in the module it belongs to, with the reason beside it.

#![no_std]

extern crate alloc;

pub mod arp;
pub mod ethernet;
pub mod icmp;
pub mod icmpv6;
pub mod ipv4;
pub mod ipv6;
pub mod ndp;
pub mod tcp;
pub mod udp;
