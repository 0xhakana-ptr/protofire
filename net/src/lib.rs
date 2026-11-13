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
//! The Ethernet frame, ARP, IPv4 and ICMP: the layout of each, a request this
//! crate builds and a reply it reads.  ARP is the smallest exchange that
//! proves a card in both directions, IPv4 is the packet the rest of the stack
//! rides in with the one checksum three protocols share, and ICMP is the
//! round trip that proves a packet built by another machine parses.
//!
//! ## What is not here yet
//!
//! UDP and TCP, in that order.  `docs/roadmap.md` carries the eight steps and
//! what each is proved by.

#![no_std]

pub mod arp;
pub mod ethernet;
pub mod icmp;
pub mod ipv4;
