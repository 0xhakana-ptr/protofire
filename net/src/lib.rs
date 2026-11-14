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
//! The Ethernet frame, ARP, IPv4, ICMP, UDP and TCP: the layout of each, a
//! request this crate builds and a reply it reads.  ARP is the smallest
//! exchange that proves a card in both directions, IPv4 is the packet the
//! rest of the stack rides in with the one checksum three protocols share,
//! ICMP is the round trip that proves a packet built by another machine
//! parses, UDP is the datagram whose refusal a peer answers with the
//! datagram's own header, and TCP is the stream a handshake opens and an
//! orderly close shuts.
//!
//! ## What is not here yet
//!
//! Nothing of the stack `docs/roadmap.md` Level 5 promised: the eight steps
//! are the eight layers above the frame, and what each is proved by is the
//! roadmap's own table.

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
