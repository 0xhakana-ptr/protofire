//! net/src/internet/mod.rs
//!
//! The internet layer: the packet each protocol above the frame rides in, the
//! control messages about it, and the state a host keeps about its neighbours.
//!
//! | File | What it holds |
//! |---|---|
//! | [`arp`] | who holds this IPv4 address, and the cache an answer fills |
//! | [`icmp`] | IPv4's echo and the error a sender is told about |
//! | [`icmpv6`] | ICMPv6's echo, its errors, and the four NDP messages |
//! | [`ipv4`] | the header, its checksum, and the fragment fields |
//! | [`ipv6`] | the header, the extension-header walk, and the pseudo-header sum |
//! | [`ndp`] | the neighbour states, and the two addresses a host derives |
//! | [`reassembly`] | the pieces of a fragmented datagram, held until the last |
//! | [`reply`] | the frames a host answers on its own, composed byte for byte |
//!
//! These are grouped here rather than left flat because they answer one
//! question between them: what a packet means before any transport reads it.
//! The split from [`crate::transport`] is the one a reader looks for, and it
//! is the same split the previous tree's `network/internet/` made.
//!
//! Nothing here is re-exported as part of the crate's surface from this file:
//! the crate root does that, so a caller spells `net::ipv4` and never learns
//! which directory the module is in.

pub mod arp;
pub mod icmp;
pub mod icmpv6;
pub mod ipv4;
pub mod ipv6;
pub mod ndp;
pub mod reassembly;
pub mod reply;
