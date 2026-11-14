//! net/src/link/mod.rs
//!
//! The link layer: the frame a card carries, and nothing above it.
//!
//! One file, for now.  [`ethernet`] is the frame's own vocabulary, the type
//! numbers and the header, and the header length itself lives in
//! [`netdev::ETHERNET_HEADER_LEN`] because a receive buffer is sized from it
//! and the ethertype reader is the one function both crates use.
//!
//! The directory exists with one file in it because the layer does: a second
//! link format is a second file here, and what it would share with this one is
//! exactly the vocabulary [`ethernet`] holds.  A flat `ethernet.rs` would have
//! to be moved on the day that arrives, and the split is free now.

pub mod ethernet;
