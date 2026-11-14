//! net/src/transport/mod.rs
//!
//! The transports: the two ways a program's bytes cross the internet layer,
//! and the state a machine holds for each.
//!
//! | File | What it holds |
//! |---|---|
//! | [`tcp`] | the segment, and the states a stream moves through |
//! | [`tcp_table`] | which streams exist, and the four fields a segment is keyed on |
//! | [`udp`] | the datagram, its checksum, and the rule that zero means none |
//! | [`udp_socket`] | one bound port's queue and the bounds on it |
//!
//! The last file in each pair is the one kind of state this crate holds: a
//! value a caller owns, with no lock and no `static`, which is what lets the
//! same arithmetic be a host test and a boot's actual table.
//!
//! The transports are the same code for both families.  [`crate::udp`] and
//! [`crate::tcp`] differ from their IPv4 twins only in the pseudo-header,
//! which is the one place the two versions of a checksum disagree.

pub mod tcp;
pub mod tcp_table;
pub mod udp;
pub mod udp_socket;
