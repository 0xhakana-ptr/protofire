//! block/src/lib.rs
//!
//! The block-device interface: what a disk driver implements and what a
//! filesystem reads.
//!
//! ## Why a crate, and why at the top of the tree
//!
//! A disk driver has to name the device interface to implement it, and it must
//! not have to name the filesystem to do that, the filesystem is one consumer
//! of the interface, not its owner.  That is not a fact about another kernel's
//! layout; it is what the implementors require.  The drivers that implement
//! this are `virtio`'s block device and whatever a machine adds after it, and
//! that list grows with every machine while the filesystem list does not.  If
//! `fs` owned the trait, every new driver would have to depend on the
//! filesystem to be written.
//!
//! This is not `libs/`.  A crate under `libs/` is a tool with no client shape:
//! a cell, a set of flags, an allocator.  `block` defines a *role*, what a
//! disk driver is, and a role is what `drivers/` and `fs/` share, not what
//! either one owns.  That is the same position `abi` and `fs` are in, which is
//! why they are siblings.
//!
//! ## Two traits and why they are two
//!
//! [`BlockDevice`] is what every device is: a name, a size, and reads and
//! writes that finish before they return.  [`QueuedBlockDevice`] is what a
//! device that can be *ahead* of its caller is, and it is separate because
//! `submit_read` is `unsafe`: the caller's buffer has to stay put until the
//! device is done with it.  An in-memory device copies during the submit and
//! needs no such promise, and neither does any caller of one.  While the
//! promise lived on `BlockDevice`, every implementor carried a contract it
//! did not use.
//!
//! ## What is here
//!
//! The two traits, the in-memory devices a test uses (`MemoryBlockDevice` and
//! `BlockSliceDevice`), the ticket a queued request is named by, the device
//! registry a driver publishes through, and the counters a boot's reads are
//! reported in.
//!
//! The counters are here because they are the bottom of three heights a read
//! is counted at, filesystem, cache, device, and the difference between them
//! is where a boot's reads go.  A counter at the bottom belongs where the
//! bottom is.
//!
//! ## Why it holds a `spin` lock
//!
//! Because it is at layer 4, below `sync`.  A device interface that reached up
//! for the kernel's interrupt-aware lock would be an upward edge, and the
//! devices here are in-memory ones whose storage is only ever touched from
//! ordinary context.  A real driver takes its own lock, in `drivers/`, where
//! the interrupt question is its own to answer.

#![no_std]

extern crate alloc;

pub mod block;
pub mod queue;

pub use block::*;
pub use queue::*;
