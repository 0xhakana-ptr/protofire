//! libs/block/src/lib.rs
//!
//! The block-device interface: what a disk driver implements and what a
//! filesystem reads.
//!
//! ## Why a crate
//!
//! A disk driver has to name the device interface to implement it, and it must
//! not have to name the filesystem to do that — the filesystem is one consumer
//! of the interface, not its owner.  That is not a fact about another kernel's
//! layout; it is what the implementors require.  The drivers that will
//! implement this are `virtio`'s block device and whatever a machine adds after
//! it, and that list grows with every machine while the filesystem list does
//! not.  If `fs` owned the trait, every new driver would have to depend on the
//! filesystem to be written.
//!
//! A crate is what makes that structural rather than stated.  `drivers` and
//! `fs` both name this, neither names the other, and
//! `scripts/check-layering.sh` refuses the edge that would couple them.
//!
//! ## What is here
//!
//! The trait, the two in-memory devices a test uses (`MemoryBlockDevice` and
//! `BlockSliceDevice`), the ticket a queued request is named by, and the
//! counters a boot's reads are reported in.  The counters are here rather than
//! in the filesystem because they are the bottom of three heights a read is
//! counted at — filesystem, cache, device — and the difference between them is
//! where a boot's reads go.  A counter at the bottom belongs where the bottom
//! is.
//!
//! ## What is not
//!
//! The device registry.  `publish_device` hands a found device to whoever
//! registered for it, and the registrar is the kernel — the one thing that
//! knows which devices a machine has and what mounts them.  So that half
//! arrives with the driver registry, and the interface stays a shape without a
//! policy.

#![no_std]

extern crate alloc;

pub mod block;

pub use block::*;
