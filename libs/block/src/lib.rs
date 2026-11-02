//! libs/block/src/lib.rs
//!
//! The block-device interface: what a disk driver implements and what a
//! filesystem reads.
//!
//! ## Why a crate
//!
//! The previous tree's header states the argument and it is right: this sits
//! below the filesystem on purpose, because a disk driver has to name the
//! device interface to implement it and must not have to name the filesystem to
//! do that — the filesystem is one consumer of the interface, not its owner.
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
//! in the filesystem for the reason the previous tree gives: they are the
//! bottom of three heights a read is counted at, and the difference between
//! them is where a boot's reads go.
//!
//! ## What is not
//!
//! The device registry.  `publish_device` in the previous tree hands a found
//! device to whoever registered for it, and the registrar is the kernel — so
//! that half arrives with the driver registry rather than with the interface.

#![no_std]

extern crate alloc;

pub mod block;

pub use block::*;
