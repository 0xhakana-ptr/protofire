//! libs/fdt/src/lib.rs
//!
//! A flattened device tree: the format, and the walks over it that a boot
//! needs.
//!
//! ## What a device tree is
//!
//! A byte blob firmware hands over in a register.  Four blocks, in this order:
//!
//! | block | what |
//! |---|---|
//! | header | ten big-endian `u32`s; magic, sizes, offsets |
//! | memory reservation map | `(address, size)` pairs, terminated by a zero pair |
//! | structure block | the nodes and properties, as tagged tokens |
//! | strings block | the property names, as NUL-terminated strings |
//!
//! The structure block does not store names inline.  A property token carries
//! an offset into the strings block, and the same name is therefore stored once
//! no matter how many nodes use it, which is why a device tree with three
//! hundred `reg` properties is a few kilobytes rather than thirty.
//!
//! ## Why this is a `libs` crate and not `arch`'s
//!
//! A *format* is not a machine.  The same blob is read by aarch64's boot, by
//! riscv64's, and by a host test that has neither; what differs is which
//! register the pointer arrived in, and that is the machine's business.
//! [`Fdt::new`] takes a pointer and a length, so a machine supplies the first
//! and this crate never asks who gave it.
//!
//! ## Why it is byte-oriented and not a `repr(C)` cast
//!
//! Reading the header by casting a struct over the blob and indexing fields
//! works exactly once: on a little-endian machine, with a compiler that padded
//! the struct the way the author assumed, and with a blob whose version
//! matched.  A device tree is a *defined* byte layout that happens to agree
//! with such a struct on one platform, and the difference appears as a wrong
//! offset rather than as a compile error.
//!
//! So every field is read with a big-endian [`u32`] decode at a named offset,
//! and the tests build blobs byte by byte.

#![no_std]

mod property;
mod tree;

pub use property::Property;
pub use tree::Error;
pub use tree::Fdt;
pub use tree::Node;
pub use tree::Reg;

/// The magic, `0xd00dfeed`, big-endian.
pub const MAGIC: u32 = 0xd00d_feed;

/// The smallest version this tree reads.
///
/// Version 16 introduced the `size_strings` field in the header.  Older blobs
/// exist and this crate does not read them: a size the header does not state is
/// one that has to be found by scanning, and a scan that assumed a terminator
/// would read past a blob that lacks one.
pub const MINIMUM_VERSION: u32 = 16;

/// The last version this tree was written against.
pub const MAXIMUM_VERSION: u32 = 17;
