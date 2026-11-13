//! fs/src/fat32/mod.rs
//!
//! FAT12/16/32, read-write: the BPB's geometry, the FAT table in all three
//! entry widths, cluster chains walked and allocated, 8.3 short names and
//! the LFN sets that long names ride in, and the FSInfo sector's
//! free-cluster bookkeeping.
//!
//! ## What this module is
//!
//! A filesystem backend in the [`crate::filesystem::FileSystem`] shape:
//! [`FatVolume::open`] mounts a volume a device holds, and everything
//! between — lookup, listing, creation, rename, removal, reading, writing,
//! truncation — is the format's own arithmetic through the block cache.
//! The FAT family's writes are in-place: a cluster's content is overwritten,
//! unlike f2fs's appended, and the chain is the only allocation.
//!
//! ## The conventions the port pins
//!
//! A listing answers the names a caller made.  A create of a name the
//! volume already holds is the create's own refusal.  Both are the same
//! conventions the other backends keep, and both are pinned by the tests.

pub(super) mod fs;
#[cfg(test)]
mod tests;
pub(super) mod types;
pub(super) mod vfs;

pub use vfs::FatVolume;
