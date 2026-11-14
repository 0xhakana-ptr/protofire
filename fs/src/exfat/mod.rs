//! fs/src/exfat/mod.rs
//!
//! exFAT, read-write: the checksummed boot region, the 32-bit FAT and the
//! allocation bitmap beside it, entry sets of File/Stream/Filename entries,
//! and the NoFatChain contiguous streams a large file can take.
//!
//! ## What this module is
//!
//! A filesystem backend in the [`crate::filesystem::FileSystem`] shape:
//! [`ExfatVolume::open`] mounts a volume a device holds, and everything
//! between, lookup, listing, creation, rename, removal, reading, writing,
//! truncation, is the format's own arithmetic through the block cache.
//! The allocation is the bitmap's, not the FAT's: a cluster is free when
//! its bit says so, and the chain links follow.
//!
//! ## The conventions the other ports pinned
//!
//! A listing answers the names a caller made.  A create of an existing
//! name is the create's own refusal.  A rename across directories answers
//! `Unsupported` rather than moving the entry set it cannot.

pub(super) mod fs;
#[cfg(test)]
mod tests;
pub(super) mod types;
pub(super) mod vfs;

pub use vfs::ExfatVolume;
