//! fs/src/f2fs/mod.rs
//!
//! f2fs: the log-structured filesystem — append-only writes, a NAT that
//! says where each node's newest block is, a SIT that says which blocks in
//! each segment are valid, and the two-copy checkpoint that commits both.
//!
//! ## What this module is
//!
//! A filesystem backend in the [`crate::filesystem::FileSystem`] shape:
//! [`F2fsVolume::open`] mounts a volume a device holds, [`F2fsVolume::make`]
//! writes a fresh one, and everything between them — lookup, listing,
//! creation, rename, removal, reading, writing — is the format's own
//! arithmetic through the block cache.
//!
//! ## What this build's f2fs deliberately does not do
//!
//! No garbage collection: blocks are appended and never reclaimed, so a
//! volume's freeing is a SIT mark and its space is spent for good.  No
//! hot/warm/cold segment separation.  Direct block pointers only — an
//! inode maps what `i_addr` holds and nothing past it.  Fast symlinks
//! only.  No extended attributes.  Each of those is a mechanism the write
//! path does not need to prove itself, and each says so where a reader
//! would otherwise assume it.

pub(super) mod checkpoint;
pub(super) mod constants;
pub(super) mod data;
pub(super) mod format;
pub(super) mod fs;
pub(super) mod node;
pub(super) mod segment;
#[cfg(test)]
mod tests;
pub(super) mod types;
pub(super) mod vfs;

pub use vfs::F2fsVolume;
