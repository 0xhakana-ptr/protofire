//! fs/src/btrfs/mod.rs
//!
//! Btrfs: the superblock and the trees it names, checksummed at every level,
//! read through the chunk map a single device holds.  The write path is the
//! last of the ten — a copy-on-write tree is a project of its own, and this
//! driver is the reader the roadmap ordered before it.

pub(crate) mod fs;
#[cfg(test)]
mod tests;
pub(crate) mod types;
mod volume;

pub use volume::BtrfsVolume;
