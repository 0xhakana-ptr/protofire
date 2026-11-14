//! fs/src/squashfs/mod.rs
//!
//! SquashFS: a read-only, compressed filesystem.  The superblock's flags name
//! the compressor, LZ4 and ZSTD are the two this driver decodes, and each
//! codec lives in this module, because the roadmap promises no shared
//! compression abstraction until a third user appears.

pub(crate) mod fs;
#[cfg(test)]
mod tests;
pub(crate) mod types;
mod volume;
pub(crate) mod zstd;

pub use volume::SquashfsVolume;
