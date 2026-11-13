//! fs/src/ext4/mod.rs
//!
//! ext4: the on-disk format, read whole and written — files, directories,
//! symlinks, device nodes, the allocator, and the journal that orders the
//! metadata's writes.
//!
//! ## What this module is
//!
//! A filesystem backend in the [`crate::filesystem::FileSystem`] shape:
//! [`Ext4Volume::open`] mounts a volume a device holds, [`Ext4Volume::make`]
//! writes a fresh one, and everything between them — lookup, listing,
//! creation, rename, removal, reading, writing — is the format's own
//! arithmetic, read and written through the block cache and ordered by the
//! journal when the volume carries one.
//!
//! ## The two block models, and the journal
//!
//! A file's blocks are mapped by an extent tree rooted in the inode, or by
//! the direct-and-indirect pointer array an ext2 volume uses; a tree whose
//! leaf fills falls back to the array, which is the format's own fallback
//! and the reason both models live here.  Metadata writes go through the
//! journal first — descriptor, data, commit, with the superblock's `errno`
//! as the volume's dirty flag — so a crash leaves the transaction's older
//! self rather than a half-written newer one, and a dirty journal replays
//! at open before anything reads a byte.
//!
//! ## What is deliberately not here
//!
//! Truncation, which would free the blocks past the new end; the xattr and
//! checksum surfaces, which the VFS's defaults refuse; and a connect to
//! any feature the incompat word names that this driver cannot read, which
//! is what makes it refuse the volume rather than guess at its bytes.

pub(super) mod constants;
pub(super) mod format;
pub(super) mod fs;
pub(super) mod journal;
#[cfg(test)]
mod tests;
pub(super) mod types;
pub(super) mod vfs;

pub use vfs::Ext4Volume;
