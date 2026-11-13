//! fs/src/ntfs/mod.rs
//!
//! NTFS: the boot sector and the MFT it points at, a record's attributes
//! wherever an attribute list has moved them, the index a directory's names
//! live in, and the read and write paths both — reads through the runs a
//! record names, writes through the same runs with the bitmap and the index
//! and the MFT's own size kept in step.

pub(crate) mod fs;
pub(crate) mod lznt1;
#[cfg(test)]
mod tests;
pub(crate) mod types;
mod volume;

pub use volume::NtfsFs;
