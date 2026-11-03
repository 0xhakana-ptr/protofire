//! fs/src/iso9660/mod.rs
//!
//! ISO 9660: the format a CD-ROM uses, read through Rock Ridge and Joliet.
//!
//! ## What this is, and what it is not
//!
//! It is a reader.  A disc is a read-only medium, so a write path would be a
//! writer for an *image* — which is what the previous tree had, and it was
//! built for a requirement of that kernel rather than for the format.  That
//! writer is 800 of the previous tree's 1,105 lines in one file, and it came
//! with three limits it documented itself: no multi-extent files, two-tree
//! discs written only where the trees agree, XA attributes ignored.
//!
//! None of that is here.  What is here is the reading half, rewritten:
//!
//! - `volume_descriptor` — the descriptor set, read by offset from bytes rather
//!   than by casting a sector to a packed struct.
//! - `record` — one directory record, and the three things this reader refuses
//!   (an extended attribute record, a multi-extent file, an interleaved one).
//! - `susp` — Rock Ridge: the POSIX name, the attributes, a symlink's target.
//! - `volume` — mounting, path resolution, and a file's bytes.
//!
//! ## Read-only, and what that buys
//!
//! Every path through a reader can be tested with an image built to the
//! specification, and a wrong answer is a wrong answer — not a write that
//! corrupted a disc somebody has to find later.  The one thing a reader cannot
//! check is "did something else understand what we wrote", which is the whole
//! difficulty of the writer this replaced.
//!
//! ## What is refused rather than half-read
//!
//! A volume that names an extended attribute record, a multi-extent file or an
//! interleaved one is refused at the point the reader meets it.  Reading the
//! first extent of a multi-extent file returns a truncated file that looks
//! complete, and a wrong file is worse than an error.

pub mod record;
pub mod susp;
#[cfg(test)]
mod tests;
pub mod volume;
pub mod volume_descriptor;

pub use record::Record;
pub use susp::SystemUse;
pub use volume::Iso9660Volume;
pub use volume_descriptor::SECTOR_SIZE;
pub use volume_descriptor::VolumeDescriptor;
