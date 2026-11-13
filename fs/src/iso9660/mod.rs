//! fs/src/iso9660/mod.rs
//!
//! ISO 9660: the format a CD-ROM uses, read through Rock Ridge and Joliet, and
//! written in the places the format and the volume allow.
//!
//! ## What this is
//!
//! - `volume_descriptor`, the descriptor set, read by offset from bytes rather
//!   than by casting a sector to a packed struct.
//! - `record`, one directory record, and the three things this driver refuses
//!   (an extended attribute record, a multi-extent file, an interleaved one).
//! - `susp`, Rock Ridge: the POSIX name, the attributes, a symlink's target —
//!   parsed and built, because a record this driver creates or renames carries
//!   the entries it writes.
//! - `volume`, mounting, path resolution, a file's bytes, and the mutations a
//!   writable device takes.
//! - `write`, the write half of the format's structures: extents, records
//!   pointed at new places, records appended to or taken out of directories,
//!   and the path tables serialised in both byte orders.
//! - `allocate`, where new space comes from: the map of what the volume holds,
//!   the allocator that hands out what it does not, and the tail rule that
//!   gives blocks back.
//!
//! ## The write path, and where its lines are
//!
//! An ISO 9660 file is one raw contiguous extent whose two fields — where it
//! starts and how long it is — are in its directory record.  So a write
//! inside the length changes no metadata at all; a length change rewrites one
//! record in place; growing past the block the file has takes blocks from the
//! volume's free space, which is what its structures do not name: a block map
//! is built by walking the whole volume, and a volume with anything this
//! driver cannot account for — a descriptor it does not know, an extended
//! attribute record, no terminator on the descriptor set — is one it appends
//! to instead, because handing a block out is not a thing to guess at.  A file
//! with something after it *moves* into that free space rather than growing
//! where it is, because an extent is one contiguous run.  A regular file can
//! be created — empty, in the directory it names — and removed, which is a
//! record appended to that directory or shifted out of it; a **directory** can
//! be created and removed too, and that is what moves the path tables, which
//! are rebuilt from the tree rather than edited in place.  A directory that
//! still holds something refuses to go, and an entry can be renamed or moved:
//! its record leaves one directory and joins another, a directory's ".."
//! follows it, and the tables are rebuilt.
//!
//! The stages those come in — a file's data, then its length, then space from
//! the allocator, then its record, then directories, then rename — are the
//! order the old tree's RFC 0011 took, and the tests keep it.
//!
//! ## A disc with two trees
//!
//! A Joliet disc names every file twice, and the trees share the files' *data*
//! but not their directories.  This driver reads through one tree — the
//! supplementary one when there is one, because its names are the author's —
//! and writes only where the two agree, which is the file's data: an
//! overwrite inside its length is the same bytes under both records.  A
//! length change and everything structural is refused, because each would
//! have to appear in both trees and the trees spell a name differently by
//! design, so nothing on the volume says which record in the other tree is
//! the same file's.
//!
//! ## What a writable mount writes at open
//!
//! A volume whose System Use areas carry Rock Ridge entries is required to
//! name the extension in an `ER` entry, and this driver has been writing such
//! entries since names stopped having to be ISO 9660 identifiers.  The entry
//! cannot fit in a record (its mandated text makes it 237 bytes and a
//! record's length is one byte), so the root's own "." record carries an `SP`
//! marker and a `CE` naming a continuation area, where the reference goes —
//! and the root, rebuilt elsewhere, is what the descriptor is repointed at.
//! It happens at open because the root's "." record grows by the area and
//! every record after it moves, and at open no node holds a record offset
//! that could be left pointing at another file's bytes.  It is best-effort: a
//! volume this cannot be written to still mounts.
//!
//! ## Limits
//!
//! - No multi-extent files (ISO 9660 Level 3 interleave).
//! - XA attributes are ignored; a record that names an Extended Attribute
//!   Record is one whose blocks the block map refuses to hand out of.
//! - Sector size is always assumed to be 2048 bytes.
//! - A disc has no journal and no data checksum, so a write that stops half way
//!   leaves what it touched half new — exactly what a raw write means on any
//!   filesystem without one, and nothing here claims atomicity it does not
//!   have.

pub mod allocate;
pub mod record;
pub mod susp;
#[cfg(test)]
mod tests;
pub mod volume;
pub mod volume_descriptor;
pub mod write;

pub use record::Record;
pub use susp::SystemUse;
pub use volume::Iso9660Volume;
pub use volume_descriptor::SECTOR_SIZE;
pub use volume_descriptor::VolumeDescriptor;
