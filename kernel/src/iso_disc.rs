//! kernel/src/iso_disc.rs
//!
//! The ISO 9660 image this boot mounts.
//!
//! ## Why the kernel builds a disc
//!
//! The boot's third filesystem is a disc, and a disc is read-only, which is
//! what makes it the one that proves the namespace.  A tmpfs can be written, so
//! evidence that it holds what was put there is evidence about the tmpfs; a
//! disc cannot be, so the bytes a read returns are the bytes the image was
//! built with.
//!
//! The image is built here rather than shipped for the reason the PyroFS one
//! is: an image in the tree is one nobody rebuilt, and a format change would
//! find the stale copy before it found the code.
//!
//! ## The smallest disc that is legal
//!
//! ```text
//! sector 16 : primary volume descriptor
//! sector 17 : terminator
//! sector 18 : root directory: ".", "..", "README.TXT;1"
//! sector 19 : README.TXT's bytes
//! ```
//!
//! Four sectors, and every field the specification requires is filled.  A
//! disc missing the terminator still reads here, the reader stops when the
//! magic is gone, but a disc that is legal is the one worth building, because
//! it is what another reader would accept.

use alloc::vec;
use alloc::vec::Vec;

use fs::iso9660::SECTOR_SIZE;

/// The sectors the image occupies.
const SECTORS: usize = 20;

/// The sectors the volume claims.  Everything the image holds is inside them,
/// which is what a reader checks.
const VOLUME_BLOCKS: u32 = 16;

/// The sector the primary volume descriptor is in.
const DESCRIPTOR_SECTOR: usize = 16;
/// The sector the set's terminator is in.
const TERMINATOR_SECTOR: usize = 17;
/// The sector the root directory's extent is in.
const ROOT_SECTOR: u32 = 18;
/// The sector the file's bytes are in.
const FILE_SECTOR: u32 = 19;

/// The file's path, as an ISO 9660 identifier: uppercase, and `;1` for version
/// 1, which the format requires of every file.
const FILE_IDENTIFIER: &[u8] = b"README.TXT;1";

/// What the file holds.
///
/// A string no other file in the tree contains, for the same reason the volume
/// contents are: a comparison against a constant the disc never held would pass
/// on a disc that was never written.
pub const DISC_CONTENT: &[u8] = b"protofire reads this off a disc";

/// Build the image.
pub fn build() -> Vec<u8> {
    let mut image = vec![0u8; SECTORS * SECTOR_SIZE];

    let root = root_extent();
    let start = ROOT_SECTOR as usize * SECTOR_SIZE;
    image[start..start + root.len()].copy_from_slice(&root);

    let start = FILE_SECTOR as usize * SECTOR_SIZE;
    image[start..start + DISC_CONTENT.len()].copy_from_slice(DISC_CONTENT);

    let descriptor = descriptor(root.len() as u32);
    let start = DESCRIPTOR_SECTOR * SECTOR_SIZE;
    image[start..start + SECTOR_SIZE].copy_from_slice(&descriptor);

    let start = TERMINATOR_SECTOR * SECTOR_SIZE;
    image[start] = 255;
    image[start + 1..start + 6].copy_from_slice(b"CD001");
    image[start + 6] = 1;

    image
}

/// The root directory's extent: its own `.` and `..`, then the file.
fn root_extent() -> Vec<u8> {
    let mut extent = Vec::new();
    extent.extend_from_slice(&record(&[0x00], ROOT_SECTOR, SECTOR_SIZE as u32, true));
    extent.extend_from_slice(&record(&[0x01], ROOT_SECTOR, SECTOR_SIZE as u32, true));
    extent.extend_from_slice(&record(
        FILE_IDENTIFIER,
        FILE_SECTOR,
        DISC_CONTENT.len() as u32,
        false,
    ));
    // The extent is one sector, and the rest of it is zero, which is what
    // ends the record walk.
    extent.resize(SECTOR_SIZE, 0);
    extent
}

/// A directory record, laid out field by field as ECMA-119 9.1 has it.
///
/// The record's length is even, and 33 plus an *even* identifier is odd, so
/// the padding byte follows an even-length identifier, the rule a reader
/// walks by, and the one this disc has to be built by to be legal.
fn record(identifier: &[u8], extent: u32, length: u32, directory: bool) -> Vec<u8> {
    let padded = identifier.len() + (identifier.len().is_multiple_of(2) as usize);
    let total = 33 + padded;
    let mut bytes = Vec::with_capacity(total);
    bytes.push(total as u8);
    bytes.push(0); // extended attribute record length
    bytes.extend_from_slice(&extent.to_le_bytes());
    bytes.extend_from_slice(&extent.to_be_bytes());
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&[0u8; 7]); // recording date and time
    bytes.push(if directory { 0x02 } else { 0x00 });
    bytes.push(0); // file unit size
    bytes.push(0); // interleave gap
    bytes.extend_from_slice(&1u16.to_le_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.push(identifier.len() as u8);
    bytes.extend_from_slice(identifier);
    if identifier.len().is_multiple_of(2) {
        bytes.push(0);
    }
    bytes
}

/// The primary volume descriptor.
fn descriptor(root_length: u32) -> [u8; SECTOR_SIZE] {
    let mut descriptor = [0u8; SECTOR_SIZE];
    descriptor[0] = 1;
    descriptor[1..6].copy_from_slice(b"CD001");
    descriptor[6] = 1;

    // The system identifier and the volume identifier, both space padded.
    for slot in descriptor[8..40].iter_mut() {
        *slot = b' ';
    }
    for slot in descriptor[40..72].iter_mut() {
        *slot = b' ';
    }
    descriptor[40..48].copy_from_slice(b"BOOTDISC");

    // Volume space size, both halves.
    descriptor[80..84].copy_from_slice(&VOLUME_BLOCKS.to_le_bytes());
    descriptor[84..88].copy_from_slice(&VOLUME_BLOCKS.to_be_bytes());

    // Logical block size, both halves.
    descriptor[128..130].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
    descriptor[130..132].copy_from_slice(&(SECTOR_SIZE as u16).to_be_bytes());

    // Path table size and location: this image has no path table, and the
    // format allows a size of zero for a disc that a reader walks by records
    // alone.  A reader that needed the table would find zero tables here, which
    // is the honest description of the image.
    descriptor[132..136].copy_from_slice(&0u32.to_le_bytes());
    descriptor[136..140].copy_from_slice(&0u32.to_be_bytes());

    // The root directory's record, embedded at offset 156.
    let root = record(&[0x00], ROOT_SECTOR, root_length, true);
    descriptor[156..156 + 34].copy_from_slice(&root[..34]);

    // File structure version 1, which is the only one there is.
    descriptor[881] = 1;
    descriptor
}

#[cfg(test)]
mod tests {
    use super::DISC_CONTENT;
    use super::SECTOR_SIZE;
    use super::VOLUME_BLOCKS;
    use super::build;

    /// The image is the size its constants claim, and the volume does not
    /// claim more than the image holds.
    #[test]
    fn the_image_is_self_consistent() {
        let image = build();
        assert_eq!(image.len() % SECTOR_SIZE, 0);
        assert!((VOLUME_BLOCKS as usize) * SECTOR_SIZE <= image.len());
    }

    /// The descriptor is where the format puts it and says what this disc is.
    #[test]
    fn the_descriptor_is_where_the_format_puts_it() {
        let image = build();
        let start = 16 * SECTOR_SIZE;
        assert_eq!(image[start], 1, "the primary descriptor");
        assert_eq!(&image[start + 1..start + 6], b"CD001");
        assert_eq!(image[start + 6], 1, "version 1");
    }

    /// The set is terminated, which is what makes the disc legal.
    ///
    /// The reader stops when the magic is gone, so a disc without this still
    /// reads here, but a disc that is legal is the one another reader accepts.
    #[test]
    fn the_descriptor_set_is_terminated() {
        let image = build();
        let start = 17 * SECTOR_SIZE;
        assert_eq!(image[start], 255);
        assert_eq!(&image[start + 1..start + 6], b"CD001");
    }

    /// The file's bytes are on the disc, where its record says they are.
    #[test]
    fn the_content_is_on_the_disc() {
        let image = build();
        let start = 19 * SECTOR_SIZE;
        assert_eq!(&image[start..start + DISC_CONTENT.len()], DISC_CONTENT);
    }

    /// The label is the one the descriptor carries.
    #[test]
    fn the_label_is_the_one_the_descriptor_carries() {
        let image = build();
        let start = 16 * SECTOR_SIZE;
        assert_eq!(&image[start + 40..start + 48], b"BOOTDISC");
    }
}
