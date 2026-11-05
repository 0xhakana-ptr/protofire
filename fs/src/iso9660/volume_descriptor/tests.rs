//! fs/src/iso9660/volume_descriptor/tests.rs
//!
//! The volume descriptor: the identifier, the root record, and the fields a
//! reader needs to mount.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

use crate::iso9660::volume_descriptor::DESCRIPTOR_SET_START;
use crate::iso9660::volume_descriptor::OFFSET_BLOCK_SIZE;
use crate::iso9660::volume_descriptor::OFFSET_VOLUME_SPACE_SIZE;
use crate::iso9660::volume_descriptor::SECTOR_SIZE;
use crate::iso9660::volume_descriptor::TYPE_PRIMARY;
use crate::iso9660::volume_descriptor::VolumeDescriptor;
use crate::iso9660::volume_descriptor::both16;
use crate::iso9660::volume_descriptor::both32;

/// A sector with a primary descriptor built to the specification.
///
/// Written by hand rather than by a writer this crate does not have: a test
/// that built its input with the code under test would agree with itself.
fn primary(label: &[u8], blocks: u32, block_size: u16) -> [u8; SECTOR_SIZE] {
    let mut sector = [0u8; SECTOR_SIZE];
    sector[0] = TYPE_PRIMARY;
    sector[1..6].copy_from_slice(b"CD001");
    sector[6] = 1;
    // The volume id: 32 bytes, space padded.
    for slot in sector[40..40 + 32].iter_mut() {
        *slot = b' ';
    }
    sector[40..40 + label.len()].copy_from_slice(label);
    // Volume space size, both halves.
    sector[OFFSET_VOLUME_SPACE_SIZE..OFFSET_VOLUME_SPACE_SIZE + 4]
        .copy_from_slice(&blocks.to_le_bytes());
    sector[OFFSET_VOLUME_SPACE_SIZE + 4..OFFSET_VOLUME_SPACE_SIZE + 8]
        .copy_from_slice(&blocks.to_be_bytes());
    // Block size, both halves.
    sector[OFFSET_BLOCK_SIZE..OFFSET_BLOCK_SIZE + 2].copy_from_slice(&block_size.to_le_bytes());
    sector[OFFSET_BLOCK_SIZE + 2..OFFSET_BLOCK_SIZE + 4].copy_from_slice(&block_size.to_be_bytes());
    sector
}

/// The descriptors begin at sector 16, which is the one constant a reader
/// has to have right before it can find anything.
#[test]
fn the_descriptor_set_begins_at_sector_sixteen() {
    assert_eq!(DESCRIPTOR_SET_START, 16);
    assert_eq!(SECTOR_SIZE, 2048);
}

/// A primary descriptor is decoded from its fields.
#[test]
fn a_primary_descriptor_is_decoded() {
    let sector = primary(b"MYVOL", 100, 2048);
    let descriptor = VolumeDescriptor::parse(16, &sector).expect("a primary descriptor");
    assert_eq!(descriptor.descriptor_type, TYPE_PRIMARY);
    assert_eq!(descriptor.volume_id, "MYVOL");
    assert_eq!(descriptor.volume_space_size, 100);
    assert_eq!(descriptor.block_size, 2048);
    assert!(!descriptor.joliet);
    assert!(descriptor.describes_a_tree());
}

/// The volume identifier is space padded, and its padding is not part of
/// the name.
#[test]
fn a_volume_identifier_drops_its_padding() {
    let sector = primary(b"AB", 1, 2048);
    let descriptor = VolumeDescriptor::parse(16, &sector).expect("descriptor");
    assert_eq!(descriptor.volume_id, "AB", "trailing spaces are padding");
}

/// A sector whose magic is elsewhere is not a descriptor, and the reader
/// says so rather than reading a filesystem's data as one.
#[test]
fn a_sector_without_the_magic_is_not_a_descriptor() {
    let mut sector = primary(b"X", 1, 2048);
    sector[1] = b'X';
    assert_eq!(VolumeDescriptor::parse(16, &sector), None);
}

/// A version other than 1 is refused: it is a descriptor this reader was
/// not written against.
#[test]
fn a_descriptor_version_of_two_is_refused() {
    let mut sector = primary(b"X", 1, 2048);
    sector[6] = 2;
    assert_eq!(VolumeDescriptor::parse(16, &sector), None);
}

/// A field stored twice is read from both halves, and a caller can see
/// whether they agree.
///
/// The two halves are the format's own redundancy: a disc whose halves
/// disagree is one two readers would see differently, and that is worth
/// being able to check rather than hiding.
#[test]
fn a_doubled_field_is_readable_from_both_halves() {
    let sector = primary(b"X", 0x1234_5678, 2048);
    let (little, big) = both32(&sector, OFFSET_VOLUME_SPACE_SIZE).expect("the field");
    assert_eq!(little, 0x1234_5678);
    assert_eq!(
        big, 0x1234_5678,
        "the two halves agree on a well-formed disc"
    );

    let (little, big) = both16(&sector, OFFSET_BLOCK_SIZE).expect("the field");
    assert_eq!(little, 2048);
    assert_eq!(big, 2048);
}

/// A field running past the sector answers `None` rather than panicking.
#[test]
fn a_field_past_the_sector_is_none() {
    let sector = [0u8; SECTOR_SIZE];
    assert_eq!(both32(&sector, SECTOR_SIZE - 4), None);
    assert_eq!(both16(&sector, SECTOR_SIZE - 2), None);
}
