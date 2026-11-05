//! fs/src/iso9660/record/tests.rs
//!
//! The ISO 9660 directory record: its variable length, the name, and the extent
//! it names.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

use crate::iso9660::record::FLAG_DIRECTORY;
use crate::iso9660::record::FLAG_MULTI_EXTENT;
use crate::iso9660::record::Record;
use crate::iso9660::record::strip_version;
use alloc::vec::Vec;

/// Build a record the way the specification lays one out.
fn record(identifier: &[u8], extent: u32, length: u32, flags: u8) -> Vec<u8> {
    let mut record = Vec::new();
    let padded_identifier = identifier.len() + (identifier.len() & 1);
    let total = 33 + padded_identifier;
    record.push(total as u8);
    record.push(0); // extended attribute blocks
    record.extend_from_slice(&extent.to_le_bytes());
    record.extend_from_slice(&extent.to_be_bytes());
    record.extend_from_slice(&length.to_le_bytes());
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(&[0u8; 7]); // recording date
    record.push(flags);
    record.push(0); // file unit size
    record.push(0); // interleave gap
    record.extend_from_slice(&1u16.to_le_bytes());
    record.extend_from_slice(&1u16.to_be_bytes());
    record.push(identifier.len() as u8);
    record.extend_from_slice(identifier);
    if identifier.len() % 2 == 1 {
        record.push(0);
    }
    record
}

/// A record is decoded from its fields.
#[test]
fn a_record_is_decoded() {
    let bytes = record(b"HELLO.TXT;1", 30, 512, 0);
    let (parsed, next) = Record::parse(&bytes, 0, false).expect("a record");
    assert_eq!(parsed.extent, 30);
    assert_eq!(parsed.data_length, 512);
    assert!(!parsed.is_directory());
    assert_eq!(next, bytes.len(), "the next record starts after this one");
}

/// A zero length is not an empty record: it ends the sector.
///
/// A reader that kept going would read padding as entries, which on a
/// directory extent is a file with a name made of its own bytes.
#[test]
fn a_zero_length_is_not_a_record() {
    let mut bytes = record(b"A;1", 0, 0, 0);
    bytes[0] = 0;
    assert_eq!(Record::parse(&bytes, 0, false), None);
}

/// A length that runs past the buffer is refused rather than read.
#[test]
fn a_record_past_the_buffer_is_refused() {
    let bytes = record(b"A;1", 0, 0, 0);
    assert_eq!(Record::parse(&bytes[..10], 0, false), None);
}

/// A directory flag is a directory.
#[test]
fn the_directory_flag_says_so() {
    let bytes = record(b"SUB", 25, 115, FLAG_DIRECTORY);
    let (parsed, _) = Record::parse(&bytes, 0, false).expect("a record");
    assert!(parsed.is_directory());
}

/// The version suffix is not part of the name, and neither is the dot that
/// separated it.
#[test]
fn a_version_suffix_is_stripped() {
    assert_eq!(strip_version("HELLO.TXT;1"), "HELLO.TXT");
    assert_eq!(strip_version("README.;1"), "README");
    assert_eq!(strip_version("SUB"), "SUB");
}

/// `.` and `..` are recognised in a primary tree and in a Joliet one, and
/// a Joliet name below U+0100 is not mistaken for one.
///
/// This is the case worth pinning: a Joliet name whose first byte is zero
/// is any name below U+0100, so checking one byte would hide most of a
/// disc's files.
#[test]
fn dot_entries_are_recognised_in_both_trees() {
    let dot = record(&[0x00], 20, 152, FLAG_DIRECTORY);
    let (parsed, _) = Record::parse(&dot, 0, false).expect("dot");
    assert!(parsed.is_dot_entry());

    let joliet_dot = record(&[0x00, 0x00], 20, 152, FLAG_DIRECTORY);
    let (parsed, _) = Record::parse(&joliet_dot, 0, true).expect("joliet dot");
    assert!(parsed.is_dot_entry());

    // "A" in UCS-2 is 0x0041, first byte zero, second not.
    let joliet_a = record(&[0x00, 0x41], 30, 10, 0);
    let (parsed, _) = Record::parse(&joliet_a, 0, true).expect("joliet A");
    assert!(
        !parsed.is_dot_entry(),
        "a name below U+0100 is not a dot entry"
    );
}

/// A multi-extent record is recognisable, so the reader can refuse it
/// rather than return its first extent as the whole file.
#[test]
fn a_multi_extent_record_says_so() {
    let bytes = record(b"BIG.BIN;1", 30, 2048, FLAG_MULTI_EXTENT);
    let (parsed, _) = Record::parse(&bytes, 0, false).expect("a record");
    assert!(parsed.is_multi_extent());
}

/// A record with an extended attribute record in front of its data says
/// so, because the reader does not read them.
#[test]
fn an_extended_attribute_record_is_reported() {
    let mut bytes = record(b"X.BIN;1", 30, 10, 0);
    bytes[1] = 1;
    let (parsed, _) = Record::parse(&bytes, 0, false).expect("a record");
    assert!(parsed.has_extended_attributes());
}

/// A record from another member of a multi-disc set is not this disc's.
#[test]
fn a_record_from_another_volume_is_refused() {
    let mut bytes = record(b"X.BIN;1", 30, 10, 0);
    // Volume sequence number, little half, at offset 28.
    bytes[28..30].copy_from_slice(&2u16.to_le_bytes());
    assert_eq!(Record::parse(&bytes, 0, false), None);
}

/// A record that says its file is interleaved is refused by the caller,
/// and the field it says so in is actually read.
///
/// The first version of this read a helper that returned zero, a check
/// that could not fail.  The field is at offset 26 and this pins that it
/// is read from there.
#[test]
fn an_interleaved_record_is_recognisable() {
    let mut bytes = record(b"I.BIN;1", 30, 10, 0);
    bytes[crate::iso9660::record::OFFSET_FILE_UNIT_SIZE] = 4;
    let (parsed, _) = Record::parse(&bytes, 0, false).expect("a record");
    assert!(
        parsed.is_interleaved(),
        "a unit size of 4 means interleaved"
    );
}

/// The name is the identifier with its version stripped, when there is no
/// Rock Ridge name.
#[test]
fn the_name_falls_back_to_the_identifier() {
    let bytes = record(b"HELLO.TXT;1", 30, 512, 0);
    let (parsed, _) = Record::parse(&bytes, 0, false).expect("a record");
    assert_eq!(parsed.name(), "HELLO.TXT");
}
