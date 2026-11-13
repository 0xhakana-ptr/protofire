//! fs/src/iso9660/tests.rs
//!
//! End-to-end tests: build an image to the specification, mount it, read it.
//!
//! ## Why the image is built here
//!
//! A test that built its input with the code under test would agree with
//! itself.  These images are written by hand from the field offsets the
//! specification gives, so a reader that read the wrong offset would read a
//! number that is not the one the builder wrote, which is the whole point.
//!
//! ## The image
//!
//! ```text
//! sector 16 : primary volume descriptor, label "TESTDISC", 32 blocks
//! sector 17 : terminator
//! sector 20 : root directory: ".", "..", "HELLO.TXT;1", "SUB"
//! sector 25 : SUB directory: ".", "..", "INNER.TXT;1"
//! sector 30 : HELLO.TXT's bytes
//! sector 31 : INNER.TXT's bytes
//! ```
//!
//! The offsets are the specification's, and the constants below name them so a
//! test that reads `<something>_OFFSET` is checking the number the reader uses.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use block::BlockDevice;
use block::MemoryBlockDevice;

use super::Iso9660Volume;
use super::volume_descriptor::SECTOR_SIZE;

use crate::FileSystem;
use crate::types::NodeKind;

impl BlockDevice for ImageDevice {
    fn name(&self) -> &str {
        "iso-image"
    }
    /// A device that says 2048 and reads 2048.
    ///
    /// The first version of this said nothing, the default is 512, and read
    /// its `lba` as a 2048-byte index anyway.  That made every test pass and
    /// every real device fail: the reader's offsets and this device's
    /// arithmetic were both wrong in the same direction.  A test device that
    /// lies about its block size is one that cannot catch the bug it is here
    /// to catch.
    fn block_size(&self) -> usize {
        SECTOR_SIZE
    }
    fn block_count(&self) -> u64 {
        (self.bytes.len() / SECTOR_SIZE) as u64
    }
    fn is_read_only(&self) -> bool {
        true
    }
    fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> abi::Result<()> {
        let start = lba as usize * SECTOR_SIZE;
        if start + buffer.len() > self.bytes.len() {
            return Err(abi::Error::InvalidArgument);
        }
        buffer.copy_from_slice(&self.bytes[start..start + buffer.len()]);
        Ok(())
    }
    fn write_blocks(&self, _lba: u64, _data: &[u8]) -> abi::Result<()> {
        Err(abi::Error::PermissionDenied)
    }
}

impl block::QueuedBlockDevice for ImageDevice {
    fn as_block_device(&self) -> &dyn BlockDevice {
        self
    }
}

/// An image held in memory.  Read-only, because a disc is.
struct ImageDevice {
    bytes: Vec<u8>,
}

const IMAGE_SECTORS: usize = 40;
const VOLUME_BLOCKS: u32 = 32;

const ROOT_SECTOR: u64 = 20;
const SUB_SECTOR: u64 = 25;
const HELLO_SECTOR: u64 = 30;
const INNER_SECTOR: u64 = 31;

/// Build a directory record: the specification's layout, field by field.
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

/// The extent a directory's records occupy, at its recorded length.
///
/// Not padded to a sector: a directory's length is what its record says, and
/// a writer that padded it would make every test's arithmetic cover for a
/// gap the reader reads as "no more records in this block".
fn directory_extent(records: &[Vec<u8>]) -> Vec<u8> {
    let mut extent = Vec::new();
    for record in records {
        extent.extend_from_slice(record);
    }
    extent
}

/// Build the image the module header describes, as bytes.
///
/// The read tests mount it on the device that lies about nothing; the write
/// tests hand the same bytes to a `MemoryBlockDevice`, whose 512-byte blocks
/// are a device's, not a disc's — the two block sizes are exactly what the
/// write path's arithmetic has to keep apart.
fn image_bytes() -> Vec<u8> {
    let mut bytes = vec![0u8; IMAGE_SECTORS * SECTOR_SIZE];

    // The root directory: ".", "..", "HELLO.TXT;1", "SUB".
    let root_records = vec![
        record(&[0x00], ROOT_SECTOR as u32, SECTOR_SIZE as u32, true),
        record(&[0x01], ROOT_SECTOR as u32, SECTOR_SIZE as u32, true),
        record(b"HELLO.TXT;1", HELLO_SECTOR as u32, 13, false),
        record(b"SUB", SUB_SECTOR as u32, SECTOR_SIZE as u32, true),
    ];
    let root = directory_extent(&root_records);
    let root_len = root.len() as u32;
    let start = ROOT_SECTOR as usize * SECTOR_SIZE;
    bytes[start..start + root.len()].copy_from_slice(&root);

    // The subdirectory.
    let sub_records = vec![
        record(&[0x00], SUB_SECTOR as u32, SECTOR_SIZE as u32, true),
        record(&[0x01], ROOT_SECTOR as u32, SECTOR_SIZE as u32, true),
        record(b"INNER.TXT;1", INNER_SECTOR as u32, 10, false),
    ];
    let sub = directory_extent(&sub_records);
    let start = SUB_SECTOR as usize * SECTOR_SIZE;
    bytes[start..start + sub.len()].copy_from_slice(&sub);

    // The file contents.
    let start = HELLO_SECTOR as usize * SECTOR_SIZE;
    bytes[start..start + 13].copy_from_slice(b"hello, world\n");
    let start = INNER_SECTOR as usize * SECTOR_SIZE;
    bytes[start..start + 10].copy_from_slice(b"inner.txt\n");

    // The primary volume descriptor at sector 16.
    let descriptor_start = 16 * SECTOR_SIZE;
    let descriptor = &mut bytes[descriptor_start..descriptor_start + SECTOR_SIZE];
    descriptor[0] = 1;
    descriptor[1..6].copy_from_slice(b"CD001");
    descriptor[6] = 1;
    for slot in descriptor[40..40 + 32].iter_mut() {
        *slot = b' ';
    }
    descriptor[40..48].copy_from_slice(b"TESTDISC");
    descriptor[80..84].copy_from_slice(&VOLUME_BLOCKS.to_le_bytes());
    descriptor[84..88].copy_from_slice(&VOLUME_BLOCKS.to_be_bytes());
    descriptor[128..130].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
    descriptor[130..132].copy_from_slice(&(SECTOR_SIZE as u16).to_be_bytes());
    // The root record, embedded at offset 156.
    let root_record = record(&[0x00], ROOT_SECTOR as u32, root_len, true);
    descriptor[156..156 + 34].copy_from_slice(&root_record[..34]);

    // The terminator at sector 17.
    let terminator = 17 * SECTOR_SIZE;
    bytes[terminator] = 255;
    bytes[terminator + 1..terminator + 6].copy_from_slice(b"CD001");
    bytes[terminator + 6] = 1;

    bytes
}

fn image() -> ImageDevice {
    ImageDevice {
        bytes: image_bytes(),
    }
}

fn mounted() -> Arc<Iso9660Volume> {
    let device: Arc<dyn block::QueuedBlockDevice> = Arc::new(image());
    Iso9660Volume::open(device).expect("the image mounts")
}

/// A disc mounts, and its label is the one the descriptor carries.
#[test]
fn a_disc_mounts_and_reports_its_label() {
    let volume = mounted();
    assert_eq!(volume.name(), "TESTDISC");
}

/// A file is found by its name, and its bytes are the ones on the disc.
///
/// The whole path: the descriptor names a root, the root's extent holds a
/// record, the record names an extent, and the extent holds the bytes.
#[test]
fn a_file_is_read_through_the_tree() {
    let volume = mounted();
    let node = volume.lookup("/HELLO.TXT").expect("the file");
    assert_eq!(node.name(), "HELLO.TXT");
    assert_eq!(node.kind(), NodeKind::File);
    assert_eq!(node.size(), 13);

    let mut buffer = [0u8; 13];
    assert_eq!(node.read(0, &mut buffer), Ok(13));
    assert_eq!(&buffer, b"hello, world\n");
}

/// A path is walked one component at a time, and a file inside a
/// subdirectory is reached the same way one in the root is.
#[test]
fn a_nested_file_is_reached() {
    let volume = mounted();
    let node = volume.lookup("/SUB/INNER.TXT").expect("the nested file");
    let mut buffer = [0u8; 10];
    assert_eq!(node.read(0, &mut buffer), Ok(10));
    assert_eq!(&buffer, b"inner.txt\n");
}

/// A read past the end answers what is left, and a read starting past it
/// answers nothing.
///
/// A caller that reads until zero is how a short read is spelled, and a reader
/// that gave an error at end of file would make it a special case.
#[test]
fn a_read_is_short_at_the_end() {
    let volume = mounted();
    let node = volume.lookup("/HELLO.TXT").expect("the file");

    let mut buffer = [0u8; 8];
    assert_eq!(node.read(10, &mut buffer), Ok(3), "three bytes left");
    assert_eq!(&buffer[..3], b"ld\n");

    assert_eq!(node.read(13, &mut buffer), Ok(0), "past the end");
    assert_eq!(node.read(1000, &mut buffer), Ok(0), "far past the end");
}

/// The root directory lists the entries a reader expects, and not the `.` and
/// `..` records every extent carries.
#[test]
fn the_root_directory_lists_its_entries() {
    let volume = mounted();
    let mut names = Vec::new();
    let mut index = 0;
    while let Ok(entry) = volume.read_dir("/", index) {
        names.push(entry.name.clone());
        index += 1;
    }
    assert_eq!(names, vec!["HELLO.TXT", "SUB"]);
    assert!(
        !names.iter().any(|name| name.is_empty()),
        "the dot entries are not entries"
    );
}

/// A directory entry says whether it is a directory.
#[test]
fn a_directory_entry_carries_its_kind_and_size() {
    let volume = mounted();
    let entry = volume.read_dir("/", 1).expect("the second entry");
    assert_eq!(entry.name, "SUB");
    assert_eq!(entry.kind, NodeKind::Directory);
}

/// A path that names nothing is `NotFound`, and one that continues past a file
/// is too.
#[test]
fn a_path_that_names_nothing_is_not_found() {
    let volume = mounted();
    assert_eq!(
        volume.lookup("/MISSING.TXT").err(),
        Some(abi::Error::NotFound)
    );
    assert_eq!(
        volume.lookup("/HELLO.TXT/child").err(),
        Some(abi::Error::NotFound),
        "a file cannot hold a path"
    );
}

/// A device that is not an ISO 9660 disc is refused, and the refusal is not a
/// panic.
#[test]
fn a_device_that_is_not_a_disc_is_refused() {
    let device: Arc<dyn block::QueuedBlockDevice> =
        MemoryBlockDevice::new("blank", vec![0u8; 64 * SECTOR_SIZE], true);
    assert_eq!(
        Iso9660Volume::open(device).err(),
        Some(abi::Error::InvalidArgument)
    );
}

/// Every mutation is refused on a read-only device, because the device is:
/// a volume mounted from a read-only slice of the boot disk — which is how
/// `/system` is mounted — rejects the device write, not the filesystem.
#[test]
fn a_disc_refuses_every_write() {
    let volume = mounted();
    assert_eq!(
        volume.create_file("/NEW.TXT").err(),
        Some(abi::Error::PermissionDenied)
    );
    assert_eq!(
        volume.create_dir("/NEWDIR").err(),
        Some(abi::Error::PermissionDenied)
    );
    assert_eq!(
        volume.remove_path("/HELLO.TXT").err(),
        Some(abi::Error::PermissionDenied)
    );
    assert_eq!(
        volume.rename("/HELLO.TXT", "/OTHER.TXT").err(),
        Some(abi::Error::PermissionDenied)
    );

    let node = volume.lookup("/HELLO.TXT").expect("the file");
    assert_eq!(
        node.write(0, b"x").err(),
        Some(abi::Error::PermissionDenied)
    );
}

/// A directory's own read is refused rather than returning its extent's bytes.
#[test]
fn reading_a_directory_is_refused() {
    let volume = mounted();
    let node = volume.lookup("/SUB").expect("the directory");
    assert_eq!(node.kind(), NodeKind::Directory);
    let mut buffer = [0u8; 16];
    assert_eq!(
        node.read(0, &mut buffer).err(),
        Some(abi::Error::InvalidArgument)
    );
}

/// The image the tests build is the size its constants claim.
#[test]
fn the_image_geometry_is_what_the_tests_say() {
    let image = image();
    assert_eq!(image.bytes.len(), IMAGE_SECTORS * SECTOR_SIZE);
}

// ── the write path (the order is RFC 0011's: data, length, space, record,
//    directories, rename) ─────────────────────────────────────────────────

use super::allocate;
use super::record::OFFSET_DATA_LENGTH;
use super::record::Record;
use super::volume::Iso9660Volume as Volume;
use super::volume_descriptor::OFFSET_L_PATH_TABLE_LOC;
use super::volume_descriptor::OFFSET_M_PATH_TABLE_LOC;
use super::volume_descriptor::OFFSET_PATH_TABLE_SIZE;
use super::volume_descriptor::OFFSET_VOLUME_SPACE_SIZE;
use super::write;

const HELLO_CONTENT: &[u8] = b"hello, world\n";
const INNER_CONTENT: &[u8] = b"inner.txt\n";

/// The volume and its device, writable: the write tests need a device that
/// takes the write, which is the one thing the read tests never do.
fn writable_volume() -> (Arc<MemoryBlockDevice>, Arc<Volume>) {
    let device = MemoryBlockDevice::new("iso-write", image_bytes(), false);
    let volume = Volume::open(device.clone()).expect("the writable image mounts");
    (device, volume)
}

/// The blocks the volume claims, read off the medium.
fn volume_blocks(device: &Arc<MemoryBlockDevice>) -> u32 {
    let mut sector = [0u8; SECTOR_SIZE];
    write::read_exact(&*device.clone(), 16 * SECTOR_SIZE as u64, &mut sector)
        .expect("the primary descriptor reads");
    super::volume_descriptor::both32(&sector, OFFSET_VOLUME_SPACE_SIZE)
        .expect("the space field")
        .0
}

/// The root directory's extent, as the descriptor names it.
///
/// A writable volume's open rebuilds that extent elsewhere, so a test that
/// looks at the medium has to ask where it is rather than assume the address
/// the fixture was built with.
fn root_extent(device: &Arc<MemoryBlockDevice>) -> (u32, u32) {
    let mut sector = [0u8; SECTOR_SIZE];
    write::read_exact(&*device.clone(), 16 * SECTOR_SIZE as u64, &mut sector)
        .expect("the primary descriptor reads");
    let (record, _) = Record::parse(&sector[156..190], 0, false).expect("the root record");
    (record.extent, record.data_length)
}

/// Walk an extent's records the way the readers do: a zero length says the
/// rest of the block holds nothing, and the next record is in the next one.
fn walk_records(data: &[u8], joliet: bool) -> Vec<Record> {
    let mut records = Vec::new();
    let mut at = 0usize;
    while at < data.len() {
        match Record::parse(data, at, joliet) {
            Some((record, next)) => {
                records.push(record);
                at = next;
            }
            None => {
                let sector_end = (at / SECTOR_SIZE + 1) * SECTOR_SIZE;
                if sector_end <= at || sector_end >= data.len() {
                    break;
                }
                at = sector_end;
            }
        }
    }
    records
}

/// A directory's records, read off the medium.
fn records_in(
    device: &Arc<MemoryBlockDevice>,
    extent_location: u32,
    extent_size: u32,
) -> Vec<Record> {
    let mut data = vec![0u8; extent_size as usize];
    allocate::read_extent_bytes(
        &*device.clone(),
        SECTOR_SIZE as u16,
        extent_location,
        extent_size,
        0,
        &mut data,
    )
    .expect("the extent reads");
    walk_records(&data, false)
}

/// One record of a directory, by its identifier.
fn record_named(
    device: &Arc<MemoryBlockDevice>,
    extent_location: u32,
    extent_size: u32,
    identifier: &[u8],
) -> Record {
    records_in(device, extent_location, extent_size)
        .into_iter()
        .find(|record| record.identifier == identifier)
        .unwrap_or_else(|| panic!("no record for {identifier:?}"))
}

/// The identifiers the root directory's records carry, in the order they sit
/// on the medium.
fn root_identifiers(device: &Arc<MemoryBlockDevice>) -> Vec<Vec<u8>> {
    let (location, size) = root_extent(device);
    records_in(device, location, size)
        .into_iter()
        .map(|record| record.identifier)
        .collect()
}

/// The directories a path table names, as `(number, parent, identifier,
/// extent)`.  A record's number is its position, so it is not read from the
/// table — it *is* the table's order.
fn parse_path_table(bytes: &[u8], big_endian: bool) -> Vec<(u16, u16, Vec<u8>, u32)> {
    let mut entries = Vec::new();
    let mut at = 0usize;
    while at < bytes.len() {
        let len_di = bytes[at] as usize;
        if len_di == 0 {
            // The table is shorter than the space it is stored in.
            break;
        }
        let extent = if big_endian {
            u32::from_be_bytes(bytes[at + 2..at + 6].try_into().expect("four bytes"))
        } else {
            u32::from_le_bytes(bytes[at + 2..at + 6].try_into().expect("four bytes"))
        };
        let parent = if big_endian {
            u16::from_be_bytes(bytes[at + 6..at + 8].try_into().expect("two bytes"))
        } else {
            u16::from_le_bytes(bytes[at + 6..at + 8].try_into().expect("two bytes"))
        };
        let identifier = bytes[at + 8..at + 8 + len_di].to_vec();
        entries.push((entries.len() as u16 + 1, parent, identifier, extent));
        at += 8 + len_di + (len_di % 2);
    }
    entries
}

/// The records a path table holds, as `(number, parent, identifier, extent)`.
type PathTableRecords = Vec<(u16, u16, Vec<u8>, u32)>;

/// Both path tables, read back off the volume.
fn path_tables(device: &Arc<MemoryBlockDevice>) -> (PathTableRecords, PathTableRecords) {
    let mut sector = [0u8; SECTOR_SIZE];
    write::read_exact(&*device.clone(), 16 * SECTOR_SIZE as u64, &mut sector)
        .expect("the primary descriptor reads");
    let size = super::volume_descriptor::both32(&sector, OFFSET_PATH_TABLE_SIZE)
        .expect("size")
        .0;
    let l = u32::from_le_bytes(
        sector[OFFSET_L_PATH_TABLE_LOC..OFFSET_L_PATH_TABLE_LOC + 4]
            .try_into()
            .expect("four bytes"),
    );
    let m = u32::from_be_bytes(
        sector[OFFSET_M_PATH_TABLE_LOC..OFFSET_M_PATH_TABLE_LOC + 4]
            .try_into()
            .expect("four bytes"),
    );

    let mut little = vec![0u8; size as usize];
    allocate::read_extent_bytes(
        &*device.clone(),
        SECTOR_SIZE as u16,
        l,
        size,
        0,
        &mut little,
    )
    .expect("the little-endian table reads");
    let mut big = vec![0u8; size as usize];
    allocate::read_extent_bytes(&*device.clone(), SECTOR_SIZE as u16, m, size, 0, &mut big)
        .expect("the big-endian table reads");

    (
        parse_path_table(&little, false),
        parse_path_table(&big, true),
    )
}

/// Check the properties a reader depends on, in both tables.
///
/// The reader never consults a path table — it walks records — so nothing in
/// the driver would notice a table that was wrong.  This is the checker.
fn assert_path_tables_name(device: &Arc<MemoryBlockDevice>, expected: &[(Vec<u8>, u32)]) {
    let (little, big) = path_tables(device);
    assert_eq!(little.len(), big.len(), "the two tables disagree");
    for (left, right) in little.iter().zip(big.iter()) {
        assert_eq!(left, right, "the two tables disagree");
    }

    assert_eq!(little[0].2, vec![0x00], "the root is the first record");
    assert_eq!(little[0].1, 1, "the root's parent is itself");
    for (index, (number, parent, _, _)) in little.iter().enumerate() {
        assert_eq!(*number as usize, index + 1, "a number is its position");
        assert!(*parent <= *number, "a parent is numbered before its child");
    }

    for (identifier, extent) in expected {
        let found = little.iter().filter(|entry| &entry.2 == identifier).count();
        assert_eq!(found, 1, "a directory is named once");
        assert!(
            little
                .iter()
                .any(|entry| &entry.2 == identifier && entry.3 == *extent),
            "a directory's extent is the one its record says"
        );
    }

    // Within one parent the identifiers are ordered, which is the part of the
    // standard's order a level-order walk does not give for free.
    for window in little.windows(2) {
        if window[0].1 == window[1].1 {
            assert!(
                window[0].2 <= window[1].2,
                "siblings are not in identifier order"
            );
        }
    }
}

/// The extent a directory's own ".." record points at, read off the medium.
///
/// One block of the directory is enough for the tests' directories, and the
/// records end at a zero length, so this does not have to know the extent's
/// recorded size.
fn parent_record_extent(device: &Arc<MemoryBlockDevice>, dir_extent: u32) -> u32 {
    let mut data = vec![0u8; SECTOR_SIZE];
    allocate::read_extent_bytes(
        &*device.clone(),
        SECTOR_SIZE as u16,
        dir_extent,
        SECTOR_SIZE as u32,
        0,
        &mut data,
    )
    .expect("the directory reads");

    let mut at = 0usize;
    while at < data.len() {
        let len = data[at] as usize;
        if len == 0 {
            break;
        }
        if data[at + 32] == 1 && data[at + 33] == 0x01 {
            return u32::from_le_bytes(data[at + 2..at + 6].try_into().expect("four bytes"));
        }
        at += len;
    }
    panic!("the directory has no parent record");
}

/// The extent a path table gives a directory, by identifier.
fn table_extent(device: &Arc<MemoryBlockDevice>, identifier: &[u8]) -> u32 {
    let (little, _) = path_tables(device);
    little
        .iter()
        .find(|entry| entry.2 == identifier)
        .unwrap_or_else(|| panic!("no path-table entry for {identifier:?}"))
        .3
}

/// A named record's eight-byte data-length field, read off the medium rather
/// than through the parser: the format stores the length twice, and a reader
/// is free to check either half.
fn record_length_field(device: &Arc<MemoryBlockDevice>, identifier: &[u8]) -> [u8; 8] {
    let (location, size) = root_extent(device);
    let mut data = vec![0u8; size as usize];
    allocate::read_extent_bytes(
        &*device.clone(),
        SECTOR_SIZE as u16,
        location,
        size,
        0,
        &mut data,
    )
    .expect("the root extent reads");

    for record in walk_records(&data, false) {
        if record.identifier == identifier {
            let field = record.source_offset + OFFSET_DATA_LENGTH;
            return data[field..field + 8].try_into().expect("eight bytes");
        }
    }
    panic!("no record for {identifier:?}");
}

// Stage 1 — the data path

/// An overwrite inside the file is what the reader reads back, and it is on
/// the medium: the sector the extent lives in carries it, and the padding
/// after the file inside that sector is untouched — the file is 13 bytes of a
/// 2048-byte sector, so this is the read-modify-write path.
#[test]
fn an_overwrite_inside_a_file_is_what_the_reader_reads_back() {
    let (device, volume) = writable_volume();
    let node = volume.lookup("/HELLO.TXT").expect("the file");

    let replacement = b"JELLO";
    assert_eq!(node.write(0, replacement), Ok(replacement.len()));

    let mut buf = vec![0u8; HELLO_CONTENT.len()];
    assert_eq!(node.read(0, &mut buf), Ok(HELLO_CONTENT.len()));
    assert_eq!(&buf[..replacement.len()], replacement);
    assert_eq!(
        &buf[replacement.len()..],
        &HELLO_CONTENT[replacement.len()..]
    );

    // The device's blocks are 512 bytes and a disc sector is 2048, so the
    // extent's sector is four device blocks in.
    let mut sector = vec![0u8; SECTOR_SIZE];
    let lba = HELLO_SECTOR * SECTOR_SIZE as u64 / 512;
    device
        .read_blocks(lba, &mut sector)
        .expect("the sector reads");
    assert_eq!(&sector[..replacement.len()], replacement);
    assert_eq!(
        &sector[replacement.len()..HELLO_CONTENT.len()],
        &HELLO_CONTENT[replacement.len()..]
    );
    assert!(
        sector[HELLO_CONTENT.len()..].iter().all(|byte| *byte == 0),
        "the sector's padding was rewritten"
    );
}

/// A write that straddles two sectors changes no byte outside its range.
///
/// An image whose every byte is distinguishable makes the read-modify-write
/// path visible byte for byte.
#[test]
fn an_extent_write_keeps_every_byte_it_was_not_given() {
    let image: Vec<u8> = (0..8 * SECTOR_SIZE).map(|i| (i % 251) as u8).collect();
    let before = image.clone();
    let device = MemoryBlockDevice::new("iso-extent", image, false);

    let extent_location = 2u32;
    let extent_size = (3 * SECTOR_SIZE) as u32;
    // Eight bytes starting four before the extent's second sector: both
    // sectors are only partly covered, so both take the read-modify-write
    // path in one call.
    let offset = (SECTOR_SIZE - 4) as u64;
    let replacement = [0xAAu8; 8];
    assert_eq!(
        write::write_extent(
            &*device.clone(),
            SECTOR_SIZE as u16,
            extent_location,
            extent_size,
            offset,
            &replacement,
        ),
        Ok(replacement.len())
    );

    let mut after = vec![0u8; before.len()];
    device
        .read_blocks(0, &mut after)
        .expect("the image reads back");

    let start = extent_location as usize * SECTOR_SIZE + offset as usize;
    assert_eq!(&after[start..start + replacement.len()], &replacement);
    for (index, (old, new)) in before.iter().zip(after.iter()).enumerate() {
        if (start..start + replacement.len()).contains(&index) {
            continue;
        }
        assert_eq!(old, new, "byte {index} outside the write changed");
    }
}

/// A write at the end grows the file by what it takes, so a caller can write
/// a file the way it writes any other — and a second mount sees the length
/// and the bytes, which is what says both are on the medium.
#[test]
fn a_write_past_the_end_grows_the_file() {
    let (device, volume) = writable_volume();
    let node = volume.lookup("/HELLO.TXT").expect("the file");
    let data = [0xAAu8; 8];

    assert_eq!(node.write(HELLO_CONTENT.len() as u64, &data), Ok(8));
    assert_eq!(node.size(), HELLO_CONTENT.len() + 8);

    let reopened = Volume::open(device).expect("reopens");
    let again = reopened.lookup("/HELLO.TXT").expect("relookup");
    assert_eq!(again.size(), HELLO_CONTENT.len() + 8);
    let mut buf = vec![0u8; again.size()];
    assert_eq!(again.read(0, &mut buf), Ok(again.size()));
    assert_eq!(&buf[..HELLO_CONTENT.len()], HELLO_CONTENT);
    assert_eq!(&buf[HELLO_CONTENT.len()..], &data);
}

// Stage 2 — the length, which is one field

/// A truncation reads back short, a second mount sees it, and both halves of
/// the field carry it.  A shrink does not lose the block: the length can go
/// back up to the end of the block it already has, and the bytes it hid were
/// never erased.
#[test]
fn truncating_a_file_rewrites_the_length_its_record_carries() {
    let (device, volume) = writable_volume();
    let node = volume.lookup("/HELLO.TXT").expect("the file");

    node.set_len(5).expect("truncate");
    assert_eq!(node.size(), 5);
    let mut buf = vec![0u8; HELLO_CONTENT.len()];
    assert_eq!(node.read(0, &mut buf), Ok(5));
    assert_eq!(&buf[..5], &HELLO_CONTENT[..5]);

    let reopened = Volume::open(device.clone()).expect("reopens");
    assert_eq!(reopened.lookup("/HELLO.TXT").expect("relookup").size(), 5);

    let field = record_length_field(&device, b"HELLO.TXT;1");
    assert_eq!(u32::from_le_bytes(field[..4].try_into().unwrap()), 5);
    assert_eq!(u32::from_be_bytes(field[4..].try_into().unwrap()), 5);

    node.set_len(SECTOR_SIZE as u64).expect("grow back");
    let mut again = vec![0u8; HELLO_CONTENT.len()];
    assert_eq!(node.read(0, &mut again), Ok(HELLO_CONTENT.len()));
    assert_eq!(again, HELLO_CONTENT);
}

/// 13 bytes occupy one 2048-byte block, and every extent begins on a block
/// boundary, so the rest of that block belongs to this file alone — and
/// nothing was allocated for it: the file is still where it was.
#[test]
fn growing_a_file_stays_inside_the_block_it_already_has() {
    let (device, volume) = writable_volume();
    let node = volume.lookup("/HELLO.TXT").expect("the file");

    node.set_len(SECTOR_SIZE as u64).expect("grow");
    assert_eq!(node.size(), SECTOR_SIZE);

    let mut buf = vec![0u8; SECTOR_SIZE];
    assert_eq!(node.read(0, &mut buf), Ok(SECTOR_SIZE));
    assert_eq!(&buf[..HELLO_CONTENT.len()], HELLO_CONTENT);
    assert!(
        buf[HELLO_CONTENT.len()..].iter().all(|byte| *byte == 0),
        "the block's tail is not this file's to grow into"
    );

    let (location, size) = root_extent(&device);
    assert_eq!(
        record_named(&device, location, size, b"HELLO.TXT;1").extent,
        HELLO_SECTOR as u32,
        "an in-block growth must not move the file"
    );
}

/// HELLO's extent is one block and INNER begins in the next one, and an
/// extent is one contiguous run — so the file moves, and what it moves into
/// is the volume's free space, which is a hole below its end here rather
/// than the end itself.  The neighbour it used to sit beside is untouched,
/// and a second mount reads the file the record now points at.
#[test]
fn growing_past_the_block_moves_a_file_that_has_something_after_it() {
    let (device, volume) = writable_volume();
    let node = volume.lookup("/HELLO.TXT").expect("the file");
    let end = volume_blocks(&device);

    node.set_len(2 * SECTOR_SIZE as u64).expect("grow");
    assert_eq!(node.size(), 2 * SECTOR_SIZE);
    let (location, size) = root_extent(&device);
    let moved_to = record_named(&device, location, size, b"HELLO.TXT;1").extent;
    assert_ne!(moved_to, HELLO_SECTOR as u32, "the file had to move");
    assert!(
        moved_to < end,
        "it moved into a hole, so the volume did not have to grow"
    );
    assert_eq!(
        volume_blocks(&device),
        end,
        "the volume's space is what it was"
    );

    let mut buf = vec![0u8; node.size()];
    assert_eq!(node.read(0, &mut buf), Ok(node.size()));
    assert_eq!(&buf[..HELLO_CONTENT.len()], HELLO_CONTENT);

    let inner = volume.lookup("/SUB/INNER.TXT").expect("the neighbour");
    let mut inner_buf = vec![0u8; INNER_CONTENT.len()];
    assert_eq!(inner.read(0, &mut inner_buf), Ok(INNER_CONTENT.len()));
    assert_eq!(inner_buf, INNER_CONTENT);

    let reopened = Volume::open(device).expect("reopens");
    let again = reopened.lookup("/HELLO.TXT").expect("relookup");
    assert_eq!(again.size(), 2 * SECTOR_SIZE);
    let mut buf = vec![0u8; again.size()];
    assert_eq!(again.read(0, &mut buf), Ok(again.size()));
    assert_eq!(&buf[..HELLO_CONTENT.len()], HELLO_CONTENT);
}

/// The file a create makes is empty and points at where the volume's space
/// ends — the upgrade that opened this volume took the blocks after INNER —
/// so the blocks that follow it belong to no one, and growing it takes them
/// where it is, with no copy.
#[test]
fn growing_past_the_block_extends_the_last_file_in_place() {
    let (device, volume) = writable_volume();
    let node = volume.create_file("/last.bin").expect("create");
    let end = volume_blocks(&device);
    let (location, size) = root_extent(&device);
    assert_eq!(
        record_named(&device, location, size, b"LAST.BIN;1").extent,
        end,
        "an empty file starts where the volume's space ends"
    );

    node.set_len(SECTOR_SIZE as u64).expect("grow");
    assert_eq!(node.size(), SECTOR_SIZE);
    let (location, size) = root_extent(&device);
    assert_eq!(
        record_named(&device, location, size, b"LAST.BIN;1").extent,
        end,
        "a file that is already last must not move"
    );
    assert_eq!(
        volume_blocks(&device),
        end + 1,
        "the volume grew over the block the file took"
    );

    let reopened = Volume::open(device).expect("reopens");
    let again = reopened.lookup("/last.bin").expect("relookup");
    assert_eq!(again.size(), SECTOR_SIZE);
    let mut buf = vec![0u8; again.size()];
    assert_eq!(again.read(0, &mut buf), Ok(again.size()));
    assert!(
        buf.iter().all(|byte| *byte == 0),
        "the blocks it grew into were the medium's own"
    );
}

/// A length the medium cannot hold is `NoSpace`, and a write that cannot
/// grow is short — the contract's own answer for a byte it could not take.
#[test]
fn growth_the_medium_cannot_hold_is_refused() {
    let (_device, volume) = writable_volume();
    let node = volume.lookup("/HELLO.TXT").expect("the file");
    assert_eq!(
        node.set_len(64 * SECTOR_SIZE as u64),
        Err(abi::Error::NoSpace)
    );
}

#[test]
fn a_write_that_cannot_grow_is_short() {
    // The same image on a medium that is exactly the volume's size, and a
    // write far enough past the end that neither the holes inside the volume
    // nor its end can hold it: the write takes what it can rather than
    // failing.
    let tight = image_bytes()[..VOLUME_BLOCKS as usize * SECTOR_SIZE].to_vec();
    let device = MemoryBlockDevice::new("iso-tight", tight, false);
    let volume = Volume::open(device).expect("mounts");
    let node = volume.lookup("/HELLO.TXT").expect("the file");
    let data = [0xAAu8; 8];

    assert_eq!(node.write(64 * SECTOR_SIZE as u64, &data), Ok(0));
    assert_eq!(node.size(), HELLO_CONTENT.len());
}

#[test]
fn a_directory_and_a_read_only_device_refuse_a_length_change() {
    let (_device, volume) = writable_volume();
    let dir = volume.lookup("/SUB").expect("the directory");
    assert_eq!(dir.set_len(1), Err(abi::Error::InvalidArgument));

    let device = MemoryBlockDevice::new("iso-ro", image_bytes(), true);
    let volume = Volume::open(device).expect("mounts");
    let node = volume.lookup("/HELLO.TXT").expect("the file");
    assert_eq!(node.set_len(1), Err(abi::Error::PermissionDenied));
}

// Stage 3b — the directory, which is where a record lives

/// The name the caller used goes into the record's `NM` entry, so that is
/// the name the file has — not the identifier's own upper-cased form — and a
/// second mount reads the record the create wrote into the directory.
#[test]
fn a_created_file_is_empty_and_findable() {
    let (device, volume) = writable_volume();
    let node = volume.create_file("/NEW.TXT").expect("create");
    assert_eq!(node.name(), "NEW.TXT");
    assert_eq!(node.kind(), NodeKind::File);
    assert_eq!(node.size(), 0);
    assert_eq!(volume.lookup("/NEW.TXT").expect("lookup").size(), 0);

    let reopened = Volume::open(device).expect("reopens");
    assert_eq!(reopened.lookup("/NEW.TXT").expect("relookup").size(), 0);
}

#[test]
fn a_created_file_can_be_written_and_read_back() {
    let (device, volume) = writable_volume();
    let node = volume.create_file("/data.bin").expect("create");
    let payload = b"written after the create";
    assert_eq!(node.write(0, payload), Ok(payload.len()));
    assert_eq!(node.size(), payload.len());

    let reopened = Volume::open(device).expect("reopens");
    let again = reopened.lookup("/data.bin").expect("relookup");
    assert_eq!(again.size(), payload.len());
    let mut buf = vec![0u8; payload.len()];
    assert_eq!(again.read(0, &mut buf), Ok(payload.len()));
    assert_eq!(buf, payload);
}

/// The record is the identifier's own 33 + 9 bytes plus the System Use area
/// that carries the name: `PX` (36), `NM` for `NEW.TXT` (12) and `ST` (4).
#[test]
fn a_created_file_makes_its_directory_longer() {
    let (_device, volume) = writable_volume();
    let before = volume.lookup("/").expect("the root").size();

    volume.create_file("/NEW.TXT").expect("create");

    let reopened = Volume::open(_device).expect("reopens");
    assert_eq!(
        reopened.lookup("/").expect("the root again").size(),
        before + 42 + 36 + 12 + 4
    );
}

/// The root's records start part-way into a 2048-byte block, so filling it
/// takes about forty records and the one that does not fit starts the next
/// block — which the volume has to give the directory.
#[test]
fn a_directory_that_fills_a_block_takes_another() {
    let (device, volume) = writable_volume();

    let mut created = Vec::new();
    for index in 0..48u32 {
        let name = alloc::format!("/F{index}.TXT");
        volume.create_file(&name).expect("create");
        created.push(name);
    }

    let reopened = Volume::open(device).expect("reopens");
    for name in &created {
        assert!(reopened.lookup(name).is_ok(), "missing {name}");
    }
    assert!(
        reopened.lookup("/").expect("the root").size() > SECTOR_SIZE,
        "the directory should need a second block"
    );
}

#[test]
fn creating_a_file_that_exists_is_refused() {
    let (_device, volume) = writable_volume();
    assert_eq!(
        volume.create_file("/HELLO.TXT").err(),
        Some(abi::Error::AlreadyExists)
    );
}

/// The record's identifier is the mangled form a reader without Rock Ridge
/// sees, and `NM` is what a reader with it — and this driver — reports.
#[test]
fn a_name_the_format_cannot_hold_is_kept_in_a_name_entry() {
    let (device, volume) = writable_volume();
    volume
        .create_file("/a name with spaces")
        .expect("a name an identifier has no room for");

    assert!(
        root_identifiers(&device).contains(&b"A_NAME_WITH_SPACES;1".to_vec()),
        "the identifier stands in for the name"
    );

    let reopened = Volume::open(device).expect("reopens");
    let node = reopened.lookup("/a name with spaces").expect("lookup");
    assert_eq!(node.name(), "a name with spaces");
}

/// Both names want `A_B;1`, and two records with one identifier are two
/// entries only one of which is reachable, so the second takes a suffix.
#[test]
fn two_names_that_mangle_alike_still_get_their_own_records() {
    let (device, volume) = writable_volume();
    volume.create_file("/a b").expect("create /a b");
    volume.create_file("/a_b").expect("create /a_b");

    let identifiers = root_identifiers(&device);
    assert!(identifiers.contains(&b"A_B;1".to_vec()));
    assert!(identifiers.contains(&b"A_B_1;1".to_vec()));

    let first = volume.lookup("/a b").expect("lookup /a b");
    let second = volume.lookup("/a_b").expect("lookup /a_b");
    assert_eq!(first.name(), "a b");
    assert_eq!(second.name(), "a_b");
}

/// The name lives in the record, whose own length is a single byte: the
/// entries cannot fit in 255 of them, so the create is refused rather than
/// writing the name in part.
#[test]
fn a_name_too_long_for_one_record_is_refused() {
    let (_device, volume) = writable_volume();
    let long = alloc::format!("/{}", "n".repeat(300));
    assert_eq!(
        volume.create_file(&long).err(),
        Some(abi::Error::InvalidArgument)
    );
}

/// A removal takes the record out, the neighbour survives, a second mount
/// agrees, and the directory is shorter by exactly the record that left it —
/// 44 bytes of `HELLO.TXT;1`.
#[test]
fn removing_a_file_takes_its_record_out_of_the_directory() {
    let (device, volume) = writable_volume();
    let before = volume.lookup("/").expect("the root").size();
    volume.remove_path("/HELLO.TXT").expect("remove");
    assert_eq!(
        volume.lookup("/HELLO.TXT").err(),
        Some(abi::Error::NotFound)
    );
    assert!(volume.lookup("/SUB/INNER.TXT").is_ok());

    let reopened = Volume::open(device).expect("reopens");
    assert_eq!(
        reopened.lookup("/HELLO.TXT").err(),
        Some(abi::Error::NotFound)
    );
    assert!(reopened.lookup("/SUB/INNER.TXT").is_ok());
    assert_eq!(reopened.lookup("/").expect("the root").size(), before - 44);
}

// Stage 3c — directories, which means the path tables

#[test]
fn a_created_directory_is_empty_and_findable() {
    let (device, volume) = writable_volume();
    volume.create_dir("/NEWDIR").expect("create dir");

    let node = volume.lookup("/NEWDIR").expect("lookup");
    assert_eq!(node.kind(), NodeKind::Directory);
    // It holds its own two records and nothing else, so listing it lists
    // nothing: the reader skips "." and "..".
    assert_eq!(
        volume.read_dir("/NEWDIR", 0).err(),
        Some(abi::Error::NotFound)
    );

    // A second mount sees it, and the path tables name it — at the extent its
    // own record does, which is the property the tables have to hold whether
    // the new extent came from the volume's end or from a hole.
    let (root, root_size) = root_extent(&device);
    let extent = record_named(&device, root, root_size, b"NEWDIR").extent;
    assert_path_tables_name(
        &device,
        &[
            (vec![0x00], root),
            (b"SUB".to_vec(), SUB_SECTOR as u32),
            (b"NEWDIR".to_vec(), extent),
        ],
    );
    let reopened = Volume::open(device).expect("reopens");
    assert_eq!(
        reopened.lookup("/NEWDIR").expect("relookup").kind(),
        NodeKind::Directory
    );
}

#[test]
fn a_created_directory_holds_files() {
    let (device, volume) = writable_volume();
    volume.create_dir("/holding").expect("create dir");
    let node = volume
        .create_file("/holding/item.bin")
        .expect("create file");
    assert_eq!(node.write(0, b"inside"), Ok(6));

    let reopened = Volume::open(device).expect("reopens");
    let file = reopened.lookup("/holding/item.bin").expect("relookup");
    assert_eq!(file.size(), 6);
    let mut buf = vec![0u8; 6];
    assert_eq!(file.read(0, &mut buf), Ok(6));
    assert_eq!(buf, b"inside");
}

/// Created in the order a walk would *not* list them: the tables order
/// siblings by identifier, which is the part of the standard's order a
/// level-order walk does not give for free.
#[test]
fn the_path_table_orders_siblings_by_identifier() {
    let (device, volume) = writable_volume();
    volume.create_dir("/zebra").expect("create zebra");
    volume.create_dir("/alpha").expect("create alpha");

    let (little, _) = path_tables(&device);
    let names: Vec<&Vec<u8>> = little.iter().map(|entry| &entry.2).collect();
    let alpha = names
        .iter()
        .position(|name| *name == b"ALPHA")
        .expect("alpha");
    let zebra = names
        .iter()
        .position(|name| *name == b"ZEBRA")
        .expect("zebra");
    let sub = names.iter().position(|name| *name == b"SUB").expect("sub");
    assert!(alpha < sub && sub < zebra, "siblings are out of order");
    assert!(little.iter().all(|entry| entry.1 <= entry.0));
}

#[test]
fn removing_an_empty_directory_takes_it_out_of_the_tree_and_the_tables() {
    let (device, volume) = writable_volume();
    volume.create_dir("/gone").expect("create dir");
    let (root, root_size) = root_extent(&device);
    let extent = record_named(&device, root, root_size, b"GONE").extent;
    assert_path_tables_name(
        &device,
        &[
            (vec![0x00], root),
            (b"SUB".to_vec(), SUB_SECTOR as u32),
            (b"GONE".to_vec(), extent),
        ],
    );

    volume.remove_path("/gone").expect("remove dir");
    assert_eq!(volume.lookup("/gone").err(), Some(abi::Error::NotFound));

    // The tables no longer name it, and a second mount agrees.
    assert_path_tables_name(
        &device,
        &[
            (vec![0x00], root_extent(&device).0),
            (b"SUB".to_vec(), SUB_SECTOR as u32),
        ],
    );
    let reopened = Volume::open(device).expect("reopens");
    assert_eq!(reopened.lookup("/GONE").err(), Some(abi::Error::NotFound));
    assert!(reopened.lookup("/SUB/INNER.TXT").is_ok());
}

/// `/SUB` holds `INNER.TXT`, and a directory that still holds something
/// cannot go: its child's record would be pointing at a parent nothing
/// names.
#[test]
fn removing_a_directory_that_holds_something_is_refused() {
    let (_device, volume) = writable_volume();
    assert_eq!(volume.remove_path("/SUB"), Err(abi::Error::Busy));
}

// Stage 3d — renaming and moving

#[test]
fn renaming_a_file_keeps_its_contents() {
    let (device, volume) = writable_volume();
    volume.rename("/HELLO.TXT", "/RENAMED.TXT").expect("rename");

    assert_eq!(
        volume.lookup("/HELLO.TXT").err(),
        Some(abi::Error::NotFound)
    );
    let node = volume.lookup("/RENAMED.TXT").expect("lookup");
    assert_eq!(node.size(), HELLO_CONTENT.len());
    let mut buf = vec![0u8; HELLO_CONTENT.len()];
    assert_eq!(node.read(0, &mut buf), Ok(HELLO_CONTENT.len()));
    assert_eq!(buf, HELLO_CONTENT);

    // The name is a record in the directory, so a second mount sees it.
    let reopened = Volume::open(device).expect("reopens");
    assert_eq!(
        reopened.lookup("/HELLO.TXT").err(),
        Some(abi::Error::NotFound)
    );
    assert!(reopened.lookup("/RENAMED.TXT").is_ok());
}

#[test]
fn a_rename_can_give_a_name_the_identifier_cannot_hold() {
    let (_device, volume) = writable_volume();
    volume
        .rename("/HELLO.TXT", "/a moved file")
        .expect("rename");

    let node = volume.lookup("/a moved file").expect("lookup");
    assert_eq!(node.name(), "a moved file");
    assert_eq!(node.size(), HELLO_CONTENT.len());
}

/// The record's System Use area is carried over whole, so the POSIX
/// attributes the create wrote are still there: a record rebuilt without
/// them would report the default that a record with no `PX` entry gets.
#[test]
fn a_rename_keeps_the_attributes_the_record_carried() {
    let (_device, volume) = writable_volume();
    let created = volume.create_file("/kept.txt").expect("create");
    assert_eq!(created.metadata().expect("metadata").security.mode, 0o644);

    volume.rename("/kept.txt", "/moved.txt").expect("rename");

    let node = volume.lookup("/moved.txt").expect("lookup");
    assert_eq!(node.name(), "moved.txt");
    assert_eq!(node.metadata().expect("metadata").security.mode, 0o644);
}

#[test]
fn moving_a_file_into_a_directory_takes_its_record_with_it() {
    let (_device, volume) = writable_volume();
    volume.rename("/HELLO.TXT", "/SUB/HELLO.TXT").expect("move");

    assert_eq!(
        volume.lookup("/HELLO.TXT").err(),
        Some(abi::Error::NotFound)
    );
    let node = volume.lookup("/SUB/HELLO.TXT").expect("lookup");
    let mut buf = vec![0u8; HELLO_CONTENT.len()];
    assert_eq!(node.read(0, &mut buf), Ok(HELLO_CONTENT.len()));
    assert_eq!(buf, HELLO_CONTENT);

    // The neighbour it joined is still there.
    assert!(volume.lookup("/SUB/INNER.TXT").is_ok());
}

#[test]
fn renaming_a_directory_keeps_it_and_the_tables_agree() {
    let (device, volume) = writable_volume();
    volume.rename("/SUB", "/RENAMED").expect("rename");

    assert_eq!(volume.lookup("/SUB").err(), Some(abi::Error::NotFound));
    assert!(volume.lookup("/RENAMED/INNER.TXT").is_ok());

    // A directory is in the path tables, and they must not still name the old
    // identifier.
    let (little, _) = path_tables(&device);
    let names: Vec<&Vec<u8>> = little.iter().map(|entry| &entry.2).collect();
    assert!(names.contains(&&b"RENAMED".to_vec()));
    assert!(!names.contains(&&b"SUB".to_vec()));
}

/// ".." is the moved directory's own record of its parent, and this is the
/// one thing about it that a move changes.
#[test]
fn moving_a_directory_rewrites_its_parent_record() {
    let (device, volume) = writable_volume();
    volume.create_dir("/outer").expect("create outer");
    volume.create_dir("/mover").expect("create mover");
    let outer_extent = table_extent(&device, b"OUTER");
    assert_ne!(
        parent_record_extent(&device, table_extent(&device, b"MOVER")),
        outer_extent,
        "the mover starts somewhere else"
    );

    volume.rename("/mover", "/outer/mover").expect("move");

    let moved_extent = table_extent(&device, b"MOVER");
    assert_eq!(
        parent_record_extent(&device, moved_extent),
        outer_extent,
        "\"..\" still points at the directory it left"
    );
    assert!(volume.lookup("/outer/mover").is_ok());
    assert_eq!(volume.lookup("/mover").err(), Some(abi::Error::NotFound));
}

/// Filling the root's first block makes it take a second — and the root is
/// not the last extent on the volume, so it *moves*, which is what leaves a
/// child's ".." naming the address it left.
#[test]
fn a_directory_that_moves_takes_its_childrens_parent_with_it() {
    let (device, volume) = writable_volume();
    volume.create_dir("/holding").expect("create holding");
    volume.create_dir("/holding/inner").expect("create inner");
    let root_extent_before = table_extent(&device, &[0x00]);
    assert_eq!(
        parent_record_extent(&device, table_extent(&device, b"HOLDING")),
        root_extent_before,
        "a new directory's parent is the root"
    );

    for index in 0..48u32 {
        volume
            .create_file(&alloc::format!("/F{index}.TXT"))
            .expect("create");
    }

    let moved_root = table_extent(&device, &[0x00]);
    assert_ne!(moved_root, root_extent_before, "the root should have moved");
    assert_eq!(
        parent_record_extent(&device, table_extent(&device, b"HOLDING")),
        moved_root,
        "\"..\" still names the address the root left"
    );
}

#[test]
fn moving_a_directory_into_itself_is_refused() {
    let (_device, volume) = writable_volume();
    assert_eq!(
        volume.rename("/SUB", "/SUB/inner"),
        Err(abi::Error::InvalidArgument)
    );
}

#[test]
fn renaming_onto_an_existing_name_is_refused() {
    let (_device, volume) = writable_volume();
    assert_eq!(
        volume.rename("/HELLO.TXT", "/SUB"),
        Err(abi::Error::AlreadyExists)
    );
}

// Stage 3f — the extension, which is what makes the names believed

/// The signatures a System Use area's entries carry, in the order they sit.
fn area_entries(system_use: &[u8]) -> Vec<Vec<u8>> {
    let mut signatures = Vec::new();
    let mut rest = system_use;
    while rest.len() >= 4 {
        let len = rest[2] as usize;
        if len < 4 || len > rest.len() {
            break;
        }
        signatures.push(rest[..2].to_vec());
        rest = &rest[len..];
    }
    signatures
}

/// The bytes a System Use area's `CE` entry names, read off the medium.
fn area_continuation(device: &Arc<MemoryBlockDevice>, system_use: &[u8]) -> Vec<u8> {
    let parsed = super::susp::SystemUse::parse(system_use);
    let continuation = parsed.continuation.expect("a continuation entry");
    let mut bytes = vec![0u8; continuation.length as usize];
    allocate::read_extent_bytes(
        &*device.clone(),
        SECTOR_SIZE as u16,
        continuation.block,
        continuation.offset + continuation.length,
        continuation.offset as u64,
        &mut bytes,
    )
    .expect("the continuation reads");
    bytes
}

/// The root's own "." record is where a volume says what its System Use
/// areas are: `SP` that they are SUSP's at all, `PX` for its attributes, and
/// `CE` naming where the reference continues — the entry is far longer than
/// a record can hold.
#[test]
fn opening_a_writable_volume_declares_the_extension() {
    let (device, _volume) = writable_volume();
    let (location, size) = root_extent(&device);

    let first = record_named(&device, location, size, &[0x00]);
    assert_eq!(
        area_entries(&first.system_use),
        vec![
            b"SP".to_vec(),
            b"PX".to_vec(),
            b"CE".to_vec(),
            b"ST".to_vec()
        ]
    );

    let reference = area_continuation(&device, &first.system_use);
    assert_eq!(&reference[..2], b"ER");
    assert_eq!(reference[2] as usize, reference.len());
    assert_eq!(&reference[8..18], b"RRIP_1991A");
}

/// Opening a volume that already says what its entries are adds nothing to
/// it.
#[test]
fn the_extension_is_declared_once() {
    let (device, _volume) = writable_volume();
    let (location, size) = root_extent(&device);
    let first = record_named(&device, location, size, &[0x00]).record_len;

    drop(Volume::open(device.clone()).expect("reopens"));

    let (location, size) = root_extent(&device);
    assert_eq!(
        record_named(&device, location, size, &[0x00]).record_len,
        first
    );
}

/// A read-only volume is untouched: the root is the fixture's own extent,
/// its "." record has no System Use area at all, and the volume claims what
/// it claimed.
#[test]
fn a_read_only_volume_is_left_as_it_was() {
    let device = MemoryBlockDevice::new("iso-ro", image_bytes(), true);
    let volume = Volume::open(device.clone()).expect("mounts");
    assert!(volume.lookup("/HELLO.TXT").is_ok());

    assert_eq!(
        root_extent(&device),
        (
            ROOT_SECTOR as u32,
            directory_extent(&root_records()).len() as u32
        )
    );
    let (location, size) = root_extent(&device);
    assert!(area_entries(&record_named(&device, location, size, &[0x00]).system_use).is_empty());
    assert_eq!(volume_blocks(&device), VOLUME_BLOCKS);
}

fn root_records() -> Vec<Vec<u8>> {
    vec![
        record(&[0x00], ROOT_SECTOR as u32, 2048, true),
        record(&[0x01], ROOT_SECTOR as u32, 2048, true),
        record(
            b"HELLO.TXT;1",
            HELLO_SECTOR as u32,
            HELLO_CONTENT.len() as u32,
            false,
        ),
        record(b"SUB", SUB_SECTOR as u32, 2048, true),
    ]
}

/// The upgrade builds the root elsewhere; every entry is still there, a
/// second mount agrees, and the path tables name the new address.  The
/// root's own ".." names the root and the subdirectory's names its parent,
/// so both follow the move: a reader that goes back up lands on the extent
/// the volume now points at, not the one it left.
#[test]
fn the_rebuilt_root_still_lists_what_it_listed() {
    let (device, volume) = writable_volume();

    assert!(volume.lookup("/HELLO.TXT").is_ok());
    assert!(volume.lookup("/SUB/INNER.TXT").is_ok());
    let root = root_extent(&device).0;
    assert_path_tables_name(
        &device,
        &[(vec![0x00], root), (b"SUB".to_vec(), SUB_SECTOR as u32)],
    );

    assert_eq!(parent_record_extent(&device, root), root);
    assert_eq!(parent_record_extent(&device, SUB_SECTOR as u32), root);

    let reopened = Volume::open(device).expect("reopens");
    assert!(reopened.lookup("/HELLO.TXT").is_ok());
    assert!(reopened.lookup("/SUB/INNER.TXT").is_ok());
    assert_eq!(
        reopened.read_dir("/", 0).expect("first entry").name,
        "HELLO.TXT"
    );
}

/// A volume whose descriptor set has no terminator is one this driver
/// cannot say the structures of — so it hands blocks out from the end, which
/// is where the image's own space stops.
#[test]
fn a_volume_that_cannot_be_accounted_for_is_appended_to() {
    let mut bytes = image_bytes();
    let start = 17 * SECTOR_SIZE;
    bytes[start..start + SECTOR_SIZE].fill(0);
    let device = MemoryBlockDevice::new("iso-opaque", bytes, false);
    let volume = Volume::open(device.clone()).expect("mounts");

    let (location, _size) = root_extent(&device);
    assert!(
        location >= VOLUME_BLOCKS,
        "the rebuilt root went past the space the image declared"
    );
    assert!(volume.lookup("/HELLO.TXT").is_ok());
}

/// A volume whose descriptor set has no terminator, on a medium that is
/// exactly its size: the driver cannot say what the volume's structures
/// are, so the allocation appends — and there is nowhere to append the
/// reference either, so the volume is left as it was.  It is still writable,
/// because a create is a record appended to a directory that already has the
/// room for it.
#[test]
fn a_volume_with_no_room_for_the_reference_still_mounts() {
    let mut tight = image_bytes()[..VOLUME_BLOCKS as usize * SECTOR_SIZE].to_vec();
    let opaque_start = 17 * SECTOR_SIZE;
    tight[opaque_start..opaque_start + SECTOR_SIZE].fill(0);
    let device = MemoryBlockDevice::new("iso-tight", tight, false);
    let volume = Volume::open(device.clone()).expect("mounts");

    assert_eq!(
        root_extent(&device),
        (
            ROOT_SECTOR as u32,
            directory_extent(&root_records()).len() as u32
        )
    );
    assert_eq!(volume_blocks(&device), VOLUME_BLOCKS);
    assert!(volume.lookup("/HELLO.TXT").is_ok());

    volume.create_file("/after.bin").expect("create");
    let reopened = Volume::open(device).expect("reopens");
    assert!(reopened.lookup("/after.bin").is_ok());
}

/// The root's size is a field of the descriptor's own root record, so it is
/// the first thing a broken image can lie about — and the upgrade would
/// allocate what it says.  It is bounded the way a directory read is, and
/// the volume opens without it.
#[test]
fn a_broken_root_size_does_not_stop_a_writable_open() {
    let mut bytes = image_bytes();
    let field = 16 * SECTOR_SIZE + 156 + OFFSET_DATA_LENGTH;
    bytes[field..field + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
    bytes[field + 4..field + 8].copy_from_slice(&0xFFFF_FFFFu32.to_be_bytes());

    let device = MemoryBlockDevice::new("iso-lying", bytes, false);
    let _volume = Volume::open(device.clone()).expect("mounts");

    // Nothing was written for it, and the volume claims what it claimed.
    assert_eq!(root_extent(&device).1, 0xFFFF_FFFF);
    assert_eq!(volume_blocks(&device), VOLUME_BLOCKS);
}

/// Opening a *writable* volume runs code an image can steer: the extension
/// upgrade reads a foreign root record and then writes by what it says.  So
/// the bytes worth flipping are the ones it reads — the descriptor's root
/// record and the records of a directory — and every one of these has to end
/// in an answer rather than a panic.
#[test]
fn a_writable_open_survives_a_mutated_image() {
    let base = image_bytes();
    let root = ROOT_SECTOR as usize * SECTOR_SIZE;
    let pvd_root = 16 * SECTOR_SIZE + 156;

    let mut cases: Vec<Vec<u8>> = Vec::new();
    for at in [
        pvd_root,
        pvd_root + 1,
        pvd_root + 2,
        pvd_root + 10,
        pvd_root + 32,
    ] {
        for value in [0x00u8, 0xFF] {
            let mut bytes = base.clone();
            bytes[at] = value;
            cases.push(bytes);
        }
    }
    // A record whose own length says it is shorter than the part every reader
    // reads from it, and one that says it is longer than the extent.
    for length in [1u8, 32, 33, 255] {
        let mut bytes = base.clone();
        bytes[root] = length;
        cases.push(bytes);
    }
    // Every byte of the root's first record, one at a time.
    for at in 0..35usize {
        let mut bytes = base.clone();
        bytes[root + at] = 0xFF;
        cases.push(bytes);
    }

    for (index, bytes) in cases.into_iter().enumerate() {
        let device = MemoryBlockDevice::new("iso-hostile", bytes, false);
        // Whatever it answers — and it is allowed to fail, and allowed to skip
        // the upgrade — it must not take the volume with it.
        if let Ok(volume) = Volume::open(device) {
            let _ = volume.lookup("/HELLO.TXT");
            let _ = volume.read_dir("/", 0);
            let _ = volume.create_file(&alloc::format!("/new{index}.bin"));
        }
    }
}

// Stage 3g — giving back what it took

/// A removal at the end lowers the size the volume declares over the blocks
/// it gives up, and the next thing that needs a block is handed one of them.
#[test]
fn a_removal_at_the_end_of_the_volume_gives_its_blocks_back() {
    let (device, volume) = writable_volume();
    let before = volume_blocks(&device);

    let node = volume.create_file("/tail.bin").expect("create");
    assert_eq!(node.write(0, &[0x5A; SECTOR_SIZE]), Ok(SECTOR_SIZE));
    assert_eq!(volume_blocks(&device), before + 1);

    volume.remove_path("/tail.bin").expect("remove");
    assert_eq!(
        volume_blocks(&device),
        before,
        "the blocks it held at the end are the volume's again"
    );

    // And the next thing that needs a block is handed one of them.
    let again = volume.create_file("/other.bin").expect("create");
    assert_eq!(again.write(0, &[0x11; SECTOR_SIZE]), Ok(SECTOR_SIZE));
    let (location, size) = root_extent(&device);
    assert_eq!(
        record_named(&device, location, size, b"OTHER.BIN;1").extent,
        before,
        "the reclaimed block is the one the allocator hands out"
    );
}

/// `HELLO.TXT` is in the middle: the volume's space ends past it, so the
/// *declared size* does not move.  What is free there is not lost, though —
/// the block map is what the next allocation looks in.
#[test]
fn a_removal_inside_the_volume_gives_nothing_back() {
    let (device, volume) = writable_volume();
    let before = volume_blocks(&device);

    volume.remove_path("/HELLO.TXT").expect("remove");
    assert_eq!(volume_blocks(&device), before);
}

/// A file with something after it moves into the volume's free space when it
/// grows, and here that is a hole below the volume's end.  Removing it
/// leaves two free blocks that are not the volume's tail, so the declared
/// size stays where it is — and the next file that needs two of them is
/// handed those.
#[test]
fn a_removal_inside_the_volume_frees_its_blocks_for_the_next_allocation() {
    let (device, volume) = writable_volume();

    // A file that ends up after the others, so that the ones above it in the
    // tree have something to move away from.
    let tail = volume.create_file("/tail.bin").expect("create");
    assert_eq!(tail.write(0, &[0x5A; SECTOR_SIZE]), Ok(SECTOR_SIZE));

    volume
        .lookup("/HELLO.TXT")
        .expect("lookup hello")
        .set_len(2 * SECTOR_SIZE as u64)
        .expect("grow");
    let (root, root_size) = root_extent(&device);
    let moved_to = record_named(&device, root, root_size, b"HELLO.TXT;1").extent;
    assert!(moved_to < volume_blocks(&device));
    let before = volume_blocks(&device);

    volume.remove_path("/HELLO.TXT").expect("remove");
    assert_eq!(volume_blocks(&device), before);

    volume
        .lookup("/SUB/INNER.TXT")
        .expect("lookup inner")
        .set_len(2 * SECTOR_SIZE as u64)
        .expect("grow");
    assert_eq!(
        record_named(
            &device,
            SUB_SECTOR as u32,
            SECTOR_SIZE as u32,
            b"INNER.TXT;1"
        )
        .extent,
        moved_to,
        "the allocator hands out the hole the removal left"
    );
    assert_eq!(volume_blocks(&device), before);
}

/// A directory's extent is an allocation like any other, so it comes from
/// the volume's free space — and goes back to it when the directory does.
#[test]
fn a_removed_directory_gives_its_extent_to_the_next_one() {
    let (device, volume) = writable_volume();
    let before = volume_blocks(&device);

    volume.create_dir("/first").expect("create");
    let (root, root_size) = root_extent(&device);
    let first = record_named(&device, root, root_size, b"FIRST").extent;
    assert!(first < before, "it took free space, not the end");

    volume.remove_path("/first").expect("remove");
    volume.create_dir("/second").expect("create");
    let (root, root_size) = root_extent(&device);
    assert_eq!(
        record_named(&device, root, root_size, b"SECOND").extent,
        first,
        "the extent the removal freed is handed out again"
    );
}

#[test]
fn a_truncation_at_the_end_of_the_volume_gives_its_blocks_back() {
    let (device, volume) = writable_volume();
    let node = volume.create_file("/tail.bin").expect("create");
    node.set_len(2 * SECTOR_SIZE as u64).expect("grow");
    let grown = volume_blocks(&device);

    node.set_len(SECTOR_SIZE as u64).expect("truncate");
    assert_eq!(
        volume_blocks(&device),
        grown - 1,
        "the block it gave up was the volume's last"
    );

    // The block it kept is still its own, and a second mount agrees about the
    // length.
    let (location, size) = root_extent(&device);
    let record = record_named(&device, location, size, b"TAIL.BIN;1");
    assert_eq!(record.data_length, SECTOR_SIZE as u32);
    let reopened = Volume::open(device).expect("reopens");
    assert_eq!(
        reopened.lookup("/tail.bin").expect("relookup").size(),
        SECTOR_SIZE
    );
}

/// A medium that is exactly the volume: the open cannot declare the
/// extension, so the image is the one it came with.  `INNER.TXT` is the last
/// file it holds and ends exactly where the volume does — the shape the tail
/// rule would give back — and the volume's own floor is what says no,
/// because the blocks the image came with are the image's.
#[test]
fn the_blocks_an_image_came_with_are_never_handed_out_again() {
    let tight = image_bytes()[..VOLUME_BLOCKS as usize * SECTOR_SIZE].to_vec();
    let device = MemoryBlockDevice::new("iso-tight", tight, false);
    let volume = Volume::open(device.clone()).expect("mounts");
    assert_eq!(volume_blocks(&device), VOLUME_BLOCKS);

    volume.remove_path("/SUB/INNER.TXT").expect("remove");
    assert_eq!(
        volume_blocks(&device),
        VOLUME_BLOCKS,
        "the volume never comes down to a block the image came with"
    );
}

// The block map

/// A volume the driver cannot account for gives no map at all, because
/// handing a block to a file that a structure already holds is the one thing
/// that must not happen.
#[test]
fn the_block_map_is_absent_for_a_volume_it_cannot_account_for() {
    let map = |bytes: Vec<u8>| {
        let device = MemoryBlockDevice::new("iso-map", bytes, true);
        allocate::occupied_blocks(&*device, SECTOR_SIZE as u16).is_ok()
    };
    let bytes = image_bytes();
    assert!(
        map(bytes.clone()),
        "the fixture is a volume it can account for"
    );

    // A descriptor set with no terminator: there is no telling where its
    // descriptors stop.
    let mut no_terminator = bytes.clone();
    let start = 17 * SECTOR_SIZE;
    no_terminator[start..start + SECTOR_SIZE].fill(0);
    assert!(!map(no_terminator));

    // A descriptor this driver does not know, which could name anything.
    let mut unknown = bytes.clone();
    unknown[17 * SECTOR_SIZE] = 0x03;
    unknown[17 * SECTOR_SIZE + 1..17 * SECTOR_SIZE + 6].copy_from_slice(b"CD001");
    unknown[17 * SECTOR_SIZE + 6] = 0x01;
    assert!(!map(unknown));

    // A supplementary descriptor that is not Joliet's: that is another tree,
    // and this driver would not know where its extents are.
    let mut other_tree = bytes.clone();
    other_tree[17 * SECTOR_SIZE] = 0x02;
    other_tree[17 * SECTOR_SIZE + 1..17 * SECTOR_SIZE + 6].copy_from_slice(b"CD001");
    other_tree[17 * SECTOR_SIZE + 6] = 0x01;
    assert!(!map(other_tree));

    // A root with an Extended Attribute Record in front of it.
    let mut with_attributes = bytes;
    with_attributes[16 * SECTOR_SIZE + 156 + 1] = 1;
    assert!(!map(with_attributes));
}

/// A walk of a tree whose records point back up the tree is a walk that
/// never ends unless something says where the end is.  The root's record for
/// its subdirectory is pointed at the root's own extent, so every level
/// leads to the same directory — and the walk has to come back with an
/// answer, which is "no map", rather than not come back at all.
#[test]
fn a_directory_that_names_its_ancestor_is_not_walked_forever() {
    let mut bytes = image_bytes();
    // The root's records are 34, 34, 44 and 36 bytes, so the SUB record
    // starts at byte 112 of the root's extent.
    let sub_record = ROOT_SECTOR as usize * SECTOR_SIZE + 112;
    bytes[sub_record + 2..sub_record + 6].copy_from_slice(&(ROOT_SECTOR as u32).to_le_bytes());

    let device = MemoryBlockDevice::new("iso-cycle", bytes, true);
    assert!(allocate::occupied_blocks(&*device, SECTOR_SIZE as u16).is_err());
}

// A disc with two trees

/// Where the second tree's own extents are.
const JOLIET_ROOT_SECTOR: u64 = 33;
const JOLIET_SUB_SECTOR: u64 = 34;
/// The supplementary root extent: its own two records, a file whose data is
/// the primary tree's, and a directory whose identifier is one UCS-2 code
/// unit — a name of one character below U+0100, whose first byte is zero and
/// which is nevertheless not a "." record.
const JOLIET_ROOT_BYTES: u32 = 36 + 36 + 36 + 64; // ".", "..", "A", "Hello World.txt"
/// The supplementary directory's extent: its own two records, and nothing.
const JOLIET_SUB_BYTES: u32 = 36 + 36;

/// A name as a Joliet identifier: UCS-2BE, with no version.
fn ucs2(name: &str) -> Vec<u8> {
    name.encode_utf16()
        .flat_map(|unit| unit.to_be_bytes())
        .collect()
}

/// The Supplementary Volume Descriptor of the two-tree fixture.
///
/// Its root record is the descriptor's own 34-byte field, which holds the one
/// byte identifier 0x00 whatever the tree's identifiers look like — the field
/// has no room for more, and that is what a released image has too.
fn build_svd(root_sector: u64, root_size: u32) -> [u8; SECTOR_SIZE] {
    let mut sector = [0u8; SECTOR_SIZE];
    sector[0] = 2;
    sector[1..6].copy_from_slice(b"CD001");
    sector[6] = 1;
    sector[40..46].copy_from_slice(b"JOLIET");
    for slot in sector[40..72].iter_mut() {
        if *slot == 0 {
            *slot = b' ';
        }
    }
    sector[88..91].copy_from_slice(b"%/@");
    sector[80..84].copy_from_slice(&VOLUME_BLOCKS.to_le_bytes());
    sector[84..88].copy_from_slice(&VOLUME_BLOCKS.to_be_bytes());
    sector[128..130].copy_from_slice(&(SECTOR_SIZE as u16).to_le_bytes());
    sector[130..132].copy_from_slice(&(SECTOR_SIZE as u16).to_be_bytes());
    let root = record(&[0x00], root_sector as u32, root_size, true);
    sector[156..190].copy_from_slice(&root[..34]);
    sector[881] = 1;
    sector
}

/// Build an image with two trees: the primary one the other fixtures have,
/// and a Joliet one whose names are the ones a reader is meant to see.
///
/// The file is the same file: both records name the same data extent, which
/// is what makes its length something two records have an opinion about.
fn build_joliet_image() -> Vec<u8> {
    let mut bytes = image_bytes();

    let start = 17 * SECTOR_SIZE;
    bytes[start..start + SECTOR_SIZE]
        .copy_from_slice(&build_svd(JOLIET_ROOT_SECTOR, JOLIET_ROOT_BYTES));
    let start = 18 * SECTOR_SIZE;
    bytes[start] = 255;
    bytes[start + 1..start + 6].copy_from_slice(b"CD001");
    bytes[start + 6] = 1;

    let mut root = Vec::new();
    root.extend(record(
        &[0x00, 0x00],
        JOLIET_ROOT_SECTOR as u32,
        JOLIET_ROOT_BYTES,
        true,
    ));
    root.extend(record(
        &[0x01, 0x00],
        JOLIET_ROOT_SECTOR as u32,
        JOLIET_ROOT_BYTES,
        true,
    ));
    root.extend(record(
        &ucs2("A"),
        JOLIET_SUB_SECTOR as u32,
        JOLIET_SUB_BYTES,
        true,
    ));
    root.extend(record(
        &ucs2("Hello World.txt"),
        HELLO_SECTOR as u32,
        HELLO_CONTENT.len() as u32,
        false,
    ));
    assert_eq!(root.len() as u32, JOLIET_ROOT_BYTES);
    let start = JOLIET_ROOT_SECTOR as usize * SECTOR_SIZE;
    bytes[start..start + root.len()].copy_from_slice(&root);

    let mut sub = Vec::new();
    sub.extend(record(
        &[0x00, 0x00],
        JOLIET_SUB_SECTOR as u32,
        JOLIET_SUB_BYTES,
        true,
    ));
    sub.extend(record(
        &[0x01, 0x00],
        JOLIET_ROOT_SECTOR as u32,
        JOLIET_ROOT_BYTES,
        true,
    ));
    assert_eq!(sub.len() as u32, JOLIET_SUB_BYTES);
    let start = JOLIET_SUB_SECTOR as usize * SECTOR_SIZE;
    bytes[start..start + sub.len()].copy_from_slice(&sub);

    bytes
}

/// The records of a Joliet extent, read off the medium.
fn joliet_records(
    device: &Arc<MemoryBlockDevice>,
    extent_location: u32,
    extent_size: u32,
) -> Vec<Record> {
    let mut data = vec![0u8; extent_size as usize];
    allocate::read_extent_bytes(
        &*device.clone(),
        SECTOR_SIZE as u16,
        extent_location,
        extent_size,
        0,
        &mut data,
    )
    .expect("the extent reads");

    walk_records(&data, true)
}

/// The extent the first entry of a descriptor's little-endian path table
/// names — which is that descriptor's tree's root.
fn table_root_extent(device: &Arc<MemoryBlockDevice>, sector: u64) -> u32 {
    let mut sector_bytes = [0u8; SECTOR_SIZE];
    write::read_exact(
        &*device.clone(),
        sector * SECTOR_SIZE as u64,
        &mut sector_bytes,
    )
    .expect("the descriptor reads");
    let size = super::volume_descriptor::both32(&sector_bytes, OFFSET_PATH_TABLE_SIZE)
        .expect("size")
        .0;
    let l = u32::from_le_bytes(
        sector_bytes[OFFSET_L_PATH_TABLE_LOC..OFFSET_L_PATH_TABLE_LOC + 4]
            .try_into()
            .expect("four bytes"),
    );
    let mut bytes = vec![0u8; size as usize];
    allocate::read_extent_bytes(&*device.clone(), SECTOR_SIZE as u16, l, size, 0, &mut bytes)
        .expect("the table reads");
    parse_path_table(&bytes, false)[0].3
}

/// The label comes from the supplementary descriptor, and the names a reader
/// is meant to see are that tree's.  A name whose identifier begins below
/// U+0100 is a name — not a "." record — and the primary tree names the same
/// *data* differently, which is the record the primary parser reads.
#[test]
fn a_two_tree_volume_reads_its_supplementary_tree() {
    let device = MemoryBlockDevice::new("iso-joliet", build_joliet_image(), true);
    let volume = Volume::open(device.clone()).expect("mounts");

    assert_eq!(volume.name(), "JOLIET");
    let node = volume.lookup("/Hello World.txt").expect("lookup");
    assert_eq!(node.name(), "Hello World.txt");
    assert_eq!(node.size(), HELLO_CONTENT.len());
    let mut buf = vec![0u8; HELLO_CONTENT.len()];
    assert_eq!(node.read(0, &mut buf), Ok(HELLO_CONTENT.len()));
    assert_eq!(buf, HELLO_CONTENT);

    assert_eq!(volume.read_dir("/", 0).expect("first entry").name, "A");
    assert_eq!(
        volume.read_dir("/", 1).expect("second entry").name,
        "Hello World.txt"
    );

    let (primary, size) = root_extent(&device);
    assert_eq!(
        record_named(&device, primary, size, b"HELLO.TXT;1").extent,
        HELLO_SECTOR as u32
    );
}

/// The shape a released bootable image has: the Boot Record sits between the
/// primary descriptor and the supplementary one, so the supplementary
/// descriptor is *not* at sector 17 and a reader that looked there would find
/// a boot record and no second tree at all.
#[test]
fn a_supplementary_descriptor_behind_a_boot_record_is_found() {
    let mut bytes = build_joliet_image();
    let svd = bytes[17 * SECTOR_SIZE..18 * SECTOR_SIZE].to_vec();
    let start = 18 * SECTOR_SIZE;
    bytes[start..start + SECTOR_SIZE].copy_from_slice(&svd);
    let start = 19 * SECTOR_SIZE;
    bytes[start] = 255;
    bytes[start + 1..start + 6].copy_from_slice(b"CD001");
    bytes[start + 6] = 1;
    let start = 17 * SECTOR_SIZE;
    bytes[start] = 0x00;
    bytes[start + 1..start + 6].copy_from_slice(b"CD001");
    bytes[start + 6] = 1;
    bytes[start + 71..start + 75].copy_from_slice(&22u32.to_le_bytes());
    let catalog = 22 * SECTOR_SIZE;
    bytes[catalog] = 0x01;
    bytes[catalog + 30] = 0x55;
    bytes[catalog + 31] = 0xAA;
    bytes[catalog + 32] = 0x88;

    let device = MemoryBlockDevice::new("iso-boot-joliet", bytes, true);
    let volume = Volume::open(device).expect("mounts");
    assert_eq!(volume.name(), "JOLIET");
    assert_eq!(
        volume.lookup("/Hello World.txt").expect("lookup").size(),
        HELLO_CONTENT.len()
    );
}

/// Opening a writable volume rebuilds the tables of every tree it has: the
/// primary descriptor's name the primary root — which the extension upgrade
/// moved — and the supplementary descriptor's name the supplementary one,
/// which is a different extent and a different tree.
#[test]
fn each_tree_gets_its_own_path_tables() {
    let device = MemoryBlockDevice::new("iso-joliet", build_joliet_image(), false);
    let _volume = Volume::open(device.clone()).expect("mounts");

    let mut sector = [0u8; SECTOR_SIZE];
    write::read_exact(&*device.clone(), 16 * SECTOR_SIZE as u64, &mut sector).expect("pvd reads");
    let size = super::volume_descriptor::both32(&sector, OFFSET_PATH_TABLE_SIZE)
        .expect("size")
        .0;
    let l = u32::from_le_bytes(
        sector[OFFSET_L_PATH_TABLE_LOC..OFFSET_L_PATH_TABLE_LOC + 4]
            .try_into()
            .unwrap(),
    );
    assert!(size > 0, "primary table size {} at {}", size, l);
    let primary_root = root_extent(&device).0;
    assert_eq!(table_root_extent(&device, 16), primary_root);

    let supplementary = table_root_extent(&device, 17);
    assert_eq!(supplementary, JOLIET_ROOT_SECTOR as u32);
    assert_ne!(supplementary, primary_root);
}

/// The data is one extent both records name, so an overwrite inside the
/// length is a change every tree sees — and a length is not.  Each tree's
/// record carries its own copy of it, and nothing on the volume says which
/// record in the other tree is this file's: the trees spell a name
/// differently by design.  A change that would leave one tree saying five
/// and the other thirteen is refused, and so is everything structural: the
/// primary tree's record is exactly what it was, which is the point of
/// refusing rather than half-writing.
#[test]
fn a_two_tree_volume_writes_only_what_both_trees_share() {
    let device = MemoryBlockDevice::new("iso-joliet", build_joliet_image(), false);
    let volume = Volume::open(device.clone()).expect("mounts");
    let node = volume.lookup("/Hello World.txt").expect("lookup");

    assert_eq!(node.write(0, b"JELLO"), Ok(5));
    let mut buf = vec![0u8; HELLO_CONTENT.len()];
    assert_eq!(node.read(0, &mut buf), Ok(HELLO_CONTENT.len()));
    assert_eq!(&buf[..5], b"JELLO");

    assert_eq!(node.set_len(5), Err(abi::Error::Unsupported));
    // A write that runs past the end needs the length every tree disagrees
    // about, so it takes what it can and stops: the contract's short write,
    // and not an error the caller has to know how to read.
    assert_eq!(node.write(0, &[0xAB; 40]), Ok(HELLO_CONTENT.len()));
    assert_eq!(
        volume.create_file("/new.bin").err(),
        Some(abi::Error::Unsupported)
    );
    assert_eq!(volume.create_dir("/new"), Err(abi::Error::Unsupported));
    assert_eq!(
        volume.remove_path("/Hello World.txt"),
        Err(abi::Error::Unsupported)
    );
    assert_eq!(
        volume.rename("/Hello World.txt", "/renamed.txt"),
        Err(abi::Error::Unsupported)
    );

    let (primary, size) = root_extent(&device);
    assert_eq!(
        record_named(&device, primary, size, b"HELLO.TXT;1").data_length,
        HELLO_CONTENT.len() as u32
    );
    let joliet = joliet_records(&device, JOLIET_ROOT_SECTOR as u32, JOLIET_ROOT_BYTES);
    assert_eq!(joliet[3].data_length, HELLO_CONTENT.len() as u32);
}
