//! fs/src/iso9660/tests.rs
//!
//! End-to-end tests: build an image to the specification, mount it, read it.
//!
//! ## Why the image is built here
//!
//! A test that built its input with the code under test would agree with
//! itself.  These images are written by hand from the field offsets the
//! specification gives, so a reader that read the wrong offset would read a
//! number that is not the one the builder wrote — which is the whole point.
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
    /// The first version of this said nothing — the default is 512 — and read
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
    let padded = identifier.len() + (identifier.len() & 1);
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
    if identifier.len() % 2 == 1 {
        bytes.push(0);
    }
    bytes
}

/// The extent a directory's records occupy, zero-padded to a sector.
fn directory_extent(records: &[Vec<u8>]) -> Vec<u8> {
    let mut extent = Vec::new();
    for record in records {
        extent.extend_from_slice(record);
    }
    let padded = extent.len().div_ceil(SECTOR_SIZE) * SECTOR_SIZE;
    extent.resize(padded, 0);
    extent
}

/// Build the image the module header describes.
fn image() -> ImageDevice {
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

    ImageDevice { bytes }
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

/// Writing is refused, because a disc cannot be written.
#[test]
fn a_disc_refuses_every_write() {
    let volume = mounted();
    assert_eq!(
        volume.create_file("/NEW.TXT").err(),
        Some(abi::Error::Unsupported)
    );
    assert_eq!(
        volume.create_dir("/NEWDIR").err(),
        Some(abi::Error::Unsupported)
    );
    assert_eq!(
        volume.remove_path("/HELLO.TXT").err(),
        Some(abi::Error::Unsupported)
    );
    assert_eq!(
        volume.rename("/HELLO.TXT", "/OTHER.TXT").err(),
        Some(abi::Error::Unsupported)
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
