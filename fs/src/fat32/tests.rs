//! fs/src/fat32/tests.rs
//!
//! The FAT32 tests, on a host: a writable volume the test's own builder
//! makes on an in-memory device, the boot sector, two FAT tables, and a
//! root directory with its dot entries, and the read and write paths
//! exercised against it through mount, write, flush, and re-open on the
//! same device, which is what a boot does when it finds one.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use block::MemoryBlockDevice;

use super::types::write_short_entry;
use crate::filesystem::FileSystem as _;
use crate::types::NodeKind;

use super::FatVolume;

const BYTES_PER_SECTOR: usize = 512;
const SECTORS_PER_CLUSTER: u8 = 1;
const RESERVED_SECTORS: u16 = 32;
const NUM_FATS: u8 = 2;
const SECTORS_PER_FAT: u32 = 4;
const TOTAL_SECTORS: u32 = 240;
const ROOT_CLUSTER: u32 = 2;
const ATTR_DIRECTORY: u8 = 0x10;

fn put_u16(img: &mut [u8], off: usize, val: u16) {
    img[off..off + 2].copy_from_slice(&val.to_le_bytes());
}
fn put_u32(img: &mut [u8], off: usize, val: u32) {
    img[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn data_start_lba() -> u32 {
    RESERVED_SECTORS as u32 + NUM_FATS as u32 * SECTORS_PER_FAT
}

/// The writable test image: boot sector, two FATs, root directory cluster
/// with its dot entries.
fn build_writable_image() -> Vec<u8> {
    let total = TOTAL_SECTORS as usize * BYTES_PER_SECTOR;
    let mut img = vec![0u8; total];

    let boot = &mut img[..BYTES_PER_SECTOR];
    boot[0..3].copy_from_slice(b"\xEB\x3C\x90");
    boot[3..11].copy_from_slice(b"MSDOS5.0");
    put_u16(boot, 11, BYTES_PER_SECTOR as u16);
    boot[13] = SECTORS_PER_CLUSTER;
    put_u16(boot, 14, RESERVED_SECTORS);
    boot[16] = NUM_FATS;
    put_u16(boot, 17, 0);
    put_u16(boot, 19, 0);
    boot[21] = 0xF8;
    put_u16(boot, 22, 0);
    put_u32(boot, 32, TOTAL_SECTORS);
    put_u32(boot, 36, SECTORS_PER_FAT);
    put_u32(boot, 44, ROOT_CLUSTER);
    put_u16(boot, 48, 1);
    put_u16(boot, 50, 6);
    boot[66] = 0x29;
    put_u32(boot, 67, 0x1234_5678);
    boot[71..82].copy_from_slice(b"TESTVOL    ");
    boot[82..90].copy_from_slice(b"FAT32   ");
    boot[510] = 0x55;
    boot[511] = 0xAA;

    let fat_base = RESERVED_SECTORS as usize * BYTES_PER_SECTOR;
    for fat in 0..NUM_FATS as usize {
        let base = fat_base + fat * SECTORS_PER_FAT as usize * BYTES_PER_SECTOR;
        put_u32(&mut img, base, 0x0FFF_FFF8);
        put_u32(&mut img, base + 4, 0xFFFF_FFFF);
        put_u32(&mut img, base + 8, 0x0FFF_FFFF);
    }

    let root_off = data_start_lba() as usize * BYTES_PER_SECTOR;
    write_short_entry(
        &mut img,
        root_off,
        b".          ",
        ATTR_DIRECTORY,
        ROOT_CLUSTER,
        0,
    );
    write_short_entry(
        &mut img,
        root_off + 32,
        b"..         ",
        ATTR_DIRECTORY,
        ROOT_CLUSTER,
        0,
    );

    img
}

/// A volume, opened on a fresh image.
fn mounted() -> Arc<FatVolume> {
    let device = MemoryBlockDevice::new("fat32-test", build_writable_image(), false);
    FatVolume::open(device).expect("a mounted volume")
}

/// A volume, opened on the device itself: the first mount after a format.
fn mounted_on(device: &Arc<MemoryBlockDevice>) -> Arc<FatVolume> {
    FatVolume::open(device.clone()).expect("a mounted volume")
}

/// A fresh volume opens, and is a directory at its root.
#[test]
fn a_volume_opens_and_its_root_is_a_directory() {
    let volume = mounted();
    assert!(
        volume.name().starts_with("fat32:"),
        "the volume names itself"
    );
    let root = volume.lookup("/").expect("the root");
    assert_eq!(root.kind(), NodeKind::Directory);
}

/// A file created, written, flushed, and read back **after a fresh open on
/// the same device**, the device is the disk, and re-opening it is what a
/// boot does when it finds one.
#[test]
fn a_written_file_is_the_disks_own_bytes_after_a_remount() {
    let device = MemoryBlockDevice::new("fat32-test", build_writable_image(), false);
    {
        let volume = mounted_on(&device);
        let node = volume.create_file("/hello.txt").expect("a create");
        let written = node
            .write(0, b"hello from the fat write path")
            .expect("a write");
        assert_eq!(written, 29);
        volume.sync().expect("a flush");
    }
    let volume = mounted_on(&device);
    let node = volume
        .lookup("/hello.txt")
        .expect("the file, after remount");
    assert_eq!(node.size(), 29);
    let mut buffer = [0_u8; 64];
    let read = node.read(0, &mut buffer).expect("a read");
    assert_eq!(
        &buffer[..read],
        b"hello from the fat write path",
        "the bytes are the disk's"
    );
}

/// A write into a file's middle keeps the bytes around it.
#[test]
fn a_write_in_the_middle_keeps_the_bytes_around_it() {
    let volume = mounted();
    let node = volume.create_file("/middle.txt").expect("a create");
    node.write(0, b"AAABBBCCC").expect("the first write");
    node.write(3, b"xy").expect("the overwrite");
    volume.sync().expect("a flush");

    let mut buffer = [0_u8; 9];
    let read = node.read(0, &mut buffer).expect("a read");
    assert_eq!(
        &buffer[..read],
        b"AAAxyBCCC",
        "only the written bytes moved"
    );
}

/// Directories: created, listed, a file made inside one, and the listing
/// answers with the names the volume holds.
#[test]
fn a_directory_holds_what_was_made_in_it() {
    let volume = mounted();
    volume.create_dir("/notes").expect("a directory");
    let file = volume.create_file("/notes/todo.txt").expect("a create");
    file.write(0, b"buy milk").expect("a write");
    volume.sync().expect("a flush");

    let entry = volume.read_dir("/notes", 0).expect("the first entry");
    assert_eq!(entry.name, "todo.txt");
    assert_eq!(entry.kind, NodeKind::File);
    assert_eq!(entry.size, 8);
    assert!(volume.read_dir("/notes", 1).is_err(), "one entry, no more");

    let node = volume.lookup("/notes/todo.txt").expect("the file inside");
    let mut buffer = [0_u8; 8];
    let read = node.read(0, &mut buffer).expect("a read");
    assert_eq!(&buffer[..read], b"buy milk");
}

/// A rename moves the file and its bytes, under the new name.
#[test]
fn a_rename_moves_the_file_and_its_bytes() {
    let volume = mounted();
    let node = volume.create_file("/draft.txt").expect("a create");
    node.write(0, b"final v2").expect("a write");
    volume.rename("/draft.txt", "/sent.txt").expect("a rename");
    volume.sync().expect("a flush");

    assert!(volume.lookup("/draft.txt").is_err(), "the old name is gone");
    let node = volume.lookup("/sent.txt").expect("the new name");
    let mut buffer = [0_u8; 8];
    let read = node.read(0, &mut buffer).expect("a read");
    assert_eq!(&buffer[..read], b"final v2", "the bytes moved with it");
}

/// A removal takes the file and frees its cluster chain: the name answers
/// nothing afterwards, and the freed space is what the next create reuses.
#[test]
fn a_removal_takes_the_file_and_frees_the_chain() {
    let volume = mounted();
    let node = volume.create_file("/gone.txt").expect("a create");
    node.write(0, b"soon forgotten").expect("a write");
    volume.remove_path("/gone.txt").expect("a remove");
    volume.sync().expect("a flush");

    assert!(volume.lookup("/gone.txt").is_err());
    let node = volume.create_file("/reused.txt").expect("the next create");
    node.write(0, b"reused").expect("a write");
}

/// The same name twice is the create's own refusal.
#[test]
fn a_second_create_of_one_name_is_refused() {
    let volume = mounted();
    volume.create_file("/once.txt").expect("the first create");
    assert!(
        matches!(
            volume.create_file("/once.txt"),
            Err(abi::Error::AlreadyExists)
        ),
        "the second create of one name is the create's own refusal"
    );
}

/// A directory that still holds children is not removed.
#[test]
fn a_directory_with_children_is_not_removed() {
    let volume = mounted();
    volume.create_dir("/full").expect("a directory");
    volume.create_file("/full/keeper.txt").expect("a create");

    assert!(
        matches!(volume.remove_path("/full"), Err(abi::Error::Busy)),
        "the directory is not empty"
    );
    assert!(volume.lookup("/full/keeper.txt").is_ok(), "the child stays");
}

/// A truncated file reads nothing past its new end.
#[test]
fn a_truncated_file_reads_nothing_past_its_new_end() {
    let volume = mounted();
    let node = volume.create_file("/cut.txt").expect("a create");
    node.write(0, b"all of this goes").expect("a write");
    node.set_len(4).expect("a truncation");
    volume.sync().expect("a flush");

    assert_eq!(node.size(), 4);
    let mut buffer = [0_u8; 16];
    let read = node.read(0, &mut buffer).expect("a read");
    assert_eq!(&buffer[..read], b"all ", "and nothing past the new end");
}
