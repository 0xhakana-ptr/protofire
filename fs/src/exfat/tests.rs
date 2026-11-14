//! fs/src/exfat/tests.rs
//!
//! The exFAT tests, on a host: a writable volume the test's own builder
//! makes, boot region with its checksum, FAT, allocation bitmap, up-case
//! table, and a root directory whose entry sets name the bitmap and the
//! table, and the read and write paths exercised against it.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use block::MemoryBlockDevice;

use crate::filesystem::FileSystem as _;
use crate::types::NodeKind;

use super::ExfatVolume;
use super::types::B_BYTES_PER_SECTOR_SHIFT;
use super::types::B_CHECKSUM_OFFSET;
use super::types::B_CHECKSUM_SECTOR;
use super::types::B_CLUSTER_COUNT;
use super::types::B_CLUSTER_HEAP_OFFSET;
use super::types::B_FAT_LENGTH;
use super::types::B_FAT_OFFSET;
use super::types::B_FS_REVISION;
use super::types::B_NUM_FATS;
use super::types::B_OEM_NAME;
use super::types::B_ROOT_DIR_CLUSTER;
use super::types::B_SECTORS_PER_CLUSTER_SHIFT;
use super::types::B_VOLUME_FLAGS;
use super::types::B_VOLUME_LENGTH;
use super::types::B_VOLUME_SERIAL;
use super::types::BOOT_SIGNATURE_OFFSET;
use super::types::EXFAT_ENTRY_BITMAP;
use super::types::EXFAT_ENTRY_STREAM;
use super::types::EXFAT_ENTRY_UPCASE;
use super::types::FIRST_DATA_CLUSTER;
use super::types::S_DATA_LEN;
use super::types::S_FIRST_CLUSTER;
use super::types::S_VALID_DATA_LEN;
use super::types::write_u16_le;
use super::types::write_u32_le;
use super::types::write_u64_le;

const BYTES_PER_SECTOR: usize = 512;
const FAT_OFFSET: u32 = 12;
const FAT_LENGTH: u32 = 8;
const CLUSTER_HEAP_OFFSET: u32 = 20;
const CLUSTER_COUNT: u32 = 96;
const ROOT_DIR_CLUSTER: u32 = 2;
const BITMAP_CLUSTER: u32 = 3;
const UPCASE_CLUSTER: u32 = 4;
const VOLUME_LENGTH: u32 = CLUSTER_HEAP_OFFSET + CLUSTER_COUNT;

fn put_u32(img: &mut [u8], off: usize, val: u32) {
    img[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn cluster_lba(cluster: u32) -> u32 {
    CLUSTER_HEAP_OFFSET + (cluster - FIRST_DATA_CLUSTER)
}

/// The writable test image, laid out as the module header describes.
fn build_exfat_rw_image() -> Vec<u8> {
    let total = VOLUME_LENGTH as usize * BYTES_PER_SECTOR;
    let mut img = vec![0u8; total];

    let boot = &mut img[..BYTES_PER_SECTOR];
    boot[B_OEM_NAME..B_OEM_NAME + 8].copy_from_slice(b"EXFAT   ");
    write_u64_le(boot, B_VOLUME_LENGTH, VOLUME_LENGTH as u64);
    write_u32_le(boot, B_FAT_OFFSET, FAT_OFFSET);
    write_u32_le(boot, B_FAT_LENGTH, FAT_LENGTH);
    write_u32_le(boot, B_CLUSTER_HEAP_OFFSET, CLUSTER_HEAP_OFFSET);
    write_u32_le(boot, B_CLUSTER_COUNT, CLUSTER_COUNT);
    write_u32_le(boot, B_ROOT_DIR_CLUSTER, ROOT_DIR_CLUSTER);
    write_u32_le(boot, B_VOLUME_SERIAL, 0x1234_5678);
    write_u16_le(boot, B_FS_REVISION, 0x0100);
    write_u16_le(boot, B_VOLUME_FLAGS, 0);
    boot[B_BYTES_PER_SECTOR_SHIFT] = 9;
    boot[B_SECTORS_PER_CLUSTER_SHIFT] = 0;
    boot[B_NUM_FATS] = 1;
    boot[BOOT_SIGNATURE_OFFSET] = 0x55;
    boot[BOOT_SIGNATURE_OFFSET + 1] = 0xAA;

    let sum: u32 = img[..BYTES_PER_SECTOR * B_CHECKSUM_SECTOR]
        .iter()
        .fold(0u32, |acc, &b| acc.wrapping_add(b as u32));
    let cs_off = BYTES_PER_SECTOR * B_CHECKSUM_SECTOR + B_CHECKSUM_OFFSET;
    img[cs_off..cs_off + 4].copy_from_slice(&sum.to_le_bytes());

    // The FAT: media descriptor, then EOC for the root, the bitmap and the
    // up-case table.
    let fat_base = FAT_OFFSET as usize * BYTES_PER_SECTOR;
    put_u32(&mut img, fat_base, 0xFFFF_FFF8);
    put_u32(&mut img, fat_base + 4, 0xFFFF_FFFF);
    put_u32(&mut img, fat_base + 8, 0xFFFF_FFFF);
    put_u32(&mut img, fat_base + 12, 0xFFFF_FFFF);
    put_u32(&mut img, fat_base + 16, 0xFFFF_FFFF);

    // The bitmap: clusters 2, 3 and 4 allocated.
    let bitmap_off = cluster_lba(BITMAP_CLUSTER) as usize * BYTES_PER_SECTOR;
    img[bitmap_off] = 0x07;

    // The up-case table's placeholder.
    let upcase_off = cluster_lba(UPCASE_CLUSTER) as usize * BYTES_PER_SECTOR;
    img[upcase_off..upcase_off + 4].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

    // The root directory: the bitmap's and the up-case table's entry sets.
    let root = cluster_lba(ROOT_DIR_CLUSTER) as usize * BYTES_PER_SECTOR;
    img[root] = EXFAT_ENTRY_BITMAP;
    img[root + 32] = EXFAT_ENTRY_STREAM;
    write_u32_le(&mut img[root..], 32 + S_FIRST_CLUSTER, BITMAP_CLUSTER);
    write_u32_le(&mut img[root..], 32 + S_VALID_DATA_LEN, 12);
    write_u32_le(&mut img[root..], 32 + S_DATA_LEN, 12);
    img[root + 64] = EXFAT_ENTRY_UPCASE;
    img[root + 96] = EXFAT_ENTRY_STREAM;
    write_u32_le(&mut img[root..], 96 + S_FIRST_CLUSTER, UPCASE_CLUSTER);
    write_u32_le(&mut img[root..], 96 + S_VALID_DATA_LEN, 256);
    write_u32_le(&mut img[root..], 96 + S_DATA_LEN, 256);

    img
}

/// A volume, opened on a fresh image.
fn mounted() -> Arc<ExfatVolume> {
    let device = MemoryBlockDevice::new("exfat-test", build_exfat_rw_image(), false);
    ExfatVolume::open(device).expect("open exFAT volume")
}

/// A file created, written, and read back, the write path's own proof
/// through the NoFatChain contiguous stream every new file takes.
#[test]
fn a_written_file_reads_back_its_bytes() {
    let volume = mounted();
    let vnode = volume.create_file("/newfile.txt").expect("create_file");
    assert_eq!(vnode.kind(), NodeKind::File);
    assert_eq!(vnode.size(), 0);

    let n = vnode.write(0, b"Hello exFAT!").expect("write");
    assert_eq!(n, 12);

    let mut buf = [0u8; 20];
    let n = vnode.read(0, &mut buf).expect("read");
    assert_eq!(&buf[..n], b"Hello exFAT!");
}

/// A directory created and found through the lookup.
#[test]
fn a_directory_created_and_found() {
    let volume = mounted();
    volume.create_dir("/subdir").expect("create_dir");

    let vnode = volume.lookup("/subdir").expect("lookup subdir");
    assert_eq!(vnode.kind(), NodeKind::Directory);
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

/// A rename under a new name in the same directory moves the entry set.
#[test]
fn a_rename_moves_the_file() {
    let volume = mounted();
    let vnode = volume.create_file("/draft.txt").expect("a create");
    vnode.write(0, b"final v2").expect("a write");
    volume.rename("/draft.txt", "/sent.txt").expect("a rename");

    assert!(volume.lookup("/draft.txt").is_err(), "the old name is gone");
    let node = volume.lookup("/sent.txt").expect("the new name");
    let mut buffer = [0_u8; 8];
    let read = node.read(0, &mut buffer).expect("a read");
    assert_eq!(&buffer[..read], b"final v2", "the bytes moved with it");
}

/// A removal takes the file: the entry set's in-use bit goes down and the
/// name answers nothing afterwards.
#[test]
fn a_removal_takes_the_file() {
    let volume = mounted();
    let vnode = volume.create_file("/gone.txt").expect("a create");
    vnode.write(0, b"soon forgotten").expect("a write");
    volume.remove_path("/gone.txt").expect("a remove");

    assert!(volume.lookup("/gone.txt").is_err());
}

/// The volume's mutations beyond the write path answer the read-only
/// refusals their absence deserves, the check's own sanity pass.
#[test]
fn the_check_reports_a_fresh_volume_clean() {
    let volume = mounted();
    let report = volume.check_and_repair().expect("a check");
    assert_eq!(report.issues_detected, 0, "a fresh volume has no issues");
}
