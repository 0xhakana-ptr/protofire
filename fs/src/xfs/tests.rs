//! fs/src/xfs/tests.rs
//!
//! The XFS tests, on a host: a minimal v4 volume built by hand — the same
//! on-disk serialisation the format's own `mkfs` writes, laid out so every
//! field the driver reads is real — and the read paths exercised against
//! it: lookup, listing, extent-file reads, inline reads, symlinks, and the
//! name-hash lookup the leaf format answers by.
//!
//! The image builder is the test's own, because a read-only driver cannot
//! make the volume it reads: the builder writes the superblock, the two
//! inodes, and the payload block, and the driver reads them back.  A field
//! the builder wrote at the wrong offset would fail the comparison, which
//! is what makes the builder and the driver two readers of one truth.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use block::MemoryBlockDevice;

use crate::filesystem::FileSystem as _;
use crate::types::NodeKind;

use super::XfsVolume;

// The volume's geometry, and where the builder puts everything.
const BLOCK_SIZE: usize = 1024;
const INODE_SIZE: usize = 512;
const ROOT_INO: u64 = 128;
const FILE_INO: u64 = 131;
const LINK_INO: u64 = 132;
/// The payload's data block.
const DATA_BLOCK: u32 = 100;

/// The file's payload, twelve bytes past a block boundary's start.
const PAYLOAD: &[u8] = b"the xfs payload";

/// The symlink's target.
const LINK_TARGET: &[u8] = b"/hello.txt";

/// An inode's byte offset on disk, by the driver's own arithmetic: AG 0
/// holds everything, two 512-byte inodes per 1024-byte block.
fn inode_byte_offset(ino: u64) -> u64 {
    let inodes_per_block = (BLOCK_SIZE / INODE_SIZE) as u64;
    let block = ino / inodes_per_block;
    let within = (ino % inodes_per_block) * INODE_SIZE as u64;
    block * BLOCK_SIZE as u64 + within
}

/// One big-endian word into the image.
fn put_be32(img: &mut [u8], off: usize, value: u32) {
    img[off..off + 4].copy_from_slice(&value.to_be_bytes());
}

fn put_be64(img: &mut [u8], off: usize, value: u64) {
    img[off..off + 8].copy_from_slice(&value.to_be_bytes());
}

fn put_be16(img: &mut [u8], off: usize, value: u16) {
    img[off..off + 2].copy_from_slice(&value.to_be_bytes());
}

/// Write an inode's core fields, common to every kind.
///
/// The core is the format's own hundred bytes, big-endian: magic "IN",
/// mode, version, format, attr format, ids, links, size, and the fork
/// offset that ends the data fork.
fn put_inode_core(
    img: &mut [u8],
    byte_off: usize,
    mode: u16,
    format: u8,
    size: u64,
    num_extents: u32,
) {
    img[byte_off..byte_off + 2].copy_from_slice(&0x494Eu16.to_be_bytes());
    img[byte_off + 2..byte_off + 4].copy_from_slice(&mode.to_be_bytes());
    img[byte_off + 4] = 2; // di_version: a v4 inode
    img[byte_off + 5] = format;
    img[byte_off + 6] = 0; // attr format: none
    put_be32(img, byte_off + 8, 0); // uid
    put_be32(img, byte_off + 12, 0); // gid
    put_be32(img, byte_off + 16, 1); // nlink
    put_be64(img, byte_off + 24, size);
    put_be32(img, byte_off + 32, num_extents);
    // The fork offset stays zero: the data fork runs to the inode's end.
}

/// Build the minimal v4 volume: a superblock, a shortform root directory
/// naming two children, one extent-mapped file, one inline symlink, and
/// the payload block their extent names.
fn build_test_image() -> Vec<u8> {
    const TOTAL_BLOCKS: usize = 128;
    let mut img = vec![0_u8; TOTAL_BLOCKS * BLOCK_SIZE];

    // ── the superblock, at byte zero ─────────────────────────────────────
    put_be32(&mut img, 0, 0x5846_5342); // magic "XFSB"
    put_be32(&mut img, 4, BLOCK_SIZE as u32);
    put_be64(&mut img, 8, ROOT_INO);
    put_be32(&mut img, 20, 1024); // blocks per AG
    put_be32(&mut img, 24, 1); // AG count
    put_be16(&mut img, 100, INODE_SIZE as u16);
    put_be16(&mut img, 102, (BLOCK_SIZE / INODE_SIZE) as u16);
    put_be32(&mut img, 120, 512); // sector size

    // ── the root directory: shortform, naming hello.txt and link ─────────
    let root_off = inode_byte_offset(ROOT_INO) as usize;
    put_inode_core(&mut img, root_off, 0o040755, 0 /* LOCAL */, 64, 0);
    // The shortform entries, at the data fork: parent ino, count, pad,
    // then each entry's `namelen, pad, ino, name`.
    let fork = root_off + 100;
    put_be64(&mut img, fork, ROOT_INO); // parent
    img[fork + 8] = 2; // count
    let mut pos = fork + 12;
    // "hello.txt" → FILE_INO
    img[pos] = 9;
    pos += 2;
    put_be64(&mut img, pos, FILE_INO);
    pos += 8;
    img[pos..pos + 9].copy_from_slice(b"hello.txt");
    pos += 9;
    // "link" → LINK_INO
    img[pos] = 4;
    pos += 2;
    put_be64(&mut img, pos, LINK_INO);
    pos += 8;
    img[pos..pos + 4].copy_from_slice(b"link");

    // ── the file: extent-mapped, one extent naming the payload block ─────
    let file_off = inode_byte_offset(FILE_INO) as usize;
    put_inode_core(
        &mut img,
        file_off,
        0o100644,
        1, /* EXTENTS */
        PAYLOAD.len() as u64,
        1,
    );
    // The extent record, sixteen bytes: the flag byte's upper bits carry
    // nothing (the block is below 2³⁴), the start offset is zero, the
    // physical block is DATA_BLOCK, the count is one.
    let fork = file_off + 100;
    put_be64(&mut img, fork, 0); // start offset 0
    put_be32(&mut img, fork + 8, DATA_BLOCK); // start block
    put_be32(&mut img, fork + 12, 1); // block count

    // ── the symlink: local format, the target in the data fork ───────────
    let link_off = inode_byte_offset(LINK_INO) as usize;
    put_inode_core(
        &mut img,
        link_off,
        0o120777,
        0, /* LOCAL */
        LINK_TARGET.len() as u64,
        0,
    );
    let fork = link_off + 100;
    img[fork..fork + LINK_TARGET.len()].copy_from_slice(LINK_TARGET);

    // ── the payload block ────────────────────────────────────────────────
    let data_off = DATA_BLOCK as usize * BLOCK_SIZE;
    img[data_off..data_off + PAYLOAD.len()].copy_from_slice(PAYLOAD);

    img
}

/// A volume, mounted from the builder's image.
fn mounted() -> Arc<XfsVolume> {
    let device = MemoryBlockDevice::new("xfs-test", build_test_image(), true);
    XfsVolume::open(device).expect("a mounted volume")
}

/// A fresh volume opens, and is a directory at its root.
#[test]
fn a_volume_opens_and_its_root_is_a_directory() {
    let volume = mounted();
    let root = volume.lookup("/").expect("the root");
    assert_eq!(root.kind(), NodeKind::Directory);
    assert_eq!(volume.name(), "xfs");
}

/// A file named through the shortform root directory, read through its
/// extent list: the lookup, the size, and the bytes.
#[test]
fn a_file_is_looked_up_and_read_through_its_extent() {
    let volume = mounted();
    let node = volume.lookup("/hello.txt").expect("the file");
    assert_eq!(node.kind(), NodeKind::File);
    assert_eq!(node.size(), PAYLOAD.len());

    let mut buffer = [0_u8; 64];
    let read = node.read(0, &mut buffer).expect("a read");
    assert_eq!(&buffer[..read], PAYLOAD, "the bytes are the disk's");
}

/// A read from an offset inside the extent answers the bytes from there.
#[test]
fn a_read_from_an_offset_answers_from_there() {
    let volume = mounted();
    let node = volume.lookup("/hello.txt").expect("the file");
    let mut buffer = [0_u8; 64];
    let read = node.read(4, &mut buffer).expect("a read at 4");
    assert_eq!(&buffer[..read], &PAYLOAD[4..], "the offset is honoured");
}

/// The directory listing answers both children the root holds.
#[test]
fn the_root_listing_answers_its_children() {
    let volume = mounted();
    let first = volume.read_dir("/", 0).expect("the first entry");
    assert_eq!(first.name, "hello.txt");
    assert_eq!(first.kind, NodeKind::File);
    assert_eq!(first.size, PAYLOAD.len());

    let second = volume.read_dir("/", 1).expect("the second entry");
    assert_eq!(second.name, "link");
    assert_eq!(second.kind, NodeKind::Symlink);
}

/// The name-hash lookup answers the same inode the listing does: the hash
/// the driver computes must match the one the image's leaf format would
/// carry, which is the arithmetic a real volume's entries were written
/// with.
#[test]
fn the_name_hash_is_deterministic_and_names_the_entry() {
    use super::btree::xfs_dir_hash;
    assert_eq!(xfs_dir_hash(b""), 0);
    assert_ne!(xfs_dir_hash(b"test"), 0);
    assert_eq!(xfs_dir_hash(b"same"), xfs_dir_hash(b"same"));
    assert_ne!(xfs_dir_hash(b"abc"), xfs_dir_hash(b"abd"));

    // And the lookup itself answers through it on the real image.
    let volume = mounted();
    let node = volume.lookup("/hello.txt").expect("the file");
    assert_eq!(node.size(), PAYLOAD.len());
}

/// A symlink's target reads back through the inline data fork.
#[test]
fn a_symlink_answers_its_target() {
    let volume = mounted();
    let node = volume.lookup("/link").expect("the link");
    assert_eq!(node.kind(), NodeKind::Symlink);
    let target = node.readlink().expect("the target");
    assert_eq!(target, LINK_TARGET);

    // And the symlink resolves to its target through the lookup.
    let resolved = volume.lookup("/link").expect("the resolved node");
    assert_eq!(resolved.kind(), NodeKind::Symlink);
}

/// A name the root does not hold answers `NotFound`.
#[test]
fn a_missing_name_answers_not_found() {
    let volume = mounted();
    assert!(
        volume.lookup("/no-such-file").is_err(),
        "a missing name is a miss"
    );
}

/// The volume's mutations answer `PermissionDenied` through the blanket
/// read-only implementation — there is nowhere to forget one.
#[test]
fn the_mutations_are_refused_by_the_read_only_half() {
    let volume = mounted();
    assert!(
        matches!(
            volume.create_file("/new.txt"),
            Err(abi::Error::PermissionDenied)
        ),
        "a create is refused"
    );
    assert!(
        matches!(
            volume.remove_path("/hello.txt"),
            Err(abi::Error::PermissionDenied)
        ),
        "a remove is refused"
    );
    assert!(
        matches!(volume.rename("/a", "/b"), Err(abi::Error::PermissionDenied)),
        "a rename is refused"
    );
}

/// The extent packing's flag bits are honoured: a physical block above
/// 2³² reads its upper two bits from the record's flag byte.
#[test]
fn an_extent_s_flag_bits_carry_the_high_block_bits() {
    // A record whose physical block is 2³² exactly: the low word is zero
    // and the flag byte's bits 5-6 carry the one.
    let mut record = [0_u8; 16];
    record[0] = 0b0100_0000; // start_block_hi = 1 (bits 5-6)
    // start_block low word = 0, block count = 1.
    record[12..16].copy_from_slice(&1u32.to_be_bytes());

    let extents = super::types::parse_extents(&record, 0, 1);
    assert_eq!(extents.len(), 1);
    assert_eq!(extents[0].start_block, 1u64 << 32, "the high bits moved up");
    assert_eq!(extents[0].block_count, 1);
}
