//! fs/src/f2fs/tests.rs
//!
//! The f2fs tests, on a host: a volume this module's own formatter makes on
//! an in-memory device, mounted, written, checkpointed, and **reopened from
//! the raw bytes** — which is the round trip a boot actually runs, and the
//! one a parser that agreed with its own writer could never catch.

use alloc::sync::Arc;
use alloc::vec::Vec;

use block::MemoryBlockDevice;

use crate::filesystem::FileSystem as _;
use crate::types::NodeKind;

use super::F2fsVolume;

/// How many blocks a test volume has: the main area's two segments.
const TEST_BLOCKS: usize = (6 + 512 * 2) as usize;

/// A freshly formatted volume, as its raw bytes on an in-memory device.
fn formatted() -> Arc<MemoryBlockDevice> {
    let device = MemoryBlockDevice::new("f2fs-test", alloc::vec![0_u8; TEST_BLOCKS * 4096], false);
    F2fsVolume::make(device.clone()).expect("a formatted volume");
    device
}

/// A volume, opened on the device itself: the first mount after a format.
fn mounted(device: &Arc<MemoryBlockDevice>) -> Arc<F2fsVolume> {
    F2fsVolume::open(device.clone()).expect("a mounted volume")
}

/// A volume, mounted from the bytes the device now holds — the round trip
/// a boot runs, with nothing surviving in memory the first volume holds.
fn remounted(device: &Arc<MemoryBlockDevice>) -> Arc<F2fsVolume> {
    let mut image = Vec::with_capacity(TEST_BLOCKS * 4096);
    for sector in 0..(TEST_BLOCKS * 4096 / 512) as u64 {
        let mut chunk = [0_u8; 512];
        block::BlockDevice::read_blocks(device.as_ref(), sector, &mut chunk)
            .expect("read the formatted image back");
        image.extend_from_slice(&chunk);
    }
    let device = MemoryBlockDevice::new("f2fs-remount", image, false);
    F2fsVolume::open(device).expect("a mounted volume")
}

/// A fresh volume opens, and is a directory at its root.
#[test]
fn a_formatted_volume_opens_and_its_root_is_a_directory() {
    let device = formatted();
    let volume = mounted(&device);
    assert!(
        volume.name().starts_with("f2fs:"),
        "the volume names itself"
    );
    let root = volume.lookup("/").expect("the root");
    assert_eq!(root.kind(), NodeKind::Directory);
    assert_eq!(root.name(), "root");
}

/// A file created, written, checkpointed, and read back **after a
/// remount** — the write path's own proof, through the log-structured
/// append and the checkpoint that commits it.
#[test]
fn a_written_file_is_the_disks_own_bytes_after_a_remount() {
    let device = formatted();
    {
        let volume = mounted(&device);
        let node = volume.create_file("/hello.txt").expect("a create");
        let written = node
            .write(0, b"hello from the f2fs write path")
            .expect("a write");
        assert_eq!(written, 30);
        // The live volume reads its own write back through the cache.
        let mut live = [0_u8; 64];
        let live_read = node.read(0, &mut live).expect("a live read");
        assert_eq!(&live[..live_read], b"hello from the f2fs write path");
        // A write rides the cache; the sync is what commits it — the same
        // call a program's fsync makes, and the reason the remount below
        // sees the bytes at all.
        volume.sync().expect("a flush");
    }
    // The checkpoint versions on the device, both copies: the sync's
    // checkpoint is the third (format, create, sync).
    let mut cp0 = [0_u8; 512];
    let mut cp1 = [0_u8; 512];
    block::BlockDevice::read_blocks(device.as_ref(), 8, &mut cp0).expect("a raw read");
    block::BlockDevice::read_blocks(device.as_ref(), 16, &mut cp1).expect("a raw read");
    let ver0 = u64::from_le_bytes([
        cp0[0], cp0[1], cp0[2], cp0[3], cp0[4], cp0[5], cp0[6], cp0[7],
    ]);
    let ver1 = u64::from_le_bytes([
        cp1[0], cp1[1], cp1[2], cp1[3], cp1[4], cp1[5], cp1[6], cp1[7],
    ]);
    assert_eq!(
        (ver0, ver1),
        (3, 2),
        "checkpoint versions after format(1/0), create(→copy1 ver2), sync(→copy0 ver3)"
    );

    // The NAT area on the device, straight off the interface: nid 4's
    // entry is eight bytes at offset 32 of NAT block 4 (LBA 32).
    let mut nat = [0_u8; 4096];
    for i in 0..8usize {
        block::BlockDevice::read_blocks(
            device.as_ref(),
            (4 * 8 + i) as u64,
            &mut nat[i * 512..(i + 1) * 512],
        )
        .expect("a raw read");
    }
    // Every NAT entry, on the device.
    let entries: Vec<u32> = (0..8usize)
        .map(|nid| {
            u32::from_le_bytes([
                nat[nid * 8],
                nat[nid * 8 + 1],
                nat[nid * 8 + 2],
                nat[nid * 8 + 3],
            ])
        })
        .collect();
    let entry_addr = entries[4];
    assert_ne!(entry_addr, 0, "nid 4 names a block: entries {entries:?}");

    // Where the payload landed, by scan.
    let mut data_sector = None;
    for sector in 0..(TEST_BLOCKS * 8) as u64 {
        let mut chunk = [0_u8; 512];
        block::BlockDevice::read_blocks(device.as_ref(), sector, &mut chunk).expect("a raw read");
        if chunk.windows(19).any(|w| w == b"hello from the f2fs") {
            data_sector = Some(sector);
            break;
        }
    }
    let data_sector = data_sector.expect("the payload is on the device somewhere");

    // The inode block the NAT names, straight off the device: its size
    // field is at offset 16, eight bytes little-endian.
    let mut inode_block = [0_u8; 4096];
    for i in 0..8usize {
        block::BlockDevice::read_blocks(
            device.as_ref(),
            (entry_addr as usize * 8 + i) as u64,
            &mut inode_block[i * 512..(i + 1) * 512],
        )
        .expect("a raw read");
    }
    let size = u64::from_le_bytes([
        inode_block[16],
        inode_block[17],
        inode_block[18],
        inode_block[19],
        inode_block[20],
        inode_block[21],
        inode_block[22],
        inode_block[23],
    ]);
    assert_eq!(
        size, 30,
        "the inode block at {entry_addr} holds the size; data at sector {data_sector:?}"
    );

    let volume = remounted(&device);
    let node = volume
        .lookup("/hello.txt")
        .expect("the file, after remount");
    assert_eq!(node.size(), 30);
    let mut buffer = [0_u8; 64];
    let read = node.read(0, &mut buffer).expect("a read");
    assert_eq!(
        &buffer[..read],
        b"hello from the f2fs write path",
        "the bytes are the ones written, read back through a fresh open"
    );
}

/// A write into a file's middle keeps the bytes around it: the
/// log-structured write copies the old block and overlays the written
/// range, and the inode's pointer moves to the fresh one.
#[test]
fn a_write_in_the_middle_keeps_the_bytes_around_it() {
    let device = formatted();
    {
        let volume = mounted(&device);
        let node = volume.create_file("/middle.txt").expect("a create");
        node.write(0, b"AAABBBCCC").expect("the first write");
        node.write(3, b"xy").expect("the overwrite");
        volume.sync().expect("a flush");
    }

    let volume = remounted(&device);
    let node = volume.lookup("/middle.txt").expect("the file");
    let mut buffer = [0_u8; 9];
    let read = node.read(0, &mut buffer).expect("a read");
    assert_eq!(
        &buffer[..read],
        b"AAAxyBCCC",
        "only the written bytes moved"
    );
}

/// Directories: created, listed, a file made inside one, and the listing
/// answers with the names the volume holds — after a remount.
#[test]
fn a_directory_holds_what_was_made_in_it() {
    let device = formatted();
    {
        let volume = mounted(&device);
        volume.create_dir("/notes").expect("a directory");
        let file = volume.create_file("/notes/todo.txt").expect("a create");
        file.write(0, b"buy milk").expect("a write");
        volume.sync().expect("a flush");
    }

    let volume = remounted(&device);
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

/// A rename moves the file, its bytes and nothing else.
#[test]
fn a_rename_moves_the_file_and_its_bytes() {
    let device = formatted();
    {
        let volume = mounted(&device);
        let node = volume.create_file("/draft.txt").expect("a create");
        node.write(0, b"final v2").expect("a write");
        volume.rename("/draft.txt", "/sent.txt").expect("a rename");
    }

    let volume = remounted(&device);
    assert!(volume.lookup("/draft.txt").is_err(), "the old name is gone");
    let node = volume.lookup("/sent.txt").expect("the new name");
    let mut buffer = [0_u8; 8];
    let read = node.read(0, &mut buffer).expect("a read");
    assert_eq!(&buffer[..read], b"final v2", "the bytes moved with it");
}

/// A removal takes the file and invalidates its blocks: the SIT's bits go
/// to zero, and the listing answers nothing for the name afterwards.
#[test]
fn a_removal_takes_the_file() {
    let device = formatted();
    {
        let volume = mounted(&device);
        let node = volume.create_file("/gone.txt").expect("a create");
        node.write(0, b"soon forgotten").expect("a write");
        volume.remove_path("/gone.txt").expect("a remove");
    }

    let volume = remounted(&device);
    assert!(volume.lookup("/gone.txt").is_err());
}

/// The same name twice is the create's own refusal.
#[test]
fn a_second_create_of_one_name_is_refused() {
    let device = formatted();
    let volume = mounted(&device);
    volume.create_file("/once.txt").expect("the first create");
    volume.sync().expect("a flush");
    assert!(
        matches!(
            volume.create_file("/once.txt"),
            Err(abi::Error::AlreadyExists)
        ),
        "the second create of one name is the create's own refusal"
    );
}

/// Symlinks resolve: a fast symlink to a file, walked through the link.
#[test]
fn a_symlink_resolves_to_its_target() {
    let device = formatted();
    {
        let volume = mounted(&device);
        let node = volume.create_file("/target.txt").expect("a create");
        node.write(0, b"behind the link").expect("a write");
        volume
            .create_symlink("/target.txt", "/link")
            .expect("a link");
    }

    let volume = remounted(&device);
    let node = volume.lookup("/link").expect("the link resolves");
    let mut buffer = [0_u8; 16];
    let read = node.read(0, &mut buffer).expect("a read through the link");
    assert_eq!(&buffer[..read], b"behind the link");
}

/// A device node answers the number it was made with.
#[test]
fn a_device_node_answers_its_number() {
    let device = formatted();
    let volume = mounted(&device);
    volume
        .create_device("/console", 4, 7)
        .expect("a device node");
    let node = volume.lookup("/console").expect("the node");
    assert_eq!(node.device_id().expect("a device number"), (4, 7));
}

/// A file truncated to a shorter length reads nothing past it, and its
/// blocks are invalidated — the one direction of `set_len` the
/// log-structured model takes without a garbage collector.
#[test]
fn a_truncated_file_reads_nothing_past_its_new_end() {
    let device = formatted();
    {
        let volume = mounted(&device);
        let node = volume.create_file("/cut.txt").expect("a create");
        node.write(0, b"all of this goes").expect("a write");
        node.set_len(4).expect("a truncation");
        volume.sync().expect("a flush");
    }

    let volume = remounted(&device);
    let node = volume.lookup("/cut.txt").expect("the file");
    assert_eq!(node.size(), 4);
    let mut buffer = [0_u8; 16];
    let read = node.read(0, &mut buffer).expect("a read");
    assert_eq!(&buffer[..read], b"all ", "and nothing past the new end");
}

/// Many small files: the NAT hands out distinct NIDs, every file reads
/// back its own bytes, and no file sees another's — the collision the
/// node-id scan exists to prevent.
#[test]
fn many_files_read_back_their_own_bytes() {
    let device = formatted();
    {
        let volume = mounted(&device);
        for index in 0..12u32 {
            let path = alloc::format!("/file{index}.txt");
            let node = volume.create_file(&path).expect("a create");
            let payload = alloc::format!("contents of file {index}");
            node.write(0, payload.as_bytes()).expect("a write");
        }
        volume.sync().expect("a flush");
    }

    let volume = remounted(&device);
    for index in 0..12u32 {
        let path = alloc::format!("/file{index}.txt");
        let node = volume.lookup(&path).expect("the file");
        let mut buffer = [0_u8; 32];
        let read = node.read(0, &mut buffer).expect("a read");
        let expected = alloc::format!("contents of file {index}");
        assert_eq!(&buffer[..read], expected.as_bytes(), "file {index} moved");
    }
}
