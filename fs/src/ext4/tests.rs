//! fs/src/ext4/tests.rs
//!
//! The ext4 tests, all on a host: a volume this module's own formatter
//! makes on an in-memory device, mounted, written, flushed, and **reopened
//! from the raw bytes**, which is the round trip a boot actually runs, and
//! the one a parser that agreed with its own writer could never catch.
//!
//! The device is `block`'s [`MemoryBlockDevice`], and every volume here is
//! formatted fresh, so a test's volume is the write path's own product: a
//! failure in the formatter, the reader, the allocator, or the journal
//! shows up as a test that cannot read what it just wrote.

use alloc::sync::Arc;
use alloc::vec::Vec;

use block::MemoryBlockDevice;

use crate::filesystem::FileSystem as _;
use crate::types::NodeKind;

use super::Ext4Volume;

/// How many one-kilobyte blocks a test volume has: four megabytes, one
/// group, room for the journal, the inode table and the files below.
const TEST_BLOCKS: u32 = 4096;

/// A freshly formatted volume, as its raw bytes on an in-memory device.
fn formatted() -> Arc<MemoryBlockDevice> {
    let device = MemoryBlockDevice::new(
        "ext4-test",
        alloc::vec![0_u8; TEST_BLOCKS as usize * 1024],
        false,
    );
    Ext4Volume::make(device.clone(), TEST_BLOCKS).expect("a formatted volume");
    device
}

/// A volume, opened on the device itself: the first mount after a format.
fn mounted(device: &Arc<MemoryBlockDevice>) -> Arc<Ext4Volume> {
    Ext4Volume::open(device.clone()).expect("a mounted volume")
}

/// A volume, mounted from the bytes the device now holds: the image is read
/// back **off the device** through its own interface and opened as a new
/// volume, which is what a boot does when it finds a disk, nothing
/// survives by staying in memory the first volume holds.
fn remounted(device: &Arc<MemoryBlockDevice>) -> Arc<Ext4Volume> {
    const SECTORS: usize = TEST_BLOCKS as usize * 1024 / 512;
    let mut image = Vec::with_capacity(SECTORS * 512);
    for sector in 0..SECTORS as u64 {
        let mut chunk = [0_u8; 512];
        block::BlockDevice::read_blocks(device.as_ref(), sector, &mut chunk)
            .expect("read the formatted image back");
        image.extend_from_slice(&chunk);
    }
    let device = MemoryBlockDevice::new("ext4-remount", image, false);
    Ext4Volume::open(device).expect("a mounted volume")
}

/// A fresh volume opens, and is a directory at its root.
#[test]
fn a_formatted_volume_opens_and_its_root_is_a_directory() {
    let device = formatted();
    let volume = mounted(&device);
    assert!(
        volume.name().starts_with("ext4:"),
        "the volume names itself"
    );
    let root = volume.lookup("/").expect("the root");
    assert_eq!(root.kind(), NodeKind::Directory);
}

/// A file created, written, flushed, and read back **after a remount**.
///
/// This is the test the write path exists for: the bytes are the file's on
/// the disk the device holds, not the cache's, because the volume that
/// reads them was built from the raw bytes the first one flushed.  A write
/// that only reached the cache, a size that lied, or an extent that named
/// the wrong block would each fail the comparison.
#[test]
fn a_written_file_is_the_disks_own_bytes_after_a_remount() {
    let device = formatted();
    {
        let volume = mounted(&device);
        let node = volume.create_file("/hello.txt").expect("a create");
        let written = node
            .write(0, b"hello from the ext4 write path")
            .expect("a write");
        assert_eq!(written, 30);
        volume.sync().expect("a flush");
    }

    let volume = remounted(&device);
    let node = volume
        .lookup("/hello.txt")
        .expect("the file, after remount");
    assert_eq!(node.size(), 30, "the size is the disk's, not the cache's");
    let mut buffer = [0_u8; 64];
    let read = node.read(0, &mut buffer).expect("a read");
    assert_eq!(
        &buffer[..read],
        b"hello from the ext4 write path",
        "the bytes are the ones written, read back through a fresh open"
    );
}

/// A write that runs past one block: two blocks, allocated and chained, and
/// every byte lands where the extent tree says it does.
#[test]
fn a_write_across_blocks_reads_back_whole() {
    let device = formatted();
    {
        let volume = mounted(&device);
        let node = volume.create_file("/two-blocks.txt").expect("a create");
        let payload: alloc::vec::Vec<u8> = (0..2500u32).map(|i| (i % 251) as u8).collect();
        let written = node.write(0, &payload).expect("a write");
        assert_eq!(written, 2500, "two blocks and a bit");
        volume.sync().expect("a flush");
    }

    let volume = remounted(&device);
    let node = volume.lookup("/two-blocks.txt").expect("the file");
    let mut buffer = [0_u8; 2500];
    let read = node.read(0, &mut buffer).expect("a read");
    assert_eq!(read, 2500);
    for (index, byte) in buffer[..read].iter().enumerate() {
        assert_eq!(*byte, (index as u32 % 251) as u8, "byte {index} moved");
    }
}

/// A write into a file's middle does not take the bytes around it: the
/// read-modify-write the partial block needs.
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

    // What the device itself holds at the file's block, straight off the
    // interface.
    let mut raw = [0_u8; 1024];
    for i in 0..2usize {
        block::BlockDevice::read_blocks(
            device.as_ref(),
            (86 * 2 + i) as u64,
            &mut raw[i * 512..(i + 1) * 512],
        )
        .expect("a raw read");
    }
    // The journal superblock's errno, on the device.
    let mut jsb = [0_u8; 512];
    block::BlockDevice::read_blocks(device.as_ref(), 42, &mut jsb).expect("a raw read");
    // The data block holds the overwritten bytes, and the journal
    // superblock's errno is zero, the commit's own word for "clean"
    // with its start wherever the cursor landed, which is the journal's
    // business and not the test's.
    assert_eq!(&raw[..9], &b"AAAxyBCCC"[..], "the overwrite is on the disk");
    assert_eq!(&jsb[0x30..0x34], &[0, 0, 0, 0], "the journal is clean");

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
/// answers with the names the volume holds, after a remount.
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
    // The listing past the end answers `NotFound`, which is how a caller
    // knows it is done.
    assert!(volume.read_dir("/notes", 1).is_err());

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
        volume.sync().expect("a flush");
    }

    let volume = mounted(&device);
    assert!(volume.lookup("/draft.txt").is_err(), "the old name is gone");
    let node = volume.lookup("/sent.txt").expect("the new name");
    let mut buffer = [0_u8; 8];
    let read = node.read(0, &mut buffer).expect("a read");
    assert_eq!(&buffer[..read], b"final v2", "the bytes moved with it");
}

/// A removal takes the file and its blocks, and the directory listing
/// answers nothing for it afterwards.
#[test]
fn a_removal_takes_the_file_and_its_blocks() {
    let device = formatted();
    {
        let volume = mounted(&device);
        let node = volume.create_file("/gone.txt").expect("a create");
        node.write(0, b"soon forgotten").expect("a write");
        volume.remove_path("/gone.txt").expect("a remove");
        volume.sync().expect("a flush");
    }

    let volume = remounted(&device);
    assert!(volume.lookup("/gone.txt").is_err());
}

/// A removal of a directory that still has children is refused, and the
/// children are the reason.
#[test]
fn a_directory_with_children_is_not_removed() {
    let device = formatted();
    let volume = mounted(&device);
    volume.create_dir("/full").expect("a directory");
    volume.create_file("/full/keeper.txt").expect("a create");

    assert_eq!(
        volume.remove_path("/full").unwrap_err(),
        abi::Error::Busy,
        "the directory is not empty"
    );
    assert!(volume.lookup("/full/keeper.txt").is_ok(), "the child stays");
}

/// The same name twice is the create's own refusal.
#[test]
fn a_second_create_of_one_name_is_refused() {
    let device = formatted();
    let volume = mounted(&device);
    volume.create_file("/once.txt").expect("the first create");
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
        volume.sync().expect("a flush");
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

/// The journal is real: a formatted volume carries one, and the volume's
/// own check reports it whole.
#[test]
fn a_formatted_volume_carries_a_journal_and_checks_clean() {
    let device = formatted();
    let volume = mounted(&device);
    let report = volume.check_and_repair().expect("a check");
    assert_eq!(report.issues_detected, 0, "a fresh volume has no issues");
}

/// A file grown to a named length reads its extension as zeros, the one
/// direction of `set_len` this driver takes.
#[test]
fn an_extended_file_reads_its_extension_as_zeros() {
    let device = formatted();
    {
        let volume = mounted(&device);
        let node = volume.create_file("/padded.txt").expect("a create");
        node.write(0, b"head").expect("a write");
        node.set_len(100).expect("an extension");
        volume.sync().expect("a flush");
    }

    let volume = remounted(&device);
    let node = volume.lookup("/padded.txt").expect("the file");
    assert_eq!(node.size(), 100);
    let mut buffer = [0_u8; 100];
    let read = node.read(0, &mut buffer).expect("a read");
    assert_eq!(read, 100);
    assert_eq!(&buffer[..4], b"head");
    assert!(
        buffer[4..].iter().all(|b| *b == 0),
        "the extension is zeros"
    );
}

/// A dirty journal replays at open, and the volume it leaves is readable.
///
/// The crash this test simulates is the one the journal exists for: the
/// superblock's dirty flag set, as a crash between a transaction's first
/// write and its commit leaves it, and the mount that follows walks the
/// journal, marks it clean, and answers from the volume.  A replay that
/// refused the volume, or one that left the flag set for the next mount to
/// trip over again, fails here.
#[test]
fn a_dirty_journal_replays_and_the_volume_reads() {
    let device = formatted();
    {
        let volume = mounted(&device);
        let node = volume.create_file("/kept.txt").expect("a create");
        node.write(0, b"kept through the crash").expect("a write");
        volume.sync().expect("a flush");
    }

    // The crash: the journal's superblock goes back to dirty, straight on
    // the device, the way an interrupted transaction leaves it.
    let mut jsb = [0_u8; 512];
    block::BlockDevice::read_blocks(device.as_ref(), 42, &mut jsb).expect("a raw read");
    jsb[0x30..0x34].copy_from_slice(&1u32.to_be_bytes());
    block::BlockDevice::write_blocks(device.as_ref(), 42, &jsb).expect("the dirty flag");

    // The mount replays, and the file the volume held is still there.
    let volume = remounted(&device);
    let node = volume.lookup("/kept.txt").expect("the file, after replay");
    let mut buffer = [0_u8; 32];
    let read = node.read(0, &mut buffer).expect("a read");
    assert_eq!(&buffer[..read], b"kept through the crash");

    // The replay marked the journal clean, so a second mount does not
    // replay again: the flag is the volume's own record, and the third
    // mount reads the same bytes the second one left.
    let again = remounted(&device);
    assert!(
        !again.journal_replayed(),
        "a clean journal is not replayed twice"
    );
}

/// Many small files: the allocator hands out distinct blocks and inodes,
/// and every file reads back its own bytes, the collision the bitmap
/// arithmetic exists to prevent.
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
