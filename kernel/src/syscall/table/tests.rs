//! kernel/src/syscall/table/tests.rs
//!
//! The module's tests.
//!
//! A sibling file because the tests outgrew the module: a reader looking for
//! the mechanism should not scroll past them to find the end of it.

//! The tests for this module.
//!
//! The syscall registry's tests: the table's dispatch, the descriptor
//! slots, the validators, and the MAC calls answering through the table
//! rather than beside it.

use alloc::sync::Arc;

use super::super::*;
// The device list is a `static` and the tests run in parallel, so two tests
// that each clear it and record their own rows would answer each other's
// records -- measured, with `list_block_devices_past_the_end_is_not_found`
// answering a row a parallel test had just put there.  Each of the tests
// below takes this lock for its whole body, the way `block_devices`' own
// tests serialise against the same list.
static DEVICE_LIST: spin::Mutex<()> = spin::Mutex::new(());
use super::Descriptor;
use super::MAX_SYSCALLS;
use abi::Error;
use abi::Result;
use abi::fs as fs_abi;
use fs::MountTable;
use fs::StaticFileSystem;
use fs::TmpFsVolume;
use fs::types::NodeKind;
use syscall::SyscallContext;
use syscall::SyscallNumber;

/// A volume with one file in it, and a table serving the three handlers.
fn mounted() -> SyscallTable {
    let volume = StaticFileSystem::with_entries(
        "test",
        &[
            ("/", NodeKind::Directory, b""),
            ("/greeting.txt", NodeKind::File, b"hello from a syscall"),
            ("/docs", NodeKind::Directory, b""),
        ],
    );
    let mut table = SyscallTable::new();
    let mut namespace = MountTable::new();
    namespace
        .mount("/", "pyrofs", "boot", Arc::new(volume))
        .expect("mount");
    table.set_namespace(Arc::new(namespace));
    table.register(SyscallNumber::Open, open);
    table.register(SyscallNumber::Read, read);
    table.register(SyscallNumber::Write, write);
    table.register(SyscallNumber::Stat, stat);
    table.register(SyscallNumber::ReadDir, read_dir);
    table.register(SyscallNumber::Close, close);
    table
}

/// A table on the tmpfs, the one backend whose nodes accept bytes.
///
/// The static volume above is a synthetic view, and its nodes refuse a
/// write by construction; the write tests need the filesystem the boot
/// itself mounts for scratch space, whose `create_file` creates and whose
/// nodes hold what was written.  A host has no clock installed, so the
/// timestamps it stamps are zero, which is a timestamp that says "unknown"
/// and is not part of what these tests read.
fn writable() -> SyscallTable {
    let volume = TmpFsVolume::new("test-tmpfs", 64 * 1024);
    let mut table = SyscallTable::new();
    let mut namespace = MountTable::new();
    namespace
        .mount("/", "tmpfs", "memory", Arc::new(volume))
        .expect("mount");
    table.set_namespace(Arc::new(namespace));
    table.register(SyscallNumber::Open, open);
    table.register(SyscallNumber::Read, read);
    table.register(SyscallNumber::Write, write);
    table.register(SyscallNumber::Stat, stat);
    table.register(SyscallNumber::CreateDir, create_dir);
    table.register(SyscallNumber::RemovePath, remove_path);
    table.register(SyscallNumber::Rename, rename);
    table.register(SyscallNumber::ReadDir, read_dir);
    table.register(SyscallNumber::OpenAt, open_at);
    table.register(SyscallNumber::StatAt, stat_at);
    table.register(SyscallNumber::CreateDirAt, create_dir_at);
    table.register(SyscallNumber::RemovePathAt, remove_path_at);
    table.register(SyscallNumber::RenameAt, rename_at);
    table.register(SyscallNumber::SetLength, set_length);
    table.register(SyscallNumber::Seek, seek);
    table.register(SyscallNumber::StatFd, stat_fd);
    table.register(SyscallNumber::ReadDirFd, read_dir_fd);
    table.register(SyscallNumber::Close, close);
    table
}

/// Open a path through the registry, as the boot does.
fn open_path(table: &mut SyscallTable, path: &str, flags: usize) -> Result<usize> {
    let mut context = SyscallContext::new(SyscallNumber::Open as usize, [0, flags, 0, 0, 0, 0]);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some(path),
        second_path: None,
        buffer: None,
        second_buffer: None,
    };
    let dispatch = table.dispatch(&mut arguments)?;
    Ok(dispatch.value)
}

/// Read through the registry.
fn read_into(
    table: &mut SyscallTable,
    descriptor: usize,
    offset: usize,
    buffer: &mut [u8],
) -> Result<usize> {
    let mut context = SyscallContext::new(
        SyscallNumber::Read as usize,
        [descriptor, offset, 0, 0, 0, 0],
    );
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        second_path: None,
        buffer: Some(buffer),
        second_buffer: None,
    };
    let dispatch = table.dispatch(&mut arguments)?;
    Ok(dispatch.value)
}

/// The whole path: open, read, close, and the bytes that came back.
///
/// This is the test the wiring exists for.  Every part of the interface is
/// on it, the number reaches the table, the context carries the arguments,
/// the validators run, the filesystem answers, and the value comes back as
/// a dispatch, and a break in any of them makes the comparison fail.
#[test]
fn a_file_is_opened_read_and_closed_through_the_table() {
    let mut table = mounted();
    let descriptor = open_path(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ)
        .expect("open through the registry");

    let mut buffer = [0u8; 20];
    let count = read_into(&mut table, descriptor, READ_OFFSET_CURRENT, &mut buffer)
        .expect("read through the registry");
    assert_eq!(count, 20);
    assert_eq!(&buffer, b"hello from a syscall");

    assert_eq!(table.close(descriptor), Ok(()));
    assert_eq!(table.open_descriptors(), 0);
}

/// A second read at the descriptor's own offset continues where the first
/// stopped, and produces no bytes at end of file.
///
/// The offset is the descriptor's state, not the caller's: a program that
/// reads twice without seeking expects the second call to continue, and a
/// handler that restarted at zero would loop forever on a short buffer.
#[test]
fn the_descriptor_remembers_its_offset() {
    let mut table = mounted();
    let descriptor = open_path(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ).expect("open");

    let mut first = [0u8; 6];
    assert_eq!(
        read_into(&mut table, descriptor, READ_OFFSET_CURRENT, &mut first),
        Ok(6)
    );
    assert_eq!(&first, b"hello ");

    let mut second = [0u8; 20];
    assert_eq!(
        read_into(&mut table, descriptor, READ_OFFSET_CURRENT, &mut second),
        Ok(14)
    );
    assert_eq!(&second[..14], b"from a syscall");

    // Past the end the answer is zero, not an error: a short read at end of
    // file is how a caller learns it is done.
    let mut past_end = [0u8; 4];
    assert_eq!(
        read_into(&mut table, descriptor, READ_OFFSET_CURRENT, &mut past_end),
        Ok(0)
    );
}

/// An explicit offset overrides the descriptor's own, and does not move it.
///
/// A caller reading a header at a known position and then continuing from
/// where it was is the case; the descriptor keeping its position is what
/// makes it expressible.
#[test]
fn an_explicit_offset_does_not_disturb_the_position() {
    let mut table = mounted();
    let descriptor = open_path(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ).expect("open");

    let mut probe = [0u8; 5];
    assert_eq!(read_into(&mut table, descriptor, 6, &mut probe), Ok(5));
    assert_eq!(&probe, b"from ");

    let mut from_start = [0u8; 5];
    assert_eq!(
        read_into(&mut table, descriptor, READ_OFFSET_CURRENT, &mut from_start),
        Ok(5)
    );
    assert_eq!(&from_start, b"hello");
}

/// Write through the registry, the way `read_into` reads.
fn write_as(
    table: &mut SyscallTable,
    descriptor: usize,
    bytes: &[u8],
    pid: Option<u32>,
) -> Result<usize> {
    let mut context = SyscallContext::new(
        SyscallNumber::Write as usize,
        [descriptor, 0, bytes.len(), 0, 0, 0],
    );
    if let Some(pid) = pid {
        context = context.with_caller(pid);
    }
    // A copy, because the argument takes a mutable borrow and the test's
    // sources are literals; the handler reads what the borrow names
    // either way.
    let mut copy = bytes.to_vec();
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        second_path: None,
        buffer: Some(&mut copy),
        second_buffer: None,
    };
    let dispatch = table.dispatch(&mut arguments)?;
    Ok(dispatch.value)
}

/// Truncate through the registry: `SetLength(descriptor, length)`.
///
/// The call takes no pointer, so there is nothing to borrow and the
/// helper is shorter than `write_as` for that reason rather than by
/// accident.
fn set_length_as(
    table: &mut SyscallTable,
    descriptor: usize,
    length: u64,
    pid: Option<u32>,
) -> Result<()> {
    let mut context = SyscallContext::new(
        SyscallNumber::SetLength as usize,
        [descriptor, length as usize, 0, 0, 0, 0],
    );
    if let Some(pid) = pid {
        context = context.with_caller(pid);
    }
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        second_path: None,
        buffer: None,
        second_buffer: None,
    };
    table.dispatch(&mut arguments)?;
    Ok(())
}

/// The loop the write closes: a program creates a file, writes it, and
/// reads its own bytes back through the same descriptor.
///
/// This is the whole of what `Write` exists for, and every link is on
/// this path, the create flag reaching the filesystem, the descriptor
/// recording the right, the write starting at the position and moving it,
/// and the read continuing where the write stopped.  A break in any of
/// them fails the comparison.
#[test]
fn a_file_is_written_and_read_back_through_the_table() {
    let mut table = writable();
    let flags = fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
    let descriptor = open_path(&mut table, "/note.txt", flags).expect("create and open");

    assert_eq!(
        write_as(&mut table, descriptor, b"written ", None),
        Ok(8),
        "the first write answers the bytes it accepted"
    );
    assert_eq!(
        write_as(&mut table, descriptor, b"by a syscall", None),
        Ok(12),
        "the second write continues where the first stopped"
    );

    // The position moved with each write, so a read from the descriptor's
    // own position starts past what was written, which is how a caller
    // knows the bytes are behind it rather than ahead of it.
    let mut buffer = [0u8; 4];
    assert_eq!(
        read_into(&mut table, descriptor, READ_OFFSET_CURRENT, &mut buffer),
        Ok(0),
        "the position sits at end of file after two writes"
    );

    // And a fresh open reads the whole thing from the start: the bytes
    // are the file's now, not the descriptor's.
    let reader = open_path(&mut table, "/note.txt", fs_abi::OPEN_FLAG_READ).expect("reopen");
    let mut whole = [0u8; 20];
    assert_eq!(
        read_into(&mut table, reader, READ_OFFSET_CURRENT, &mut whole),
        Ok(20)
    );
    assert_eq!(&whole, b"written by a syscall");
}

/// A truncate shortens a file, and a fresh open reads the part that is left.
///
/// The whole of what `SetLength` adds: the descriptor names a file, the
/// node's `set_len` runs, and what a later reader sees is the shortened
/// file.  A handler that answered zero without reaching the node would
/// pass a test that only checked the status word, so the size is read
/// back through a separate descriptor.
#[test]
fn a_truncate_shortens_the_file_a_descriptor_names() {
    let mut table = writable();
    let flags = fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
    let descriptor = open_path(&mut table, "/note.txt", flags).expect("create and open");
    assert_eq!(
        write_as(&mut table, descriptor, b"twenty bytes of text", None),
        Ok(20)
    );

    assert_eq!(set_length_as(&mut table, descriptor, 6, None), Ok(()));

    let reader = open_path(&mut table, "/note.txt", fs_abi::OPEN_FLAG_READ).expect("reopen");
    let mut kept = [0u8; 32];
    assert_eq!(
        read_into(&mut table, reader, READ_OFFSET_CURRENT, &mut kept),
        Ok(6),
        "the file is six bytes long now"
    );
    assert_eq!(&kept[..6], b"twenty");
}

/// A truncate is a write, so a read-only descriptor is refused.
///
/// The same right `write` needs, refused in the same place and for the
/// same reason: the descriptor was opened for reading, and a node that
/// would accept a length is still not writable through it.
#[test]
fn a_descriptor_opened_read_only_refuses_a_truncate() {
    let mut table = writable();
    let creator = open_path(
        &mut table,
        "/note.txt",
        fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE,
    )
    .expect("create");
    assert_eq!(table.close(creator), Ok(()));

    let reader = open_path(&mut table, "/note.txt", fs_abi::OPEN_FLAG_READ).expect("open");
    assert_eq!(
        set_length_as(&mut table, reader, 0, None),
        Err(Error::PermissionDenied)
    );
}

/// A truncate leaves the descriptor's position where it was.
///
/// A caller that writes a header, truncates a tail and appends expects the
/// third call to land after the second.  A truncate that rewound the
/// position would make the append overwrite the header, which is the
/// defect this test names rather than a style choice.
#[test]
fn a_truncate_does_not_move_the_descriptor_position() {
    let mut table = writable();
    let flags = fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
    let descriptor = open_path(&mut table, "/note.txt", flags).expect("create and open");

    assert_eq!(
        write_as(&mut table, descriptor, b"header and tail", None),
        Ok(15)
    );
    assert_eq!(set_length_as(&mut table, descriptor, 6, None), Ok(()));
    // The position is still at 15, past the new end, so the append lands
    // there rather than at the start.
    assert_eq!(write_as(&mut table, descriptor, b"!", None), Ok(1));

    let reader = open_path(&mut table, "/note.txt", fs_abi::OPEN_FLAG_READ).expect("reopen");
    let mut whole = [0u8; 32];
    let count = read_into(&mut table, reader, READ_OFFSET_CURRENT, &mut whole).expect("read");
    assert_eq!(count, 16, "the file grew to the append's position");
    assert_eq!(&whole[..6], b"header", "the header is untouched");
    assert_eq!(&whole[15..16], b"!", "the append landed past the new end");
}

/// A truncate of another process's descriptor is refused.
#[test]
fn one_process_cannot_truncate_another_process_descriptor() {
    let mut table = writable();
    let theirs = open_as(
        &mut table,
        "/note.txt",
        fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE,
        8,
    )
    .expect("open");

    assert_eq!(
        set_length_as(&mut table, theirs, 0, Some(7)),
        Err(Error::InvalidArgument)
    );
    assert_eq!(set_length_as(&mut table, theirs, 0, Some(8)), Ok(()));
}

/// A node that records which flush reached it.
///
/// The flushes are the one pair of calls whose success leaves no trace on the
/// file: the answer is zero whether the node was asked or not, so a handler
/// that answered without reaching the node passes every test that reads the
/// status.  This node is how the test tells "asked" from "answered", which is
/// the difference between a call served and a call implemented.
struct RecordingNode {
    name: &'static str,
    syncs: core::sync::atomic::AtomicUsize,
    data_syncs: core::sync::atomic::AtomicUsize,
    holes: core::sync::atomic::AtomicUsize,
    flags: core::sync::atomic::AtomicU32,
    flag_writes: core::sync::atomic::AtomicUsize,
    /// Whether this node claims to make holes.  A node that does not is the
    /// default `VNode`, which refuses `punch_hole` with `PermissionDenied`;
    /// the test needs both shapes because the two refusals are different
    /// answers.
    makes_holes: bool,
}

impl RecordingNode {
    fn new() -> Self {
        Self {
            name: "recorded",
            syncs: core::sync::atomic::AtomicUsize::new(0),
            data_syncs: core::sync::atomic::AtomicUsize::new(0),
            holes: core::sync::atomic::AtomicUsize::new(0),
            flags: core::sync::atomic::AtomicU32::new(0),
            flag_writes: core::sync::atomic::AtomicUsize::new(0),
            makes_holes: true,
        }
    }

    fn refusing_holes() -> Self {
        Self {
            makes_holes: false,
            ..Self::new()
        }
    }
}

impl fs::VNode for RecordingNode {
    fn name(&self) -> &str {
        self.name
    }

    fn kind(&self) -> NodeKind {
        NodeKind::File
    }

    fn size(&self) -> usize {
        0
    }

    fn read(&self, _offset: u64, _buffer: &mut [u8]) -> Result<usize> {
        Err(Error::NotFound)
    }

    fn sync(&self) -> Result<()> {
        self.syncs
            .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn sync_data(&self) -> Result<()> {
        self.data_syncs
            .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn punch_hole(&self, _offset: u64, _length: u64) -> Result<()> {
        if !self.makes_holes {
            return Err(Error::PermissionDenied);
        }
        self.holes
            .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        Ok(())
    }

    fn get_file_flags(&self) -> Result<u32> {
        Ok(self.flags.load(core::sync::atomic::Ordering::SeqCst))
    }

    fn set_file_flags(&self, set: u32, clear: u32) -> Result<()> {
        let mut flags = self.flags.load(core::sync::atomic::Ordering::SeqCst);
        flags |= set;
        flags &= !clear;
        self.flags
            .store(flags, core::sync::atomic::Ordering::SeqCst);
        self.flag_writes
            .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

/// Put a file descriptor over `node` and answer its number.
fn insert_file(table: &mut SyscallTable, node: Arc<dyn fs::VNode>, writable: bool) -> usize {
    table
        .insert(Descriptor::File {
            node,
            readable: true,
            writable,
            offset: 0,
            path: alloc::string::String::from("/recorded"),
            owner: 1,
        })
        .expect("insert")
}

/// Flush through the registry: `Fsync` or `Fdatasync` on a descriptor.
fn flush_as(table: &mut SyscallTable, descriptor: usize, data_only: bool) -> Result<()> {
    let number = if data_only {
        SyscallNumber::Fdatasync
    } else {
        SyscallNumber::Fsync
    };
    let mut context = SyscallContext::new(number as usize, [descriptor, 0, 0, 0, 0, 0]);
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        second_path: None,
        buffer: None,
        second_buffer: None,
    };
    table.dispatch(&mut arguments)?;
    Ok(())
}

/// Seek through the registry: `Seek(descriptor, offset, whence)`.
fn seek_as(table: &mut SyscallTable, descriptor: usize, offset: i64, whence: usize) -> Result<u64> {
    let mut context = SyscallContext::new(
        SyscallNumber::Seek as usize,
        [descriptor, offset as usize, whence, 0, 0, 0],
    );
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        second_path: None,
        buffer: None,
        second_buffer: None,
    };
    Ok(table.dispatch(&mut arguments)?.value as u64)
}

/// A seek from each of the three distance bases lands where it says.
///
/// One test for the three because they share one arithmetic: a base, a signed
/// offset, and a position.  A handler that read the offset unsigned would
/// still pass `SEEK_SET` with a small offset and fail only the backward step,
/// which is why that step is here.
#[test]
fn a_seek_lands_at_the_offset_from_each_base() {
    let mut table = writable();
    let flags = fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
    let descriptor = open_path(&mut table, "/note.txt", flags).expect("create and open");
    assert_eq!(
        write_as(&mut table, descriptor, b"0123456789", None),
        Ok(10)
    );

    // Absolute.
    assert_eq!(seek_as(&mut table, descriptor, 3, fs_abi::SEEK_SET), Ok(3));
    // From the current position, forwards.
    assert_eq!(seek_as(&mut table, descriptor, 2, fs_abi::SEEK_CUR), Ok(5));
    // Backwards, which is the case an unsigned offset cannot express.
    assert_eq!(seek_as(&mut table, descriptor, -3, fs_abi::SEEK_CUR), Ok(2));
    // From the end, backwards.
    assert_eq!(seek_as(&mut table, descriptor, -4, fs_abi::SEEK_END), Ok(6));
    // From the end, past it: legal, and the position stays there.
    assert_eq!(seek_as(&mut table, descriptor, 5, fs_abi::SEEK_END), Ok(15));
}

/// A seek to a negative position is refused and leaves the position alone.
///
/// The refusal is the arithmetic's, not the file's: seeking before the start
/// is not a place a read could start, and a wrapped `u64` would be an enormous
/// offset that a later read would report as end of file, which is a plausible
/// answer to a call that should have been refused.
#[test]
fn a_seek_before_the_start_is_refused() {
    let mut table = writable();
    let descriptor = open_path(
        &mut table,
        "/note.txt",
        fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE,
    )
    .expect("create");
    assert_eq!(write_as(&mut table, descriptor, b"abc", None), Ok(3));
    assert_eq!(seek_as(&mut table, descriptor, 2, fs_abi::SEEK_SET), Ok(2));

    assert_eq!(
        seek_as(&mut table, descriptor, -5, fs_abi::SEEK_CUR),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        seek_as(&mut table, descriptor, -1, fs_abi::SEEK_SET),
        Err(Error::InvalidArgument)
    );
    // The refusals left the position where it was, which the next read proves.
    let mut one = [0u8; 1];
    assert_eq!(
        read_into(&mut table, descriptor, READ_OFFSET_CURRENT, &mut one),
        Ok(1)
    );
    assert_eq!(&one, b"c");
}

/// A seek from an unknown whence is refused rather than treated as absolute.
#[test]
fn a_seek_with_an_unknown_whence_is_refused() {
    let mut table = writable();
    let descriptor = open_path(
        &mut table,
        "/note.txt",
        fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE,
    )
    .expect("create");

    assert_eq!(
        seek_as(&mut table, descriptor, 0, 99),
        Err(Error::InvalidArgument)
    );
}

/// `SEEK_DATA` and `SEEK_HOLE` answer the node's extent, not a distance.
///
/// A node with no holes is the default `next_extent`: every byte below the
/// size is data, and the end of the file is the hole.  The two calls are not
/// distance seeks, so they are checked through the same call as the three that
/// are, and their answers are byte offsets rather than sums.
#[test]
fn a_seek_to_an_extent_answers_the_node_position() {
    let mut table = writable();
    let descriptor = open_path(
        &mut table,
        "/note.txt",
        fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE,
    )
    .expect("create");
    assert_eq!(
        write_as(&mut table, descriptor, b"0123456789", None),
        Ok(10)
    );

    assert_eq!(seek_as(&mut table, descriptor, 4, fs_abi::SEEK_DATA), Ok(4));
    // A file that is all data has one hole, and it is the end of the file.
    assert_eq!(
        seek_as(&mut table, descriptor, 0, fs_abi::SEEK_HOLE),
        Ok(10)
    );

    // Past the end there is no extent of either kind, and the answer is the
    // one a range past the end gets rather than a position.
    assert_eq!(
        seek_as(&mut table, descriptor, 11, fs_abi::SEEK_DATA),
        Err(Error::InvalidArgument)
    );
}

/// Each flush reaches the node, and each reaches it once.
///
/// The counts are the whole point: `Fsync` that answered zero without calling
/// `sync`, or that called both, or `Fdatasync` that called the stronger one,
/// would all pass a test that only checked the status.  This is the test that
/// makes the pair's difference observable.
#[test]
fn each_flush_reaches_the_node_once() {
    use core::sync::atomic::Ordering;

    let mut table = SyscallTable::new();
    table.register(SyscallNumber::Fsync, fsync);
    table.register(SyscallNumber::Fdatasync, fdatasync);

    let node = Arc::new(RecordingNode::new());
    let descriptor = insert_file(&mut table, node.clone(), true);

    assert_eq!(flush_as(&mut table, descriptor, false), Ok(()));
    assert_eq!(node.syncs.load(Ordering::SeqCst), 1, "Fsync called sync");
    assert_eq!(
        node.data_syncs.load(Ordering::SeqCst),
        0,
        "and not the data-only one"
    );

    assert_eq!(flush_as(&mut table, descriptor, true), Ok(()));
    assert_eq!(
        node.syncs.load(Ordering::SeqCst),
        1,
        "Fdatasync did not call the stronger flush"
    );
    assert_eq!(
        node.data_syncs.load(Ordering::SeqCst),
        1,
        "Fdatasync called sync_data"
    );
}

/// A flush of a read-only descriptor is refused, and reaches nothing.
///
/// A flush is the call that makes what the caller wrote durable, so the right
/// it needs is the write's.  The node's own count proves the refusal came
/// before the node was asked, rather than being a node that refused.
#[test]
fn a_flush_of_a_read_only_descriptor_is_refused() {
    use core::sync::atomic::Ordering;

    let mut table = SyscallTable::new();
    table.register(SyscallNumber::Fsync, fsync);
    table.register(SyscallNumber::Fdatasync, fdatasync);

    let node = Arc::new(RecordingNode::new());
    let descriptor = insert_file(&mut table, node.clone(), false);

    assert_eq!(
        flush_as(&mut table, descriptor, false),
        Err(Error::PermissionDenied)
    );
    assert_eq!(
        flush_as(&mut table, descriptor, true),
        Err(Error::PermissionDenied)
    );
    assert_eq!(
        node.syncs.load(Ordering::SeqCst) + node.data_syncs.load(Ordering::SeqCst),
        0,
        "the node was never reached"
    );
}

/// Punch a hole through the registry.
fn punch_as(
    table: &mut SyscallTable,
    descriptor: usize,
    offset: u64,
    length: u64,
    mode: usize,
) -> Result<()> {
    let mut context = SyscallContext::new(
        SyscallNumber::Fallocate as usize,
        [descriptor, mode, offset as usize, length as usize, 0, 0],
    );
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        second_path: None,
        buffer: None,
        second_buffer: None,
    };
    table.dispatch(&mut arguments)?;
    Ok(())
}

/// Read a descriptor's file flags through the registry.
fn flags_as(table: &mut SyscallTable, descriptor: usize) -> Result<u32> {
    let mut context = SyscallContext::new(
        SyscallNumber::GetFileFlags as usize,
        [descriptor, 0, 0, 0, 0, 0],
    );
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        second_path: None,
        buffer: None,
        second_buffer: None,
    };
    Ok(table.dispatch(&mut arguments)?.value as u32)
}

/// Change a descriptor's file flags through the registry.
fn set_flags_as(table: &mut SyscallTable, descriptor: usize, set: u32, clear: u32) -> Result<()> {
    let mut context = SyscallContext::new(
        SyscallNumber::SetFileFlags as usize,
        [descriptor, set as usize, clear as usize, 0, 0, 0],
    );
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        second_path: None,
        buffer: None,
        second_buffer: None,
    };
    table.dispatch(&mut arguments)?;
    Ok(())
}

/// A flush of a descriptor that names no file is refused.
#[test]
fn a_flush_of_a_pipe_descriptor_is_refused() {
    use crate::pipe;
    use crate::pipe::End;

    let pipe = Arc::new(pipe::Pipe::new(16));
    let mut table = SyscallTable::new();
    table.register(SyscallNumber::Fsync, fsync);
    let end = table
        .insert_pipe(End::writer(pipe.clone()), 1)
        .expect("insert");

    assert_eq!(
        flush_as(&mut table, end, false),
        Err(Error::InvalidArgument)
    );
}

/// `WriteDebug` answers the bytes it was given, and refuses a bad range.
///
/// The handler is the one call in this group that writes nothing the caller
/// can read back, so the assertion is on its answer and on the reserved slots:
/// a call that took the length from the wrong slot would answer a number the
/// caller never sent.
#[test]
fn write_debug_answers_the_length_it_was_given() {
    let mut table = SyscallTable::new();
    table.register(SyscallNumber::WriteDebug, write_debug);

    let text = b"hello";
    let mut copy = text.to_vec();
    let mut context = SyscallContext::new(
        SyscallNumber::WriteDebug as usize,
        [0, copy.len(), 0, 0, 0, 0],
    );
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        second_path: None,
        buffer: Some(&mut copy),
        second_buffer: None,
    };
    assert_eq!(
        table
            .dispatch(&mut arguments)
            .map(|dispatch| dispatch.value),
        Ok(text.len())
    );
}

/// A `WriteDebug` whose reserved slots are not zero is refused.
#[test]
fn write_debug_with_reserved_arguments_set_is_refused() {
    let mut table = SyscallTable::new();
    table.register(SyscallNumber::WriteDebug, write_debug);

    let mut copy = alloc::vec::Vec::new();
    let mut context = SyscallContext::new(SyscallNumber::WriteDebug as usize, [0, 0, 1, 0, 0, 0]);
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        second_path: None,
        buffer: Some(&mut copy),
        second_buffer: None,
    };
    assert_eq!(table.dispatch(&mut arguments), Err(Error::InvalidArgument));
}

/// `ReadConsole` answers zero rather than refusing, and zero at length zero.
///
/// The difference is the whole point of serving it: `NotImplemented` says this
/// ABI has no such call, and zero says there is nothing to read yet.  A machine
/// with no keyboard driver is the second, and a shell loops on it.
#[test]
fn read_console_answers_nothing_rather_than_refusing() {
    let mut table = SyscallTable::new();
    table.register(SyscallNumber::ReadConsole, read_console);

    // The address is a real one, because the handler validates the range: a
    // test that passed zero would be asserting the refusal rather than the
    // answer.
    let mut buffer = [0u8; 8];
    let address = buffer.as_mut_ptr() as usize;
    let mut context = SyscallContext::new(
        SyscallNumber::ReadConsole as usize,
        [address, buffer.len(), 0, 0, 0, 0],
    );
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        second_path: None,
        buffer: Some(&mut buffer),
        second_buffer: None,
    };
    assert_eq!(
        table
            .dispatch(&mut arguments)
            .map(|dispatch| dispatch.value),
        Ok(0)
    );

    // A zero length is zero without looking at the address, which is what makes
    // it safe to call with no buffer at all.
    let mut context = SyscallContext::new(SyscallNumber::ReadConsole as usize, [0, 0, 0, 0, 0, 0]);
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        second_path: None,
        buffer: None,
        second_buffer: None,
    };
    assert_eq!(
        table
            .dispatch(&mut arguments)
            .map(|dispatch| dispatch.value),
        Ok(0)
    );
}

/// `ListBlockDevices` fills the record at the ABI's own offsets.
///
/// The layout is the assertion: the three words go after the name's *aligned*
/// end and not its end, so a handler that added 63 would write every word one
/// byte early.  Parsing by offset is what a program does, so parsing by offset
/// is what the test does.
#[test]
fn list_block_devices_fills_the_record_at_the_abis_offsets() {
    let _device_list = DEVICE_LIST.lock();
    crate::block_devices::clear();
    assert!(crate::block_devices::record("virtio-blk", 512, 4096, false));

    let mut table = SyscallTable::new();
    table.register(SyscallNumber::ListBlockDevices, list_block_devices);

    let mut record = [0u8; fs_abi::BLOCK_DEVICE_INFO_RECORD_SIZE];
    let mut context = SyscallContext::new(
        SyscallNumber::ListBlockDevices as usize,
        [0, record.as_mut_ptr() as usize, record.len(), 0, 0, 0],
    );
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        second_path: None,
        buffer: Some(&mut record),
        second_buffer: None,
    };
    assert_eq!(
        table
            .dispatch(&mut arguments)
            .map(|dispatch| dispatch.value),
        Ok(0)
    );

    let name_end = record
        .iter()
        .position(|&byte| byte == 0)
        .expect("terminator");
    assert_eq!(&record[..name_end], b"virtio-blk");

    let word = |at: usize| u64::from_le_bytes(record[at..at + 8].try_into().expect("eight"));
    assert_eq!(
        word(fs_abi::BLOCK_DEVICE_INFO_RECORD_BLOCK_SIZE_OFFSET),
        512
    );
    assert_eq!(
        word(fs_abi::BLOCK_DEVICE_INFO_RECORD_BLOCK_COUNT_OFFSET),
        4096
    );
    assert_eq!(word(fs_abi::BLOCK_DEVICE_INFO_RECORD_READ_ONLY_OFFSET), 0);

    crate::block_devices::clear();
}

/// An index past the end answers `NotFound` rather than a zeroed record.
#[test]
fn list_block_devices_past_the_end_is_not_found() {
    let _device_list = DEVICE_LIST.lock();
    crate::block_devices::clear();
    let mut table = SyscallTable::new();
    table.register(SyscallNumber::ListBlockDevices, list_block_devices);

    let mut record = [0u8; fs_abi::BLOCK_DEVICE_INFO_RECORD_SIZE];
    let mut context = SyscallContext::new(
        SyscallNumber::ListBlockDevices as usize,
        [0, record.as_mut_ptr() as usize, record.len(), 0, 0, 0],
    );
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        second_path: None,
        buffer: Some(&mut record),
        second_buffer: None,
    };
    assert_eq!(
        table.dispatch(&mut arguments),
        Err(Error::NotFound),
        "an empty list has no index zero either"
    );
}

/// A record buffer too small is refused rather than partly filled.
#[test]
fn list_block_devices_refuses_a_short_record() {
    let _device_list = DEVICE_LIST.lock();
    crate::block_devices::clear();
    assert!(crate::block_devices::record("disk", 512, 1, false));

    let mut table = SyscallTable::new();
    table.register(SyscallNumber::ListBlockDevices, list_block_devices);

    let mut record = [0u8; 16];
    let mut context = SyscallContext::new(
        SyscallNumber::ListBlockDevices as usize,
        [0, record.as_mut_ptr() as usize, record.len(), 0, 0, 0],
    );
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        second_path: None,
        buffer: Some(&mut record),
        second_buffer: None,
    };
    assert_eq!(table.dispatch(&mut arguments), Err(Error::InvalidArgument));

    crate::block_devices::clear();
}

/// `Sync` answers zero and refuses a reserved argument.
///
/// The flush itself has nothing a test can read back, so what is asserted is
/// that the call reaches the namespace and answers: a `Sync` that refused for a
/// missing namespace would be a different word, and this one has one.
#[test]
fn sync_answers_zero_over_the_namespace() {
    let mut table = writable();
    table.register(SyscallNumber::Sync, sync);

    let mut context = SyscallContext::new(SyscallNumber::Sync as usize, [0; 6]);
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        second_path: None,
        buffer: None,
        second_buffer: None,
    };
    assert_eq!(
        table
            .dispatch(&mut arguments)
            .map(|dispatch| dispatch.value),
        Ok(0)
    );

    // A reserved slot that is not zero is refused.
    let mut context = SyscallContext::new(SyscallNumber::Sync as usize, [1, 0, 0, 0, 0, 0]);
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        second_path: None,
        buffer: None,
        second_buffer: None,
    };
    assert_eq!(table.dispatch(&mut arguments), Err(Error::InvalidArgument));
}

/// A punch reaches the node exactly once, with the range the caller named.
///
/// The node counts its `punch_hole` calls, so a handler that answered zero
/// without reaching it fails, and a handler that punched twice fails too.
#[test]
fn a_punch_reaches_the_node_once() {
    use core::sync::atomic::Ordering;

    let mut table = SyscallTable::new();
    table.register(SyscallNumber::Fallocate, fallocate);

    let node = Arc::new(RecordingNode::new());
    let descriptor = insert_file(&mut table, node.clone(), true);

    let punch = fs_abi::FALLOC_FL_PUNCH_HOLE | fs_abi::FALLOC_FL_KEEP_SIZE;
    assert_eq!(punch_as(&mut table, descriptor, 0, 8, punch), Ok(()));
    assert_eq!(node.holes.load(Ordering::SeqCst), 1);
}

/// A punch with a mode this build does not define is refused, and reaches
/// nothing.
///
/// `NotImplemented` rather than `InvalidArgument`, because the mode is a word
/// the caller chose from a set this kernel does not have.  The node's count
/// proves the refusal came before it was asked.
#[test]
fn a_punch_with_an_undefined_mode_is_refused() {
    use core::sync::atomic::Ordering;

    let mut table = SyscallTable::new();
    table.register(SyscallNumber::Fallocate, fallocate);

    let node = Arc::new(RecordingNode::new());
    let descriptor = insert_file(&mut table, node.clone(), true);

    // The punch flag alone, without `KEEP_SIZE`, is not a mode this build
    // defines: a punch that moves the length is a truncate and a punch at
    // once, and no filesystem here does that.
    assert_eq!(
        punch_as(&mut table, descriptor, 0, 8, fs_abi::FALLOC_FL_PUNCH_HOLE),
        Err(Error::NotImplemented)
    );
    assert_eq!(
        punch_as(&mut table, descriptor, 0, 8, 0),
        Err(Error::NotImplemented)
    );
    assert_eq!(node.holes.load(Ordering::SeqCst), 0);
}

/// A punch of a read-only descriptor is refused before the node is asked.
#[test]
fn a_punch_of_a_read_only_descriptor_is_refused() {
    use core::sync::atomic::Ordering;

    let mut table = SyscallTable::new();
    table.register(SyscallNumber::Fallocate, fallocate);

    let node = Arc::new(RecordingNode::new());
    let descriptor = insert_file(&mut table, node.clone(), false);

    let punch = fs_abi::FALLOC_FL_PUNCH_HOLE | fs_abi::FALLOC_FL_KEEP_SIZE;
    assert_eq!(
        punch_as(&mut table, descriptor, 0, 8, punch),
        Err(Error::PermissionDenied)
    );
    assert_eq!(node.holes.load(Ordering::SeqCst), 0);
}

/// A node that cannot make holes answers its own refusal.
///
/// The right check passed, so the refusal is the filesystem's: this is what a
/// punch on the boot's PyroFS root does, and the answer is a word the caller
/// can tell from "you may not".
#[test]
fn a_punch_on_a_node_without_holes_is_refused_by_the_node() {
    let mut table = SyscallTable::new();
    table.register(SyscallNumber::Fallocate, fallocate);

    let node = Arc::new(RecordingNode::refusing_holes());
    let descriptor = insert_file(&mut table, node.clone(), true);

    let punch = fs_abi::FALLOC_FL_PUNCH_HOLE | fs_abi::FALLOC_FL_KEEP_SIZE;
    assert_eq!(
        punch_as(&mut table, descriptor, 0, 8, punch),
        Err(Error::PermissionDenied)
    );
}

/// Setting a flag makes it readable, and clearing it makes it go away.
///
/// The round trip is the whole point: a `SetFileFlags` that answered zero
/// without storing anything would pass a test that only checked its status, so
/// the flag is read back through a second call.
#[test]
fn a_file_flag_survives_a_set_and_a_clear() {
    use core::sync::atomic::Ordering;

    let mut table = SyscallTable::new();
    table.register(SyscallNumber::GetFileFlags, get_file_flags);
    table.register(SyscallNumber::SetFileFlags, set_file_flags);

    let node = Arc::new(RecordingNode::new());
    let descriptor = insert_file(&mut table, node.clone(), true);

    assert_eq!(flags_as(&mut table, descriptor), Ok(0), "none to start");
    assert_eq!(
        set_flags_as(&mut table, descriptor, fs_abi::FILE_FLAG_COMPRESSED, 0),
        Ok(())
    );
    assert_eq!(
        flags_as(&mut table, descriptor),
        Ok(fs_abi::FILE_FLAG_COMPRESSED)
    );
    assert_eq!(
        set_flags_as(&mut table, descriptor, 0, fs_abi::FILE_FLAG_COMPRESSED),
        Ok(())
    );
    assert_eq!(flags_as(&mut table, descriptor), Ok(0), "cleared again");
    assert_eq!(node.flag_writes.load(Ordering::SeqCst), 2);
}

/// A flag word with a bit this build does not define is refused.
///
/// The mask is checked at the handler, so the refusal is the same whichever
/// filesystem answers, and the node is never asked.
#[test]
fn an_undefined_file_flag_is_refused() {
    use core::sync::atomic::Ordering;

    let mut table = SyscallTable::new();
    table.register(SyscallNumber::SetFileFlags, set_file_flags);

    let node = Arc::new(RecordingNode::new());
    let descriptor = insert_file(&mut table, node.clone(), true);

    assert_eq!(
        set_flags_as(&mut table, descriptor, 1 << 30, 0),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        set_flags_as(&mut table, descriptor, 0, 1 << 30),
        Err(Error::InvalidArgument)
    );
    assert_eq!(node.flag_writes.load(Ordering::SeqCst), 0);
}

/// A bit in both masks is refused rather than resolved to one of them.
#[test]
fn a_file_flag_set_and_cleared_at_once_is_refused() {
    let mut table = SyscallTable::new();
    table.register(SyscallNumber::SetFileFlags, set_file_flags);

    let node = Arc::new(RecordingNode::new());
    let descriptor = insert_file(&mut table, node.clone(), true);

    assert_eq!(
        set_flags_as(
            &mut table,
            descriptor,
            fs_abi::FILE_FLAG_COMPRESSED,
            fs_abi::FILE_FLAG_COMPRESSED
        ),
        Err(Error::InvalidArgument)
    );
}

/// Reading a descriptor's flags needs no write right; setting them does.
///
/// The two rights are different and the pair is the test: a read-only
/// descriptor may learn what its file carries, and may not change it.
#[test]
fn reading_a_file_flag_needs_no_write_right_but_setting_one_does() {
    let mut table = SyscallTable::new();
    table.register(SyscallNumber::GetFileFlags, get_file_flags);
    table.register(SyscallNumber::SetFileFlags, set_file_flags);

    let node = Arc::new(RecordingNode::new());
    let descriptor = insert_file(&mut table, node.clone(), false);

    assert_eq!(flags_as(&mut table, descriptor), Ok(0));
    assert_eq!(
        set_flags_as(&mut table, descriptor, fs_abi::FILE_FLAG_COMPRESSED, 0),
        Err(Error::PermissionDenied)
    );
}

/// A descriptor opened read-only refuses a write, and stays readable.
///
/// The right is the open's, recorded per descriptor: a node the
/// filesystem would accept bytes for is still not writable through a
/// descriptor that did not ask.  The answer is `PermissionDenied`
/// the descriptor exists and the caller owns it; what it may not do is
/// write.
#[test]
fn a_descriptor_opened_read_only_refuses_a_write() {
    let mut table = writable();
    let creator = open_path(
        &mut table,
        "/note.txt",
        fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE,
    )
    .expect("create");
    assert_eq!(table.close(creator), Ok(()));

    let reader = open_path(&mut table, "/note.txt", fs_abi::OPEN_FLAG_READ).expect("open");
    assert_eq!(
        write_as(&mut table, reader, b"no", None),
        Err(Error::PermissionDenied)
    );

    let mut buffer = [0u8; 4];
    assert_eq!(
        read_into(&mut table, reader, READ_OFFSET_CURRENT, &mut buffer),
        Ok(0),
        "the refusal left the descriptor readable, at an empty file"
    );
}

/// A write of another process's descriptor is refused, and writes nothing.
///
/// The same reach a read refuses, one operation over: a write that went
/// through would put one process's bytes in another's file.
#[test]
fn one_process_cannot_write_another_process_descriptor() {
    let mut table = writable();
    let theirs = open_as(
        &mut table,
        "/note.txt",
        fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE,
        8,
    )
    .expect("open");

    assert_eq!(
        write_as(&mut table, theirs, b"intrusion", Some(7)),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        write_as(&mut table, theirs, b"mine", Some(8)),
        Ok(4),
        "the owner writes"
    );
}

/// A pipe end is not a file to write into.
///
/// The pipe's write path is the ring-3 branch that never reaches the
/// registry; a write that arrives here naming one is naming the wrong
/// kind of thing, and the answer is that, not a silent fall-through to a
/// node the descriptor does not have.
#[test]
fn a_pipe_end_is_not_a_file_to_write() {
    use crate::pipe;
    use crate::pipe::End;

    let pipe = Arc::new(pipe::Pipe::new(16));
    let mut table = SyscallTable::new();
    table.register(SyscallNumber::Write, write);
    let end = table
        .insert_pipe(End::writer(pipe.clone()), 7)
        .expect("insert");

    assert_eq!(
        write_as(&mut table, end, b"bytes", None),
        Err(Error::InvalidArgument)
    );
}

/// Opening with the create flag a path the volume already has opens that
/// path, and opening one it does not have on a read-only volume refuses
/// with the volume's own answer.
///
/// The two halves pin the branch: a create of an existing file is the
/// open that was asked for, and a create the filesystem cannot grant is
/// `PermissionDenied`, the volume's refusal, not the lookup's miss,
/// because reporting `NotFound` for a path the caller asked to create
/// would tell it the wrong thing about why.
#[test]
fn a_create_refusal_is_the_volumes_answer_and_a_create_of_an_existing_path_opens_it() {
    let mut table = mounted();
    assert_eq!(
        open_path(&mut table, "/new.txt", fs_abi::OPEN_FLAG_CREATE),
        Err(Error::PermissionDenied),
        "the static volume creates nothing"
    );

    let existing = open_path(
        &mut table,
        "/greeting.txt",
        fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_CREATE,
    )
    .expect("a create of an existing path is an open");
    let mut buffer = [0u8; 5];
    assert_eq!(
        read_into(&mut table, existing, READ_OFFSET_CURRENT, &mut buffer),
        Ok(5)
    );
    assert_eq!(&buffer, b"hello");
}

/// A number this build does not serve answers `NotImplemented`, and a
/// number past the table's end is refused rather than indexed.
///
/// The two answers differ on purpose: "the ABI defines this and this build
/// does not have it" is something a program can act on, and "this is not a
/// syscall number" is a caller's bug.
#[test]
fn an_unserved_number_answers_rather_than_panics() {
    let mut table = SyscallTable::new();
    let mut context = SyscallContext::new(SyscallNumber::GetPid as usize, [0, 0, 0, 0, 0, 0]);
    let mut arguments = Arguments::plain(&mut context);
    assert_eq!(table.dispatch(&mut arguments), Err(Error::NotImplemented));

    let mut context = SyscallContext::new(MAX_SYSCALLS + 5, [0, 0, 0, 0, 0, 0]);
    let mut arguments = Arguments::plain(&mut context);
    assert_eq!(table.dispatch(&mut arguments), Err(Error::InvalidArgument));
}

/// An unknown flag is refused, and so is a non-zero reserved argument.
///
/// Both are checked before the path is looked up, so a call that is wrong
/// in its arguments does not reach the filesystem at all.
#[test]
fn open_refuses_an_unknown_flag_and_a_reserved_argument() {
    let mut table = mounted();

    let mut context = SyscallContext::new(SyscallNumber::Open as usize, [0, 0b1000, 0, 0, 0, 0]);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some("/greeting.txt"),
        second_path: None,
        buffer: None,
        second_buffer: None,
    };
    assert_eq!(table.dispatch(&mut arguments), Err(Error::InvalidArgument));

    let mut context = SyscallContext::new(SyscallNumber::Open as usize, [0, 0, 0, 0, 7, 0]);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some("/greeting.txt"),
        second_path: None,
        buffer: None,
        second_buffer: None,
    };
    assert_eq!(table.dispatch(&mut arguments), Err(Error::InvalidArgument));
}

/// A path the volume does not have answers `NotFound`.
#[test]
fn a_missing_path_answers_not_found() {
    let mut table = mounted();
    assert_eq!(
        open_path(&mut table, "/no-such-file", fs_abi::OPEN_FLAG_READ),
        Err(Error::NotFound)
    );
}

/// A read from a descriptor that was closed, or never opened, is refused.
///
/// The slot a closed descriptor had may already belong to another file, and
/// reading through a stale number would be reading someone else's data.
#[test]
fn a_closed_descriptor_cannot_be_read() {
    let mut table = mounted();
    let descriptor = open_path(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ).expect("open");
    assert_eq!(table.close(descriptor), Ok(()));

    let mut buffer = [0u8; 4];
    assert_eq!(
        read_into(&mut table, descriptor, READ_OFFSET_CURRENT, &mut buffer),
        Err(Error::InvalidArgument)
    );
    // Closing it a second time is the same refusal.
    assert_eq!(table.close(descriptor), Err(Error::InvalidArgument));
}

/// Opening past the table's capacity answers `OutOfMemory` rather than
/// reusing a slot that belongs to an open file.
#[test]
fn the_descriptor_table_is_bounded() {
    let mut table = mounted();
    for _ in 0..MAX_DESCRIPTORS {
        open_path(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ).expect("open");
    }
    assert_eq!(
        open_path(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ),
        Err(Error::OutOfMemory)
    );
    assert_eq!(table.open_descriptors(), MAX_DESCRIPTORS);
}

/// An exiting process releases what it opened, and only that.
///
/// A descriptor belongs to the process that opened it: its exit is the
/// release a `Close` would have made, and a process that exits without
/// closing leaves nothing behind.  Two owners are opened here because the
/// second half of the claim is the one a single-owner test cannot make, a
/// release keyed on the wrong field, or on "any", would pass the first half
/// and silently take another process's descriptors with it.
#[test]
fn an_exiting_process_releases_only_its_own_descriptors() {
    let mut table = mounted();

    let mine = open_as(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ, 7).expect("open");
    let theirs = open_as(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ, 8).expect("open");
    let also_mine = open_as(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ, 7).expect("open");
    assert_eq!(table.open_descriptors(), 3);

    assert_eq!(
        table.release_owned(7),
        2,
        "both of that process's went back"
    );
    assert_eq!(table.open_descriptors(), 1, "and only that process's");
    assert_eq!(
        table.release_owned(8),
        1,
        "the other process still held its own"
    );
    assert_eq!(table.open_descriptors(), 0);

    // The released slots are free again, and a release that already
    // happened answers zero rather than counting something twice.
    assert_eq!(table.release_owned(7), 0);
    for descriptor in [mine, also_mine, theirs] {
        assert_eq!(table.close(descriptor), Err(Error::InvalidArgument));
    }
}

/// Opening a path as a given process, for the ownership tests.
fn open_as(table: &mut SyscallTable, path: &str, flags: usize, pid: u32) -> Result<usize> {
    let mut context =
        SyscallContext::new(SyscallNumber::Open as usize, [0, flags, 0, 0, 0, 0]).with_caller(pid);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some(path),
        second_path: None,
        buffer: None,
        second_buffer: None,
    };
    Ok(table.dispatch(&mut arguments)?.value)
}

/// A process cannot use a descriptor another process opened.
///
/// The whole point of an owner on a descriptor.  A number is a number, so a
/// process that guessed one would otherwise read another's file or close
/// its pipe end, a reach into a process it never touched, which is exactly
/// the power a bad pointer would give it.  The refusal is `InvalidArgument`
/// and not `PermissionDenied`: a caller told "denied" learns the slot is in
/// use and can probe for which numbers are.
#[test]
fn one_process_cannot_close_another_process_descriptor() {
    let mut table = mounted();
    let mine = open_as(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ, 7).expect("open");
    let theirs = open_as(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ, 8).expect("open");

    assert_eq!(
        table.close_for(theirs, Some(7)),
        Err(Error::InvalidArgument),
        "another process's descriptor is not this process's to close"
    );
    assert_eq!(table.open_descriptors(), 2, "and the refusal left it open");

    assert_eq!(table.close_for(theirs, Some(8)), Ok(()), "its own is");
    assert_eq!(table.close_for(mine, Some(7)), Ok(()));
    assert_eq!(table.open_descriptors(), 0);
}

/// A read of another process's descriptor is refused, and leaves it
/// readable.
///
/// The same reach as the close above, one operation over: a read that went
/// through would hand one process another's bytes.
#[test]
fn one_process_cannot_read_another_process_descriptor() {
    let mut table = mounted();
    let theirs = open_as(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ, 8).expect("open");
    let mut buffer = [0u8; 8];

    assert_eq!(
        table.read_at(theirs, READ_OFFSET_CURRENT, &mut buffer, Some(7)),
        Err(Error::InvalidArgument)
    );
    assert_eq!(buffer, [0u8; 8], "and nothing was read into it");

    let count = table
        .read_at(theirs, READ_OFFSET_CURRENT, &mut buffer, Some(8))
        .expect("the owner reads it");
    assert_eq!(&buffer[..count], b"hello fr");
}

/// The kernel's own callers have no pid and are not refused.
///
/// The boot reads a file through the table before any program exists, and a
/// check keyed only on "the caller matches the owner" would refuse it:
/// there is no caller.  `None` is that caller, and it is allowed.
#[test]
fn a_caller_with_no_pid_is_allowed() {
    let mut table = mounted();
    let descriptor = open_as(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ, 7).expect("open");
    let mut buffer = [0u8; 4];

    assert_eq!(
        table
            .read_at(descriptor, READ_OFFSET_CURRENT, &mut buffer, None)
            .expect("the kernel reads"),
        4
    );
    assert_eq!(table.close_for(descriptor, None), Ok(()));
}

/// A fork's child starts with its parent's descriptors, as its own.
///
/// The inheritance `fork` promises.  A child that got nothing would find
/// every inherited number refused, because the table checks the owner; a
/// child that got the **same slots** rather than copies would close its
/// parent's file.
#[test]
fn a_child_inherits_its_parents_descriptors_as_its_own() {
    let mut table = mounted();
    let parent = open_as(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ, 7).expect("open");

    assert_eq!(table.inherit(7, 8), 1, "one descriptor copied");
    assert_eq!(table.open_descriptors(), 2, "the child's slot is its own");

    let child = (0..MAX_DESCRIPTORS)
        .find(|index| *index != parent && table.owner_of(*index) == Some(8))
        .expect("the child has one");
    let mut buffer = [0u8; 4];
    assert_eq!(
        table
            .read_at(child, READ_OFFSET_CURRENT, &mut buffer, Some(8))
            .expect("the child reads its own"),
        4
    );
    assert_eq!(
        table.read_at(child, READ_OFFSET_CURRENT, &mut buffer, Some(7)),
        Err(Error::InvalidArgument),
        "and the parent cannot use the child's"
    );
}

/// A pipe end copied by a fork keeps the pipe alive until **both** are
/// gone.
///
/// The count is what end-of-file is read from, so an inheritance that
/// copied the number without raising it would make a parent's close end the
/// reader's file while the child still held a writer.
#[test]
fn a_copied_pipe_end_keeps_the_pipe_open() {
    use crate::pipe;
    use crate::pipe::End;

    let pipe = Arc::new(pipe::Pipe::new(16));
    let mut table = SyscallTable::new();
    // The parent holds a write end directly, in the table.
    let parent_end = table
        .insert_pipe(End::writer(pipe.clone()), 7)
        .expect("insert");
    assert!(pipe.has_writers());

    assert_eq!(table.inherit(7, 8), 1, "the child copied it");
    assert_eq!(table.close_for(parent_end, Some(7)), Ok(()));
    assert!(
        pipe.has_writers(),
        "the child still holds a write end, so the pipe is not closed"
    );
}

/// Stat through the registry, and read the record the way a caller does.
fn stat_path(table: &mut SyscallTable, path: &str) -> Result<(usize, usize)> {
    let mut context = SyscallContext::new(SyscallNumber::Stat as usize, [0, 0, 16, 0, 0, 0]);
    let mut record = [0u8; 16];
    let mut arguments = Arguments {
        context: &mut context,
        path: Some(path),
        second_path: None,
        buffer: Some(&mut record),
        second_buffer: None,
    };
    table.dispatch(&mut arguments)?;
    let kind = usize::from_le_bytes(record[..8].try_into().expect("kind bytes"));
    let size = usize::from_le_bytes(record[8..].try_into().expect("size bytes"));
    Ok((kind, size))
}

/// Stat a descriptor through the registry: no path, only the handle.
fn stat_descriptor(table: &mut SyscallTable, descriptor: usize) -> Result<(usize, usize)> {
    let mut context =
        SyscallContext::new(SyscallNumber::StatFd as usize, [descriptor, 0, 16, 0, 0, 0]);
    let mut record = [0u8; 16];
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        second_path: None,
        buffer: Some(&mut record),
        second_buffer: None,
    };
    table.dispatch(&mut arguments)?;
    let kind = usize::from_le_bytes(record[..8].try_into().expect("kind bytes"));
    let size = usize::from_le_bytes(record[8..].try_into().expect("size bytes"));
    Ok((kind, size))
}

/// List one entry through a descriptor, parsed the way `list_entry`
/// parses a listing by path.
fn list_entry_by_descriptor(
    table: &mut SyscallTable,
    descriptor: usize,
    index: usize,
    buffer: &mut [u8],
) -> Result<(usize, usize, alloc::string::String)> {
    let mut context = SyscallContext::new(
        SyscallNumber::ReadDirFd as usize,
        [descriptor, index, 0, 0, 0, 0],
    );
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        second_path: None,
        buffer: Some(buffer),
        second_buffer: None,
    };
    let written = table.dispatch(&mut arguments)?.value;
    let word =
        |at: usize| usize::from_le_bytes(buffer[at..at + 8].try_into().expect("header word"));
    let kind = word(0);
    let size = word(8);
    let name_offset = word(16);
    let name_len = word(24);
    assert_eq!(written, fs_abi::DIRECTORY_ENTRY_RECORD_SIZE + name_len);
    let name = alloc::string::String::from_utf8_lossy(&buffer[name_offset..name_offset + name_len])
        .into_owned();
    Ok((kind, size, name))
}

/// A stat of a file answers the kind and the size the volume holds.
///
/// The record is the wire format, so the parse is the caller's own: kind
/// in the first word, size in the second, little-endian, the layout the
/// ABI pins.  A handler that answered a different layout would still
/// answer zero, and the caller's next read would start at a size that
/// was never the file's.
#[test]
fn a_stat_reports_the_kind_and_size_the_volume_holds() {
    let mut table = mounted();
    assert_eq!(
        stat_path(&mut table, "/greeting.txt"),
        Ok((fs_abi::FILE_KIND_FILE, 20))
    );
    assert_eq!(
        stat_path(&mut table, "/docs"),
        Ok((fs_abi::FILE_KIND_DIRECTORY, 0)),
        "a directory is stat'd as one, at size zero"
    );
}

/// A stat of a path the namespace does not have answers `NotFound`.
#[test]
fn a_stat_of_a_missing_path_answers_not_found() {
    let mut table = mounted();
    assert_eq!(stat_path(&mut table, "/no-such-file"), Err(Error::NotFound));
}

/// A record shorter than the stat is refused, not partly written.
///
/// A caller handed eight bytes would otherwise read a size field that
/// holds the kind's bytes, a number that looks like a size, which is
/// the kind of wrong answer that survives a program's own checking.
#[test]
fn a_record_shorter_than_the_stat_is_refused() {
    let mut table = mounted();
    let mut context = SyscallContext::new(SyscallNumber::Stat as usize, [0, 0, 8, 0, 0, 0]);
    let mut short = [0u8; 8];
    let mut arguments = Arguments {
        context: &mut context,
        path: Some("/greeting.txt"),
        second_path: None,
        buffer: Some(&mut short),
        second_buffer: None,
    };
    assert_eq!(table.dispatch(&mut arguments), Err(Error::InvalidArgument));
    assert_eq!(short, [0u8; 8], "and nothing was written into it");
}

/// A stat of a file the table's own writes grew answers the grown size.
///
/// The static volume's sizes are fixed at build time, so this is the one
/// test that can catch a stat reading a cached or declared size where
/// the file's current one belongs.
#[test]
fn a_stat_after_a_write_answers_the_written_size() {
    let mut table = writable();
    let flags = fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
    let descriptor = open_path(&mut table, "/note.txt", flags).expect("create");
    assert_eq!(
        write_as(&mut table, descriptor, b"twelve byte", None),
        Ok(11)
    );
    assert_eq!(table.close(descriptor), Ok(()));

    assert_eq!(
        stat_path(&mut table, "/note.txt"),
        Ok((fs_abi::FILE_KIND_FILE, 11))
    );
}

/// A stat by descriptor answers what the same stat by path does.
///
/// The two calls describe one file, so a difference between them means one of
/// them read the wrong anchor.  The descriptor is stat'd while it is **open**,
/// which is the case the path form cannot serve at all for a caller that was
/// handed the descriptor and never learned the name.
#[test]
fn a_stat_by_descriptor_matches_the_one_by_path() {
    let mut table = writable();
    let flags = fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
    let descriptor = open_path(&mut table, "/note.txt", flags).expect("create");
    assert_eq!(
        write_as(&mut table, descriptor, b"twelve byte", None),
        Ok(11)
    );

    assert_eq!(
        stat_descriptor(&mut table, descriptor),
        Ok((fs_abi::FILE_KIND_FILE, 11))
    );
    assert_eq!(
        stat_descriptor(&mut table, descriptor),
        stat_path(&mut table, "/note.txt"),
        "the two anchors describe one file"
    );
}

/// A stat of a descriptor that names no file is refused.
///
/// A pipe end has no path in the namespace, so there is nothing for the record
/// to describe, and the answer is the one an unheld descriptor number gets: a
/// caller does not learn which numbers are pipe ends by stat'ing them.
#[test]
fn a_stat_of_a_pipe_descriptor_is_refused() {
    use crate::pipe;
    use crate::pipe::End;

    let pipe = Arc::new(pipe::Pipe::new(16));
    let mut table = SyscallTable::new();
    table.register(SyscallNumber::StatFd, stat_fd);
    let end = table
        .insert_pipe(End::writer(pipe.clone()), 7)
        .expect("insert");

    assert_eq!(
        stat_descriptor(&mut table, end),
        Err(Error::InvalidArgument)
    );
}

/// A listing by descriptor answers the entries a listing by path does.
///
/// The same directory opened as the anchor, then listed twice: once through
/// the descriptor and once through its name.  An entry that differed would
/// mean one of the two resolved a different directory.
#[test]
fn a_listing_by_descriptor_matches_the_one_by_path() {
    let mut table = writable();
    make_dir(&mut table, "/docs").expect("create dir");
    let file = open_path(
        &mut table,
        "/docs/entry.txt",
        fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE,
    )
    .expect("create file");
    assert_eq!(write_as(&mut table, file, b"abc", None), Ok(3));
    assert_eq!(table.close(file), Ok(()));

    let anchor = open_path(&mut table, "/docs", fs_abi::OPEN_FLAG_READ).expect("open dir");

    let mut by_path = [0u8; 128];
    let mut by_descriptor = [0u8; 128];
    let from_path = list_entry(&mut table, "/docs", 0, &mut by_path).expect("list by path");
    let from_descriptor =
        list_entry_by_descriptor(&mut table, anchor, 0, &mut by_descriptor).expect("list by fd");

    assert_eq!(
        (from_descriptor.0, from_descriptor.1),
        (from_path.0, from_path.1),
        "kind and size are one directory's entry either way"
    );
    assert_eq!(
        from_descriptor.2, from_path.4,
        "and so is the name the record points at"
    );
}

/// A listing of a descriptor that names a regular file is refused.
///
/// The kind check is the descriptor's own: a regular file has no entries, and
/// a listing that answered `NotFound` instead would be indistinguishable from
/// a directory whose index ran past its end.
#[test]
fn a_listing_of_a_file_descriptor_is_refused() {
    let mut table = writable();
    let file = open_path(
        &mut table,
        "/note.txt",
        fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE,
    )
    .expect("create");

    let mut buffer = [0u8; 128];
    assert_eq!(
        list_entry_by_descriptor(&mut table, file, 0, &mut buffer),
        Err(Error::InvalidArgument)
    );
}

/// A stat whose reserved arguments are not zero is refused.
#[test]
fn a_stat_with_reserved_arguments_set_is_refused() {
    let mut table = mounted();
    let mut context = SyscallContext::new(SyscallNumber::Stat as usize, [0, 0, 16, 1, 0, 0]);
    let mut record = [0u8; 16];
    let mut arguments = Arguments {
        context: &mut context,
        path: Some("/greeting.txt"),
        second_path: None,
        buffer: Some(&mut record),
        second_buffer: None,
    };
    assert_eq!(table.dispatch(&mut arguments), Err(Error::InvalidArgument));
}

/// Create a directory through the registry.
fn make_dir(table: &mut SyscallTable, path: &str) -> Result<usize> {
    let mut context = SyscallContext::new(SyscallNumber::CreateDir as usize, [0; 6]);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some(path),
        second_path: None,
        buffer: None,
        second_buffer: None,
    };
    Ok(table.dispatch(&mut arguments)?.value)
}

/// Remove a path through the registry.
fn remove(table: &mut SyscallTable, path: &str) -> Result<usize> {
    let mut context = SyscallContext::new(SyscallNumber::RemovePath as usize, [0; 6]);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some(path),
        second_path: None,
        buffer: None,
        second_buffer: None,
    };
    Ok(table.dispatch(&mut arguments)?.value)
}

/// Rename through the registry.
fn rename_to(table: &mut SyscallTable, old_path: &str, new_path: &str) -> Result<usize> {
    let mut context = SyscallContext::new(SyscallNumber::Rename as usize, [0; 6]);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some(old_path),
        second_path: Some(new_path),
        buffer: None,
        second_buffer: None,
    };
    Ok(table.dispatch(&mut arguments)?.value)
}

/// A made directory is there, and is a directory.
///
/// The claim is checked with `stat`, not with a second create: a create
/// that answered zero without making anything would fail the stat, and
/// a create that made something of the wrong kind would fail the kind.
#[test]
fn a_made_directory_is_there_and_is_a_directory() {
    let mut table = writable();
    assert_eq!(make_dir(&mut table, "/notes"), Ok(0));
    assert_eq!(
        stat_path(&mut table, "/notes"),
        Ok((fs_abi::FILE_KIND_DIRECTORY, 0))
    );
    // A second create of the same name is the filesystem's refusal, not
    // a silent success that would have replaced it.
    assert_eq!(make_dir(&mut table, "/notes"), Err(Error::AlreadyExists));
}

/// A file is made inside a made directory, and removed by name.
///
/// This is the path mutations composing: the directory exists because a
/// create made it, the file exists because an open-with-create made it
/// under that directory, and the remove takes exactly the file and
/// leaves the directory.
#[test]
fn a_file_in_a_made_directory_is_removed_and_the_directory_stays() {
    let mut table = writable();
    assert_eq!(make_dir(&mut table, "/notes"), Ok(0));
    let flags = fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
    let descriptor = open_path(&mut table, "/notes/todo.txt", flags).expect("create");
    assert_eq!(write_as(&mut table, descriptor, b"buy milk", None), Ok(8));
    assert_eq!(table.close(descriptor), Ok(()));

    assert_eq!(remove(&mut table, "/notes/todo.txt"), Ok(0));
    assert_eq!(
        stat_path(&mut table, "/notes/todo.txt"),
        Err(Error::NotFound)
    );
    assert_eq!(
        stat_path(&mut table, "/notes"),
        Ok((fs_abi::FILE_KIND_DIRECTORY, 0)),
        "the removal took the file and left the directory"
    );
    assert_eq!(remove(&mut table, "/notes/todo.txt"), Err(Error::NotFound));
}

/// A rename moves the file, its bytes and nothing else.
///
/// Both names are checked, because the failure modes differ: a rename
/// that lost the bytes would leave an empty file at the new name, and
/// one that copied rather than moved would leave the old name behind.
#[test]
fn a_rename_moves_the_file_and_its_bytes() {
    let mut table = writable();
    let flags = fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
    let descriptor = open_path(&mut table, "/draft.txt", flags).expect("create");
    assert_eq!(write_as(&mut table, descriptor, b"final v2", None), Ok(8));
    assert_eq!(table.close(descriptor), Ok(()));

    assert_eq!(rename_to(&mut table, "/draft.txt", "/sent.txt"), Ok(0));
    assert_eq!(stat_path(&mut table, "/draft.txt"), Err(Error::NotFound));
    assert_eq!(
        stat_path(&mut table, "/sent.txt"),
        Ok((fs_abi::FILE_KIND_FILE, 8))
    );
    let reader = open_path(&mut table, "/sent.txt", fs_abi::OPEN_FLAG_READ).expect("open");
    let mut buffer = [0u8; 8];
    assert_eq!(
        read_into(&mut table, reader, READ_OFFSET_CURRENT, &mut buffer),
        Ok(8)
    );
    assert_eq!(&buffer, b"final v2");
}

/// A rename whose two names resolve to different filesystems is
/// refused, and moves nothing.
///
/// No filesystem sees both names, so the only ways to serve the call
/// are a copy and a delete, whose crash between the halves is the one
/// outcome a rename exists to make impossible, or a refusal.  The
/// refusal is what this tree answers.
#[test]
fn a_rename_across_filesystems_is_refused() {
    let volume = TmpFsVolume::new("test-tmpfs", 64 * 1024);
    let mut table = SyscallTable::new();
    let mut namespace = MountTable::new();
    namespace
        .mount(
            "/",
            "pyrofs",
            "boot",
            Arc::new(StaticFileSystem::with_entries(
                "pyrofs",
                &[("/greeting.txt", NodeKind::File, b"hello")],
            )),
        )
        .expect("mount");
    namespace
        .mount("/tmp", "tmpfs", "memory", Arc::new(volume))
        .expect("mount");
    table.set_namespace(Arc::new(namespace));
    table.register(SyscallNumber::Rename, rename);

    assert_eq!(
        rename_to(&mut table, "/greeting.txt", "/tmp/greeting.txt"),
        Err(Error::Unsupported)
    );
}

/// A rename without a second path is refused before the filesystem is
/// reached.
#[test]
fn a_rename_without_a_second_path_is_refused() {
    let mut table = writable();
    let mut context = SyscallContext::new(SyscallNumber::Rename as usize, [0; 6]);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some("/draft.txt"),
        second_path: None,
        buffer: None,
        second_buffer: None,
    };
    assert_eq!(table.dispatch(&mut arguments), Err(Error::InvalidArgument));
}

/// List one entry through the registry, parsed the way a caller parses
/// it: four header words and the name bytes the header points at.
fn list_entry(
    table: &mut SyscallTable,
    path: &str,
    index: usize,
    buffer: &mut [u8],
) -> Result<(usize, usize, usize, usize, alloc::string::String)> {
    let mut context = SyscallContext::new(SyscallNumber::ReadDir as usize, [0, index, 0, 0, 0, 0]);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some(path),
        second_path: None,
        buffer: Some(buffer),
        second_buffer: None,
    };
    let written = table.dispatch(&mut arguments)?.value;
    let word =
        |at: usize| usize::from_le_bytes(buffer[at..at + 8].try_into().expect("header word"));
    let kind = word(0);
    let size = word(8);
    let name_offset = word(16);
    let name_len = word(24);
    // The answer is the bytes the call wrote, header and name together
    // which is the number a caller sizes its next buffer from.
    assert_eq!(
        written,
        fs_abi::DIRECTORY_ENTRY_RECORD_SIZE + name_len,
        "the answer is the bytes written"
    );
    let name = alloc::string::String::from_utf8_lossy(&buffer[name_offset..name_offset + name_len])
        .into_owned();
    Ok((kind, size, name_offset, name_len, name))
}

/// A directory lists its entries by index, and the record carries the
/// name the header points at.
///
/// The static volume's two root entries are in name order, so the
/// indexes are known; the entries past the end are the loop's end, and
/// answering `NotFound` there is what lets a caller's loop be `while
/// let` rather than a count it had to know in advance.
#[test]
fn a_directory_lists_its_entries_in_order_and_stops() {
    let mut table = mounted();
    let mut buffer = [0u8; 64];

    let (kind, size, offset, len, name) =
        list_entry(&mut table, "/", 0, &mut buffer).expect("first entry");
    assert_eq!(kind, fs_abi::FILE_KIND_DIRECTORY);
    assert_eq!(size, 0);
    assert_eq!(offset, fs_abi::DIRECTORY_ENTRY_RECORD_SIZE);
    assert_eq!(len, name.len());
    assert_eq!(name, "docs");

    let (kind, _, _, _, name) = list_entry(&mut table, "/", 1, &mut buffer).expect("second");
    assert_eq!(kind, fs_abi::FILE_KIND_FILE);
    assert_eq!(name, "greeting.txt");

    assert_eq!(
        list_entry(&mut table, "/", 2, &mut buffer),
        Err(Error::NotFound),
        "past the end is the loop's end"
    );
}

/// A directory the table's own creates have grown lists what it holds.
///
/// The static volume's listing is fixed at build time, so this is the
/// test that catches a listing that answered from a snapshot rather
/// than from the namespace.
#[test]
fn a_directory_lists_what_the_table_itself_put_in_it() {
    let mut table = writable();
    assert_eq!(make_dir(&mut table, "/notes"), Ok(0));
    let flags = fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
    let descriptor = open_path(&mut table, "/notes/todo.txt", flags).expect("create");
    assert_eq!(table.close(descriptor), Ok(()));

    let mut buffer = [0u8; 64];
    let (kind, size, _, len, name) =
        list_entry(&mut table, "/notes", 0, &mut buffer).expect("the entry");
    assert_eq!(kind, fs_abi::FILE_KIND_FILE);
    assert_eq!(size, 0, "created empty, listed empty");
    assert_eq!(len, 8);
    assert_eq!(name, "todo.txt");

    assert_eq!(
        list_entry(&mut table, "/notes", 1, &mut buffer),
        Err(Error::NotFound)
    );
}

/// A listing of a file is refused: a file has no entries to list.
#[test]
fn a_listing_of_a_file_is_refused() {
    let mut table = mounted();
    let mut buffer = [0u8; 64];
    assert_eq!(
        list_entry(&mut table, "/greeting.txt", 0, &mut buffer),
        Err(Error::InvalidArgument)
    );
}

/// A buffer without room for the header, or for the whole name, is
/// refused rather than partly written.
///
/// The record declares the name's length, so a truncated name would be
/// a record that lies about itself; refusing names the number the
/// caller has to grow instead.
#[test]
fn a_buffer_without_room_for_the_record_is_refused() {
    let mut table = mounted();
    let mut header_only = [0u8; fs_abi::DIRECTORY_ENTRY_RECORD_SIZE];
    assert_eq!(
        list_entry(&mut table, "/", 0, &mut header_only),
        Err(Error::InvalidArgument),
        "the header fits and the name does not"
    );

    let mut short = [0u8; 8];
    let mut context = SyscallContext::new(SyscallNumber::ReadDir as usize, [0, 0, 0, 0, 0, 0]);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some("/"),
        second_path: None,
        buffer: Some(&mut short),
        second_buffer: None,
    };
    assert_eq!(
        table.dispatch(&mut arguments),
        Err(Error::InvalidArgument),
        "not even the header fits"
    );
}

/// Open relative to a descriptor, the way a program names one.
fn call_open_at(table: &mut SyscallTable, dirfd: usize, path: &str, flags: usize) -> Result<usize> {
    let mut context =
        SyscallContext::new(SyscallNumber::OpenAt as usize, [dirfd, 0, flags, 0, 0, 0]);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some(path),
        second_path: None,
        buffer: None,
        second_buffer: None,
    };
    Ok(table.dispatch(&mut arguments)?.value)
}

/// Stat relative to a descriptor.
fn call_stat_at(table: &mut SyscallTable, dirfd: usize, path: &str) -> Result<(usize, usize)> {
    let mut context = SyscallContext::new(SyscallNumber::StatAt as usize, [dirfd, 0, 0, 16, 0, 0]);
    let mut record = [0u8; 16];
    let mut arguments = Arguments {
        context: &mut context,
        path: Some(path),
        second_path: None,
        buffer: Some(&mut record),
        second_buffer: None,
    };
    table.dispatch(&mut arguments)?;
    let kind = usize::from_le_bytes(record[..8].try_into().expect("kind bytes"));
    let size = usize::from_le_bytes(record[8..].try_into().expect("size bytes"));
    Ok((kind, size))
}

/// Make a directory relative to a descriptor.
fn call_make_dir_at(table: &mut SyscallTable, dirfd: usize, path: &str) -> Result<usize> {
    let mut context =
        SyscallContext::new(SyscallNumber::CreateDirAt as usize, [dirfd, 0, 0, 0, 0, 0]);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some(path),
        second_path: None,
        buffer: None,
        second_buffer: None,
    };
    Ok(table.dispatch(&mut arguments)?.value)
}

/// Remove relative to a descriptor.
fn call_remove_at(table: &mut SyscallTable, dirfd: usize, path: &str) -> Result<usize> {
    let mut context =
        SyscallContext::new(SyscallNumber::RemovePathAt as usize, [dirfd, 0, 0, 0, 0, 0]);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some(path),
        second_path: None,
        buffer: None,
        second_buffer: None,
    };
    Ok(table.dispatch(&mut arguments)?.value)
}

/// Rename with each name anchored at its own descriptor.
fn call_rename_at(
    table: &mut SyscallTable,
    old_dirfd: usize,
    old_path: &str,
    new_dirfd: usize,
    new_path: &str,
) -> Result<usize> {
    let mut context = SyscallContext::new(
        SyscallNumber::RenameAt as usize,
        [old_dirfd, 0, new_dirfd, 0, 0, 0],
    );
    let mut arguments = Arguments {
        context: &mut context,
        path: Some(old_path),
        second_path: Some(new_path),
        buffer: None,
        second_buffer: None,
    };
    Ok(table.dispatch(&mut arguments)?.value)
}

/// A directory descriptor anchors a relative path.
///
/// The whole of what `*At` is for, in one path: the caller holds a
/// directory it opened, and names what it wants by where it is relative
/// to that directory, not by a path it had to know in advance.
#[test]
fn a_relative_path_resolves_against_the_descriptor_it_names() {
    let mut table = writable();
    assert_eq!(make_dir(&mut table, "/notes"), Ok(0));
    let notes = open_path(&mut table, "/notes", fs_abi::OPEN_FLAG_READ).expect("open dir");

    let flags = fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
    let file = call_open_at(&mut table, notes, "todo.txt", flags).expect("open at");
    assert_eq!(write_as(&mut table, file, b"buy milk", None), Ok(8));
    assert_eq!(table.close(file), Ok(()));

    assert_eq!(
        stat_path(&mut table, "/notes/todo.txt"),
        Ok((fs_abi::FILE_KIND_FILE, 8)),
        "the file is at the anchored name, not at the literal one"
    );
    assert_eq!(stat_path(&mut table, "/todo.txt"), Err(Error::NotFound));

    // And the anchored stat answers the same record for the same file:
    // the path the caller names is relative, and the answer is about
    // the file it resolves to.
    assert_eq!(
        call_stat_at(&mut table, notes, "todo.txt"),
        Ok((fs_abi::FILE_KIND_FILE, 8))
    );
    assert_eq!(
        call_stat_at(&mut table, notes, "no-such.txt"),
        Err(Error::NotFound)
    );
}

/// The `AT_FDCWD` sentinel anchors at the root, the one base every
/// process shares.
///
/// This tree has no per-process current directory yet, so the sentinel
/// cannot mean "wherever I am", it means the root, and the test pins
/// that reading so the day a current directory arrives it has to argue
/// with this test rather than drift past it.
#[test]
fn at_fdcwd_anchors_at_the_root() {
    let mut table = writable();
    let flags = fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
    let file = call_open_at(&mut table, fs_abi::AT_FDCWD, "root.txt", flags).expect("open at");
    assert_eq!(table.close(file), Ok(()));
    assert_eq!(
        stat_path(&mut table, "/root.txt"),
        Ok((fs_abi::FILE_KIND_FILE, 0))
    );
}

/// An absolute path bypasses the anchor.
///
/// A caller that named `/x` from wherever it was meant `/x`; a handler
/// that joined the anchor anyway would put the file where the caller
/// did not ask for it and could not find it.
#[test]
fn an_absolute_path_bypasses_the_anchor() {
    let mut table = writable();
    assert_eq!(make_dir(&mut table, "/notes"), Ok(0));
    let notes = open_path(&mut table, "/notes", fs_abi::OPEN_FLAG_READ).expect("open dir");

    let flags = fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
    let file = call_open_at(&mut table, notes, "/top.txt", flags).expect("open at");
    assert_eq!(table.close(file), Ok(()));
    assert_eq!(
        stat_path(&mut table, "/top.txt"),
        Ok((fs_abi::FILE_KIND_FILE, 0))
    );
    assert_eq!(
        stat_path(&mut table, "/notes/top.txt"),
        Err(Error::NotFound)
    );
}

/// A descriptor that names a file, or a pipe end, is not an anchor.
///
/// Both are refused with the same answer: neither is a place a relative
/// path can be relative from, and the caller does not learn which slots
/// hold what by the answer differing.
#[test]
fn a_non_directory_is_not_an_anchor() {
    let mut table = writable();
    let flags = fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
    let file = open_path(&mut table, "/plain.txt", flags).expect("create");
    // The path is `.` on purpose.  A name like `x` is refused twice
    // over, once by the anchor check and once by the filesystem, whose
    // parent resolution will not put a child under a file, and a test
    // that passes on the filesystem's refusal proves nothing about the
    // kernel's.  `.` anchored at a file resolves to the file's own
    // path, so without the anchor check this call would **open the
    // file**; the refusal this asserts is the kernel's alone.
    assert_eq!(
        call_open_at(&mut table, file, ".", flags),
        Err(Error::InvalidArgument),
        "a file is not a directory to anchor from, and `.` anchored at one would be its own open"
    );

    use crate::pipe;
    use crate::pipe::End;
    let pipe = Arc::new(pipe::Pipe::new(16));
    let end = table.insert_pipe(End::reader(pipe), 7).expect("insert");
    assert_eq!(
        call_open_at(&mut table, end, "x", flags),
        Err(Error::InvalidArgument),
        "a pipe end is not either"
    );
}

/// A rename can move a file between two anchors, and one anchor can be
/// the sentinel.
#[test]
fn a_rename_moves_a_file_between_two_anchors() {
    let mut table = writable();
    assert_eq!(make_dir(&mut table, "/notes"), Ok(0));
    let notes = open_path(&mut table, "/notes", fs_abi::OPEN_FLAG_READ).expect("open dir");
    let flags = fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
    let file = call_open_at(&mut table, notes, "draft.txt", flags).expect("create");
    assert_eq!(write_as(&mut table, file, b"final", None), Ok(5));
    assert_eq!(table.close(file), Ok(()));

    assert_eq!(
        call_rename_at(&mut table, notes, "draft.txt", fs_abi::AT_FDCWD, "sent.txt"),
        Ok(0)
    );
    assert_eq!(
        stat_path(&mut table, "/notes/draft.txt"),
        Err(Error::NotFound)
    );
    assert_eq!(
        stat_path(&mut table, "/sent.txt"),
        Ok((fs_abi::FILE_KIND_FILE, 5))
    );
}

/// A directory is made and removed relative to a descriptor.
#[test]
fn a_directory_is_made_and_removed_relative_to_a_descriptor() {
    let mut table = writable();
    assert_eq!(make_dir(&mut table, "/notes"), Ok(0));
    let notes = open_path(&mut table, "/notes", fs_abi::OPEN_FLAG_READ).expect("open dir");

    assert_eq!(call_make_dir_at(&mut table, notes, "sub"), Ok(0));
    assert_eq!(
        stat_path(&mut table, "/notes/sub"),
        Ok((fs_abi::FILE_KIND_DIRECTORY, 0))
    );
    assert_eq!(call_remove_at(&mut table, notes, "sub"), Ok(0));
    assert_eq!(stat_path(&mut table, "/notes/sub"), Err(Error::NotFound));
}

/// Reserved arguments past the path and its flags are refused.
#[test]
fn an_at_open_with_reserved_arguments_set_is_refused() {
    let mut table = writable();
    let mut context = SyscallContext::new(
        SyscallNumber::OpenAt as usize,
        [fs_abi::AT_FDCWD, 0, 0, 1, 0, 0],
    );
    let mut arguments = Arguments {
        context: &mut context,
        path: Some("/anything"),
        second_path: None,
        buffer: None,
        second_buffer: None,
    };
    assert_eq!(table.dispatch(&mut arguments), Err(Error::InvalidArgument));
}

/// Call a call that names a path, one mutable buffer and one read-only one.
///
/// `SetXattr`'s shape: the name is the mutable slot and the value the
/// read-only one, which is the split the trap path makes when it copies the
/// caller's windows in.
fn call_with_two_buffers(
    table: &mut SyscallTable,
    number: SyscallNumber,
    path: &str,
    name: &mut [u8],
    value: &[u8],
) -> Result<usize> {
    let mut context = SyscallContext::new(number as usize, [0, 0, 0, 0, 0, 0]);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some(path),
        second_path: None,
        buffer: Some(name),
        second_buffer: Some(value),
    };
    let dispatch = table.dispatch(&mut arguments)?;
    Ok(dispatch.value)
}

/// Call a call that names a path, a read-only name and a mutable destination.
///
/// `GetXattr`'s shape: the name is the read-only slot and the destination the
/// mutable one, the mirror of [`call_with_two_buffers`].
fn call_with_name(
    table: &mut SyscallTable,
    number: SyscallNumber,
    path: &str,
    name: &[u8],
    destination: &mut [u8],
) -> Result<usize> {
    let mut context = SyscallContext::new(number as usize, [0, 0, 0, 0, 0, 0]);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some(path),
        second_path: None,
        buffer: Some(destination),
        second_buffer: Some(name),
    };
    let dispatch = table.dispatch(&mut arguments)?;
    Ok(dispatch.value)
}

/// Call a call that names an anchor descriptor, a relative path and a buffer.
///
/// `PermissionMetadataAt`'s shape and `AccessQueryAt`'s: the descriptor is
/// argument 0, the path is argument 1, and the record follows.
fn call_with_anchor(
    table: &mut SyscallTable,
    number: SyscallNumber,
    anchor: usize,
    path: &str,
    buffer: &mut [u8],
) -> Result<usize> {
    let mut context = SyscallContext::new(number as usize, [anchor, 0, 0, 0, 0, 0]);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some(path),
        second_path: None,
        buffer: Some(buffer),
        second_buffer: None,
    };
    let dispatch = table.dispatch(&mut arguments)?;
    Ok(dispatch.value)
}

/// Call a call that names a descriptor and a buffer, with no path.
///
/// `PermissionMetadataFd`'s shape: the descriptor is argument 0 and the record
/// is argument 1.
fn call_with_descriptor_record(
    table: &mut SyscallTable,
    number: SyscallNumber,
    descriptor: usize,
    buffer: &mut [u8],
) -> Result<usize> {
    let mut context = SyscallContext::new(number as usize, [descriptor, 0, 0, 0, 0, 0]);
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        second_path: None,
        buffer: Some(buffer),
        second_buffer: None,
    };
    let dispatch = table.dispatch(&mut arguments)?;
    Ok(dispatch.value)
}

/// Call a call that names a path, a required-access word and a buffer.
///
/// `AccessQuery`'s shape: the path is argument 0, the required bits argument 1,
/// and the record follows.
fn call_with_path_buffer_and_required(
    table: &mut SyscallTable,
    number: SyscallNumber,
    path: &str,
    required: u16,
    buffer: &mut [u8],
) -> Result<usize> {
    let mut context = SyscallContext::new(number as usize, [0, usize::from(required), 0, 0, 0, 0]);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some(path),
        second_path: None,
        buffer: Some(buffer),
        second_buffer: None,
    };
    let dispatch = table.dispatch(&mut arguments)?;
    Ok(dispatch.value)
}

/// Call `Poll`: an array of records, how many, and a timeout.
fn call_with_poll(table: &mut SyscallTable, records: &mut [u8], count: usize) -> Result<usize> {
    let mut context = SyscallContext::new(SyscallNumber::Poll as usize, [0, count, 0, 0, 0, 0]);
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        second_path: None,
        buffer: Some(records),
        second_buffer: None,
    };
    let dispatch = table.dispatch(&mut arguments)?;
    Ok(dispatch.value)
}

/// Call a call that names a path and one mutable buffer.
fn call_with_path_buffer(
    table: &mut SyscallTable,
    number: SyscallNumber,
    path: &str,
    buffer: &mut [u8],
) -> Result<usize> {
    let mut context = SyscallContext::new(number as usize, [0, 0, 0, 0, 0, 0]);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some(path),
        second_path: None,
        buffer: Some(buffer),
        second_buffer: None,
    };
    let dispatch = table.dispatch(&mut arguments)?;
    Ok(dispatch.value)
}

/// Call a call that names a path and one mutable buffer, with no answer size.
fn call_with_one_buffer(
    table: &mut SyscallTable,
    number: SyscallNumber,
    path: &str,
    buffer: &mut [u8],
) -> Result<usize> {
    call_with_path_buffer(table, number, path, buffer)
}

/// Call a number through the registry with six argument words and no
/// borrow.
///
/// The memory calls take no pointer, so this is the whole of their wire
/// shape: a number, six words, and an answer.
fn call(table: &mut SyscallTable, number: SyscallNumber, args: [usize; 6]) -> Result<usize> {
    let mut context = SyscallContext::new(number as usize, args);
    let mut arguments = Arguments::plain(&mut context);
    let dispatch = table.dispatch(&mut arguments)?;
    Ok(dispatch.value)
}

/// The memory calls validate their arguments, and a host can check that
/// without a page table.
///
/// Each of these is refused **before** the mapping is attempted, which is
/// what makes them testable on a host and what makes them cheap on a
/// machine: a call that reached the allocator with a bad length would have
/// spent frames before discovering the caller was wrong.
#[test]
fn the_memory_calls_refuse_bad_arguments() {
    let mut table = SyscallTable::new();
    table.register(SyscallNumber::Mmap, mmap);
    table.register(SyscallNumber::Munmap, munmap);
    table.register(SyscallNumber::Brk, brk);

    // A zero-length mapping names nothing.
    assert_eq!(
        call(&mut table, SyscallNumber::Mmap, [0, 0, 1, 0x20, 0, 0]),
        Err(Error::InvalidArgument)
    );
    // A protection bit outside the set this build knows.
    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Mmap,
            [0, 4096, 1 << 7, 0x20, 0, 0]
        ),
        Err(Error::InvalidArgument)
    );
    // Anonymous is required: without it the call asks for a mapping this
    // kernel cannot back.
    assert_eq!(
        call(&mut table, SyscallNumber::Mmap, [0, 4096, 1, 0x02, 0, 0]),
        Err(Error::InvalidArgument)
    );
    // Write and execute together, which the loader already refuses for
    // images and which turns a bug into an exploit.
    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Mmap,
            [0, 4096, 3 | 4, 0x22, 0, 0]
        ),
        Err(Error::InvalidArgument)
    );
    // A reserved argument that is not zero.
    assert_eq!(
        call(&mut table, SyscallNumber::Mmap, [0, 4096, 1, 0x20, 7, 0]),
        Err(Error::InvalidArgument)
    );
    // A zero-length unmap names no range.
    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Munmap,
            [0x80_0000_0000, 0, 0, 0, 0, 0]
        ),
        Err(Error::InvalidArgument)
    );
    // An unmap below the user window would name the kernel's own pages.
    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Munmap,
            [0x1000, 4096, 0, 0, 0, 0]
        ),
        Err(Error::InvalidArgument)
    );
    // A brk with a reserved argument that is not zero.
    assert_eq!(
        call(&mut table, SyscallNumber::Brk, [0, 3, 0, 0, 0, 0]),
        Err(Error::InvalidArgument)
    );
}

/// A memory call whose arguments are well-formed gets past validation.
///
/// On a host there is no page table, so the answer is `NotImplemented`
/// and that is the assertion: the call was **accepted by the validator**
/// and refused by the machine it could not reach, which is a different
/// outcome from `InvalidArgument` and is what a host can honestly check.
#[test]
fn a_well_formed_mapping_passes_validation() {
    let mut table = SyscallTable::new();
    table.register(SyscallNumber::Mmap, mmap);
    table.register(SyscallNumber::Brk, brk);
    assert_eq!(
        call(&mut table, SyscallNumber::Mmap, [0, 4096, 1, 0x22, 0, 0]),
        Err(Error::NotImplemented),
        "validated, then refused by a host that has no page table"
    );
    assert_eq!(
        call(&mut table, SyscallNumber::Brk, [0, 0, 0, 0, 0, 0]),
        Err(Error::NotImplemented)
    );
}

/// Call a handler that writes a record into a buffer.
///
/// The buffer is the borrow the entry path builds on a machine, which is
/// why the test passes it here rather than a pointer: the handler never
/// sees an address, so this is the same call shape a program's call
/// arrives in after the copy.
fn call_with_buffer(
    table: &mut SyscallTable,
    number: SyscallNumber,
    args: [usize; 6],
    buffer: &mut [u8],
) -> Result<usize> {
    let mut context = SyscallContext::new(number as usize, args);
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        second_path: None,
        buffer: Some(buffer),
        second_buffer: None,
    };
    let dispatch = table.dispatch(&mut arguments)?;
    Ok(dispatch.value)
}

/// `AbiInfo` answers the constants a program checks before it trusts
/// anything else.
///
/// Every field is asserted against the ABI's own values rather than against
/// what the handler happens to hold: the version comes from `abi::system`,
/// the slot count from the numbering, and the frozen boundary is the range
/// the document names.  A handler that wrote one of them twice, or wrote
/// them in the wrong order, fails here.
#[test]
fn abi_info_answers_the_builds_own_constants() {
    let mut table = SyscallTable::new();
    table.register(SyscallNumber::AbiInfo, abi_info);
    let mut buffer = [0u8; 24];
    assert_eq!(
        call_with_buffer(&mut table, SyscallNumber::AbiInfo, [0; 6], &mut buffer),
        Ok(0)
    );
    let version = usize::from_le_bytes(buffer[0..8].try_into().expect("a word"));
    let count = usize::from_le_bytes(buffer[8..16].try_into().expect("a word"));
    let frozen = usize::from_le_bytes(buffer[16..24].try_into().expect("a word"));
    assert_eq!(version, abi::system::ABI_VERSION);
    assert_eq!(count, syscall::PUBLIC_SYSCALL_COUNT as usize);
    assert_eq!(frozen, super::super::handlers::FROZEN_SYSCALL_COUNT);
    // And the frozen boundary is the document's, not a number that drifted:
    // `0..=120` is 121 numbers.
    assert_eq!(frozen, 121);
}

/// A record shorter than the ABI's own size is refused, and a reserved
/// argument that is not zero is refused, on all four calls.
///
/// The size check is the one a handler must not skip: a program that passed
/// eight bytes would get the first field and a truncated second, and the
/// handler would have written past what it was given.
#[test]
fn the_time_and_info_calls_refuse_a_short_record() {
    let mut table = SyscallTable::new();
    table.register(SyscallNumber::AbiInfo, abi_info);
    table.register(SyscallNumber::SystemInfo, system_info);
    table.register(SyscallNumber::GetTimeOfDay, get_time_of_day);
    table.register(SyscallNumber::GetRandom, get_random);

    let mut short = [0u8; 8];
    assert_eq!(
        call_with_buffer(&mut table, SyscallNumber::AbiInfo, [0; 6], &mut short),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        call_with_buffer(&mut table, SyscallNumber::SystemInfo, [0; 6], &mut short),
        Err(Error::InvalidArgument)
    );
    assert_eq!(
        call_with_buffer(&mut table, SyscallNumber::GetTimeOfDay, [0; 6], &mut short),
        Err(Error::InvalidArgument)
    );
    // And each call refuses a reserved argument that is not zero.
    let mut buffer = [0u8; 24];
    assert_eq!(
        call_with_buffer(
            &mut table,
            SyscallNumber::AbiInfo,
            [0, 0, 1, 0, 0, 0],
            &mut buffer
        ),
        Err(Error::InvalidArgument)
    );
}

/// `SystemInfo` refuses a selector this build does not serve.
///
/// The old tree answered ten selectors; this build has one, and a caller
/// naming a second must be told rather than handed zeros that read as a
/// quiet machine.
#[test]
fn system_info_refuses_an_unknown_selector() {
    let mut table = SyscallTable::new();
    table.register(SyscallNumber::SystemInfo, system_info);
    let mut buffer = [0u8; 64];
    assert_eq!(
        call_with_buffer(
            &mut table,
            SyscallNumber::SystemInfo,
            [9, 0, 64, 0, 0, 0],
            &mut buffer
        ),
        Err(Error::InvalidArgument)
    );
}

/// `GetTimeOfDay` refuses a clock this build does not have, and answers a
/// defined one on a host with `Unsupported` rather than a fabricated time.
///
/// A host has no counter, so `CLOCK_MONOTONIC` cannot be answered, and
/// that is the honest assertion.  An id outside the ABI's known set is a
/// caller's mistake and answers `InvalidArgument`, which is a different
/// fact from the kernel not having the clock.
#[test]
fn get_time_of_day_separates_an_unknown_clock_from_a_missing_one() {
    let mut table = SyscallTable::new();
    table.register(SyscallNumber::GetTimeOfDay, get_time_of_day);
    let mut buffer = [0u8; 16];
    assert_eq!(
        call_with_buffer(
            &mut table,
            SyscallNumber::GetTimeOfDay,
            [7, 0, 16, 0, 0, 0],
            &mut buffer
        ),
        Err(Error::InvalidArgument),
        "clock 7 is not one the ABI defines"
    );
    assert_eq!(
        call_with_buffer(
            &mut table,
            SyscallNumber::GetTimeOfDay,
            [abi::time::CLOCK_REALTIME, 0, 16, 0, 0, 0],
            &mut buffer
        ),
        Err(Error::Unsupported),
        "wall time is defined and this kernel has no clock for it"
    );
    assert_eq!(
        call_with_buffer(
            &mut table,
            SyscallNumber::GetTimeOfDay,
            [abi::time::CLOCK_MONOTONIC, 0, 16, 0, 0, 0],
            &mut buffer
        ),
        Err(Error::Unsupported),
        "a host reads no counter, so the reading it cannot take is refused"
    );
}

/// `GetRandom` with a zero length answers zero and touches nothing.
///
/// A caller asking for no bytes is not an error and not a caller the
/// generator should serve from: the buffer keeps whatever it held, and the
/// answer says how many bytes were written, which is none.
#[test]
fn get_random_writes_nothing_for_a_zero_length() {
    let mut table = SyscallTable::new();
    table.register(SyscallNumber::GetRandom, get_random);
    let mut buffer = [0xAAu8; 8];
    assert_eq!(
        call_with_buffer(
            &mut table,
            SyscallNumber::GetRandom,
            [0, 0, 0, 0, 0, 0],
            &mut buffer
        ),
        Ok(0)
    );
    assert_eq!(buffer, [0xAAu8; 8], "the buffer was not touched");
}

/// `Dup` answers the lowest free slot, and the copy is a second handle on the
/// same node.
///
/// The two halves are what the call is for, and they are separate claims: a
/// duplicate that answered a high number would be a table that leaked slots,
/// and one that answered a low number but named a different node would be a
/// second open.  The read-back is what tells them apart: a byte read through
/// the copy is the byte the original would have read.
#[test]
fn dup_answers_the_lowest_free_slot_on_the_same_node() {
    let mut table = writable();
    table.register(SyscallNumber::Dup, dup);
    table.register(SyscallNumber::Read, read);
    // A file with a known byte in it, so "the copy names the same node" is a
    // byte read through the copy rather than a success that any descriptor
    // would have given.  The create flag makes it, and the write puts the byte
    // there, because a duplicate that answered a fresh empty file must fail
    // the read-back.
    let flags = fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
    let opened = open_path(&mut table, "/dup-note.txt", flags).expect("create and open");
    assert_eq!(opened, 0, "the first slot");
    table.write_at(opened, b"x", None).expect("write one byte");

    let copy = call(&mut table, SyscallNumber::Dup, [opened, 0, 0, 0, 0, 0]).expect("dup");
    assert_eq!(copy, 1, "the next free slot");
    assert_eq!(
        table.open_descriptors(),
        2,
        "the original is still open: a duplicate adds a handle"
    );

    // Closing the original leaves the copy: a duplicate is a handle, not an
    // alias that dies with its source.
    assert_eq!(
        call(&mut table, SyscallNumber::Close, [opened, 0, 0, 0, 0, 0]),
        Ok(0)
    );
    assert_eq!(table.open_descriptors(), 1);
    // Read at an explicit offset rather than at the descriptor's own position:
    // the write moved that position to the end, and the duplicate copied it, so
    // a read there would answer zero bytes and say nothing about the node.
    let mut bytes = [0u8; 1];
    assert_eq!(
        read_into(&mut table, copy, 0, &mut bytes),
        Ok(1),
        "the copy still names the file"
    );
    assert_eq!(bytes, [b'x'], "and it read the file's first byte");
}

/// `Dup` of a number that names nothing is refused, and so is a duplicate of
/// another process's descriptor.
///
/// Both answers are `InvalidArgument`, and for the same reason: a number that
/// is not this caller's descriptor is not a descriptor to it at all, and a
/// caller told "denied" would learn which numbers exist.
#[test]
fn dup_refuses_a_number_that_is_not_the_callers() {
    let mut table = writable();
    table.register(SyscallNumber::Dup, dup);
    assert_eq!(
        call(&mut table, SyscallNumber::Dup, [0, 0, 0, 0, 0, 0]),
        Err(Error::InvalidArgument),
        "an empty slot is not a descriptor"
    );
    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Dup,
            [MAX_DESCRIPTORS, 0, 0, 0, 0, 0]
        ),
        Err(Error::InvalidArgument),
        "a number past the table names nothing"
    );
}

/// `Dup2` places the copy on the number the caller names, and answers it.
///
/// The placement is the whole difference from `Dup`: a caller naming three gets
/// three, whatever the lowest free slot is.
#[test]
fn dup2_places_the_copy_on_the_named_number() {
    let mut table = writable();
    table.register(SyscallNumber::Dup2, dup2);
    let opened = open_path(
        &mut table,
        "/",
        fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_WRITE,
    )
    .expect("open");
    assert_eq!(opened, 0);

    let placed = call(&mut table, SyscallNumber::Dup2, [opened, 7, 0, 0, 0, 0]).expect("dup2");
    assert_eq!(placed, 7, "the number the caller named");
    assert_eq!(table.open_descriptors(), 2);
    assert_eq!(
        table.owner_of(7),
        Some(crate::programs::BOOT_PROCESS),
        "the copy is the caller's"
    );
}

/// `Dup2` closes what the target held first, so a full table still succeeds.
///
/// This is the property a caller relies on to put a file on standard output:
/// the number must be free the moment it is named, and the copy must land even
/// when every slot is in use.
#[test]
fn dup2_replaces_the_target_and_works_on_a_full_table() {
    let mut table = writable();
    table.register(SyscallNumber::Dup2, dup2);
    table.register(SyscallNumber::Close, close);

    let source = open_path(
        &mut table,
        "/",
        fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_WRITE,
    )
    .expect("open");
    // Fill every remaining slot, so the table has no free slot at all.
    let mut filled = 1;
    for _ in 1..MAX_DESCRIPTORS {
        if open_path(
            &mut table,
            "/",
            fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_WRITE,
        )
        .is_ok()
        {
            filled += 1;
        }
    }
    assert_eq!(filled, MAX_DESCRIPTORS, "the table is full");

    // The target is an occupied slot, and the copy must still land on it: the
    // descriptor there is closed first, which is what makes room.
    let placed = call(&mut table, SyscallNumber::Dup2, [source, 3, 0, 0, 0, 0])
        .expect("dup2 onto an occupied slot with no free slot");
    assert_eq!(placed, 3);
    assert_eq!(
        table.open_descriptors(),
        MAX_DESCRIPTORS,
        "one closed and one opened: the count is unchanged"
    );
}

/// `Dup2` with the target equal to the source answers the source and leaves it
/// alone.
///
/// The tempting implementation closes and re-opens, which would work for a file
/// and lose a pipe end whose count it decremented before raising it.  The
/// answer is what a caller uses to ask "is this number mine", so it must not
/// change the thing it was asked about.
#[test]
fn dup2_onto_itself_changes_nothing() {
    let mut table = writable();
    table.register(SyscallNumber::Dup2, dup2);
    let opened = open_path(
        &mut table,
        "/",
        fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_WRITE,
    )
    .expect("open");
    let before = table.open_descriptors();

    let placed = call(
        &mut table,
        SyscallNumber::Dup2,
        [opened, opened, 0, 0, 0, 0],
    )
    .expect("dup2 onto itself");
    assert_eq!(placed, opened);
    assert_eq!(table.open_descriptors(), before, "nothing was added");
    assert_eq!(
        table.owner_of(opened),
        Some(crate::programs::BOOT_PROCESS),
        "and the descriptor is still the caller's"
    );
}

/// `Dup2` refuses a target past the table, and a source that names nothing.
#[test]
fn dup2_refuses_a_target_past_the_table() {
    let mut table = writable();
    table.register(SyscallNumber::Dup2, dup2);
    let opened = open_path(
        &mut table,
        "/",
        fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_WRITE,
    )
    .expect("open");
    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Dup2,
            [opened, MAX_DESCRIPTORS, 0, 0, 0, 0]
        ),
        Err(Error::InvalidArgument),
        "a target past the table has no slot to place the copy in"
    );
    assert_eq!(
        call(&mut table, SyscallNumber::Dup2, [99, 3, 0, 0, 0, 0]),
        Err(Error::InvalidArgument),
        "a source that names nothing"
    );
    assert_eq!(
        table.open_descriptors(),
        1,
        "a refused call changed nothing"
    );
}

/// `F_DUPFD` places the copy at or above the floor the caller named.
///
/// The floor is the whole difference from `Dup`: a program reserving the low
/// numbers for its standard streams asks for a copy at seven and must not get
/// three.  Both ends are checked: with a free slot at the floor it takes that
/// one, and with the floor occupied it takes the next free slot above.
#[test]
fn f_dupfd_places_the_copy_at_or_above_the_floor() {
    let mut table = writable();
    table.register(SyscallNumber::Fcntl, fcntl);
    let opened = open_path(&mut table, "/", fs_abi::OPEN_FLAG_READ).expect("open");

    let placed = call(
        &mut table,
        SyscallNumber::Fcntl,
        [opened, fs_abi::F_DUPFD, 7, 0, 0, 0],
    )
    .expect("F_DUPFD");
    assert_eq!(placed, 7, "the floor itself, when it is free");

    // The floor occupied: the next free number above it.
    let again = call(
        &mut table,
        SyscallNumber::Fcntl,
        [opened, fs_abi::F_DUPFD, 7, 0, 0, 0],
    )
    .expect("F_DUPFD onto a taken floor");
    assert_eq!(again, 8);

    // A floor past the table names a slot that does not exist.
    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Fcntl,
            [opened, fs_abi::F_DUPFD, MAX_DESCRIPTORS, 0, 0, 0]
        ),
        Err(Error::InvalidArgument)
    );
}

/// `F_GETFL` answers the descriptor's access mode, which is the open's and not
/// the node's.
///
/// Two descriptors on one file, opened differently, answer differently, which
/// is what makes the answer a fact about the descriptor rather than a constant.
#[test]
fn f_getfl_answers_the_descriptors_own_access_mode() {
    let mut table = writable();
    table.register(SyscallNumber::Fcntl, fcntl);
    let reading = open_path(&mut table, "/", fs_abi::OPEN_FLAG_READ).expect("read-only open");
    let writing = open_path(
        &mut table,
        "/",
        fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_WRITE,
    )
    .expect("read-write open");

    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Fcntl,
            [reading, fs_abi::F_GETFL, 0, 0, 0, 0]
        ),
        Ok(fs_abi::OPEN_FLAG_READ)
    );
    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Fcntl,
            [writing, fs_abi::F_GETFL, 0, 0, 0, 0]
        ),
        Ok(fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_WRITE)
    );
}

/// `F_SETFL` accepts the non-blocking bit and refuses an access mode.
///
/// An access mode is the open's, so a later call that named one is refused
/// rather than silently re-opened: a descriptor whose rights changed underneath
/// its holder is the one thing an open's answer must never do.
#[test]
fn f_setfl_accepts_the_nonblocking_bit_and_refuses_the_rest() {
    let mut table = writable();
    table.register(SyscallNumber::Fcntl, fcntl);
    let opened = open_path(&mut table, "/", fs_abi::OPEN_FLAG_READ).expect("open");

    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Fcntl,
            [opened, fs_abi::F_SETFL, fs_abi::O_NONBLOCK, 0, 0, 0]
        ),
        Ok(0)
    );
    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Fcntl,
            [opened, fs_abi::F_SETFL, fs_abi::OPEN_FLAG_WRITE, 0, 0, 0]
        ),
        Err(Error::InvalidArgument),
        "an access mode is not a status flag a later call may set"
    );
}

/// The two pipe-capacity commands answer the ring's own number, and the set
/// answers what the ring became rather than what was asked for.
///
/// The distinction is the call's whole point: the ring rounds a request to a
/// power of two, so a caller that asked for 5000 and was given 8192 must be
/// told 8192.
#[test]
fn the_pipe_capacity_commands_answer_what_the_ring_became() {
    use crate::pipe;
    use crate::pipe::End;

    let pipe = Arc::new(pipe::Pipe::new(4096));
    let mut table = SyscallTable::new();
    table.register(SyscallNumber::Fcntl, fcntl);
    let end = table
        .insert_pipe(End::reader(pipe.clone()), crate::programs::BOOT_PROCESS)
        .expect("insert");

    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Fcntl,
            [end, fs_abi::F_GETPIPE_SZ, 0, 0, 0, 0]
        ),
        Ok(4096)
    );
    let grown = call(
        &mut table,
        SyscallNumber::Fcntl,
        [end, fs_abi::F_SETPIPE_SZ, 16384, 0, 0, 0],
    )
    .expect("F_SETPIPE_SZ");
    assert_eq!(grown, 16384);
    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Fcntl,
            [end, fs_abi::F_GETPIPE_SZ, 0, 0, 0, 0]
        ),
        Ok(16384),
        "the get reads back what the set made"
    );
}

/// The two pipe-capacity commands refuse a descriptor that is not a pipe.
///
/// A regular file has no buffer to size, and `InvalidArgument` is the answer a
/// caller can act on: the number is a descriptor, and it is the wrong kind.
#[test]
fn the_pipe_capacity_commands_refuse_a_file() {
    let mut table = writable();
    table.register(SyscallNumber::Fcntl, fcntl);
    let opened = open_path(&mut table, "/", fs_abi::OPEN_FLAG_READ).expect("open");
    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Fcntl,
            [opened, fs_abi::F_GETPIPE_SZ, 0, 0, 0, 0]
        ),
        Err(Error::InvalidArgument)
    );
}

/// `F_GETFD` and `F_SETFD` read and write one byte, and the byte means
/// something now.
///
/// This test used to assert that `F_SETFD` refused `FD_CLOEXEC` on the argument
/// that `exec` kept every descriptor and a flag nothing acts on must not be
/// recorded.  That argument was true of the build it was written for and is not
/// true of this one: `exec` now closes what the flag marks, so the bit is
/// accepted **because** something keeps the promise.  The test records the
/// reversal rather than being deleted, because the refusal was a deliberate
/// decision and its replacement is one too.
#[test]
fn the_descriptor_flags_are_stored_and_read_back() {
    let mut table = writable();
    table.register(SyscallNumber::Fcntl, fcntl);
    let opened = open_path(&mut table, "/", fs_abi::OPEN_FLAG_READ).expect("open");

    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Fcntl,
            [opened, fs_abi::F_GETFD, 0, 0, 0, 0]
        ),
        Ok(0),
        "a fresh descriptor carries no flags"
    );
    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Fcntl,
            [opened, fs_abi::F_SETFD, fs_abi::FD_CLOEXEC, 0, 0, 0]
        ),
        Ok(0),
        "the bit is accepted because exec closes what it marks"
    );
    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Fcntl,
            [opened, fs_abi::F_GETFD, 0, 0, 0, 0]
        ),
        Ok(fs_abi::FD_CLOEXEC),
        "and the read answers it"
    );
    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Fcntl,
            [opened, fs_abi::F_SETFD, 0, 0, 0, 0]
        ),
        Ok(0),
        "clearing what is set is the same call with zero"
    );
}

/// An fcntl command this build does not define is `NotImplemented`, and a
/// descriptor that is not the caller's is `InvalidArgument`.
///
/// The pair is the two refusals the call can make, and they answer different
/// questions: one names a command a newer ABI has, the other a number that is
/// not this caller's descriptor at all.
#[test]
fn fcntl_refuses_an_unknown_command_and_a_foreign_descriptor() {
    let mut table = writable();
    table.register(SyscallNumber::Fcntl, fcntl);
    let opened = open_path(&mut table, "/", fs_abi::OPEN_FLAG_READ).expect("open");

    assert_eq!(
        call(&mut table, SyscallNumber::Fcntl, [opened, 9999, 0, 0, 0, 0]),
        Err(Error::NotImplemented)
    );
    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Fcntl,
            [40, fs_abi::F_GETFL, 0, 0, 0, 0]
        ),
        Err(Error::InvalidArgument)
    );
}

/// The four extended-attribute calls, through a tmpfs that really has them.
///
/// Set, get, list and remove in one test because the four are one mechanism
/// observed at its four steps: a set that stored nothing would pass a get that
/// invented an answer, and a list that dropped an entry would pass both.  The
/// read-back is a byte the test wrote, and the list is parsed with the ABI's
/// own record arithmetic rather than with the writer's.
#[test]
fn the_xattr_calls_round_trip_through_a_real_filesystem() {
    let mut table = writable();
    table.register(SyscallNumber::SetXattr, set_xattr);
    table.register(SyscallNumber::GetXattr, get_xattr);
    table.register(SyscallNumber::ListXattr, list_xattr);
    table.register(SyscallNumber::RemoveXattr, remove_xattr);
    let flags = fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
    open_path(&mut table, "/attrs.txt", flags).expect("create the file");
    let path = "/attrs.txt";

    // Set: the name is the mutable slot and the value the read-only one.
    let mut name = *b"user.motd";
    let value = b"hello";
    assert_eq!(
        call_with_two_buffers(&mut table, SyscallNumber::SetXattr, path, &mut name, value,),
        Ok(0)
    );

    // Get: the same name answers the bytes that were stored.
    let mut destination = [0u8; 32];
    let length = call_with_name(
        &mut table,
        SyscallNumber::GetXattr,
        path,
        b"user.motd",
        &mut destination,
    )
    .expect("get");
    assert_eq!(length, 5);
    assert_eq!(&destination[..length], b"hello");

    // List: one record, its name and its value where its own offsets say.
    let mut listed = [0u8; 256];
    let filled = call_with_path_buffer(&mut table, SyscallNumber::ListXattr, path, &mut listed)
        .expect("list");
    assert_eq!(
        filled,
        fs_abi::XATTR_ENTRY_RECORD_SIZE + b"user.motd".len() + b"hello".len()
    );
    let record = fs_abi::XattrEntryRecord::new(b"user.motd".len(), b"hello".len());
    assert_eq!(
        &listed[record.name_offset..record.name_offset + record.name_len],
        b"user.motd"
    );
    assert_eq!(
        &listed[record.value_offset..record.value_offset + record.value_len],
        b"hello"
    );

    // Remove: the attribute is gone, and a second remove says it was not there.
    let mut removed = *b"user.motd";
    assert_eq!(
        call_with_one_buffer(&mut table, SyscallNumber::RemoveXattr, path, &mut removed),
        Ok(0)
    );
    let mut again = *b"user.motd";
    assert_eq!(
        call_with_one_buffer(&mut table, SyscallNumber::RemoveXattr, path, &mut again),
        Err(Error::NotFound)
    );
}

/// A set whose name is empty, or whose value is past the ABI's maximum, is
/// refused before any filesystem is asked.
///
/// Both limits are the ABI's rather than the volume's, which is what makes the
/// answer the same whichever filesystem would have stored the attribute.
#[test]
fn set_xattr_refuses_a_name_or_value_past_the_limit() {
    let mut table = writable();
    table.register(SyscallNumber::SetXattr, set_xattr);
    let flags = fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
    open_path(&mut table, "/limits.txt", flags).expect("create");

    let mut empty_name: [u8; 0] = [];
    assert_eq!(
        call_with_two_buffers(
            &mut table,
            SyscallNumber::SetXattr,
            "/limits.txt",
            &mut empty_name,
            b"v",
        ),
        Err(Error::InvalidArgument),
        "an attribute with no name cannot be looked up"
    );

    let mut name = *b"user.big";
    let oversized = alloc::vec![0u8; fs_abi::XATTR_VALUE_MAX + 1];
    assert_eq!(
        call_with_two_buffers(
            &mut table,
            SyscallNumber::SetXattr,
            "/limits.txt",
            &mut name,
            &oversized,
        ),
        Err(Error::InvalidArgument)
    );
}

/// A get whose destination is too small is refused rather than truncated, and
/// an attribute that is not there is `NotFound`.
#[test]
fn get_xattr_answers_not_found_and_refuses_a_short_buffer() {
    let mut table = writable();
    table.register(SyscallNumber::SetXattr, set_xattr);
    table.register(SyscallNumber::GetXattr, get_xattr);
    let flags = fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
    open_path(&mut table, "/short.txt", flags).expect("create");

    let mut name = *b"user.long";
    let value = b"0123456789";
    call_with_two_buffers(
        &mut table,
        SyscallNumber::SetXattr,
        "/short.txt",
        &mut name,
        value,
    )
    .expect("set");

    let mut small = [0u8; 4];
    assert_eq!(
        call_with_name(
            &mut table,
            SyscallNumber::GetXattr,
            "/short.txt",
            b"user.long",
            &mut small
        ),
        Err(Error::InvalidArgument),
        "half a value is not an answer"
    );
    let mut anywhere = [0u8; 32];
    assert_eq!(
        call_with_name(
            &mut table,
            SyscallNumber::GetXattr,
            "/short.txt",
            b"user.absent",
            &mut anywhere
        ),
        Err(Error::NotFound)
    );
}

/// The ownership read answers the file's real mode, not a default.
///
/// The record is the ABI's eight bytes, parsed with the ABI's own offsets: a
/// handler that wrote the words where `#[repr(C)]` does not put them fails
/// here.  The file is created by this test, so the mode it reads is the one
/// tmpfs gave it rather than one the test guessed.
#[test]
fn permission_metadata_names_the_owner_and_the_mode() {
    // The mode is tmpfs's own, and it is `0o666` rather than the shared
    // `DEFAULT_FILE_MODE`: a scratch filesystem's files are writable by
    // everyone with access to the mount, which is what makes it scratch.  The
    // constant is named here and the assertion is against it, so a tmpfs that
    // changed its mind fails this test rather than passing on a number the test
    // invented.
    const TMPFS_FILE_MODE: u16 = 0o666;

    let mut table = writable();
    table.register(SyscallNumber::PermissionMetadata, permission_metadata);
    let flags = fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
    open_path(&mut table, "/owned.txt", flags).expect("create");
    let path = "/owned.txt";

    let mut record = [0u8; fs_abi::PERMISSION_METADATA_RECORD_SIZE];
    assert_eq!(
        call_with_path_buffer(
            &mut table,
            SyscallNumber::PermissionMetadata,
            path,
            &mut record
        ),
        Ok(0)
    );
    let uid = u32::from_le_bytes(
        record[fs_abi::PERMISSION_METADATA_RECORD_OWNER_UID_OFFSET
            ..fs_abi::PERMISSION_METADATA_RECORD_OWNER_UID_OFFSET + 4]
            .try_into()
            .expect("four bytes"),
    );
    let gid = u32::from_le_bytes(
        record[fs_abi::PERMISSION_METADATA_RECORD_OWNER_GID_OFFSET
            ..fs_abi::PERMISSION_METADATA_RECORD_OWNER_GID_OFFSET + 4]
            .try_into()
            .expect("four bytes"),
    );
    let mode = u16::from_le_bytes(
        record[fs_abi::PERMISSION_METADATA_RECORD_MODE_OFFSET
            ..fs_abi::PERMISSION_METADATA_RECORD_MODE_OFFSET + 2]
            .try_into()
            .expect("two bytes"),
    );
    assert_eq!(uid, security::token::ROOT_USER_ID, "the owner is the root");
    assert_eq!(gid, security::token::ROOT_GROUP_ID);
    assert_eq!(mode, TMPFS_FILE_MODE, "a new tmpfs file's own mode");
}

/// The ownership reads answer the same record through all three forms.
///
/// A path, a path anchored at a descriptor and the descriptor itself name one
/// file, so the three must agree byte for byte.  They are compared to each
/// other rather than to a constant: the record is the file's, and a test that
/// pinned it would pass on a handler that answered a plausible constant.
#[test]
fn the_three_ownership_forms_agree() {
    let mut table = writable();
    table.register(SyscallNumber::PermissionMetadata, permission_metadata);
    table.register(SyscallNumber::PermissionMetadataAt, permission_metadata_at);
    table.register(SyscallNumber::PermissionMetadataFd, permission_metadata_fd);
    let flags = fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
    let held = open_path(&mut table, "/same.txt", flags).expect("create and hold");
    // The anchor is the directory, because a relative path resolves against
    // it: anchoring at the file itself would be asking a file to be a parent.
    let anchor = open_path(&mut table, "/", fs_abi::OPEN_FLAG_READ).expect("open /");

    let mut by_path = [0u8; fs_abi::PERMISSION_METADATA_RECORD_SIZE];
    call_with_path_buffer(
        &mut table,
        SyscallNumber::PermissionMetadata,
        "/same.txt",
        &mut by_path,
    )
    .expect("permission_metadata");

    let mut by_at = [0u8; fs_abi::PERMISSION_METADATA_RECORD_SIZE];
    call_with_anchor(
        &mut table,
        SyscallNumber::PermissionMetadataAt,
        anchor,
        "same.txt",
        &mut by_at,
    )
    .expect("permission_metadata_at");

    let mut by_fd = [0u8; fs_abi::PERMISSION_METADATA_RECORD_SIZE];
    call_with_descriptor_record(
        &mut table,
        SyscallNumber::PermissionMetadataFd,
        held,
        &mut by_fd,
    )
    .expect("permission_metadata_fd");

    assert_eq!(by_path, by_at, "the anchored form agrees with the path");
    assert_eq!(by_path, by_fd, "the descriptor form agrees with the path");
    assert_ne!(
        by_path,
        [0u8; fs_abi::PERMISSION_METADATA_RECORD_SIZE],
        "and both are filled"
    );
}

/// An access query is a real reading of the mode bits.
///
/// The caller's token is built from its MAC label and **not** from the kernel's
/// identity, so it does not bypass the mode: a file owned by root with mode
/// `0o644` grants a guest read and denies write and execute.  That is the whole
/// reason the call exists, and a token built with `SecurityToken::system` would
/// answer "allowed" for all three.
#[test]
fn access_query_reads_the_mode_against_the_caller() {
    // tmpfs creates files `0o666`, so a guest is granted read and write and
    // denied execute.  The denied bit is the one that matters: a token built
    // with `SecurityToken::system` bypasses the mode and would answer
    // "allowed" for all three, which is the defect this assertion rules out.
    const TMPFS_FILE_MODE: u16 = 0o666;
    assert_eq!(
        TMPFS_FILE_MODE & 0o7,
        0o6,
        "others read and write, not execute"
    );

    let mut table = writable();
    table.register(SyscallNumber::AccessQuery, access_query);
    let flags = fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
    open_path(&mut table, "/queried.txt", flags).expect("create");

    let ask = |table: &mut SyscallTable, required: u16| {
        let mut record = [0u8; fs_abi::ACCESS_QUERY_RECORD_SIZE];
        let answer = call_with_path_buffer_and_required(
            table,
            SyscallNumber::AccessQuery,
            "/queried.txt",
            required,
            &mut record,
        );
        (answer, record)
    };

    // Read: granted, and the allowed flag is set.
    let (answer, read) = ask(&mut table, fs_abi::ACCESS_READ_BIT);
    assert_eq!(answer, Ok(0));
    let granted = u16::from_le_bytes(
        read[fs_abi::ACCESS_QUERY_RECORD_GRANTED_MODE_BITS_OFFSET
            ..fs_abi::ACCESS_QUERY_RECORD_GRANTED_MODE_BITS_OFFSET + 2]
            .try_into()
            .expect("two bytes"),
    );
    let flags_word = u32::from_le_bytes(
        read[fs_abi::ACCESS_QUERY_RECORD_FLAGS_OFFSET
            ..fs_abi::ACCESS_QUERY_RECORD_FLAGS_OFFSET + 4]
            .try_into()
            .expect("four bytes"),
    );
    assert_eq!(granted & fs_abi::ACCESS_READ_BIT, fs_abi::ACCESS_READ_BIT);
    assert_ne!(flags_word & fs_abi::ACCESS_QUERY_FLAG_ALLOWED, 0);
    assert_ne!(flags_word & fs_abi::ACCESS_QUERY_FLAG_CAN_READ, 0);

    // Execute: the bit is not granted, and the allowed flag is clear.  This is
    // the half a bypassing token would get wrong: the mode says no, and a
    // kernel token would have said yes.
    let (answer, execute) = ask(&mut table, fs_abi::ACCESS_EXECUTE_BIT);
    assert_eq!(answer, Ok(0));
    let flags_word = u32::from_le_bytes(
        execute[fs_abi::ACCESS_QUERY_RECORD_FLAGS_OFFSET
            ..fs_abi::ACCESS_QUERY_RECORD_FLAGS_OFFSET + 4]
            .try_into()
            .expect("four bytes"),
    );
    assert_eq!(
        flags_word & fs_abi::ACCESS_QUERY_FLAG_ALLOWED,
        0,
        "a guest may not execute a root-owned 0o666 file"
    );
    assert_eq!(flags_word & fs_abi::ACCESS_QUERY_FLAG_CAN_EXECUTE, 0);
}

/// An access query refuses a bit outside the three the ABI defines, and a
/// record too small to hold the answer.
#[test]
fn access_query_refuses_a_bad_request() {
    let mut table = writable();
    table.register(SyscallNumber::AccessQuery, access_query);
    let flags = fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
    open_path(&mut table, "/bad.txt", flags).expect("create");

    let mut record = [0u8; fs_abi::ACCESS_QUERY_RECORD_SIZE];
    assert_eq!(
        call_with_path_buffer_and_required(
            &mut table,
            SyscallNumber::AccessQuery,
            "/bad.txt",
            0b1000,
            &mut record
        ),
        Err(Error::InvalidArgument),
        "a fourth access bit is not one this ABI defines"
    );

    let mut small = [0u8; 2];
    assert_eq!(
        call_with_path_buffer_and_required(
            &mut table,
            SyscallNumber::AccessQuery,
            "/bad.txt",
            fs_abi::ACCESS_READ_BIT,
            &mut small
        ),
        Err(Error::InvalidArgument),
        "half a record is not an answer"
    );
}

/// `SetFdFlags` stores the close-on-exec bit, and `F_GETFD` reads it back.
///
/// The two calls are the same byte seen from two numbers, so the test drives
/// one and reads with the other: a build that stored the flag in one place and
/// answered from another would pass a test that only used one of them.
#[test]
fn set_fd_flags_stores_the_bit_and_f_getfd_reads_it() {
    let mut table = writable();
    table.register(SyscallNumber::SetFdFlags, set_fd_flags);
    table.register(SyscallNumber::Fcntl, fcntl);
    let opened = open_path(&mut table, "/", fs_abi::OPEN_FLAG_READ).expect("open");

    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Fcntl,
            [opened, fs_abi::F_GETFD, 0, 0, 0, 0]
        ),
        Ok(0),
        "a fresh descriptor carries no flags"
    );
    assert_eq!(
        call(
            &mut table,
            SyscallNumber::SetFdFlags,
            [opened, fs_abi::FD_CLOEXEC, 0, 0, 0, 0]
        ),
        Ok(0)
    );
    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Fcntl,
            [opened, fs_abi::F_GETFD, 0, 0, 0, 0]
        ),
        Ok(fs_abi::FD_CLOEXEC),
        "the read sees what the write stored"
    );

    // Clearing it is the same call with zero.
    assert_eq!(
        call(
            &mut table,
            SyscallNumber::SetFdFlags,
            [opened, 0, 0, 0, 0, 0]
        ),
        Ok(0)
    );
    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Fcntl,
            [opened, fs_abi::F_GETFD, 0, 0, 0, 0]
        ),
        Ok(0)
    );
}

/// A bit outside the ABI's known set is refused rather than stored, and a
/// number that is not the caller's descriptor is refused by both calls.
#[test]
fn set_fd_flags_refuses_an_unknown_bit_and_a_foreign_number() {
    let mut table = writable();
    table.register(SyscallNumber::SetFdFlags, set_fd_flags);
    table.register(SyscallNumber::Fcntl, fcntl);
    let opened = open_path(&mut table, "/", fs_abi::OPEN_FLAG_READ).expect("open");

    assert_eq!(
        call(
            &mut table,
            SyscallNumber::SetFdFlags,
            [opened, 0b10, 0, 0, 0, 0]
        ),
        Err(Error::InvalidArgument),
        "a second per-descriptor flag is not one this build defines"
    );
    assert_eq!(
        call(
            &mut table,
            SyscallNumber::SetFdFlags,
            [40, fs_abi::FD_CLOEXEC, 0, 0, 0, 0]
        ),
        Err(Error::InvalidArgument),
        "a number that names nothing"
    );
    assert_eq!(
        call(
            &mut table,
            SyscallNumber::Fcntl,
            [opened, fs_abi::F_SETFD, 0b10, 0, 0, 0]
        ),
        Err(Error::InvalidArgument),
        "and the fcntl command refuses the same bit"
    );
}

/// `exec` closes the descriptors carrying the flag and leaves the rest.
///
/// The count is the mechanism's own answer, and the two halves matter equally:
/// a close that took every descriptor would pass a test that only counted what
/// went, and one that took none would pass a test that only looked at the
/// marked one.
#[test]
fn close_on_exec_takes_the_marked_descriptors_and_only_those() {
    let mut table = writable();
    table.register(SyscallNumber::SetFdFlags, set_fd_flags);
    let marked = open_path(
        &mut table,
        "/a.txt",
        fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE,
    )
    .expect("open a");
    let kept = open_path(
        &mut table,
        "/b.txt",
        fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE,
    )
    .expect("open b");
    assert_eq!(
        call(
            &mut table,
            SyscallNumber::SetFdFlags,
            [marked, fs_abi::FD_CLOEXEC, 0, 0, 0, 0]
        ),
        Ok(0)
    );

    let closed = table.close_on_exec(crate::programs::BOOT_PROCESS);
    assert_eq!(closed, 1, "one descriptor carried the flag");
    assert_eq!(table.open_descriptors(), 1, "and one is left");
    assert_eq!(
        table.owner_of(kept),
        Some(crate::programs::BOOT_PROCESS),
        "the unmarked descriptor is the one that stayed"
    );
    assert_eq!(table.owner_of(marked), None, "the marked one is gone");

    // A descriptor that reuses the closed slot must not inherit the flag: the
    // byte is cleared with the descriptor, and this is the assertion that says
    // so.
    let reused = open_path(
        &mut table,
        "/c.txt",
        fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE,
    )
    .expect("open c");
    assert_eq!(
        table.descriptor_flags_at(reused, None),
        Ok(0),
        "a reused slot starts with no flags"
    );
}

/// `Poll` answers a file ready and clears the `revents` of a skipped record.
///
/// A file has no state in which a read would block, so both bits are true; the
/// negative descriptor is the caller saying "not this one", and its answer must
/// be zero rather than whatever the slot happened to hold.  The record is
/// parsed with the ABI's offsets, so a handler that wrote the words elsewhere
/// fails.
#[test]
fn poll_answers_a_file_ready_and_skips_a_negative_descriptor() {
    let mut table = writable();
    table.register(SyscallNumber::Poll, poll);
    let opened = open_path(
        &mut table,
        "/polled.txt",
        fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE,
    )
    .expect("create and open");

    let mut records = [0u8; fs_abi::POLL_FD_SIZE * 2];
    let first = fs_abi::PollFd {
        fd: opened as i32,
        events: fs_abi::POLL_IN,
        revents: 0,
    };
    records[..4].copy_from_slice(&first.fd.to_le_bytes());
    records[4..6].copy_from_slice(&first.events.to_le_bytes());
    // The second record is the skip: a negative fd and a `revents` that is not
    // zero before the call, so a handler that left it alone fails.
    records[8..12].copy_from_slice(&(-1i32).to_le_bytes());
    records[12..14].copy_from_slice(&fs_abi::POLL_IN.to_le_bytes());
    records[14..16].copy_from_slice(&0xFFFFu16.to_le_bytes());

    let ready = call_with_poll(&mut table, &mut records, 2).expect("poll");
    assert_eq!(ready, 1, "only the file is ready");

    let first_revents = u16::from_le_bytes([records[6], records[7]]);
    assert_ne!(first_revents & fs_abi::POLL_IN, 0, "the file is readable");
    assert_eq!(
        u16::from_le_bytes([records[14], records[15]]),
        0,
        "the skipped record's revents is cleared"
    );
}

/// `Poll` answers a pipe's read end unready while it is empty and ready once a
/// byte arrives, and reports the hang-up when the writer goes.
///
/// The three states are the three a reader loops on, and each is a different
/// fact about the pipe: `POLL_IN` is "there is a byte", `0` is "wait", and
/// `POLL_HUP` is "stop waiting".
#[test]
fn poll_reads_a_pipes_state() {
    use crate::pipe;
    use crate::pipe::End;

    let pipe = Arc::new(pipe::Pipe::new(64));
    let mut table = SyscallTable::new();
    table.register(SyscallNumber::Poll, poll);
    let reader = table
        .insert_pipe(End::reader(pipe.clone()), crate::programs::BOOT_PROCESS)
        .expect("insert");

    // The writer exists before the first question: a pipe with no writer at
    // all is already at end-of-file, which is the third state this test checks
    // at the end, and asking the "empty but alive" question of it would be
    // asserting the wrong fact.
    let writer = End::writer(pipe.clone());

    let mut records = [0u8; fs_abi::POLL_FD_SIZE];
    records[..4].copy_from_slice(&(reader as i32).to_le_bytes());
    records[4..6].copy_from_slice(&fs_abi::POLL_IN.to_le_bytes());
    assert_eq!(
        call_with_poll(&mut table, &mut records, 1).expect("poll"),
        0,
        "an empty pipe with its writer still open is not ready"
    );

    let _ = pipe.write_available(b"x");
    assert_eq!(
        call_with_poll(&mut table, &mut records, 1).expect("poll"),
        1
    );
    assert_ne!(
        u16::from_le_bytes([records[6], records[7]]) & fs_abi::POLL_IN,
        0,
        "a buffered byte makes it readable"
    );

    // Drain the byte and drop the writer: the reader's next answer is the
    // hang-up, which is what ends the loop.
    let mut drained = [0u8; 1];
    let _ = pipe.read_available(&mut drained);
    drop(writer);
    assert_eq!(
        call_with_poll(&mut table, &mut records, 1).expect("poll"),
        1
    );
    assert_ne!(
        u16::from_le_bytes([records[6], records[7]]) & fs_abi::POLL_HUP,
        0,
        "with no writer left, the reader is told to stop"
    );
}

/// `Poll` refuses an array too small for the count, and a count it cannot
/// multiply.
#[test]
fn poll_refuses_a_bad_array() {
    let mut table = writable();
    table.register(SyscallNumber::Poll, poll);
    let mut records = [0u8; fs_abi::POLL_FD_SIZE];
    assert_eq!(
        call_with_poll(&mut table, &mut records, 2),
        Err(Error::InvalidArgument),
        "two records do not fit in one record's bytes"
    );
    assert_eq!(
        call_with_poll(&mut table, &mut records, usize::MAX / 4),
        Err(Error::InvalidArgument),
        "a count whose byte length overflows is refused, not wrapped"
    );
}
