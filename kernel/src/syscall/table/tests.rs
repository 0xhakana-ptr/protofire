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
}

impl RecordingNode {
    fn new() -> Self {
        Self {
            name: "recorded",
            syncs: core::sync::atomic::AtomicUsize::new(0),
            data_syncs: core::sync::atomic::AtomicUsize::new(0),
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
    };
    assert_eq!(table.dispatch(&mut arguments), Err(Error::InvalidArgument));

    let mut context = SyscallContext::new(SyscallNumber::Open as usize, [0, 0, 0, 0, 7, 0]);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some("/greeting.txt"),
        second_path: None,
        buffer: None,
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
    };
    assert_eq!(table.dispatch(&mut arguments), Err(Error::InvalidArgument));
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
