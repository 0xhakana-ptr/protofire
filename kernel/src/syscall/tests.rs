//! kernel/src/syscall/tests.rs
//!
//! The syscall registry's tests: the table's dispatch, the descriptor slots,
//! the validators, and the MAC calls answering through the table rather than
//! beside it.

use alloc::sync::Arc;

use super::table::MAX_SYSCALLS;
use super::*;
use abi::Error;
use abi::Result;
use abi::fs as fs_abi;
use fs::MountTable;
use fs::StaticFileSystem;
use fs::types::NodeKind;
use syscall::SyscallContext;
use syscall::SyscallNumber;

/// A volume with one file in it, and a table serving the three handlers.
fn mounted() -> SyscallTable {
    let volume = StaticFileSystem::with_entries(
        "test",
        &[("/greeting.txt", NodeKind::File, b"hello from a syscall")],
    );
    let mut table = SyscallTable::new();
    let mut namespace = MountTable::new();
    namespace
        .mount("/", "pyrofs", "boot", Arc::new(volume))
        .expect("mount");
    table.set_namespace(Arc::new(namespace));
    table.register(SyscallNumber::Open, open);
    table.register(SyscallNumber::Read, read);
    table.register(SyscallNumber::Close, close);
    table
}

/// Open a path through the registry, as the boot does.
fn open_path(table: &mut SyscallTable, path: &str, flags: usize) -> Result<usize> {
    let mut context = SyscallContext::new(SyscallNumber::Open as usize, [0, flags, 0, 0, 0, 0]);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some(path),
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
        buffer: Some(buffer),
    };
    let dispatch = table.dispatch(&mut arguments)?;
    Ok(dispatch.value)
}

/// The whole path: open, read, close, and the bytes that came back.
///
/// This is the test the wiring exists for.  Every part of the interface is
/// on it — the number reaches the table, the context carries the arguments,
/// the validators run, the filesystem answers, and the value comes back as
/// a dispatch — and a break in any of them makes the comparison fail.
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
        buffer: None,
    };
    assert_eq!(table.dispatch(&mut arguments), Err(Error::InvalidArgument));

    let mut context = SyscallContext::new(SyscallNumber::Open as usize, [0, 0, 0, 0, 7, 0]);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some("/greeting.txt"),
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
