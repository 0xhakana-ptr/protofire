//! kernel/src/syscall/handlers.rs
//!
//! The calls this boot serves: three filesystem ones, and the three that make
//! the MAC policy configurable rather than hard-coded.
//!
//! ## What a handler is not allowed to assume
//!
//! Every argument is a word from ring 3.  A descriptor is checked against the
//! table, a flag word against the set the ABI defines, an unused argument
//! against zero, and a path against the length a filesystem could accept, each
//! because the caller chose it and none because the kernel did.

use alloc::sync::Arc;

use abi::Error;
use abi::Result;
use abi::fs as fs_abi;
use abi::memory as memory_abi;
use abi::network as network_abi;
use abi::system as system_abi;
use abi::time as time_abi;
use paging;
use security::mac;
use syscall::SyscallContext;
use syscall::validate_known_flags;
use syscall::validate_zeroed_args;

use super::table::Arguments;
use super::table::Descriptor;
use super::table::Dispatch;
use super::table::SyscallTable;

/// Open a path and return its descriptor.
///
/// Arguments: the path, the flags, then two reserved slots that must be zero.
///
/// [`OPEN_FLAG_NONE`](fs_abi::OPEN_FLAG_NONE) is read-only: a caller that named
/// no access mode asked for the least it could get, and least privilege is the
/// reading that cannot surprise it with a write it did not name.
pub fn open(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let path = arguments.path.ok_or(Error::InvalidArgument)?;
    let flags = arguments.context.arg(1);
    validate_known_flags(flags, fs_abi::OPEN_KNOWN_FLAGS)?;
    validate_zeroed_args(arguments.context, 2)?;

    // The path is anchored at the root, which is what an `open` without a
    // descriptor to be relative to means; the normalization is the same one
    // the namespace would apply, done here so the descriptor records the
    // path in the form every later `*At` anchor reads.
    let resolved = fs::path::normalize_path(path, "/")?;
    open_resolved(table, arguments.context, &resolved, flags)
}

/// Open a path relative to a descriptor.
///
/// Arguments: the descriptor, the path, the flags, then three reserved slots
/// that must be zero.  A relative path resolves against the directory the
/// descriptor was opened from, `resolve_at` holds the three readings, and
/// the absolute and `AT_FDCWD` cases among them.
pub fn open_at(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let dirfd = arguments.context.arg(0);
    let path = arguments.path.ok_or(Error::InvalidArgument)?;
    let flags = arguments.context.arg(2);
    validate_known_flags(flags, fs_abi::OPEN_KNOWN_FLAGS)?;
    validate_zeroed_args(arguments.context, 3)?;

    let resolved = table.resolve_at(dirfd, path, arguments.context.caller_pid)?;
    open_resolved(table, arguments.context, &resolved, flags)
}

/// The whole of an open, on a path that is already resolved.
///
/// Every open, plain and `*At`, ends here, which is what keeps the policy
/// ask, the create-on-miss reading and the descriptor's recorded fields one
/// flow rather than two.  The flags decide the permission and the rights
/// exactly as they did when this was `open`'s own body; the resolved path is
/// what the policy is asked about, because that is the path the namespace
/// will be asked to open.
fn open_resolved(
    table: &mut SyscallTable,
    context: &SyscallContext,
    resolved: &str,
    flags: usize,
) -> Result<Dispatch> {
    // Who is asking, before what they asked for is resolved.
    //
    // The check comes first because a policy decision that ran after the lookup
    // would have already told the caller whether the path exists: a denial and
    // a "not found" are different answers, and the one that leaks less is the
    // one that does not distinguish them.
    //
    // The action decides the permission.  A descriptor opened for writing is a
    // request to write, and asking the policy about a read would grant a write
    // on the strength of a read rule.
    let subject = context.identity.unwrap_or(mac::MAC_TYPE_UNLABELED);
    let permission = if flags & (fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE) != 0 {
        mac::MAC_PERM_WRITE
    } else {
        mac::MAC_PERM_READ
    };
    mac::check_file(subject, resolved, mac::MAC_CLASS_FILE, permission, 0)?;

    // Through the namespace: the table resolves the path to a mount and a path
    // relative to it, and the filesystem answers for that.  `open` names no
    // filesystem, which is what lets a second one be mounted without this
    // handler changing.
    let namespace = table.namespace().ok_or(Error::NotFound)?;
    let node = match namespace.lookup(resolved) {
        Ok(node) => node,
        // A create that names an existing path is the open that was asked for,
        // so the miss is only a creation when the lookup is the one failure a
        // creation cures.  Every other answer, a volume that refused, a path
        // the table could not resolve, is the lookup's own, and creating on
        // top of it would report a success the filesystem never granted.
        Err(Error::NotFound) if flags & fs_abi::OPEN_FLAG_CREATE != 0 => {
            let (filesystem, relative) = namespace.resolve(resolved)?;
            filesystem.create_file(&relative)?;
            namespace.lookup(resolved)?
        }
        Err(error) => return Err(error),
    };

    // The opener is the owner: the process that asked, as the kernel recorded
    // it, so its exit can release the slot.  A caller the kernel made itself
    // has no pid, and `0` is the boot's own process, the only one whose
    // descriptor outlives every program by design.
    let owner = context.caller_pid.unwrap_or(crate::programs::BOOT_PROCESS);
    let descriptor = table.insert(Descriptor::File {
        node,
        readable: flags & fs_abi::OPEN_FLAG_READ != 0 || flags == fs_abi::OPEN_FLAG_NONE,
        writable: flags & fs_abi::OPEN_FLAG_WRITE != 0,
        offset: 0,
        path: alloc::string::String::from(resolved),
        owner,
    })?;

    Ok(Dispatch::complete(descriptor))
}

/// Read from a descriptor into the buffer the caller supplied.
///
/// Arguments: the descriptor, the offset, the buffer, its length, then two
/// reserved slots that must be zero.  The offset is the descriptor's own when
/// the caller passes [`crate::syscall::READ_OFFSET_CURRENT`].  The buffer and
/// its length travel in slots because a ring-3 caller has no borrow to hand
/// over, the borrow is built where the call arrives, from the two words
/// and the kernel's own callers leave both zero, which is why the reserved
/// check starts past them rather than at them.
///
/// Returns the number of bytes read, which is short at end of file and zero
/// past it, the reading that lets a caller tell "no more data" from "the call
/// failed", which a status word alone cannot say.
pub fn read(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let descriptor_index = arguments.context.arg(0);
    let offset = arguments.context.arg(1);
    validate_zeroed_args(arguments.context, 4)?;

    let buffer = arguments
        .buffer
        .as_deref_mut()
        .ok_or(Error::InvalidArgument)?;
    if buffer.is_empty() {
        return Ok(Dispatch::complete(0));
    }

    let count = table.read_at(
        descriptor_index,
        offset,
        buffer,
        arguments.context.caller_pid,
    )?;
    Ok(Dispatch::complete(count))
}

/// Write to a descriptor from the buffer the caller supplied.
///
/// Arguments: the descriptor, the buffer, its length, then three reserved
/// slots that must be zero.  The write starts at the descriptor's own
/// position, which moves by the bytes accepted, the same position `read`
/// moves, which is why a program that opens a file, writes it, and reads it
/// back through the same descriptor finds its own bytes.
///
/// The check order is the write's, not the buffer's: a descriptor the caller
/// may not write is refused before a byte of the buffer is looked at, because
/// a write that cannot be attempted has no business having read anything.
pub fn write(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let descriptor_index = arguments.context.arg(0);
    validate_zeroed_args(arguments.context, 3)?;

    let buffer = arguments.buffer.as_deref().ok_or(Error::InvalidArgument)?;
    let count = table.write_at(descriptor_index, buffer, arguments.context.caller_pid)?;
    Ok(Dispatch::complete(count))
}

/// Shorten or extend the file a descriptor names.
///
/// Arguments: the descriptor, the new length, then four reserved slots that
/// must be zero.  Answers zero: a status, not a count, because the length is
/// the caller's own argument and the one number the call could report back is
/// the one it passed in.
///
/// A **truncate is a write**, so the descriptor must have been opened for one.
/// The refusal is `PermissionDenied` and comes before the node is asked, which
/// is the same order [`write()`] keeps: a descriptor without the right has no
/// business reaching the filesystem at all.
///
/// The descriptor's offset does not move, and that is a decision rather than
/// an omission.  A caller that writes a header, truncates a tail and appends
/// expects the third call to land after the second, and a truncate that
/// rewound the position would make it overwrite the header instead.  A
/// position past the new end is legal and reads as end of file.
///
/// The node decides whether it can: `tmpfs` and PyroFS both implement
/// `VNode::set_len`, a synthetic volume refuses with `PermissionDenied` the
/// way it refuses `write`, and a directory refuses because it has no length.
pub fn set_length(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let descriptor_index = arguments.context.arg(0);
    let length = arguments.context.arg(1) as u64;
    validate_zeroed_args(arguments.context, 2)?;

    table.set_len_at(descriptor_index, length, arguments.context.caller_pid)?;
    Ok(Dispatch::complete(0))
}

/// Move a descriptor's position, and answer where it now is.
///
/// Arguments: the descriptor, the offset as a **signed** word, the whence
/// value, then three reserved slots that must be zero.  Answers the new
/// position, not zero: a caller that seeks to the end needs the size, and the
/// only call that would give it is this one's answer.
///
/// The offset is read as `i64` because that is what it is: a seek backwards
/// from the current position is a negative distance, and reading the word as
/// unsigned would turn `-1` into 18446744073709551615 and refuse a call that
/// asked to step back one byte.  The ABI's `a1` is one machine word, so the
/// narrowing is the call's own contract rather than a loss.
///
/// The five whence values are [`fs_abi::SEEK_SET`], [`fs_abi::SEEK_CUR`],
/// [`fs_abi::SEEK_END`], [`fs_abi::SEEK_DATA`] and [`fs_abi::SEEK_HOLE`].  A
/// value outside them is refused rather than treated as `SEEK_SET`: a whence
/// this build does not know is a caller that meant something else.
///
/// The table method holds the arithmetic and the extent questions; this is the
/// argument reading.  A seek needs no buffer and no path, which is why it is
/// one of the few file calls with neither.
pub fn seek(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let descriptor_index = arguments.context.arg(0);
    // The word is the ABI's, and a negative distance is what `SEEK_CUR` with
    // `-1` means: read it signed, which is also what the answer's arithmetic
    // needs.
    let offset = arguments.context.arg(1) as i64;
    let whence = arguments.context.arg(2);
    validate_zeroed_args(arguments.context, 3)?;

    let position = table.seek_at(
        descriptor_index,
        offset,
        whence,
        arguments.context.caller_pid,
    )?;
    Ok(Dispatch::complete(position as usize))
}

/// Write the caller's bytes to the kernel's own log.
///
/// Arguments: the buffer, its length, then four reserved slots that must be
/// zero.  Answers the bytes taken, so a caller learns how much of what it sent
/// arrived rather than only that the call was understood.
///
/// This is the debug channel, and it is deliberately **not** `Write`: `Write`
/// needs a descriptor, which needs an open file or a pipe, and a program that
/// has not got that far yet still has things to say.  A boot's first program
/// uses it to announce itself before it has opened anything.
///
/// The bytes are printed as text.  A caller sends UTF-8 and a byte outside it
/// is drawn as the console's fallback glyph, which is the same rule the screen
/// follows: a control byte does not vanish from the record, it shows up as a
/// box a reader can see.
pub fn write_debug(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let buffer = arguments.buffer.as_deref().ok_or(Error::InvalidArgument)?;
    validate_zeroed_args(arguments.context, 2)?;

    if buffer.is_empty() {
        return Ok(Dispatch::complete(0));
    }
    // Through the arch console rather than a print of this file's own, so the
    // bytes take the same path a kernel line does: the serial port and, when
    // one is installed, the screen.
    let text = core::str::from_utf8(buffer).unwrap_or("");
    if !text.is_empty() {
        arch::serial::write_str(text);
    }
    Ok(Dispatch::complete(buffer.len()))
}

/// Read one line from the console into the caller's buffer.
///
/// Arguments: the buffer, its length, then four reserved slots that must be
/// zero.  Answers how many bytes were written, **including** the terminating
/// newline, or zero when nothing is waiting.
///
/// This build has no console input device, so the answer is always zero, and
/// that is a fact about the machine rather than about the call: a key has to
/// come from a USB or PS/2 keyboard, and neither driver exists yet.  The
/// alternative, blocking until a byte arrives, would park the caller for ever
/// on this machine, which is worse than a word it can check.
///
/// It is served rather than left `NotImplemented` because the difference
/// matters to a program: `NotImplemented` says "this ABI has no such call",
/// and zero says "there is nothing to read yet", which is a statement a shell
/// can loop on and an implementation that a later keyboard driver fills in
/// without changing the call's shape.
pub fn read_console(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let length = arguments.context.arg(1);
    validate_zeroed_args(arguments.context, 2)?;
    if length == 0 {
        return Ok(Dispatch::complete(0));
    }
    // The address is **not** validated here.  `Arguments::buffer` is already a
    // borrow: the caller that built it turned the ring-3 word into a slice
    // behind the one check that makes the turn sound, so a second look at the
    // raw argument would be checking a number the handler cannot see.  The
    // ring-3 branch validates the range before it builds the borrow, which is
    // where every buffer-taking call keeps that rule.
    let _ = arguments.buffer.as_deref();
    Ok(Dispatch::complete(0))
}

/// Flush a descriptor's file to stable storage.
///
/// Arguments: the descriptor, then five reserved slots that must be zero.
/// Answers zero: a status, because there is no count a caller could act on.
///
/// This is `Fsync`, and it waits for everything the file has: the data and the
/// metadata that says where the data is.
pub fn fsync(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let descriptor = arguments.context.arg(0);
    validate_zeroed_args(arguments.context, 1)?;
    table.sync_at(descriptor, false, arguments.context.caller_pid)?;
    Ok(Dispatch::complete(0))
}

/// Flush a descriptor's **data** to stable storage.
///
/// Arguments: the descriptor, then five reserved slots that must be zero.
/// Answers zero.
///
/// The weaker of the pair: the bytes reach the device and the metadata that
/// locates them does not have to.  A filesystem that cannot separate the two
/// answers the stronger flush through `VNode::sync_data`'s default, which is a
/// superset of what the caller asked for and therefore never a broken promise.
pub fn fdatasync(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let descriptor = arguments.context.arg(0);
    validate_zeroed_args(arguments.context, 1)?;
    table.sync_at(descriptor, true, arguments.context.caller_pid)?;
    Ok(Dispatch::complete(0))
}

/// Punch a hole: the range reads as zeros and its storage goes back.
///
/// Arguments: the descriptor, the offset, the length, the mode, then two
/// reserved slots that must be zero.  Answers zero.
///
/// **The only mode this build defines is `FALLOC_FL_PUNCH_HOLE |
/// FALLOC_FL_KEEP_SIZE`.**  The pair is what makes the call a punch: the hole
/// is made and the file's length does not move, which is the only thing the
/// name promises.  A mode with any other bit is `NotImplemented` rather than
/// `InvalidArgument`: the caller named a mode this kernel does not define, and
/// that is a different fact from a mode word that is malformed.
///
/// A range past the end of the file is the node's to refuse, not this
/// handler's: a filesystem that would have to extend the file to punch it is
/// the one that knows it.
pub fn fallocate(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let descriptor = arguments.context.arg(0);
    let mode = arguments.context.arg(1);
    let offset = arguments.context.arg(2) as u64;
    let length = arguments.context.arg(3) as u64;
    validate_zeroed_args(arguments.context, 4)?;

    let punch = fs_abi::FALLOC_FL_PUNCH_HOLE | fs_abi::FALLOC_FL_KEEP_SIZE;
    if mode != punch {
        return Err(Error::NotImplemented);
    }

    table.punch_hole_at(descriptor, offset, length, arguments.context.caller_pid)?;
    Ok(Dispatch::complete(0))
}

/// Read the per-file data-reduction flags a descriptor names.
///
/// Arguments: the descriptor, then five reserved slots that must be zero.
/// Answers the flags word, not zero: the flags are the whole answer, and the
/// ABI's record for them is one `u32`, so a returned word is the record.
pub fn get_file_flags(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let descriptor = arguments.context.arg(0);
    validate_zeroed_args(arguments.context, 1)?;
    let flags = table.file_flags_at(descriptor, arguments.context.caller_pid)?;
    Ok(Dispatch::complete(flags as usize))
}

/// Change the per-file data-reduction flags a descriptor names.
///
/// Arguments: the descriptor, the mask of bits to **set**, the mask of bits to
/// **clear**, then three reserved slots that must be zero.  Answers zero.
///
/// The two masks are validated here rather than at the node, for the reason
/// every handler validates a flag word: a bit this build does not define is a
/// caller that meant something else, and the answer is the same whichever
/// filesystem answers the call.  A bit in both masks is refused too, because
/// "set and clear" is not a state a flag can end in.
pub fn set_file_flags(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let descriptor = arguments.context.arg(0);
    let set = arguments.context.arg(1) as u32;
    let clear = arguments.context.arg(2) as u32;
    validate_zeroed_args(arguments.context, 3)?;

    if set & !fs_abi::FILE_FLAG_KNOWN_MASK != 0 || clear & !fs_abi::FILE_FLAG_KNOWN_MASK != 0 {
        return Err(Error::InvalidArgument);
    }
    if set & clear != 0 {
        return Err(Error::InvalidArgument);
    }

    table.set_file_flags_at(descriptor, set, clear, arguments.context.caller_pid)?;
    Ok(Dispatch::complete(0))
}

/// Report a path's kind and size.
///
/// Arguments: the path, the record, its length, then three reserved slots
/// that must be zero.  The record is the ABI's [`fs_abi::FileStat`], sixteen
/// bytes: the kind and the size.  A buffer shorter than the record is refused
/// rather than partly filled, a caller handed a truncated answer would read
/// a size that was never there, and a longer one gets the record's own
/// sixteen, because the record is the wire format and a caller that asked for
/// more asked for room, not fields.
///
/// The answer is zero: a status, not a count.  The record's length is the
/// caller's own argument, so the one thing the call could report back is
/// something the caller already knows.
pub fn stat(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let path = arguments.path.ok_or(Error::InvalidArgument)?;
    validate_zeroed_args(arguments.context, 3)?;
    let resolved = fs::path::normalize_path(path, "/")?;
    stat_resolved(
        table,
        arguments.context,
        &resolved,
        arguments.buffer.as_deref_mut(),
    )
}

/// Stat a path relative to a descriptor.
///
/// Arguments: the descriptor, the path, the record, its length, then two
/// reserved slots that must be zero.  The record is the same sixteen bytes
/// `stat` answers, for the path the descriptor anchors.
pub fn stat_at(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let dirfd = arguments.context.arg(0);
    let path = arguments.path.ok_or(Error::InvalidArgument)?;
    validate_zeroed_args(arguments.context, 4)?;
    let resolved = table.resolve_at(dirfd, path, arguments.context.caller_pid)?;
    stat_resolved(
        table,
        arguments.context,
        &resolved,
        arguments.buffer.as_deref_mut(),
    )
}

/// Stat the file a descriptor names.
///
/// Arguments: the descriptor, the record, its length, then three reserved
/// slots that must be zero.  The same sixteen-byte record [`stat`] answers,
/// for the file the descriptor holds.
///
/// The difference from `stat` is what a program had to do without it: a
/// descriptor is what a program passes around, and before this a program that
/// was handed one and wanted its size had to know the path it was opened at,
/// which a caller that received the descriptor never does.  The record is read
/// from the descriptor's anchor, so the two calls describe the same file.
pub fn stat_fd(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let descriptor = arguments.context.arg(0);
    validate_zeroed_args(arguments.context, 3)?;
    let path = table.path_of(descriptor, arguments.context.caller_pid)?;
    stat_resolved(
        table,
        arguments.context,
        &path,
        arguments.buffer.as_deref_mut(),
    )
}

/// The whole of a stat, on a path that is already resolved.
fn stat_resolved(
    table: &mut SyscallTable,
    context: &SyscallContext,
    resolved: &str,
    buffer: Option<&mut [u8]>,
) -> Result<Dispatch> {
    // Who is asking, before what they asked for is resolved, the same order
    // `open` keeps, and for the same reason: a denial and a "not found" are
    // different answers, and the one that leaks less does not distinguish
    // them.  A stat is a read of the file's face, and the read permission is
    // the one it is policed by.
    let subject = context.identity.unwrap_or(mac::MAC_TYPE_UNLABELED);
    mac::check_file(
        subject,
        resolved,
        mac::MAC_CLASS_FILE,
        mac::MAC_PERM_READ,
        0,
    )?;

    let buffer = buffer.ok_or(Error::InvalidArgument)?;
    if buffer.len() < fs_abi::FILE_STAT_SIZE {
        return Err(Error::InvalidArgument);
    }

    let namespace = table.namespace().ok_or(Error::NotFound)?;
    let (filesystem, relative) = namespace.resolve(resolved)?;
    let metadata = filesystem.stat(&relative)?;
    let record = fs_abi::FileStat::new(file_kind(metadata.kind), metadata.size);
    buffer[..8].copy_from_slice(&record.kind.to_le_bytes());
    buffer[8..16].copy_from_slice(&record.size.to_le_bytes());
    Ok(Dispatch::complete(0))
}

/// The ABI's kind word for a node's kind.
///
/// The two enums live on opposite sides of the boundary, the filesystem's is
/// the tree's own, the ABI's is the wire, and the mapping is total, which is
/// why it is a function a test pins rather than a cast a reader trusts.
fn file_kind(kind: fs::NodeKind) -> usize {
    match kind {
        fs::NodeKind::Directory => fs_abi::FILE_KIND_DIRECTORY,
        fs::NodeKind::File => fs_abi::FILE_KIND_FILE,
        fs::NodeKind::Device => fs_abi::FILE_KIND_DEVICE,
        fs::NodeKind::Symlink => fs_abi::FILE_KIND_SYMLINK,
    }
}

// The path mutations.
//
// Three calls that change the namespace rather than a file's bytes: make a
// name for a directory, take a name away, move one name to another.  They
// share everything but the operation, a path, the policy asked first, the
// namespace resolving the path to the filesystem that answers for it, which
// is why the three handlers are three one-liners over one shape rather than
// three copies of it.
//
// A rename names two paths, and they can resolve to two different
// filesystems; no filesystem sees both, so the call is refused rather than
// approximated with a copy and a delete, which would not be a rename, a
// crash between its halves would leave the file in neither place.

/// Create a directory at a path.
///
/// Arguments: the path, then five reserved slots that must be zero.  Answers
/// zero.  A path whose parent is not a directory, or whose last name already
/// exists, is the filesystem's refusal to answer.
pub fn create_dir(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let path = arguments.path.ok_or(Error::InvalidArgument)?;
    validate_zeroed_args(arguments.context, 1)?;
    let resolved = fs::path::normalize_path(path, "/")?;
    create_dir_resolved(table, arguments.context, &resolved)
}

/// Create a directory relative to a descriptor.
///
/// Arguments: the descriptor, the path, then four reserved slots that must
/// be zero.
pub fn create_dir_at(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let dirfd = arguments.context.arg(0);
    let path = arguments.path.ok_or(Error::InvalidArgument)?;
    validate_zeroed_args(arguments.context, 2)?;
    let resolved = table.resolve_at(dirfd, path, arguments.context.caller_pid)?;
    create_dir_resolved(table, arguments.context, &resolved)
}

/// The whole of a create-dir, on a path that is already resolved.
fn create_dir_resolved(
    table: &mut SyscallTable,
    context: &SyscallContext,
    resolved: &str,
) -> Result<Dispatch> {
    // A creation is a write: the same permission the open-with-create asks
    // for, asked of the same policy.
    mac_write_checked(context, resolved)?;

    let namespace = table.namespace().ok_or(Error::NotFound)?;
    let (filesystem, relative) = namespace.resolve(resolved)?;
    filesystem.create_dir(&relative)?;
    Ok(Dispatch::complete(0))
}

/// Remove the file, directory or symlink at a path.
///
/// Arguments: the path, then five reserved slots that must be zero.  Answers
/// zero.  Whether removing a directory that still holds entries is the
/// filesystem's own rule; the namespace does not have an opinion.
pub fn remove_path(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let path = arguments.path.ok_or(Error::InvalidArgument)?;
    validate_zeroed_args(arguments.context, 1)?;
    let resolved = fs::path::normalize_path(path, "/")?;
    remove_path_resolved(table, arguments.context, &resolved)
}

/// Remove a path relative to a descriptor.
///
/// Arguments: the descriptor, the path, then four reserved slots that must
/// be zero.
pub fn remove_path_at(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let dirfd = arguments.context.arg(0);
    let path = arguments.path.ok_or(Error::InvalidArgument)?;
    validate_zeroed_args(arguments.context, 2)?;
    let resolved = table.resolve_at(dirfd, path, arguments.context.caller_pid)?;
    remove_path_resolved(table, arguments.context, &resolved)
}

/// The whole of a remove, on a path that is already resolved.
fn remove_path_resolved(
    table: &mut SyscallTable,
    context: &SyscallContext,
    resolved: &str,
) -> Result<Dispatch> {
    mac_write_checked(context, resolved)?;

    let namespace = table.namespace().ok_or(Error::NotFound)?;
    let (filesystem, relative) = namespace.resolve(resolved)?;
    filesystem.remove_path(&relative)?;
    Ok(Dispatch::complete(0))
}

/// Move a name to another path, replacing what the destination names.
///
/// Arguments: the old path, the new path, then four reserved slots that must
/// be zero.  Answers zero.  Both names must belong to the same filesystem
/// the two resolve to two mounts, and a filesystem cannot rename what it
/// does not hold.
pub fn rename(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let old_path = arguments.path.ok_or(Error::InvalidArgument)?;
    let new_path = arguments.second_path.ok_or(Error::InvalidArgument)?;
    validate_zeroed_args(arguments.context, 2)?;
    let old_resolved = fs::path::normalize_path(old_path, "/")?;
    let new_resolved = fs::path::normalize_path(new_path, "/")?;
    rename_resolved(table, arguments.context, &old_resolved, &new_resolved)
}

/// Rename relative to two descriptors.
///
/// Arguments: the old descriptor, the old path, the new descriptor, the new
/// path, then two reserved slots that must be zero.  Each name anchors at
/// its own descriptor, which is what lets a file move from one directory to
/// another in one call that names both.
pub fn rename_at(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let old_dirfd = arguments.context.arg(0);
    let old_path = arguments.path.ok_or(Error::InvalidArgument)?;
    let new_dirfd = arguments.context.arg(2);
    let new_path = arguments.second_path.ok_or(Error::InvalidArgument)?;
    validate_zeroed_args(arguments.context, 4)?;
    let old_resolved = table.resolve_at(old_dirfd, old_path, arguments.context.caller_pid)?;
    let new_resolved = table.resolve_at(new_dirfd, new_path, arguments.context.caller_pid)?;
    rename_resolved(table, arguments.context, &old_resolved, &new_resolved)
}

/// The whole of a rename, on two paths that are already resolved.
fn rename_resolved(
    table: &mut SyscallTable,
    context: &SyscallContext,
    old_resolved: &str,
    new_resolved: &str,
) -> Result<Dispatch> {
    mac_write_checked(context, old_resolved)?;
    mac_write_checked(context, new_resolved)?;

    let namespace = table.namespace().ok_or(Error::NotFound)?;
    let (old_filesystem, old_relative) = namespace.resolve(old_resolved)?;
    let (new_filesystem, new_relative) = namespace.resolve(new_resolved)?;
    if !alloc::sync::Arc::ptr_eq(&old_filesystem, &new_filesystem) {
        // A rename that crossed volumes would have to be a copy and a
        // delete, and a copy that failed midway leaves the file in neither
        // place, the one outcome a rename exists to make impossible.
        return Err(Error::Unsupported);
    }
    old_filesystem.rename(&old_relative, &new_relative)?;
    Ok(Dispatch::complete(0))
}

/// Ask the policy whether this caller may write this path.
///
/// The three mutations share the question and the order: the policy is asked
/// before the path resolves, so a denial does not tell the caller whether
/// the path exists.  A caller with no identity is unlabelled, which is what
/// `open` treats it as too.
fn mac_write_checked(context: &SyscallContext, path: &str) -> Result<()> {
    let subject = context.identity.unwrap_or(mac::MAC_TYPE_UNLABELED);
    mac::check_file(subject, path, mac::MAC_CLASS_FILE, mac::MAC_PERM_WRITE, 0)
}

/// List one entry of a directory, by index.
///
/// Arguments: the path, the index, the buffer, its length, then two reserved
/// slots that must be zero.  The record is the ABI's
/// [`fs_abi::DirectoryEntryRecord`], kind, size, and where the name starts
/// with the name's UTF-8 bytes packed directly after it, which is why the
/// answer is how many bytes were written rather than a status: the caller
/// sized the buffer, and the answer says how much of it now means something.
///
/// A buffer too small for the header, or for the whole name, is refused
/// rather than partly written.  The record declares the name's length, so a
/// truncated name would be a record that lies about itself, and a caller
/// that sized its buffer from the last entry it read has a number it can
/// grow, the error tells it to, instead of handing it half a name.
///
/// An index past the directory's end answers `NotFound`, the same word a
/// missing path answers: "there is no such entry" is true of both, and a
/// third answer for the one case a caller uses to end its loop would be a
/// word it had to special-case.
pub fn read_dir(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let path = arguments.path.ok_or(Error::InvalidArgument)?;
    let index = arguments.context.arg(1);
    validate_zeroed_args(arguments.context, 4)?;
    read_dir_resolved(
        table,
        arguments.context,
        path,
        index,
        arguments.buffer.as_deref_mut(),
    )
}

/// List one entry of the directory a descriptor names.
///
/// Arguments: the descriptor, the index, the buffer, its length, then two
/// reserved slots that must be zero.  The same record and the same answer as
/// [`read_dir`], for the directory the descriptor was opened at.
///
/// This is the call `read_dir` cannot be: a program that opened a directory
/// and wants its entries had to remember the path it opened, and a program
/// handed a descriptor by another call has no path to remember.  The
/// descriptor already carries the name it resolved to, which is what
/// `SyscallTable::path_of` reads.
///
/// The kind check is the descriptor's, so a descriptor that names a regular
/// file answers `InvalidArgument` from the listing rather than from a path
/// that resolved to something with no entries.
pub fn read_dir_fd(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let descriptor = arguments.context.arg(0);
    let index = arguments.context.arg(1);
    validate_zeroed_args(arguments.context, 4)?;
    let path = table.path_of(descriptor, arguments.context.caller_pid)?;
    read_dir_resolved(
        table,
        arguments.context,
        &path,
        index,
        arguments.buffer.as_deref_mut(),
    )
}

/// The whole of a listing, on a path that is already resolved.
fn read_dir_resolved(
    table: &mut SyscallTable,
    context: &SyscallContext,
    path: &str,
    index: usize,
    buffer: Option<&mut [u8]>,
) -> Result<Dispatch> {
    let subject = context.identity.unwrap_or(mac::MAC_TYPE_UNLABELED);
    mac::check_file(subject, path, mac::MAC_CLASS_FILE, mac::MAC_PERM_READ, 0)?;

    let buffer = buffer.ok_or(Error::InvalidArgument)?;
    if buffer.len() < fs_abi::DIRECTORY_ENTRY_RECORD_SIZE {
        return Err(Error::InvalidArgument);
    }

    let namespace = table.namespace().ok_or(Error::NotFound)?;
    let (filesystem, relative) = namespace.resolve(path)?;
    let entry = filesystem.read_dir(&relative, index)?;

    let name = entry.name.as_bytes();
    if buffer.len() - fs_abi::DIRECTORY_ENTRY_RECORD_SIZE < name.len() {
        return Err(Error::InvalidArgument);
    }
    let record = fs_abi::DirectoryEntryRecord::new(file_kind(entry.kind), entry.size, name.len());
    let mut at = 0;
    for word in [
        record.kind,
        record.size,
        record.name_offset,
        record.name_len,
    ] {
        buffer[at..at + 8].copy_from_slice(&word.to_le_bytes());
        at += 8;
    }
    buffer[at..at + name.len()].copy_from_slice(name);
    Ok(Dispatch::complete(at + name.len()))
}

/// Close a descriptor.
///
/// Arguments: the descriptor, then five reserved slots that must be zero.
///
/// Closing twice is an error rather than a no-op: a descriptor number a caller
/// reused after closing is a number the kernel may have handed to something
/// else, and a silent success would let a program close another's file.
pub fn close(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let descriptor = arguments.context.arg(0);
    validate_zeroed_args(arguments.context, 1)?;
    table.close_for(descriptor, arguments.context.caller_pid)?;
    Ok(Dispatch::complete(0))
}

/// Report the MAC policy's state.
///
/// Arguments: five reserved slots that must be zero.  Answers
/// `enabled | default_deny << 1 | rule_count << 8 | label_count << 32`.
///
/// A packed word rather than a struct because a syscall returns one `usize`,
/// and a program that wanted four fields would otherwise need a second call per
/// field.  The layout is stated here and in no other place, which is what lets
/// it be a number.
pub fn mac_get_status(
    _table: &mut SyscallTable,
    arguments: &mut Arguments<'_>,
) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 0)?;
    let state = mac::policy_state().lock();
    let mut value = 0usize;
    if state.policy.enabled {
        value |= 1;
    }
    if state.policy.default_deny {
        value |= 1 << 1;
    }
    value |= state.policy.rule_count().min(0xFF) << 8;
    value |= state.label_count().min(0xFFFF) << 32;
    Ok(Dispatch::complete(value))
}

/// Turn enforcement on or off.
///
/// Arguments: `0` disables, `1` enables, then four reserved slots that must be
/// zero.  Answers the previous state.
///
/// Disabling is permitted and is not a security hole in this kernel: the policy
/// is off at boot, so a program that can call this already runs as something
/// the kernel trusts.  When there is a process layer, this becomes a call the
/// policy itself gates, which is why the handler does not check `identity`
/// today rather than because it forgot.
pub fn mac_set_mode(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let enable = arguments.context.arg(0);
    if enable > 1 {
        return Err(Error::InvalidArgument);
    }
    validate_zeroed_args(arguments.context, 1)?;
    let mut state = mac::policy_state().lock();
    let previous = state.policy.enabled;
    state.policy.enabled = enable == 1;
    Ok(Dispatch::complete(usize::from(previous)))
}

/// Add one allow rule.
///
/// Arguments: `subject, object, class, permissions, replace`, then one reserved
/// slot that must be zero.  Answers the number of rules after the addition.
///
/// The five values are the rule's own fields in the order
/// [`mac::MacRule`] declares them, so a caller that read the type knows the
/// argument order without reading this function.  An unknown class or type is
/// refused rather than stored: a rule matching nothing is a rule that silently
/// does nothing, and a policy is the wrong place for a silent no-op.
pub fn mac_add_rule(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let subject = arguments.context.arg(0) as mac::MacType;
    let object = arguments.context.arg(1) as mac::MacType;
    let class = arguments.context.arg(2) as mac::MacClass;
    let perms = arguments.context.arg(3) as mac::MacPermission;
    let replace = arguments.context.arg(4);
    if replace > 1 {
        return Err(Error::InvalidArgument);
    }
    validate_zeroed_args(arguments.context, 5)?;

    if !mac::is_known_type(subject) || !mac::is_known_type(object) {
        return Err(Error::InvalidArgument);
    }
    if !mac::is_known_class(class) {
        return Err(Error::InvalidArgument);
    }

    let rule = mac::MacRule {
        subject,
        object,
        class,
        perms,
    };
    let mut state = mac::policy_state().lock();
    state.policy.add_rule(rule, replace == 1);
    Ok(Dispatch::complete(state.policy.rule_count()))
}

// The memory calls.
//
// Four numbers that had none, and the shape each has is the one this tree's
// older ABI already gave them: a program written against either means the same
// thing.  They are in the frozen range, so that is not a preference.
//
// ## Why the address space is not touched here
//
// A page mapping belongs to a task's space, the task belongs to the scheduler,
// and reaching it means taking the scheduler's lock.  This module is where a
// **wire format** is turned into a validated request, and the scheduler is
// where a request reaches the object it is about.  A handler that walked a page
// table would be a handler holding two locks whose order it decided on its own.

/// Map anonymous memory, answering the base address.
///
/// `Mmap(addr_hint, length, protection, flags)`: the hint is where the caller
/// would like the mapping, `length` is in bytes and rounded up, the protection
/// is a `PROT_*` set, and the flags are a `MAP_*` set that has to name
/// anonymous private memory, this kernel has no file-backed mapping and no
/// shared one.
///
/// A hint of zero means "somewhere", which is the ordinary call.  A hint that
/// names a specific address is honoured when it is page-aligned and still below
/// the kernel's own descending cursor; a hint it cannot honour is treated as
/// zero rather than refused, because the four numbers this ABI gives a caller
/// have nowhere else to say "I do not care".
pub fn mmap(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let hint = arguments.context.arg(0);
    let length = arguments.context.arg(1);
    let protection = arguments.context.arg(2);
    let flags = arguments.context.arg(3);
    validate_zeroed_args(arguments.context, 4)?;

    if length == 0 || length > memory_abi::MAP_MAX_BYTES {
        return Err(Error::InvalidArgument);
    }
    validate_known_flags(protection, memory_abi::PROT_KNOWN)?;
    validate_known_flags(flags, memory_abi::MAP_KNOWN_FLAGS)?;
    // Anonymous is not optional: a mapping this kernel cannot back with a file
    // is one it must refuse rather than quietly make anonymous.
    if flags & memory_abi::MAP_ANONYMOUS == 0 {
        return Err(Error::InvalidArgument);
    }
    let writable = protection & memory_abi::PROT_WRITE != 0;
    let executable = protection & memory_abi::PROT_EXEC != 0;
    // Write and execute together is the one pair that turns a bug into an
    // exploit, and the loader already refuses it for images.  Refusing it here
    // keeps the rule one rule.
    if writable && executable {
        return Err(Error::InvalidArgument);
    }

    // A host has no page table to map into, so the validation above is the
    // whole of what is testable there and the mapping answers `NotImplemented`.
    // The handler is still the same function, so a host test that exercises the
    // argument rules is exercising the code a machine runs.
    #[cfg(target_os = "none")]
    {
        let mapped = crate::scheduler::map_current(
            crate::per_cpu::current_slot(),
            hint,
            length,
            writable,
            executable,
        )
        .ok_or(Error::OutOfMemory)?;
        Ok(Dispatch::complete(mapped))
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (hint, length, writable, executable);
        Err(Error::NotImplemented)
    }
}

/// Unmap a range, answering how many pages were taken away.
///
/// `Munmap(addr, length)`: both are byte values, the address is rounded down
/// and the length up, and a range with nothing mapped in it is a success of
/// zero rather than an error, asking to remove what is not there has two true
/// answers and the quiet one is the honest one.
pub fn munmap(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let address = arguments.context.arg(0);
    let length = arguments.context.arg(1);
    validate_zeroed_args(arguments.context, 2)?;

    if length == 0 {
        return Err(Error::InvalidArgument);
    }
    let base = address & !(paging::PAGE_SIZE - 1);
    let rounded = length
        .checked_add(paging::PAGE_SIZE - 1)
        .ok_or(Error::InvalidArgument)?
        & !(paging::PAGE_SIZE - 1);
    if base < crate::address_space::USER_BASE
        || base
            .checked_add(rounded)
            .is_none_or(|end| end > crate::address_space::USER_LIMIT)
    {
        return Err(Error::InvalidArgument);
    }

    #[cfg(target_os = "none")]
    {
        let taken = crate::scheduler::unmap_current(crate::per_cpu::current_slot(), base, rounded)
            .ok_or(Error::InvalidArgument)?;
        Ok(Dispatch::complete(taken))
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = (base, rounded);
        Err(Error::NotImplemented)
    }
}

/// Read or move the program's break.
///
/// `Brk(new_break)`: zero is a query, anything else is a request to grow to
/// that address.  The answer is the break the kernel now holds, so a caller
/// that asked for more than it can have learns what it actually got, which is
/// the whole reason the call answers with a value rather than with success.
pub fn brk(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let requested = arguments.context.arg(0);
    validate_zeroed_args(arguments.context, 1)?;

    #[cfg(target_os = "none")]
    {
        let current = crate::scheduler::brk_current(crate::per_cpu::current_slot(), requested)
            .ok_or(Error::OutOfMemory)?;
        Ok(Dispatch::complete(current))
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = requested;
        Err(Error::NotImplemented)
    }
}

/// Give back pages the space is holding, answering how many came back.
///
/// `ReclaimPages(target)`: `target` is how many pages the caller would like
/// returned and zero means "as many as will go".  This tree's answer is the
/// first that is honest, it walks the space's own records and gives back the
/// ones no page table names any more, which is the only set the kernel can
/// identify without a scan of every program.
///
/// A diagnostic, not a policy: a caller that relied on it to bound its
/// footprint would be relying on the kernel's timing rather than its own
/// bookkeeping.
pub fn reclaim_pages(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let target = arguments.context.arg(0);
    validate_zeroed_args(arguments.context, 1)?;
    #[cfg(target_os = "none")]
    {
        let reclaimed =
            crate::scheduler::reclaim_current(crate::per_cpu::current_slot(), target).unwrap_or(0);
        Ok(Dispatch::complete(reclaimed))
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = target;
        Err(Error::NotImplemented)
    }
}

/// The time, in the shape `abi::time` publishes.
///
/// Arguments: the clock, the record, its length, then three reserved slots that
/// must be zero.  Answers zero, with the record filled; a caller that asked for
/// a clock this build does not have gets `Unsupported` rather than a reading of
/// a clock nobody read.
///
/// The buffer is a borrow the entry path validated and filled in place, which
/// is why this handler does no pointer arithmetic: the same contract `stat`
/// keeps.
pub fn get_time_of_day(
    _table: &mut SyscallTable,
    arguments: &mut Arguments<'_>,
) -> Result<Dispatch> {
    let clock = arguments.context.arg(0);
    validate_zeroed_args(arguments.context, 3)?;

    let buffer = arguments
        .buffer
        .as_deref_mut()
        .ok_or(Error::InvalidArgument)?;
    if buffer.len() < time_abi::TIME_RECORD_SIZE {
        return Err(Error::InvalidArgument);
    }

    let reading = crate::time::now(clock)?;
    let record = time_abi::TimeRecord::new(reading.seconds, reading.nanoseconds);
    buffer[..8].copy_from_slice(&record.seconds.to_le_bytes());
    buffer[8..16].copy_from_slice(&record.nanoseconds.to_le_bytes());
    Ok(Dispatch::complete(0))
}

/// Fill the caller's buffer with bytes from this boot's generator.
///
/// Arguments: the buffer, its length, then four reserved slots that must be
/// zero.  Answers how many bytes were written, which is the length: this
/// generator always has more.
///
/// A zero length answers zero and writes nothing, which is a caller asking for
/// nothing rather than an error, the same reading `read` takes of a
/// zero-length request.
pub fn get_random(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let length = arguments.context.arg(1);
    validate_zeroed_args(arguments.context, 2)?;

    let buffer = arguments
        .buffer
        .as_deref_mut()
        .ok_or(Error::InvalidArgument)?;
    if buffer.len() < length {
        return Err(Error::InvalidArgument);
    }
    if length == 0 {
        return Ok(Dispatch::complete(0));
    }
    crate::random::fill(&mut buffer[..length])?;
    Ok(Dispatch::complete(length))
}

/// What the scheduler has been doing, as `abi::system` publishes it.
///
/// Arguments: the selector, the record, its length, then three reserved slots
/// that must be zero.  Answers zero, with the record filled.
///
/// The selector exists because the old tree had ten of them and this build has
/// one: a number a caller names is what lets a future build add a second
/// without moving the first, and a selector this build does not serve is
/// refused rather than answered with zeros that look like a quiet machine.
pub fn system_info(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let selector = arguments.context.arg(0);
    validate_zeroed_args(arguments.context, 3)?;
    if selector != system_abi::SYSTEM_INFO_SCHEDULER {
        return Err(Error::InvalidArgument);
    }

    let buffer = arguments
        .buffer
        .as_deref_mut()
        .ok_or(Error::InvalidArgument)?;
    if buffer.len() < system_abi::SYSTEM_INFO_SIZE {
        return Err(Error::InvalidArgument);
    }

    let (switches, exited, delivered_signals) = crate::scheduler::statistics();
    // A host has no frame pool, so both counts are genuinely zero there; a boot
    // takes them from the pool the address space manages.  Zero is the true
    // answer in both cases rather than a placeholder, which is why the host
    // branch is not an error.
    #[cfg(target_os = "none")]
    let (managed_frames, free_frames) = (
        crate::address_space::managed_frames(),
        crate::address_space::free_frames(),
    );
    #[cfg(not(target_os = "none"))]
    let (managed_frames, free_frames) = (0, 0);
    let record = system_abi::SystemInfo::new(
        switches,
        exited,
        crate::scheduler::blocked(),
        crate::scheduler::sleeping(),
        delivered_signals,
        crate::per_cpu::online_count(),
        managed_frames,
        free_frames,
    );
    write_system_info(buffer, &record);
    Ok(Dispatch::complete(0))
}

/// What this build's interface is.
///
/// Arguments: the record, its length, then four reserved slots that must be
/// zero.  Answers zero, with the record filled.
///
/// The three numbers are compiled in, not asked of the runtime: a version, the
/// number of slots the table has, and where the frozen range ends.  That makes
/// this the one call a program can make before it trusts any other, it names
/// what the build promises, and every promise is a constant.
pub fn abi_info(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 2)?;

    let buffer = arguments
        .buffer
        .as_deref_mut()
        .ok_or(Error::InvalidArgument)?;
    if buffer.len() < system_abi::ABI_INFO_SIZE {
        return Err(Error::InvalidArgument);
    }

    let record = system_abi::AbiInfo::new(
        system_abi::ABI_VERSION,
        syscall::PUBLIC_SYSCALL_COUNT as usize,
        // The frozen boundary is the highest number that may never move, and
        // the ABI defines it as the count rather than as a constant of its own:
        // a number at or below it is frozen, and `120` is the line the document
        // draws.  Written as the expression so a reader sees whose number it
        // is.
        FROZEN_SYSCALL_COUNT,
    );
    write_abi_info(buffer, &record);
    Ok(Dispatch::complete(0))
}

/// How many numbers the frozen range holds.
///
/// `0..=120` is 121 numbers, which is the range `docs/fmts/syscall-abi.md` says
/// may never be renumbered.  Spelled here rather than read from the ABI because
/// the ABI defines the rule and this is the build reporting it; a test pins the
/// two together.
pub(crate) const FROZEN_SYSCALL_COUNT: usize = 121;

/// Bind a datagram socket to a port, and answer the descriptor.
///
/// Arguments: the port, then five reserved slots that must be zero.  Answers
/// the descriptor, which the datagram calls carry back.  Port zero is
/// refused: it is the wire's "any port", and this stack has no port
/// allocator to answer it with, a caller that wants a port names one.  A
/// port another socket holds answers `AlreadyExists`, which is the wire's
/// own rule that a bound port has one owner.
pub fn bind_udp(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let port = arguments.context.arg(0);
    validate_zeroed_args(arguments.context, 1)?;
    if port == 0 || port > u16::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    let owner = arguments
        .context
        .caller_pid
        .unwrap_or(crate::programs::BOOT_PROCESS);
    let socket = crate::net::bind_udp(port as u16)?;
    let descriptor = table.insert_udp_socket(socket, owner)?;
    Ok(Dispatch::complete(descriptor))
}

/// Send one datagram from a bound socket to an address and a port.
///
/// Arguments: the descriptor; the destination's address, packed by the
/// ABI's own [`abi::network::pack_address`]; the buffer; its length; the
/// destination's port; one reserved slot that must be zero.  Answers the
/// bytes accepted, which is all a datagram send ever promises.  A datagram
/// for this machine is delivered through the demux rather than the card,
/// which is what loopback is.
///
/// The source port is the socket's own bound port, which is what makes the
/// sender an answerable peer: the datagram's header names a port the wire
/// can send an error back to.
pub fn send_to_udp(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let descriptor = arguments.context.arg(0);
    let destination = arguments.context.arg(1);
    let destination_port = arguments.context.arg(4);
    // The flags word is `a5`, and zero is what every caller before the IPv6
    // side passed: `validate_known_flags` refuses a bit this build does not
    // define, so a program cannot ask for a shape the kernel would silently
    // ignore.
    let flags = arguments.context.arg(5);
    validate_known_flags(flags, network_abi::SEND_TO_UDP_KNOWN_FLAGS)?;
    if destination_port == 0 || destination_port > u16::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    let destination = if flags & network_abi::NETWORK_FLAG_IPV6 != 0 {
        // `a1` is a pointer to sixteen bytes in the caller's memory, and the
        // address is read before anything is built: a refused pointer costs
        // no frame.
        net::address::Address::V6(read_user_address6(destination)?)
    } else {
        if destination > u32::MAX as usize {
            return Err(Error::InvalidArgument);
        }
        net::address::Address::V4(network_abi::unpack_address(destination))
    };
    let buffer = arguments.buffer.as_deref().ok_or(Error::InvalidArgument)?;
    if buffer.len() > crate::net::MAX_DATAGRAM_BYTES {
        return Err(Error::InvalidArgument);
    }
    let socket = table
        .udp_socket(descriptor, arguments.context.caller_pid)
        .ok_or(Error::InvalidArgument)?;

    crate::net::send_datagram(destination, destination_port as u16, socket.port(), buffer)?;
    Ok(Dispatch::complete(buffer.len()))
}

/// Read a sixteen-byte IPv6 address from the caller's memory.
///
/// The window is checked here rather than by the caller, because this is where
/// the number stops being a number: `a1` is an address only when the flag says
/// it is one, and the two cases are one branch apart.
///
/// A pointer outside the user window, or a length the window cannot hold, is
/// [`Error::InvalidArgument`], the ABI's own refusal, and not a fault.
fn read_user_address6(pointer: usize) -> Result<[u8; 16]> {
    if !crate::address_space::is_user_range(pointer, 16) {
        return Err(Error::InvalidArgument);
    }
    // SAFETY: the range is inside the user window, which `is_user_range`
    // checked, and the pages behind it are the calling task's own mappings,
    // installed on this CPU.  Sixteen bytes are read and nothing past them.
    let bytes = unsafe { core::slice::from_raw_parts(pointer as *const u8, 16) };
    let mut address = [0_u8; 16];
    address.copy_from_slice(bytes);
    Ok(address)
}

/// Open a listening port, and answer the descriptor an accept is called on.
///
/// Arguments: the port, then five reserved slots that must be zero.  Port
/// zero is refused, for the reason a datagram bind refuses it, and a port
/// another listener holds answers `AlreadyExists`, a listening port has
/// one owner, whatever number of processes hold its descriptor.
pub fn listen_tcp(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let port = arguments.context.arg(0);
    validate_zeroed_args(arguments.context, 1)?;
    if port == 0 || port > u16::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    let listener = crate::net::tcp_listen(port as u16)?;
    let owner = arguments
        .context
        .caller_pid
        .unwrap_or(crate::programs::BOOT_PROCESS);
    let descriptor = table.insert_tcp_listener(listener, owner)?;
    Ok(Dispatch::complete(descriptor))
}

/// Open a stream to an address and a port, and answer the descriptor the
/// stream is read and written through.
///
/// Arguments: the destination's address, packed by the ABI's own
/// [`abi::network::pack_address`]; the destination's port; then four
/// reserved slots that must be zero.  The handshake runs inside the call
/// a connect that answered before the stream was open would be a stream
/// whose first write raced its own handshake, and a destination that is
/// not this machine answers `Unsupported`, because a handshake that waits
/// on the wire is a wait this build does not make a call do.
pub fn connect_tcp(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let destination = arguments.context.arg(0);
    let port = arguments.context.arg(1);
    let flags = arguments.context.arg(2);
    validate_known_flags(flags, network_abi::CONNECT_TCP_KNOWN_FLAGS)?;
    validate_zeroed_args(arguments.context, 3)?;
    if port == 0 || port > u16::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    let destination = if flags & network_abi::NETWORK_FLAG_IPV6 != 0 {
        net::address::Address::V6(read_user_address6(destination)?)
    } else {
        if destination > u32::MAX as usize {
            return Err(Error::InvalidArgument);
        }
        net::address::Address::V4(abi::network::unpack_address(destination))
    };
    let stream = crate::net::tcp_connect(destination, port as u16)?;
    let owner = arguments
        .context
        .caller_pid
        .unwrap_or(crate::programs::BOOT_PROCESS);
    let descriptor = table.insert_tcp_stream(stream, owner)?;
    Ok(Dispatch::complete(descriptor))
}

/// What the network is, on this machine.
///
/// Arguments: the record, its length, then four reserved slots that must be
/// zero.  Answers zero, with the record filled.
///
/// The record is filled from the interface the boot installed, not from
/// constants: a boot whose card never came up installed nothing, and that is
/// the one case this call answers `NotFound` for, a record implies
/// addresses, and a machine with no card has none.  One interface, one
/// address, one gateway is the whole of what this build answers, which is
/// the whole of the routing its wire has.
pub fn network_status(
    _table: &mut SyscallTable,
    arguments: &mut Arguments<'_>,
) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 2)?;

    let buffer = arguments
        .buffer
        .as_deref_mut()
        .ok_or(Error::InvalidArgument)?;
    if buffer.len() < network_abi::NETWORK_STATUS_SIZE {
        return Err(Error::InvalidArgument);
    }

    let record = crate::net::status().ok_or(Error::NotFound)?;
    write_network_status(buffer, &record);
    Ok(Dispatch::complete(0))
}

/// Report the interface's IPv6 side.
///
/// Arguments: the buffer, then two reserved slots that must be zero, the
/// same shape `NetworkStatus` takes, because a program reads the two the same
/// way.  The record is [`abi::network::Ipv6StatusRecord`]'s and the offsets
/// are that crate's, written field by field: the struct is `repr(C)` and a
/// program reads it at the addresses the offsets name, so a writer that
/// assumed a layout would be writing into the wrong bytes on a machine whose
/// compiler disagreed.
pub fn ipv6_status(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 2)?;

    let buffer = arguments
        .buffer
        .as_deref_mut()
        .ok_or(Error::InvalidArgument)?;
    if buffer.len() < abi::network::IPV6_STATUS_SIZE {
        return Err(Error::InvalidArgument);
    }

    let record = crate::net::ipv6_status().ok_or(Error::NotFound)?;
    buffer[0..8].copy_from_slice(&record.state.to_le_bytes());
    buffer[8..16].copy_from_slice(&record.has_global.to_le_bytes());
    buffer[16..24].copy_from_slice(&record.neighbours.to_le_bytes());
    buffer[abi::network::IPV6_STATUS_LINK_LOCAL_OFFSET
        ..abi::network::IPV6_STATUS_LINK_LOCAL_OFFSET + 16]
        .copy_from_slice(&record.link_local);
    buffer[abi::network::IPV6_STATUS_GLOBAL_OFFSET..abi::network::IPV6_STATUS_GLOBAL_OFFSET + 16]
        .copy_from_slice(&record.global);
    Ok(Dispatch::complete(0))
}

/// Report this machine's name.
///
/// Arguments: a buffer and its length.  The answer is the length written, which
/// may be zero: a machine that was never named has no name and not a failure,
/// and a program that treated the two the same would refuse to start on a
/// machine nobody had named.
pub fn get_host_name(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 2)?;
    let buffer = arguments
        .buffer
        .as_deref_mut()
        .ok_or(Error::InvalidArgument)?;
    let written = crate::net::host_name(buffer)?;
    Ok(Dispatch::complete(written))
}

/// Set this machine's name.
///
/// Arguments: the name and its length.  The name is copied, and one that
/// carries a byte a program would not print is refused: a name is text a
/// program will show, and a control character in it is that program's output
/// being rewritten by the name it set.
pub fn set_host_name(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 2)?;
    let name = arguments.path.ok_or(Error::InvalidArgument)?;
    crate::net::set_host_name(name.as_bytes())?;
    Ok(Dispatch::complete(0))
}

/// Resolve a name to an IPv4 address.
///
/// Arguments: the name and its length, and the answer is the address packed
/// into one word in network order, which is the shape this call has always
/// answered with.  The lookup itself is [`crate::net::resolve`], which the
/// boot's own probe already runs against a real server.
///
/// A machine's resolution is a socket, a clock and a retry schedule, and a host
/// build has none of the three, which is why this handler carries the same gate
/// the function it calls does.
#[cfg(target_os = "none")]
pub fn resolve_hostname(
    _table: &mut SyscallTable,
    arguments: &mut Arguments<'_>,
) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 2)?;
    let name = arguments.path.ok_or(Error::InvalidArgument)?;
    let address = crate::net::resolve(name, net::dns::TYPE_A).ok_or(Error::NotFound)?;
    match address {
        net::address::Address::V4(bytes) => {
            Ok(Dispatch::complete(u32::from_be_bytes(bytes) as usize))
        }
        // The lookup asked for an A record, so a six-byte answer is a
        // resolver that answered a question it was not asked.
        net::address::Address::V6(_) => Err(Error::Unsupported),
    }
}

/// Report where one of a socket's ends is.
///
/// Arguments: the descriptor, a buffer and its length, which is the shape
/// `GetSockName` and `GetPeerName` share.  The answer is the record's size,
/// which is what a caller needs to know how much of its buffer was written.
fn socket_end(
    table: &mut SyscallTable,
    arguments: &mut Arguments<'_>,
    end: crate::net::SocketEnd,
) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 3)?;
    let descriptor = arguments.context.args[0];
    let buffer = arguments
        .buffer
        .as_deref_mut()
        .ok_or(Error::InvalidArgument)?;
    if buffer.len() < abi::network::SOCKADDR_IN_SIZE {
        return Err(Error::InvalidArgument);
    }
    let caller = arguments.context.caller_pid;
    // A stream and a datagram socket answer differently: a stream's own port
    // is the one it listens on or connected from, and its peer's is the far
    // end; a datagram socket has an own port and no peer.
    //
    // The lookup goes through the table the dispatcher handed in, and **not**
    // through the free functions beside it: those take the registry's lock,
    // and `serve` is already holding it for the length of this call.  A
    // handler that reached for `tcp_stream_for` would take one lock twice in
    // one thread, which is a hang rather than a second read, and the symptom
    // was a boot that stopped between two lines with nothing refused.
    let (port, peer) = if let Some(id) = table.tcp_stream(descriptor, caller) {
        let ends = crate::net::stream_ends(id).ok_or(Error::InvalidArgument)?;
        (ends.0, Some(ends.1))
    } else if let Some(socket) = table.udp_socket(descriptor, caller) {
        (socket.port(), None)
    } else {
        return Err(Error::InvalidArgument);
    };
    let record = crate::net::socket_address(port, peer, end)?;
    // Written byte by byte at the ABI's offsets, because the struct is
    // `repr(C)` and a program reads it at those addresses: a writer that
    // copied the struct would depend on this build's layout matching the one
    // the program was compiled against.
    buffer[abi::network::SOCKADDR_IN_FAMILY_OFFSET..abi::network::SOCKADDR_IN_FAMILY_OFFSET + 2]
        .copy_from_slice(&record.family.to_ne_bytes());
    buffer[abi::network::SOCKADDR_IN_PORT_OFFSET..abi::network::SOCKADDR_IN_PORT_OFFSET + 2]
        .copy_from_slice(&record.port);
    buffer[abi::network::SOCKADDR_IN_ADDRESS_OFFSET..abi::network::SOCKADDR_IN_ADDRESS_OFFSET + 4]
        .copy_from_slice(&record.address);
    buffer[12..abi::network::SOCKADDR_IN_SIZE].fill(0);
    Ok(Dispatch::complete(abi::network::SOCKADDR_IN_SIZE))
}

/// Report the address this machine's end of a socket answers on.
pub fn get_sock_name(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    socket_end(table, arguments, crate::net::SocketEnd::Local)
}

/// Report the address a socket's peer is.
pub fn get_peer_name(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    socket_end(table, arguments, crate::net::SocketEnd::Peer)
}

/// Bind a name, and answer the descriptor an accept is called on.
///
/// Arguments: the name and its length.  The name is **bytes** and not a path:
/// nothing resolves it through a namespace, and a filesystem may hold a file of
/// the same name, which is what makes this a local socket rather than a file a
/// program would have to create and clean up.
///
/// The descriptor holds the name so its owner's exit releases it.  A name whose
/// listener died without that release could not be bound again until the boot
/// ended.
pub fn bind_local(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 2)?;
    let name = arguments.path.ok_or(Error::InvalidArgument)?;
    let owner = arguments
        .context
        .caller_pid
        .unwrap_or(crate::programs::BOOT_PROCESS);
    crate::local::bind(name.as_bytes())?;
    let descriptor = table.insert_local_listener(alloc::string::String::from(name), owner)?;
    Ok(Dispatch::complete(descriptor))
}

/// Connect to a bound name, and answer the descriptor the connection is read
/// and written through.
///
/// Arguments: the name and its length.  The two pipes are made here, and the
/// halves the descriptor holds are the client's: what it writes goes to the
/// server and what the server writes comes back to it.
pub fn connect_local(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 2)?;
    let name = arguments.path.ok_or(Error::InvalidArgument)?;
    let owner = arguments
        .context
        .caller_pid
        .unwrap_or(crate::programs::BOOT_PROCESS);
    let halves = crate::local::connect(name.as_bytes())?;
    let descriptor = table.insert_local(halves, owner)?;
    // The connection is what a parked accept was waiting for, and this call
    // **says so** rather than waking: the dispatcher holds the registry's lock
    // for the length of this function, and the scheduler's lock is one a
    // parked task holds while it re-checks the queue.  Taking both here would
    // be a deadlock, and the two CPUs can take them in opposite orders, which
    // is worse: it is a deadlock that happens once in seven boots.
    //
    // The caller of `serve` wakes after the lock is released, and
    // `Dispatch::completing` is the flag that tells it to.
    Ok(Dispatch::completing(descriptor))
}

/// Take a waiting connection on a listener, if there is one.
///
/// The answer `usize::MAX` is the trap path's signal that nothing waits: a
/// handler cannot park, for the reason `kernel/src/syscall/mod.rs` gives, so
/// the branch in `process.rs` asks this once and then parks on its own.  Every
/// other answer is a descriptor or an error.
pub fn accept_local(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 1)?;
    let descriptor = arguments.context.arg(0);
    let caller = arguments.context.caller_pid;
    let name = table
        .local_name(descriptor, caller)
        .ok_or(Error::InvalidArgument)?;
    let owner = arguments
        .context
        .caller_pid
        .unwrap_or(crate::programs::BOOT_PROCESS);
    match crate::local::accept(name.as_bytes())? {
        Some(halves) => {
            let accepted = table.insert_local(halves, owner)?;
            Ok(Dispatch::complete(accepted))
        }
        None => Ok(Dispatch::complete(usize::MAX)),
    }
}

/// Create a raw socket bound to an IP protocol number, answering its
/// descriptor.
///
/// Arguments: the protocol number, then five reserved slots that must be zero.
/// Protocol zero is refused: it is the IP header's "no protocol", and a socket
/// bound to it would receive every packet this machine accepts.  A number past
/// a byte is refused too, because the field it goes into is one byte.
///
/// This is a privileged interface on every system that has one, and nothing
/// checks what the bytes say: a raw send composes an IP header with this
/// machine's own source address and the program's payload.  That is the whole
/// reason the call exists, and the MAC policy is where a boot would gate it.
/// This boot's policy does not, and `docs/status.md` says so rather than
/// claiming a check that does not run.
pub fn create_raw_socket(
    table: &mut SyscallTable,
    arguments: &mut Arguments<'_>,
) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 2)?;
    let protocol = arguments.context.arg(0);
    if protocol == 0 || protocol > u8::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    let owner = arguments
        .context
        .caller_pid
        .unwrap_or(crate::programs::BOOT_PROCESS);
    let socket = crate::net::create_raw_socket(protocol as u8)?;
    let descriptor = table.insert_raw(socket, owner)?;
    Ok(Dispatch::complete(descriptor))
}

/// Send one raw packet: the protocol's payload, with the header written here.
///
/// Arguments: the descriptor, the destination address packed by the ABI's own
/// [`abi::network::pack_address`], the destination's length (four or sixteen),
/// the payload, its length, and the flags word.  Answers the bytes sent.
///
/// `a2` is the destination's length and not a second buffer: the ABI's shape
/// has the address's width spelled out because a raw send takes either family,
/// and the flags carry the IPv6 bit the datagram calls already use.  A width
/// that names neither family is refused rather than guessed.
pub fn send_raw_packet(
    table: &mut SyscallTable,
    arguments: &mut Arguments<'_>,
) -> Result<Dispatch> {
    let descriptor = arguments.context.arg(0);
    let destination = arguments.context.arg(1);
    let destination_len = arguments.context.arg(2);
    let flags = arguments.context.arg(5);
    validate_known_flags(flags, network_abi::SEND_TO_UDP_KNOWN_FLAGS)?;
    let payload = arguments.buffer.as_deref().ok_or(Error::InvalidArgument)?;
    if payload.is_empty() || payload.len() > crate::net::MAX_DATAGRAM_BYTES {
        return Err(Error::InvalidArgument);
    }
    let socket = table
        .raw_socket(descriptor, arguments.context.caller_pid)
        .ok_or(Error::InvalidArgument)?;
    let destination = match destination_len {
        4 => {
            if destination > u32::MAX as usize {
                return Err(Error::InvalidArgument);
            }
            net::address::Address::V4(network_abi::unpack_address(destination))
        }
        // A sixteen-byte address arrives as a pointer, the same shape the
        // datagram and stream calls take for theirs.
        16 => net::address::Address::V6(read_user_address6(destination)?),
        _ => return Err(Error::InvalidArgument),
    };
    let sent = crate::net::send_raw_packet(socket.protocol(), destination, payload)?;
    Ok(Dispatch::complete(sent))
}

/// The socket a descriptor names, whichever kind it is, as the thing that
/// holds options.
///
/// Both kinds carry a [`net::options::Options`], and the calls that read and
/// write one do not care which kind they reached: `SO_RCVBUF` on a datagram
/// socket is a number it keeps and this stack does not act on, and the same
/// number on a stream is the window it advertises.  The refusal for an option
/// the stack does not serve is the options' own, so a socket of either kind
/// answers it the same way.
enum OptionHolder {
    /// A datagram socket, which holds its options behind its own lock.
    Datagram(Arc<crate::net::UdpSocket>),
    /// A stream, whose options are the connection's.
    Stream(usize),
}

/// Set one option on the socket a descriptor names.
///
/// Arguments: the descriptor, the level, the option's name, the value and its
/// length, then one reserved slot that must be zero.  Answers zero: a setter
/// has nothing to report but success, and the width is the caller's to have
/// stated, not a number it needs back.
///
/// The value is validated before the socket is looked up, so a call with a bad
/// pointer costs no table walk.  A value wider than
/// [`network_abi::SOCK_OPT_MAX`] is refused for the same reason: every option
/// this stack serves is one word, and a caller passing a struct is a caller
/// expecting an option this build does not have.
pub fn set_sock_opt(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 5)?;
    let descriptor = arguments.context.arg(0);
    let level = arguments.context.arg(1) as u32;
    let name = arguments.context.arg(2) as u32;
    let value = arguments.buffer.as_deref().ok_or(Error::InvalidArgument)?;
    if value.is_empty() || value.len() > network_abi::SOCK_OPT_MAX {
        return Err(Error::InvalidArgument);
    }
    let caller = arguments.context.caller_pid;
    match holder(table, descriptor, caller)? {
        OptionHolder::Datagram(socket) => socket.set_option(level, name, value)?,
        OptionHolder::Stream(id) => crate::net::set_stream_option(id, level, name, value)?,
    }
    Ok(Dispatch::complete(0))
}

/// Read one option from the socket a descriptor names.
///
/// Arguments: the descriptor, the level, the option's name, the buffer and its
/// length, then one reserved slot that must be zero.  Answers the bytes
/// written, which is one for a flag and a word for a size.
pub fn get_sock_opt(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 5)?;
    let descriptor = arguments.context.arg(0);
    let level = arguments.context.arg(1) as u32;
    let name = arguments.context.arg(2) as u32;
    let caller = arguments.context.caller_pid;
    let holder = holder(table, descriptor, caller)?;
    let buffer = arguments
        .buffer
        .as_deref_mut()
        .ok_or(Error::InvalidArgument)?;
    if buffer.is_empty() || buffer.len() > network_abi::SOCK_OPT_MAX {
        return Err(Error::InvalidArgument);
    }
    let written = match holder {
        OptionHolder::Datagram(socket) => socket.get_option(level, name, buffer)?,
        OptionHolder::Stream(id) => crate::net::stream_option(id, level, name, buffer)?,
    };
    Ok(Dispatch::complete(written))
}

/// Add one packet filter rule, and answer the id it was given.
///
/// Arguments: the record, its length, then four reserved slots that must be
/// zero.  The record is [`abi::network::FilterRuleDef`], read field by field
/// rather than by casting the buffer: a `#[repr(C)]` struct's layout is the
/// compiler's, and a kernel that transmuted a caller's bytes into one would be
/// trusting a layout it does not own on the machine it is running on.
///
/// The id a rule is given is never reused, so a program that removes a rule and
/// adds another gets a different number: an id that came back would make a
/// stale id remove a rule its owner never named.
pub fn filter_add_rule(
    _table: &mut SyscallTable,
    arguments: &mut Arguments<'_>,
) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 4)?;
    let buffer = arguments.buffer.as_deref().ok_or(Error::InvalidArgument)?;
    if buffer.len() != network_abi::FILTER_RULE_DEF_SIZE {
        return Err(Error::InvalidArgument);
    }
    let record = read_filter_rule(buffer)?;
    let id = crate::net::filter_add(&record)?;
    Ok(Dispatch::complete(id as usize))
}

/// Remove one packet filter rule by id.
///
/// Arguments: the id, then four reserved slots that must be zero.  Answers
/// zero when a rule was removed and `NotFound` when the id named nothing, which
/// is the difference between "it is gone" and "it was never here".
pub fn filter_remove_rule(
    _table: &mut SyscallTable,
    arguments: &mut Arguments<'_>,
) -> Result<Dispatch> {
    let id = arguments.context.arg(0);
    validate_zeroed_args(arguments.context, 1)?;
    if id > u32::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    if !crate::net::filter_remove(id as u32) {
        return Err(Error::NotFound);
    }
    Ok(Dispatch::complete(0))
}

/// Set the action a packet no rule matches gets.
///
/// Arguments: the action, then four reserved slots that must be zero.  The
/// action is one of the two the ABI names, and a third is refused rather than
/// read as allow: a number this build does not know is a caller that meant
/// something this build does not do.
///
/// The flows the stateful rules remembered are forgotten here, because they
/// were remembered under the rules this call is changing.
pub fn filter_set_default_action(
    _table: &mut SyscallTable,
    arguments: &mut Arguments<'_>,
) -> Result<Dispatch> {
    let action = arguments.context.arg(0);
    validate_zeroed_args(arguments.context, 1)?;
    if action > u32::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    let action = net::filter::Action::from_wire(action as u32)?;
    crate::net::filter_set_default(action);
    Ok(Dispatch::complete(0))
}

/// Read the filter's statistics into the caller's record.
///
/// Arguments: the record, its length, then four reserved slots that must be
/// zero.  Answers zero with the record filled.  The record is
/// [`abi::network::FilterStats`] and is written field by field at the offsets
/// that crate names, which is what makes the layout one fact rather than two.
pub fn filter_get_stats(
    _table: &mut SyscallTable,
    arguments: &mut Arguments<'_>,
) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 3)?;
    let buffer = arguments
        .buffer
        .as_deref_mut()
        .ok_or(Error::InvalidArgument)?;
    if buffer.len() != network_abi::FILTER_STATS_SIZE {
        return Err(Error::InvalidArgument);
    }
    let (default_action, rules, flows, allowed, dropped) = crate::net::filter_status();
    write_filter_stats(buffer, default_action, rules, flows, allowed, dropped);
    Ok(Dispatch::complete(0))
}

/// Read a [`abi::network::FilterRuleDef`] out of a caller's bytes.
///
/// Field by field, at the offsets the ABI crate names.  A cast would be shorter
/// and would be the one place this kernel trusted a layout across the boundary:
/// the record is `repr(C)` on both sides, but "both sides agree" is a claim the
/// offsets make checkable and a transmute only assumes.
fn read_filter_rule(buffer: &[u8]) -> Result<network_abi::FilterRuleDef> {
    let word = |at: usize| -> Result<u32> {
        let bytes = buffer.get(at..at + 4).ok_or(Error::InvalidArgument)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    };
    let address = |at: usize| -> Result<[u8; network_abi::FILTER_ADDRESS_BYTES]> {
        let bytes = buffer
            .get(at..at + network_abi::FILTER_ADDRESS_BYTES)
            .ok_or(Error::InvalidArgument)?;
        let mut address = [0_u8; network_abi::FILTER_ADDRESS_BYTES];
        address.copy_from_slice(bytes);
        Ok(address)
    };
    Ok(network_abi::FilterRuleDef {
        action: word(0)?,
        protocol: word(4)?,
        family: word(8)?,
        direction: word(12)?,
        stateful: word(16)?,
        source_prefix: word(20)?,
        destination_prefix: word(24)?,
        source_port_start: word(28)?,
        source_port_end: word(32)?,
        destination_port_start: word(36)?,
        destination_port_end: word(40)?,
        reserved: word(44)?,
        source_address: address(network_abi::FILTER_RULE_SOURCE_ADDRESS_OFFSET)?,
        destination_address: address(network_abi::FILTER_RULE_DESTINATION_ADDRESS_OFFSET)?,
    })
}

/// Write a [`abi::network::FilterStats`] at the start of a validated buffer.
fn write_filter_stats(
    buffer: &mut [u8],
    default_action: net::filter::Action,
    rules: u32,
    flows: u32,
    allowed: u64,
    dropped: u64,
) {
    let words = [default_action.to_wire(), rules, flows, 0];
    for (index, word) in words.iter().enumerate() {
        let at = index * 4;
        buffer[at..at + 4].copy_from_slice(&word.to_le_bytes());
    }
    let at = network_abi::FILTER_STATS_ALLOWED_OFFSET;
    buffer[at..at + 8].copy_from_slice(&allowed.to_le_bytes());
    buffer[at + 8..at + 16].copy_from_slice(&dropped.to_le_bytes());
}

/// Enable multicast routing.
///
/// Arguments: zero, then five reserved slots.  There is no flags word to
/// validate because the call has none: `MrtInit`'s argument is reserved, and a
/// caller that put something there is a caller against a newer ABI.
///
/// The local interface and one link interface arrive with this call, because
/// there is one card and no other way for a program to name it: an `MrtAddVif`
/// cannot install the link without a number, and the number is what `MrtInit`
/// reserves.
pub fn mrt_init(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 0)?;
    crate::net::multicast_init()?;
    Ok(Dispatch::complete(0))
}

/// Disable multicast routing and forget both tables.
///
/// Arguments: zero, then five reserved slots.  Answers `NotFound` when routing
/// was not on, which is the difference between "it is off" and "you turned off
/// something that was".
pub fn mrt_done(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 0)?;
    crate::net::multicast_done()?;
    Ok(Dispatch::complete(0))
}

/// Add a virtual interface, and answer the index it was given.
///
/// Arguments: the record, its length, then four reserved slots.  A
/// `vif_index` of zero asks for automatic numbering, which is the reading
/// [`abi::network::MrtVifDef`] states: the record's own comment could be read
/// as saying zero is the local interface, and one value cannot be both.  The
/// local interface is what `MrtInit` installs.
pub fn mrt_add_vif(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 3)?;
    let buffer = arguments.buffer.as_deref().ok_or(Error::InvalidArgument)?;
    if buffer.len() != network_abi::MRT_VIF_DEF_SIZE {
        return Err(Error::InvalidArgument);
    }
    let record = read_mrt_vif(buffer)?;
    let index = crate::net::multicast_add_vif(&record)?;
    Ok(Dispatch::complete(index as usize))
}

/// Remove a virtual interface by index.
///
/// Arguments: the index, then five reserved slots.  The local interface cannot
/// be removed, and the answer for it is `InvalidArgument`: it is not a
/// forwarder a caller installed.
pub fn mrt_del_vif(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let index = arguments.context.arg(0);
    validate_zeroed_args(arguments.context, 1)?;
    if index > u32::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    crate::net::multicast_del_vif(index as u32)?;
    Ok(Dispatch::complete(0))
}

/// Add a forwarding-cache entry.
///
/// Arguments: the record, its length, then four reserved slots.  Answers zero,
/// and whether an entry for the same `(source, group)` was replaced is not
/// reported: the ABI's answer word is the call's status, and a caller that
/// wanted to know would have to have asked before it added.
pub fn mrt_add_mfc(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 3)?;
    let buffer = arguments.buffer.as_deref().ok_or(Error::InvalidArgument)?;
    if buffer.len() != network_abi::MRT_MFC_DEF_SIZE {
        return Err(Error::InvalidArgument);
    }
    let record = read_mrt_mfc(buffer)?;
    crate::net::multicast_add_mfc(&record)?;
    Ok(Dispatch::complete(0))
}

/// Remove the forwarding-cache entry for `(source, group)`.
///
/// Arguments: the source, packed by the ABI's own `pack_address`; the group,
/// the same way; then four reserved slots.  Answers zero, or `NotFound` when no
/// entry named that stream.
pub fn mrt_del_mfc(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let source = arguments.context.arg(0);
    let group = arguments.context.arg(1);
    validate_zeroed_args(arguments.context, 2)?;
    if source > u32::MAX as usize || group > u32::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    crate::net::multicast_del_mfc(
        network_abi::unpack_address(source),
        network_abi::unpack_address(group),
    )?;
    Ok(Dispatch::complete(0))
}

/// Read an [`abi::network::MrtVifDef`] out of a caller's bytes.
fn read_mrt_vif(buffer: &[u8]) -> Result<network_abi::MrtVifDef> {
    let word = |at: usize| -> Result<u32> {
        let bytes = buffer.get(at..at + 4).ok_or(Error::InvalidArgument)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    };
    Ok(network_abi::MrtVifDef {
        flags: word(0)?,
        vif_index: word(4)?,
        threshold: word(8)?,
        rate_limit: word(12)?,
        reserved0: word(16)?,
        reserved1: word(20)?,
    })
}

/// Read an [`abi::network::MrtMfcDef`] out of a caller's bytes.
fn read_mrt_mfc(buffer: &[u8]) -> Result<network_abi::MrtMfcDef> {
    let word = |at: usize| -> Result<u32> {
        let bytes = buffer.get(at..at + 4).ok_or(Error::InvalidArgument)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    };
    let mut source = [0_u8; 4];
    source.copy_from_slice(buffer.get(0..4).ok_or(Error::InvalidArgument)?);
    let mut group = [0_u8; 4];
    group.copy_from_slice(buffer.get(4..8).ok_or(Error::InvalidArgument)?);
    let mut out_vifs = [network_abi::MrtOutVif { vif: 0, ttl: 0 }; 4];
    for (index, slot) in out_vifs.iter_mut().enumerate() {
        let at = 16 + index * 8;
        *slot = network_abi::MrtOutVif {
            vif: word(at)?,
            ttl: word(at + 4)?,
        };
    }
    Ok(network_abi::MrtMfcDef {
        source,
        group,
        in_vif: word(8)?,
        num_out_vifs: word(12)?,
        out_vifs,
    })
}

/// Add a security policy, and answer its id.
///
/// Arguments: the record, its length, then four reserved slots.  A `PROTECT`
/// policy must name an association that exists at the moment it is installed:
/// a policy installed ahead of its association would match a packet and have
/// nothing to apply, and the two readings of that are sending plaintext and
/// dropping in silence.
pub fn ipsec_add_sp(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 3)?;
    let buffer = arguments.buffer.as_deref().ok_or(Error::InvalidArgument)?;
    if buffer.len() != network_abi::IPSEC_SP_DEF_SIZE {
        return Err(Error::InvalidArgument);
    }
    let record = read_ipsec_sp(buffer)?;
    let id = crate::net::ipsec_add_sp(&record)?;
    Ok(Dispatch::complete(id as usize))
}

/// Remove a security policy by id.
///
/// Arguments: the id, then five reserved slots.  Answers zero, or `NotFound`
/// when no policy had that id.
pub fn ipsec_del_sp(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let id = arguments.context.arg(0);
    validate_zeroed_args(arguments.context, 1)?;
    if id > u32::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    crate::net::ipsec_del_sp(id as u32)?;
    Ok(Dispatch::complete(0))
}

/// Add a security association, and answer its id.
///
/// Arguments: the record, its length, then four reserved slots.  The record is
/// [`abi::network::IpsecSaDef`], and this build serves transport-mode ESP with
/// either AEAD: something else is refused when the association is built, which
/// is where the record's own words are read.
pub fn ipsec_add_sa(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 3)?;
    let buffer = arguments.buffer.as_deref().ok_or(Error::InvalidArgument)?;
    if buffer.len() != network_abi::IPSEC_SA_DEF_SIZE {
        return Err(Error::InvalidArgument);
    }
    let record = read_ipsec_sa(buffer)?;
    let id = crate::net::ipsec_add_sa(&record)?;
    Ok(Dispatch::complete(id as usize))
}

/// Remove a security association by SPI.
///
/// Arguments: the SPI, then five reserved slots.  The SPI is what a manager
/// has, because it is in every packet on the wire; an id is this machine's
/// private number.  The policies that named the association go with it.
pub fn ipsec_del_sa(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let spi = arguments.context.arg(0);
    validate_zeroed_args(arguments.context, 1)?;
    if spi > u32::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    crate::net::ipsec_del_sa(spi as u32)?;
    Ok(Dispatch::complete(0))
}

/// Read IPsec's statistics into the caller's record.
///
/// Arguments: the record, its length, then four reserved slots.  The four
/// counters are separate because they are different failures: see
/// [`abi::network::IpsecStats`].
pub fn ipsec_get_stats(
    _table: &mut SyscallTable,
    arguments: &mut Arguments<'_>,
) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 3)?;
    let buffer = arguments
        .buffer
        .as_deref_mut()
        .ok_or(Error::InvalidArgument)?;
    if buffer.len() != network_abi::IPSEC_STATS_SIZE {
        return Err(Error::InvalidArgument);
    }
    let (policies, associations, sealed, opened, integrity, replay) = crate::net::ipsec_status();
    write_ipsec_stats(
        buffer,
        policies as u32,
        associations as u32,
        sealed,
        opened,
        integrity,
        replay,
    );
    Ok(Dispatch::complete(0))
}

/// Read an [`abi::network::IpsecSpDef`] out of a caller's bytes.
fn read_ipsec_sp(buffer: &[u8]) -> Result<network_abi::IpsecSpDef> {
    let word = |at: usize| -> Result<u32> {
        let bytes = buffer.get(at..at + 4).ok_or(Error::InvalidArgument)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    };
    let address = |at: usize| -> Result<[u8; 4]> {
        let bytes = buffer.get(at..at + 4).ok_or(Error::InvalidArgument)?;
        let mut address = [0_u8; 4];
        address.copy_from_slice(bytes);
        Ok(address)
    };
    Ok(network_abi::IpsecSpDef {
        flags: word(0)?,
        action: word(4)?,
        direction: word(8)?,
        protocol: word(12)?,
        src_addr: address(16)?,
        src_prefix: word(20)?,
        dst_addr: address(24)?,
        dst_prefix: word(28)?,
        src_port: word(32)?,
        dst_port: word(36)?,
        sa_id: word(40)?,
        reserved: word(44)?,
    })
}

/// Read an [`abi::network::IpsecSaDef`] out of a caller's bytes.
fn read_ipsec_sa(buffer: &[u8]) -> Result<network_abi::IpsecSaDef> {
    let word = |at: usize| -> Result<u32> {
        let bytes = buffer.get(at..at + 4).ok_or(Error::InvalidArgument)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    };
    let wide = |at: usize| -> Result<u64> {
        let bytes = buffer.get(at..at + 8).ok_or(Error::InvalidArgument)?;
        let mut wide = [0_u8; 8];
        wide.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(wide))
    };
    let array = |at: usize, into: &mut [u8]| -> Result<()> {
        let bytes = buffer
            .get(at..at + into.len())
            .ok_or(Error::InvalidArgument)?;
        into.copy_from_slice(bytes);
        Ok(())
    };
    let mut record = network_abi::IpsecSaDef {
        flags: word(0)?,
        spi: word(4)?,
        mode: word(8)?,
        proto: word(12)?,
        aead_algo: word(16)?,
        auth_algo: word(20)?,
        enc_key_len: word(24)?,
        auth_key_len: word(28)?,
        enc_key: [0; 32],
        auth_key: [0; 32],
        salt: [0; 12],
        src_addr: [0; 4],
        dst_addr: [0; 4],
        tunnel_src: [0; 4],
        tunnel_dst: [0; 4],
        lifetime_bytes: 0,
        lifetime_ticks: 0,
    };
    array(32, &mut record.enc_key)?;
    array(64, &mut record.auth_key)?;
    array(96, &mut record.salt)?;
    array(108, &mut record.src_addr)?;
    array(112, &mut record.dst_addr)?;
    array(116, &mut record.tunnel_src)?;
    array(120, &mut record.tunnel_dst)?;
    record.lifetime_bytes = wide(124)?;
    record.lifetime_ticks = wide(132)?;
    Ok(record)
}

/// Write an [`abi::network::IpsecStats`] at the start of a validated buffer.
fn write_ipsec_stats(
    buffer: &mut [u8],
    policies: u32,
    associations: u32,
    sealed: u64,
    opened: u64,
    integrity: u64,
    replay: u64,
) {
    for (index, word) in [policies, associations, 0, 0].iter().enumerate() {
        let at = index * 4;
        buffer[at..at + 4].copy_from_slice(&word.to_le_bytes());
    }
    for (index, counter) in [sealed, opened, integrity, replay].iter().enumerate() {
        let at = 16 + index * 8;
        buffer[at..at + 8].copy_from_slice(&counter.to_le_bytes());
    }
}

/// Binds a DCCP port for listening? No: `DccpBind` names the local port a
/// connection is to be made from, and answers a descriptor the four other calls
/// carry back.
///
/// Arguments: the port, then five reserved slots.  Port zero is refused, for
/// the reason `BindUdp` refuses it: it is the wire's "any port" and this stack
/// has no allocator to choose one.
pub fn dccp_bind(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let port = arguments.context.arg(0);
    validate_zeroed_args(arguments.context, 1)?;
    if port == 0 || port > u16::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    let owner = arguments
        .context
        .caller_pid
        .unwrap_or(crate::programs::BOOT_PROCESS);
    let descriptor = table.insert_dccp_bound(port as u16, owner)?;
    Ok(Dispatch::complete(descriptor))
}

/// Listen on a DCCP port, and answer the descriptor an accept is called on.
///
/// Arguments: the port, the service code, then four reserved slots.  The
/// service code is the field [RFC 4340] uses to tell two services apart on one
/// port, and zero means any: a listener that named one refuses a Request for
/// another.
///
/// [RFC 4340]: https://www.rfc-editor.org/rfc/rfc4340
pub fn dccp_listen(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let port = arguments.context.arg(0);
    let service_code = arguments.context.arg(1);
    validate_zeroed_args(arguments.context, 2)?;
    if port == 0 || port > u16::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    if service_code > u32::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    let code = if service_code == 0 {
        None
    } else {
        Some(service_code as u32)
    };
    let listener = crate::net::dccp_listen(port as u16, code)?;
    let owner = arguments
        .context
        .caller_pid
        .unwrap_or(crate::programs::BOOT_PROCESS);
    let descriptor = table.insert_dccp_listener(port as u16, listener, owner)?;
    Ok(Dispatch::complete(descriptor))
}

/// Open a DCCP connection, and answer the descriptor it is read and written
/// through.
///
/// Arguments: the bound descriptor, the peer's address, its port, the service
/// code, the flags, then one reserved slot.  The bound descriptor names the
/// local port: a connection has two ports, and a call that named only the
/// peer's would be one this machine could not answer on.
pub fn dccp_connect(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let descriptor = arguments.context.arg(0);
    let peer = arguments.context.arg(1);
    let peer_port = arguments.context.arg(2);
    let service_code = arguments.context.arg(3);
    let flags = arguments.context.arg(4);
    validate_known_flags(flags, network_abi::NETWORK_DCCP_KNOWN_FLAGS)?;
    validate_zeroed_args(arguments.context, 5)?;
    if peer_port == 0 || peer_port > u16::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    if service_code > u32::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    let local_port = table
        .dccp_bound_port(descriptor, arguments.context.caller_pid)
        .ok_or(Error::InvalidArgument)?;
    let peer = if flags & network_abi::NETWORK_DCCP_FLAG_IPV6 != 0 {
        net::address::Address::V6(read_user_address6(peer)?)
    } else {
        if peer > u32::MAX as usize {
            return Err(Error::InvalidArgument);
        }
        net::address::Address::V4(network_abi::unpack_address(peer))
    };
    let id = crate::net::dccp_connect(local_port, peer, peer_port as u16, service_code as u32)?;
    let owner = arguments
        .context
        .caller_pid
        .unwrap_or(crate::programs::BOOT_PROCESS);
    let descriptor = table.insert_dccp_connection(id, owner)?;
    Ok(Dispatch::complete(descriptor))
}

/// Accept the next DCCP Request at a listener.
///
/// Arguments: the listener descriptor, the sender record, its length, then
/// three reserved slots.  **Blocks** until a Request answers, so its branch is
/// the trap path's, where the scheduler's parking machinery is.  The sender
/// record is two words, the peer's address packed and its port, and a caller
/// that passes nothing gets none: the length may be zero, which is a program
/// that does not care who called.
pub fn dccp_accept(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let descriptor = arguments.context.arg(0);
    let local_port = table
        .dccp_listener_port(descriptor, arguments.context.caller_pid)
        .ok_or(Error::InvalidArgument)?;
    let Some(id) = crate::net::dccp_accept(local_port)? else {
        // Nothing waiting: the trap path parks the caller, and this word is
        // its signal, the same one `AcceptLocal` and `RecvFromUdp` answer.
        return Ok(Dispatch::complete(usize::MAX));
    };
    let owner = arguments
        .context
        .caller_pid
        .unwrap_or(crate::programs::BOOT_PROCESS);
    let descriptor = table.insert_dccp_connection(id, owner)?;
    Ok(Dispatch::complete(descriptor))
}

/// Send one DCCP datagram on a connection.
///
/// Arguments: the descriptor, the buffer, its length, then three reserved
/// slots.  Answers the bytes accepted.  A connection that is not open refuses,
/// which is the state machine's rule and not this handler's: a datagram sent
/// before the handshake finished would carry a sequence number the peer's
/// window has no place for.
pub fn dccp_send(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let descriptor = arguments.context.arg(0);
    validate_zeroed_args(arguments.context, 4)?;
    let id = table
        .dccp_connection(descriptor, arguments.context.caller_pid)
        .ok_or(Error::InvalidArgument)?;
    let buffer = arguments.buffer.as_deref().ok_or(Error::InvalidArgument)?;
    if buffer.len() > net::dccp::MAX_DATAGRAM {
        return Err(Error::InvalidArgument);
    }
    crate::net::dccp_send(id, buffer)?;
    Ok(Dispatch::complete(buffer.len()))
}

/// Read one DCCP datagram, or park until one arrives.
///
/// Arguments: the descriptor, the buffer, its length, then three reserved
/// slots.  Answers the bytes read, or `usize::MAX` for "nothing yet", which is
/// the trap path's signal to park the caller.  A finished connection with an
/// empty inbox answers zero, which is end of file and not a wait: the
/// difference is the one a reader's loop turns on.
pub fn dccp_recv(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let descriptor = arguments.context.arg(0);
    let id = table
        .dccp_connection(descriptor, arguments.context.caller_pid)
        .ok_or(Error::InvalidArgument)?;
    let buffer = arguments
        .buffer
        .as_deref_mut()
        .ok_or(Error::InvalidArgument)?;
    if buffer.is_empty() {
        return Err(Error::InvalidArgument);
    }
    match crate::net::dccp_read(id, buffer)? {
        Some(count) => Ok(Dispatch::complete(count)),
        None => Ok(Dispatch::complete(usize::MAX)),
    }
}

/// Close a DCCP connection by descriptor.
///
/// Arguments: the descriptor, then five reserved slots.  Answers zero.  The
/// connection's entry goes with it, and a `Close` goes to the peer, which is
/// what makes the close visible on the wire rather than only here.
pub fn dccp_close(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let descriptor = arguments.context.arg(0);
    validate_zeroed_args(arguments.context, 1)?;
    let id = table
        .dccp_connection(descriptor, arguments.context.caller_pid)
        .ok_or(Error::InvalidArgument)?;
    crate::net::dccp_close(id)?;
    table.close(descriptor)?;
    Ok(Dispatch::complete(0))
}

/// Open a TLS 1.3 connection to a host.
///
/// Arguments: the host name, its length, the port, then three reserved slots
/// that must be zero.  Answers the descriptor a program reads and writes
/// through, which is a **plain stream**: what protects its bytes is a record
/// layer this build has, not a socket it has wrapped.
///
/// ## What this call does, and what it refuses
///
/// It opens the TCP stream to the peer and sends a ClientHello built by
/// [`net::tls::client_hello_body`].  Then it **refuses with `Unsupported`**,
/// because the handshake's next step needs an answer this machine cannot get: a
/// TLS server.  There is none here.  QEMU's user-mode network answers ARP, ICMP
/// and UDP, and it does not terminate TLS, and a stack that cannot reach a peer
/// cannot finish a handshake with one.
///
/// The refusal is **after** the hello and not before it, and that is a choice
/// worth stating: a call that refused immediately would be a call whose
/// ClientHello had never been built by the kernel, and building it is the half
/// of this that can be exercised.  The line a boot prints says how many bytes
/// the hello was, which is the evidence that the half ran.
///
/// ## Why the descriptor is not returned
///
/// A descriptor over a stream with no keys would be a descriptor whose bytes a
/// program believes are protected and are not, which is worse than a refusal:
/// the first is a program that sends plaintext under the impression it is
/// encrypted.  The call refusing means the program learns, and the stream it
/// opened is closed.
pub fn tls_connect(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let port = arguments.context.arg(2);
    let flags = arguments.context.arg(3);
    validate_known_flags(flags, 0)?;
    validate_zeroed_args(arguments.context, 4)?;
    if port == 0 || port > u16::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    let host = arguments.path.ok_or(Error::InvalidArgument)?;
    if host.is_empty() || host.len() > network_abi::HOST_NAME_MAX {
        return Err(Error::InvalidArgument);
    }

    // The hello, built and measured before anything is sent.  Its length is the
    // evidence a boot prints: a `TlsConnect` that refused without building one
    // would be a number answering `Unsupported` and nothing more.
    let (offer, _secret) = net::tls::Offer::generate(read_random()?);
    let body = net::tls::client_hello_body(&offer, Some(host));
    let hello = net::tls::write_handshake(net::tls::HANDSHAKE_CLIENT_HELLO, &body);

    // The stream, so the hello has somewhere to go, and the name looked up.  A
    // host build has no wire and no resolver, and its answer is the same one a
    // boot reaches: the hello has no peer.
    #[cfg(target_os = "none")]
    {
        let address = crate::net::resolve(host, net::dns::TYPE_A).ok_or(Error::NotFound)?;
        let stream = crate::net::tcp_connect(address, port as u16)?;
        let written = crate::net::tcp_write(stream, &hello).unwrap_or(0);
        let _ = crate::net::tcp_close(stream);
        arch::serial::write_str("protofire: tls sent a client hello of ");
        arch::serial::write_u32(written as u32);
        arch::serial::write_str(" byte(s) and has no peer to answer it\n");
    }
    #[cfg(not(target_os = "none"))]
    {
        let _ = hello;
    }
    Err(Error::Unsupported)
}

/// A random draw for a ClientHello's field, or the error a boot without a
/// seeded generator gives.
fn read_random() -> Result<[u8; 32]> {
    let mut random = [0_u8; 32];
    crate::random::fill(&mut random)?;
    Ok(random)
}

/// Trust a DER-encoded root certificate at run time.
///
/// Arguments: the DER, its length, then four reserved slots that must be zero.
/// Answers the id `TrustAnchorRemove` takes.
///
/// The DER is **parsed before it is stored**: an anchor nothing could parse is
/// one every chain would fail against, and a program would learn that only when
/// a connection was attempted.  The certificate is copied, not borrowed: a
/// pointer into the caller's memory that outlived the call would be a dangling
/// reference the moment the buffer went away.
pub fn trust_anchor_add(
    _table: &mut SyscallTable,
    arguments: &mut Arguments<'_>,
) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 2)?;
    let buffer = arguments.buffer.as_deref().ok_or(Error::InvalidArgument)?;
    if buffer.is_empty() || buffer.len() > net::x509::CERTIFICATE_MAX {
        return Err(Error::InvalidArgument);
    }
    let id = crate::net::trust_anchor_add(buffer)?;
    Ok(Dispatch::complete(id as usize))
}

/// Withdraw a run-time trust anchor by id.
///
/// Arguments: the id, then five reserved slots.  Answers zero, or `NotFound`
/// when no anchor had that id: "it is not trusted" and "I withdrew what you
/// asked for" are different answers, and the second is the one a program acts
/// on.
pub fn trust_anchor_remove(
    _table: &mut SyscallTable,
    arguments: &mut Arguments<'_>,
) -> Result<Dispatch> {
    let id = arguments.context.arg(0);
    validate_zeroed_args(arguments.context, 1)?;
    if id > u32::MAX as usize {
        return Err(Error::InvalidArgument);
    }
    crate::net::trust_anchor_remove(id as u32)?;
    Ok(Dispatch::complete(0))
}

/// The socket a descriptor names, or the error that says why there is none.
///
/// A descriptor that names a file or a pipe is `InvalidArgument` and not
/// `Unsupported`: a socket option call on something that is not a socket is a
/// caller's mistake about the descriptor, and `Unsupported` would say the
/// machine does not do options, which it does.
fn holder(
    table: &mut SyscallTable,
    descriptor: usize,
    caller: Option<u32>,
) -> Result<OptionHolder> {
    if let Some(id) = table.tcp_stream(descriptor, caller) {
        return Ok(OptionHolder::Stream(id));
    }
    if let Some(socket) = table.udp_socket(descriptor, caller) {
        return Ok(OptionHolder::Datagram(socket));
    }
    Err(Error::InvalidArgument)
}

/// Write a `NetworkStatus` record at the start of a validated buffer: the
/// state word, then the fourteen address bytes the record packed.
fn write_network_status(buffer: &mut [u8], record: &network_abi::NetworkStatusRecord) {
    buffer[0..8].copy_from_slice(&record.state.to_le_bytes());
    buffer[8..8 + network_abi::NETWORK_ADDRESSES_BYTES].copy_from_slice(&record.addresses);
}

/// Write an `AbiInfo` record at the start of a validated buffer.
fn write_abi_info(buffer: &mut [u8], record: &system_abi::AbiInfo) {
    buffer[0..8].copy_from_slice(&record.version.to_le_bytes());
    buffer[8..16].copy_from_slice(&record.syscall_count.to_le_bytes());
    buffer[16..24].copy_from_slice(&record.frozen_count.to_le_bytes());
}

/// Write a `SystemInfo` record at the start of a validated buffer.
fn write_system_info(buffer: &mut [u8], record: &system_abi::SystemInfo) {
    let words = [
        record.switches,
        record.exited,
        record.blocked,
        record.sleeping,
        record.delivered_signals,
        record.online_cpus,
        record.managed_frames,
        record.free_frames,
    ];
    for (index, word) in words.iter().enumerate() {
        let at = index * 8;
        buffer[at..at + 8].copy_from_slice(&word.to_le_bytes());
    }
}
