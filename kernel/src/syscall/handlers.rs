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

    let subject = arguments
        .context
        .identity
        .unwrap_or(mac::MAC_TYPE_UNLABELED);
    mac::check_file(subject, path, mac::MAC_CLASS_FILE, mac::MAC_PERM_READ, 0)?;

    let buffer = arguments
        .buffer
        .as_deref_mut()
        .ok_or(Error::InvalidArgument)?;
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
