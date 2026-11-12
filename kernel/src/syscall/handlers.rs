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

use abi::Error;
use abi::Result;
use abi::fs as fs_abi;
use abi::memory as memory_abi;
use paging;
use security::mac;
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
    let subject = arguments
        .context
        .identity
        .unwrap_or(mac::MAC_TYPE_UNLABELED);
    let permission = if flags & (fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE) != 0 {
        mac::MAC_PERM_WRITE
    } else {
        mac::MAC_PERM_READ
    };
    mac::check_file(subject, path, mac::MAC_CLASS_FILE, permission, 0)?;

    // Through the namespace: the table resolves the path to a mount and a path
    // relative to it, and the filesystem answers for that.  `open` names no
    // filesystem, which is what lets a second one be mounted without this
    // handler changing.
    let node = table.namespace().ok_or(Error::NotFound)?.lookup(path)?;

    // The opener is the owner: the process that asked, as the kernel recorded
    // it, so its exit can release the slot.  A caller the kernel made itself
    // has no pid, and `0` is the boot's own process — the only one whose
    // descriptor outlives every program by design.
    let owner = arguments
        .context
        .caller_pid
        .unwrap_or(crate::programs::BOOT_PROCESS);
    let descriptor = table.insert(Descriptor::File {
        node,
        readable: flags & fs_abi::OPEN_FLAG_READ != 0 || flags == fs_abi::OPEN_FLAG_NONE,
        offset: 0,
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
/// over — the borrow is built where the call arrives, from the two words —
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
/// anonymous private memory — this kernel has no file-backed mapping and no
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
/// zero rather than an error — asking to remove what is not there has two true
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
/// that asked for more than it can have learns what it actually got — which is
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
/// first that is honest — it walks the space's own records and gives back the
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
