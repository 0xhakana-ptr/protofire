//! userland/src/lib.rs
//!
//! The wrappers a program of this kernel is written against: the numbering,
//! the one call gate per machine, and the typed-on-nothing helpers above them.
//!
//! ## Why this crate exists
//!
//! `docs/fmts/syscall-abi.md` §8 records the convention and the reason: a
//! program carries no kernel crate, so without a crate both sides compile
//! against, every program spells the gate itself — and two programs that each
//! spell it are two places for one fact to drift.  This is that crate.  It
//! names nothing of the tree: the numbering is spelled here as constants,
//! because a program compiles against the numbering, not against the kernel's
//! `abi` crate, and a dependency that carried the numbers would be a
//! dependency that carried the kernel.
//!
//! ## The shape
//!
//! One gate per machine — six argument words in, one answer out — plus the
//! `exit` that does not return: two pieces of assembly each, and every
//! operation above them is a machine-independent wrapper that names the
//! number and packs the slots.  A new architecture teaches this crate two
//! calls, not one per operation.
//!
//! The wrappers answer the **raw status word**.  The ABI encodes an error as
//! a word with its high bit set, which makes `is_error` the one test a
//! program needs; `insist` is the fail-fast form, for a program whose next
//! step is meaningless after a refused one.

#![cfg_attr(target_os = "none", no_std)]

#[cfg(target_os = "none")]
use core::arch::asm;

// The numbering, spelled here because a program compiles against it.

/// `Open`, and the rest of the file interface.
pub const SYS_OPEN: usize = 2;
/// `Exit`.
pub const SYS_EXIT: usize = 3;
/// `Read`, from a descriptor.
pub const SYS_READ: usize = 5;
/// `Write`, to a file or a pipe.
pub const SYS_WRITE: usize = 6;
/// `Close`.
pub const SYS_CLOSE: usize = 7;
/// `Stat`, by path.
pub const SYS_STAT: usize = 27;
/// `ReadDir`, by path and index.
pub const SYS_READ_DIR: usize = 28;
/// `OpenAt`, relative to a descriptor.
pub const SYS_OPEN_AT: usize = 32;
/// `StatAt`, relative to a descriptor.
pub const SYS_STAT_AT: usize = 33;
/// `RenameAt`, each side anchored at its own descriptor.
pub const SYS_RENAME_AT: usize = 34;
/// `CreateDirAt`, relative to a descriptor.
pub const SYS_CREATE_DIR_AT: usize = 35;
/// `RemovePathAt`, relative to a descriptor.
pub const SYS_REMOVE_PATH_AT: usize = 36;
/// `SendSignal`, a signal to one process.
pub const SYS_SEND_SIGNAL: usize = 40;
/// `WaitSignal`, one pending signal's record.
pub const SYS_WAIT_SIGNAL: usize = 41;
/// `SpawnProcess`, a new process running the program at a path.
pub const SYS_SPAWN_PROCESS: usize = 25;
/// `GetPpid`, the caller's parent.
pub const SYS_GETPPID: usize = 82;
/// `SIGUSR1`, the signal a program may use for anything of its own.
pub const SIGUSR1: usize = 10;
/// `SetSignalMask`, the caller's block set.
pub const SYS_SET_SIGNAL_MASK: usize = 94;
/// `SigSuspend`, a ring run under a mask until an unblocked signal answers.
pub const SYS_SIGSUSPEND: usize = 135;
/// `WaitProcessOf`, one named process's exit status.
pub const SYS_WAIT_PROCESS_OF: usize = 196;
/// `Mmap`, anonymous private memory.
pub const SYS_MMAP: usize = 67;
/// `Brk`, the program's break.
pub const SYS_BRK: usize = 92;

// The flags and values the wrappers' callers pass.

/// Open for reading only.
pub const OPEN_READ: usize = 1;
/// Open for writing, creating the file when it is not there.
pub const OPEN_WRITE_CREATE: usize = 2 | 4;
/// Readable and writable, and not executable: the kernel refuses
/// write-xor-execute together, and a page of data is not a page of code.
pub const PROT_READ_WRITE: usize = 1 | 2;
/// Anonymous private memory: the only kind this kernel maps.
pub const MAP_ANONYMOUS_PRIVATE: usize = 0x20 | 0x02;
/// One page, the smallest mapping worth asking for.
pub const MMAP_BYTES: usize = 4096;
/// The descriptor value that means "resolve from the caller's own base".
pub const AT_FDCWD: usize = (-100_isize) as usize;

// The gate, one per machine.
//
// Six argument words in, one answer out — the whole of the ABI's calling
// convention, which is why there is one of these and not one per operation.

/// The call gate: `int 0x80`, arguments in `rdi`..`r9`, answer in `rax`.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub fn syscall6(
    number: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) -> usize {
    let answer: u64;
    // SAFETY: `int 0x80` with the arguments in the registers the ABI names;
    // the kernel validates every one of them and answers with a value.
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") number as u64 => answer,
            in("rdi") a0 as u64,
            in("rsi") a1 as u64,
            in("rdx") a2 as u64,
            // `int 0x80`, so the fourth argument is `rcx` and not `r10`: the
            // tree's call gate is the interrupt, and the trap entry reads the
            // six words from `rdi, rsi, rdx, rcx, r8, r9`.  Writing `r10` put
            // the flags where nothing reads them, and every call was refused
            // as `InvalidArgument` — measured, both calls answered `-1` on
            // x86_64 while the other two machines were fine.
            in("rcx") a3 as u64,
            in("r8") a4 as u64,
            in("r9") a5 as u64,
            options(nostack)
        );
    }
    answer as usize
}

/// The call gate: `svc #0`, number in `x8`, arguments in `x0`..`x5`.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub fn syscall6(
    number: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) -> usize {
    let answer: usize;
    // SAFETY: `svc #0` with the arguments in the registers the ABI names.
    unsafe {
        asm!(
            "svc #0",
            in("x8") number,
            inlateout("x0") a0 => answer,
            in("x1") a1,
            in("x2") a2,
            in("x3") a3,
            in("x4") a4,
            in("x5") a5,
            options(nostack)
        );
    }
    answer
}

/// The call gate: `ecall`, number in `a7`, arguments in `a0`..`a5`.
#[cfg(all(target_os = "none", target_arch = "riscv64"))]
pub fn syscall6(
    number: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) -> usize {
    let answer: usize;
    // SAFETY: `ecall` with the arguments in the registers the ABI names.
    unsafe {
        asm!(
            "ecall",
            in("a7") number,
            inlateout("a0") a0 => answer,
            in("a1") a1,
            in("a2") a2,
            in("a3") a3,
            in("a4") a4,
            in("a5") a5,
            options(nostack)
        );
    }
    answer
}

/// `exit(status)`: control does not come back.
///
/// One piece of assembly per machine beside the gate, because the gate
/// returns and this does not: a wrapper over the gate would have to lie
/// about what happens after it.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
pub fn sys_exit(status: usize) -> ! {
    unsafe {
        asm!(
            "int 0x80",
            in("rax") SYS_EXIT as u64,
            in("rdi") status as u64,
            options(noreturn, nostack)
        );
    }
}

/// `exit(status)`: control does not come back.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
pub fn sys_exit(status: usize) -> ! {
    unsafe {
        asm!(
            "svc #0",
            in("x8") SYS_EXIT,
            in("x0") status,
            options(noreturn, nostack)
        );
    }
}

/// `exit(status)`: control does not come back.
#[cfg(all(target_os = "none", target_arch = "riscv64"))]
pub fn sys_exit(status: usize) -> ! {
    unsafe {
        asm!(
            "ecall",
            in("a7") SYS_EXIT,
            in("a0") status,
            options(noreturn, nostack)
        );
    }
}

// The operations, machine-independent: each names its number and packs its
// slots, which is the whole of what a wrapper is for.

/// `open(path, flags)`: the descriptor, or the ABI's error encoding.
///
/// `path` is a NUL-terminated string's address, the shape the kernel's copy
/// reads; the wrappers take addresses rather than slices because a slice
/// with a NUL in it is a slice that lies about where the string ends.
#[cfg(target_os = "none")]
pub fn sys_open(path: usize, flags: usize) -> usize {
    syscall6(SYS_OPEN, path, flags, 0, 0, 0, 0)
}

/// `read(descriptor, buffer)`: the byte count.
///
/// Reads from the descriptor's own position, which is what a caller that
/// just wants the next bytes asks for; the offset slot travels as
/// `READ_OFFSET_CURRENT`.
#[cfg(target_os = "none")]
pub fn sys_read(descriptor: usize, buffer: &mut [u8]) -> usize {
    syscall6(
        SYS_READ,
        descriptor,
        usize::MAX,
        buffer.as_mut_ptr() as usize,
        buffer.len(),
        0,
        0,
    )
}

/// `write(descriptor, buffer)`: the bytes accepted.
#[cfg(target_os = "none")]
pub fn sys_write(descriptor: usize, buffer: &[u8]) -> usize {
    syscall6(
        SYS_WRITE,
        descriptor,
        buffer.as_ptr() as usize,
        buffer.len(),
        0,
        0,
        0,
    )
}

/// `close(descriptor)`.
#[cfg(target_os = "none")]
pub fn sys_close(descriptor: usize) -> usize {
    syscall6(SYS_CLOSE, descriptor, 0, 0, 0, 0, 0)
}

/// `stat(path, record)`: zero, with the record filled.
///
/// The record is the ABI's `FileStat`: kind in the first word, size in the
/// second, little-endian — [`stat_words`] is the read-back side of that.
#[cfg(target_os = "none")]
pub fn sys_stat(path: usize, record: &mut [u8; 16]) -> usize {
    syscall6(
        SYS_STAT,
        path,
        record.as_mut_ptr() as usize,
        record.len(),
        0,
        0,
        0,
    )
}

/// `read_dir(path, index, buffer)`: the bytes written.
#[cfg(target_os = "none")]
pub fn sys_read_dir(path: usize, index: usize, buffer: &mut [u8]) -> usize {
    syscall6(
        SYS_READ_DIR,
        path,
        index,
        buffer.as_mut_ptr() as usize,
        buffer.len(),
        0,
        0,
    )
}

/// `open_at(dirfd, path, flags)`: the descriptor, or the error encoding.
#[cfg(target_os = "none")]
pub fn sys_open_at(dirfd: usize, path: usize, flags: usize) -> usize {
    syscall6(SYS_OPEN_AT, dirfd, path, flags, 0, 0, 0)
}

/// `stat_at(dirfd, path, record)`: zero, with the record filled.
#[cfg(target_os = "none")]
pub fn sys_stat_at(dirfd: usize, path: usize, record: &mut [u8; 16]) -> usize {
    syscall6(
        SYS_STAT_AT,
        dirfd,
        path,
        record.as_mut_ptr() as usize,
        record.len(),
        0,
        0,
    )
}

/// `rename_at(old_dirfd, old_path, new_dirfd, new_path)`.
#[cfg(target_os = "none")]
pub fn sys_rename_at(
    old_dirfd: usize,
    old_path: usize,
    new_dirfd: usize,
    new_path: usize,
) -> usize {
    syscall6(
        SYS_RENAME_AT,
        old_dirfd,
        old_path,
        new_dirfd,
        new_path,
        0,
        0,
    )
}

/// `create_dir_at(dirfd, path)`.
#[cfg(target_os = "none")]
pub fn sys_create_dir_at(dirfd: usize, path: usize) -> usize {
    syscall6(SYS_CREATE_DIR_AT, dirfd, path, 0, 0, 0, 0)
}

/// `remove_path_at(dirfd, path)`.
#[cfg(target_os = "none")]
pub fn sys_remove_path_at(dirfd: usize, path: usize) -> usize {
    syscall6(SYS_REMOVE_PATH_AT, dirfd, path, 0, 0, 0, 0)
}

/// `send_signal(pid, signal, payload)`: zero, or the error encoding.
#[cfg(target_os = "none")]
pub fn sys_send_signal(pid: usize, signal: usize, payload: usize) -> usize {
    syscall6(SYS_SEND_SIGNAL, pid, signal, payload, 0, 0, 0)
}

/// `wait_signal(record)`: zero, with the record filled — the signal, its
/// sender, and the sender's payload.  Blocks until a signal arrives.
#[cfg(target_os = "none")]
pub fn sys_wait_signal(record: &mut [u8; 24]) -> usize {
    syscall6(
        SYS_WAIT_SIGNAL,
        record.as_mut_ptr() as usize,
        record.len(),
        0,
        0,
        0,
        0,
    )
}

/// `set_signal_mask(mask)`: the mask the caller had.
#[cfg(target_os = "none")]
pub fn sys_set_signal_mask(mask: usize) -> usize {
    syscall6(SYS_SET_SIGNAL_MASK, mask, 0, 0, 0, 0, 0)
}

/// `sigsuspend(mask, record)`: zero, with the record filled — an unblocked
/// signal that arrived under the mask, with the previous mask put back.
#[cfg(target_os = "none")]
pub fn sys_sigsuspend(mask: usize, record: &mut [u8; 24]) -> usize {
    syscall6(
        SYS_SIGSUSPEND,
        mask,
        0,
        record.as_mut_ptr() as usize,
        record.len(),
        0,
        0,
    )
}

/// `get_ppid()`: the caller's parent's pid.
#[cfg(target_os = "none")]
pub fn sys_get_ppid() -> usize {
    syscall6(SYS_GETPPID, 0, 0, 0, 0, 0, 0)
}

/// `spawn_process(path)`: the new process's pid, or the error encoding.
///
/// The caller becomes the parent, which is what makes the pid worth
/// having: the wait that supervises names it.
#[cfg(target_os = "none")]
pub fn sys_spawn(path: usize) -> usize {
    syscall6(SYS_SPAWN_PROCESS, path, 0, 0, 0, 0, 0)
}

/// `wait_process_of(pid)`: that process's exit status.
///
/// Blocks until the named process has ended; a pid that is not a process of
/// this boot answers the error encoding rather than parking for ever.
#[cfg(target_os = "none")]
pub fn sys_wait_process_of(pid: usize) -> usize {
    syscall6(SYS_WAIT_PROCESS_OF, pid, 0, 0, 0, 0, 0)
}

/// `mmap(hint, length, prot, flags)`: the base address, or an error encoding.
#[cfg(target_os = "none")]
pub fn sys_mmap(hint: usize, length: usize, protection: usize, flags: usize) -> usize {
    syscall6(SYS_MMAP, hint, length, protection, flags, 0, 0)
}

/// `brk(new_break)`: the break the kernel now holds.
#[cfg(target_os = "none")]
pub fn sys_brk(requested: usize) -> usize {
    syscall6(SYS_BRK, requested, 0, 0, 0, 0, 0)
}

/// Whether a syscall's answer is the ABI's error encoding.
///
/// The ABI encodes an error as a word with its high bit set, which is the one
/// test a program needs: a successful answer is a small positive number — a
/// descriptor, a count, an address inside the user window.
#[cfg(target_os = "none")]
pub const fn is_error(answer: usize) -> bool {
    answer & (1 << (usize::BITS - 1)) != 0
}

/// End the program because a step did not do what it was told.
///
/// Any answer the caller cannot use ends it here, with a status the boot's
/// exit line shows as not the program's ordinary byte — which is how a
/// broken step turns the gate red instead of the program printing something
/// plausible and carrying on over a hole.  Which step broke is the kernel
/// log's to say: every call's answer is printed beside the mechanism that
/// served it.
#[cfg(target_os = "none")]
pub fn insist(answer: usize) -> usize {
    if is_error(answer) {
        sys_exit(200);
    }
    answer
}

/// The three words of a filled `ProcessSignalRecord`: the signal, its
/// sender, and the sender's payload — the read-back side of what
/// `wait_signal` fills.
#[cfg(target_os = "none")]
pub fn signal_words(record: &[u8; 24]) -> (usize, usize, usize) {
    let mut signal = [0u8; 8];
    let mut sender = [0u8; 8];
    let mut payload = [0u8; 8];
    signal.copy_from_slice(&record[..8]);
    sender.copy_from_slice(&record[8..16]);
    payload.copy_from_slice(&record[16..]);
    (
        usize::from_le_bytes(signal),
        usize::from_le_bytes(sender),
        usize::from_le_bytes(payload),
    )
}

/// The two words of a filled `FileStat` record, as the ABI lays them out.
#[cfg(target_os = "none")]
pub fn stat_words(record: &[u8; 16]) -> (usize, usize) {
    let mut kind_bytes = [0u8; 8];
    let mut size_bytes = [0u8; 8];
    kind_bytes.copy_from_slice(&record[..8]);
    size_bytes.copy_from_slice(&record[8..]);
    (
        usize::from_le_bytes(kind_bytes),
        usize::from_le_bytes(size_bytes),
    )
}

#[cfg(test)]
mod tests {
    //! The program-side numbering, pinned to the ABI's own enum.
    //!
    //! The constants above are a copy of `abi`'s numbers — a program cannot
    //! depend on the kernel's crate, so the copy is the price of the layer,
    //! and a copy without a test is a second place for one fact to drift,
    //! which is the failure this crate exists to prevent.  The
    //! dev-dependency that makes these tests possible is one no program
    //! build carries: `cargo metadata` reports dev-dependencies to the
    //! layering gate, and the gate does not count one as an edge.

    use super::SYS_BRK;
    use super::SYS_CLOSE;
    use super::SYS_CREATE_DIR_AT;
    use super::SYS_GETPPID;
    use super::SYS_MMAP;
    use super::SYS_OPEN;
    use super::SYS_OPEN_AT;
    use super::SYS_READ;
    use super::SYS_READ_DIR;
    use super::SYS_REMOVE_PATH_AT;
    use super::SYS_RENAME_AT;
    use super::SYS_SEND_SIGNAL;
    use super::SYS_SET_SIGNAL_MASK;
    use super::SYS_SIGSUSPEND;
    use super::SYS_SPAWN_PROCESS;
    use super::SYS_STAT;
    use super::SYS_STAT_AT;
    use super::SYS_WAIT_PROCESS_OF;
    use super::SYS_WAIT_SIGNAL;
    use super::SYS_WRITE;

    /// Every number this crate names is the ABI's own, by value.
    #[test]
    fn the_program_side_numbers_are_the_abi_s_own() {
        use abi::SyscallNumber;
        assert_eq!(SYS_OPEN, SyscallNumber::Open as usize);
        assert_eq!(SYS_READ, SyscallNumber::Read as usize);
        assert_eq!(SYS_WRITE, SyscallNumber::Write as usize);
        assert_eq!(SYS_CLOSE, SyscallNumber::Close as usize);
        assert_eq!(SYS_STAT, SyscallNumber::Stat as usize);
        assert_eq!(SYS_READ_DIR, SyscallNumber::ReadDir as usize);
        assert_eq!(SYS_OPEN_AT, SyscallNumber::OpenAt as usize);
        assert_eq!(SYS_STAT_AT, SyscallNumber::StatAt as usize);
        assert_eq!(SYS_RENAME_AT, SyscallNumber::RenameAt as usize);
        assert_eq!(SYS_CREATE_DIR_AT, SyscallNumber::CreateDirAt as usize);
        assert_eq!(SYS_REMOVE_PATH_AT, SyscallNumber::RemovePathAt as usize);
        assert_eq!(SYS_MMAP, SyscallNumber::Mmap as usize);
        assert_eq!(SYS_BRK, SyscallNumber::Brk as usize);
        assert_eq!(SYS_SEND_SIGNAL, SyscallNumber::SendSignal as usize);
        assert_eq!(SYS_SET_SIGNAL_MASK, SyscallNumber::SetSignalMask as usize);
        assert_eq!(SYS_SIGSUSPEND, SyscallNumber::SigSuspend as usize);
        assert_eq!(SYS_WAIT_SIGNAL, SyscallNumber::WaitSignal as usize);
        assert_eq!(SYS_GETPPID, SyscallNumber::GetPpid as usize);
        assert_eq!(SYS_SPAWN_PROCESS, SyscallNumber::SpawnProcess as usize);
        assert_eq!(SYS_WAIT_PROCESS_OF, SyscallNumber::WaitProcessOf as usize);
    }

    /// The frozen range's boundary, from the program's side: a number a
    /// program hard-codes is a number these constants have to keep being.
    #[test]
    fn the_frozen_numbers_this_crate_carries_have_not_moved() {
        use abi::SyscallNumber;
        assert_eq!(SYS_OPEN, 2);
        assert_eq!(SYS_READ, 5);
        assert_eq!(SYS_WRITE, 6);
        assert_eq!(SYS_CLOSE, 7);
        assert_eq!(SYS_MMAP, 67);
        assert_eq!(SYS_BRK, 92);
        assert_eq!(SyscallNumber::EpollWait as usize, 120);
    }
}
