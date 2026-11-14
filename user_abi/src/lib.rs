//! user_abi/src/lib.rs
//!
//! The wrappers a program of this kernel is written against: the numbering,
//! the one call gate per machine, and the typed-on-nothing helpers above them.
//!
//! ## Why this crate exists
//!
//! `docs/fmts/syscall-abi.md` §8 records the convention and the reason: a
//! program carries no kernel crate, so without a crate both sides compile
//! against, every program spells the gate itself, and two programs that each
//! spell it are two places for one fact to drift.  This is that crate.
//!
//! ## Where the numbering lives
//!
//! In `abi`, beside the records and the flags it names with it.  The numbers
//! are the one thing of this tree both sides of the privilege boundary name,
//! and this tree's `abi` carries nothing of the kernel that a program would
//! inherit by naming it, so every constant here is derived from abi's own
//! value, and a number that moves in `abi` breaks this crate's build instead
//! of drifting until a host test notices.  (The literal copy this crate used
//! to carry, and its justification, "a program compiles against the
//! numbering, not against the kernel's `abi` crate", were the previous
//! tree's, where `abi` did carry the kernel.)  The call-site names stay this
//! crate's: a program writes `SYS_OPEN`, and the enum keeps the wire's own
//! spelling.
//!
//! ## The shape
//!
//! One gate per machine, six argument words in, one answer out, plus the
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

// The numbering, taken from `abi`: each constant here is the call-site
// spelling of one of the ABI's own values.

use abi::SyscallNumber;

/// `Open`, and the rest of the file interface.
pub const SYS_OPEN: usize = SyscallNumber::Open as usize;
/// `Exit`.
pub const SYS_EXIT: usize = SyscallNumber::Exit as usize;
/// `Read`, from a descriptor.
pub const SYS_READ: usize = SyscallNumber::Read as usize;
/// `Write`, to a file or a pipe.
pub const SYS_WRITE: usize = SyscallNumber::Write as usize;
/// `Close`.
pub const SYS_CLOSE: usize = SyscallNumber::Close as usize;
/// `Stat`, by path.
pub const SYS_STAT: usize = SyscallNumber::Stat as usize;
/// `ReadDir`, by path and index.
pub const SYS_READ_DIR: usize = SyscallNumber::ReadDir as usize;
/// `OpenAt`, relative to a descriptor.
pub const SYS_OPEN_AT: usize = SyscallNumber::OpenAt as usize;
/// `StatAt`, relative to a descriptor.
pub const SYS_STAT_AT: usize = SyscallNumber::StatAt as usize;
/// `RenameAt`, each side anchored at its own descriptor.
pub const SYS_RENAME_AT: usize = SyscallNumber::RenameAt as usize;
/// `CreateDirAt`, relative to a descriptor.
pub const SYS_CREATE_DIR_AT: usize = SyscallNumber::CreateDirAt as usize;
/// `RemovePathAt`, relative to a descriptor.
pub const SYS_REMOVE_PATH_AT: usize = SyscallNumber::RemovePathAt as usize;
/// `SendSignal`, a signal to one process.
pub const SYS_SEND_SIGNAL: usize = SyscallNumber::SendSignal as usize;
/// `WaitSignal`, one pending signal's record.
pub const SYS_WAIT_SIGNAL: usize = SyscallNumber::WaitSignal as usize;
/// `SpawnProcess`, a new process running the program at a path.
pub const SYS_SPAWN_PROCESS: usize = SyscallNumber::SpawnProcess as usize;
/// `Fork`, a copy of the calling process, answered differently on each side.
pub const SYS_FORK: usize = SyscallNumber::Fork as usize;
/// `ConnectTcp`, a stream to an address and a port.
pub const SYS_CONNECT_TCP: usize = SyscallNumber::ConnectTcp as usize;
/// `ListenTcp`, a listening port an accept is called on.
pub const SYS_LISTEN_TCP: usize = SyscallNumber::ListenTcp as usize;
/// `AcceptTcp`, one stream from a listener's pending list.
pub const SYS_ACCEPT_TCP: usize = SyscallNumber::AcceptTcp as usize;
/// `GetPpid`, the caller's parent.
pub const SYS_GETPPID: usize = SyscallNumber::GetPpid as usize;
/// `SIGUSR1`, the signal a program may use for anything of its own.
pub use abi::process::SIGUSR1;
/// `SetSignalMask`, the caller's block set.
pub const SYS_SET_SIGNAL_MASK: usize = SyscallNumber::SetSignalMask as usize;
/// `SigSuspend`, a ring run under a mask until an unblocked signal answers.
pub const SYS_SIGSUSPEND: usize = SyscallNumber::SigSuspend as usize;
/// `SetSignalHandler`, the program's own code for one signal.
pub const SYS_SET_SIGNAL_HANDLER: usize = SyscallNumber::SetSignalHandler as usize;
/// `SigReturn`, the resume a delivered signal's handler exits through.
pub const SYS_SIGRETURN: usize = SyscallNumber::SigReturn as usize;
/// `WaitProcessOf`, one named process's exit status.
pub const SYS_WAIT_PROCESS_OF: usize = SyscallNumber::WaitProcessOf as usize;
/// `Mmap`, anonymous private memory.
pub const SYS_MMAP: usize = SyscallNumber::Mmap as usize;
/// `Brk`, the program's break.
pub const SYS_BRK: usize = SyscallNumber::Brk as usize;
/// `AbiInfo`, what this build's interface is.
pub const SYS_ABI_INFO: usize = SyscallNumber::AbiInfo as usize;
/// `SystemInfo`, what the machine has been doing.
pub const SYS_SYSTEM_INFO: usize = SyscallNumber::SystemInfo as usize;
/// `GetTimeOfDay`, one clock's reading.
pub const SYS_GET_TIME_OF_DAY: usize = SyscallNumber::GetTimeOfDay as usize;
/// `GetRandom`, bytes from the kernel's generator.
pub const SYS_GET_RANDOM: usize = SyscallNumber::GetRandom as usize;
/// The selector `SystemInfo` serves.
pub use abi::system::SYSTEM_INFO_SCHEDULER;
/// `NetworkStatus`, what the machine's network is.
pub const SYS_NETWORK_STATUS: usize = SyscallNumber::NetworkStatus as usize;
/// `BindUdp`, a datagram socket on a port.
pub const SYS_BIND_UDP: usize = SyscallNumber::BindUdp as usize;
/// `SendToUdp`, one datagram out.
pub const SYS_SEND_TO_UDP: usize = SyscallNumber::SendToUdp as usize;
/// `RecvFromUdp`, one datagram in.
pub const SYS_RECV_FROM_UDP: usize = SyscallNumber::RecvFromUdp as usize;
/// A `NetworkStatus` record is a word of state and fourteen address bytes.
pub const NETWORK_STATUS_BYTES: usize = core::mem::size_of::<abi::network::NetworkStatusRecord>();
/// `ipv6_status(record)`: the interface's IPv6 side.
pub const SYS_IPV6_STATUS: usize = SyscallNumber::Ipv6Status as usize;
/// Whether a status word means failure.
///
/// Re-exported so a program that calls these wrappers does not also have to
/// name `abi`: the two crates are one ABI seen from two sides, and a program
/// that had to import both would be choosing between them for no reason.
pub use abi::syscall::is_error_status;

/// Decode a status word into the error it carries, or `None` when it is a
/// success.
///
/// Re-exported with `is_error_status` for the same reason: a program that
/// calls these wrappers and checks a status needs the error the status means,
/// and it should not have to name `abi` to find out.
pub fn decode_error(status: usize) -> Option<abi::Error> {
    abi::syscall::decode_result(status).err()
}

/// Whether a status word is the refusal a number this build does not serve
/// answers.
///
/// The one answer that means "this call was never wired", which is what a
/// program checking that a number reached a handler must rule out: every other
/// refusal says something about the arguments or the machine, and this one says
/// something about the build.
pub fn is_not_implemented(status: usize) -> bool {
    decode_error(status) == Some(abi::Error::NotImplemented)
}

/// The size of the `sockaddr_in` record `GetSockName` and `GetPeerName`
/// write, derived from the ABI's own type rather than restated.
pub const SOCKADDR_IN_BYTES: usize = abi::network::SOCKADDR_IN_SIZE;

/// The family word of a `sockaddr_in` record, in the host's byte order.
pub fn sockaddr_family(record: &[u8]) -> u16 {
    u16::from_ne_bytes([
        record[abi::network::SOCKADDR_IN_FAMILY_OFFSET],
        record[abi::network::SOCKADDR_IN_FAMILY_OFFSET + 1],
    ])
}

/// The port of a `sockaddr_in` record, read back out of network order into the
/// host's.
pub fn sockaddr_port(record: &[u8]) -> u16 {
    u16::from_be_bytes([
        record[abi::network::SOCKADDR_IN_PORT_OFFSET],
        record[abi::network::SOCKADDR_IN_PORT_OFFSET + 1],
    ])
}

/// The address of a `sockaddr_in` record.
pub fn sockaddr_address(record: &[u8]) -> [u8; 4] {
    let at = abi::network::SOCKADDR_IN_ADDRESS_OFFSET;
    [record[at], record[at + 1], record[at + 2], record[at + 3]]
}

pub const SYS_GET_HOST_NAME: usize = SyscallNumber::GetHostName as usize;
pub const SYS_SET_HOST_NAME: usize = SyscallNumber::SetHostName as usize;
pub const SYS_GET_SOCK_NAME: usize = SyscallNumber::GetSockName as usize;
pub const SYS_GET_PEER_NAME: usize = SyscallNumber::GetPeerName as usize;
pub const SYS_RESOLVE_HOSTNAME: usize = SyscallNumber::ResolveHostname as usize;
/// The two option calls, and the level and names this build serves.
pub const SYS_SET_SOCK_OPT: usize = SyscallNumber::SetSockOpt as usize;
pub const SYS_GET_SOCK_OPT: usize = SyscallNumber::GetSockOpt as usize;
pub use abi::network::IPPROTO_TCP;
pub use abi::network::SO_RCVBUF;
pub use abi::network::SO_SNDBUF;
pub use abi::network::SOL_SOCKET;
pub use abi::network::TCP_NODELAY;
pub const IPV6_STATUS_BYTES: usize = core::mem::size_of::<abi::network::Ipv6StatusRecord>();
/// The state word for a card the kernel drives.
pub use abi::network::NETWORK_STATUS_UP;
/// The machine's own counter, the only clock this build answers.
pub use abi::time::CLOCK_MONOTONIC;
/// An `AbiInfo` record is three words.
pub const ABI_INFO_BYTES: usize = core::mem::size_of::<abi::AbiInfo>();
/// A `SystemInfo` record is eight words.
pub const SYSTEM_INFO_BYTES: usize = core::mem::size_of::<abi::SystemInfo>();
/// A `TimeRecord` is two words.
pub const TIME_RECORD_BYTES: usize = core::mem::size_of::<abi::time::TimeRecord>();

// The flags and values the wrappers' callers pass, taken from `abi` where abi
// names them.  `MMAP_BYTES` is the one literal: it is a call-site convenience
// one page, the smallest mapping worth asking for, and not a wire value.

/// Open for reading only.
pub const OPEN_READ: usize = abi::fs::OPEN_FLAG_READ;
/// Open for writing, creating the file when it is not there.
pub const OPEN_WRITE_CREATE: usize = abi::fs::OPEN_FLAG_WRITE | abi::fs::OPEN_FLAG_CREATE;
/// Readable and writable, and not executable: the kernel refuses
/// write-xor-execute together, and a page of data is not a page of code.
pub const PROT_READ_WRITE: usize = abi::memory::PROT_READ | abi::memory::PROT_WRITE;
/// Anonymous private memory: the only kind this kernel maps.
pub const MAP_ANONYMOUS_PRIVATE: usize = abi::memory::MAP_ANONYMOUS | abi::memory::MAP_PRIVATE;
/// One page, the smallest mapping worth asking for.
pub const MMAP_BYTES: usize = 4096;
/// The descriptor value that means "resolve from the caller's own base".
pub use abi::fs::AT_FDCWD;

// The gate, one per machine.
//
// Six argument words in, one answer out, the whole of the ABI's calling
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
            // as `InvalidArgument`, measured, both calls answered `-1` on
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
/// second, little-endian, [`stat_words`] is the read-back side of that.
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

/// `wait_signal(record)`: zero, with the record filled, the signal, its
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

/// `sigsuspend(mask, record)`: zero, with the record filled, an unblocked
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

/// `set_signal_handler(signal, action, handler)`: zero when the action was
/// taken.  Action `1` installs, `0` withdraws.
#[cfg(target_os = "none")]
pub fn sys_set_signal_handler(signal: usize, action: usize, handler: usize) -> usize {
    syscall6(SYS_SET_SIGNAL_HANDLER, signal, action, handler, 0, 0, 0)
}

/// `sigreturn(resume)`: the delivered-signal handler's way out.  The kernel
/// puts the displaced registers back and the interrupted flow resumes at
/// `resume`; control does not come back to the handler.
#[cfg(target_os = "none")]
pub fn sys_sigreturn(resume: usize) -> usize {
    syscall6(SYS_SIGRETURN, resume, 0, 0, 0, 0, 0)
}

/// `return_from_exception(resume, value)`: the handler's way out.  The
/// interrupted flow resumes at `resume`, reading `value` as the interrupted
/// call's answer; control does not come back to the handler.
#[cfg(target_os = "none")]
pub fn sys_return_from_exception(resume: usize, value: usize) -> usize {
    syscall6(
        SyscallNumber::ReturnFromException as usize,
        resume,
        value,
        0,
        0,
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

/// `fork()`: the child learns zero, the parent learns the child's pid.
#[cfg(target_os = "none")]
pub fn sys_fork() -> usize {
    syscall6(SYS_FORK, 0, 0, 0, 0, 0, 0)
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

/// `get_time_of_day(clock, record)`: zero, with the record filled.
#[cfg(target_os = "none")]
pub fn sys_get_time_of_day(clock: usize, record: &mut [u8; TIME_RECORD_BYTES]) -> usize {
    syscall6(
        SYS_GET_TIME_OF_DAY,
        clock,
        record.as_mut_ptr() as usize,
        record.len(),
        0,
        0,
        0,
    )
}

/// `get_random(buffer)`: how many bytes were written.
#[cfg(target_os = "none")]
pub fn sys_get_random(buffer: &mut [u8]) -> usize {
    syscall6(
        SYS_GET_RANDOM,
        buffer.as_mut_ptr() as usize,
        buffer.len(),
        0,
        0,
        0,
        0,
    )
}

/// `system_info(selector, record)`: zero, with the record filled.
#[cfg(target_os = "none")]
pub fn sys_system_info(selector: usize, record: &mut [u8; SYSTEM_INFO_BYTES]) -> usize {
    syscall6(
        SYS_SYSTEM_INFO,
        selector,
        record.as_mut_ptr() as usize,
        record.len(),
        0,
        0,
        0,
    )
}

/// `abi_info(record)`: zero, with the record filled.
#[cfg(target_os = "none")]
pub fn sys_abi_info(record: &mut [u8; ABI_INFO_BYTES]) -> usize {
    syscall6(
        SYS_ABI_INFO,
        record.as_mut_ptr() as usize,
        record.len(),
        0,
        0,
        0,
        0,
    )
}

/// `network_status(record)`: zero, with the record filled, whether a card
/// is up, and the addresses it answers for.
#[cfg(target_os = "none")]
pub fn sys_network_status(record: &mut [u8; NETWORK_STATUS_BYTES]) -> usize {
    syscall6(
        SYS_NETWORK_STATUS,
        record.as_mut_ptr() as usize,
        record.len(),
        0,
        0,
        0,
        0,
    )
}

/// `get_host_name(buffer)`: the name's length, or an error status.
///
/// A machine that was never named answers zero, which is not an error: the
/// name is empty and the caller has nothing to print.
#[cfg(target_os = "none")]
pub fn sys_get_host_name(buffer: &mut [u8]) -> usize {
    syscall6(
        SYS_GET_HOST_NAME,
        buffer.as_mut_ptr() as usize,
        buffer.len(),
        0,
        0,
        0,
        0,
    )
}

/// `set_host_name(name)`: zero, or an error status.
#[cfg(target_os = "none")]
pub fn sys_set_host_name(name: &str) -> usize {
    syscall6(
        SYS_SET_HOST_NAME,
        name.as_ptr() as usize,
        name.len(),
        0,
        0,
        0,
        0,
    )
}

/// `get_sock_name(descriptor, buffer)`: the record's size, or an error.
#[cfg(target_os = "none")]
pub fn sys_get_sock_name(descriptor: usize, buffer: &mut [u8]) -> usize {
    syscall6(
        SYS_GET_SOCK_NAME,
        descriptor,
        buffer.as_mut_ptr() as usize,
        buffer.len(),
        0,
        0,
        0,
    )
}

/// `get_peer_name(descriptor, buffer)`: the record's size, or an error.
#[cfg(target_os = "none")]
pub fn sys_get_peer_name(descriptor: usize, buffer: &mut [u8]) -> usize {
    syscall6(
        SYS_GET_PEER_NAME,
        descriptor,
        buffer.as_mut_ptr() as usize,
        buffer.len(),
        0,
        0,
        0,
    )
}

/// `resolve_hostname(name)`: the address as one word in network order, or an
/// error status.
#[cfg(target_os = "none")]
pub fn sys_resolve_hostname(name: &str) -> usize {
    syscall6(
        SYS_RESOLVE_HOSTNAME,
        name.as_ptr() as usize,
        name.len(),
        0,
        0,
        0,
        0,
    )
}

/// `set_sock_opt(descriptor, level, name, value)`: zero, or an error status.
///
/// The value is a byte for a flag and a word for a size, which is what
/// [`abi::network`] states for each option; a caller that passes the wrong
/// width for the option it names gets `InvalidArgument` rather than a value
/// this stack read out of padding.
#[cfg(target_os = "none")]
pub fn sys_set_sock_opt(descriptor: usize, level: u32, name: u32, value: &[u8]) -> usize {
    syscall6(
        SYS_SET_SOCK_OPT,
        descriptor,
        level as usize,
        name as usize,
        value.as_ptr() as usize,
        value.len(),
        0,
    )
}

/// `get_sock_opt(descriptor, level, name, buffer)`: the bytes written, or an
/// error status.
#[cfg(target_os = "none")]
pub fn sys_get_sock_opt(descriptor: usize, level: u32, name: u32, buffer: &mut [u8]) -> usize {
    syscall6(
        SYS_GET_SOCK_OPT,
        descriptor,
        level as usize,
        name as usize,
        buffer.as_mut_ptr() as usize,
        buffer.len(),
        0,
    )
}

/// `ipv6_status(record)`: zero, with the record filled, the interface's
/// link-local address, whether a router configured a global one, and how
/// many neighbours its cache holds.
#[cfg(target_os = "none")]
pub fn sys_ipv6_status(record: &mut [u8; IPV6_STATUS_BYTES]) -> usize {
    syscall6(
        SYS_IPV6_STATUS,
        record.as_mut_ptr() as usize,
        record.len(),
        0,
        0,
        0,
        0,
    )
}

/// `bind_udp(port)`: the descriptor the datagram calls carry back.
#[cfg(target_os = "none")]
pub fn sys_bind_udp(port: usize) -> usize {
    syscall6(SYS_BIND_UDP, port, 0, 0, 0, 0, 0)
}

/// `send_to_udp(descriptor, destination, buffer, port)`: the bytes accepted.
///
/// The destination is four bytes packed into one word by
/// [`user_abi::pack_address`](abi::network::pack_address), the wire's own
/// byte order, because a syscall argument is a word, and an address that
/// crossed as a pointer would be an address this program has no reason to
/// hold.
#[cfg(target_os = "none")]
pub fn sys_send_to_udp(descriptor: usize, destination: usize, buffer: &[u8], port: usize) -> usize {
    syscall6(
        SYS_SEND_TO_UDP,
        descriptor,
        destination,
        buffer.as_ptr() as usize,
        buffer.len(),
        port,
        0,
    )
}

/// `send_to_udp6(descriptor, destination, buffer, port)`: the bytes sent to an
/// IPv6 destination.
///
/// The same number and the same slots as `sys_send_to_udp`; what differs is
/// that `a1` is a pointer to the sixteen-byte address and `a5` carries
/// [`NETWORK_FLAG_IPV6`](abi::network::NETWORK_FLAG_IPV6).  A program that
/// calls the IPv4 form keeps passing zero, which is the whole of what makes
/// this additive.
#[cfg(target_os = "none")]
pub fn sys_send_to_udp6(
    descriptor: usize,
    destination: &[u8; 16],
    buffer: &[u8],
    port: usize,
) -> usize {
    syscall6(
        SYS_SEND_TO_UDP,
        descriptor,
        destination.as_ptr() as usize,
        buffer.as_ptr() as usize,
        buffer.len(),
        port,
        abi::network::NETWORK_FLAG_IPV6,
    )
}

/// `recv_from_udp(descriptor, buffer, sender)`: the bytes received, with
/// `sender` filled by the sender record the ABI defines.  Blocks until a
/// datagram arrives.
#[cfg(target_os = "none")]
pub fn sys_recv_from_udp(
    descriptor: usize,
    buffer: &mut [u8],
    sender: &mut [u8; UDP_SENDER_RECORD_BYTES],
) -> usize {
    syscall6(
        SYS_RECV_FROM_UDP,
        descriptor,
        buffer.as_mut_ptr() as usize,
        buffer.len(),
        sender.as_mut_ptr() as usize,
        sender.len(),
        0,
    )
}

/// A `UdpSender6Record` is a sixteen-byte address and a word of port.
pub const UDP_SENDER6_RECORD_BYTES: usize = core::mem::size_of::<abi::network::UdpSender6Record>();

/// `recv_from_udp6(descriptor, buffer, sender)`: a datagram whose sender may
/// be an IPv6 address.
///
/// The same number as `sys_recv_from_udp`, with the flag set: `a4` names the
/// wider record's length, which is what the kernel checks before it writes.
#[cfg(target_os = "none")]
pub fn sys_recv_from_udp6(
    descriptor: usize,
    buffer: &mut [u8],
    sender: &mut [u8; UDP_SENDER6_RECORD_BYTES],
) -> usize {
    syscall6(
        SYS_RECV_FROM_UDP,
        descriptor,
        buffer.as_mut_ptr() as usize,
        buffer.len(),
        sender.as_mut_ptr() as usize,
        sender.len(),
        abi::network::NETWORK_FLAG_IPV6,
    )
}

/// A filled `UdpSender6Record`, read back: where the datagram came from.
#[cfg(target_os = "none")]
pub fn sender6_record(record: &[u8; UDP_SENDER6_RECORD_BYTES]) -> ([u8; 16], usize) {
    let mut address = [0_u8; 16];
    address.copy_from_slice(&record[..16]);
    let port = usize::from_le_bytes(
        record[16..16 + core::mem::size_of::<usize>()]
            .try_into()
            .expect("the port word"),
    );
    (address, port)
}

/// `listen_tcp(port)`: the descriptor the accept is called on.
#[cfg(target_os = "none")]
pub fn sys_listen_tcp(port: usize) -> usize {
    syscall6(SYS_LISTEN_TCP, port, 0, 0, 0, 0, 0)
}

/// `connect_tcp(destination, port)`: the descriptor the stream is read and
/// written through.  The destination is packed the way `send_to_udp`'s is.
#[cfg(target_os = "none")]
pub fn sys_connect_tcp(destination: usize, port: usize) -> usize {
    syscall6(SYS_CONNECT_TCP, destination, port, 0, 0, 0, 0)
}

/// `connect_tcp6(destination, port)`: a stream to an IPv6 peer.
///
/// The same number as `sys_connect_tcp`, with `a0` a pointer to sixteen bytes
/// instead of a packed word and `a2` carrying the flag.
#[cfg(target_os = "none")]
pub fn sys_connect_tcp6(destination: &[u8; 16], port: usize) -> usize {
    syscall6(
        SYS_CONNECT_TCP,
        destination.as_ptr() as usize,
        port,
        abi::network::NETWORK_FLAG_IPV6,
        0,
        0,
        0,
    )
}

/// `accept_tcp(listener)`: the descriptor of one stream from the listener's
/// pending list.  Blocks until a client's handshake opens one.
#[cfg(target_os = "none")]
pub fn sys_accept_tcp(listener: usize) -> usize {
    syscall6(SYS_ACCEPT_TCP, listener, 0, 0, 0, 0, 0)
}

/// A `UdpSenderRecord` is two words: the address, then the port.
pub const UDP_SENDER_RECORD_BYTES: usize = core::mem::size_of::<abi::network::UdpSenderRecord>();

/// A filled `UdpSenderRecord`, read back: where the datagram came from, as
/// the four bytes the wire carries and the port they name.
#[cfg(target_os = "none")]
pub fn sender_record(record: &[u8; UDP_SENDER_RECORD_BYTES]) -> ([u8; 4], usize) {
    let mut address = [0u8; 8];
    let mut port = [0u8; 8];
    address.copy_from_slice(&record[..8]);
    port.copy_from_slice(&record[8..]);
    (
        abi::network::unpack_address(usize::from_le_bytes(address)),
        usize::from_le_bytes(port),
    )
}

/// An IPv4 address packed into one word, the first byte in the highest byte
/// of the low word: `10.0.2.2` is `0x0A000202`.
pub use abi::network::pack_address;

/// A filled `NetworkStatus` record, read back: the state word, the card's
/// hardware address, its protocol address, and the gateway.
#[cfg(target_os = "none")]
pub fn network_record(record: &[u8; NETWORK_STATUS_BYTES]) -> (usize, [u8; 6], [u8; 4], [u8; 4]) {
    let mut state_bytes = [0u8; 8];
    state_bytes.copy_from_slice(&record[..8]);
    let mut hardware = [0u8; 6];
    hardware.copy_from_slice(&record[8..14]);
    let mut protocol = [0u8; 4];
    protocol.copy_from_slice(&record[14..18]);
    let mut gateway = [0u8; 4];
    gateway.copy_from_slice(&record[18..22]);
    (
        usize::from_le_bytes(state_bytes),
        hardware,
        protocol,
        gateway,
    )
}

/// The three words and two addresses of an `Ipv6Status` record.
///
/// The addresses are at the offsets `abi::network` names, not at a
/// hand-counted position: the record is `repr(C)` and this is the other side
/// of that boundary, so the two must agree or a program reads its neighbour
/// count out of an address.
#[cfg(target_os = "none")]
pub fn ipv6_status_record(
    record: &[u8; IPV6_STATUS_BYTES],
) -> (usize, usize, usize, [u8; 16], [u8; 16]) {
    let mut state = [0u8; 8];
    state.copy_from_slice(&record[..8]);
    let mut has_global = [0u8; 8];
    has_global.copy_from_slice(&record[8..16]);
    let mut neighbours = [0u8; 8];
    neighbours.copy_from_slice(&record[16..24]);
    let mut link_local = [0u8; 16];
    link_local.copy_from_slice(
        &record[abi::network::IPV6_STATUS_LINK_LOCAL_OFFSET
            ..abi::network::IPV6_STATUS_LINK_LOCAL_OFFSET + 16],
    );
    let mut global = [0u8; 16];
    global.copy_from_slice(
        &record
            [abi::network::IPV6_STATUS_GLOBAL_OFFSET..abi::network::IPV6_STATUS_GLOBAL_OFFSET + 16],
    );
    (
        usize::from_le_bytes(state),
        usize::from_le_bytes(has_global),
        usize::from_le_bytes(neighbours),
        link_local,
        global,
    )
}

/// The two words of a `TimeRecord`: seconds, then nanoseconds.
#[cfg(target_os = "none")]
pub fn time_words(record: &[u8; TIME_RECORD_BYTES]) -> (usize, usize) {
    let mut seconds = [0u8; 8];
    let mut nanoseconds = [0u8; 8];
    seconds.copy_from_slice(&record[..8]);
    nanoseconds.copy_from_slice(&record[8..]);
    (
        usize::from_le_bytes(seconds),
        usize::from_le_bytes(nanoseconds),
    )
}

/// The three words of an `AbiInfo`: version, slot count, frozen count.
#[cfg(target_os = "none")]
pub fn abi_words(record: &[u8; ABI_INFO_BYTES]) -> (usize, usize, usize) {
    let mut words = [0usize; 3];
    for (index, word) in words.iter_mut().enumerate() {
        let mut bytes = [0u8; 8];
        bytes.copy_from_slice(&record[index * 8..index * 8 + 8]);
        *word = usize::from_le_bytes(bytes);
    }
    (words[0], words[1], words[2])
}

/// Whether a syscall's answer is the ABI's error encoding.
///
/// The ABI encodes an error as a word with its high bit set, which is the one
/// test a program needs: a successful answer is a small positive number, a
/// descriptor, a count, an address inside the user window.
#[cfg(target_os = "none")]
pub const fn is_error(answer: usize) -> bool {
    answer & (1 << (usize::BITS - 1)) != 0
}

/// End the program because a step did not do what it was told.
///
/// Any answer the caller cannot use ends it here, with a status the boot's
/// exit line shows as not the program's ordinary byte, which is how a
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
/// sender, and the sender's payload, the read-back side of what
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
    //! The frozen numbers, from the program's side.
    //!
    //! Deriving the constants from `abi` makes a rename there a compile error
    //! here; what a derivation cannot pin is the *value*.  A number a program
    //! hard-codes is a number these constants have to keep being, the frozen
    //! range's own rule, `0..=120` (`docs/fmts/syscall-abi.md`), and these
    //! literals are the guard.  `cargo test -p user_abi` runs them on a host,
    //! with no kernel involved.

    use super::SYS_BRK;
    use super::SYS_CLOSE;
    use super::SYS_MMAP;
    use super::SYS_OPEN;
    use super::SYS_READ;
    use super::SYS_WRITE;

    /// The frozen range's boundary, from the program's side: a number a
    /// program hard-codes is a number these constants have to keep being.
    #[test]
    fn the_frozen_numbers_this_crate_carries_have_not_moved() {
        assert_eq!(SYS_OPEN, 2);
        assert_eq!(SYS_READ, 5);
        assert_eq!(SYS_WRITE, 6);
        assert_eq!(SYS_CLOSE, 7);
        assert_eq!(SYS_MMAP, 67);
        assert_eq!(SYS_BRK, 92);
        assert_eq!(abi::SyscallNumber::EpollWait as usize, 120);
    }
}
