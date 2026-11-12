//! apps/init/src/main.rs
//!
//! `init`: the first program the kernel execs from its own filesystem, in
//! ring 3 — a **compiled** program, not machine code the boot copies from an
//! array.
//!
//! ## What it does, and why that
//!
//! One file read, end to end: `open` the boot's `/greeting.txt`, `read` it,
//! `close` the descriptor, and `exit` with the **first byte**.  That is the
//! whole of the proof that a program built by the workspace's own toolchain,
//! delivered as bytes in a filesystem, was loaded by the kernel's loader,
//! mapped into a fresh address space, and run: the exit status is the file's
//! content, and content cannot be faked by a call that skipped the read.
//! Everything after this — reaping, a shell, services — is more of the same
//! shape, not a new kind.
//!
//! ## Ring 3, and the one boundary the census records
//!
//! `init` runs unprivileged and reaches everything through syscalls, which is
//! the point: a bug here faults this process, not the machine.  The syscalls
//! are inline assembly below, one shape per machine — `int 0x80`, `svc`,
//! `ecall` — behind `cfg(target_arch)`, which is why this file appears in the
//! architecture census with its reason: a program's call gate is its
//! machine's, and the arch layer's own gates cannot speak for ring 3.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
use core::arch::asm;
#[cfg(target_os = "none")]
use core::panic::PanicInfo;

/// The path `init` reads, NUL-terminated in its own `.rodata`.
///
/// A file the boot formats into its volume, so the read is a read of the
/// filesystem the kernel mounted, and not of a constant this program was
/// handed.
#[cfg(target_os = "none")]
static GREETING_PATH: &[u8] = b"/greeting.txt\0";

/// The read's buffer length: longer than the file, shorter than a page.
#[cfg(target_os = "none")]
const BUFFER_LEN: usize = 32;

/// The ABI's syscall numbers, spelled here because a program compiles against
/// the numbering, not against the kernel's crate.
#[cfg(target_os = "none")]
const SYS_OPEN: usize = 2;
#[cfg(target_os = "none")]
const SYS_READ: usize = 5;
#[cfg(target_os = "none")]
const SYS_CLOSE: usize = 7;
#[cfg(target_os = "none")]
const SYS_EXIT: usize = 3;
/// `Mmap`, and the only two of its arguments this program varies.
///
/// The numbers are the ABI's, spelled here for the same reason the file's
/// others are: a program compiles against the numbering and not against the
/// kernel's crate.
#[cfg(target_os = "none")]
const SYS_MMAP: usize = 67;
#[cfg(target_os = "none")]
const SYS_BRK: usize = 92;
/// Readable and writable, which is what a mapping this program stores into
/// needs.  Not executable: the kernel refuses write-xor-execute together, and
/// a page of data is not a page of code.
#[cfg(target_os = "none")]
const PROT_READ_WRITE: usize = 1 | 2;
/// Anonymous private memory: the only kind this kernel maps.
#[cfg(target_os = "none")]
const MAP_ANONYMOUS_PRIVATE: usize = 0x20 | 0x02;
/// One page, which is the smallest mapping worth asking for.
#[cfg(target_os = "none")]
const MMAP_BYTES: usize = 4096;

/// `open(path, OPEN_FLAG_READ)`: the descriptor, or the ABI's error encoding.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn sys_open(path: usize) -> usize {
    let number = SYS_OPEN as u64;
    let flags = 1u64; // OPEN_FLAG_READ
    let answer: u64;
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") number => answer,
            in("rdi") path as u64,
            in("rsi") flags,
            options(nostack)
        );
    }
    answer as usize
}

/// `read(descriptor, offset, buffer, length)`: the byte count.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn sys_read(descriptor: usize, buffer: &mut [u8]) -> usize {
    let number = SYS_READ as u64;
    let offset = usize::MAX as u64; // READ_OFFSET_CURRENT
    let length = buffer.len() as u64;
    let answer: u64;
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") number => answer,
            in("rdi") descriptor as u64,
            in("rsi") offset,
            in("rdx") buffer.as_mut_ptr() as u64,
            in("rcx") length,
            options(nostack)
        );
    }
    answer as usize
}

/// `close(descriptor)`.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn sys_close(descriptor: usize) {
    let number = SYS_CLOSE as u64;
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") number => _,
            in("rdi") descriptor as u64,
            options(nostack)
        );
    }
}

/// `mmap(hint, length, prot, flags)`: the base address, or an error encoding.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn sys_mmap(hint: usize, length: usize, protection: usize, flags: usize) -> usize {
    let number = SYS_MMAP as u64;
    let answer: u64;
    // SAFETY: `int 0x80` with the arguments in the registers the ABI names;
    // the kernel validates every one of them and answers with a value.
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") number => answer,
            in("rdi") hint as u64,
            in("rsi") length as u64,
            in("rdx") protection as u64,
            // `int 0x80`, so the fourth argument is `rcx` and not `r10`: the
            // tree's call gate is the interrupt, and the trap entry reads the
            // six words from `rdi, rsi, rdx, rcx, r8, r9`.  Writing `r10` put
            // the flags where nothing reads them, and every call was refused
            // as `InvalidArgument` — measured, both calls answered `-1` on
            // x86_64 while the other two machines were fine.
            in("rcx") flags as u64,
            in("r8") 0u64,
            in("r9") 0u64,
            options(nostack)
        );
    }
    answer as usize
}

/// `brk(new_break)`: the break the kernel now holds.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn sys_brk(requested: usize) -> usize {
    let number = SYS_BRK as u64;
    let answer: u64;
    // SAFETY: as `sys_mmap`.
    unsafe {
        asm!(
            "int 0x80",
            inlateout("rax") number => answer,
            in("rdi") requested as u64,
            // The ABI requires the unused slots to be zero, and a register
            // holds whatever the last code left in it: a call that left them
            // alone was refused as "a reserved argument that is not zero".
            in("rsi") 0u64,
            in("rdx") 0u64,
            in("rcx") 0u64,
            in("r8") 0u64,
            in("r9") 0u64,
            options(nostack)
        );
    }
    answer as usize
}

/// `exit(status)`: control does not come back.
#[cfg(all(target_os = "none", target_arch = "x86_64"))]
fn sys_exit(status: usize) -> ! {
    unsafe {
        asm!(
            "int 0x80",
            in("rax") SYS_EXIT as u64,
            in("rdi") status as u64,
            options(noreturn, nostack)
        );
    }
}

/// `open(path, OPEN_FLAG_READ)`: the descriptor, or the ABI's error encoding.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
fn sys_open(path: usize) -> usize {
    let answer: usize;
    unsafe {
        asm!(
            "svc #0",
            in("x8") SYS_OPEN,
            inlateout("x0") path => answer,
            in("x1") 1, // OPEN_FLAG_READ
            options(nostack)
        );
    }
    answer
}

/// `read(descriptor, offset, buffer, length)`: the byte count.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
fn sys_read(descriptor: usize, buffer: &mut [u8]) -> usize {
    let answer: usize;
    unsafe {
        asm!(
            "svc #0",
            in("x8") SYS_READ,
            inlateout("x0") descriptor => answer,
            in("x1") usize::MAX, // READ_OFFSET_CURRENT
            in("x2") buffer.as_mut_ptr(),
            in("x3") buffer.len(),
            options(nostack)
        );
    }
    answer
}

/// `close(descriptor)`.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
fn sys_close(descriptor: usize) {
    unsafe {
        asm!(
            "svc #0",
            in("x8") SYS_CLOSE,
            in("x0") descriptor,
            options(nostack)
        );
    }
}

/// `exit(status)`: control does not come back.
/// `mmap(hint, length, prot, flags)`: the base address, or an error encoding.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
fn sys_mmap(hint: usize, length: usize, protection: usize, flags: usize) -> usize {
    let answer: usize;
    // SAFETY: `svc #0` with the arguments in the registers the ABI names.
    unsafe {
        asm!(
            "svc #0",
            in("x8") SYS_MMAP,
            inlateout("x0") hint => answer,
            in("x1") length,
            in("x2") protection,
            in("x3") flags,
            in("x4") 0usize,
            in("x5") 0usize,
            options(nostack)
        );
    }
    answer
}

/// `brk(new_break)`: the break the kernel now holds.
#[cfg(all(target_os = "none", target_arch = "aarch64"))]
fn sys_brk(requested: usize) -> usize {
    let answer: usize;
    // SAFETY: as `sys_mmap`.
    unsafe {
        asm!(
            "svc #0",
            in("x8") SYS_BRK,
            inlateout("x0") requested => answer,
            // Unused slots zero, for the reason the x86_64 arm gives.
            in("x1") 0usize,
            in("x2") 0usize,
            in("x3") 0usize,
            in("x4") 0usize,
            in("x5") 0usize,
            options(nostack)
        );
    }
    answer
}

#[cfg(all(target_os = "none", target_arch = "aarch64"))]
fn sys_exit(status: usize) -> ! {
    unsafe {
        asm!(
            "svc #0",
            in("x8") SYS_EXIT,
            in("x0") status,
            options(noreturn, nostack)
        );
    }
}

/// `open(path, OPEN_FLAG_READ)`: the descriptor, or the ABI's error encoding.
#[cfg(all(target_os = "none", target_arch = "riscv64"))]
fn sys_open(path: usize) -> usize {
    let answer: usize;
    unsafe {
        asm!(
            "ecall",
            in("a7") SYS_OPEN,
            inlateout("a0") path => answer,
            in("a1") 1, // OPEN_FLAG_READ
            options(nostack)
        );
    }
    answer
}

/// `read(descriptor, offset, buffer, length)`: the byte count.
#[cfg(all(target_os = "none", target_arch = "riscv64"))]
fn sys_read(descriptor: usize, buffer: &mut [u8]) -> usize {
    let answer: usize;
    unsafe {
        asm!(
            "ecall",
            in("a7") SYS_READ,
            inlateout("a0") descriptor => answer,
            in("a1") usize::MAX, // READ_OFFSET_CURRENT
            in("a2") buffer.as_mut_ptr(),
            in("a3") buffer.len(),
            options(nostack)
        );
    }
    answer
}

/// `close(descriptor)`.
#[cfg(all(target_os = "none", target_arch = "riscv64"))]
fn sys_close(descriptor: usize) {
    unsafe {
        asm!(
            "ecall",
            in("a7") SYS_CLOSE,
            in("a0") descriptor,
            options(nostack)
        );
    }
}

/// `exit(status)`: control does not come back.
/// `mmap(hint, length, prot, flags)`: the base address, or an error encoding.
#[cfg(all(target_os = "none", target_arch = "riscv64"))]
fn sys_mmap(hint: usize, length: usize, protection: usize, flags: usize) -> usize {
    let answer: usize;
    // SAFETY: `ecall` with the arguments in the registers the ABI names.
    unsafe {
        asm!(
            "ecall",
            in("a7") SYS_MMAP,
            inlateout("a0") hint => answer,
            in("a1") length,
            in("a2") protection,
            in("a3") flags,
            in("a4") 0usize,
            in("a5") 0usize,
            options(nostack)
        );
    }
    answer
}

/// `brk(new_break)`: the break the kernel now holds.
#[cfg(all(target_os = "none", target_arch = "riscv64"))]
fn sys_brk(requested: usize) -> usize {
    let answer: usize;
    // SAFETY: as `sys_mmap`.
    unsafe {
        asm!(
            "ecall",
            in("a7") SYS_BRK,
            inlateout("a0") requested => answer,
            // Unused slots zero, for the reason the x86_64 arm gives.
            in("a1") 0usize,
            in("a2") 0usize,
            in("a3") 0usize,
            in("a4") 0usize,
            in("a5") 0usize,
            options(nostack)
        );
    }
    answer
}

#[cfg(all(target_os = "none", target_arch = "riscv64"))]
fn sys_exit(status: usize) -> ! {
    unsafe {
        asm!(
            "ecall",
            in("a7") SYS_EXIT,
            in("a0") status,
            options(noreturn, nostack)
        );
    }
}

/// What a panic does in a program with no unwinder: stop.
///
/// There is nowhere to unwind to and no console this program owns.  Stopping
/// leaves the machine in a state a debugger can read, and the kernel's
/// fatal-fault machinery is what turns it into a line if it ever fires.
#[cfg(target_os = "none")]
#[cfg_attr(target_os = "none", panic_handler)]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}

/// The host build, which is a typecheck and nothing else.
#[cfg(not(target_os = "none"))]
fn main() {}

/// The program's entry, named by the linker script: read the boot's file and
/// exit with its first byte.
///
/// Machine-only: the host build links its own crt, whose `_start` this would
/// collide with, and a host has no syscalls to reach.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut buffer = [0u8; BUFFER_LEN];

    // The path's address is this image's own `.rodata`, at the address the
    // linker fixed — the loader maps the segments at their linked addresses,
    // which is why the constant is the truth and not a guess.
    let path = GREETING_PATH.as_ptr() as usize;
    let descriptor = sys_open(path);
    let first = read_first_byte(descriptor, &mut buffer);

    // Two memory calls, and the kernel prints both answers.
    //
    // A program here cannot print a value — `Write` prints a fixed line — so
    // the evidence for these is the kernel's own line beside each answer.  What
    // makes the pair worth having is that neither number can be invented: the
    // mapping's base is inside this program's window and the break is past its
    // own stack, and a kernel that had mapped nothing could not name either.
    //
    // The **store** is the part that proves the mapping is real: a page the
    // kernel reported but did not map faults here, and the boot would show the
    // fault instead of the exit status.
    let mapping = sys_mmap(0, MMAP_BYTES, PROT_READ_WRITE, MAP_ANONYMOUS_PRIVATE);
    if mapping != 0 && !is_error(mapping) {
        // SAFETY: the kernel just answered with a base it mapped writable for
        // this program, one page long, which is what this program asked for.
        unsafe { core::ptr::write_volatile(mapping as *mut u8, first as u8) };
    }
    let break_now = sys_brk(0);
    let _ = break_now;

    sys_exit(first)
}

/// Whether a syscall's answer is the ABI's error encoding.
///
/// The ABI encodes an error as a word with its high bit set, which is the one
/// test a program needs: a successful answer is a small positive number — a
/// descriptor, a count, an address inside the user window.
#[cfg(target_os = "none")]
const fn is_error(answer: usize) -> bool {
    answer & (1 << (usize::BITS - 1)) != 0
}

/// Read the file and answer its first byte, closing the descriptor on the way
/// out either way: a slot left open in the table the kernel keeps is the kind
/// of leak that shows up as a limit much later.
#[cfg(target_os = "none")]
fn read_first_byte(descriptor: usize, buffer: &mut [u8]) -> usize {
    let read = sys_read(descriptor, buffer);
    sys_close(descriptor);
    if read == 0 {
        return 1;
    }
    buffer[0] as usize
}
