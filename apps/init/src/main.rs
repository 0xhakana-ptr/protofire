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
    sys_exit(first)
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
