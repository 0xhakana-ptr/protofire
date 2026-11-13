//! apps/shell/src/main.rs
//!
//! `shell`: the second program the tree ships, and the first one a program
//! other than the boot can start.
//!
//! ## What it is
//!
//! Not the interactive shell the doc comment once promised — that one needs a
//! console descriptor this kernel does not serve yet.  What it is, is the
//! smallest program whose **running is somebody else's doing**: `init` starts
//! it, and the exit status it answers is the evidence the start worked.  A
//! program that reads the greeting and answers its length is the shortest
//! body whose exit status cannot be produced without the kernel having
//! loaded, mapped and run a second image from the filesystem — 23 is the
//! greeting's length, and no constant this program was handed can fake it.
//!
//! ## Ring 3, and where the wrappers live
//!
//! The calls go through the `userland` crate, the same gate `init` uses:
//! two programs that spell the gate separately are two places for one fact
//! to drift, which is why the crate exists.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
use core::panic::PanicInfo;

#[cfg(target_os = "none")]
use userland::OPEN_READ;
#[cfg(target_os = "none")]
use userland::SIGUSR1;
#[cfg(target_os = "none")]
use userland::insist;
#[cfg(target_os = "none")]
use userland::sys_close;
#[cfg(target_os = "none")]
use userland::sys_exit;
#[cfg(target_os = "none")]
use userland::sys_get_ppid;
#[cfg(target_os = "none")]
use userland::sys_open;
#[cfg(target_os = "none")]
use userland::sys_read;
#[cfg(target_os = "none")]
use userland::sys_send_signal;

/// The path the shell reads, NUL-terminated in its own `.rodata`: the same
/// file `init` reads, which is what makes the two statuses comparable — the
/// shell answers the file's length where `init` answers its first byte.
#[cfg(target_os = "none")]
static GREETING_PATH: &[u8] = b"/greeting.txt\0";

/// The read's buffer length: longer than the greeting, shorter than a page.
#[cfg(target_os = "none")]
const BUFFER_LEN: usize = 32;

/// What a panic does in a program with no unwinder: stop.
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

/// The program's entry, named by the linker script.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub extern "C" fn _start() -> ! {
    let mut buffer = [0u8; BUFFER_LEN];
    let descriptor = insist(sys_open(GREETING_PATH.as_ptr() as usize, OPEN_READ));
    let read = insist(sys_read(descriptor, &mut buffer));
    insist(sys_close(descriptor));

    // The length is the answer, and a zero read is not one: a program that
    // answered 23 without reading would be answering a constant, which is
    // the one thing this exit status exists to refuse.
    if read == 0 {
        sys_exit(1);
    }

    // The signal: one to the parent that started this process, carrying a
    // payload that names the sender — `0x5348` is "SH" in the hex the
    // kernel's log prints.  A signal is how a child speaks before it exits,
    // and the parent's wait is the ear.
    let parent = insist(sys_get_ppid());
    insist(sys_send_signal(parent, SIGUSR1, 0x5348));
    sys_exit(read)
}
