//! apps/shell/src/main.rs
//!
//! `shell`: the second program the tree ships, and the first one a program
//! other than the boot can start.
//!
//! ## What it is
//!
//! Not the interactive shell the doc comment once promised, that one needs a
//! console descriptor this kernel does not serve yet.  What it is, is the
//! smallest program whose **running is somebody else's doing**: `init` starts
//! it, and the exit status it answers is the evidence the start worked.  A
//! program that reads the greeting and answers its length is the shortest
//! body whose exit status cannot be produced without the kernel having
//! loaded, mapped and run a second image from the filesystem, 23 is the
//! greeting's length, and no constant this program was handed can fake it.
//!
//! ## Ring 3, and where the wrappers live
//!
//! The calls go through the `user_abi` crate, the same gate `init` uses:
//! two programs that spell the gate separately are two places for one fact
//! to drift, which is why the crate exists.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
use core::panic::PanicInfo;

#[cfg(target_os = "none")]
use user_abi::OPEN_READ;
#[cfg(target_os = "none")]
use user_abi::SIGUSR1;
#[cfg(target_os = "none")]
use user_abi::insist;
#[cfg(target_os = "none")]
use user_abi::sys_close;
#[cfg(target_os = "none")]
use user_abi::sys_exit;
#[cfg(target_os = "none")]
use user_abi::sys_get_ppid;
#[cfg(target_os = "none")]
use user_abi::sys_open;
#[cfg(target_os = "none")]
use user_abi::sys_read;
#[cfg(target_os = "none")]
use user_abi::sys_send_signal;
#[cfg(target_os = "none")]
use user_abi::sys_set_signal_handler;
#[cfg(target_os = "none")]
use user_abi::sys_sigreturn;

/// The path the shell reads, NUL-terminated in its own `.rodata`: the same
/// file `init` reads, which is what makes the two statuses comparable, the
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

    // The signal, in both directions.  First this process arms its own
    // handler, the address is its own code, and the contract is the fault
    // handler's: the record arrives in the argument registers, and the way
    // out is `ReturnFromException(resume, value)`.  Then it tells the
    // parent it is ready, and spins for the delivery, which the kernel
    // makes at the next install of this context, the first tick after the
    // parent's send, not the send itself, because a context mid-flight on
    // another CPU is the kernel's to leave alone.
    let handler = signal_handler as usize;
    insist(sys_set_signal_handler(SIGUSR1, 1, handler));
    let parent = insist(sys_get_ppid());
    insist(sys_send_signal(parent, SIGUSR1, 0x5348));
    while DELIVERED.load(core::sync::atomic::Ordering::Acquire) == 0 {
        core::hint::spin_loop();
    }
    sys_exit(read)
}

/// Whether the handler has run: the spin above waits for exactly this.
#[cfg(target_os = "none")]
static DELIVERED: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// The signal handler, in the contract the kernel delivers under: the
/// signal in the answer register, the sender and its payload beside it, and
/// the interrupted resume as the fourth word.
///
/// The checks are the program's own reading of who spoke and why, a record
/// that disagrees is a delivery this process refuses to count, and the way
/// out is the same `ReturnFromException` the fault handler exits through:
/// the interrupted flow resumes at the address the kernel supplied, reading
/// zero as the answer.  Control does not come back here.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
extern "C" fn signal_handler(signal: usize, sender: usize, payload: usize, resume: usize) -> ! {
    if signal == SIGUSR1 && payload == 0x4944 {
        DELIVERED.store(1, core::sync::atomic::Ordering::Release);
    }
    let _ = sender;
    sys_sigreturn(resume);
    loop {
        core::hint::spin_loop();
    }
}
