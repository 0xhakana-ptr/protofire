//! apps/shell/src/main.rs
//!
//! The interactive shell: a prompt, a line reader, and the
//! commands the previous tree's `src/shell` carried.
//!
//! ## What this file is, today
//!
//! A skeleton that links and says what it will become.  It exists so the crate
//! has the shape a program grows into: the `no_std`/`no_main` pair, a panic
//! handler, and an entry symbol — the three things only a binary can define.
//!
//! ## Why the body is gated
//!
//! `cargo build --workspace` builds this package for the host, where
//! `#[panic_handler]` collides with `std`'s.  So the program half is behind
//! `target_os = "none"` and the host build is an empty `main`: enough for the
//! workspace to typecheck the package without claiming a program that has no
//! kernel to run under yet. `bootloader/src/main.rs` draws the same line for
//! the same reason.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
use core::panic::PanicInfo;

/// The program's entry, once a kernel can start it and a console can
/// reach it.
#[cfg(target_os = "none")]
fn main() -> ! {
    loop {
        // A spin rather than a machine's wait instruction: this file is built
        // for all three machines, and `hlt` is x86's, `wfi` is aarch64's and
        // riscv64's.  Naming one here would compile on a third of the targets
        // and be the wrong instruction on the others.  A real body replaces
        // this with the syscall that exits.
        core::hint::spin_loop();
    }
}

/// What a panic does in a program with no unwinder: stop.
///
/// There is nowhere to unwind to and, on a program that has not yet made a
/// syscall, no console guaranteed to be its own.  Stopping leaves the machine
/// in a state a debugger can read, which is the honest answer.
#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        // As above: portable, because this crate is built for three machines.
        core::hint::spin_loop();
    }
}

/// The host build, which is a typecheck and nothing else.
#[cfg(not(target_os = "none"))]
fn main() {}
