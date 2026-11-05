//! apps/shell/src/main.rs
//!
//! `shell`: the interactive shell, and a ring-3 program.
//!
//! ## What it is
//!
//! A prompt, a line reader, and the commands the previous tree's `src/shell`
//! carried, but a program, not a kernel module.  The distinction matters for
//! what a command can do: a shell in ring 3 can only do what its user could do
//! by writing the same syscalls, so "the shell can do it" and "the user can do
//! it" become the same sentence.  A shell inside the kernel makes every
//! debugging command an unprivileged bypass, which is how a system ends up
//! with a command that is the only way to reach a capability.
//!
//! It is not PID 1.  `init` starts it, and a machine whose shell crashed still
//! has an `init`.
//!
//! ## What is here, today
//!
//! The shape a program must have and nothing else.  A line reader needs a
//! `read` on a console descriptor, and the console is not a descriptor yet.

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
