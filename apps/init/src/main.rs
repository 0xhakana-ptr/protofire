//! apps/init/src/main.rs
//!
//! `init`: the first program the kernel starts, at PID 1, in ring 3.
//!
//! ## What PID 1 means here
//!
//! The kernel does not start any other program before this one, and every
//! later process descends from it.  That makes `init` the answer to "who
//! reaps an orphan" — a program whose parent exited is reparented to PID 1, so
//! a system that loses its `init` has no one to answer for the processes it
//! left behind.  It is also why `init` is the program that reads the service
//! declarations and starts what they name, rather than the kernel doing it:
//! policy about which services a machine runs belongs to a program a policy
//! file can be changed without a rebuild.
//!
//! ## Ring 3
//!
//! `init` runs unprivileged, on a stack and page tables the kernel built, and
//! reaches everything through syscalls.  That is not a restriction to work
//! around — it is the point: a bug in `init` should fault `init`, not the
//! machine, and the kernel's authority is exactly the syscall surface it
//! serves.
//!
//! That surface does not include starting a process yet, so this crate cannot
//! do its job: `SpawnProcess` exists in the numbering and answers
//! `NotImplemented`.  What is here is the shape a program must have, so that
//! the change which adds the process layer has somewhere to put the first
//! call.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
use core::panic::PanicInfo;

/// The program's entry, once a kernel can start it.  `-> !` because a
/// program does not return: when there is an `exit` to call, this is where it
/// will call it.
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
