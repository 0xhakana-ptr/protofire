//! apps/service_manager/src/main.rs
//!
//! `service_manager`: starting, stopping and supervising services, as a
//! ring-3 program.
//!
//! ## "Everything is a service"
//!
//! That phrase is a direction rather than a settled design, and this crate is
//! where the question is being asked.  The shape it implies: a service is
//! something with a name, a program behind it, a run state, and a supervision
//! policy (restart on exit, restart on failure, never).  `init` declares them;
//! this program holds them.
//!
//! The alternative the name also admits is narrower: this is a manager of the
//! services in `rc.d`-shaped declarations, and the rest of the system is not
//! modelled as services at all.  Which one this becomes is a decision the
//! process layer will inform, a manager of processes and a manager of
//! services are the same code until something needs a restart policy.
//!
//! ## What is here, today
//!
//! The shape a program must have.  Supervising anything needs to spawn, wait
//! and signal, and none of those are served yet.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
use core::panic::PanicInfo;

/// The program's entry, once a kernel can start it.
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
