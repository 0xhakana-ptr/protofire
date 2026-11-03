//! arch/aarch64/src/lib.rs
//!
//! The aarch64 machine, as far as the kernel can ask it anything today.
//!
//! This crate is a sibling of `arch/x86_64` and the two share no code: what
//! they share is the *names* the kernel calls, which is the whole interface.
//! A machine's differences are allowed to be large; the point of the split is
//! that the rest of the tree never learns which ones they are.
//!
//! ## No crate-level architecture gate
//!
//! The first version of this file had `#![cfg(target_arch = "aarch64")]`, so
//! that `cargo build --workspace` — which builds every member for the host —
//! would not try to assemble `wfi` into an x86 binary.  What that also did was
//! make the whole crate empty on a host, *including its tests*:
//! `cargo test -p arch_aarch64` reported zero, and every assertion in
//! `interrupts.rs` was dead code that had never been compiled once.
//!
//! A gate that makes a build succeed by removing the code is the wrong tool.
//! Each module keeps its own `cfg(target_os)` arms instead: a host has no
//! `DAIF` and no `wfi`, so those arms are no-ops a test can still run, and the
//! crate stays compilable wherever it is named.

#![no_std]

// The host arm of the console records bytes instead of writing a port.
#[cfg(not(target_os = "none"))]
extern crate alloc;

// The entry: the stack, the bss clear, the drop to EL1 and the vector table.
//
// Here rather than in `bootloader` for the reason the x86_64 entry is: every
// instruction is a fact about this machine, and the protocol crate is not the
// machine.
#[cfg(target_os = "none")]
core::arch::global_asm!(include_str!("entry.S"));

pub mod boot;
pub mod interrupts;
pub mod paging;
pub mod port;
pub mod serial;
pub mod trap;
pub mod vbar;

/// Stop this CPU until an interrupt arrives.
///
/// `wfi` is the wait-for-interrupt hint, and the loop around it is what makes
/// the function `-> !`: an interrupt that returns here would fall into whatever
/// follows, and there is nothing after a stop.
///
/// A host has no `wfi`.  The no-op arm does not loop, which would be a spin —
/// it stops the process the way the real one stops the core, so a test that
/// calls it returns rather than hanging.  That difference is the honest one:
/// this is the only function in the crate a test has no reason to call, and a
/// test build that hung would be worse than one that did not run it.
#[cfg(target_os = "none")]
pub fn halt() -> ! {
    loop {
        // SAFETY: `wfi` is a hint that permits the core to enter a low-power
        // state until an interrupt is pending.  On this kernel's paths the DAIF
        // mask is set, so no interrupt is taken and the loop does not exit.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
    }
}

/// The host build's stop: end the process, because a host has no core to idle.
///
/// Only reachable from a test, and only if one calls it deliberately.
#[cfg(not(target_os = "none"))]
pub fn halt() -> ! {
    panic!("halt() called on a host: this is the kernel's stop, not a test's")
}

/// Install the exception vector table, and prove it delivers.
///
/// Returns whether this machine will now take an exception through
/// [`trap::aarch64_exception_dispatch`].  The table itself is `entry.S`'s —
/// sixteen entries that record their index in `x16` and branch to one common
/// save/restore path — and this installs the register that names it.
///
/// The answer is not "the register was written".  A register written and never
/// exercised is the recurring defect in this tree: code that is written, wired,
/// and never executed.  So [`trap::install_table`] raises a supervisor call
/// from EL1 after installing, and the supervisor call has to arrive at entry 4
/// and return.  That exercises the save, the restore, the vector numbering, the
/// sink and the `eret` in one go, and the frame's offsets are what the return
/// path restored — a frame laid out wrong would return into garbage instead of
/// returning at all.
///
/// It runs here rather than in a separate probe because it needs nothing the
/// boot has not done: the stack is up, the console is up, and the sink is
/// installed by the caller immediately before.
///
/// # Safety
///
/// Called once, after [`set_interrupt_dispatch`], before the kernel enables
/// interrupts.  It writes `VBAR_EL1` and executes one `svc`, which the machine
/// takes as an exception; that is safe at EL1 with the kernel's stack valid and
/// not safe anywhere else.
#[cfg(target_os = "none")]
pub unsafe fn install_interrupt_table() -> bool {
    // SAFETY: the caller's contract is this function's — once, with the sink
    // installed and the stack valid.
    unsafe { trap::install_table() }
}

/// Install the sink a trap frame goes to.
///
/// The frame reaches [`trap::aarch64_exception_dispatch`], which calls this
/// sink and stops the machine when it answers `false`.  Installing one is what
/// makes an exception observable rather than a silent `wfe` — which is exactly
/// what this machine's first boot was, and why it printed four lines and
/// stopped with nothing after them.
///
/// # Safety
///
/// The caller promises to call this once, before any vector can be raised.  The
/// function must not allocate, block, or enable interrupts: it runs on the
/// kernel stack the exception found.
#[cfg(target_os = "none")]
pub unsafe fn set_interrupt_dispatch(sink: fn(irq::Frame) -> bool) {
    // SAFETY: passed through to the module that owns the static; the caller's
    // promise is the same one that function states.
    unsafe { trap::set_sink(sink) };
}
