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

pub mod boot;
pub mod interrupts;
pub mod paging;
pub mod port;
pub mod serial;
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

/// Install the exception vector table.
///
/// Returns whether a table was installed.  This machine has the table's
/// *structure* — `vbar::Table` is the sixteen entries the architecture defines
/// and it is tested — and not its *entry*: the boot assembly does not yet
/// branch into a Rust trap handler, so a `VBAR_EL1` pointing at an unfilled
/// table would be a register naming code that is not there.
///
/// So it answers `false`, and the boot says so.  A machine's silent failure and
/// a machine's honest gap look the same in a log unless the gap is reported,
/// and this is the report.
/// # Safety
///
/// A machine with an entry would make a register name an address here; this
/// one has none, and the promise is kept by doing nothing.  The signature is
/// unsafe on every machine so that the caller reads one contract.
#[cfg(target_os = "none")]
pub unsafe fn install_interrupt_table() -> bool {
    false
}

/// Install the sink a trap frame goes to.
///
/// A machine with no trap entry has nothing to hand a frame to, so this records
/// nothing and says nothing: the sink is installed by a machine that can call
/// one, and [`install_interrupt_table`] is what reports whether that is this
/// one.
///
/// # Safety
///
/// The caller promises to call this once, before any vector can be raised.  A
/// machine that cannot raise one keeps that promise trivially.
#[cfg(target_os = "none")]
pub unsafe fn set_interrupt_dispatch(sink: fn(irq::Frame) -> bool) {
    let _ = sink;
}
