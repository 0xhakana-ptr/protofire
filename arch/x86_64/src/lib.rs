//! arch/x86_64/src/lib.rs
//!
//! The x86_64 machine: what the kernel asks it, and nothing else.
//!
//! Everything here is a fact about this architecture — a port, an instruction,
//! a register — and none of it may be spelled outside this crate.  The test is
//! mechanical: a `#[cfg(target_arch = ...)]` anywhere else in the tree is a
//! question this crate should answer instead.

#![no_std]

pub mod serial;

/// Stop this CPU until an interrupt arrives.
///
/// Interrupts are disabled first, so this does not return unless something
/// enables them; every caller in the kernel treats it as a final stop.
pub fn halt() -> ! {
    loop {
        // SAFETY: `cli` clears the interrupt flag and `hlt` stops the core
        // until an interrupt is pending.  With the flag clear there is none to
        // take, so the pair cannot leave this loop.
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}
