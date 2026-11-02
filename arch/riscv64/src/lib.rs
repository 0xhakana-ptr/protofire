//! arch/riscv64/src/lib.rs
//!
//! The riscv64 machine, as far as the kernel can ask it anything today.
//!
//! This crate is a sibling of `arch/x86_64` and `arch/aarch64` and shares no
//! code with either: what they share is the *names* the kernel calls, which is
//! the whole interface.

#![no_std]
// Built on the host, this crate has nothing to say: `wfi` is not an x86
// instruction, and `cargo build --workspace` builds every member for the host.
// The gate is `target_arch` rather than `target_os` because a cross build to
// this machine from a host is exactly the case that must compile the body.
#![cfg(target_arch = "riscv64")]

pub mod boot;
pub mod interrupts;
pub mod serial;

/// Stop this CPU until an interrupt arrives.
///
/// `wfi` in S-mode waits for an interrupt.  The loop is what makes the
/// function `-> !`: a stop that returned would fall into whatever follows, and
/// there is nothing after a stop.
pub fn halt() -> ! {
    loop {
        // SAFETY: `wfi` is the wait-for-interrupt hint.  `sstatus.SIE` is clear
        // on every path that reaches here, so no interrupt is taken and the
        // loop does not exit.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
    }
}
