//! arch/riscv64/src/lib.rs
//!
//! The riscv64 machine, as far as the kernel can ask it anything today.
//!
//! This crate is a sibling of `arch/x86_64` and `arch/aarch64` and shares no
//! code with either: what they share is the *names* the kernel calls, which is
//! the whole interface.

#![no_std]

// The host arm of the console records bytes instead of writing a port.
#[cfg(not(target_os = "none"))]
extern crate alloc;

// No crate-level `cfg(target_arch)` gate, and its absence is the point.
//
// The first version of this file had one, so that `cargo build --workspace` —
// which builds every member for the host — would not try to assemble `wfi` into
// an x86 binary.  What that also did was make the whole crate empty on a host,
// including the tests: `cargo test -p arch_aarch64` reported zero, and every
// assertion in `interrupts.rs` was dead code that had never been compiled.
//
// A gate that silences a build by removing the code is the wrong tool.  Each
// module keeps its own `cfg(target_os)` arms — a host has no `DAIF` and no
// `wfi`, so those arms are no-ops that a test can still run — and the crate
// stays compilable everywhere it is named.

pub mod boot;
pub mod interrupts;
pub mod port;
pub mod serial;

/// Stop this CPU until an interrupt arrives.
///
/// `wfi` in S-mode waits for an interrupt.  The loop is what makes the function
/// `-> !`: a stop that returned would fall into whatever follows, and there is
/// nothing after a stop.
#[cfg(target_os = "none")]
pub fn halt() -> ! {
    loop {
        // SAFETY: `wfi` is the wait-for-interrupt hint.  `sstatus.SIE` is clear
        // on every path that reaches here, so no interrupt is taken and the
        // loop does not exit.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
    }
}

/// The host build's stop: end the process, because a host has no hart to idle.
#[cfg(not(target_os = "none"))]
pub fn halt() -> ! {
    panic!("halt() called on a host: this is the kernel's stop, not a test's")
}
