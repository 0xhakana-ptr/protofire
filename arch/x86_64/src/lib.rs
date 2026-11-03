//! arch/x86_64/src/lib.rs
//!
//! The x86_64 machine: what the kernel asks it, and nothing else.
//!
//! Everything here is a fact about this architecture — a port, an instruction,
//! a register — and none of it may be spelled outside this crate.  The test is
//! mechanical: a `#[cfg(target_arch = ...)]` anywhere else in the tree is a
//! question this crate should answer instead.

#![no_std]

// The host arm of the console records bytes instead of writing a port.
#[cfg(not(target_os = "none"))]
extern crate alloc;

pub mod boot;
pub mod interrupts;
pub mod paging;
pub mod port;
pub mod serial;

// The machine's entry, assembled from `src/boot-x86-64.S`.
//
// It is here rather than in `bootloader` because everything in it is a fact
// about this architecture: the multiboot2 header's checksum, the PVH note's
// type, the identity map's page-table layout, the GDT's descriptor bits.  A
// machine that entered differently writes its own file and `bootloader` does
// not change.
//
// `bootloader` supplies the symbol it calls.  The direction is a link-time
// reference rather than a crate dependency, because `arch` sits below
// `bootloader` and an upward `use` is the edge this tree's layering forbids.
#[cfg(target_os = "none")]
core::arch::global_asm!(include_str!("boot-x86-64.S"));

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
