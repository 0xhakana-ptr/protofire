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
pub mod idt;
pub mod interrupts;
pub mod paging;
pub mod pic;

// The entry encoding, re-exported by name: `kernel::address_space` builds a
// mapping and asks the machine how to write it down, and asking through `arch`
// is what keeps the answer a machine's business.
pub use paging::install;

// The interrupt table, by name: the kernel installs one and hands it a sink,
// and both are this crate's decisions about the machine.  Bare-metal only: a
// host has no IDT to load and no vector to take, and the types are gated the
// same way for the same reason.
#[cfg(target_os = "none")]
pub use idt::InterruptFrame;
#[cfg(target_os = "none")]
pub use idt::install as install_interrupt_table;
#[cfg(target_os = "none")]
pub use idt::loaded as idt_descriptor;
#[cfg(target_os = "none")]
pub use idt::set_dispatch as set_interrupt_dispatch;

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

/// Enable one of the machine's interrupt lines.
///
/// False: this machine has no controller this crate drives yet.  The function
/// exists on every machine so a driver asks one question, and `false` is an
/// answer a caller reports rather than a gap it works around.
///
/// # Safety
///
/// As the aarch64 arm: after [`install_interrupt_table`], once per line.
#[cfg(target_os = "none")]
pub unsafe fn enable_interrupt_line(number: usize) -> bool {
    let _ = number;
    false
}

/// Raise one interrupt from the controller: this machine has none to raise.
///
/// False, as [`enable_interrupt_line`] is — the machine has no controller this
/// crate drives, so there is nothing to ask.
///
/// # Safety
///
/// As the aarch64 arm.
#[cfg(target_os = "none")]
pub unsafe fn raise_interrupt(number: usize) -> bool {
    let _ = number;
    false
}
