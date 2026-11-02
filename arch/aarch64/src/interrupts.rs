//! arch/aarch64/src/interrupts.rs
//!
//! Saving, disabling and restoring the local interrupt mask.
//!
//! ## Why a lock needs this
//!
//! A spinlock that only spins is safe between CPUs and unsafe against itself:
//! an interrupt taken while the lock is held, whose handler takes the same
//! lock, spins forever on a CPU that cannot make progress.  Acquisition
//! therefore closes that window, which means it needs a way to say "stop
//! taking interrupts, and remember whether they were on".
//!
//! ## How this machine reports it
//!
//! `DAIF` holds the four mask bits — debug, SError, IRQ, FIQ — and bit 7 is
//! `I`, the IRQ mask.  `I` set means IRQs are masked, so "enabled" is the bit
//! being clear.  Setting and clearing the whole group is `msr DAIFSet, #0xf`
//! and `msr DAIFClr, #0xf`; the previous tree's `arch/aarch64/mod.rs` does the
//! same three operations, and this file is that code given its own module.
//!
//! ## On a host build
//!
//! A host has no `DAIF` and no EL1, so the three functions are no-ops and
//! `save_and_disable` reports `false` — the state a host's userspace is in with
//! respect to this kernel's interrupts.  That is what lets a lock be tested on
//! the host at all.

/// Whether interrupts are unmasked right now.
#[cfg(not(target_os = "none"))]
pub fn are_enabled() -> bool {
    false
}

/// The bare-metal answer: read `DAIF` and test the IRQ mask.
#[cfg(target_os = "none")]
pub fn are_enabled() -> bool {
    let daif: u64;
    // SAFETY: reading DAIF is an EL1 system-register read with no memory side
    // effects; the mask bits are what this asks about.
    unsafe {
        core::arch::asm!("mrs {daif}, DAIF", daif = out(reg) daif, options(nomem, nostack, preserves_flags));
    }
    daif & (1 << 7) == 0
}

#[cfg(not(target_os = "none"))]
pub fn disable() {}

/// The bare-metal form: set every mask bit.
#[cfg(target_os = "none")]
pub fn disable() {
    // SAFETY: setting the DAIF masks is an EL1 operation with no memory
    // operand. The caller is responsible for being in a state where masking is
    // correct.
    unsafe {
        core::arch::asm!(
            "msr DAIFSet, #0xf",
            options(nomem, nostack, preserves_flags)
        );
    }
}

#[cfg(not(target_os = "none"))]
pub fn enable() {}

/// The bare-metal form: clear every mask bit.
#[cfg(target_os = "none")]
pub fn enable() {
    // SAFETY: as `disable` — clearing the masks, which the caller pairs with a
    // later disable.
    unsafe {
        core::arch::asm!(
            "msr DAIFClr, #0xf",
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Disable local interrupts, reporting whether they were enabled.
///
/// The return value is the argument [`restore`] expects.  Getting it backwards
/// turns a nested acquisition into an interrupt storm or a hang.
pub fn save_and_disable() -> bool {
    let enabled = are_enabled();
    if enabled {
        disable();
    }
    enabled
}

/// Restore the interrupt state [`save_and_disable`] reported.
pub fn restore(enabled: bool) {
    if enabled {
        enable();
    }
}

#[cfg(test)]
mod tests {
    use super::save_and_disable;

    /// A host has no `DAIF`, so `save_and_disable` reports that interrupts were
    /// already off.  A host build reporting `true` would have every lock try to
    /// re-enable a state the host never had.
    #[test]
    fn a_host_reports_interrupts_were_off() {
        assert!(!save_and_disable());
    }
}
