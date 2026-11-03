//! arch/riscv64/src/interrupts.rs
//!
//! Saving, disabling and restoring the local interrupt enable bit.
//!
//! ## Why a lock needs this
//!
//! A spinlock that only spins is safe between harts and unsafe against itself:
//! an interrupt taken while the lock is held, whose handler takes the same
//! lock, spins forever on a hart that cannot make progress.  Acquisition
//! therefore closes that window, which means it needs a way to say "stop
//! taking interrupts, and remember whether they were on".
//!
//! ## How this machine reports it
//!
//! `sstatus.SIE` is bit 1 — note that bit 0 is `UIE` and is not the one that
//! gates supervisor interrupts, which is the mistake the previous tree's
//! `arch/riscv64/mod.rs` calls out beside the instruction.  `csrsi sstatus, 2`
//! and `csrci sstatus, 2` set and clear it.
//!
//! ## On a host build
//!
//! A host has no `sstatus` and no S-mode, so the three functions are no-ops and
//! `save_and_disable` reports `false` — the state a host's userspace is in with
//! respect to this kernel's interrupts.

/// Whether supervisor interrupts are enabled right now.
#[cfg(not(target_os = "none"))]
pub fn are_enabled() -> bool {
    false
}

/// The bare-metal answer: read `sstatus` and test `SIE`.
#[cfg(target_os = "none")]
pub fn are_enabled() -> bool {
    let sstatus: u64;
    // SAFETY: reading sstatus is a supervisor-CSR read with no memory side
    // effects.
    unsafe {
        core::arch::asm!("csrr {sstatus}, sstatus", sstatus = out(reg) sstatus, options(nomem, nostack, preserves_flags));
    }
    sstatus & (1 << 1) != 0
}

#[cfg(not(target_os = "none"))]
pub fn disable() {}

/// The bare-metal form: clear `SIE`.
#[cfg(target_os = "none")]
pub fn disable() {
    // SAFETY: clearing SIE is a supervisor operation on this hart's own status
    // register.  Bit 1, not bit 0: `UIE` does not gate supervisor interrupts.
    unsafe {
        core::arch::asm!("csrci sstatus, 2", options(nomem, nostack, preserves_flags));
    }
}

#[cfg(not(target_os = "none"))]
pub fn enable() {}

/// The bare-metal form: set `SIE`.
#[cfg(target_os = "none")]
pub fn enable() {
    // SAFETY: as `disable` — setting SIE, which the caller pairs with a later
    // disable.
    unsafe {
        core::arch::asm!("csrsi sstatus, 2", options(nomem, nostack, preserves_flags));
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

/// Silence the legacy interrupt controller, of which this machine has none.
///
/// The 8259 is a PC part: its reset vector base is 8, the double fault, which
/// is why x86_64 masks it before enabling interrupts.  A device-tree machine
/// has a GIC or a PLIC from reset, with bases the firmware chose and no
/// collision, so there is nothing to silence.
///
/// The function exists on every machine so that enabling interrupts is one call
/// rather than a question about which machine is running.
pub fn silence_legacy_controller() {}

#[cfg(test)]
mod tests {
    use super::save_and_disable;

    /// A host has no `sstatus`, so `save_and_disable` reports that interrupts
    /// were already off.  A host build reporting `true` would have every lock
    /// try to re-enable a state the host never had.
    #[test]
    fn a_host_reports_interrupts_were_off() {
        assert!(!save_and_disable());
    }
}
