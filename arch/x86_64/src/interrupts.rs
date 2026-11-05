//! arch/x86_64/src/interrupts.rs
//!
//! Saving, disabling and restoring the local interrupt flag.
//!
//! A spinlock that only spins is safe between CPUs and unsafe against itself:
//! an interrupt taken while the lock is held, whose handler takes the same
//! lock, spins forever on a CPU that cannot make progress.  Every acquisition
//! therefore has to close that window, which means every acquisition needs a
//! way to say "stop taking interrupts, and remember whether they were on".
//!
//! ## On a host build
//!
//! A host has no interrupt flag to clear and no `cli` privilege to clear it
//! with, so the three functions below are no-ops there and `save_and_disable`
//! reports `false`, "they were already off", which is the state a host's
//! userspace is in with respect to this kernel's interrupts.  That is what lets
//! a lock be tested on the host at all: the type is the same, the algorithm is
//! the same, and only the instruction that is meaningless outside a kernel is
//! absent.

/// Whether interrupts are enabled right now.
///
/// On a host there is no such flag, and `false` is the answer that keeps
/// `save_and_disable` from trying to restore something it never turned off.
#[cfg(not(target_os = "none"))]
pub fn are_enabled() -> bool {
    false
}

/// The bare-metal answer: read `RFLAGS.IF`.
#[cfg(target_os = "none")]
pub fn are_enabled() -> bool {
    let flags: u64;
    // SAFETY: `pushfq` reads the flags register and has no other effect.  This
    // is not privileged, so it is meaningful at any privilege level.
    unsafe { core::arch::asm!("pushfq; pop {}", out(reg) flags, options(preserves_flags)) };
    flags & (1 << 9) != 0
}

/// Silences the legacy 8259 before interrupts are enabled.
///
/// The 8259's reset vector bases are 8 and 0x70, and vector 8 is the double
/// fault.  A machine whose timer still reaches the 8259 takes its first tick as
/// a double fault through whatever gate the kernel wrote for vector 8, which
/// is a gate for an exception the kernel never meant to raise, so the answer it
/// gives is the wrong one and the machine stops.
///
/// So enabling interrupts on this machine is two things, and they are one
/// function: silence the legacy controller, then set the flag.  A caller that
/// did only the second is a caller whose first interrupt is a fault, and this
/// tree learned that by executing `sti` once.
///
/// Masked rather than remapped: q35 has an IOAPIC, and a machine with two
/// controllers able to raise one line is a worse state than one controller
/// silent.
pub fn silence_legacy_controller() {
    // SAFETY: the two writes go to the 8259's mask registers.  A machine with
    // no 8259 ignores them, which is the correct effect there.
    #[cfg(target_os = "none")]
    crate::pic::mask_all();
}

/// Disable local interrupts.
///
/// On a host this does nothing: there is no interrupt flag to clear, and the
/// call is here so that code holding a lock reads the same in both builds.
#[cfg(not(target_os = "none"))]
pub fn disable() {}

/// The bare-metal form.
#[cfg(target_os = "none")]
pub fn disable() {
    // SAFETY: `cli` clears `RFLAGS.IF`, which stops this CPU taking maskable
    // interrupts.  It is privileged, which is why the host arm above exists.
    unsafe { core::arch::asm!("cli", options(nomem, nostack)) };
}

#[cfg(not(target_os = "none"))]
pub fn enable() {}

/// The bare-metal form.
#[cfg(target_os = "none")]
pub fn enable() {
    // SAFETY: `sti` sets `RFLAGS.IF`.  It takes effect after the following
    // instruction, so a caller that needs an atomic window around it has to
    // account for that, this function does not.
    unsafe { core::arch::asm!("sti", options(nomem, nostack)) };
}

/// Disable local interrupts, reporting whether they were enabled.
///
/// The return value is the argument [`restore`] expects: a lock that took them
/// from a disabled context puts them back off, and one that took them from an
/// enabled context puts them back on.  Getting this backwards turns a nested
/// acquisition into an interrupt storm or a hang.
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

    /// A host has no interrupt flag, so `save_and_disable` reports that
    /// interrupts were already off and `restore(false)` is a no-op.  The pair
    /// has to round-trip: whatever it reported is what a caller passes back,
    /// and a host build reporting `true` would have every lock try to re-enable
    /// an interrupt state the host never had.
    #[test]
    fn a_host_reports_interrupts_were_off() {
        assert!(!save_and_disable());
    }
}
