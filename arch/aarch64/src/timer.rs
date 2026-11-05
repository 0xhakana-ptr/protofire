//! arch/aarch64/src/timer.rs
//!
//! The generic timer: a counter that counts, and one register that says when to
//! be interrupted.
//!
//! ## What the machine has
//!
//! Every AArch64 core has a system counter that runs at a fixed frequency and
//! two timers over it:
//!
//! | register | what |
//! |---|---|
//! | `CNTFRQ_EL0` | the counter's frequency in Hz |
//! | `CNTPCT_EL0` | the counter's value, which only goes up |
//! | `CNTP_TVAL_EL0` | a countdown that fires when it reaches zero |
//! | `CNTP_CTL_EL0` | the timer's enable and its interrupt mask |
//!
//! The `P` is the **physical** timer; there is also a virtual one (`CNTV_*`)
//! which a hypervisor's guest uses.  This kernel runs at EL1 on the physical
//! machine and uses the physical timer.
//!
//! ## Why a countdown and not a deadline
//!
//! `CNTP_CVAL_EL0` takes an absolute compare value and `CNTP_TVAL_EL0` takes a
//! countdown.  The countdown is the one this kernel uses because it cannot be
//! wrong by arithmetic: a caller that computed a deadline from the counter
//! would have to subtract the counter's *current* value, and a read that
//! arrived one tick late would program a deadline in the past, which fires
//! immediately and looks like a timer that ignores its interval.
//!
//! ## The trap a frequency invites
//!
//! `CNTFRQ_EL0` is not a constant of the format; the firmware sets it, and a
//! machine may report anything.  So every conversion here takes the frequency
//! as an argument, and a zero is treated as a machine that cannot say, not as
//! a division by zero and not as a guess.

/// `CNTP_CTL_EL0` bit 0: the timer is enabled.
pub const CONTROL_ENABLE: u64 = 1 << 0;
/// `CNTP_CTL_EL0` bit 1: the timer's interrupt is masked.
///
/// **Set means masked**, which is the opposite of every other enable here and
/// the reason a timer that was "enabled" can still never fire.
pub const CONTROL_MASKED: u64 = 1 << 1;
/// `CNTP_CTL_EL0` bit 2: the timer has fired and the interrupt has not been
/// acknowledged.  Reading the status clears nothing; reprogramming does.
pub const CONTROL_ISTATUS: u64 = 1 << 2;

/// The generic timer's interrupt, as a private interrupt number.
///
/// 30 on the `virt` machine and on every GIC that follows the architecture.
/// A machine that put it elsewhere says so in its device tree, and this kernel
/// reads that; the constant is the fallback for a machine whose tree is
/// silent.
pub const TIMER_INTERRUPT: usize = 30;

/// The counter's frequency in Hz, or `None` when the machine does not say.
///
/// # Safety
///
/// Reads a system register at EL0 or above; no side effects.
#[cfg(target_os = "none")]
pub unsafe fn frequency() -> Option<u64> {
    let value: u64;
    // SAFETY: an ID register read with no side effect.  `CNTFRQ_EL0` is
    // writable only from the highest exception level, and readable everywhere.
    unsafe {
        core::arch::asm!(
            "mrs {}, cntfrq_el0",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        )
    };
    (value != 0).then_some(value)
}

/// The counter's current value.
///
/// # Safety
///
/// As [`frequency`].
#[cfg(target_os = "none")]
pub unsafe fn counter() -> u64 {
    let value: u64;
    // SAFETY: a counter read with no side effect.
    unsafe {
        core::arch::asm!(
            "mrs {}, cntpct_el0",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        )
    };
    value
}

/// The physical timer's control register, as it reads.
///
/// # Safety
///
/// Reads a system register; no side effects.
#[cfg(target_os = "none")]
pub unsafe fn control() -> u64 {
    let value: u64;
    // SAFETY: a register read with no side effect.
    unsafe {
        core::arch::asm!(
            "mrs {}, cntp_ctl_el0",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        )
    };
    value
}

/// Turn the timer on so that it fires `ticks` counter ticks from now.
///
/// # Safety
///
/// Called at EL1, after the timer's interrupt is enabled in the controller.
/// Programming a timer whose line is not enabled is a machine that counts and
/// never tells anyone.
#[cfg(target_os = "none")]
pub unsafe fn arm(ticks: u64) {
    // SAFETY: `CNTP_TVAL_EL0` is the countdown and `CNTP_CTL_EL0` its control;
    // both are EL1 registers with no memory operand.
    unsafe {
        core::arch::asm!("msr cntp_tval_el0, {}", in(reg) ticks, options(nostack));
        core::arch::asm!(
            "msr cntp_ctl_el0, {}",
            in(reg) CONTROL_ENABLE,
            options(nostack)
        );
        core::arch::asm!("isb", options(nostack));
    }
}

/// Stop the timer.
///
/// # Safety
///
/// As [`arm`].
#[cfg(target_os = "none")]
pub unsafe fn disarm() {
    // SAFETY: as `arm`, disabling rather than enabling.
    unsafe {
        core::arch::asm!("msr cntp_ctl_el0, {}", in(reg) 0u64, options(nostack));
        core::arch::asm!("isb", options(nostack));
    }
}

/// Whether the timer has fired and not been reprogrammed.
///
/// # Safety
///
/// As [`frequency`].
#[cfg(target_os = "none")]
pub unsafe fn has_fired() -> bool {
    let control: u64;
    // SAFETY: a register read with no side effect.
    unsafe {
        core::arch::asm!(
            "mrs {}, cntp_ctl_el0",
            out(reg) control,
            options(nomem, nostack, preserves_flags)
        )
    };
    control & CONTROL_ISTATUS != 0
}

/// How many ticks one millisecond is, given the counter's frequency.
///
/// The function is separate from the read so a test can check the arithmetic
/// without a machine: a frequency of 62.5 MHz is `62500` ticks per millisecond,
/// and a scheduler that got that wrong would run its time slice ten times too
/// long or too short.
pub const fn ticks_per_millisecond(frequency: u64) -> u64 {
    frequency / 1000
}

/// How many ticks one microsecond is.
///
/// The counter's frequency is in Hz, which is ticks per *second*, so a
/// microsecond is the frequency divided by a million.  At 1 GHz that is a
/// thousand ticks, and at 62.5 MHz it is zero, a counter too slow to express a
/// microsecond, which a caller learns here rather than by arming a slice that
/// is one tick long whatever it asked for.
pub const fn ticks_per_microsecond(frequency: u64) -> u64 {
    frequency / 1_000_000
}

/// How many ticks `microseconds` is, saturating rather than wrapping.
pub const fn ticks_for_microseconds(frequency: u64, microseconds: u64) -> u64 {
    let ticks = ticks_per_microsecond(frequency).saturating_mul(microseconds);
    // A zero countdown is a timer that fired before it was armed, so the
    // smallest slice this can produce is one tick.
    if ticks == 0 { 1 } else { ticks }
}

/// How many ticks `milliseconds` is, saturating rather than wrapping.
///
/// A caller that asked for a slice longer than the counter can express gets the
/// longest one it can have, which fires later rather than immediately.
pub const fn ticks_for(frequency: u64, milliseconds: u64) -> u64 {
    ticks_per_millisecond(frequency).saturating_mul(milliseconds)
}

#[cfg(test)]
mod tests {
    use super::CONTROL_ENABLE;
    use super::CONTROL_ISTATUS;
    use super::CONTROL_MASKED;
    use super::TIMER_INTERRUPT;
    use super::ticks_for;
    use super::ticks_per_millisecond;

    /// The control register's three bits are the ones the architecture names.
    ///
    /// Bit 1 is **masked**, not enabled, which is the inversion that makes a
    /// timer that was "turned on" never fire: a driver that wrote `1 << 1` to
    /// enable it would be masking it.
    #[test]
    fn the_control_bits_are_the_architectures() {
        assert_eq!(CONTROL_ENABLE, 1);
        assert_eq!(CONTROL_MASKED, 2);
        assert_eq!(CONTROL_ISTATUS, 4);
        // Enabling is bit 0 and it does not carry the mask bit.
        assert_eq!(CONTROL_ENABLE & CONTROL_MASKED, 0);
    }

    /// A millisecond is the frequency divided by a thousand.
    ///
    /// The `virt` machine's counter runs at 62.5 MHz, so one millisecond is
    /// 62500 ticks.  The number is written out because a driver that used the
    /// frequency directly would program a slice a thousand times too long.
    #[test]
    fn a_millisecond_is_the_frequency_over_a_thousand() {
        assert_eq!(ticks_per_millisecond(62_500_000), 62_500);
        assert_eq!(ticks_per_millisecond(1_000), 1);
        assert_eq!(ticks_per_millisecond(999), 0, "a frequency below 1 kHz");
    }

    /// A slice is the millisecond count times that, saturating.
    #[test]
    fn a_slice_is_its_milliseconds() {
        let frequency = 62_500_000;
        assert_eq!(ticks_for(frequency, 10), 625_000);
        assert_eq!(ticks_for(frequency, 1), 62_500);
        // A slice longer than the counter can express is the longest one, not a
        // wrapped one that fires immediately.
        assert_eq!(ticks_for(frequency, u64::MAX), u64::MAX);
    }

    /// The timer's interrupt is a private one.
    ///
    /// 30 is below 32, which is why the controller's enable path has a separate
    /// branch for private interrupts: a driver that wrote a target byte for it
    /// would be writing another interrupt's.
    #[test]
    fn the_timer_interrupt_is_private() {
        assert_eq!(TIMER_INTERRUPT, 30);
        // A relation between two constants, so it is checked at compile time
        // rather than by a test that can only ever pass.
        const _: () = assert!(TIMER_INTERRUPT < 32, "private, so it has no target byte");
    }
}
