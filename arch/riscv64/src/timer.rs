//! arch/riscv64/src/timer.rs
//!
//! The S-mode timer, which on this machine is a firmware call.
//!
//! ## What the machine has
//!
//! A counter, `time`, that only goes up; a rate for it that exists nowhere in
//! the machine but the device tree's `/cpus` node; and a deadline, which S-mode
//! does not hold.  The compare register `stimecmp`, and with it the `Sstc`
//! extension, would let this mode arm the timer with one CSR write, but what
//! OpenSBI hands every machine is the **legacy** timer call: an `ecall` from
//! S-mode that traps to M-mode and writes the deadline there.  That is the arm
//! this machine uses, and it is why arming is a trap and not a register write.
//!
//! ## The clobbers are the trap
//!
//! An `ecall` into firmware clobbers the argument registers, the firmware is
//! another machine's code running on this hart, and it keeps its state
//! wherever it likes.  A timer call that does not declare them destroys
//! whatever the interrupted code had in `a0`..`a7`, so every timer interrupt
//! reports tick 1: the deadline is recomputed against a register that was just
//! eaten. Every register the call can reach is declared here, which is the one
//! place a reader can check it.
//!
//! ## A fire is a deadline passed
//!
//! There is no compare register to read back and no status bit this mode owns:
//! whether the timer has fired is whether `mtime` is past the deadline M-mode
//! wrote.  The honest answer to "did it fire" is the pending bit in `sip`,
//! which is set by the machine when the counter passes the deadline and cleared
//! by the next arm.

/// The rate the counter runs at, as the tree states it.
///
/// RISC-V has no register that reports it, so the machine's answer comes from
/// the machine's description; `None` is what a boot without a tree gets, and a
/// caller treats that as "no timer" rather than as a frequency of zero.
///
/// # Safety
///
/// Reads the device tree's pointer, which stays mapped for the life of the
/// boot; no side effects.
#[cfg(target_os = "none")]
pub unsafe fn frequency() -> Option<u64> {
    crate::boot::timebase_frequency()
}

/// The counter's current value.
///
/// # Safety
///
/// A counter read with no side effect.
#[cfg(target_os = "none")]
pub unsafe fn counter() -> u64 {
    let value: u64;
    // SAFETY: a read-only CSR with no side effect.
    unsafe {
        core::arch::asm!(
            "csrr {}, time",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        )
    };
    value
}

/// Whether the timer's line is pending.
///
/// `sip`'s supervisor timer bit is the only fire this mode can read: the
/// deadline itself lives in M-mode, and the counter alone cannot say whether
/// the machine has agreed to act.
///
/// # Safety
///
/// A read-only CSR read; no side effects.
#[cfg(target_os = "none")]
pub unsafe fn has_fired() -> bool {
    let pending: u64;
    // SAFETY: a read-only CSR read; no side effect.
    unsafe {
        core::arch::asm!(
            "csrr {}, sip",
            out(reg) pending,
            options(nomem, nostack, preserves_flags)
        )
    };
    pending & PENDING_TIMER != 0
}

/// The enable and pending bits this machine's timer answers through.
///
/// `sie` bit 5 gates delivery of the supervisor timer interrupt and `sip` bit 5
/// reports it pending; both are the timer's, and both are read here rather
/// than spelled at the call sites.
pub const ENABLE_TIMER: u64 = 1 << 5;
pub const PENDING_TIMER: u64 = 1 << 5;

/// Tell the firmware the deadline is `ticks` counter ticks from now.
///
/// The legacy call takes the **absolute** deadline, not a countdown, which is
/// the opposite of the aarch64 timer's `TVAL` register, and the reason the
/// deadline is computed here against a counter read made inside the same
/// function: a caller that computed one from an earlier read would arm a
/// deadline that is partly in the past by however long the call took to reach
/// here.
///
/// # Safety
///
/// Called at S-mode with the firmware's timer extension present.  The call
/// traps to M-mode and returns; nothing in this crate's state changes except
/// the deadline.
#[cfg(target_os = "none")]
pub unsafe fn arm(ticks: u64) {
    // The deadline is absolute: the counter read and the call are one
    // transaction, so the read is fresh by however many instructions separate
    // it from the `ecall`.
    //
    // SAFETY: a read-only counter read.
    let deadline = unsafe { counter() }.wrapping_add(ticks);
    let error: i64;
    // SAFETY: the legacy timer call, `ecall` with `a7` = 0 and the deadline in
    // `a0`.  Every argument register is declared late-out because the firmware
    // clobbers them, an undeclared clobber is a register the interrupted code
    // loses silently, which is the defect this module's header describes.
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") deadline => error,
            lateout("a1") _,
            lateout("a2") _,
            lateout("a3") _,
            lateout("a4") _,
            lateout("a5") _,
            lateout("a6") _,
            // `a7` carries the extension id in, and the firmware may eat it
            // on the way out: declaring it input-only would let the compiler
            // keep something live in it across the call.
            inlateout("a7") 0u64 => _,
            options(nostack)
        )
    };
    // The legacy call answers `0` for success and negative for failure, and a
    // failure leaves the timer as it was, which a boot sees as a counter that
    // reads the same twice, not as an error here.  The value is read so the
    // call is honest about producing one; nothing in this crate can act on a
    // firmware refusal to arm.
    let _ = error;
}

/// Push the deadline out beyond any boot's lifetime.
///
/// There is no disable bit this mode owns: "off" is a deadline the counter
/// will not reach, which is what half the counter's range from now is.  It is
/// **half** and not the whole range for an arithmetic reason the first boot
/// demonstrated at four thousand ticks a second: the deadline is computed by
/// adding to the counter, and adding the counter's full range *wraps* to one
/// tick in the past, a disarm that fires immediately, whose handler re-arms
/// the real slice, and whose boot then spends its quiet phases taking a trap
/// every hundred microseconds.
///
/// # Safety
///
/// As [`arm`].
#[cfg(target_os = "none")]
pub unsafe fn disarm() {
    // SAFETY: as `arm`.
    unsafe { arm(u64::MAX >> 1) }
}

/// The register that holds the timer's enable, as it reads.
///
/// This machine's timer has no control register of its own, the aarch64
/// timer's `CNTP_CTL_EL0` and x86_64's LVT entry are registers this platform
/// does not have.  What it has is the `sie` register, whose bit 5 is the
/// timer's enable, so that register is what "the timer's control" reads here.
/// A boot that printed it after enabling the line finds the bit set, which is
/// the one fact a control read can give.
///
/// # Safety
///
/// A read-only CSR read; no side effects.
#[cfg(target_os = "none")]
pub unsafe fn control() -> u64 {
    let value: u64;
    // SAFETY: a read-only CSR read; no side effect.
    unsafe {
        core::arch::asm!(
            "csrr {}, sie",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        )
    };
    value
}

/// How many ticks one millisecond is, given the counter's rate.
pub const fn ticks_per_millisecond(frequency: u64) -> u64 {
    frequency / 1000
}

/// How many ticks `microseconds` is, saturating rather than wrapping.
///
/// **Multiply first, then divide**, for the reason the aarch64 copy of this
/// function states at length: dividing the frequency first throws away what
/// the division discards, and a frequency below one megahertz divided to zero
/// and made every slice one tick whatever the caller asked for.
pub const fn ticks_for_microseconds(frequency: u64, microseconds: u64) -> u64 {
    let ticks = (frequency as u128 * microseconds as u128) / 1_000_000;
    let ticks = if ticks > u64::MAX as u128 {
        u64::MAX
    } else {
        ticks as u64
    };
    // A deadline equal to the counter's current value is a fire that already
    // happened, so the smallest slice this can produce is one tick.
    if ticks == 0 { 1 } else { ticks }
}

/// How many ticks `milliseconds` is, saturating rather than wrapping.
pub const fn ticks_for(frequency: u64, milliseconds: u64) -> u64 {
    ticks_per_millisecond(frequency).saturating_mul(milliseconds)
}

#[cfg(test)]
mod tests {
    use super::ENABLE_TIMER;
    use super::PENDING_TIMER;
    use super::ticks_for;
    use super::ticks_per_millisecond;

    /// The enable and pending bits are the same one: `sie` and `sip` name
    /// their sources in step, and the timer's is bit 5 on both.
    #[test]
    fn the_timer_is_bit_five_on_both_sides() {
        assert_eq!(ENABLE_TIMER, 1 << 5);
        assert_eq!(PENDING_TIMER, 1 << 5);
    }

    /// A millisecond is the rate over a thousand, and the rate this machine's
    /// tree reports is written out because a driver that used it directly
    /// would program a slice a thousand times too long.
    #[test]
    fn a_millisecond_is_the_frequency_over_a_thousand() {
        assert_eq!(ticks_per_millisecond(10_000_000), 10_000);
        assert_eq!(ticks_per_millisecond(999), 0, "a rate below 1 kHz");
    }

    /// A slice is its microseconds at ten ticks each, saturating.
    #[test]
    fn a_slice_is_its_microseconds() {
        let frequency = 10_000_000;
        assert_eq!(super::ticks_for_microseconds(frequency, 20_000), 200_000);
        assert_eq!(super::ticks_for_microseconds(frequency, 100), 1_000);
        // A slice the counter cannot express is one tick, not a deadline in
        // the past that fires before it is armed.
        assert_eq!(super::ticks_for_microseconds(frequency, 0), 1);
        assert_eq!(ticks_for(frequency, u64::MAX), u64::MAX);
    }
}
