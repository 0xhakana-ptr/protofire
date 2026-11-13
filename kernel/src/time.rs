//! kernel/src/time.rs
//!
//! What a program gets when it asks the kernel for the time.
//!
//! ## One clock, and the one it is
//!
//! The machine's counter, divided by its rate.  `arch::timer_counter` is the
//! only source of elapsed time this kernel has: there is no real-time-clock
//! driver, so wall time is a question with no answer here, and
//! [`abi::time::CLOCK_REALTIME`] is answered `Unsupported` rather than with a
//! plausible-looking number nobody read.
//!
//! The counter's own zero is wherever it was when the boot started, which is
//! not the same value on two machines and is not zero even on one — a
//! timestamp counter has been running since firmware.  So the boot records the
//! reading it saw, and every answer is measured from there: a program asking
//! for the time twice gets two readings of the same clock, and the difference
//! is a duration in real units.
//!
//! ## Why the division lives here and not in `arch`
//!
//! A machine answers "what does the counter read" and "how fast does it count".
//! Turning the pair into seconds and nanoseconds is arithmetic, and arithmetic
//! is the part a host can test — which is why [`split`] is a pure function and
//! the only thing [`now`] adds to it is the two machine reads.
//!
//! ## Not to be confused with `service::clock`
//!
//! That module is the service table's demonstration: a service whose operation
//! is "read the counter", installed so a boot can show the table resolving a
//! name and answering a completion.  This module is the syscall's source.  They
//! read the same register and share no code, and neither is a wrapper around
//! the other.

use abi::Error;
use abi::Result;
use abi::time as time_abi;

// The two machine facts, recorded once at boot.  Absent on the host, which has
// no counter to read: there they would be two statics nothing could load, and
// a host build that carried them would be carrying the state of a clock it
// cannot consult.
#[cfg(target_os = "none")]
use core::sync::atomic::AtomicU64;
#[cfg(target_os = "none")]
use core::sync::atomic::Ordering;

/// The counter reading the boot saw, which every answer is measured from.
///
/// Zero when the clock was never brought up, which [`now`] treats as "this
/// machine cannot tell the time" rather than as an origin at the counter's
/// zero — the two are only the same on a counter that started at zero.
#[cfg(target_os = "none")]
static ORIGIN: AtomicU64 = AtomicU64::new(0);

/// How fast the counter counts, in ticks per second.
///
/// Zero until [`bring_up`] has measured it, and zero is the reason [`now`]
/// refuses rather than divides.
#[cfg(target_os = "none")]
static RATE: AtomicU64 = AtomicU64::new(0);

/// Read the machine's counter and rate, and remember both.
///
/// Answers the origin and the rate it recorded, or `None` when the machine will
/// not say how fast it counts.  A `None` is not a failure of the boot: a
/// program that asks for the time on a machine like that is told the call is
/// unsupported, which is true, instead of being handed a number whose unit is
/// unknown.
///
/// Both are answered because both are facts the boot's line has to name to be
/// worth printing.  A line that reported only the rate would say "the clock is
/// set up" without ever showing the reading every later answer is measured
/// from, and the reading is the part that comes from the machine.
///
/// # Safety
///
/// Called once, from the boot, after the timer's rate is known and before any
/// program runs.  It reads the counter and writes the two statics above.
#[cfg(target_os = "none")]
pub unsafe fn bring_up() -> Option<(u64, u64)> {
    // SAFETY: the caller's contract is this function's; the rate is read after
    // the boot has brought the timer up, which is what makes it a measurement.
    let rate = unsafe { arch::clock_frequency() }?;
    if rate == 0 {
        return None;
    }
    // SAFETY: read-only.
    let origin = unsafe { arch::timer_counter() };
    ORIGIN.store(origin, Ordering::Release);
    RATE.store(rate, Ordering::Release);
    Some((origin, rate))
}

/// Divide a counter reading into whole seconds and nanoseconds.
///
/// Answers `None` when the rate is zero, which is the only division that would
/// fault: a clock with no rate is a machine that could not say how fast its
/// counter moves, and a caller must be told that rather than given a reading it
/// cannot convert.
///
/// The multiplication is in `u128` on purpose.  The remainder is below the
/// rate, so `remainder * 1_000_000_000` at a 3 GHz rate is 3e18, which fits a
/// `u64` — but only just, and a machine with a 20 GHz counter would overflow it
/// silently.  The wider type costs one multiply on a path a program calls by
/// hand and cannot be wrong.
pub fn split(ticks: u64, rate: u64) -> Option<(u64, u64)> {
    if rate == 0 {
        return None;
    }
    let seconds = ticks / rate;
    let remainder = ticks % rate;
    let nanoseconds = (remainder as u128 * time_abi::NANOSECONDS_PER_SECOND as u128) / rate as u128;
    // The division cannot reach a whole second: the numerator is below the
    // divisor times a second, which is what `remainder < rate` says.
    Some((seconds, nanoseconds as u64))
}

/// The reading one clock gives right now.
///
/// `clock` is `abi::time::CLOCK_MONOTONIC` or `CLOCK_REALTIME`; anything else
/// is a caller naming a clock this ABI does not define, and a defined clock
/// this build cannot answer is `Unsupported`.
pub fn now(clock: usize) -> Result<time_abi::TimeRecord> {
    match clock {
        time_abi::CLOCK_MONOTONIC => monotonic(),
        // Defined, and honest about being missing: a wall clock needs a
        // real-time clock device, and this kernel has no driver for one.
        time_abi::CLOCK_REALTIME => Err(Error::Unsupported),
        _ => Err(Error::InvalidArgument),
    }
}

/// The machine's own counter, as a reading.
fn monotonic() -> Result<time_abi::TimeRecord> {
    #[cfg(target_os = "none")]
    {
        let rate = RATE.load(Ordering::Acquire);
        // SAFETY: read-only, and the counter is read after the boot armed it.
        let counter = unsafe { arch::timer_counter() };
        let origin = ORIGIN.load(Ordering::Acquire);
        // A counter that went backwards is a machine whose origin is not one;
        // measuring from it would answer a reading of nearly four billion
        // seconds.  `saturating_sub` says "zero elapsed" instead, which is
        // wrong by less.
        let elapsed = counter.saturating_sub(origin);
        let (seconds, nanoseconds) = split(elapsed, rate).ok_or(Error::Unsupported)?;
        Ok(time_abi::TimeRecord::new(
            seconds as usize,
            nanoseconds as usize,
        ))
    }
    #[cfg(not(target_os = "none"))]
    {
        // A host has no counter to read, so the answer is the true one: this
        // build cannot tell the time.  The arithmetic is still tested, through
        // `split`, which is where the division actually lives.
        Err(Error::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    use super::split;

    /// A reading splits into the seconds it holds and the rest.
    ///
    /// The three cases are the ones a conversion gets wrong: an exact second
    /// (a remainder that must read zero and not one nanosecond short), a
    /// fraction (the nanoseconds must be the fraction, scaled), and a reading
    /// below one second (seconds must be zero rather than one).
    #[test]
    fn a_reading_splits_into_seconds_and_a_fraction() {
        assert_eq!(split(3_000_000_000, 1_000_000_000), Some((3, 0)));
        assert_eq!(split(3_500_000_000, 1_000_000_000), Some((3, 500_000_000)));
        assert_eq!(split(999_999_999, 1_000_000_000), Some((0, 999_999_999)));
        assert_eq!(split(0, 1_000_000_000), Some((0, 0)));
    }

    /// The nanoseconds field never reaches a second.
    ///
    /// This is the invariant a caller divides by: a field that could equal
    /// `1_000_000_000` would make a program's own arithmetic spill into the
    /// seconds it already counted.  Checked across a counter that starts at an
    /// arbitrary value and moves by a stride that is not a divisor of the rate.
    #[test]
    fn the_fraction_never_reaches_a_second() {
        let rate = 1_000_000_000u64;
        for step in 0..1_000u64 {
            let ticks = 12_345_678_901 + step * 7_919_123;
            let (_, nanoseconds) = split(ticks, rate).expect("a rate was given");
            assert!(
                nanoseconds < 1_000_000_000,
                "{nanoseconds} nanoseconds is not inside a second"
            );
        }
    }

    /// A rate of zero is refused rather than divided by.
    ///
    /// The one input that would fault, and it arrives from the machine: a boot
    /// whose timer never reported a frequency records zero, and a program
    /// asking for the time then must be told the call is unsupported.
    #[test]
    fn a_rate_of_zero_is_refused() {
        assert_eq!(split(1, 0), None);
    }

    /// A fast counter does not overflow the scaling multiply.
    ///
    /// The reason the multiply is `u128`: at 20 GHz the remainder can be 2e10,
    /// and `2e10 * 1e9` is 2e19, past `u64::MAX`.  A `u64` multiply would
    /// answer a fraction that is not the fraction, which is the quiet kind of
    /// wrong.
    #[test]
    fn a_fast_counter_scales_without_overflow() {
        let rate = 20_000_000_000u64;
        let (seconds, nanoseconds) = split(rate / 2, rate).expect("a rate was given");
        assert_eq!(seconds, 0);
        assert_eq!(nanoseconds, 500_000_000);
    }
}
