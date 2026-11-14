//! abi/src/time.rs
//!
//! The wire shape of a time value, and the clock a caller asked it of.
//!
//! ## Why a record and not one word
//!
//! A counter reading is a word, and a program cannot use it: the rate it counts
//! at is the machine's, and two machines convert a reading to seconds with two
//! different divisors.  So the kernel does the division and the answer is a
//! pair, whole seconds since the machine started counting, and the nanoseconds
//! inside the second.  Two words, sixteen bytes, and no unit left for a caller
//! to guess.
//!
//! ## Why the clock is an argument
//!
//! Because there is more than one thing a caller could mean by "now", and the
//! one this build cannot answer has to be refused rather than approximated.
//! [`CLOCK_MONOTONIC`] is the machine's own counter: it starts somewhere the
//! kernel remembers and never goes backwards.  [`CLOCK_REALTIME`] is wall-clock
//! time, which needs a real-time clock device, and this kernel has no driver
//! for one, the number is defined so a caller gets
//! [`crate::Error::Unsupported`] instead of a timestamp that looks real and is
//! not.

use core::mem::offset_of;
use core::mem::size_of;

/// The machine's own counter, divided by its rate: seconds since it started.
///
/// "Since it started" and not "since the epoch": this clock never goes
/// backwards and its zero is not a calendar date.  That is what makes it useful
/// for measuring an interval and useless for naming an instant to somebody
/// else.
pub const CLOCK_MONOTONIC: usize = 0;

/// Wall-clock time, which this build does not have.
///
/// Defined rather than absent so the refusal is specific.  A caller that asked
/// for it and got `InvalidArgument` would be told its own argument was wrong;
/// `Unsupported` is the answer that says the kernel is what is missing.
pub const CLOCK_REALTIME: usize = 1;

/// The clocks this build understands, and therefore the ids a caller may name.
pub const CLOCK_KNOWN: usize = CLOCK_MONOTONIC | CLOCK_REALTIME;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// One clock reading, as `GetTimeOfDay` answers it.
///
/// `seconds` is whole seconds and `nanoseconds` is the rest of the second, in
/// `0..1_000_000_000`.  Both are words, so the record is sixteen bytes on every
/// machine this tree builds for; the offsets below are what a program uses to
/// read it out of the buffer it handed over.
pub struct TimeRecord {
    pub seconds: usize,
    pub nanoseconds: usize,
}

impl TimeRecord {
    pub const fn new(seconds: usize, nanoseconds: usize) -> Self {
        Self {
            seconds,
            nanoseconds,
        }
    }
}

pub const TIME_RECORD_SIZE: usize = size_of::<TimeRecord>();
pub const TIME_RECORD_SECONDS_OFFSET: usize = offset_of!(TimeRecord, seconds);
pub const TIME_RECORD_NANOSECONDS_OFFSET: usize = offset_of!(TimeRecord, nanoseconds);

/// The most nanoseconds one second can hold.
///
/// A named constant because it is the divisor the conversion uses and the bound
/// a reader checks an answer against; a `1_000_000_000` spelled inside a
/// function would be the same number in a place a program cannot cite.
pub const NANOSECONDS_PER_SECOND: usize = 1_000_000_000;

#[cfg(test)]
mod tests {
    use super::CLOCK_KNOWN;
    use super::CLOCK_MONOTONIC;
    use super::CLOCK_REALTIME;
    use super::NANOSECONDS_PER_SECOND;
    use super::TIME_RECORD_NANOSECONDS_OFFSET;
    use super::TIME_RECORD_SECONDS_OFFSET;
    use super::TIME_RECORD_SIZE;
    use super::TimeRecord;

    /// The ids and the record's layout are the wire format.
    ///
    /// A program reads the record at the offsets below and names its clock by
    /// the numbers above; both sides compiling against this crate is what keeps
    /// them in step, and these assertions are what keeps the crate's promise
    /// from moving in a release nobody noticed.
    #[test]
    fn the_record_and_the_clock_ids_are_the_wire_values() {
        assert_eq!(CLOCK_MONOTONIC, 0);
        assert_eq!(CLOCK_REALTIME, 1);
        assert_eq!(CLOCK_KNOWN, CLOCK_MONOTONIC | CLOCK_REALTIME);
        assert_eq!(TIME_RECORD_SIZE, 16);
        assert_eq!(TIME_RECORD_SECONDS_OFFSET, 0);
        assert_eq!(TIME_RECORD_NANOSECONDS_OFFSET, 8);
        assert_eq!(NANOSECONDS_PER_SECOND, 1_000_000_000);
    }

    /// A reading keeps the fields it was built with, and the record is `Copy`.
    #[test]
    fn a_reading_keeps_its_two_fields() {
        let reading = TimeRecord::new(7, 500);
        assert_eq!(reading.seconds, 7);
        assert_eq!(reading.nanoseconds, 500);
        assert_eq!(reading, TimeRecord::new(7, 500));
        assert_ne!(reading, TimeRecord::new(8, 500));
    }
}
