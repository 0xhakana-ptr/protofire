//! abi/src/power.rs
//!
//! What a machine can do about its own clock.
//!
//! ## Why this is an ABI type
//!
//! The power layer asks the machine for a frequency and the machine answers;
//! the machine's driver is written against this trait, so both sides name it.
//! In the previous tree the trait lived in `kernel::power` and the architecture
//! crates imported it, which made `arch` depend on `kernel` — the exact upward
//! edge this tree's layering refuses, and one of the 322 such edges that made
//! the old tree's `arch` impossible to read on its own.
//!
//! Frequencies are in KHz throughout, because that is what the MSR ratios and
//! the device-tree OPP tables both produce and a conversion in the middle would
//! be a second place a unit is written down.

use crate::Result;

/// A machine's CPU-frequency control, if it has one.
///
/// A driver may exist in **report-only** mode: a machine whose P-state control
/// is not writable still knows its frequency and its temperature, and reporting
/// those is worth doing.  `is_supported` is what distinguishes the two, and
/// `set_freq` returns `Unsupported` rather than silently doing nothing.
pub trait CpuFreqDriver {
    /// The driver's name, e.g. `"x86_64 MSR"`, for a log line.
    fn name(&self) -> &'static str;

    /// Whether this driver can actually scale frequency.
    fn is_supported(&self) -> bool;

    /// Current core frequency in KHz.
    fn get_current_freq(&self) -> u32;

    /// Request a core frequency in KHz.
    ///
    /// The driver clamps to its supported range.  Returns
    /// [`Error::Unsupported`] in report-only mode.
    fn set_freq(&mut self, freq_khz: u32) -> Result<()>;

    /// The achievable range in KHz, if the machine reports one.
    fn get_freq_range(&self) -> Option<(u32, u32)>;

    /// The package temperature in millidegrees Celsius, if readable.
    fn get_temperature_mc(&self) -> Option<u32>;
}
