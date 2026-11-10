//! power/src/lib.rs
//!
//! Frequency policy: which frequency a load asks for, and how fast the answer
//! may change.
//!
//! ## What is here
//!
//! The governors.  A governor is a pure function from a load sample and a range
//! to a target frequency, plus the state an `ondemand`-shaped one carries
//! between samples, a rising threshold, a falling one, and a step.  None of
//! that names a machine: the frequency range comes in as an argument and the
//! answer leaves as one, which is why all of it is testable on a host.
//!
//! ## What is not here yet
//!
//! The driver probing and the `arch::cpufreq_*` dispatchers.  Those ask a
//! machine for its MSRs, its device tree or its PSCI calls, and they move when
//! the architecture crates grow a `cpufreq` module, which is a change to three
//! crates, not one.
//!
//! The split is the point: a governor that had to know what an MSR is could not
//! be tested without one, and the arithmetic in `ondemand`, a threshold
//! compare, a percentage step and a clamp, is exactly the kind of thing that
//! is wrong quietly.
//!
//! ## The trait it will answer through
//!
//! `abi`'s `CpuFreqDriver` is the machine's side: what frequency it is at, what
//! range it supports, and how to ask for a change.  It lives in `abi` rather
//! than here because the architecture crates implement it, and in the previous
//! tree they imported it from `kernel::power`, an upward edge, 322 of which
//! made that tree's `arch` impossible to read alone.
//!
//! This crate names nothing: the governors are arithmetic, and the boundary to
//! the machine is whatever the change that wires the first driver decides it
//! is.

#![no_std]

pub mod governors;

pub use governors::GovernorType;
pub use governors::calculate_target;

#[cfg(test)]
mod tests {
    //! The tests for this file.
    //!
    //! Host-side unit tests for the power-management subsystem.

    use super::governors::GovernorType;
    use super::governors::calculate_target;

    /// The power subsystem is inert without an architecture driver: the default
    /// governor is still installed, but policy updates never reach the
    /// hardware. These tests exercise the pieces that are meaningful on the
    /// host (policy pure functions); driver probing itself is a bare-metal
    /// concern.
    #[test]
    fn governor_policy_pure_logic_is_stable() {
        // Performance is always the ceiling, Powersave the floor, Userspace
        // inert.
        assert_eq!(
            calculate_target(GovernorType::Performance, 42, 100_000, 400_000, 100_000),
            Some(400_000)
        );
        assert_eq!(
            calculate_target(GovernorType::Powersave, 42, 100_000, 400_000, 400_000),
            Some(100_000)
        );
        assert_eq!(
            calculate_target(GovernorType::Userspace, 42, 100_000, 400_000, 200_000),
            None
        );
    }

    #[test]
    fn schedutil_tracks_load() {
        // Linear mapping: 50% of [100k, 400k] from a 200k baseline → 250 MHz.
        assert_eq!(
            calculate_target(GovernorType::Schedutil, 50, 100_000, 400_000, 200_000),
            Some(250_000)
        );
    }
}
