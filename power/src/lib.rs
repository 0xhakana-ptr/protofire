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

#[cfg(test)]
mod tests;

pub use governors::GovernorType;
pub use governors::calculate_target;
