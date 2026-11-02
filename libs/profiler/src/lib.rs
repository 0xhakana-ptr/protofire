//! libs/profiler/src/lib.rs
//!
//! Operation counters, compiled out when nobody asked for them.
//!
//! ## Why a crate
//!
//! The allocator counts allocations; the frame pool counts frames; whatever is
//! measured next will want the same shape.  The counters are a *feature*
//! (`alloc_profiler`), and the feature has to reach the crate that owns the
//! code being counted — which is why this cannot live inside the allocator: the
//! allocator would then be the thing deciding whether it is measured, and a
//! caller that wanted the counters would have to enable the allocator's
//! feature rather than this one.
//!
//! ## The zero-cost claim
//!
//! With the feature off, every counter is a no-op and `AllocProfiler` is a
//! zero-sized type, so a field of it in an allocator struct costs nothing.
//! That is a property of the type rather than of the build flags, and the test
//! below is what holds it: a build that lost the zero-sized property would
//! change the size of every allocator struct that embeds one, silently.
//!
//! Counters are `Relaxed` on purpose: they are observed by a log line at the
//! end of a boot, not synchronised with, and an `AcqRel` on the allocation path
//! would cost more than the measurement is worth.

#![no_std]

pub mod profiler;

pub use profiler::AllocProfiler;
pub use profiler::AllocProfilerSnapshot;
