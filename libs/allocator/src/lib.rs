//! libs/allocator/src/lib.rs
//!
//! A TLSF allocator, as a library with no kernel in it.
//!
//! ## What this crate is
//!
//! The heap: a two-level segregated fit allocator over a fixed arena, with the
//! block splitting, merging and free-list bookkeeping that arrangement implies.
//! It knows about memory and nothing else, no console, no filesystem, no
//! thread, which is what lets its arithmetic be tested on the host.
//!
//! ## What it is not
//!
//! It does not find memory.  The arena is a `static` array in `tlsf.rs`, sized
//! at compile time; a kernel that wants frames from a machine's memory map
//! arranges that elsewhere.  It does not install itself as
//! `#[global_allocator]` either, that is the kernel's decision, because a
//! library that installed one could not be a dependency of a test binary.
//!
//! ## The one thing it needs from its caller
//!
//! A diagnostic sink.  Allocation failures are reported through
//! [`diag::set_writer`] rather than through the kernel's `println!`, because a
//! heap that cannot be built without a console cannot be tested without one.
//! With no writer installed the messages are dropped, which is the state a host
//! test is in by default.
//!
//! ## Why the tests live here
//!
//! They exercise block splitting and merging, alignment, the free lists and the
//! failure paths, the parts where an arithmetic mistake is silent until a boot
//! corrupts something.  None of it needs a machine, and all of it is cheaper to
//! run here than under QEMU.

#![no_std]

// The tests drive the allocator through `Vec`, which is the shape a caller
// uses; nothing in the library itself allocates.
#[cfg(test)]
extern crate alloc;

#[cfg(test)]
extern crate std;

mod allocator;
pub mod diag;
mod tlsf;
mod wrapper;

pub use allocator::KernelGlobalAllocator;
pub use wrapper::HeapAllocator;
pub use wrapper::verify_kernel_heap;

#[cfg(test)]
mod tests;
