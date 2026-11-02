//! libs/allocator/src/wrapper.rs
//!
//! Global allocator wiring, `HeapAllocator` public API, and `heap_model()`
//! accessor.

pub use super::allocator::KernelGlobalAllocator;

// ─── The heap model ───────────────────────────────────────────────────────
//
// This crate does **not** install a `#[global_allocator]`, and the absence is
// the design: a library that installed one could not be a dependency of a test
// binary, because two global allocators is a link error.  The kernel installs
// `KernelGlobalAllocator` in the change that gives it a `#[global_allocator]`
// of its own; here the model is a static the tests and the kernel both reach.
//
// The host arm is gone for the same reason: `std::alloc::System` was how the
// previous tree let the same file serve a host build, and in this tree the host
// build is the crate's own tests, which use `HeapAllocator` over the model
// rather than a second allocator.

/// The model the kernel and the tests both drive.
pub static HEAP_MODEL: KernelGlobalAllocator = KernelGlobalAllocator::new();

#[derive(Clone, Copy, Default)]
pub struct HeapAllocator;

impl HeapAllocator {
    /// Create a new `HeapAllocator` handle.
    ///
    /// The allocator is not initialised until [`init()`] is called.
    pub const fn new() -> Self {
        Self
    }

    /// Initialise the kernel heap allocator.
    ///
    /// Must be called once during kernel initialisation, after the MMU
    /// and page tables are active.  Subsequent calls are idempotent.
    pub fn init(&self) {
        heap_model().ensure_init();
    }

    /// Return the `(start, end)` addresses of the kernel heap region.
    pub fn bounds(&self) -> (usize, usize) {
        heap_model().bounds()
    }

    /// Return the number of free bytes remaining in the kernel heap.
    pub fn remaining(&self) -> usize {
        heap_model().remaining()
    }
}

pub(crate) fn heap_model() -> &'static KernelGlobalAllocator {
    &HEAP_MODEL
}

/// Verify the integrity of the kernel heap. Returns a human-readable report.
pub fn verify_kernel_heap() {
    heap_model().verify_heap_integrity();
}
