//! libs/allocator/src/wrapper.rs
//!
//! Global allocator wiring, `HeapAllocator` public API, and `heap_model()`
//! accessor.

pub use super::allocator::KernelGlobalAllocator;

// One heap, reached through handles
//
// This crate does **not** install a `#[global_allocator]`, and the absence is
// the design: a library that installed one could not be a dependency of a test
// binary, because two global allocators is a link error.  The kernel installs
// `KernelGlobalAllocator` as its own, and what it installs is a zero-sized
// handle: the free lists live in a `static` inside this crate, so every handle
// reaches the same lists.
//
// That arrangement replaces a defect rather than tidying one.  The state used
// to be a field, so the kernel's `#[global_allocator]` and the accessor below
// were two objects with a view of the arena each.  Only the global allocator
// was ever asked for memory, and `verify_kernel_heap` went through the other
// one, which still described the heap as one free block and reported a free
// list naming a block marked in use.  The block really was in use, by the
// allocator the check was not looking at.
//
// The host arm is gone for the same reason: `std::alloc::System` was how one
// file could serve a host build, and the host build here is the crate's own
// tests, which use `HeapAllocator` over the same `static` rather than a second
// allocator.
//
// There is deliberately no `HEAP_MODEL` static beside the state.  One used to
// sit here, and its existence was the defect: a name that looked like "the
// heap" while holding a second copy of the free lists.  `heap_model()` below
// returns a handle, which costs nothing and cannot diverge.

#[derive(Clone, Copy, Default)]
pub struct HeapAllocator;

impl HeapAllocator {
    /// Create a new `HeapAllocator` handle.
    ///
    /// The allocator is not initialised until `bounds()` is called, which is
    /// what lays out its free lists.
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

/// A handle over the one heap, for code written against the accessor.
pub(crate) fn heap_model() -> KernelGlobalAllocator {
    KernelGlobalAllocator::new()
}

/// Verify the integrity of the kernel heap. Returns a human-readable report.
pub fn verify_kernel_heap() {
    heap_model().verify_heap_integrity();
}
