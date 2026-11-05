//! memory/src/lib.rs
//!
//! Physical memory: the frame pool, the pools that hand out numbered regions,
//! and the bookkeeping that decides what is free.
//!
//! ## What is here now
//!
//! The part that is a data structure and nothing else.  A frame pool is a range
//! of address space and a bitmap of which frames are taken; a slot pool is a
//! bitmap of taken indices and one reference count per index; the fault
//! profiler is arithmetic over a fixed layout.  None of them names a page
//! table, a machine or a thread, which is what lets all of it be tested on the
//! host.
//!
//! `compressed` waits: its page-set arithmetic is clean, but it names
//! `PAGE_SIZE` from the paging module, so it moves in with the page table.
//!
//! ## What is not here yet
//!
//! The rest of the previous tree's `src/memory/`, the manager, the page table
//! walk, the architecture glue, the swapping, is the half that does name a
//! machine.  It arrives in changes of its own, because each of those files
//! reaches for `arch` and for the kernel, and moving them together would be a
//! change nobody could review.
//!
//! The boundary is worth stating because it is the crate's whole argument: a
//! frame allocator that knows how to map a page cannot be tested without a page
//! table, and the arithmetic in `allocate` and `deallocate` is where the
//! silent corruption lives.

#![no_std]

// The frame pool's node map and the profiler's snapshots are `Vec`s; a region
// of address space is not a fixed-size array, and the kernel has a heap by the
// time it asks.
extern crate alloc;

pub mod compressed;
pub mod fault_profiler;
pub mod frame;
pub mod slot_pool;

pub use frame::FrameAllocator;
pub use slot_pool::SlotPool;

#[cfg(test)]
mod tests {
    //! The tests live in the modules they test; this is only the crate-level
    //! one, which is that a hook nobody installed is not a crash.
    use crate::frame::FrameAllocator;

    /// A fresh allocator treats frames as already writable.
    ///
    /// The default hook is a no-op, and that is a decision rather than an
    /// omission: a test's frames are its own memory.  A kernel installs its
    /// own through `set_map_hook`, and a boot that forgot to would fault on the
    /// first write rather than quietly handing out unmapped memory.
    #[test]
    fn the_default_mapping_hook_is_safe_to_call() {
        let mut allocator = FrameAllocator::new();
        // No pool, so `allocate` refuses before it ever reaches the hook, //
        // which is the other half of the same property: an uninitialised
        // allocator does not call into a machine that has not been told about
        // it.
        assert!(allocator.allocate(1).is_none());
    }
}
