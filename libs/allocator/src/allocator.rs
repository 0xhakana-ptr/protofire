//! libs/allocator/src/allocator.rs
//!
//! `KernelGlobalAllocator`, the core TLSF-based kernel heap allocator with
//! exponential-backoff spinlock and `GlobalAlloc` trait implementation.

use core::alloc::GlobalAlloc;
use core::alloc::Layout;
use core::ptr::null_mut;

use profiler::AllocProfiler;
use sync::SpinLock;

use super::tlsf::AllocatorState;
use super::tlsf::HEADER_SIZE;
use super::tlsf::HEAP_BLOCK_ALIGNMENT;
use super::tlsf::KERNEL_HEAP;
use super::tlsf::KERNEL_HEAP_SIZE;
use super::tlsf::MIN_FREE_BLOCK;
use super::tlsf::SL_COUNT;
use super::tlsf::SL_INDEX_LOG2;
use super::tlsf::align_up;
use super::tlsf::block_clear_used;
use super::tlsf::block_is_used;
use super::tlsf::block_set_prev_phys;
use super::tlsf::block_set_prev_phys_of_next;
use super::tlsf::block_set_size;
use super::tlsf::block_set_used;
use super::tlsf::block_size;
#[cfg(debug_assertions)]
use super::tlsf::check_invariants;
use super::tlsf::coalesce;
use super::tlsf::find_suitable_block;
use super::tlsf::insert_free_block;
use super::tlsf::mapping;
use super::tlsf::remove_free_block;
#[cfg(debug_assertions)]
use super::tlsf::scan_free_lists;

/// The free lists and bitmaps, behind the crate's lock.
///
/// Hand-rolling a spinlock here would mean a second backoff and a second
/// interrupt save/restore, a third copy of what `sync` already provides.  One
/// lock is one place to get the interrupt ordering right, and this is it.
///
/// It is a `static` rather than a field, and that is the repair for a defect
/// this tree shipped.  The kernel installed one `KernelGlobalAllocator` as its
/// `#[global_allocator]` while `verify_kernel_heap` reached a second one kept
/// by the crate, and each carried its own view of this state.  Only the first
/// was ever asked for memory, so the second went on describing the arena as one
/// free block while the first carved it, and the check read a record that
/// stopped being true at the first allocation.  Nothing was corrupt; the check
/// was reading an allocator that had never allocated.
///
/// With the state here, a handle is a way to reach these lists and not a place
/// to keep them, so the divergence is not something a caller can write down.
static STATE: SpinLock<AllocatorState> = SpinLock::new(AllocatorState::new());

/// The counters, which belong to the heap for the same reason its free lists
/// do: a per-handle copy would let one handle's allocations be invisible to a
/// snapshot taken through another.
static PROFILER: AllocProfiler = AllocProfiler::new();

/// A handle over the one heap state.
///
/// Zero-sized on purpose: it owns nothing, so two handles cannot disagree about
/// a free list.  The kernel's `#[global_allocator]` and the crate's own
/// accessor are both this type, and
/// `a_second_handle_sees_the_first_handle_s_allocation` is what holds that: it
/// allocates through one handle and asserts the other one's byte count moved.
pub struct KernelGlobalAllocator;

impl Default for KernelGlobalAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelGlobalAllocator {
    pub const fn new() -> Self {
        Self
    }

    pub(crate) fn with_state<R>(&self, callback: impl FnOnce(&mut AllocatorState) -> R) -> R {
        let mut guard = STATE.lock();
        if !guard.initialized {
            self.initialize(&mut guard);
        }

        callback(&mut guard)
    }

    pub(crate) fn ensure_init(&self) {
        self.with_state(|_| ());
    }

    pub(crate) fn initialize(&self, state: &mut AllocatorState) {
        let start = KERNEL_HEAP.get() as *mut u8 as usize;
        let end = start + KERNEL_HEAP_SIZE;

        debug_assert_eq!(start % HEAP_BLOCK_ALIGNMENT, 0);

        state.start = start;
        state.end = end;
        state.available = KERNEL_HEAP_SIZE;
        state.initialized = true;

        // Register the entire heap as one free block.
        // SAFETY: the heap is one fresh region the kernel owns, and this writes
        // the first block's header before any pointer into that region is
        // handed out.
        unsafe {
            block_set_size(start, KERNEL_HEAP_SIZE);
            block_clear_used(start);
            block_set_prev_phys(start, 0);

            insert_free_block(state, start);
        }
    }

    /// Allocate a block of memory matching the given `layout`.
    ///
    /// Searches the TLSF free lists for a suitable block, splits it if
    /// necessary, and returns a pointer to the payload (past the block
    /// header).  Returns a null pointer on allocation failure.
    ///
    /// # Parameters
    ///
    /// * `state`, mutable reference to the allocator state containing the free
    ///   lists and bitmaps.
    /// * `layout`, the requested size and alignment.
    /// * `profiler`, profiler for tracking allocated byte counts.
    pub(crate) fn allocate_locked(
        state: &mut AllocatorState,
        layout: Layout,
        profiler: &AllocProfiler,
    ) -> *mut u8 {
        let requested_size = layout.size().max(1);
        // Reserve room for the block's canary.  It is part of what the block
        // must hold, so it has to be in the size the carve is computed from, //
        // otherwise the canary would land on the caller's last bytes.
        let reserved_size = requested_size.saturating_add(super::tlsf::CANARY_SIZE);
        let requested_align = layout.align().max(HEAP_BLOCK_ALIGNMENT);

        // The block we request from the free lists must be large enough for
        // the header, the payload, and worst‑case alignment padding.
        // Tail-rounding to HEAP_BLOCK_ALIGNMENT is deterministic, so we
        // fold it in exactly:
        let end_round = HEAP_BLOCK_ALIGNMENT.wrapping_sub(HEADER_SIZE.wrapping_add(reserved_size))
            % HEAP_BLOCK_ALIGNMENT;
        let mut min_block_size = HEADER_SIZE
            .saturating_add(reserved_size)
            .saturating_add(requested_align.saturating_sub(HEAP_BLOCK_ALIGNMENT))
            .saturating_add(end_round);

        // Find a suitable free block via the TLSF bitmaps.
        // If alignment padding makes the chosen block too tight (rare, //
        // happens when there is a gap smaller than MIN_FREE_BLOCK that
        // cannot be carved into a prefix), we re-insert it and search
        // for a larger one instead of giving up.
        'search: loop {
            let candidate = find_suitable_block(state, min_block_size);
            if candidate == 0 {
                crate::diag::write(format_args!(
                    "[heap] ALLOC FAIL: requested {} bytes (align {}), min_block {} bytes, available {} KiB, fl_bitmap=0x{:x}",
                    requested_size,
                    requested_align,
                    min_block_size,
                    state.available / 1024,
                    state.fl_bitmap
                ));
                return null_mut();
            }

            // SAFETY: the candidate came out of the free lists with the lock
            // held, so its header is a block header the allocator itself wrote.
            unsafe {
                remove_free_block(state, candidate);

                let block_end = candidate.saturating_add(block_size(candidate));
                let payload_start = match align_up(candidate + HEADER_SIZE, requested_align) {
                    Some(addr) => addr,
                    None => {
                        crate::diag::write(format_args!(
                            "[heap] ALLOC FAIL (align_up overflow): block=0x{:x} size={} align={}",
                            candidate,
                            block_size(candidate),
                            requested_align,
                        ));
                        insert_free_block(state, candidate);
                        return null_mut();
                    }
                };
                let alloc_header_start = match payload_start.checked_sub(HEADER_SIZE) {
                    Some(addr) => addr,
                    None => {
                        crate::diag::write(format_args!(
                            "[heap] ALLOC FAIL (header underflow): block=0x{:x} payload=0x{:x}",
                            candidate, payload_start,
                        ));
                        insert_free_block(state, candidate);
                        return null_mut();
                    }
                };

                let mut alloc_end = match alloc_header_start
                    .checked_add(HEADER_SIZE)
                    .and_then(|a| a.checked_add(reserved_size))
                {
                    Some(addr) => addr,
                    None => {
                        crate::diag::write(format_args!(
                            "[heap] ALLOC FAIL (size overflow): block=0x{:x} header=0x{:x} requested={}",
                            candidate, alloc_header_start, requested_size,
                        ));
                        insert_free_block(state, candidate);
                        return null_mut();
                    }
                };
                alloc_end = match align_up(alloc_end, HEAP_BLOCK_ALIGNMENT) {
                    Some(addr) => addr,
                    None => {
                        crate::diag::write(format_args!(
                            "[heap] ALLOC FAIL (end align overflow): block=0x{:x} alloc_end=0x{:x}",
                            candidate, alloc_end,
                        ));
                        insert_free_block(state, candidate);
                        return null_mut();
                    }
                };

                if alloc_end > block_end {
                    // Alignment gap made this block too tight.
                    // Re-insert it and search for a larger one.
                    insert_free_block(state, candidate);
                    // Advance past the rejected block's entire SL class.
                    // Simply adding 1 to candidate_size can land in the same
                    // SL bucket, which would cause find_suitable_block to
                    // return the same block (now re-inserted at the list head)
                    // and create an infinite loop.
                    let candidate_size = block_size(candidate);
                    let (fl, sl) = mapping(candidate_size);
                    let sl_step = 1usize << fl.saturating_sub(SL_INDEX_LOG2);
                    let next_class_min = if sl + 1 < SL_COUNT {
                        // Start of the next SL class within the same FL.
                        (1usize << fl) + (sl + 1) * sl_step
                    } else {
                        // Start of the next FL class.
                        1usize << (fl + 1)
                    };
                    min_block_size = next_class_min;
                    continue 'search;
                }

                // Prefix (before aligned payload)
                let prefix_size = alloc_header_start.wrapping_sub(candidate);
                let prefix_created = prefix_size >= MIN_FREE_BLOCK;

                // Suffix (after the allocation)
                let suffix_size = block_end.wrapping_sub(alloc_end);
                let suffix_created = suffix_size >= MIN_FREE_BLOCK;

                // A suffix too small to stand as a free block cannot be a block
                // at all, so it is absorbed into the allocation.
                //
                // Leaving it out orphans the bytes between this allocation and
                // the next block: they belong to no block, their header is
                // never written, and `state.available` never accounts for
                // them.  Any walk along the physical block list, and any
                // coalesce that reaches a neighbouring free block, then steps
                // into that gap, reads a size of zero, and reports a damaged
                // heap from a place that was never a block.
                //
                // The prefix below has always been absorbed for exactly this
                // reason; the suffix has to be treated the same way.
                let allocation_end = if suffix_created { alloc_end } else { block_end };

                // Mark the allocated block as used
                // A sub-minimum prefix (smaller than MIN_FREE_BLOCK) is too
                // small to be inserted as a free block.  Absorb it into the
                // allocated block by placing the block header at the free
                // block start, so the gap is reclaimed on free instead of
                // being orphaned forever.  A forwarding pointer to that start
                // is stored in the padding slot at `alloc_header_start` so
                // deallocate_locked can locate the real header.
                let (alloc_start, allocated_size) = if prefix_created {
                    block_set_size(candidate, prefix_size);
                    block_clear_used(candidate);
                    insert_free_block(state, candidate);

                    let allocated_size = allocation_end.wrapping_sub(alloc_header_start);
                    block_set_size(alloc_header_start, allocated_size);
                    block_set_used(alloc_header_start);
                    (alloc_header_start, allocated_size)
                } else if prefix_size > 0 {
                    let allocated_size = allocation_end.wrapping_sub(candidate);
                    block_set_size(candidate, allocated_size);
                    block_set_used(candidate);
                    // Already inside the enclosing `unsafe` block above.
                    core::ptr::write(alloc_header_start as *mut usize, candidate);
                    (candidate, allocated_size)
                } else {
                    let allocated_size = allocation_end.wrapping_sub(alloc_header_start);
                    block_set_size(alloc_header_start, allocated_size);
                    block_set_used(alloc_header_start);
                    (alloc_header_start, allocated_size)
                };

                // Suffix (after the allocation)
                if suffix_created {
                    block_set_size(alloc_end, suffix_size);
                    block_clear_used(alloc_end);
                    block_set_prev_phys(alloc_end, alloc_start);
                    insert_free_block(state, alloc_end);
                }

                // Fix up prev_phys chain
                if prefix_created {
                    block_set_prev_phys(alloc_header_start, candidate);
                }
                if suffix_created {
                    block_set_prev_phys_of_next(alloc_end, alloc_end);
                } else if block_end < state.end {
                    // No suffix: the allocation now runs to the end of the
                    // free block it was carved from, so the block after it has
                    // a new physical predecessor.  Leaving the old value in
                    // place is invisible whenever `alloc_start` happens to
                    // equal the free block's original start, which is every
                    // case without a prefix, but as soon as a prefix is
                    // created the successor still points at the pre-split
                    // start, and the next full walk reports a defect far from
                    // the operation that caused it.
                    block_set_prev_phys(block_end, alloc_start);
                }

                // Canary
                // Written once the block's extent is final.  The request was
                // inflated by `CANARY_SIZE` when the block was carved, so this
                // word sits after the caller's bytes and the first thing an
                // overrun meets is the canary rather than the next block's
                // header.
                super::tlsf::canary_write(alloc_start);

                // Accounting: only the bytes that become unavailable are
                // removed.  The allocated block (which may include an absorbed
                // alignment prefix) is subtracted here and added back on free;
                // re-inserted prefix/suffix free blocks are not double-counted.
                state.available = state.available.saturating_sub(allocated_size);

                profiler.add_heap_bytes_allocated(allocated_size as u64);
                #[cfg(feature = "heap_audit")]
                super::tlsf::audit_after_operation(state, "allocate");
                break 'search payload_start as *mut u8;
            }
        }
    }

    /// Deallocate a block previously returned by [`allocate_locked`].
    ///
    /// Coalesces the freed block with its physical neighbours and
    /// inserts the result into the appropriate free list.
    ///
    /// Returns `true` if the block was successfully freed, `false` if
    /// `ptr` is null, outside the heap, or already free (double-free).
    ///
    /// # Parameters
    ///
    /// * `state`, mutable reference to the allocator state.
    /// * `ptr`, pointer to the payload (must have been returned by a prior call
    ///   to [`allocate_locked`]).
    /// * `profiler`, profiler for tracking freed byte counts.
    pub(crate) fn deallocate_locked(
        state: &mut AllocatorState,
        ptr: *mut u8,
        profiler: &AllocProfiler,
    ) -> bool {
        if ptr.is_null() {
            return false;
        }

        let payload_start = ptr as usize;
        let nominal = match payload_start.checked_sub(HEADER_SIZE) {
            Some(addr) => addr,
            None => return false,
        };

        // A block whose allocation absorbed a sub-minimum (16-byte) alignment
        // prefix keeps its true header at the free-block start, one
        // HEAP_BLOCK_ALIGNMENT below `nominal`, and stores a forwarding
        // pointer to that start in the padding slot at `nominal`.  A used
        // block's size word at `nominal` is always odd (bit 0 is the used
        // flag), so a 16-aligned value there unambiguously marks a forwarded
        // block.
        let header_start = if nominal >= state.start && nominal < state.end {
            // SAFETY: `nominal` was clamped into the heap above, and its first
            // word is either the block's size (odd, because the used flag is
            // set) or the forwarding pointer this allocator writes for an
            // absorbed alignment prefix, both are words the allocator put
            // there.
            let fwd = unsafe { *(nominal as *const usize) };
            if fwd >= state.start
                && fwd < nominal
                && fwd.is_multiple_of(HEAP_BLOCK_ALIGNMENT)
                && nominal == fwd.wrapping_add(HEAP_BLOCK_ALIGNMENT)
            {
                // SAFETY: the forwarding pointer was just validated: inside the
                // heap, 16-byte aligned, below `nominal`, and exactly one
                // alignment unit below it.
                let size = unsafe { block_size(fwd) };
                let end = fwd.wrapping_add(size);
                // SAFETY: the same validated block; the checks below confirm it
                // covers the payload before it is trusted.
                if unsafe { block_is_used(fwd) }
                    && size >= HEADER_SIZE
                    && fwd <= payload_start
                    && payload_start < end
                    && end <= state.end
                {
                    fwd
                } else {
                    nominal
                }
            } else {
                nominal
            }
        } else {
            nominal
        };

        if !(state.start..state.end).contains(&header_start) {
            return false;
        }

        // SAFETY: `header_start` was bounds-checked against the heap above, and
        // it either came from the validation above or is `nominal` itself.
        let size = unsafe { block_size(header_start) };
        if size == 0 || size < HEADER_SIZE {
            return false;
        }
        // SAFETY: the same block, whose size is non-zero and at least a header,
        // so its size word is a block header's.
        if !unsafe { block_is_used(header_start) } {
            // Already free, double‑free is a no‑op.
            return false;
        }

        // The canary is checked here, while the block is still intact and
        // still identifiable as this allocation: the address reported points at
        // the allocation that overran rather than at whichever free-list walk
        // later stumbled over the damage.
        // SAFETY: the canary is inside the block, the check refuses a block
        // too small to hold one, and it is read while the block is still
        // marked used, before a free-list walk could trip over an overrun.
        if let Err(defect) = unsafe { super::tlsf::canary_check(header_start) } {
            // SAFETY: this is the damage path and the heap is suspect; the
            // report walks the lists under the same lock, before anything is
            // modified, which is what makes the walk worth doing there.
            unsafe {
                super::tlsf::report_heap_damage(state, "deallocate");
            }
            panic!(
                "heap canary: block 0x{:x} was overrun ({})",
                defect.address, defect.reason
            );
        }

        state.available = state.available.saturating_add(size);

        // Mark the block as free.
        // SAFETY: the block was identified as an in-use block above; clearing
        // its flag is the one edit that turns it back into free heap.
        unsafe {
            block_clear_used(header_start);
        }

        // Coalesce with physical neighbours, then insert.
        // SAFETY: the block is free now and its header says how far it extends;
        // the neighbours it may merge with are validated inside `coalesce`.
        let block = unsafe { coalesce(state, header_start) };

        // SAFETY: the block returned by coalescing is a free block with a valid
        // header, and the insert links it into the free lists it belongs on.
        unsafe {
            insert_free_block(state, block);
        }

        profiler.add_heap_bytes_freed(size as u64);
        #[cfg(feature = "heap_audit")]
        unsafe {
            super::tlsf::audit_after_operation(state, "deallocate");
        }
        true
    }

    /// Return the `(start, end)` physical addresses of the kernel heap.
    pub fn bounds(&self) -> (usize, usize) {
        self.with_state(|state| (state.start, state.end))
    }

    /// Return the number of free bytes remaining in the kernel heap.
    pub fn remaining(&self) -> usize {
        self.with_state(|state| state.available)
    }

    /// Debug-only: walk all free lists and verify every block is well-formed.
    /// Panics with diagnostic information on the first invalid block found.
    #[cfg(debug_assertions)]
    pub fn verify_heap_integrity(&self) {
        // SAFETY: the walk runs inside `with_state`, so it holds the
        // allocator's lock and the lists it reads cannot change underneath it.
        self.with_state(|state| unsafe {
            // Both structures, because either can be wrong while the other is
            // right, and a checker that reads one reports a clean heap for a
            // heap whose other structure names a block somebody owns.
            if let Err(defect) = check_invariants(state) {
                crate::diag::write(format_args!(
                    "[heap  ] {} at 0x{:x}",
                    defect.reason, defect.address
                ));
                panic!("verify_kernel_heap: {:?}", defect);
            }
            scan_free_lists(state);
        });
    }

    #[cfg(not(debug_assertions))]
    pub fn verify_heap_integrity(&self) {}
}

// GlobalAlloc impl

// SAFETY: the `GlobalAlloc` methods take `&self` and reach the state only
// through `with_state`, which holds the heap's lock for the duration of each
// call.  The handle is zero-sized, so every handle reaches the same lists.
unsafe impl GlobalAlloc for KernelGlobalAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        self.with_state(|state| {
            let result = Self::allocate_locked(state, layout, &PROFILER);
            if !result.is_null() {
                // Recorded inside the allocator's critical section, so the
                // trace is ordered with respect to the heap changes it
                // describes.
                super::tlsf::record_heap_trace(super::tlsf::TRACE_ALLOC, result as usize);
                PROFILER.inc_heap_allocs();
            }
            result
        })
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        self.with_state(|state| {
            // Recorded before the free, so a pointer freed twice shows up as
            // two adjacent entries instead of being hidden by the corruption
            // the second free causes.
            super::tlsf::record_heap_trace(super::tlsf::TRACE_DEALLOC, ptr as usize);
            if Self::deallocate_locked(state, ptr, &PROFILER) {
                PROFILER.inc_heap_frees();
            }
        });
    }
}
