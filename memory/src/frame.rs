//! memory/src/frame.rs
//!
//! Physical frame allocator with free-range tracking, reuse, and coalescing.
//!
//! The first version tracked free ranges in a `BTreeMap`.  That is the right
//! shape for an unbounded set and the wrong one here for a reason that is not
//! about speed: **this allocator hands out the frames a page table is built
//! from, and a page table has to exist before the heap does.**  A free list
//! that needed `alloc` could not run at the moment it is most needed, and the
//! way that surfaced was the kernel working around it, building its tables in
//! a `static` array instead, with a fixed bound nobody had justified.
//!
//! The second version was a sorted array of a fixed number of ranges.  It
//! dropped `alloc` and it **broke a test that existed to say why the map was
//! there**: freeing every other frame of a hundred and forty leaves seventy
//! separate holes, and a `deallocate` with nowhere to put one returns `false`
//! and loses the frame.  A free list that drops memory under fragmentation is
//! worse than one that cannot be built.
//!
//! One bit per frame is the shape that is both fixed-size and unbounded in
//! fragmentation.  The bitmap is `MAX_FRAMES / 8` bytes, sixteen kilobytes for
//! the 512 MiB pool, and it lives in a `static`, so it needs no heap and no
//! caller-supplied storage.
//!
//! Beside the bitmap sit two arrays with the same shape: one byte per frame
//! counting the address spaces that own it, and one bit per frame saying the
//! frame was demoted for copy-on-write.  Both exist for the same reason the
//! bitmap does, a fork that shares a frame needs a fact the allocator holds
//! rather than one each owner re-derives, and a count kept anywhere else is a
//! second record of the same fact, and the first thing to diverge.

use profiler::AllocProfiler;

pub const FRAME_SIZE: usize = 4096;

/// The most frames this allocator can manage.
///
/// The pool is a linker-reserved span, and the machine's answer is clamped to
/// it.  512 MiB is what every linker script reserves, so this is that span in
/// frames, a ceiling, and one the bitmap is sized from.
pub const MAX_FRAMES: usize = 512 * 1024 * 1024 / FRAME_SIZE;

/// The bitmap is one bit per frame: 16 KiB for [`MAX_FRAMES`].
const BITMAP_WORDS: usize = MAX_FRAMES / 64;

/// The host build's pool backing store, in bytes.
///
/// On a machine the pool's span is the linker's (`POOL_SIZE` in each linker
/// script, between `__pool_start` and `__pool_end`) and nothing is loaded
/// there; this constant is what a host build, the unit tests, backs its
/// span with, because the host has no linker script and its allocator needs
/// real memory to hand out.
#[cfg(not(target_os = "none"))]
const HOST_POOL_SIZE: usize = 512 * 1024 * 1024;

/// The pool's bounds on this machine.
///
/// On a machine this is **reserved address space** rather than storage: the
/// linker script places the span after the kernel's BSS, nothing is loaded
/// there, no boot clears it, and the allocator makes a frame zero when it
/// hands one out, the guarantee that is actually needed.  It used to be a
/// 512 MiB array in `.bss` that the boot cleared, and that clear ran past the
/// end of RAM on a small machine: measured, a 528 MiB machine printed
/// **nothing at all**, where 640 MiB booted, because that is where the last
/// store of the clear landed inside RAM.
///
/// The span is also a *ceiling*: the manager hands the allocator the machine's
/// answer, clamped to this, so a machine whose RAM ends inside the span
/// manages only the frames that are really there
/// (`arch::managed_pool_bytes` on the machine that has one).
#[cfg(target_os = "none")]
fn pool_bounds() -> (usize, usize) {
    // SAFETY: the two symbols are the linker script's own markers around the
    // pool's span; neither is called, and this block only takes their
    // addresses.
    unsafe extern "C" {
        static __pool_start: u8;
        static __pool_end: u8;
    }
    // The addresses of the linker's own symbols that bracket the span; neither
    // is dereferenced here, and taking one is safe.
    (
        core::ptr::addr_of!(__pool_start) as usize,
        core::ptr::addr_of!(__pool_end) as usize,
    )
}

/// A host build's pool: the same shape, backed by a real array.
#[cfg(not(target_os = "none"))]
fn pool_bounds() -> (usize, usize) {
    use cell::SyncUnsafeCell;

    #[repr(C, align(4096))]
    struct PhysicalPool([u8; HOST_POOL_SIZE]);

    static PHYSICAL_POOL: SyncUnsafeCell<PhysicalPool> =
        SyncUnsafeCell::new(PhysicalPool([0; HOST_POOL_SIZE]));

    let base = PHYSICAL_POOL.get() as *mut u8 as usize;
    (base, base + HOST_POOL_SIZE)
}

/// The address range of the pool: where the kernel's memory is.
///
/// A frame's address is its physical address, and the pool is the memory the
/// allocator manages, so this is the range a boot checks against the map a
/// machine described.
pub fn pool_range() -> (usize, usize) {
    pool_bounds()
}

/// The pool's span, in bytes, read from the span itself rather than written
/// down a second time, so the linker's reservation is the one source of the
/// number on a machine.
pub fn physical_pool_size() -> usize {
    let (start, end) = pool_bounds();
    end.saturating_sub(start)
}

/// The mapping hook a pool starts with: frames are already writable.
///
/// A test's frames are memory the test owns, and a kernel installs its own hook
/// before handing the allocator a real pool.  Doing nothing is the right
/// default precisely because it is wrong for a machine, a boot that forgot to
/// install the real one fails on the first write to a frame it thought it had
/// mapped, which is louder than a silently skipped repair.
fn no_mapping_needed(_address: usize, _byte_len: usize) {}

pub struct FrameAllocator {
    // `next_frame` is the bump-allocation high-water mark; anything below it is
    // either live or has its bit set in `free`.
    base: usize,
    total_frames: usize,
    next_frame: usize,
    /// One bit per frame below `next_frame`: **set means free**.
    ///
    /// Inline rather than behind a pointer: a `static` shared by every
    /// instance would make two allocators in one test decide against each
    /// other's bits, and the tests create one per case.  Sixteen kilobytes is
    /// the cost, paid once by the kernel and once per test, and a test thread
    /// has megabytes of stack.
    ///
    /// "Free" is the set state because the common operation is "is this frame
    /// available", and a cleared word is then the common case for a full pool.
    free: [u64; BITMAP_WORDS],
    /// Per frame, how many owners share it **beyond the first**.
    ///
    /// One byte per frame, 128 KiB for [`MAX_FRAMES`], the same trade the free
    /// bitmap made: fixed-size, no heap, indexed by the frame's own position in
    /// the pool.  Zero is the ordinary state of every frame the pool hands out
    ///, one owner, untracked, and a fork that shares a frame raises it to one
    /// per additional address space.
    ///
    /// The count is the co-owners and not the total on purpose, because the
    /// callers this allocator already has deallocate **without** ever sharing:
    /// a page table's root, the self-check's frame, every frame a test takes
    /// and gives back.  Counting those would make every existing
    /// `allocate`-then-`deallocate` a refusal.  What the count buys instead is
    /// the release protocol: an owner that shares asks
    /// [`Self::release_reference`] and returns the frame only when that answers
    /// `true`, and [`Self::deallocate`] refuses a frame whose co-owner count is
    /// above zero, which is the one shape of a premature free the count can
    /// see. The shape it cannot see, a free after the co-owner released but
    /// before the first owner did, is not reachable by any caller here,
    /// because the only ones that free a shared frame go through the protocol.
    refs: [u8; MAX_FRAMES],
    /// Per frame, one bit: set means the frame is **demoted for
    /// copy-on-write**.
    ///
    /// A demoted frame is one whose owners were given read-only mappings and
    /// will be copied on the first write.  The bit is not derivable from the
    /// count, a fork shares read-only image pages too, and those have the same
    /// count with no demotion, so it is its own bit rather than a value
    /// smuggled into `refs`.
    cow: [u64; BITMAP_WORDS],
    /// Frame allocator profiler (zero-cost when `alloc_profiler` feature is
    /// disabled).
    pub profiler: AllocProfiler,
    /// What makes a range of physical frames safe to write through.
    ///
    /// The allocator cannot do this for itself (it has no page table and should
    /// not have one) and cannot skip it (a frame handed out has to be writable
    /// before the caller zeros or reads it).  Calling a machine function from
    /// this data structure would be the one line that made this file impossible
    /// to build without a page table, and therefore impossible to test on a
    /// host.
    ///
    /// So the machine supplies the answer once, at [`Self::set_map_hook`], and
    /// the default is a no-op for a test, where frames are ordinary memory and
    /// nothing needs mapping.
    map_hook: fn(usize, usize),
}

impl Default for FrameAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameAllocator {
    pub const fn new() -> Self {
        Self {
            base: 0,
            total_frames: 0,
            next_frame: 0,
            free: [0; BITMAP_WORDS],
            refs: [0; MAX_FRAMES],
            cow: [0; BITMAP_WORDS],
            profiler: AllocProfiler::new(),
            map_hook: no_mapping_needed,
        }
    }

    /// Install the function that makes a frame range writable.
    ///
    /// Called once by the kernel after its page tables exist.  A host test does
    /// not call it: the default treats every frame as already writable, which
    /// is true of a `Vec`-backed pool and false of a machine whose pages are
    /// unmapped after a shootdown, which is exactly why the machine has to
    /// say so rather than this crate guessing.
    pub fn set_map_hook(&mut self, hook: fn(usize, usize)) {
        self.map_hook = hook;
    }

    pub fn init(&mut self, total_size: usize) {
        let (pool_base, pool_end) = pool_bounds();
        self.base = pool_base;
        // Clamp callers to the pool's own span and ignore any tail smaller
        // than one frame so raw byte counts remain acceptable.  The span is a
        // ceiling, and a machine whose RAM ends before it manages less: the
        // caller passes the machine's answer, and the pool's end is only
        // reached when the machine really has that much.
        let pool_size = pool_end.saturating_sub(pool_base);
        self.total_frames = total_size.min(pool_size) / FRAME_SIZE;
        self.next_frame = 0;
        self.clear_free();
    }

    /// Configure this allocator to manage a sub-range of the physical pool.
    ///
    /// `start_frame` and `end_frame` are frame indices relative to the start of
    /// the physical pool.  The range is `[start_frame, end_frame)`.
    /// `node_id` is stored for diagnostic / profiling use.
    pub fn set_node_range(&mut self, node_id: u8, start_frame: usize, end_frame: usize) {
        let (pool_base, _) = pool_bounds();
        self.base = pool_base + start_frame * FRAME_SIZE;
        self.total_frames = end_frame.saturating_sub(start_frame);
        self.next_frame = 0;
        self.clear_free();
        let _ = node_id; // Reserved for future per-node profiling.
    }

    pub fn allocate(&mut self, count: usize) -> Option<*mut u8> {
        if self.base == 0 || count == 0 {
            return None;
        }

        // Reuse holes first so long-lived churn does not force the bump tail
        // forward.
        if let Some(frame_start) = self.find_free_run(count) {
            // A hole is available until it is taken: the bit is what says so,
            // and a recycled range that did not clear it would be handed out a
            // second time.
            for frame in frame_start..frame_start + count {
                self.set_used(frame);
            }
            self.reset_references(frame_start, count);
            let address = self.frame_address(frame_start)?;
            let zero_bytes = (count * FRAME_SIZE) as u64;
            self.zero_frame_range(frame_start, count)?;
            self.profiler.inc_frame_allocs();
            self.profiler.inc_frame_recycled();
            self.profiler.add_frame_zero_bytes(zero_bytes);
            return Some(address as *mut u8);
        }

        let frame_start = self.next_frame;
        let end_frame = frame_start.checked_add(count)?;
        if end_frame > self.total_frames {
            return None;
        }

        let address = self.frame_address(frame_start)?;
        self.next_frame = end_frame;
        self.reset_references(frame_start, count);
        let zero_bytes = (count * FRAME_SIZE) as u64;
        self.zero_frame_range(frame_start, count)?;
        self.profiler.inc_frame_allocs();
        self.profiler.inc_frame_bump_allocs();
        self.profiler.add_frame_zero_bytes(zero_bytes);
        Some(address as *mut u8)
    }

    /// Return the total number of physical frames managed by this allocator.
    pub fn total_frames(&self) -> usize {
        self.total_frames
    }

    /// Return the number of currently free/allocation frames.
    ///
    /// This is the bump tail (`next_frame`) minus allocated frames currently
    /// tracked as live.  Free ranges (holes returned via deallocate) are
    /// included because the bump tail already covers past them.
    pub fn available_frames(&self) -> usize {
        self.total_frames.saturating_sub(self.next_frame)
    }

    pub fn deallocate(&mut self, ptr: *mut u8, count: usize) -> bool {
        if self.base == 0 || ptr.is_null() || count == 0 {
            return false;
        }

        let address = ptr as usize;
        if address < self.base {
            return false;
        }

        let offset = address - self.base;
        // The allocator only speaks in whole frames; partial-frame frees would
        // corrupt the free list.
        if !offset.is_multiple_of(FRAME_SIZE) {
            return false;
        }

        let start_frame = offset / FRAME_SIZE;
        let end_frame = match start_frame.checked_add(count) {
            Some(end) => end,
            None => return false,
        };

        if end_frame > self.total_frames || end_frame > self.next_frame {
            return false;
        }

        // A double free is the caller's bug and a corruption if believed: the
        // frames would be handed out twice and two owners would write to one.
        // A frame with co-owners is the same corruption wearing a different
        // coat, one owner freeing while another still maps it, and it is
        // refused here rather than at the page table, where the symptom would
        // be a fault in whichever program kept the page.
        for frame in start_frame..end_frame {
            if self.is_free(frame) {
                return false;
            }
            if self.refs[frame] != 0 {
                return false;
            }
        }
        for frame in start_frame..end_frame {
            self.set_free(frame);
            self.refs[frame] = 0;
            self.clear_cow_bit(frame);
        }

        self.rewind_tail_high_water_mark();
        self.profiler.inc_frame_frees();
        true
    }

    /// Record that one more owner shares `frame`, answering whether it did.
    ///
    /// The caller is a fork that has decided two address spaces will map one
    /// frame; the count is what turns that decision into a fact the allocator
    /// can police.  `false` means the frame is outside the pool or the count
    /// ran out, a fork that adds a reference to a frame nobody allocated would
    /// otherwise be a share of nothing, and the pool would learn of it only as
    /// a double free much later.
    pub fn add_reference(&mut self, frame: usize) -> bool {
        let Some(index) = self.frame_index(frame) else {
            return false;
        };
        // Saturation is a refusal and not a wrap: a count that wrapped would
        // hand a frame back while owners still held it, which is the corruption
        // `deallocate` exists to refuse.
        if self.refs[index] == u8::MAX {
            return false;
        }
        self.refs[index] += 1;
        true
    }

    /// One owner of `frame` lets go, answering whether it was the last.
    ///
    /// `true` means the caller must return the frame to the pool; `false`
    /// means another owner still maps it and the frame stays, and **must**:
    /// the caller that frees on a `false` is the double free the protocol
    /// exists to prevent.  A frame whose count is zero was never shared, so
    /// the sole owner leaving is the last owner leaving, which is why the
    /// count reads zero both for "never shared" and for "the last co-owner
    /// went": from the point of view of whoever holds the frame, the two are
    /// the same state, one holder and no co-owners.
    pub fn release_reference(&mut self, frame: usize) -> bool {
        let Some(index) = self.frame_index(frame) else {
            return false;
        };
        if self.refs[index] == 0 {
            return true;
        }
        self.refs[index] -= 1;
        false
    }

    /// How many owners share `frame` beyond the first, which is the question
    /// a copy-on-write fault asks: a count above zero means a copy, zero means
    /// the faulting owner may have the frame outright.
    ///
    /// Zero also answers for a frame outside this pool, which is the right
    /// answer there too: a frame the pool does not manage has no co-owners to
    /// copy away from, and the fault handler's other checks, the walk, the
    /// demotion bit, refuse it long before the count decides.
    pub fn co_owners(&self, frame: usize) -> usize {
        match self.frame_index(frame) {
            Some(index) => self.refs[index] as usize,
            None => 0,
        }
    }

    /// Mark whether `frame` is demoted for copy-on-write.
    ///
    /// A fork sets this on every writable page it shares, at the same moment
    /// it demotes both mappings to read-only.  The pair is one fact in two
    /// places, and the fault handler reads the bit to tell a page a fork
    /// demoted from one that was mapped read-only to begin with, the first
    /// wants a copy, the second wants the program to stop writing its own
    /// code.
    pub fn set_cow(&mut self, frame: usize, demoted: bool) {
        let Some(index) = self.frame_index(frame) else {
            return;
        };
        if demoted {
            self.cow[index / 64] |= 1 << (index % 64);
        } else {
            self.cow[index / 64] &= !(1 << (index % 64));
        }
    }

    /// Whether `frame` is demoted for copy-on-write.
    pub fn is_cow(&self, frame: usize) -> bool {
        match self.frame_index(frame) {
            Some(index) => self.cow[index / 64] & (1 << (index % 64)) != 0,
            None => false,
        }
    }

    /// Shrink the high-water mark past frames that are free.
    ///
    /// The bump tail is only ever a high-water mark, so a free frame at the top
    /// is one the next bump allocation would have to step over: pulling the
    /// mark down makes it available without a search.
    fn rewind_tail_high_water_mark(&mut self) {
        while self.next_frame > 0 && self.is_free(self.next_frame - 1) {
            self.next_frame -= 1;
            self.set_used(self.next_frame);
        }
    }

    fn frame_address(&self, frame_start: usize) -> Option<usize> {
        self.base.checked_add(frame_start.checked_mul(FRAME_SIZE)?)
    }

    /// Return the number of frames in the largest contiguous free region.
    ///
    /// This includes the untracked bump tail: every frame at or above
    /// `next_frame` is free and contiguous, so a fully-compacted pool
    /// reports its whole tail here.  A value of `0` means the pool is fully
    /// allocated.
    pub fn largest_free_contiguous_frames(&self) -> usize {
        let tail_free = self.total_frames.saturating_sub(self.next_frame);
        // The largest free run, which the tail is when nothing is fragmented.
        self.largest_free_run().max(tail_free)
    }

    /// Number of distinct free ranges, a fragmentation metric.  Fragmented
    /// pools have many small ranges; a compacted pool has at most one.
    ///
    /// A run is a maximal sequence of free frames, which is what the ranges in
    /// a map or an array were.  Counting transitions over the bitmap is the
    /// same number and needs no stored list.
    pub fn free_range_count(&self) -> usize {
        let limit = self.next_frame.min(MAX_FRAMES);
        let mut runs = 0;
        let mut previously_free = false;
        for index in 0..limit {
            let free = self.is_free(index);
            if free && !previously_free {
                runs += 1;
            }
            previously_free = free;
        }
        runs
    }

    /// The length of the longest run of free frames.
    fn largest_free_run(&self) -> usize {
        let limit = self.next_frame.min(MAX_FRAMES);
        let mut best = 0;
        let mut current = 0;
        for index in 0..limit {
            if self.is_free(index) {
                current += 1;
                best = best.max(current);
            } else {
                current = 0;
            }
        }
        best
    }

    /// How many frames are free below the high-water mark.
    pub fn free_frames(&self) -> usize {
        let limit = self.next_frame.min(MAX_FRAMES);
        let mut total = 0;
        for index in 0..limit {
            if self.is_free(index) {
                total += 1;
            }
        }
        total
    }

    /// Compact the physical pool by moving live frames down into holes,
    /// consolidating all free space into a single contiguous block at the
    /// tail.
    ///
    /// `fixup` is invoked as `(old_address, new_address)` for each live frame
    /// that is relocated, *before* its contents are copied; it must update
    /// any external references (page-table mappings) to the frame's new
    /// address and return `true`.  When it returns `false` the frame is left
    /// in place and compaction stops, unmovable frames act as barriers.  Any
    /// frames already moved before the barrier are preserved.
    ///
    /// Returns the number of frames successfully moved.
    ///
    /// The first version of this method allocated a `Vec` the size of the pool,
    /// which is the thing this file spent a change removing.  The second took
    /// one from its caller, which moved the problem instead of solving it.  The
    /// allocator already holds one bit per frame, so compaction works against a
    /// copy of the bits it has, sixteen kilobytes on the stack of the one
    /// caller that compacts, and no allocation anywhere.
    pub fn compact<F>(&mut self, mut fixup: F) -> usize
    where
        F: FnMut(usize, usize) -> bool,
    {
        let n = self.next_frame.min(MAX_FRAMES);
        // A local copy rather than mutating `self.free` in place: an early stop
        // at an unmovable frame leaves the bits past it meaningful, and the
        // rebuild below has to start from what was true on entry.
        let mut bits = self.free;

        let mut moved = 0usize;
        let mut fill = 0usize;
        let mut f = 0usize;
        while f < n {
            if bits[f / 64] & (1 << (f % 64)) != 0 {
                f += 1;
                continue;
            }
            if fill < f {
                // Invariant: position `fill` is free, every position below
                // `fill` has been finalized live, and everything in
                // [`fill`, `f`) is a hole or a vacated source.
                let (Some(old_addr), Some(new_addr)) =
                    (self.frame_address(f), self.frame_address(fill))
                else {
                    break;
                };
                if !fixup(old_addr, new_addr) {
                    // Unmovable frame, everything below it is now final.
                    break;
                }
                // SAFETY: both frames come from this allocator's pool in the
                // same pass, `f` is the live frame being moved and `fill` a
                // hole the invariant above says is free and below it, so the
                // two ranges are distinct and inside the pool.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        old_addr as *const u8,
                        new_addr as *mut u8,
                        FRAME_SIZE,
                    );
                }
                bits[fill / 64] &= !(1 << (fill % 64));
                bits[f / 64] |= 1 << (f % 64);
                // The sharing state travels with the frame, not with its
                // address: `fixup` has just repointed the page tables at the
                // new address, so the owners that remain follow, and the
                // vacated position reads as a sole-owner frame the next time
                // the pool hands it out.
                self.refs[fill] = self.refs[f];
                self.refs[f] = 0;
                let demoted = self.cow[f / 64] & (1 << (f % 64)) != 0;
                if demoted {
                    self.cow[fill / 64] |= 1 << (fill % 64);
                } else {
                    self.cow[fill / 64] &= !(1 << (fill % 64));
                }
                self.cow[f / 64] &= !(1 << (f % 64));
                moved += 1;
            }
            fill += 1;
            f += 1;
        }

        // The bits are the free list: publishing them is the rebuild.
        self.free = bits;
        moved
    }

    fn zero_frame_range(&self, frame_start: usize, count: usize) -> Option<()> {
        let address = self.frame_address(frame_start)?;
        let byte_len = count.checked_mul(FRAME_SIZE)?;
        // A frame the allocator hands out has to be writable, and this is the
        // first access to one after it comes back.  Repair the mapping at the
        // one place every allocation passes through, instead of asking each
        // subsystem that un-maps a page to remember to undo it before freeing
        // the frames.
        (self.map_hook)(address, byte_len);
        // SAFETY: the range was just made identity-mapped by the call above,
        // which is what makes a write through the physical address reach the
        // frames; the length is `count` frames and cannot overflow
        // (`checked_mul`).
        unsafe {
            core::ptr::write_bytes(address as *mut u8, 0, byte_len);
        }
        Some(())
    }

    fn is_free(&self, index: usize) -> bool {
        index < self.total_frames && self.free[index / 64] & (1 << (index % 64)) != 0
    }

    fn set_free(&mut self, index: usize) {
        if index < MAX_FRAMES {
            self.free[index / 64] |= 1 << (index % 64);
        }
    }

    fn set_used(&mut self, index: usize) {
        if index < MAX_FRAMES {
            self.free[index / 64] &= !(1 << (index % 64));
        }
    }

    /// The pool position of a frame **address**, or `None` when the address is
    /// not one this allocator manages.
    ///
    /// The refcount API speaks in addresses because its callers do, a page
    /// table names frames, not indices, and this is the one place the two
    /// vocabularies meet.  Unaligned or out-of-span addresses answer `None`
    /// rather than indexing a neighbour, which is what a truncating division
    /// would do.
    fn frame_index(&self, frame: usize) -> Option<usize> {
        if self.base == 0 || frame < self.base {
            return None;
        }
        let offset = frame.checked_sub(self.base)?;
        if !offset.is_multiple_of(FRAME_SIZE) {
            return None;
        }
        let index = offset / FRAME_SIZE;
        (index < self.total_frames).then_some(index)
    }

    /// Forget everything sharing says about a range the allocator is handing
    /// out: a frame that comes back has one owner, the one taking it now,
    /// untracked, and is not demoted.
    ///
    /// Both allocation paths call this, the recycled holes and the bump tail
    /// because a reset done on one path only is a stale co-owner count on the
    /// other, and the symptom is a fork that trusts a count a previous owner
    /// left behind.
    fn reset_references(&mut self, frame_start: usize, count: usize) {
        for frame in frame_start..frame_start + count {
            if frame < MAX_FRAMES {
                self.refs[frame] = 0;
                self.clear_cow_bit(frame);
            }
        }
    }

    fn clear_cow_bit(&mut self, index: usize) {
        if index < MAX_FRAMES {
            self.cow[index / 64] &= !(1 << (index % 64));
        }
    }

    /// Clear every bit, which is "every frame used".
    fn clear_free(&mut self) {
        self.free = [0; BITMAP_WORDS];
    }

    /// The first run of `count` free frames, if there is one.
    ///
    /// A first-fit scan from the lowest address, which is the answer the
    /// ordered map and then the sorted array gave: a caller that got the
    /// lowest-addressed hole before gets it now.  The scan starts at the
    /// bitmap's first word and skips a whole word at a time when it is clear,
    /// so a full pool costs one load per sixty-four frames.
    fn find_free_run(&self, count: usize) -> Option<usize> {
        if count == 0 {
            return None;
        }
        let limit = self.next_frame.min(MAX_FRAMES);
        let mut index = 0;
        while index < limit {
            if self.free[index / 64] == 0 {
                index = (index / 64 + 1) * 64;
                continue;
            }
            if !self.is_free(index) {
                index += 1;
                continue;
            }
            // Measure this run without committing to it.
            let run_start = index;
            let mut run = 0;
            while index < limit && self.is_free(index) && run < count {
                run += 1;
                index += 1;
            }
            if run == count {
                return Some(run_start);
            }
            if index == run_start {
                index += 1;
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    //! The tests for this module.
    //!
    //! The frame allocator: a bump tail, the free-list fusing a freed pair, and
    //! the high-water mark a rewind restores.
    //!
    //! Extracted from the module so a reader following the mechanism does not
    //! have to scroll past every case it satisfies; see `docs/fmts/testing.md`
    //! §1.

    use crate::frame::FRAME_SIZE;
    use crate::frame::FrameAllocator;
    use crate::frame::physical_pool_size;
    use alloc::vec::Vec;

    /// The free list survives fragmentation far past any fixed bound.
    ///
    /// This is the test that decided the representation.  A sorted array of
    /// ranges dropped `alloc` and lost frames: seventy interleaved single-frame
    /// holes do not fit in eight nodes, and `deallocate` answered `false` and
    /// dropped the frame.  A bitmap has one bit per frame, so the number of
    /// holes is the pool's size and not a constant somebody picked.
    ///
    /// The `is_some` on every allocation is the assertion that matters: a
    /// figure that merely counted free frames right would pass while the
    /// allocator had forgotten where they were.
    #[test]
    fn fragmentation_is_bounded_by_the_pool_and_not_by_a_constant() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 256);

        let mut frames = Vec::new();
        for _ in 0..200 {
            frames.push(allocator.allocate(1).expect("allocate frame"));
        }

        // Every other frame, which is the worst case: no two holes are adjacent
        // and none of them coalesce.
        for index in (0..frames.len()).step_by(2) {
            assert!(
                allocator.deallocate(frames[index], 1),
                "a deallocation that answers false loses the frame"
            );
        }
        assert_eq!(allocator.free_range_count(), 100);

        for _ in 0..100 {
            assert!(allocator.allocate(1).is_some(), "every hole is reusable");
        }
        assert_eq!(allocator.free_frames(), 0);
    }

    #[test]
    fn allocator_reuses_a_freed_frame_range() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 16);

        let first = allocator.allocate(1).expect("allocate first frame") as usize;
        let second = allocator.allocate(1).expect("allocate second frame") as usize;

        assert!(allocator.deallocate(first as *mut u8, 1));
        let recycled = allocator.allocate(1).expect("reuse freed frame") as usize;

        assert_eq!(recycled, first);
        assert_ne!(recycled, second);
    }

    #[test]
    fn allocator_coalesces_adjacent_freed_ranges() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 16);

        let head = allocator.allocate(3).expect("allocate head") as usize;
        let tail = allocator.allocate(3).expect("allocate tail") as usize;

        assert_eq!(tail, head + 3 * FRAME_SIZE);
        assert!(allocator.deallocate(head as *mut u8, 3));
        assert!(allocator.deallocate(tail as *mut u8, 3));

        let merged = allocator.allocate(6).expect("allocate merged range") as usize;
        assert_eq!(merged, head);
    }

    #[test]
    fn allocator_rejects_invalid_or_overlapping_deallocations() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 8);

        let first = allocator.allocate(2).expect("allocate test range");
        assert!(!allocator.deallocate(core::ptr::null_mut(), 1));
        assert!(!allocator.deallocate((first as usize + 1) as *mut u8, 1));
        assert!(!allocator.deallocate(first, 0));
        assert!(!allocator.deallocate((first as usize + 4 * FRAME_SIZE) as *mut u8, 1));

        assert!(allocator.deallocate(first, 2));
        assert!(!allocator.deallocate(first, 1));
    }

    #[test]
    fn allocator_rewinds_high_water_mark_after_tail_free() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 8);

        let _head = allocator.allocate(2).expect("allocate head range") as usize;
        let tail = allocator.allocate(2).expect("allocate tail range") as usize;

        assert!(allocator.deallocate(tail as *mut u8, 2));
        let rewound = allocator.allocate(4).expect("allocate after tail rewind") as usize;

        assert_eq!(rewound, tail);
    }

    #[test]
    fn allocator_zeroes_recycled_frames_before_reuse() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 8);

        let frame = allocator.allocate(1).expect("allocate test frame");
        // SAFETY: a frame this allocator just handed out, one `FRAME_SIZE`
        // long; the test fills it to prove the reuse path zeroes it.
        unsafe {
            core::ptr::write_bytes(frame, 0xA5, FRAME_SIZE);
        }

        assert!(allocator.deallocate(frame, 1));
        let recycled = allocator.allocate(1).expect("reallocate test frame");
        assert_eq!(recycled as usize, frame as usize);

        // SAFETY: as the fill above: the frame is the one the allocator
        // returned and the slice covers exactly it.
        let bytes = unsafe { core::slice::from_raw_parts(recycled as *const u8, FRAME_SIZE) };
        assert!(bytes.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn allocator_tracks_more_than_legacy_free_range_capacity() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 256);

        let mut frames = Vec::new();
        for _ in 0..140 {
            frames.push(allocator.allocate(1).expect("allocate frame"));
        }

        for index in (0..frames.len()).step_by(2) {
            assert!(allocator.deallocate(frames[index], 1));
        }

        for _ in 0..70 {
            assert!(allocator.allocate(1).is_some());
        }
    }

    #[test]
    fn allocator_init_clamps_capacity_to_backing_pool_size() {
        let mut allocator = FrameAllocator::new();
        allocator.init(physical_pool_size() + FRAME_SIZE * 8);

        let max_frames = physical_pool_size() / FRAME_SIZE;
        for _ in 0..max_frames {
            assert!(allocator.allocate(1).is_some());
        }
        assert!(allocator.allocate(1).is_none());
    }

    // compaction / defragmentation

    /// Helper: build a fragmented pool with `total` single frames, then free
    /// every even-indexed frame so the free ranges interleave with live
    /// frames.
    fn fragmented_pool(total: usize) -> (FrameAllocator, Vec<*mut u8>) {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * total);
        let mut frames = Vec::new();
        for _ in 0..total {
            frames.push(allocator.allocate(1).expect("allocate frame"));
        }
        for &frame in frames.iter().step_by(2) {
            assert!(allocator.deallocate(frame, 1));
        }
        (allocator, frames)
    }

    #[test]
    fn compact_consolidates_fragmented_free_ranges_into_one_block() {
        let (mut allocator, frames) = fragmented_pool(10);

        // Before: 5 interleaved single-frame holes.
        assert_eq!(allocator.free_range_count(), 5);
        assert_eq!(allocator.largest_free_contiguous_frames(), 1);

        // The bitmap is the caller's, because the allocator must work before
        // the heap and one bit per frame cannot live in its own struct.
        let moved = allocator.compact(|_, _| true);
        assert_eq!(moved, 5); // the 5 live frames moved into the 5 holes

        // After: a single contiguous 5-frame free block at the tail.
        assert_eq!(allocator.free_range_count(), 1);
        assert_eq!(allocator.largest_free_contiguous_frames(), 5);

        // The freed tail now satisfies a 5-frame allocation.
        assert!(allocator.allocate(5).is_some());
        // Keep `frames` alive for the duration of the test (borrow semantics).
        let _ = &frames;
    }

    #[test]
    fn compact_moves_contents_and_reports_address_pairs() {
        let (mut allocator, _frames) = fragmented_pool(6);
        // Fragmented: live at {1,3,5}, holes at {0,2,4}.
        let mut moves: Vec<(usize, usize)> = Vec::new();
        let moved = allocator.compact(|old_addr, new_addr| {
            moves.push((old_addr, new_addr));
            true
        });
        assert_eq!(moved, 3); // frames 1, 3, 5 move down into holes 0, 1, 2
        // Every move relocates a frame strictly downward.
        assert!(moves.iter().all(|(old, new)| old > new));
        assert_eq!(allocator.largest_free_contiguous_frames(), 3);
    }

    #[test]
    fn compact_preserves_content_of_moved_frames() {
        // Use a high sub-range of the shared backing pool (64 MiB in) so
        // parallel frame tests allocating from the front of the pool cannot
        // clobber the patterns written here.
        const BASE_FRAME: usize = 1 << 14;
        let mut allocator = FrameAllocator::new();
        allocator.set_node_range(0, BASE_FRAME, BASE_FRAME + 16);
        let mut frames = Vec::new();
        for _ in 0..16 {
            frames.push(allocator.allocate(1).expect("allocate frame"));
        }
        for &frame in frames.iter().step_by(2) {
            assert!(allocator.deallocate(frame, 1));
        }

        // Write a distinctive pattern into every frame so we can verify the
        // live frames' contents survive the move.  Frames 1, 3, .., 15 are
        // live (evens were freed); each holds value (index + 1).
        let base = allocator.base;
        for (i, &_frame) in frames.iter().enumerate() {
            // SAFETY: `base` is the pool's start and `i` indexes frames this
            // allocator handed out, so the range is inside the pool.
            unsafe {
                core::ptr::write_bytes(
                    (base + i * FRAME_SIZE) as *mut u8,
                    (i + 1) as u8,
                    FRAME_SIZE,
                );
            }
        }
        let moved = allocator.compact(|_, _| true);
        assert_eq!(moved, 8);

        // After compaction the live frames occupy slots 0..8, contents must
        // match the original frames 1, 3, .., 15 (values 2, 4, .., 16).
        let expected: Vec<u8> = (0..8).map(|k| ((k * 2) + 2) as u8).collect();
        for (slot, &value) in expected.iter().enumerate() {
            let frame_base = base + slot * FRAME_SIZE;
            // SAFETY: as above, for a frame the compaction left in place; the
            // slice covers one whole frame.
            let bytes = unsafe { core::slice::from_raw_parts(frame_base as *const u8, FRAME_SIZE) };
            assert!(
                bytes.iter().all(|&b| b == value),
                "compacted frame {slot} should hold original value {value}"
            );
        }
    }

    #[test]
    fn compact_stops_at_immovable_frame() {
        let (mut allocator, _frames) = fragmented_pool(6);
        // Refuse the very first move: nothing should be relocated and the
        // free ranges must stay untouched.
        let moved = allocator.compact(|_, _| false);
        assert_eq!(moved, 0);
        assert_eq!(allocator.free_range_count(), 3);
    }

    #[test]
    fn compact_is_idempotent_on_already_compacted_pool() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 8);
        let head = allocator.allocate(2).expect("allocate head");
        let tail = allocator.allocate(3).expect("allocate tail");
        assert!(allocator.deallocate(tail, 3));

        // Freeing the exact tail rewinds the high-water mark, so the whole
        // remaining pool is one contiguous free block above `next_frame`.
        assert_eq!(allocator.free_range_count(), 0);
        let moved = allocator.compact(|_, _| true);
        assert_eq!(moved, 0);
        assert_eq!(allocator.largest_free_contiguous_frames(), 6);
        // head/tail handles keep their allocations valid for this test scope.
        let _ = (head, tail);
    }

    // The reference counts: what a fork needs, and what a double free of a
    // shared frame looks like from inside the allocator.

    #[test]
    fn a_frame_starts_unshared_and_undemoted() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 4);

        let frame = allocator.allocate(1).expect("allocate frame") as usize;
        assert_eq!(allocator.co_owners(frame), 0);
        assert!(!allocator.is_cow(frame));
    }

    #[test]
    fn a_shared_frame_goes_back_only_through_its_release_protocol() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 4);

        let frame = allocator.allocate(1).expect("allocate frame") as usize;
        assert!(allocator.add_reference(frame), "the fork records its share");
        assert_eq!(allocator.co_owners(frame), 1);

        // The release protocol: a `false` means the caller keeps its hands off
        // the frame, because another owner still maps it.  The kernel's release
        // path is written as `if release_reference { deallocate }`, and this is
        // the sequence it runs against a fork's child going away first.
        assert!(!allocator.release_reference(frame), "one owner remains");

        assert!(allocator.release_reference(frame), "the last owner");
        assert!(allocator.deallocate(frame as *mut u8, 1));
        // The freed frame was the whole bump tail, so the rewind takes it back
        // into the available tail rather than into the holes: the count that
        // holds is the pool's whole size, not the hole count.
        assert_eq!(
            allocator.free_frames() + allocator.available_frames(),
            allocator.total_frames()
        );
    }

    #[test]
    fn deallocate_refuses_a_frame_with_co_owners_still_recorded() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 4);

        let frame = allocator.allocate(1).expect("allocate frame") as usize;
        assert!(allocator.add_reference(frame));

        // A direct free while the count is above zero is the premature free the
        // count can see, and refusing it costs the caller nothing: the frame is
        // still mapped by someone, so a `true` here would hand a live frame to
        // the next allocation.
        assert!(!allocator.deallocate(frame as *mut u8, 1));
        assert_eq!(allocator.free_frames(), 0);
    }

    #[test]
    fn an_unshared_frame_releases_in_one_step() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 4);

        let frame = allocator.allocate(1).expect("allocate frame") as usize;
        assert!(
            allocator.release_reference(frame),
            "no co-owner to wait for"
        );
        assert!(allocator.deallocate(frame as *mut u8, 1));
    }

    #[test]
    fn a_frame_the_pool_hands_out_again_carries_no_stale_owners() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 4);

        let frame = allocator.allocate(1).expect("allocate frame") as usize;
        assert!(allocator.add_reference(frame));
        allocator.set_cow(frame, true);
        assert!(!allocator.release_reference(frame), "one owner remains");
        assert!(allocator.release_reference(frame), "and now the last");
        assert!(allocator.deallocate(frame as *mut u8, 1));

        let recycled = allocator.allocate(1).expect("reuse the frame") as usize;
        assert_eq!(recycled, frame, "the hole is the first candidate");
        assert_eq!(allocator.co_owners(recycled), 0, "the count reset");
        assert!(!allocator.is_cow(recycled), "the demotion reset");
    }

    #[test]
    fn an_address_outside_the_pool_is_not_a_count() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 4);

        assert!(!allocator.add_reference(0xDEAD_0000), "not a frame here");
        assert!(!allocator.release_reference(0xDEAD_0000));
        assert_eq!(allocator.co_owners(0xDEAD_0000), 0, "no co-owners, either");
        assert!(!allocator.is_cow(0xDEAD_0000));
    }

    #[test]
    fn the_reference_count_refuses_to_wrap() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 4);

        let frame = allocator.allocate(1).expect("allocate frame") as usize;
        for _ in 1..=255 {
            assert!(allocator.add_reference(frame), "up to the byte's ceiling");
        }
        assert_eq!(allocator.co_owners(frame), 255);
        assert!(!allocator.add_reference(frame), "saturated, refused");
        assert_eq!(allocator.co_owners(frame), 255, "and not wrapped to zero");
    }

    #[test]
    fn compaction_moves_the_sharing_state_with_the_frame() {
        let mut allocator = FrameAllocator::new();
        allocator.init(FRAME_SIZE * 8);

        let first = allocator.allocate(1).expect("allocate first") as usize;
        let hole = allocator.allocate(1).expect("allocate the hole") as usize;
        let shared = allocator.allocate(1).expect("allocate shared") as usize;

        // The hole sits between two live frames, so compaction has exactly one
        // move to make, and it is the shared one.
        assert!(allocator.deallocate(hole as *mut u8, 1));
        assert!(allocator.add_reference(shared), "a fork shares it");
        allocator.set_cow(shared, true);

        let moved = allocator.compact(|_, _| true);
        assert_eq!(moved, 1);

        // The frame now lives where the hole was, and everything the fork
        // needed to know about it is there and not where it used to be.
        let relocated = hole;
        assert_eq!(allocator.co_owners(relocated), 1, "the share followed");
        assert!(allocator.is_cow(relocated), "the demotion followed");
        assert_eq!(allocator.co_owners(shared), 0, "the old position is reset");

        let _ = first;
    }
}
