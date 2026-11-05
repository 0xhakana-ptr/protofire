//! memory/src/slot_pool.rs
//!
//! A pool of numbered regions, shared by the address spaces that hold one.
//!
//! Both device-tree architectures carve their user demo regions into a fixed
//! set of slots, hand one to each process, and let `fork` share it.  The
//! bookkeeping that decides which slot is free and when a shared one returns
//! is not a property of either machine: it is one bitmap of taken indices and
//! one reference count per index, and it was written twice, byte for byte,
//! comments included, in the two MMUs.  A fix to either copy would have had
//! to be made twice, and nothing in the tree would have said so.
//!
//! What stays with the architecture is where the regions *are*: the linker
//! script places them and the MMU turns an index into an address.  This type
//! never sees an address.

use core::sync::atomic::AtomicU64;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

/// A pool of `COUNT` numbered regions with per-region reference counts.
///
/// `COUNT` is at most 64: the taken-set is one `AtomicU64` and the whole
/// allocation is a compare-exchange on it, which is what makes two CPUs
/// racing for the last free slot resolve without a lock.
pub struct SlotPool<const COUNT: usize> {
    /// One bit per region; set means taken.
    taken: AtomicU64,
    /// How many address spaces hold each region.
    references: [AtomicUsize; COUNT],
}

impl<const COUNT: usize> SlotPool<COUNT> {
    /// An empty pool.
    ///
    /// `const` so an architecture can write it as a static initialiser without
    /// a constructor call at boot.
    pub const fn new() -> Self {
        const { assert!(COUNT <= 64, "the taken-set is one 64-bit word") };
        Self {
            taken: AtomicU64::new(0),
            references: [const { AtomicUsize::new(0) }; COUNT],
        }
    }

    /// Claim a free region, or `None` when every one is taken.
    pub fn claim(&self) -> Option<usize> {
        loop {
            let taken = self.taken.load(Ordering::Acquire);
            let mut found = None;
            for index in 0..COUNT {
                let mask = 1u64 << index;
                if taken & mask == 0 {
                    found = Some((index, mask));
                    break;
                }
            }
            let (index, mask) = found?;
            if self
                .taken
                .compare_exchange(taken, taken | mask, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                // The index is ours; the count starts at the holder about to
                // be built.  `store` rather than `fetch_add` because the
                // bitmap is the lock: no other holder of this index exists
                // yet, and a stale value from a previous generation would
                // over-count.
                self.references[index].store(1, Ordering::Release);
                return Some(index);
            }
            // CAS failed, someone else took a region; retry with a fresh
            // snapshot.
        }
    }

    /// Record one more holder of `index`.
    ///
    /// What `fork` does: the child maps the same region the parent does, so
    /// the region must outlive both.
    pub fn retain(&self, index: usize) {
        if index < COUNT {
            self.references[index].fetch_add(1, Ordering::AcqRel);
        }
    }

    /// Drop one holder of `index`, returning it to the pool when it was the
    /// last.
    ///
    /// Releasing on the first drop would hand a live process's pages to
    /// whatever claims the slot next: a claim zeroes the whole region and
    /// copies a new payload into it, and the frames a surviving child still
    /// maps would then hold another program's bytes.  Releasing on neither
    /// (which is what a `forked` flag used to do) reserves the region for the
    /// life of the kernel.
    pub fn release(&self, index: usize) {
        if index < COUNT {
            // `AcqRel`: this is the last read-modify-write the region's
            // lifetime depends on, and it must both see the other holders'
            // decrements and publish this one before the index goes back to
            // the bitmap.
            let previous = self.references[index].fetch_sub(1, Ordering::AcqRel);
            if previous <= 1 {
                self.taken.fetch_and(!(1u64 << index), Ordering::AcqRel);
            }
        }
    }

    /// Is `index` currently taken?
    pub fn is_taken(&self, index: usize) -> bool {
        index < COUNT && self.taken.load(Ordering::Acquire) & (1u64 << index) != 0
    }

    /// How many holders `index` has.
    pub fn holders(&self, index: usize) -> usize {
        if index < COUNT {
            self.references[index].load(Ordering::Acquire)
        } else {
            0
        }
    }
}

impl<const COUNT: usize> Default for SlotPool<COUNT> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests;
