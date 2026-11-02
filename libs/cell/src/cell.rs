//! libs/cell/src/cell.rs
//!
//! A `Sync`-capable `UnsafeCell` wrapper for kernel statics.
//!
//! A bare `UnsafeCell<T>` is `!Sync`, so it cannot appear in `static`
//! items.  Architecture code (GDT, IDT, per-AP stacks, spin tables) needs
//! mutable cell-like statics whose access is serialised by the surrounding
//! unsafe code (interrupts disabled, single boot CPU, explicit barriers).
//! This type opts into `Sync` explicitly: soundness rests on the caller
//! guaranteeing that no two threads access the cell concurrently.

use core::cell::UnsafeCell;

/// A `Sync`-capable wrapper around [`UnsafeCell`].
#[repr(transparent)]
pub struct SyncUnsafeCell<T> {
    inner: UnsafeCell<T>,
}

// SAFETY: access through the cell is always `unsafe`; the type exists
// precisely so kernel statics can opt into `Sync` while keeping every
// mutation behind an unsafe block that the caller must synchronise.
unsafe impl<T> Sync for SyncUnsafeCell<T> {}

impl<T> SyncUnsafeCell<T> {
    /// Create a new cell holding `value`.
    #[inline]
    pub const fn new(value: T) -> Self {
        Self {
            inner: UnsafeCell::new(value),
        }
    }

    /// Get a raw mutable pointer to the inner value.
    #[inline]
    pub fn get(&self) -> *mut T {
        self.inner.get()
    }

    /// Read the inner value by copying it out.
    ///
    /// # Safety
    ///
    /// The caller must ensure that no concurrent write is in flight.
    /// In a single-threaded kernel this is trivially satisfied.
    #[inline]
    pub unsafe fn read(&self) -> T
    where
        T: Copy,
    {
        // SAFETY: caller guarantees no concurrent writes.
        unsafe { core::ptr::read(self.inner.get()) }
    }

    /// Write `value` into the cell.
    ///
    /// # Safety
    ///
    /// The caller must ensure that no concurrent read or write is in
    /// flight (e.g. interrupts disabled or single CPU).
    #[inline]
    pub unsafe fn write(&self, value: T) {
        // SAFETY: caller guarantees exclusive access.
        unsafe { core::ptr::write(self.inner.get(), value) }
    }

    /// Get an immutable reference to the inner value.
    ///
    /// # Safety
    ///
    /// The caller must ensure no concurrent mutation is in flight.
    #[inline]
    pub unsafe fn get_ref(&self) -> &T {
        // SAFETY: caller guarantees exclusive read access.
        unsafe { &*self.inner.get() }
    }

    /// Get a mutable reference to the inner value.
    ///
    /// Requires exclusive (`&mut self`) access to the cell itself.
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut()
    }

    /// Replace the inner value, returning the previous value.
    ///
    /// # Safety
    ///
    /// The caller must ensure no concurrent access is in flight.
    #[inline]
    pub unsafe fn replace(&self, value: T) -> T {
        // SAFETY: caller guarantees exclusive access.
        unsafe { core::ptr::replace(self.inner.get(), value) }
    }
}

impl<T: Default> Default for SyncUnsafeCell<T> {
    #[inline]
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: core::fmt::Debug> core::fmt::Debug for SyncUnsafeCell<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // SAFETY: formatting requires no concurrent mutation by convention.
        unsafe {
            f.debug_struct("SyncUnsafeCell")
                .field("value", &*self.inner.get())
                .finish()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SyncUnsafeCell;

    /// A cell holds what it was given, and `get` reports the same address
    /// twice.
    ///
    /// The address stability is the property the type exists for: a `static`
    /// whose contents are reached through a raw pointer needs the pointer not
    /// to move, and a cell that copied its value on `get` would satisfy the
    /// type checker and break every caller.
    #[test]
    fn the_address_is_stable() {
        let cell = SyncUnsafeCell::new(41u32);
        let first = cell.get();
        let second = cell.get();
        assert_eq!(first, second);
        // SAFETY: the cell is not shared, no other access is in flight, and
        // this is the only pointer in existence.
        assert_eq!(unsafe { *first }, 41);
    }

    /// A value written through `get` is read back through `get`.
    ///
    /// This is what the kernel's statics do — the boot assembly writes through
    /// the symbol's address and Rust reads it later — so it is checked with the
    /// same shape rather than with `get_mut`, which borrows and is a different
    /// guarantee.
    #[test]
    fn a_write_through_the_pointer_is_visible() {
        let cell = SyncUnsafeCell::new(0u32);
        // SAFETY: one pointer, no other access, and the write is not concurrent
        // with anything.
        unsafe { *cell.get() = 0xDEAD_BEEF };
        // SAFETY: as above; the write has completed.
        assert_eq!(unsafe { *cell.get() }, 0xDEAD_BEEF);
    }

    /// `get_mut` and `get` reach the same storage.
    ///
    /// A cell whose borrowed and raw paths disagreed would corrupt a static the
    /// first time both were used, and nothing in the type checker would say so.
    #[test]
    fn the_borrowed_and_raw_paths_agree() {
        let mut cell = SyncUnsafeCell::new(7u8);
        *cell.get_mut() = 9;
        // SAFETY: the mutable borrow ended at the previous statement; this is
        // the only outstanding access.
        assert_eq!(unsafe { *cell.get() }, 9);
    }

    /// The cell is `#[repr(transparent)]`, so a `static` of it has the layout
    /// of its contents.
    ///
    /// The kernel's boot assembly reaches these through symbol addresses, and a
    /// wrapper that added a field would change the address arithmetic the
    /// assembly was written against.
    #[test]
    fn the_layout_is_the_contents() {
        assert_eq!(
            core::mem::size_of::<SyncUnsafeCell<u64>>(),
            core::mem::size_of::<u64>()
        );
        assert_eq!(
            core::mem::align_of::<SyncUnsafeCell<u64>>(),
            core::mem::align_of::<u64>()
        );
    }
}
