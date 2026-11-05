//! libs/cell/src/cell/tests.rs
//!
//! The cell: a value written once and read after, which is what makes a static
//! sink sound.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

use crate::cell::SyncUnsafeCell;

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
/// This is what the kernel's statics do, the boot assembly writes through
/// the symbol's address and Rust reads it later, so it is checked with the
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
