//! libs/paging/src/index/tests.rs
//!
//! The walk arithmetic: each level's shift, an address split into nine-bit
//! indices, and the span each level covers.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

use crate::index::Cache;
use crate::index::ENTRIES_PER_TABLE;
use crate::index::Level;
use crate::index::PAGE_SIZE;
use crate::index::Permissions;
use crate::index::index;
use crate::index::page_base;
use crate::index::span;

/// The four levels' shifts are the ones the arithmetic gives, and they
/// partition a 48-bit address.
///
/// A shift off by one maps the wrong page, and the failure shows up as
/// corruption somewhere else entirely — which is why this is pinned.
#[test]
fn the_levels_shift_by_nine_bits_each() {
    assert_eq!(Level::Leaf.shift(), 12);
    assert_eq!(Level::Third.shift(), 21);
    assert_eq!(Level::Second.shift(), 30);
    assert_eq!(Level::Root.shift(), 39);
}

/// A virtual address's indices are its nine-bit fields, from the top down.
///
/// The address `0x0000_7f00_1234_5000` is chosen so every level's index is
/// a different number: a test that used an address whose fields repeated
/// would pass with the fields swapped.
#[test]
fn an_address_is_split_into_nine_bit_indices() {
    let address = 0x0000_7f00_1234_5000usize;
    assert_eq!(index(Level::Root, address), 0x0FE);
    assert_eq!(index(Level::Second, address), 0x000);
    assert_eq!(index(Level::Third, address), 0x091);
    assert_eq!(index(Level::Leaf, address), 0x145);
}

/// Every index is inside a table, for every address a 48-bit machine can
/// produce.
///
/// The mask is what makes that true: an index is nine bits, and an address
/// whose high bits are set would otherwise ask for entry 512 of a table of
/// 512 entries.
#[test]
fn every_index_fits_in_a_table() {
    for address in [
        0usize,
        0xFFF,
        0x1000,
        usize::MAX,
        0x0000_FFFF_FFFF_FFFF,
        0xFFFF_8000_0000_0000,
    ] {
        for level in [Level::Root, Level::Second, Level::Third, Level::Leaf] {
            assert!(
                index(level, address) < ENTRIES_PER_TABLE,
                "index {} for {level:?} at {address:#x}",
                index(level, address)
            );
        }
    }
}

/// Each level's span is the one below it times the entries in a table.
#[test]
fn a_level_covers_what_the_level_below_holds() {
    assert_eq!(span(Level::Leaf), PAGE_SIZE);
    assert_eq!(span(Level::Third), PAGE_SIZE * ENTRIES_PER_TABLE);
    assert_eq!(span(Level::Second), span(Level::Third) * ENTRIES_PER_TABLE);
    assert_eq!(span(Level::Root), span(Level::Second) * ENTRIES_PER_TABLE);
    // A root slot covers 512 GiB, which is what a four-level table reaches.
    assert_eq!(span(Level::Root), 512 * 1024 * 1024 * 1024);
}

/// An address's page base drops the offset within the page.
#[test]
fn the_page_base_drops_the_offset() {
    assert_eq!(page_base(0x1234_5678), 0x1234_5000);
    assert_eq!(page_base(0x1000), 0x1000);
    assert_eq!(page_base(0xFFF), 0);
}

/// The permission flags are the ones an entry carries.
#[test]
fn permissions_become_entry_flags() {
    let read_write = Permissions::KERNEL_READ_WRITE.flags();
    assert_eq!(
        read_write & crate::index::FLAG_PRESENT,
        crate::index::FLAG_PRESENT
    );
    assert_eq!(
        read_write & crate::index::FLAG_WRITABLE,
        crate::index::FLAG_WRITABLE
    );
    assert_eq!(
        read_write & crate::index::FLAG_NO_EXECUTE,
        crate::index::FLAG_NO_EXECUTE
    );

    let read_execute = Permissions::KERNEL_READ_EXECUTE.flags();
    assert_eq!(
        read_execute & crate::index::FLAG_PRESENT,
        crate::index::FLAG_PRESENT
    );
    assert_eq!(read_execute & crate::index::FLAG_WRITABLE, 0);
    assert_eq!(read_execute & crate::index::FLAG_NO_EXECUTE, 0);
}

/// A device mapping is not cached, and an ordinary one is.
///
/// A device's registers read through a cached mapping return stale values,
/// and a store to one may never reach the device — which is the difference
/// between a driver that works and one that works on an emulator.
#[test]
fn a_device_mapping_is_not_cached() {
    assert_eq!(Permissions::DEVICE.cache, Cache::Device);
    assert_eq!(Permissions::KERNEL_READ_WRITE.cache, Cache::Normal);
}

/// A kernel mapping is not user-accessible, and that is not incidental.
///
/// If the flag were always set, a user program could read the kernel's
/// memory — and nothing in a boot would notice.
#[test]
fn a_kernel_mapping_is_not_user_accessible() {
    assert_eq!(
        Permissions::KERNEL_READ_WRITE.flags() & crate::index::FLAG_USER,
        0
    );
    assert_eq!(
        Permissions::KERNEL_READ_EXECUTE.flags() & crate::index::FLAG_USER,
        0
    );
}
