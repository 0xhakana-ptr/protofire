//! libs/paging/src/table/tests.rs
//!
//! The table and the walk: an entry installed, a translation found, and a level
//! that decides what a word means.
//!
//! Extracted from the module so a reader following the mechanism does not have
//! to scroll past every case it satisfies; see `docs/fmts/testing.md` §1.

use crate::index::ENTRIES_PER_TABLE;
use crate::index::Permissions;
use crate::table::Entry;
use crate::table::PageTable;
use crate::table::map;

/// The encoding a test uses: the identity, with the address's low bits
/// cleared.
///
/// A machine's encoding sets flags in the low bits; this one does not, so a
/// test can read the address straight back out of the word.
fn identity(entry: Entry) -> u64 {
    if entry.present {
        entry.address as u64
    } else {
        0
    }
}

/// A fresh table maps nothing.
#[test]
fn a_new_table_is_empty() {
    let table = PageTable::new();
    assert!(table.is_empty());
    assert_eq!(table.used_entries(), 0);
    for index in 0..ENTRIES_PER_TABLE {
        assert_eq!(table.entry(index), 0);
    }
}

/// The table is a page, and it is page-aligned, because the machine reads
/// it through an address it was given.
#[test]
fn the_table_is_a_page_and_aligned() {
    use core::mem::align_of;
    use core::mem::size_of;
    assert_eq!(size_of::<PageTable>(), crate::index::PAGE_SIZE);
    assert_eq!(align_of::<PageTable>(), crate::index::PAGE_SIZE);
}

/// A mapping is visible in the entry, and mapping twice says so.
///
/// A remap is a caller's bug worth reporting: two owners of one address is
/// otherwise discovered as one of them silently losing it.
#[test]
fn a_mapping_is_written_and_a_remap_is_reported() {
    let table = PageTable::new();
    let first = map(
        &table,
        3,
        0x1000,
        Permissions::KERNEL_READ_WRITE,
        true,
        identity,
    );
    assert!(!first, "the entry was empty");
    assert_eq!(table.entry(3), 0x1000);

    let second = map(
        &table,
        3,
        0x2000,
        Permissions::KERNEL_READ_WRITE,
        true,
        identity,
    );
    assert!(second, "the entry already held a mapping");
    assert_eq!(table.entry(3), 0x2000, "the newer mapping won");
}

/// Two entries are two mappings: writing one does not disturb its
/// neighbour.
#[test]
fn entries_are_independent() {
    let table = PageTable::new();
    map(
        &table,
        0,
        0x1000,
        Permissions::KERNEL_READ_WRITE,
        true,
        identity,
    );
    map(
        &table,
        511,
        0x2000,
        Permissions::KERNEL_READ_WRITE,
        true,
        identity,
    );
    assert_eq!(table.entry(0), 0x1000);
    assert_eq!(table.entry(511), 0x2000);
    assert_eq!(table.used_entries(), 2);
}

/// An unaligned physical address is a caller's bug, and a debug build
/// says so rather than setting a permission bit nobody asked for.
///
/// The assertion is a `debug_assert` because the mask would silently drop
/// the low bits in a release build, and a mapping one page off is worse
/// than a panic.
#[test]
#[cfg(debug_assertions)]
#[should_panic(expected = "assertion")]
fn an_unaligned_address_is_refused() {
    let table = PageTable::new();
    map(
        &table,
        0,
        0x1234,
        Permissions::KERNEL_READ_WRITE,
        true,
        identity,
    );
}
