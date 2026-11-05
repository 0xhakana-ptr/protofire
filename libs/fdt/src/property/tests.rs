//! libs/fdt/src/property/tests.rs
//!
//! The device-tree property: its bytes, the cells they decode to, and a string
//! list.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

// The tests collect cells into a `Vec`, which is the shape a caller uses;
// the library itself allocates nothing.
extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use crate::property::Property;

fn property<'a>(name: &'a str, value: &'a [u8]) -> Property<'a> {
    Property { name, value }
}

/// A one-cell property reads as a big-endian `u32`.
///
/// The byte order is the test's point: `00 00 00 02` is two, and a reader
/// that used the machine's order would answer `0x0200_0000` on a
/// little-endian host — which is the mistake a `from_le_bytes` call makes
/// and a device tree punishes.
#[test]
fn a_cell_is_big_endian() {
    assert_eq!(property("x", &[0, 0, 0, 2]).as_u32(), Some(2));
    assert_eq!(
        property("x", &[0x12, 0x34, 0x56, 0x78]).as_u32(),
        Some(0x1234_5678)
    );
}

/// A property that is not one cell answers `None` rather than its first
/// four bytes.
///
/// `#address-cells` and `reg` are the properties this protects: an
/// eight-byte `reg` read as one cell would give the high half of an
/// address, which is a plausible-looking number for a wrong reason.
#[test]
fn a_property_that_is_not_one_cell_has_no_scalar_value() {
    assert_eq!(property("x", &[]).as_u32(), None);
    assert_eq!(property("x", &[0, 0, 0, 1, 0, 0, 0, 2]).as_u32(), None);
    assert_eq!(property("x", &[0, 0, 0]).as_u32(), None);
}

/// Cells come out in order, and a length that is not a whole number of
/// cells is refused.
#[test]
fn cells_are_big_endian_and_whole() {
    let cells = property("reg", &[0, 0, 0, 1, 0, 0, 0, 2]).as_cells();
    assert_eq!(cells.map(|c| c.collect::<Vec<_>>()), Some(vec![1, 2]));
    assert_eq!(property("reg", &[0, 0, 0, 1, 0]).as_cells(), None);
}

/// A string property reads without its terminator, and a list reads as
/// several.
///
/// `compatible` is the list in practice: `"arm,pl011"` then
/// `"arm,primecell"`.  A reader that returned the whole value would give a
/// caller a string with an embedded NUL, and an equality test against
/// `arm,pl011` would fail on a node that claims it.
#[test]
fn strings_stop_at_their_terminator() {
    let value = b"arm,pl011\0arm,primecell\0";
    let property = property("compatible", value);
    assert_eq!(property.as_str(), Some("arm,pl011"));
    let all: Vec<_> = property.strings().unwrap().collect();
    assert_eq!(all, vec!["arm,pl011", "arm,primecell"]);
}

/// `has_string` is exact, which is what a `compatible` check needs.
///
/// A substring test would match `arm,pl011-fake` and a driver for the real
/// part would bind to a node that is not it.
#[test]
fn a_compatible_entry_matches_exactly() {
    let property = property("compatible", b"arm,pl011-fake\0");
    assert!(!property.has_string("arm,pl011"));
    assert!(property.has_string("arm,pl011-fake"));
}

/// A value that is not UTF-8 is refused rather than lossily decoded.
#[test]
fn a_non_utf8_string_is_refused() {
    let property = property("x", &[0xFF, 0xFE, 0]);
    assert_eq!(property.as_str(), None);
    assert!(!property.has_string("x"));
}
