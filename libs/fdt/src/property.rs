//! libs/fdt/src/property.rs
//!
//! One property: a name, and the bytes behind it.
//!
//! ## Why the bytes are borrowed and not copied
//!
//! A device tree is firmware's memory, mapped read-only and already in place.
//! Copying a property would need an allocator — which a boot does not have when
//! it first reads the tree, since the tree is what tells it how much memory
//! there is.  So a [`Property`] is two slices into the blob, and its lifetime
//! is the blob's.
//!
//! ## Why the readers are here and not at the call site
//!
//! A device tree's integers are **big-endian**, and every caller that read one
//! with `from_le_bytes` would be wrong in the same way.  The accessors below
//! are the only place the byte order is decided, and they all return `Option`
//! because a property's length is the firmware's claim rather than a type's
//! guarantee: a `reg` with three cells where four were expected is a blob this
//! code must refuse rather than read past.

/// A named value in a device tree node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Property<'a> {
    /// The property's name, borrowed from the strings block.
    pub name: &'a str,
    /// The property's value, borrowed from the structure block.
    pub value: &'a [u8],
}

impl<'a> Property<'a> {
    /// The value as one big-endian cell.
    ///
    /// `None` when the value is not exactly four bytes.  A property that holds
    /// more than one cell is a *list*, and a caller that read the first four
    /// bytes of an eight-byte property would be reading half a pair.
    pub fn as_u32(&self) -> Option<u32> {
        let bytes: [u8; 4] = self.value.try_into().ok()?;
        Some(u32::from_be_bytes(bytes))
    }

    /// The value as big-endian cells, refusing a value that is not a whole
    /// number of them.
    pub fn as_cells(&self) -> Option<Cells<'a>> {
        if self.value.len() % 4 != 0 {
            return None;
        }
        Some(Cells {
            bytes: self.value,
            index: 0,
        })
    }

    /// The value as a NUL-terminated string, without the terminator.
    ///
    /// A device tree string is NUL-terminated *and* the property may hold
    /// several of them in a row (`compatible`, `clock-names`).  This reads the
    /// first, which is what a caller asking "is this node compatible with X"
    /// wants; [`Self::strings`] is the one that reads all of them.
    pub fn as_str(&self) -> Option<&'a str> {
        self.strings()?.next()
    }

    /// Every NUL-terminated string in the value, in order.
    ///
    /// `None` only if the bytes are not valid UTF-8.  A `compatible` list is
    /// the property this exists for: a node's first entry is its most specific
    /// claim, and a driver looking for `arm,pl011` has to consider that a node
    /// may claim `arm,primecell` as well.
    pub fn strings(&self) -> Option<Strings<'a>> {
        // Validated up front rather than per string, so that an iterator a
        // caller stops early still gives an answer this function promised.
        if core::str::from_utf8(self.value).is_err() {
            return None;
        }
        Some(Strings {
            bytes: self.value,
            offset: 0,
        })
    }

    /// Whether the value contains `name` in its string list.
    ///
    /// The exact comparison a `compatible` check needs: a substring test would
    /// match `arm,pl011-fake` for `arm,pl011`, and a device tree is where a
    /// firmware's own naming decides which driver runs.
    pub fn has_string(&self, wanted: &str) -> bool {
        match self.strings() {
            Some(mut strings) => strings.any(|entry| entry == wanted),
            None => false,
        }
    }
}

/// A cursor over a property's big-endian cells.
///
/// `PartialEq` compares the cells still to be read, which is what makes an
/// `assert_eq!` against `None` mean "this value is not a whole number of
/// cells" rather than "this value is a different cursor".
#[derive(Debug, Clone)]
pub struct Cells<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl Iterator for Cells<'_> {
    type Item = u32;

    fn next(&mut self) -> Option<u32> {
        let start = self.index * 4;
        let cell = self.bytes.get(start..start + 4)?;
        self.index += 1;
        let bytes: [u8; 4] = cell.try_into().ok()?;
        Some(u32::from_be_bytes(bytes))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let left = self.bytes.len() / 4 - self.index.min(self.bytes.len() / 4);
        (left, Some(left))
    }
}

impl ExactSizeIterator for Cells<'_> {}

impl PartialEq for Cells<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.bytes[self.index * 4..] == other.bytes[other.index * 4..]
    }
}

impl Eq for Cells<'_> {}

/// A cursor over a property's NUL-terminated strings.
#[derive(Debug, Clone)]
pub struct Strings<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Iterator for Strings<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<&'a str> {
        if self.offset >= self.bytes.len() {
            return None;
        }
        let rest = &self.bytes[self.offset..];
        let length = rest.iter().position(|byte| *byte == 0)?;
        // The bytes were validated as UTF-8 by `Property::strings`, and a
        // prefix ending at a NUL is still a prefix of that string.
        let text = core::str::from_utf8(&rest[..length]).ok()?;
        self.offset += length + 1;
        Some(text)
    }
}

#[cfg(test)]
mod tests {
    // The tests collect cells into a `Vec`, which is the shape a caller uses;
    // the library itself allocates nothing.
    extern crate alloc;
    use alloc::vec;
    use alloc::vec::Vec;

    use super::Property;

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
}
