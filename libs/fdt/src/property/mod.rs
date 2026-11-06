//! libs/fdt/src/property/mod.rs
//!
//! One property: a name, and the bytes behind it.
//!
//! ## Why the bytes are borrowed and not copied
//!
//! A device tree is firmware's memory, mapped read-only and already in place.
//! Copying a property would need an allocator, which a boot does not have when
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
mod tests;
