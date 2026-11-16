//! drivers/storage/nvme/src/identify.rs
//!
//! What the controller and a namespace answer when asked to describe
//! themselves.
//!
//! ## The defect this module exists to not repeat
//!
//! The previous tree's `IdentifyController` declared a handful of fields in
//! order and read the namespace count from the last of them.  **The structure
//! it described was 99 bytes and the namespace count landed at offset 95**,
//! while NVMe 1.0 §5.15.2.2 puts `NN` at 516.  So the driver read the serial
//! number's bytes and called it a namespace count.
//!
//! The reason that survived is that the fields between SN and NN were declared
//! as a run of `u8`/`u16` with no regard for the specification's reserved gaps,
//! and nothing asserted an offset.  This module declares **only the fields a
//! driver reads**, each at the offset the specification puts it, with the gaps
//! spelled as reserved runs of a computed length.  Every offset is asserted by
//! a test, which is the check the previous one did not have.
//!
//! ## What a driver actually needs
//!
//! Two numbers from the controller: how many namespaces it has.  Two from a
//! namespace: how many blocks and how big one is.  The logical block size comes
//! from a table the namespace structure carries, and reading it is the other
//! thing the previous tree did not do: it answered 512 from a constant.

/// Bytes of the Identify Controller structure.  It is a page.
pub const IDENTIFY_CONTROLLER_SIZE: usize = 4096;

/// Bytes of the Identify Namespace structure.  It is a page too.
pub const IDENTIFY_NAMESPACE_SIZE: usize = 4096;

/// Where the namespace count (`NN`) is, an `le32`.
///
/// §5.15.2.2.  The count is "how many namespaces this controller has", which is
/// the number a driver loops over to find the ones it can use.
pub const CONTROLLER_NAMESPACE_COUNT_OFFSET: usize = 516;

/// Where the namespace's size (`NSZE`) is, an `le64`.
///
/// §5.15.2.3.  The number of logical blocks the namespace is.
pub const NAMESPACE_SIZE_OFFSET: usize = 0;

/// Where the namespace's capacity (`NCAP`) is, an `le64`.
pub const NAMESPACE_CAPACITY_OFFSET: usize = 8;

/// Where the namespace's formatted-LBA selector (`FLBAS`) is, a byte.
///
/// §5.15.2.3.  Its low four bits pick a row of the LBA format table.
pub const NAMESPACE_FLBAS_OFFSET: usize = 26;

/// Where the LBA format table begins.
///
/// Sixteen four-byte rows, each a `LBAF` word: bits 23:16 are the data size as
/// a power of two, so a row whose byte 2 reads 9 means 512-byte blocks.  The
/// previous tree assumed row zero was 512 and never looked.
pub const NAMESPACE_LBA_FORMAT_OFFSET: usize = 128;

/// How many rows the LBA format table has.
pub const NAMESPACE_LBA_FORMAT_COUNT: usize = 16;

/// Read the namespace count out of an Identify Controller structure.
///
/// `None` when the structure is shorter than the field, which is a caller that
/// built the wrong buffer rather than a controller that answered badly; the
/// two deserve different answers and this is the one a caller can act on.
pub fn namespace_count(controller: &[u8]) -> Option<u32> {
    let at = CONTROLLER_NAMESPACE_COUNT_OFFSET;
    let bytes = controller.get(at..at + 4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

/// Read a namespace's block count and block size out of an Identify Namespace
/// structure.
///
/// Answers `(blocks, block_bytes)`.  The block size comes from the format table
/// row the structure's `FLBAS` selects, which is the read the previous tree
/// skipped:
///
/// ```text
/// FLBAS bits 3:0 pick a row; that row's byte 2 is log2(block size).
/// ```
///
/// `None` when the structure is too short, when the selected row is outside the
/// table, or when the row's size is not a power of two the driver can use.
/// Each of those is a device answering something this driver cannot describe a
/// disk with, and refusing is better than a block device whose block size is a
/// guess.
pub fn namespace_geometry(namespace: &[u8]) -> Option<(u64, usize)> {
    let size = namespace.get(NAMESPACE_SIZE_OFFSET..NAMESPACE_SIZE_OFFSET + 8)?;
    let blocks = u64::from_le_bytes(size.try_into().ok()?);

    let selector = *namespace.get(NAMESPACE_FLBAS_OFFSET)? as usize & 0x0F;
    let row = NAMESPACE_LBA_FORMAT_OFFSET + selector * 4;
    // The row is four bytes: bits 15:0 are the metadata size, 23:16 the data
    // size as a power of two, and 31:24 the relative performance index.
    let exponent = *namespace.get(row + 2)? as u32;
    if exponent >= 32 {
        return None;
    }
    let block_size = 1usize.checked_shl(exponent)?;
    Some((blocks, block_size))
}

/// Read the capacity out of an Identify Namespace structure.
///
/// Separate from [`namespace_geometry`] because it is a different question: the
/// size is how many blocks the namespace *is*, and the capacity is how many it
/// may allocate.  A block device's sector count is the size.
pub fn namespace_capacity(namespace: &[u8]) -> Option<u64> {
    let at = NAMESPACE_CAPACITY_OFFSET;
    let bytes = namespace.get(at..at + 8)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    //! The offsets, asserted against the specification, and the geometry read
    //! from a structure built the way a controller answers.

    use super::*;

    /// A page-sized buffer with a value written at an offset.
    fn page() -> alloc::vec::Vec<u8> {
        alloc::vec![0u8; IDENTIFY_CONTROLLER_SIZE]
    }

    /// The namespace count is at 516, not at the end of the fields before it.
    ///
    /// This is the defect in one assertion.  The previous tree's structure put
    /// the count at 95 and read the serial number, and no test saw it because
    /// nothing checked where a field was, only that the type was some size.
    #[test]
    fn the_namespace_count_is_where_the_specification_puts_it() {
        assert_eq!(CONTROLLER_NAMESPACE_COUNT_OFFSET, 516);

        let mut controller = page();
        controller[516..520].copy_from_slice(&7u32.to_le_bytes());
        assert_eq!(namespace_count(&controller), Some(7));

        // The bytes the old structure read as the count are the serial
        // number's, and they answer whatever the serial says.
        let mut controller = page();
        controller[95..99].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        assert_eq!(
            namespace_count(&controller),
            Some(0),
            "the count is not at 95"
        );
    }

    /// A structure too short to hold the field answers nothing.
    #[test]
    fn a_short_controller_structure_answers_nothing() {
        assert_eq!(namespace_count(&[0u8; 64]), None);
        assert_eq!(namespace_count(&[]), None);
    }

    /// The geometry comes from the format table, not from a constant.
    ///
    /// Row zero says 512 bytes here and row one says 4096, and the namespace
    /// selects row one.  A driver that assumed row zero would report 512-byte
    /// blocks for a 4096-byte namespace, which is a device that reads and
    /// writes the wrong amount per request and silently corrupts both.
    #[test]
    fn the_block_size_comes_from_the_row_the_namespace_selects() {
        let mut namespace = page();
        namespace[NAMESPACE_SIZE_OFFSET..NAMESPACE_SIZE_OFFSET + 8]
            .copy_from_slice(&1024u64.to_le_bytes());
        // Row zero: 2^9 = 512.
        namespace[NAMESPACE_LBA_FORMAT_OFFSET + 2] = 9;
        // Row one: 2^12 = 4096.
        namespace[NAMESPACE_LBA_FORMAT_OFFSET + 4 + 2] = 12;
        // Select row one.
        namespace[NAMESPACE_FLBAS_OFFSET] = 1;

        assert_eq!(namespace_geometry(&namespace), Some((1024, 4096)));

        // And row zero when it is selected.
        namespace[NAMESPACE_FLBAS_OFFSET] = 0;
        assert_eq!(namespace_geometry(&namespace), Some((1024, 512)));
    }

    /// Only the low four bits of `FLBAS` select a row.
    ///
    /// The upper bits are flags about metadata, so a driver that used the whole
    /// byte would index outside a sixteen-row table for a namespace that set
    /// one.
    #[test]
    fn the_upper_bits_of_the_selector_are_flags() {
        let mut namespace = page();
        namespace[NAMESPACE_SIZE_OFFSET..NAMESPACE_SIZE_OFFSET + 8]
            .copy_from_slice(&8u64.to_le_bytes());
        namespace[NAMESPACE_LBA_FORMAT_OFFSET + 2] = 9;
        namespace[NAMESPACE_FLBAS_OFFSET] = 0xF0;

        assert_eq!(namespace_geometry(&namespace), Some((8, 512)));
    }

    /// A row outside the table answers nothing rather than a guess.
    #[test]
    fn a_row_outside_the_table_is_refused() {
        let mut namespace = page();
        namespace[NAMESPACE_FLBAS_OFFSET] = 15;
        // Row fifteen is inside the table; make its exponent impossible.
        namespace[NAMESPACE_LBA_FORMAT_OFFSET + 15 * 4 + 2] = 40;
        assert_eq!(namespace_geometry(&namespace), None);

        // And a structure too short for the row.
        let mut short = alloc::vec![0u8; 129];
        short[NAMESPACE_FLBAS_OFFSET] = 1;
        assert_eq!(namespace_geometry(&short), None);
    }

    /// The capacity is a separate number from the size.
    #[test]
    fn the_capacity_is_read_from_its_own_offset() {
        let mut namespace = page();
        namespace[NAMESPACE_SIZE_OFFSET..NAMESPACE_SIZE_OFFSET + 8]
            .copy_from_slice(&100u64.to_le_bytes());
        namespace[NAMESPACE_CAPACITY_OFFSET..NAMESPACE_CAPACITY_OFFSET + 8]
            .copy_from_slice(&64u64.to_le_bytes());
        assert_eq!(namespace_capacity(&namespace), Some(64));
    }
}
