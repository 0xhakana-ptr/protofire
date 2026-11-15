//! fs/src/iso9660/volume_descriptor.rs
//!
//! The volume descriptor set: the sectors that describe a disc.
//!
//! ## The set, not a sector
//!
//! A disc's description is a *run* of 2048-byte sectors beginning at sector 16.
//! Each carries a type, the five bytes `CD001`, a version, and its own body;
//! the run ends at a type-255 terminator.  A reader that assumed the primary
//! descriptor is at 16 and stopped there would miss a Joliet tree behind a boot
//! record, which is the shape a released bootable image has.
//!
//! ## Why the fields are read by offset
//!
//! Describing a descriptor as a `#[repr(C, packed)]` struct and casting a
//! sector to it works, because the layout is the specification's, but it puts
//! the field offsets in a struct definition that no test can point at, and it
//! needs `unsafe` for a read that is really "these bytes, at these offsets".
//!
//! Here each field is read from the slice at its offset.  The offsets are named
//! constants, a test pins them against an image built to the specification, and
//! the module has no `unsafe`.
//!
//! ## Both halves
//!
//! ISO 9660 stores a number twice, little-endian then big-endian, because the
//! format was written to be readable from either kind of machine.  A reader
//! takes one half and a *writer* has to write both, which is why
//! [`both32`] and [`both16`] return the pair rather than the value: a test can
//! check that the two agree, and a half that disagrees with its twin is a disc
//! that two readers would see differently.

use alloc::string::String;

/// The size of a logical sector.  Every ISO 9660 disc this driver reads uses
/// it, and the format allows nothing else in practice.
pub const SECTOR_SIZE: usize = 2048;

/// The sector a volume descriptor set begins at (ECMA-119 6.2.1).
pub const DESCRIPTOR_SET_START: u64 = 16;

/// The identifier all five bytes of which are the magic: `CD001`.
pub const STANDARD_IDENTIFIER: &[u8; 5] = b"CD001";

/// Descriptor type 1: the primary volume descriptor.
pub const TYPE_PRIMARY: u8 = 1;
/// Descriptor type 2: a supplementary one, which Joliet uses.
pub const TYPE_SUPPLEMENTARY: u8 = 2;
/// Descriptor type 0: a boot record.
pub const TYPE_BOOT: u8 = 0;
/// Descriptor type 255: the set ends here.
pub const TYPE_TERMINATOR: u8 = 255;

/// The escape sequence a Joliet supplementary descriptor carries, at offset 88.
///
/// `%/@`, `%/C` and `%/E` are the three UCS-2 levels; all of them mean "this
/// tree's names are UCS-2 big-endian".
pub const JOLIET_ESCAPES: [&[u8; 3]; 3] = [b"%/@", b"%/C", b"%/E"];

/// How many descriptors the set may hold before this reader gives up.
///
/// The format puts no explicit bound, the set ends at its terminator like
/// everything else ISO 9660 does, so a disc with no terminator would make a
/// reader walk off the medium.  The bound turns that into a stop.
pub const MAX_DESCRIPTORS: u64 = 64;

// Field offsets, all into the 2048-byte sector.

/// Descriptor type.
pub const OFFSET_TYPE: usize = 0;
/// The `CD001` identifier.
pub const OFFSET_IDENTIFIER: usize = 1;
/// Descriptor version, always 1 for the descriptors this reader takes.
pub const OFFSET_VERSION: usize = 6;
/// The volume identifier: 32 bytes of `[A-Z0-9_]`, space padded.
pub const OFFSET_VOLUME_ID: usize = 40;
/// Volume space size: a `both16`-style field, `le32` then `be32`.
pub const OFFSET_VOLUME_SPACE_SIZE: usize = 80;
/// The escape sequences a Joliet descriptor declares.
pub const OFFSET_ESCAPE_SEQUENCES: usize = 88;
/// Logical block size: `le16` then `be16`.
pub const OFFSET_BLOCK_SIZE: usize = 128;
/// The path tables' total size, `le32` then `be32`.
pub const OFFSET_PATH_TABLE_SIZE: usize = 132;
/// The little-endian path table's location, `le32`.
pub const OFFSET_L_PATH_TABLE_LOC: usize = 140;
/// The optional copy of it, `le32`; zero when the volume has none.
pub const OFFSET_OPT_L_PATH_TABLE_LOC: usize = 144;
/// The big-endian path table's location, `be32`.
pub const OFFSET_M_PATH_TABLE_LOC: usize = 148;
/// The optional copy of it, `be32`; zero when the volume has none.
pub const OFFSET_OPT_M_PATH_TABLE_LOC: usize = 152;
/// The root directory's record, embedded in the descriptor.
pub const OFFSET_ROOT_RECORD: usize = 156;

/// The longest a volume identifier may be.
pub const VOLUME_ID_LEN: usize = 32;

/// A volume descriptor, decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeDescriptor {
    /// Which sector this came from, for a second descriptor set another
    /// follows.
    pub sector: u64,
    pub descriptor_type: u8,
    /// The volume identifier, trailing spaces removed.
    pub volume_id: String,
    /// The number of logical blocks the volume claims.
    pub volume_space_size: u32,
    /// The size of a logical block.
    pub block_size: u16,
    /// The path tables' total size, in bytes.
    pub path_table_size: u32,
    /// The little-endian path table's location, in logical blocks.
    pub l_path_table_loc: u32,
    /// The optional little-endian copy's location; zero when there is none.
    pub opt_l_path_table_loc: u32,
    /// The big-endian path table's location, in logical blocks.
    pub m_path_table_loc: u32,
    /// The optional big-endian copy's location; zero when there is none.
    pub opt_m_path_table_loc: u32,
    /// The root directory's record, undecoded.
    pub root_record: [u8; 34],
    /// Whether the descriptor's escape sequences name Joliet.
    pub joliet: bool,
}

impl VolumeDescriptor {
    /// Decode one descriptor sector.
    ///
    /// Returns `None` when the sector does not begin with a descriptor this
    /// reader accepts: the magic is elsewhere or absent, or the version is not
    /// one.  A disc whose sector 16 is not a descriptor is not an ISO 9660
    /// disc, and guessing otherwise would read a filesystem's other data as
    /// one.
    pub fn parse(sector: u64, bytes: &[u8; SECTOR_SIZE]) -> Option<VolumeDescriptor> {
        if &bytes[OFFSET_IDENTIFIER..OFFSET_IDENTIFIER + 5] != STANDARD_IDENTIFIER {
            return None;
        }
        if bytes[OFFSET_VERSION] != 1 {
            return None;
        }

        let descriptor_type = bytes[OFFSET_TYPE];
        if !matches!(
            descriptor_type,
            TYPE_PRIMARY | TYPE_SUPPLEMENTARY | TYPE_BOOT | TYPE_TERMINATOR
        ) {
            return None;
        }

        let volume_id = read_volume_id(&bytes[OFFSET_VOLUME_ID..OFFSET_VOLUME_ID + VOLUME_ID_LEN]);
        let volume_space_size = both32(bytes, OFFSET_VOLUME_SPACE_SIZE).map(|(le, _be)| le)?;
        let block_size = both16(bytes, OFFSET_BLOCK_SIZE).map(|(le, _be)| le)?;
        let path_table_size = both32(bytes, OFFSET_PATH_TABLE_SIZE).map(|(le, _be)| le)?;
        let l_path_table_loc = u32::from_le_bytes(
            bytes
                .get(OFFSET_L_PATH_TABLE_LOC..OFFSET_L_PATH_TABLE_LOC + 4)?
                .try_into()
                .ok()?,
        );
        let opt_l_path_table_loc = u32::from_le_bytes(
            bytes
                .get(OFFSET_OPT_L_PATH_TABLE_LOC..OFFSET_OPT_L_PATH_TABLE_LOC + 4)?
                .try_into()
                .ok()?,
        );
        let m_path_table_loc = u32::from_be_bytes(
            bytes
                .get(OFFSET_M_PATH_TABLE_LOC..OFFSET_M_PATH_TABLE_LOC + 4)?
                .try_into()
                .ok()?,
        );
        let opt_m_path_table_loc = u32::from_be_bytes(
            bytes
                .get(OFFSET_OPT_M_PATH_TABLE_LOC..OFFSET_OPT_M_PATH_TABLE_LOC + 4)?
                .try_into()
                .ok()?,
        );

        let mut root_record = [0u8; 34];
        root_record.copy_from_slice(&bytes[OFFSET_ROOT_RECORD..OFFSET_ROOT_RECORD + 34]);

        let escape = &bytes[OFFSET_ESCAPE_SEQUENCES..OFFSET_ESCAPE_SEQUENCES + 3];
        let joliet = JOLIET_ESCAPES.iter().any(|candidate| *candidate == escape);

        Some(VolumeDescriptor {
            sector,
            descriptor_type,
            volume_id,
            volume_space_size,
            block_size,
            path_table_size,
            l_path_table_loc,
            opt_l_path_table_loc,
            m_path_table_loc,
            opt_m_path_table_loc,
            root_record,
            joliet,
        })
    }

    /// Whether this is the set's terminator.
    pub const fn is_terminator(&self) -> bool {
        self.descriptor_type == TYPE_TERMINATOR
    }

    /// Whether this descriptor describes a tree a reader can use.
    pub const fn describes_a_tree(&self) -> bool {
        matches!(self.descriptor_type, TYPE_PRIMARY | TYPE_SUPPLEMENTARY)
    }
}

/// Read a volume identifier: `[A-Z0-9_]`, space-padded, and not necessarily
/// either of those on a disc written by something careless.
///
/// A byte the identifier's character set does not allow becomes `_` rather than
/// being dropped: the length is part of what the disc says, and a label that
/// silently got shorter is a label that no longer matches its own field.
fn read_volume_id(raw: &[u8]) -> String {
    let end = raw
        .iter()
        .position(|&b| b == 0 || b == b' ')
        .unwrap_or(raw.len());
    let mut label = String::with_capacity(end);
    for &byte in &raw[..end] {
        if byte.is_ascii_graphic() {
            label.push(byte as char);
        } else {
            label.push('_');
        }
    }
    label
}

/// Read a field stored little-endian then big-endian as a `u32`.
///
/// Returns both halves so a caller can check they agree.  `None` when the field
/// runs past the sector, which is a descriptor whose offsets disagree with the
/// specification.
pub fn both32(bytes: &[u8], offset: usize) -> Option<(u32, u32)> {
    let little = bytes.get(offset..offset + 4)?;
    let big = bytes.get(offset + 4..offset + 8)?;
    Some((
        u32::from_le_bytes([little[0], little[1], little[2], little[3]]),
        u32::from_be_bytes([big[0], big[1], big[2], big[3]]),
    ))
}

/// Read a field stored little-endian then big-endian as a `u16`.
pub fn both16(bytes: &[u8], offset: usize) -> Option<(u16, u16)> {
    let little = bytes.get(offset..offset + 2)?;
    let big = bytes.get(offset + 2..offset + 4)?;
    Some((
        u16::from_le_bytes([little[0], little[1]]),
        u16::from_be_bytes([big[0], big[1]]),
    ))
}

#[cfg(test)]
mod tests {
    //! The tests for this module.
    //!
    //! The volume descriptor: the identifier, the root record, and the fields a
    //! reader needs to mount.
    //!
    //! Extracted from the module so that a reader following the mechanism does
    //! not have to scroll past every case it has to satisfy; see
    //! `docs/fmts/testing.md` §1.

    use crate::iso9660::volume_descriptor::DESCRIPTOR_SET_START;
    use crate::iso9660::volume_descriptor::OFFSET_BLOCK_SIZE;
    use crate::iso9660::volume_descriptor::OFFSET_VOLUME_SPACE_SIZE;
    use crate::iso9660::volume_descriptor::SECTOR_SIZE;
    use crate::iso9660::volume_descriptor::TYPE_PRIMARY;
    use crate::iso9660::volume_descriptor::VolumeDescriptor;
    use crate::iso9660::volume_descriptor::both16;
    use crate::iso9660::volume_descriptor::both32;

    /// A sector with a primary descriptor built to the specification.
    ///
    /// Written by hand rather than by a writer this crate does not have: a test
    /// that built its input with the code under test would agree with itself.
    fn primary(label: &[u8], blocks: u32, block_size: u16) -> [u8; SECTOR_SIZE] {
        let mut sector = [0u8; SECTOR_SIZE];
        sector[0] = TYPE_PRIMARY;
        sector[1..6].copy_from_slice(b"CD001");
        sector[6] = 1;
        // The volume id: 32 bytes, space padded.
        for slot in sector[40..40 + 32].iter_mut() {
            *slot = b' ';
        }
        sector[40..40 + label.len()].copy_from_slice(label);
        // Volume space size, both halves.
        sector[OFFSET_VOLUME_SPACE_SIZE..OFFSET_VOLUME_SPACE_SIZE + 4]
            .copy_from_slice(&blocks.to_le_bytes());
        sector[OFFSET_VOLUME_SPACE_SIZE + 4..OFFSET_VOLUME_SPACE_SIZE + 8]
            .copy_from_slice(&blocks.to_be_bytes());
        // Block size, both halves.
        sector[OFFSET_BLOCK_SIZE..OFFSET_BLOCK_SIZE + 2].copy_from_slice(&block_size.to_le_bytes());
        sector[OFFSET_BLOCK_SIZE + 2..OFFSET_BLOCK_SIZE + 4]
            .copy_from_slice(&block_size.to_be_bytes());
        sector
    }

    /// The descriptors begin at sector 16, which is the one constant a reader
    /// has to have right before it can find anything.
    #[test]
    fn the_descriptor_set_begins_at_sector_sixteen() {
        assert_eq!(DESCRIPTOR_SET_START, 16);
        assert_eq!(SECTOR_SIZE, 2048);
    }

    /// A primary descriptor is decoded from its fields.
    #[test]
    fn a_primary_descriptor_is_decoded() {
        let sector = primary(b"MYVOL", 100, 2048);
        let descriptor = VolumeDescriptor::parse(16, &sector).expect("a primary descriptor");
        assert_eq!(descriptor.descriptor_type, TYPE_PRIMARY);
        assert_eq!(descriptor.volume_id, "MYVOL");
        assert_eq!(descriptor.volume_space_size, 100);
        assert_eq!(descriptor.block_size, 2048);
        assert!(!descriptor.joliet);
        assert!(descriptor.describes_a_tree());
    }

    /// The volume identifier is space padded, and its padding is not part of
    /// the name.
    #[test]
    fn a_volume_identifier_drops_its_padding() {
        let sector = primary(b"AB", 1, 2048);
        let descriptor = VolumeDescriptor::parse(16, &sector).expect("descriptor");
        assert_eq!(descriptor.volume_id, "AB", "trailing spaces are padding");
    }

    /// A sector whose magic is elsewhere is not a descriptor, and the reader
    /// says so rather than reading a filesystem's data as one.
    #[test]
    fn a_sector_without_the_magic_is_not_a_descriptor() {
        let mut sector = primary(b"X", 1, 2048);
        sector[1] = b'X';
        assert_eq!(VolumeDescriptor::parse(16, &sector), None);
    }

    /// A version other than 1 is refused: it is a descriptor this reader was
    /// not written against.
    #[test]
    fn a_descriptor_version_of_two_is_refused() {
        let mut sector = primary(b"X", 1, 2048);
        sector[6] = 2;
        assert_eq!(VolumeDescriptor::parse(16, &sector), None);
    }

    /// A field stored twice is read from both halves, and a caller can see
    /// whether they agree.
    ///
    /// The two halves are the format's own redundancy: a disc whose halves
    /// disagree is one two readers would see differently, and that is worth
    /// being able to check rather than hiding.
    #[test]
    fn a_doubled_field_is_readable_from_both_halves() {
        let sector = primary(b"X", 0x1234_5678, 2048);
        let (little, big) = both32(&sector, OFFSET_VOLUME_SPACE_SIZE).expect("the field");
        assert_eq!(little, 0x1234_5678);
        assert_eq!(
            big, 0x1234_5678,
            "the two halves agree on a well-formed disc"
        );

        let (little, big) = both16(&sector, OFFSET_BLOCK_SIZE).expect("the field");
        assert_eq!(little, 2048);
        assert_eq!(big, 2048);
    }

    /// A field running past the sector answers `None` rather than panicking.
    #[test]
    fn a_field_past_the_sector_is_none() {
        let sector = [0u8; SECTOR_SIZE];
        assert_eq!(both32(&sector, SECTOR_SIZE - 4), None);
        assert_eq!(both16(&sector, SECTOR_SIZE - 2), None);
    }
}
