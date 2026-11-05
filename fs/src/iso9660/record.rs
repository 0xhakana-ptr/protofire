//! fs/src/iso9660/record.rs
//!
//! A directory record: one entry in a directory's extent.
//!
//! ## The record is variable-length and the length is its first byte
//!
//! ```text
//! 0   length of this record, in bytes, including this byte
//! 1   extended attribute record length, in blocks
//! 2   extent location, le32 then be32
//! 10  data length, le32 then be32
//! 18  recording date and time, 7 bytes
//! 25  file flags
//! 26  file unit size (interleaved files; this reader refuses them)
//! 27  interleave gap
//! 28  volume sequence number, le16 then be16
//! 32  length of the file identifier
//! 33  the identifier
//!     then padding to an even total length, then the System Use area
//! ```
//!
//! A length of zero does not mean an empty record: it means the rest of this
//! sector holds nothing, and the next record starts in the next one.  A reader
//! that treated zero as "empty record, keep going" would read padding as
//! entries.
//!
//! ## Identifiers are not filenames
//!
//! The identifier is what the format calls the entry: uppercase, restricted to
//! `[A-Z0-9_.]`, with `;1` for a file's version.  A disc with Rock Ridge
//! carries the name the author meant in a *System Use* extension, and
//! [`Record::name`] is where that choice is made.

use alloc::string::String;
use alloc::vec::Vec;

use super::susp::SystemUse;

/// Fixed part of a record, up to and including the identifier's length byte.
pub const FIXED_LEN: usize = 33;

/// Offset of the extent location field.
pub const OFFSET_EXTENT: usize = 2;
/// Offset of the data length field.
pub const OFFSET_DATA_LENGTH: usize = 10;
/// Offset of the file flags.
pub const OFFSET_FLAGS: usize = 25;
/// Offset of the file unit size.
pub const OFFSET_FILE_UNIT_SIZE: usize = 26;
/// Offset of the interleave gap size.
pub const OFFSET_INTERLEAVE_GAP: usize = 27;
/// Offset of the volume sequence number.
pub const OFFSET_VOLUME_SEQUENCE: usize = 28;
/// Offset of the identifier's length.
pub const OFFSET_IDENTIFIER_LEN: usize = 32;
/// Offset of the identifier itself.
pub const OFFSET_IDENTIFIER: usize = 33;

/// File flag bit 1: the extent is a directory.
pub const FLAG_DIRECTORY: u8 = 0x02;
/// File flag bit 0: hidden from a directory listing.
pub const FLAG_HIDDEN: u8 = 0x01;
/// File flag bit 7: this record continues in another.
pub const FLAG_MULTI_EXTENT: u8 = 0x80;
/// File flag bit 3: the file has an associated file, per ECMA-119.
pub const FLAG_ASSOCIATED: u8 = 0x04;

/// One directory entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Extent location, in logical blocks.
    pub extent: u32,
    /// Data length, in bytes.
    pub data_length: u32,
    /// Extended attribute record length, in blocks.  Always zero for every
    /// image this reader accepts — see [`Record::has_extended_attributes`].
    pub extended_attribute_blocks: u8,
    pub flags: u8,
    /// The identifier, exactly as the record carries it.
    pub identifier: Vec<u8>,
    /// The System Use area, exactly as the record carries it.
    pub system_use: Vec<u8>,
    /// Whether the identifier is UCS-2 big-endian (a Joliet tree).
    pub joliet: bool,
    /// The record's own length, which is where the next one starts.
    pub record_len: usize,
    /// File unit size: zero for a contiguous file, non-zero for an interleaved
    /// one.
    pub file_unit_size: u8,
}

impl Record {
    /// Parse the record at `offset` in `bytes`.
    ///
    /// Returns `None` when there is no record there: a zero length, a length
    /// that runs past the buffer, or an identifier length the record cannot
    /// hold.  All three are a disc this reader cannot walk, and returning
    /// `None` is what makes the caller move to the next sector rather than
    /// read through the buffer at an offset that means nothing.
    pub fn parse(bytes: &[u8], offset: usize, joliet: bool) -> Option<(Record, usize)> {
        let record_len = *bytes.get(offset)? as usize;
        if record_len == 0 {
            return None;
        }
        let end = offset.checked_add(record_len)?;
        if end > bytes.len() || record_len < FIXED_LEN {
            return None;
        }
        let record = bytes.get(offset..end)?;

        let identifier_len = record[OFFSET_IDENTIFIER_LEN] as usize;
        let identifier_end = OFFSET_IDENTIFIER.checked_add(identifier_len)?;
        // The identifier has to fit between the fixed part and the System Use
        // area, and an odd identifier is padded to an even total length.
        if identifier_end > record_len {
            return None;
        }
        let padded_identifier_len = identifier_len + (identifier_len & 1);

        let extent = both32(record, OFFSET_EXTENT)?.0;
        let data_length = both32(record, OFFSET_DATA_LENGTH)?.0;
        let sequence = both16(record, OFFSET_VOLUME_SEQUENCE)?.0;
        // A volume sequence number other than 1 says this record belongs to a
        // set this disc is one member of, and the reader has no second disc.
        if sequence > 1 {
            return None;
        }

        let system_use_start = (OFFSET_IDENTIFIER + padded_identifier_len).min(record_len);
        let system_use = record[system_use_start..].to_vec();

        Some((
            Record {
                extent,
                data_length,
                extended_attribute_blocks: record[1],
                flags: record[OFFSET_FLAGS],
                identifier: record[OFFSET_IDENTIFIER..identifier_end].to_vec(),
                system_use,
                joliet,
                record_len,
                file_unit_size: record[OFFSET_FILE_UNIT_SIZE],
            },
            end,
        ))
    }

    /// Whether this record names a directory.
    pub const fn is_directory(&self) -> bool {
        self.flags & FLAG_DIRECTORY != 0
    }

    /// Whether this record is a directory's own `.` or `..`.
    ///
    /// The identifier is one byte `0x00` or `0x01` in a primary tree, and two
    /// bytes — the UCS-2 code unit — in a Joliet one.  A name whose first byte
    /// is zero in Joliet is any name below U+0100, which is most of them, so
    /// both bytes are what says so.
    pub fn is_dot_entry(&self) -> bool {
        if self.joliet {
            self.identifier.len() == 2
                && (self.identifier[0] == 0x00 || self.identifier[0] == 0x01)
                && self.identifier[1] == 0x00
        } else {
            self.identifier.len() == 1 && (self.identifier[0] == 0x00 || self.identifier[0] == 0x01)
        }
    }

    /// Whether the record has an extended attribute record in front of its
    /// data.
    ///
    /// This reader does not read them, so a record with one is a file whose
    /// data starts later than the record says.  Reporting it lets the reader
    /// refuse the volume rather than return bytes from the wrong place.
    pub const fn has_extended_attributes(&self) -> bool {
        self.extended_attribute_blocks != 0
    }

    /// Whether this record is one of several extents of one file.
    ///
    /// Level 3 interleaved files; this reader refuses them rather than
    /// returning the first extent as though it were the whole file.
    pub const fn is_multi_extent(&self) -> bool {
        self.flags & FLAG_MULTI_EXTENT != 0
    }

    /// Whether the record says its file is interleaved, which this reader does
    /// not support.
    ///
    /// A file unit size other than zero means the file's data is stored in
    /// units with gaps between them: reading it as one contiguous extent
    /// returns the first unit and the gaps as though they were data.  The
    /// reader refuses such a volume rather than returning bytes from the wrong
    /// places.
    pub fn is_interleaved(&self) -> bool {
        self.file_unit_size != 0
    }

    /// The System Use area, parsed.
    pub fn system_use(&self) -> SystemUse {
        SystemUse::parse(&self.system_use)
    }

    /// The name a reader should show for this record.
    ///
    /// Rock Ridge's `NM` entry when there is one — that is the name the disc's
    /// author meant — otherwise the identifier with its version suffix removed
    /// and its case folded down.  A Joliet identifier is UCS-2 and is decoded
    /// as such.
    pub fn name(&self) -> String {
        let system_use = self.system_use();
        if let Some(name) = system_use.name {
            return name;
        }
        if self.joliet {
            decode_ucs2be(&self.identifier)
        } else {
            strip_version(&decode_ascii(&self.identifier))
        }
    }
}

/// Read a `both32`-shaped field's little half.
fn both32(bytes: &[u8], offset: usize) -> Option<(u32, u32)> {
    let little = bytes.get(offset..offset + 4)?;
    let big = bytes.get(offset + 4..offset + 8)?;
    Some((
        u32::from_le_bytes([little[0], little[1], little[2], little[3]]),
        u32::from_be_bytes([big[0], big[1], big[2], big[3]]),
    ))
}

/// Read a `both16`-shaped field's little half.
fn both16(bytes: &[u8], offset: usize) -> Option<(u16, u16)> {
    let little = bytes.get(offset..offset + 2)?;
    let big = bytes.get(offset + 2..offset + 4)?;
    Some((
        u16::from_le_bytes([little[0], little[1]]),
        u16::from_be_bytes([big[0], big[1]]),
    ))
}

/// Decode an ISO 9660 identifier as ASCII, byte for byte.
fn decode_ascii(identifier: &[u8]) -> String {
    let mut text = String::with_capacity(identifier.len());
    for &byte in identifier {
        text.push(byte as char);
    }
    text
}

/// Decode a UCS-2 big-endian identifier.
///
/// An odd length is a record this reader cannot decode; the trailing byte is
/// dropped rather than making the whole name unreadable, because the name is
/// what a caller shows and a file with no name is worse than a file with a
/// shortened one.
fn decode_ucs2be(identifier: &[u8]) -> String {
    let mut text = String::with_capacity(identifier.len() / 2);
    for pair in identifier.as_chunks::<2>().0 {
        let code = u16::from_be_bytes(*pair);
        text.push(char::from_u32(code as u32).unwrap_or('\u{FFFD}'));
    }
    text
}

/// Remove a file's `;N` version suffix, and a trailing `.` that only exists to
/// separate the name from it.
///
/// ISO 9660 requires the suffix on every file and forbids it on a directory's
/// entries other than `.` and `..`.  A reader shows the name without it, which
/// is what every other reader does and what the disc's author meant.
fn strip_version(identifier: &str) -> String {
    match identifier.rfind(';') {
        Some(semicolon) => {
            let name = &identifier[..semicolon];
            // `README.TXT;1` is `README.TXT`; `README.;1` is `README`.
            name.strip_suffix('.').unwrap_or(name).into()
        }
        None => identifier.into(),
    }
}

#[cfg(test)]
mod tests;
