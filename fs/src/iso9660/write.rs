//! fs/src/iso9660/write.rs
//!
//! The write half of the format's structures: extents and the device writes
//! underneath them, a directory record pointed at a new place, a record
//! appended to or taken out of a directory's extent, and the path tables
//! serialised in both byte orders.
//!
//! ## What is here and what is not
//!
//! Everything in this module is arithmetic on bytes the specification names:
//! a field's two halves, a record's length byte, a directory extent's blocks.
//! What is *not* here is the decision of where new space comes from, that is
//! the allocator in [`super::allocate`], or the order a mutation writes its
//! fields in, which is the volume's ([`super::volume`]), because that order is
//! what makes a crash leave a readable volume behind.

use alloc::vec;
use alloc::vec::Vec;

use block::BlockDevice;

use abi::Error;
use abi::Result;

use super::record::OFFSET_EXTENT;
use super::record::Record;
use super::volume_descriptor::OFFSET_L_PATH_TABLE_LOC;
use super::volume_descriptor::OFFSET_M_PATH_TABLE_LOC;
use super::volume_descriptor::OFFSET_OPT_L_PATH_TABLE_LOC;
use super::volume_descriptor::OFFSET_OPT_M_PATH_TABLE_LOC;
use super::volume_descriptor::OFFSET_PATH_TABLE_SIZE;
use super::volume_descriptor::SECTOR_SIZE;

/// The most bytes of directory this driver will hold in memory at once.
///
/// A directory's size is a field of its record, and the thing that wrote the
/// record is not this driver: a corrupt one must not be able to ask for an
/// allocation the size of the address space.  8 MiB is far more than any
/// real directory and small enough that a disc claiming otherwise is refused
/// rather than trusted.
pub(crate) const MAX_DIRECTORY_BYTES: u64 = 8 * 1024 * 1024;

// the device, in bytes

/// Read `buffer.len()` bytes from `offset`, which is a byte offset into the
/// disc.
///
/// ## Two block sizes
///
/// ISO 9660 counts in 2048-byte *logical blocks*, and a `BlockDevice` counts in
/// its own blocks, 512 for every device this tree has.  They are not the same
/// unit, and a reader that used one for the other reads from the wrong place:
/// logical block 16 is a device block 64, and a `read_blocks(16, …)` returns
/// the bytes of a different part of the medium.
///
/// So the arithmetic here is in bytes, and the conversion to device blocks
/// happens once, at the call.
pub(crate) fn read_exact(device: &dyn BlockDevice, offset: u64, buffer: &mut [u8]) -> Result<()> {
    if buffer.is_empty() {
        return Ok(());
    }
    let device_block = device.block_size() as u64;
    let first = offset / device_block;
    let within = (offset % device_block) as usize;
    let device_blocks = (within + buffer.len()).div_ceil(device_block as usize);
    let mut scratch = vec![0u8; device_blocks * device_block as usize];
    device.read_blocks(first, &mut scratch)?;
    buffer.copy_from_slice(&scratch[within..within + buffer.len()]);
    Ok(())
}

/// Write `buf` at a byte offset, through whole-block device writes.
///
/// A device writes blocks, so each sector the range touches is classified
/// first: one the range covers in full is written without being read, and one
/// it only partly covers is read, patched and written back, the bytes the
/// caller is not replacing have to survive, and on ISO 9660 a file's last
/// sector is where that matters, since its neighbours there are padding and
/// whatever the image put after it.
pub(crate) fn write_exact(device: &dyn BlockDevice, offset: u64, buf: &[u8]) -> Result<()> {
    if buf.is_empty() {
        return Ok(());
    }

    let bs = device.block_size();
    let first = offset / bs as u64;
    let within = (offset % bs as u64) as usize;
    let total_blocks = (within + buf.len()).div_ceil(bs);

    let mut scratch = vec![0u8; total_blocks * bs];
    for index in 0..total_blocks {
        let sector_from = index * bs;
        let sector_to = sector_from + bs;
        // A sector the range covers in full needs no read; one it only partly
        // covers does, so the bytes outside the range are written back as the
        // medium has them.
        let covered_from = within.max(sector_from);
        let covered_to = (within + buf.len()).min(sector_to);
        if covered_from > sector_from || covered_to < sector_to {
            device.read_blocks(first + index as u64, &mut scratch[sector_from..sector_to])?;
        }
    }
    scratch[within..within + buf.len()].copy_from_slice(buf);

    for index in 0..total_blocks {
        device.write_blocks(first + index as u64, &scratch[index * bs..(index + 1) * bs])?;
    }
    Ok(())
}

// extents

/// Write file data into an extent, and answer how much of `buffer` was taken.
///
/// The mirror of a read, and it is deliberately clamped to the extent's
/// recorded size: a file's length is a field of its directory record, so
/// *growing* one is a metadata change and not a data write.  A write that runs
/// past the end is therefore a short write, which is what the VFS contract
/// says a write that cannot take everything should be.
pub(crate) fn write_extent(
    device: &dyn BlockDevice,
    block_size: u16,
    extent_location: u32,
    extent_size: u32,
    file_offset: u64,
    buffer: &[u8],
) -> Result<usize> {
    if file_offset >= extent_size as u64 {
        return Ok(0);
    }

    let available = (extent_size as u64).saturating_sub(file_offset);
    let n = (buffer.len() as u64).min(available) as usize;
    if n == 0 {
        return Ok(0);
    }

    let start = extent_location as u64 * block_size as u64 + file_offset;
    write_exact(device, start, &buffer[..n])?;
    Ok(n)
}

/// Read every record an extent holds, its own "." and ".." included.
///
/// A block map needs the two: a record's System Use area can continue into a
/// block of its own, the entry that says so is in the record, and the root
/// directory's own "." record is where a volume declares its extension, so a
/// walk that skipped it would leave that block looking free.
pub(crate) fn read_all_records(
    device: &dyn BlockDevice,
    block_size: u16,
    extent_location: u32,
    extent_size: u32,
    joliet: bool,
) -> Result<Vec<Record>> {
    read_records(
        device,
        block_size,
        extent_location,
        extent_size,
        joliet,
        true,
    )
}

/// Read the records an extent holds, with or without its own "." and "..".
pub(crate) fn read_records(
    device: &dyn BlockDevice,
    block_size: u16,
    extent_location: u32,
    extent_size: u32,
    joliet: bool,
    with_dots: bool,
) -> Result<Vec<Record>> {
    if extent_size as u64 > MAX_DIRECTORY_BYTES {
        return Err(Error::InvalidArgument);
    }

    let mut data = vec![0u8; extent_size as usize];
    let extent_offset = extent_location as u64 * block_size as u64;
    read_exact(device, extent_offset, &mut data)?;

    let mut records = Vec::new();
    let mut offset = 0usize;

    while offset < data.len() {
        match Record::parse(&data, offset, joliet) {
            Some((parsed, next)) => {
                if with_dots || !parsed.is_dot_entry() {
                    records.push(parsed);
                }
                offset = next;
            }
            None => {
                // A zero length does not mean an empty record: it means the
                // rest of this sector holds nothing.  The next record is in
                // the next sector, which is what this steps to.
                let sector_end = (offset / SECTOR_SIZE + 1) * SECTOR_SIZE;
                if sector_end <= offset || sector_end >= data.len() {
                    break;
                }
                offset = sector_end;
            }
        }
    }

    Ok(records)
}

/// Whether a record is a directory's own "." or its "..", by identifier.
///
/// The map walk and the move use this on records parsed from a primary tree's
/// extents; a Joliet record's own check is [`Record::is_dot_entry`].
pub(crate) fn is_self_or_parent(record: &Record) -> bool {
    record.identifier.len() == 1 && (record.identifier[0] == 0x00 || record.identifier[0] == 0x01)
}

// placement

/// The bytes a record's extent-location and data-length fields hold.
///
/// The two fields are adjacent in the record and each is stored twice
/// little-endian then big-endian, so a reader that checks either half sees
/// the same thing.
pub(crate) fn placement_field(extent_location: u32, length: u32) -> [u8; 16] {
    let mut field = [0u8; 16];
    field[..4].copy_from_slice(&extent_location.to_le_bytes());
    field[4..8].copy_from_slice(&extent_location.to_be_bytes());
    field[8..12].copy_from_slice(&length.to_le_bytes());
    field[12..].copy_from_slice(&length.to_be_bytes());
    field
}

/// Point a record at a new extent, and give it a new length.
///
/// One write, because the two fields are adjacent and each is stored twice:
/// a resize that wrote them separately would leave a record whose halves
/// disagree if it stopped between them.
pub(crate) fn rewrite_record_placement(
    device: &dyn BlockDevice,
    record_offset: u64,
    extent_location: u32,
    length: u32,
) -> Result<()> {
    let field = placement_field(extent_location, length);
    write_exact(device, record_offset + OFFSET_EXTENT as u64, &field)
}

/// Add `record` to the end of a directory's extent, and answer where it went.
///
/// "The end" is where the reader's walk stops, not where the recorded length
/// ends: a directory's length covers the padding to its block boundary, and
/// a zero-length byte says the rest of *that block* holds nothing, so a
/// record appended after such a gap would be one no reader reaches.  This
/// walks the extent the way the readers do and puts the record where the
/// walk stops, overwriting padding, never a record.
///
/// A record may not straddle a logical block boundary, so one that does not
/// fit in the block the walk ends in starts the next one; the bytes it skips
/// are left as they are, which is a gap the reader crosses by the same rule.
///
/// The directory's recorded length grows by the record, the honest answer,
/// since the length covers the padding the way a written disc's does, and
/// is the caller's to rewrite: it says where the extent is and how long it
/// is, and nothing here touches it.
pub(crate) fn append_record(
    device: &dyn BlockDevice,
    block_size: u16,
    dir_extent: u32,
    dir_size: u32,
    record: &[u8],
    allocate: &mut super::allocate::Allocator,
) -> Result<(u32, u32, u64)> {
    let bs = block_size as u64;
    let mut data = vec![0u8; dir_size as usize];
    read_exact(device, dir_extent as u64 * bs, &mut data)?;

    // The walk the readers do, without the name decoding: a zero length says
    // the rest of the block holds nothing and the next record is in the next
    // one, the same rule the readers use to cross the gap, so the record
    // this appends lands where a reader will find it.
    let mut walk = 0usize;
    while walk < data.len() {
        match Record::parse(&data, walk, false) {
            Some((_parsed, next)) => walk = next,
            None => {
                let sector_end = (walk / SECTOR_SIZE + 1) * SECTOR_SIZE;
                if sector_end <= walk || sector_end >= data.len() {
                    break;
                }
                walk = sector_end;
            }
        }
    }

    let mut at = walk as u64;
    if at % bs + record.len() as u64 > bs {
        at = at.div_ceil(bs) * bs;
    }

    // The recorded length already covers the padding to the block boundary,
    // so a record that lands inside it costs no block at all; the length
    // grows only when the record reaches past what the extent holds.
    let end = at + record.len() as u64;
    let new_size = dir_size.max(end as u32);
    let location = super::allocate::place_extent(
        device, block_size, dir_extent, dir_size, new_size, allocate,
    )?;

    // The record goes into the extent's own byte space, which the move above
    // preserved, so `at` is where it is either way.
    write_exact(device, location as u64 * bs + at, record)?;
    Ok((location, new_size, location as u64 * bs + at))
}

/// Take one record out of a directory's extent.
///
/// The records after it move down over it and the tail is zeroed, rather than
/// the survivors being re-serialised: a record carries whatever its writer put
/// in the System Use area, and this driver does not parse all of it, so the
/// bytes are the only honest copy.  The directory's own record is rewritten to
/// the length that leaves.
pub(crate) fn remove_child_record(
    device: &dyn BlockDevice,
    block_size: u16,
    dir_extent: u32,
    dir_size: u32,
    dir_record_offset: u64,
    child_record_offset: u64,
    child_len: usize,
) -> Result<()> {
    let mut data = vec![0u8; dir_size as usize];
    super::allocate::read_extent_bytes(device, block_size, dir_extent, dir_size, 0, &mut data)?;

    let at = child_record_offset
        .checked_sub(dir_extent as u64 * block_size as u64)
        .ok_or(Error::InvalidArgument)? as usize;
    if at + child_len > data.len() {
        return Err(Error::InvalidArgument);
    }
    data.copy_within(at + child_len.., at);
    let new_size = dir_size - child_len as u32;
    data[new_size as usize..].fill(0);
    write_extent(device, block_size, dir_extent, dir_size, 0, &data)?;

    // The directory is that much shorter, and nothing else about it moved.
    rewrite_record_placement(device, dir_record_offset, dir_extent, new_size)
}

// path tables

/// One directory, as a path table describes it.
///
/// A path table is how a reader finds a directory without walking the tree
/// from the root: every directory the volume has, in level order, each naming
/// its parent by number.  A directory's number *is* its position in the table,
/// so a table is built from the whole list at once and never edited in place.
pub(crate) struct PathTableEntry {
    pub identifier: Vec<u8>,
    pub extent_location: u32,
    /// This directory's number, and its parent's, both 1-based.
    pub number: u16,
    pub parent_number: u16,
}

/// Serialise a path table.
///
/// Two are required, one little-endian and one big-endian, and they are
/// identical apart from the byte order of the numbers a record carries, which
/// is why the order is an argument.
pub(crate) fn build_path_table(entries: &[PathTableEntry], big_endian: bool) -> Vec<u8> {
    let mut out = Vec::new();
    for (position, entry) in entries.iter().enumerate() {
        // A directory's number is where it sits; a table whose numbers do not
        // say that is a table a reader cannot follow.
        debug_assert_eq!(entry.number as usize, position + 1);

        let len_di = entry.identifier.len();
        let extent = if big_endian {
            entry.extent_location.to_be_bytes()
        } else {
            entry.extent_location.to_le_bytes()
        };
        let parent = if big_endian {
            entry.parent_number.to_be_bytes()
        } else {
            entry.parent_number.to_le_bytes()
        };

        out.push(len_di as u8);
        out.push(0); // extended attribute record length
        out.extend_from_slice(&extent);
        out.extend_from_slice(&parent);
        out.extend_from_slice(&entry.identifier);
        if len_di % 2 == 1 {
            // A record's length is even, so an odd identifier takes a pad byte.
            out.push(0);
        }
    }
    out
}

/// Rewrite the four descriptor fields that describe the path tables.
///
/// The size is stored twice; the little-endian table's locations are
/// little-endian and the big-endian table's are big-endian.  That is the
/// format, not a choice.  The two optional copies are rewritten too, because a
/// reader is allowed to follow them and a stale copy is a wrong answer.
///
/// The descriptor is a parameter because a volume has one per tree: the
/// primary descriptor's tables name the primary tree's directories and the
/// supplementary descriptor's name its own.
pub(crate) fn rewrite_path_table_fields(
    device: &dyn BlockDevice,
    descriptor_sector: u64,
    size: u32,
    l_location: u32,
    opt_l_location: u32,
    m_location: u32,
    opt_m_location: u32,
) -> Result<()> {
    let at = |field: usize| descriptor_sector * SECTOR_SIZE as u64 + field as u64;

    let mut size_field = [0u8; 8];
    size_field[..4].copy_from_slice(&size.to_le_bytes());
    size_field[4..].copy_from_slice(&size.to_be_bytes());
    write_exact(device, at(OFFSET_PATH_TABLE_SIZE), &size_field)?;
    write_exact(
        device,
        at(OFFSET_L_PATH_TABLE_LOC),
        &l_location.to_le_bytes(),
    )?;
    write_exact(
        device,
        at(OFFSET_OPT_L_PATH_TABLE_LOC),
        &opt_l_location.to_le_bytes(),
    )?;
    write_exact(
        device,
        at(OFFSET_M_PATH_TABLE_LOC),
        &m_location.to_be_bytes(),
    )?;
    write_exact(
        device,
        at(OFFSET_OPT_M_PATH_TABLE_LOC),
        &opt_m_location.to_be_bytes(),
    )
}
