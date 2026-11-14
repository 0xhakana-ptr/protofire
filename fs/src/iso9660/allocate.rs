//! fs/src/iso9660/allocate.rs
//!
//! Where a new extent comes from: the map of what the volume holds, the
//! allocator that hands out what it does not, and the tail rule that gives
//! blocks back.
//!
//! ## The volume's free space is not a structure
//!
//! ISO 9660 has no free-space bitmap.  What the format has instead is a
//! volume-space size in its descriptor, and the invariant that makes the
//! append-only scheme work: everything below the size the volume declares is
//! claimed by an extent, and everything from it on is not.  So an allocator
//! has two honest shapes, and this module has both:
//!
//! - **The map.**  A walk of the whole volume that names every structure, the
//!   system area, the descriptor set, the path tables a descriptor names (with
//!   their optional copies), the boot catalog a Boot Record names and the
//!   images its entries point at, the directory trees, and the continuation
//!   areas a record's `CE` entry names.  What the gaps between those runs hold
//!   is free, and a hole a removal left is handed out again from here.  The map
//!   has to be **complete**: a volume with anything this driver cannot account
//!   for, a descriptor it does not know, an extended attribute record, no
//!   terminator on the descriptor set, gives no map at all, and then
//!   allocations append, because handing a block to a file that a structure
//!   already holds is the one thing that must not happen.
//! - **The end of the volume.**  The blocks begin where the declared size ends,
//!   and the one metadata field the allocation moves is the size itself.  It
//!   never hands out a block the image already wrote, which is what makes it
//!   correct without knowing what is on the volume, and what it costs is that
//!   nothing in the middle is ever handed out again.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use block::BlockDevice;

use abi::Error;
use abi::Result;

use super::record::Record;
use super::volume_descriptor::DESCRIPTOR_SET_START;
use super::volume_descriptor::OFFSET_VOLUME_SPACE_SIZE;
use super::volume_descriptor::SECTOR_SIZE;
use super::volume_descriptor::TYPE_BOOT;
use super::volume_descriptor::TYPE_PRIMARY;
use super::volume_descriptor::TYPE_SUPPLEMENTARY;
use super::volume_descriptor::TYPE_TERMINATOR;
use super::write::is_self_or_parent;
use super::write::read_all_records;
use super::write::read_exact;

/// The blocks the standard reserves for a volume's system area.
const SYSTEM_AREA_BLOCKS: u32 = 16;

/// The catalog block, and the sectors El Torito may continue it into.
///
/// Claiming more than a catalog uses costs space, and claiming less costs the
/// catalog, so this is generous on purpose.
const BOOT_CATALOG_BLOCKS: u32 = 8;

/// How deep a directory tree may go before the walk gives up.
const MAX_TREE_DEPTH: u32 = 64;

/// The most volume descriptors this driver will walk before giving up.
///
/// The set ends at its terminator like everything else ISO 9660 does; a
/// volume that has not reached one within this many is not one whose
/// structures this driver can name.
const MAX_DESCRIPTORS: u32 = 32;

/// How many logical blocks `bytes` takes.
fn blocks_of(bytes: u32, block_size: u16) -> u32 {
    (u64::from(bytes).div_ceil(u64::from(block_size))) as u32
}

/// Read `buffer.len()` bytes of a file from its extent.
///
/// The read the extent arithmetic goes through: a byte offset in the volume
/// maps to the extent's start plus the offset, and the number of bytes it
/// answers is clamped to the extent's own length, which is what makes a read
/// past the end short rather than wrong.
pub(crate) fn read_extent_bytes(
    device: &dyn BlockDevice,
    block_size: u16,
    extent_location: u32,
    extent_size: u32,
    file_offset: u64,
    buffer: &mut [u8],
) -> Result<usize> {
    if file_offset >= extent_size as u64 {
        return Ok(0);
    }
    let available = (extent_size as u64).saturating_sub(file_offset);
    let n = (buffer.len() as u64).min(available) as usize;
    let start = extent_location as u64 * block_size as u64 + file_offset;
    read_exact(device, start, &mut buffer[..n])?;
    Ok(n)
}

/// How many logical blocks the volume says it has.
pub(crate) fn volume_blocks(device: &dyn BlockDevice) -> Result<u32> {
    let mut sector = [0u8; SECTOR_SIZE];
    read_exact(
        device,
        DESCRIPTOR_SET_START * SECTOR_SIZE as u64,
        &mut sector,
    )?;
    super::volume_descriptor::both32(&sector, OFFSET_VOLUME_SPACE_SIZE)
        .map(|(le, _be)| le)
        .ok_or(Error::InvalidArgument)
}

/// Declare the volume to be `blocks` logical blocks long.
///
/// The size is stored twice, little-endian then big-endian, and a reader is
/// free to check either, so both halves move in one write.
pub(crate) fn set_volume_blocks(device: &dyn BlockDevice, blocks: u32) -> Result<()> {
    // The room has to be there in the device's own block size, not the
    // volume's, a volume that claimed blocks the medium does not have would
    // be a volume whose last files cannot be read.
    let needed = blocks as u64 * SECTOR_SIZE as u64;
    let available = device.block_count() * device.block_size() as u64;
    if needed > available {
        return Err(Error::NoSpace);
    }

    let mut field = [0u8; 8];
    field[..4].copy_from_slice(&blocks.to_le_bytes());
    field[4..].copy_from_slice(&blocks.to_be_bytes());
    super::write::write_exact(
        device,
        DESCRIPTOR_SET_START * SECTOR_SIZE as u64 + OFFSET_VOLUME_SPACE_SIZE as u64,
        &field,
    )
}

/// Give back the blocks an extent no longer holds.
///
/// `held` is the size the extent had and `kept` the size it has now; the
/// blocks between them are the ones it gave up.  An extent that was the last
/// thing the volume held can lower the size the volume declares over them, and
/// nothing else has to be consulted: a block past that size belongs to nobody
/// by definition.  That is the one property a volume this driver *cannot*
/// account for still has, which is why this needs no map.
///
/// This is a **tail** rule and only a tail rule: a removal in the middle gives
/// nothing back, because finding what is free in the middle is the map's
/// business, and the map already knows.
pub(crate) fn release_volume_tail(
    device: &dyn BlockDevice,
    block_size: u16,
    floor: u32,
    extent_location: u32,
    held: u32,
    kept: u32,
) -> Result<()> {
    let held_blocks = blocks_of(held, block_size);
    let kept_blocks = blocks_of(kept, block_size);
    if kept_blocks >= held_blocks {
        return Ok(());
    }

    let volume_end = volume_blocks(device)?;
    if extent_location.checked_add(held_blocks) != Some(volume_end) {
        return Ok(());
    }
    // Never below what the image itself declared: the blocks it came with are
    // the image's, whatever a file's record says about them.
    let new_end = extent_location + kept_blocks;
    if new_end < floor {
        return Ok(());
    }
    set_volume_blocks(device, new_end)
}

// what the volume holds

/// The blocks a volume's structures occupy, as sorted, disjoint runs.
///
/// A block is free when nothing in here names it, so what the map has to be is
/// **complete**: a volume with anything this driver cannot account for gives
/// no map at all, and then allocations append, because handing a block to a
/// file that a structure already holds is the one thing that must not happen.
pub struct Occupied {
    runs: Vec<(u32, u32)>,
    /// Whether `runs` is sorted and merged, which is what a gap search needs
    /// and what marking a block breaks.
    settled: bool,
}

impl Occupied {
    fn new() -> Self {
        Self {
            runs: Vec::new(),
            settled: true,
        }
    }

    /// Claim `blocks` logical blocks beginning at `start`.
    fn mark(&mut self, start: u32, blocks: u32) {
        let end = start.saturating_add(blocks);
        if end > start {
            self.runs.push((start, end));
            self.settled = false;
        }
    }

    /// Sort and merge the runs, so that what is free is the gaps between them.
    fn settle(&mut self) {
        if self.settled {
            return;
        }
        self.runs.sort_unstable_by_key(|run| run.0);
        let mut merged: Vec<(u32, u32)> = Vec::with_capacity(self.runs.len());
        for &(start, end) in &self.runs {
            match merged.last_mut() {
                Some(last) if start <= last.1 => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        self.runs = merged;
        self.settled = true;
    }

    /// The first run of `blocks` logical blocks nothing here claims.
    ///
    /// The answer may be past the space the volume declares, which is free by
    /// definition; a caller that takes it has to grow the volume over it.
    fn first_free_run(&mut self, blocks: u32) -> Option<u32> {
        self.settle();
        if blocks == 0 {
            return Some(0);
        }
        let mut at = 0u32;
        for &(start, end) in &self.runs {
            if start.saturating_sub(at) >= blocks {
                return Some(at);
            }
            at = at.max(end);
        }
        at.checked_add(blocks).map(|_| at)
    }
}

/// Where every structure a volume holds is, or an error when this driver
/// cannot account for all of them.
///
/// The structures a well-formed volume can have are a closed list, and every
/// one of them is claimed here, and anything else, from a descriptor this
/// driver does not know to an extended attribute record it does not read,
/// gives an error rather than a map with a hole in it.
pub fn occupied_blocks(device: &dyn BlockDevice, block_size: u16) -> Result<Occupied> {
    if block_size == 0 {
        return Err(Error::InvalidArgument);
    }
    let mut occupied = Occupied::new();
    occupied.mark(0, SYSTEM_AREA_BLOCKS);

    let mut trees: Vec<(Record, bool)> = Vec::new();
    let mut terminated = false;
    for offset in 0..MAX_DESCRIPTORS {
        let sector = DESCRIPTOR_SET_START as u32 + offset;
        let mut bytes = [0u8; SECTOR_SIZE];
        read_exact(
            device,
            u64::from(sector) * u64::from(block_size),
            &mut bytes,
        )?;
        if &bytes[1..6] != super::volume_descriptor::STANDARD_IDENTIFIER || bytes[6] != 0x01 {
            return Err(Error::InvalidArgument);
        }
        occupied.mark(sector, 1);

        match bytes[0] {
            TYPE_TERMINATOR => {
                terminated = true;
                break;
            }
            TYPE_PRIMARY | TYPE_SUPPLEMENTARY => {
                // There is exactly one supplementary descriptor this driver
                // reads, and a volume with another is one whose other tree it
                // cannot account for.
                let joliet = super::volume_descriptor::JOLIET_ESCAPES
                    .iter()
                    .any(|escape| &bytes[88..91] == *escape);
                if bytes[0] == TYPE_SUPPLEMENTARY && !joliet {
                    return Err(Error::Unsupported);
                }
                let Some(descriptor) =
                    super::volume_descriptor::VolumeDescriptor::parse(u64::from(sector), &bytes)
                else {
                    return Err(Error::InvalidArgument);
                };
                mark_path_tables(&mut occupied, block_size, &descriptor);
                let parsed = Record::parse(&descriptor.root_record, 0, joliet);
                let (root, _next) = parsed.ok_or(Error::InvalidArgument)?;
                trees.push((root, joliet));
            }
            TYPE_BOOT => mark_boot_record(&mut occupied, block_size, &bytes),
            _ => return Err(Error::Unsupported),
        }
    }
    if !terminated {
        return Err(Error::InvalidArgument);
    }

    for (root, joliet) in &trees {
        mark_tree(device, block_size, &mut occupied, root, *joliet, 0)?;
    }
    Ok(occupied)
}

/// Claim the path tables a descriptor names, and any optional copies of them.
fn mark_path_tables(
    occupied: &mut Occupied,
    block_size: u16,
    descriptor: &super::volume_descriptor::VolumeDescriptor,
) {
    let blocks = blocks_of(descriptor.path_table_size, block_size);
    for location in [
        descriptor.l_path_table_loc,
        descriptor.m_path_table_loc,
        descriptor.opt_l_path_table_loc,
        descriptor.opt_m_path_table_loc,
    ] {
        if location != 0 {
            occupied.mark(location, blocks);
        }
    }
}

/// Claim the boot catalog a Boot Record names, and the images its entries do.
fn mark_boot_record(occupied: &mut Occupied, block_size: u16, bytes: &[u8; SECTOR_SIZE]) {
    let catalog = u32::from_le_bytes([bytes[71], bytes[72], bytes[73], bytes[74]]);
    if catalog == 0 {
        return;
    }
    occupied.mark(catalog, BOOT_CATALOG_BLOCKS);
    for entry in parse_boot_catalog(bytes) {
        // An entry counts its image in the 512-byte sectors a boot loader
        // reads, not in the volume's logical blocks.
        let image = (u64::from(entry.sector_count) * 512).div_ceil(u64::from(block_size)) as u32;
        occupied.mark(entry.load_rba, image);
    }
}

/// Claim every extent a directory tree names, from its root down.
fn mark_tree(
    device: &dyn BlockDevice,
    block_size: u16,
    occupied: &mut Occupied,
    root: &Record,
    joliet: bool,
    depth: u32,
) -> Result<()> {
    if depth > MAX_TREE_DEPTH {
        return Err(Error::InvalidArgument);
    }
    if root.has_extended_attributes() {
        // The root's own attributes sit in front of the extent below, and what
        // this walk is about to read is not where the record says the entries
        // are.
        return Err(Error::Unsupported);
    }
    // Every record, its own "." and ".." included: those two are records like
    // any other here, and the root's "." is where a volume's extension
    // reference is, whose continuation is a block of its own.
    let records = read_all_records(device, block_size, root.extent, root.data_length, joliet)?;
    occupied.mark(root.extent, blocks_of(root.data_length, block_size));

    for record in &records {
        mark_record(occupied, block_size, record)?;
        // "." is this directory and ".." is its parent: neither is a child,
        // and following them would walk the tree in circles.
        if record.is_directory() && !record.is_dot_entry() && !is_self_or_parent(record) {
            mark_tree(device, block_size, occupied, record, joliet, depth + 1)?;
        }
    }
    Ok(())
}

/// Claim what one record names.
fn mark_record(occupied: &mut Occupied, block_size: u16, record: &Record) -> Result<()> {
    if record.has_extended_attributes() {
        // The attributes sit in front of the data and this driver does not
        // read them, so what the record says is not the whole of what the
        // entry holds.
        return Err(Error::Unsupported);
    }
    occupied.mark(record.extent, blocks_of(record.data_length, block_size));
    mark_continuations(occupied, block_size, &record.system_use);
    Ok(())
}

/// Claim the bytes a record's System Use area says it continues into.
fn mark_continuations(occupied: &mut Occupied, block_size: u16, system_use: &[u8]) {
    let parsed = super::susp::SystemUse::parse(system_use);
    if let Some(continuation) = parsed.continuation {
        // The continuation begins at a byte offset inside that block, so
        // what it takes is however many blocks its bytes fall in.
        let bytes = u64::from(continuation.offset) + u64::from(continuation.length);
        let blocks = bytes.div_ceil(u64::from(block_size)) as u32;
        occupied.mark(continuation.block, blocks);
    }
}

/// The parsed El Torito catalog entry the map claims space for.
struct BootCatalogEntry {
    sector_count: u16,
    load_rba: u32,
}

/// Parse an El Torito catalog's initial and section entries.
///
/// The validation entry is checked, a header id of 1 and the key bytes, and
/// a catalog without it names nothing, which is the same answer the reader's
/// own parser gives.
fn parse_boot_catalog(sector: &[u8]) -> Vec<BootCatalogEntry> {
    if sector.len() < 64 || sector[0] != 0x01 || sector[30] != 0x55 || sector[31] != 0xAA {
        return Vec::new();
    }

    let mut entries = Vec::new();
    let mut pos = 32usize;
    while pos + 32 <= sector.len() {
        let entry_type = sector[pos];
        if entry_type == 0x90 || entry_type == 0x91 {
            // Section header, skip.
            pos += 32;
            continue;
        }
        if entry_type == 0x88 {
            entries.push(BootCatalogEntry {
                sector_count: u16::from_le_bytes([sector[pos + 6], sector[pos + 7]]),
                load_rba: u32::from_le_bytes([
                    sector[pos + 8],
                    sector[pos + 9],
                    sector[pos + 10],
                    sector[pos + 11],
                ]),
            });
        }
        pos += 32;
    }
    entries
}

// the allocator

/// Where a new extent comes from.
///
/// The volume's free blocks are everything its structures do not name, and
/// finding them means walking the whole volume, so it happens once per
/// operation, and the blocks are claimed here as they are handed out.
pub struct Allocator<'a> {
    device: &'a Arc<dyn BlockDevice>,
    block_size: u16,
    /// The volume's structures, when this driver can account for all of them;
    /// `None` is a volume it cannot, and then every allocation appends.
    free: Option<Occupied>,
}

impl<'a> Allocator<'a> {
    /// An allocator for a volume, which hands out the blocks that are free and
    /// appends when it cannot account for what is on the volume.
    pub fn of(device: &'a Arc<dyn BlockDevice>, block_size: u16) -> Self {
        Self {
            device,
            block_size,
            free: occupied_blocks(&**device, block_size).ok(),
        }
    }

    /// Take `blocks` logical blocks, and answer where they are.
    pub fn take(&mut self, blocks: u32) -> Result<u32> {
        let Some(free) = self.free.as_mut() else {
            return allocate_blocks(&**self.device, self.block_size, blocks);
        };
        let start = free.first_free_run(blocks).ok_or(Error::NoSpace)?;
        free.mark(start, blocks);
        // The run may be past the space the volume declares, which is free by
        // definition; taking it means the volume grows over it.
        let end = start.checked_add(blocks).ok_or(Error::NoSpace)?;
        if end > volume_blocks(&**self.device)? {
            set_volume_blocks(&**self.device, end)?;
        }
        Ok(start)
    }
}

/// Take `count` logical blocks for a file, and grow the volume to hold them.
///
/// This is the **fallback** the allocator above uses for a volume whose
/// structures this driver cannot account for: the blocks begin where the
/// volume's declared extent ends, and the one metadata field it moves is the
/// volume's own size.  It never hands out a block the image already wrote,
/// which is what makes it correct without knowing what is on the volume, and
/// what it costs is that nothing in the middle is ever handed out again.
pub(crate) fn allocate_blocks(
    device: &dyn BlockDevice,
    _block_size: u16,
    count: u32,
) -> Result<u32> {
    let first = volume_blocks(device)?;
    if first == 0 {
        // The image never declared its size, so there is no end to append to.
        return Err(Error::NoSpace);
    }
    let end = first.checked_add(count).ok_or(Error::NoSpace)?;

    set_volume_blocks(device, end)?;
    Ok(first)
}

/// Give an extent the blocks `new_size` bytes need, and answer where it is.
///
/// An extent is **one contiguous run**, so there are two ways to make it
/// bigger and this picks by where it is.  When it is the last thing the volume
/// holds, the blocks it needs follow it and the volume grows over them, no
/// copy.  Otherwise something is in the way, and the extent **moves** to the
/// free blocks the allocator gives it: the data first, and the caller writes
/// the record that points at it afterwards, so a crash before that leaves the
/// old record pointing at the old content.
///
/// A size that fits in the blocks the extent already has allocates nothing and
/// moves nothing.
pub(crate) fn place_extent(
    device: &dyn BlockDevice,
    block_size: u16,
    extent_location: u32,
    extent_size: u32,
    new_size: u32,
    allocate: &mut Allocator,
) -> Result<u32> {
    let bs = block_size as u32;
    let old_blocks = extent_size.div_ceil(bs);
    let new_blocks = new_size.div_ceil(bs);
    if new_blocks <= old_blocks {
        return Ok(extent_location);
    }

    let volume_end = volume_blocks(device)?;
    if volume_end != 0 && extent_location + old_blocks == volume_end {
        // The extent is the last thing on the volume: grow the volume over the
        // blocks that follow it, which keeps a crash from leaving a record
        // that claims blocks the volume does not own.
        set_volume_blocks(device, volume_end + (new_blocks - old_blocks))?;
        return Ok(extent_location);
    }

    let first = allocate.take(new_blocks)?;
    if extent_size > 0 {
        let mut data = vec![0u8; extent_size as usize];
        read_extent_bytes(
            device,
            block_size,
            extent_location,
            extent_size,
            0,
            &mut data,
        )?;
        super::write::write_extent(device, block_size, first, new_size, 0, &data)?;
    }
    Ok(first)
}
