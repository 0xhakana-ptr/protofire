//! fs/src/exfat/types.rs
//!
//! exFAT's on-disk types: the boot region parsed and checksummed, the
//! directory entry type codes, the file/stream/filename triplet a file is
//! made of, and the little-endian helpers the parsers share.
//!
//! Every multi-byte field is little-endian, and the boot region's checksum
//! — the unsigned sum of its first eleven sectors, stored in the twelfth —
//! is what makes a volume's boot block the volume's own rather than a
//! payload that happens to parse.

use alloc::string::String;

use block::BLOCK_SIZE;

use crate::types::NodeKind;

use abi::Error;
use abi::Result;

/// The first data cluster: cluster 2, by FAT32's own convention.
pub(super) const FIRST_DATA_CLUSTER: u32 = 2;

/// The end-of-chain marker for the 32-bit FAT entries.
pub(super) const FAT32_EOC: u32 = 0xFFFF_FFFF;

/// A directory entry's size, thirty-two bytes.
pub(super) const DIR_ENTRY_SIZE: usize = 32;

/// The safety cap on a directory listing's entries.
pub(super) const MAX_DIR_ENTRIES: usize = 4096;

// Directory entry type codes.

/// End of directory — no entries beyond this point.
pub(super) const EXFAT_ENTRY_EOD: u8 = 0x00;
/// Allocation bitmap entry (primary).
pub(super) const EXFAT_ENTRY_BITMAP: u8 = 0x81;
/// Up-case table entry (primary).
pub(super) const EXFAT_ENTRY_UPCASE: u8 = 0x82;
/// File entry (primary) — always followed by a stream extension and
/// filename entries.
pub(super) const EXFAT_ENTRY_FILE: u8 = 0x85;
/// Stream extension entry (secondary).
pub(super) const EXFAT_ENTRY_STREAM: u8 = 0xC0;
/// File name extension entry (secondary).
pub(super) const EXFAT_ENTRY_FILENAME: u8 = 0xC1;

/// The in-use bit of an entry's type byte.
pub(super) const ENTRY_INUSE_MASK: u8 = 0x80;

/// File attribute bits, in the File entry at offset 4.
pub(super) const EXFAT_ATTR_DIRECTORY: u16 = 0x0010;
pub(super) const EXFAT_ATTR_ARCHIVE: u16 = 0x0020;

/// The boot signature's offset, bytes 510–511.
pub(super) const BOOT_SIGNATURE_OFFSET: usize = 510;

/// The boot region's sector count, main and backup alike.
pub(super) const BOOT_REGION_SECTORS: usize = 12;

// Boot-sector field offsets.

pub(super) const B_OEM_NAME: usize = 0x03;
#[cfg_attr(not(test), allow(dead_code))]
pub(super) const B_VOLUME_LENGTH: usize = 0x48;
pub(super) const B_FAT_OFFSET: usize = 0x50;
pub(super) const B_FAT_LENGTH: usize = 0x54;
pub(super) const B_CLUSTER_HEAP_OFFSET: usize = 0x58;
pub(super) const B_CLUSTER_COUNT: usize = 0x5C;
pub(super) const B_ROOT_DIR_CLUSTER: usize = 0x60;
#[cfg_attr(not(test), allow(dead_code))]
pub(super) const B_VOLUME_SERIAL: usize = 0x64;
#[cfg_attr(not(test), allow(dead_code))]
pub(super) const B_FS_REVISION: usize = 0x68;
#[cfg_attr(not(test), allow(dead_code))]
pub(super) const B_VOLUME_FLAGS: usize = 0x6A;
pub(super) const B_BYTES_PER_SECTOR_SHIFT: usize = 0x6C;
pub(super) const B_SECTORS_PER_CLUSTER_SHIFT: usize = 0x6D;
pub(super) const B_NUM_FATS: usize = 0x6E;
/// The checksum lives in sector 11 of the boot region, at this offset.
pub(super) const B_CHECKSUM_SECTOR: usize = 11;
pub(super) const B_CHECKSUM_OFFSET: usize = 0x1FC;

// File entry field offsets (type 0x85).

pub(super) const F_ATTR: usize = 4;
pub(super) const F_CREATE_TIME: usize = 8;
pub(super) const F_MODIFY_TIME: usize = 12;
pub(super) const F_ACCESS_TIME: usize = 16;

// Stream extension field offsets (type 0xC0).

pub(super) const S_FLAGS: usize = 1;
/// The flag bit whose file is one contiguous run, no FAT chain.
pub(super) const S_FLAG_NO_FAT_CHAIN: u8 = 0x02;
pub(super) const S_NAME_LENGTH: usize = 3;
pub(super) const S_VALID_DATA_LEN: usize = 12;
pub(super) const S_FIRST_CLUSTER: usize = 20;
pub(super) const S_DATA_LEN: usize = 24;

// File name extension field offsets (type 0xC1).

/// The fifteen UTF-16LE code units each filename entry carries.
pub(super) const FN_NAME_START: usize = 2;
pub(super) const FN_CHARS_PER_ENTRY: usize = 15;

// ── the boot region ──────────────────────────────────────────────────────

/// A parsed boot region: the geometry the whole driver's addressing is
/// built from.
#[derive(Debug, Clone)]
pub(super) struct ExfatBootRegion {
    /// Sectors per cluster: two to the shift the boot sector carries.
    pub(super) sectors_per_cluster: u8,
    pub(super) fat_offset: u32,
    pub(super) cluster_heap_offset: u32,
    pub(super) cluster_count: u32,
    pub(super) root_dir_cluster: u32,
    pub(super) cluster_size_bytes: u32,
}

impl ExfatBootRegion {
    /// Parse the boot region from twelve sectors, validating the signature,
    /// the type string, and the checksum.
    pub(super) fn parse(data: &[u8; BLOCK_SIZE * BOOT_REGION_SECTORS]) -> Result<Self> {
        if data[BOOT_SIGNATURE_OFFSET] != 0x55 || data[BOOT_SIGNATURE_OFFSET + 1] != 0xAA {
            return Err(Error::InvalidArgument);
        }

        let oem = &data[B_OEM_NAME..B_OEM_NAME + 8];
        if oem != b"EXFAT   " {
            return Err(Error::InvalidArgument);
        }

        // The checksum over sectors 0–10 lives at 0x1FC of sector 11.
        let cs_sector_offset = B_CHECKSUM_SECTOR * BLOCK_SIZE + B_CHECKSUM_OFFSET;
        let stored_checksum = read_u32_le(data, cs_sector_offset);
        let computed = boot_checksum(data);
        if stored_checksum != computed {
            return Err(Error::InvalidArgument);
        }

        let bytes_per_sector_shift = data[B_BYTES_PER_SECTOR_SHIFT];
        let sectors_per_cluster_shift = data[B_SECTORS_PER_CLUSTER_SHIFT];
        let num_fats = data[B_NUM_FATS];
        let fat_offset = read_u32_le(data, B_FAT_OFFSET);
        let fat_length = read_u32_le(data, B_FAT_LENGTH);
        let cluster_heap_offset = read_u32_le(data, B_CLUSTER_HEAP_OFFSET);
        let cluster_count = read_u32_le(data, B_CLUSTER_COUNT);
        let root_dir_cluster = read_u32_le(data, B_ROOT_DIR_CLUSTER);

        // The sector size must be 512: the block-level arithmetic below is
        // written in the device's own sectors.
        if bytes_per_sector_shift != 9 {
            return Err(Error::Unsupported);
        }
        let bytes_per_sector: u16 = 1 << bytes_per_sector_shift;

        if sectors_per_cluster_shift > 24 {
            return Err(Error::InvalidArgument);
        }
        let sectors_per_cluster: u32 = 1u32 << sectors_per_cluster_shift;
        let cluster_size_bytes = sectors_per_cluster * bytes_per_sector as u32;

        if num_fats == 0 || num_fats > 2 {
            return Err(Error::InvalidArgument);
        }
        if fat_offset == 0 || fat_length == 0 {
            return Err(Error::InvalidArgument);
        }
        if cluster_count < 2 {
            return Err(Error::InvalidArgument);
        }
        if root_dir_cluster < FIRST_DATA_CLUSTER
            || root_dir_cluster >= FIRST_DATA_CLUSTER + cluster_count
        {
            return Err(Error::InvalidArgument);
        }

        Ok(Self {
            sectors_per_cluster: sectors_per_cluster as u8,
            fat_offset,
            cluster_heap_offset,
            cluster_count,
            root_dir_cluster,
            cluster_size_bytes,
        })
    }

    /// A cluster number's starting LBA.
    pub(super) fn cluster_to_lba(&self, cluster: u32) -> u64 {
        let sectors_per_cluster = self.sectors_per_cluster as u64;
        let heap_start_sector = self.cluster_heap_offset as u64;
        let cluster_index = (cluster - FIRST_DATA_CLUSTER) as u64;
        heap_start_sector + cluster_index * sectors_per_cluster
    }

    /// A FAT sector offset's LBA.
    pub(super) fn offset_to_lba(&self, sector_offset: u32) -> u64 {
        sector_offset as u64
    }
}

/// The boot checksum: the unsigned sum of every byte in sectors 0–10.
pub(super) fn boot_checksum(data: &[u8; BLOCK_SIZE * BOOT_REGION_SECTORS]) -> u32 {
    let checksum_range_end = BLOCK_SIZE * B_CHECKSUM_SECTOR;
    let mut sum: u32 = 0;
    for &b in &data[..checksum_range_end] {
        sum = sum.wrapping_add(b as u32);
    }
    sum
}

// ── directory entries ────────────────────────────────────────────────────

/// A parsed directory entry: a file or a directory.
#[derive(Debug, Clone)]
pub(super) struct ExfatDirEntry {
    pub(super) name: String,
    pub(super) kind: NodeKind,
    /// First cluster of the data stream; zero for an empty file.
    pub(super) first_cluster: u32,
    /// The bytes the file actually holds.
    pub(super) valid_data_length: u64,
    /// The bytes allocated to it.
    pub(super) data_length: u64,
    /// Whether the stream is one contiguous run — no FAT chain.
    pub(super) no_fat_chain: bool,
    pub(super) created: u64,
    pub(super) modified: u64,
    pub(super) accessed: u64,
}

/// An exFAT timestamp to Unix epoch seconds: the same DOS date/time
/// bitfields as FAT32's, packed into one word.
pub(super) fn dos_timestamp_to_unix(ts: u32) -> u64 {
    if ts == 0 {
        return 0;
    }
    let time = (ts & 0xFFFF) as u16;
    let date = ((ts >> 16) & 0xFFFF) as u16;
    crate::fat32::types::dos_datetime_to_unix(date, time)
}

// ── little-endian helpers ────────────────────────────────────────────────

pub(super) fn read_u16_le(data: &[u8], offset: usize) -> u16 {
    if offset + 2 > data.len() {
        return 0;
    }
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

pub(super) fn read_u32_le(data: &[u8], offset: usize) -> u32 {
    if offset + 4 > data.len() {
        return 0;
    }
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

#[cfg_attr(not(test), allow(dead_code))]
pub(super) fn write_u64_le(data: &mut [u8], offset: usize, val: u64) {
    write_u32_le(data, offset, val as u32);
    write_u32_le(data, offset + 4, (val >> 32) as u32);
}

pub(super) fn write_u16_le(data: &mut [u8], offset: usize, val: u16) {
    if offset + 2 <= data.len() {
        let bytes = val.to_le_bytes();
        data[offset] = bytes[0];
        data[offset + 1] = bytes[1];
    }
}

pub(super) fn write_u32_le(data: &mut [u8], offset: usize, val: u32) {
    if offset + 4 <= data.len() {
        let bytes = val.to_le_bytes();
        data[offset] = bytes[0];
        data[offset + 1] = bytes[1];
        data[offset + 2] = bytes[2];
        data[offset + 3] = bytes[3];
    }
}

// ── entry type classification ────────────────────────────────────────────

/// An entry type byte, classified: whether it is a secondary entry, and
/// its code — the five low bits of the raw byte.
#[derive(Debug, Clone, Copy)]
pub(super) struct ExfatEntryType {
    pub(super) _is_secondary: bool,
    pub(super) type_code: u8,
}

impl ExfatEntryType {
    /// Classify a raw type byte: secondary entries carry bit 6.
    pub(super) fn from_byte(raw: u8) -> Self {
        let type_code = raw & 0x1F;
        let is_secondary = raw & 0x40 != 0;

        ExfatEntryType {
            _is_secondary: is_secondary,
            type_code,
        }
    }
}
