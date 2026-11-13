//! fs/src/fat32/types.rs
//!
//! FAT12/16/32's on-disk types: the BPB geometry parsed from the boot
//! sector, the FAT type classification, directory entry parsing and
//! serialisation — 8.3 short names, LFN fragments, and the entry sets a
//! create builds — and the DOS date arithmetic the timestamps ride on.
//!
//! Every multi-byte field is little-endian on the disk, and the format's
//! own quirks are its own: 12-bit entries packed two into three bytes, a
//! cluster count that decides the FAT type, and LFN entries recognised by
//! an attribute combination that would be illegal for a real file.

use alloc::string::String;
use alloc::vec::Vec;

use block::BLOCK_SIZE;
use unicode::OemCodePage;

use crate::types::NodeKind;

use abi::Error;
use abi::Result;

// ── the FAT family ───────────────────────────────────────────────────────

/// The FAT type, decided by the data cluster count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FatType {
    /// FAT12 — fewer than 4085 data clusters.
    Fat12,
    /// FAT16 — 4085 to 65524.
    Fat16,
    /// FAT32 — 65525 or more.
    Fat32,
}

impl FatType {
    /// The end-of-cluster-chain minimum value, inclusive.
    pub(super) fn eoc_min(self) -> u32 {
        match self {
            FatType::Fat12 => 0xFF8,
            FatType::Fat16 => 0xFFF8,
            FatType::Fat32 => 0x0FFF_FFF8,
        }
    }

    /// The mask applied to a FAT entry before the EOC comparison.
    pub(super) fn eoc_mask(self) -> u32 {
        match self {
            FatType::Fat12 => 0xFFF,
            FatType::Fat16 => 0xFFFF,
            FatType::Fat32 => 0x0FFF_FFFF,
        }
    }

    /// The volume name's label for the type.
    pub(super) fn label(self) -> &'static str {
        match self {
            FatType::Fat12 => "fat12",
            FatType::Fat16 => "fat16",
            FatType::Fat32 => "fat32",
        }
    }
}

/// The first data cluster: cluster 2, by the format's own numbering.
pub(super) const FIRST_DATA_CLUSTER: u32 = 2;

/// Directory entry attribute bits.
pub(super) const ATTR_READ_ONLY: u8 = 0x01;
pub(super) const ATTR_HIDDEN: u8 = 0x02;
pub(super) const ATTR_SYSTEM: u8 = 0x04;
pub(super) const ATTR_VOLUME_ID: u8 = 0x08;
pub(super) const ATTR_DIRECTORY: u8 = 0x10;
#[allow(dead_code)] // the format's own bit; this driver never sets it
pub(super) const ATTR_ARCHIVE: u8 = 0x20;
/// The attribute combination an LFN entry carries — illegal for a real
/// file, which is how every OS detects one.
pub(super) const ATTR_LFN_MASK: u8 = ATTR_READ_ONLY | ATTR_HIDDEN | ATTR_SYSTEM | ATTR_VOLUME_ID;

/// A directory entry's size, thirty-two bytes.
pub(super) const DIR_ENTRY_SIZE: usize = 32;

// ── the BPB ──────────────────────────────────────────────────────────────

/// BPB field offsets in the boot sector.
pub(super) const BPB_BYTES_PER_SECTOR: usize = 11;
pub(super) const BPB_SECTORS_PER_CLUSTER: usize = 13;
pub(super) const BPB_RESERVED_SECTORS: usize = 14;
pub(super) const BPB_NUM_FATS: usize = 16;
pub(super) const BPB_ROOT_ENTRIES: usize = 17;
pub(super) const BPB_TOTAL_SECTORS_16: usize = 19;
pub(super) const BPB_SECTORS_PER_FAT_16: usize = 22;
pub(super) const BPB_TOTAL_SECTORS_32: usize = 32;
pub(super) const BPB_SECTORS_PER_FAT_32: usize = 36;
pub(super) const BPB_ROOT_CLUSTER: usize = 44;
pub(super) const BPB_FSINFO_SECTOR: usize = 48;
pub(super) const BPB_BACKUP_BOOT_SECTOR: usize = 50;
pub(super) const BPB_FS_TYPE: usize = 82;

// The FSInfo structure's signatures and offsets.

pub(super) const FSINFO_LEAD_SIGNATURE: u32 = 0x4161_5252;
pub(super) const FSINFO_LEAD_OFFSET: usize = 0;
pub(super) const FSINFO_STRUCT_OFFSET: usize = 484;
pub(super) const FSINFO_STRUCT_SIGNATURE: u32 = 0x6141_7272;
pub(super) const FSINFO_FREE_COUNT_OFFSET: usize = 488;
pub(super) const FSINFO_NEXT_FREE_OFFSET: usize = 492;
pub(super) const FSINFO_TRAIL_SIGNATURE: [u8; 2] = [0x55, 0xAA];
pub(super) const FSINFO_UNKNOWN: u32 = 0xFFFF_FFFF;

// ── the geometry ─────────────────────────────────────────────────────────

/// The volume's geometry, parsed from the BPB: where the FAT tables sit,
/// where the data area starts, and how many clusters it holds.
#[derive(Debug, Clone)]
pub(super) struct FatGeometry {
    pub(super) fat_type: FatType,
    pub(super) bytes_per_sector: u16,
    pub(super) sectors_per_cluster: u8,
    pub(super) num_fats: u8,
    pub(super) sectors_per_fat: u32,
    /// FAT32's root directory cluster; zero for FAT12/16.
    pub(super) root_cluster: u32,
    /// FAT32's FSInfo sector; zero for FAT12/16 or when absent.
    pub(super) fsinfo_sector: u16,
    pub(super) backup_boot_sector: u16,
    pub(super) cluster_size_bytes: u32,
    pub(super) fat_start_lba: u64,
    /// Where cluster 2 begins.
    pub(super) data_start_lba: u64,
    /// FAT12/16's fixed root directory region.
    pub(super) root_dir_lba: u64,
    pub(super) root_dir_sectors: u64,
    pub(super) data_cluster_count: u32,
}

impl FatGeometry {
    /// Parse the BPB from the boot sector's first 512 bytes.
    ///
    /// The FAT type prefers the FS-type string the formatter wrote and
    /// falls back to the cluster-count heuristic for the legacy "FAT"
    /// spelling.
    pub(super) fn from_boot_sector(data: &[u8; BLOCK_SIZE]) -> Result<Self> {
        let bytes_per_sector = read_u16(data, BPB_BYTES_PER_SECTOR);
        let sectors_per_cluster = data[BPB_SECTORS_PER_CLUSTER];
        let reserved_sectors = read_u16(data, BPB_RESERVED_SECTORS);
        let num_fats = data[BPB_NUM_FATS];
        let root_entries = read_u16(data, BPB_ROOT_ENTRIES);
        let sectors_per_fat_16 = read_u16(data, BPB_SECTORS_PER_FAT_16);
        let total_sectors_16 = read_u16(data, BPB_TOTAL_SECTORS_16);
        let total_sectors_32 = read_u32(data, BPB_TOTAL_SECTORS_32);
        let sectors_per_fat_32 = read_u32(data, BPB_SECTORS_PER_FAT_32);
        let root_cluster = read_u32(data, BPB_ROOT_CLUSTER);
        let fsinfo_sector = read_u16(data, BPB_FSINFO_SECTOR);
        let backup_boot_sector = read_u16(data, BPB_BACKUP_BOOT_SECTOR);

        if bytes_per_sector != 512 {
            return Err(Error::Unsupported);
        }
        if sectors_per_cluster == 0 || !sectors_per_cluster.is_power_of_two() {
            return Err(Error::InvalidArgument);
        }
        if num_fats == 0 || num_fats > 4 {
            return Err(Error::InvalidArgument);
        }

        let sectors_per_fat = if sectors_per_fat_32 != 0 {
            sectors_per_fat_32
        } else {
            sectors_per_fat_16 as u32
        };
        let total_sectors = if total_sectors_32 != 0 {
            total_sectors_32
        } else {
            total_sectors_16 as u32
        };

        if sectors_per_fat == 0 || total_sectors == 0 {
            return Err(Error::InvalidArgument);
        }

        let fs_type_raw = &data[BPB_FS_TYPE..BPB_FS_TYPE + 8];
        let fs_type = core::str::from_utf8(fs_type_raw).unwrap_or("");
        if !(fs_type.starts_with("FAT32")
            || fs_type.starts_with("FAT16")
            || fs_type.starts_with("FAT12")
            || fs_type.starts_with("FAT     "))
        {
            return Err(Error::Unsupported);
        }

        let fat_start_lba = reserved_sectors as u64;
        let fat_size_blocks = sectors_per_fat as u64 * num_fats as u64;

        // FAT12/16's root directory is a fixed region between the FAT
        // tables and the data area; FAT32's is a cluster chain.
        let root_dir_sectors =
            (root_entries as u64 * DIR_ENTRY_SIZE as u64).div_ceil(bytes_per_sector as u64);
        let root_dir_lba = fat_start_lba + fat_size_blocks;
        let data_start_lba = root_dir_lba + root_dir_sectors;
        let cluster_size_bytes = sectors_per_cluster as u32 * bytes_per_sector as u32;

        let data_sectors =
            total_sectors as u64 - reserved_sectors as u64 - fat_size_blocks - root_dir_sectors;
        let data_cluster_count = (data_sectors / sectors_per_cluster as u64) as u32;

        let fat_type = if fs_type.starts_with("FAT32") {
            FatType::Fat32
        } else if fs_type.starts_with("FAT16") || (4085..65525).contains(&data_cluster_count) {
            FatType::Fat16
        } else {
            FatType::Fat12
        };

        Ok(Self {
            fat_type,
            bytes_per_sector,
            sectors_per_cluster,
            num_fats,
            sectors_per_fat,
            root_cluster,
            fsinfo_sector,
            backup_boot_sector,
            cluster_size_bytes,
            fat_start_lba,
            data_start_lba,
            root_dir_lba,
            root_dir_sectors,
            data_cluster_count,
        })
    }

    /// A cluster number's starting LBA.
    pub(super) fn cluster_to_lba(&self, cluster: u32) -> u64 {
        self.data_start_lba
            + (cluster as u64 - FIRST_DATA_CLUSTER as u64) * self.sectors_per_cluster as u64
    }
}

// ── little-endian reads ──────────────────────────────────────────────────

pub(super) fn read_u16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

pub(super) fn read_u32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

// ── DOS dates ────────────────────────────────────────────────────────────

/// A DOS date+time pair, in Unix epoch seconds.
///
/// The date field's year counts from 1980, its month is 1-based, and its
/// time field's seconds are halved — a zero date means "unset" and answers
/// zero rather than a fabricated epoch.
pub(super) fn dos_datetime_to_unix(date: u16, time: u16) -> u64 {
    if date == 0 {
        return 0;
    }
    let year = ((date >> 9) & 0x7F) as u32 + 1980;
    let month = ((date >> 5) & 0x0F) as u32;
    let day = (date & 0x1F) as u32;
    let hour = ((time >> 11) & 0x1F) as u32;
    let min = ((time >> 5) & 0x3F) as u32;
    let sec = ((time & 0x1F) * 2) as u32;

    let days = days_since_epoch(year, month, day);
    (days as u64) * 86400 + hour as u64 * 3600 + min as u64 * 60 + sec as u64
}

/// A DOS date with midnight implied.
pub(super) fn dos_date_to_unix(date: u16) -> u64 {
    dos_datetime_to_unix(date, 0)
}

/// Days since 1970-01-01, by the March-based year the civil-calendar
/// arithmetic uses so February is the last month.
fn days_since_epoch(year: u32, month: u32, day: u32) -> u32 {
    let y = year as i64;
    let m = month as i64;
    let d = day as i64;

    let y_adj = if m <= 2 { y - 1 } else { y };
    let m_adj = if m <= 2 { m + 12 } else { m };
    let era = if y_adj >= 0 {
        y_adj / 400
    } else {
        (y_adj / 400) - 1
    };
    let yoe = (y_adj - era * 400) as u32;
    let doy = (153 * (m_adj as u32 - 3) + 2) / 5 + d as u32 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era as u32 * 146097 + doe - 719468
}

// ── directory entries ────────────────────────────────────────────────────

/// A parsed directory entry.
#[derive(Debug, Clone)]
pub(super) struct FatDirEntry {
    pub(super) name: String,
    pub(super) kind: NodeKind,
    pub(super) first_cluster: u32,
    pub(super) file_size: u32,
    pub(super) created: u64,
    pub(super) modified: u64,
    pub(super) accessed: u64,
}

/// Parse one 32-byte directory entry, answering `None` for the deleted,
/// the volume-label and the LFN entries — the LFN fragments are the
/// caller's to collect.
pub(super) fn parse_short_dir_entry(data: &[u8], code_page: OemCodePage) -> Option<FatDirEntry> {
    if data.len() < DIR_ENTRY_SIZE {
        return None;
    }

    let first_byte = data[0];
    if first_byte == 0x00 || first_byte == 0xE5 {
        return None;
    }

    let attr = data[11];
    if attr == ATTR_LFN_MASK {
        return None;
    }
    if attr & 0x08 != 0 {
        return None;
    }

    let name = parse_short_name(&data[0..11], code_page);

    let kind = if attr & ATTR_DIRECTORY != 0 {
        NodeKind::Directory
    } else {
        NodeKind::File
    };

    let first_cluster = read_u16(data, 26) as u32 | ((read_u16(data, 20) as u32) << 16);
    let file_size = read_u32(data, 28);

    let create_time = read_u16(data, 14);
    let create_date = read_u16(data, 16);
    let access_date = read_u16(data, 18);
    let modify_time = read_u16(data, 22);
    let modify_date = read_u16(data, 24);

    Some(FatDirEntry {
        name,
        kind,
        first_cluster,
        file_size,
        created: dos_datetime_to_unix(create_date, create_time),
        modified: dos_datetime_to_unix(modify_date, modify_time),
        accessed: dos_date_to_unix(access_date),
    })
}

/// Parse an 8.3 short name: ASCII graphic bytes lowercased per FAT's
/// case-insensitive convention, high bytes decoded through the OEM code
/// page and Unicode-folded.
pub(super) fn parse_short_name(raw: &[u8], code_page: OemCodePage) -> String {
    let name_part = &raw[0..8];
    let ext_part = &raw[8..11];

    let name_end = name_part
        .iter()
        .position(|&b| b == b' ')
        .unwrap_or(name_part.len());
    let ext_end = ext_part
        .iter()
        .position(|&b| b == b' ')
        .unwrap_or(ext_part.len());

    let mut name = String::new();
    for &b in &name_part[..name_end] {
        push_oem_byte_lower(b, code_page, &mut name);
    }
    if ext_end > 0 {
        name.push('.');
        for &b in &ext_part[..ext_end] {
            push_oem_byte_lower(b, code_page, &mut name);
        }
    }
    name
}

/// One OEM byte, lowercased: ASCII graphic bytes directly, high bytes
/// through the code page and a Unicode fold, control characters through
/// as the replacement characters they should never have been.
fn push_oem_byte_lower(byte: u8, code_page: OemCodePage, name: &mut String) {
    if byte.is_ascii_graphic() {
        name.push(byte.to_ascii_lowercase() as char);
    } else if byte >= 0x80 {
        let ch = unicode::oem_byte_to_char(byte, code_page);
        for lower in ch.to_lowercase() {
            name.push(lower);
        }
    } else {
        name.push(byte as char);
    }
}

/// Try to parse an LFN fragment, answering its sequence metadata and the
/// thirteen UTF-16 code units the entry carries at its three fixed groups.
pub(super) fn parse_lfn_fragment(data: &[u8]) -> Option<(u8, [u16; 13])> {
    if data.len() < DIR_ENTRY_SIZE {
        return None;
    }
    if data[11] != ATTR_LFN_MASK {
        return None;
    }
    let seq = data[0];
    let last = (seq & 0x40) != 0;
    let seq_num = seq & 0x1F;

    let mut code_units = [0u16; 13];
    let mut idx = 0;

    for off in [1, 3, 5, 7, 9] {
        let cu = read_u16(data, off);
        if cu != 0 {
            code_units[idx] = cu;
            idx += 1;
        }
    }
    for off in [14, 16, 18, 20, 22, 24] {
        let cu = read_u16(data, off);
        if cu != 0 {
            code_units[idx] = cu;
            idx += 1;
        }
    }
    for off in [28, 30] {
        let cu = read_u16(data, off);
        if cu != 0 {
            code_units[idx] = cu;
            idx += 1;
        }
    }

    Some(((if last { 0x80 } else { 0 }) | seq_num, code_units))
}

/// Build a long name from the collected LFN fragments — reverse order, the
/// fragments stored last-first — decoded through the UTF-16 converter so
/// surrogate pairs land.
pub(super) fn build_lfn_name(fragments: &[(u8, [u16; 13])]) -> String {
    let mut code_units: Vec<u16> = Vec::new();
    for &(_seq, units) in fragments.iter().rev() {
        for &cu in &units {
            if cu == 0 {
                break;
            }
            code_units.push(cu);
        }
    }
    unicode::utf16le_to_utf8(&code_units)
}

// ── the write path's serialisation ───────────────────────────────────────

/// The LFN checksum over an 11-byte short name.
pub(super) fn lfn_checksum(short_name: &[u8; 11]) -> u8 {
    let mut sum: u8 = 0;
    for &byte in short_name.iter() {
        sum = sum
            .wrapping_shr(1)
            .wrapping_add(sum << 7)
            .wrapping_add(byte);
    }
    sum
}

/// Generate an 8.3 short name from a long one: up to six kept characters,
/// a `~1` suffix when the name needs one, and the extension's first three
/// characters — unmappable characters become underscores.
pub(super) fn generate_short_name(long_name: &str, code_page: OemCodePage) -> [u8; 11] {
    let mut short = [b' '; 11];

    let (stem, ext) = match long_name.rfind('.') {
        Some(dot) => (&long_name[..dot], &long_name[dot + 1..]),
        None => (long_name, ""),
    };

    let stem_bytes = unicode::utf8_to_oem(stem, code_page);
    let stem_chars: Vec<u8> = stem_bytes
        .iter()
        .filter_map(|&b| {
            if b.is_ascii_alphanumeric() || b == b'_' || b == b'-' {
                Some(b.to_ascii_uppercase())
            } else if b >= 0x80 {
                Some(b)
            } else if b == b'?' {
                Some(b'_')
            } else {
                None
            }
        })
        .take(8)
        .collect();

    let need_tilde = stem_chars.len() > 6 || stem.len() > 8 || !ext.is_empty();
    let stem_len = if need_tilde {
        let n = stem_chars.len().min(6);
        for (i, &c) in stem_chars[..n].iter().enumerate() {
            short[i] = c;
        }
        short[6] = b'~';
        short[7] = b'1';
        8
    } else {
        for (i, &c) in stem_chars.iter().enumerate() {
            short[i] = c;
        }
        stem_chars.len()
    };

    let ext_bytes = unicode::utf8_to_oem(ext, code_page);
    let ext_chars: Vec<u8> = ext_bytes
        .iter()
        .filter_map(|&b| {
            if b.is_ascii_alphanumeric() {
                Some(b.to_ascii_uppercase())
            } else if b >= 0x80 {
                Some(b)
            } else if b == b'?' {
                Some(b'_')
            } else {
                None
            }
        })
        .take(3)
        .collect();
    for (i, &c) in ext_chars.iter().enumerate() {
        short[8 + i] = c;
    }
    let _ = stem_len;

    short
}

/// Write an LFN entry's thirty-two bytes.
pub(super) fn write_lfn_entry(
    buf: &mut [u8],
    offset: usize,
    seq_num: u8,
    is_last: bool,
    chars: &[u16; 13],
    checksum: u8,
) {
    let entry = &mut buf[offset..offset + 32];
    entry.fill(0);
    let seq = (seq_num & 0x1F) | if is_last { 0x40 } else { 0 };
    entry[0] = seq;
    entry[11] = 0x0F;
    entry[12] = 0x00;
    entry[13] = checksum;

    // The thirteen code units, across the entry's three fixed groups.
    unicode::write_utf16le_chars(entry, 1, &chars[0..5], 5);
    unicode::write_utf16le_chars(entry, 14, &chars[5..11], 6);
    unicode::write_utf16le_chars(entry, 28, &chars[11..13], 2);
}

/// Write a standard 8.3 directory entry's thirty-two bytes.
pub(super) fn write_short_entry(
    buf: &mut [u8],
    offset: usize,
    short_name: &[u8; 11],
    attrs: u8,
    first_cluster: u32,
    file_size: u32,
) {
    let entry = &mut buf[offset..offset + 32];
    entry.fill(0);
    entry[0..11].copy_from_slice(short_name);
    entry[11] = attrs;
    entry[20] = (first_cluster >> 16) as u8;
    entry[21] = (first_cluster >> 24) as u8;
    entry[26] = first_cluster as u8;
    entry[27] = (first_cluster >> 8) as u8;
    entry[28] = file_size as u8;
    entry[29] = (file_size >> 8) as u8;
    entry[30] = (file_size >> 16) as u8;
    entry[31] = (file_size >> 24) as u8;
}

/// Build the raw bytes of a directory entry set — LFN entries, then the
/// short entry — answering how many entries were written.
pub(super) fn build_dir_entry_set(
    raw: &mut [u8],
    name: &str,
    attrs: u8,
    first_cluster: u32,
    file_size: u32,
    code_page: OemCodePage,
) -> usize {
    let short_name = generate_short_name(name, code_page);
    let checksum = lfn_checksum(&short_name);

    let name_utf16 = unicode::utf8_to_utf16le(name);
    let name_len = name_utf16.len();

    if name_len == 0 {
        write_short_entry(raw, 0, &short_name, attrs, first_cluster, file_size);
        return 1;
    }

    let lfn_entries_needed = name_len.div_ceil(13);
    let total_entries = lfn_entries_needed + 1;

    // The fragments go in reverse: the highest sequence number first, so
    // fragment zero holds the name's last thirteen characters.
    for frag_idx in 0..lfn_entries_needed {
        let seq_num = (lfn_entries_needed - frag_idx) as u8;
        let is_last = frag_idx == 0;
        let seg_idx = lfn_entries_needed - 1 - frag_idx;
        let char_start = seg_idx * 13;
        let char_end = (char_start + 13).min(name_len);
        let mut chars = [0u16; 13];
        for (i, &ch) in name_utf16[char_start..char_end].iter().enumerate() {
            chars[i] = ch;
        }
        write_lfn_entry(raw, frag_idx * 32, seq_num, is_last, &chars, checksum);
    }

    let short_offset = lfn_entries_needed * 32;
    write_short_entry(
        raw,
        short_offset,
        &short_name,
        attrs,
        first_cluster,
        file_size,
    );

    total_entries
}

/// Insert a directory entry set into raw directory bytes, shifting the
/// entries after it down.
pub(super) fn insert_dir_entry_set(
    raw: &mut Vec<u8>,
    insert_offset: usize,
    num_entries: usize,
    entry_set_data: &[u8],
) {
    let needed = num_entries * DIR_ENTRY_SIZE;
    let old_len = raw.len();
    let new_len = old_len + needed;

    raw.resize(new_len, 0);
    raw.copy_within(insert_offset..old_len, insert_offset + needed);
    raw[insert_offset..insert_offset + needed].copy_from_slice(&entry_set_data[..needed]);
}
