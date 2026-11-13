//! fs/src/xfs/types.rs
//!
//! XFS's on-disk structures, big-endian on the disk — the opposite endianness
//! from every other format this crate reads, which is why the byte-order
//! helpers live here and the parsers never spell `from_be_bytes` twice.
//!
//! Two on-disk generations are read: v4 and the CRC-enabled v5, whose
//! superblock, inode, and B+tree blocks each carry their extra header
//! fields.  The generation is the superblock's own fact, and every
//! offset-dependent reader asks it rather than guessing.

use alloc::vec::Vec;

/// The magic a superblock answers with: "XFSB".
pub(super) const XFS_SUPER_MAGIC: u32 = 0x5846_5342;

/// v5 ("CRC-enabled") superblock: bit 3 of `sb_versionnum`.
pub(super) const XFS_SB_VERSION_5: u16 = 0x0008;

/// Where the data fork starts within an inode buffer: byte 100 for v4
/// (after `di_next_unlinked`), 176 for v5 (after the CRC and LSN fields
/// v5 adds).
pub(super) const XFS_INODE_DATA_FORK_OFFSET_V4: usize = 100;
pub(super) const XFS_INODE_DATA_FORK_OFFSET_V5: usize = 176;

/// Where records start in a long-format B+tree block: 32 for v4, 56 for v5
/// (the CRC, UUID, owner and LSN fields v5 inserts).
pub(super) const XFS_BTREE_LBLOCK_REC_OFFSET_V4: usize = 32;
pub(super) const XFS_BTREE_LBLOCK_REC_OFFSET_V5: usize = 56;

/// The BMAP B+tree block magics, per generation.
pub(super) const XFS_BMAP_MAGIC_V4: u32 = 0x424D_4150;
pub(super) const XFS_BMAP_MAGIC_V5: u32 = 0x424D_4133;

/// Directory DA-blkinfo magics, for the format dispatch.
pub(super) const XFS_DIR2_LEAF1_MAGIC: u16 = 0xd2f1;
pub(super) const XFS_DIR2_LEAFN_MAGIC: u16 = 0xd2ff;
pub(super) const XFS_DA_NODE_MAGIC: u16 = 0xfebe;

/// Attribute leaf block magic (v4).
pub(super) const XFS_ATTR_LEAF_MAGIC: u16 = 0xfbee;

// ── the superblock ───────────────────────────────────────────────────────

/// A parsed superblock: the geometry the whole driver's addressing is
/// built from.
#[derive(Debug, Clone)]
pub(super) struct Superblock {
    // The magic is validated at parse time, before the struct exists.
    #[allow(dead_code)]
    pub(super) magic: u32,
    pub(super) block_size: u32,
    pub(super) blocks_per_ag: u32,
    // Wire-format fields, parsed for the layout's completeness; the
    // addressing uses blocks_per_ag and inode_size and never these.
    #[allow(dead_code)]
    pub(super) ag_count: u32,
    pub(super) root_ino: u64,
    pub(super) inode_size: u16,
    #[allow(dead_code)]
    pub(super) inodes_per_block: u16,
    #[allow(dead_code)]
    pub(super) features2: u32,
    pub(super) sector_size: u32,
    pub(super) log_blocks: u32,
    pub(super) log_start: u64,
    pub(super) versionnum: u16,
    pub(super) features_incompat: u32,
    pub(super) features_log: u16,
    #[allow(dead_code)]
    pub(super) features_ro_compat: u32,
    #[allow(dead_code)]
    pub(super) sb_meta_uuid: [u8; 16],
}

impl Superblock {
    /// Parse a superblock from its first 512 bytes, or `None` when the
    /// magic does not answer.
    pub(super) fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < 256 {
            return None;
        }
        let magic = read_be32(buf, 0);
        if magic != XFS_SUPER_MAGIC {
            return None;
        }
        let versionnum = read_be16(buf, 0x68);
        let is_v5 = versionnum & XFS_SB_VERSION_5 != 0;
        let features_ro_compat = if buf.len() > 212 {
            read_be32(buf, 212)
        } else {
            0
        };
        let mut meta_uuid = [0u8; 16];
        if is_v5 && buf.len() >= 264 {
            meta_uuid.copy_from_slice(&buf[248..264]);
        }
        Some(Self {
            magic,
            block_size: read_be32(buf, 4),
            blocks_per_ag: read_be32(buf, 20),
            ag_count: read_be32(buf, 24),
            root_ino: read_be64(buf, 8),
            inode_size: read_be16(buf, 100),
            inodes_per_block: read_be16(buf, 102),
            features2: read_be32(buf, 114),
            sector_size: read_be32(buf, 120),
            log_blocks: read_be32(buf, 148),
            log_start: read_be64(buf, 140),
            versionnum,
            features_incompat: read_be32(buf, 128),
            features_log: read_be16(buf, 0xAC),
            features_ro_compat,
            sb_meta_uuid: meta_uuid,
        })
    }

    /// Whether this is a v5 (CRC-enabled) filesystem.
    pub(super) fn is_v5(&self) -> bool {
        self.versionnum & XFS_SB_VERSION_5 != 0
    }

    /// The byte offset where an inode's data fork starts.
    pub(super) fn inode_data_offset(&self) -> usize {
        if self.is_v5() {
            XFS_INODE_DATA_FORK_OFFSET_V5
        } else {
            XFS_INODE_DATA_FORK_OFFSET_V4
        }
    }

    /// The byte offset where records start in a long-format B+tree block.
    pub(super) fn btree_lblock_rec_offset(&self) -> usize {
        if self.is_v5() {
            XFS_BTREE_LBLOCK_REC_OFFSET_V5
        } else {
            XFS_BTREE_LBLOCK_REC_OFFSET_V4
        }
    }

    /// This volume's BMAP B+tree block magic.
    pub(super) fn bmap_magic(&self) -> u32 {
        if self.is_v5() {
            XFS_BMAP_MAGIC_V5
        } else {
            XFS_BMAP_MAGIC_V4
        }
    }
}

// ── the journal's own facts ──────────────────────────────────────────────

/// The journal's metadata, as the superblock describes it: whether the
/// volume has one, and whether an unclean unmount left it needing replay.
#[derive(Debug, Clone)]
pub(super) struct JournalInfo {
    #[allow(dead_code)]
    pub(super) has_journal: bool,
    pub(super) is_dirty: bool,
    #[allow(dead_code)]
    pub(super) log_start: u64,
    #[allow(dead_code)]
    pub(super) log_blocks: u32,
    #[allow(dead_code)]
    pub(super) log_version: u8,
}

// ── the inode ────────────────────────────────────────────────────────────

/// The inode's magic: "IN".
pub(super) const XFS_INODE_MAGIC: u16 = 0x494E;

/// The data-fork formats an inode's contents can take.
pub(super) const XFS_DINODE_FMT_LOCAL: u8 = 0;
pub(super) const XFS_DINODE_FMT_EXTENTS: u8 = 1;
pub(super) const XFS_DINODE_FMT_BTREE: u8 = 2;

/// v5 (CRC-enabled) inode version number (`di_version = 3`).
pub(super) const XFS_DINODE_VERSION_5: u8 = 3;

/// A parsed inode's core fields.
#[derive(Debug, Clone)]
pub(super) struct InodeCore {
    pub(super) mode: u16,
    // Wire-format fields, parsed for the layout's completeness and read by
    // no path this driver serves yet.
    #[allow(dead_code)]
    pub(super) version: u8,
    pub(super) format: u8,
    pub(super) attr_format: u8,
    #[allow(dead_code)]
    pub(super) uid: u32,
    #[allow(dead_code)]
    pub(super) gid: u32,
    #[allow(dead_code)]
    pub(super) nlink: u32,
    pub(super) size: u64,
    pub(super) num_extents: u32,
    /// Attribute-fork extent count, meaningful only when `attr_format` is
    /// [`XFS_DINODE_FMT_EXTENTS`].
    pub(super) attr_num_extents: u16,
    pub(super) fork_offset: u16,
    pub(super) is_v5: bool,
}

impl InodeCore {
    /// Parse an inode's core from its raw buffer.
    pub(super) fn parse(buf: &[u8], _inode_size: usize) -> Option<Self> {
        if buf.len() < 100 {
            return None;
        }
        let magic = read_be16(buf, 0);
        if magic != XFS_INODE_MAGIC {
            return None;
        }
        let version = buf[4];
        let is_v5 = version == XFS_DINODE_VERSION_5;
        let fork_offset = read_be16(buf, 20);
        let attr_num_extents = if buf.len() > 37 {
            u16::from_be_bytes([buf[36], buf[37]])
        } else {
            0
        };
        Some(Self {
            mode: read_be16(buf, 2),
            version,
            format: buf[5],
            attr_format: buf[6],
            uid: read_be32(buf, 8),
            gid: read_be32(buf, 12),
            nlink: read_be32(buf, 16),
            size: read_be64(buf, 24),
            num_extents: read_be32(buf, 32),
            attr_num_extents,
            fork_offset,
            is_v5,
        })
    }

    /// The attribute fork's byte range within the inode buffer, or `None`
    /// when the inode has none.
    pub(super) fn attr_fork_range(&self, inode_size: usize) -> Option<(usize, usize)> {
        let fo = self.fork_offset as usize;
        if fo == 0 || fo >= inode_size {
            return None;
        }
        Some((fo, inode_size))
    }

    pub(super) fn is_dir(&self) -> bool {
        self.mode & 0o040000 != 0
    }

    pub(super) fn file_type(&self) -> u16 {
        self.mode & 0o170000
    }
}

// ── extents ──────────────────────────────────────────────────────────────

/// One extent: where a file's contiguous run sits, and which file offsets
/// it covers.
#[derive(Debug, Clone)]
pub(super) struct Extent {
    pub(super) start_block: u64,
    pub(super) block_count: u64,
    pub(super) start_offset: u64,
}

/// Parse an extent list from an inode's fork — sixteen-byte records.
///
/// The physical block number is 34 bits wide, split across the flag byte's
/// upper two bits and the record's low word: a packing the tests pin so a
/// shift mistake cannot read as a valid extent.
pub(super) fn parse_extents(buf: &[u8], fork_offset: usize, num_extents: u32) -> Vec<Extent> {
    let mut extents = Vec::with_capacity(num_extents as usize);
    let num = num_extents as usize;
    for i in 0..num {
        let off = fork_offset + i * 16;
        if off + 16 > buf.len() {
            break;
        }
        let start_off_lo = read_be64(buf, off);
        let start_block_lo = read_be32(buf, off + 8) as u64;
        let start_off_hi: u64 = (buf[off] as u64 >> 7) & 0x01;
        let start_block_hi: u64 = (buf[off] as u64 >> 6) & 0x03;
        let block_count = read_be32(buf, off + 12) as u64;

        let start_block = start_block_lo | (start_block_hi << 32);
        let start_offset = start_off_lo | (start_off_hi << 63);

        extents.push(Extent {
            start_block,
            block_count,
            start_offset,
        });
    }
    extents
}

// ── directory entries ────────────────────────────────────────────────────

/// A parsed directory entry.
#[derive(Debug, Clone)]
pub(super) struct DirEntry {
    pub(super) inode: u64,
    pub(super) name: Vec<u8>,
}

/// Parse shortform directory entries from an inode's data fork.
///
/// The shortform layout: the parent's inode number, the entry count, two
/// pad bytes, then count entries of `namelen + 2 + 8 + name` each.
pub(super) fn parse_shortform_dir(data: &[u8], offset: usize) -> Vec<DirEntry> {
    let mut entries = Vec::new();
    if offset + 4 > data.len() {
        return entries;
    }
    let _parent_ino = read_be64(data, offset);
    let count = data[offset + 8] as usize;
    let mut pos = offset + 12;

    for _ in 0..count {
        if pos + 3 > data.len() {
            break;
        }
        let name_len = data[pos] as usize;
        let ino = read_be64(data, pos + 2);
        pos += 10;
        if pos + name_len > data.len() {
            break;
        }
        let name = data[pos..pos + name_len].to_vec();
        entries.push(DirEntry { inode: ino, name });
        pos += name_len;
    }
    entries
}

/// Parse one `xfs_dir2_data_entry` at a byte offset within a directory
/// data block, or `None` when the offset or the data is out of bounds.
pub(super) fn parse_data_entry_at(data: &[u8], offset: usize) -> Option<DirEntry> {
    if offset + 24 > data.len() {
        return None;
    }
    let entry_len = read_be16(data, offset + 4) as usize;
    if entry_len == 0 || offset + entry_len > data.len() {
        return None;
    }
    let name_len = data[offset + 10] as usize;
    if name_len == 0 || offset + 24 + name_len > data.len() {
        return None;
    }
    let inode = read_be64(data, offset + 16);
    let name_start = offset + 24;
    let name = data[name_start..name_start + name_len].to_vec();
    Some(DirEntry { inode, name })
}

/// Parse block-format directory entries from a directory block.
pub(super) fn parse_block_dir(data: &[u8]) -> Vec<DirEntry> {
    let mut entries = Vec::new();
    let mut offset = 0usize;

    while offset + 16 <= data.len() {
        let entry_len = read_be16(data, offset + 4) as usize;
        if entry_len == 0 || offset + entry_len > data.len() {
            offset += 8;
            if offset >= data.len() {
                break;
            }
            continue;
        }
        if let Some(entry) = parse_data_entry_at(data, offset) {
            entries.push(entry);
        }
        offset += entry_len;
    }
    entries
}

// ── byte-order helpers ───────────────────────────────────────────────────

fn read_be16(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}

pub(super) fn read_be32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

pub(super) fn read_be64(buf: &[u8], off: usize) -> u64 {
    u64::from_be_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}
