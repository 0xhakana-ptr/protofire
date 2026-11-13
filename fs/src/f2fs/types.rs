//! fs/src/f2fs/types.rs
//!
//! f2fs's on-disk structures, the in-memory forms this driver reads them
//! into, and the serialisation between the two — superblock, NAT and SIT
//! entries, the checkpoint with its inline NAT journal, the inode, and the
//! directory entries.
//!
//! Every multi-byte field is little-endian.  The inode's layout is this
//! volume's own contiguous arrangement, written and read only by this
//! module's two helpers, which is what keeps the offsets in `constants` and
//! the fields here one fact written twice that the tests pin together.

use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;

use crate::types::NodeKind;

use super::constants::*;

// ── the superblock ───────────────────────────────────────────────────────

/// A parsed f2fs superblock, from block zero.
#[derive(Debug, Clone)]
pub(super) struct F2fsSuperblock {
    pub(super) magic: u32,
    pub(super) major_ver: u16,
    pub(super) minor_ver: u16,
    pub(super) log_sectorsize: u32,
    pub(super) log_sectors_per_block: u32,
    pub(super) log_blocksize: u32,
    pub(super) log_blocks_per_seg: u32,
    pub(super) segs_per_sec: u32,
    pub(super) secs_per_zone: u32,
    pub(super) checksum_offset: u32,
    pub(super) block_count: u64,
    pub(super) section_count: u32,
    pub(super) segment_count: u32,
    pub(super) segment_count_main: u32,
    pub(super) segment0_blkaddr: u32,
    pub(super) cp_blkaddr: u32,
    pub(super) sit_blkaddr: u32,
    pub(super) nat_blkaddr: u32,
    pub(super) ssa_blkaddr: u32,
    pub(super) main_blkaddr: u32,
    pub(super) root_ino: u32,
    pub(super) node_ino: u32,
    pub(super) meta_ino: u32,
    pub(super) cp_payload: u32,
    pub(super) feature: u32,
    pub(super) nat_entry_cnt: u32,
    pub(super) sit_entry_cnt: u32,
    pub(super) node_count: u32,
}

impl F2fsSuperblock {
    /// The block size in bytes: two to the `log_blocksize`.
    pub(super) fn block_size(&self) -> usize {
        1usize << self.log_blocksize
    }

    /// Blocks per segment: two to the `log_blocks_per_seg`.
    pub(super) fn blocks_per_seg(&self) -> u32 {
        1u32 << self.log_blocks_per_seg
    }
}

/// A little-endian word read from `raw` at `off`.
fn read_word(raw: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]])
}

/// A little-endian half-word read from `raw` at `off`.
fn read_half(raw: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([raw[off], raw[off + 1]])
}

/// A little-endian double word read from `raw` at `off`.
fn read_dword(raw: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        raw[off],
        raw[off + 1],
        raw[off + 2],
        raw[off + 3],
        raw[off + 4],
        raw[off + 5],
        raw[off + 6],
        raw[off + 7],
    ])
}

/// Parse a superblock from a 4096-byte raw buffer.
pub(super) fn parse_f2fs_superblock(raw: &[u8]) -> F2fsSuperblock {
    F2fsSuperblock {
        magic: read_word(raw, F2FS_SB_MAGIC_OFF),
        major_ver: read_half(raw, F2FS_SB_MAJOR_VER_OFF),
        minor_ver: read_half(raw, F2FS_SB_MINOR_VER_OFF),
        log_sectorsize: read_word(raw, F2FS_SB_LOG_SECTORSIZE_OFF),
        log_sectors_per_block: read_word(raw, F2FS_SB_LOG_SECTORS_PER_BLOCK_OFF),
        log_blocksize: read_word(raw, F2FS_SB_LOG_BLOCKSIZE_OFF),
        log_blocks_per_seg: read_word(raw, F2FS_SB_LOG_BLOCKS_PER_SEG_OFF),
        segs_per_sec: read_word(raw, F2FS_SB_SEGS_PER_SEC_OFF),
        secs_per_zone: read_word(raw, F2FS_SB_SECS_PER_ZONE_OFF),
        checksum_offset: read_word(raw, F2FS_SB_CHECKSUM_OFFSET_OFF),
        block_count: read_dword(raw, F2FS_SB_BLOCK_COUNT_OFF),
        section_count: read_word(raw, F2FS_SB_SECTION_COUNT_OFF),
        segment_count: read_word(raw, F2FS_SB_SEGMENT_COUNT_OFF),
        segment_count_main: read_word(raw, F2FS_SB_SEGMENT_COUNT_MAIN_OFF),
        segment0_blkaddr: read_word(raw, F2FS_SB_SEGMENT0_BLKADDR_OFF),
        cp_blkaddr: read_word(raw, F2FS_SB_CP_BLKADDR_OFF),
        sit_blkaddr: read_word(raw, F2FS_SB_SIT_BLKADDR_OFF),
        nat_blkaddr: read_word(raw, F2FS_SB_NAT_BLKADDR_OFF),
        ssa_blkaddr: read_word(raw, F2FS_SB_SSA_BLKADDR_OFF),
        main_blkaddr: read_word(raw, F2FS_SB_MAIN_BLKADDR_OFF),
        root_ino: read_word(raw, F2FS_SB_ROOT_INO_OFF),
        node_ino: read_word(raw, F2FS_SB_NODE_INO_OFF),
        meta_ino: read_word(raw, F2FS_SB_META_INO_OFF),
        cp_payload: read_word(raw, F2FS_SB_CP_PAYLOAD_OFF),
        feature: read_word(raw, F2FS_SB_FEATURE_OFF),
        nat_entry_cnt: read_word(raw, F2FS_SB_NAT_ENTRY_CNT_OFF),
        sit_entry_cnt: read_word(raw, F2FS_SB_SIT_ENTRY_CNT_OFF),
        node_count: read_word(raw, F2FS_SB_NODE_COUNT_OFF),
    }
}

/// Serialise a superblock into a 4096-byte raw buffer.
fn write_word(raw: &mut [u8], off: usize, value: u32) {
    raw[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_half(raw: &mut [u8], off: usize, value: u16) {
    raw[off..off + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_dword(raw: &mut [u8], off: usize, value: u64) {
    raw[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn write_f2fs_superblock(sb: &F2fsSuperblock, raw: &mut [u8]) {
    write_word(raw, F2FS_SB_MAGIC_OFF, sb.magic);
    write_half(raw, F2FS_SB_MAJOR_VER_OFF, sb.major_ver);
    write_half(raw, F2FS_SB_MINOR_VER_OFF, sb.minor_ver);
    write_word(raw, F2FS_SB_LOG_SECTORSIZE_OFF, sb.log_sectorsize);
    write_word(
        raw,
        F2FS_SB_LOG_SECTORS_PER_BLOCK_OFF,
        sb.log_sectors_per_block,
    );
    write_word(raw, F2FS_SB_LOG_BLOCKSIZE_OFF, sb.log_blocksize);
    write_word(raw, F2FS_SB_LOG_BLOCKS_PER_SEG_OFF, sb.log_blocks_per_seg);
    write_word(raw, F2FS_SB_SEGS_PER_SEC_OFF, sb.segs_per_sec);
    write_word(raw, F2FS_SB_SECS_PER_ZONE_OFF, sb.secs_per_zone);
    write_word(raw, F2FS_SB_CHECKSUM_OFFSET_OFF, sb.checksum_offset);
    write_dword(raw, F2FS_SB_BLOCK_COUNT_OFF, sb.block_count);
    write_word(raw, F2FS_SB_SECTION_COUNT_OFF, sb.section_count);
    write_word(raw, F2FS_SB_SEGMENT_COUNT_OFF, sb.segment_count);
    write_word(raw, F2FS_SB_SEGMENT_COUNT_MAIN_OFF, sb.segment_count_main);
    write_word(raw, F2FS_SB_SEGMENT0_BLKADDR_OFF, sb.segment0_blkaddr);
    write_word(raw, F2FS_SB_CP_BLKADDR_OFF, sb.cp_blkaddr);
    write_word(raw, F2FS_SB_SIT_BLKADDR_OFF, sb.sit_blkaddr);
    write_word(raw, F2FS_SB_NAT_BLKADDR_OFF, sb.nat_blkaddr);
    write_word(raw, F2FS_SB_SSA_BLKADDR_OFF, sb.ssa_blkaddr);
    write_word(raw, F2FS_SB_MAIN_BLKADDR_OFF, sb.main_blkaddr);
    write_word(raw, F2FS_SB_ROOT_INO_OFF, sb.root_ino);
    write_word(raw, F2FS_SB_NODE_INO_OFF, sb.node_ino);
    write_word(raw, F2FS_SB_META_INO_OFF, sb.meta_ino);
    write_word(raw, F2FS_SB_CP_PAYLOAD_OFF, sb.cp_payload);
    write_word(raw, F2FS_SB_FEATURE_OFF, sb.feature);
    write_word(raw, F2FS_SB_NAT_ENTRY_CNT_OFF, sb.nat_entry_cnt);
    write_word(raw, F2FS_SB_SIT_ENTRY_CNT_OFF, sb.sit_entry_cnt);
    write_word(raw, F2FS_SB_NODE_COUNT_OFF, sb.node_count);
}

// ── NAT entries ──────────────────────────────────────────────────────────

/// A NAT (Node Address Table) entry: which block a node id lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct F2fsNatEntry {
    /// The node's physical block address; zero means the NID is free.
    pub(super) block_addr: u32,
    /// The owner inode's NID.
    pub(super) ino: u32,
}

/// Parse a NAT entry from eight raw bytes.
pub(super) fn parse_nat_entry(raw: &[u8]) -> F2fsNatEntry {
    F2fsNatEntry {
        block_addr: u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
        ino: u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
    }
}

/// Serialise a NAT entry into eight bytes.
pub(super) fn write_nat_entry(entry: &F2fsNatEntry, raw: &mut [u8]) {
    raw[0..4].copy_from_slice(&entry.block_addr.to_le_bytes());
    raw[4..8].copy_from_slice(&entry.ino.to_le_bytes());
}

// ── SIT entries ──────────────────────────────────────────────────────────

/// A SIT (Segment Information Table) entry: which blocks in one segment
/// hold valid data.
#[derive(Debug, Clone)]
pub(super) struct F2fsSitEntry {
    /// How many blocks of this segment are valid.
    pub(super) vblocks: u16,
    /// One bit per block, sixty-four bytes for a 512-block segment.
    pub(super) valid_map: [u8; 64],
}

impl F2fsSitEntry {
    /// Whether the block at `offset` within the segment is valid.
    pub(super) fn is_valid(&self, offset: u16) -> bool {
        let byte = self.valid_map[offset as usize / 8];
        (byte >> (offset % 8)) & 1 != 0
    }

    /// Mark the block at `offset` valid.
    pub(super) fn mark_valid(&mut self, offset: u16) {
        let idx = offset as usize / 8;
        let bit = offset % 8;
        if (self.valid_map[idx] >> bit) & 1 == 0 {
            self.valid_map[idx] |= 1 << bit;
            self.vblocks += 1;
        }
    }

    /// Mark the block at `offset` invalid.
    pub(super) fn mark_invalid(&mut self, offset: u16) {
        let idx = offset as usize / 8;
        let bit = offset % 8;
        if (self.valid_map[idx] >> bit) & 1 != 0 {
            self.valid_map[idx] &= !(1 << bit);
            self.vblocks = self.vblocks.saturating_sub(1);
        }
    }
}

/// Parse a SIT entry from sixty-six raw bytes.
pub(super) fn parse_sit_entry(raw: &[u8]) -> F2fsSitEntry {
    let vblocks = u16::from_le_bytes([raw[0], raw[1]]);
    let mut valid_map = [0u8; 64];
    valid_map.copy_from_slice(&raw[2..66]);
    F2fsSitEntry { vblocks, valid_map }
}

/// Serialise a SIT entry into sixty-six bytes.
pub(super) fn write_sit_entry(entry: &F2fsSitEntry, raw: &mut [u8]) {
    raw[0..2].copy_from_slice(&entry.vblocks.to_le_bytes());
    raw[2..66].copy_from_slice(&entry.valid_map);
}

// ── the checkpoint ───────────────────────────────────────────────────────

/// A parsed checkpoint: the versions, the allocator hints, the valid
/// counts, and the inline NAT journal.
#[derive(Debug, Clone)]
pub(super) struct F2fsCheckpoint {
    /// The checkpoint's version, monotonic — larger is newer.
    pub(super) check_ver: u64,
    pub(super) nat_ver: u64,
    pub(super) sit_ver: u64,
    /// The allocator's hint for the next free NID.
    pub(super) next_free_nid: u32,
    pub(super) valid_block_count: u32,
    pub(super) valid_node_count: u32,
    pub(super) valid_inode_count: u32,
    /// How many NAT journal entries this checkpoint carries.
    pub(super) nat_journal_entries: u32,
    /// The inline NAT journal: recent NAT updates batched into the CP block.
    pub(super) nat_journal: Vec<NatJournalEntry>,
    /// How many SIT journal entries this checkpoint names.
    pub(super) sit_journal_entries: u32,
    /// Which checkpoint copy (0 or 1) won.
    pub(super) cp_copy: u8,
}

/// One inline NAT journal entry, twelve bytes on the disk.
#[derive(Debug, Clone, Copy)]
pub(super) struct NatJournalEntry {
    pub(super) nid: u32,
    pub(super) ne: F2fsNatEntry,
}

/// Parse a checkpoint from a raw CP block.
///
/// `cp_copy` names which copy this is, for the toggle the writer uses.
pub(super) fn parse_f2fs_checkpoint(raw: &[u8], cp_copy: u8) -> F2fsCheckpoint {
    let nat_journal_entries =
        read_word(raw, F2FS_CP_NAT_JOURNAL_COUNT_OFF).min(F2FS_MAX_NAT_JOURNAL_ENTRIES as u32);
    let mut nat_journal = Vec::with_capacity(nat_journal_entries as usize);
    let mut offset = F2FS_CP_NAT_JOURNAL_OFF;
    for _ in 0..nat_journal_entries {
        if offset + 12 > raw.len() {
            break;
        }
        let nid = read_word(raw, offset);
        let ne = parse_nat_entry(&raw[offset + 4..offset + 12]);
        nat_journal.push(NatJournalEntry { nid, ne });
        offset += 12;
    }

    F2fsCheckpoint {
        check_ver: read_dword(raw, F2FS_CP_CHECK_VER_OFF),
        nat_ver: read_dword(raw, F2FS_CP_NAT_VER_OFF),
        sit_ver: read_dword(raw, F2FS_CP_SIT_VER_OFF),
        next_free_nid: read_word(raw, F2FS_CP_NEXT_FREE_NID_OFF),
        valid_block_count: read_word(raw, F2FS_CP_VALID_BLOCK_COUNT_OFF),
        valid_node_count: read_word(raw, F2FS_CP_VALID_NODE_COUNT_OFF),
        valid_inode_count: read_word(raw, F2FS_CP_VALID_INODE_COUNT_OFF),
        nat_journal_entries: read_word(raw, F2FS_CP_NAT_JOURNAL_COUNT_OFF),
        nat_journal,
        sit_journal_entries: read_word(raw, F2FS_CP_SIT_JOURNAL_COUNT_OFF),
        cp_copy,
    }
}

/// Serialise a checkpoint into a raw CP block.
pub(super) fn write_f2fs_checkpoint(cp: &F2fsCheckpoint, raw: &mut [u8]) {
    write_dword(raw, F2FS_CP_CHECK_VER_OFF, cp.check_ver);
    write_dword(raw, F2FS_CP_NAT_VER_OFF, cp.nat_ver);
    write_dword(raw, F2FS_CP_SIT_VER_OFF, cp.sit_ver);
    write_word(raw, F2FS_CP_NEXT_FREE_NID_OFF, cp.next_free_nid);
    write_word(raw, F2FS_CP_VALID_BLOCK_COUNT_OFF, cp.valid_block_count);
    write_word(raw, F2FS_CP_VALID_NODE_COUNT_OFF, cp.valid_node_count);
    write_word(raw, F2FS_CP_VALID_INODE_COUNT_OFF, cp.valid_inode_count);

    let nat_count = cp.nat_journal.len() as u32;
    write_word(raw, F2FS_CP_NAT_JOURNAL_COUNT_OFF, nat_count);
    let mut offset = F2FS_CP_NAT_JOURNAL_OFF;
    for entry in &cp.nat_journal {
        if offset + 12 > raw.len() {
            break;
        }
        write_word(raw, offset, entry.nid);
        write_nat_entry(&entry.ne, &mut raw[offset + 4..offset + 12]);
        offset += 12;
    }

    write_word(raw, F2FS_CP_SIT_JOURNAL_COUNT_OFF, cp.sit_journal_entries);
}

// ── the inode ────────────────────────────────────────────────────────────

/// A parsed inode.  The direct block addresses are the whole of the
/// mapping this driver reads: zero is a hole, all-ones is a fresh
/// reservation.
#[derive(Debug, Clone)]
pub(super) struct F2fsInode {
    pub(super) i_mode: u16,
    pub(super) i_uid: u32,
    pub(super) i_gid: u32,
    pub(super) i_links: u32,
    pub(super) i_size: u64,
    /// Block count in 512-byte sectors, as the format counts it.
    pub(super) i_blocks: u64,
    pub(super) i_atime: u64,
    pub(super) i_ctime: u64,
    pub(super) i_mtime: u64,
    pub(super) i_atime_nsec: u32,
    pub(super) i_ctime_nsec: u32,
    pub(super) i_mtime_nsec: u32,
    pub(super) i_xattr_nid: u32,
    pub(super) i_flags: u32,
    pub(super) i_addr: [u32; F2FS_ADDRS_PER_INODE],
}

impl F2fsInode {
    /// The node's kind, from the mode word's type bits.
    pub(super) fn kind(&self) -> NodeKind {
        match self.i_mode & F2FS_S_IFMT {
            F2FS_S_IFDIR => NodeKind::Directory,
            F2FS_S_IFREG => NodeKind::File,
            F2FS_S_IFCHR | F2FS_S_IFBLK => NodeKind::Device,
            F2FS_S_IFLNK => NodeKind::Symlink,
            _ => NodeKind::File,
        }
    }

    /// The file's size in bytes.
    pub(super) fn file_size(&self) -> u64 {
        self.i_size
    }

    /// The mode word's permission bits.
    pub(super) fn permission_mode(&self) -> u16 {
        self.i_mode & 0o777
    }
}

/// Parse an inode from a 4096-byte raw inode block.
pub(super) fn parse_f2fs_inode(raw: &[u8]) -> F2fsInode {
    let word =
        |off: usize| u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]);
    let dword = |off: usize| {
        u64::from_le_bytes([
            raw[off],
            raw[off + 1],
            raw[off + 2],
            raw[off + 3],
            raw[off + 4],
            raw[off + 5],
            raw[off + 6],
            raw[off + 7],
        ])
    };

    let mut i_addr = [0u32; F2FS_ADDRS_PER_INODE];
    for (i, addr) in i_addr.iter_mut().enumerate() {
        *addr = word(F2FS_INODE_ADDR_OFF + i * 4);
    }

    F2fsInode {
        i_mode: u16::from_le_bytes([raw[F2FS_INODE_MODE_OFF], raw[F2FS_INODE_MODE_OFF + 1]]),
        i_uid: word(F2FS_INODE_UID_OFF),
        i_gid: word(F2FS_INODE_GID_OFF),
        i_links: word(F2FS_INODE_LINKS_OFF),
        i_size: dword(F2FS_INODE_SIZE_OFF),
        i_blocks: dword(F2FS_INODE_BLOCKS_OFF),
        i_atime: dword(F2FS_INODE_ATIME_OFF),
        i_ctime: dword(F2FS_INODE_CTIME_OFF),
        i_mtime: dword(F2FS_INODE_MTIME_OFF),
        i_atime_nsec: word(F2FS_INODE_ATIME_NSEC_OFF),
        i_ctime_nsec: word(F2FS_INODE_CTIME_NSEC_OFF),
        i_mtime_nsec: word(F2FS_INODE_MTIME_NSEC_OFF),
        i_xattr_nid: word(F2FS_INODE_XATTR_NID_OFF),
        i_flags: word(F2FS_INODE_FLAGS_OFF),
        i_addr,
    }
}

/// Serialise an inode into a 4096-byte raw inode block.
pub(super) fn write_f2fs_inode(inode: &F2fsInode, raw: &mut [u8]) {
    raw[F2FS_INODE_MODE_OFF..F2FS_INODE_MODE_OFF + 2].copy_from_slice(&inode.i_mode.to_le_bytes());
    write_word(raw, F2FS_INODE_UID_OFF, inode.i_uid);
    write_word(raw, F2FS_INODE_GID_OFF, inode.i_gid);
    write_word(raw, F2FS_INODE_LINKS_OFF, inode.i_links);
    write_dword(raw, F2FS_INODE_SIZE_OFF, inode.i_size);
    write_dword(raw, F2FS_INODE_BLOCKS_OFF, inode.i_blocks);
    write_dword(raw, F2FS_INODE_ATIME_OFF, inode.i_atime);
    write_dword(raw, F2FS_INODE_CTIME_OFF, inode.i_ctime);
    write_dword(raw, F2FS_INODE_MTIME_OFF, inode.i_mtime);
    write_word(raw, F2FS_INODE_ATIME_NSEC_OFF, inode.i_atime_nsec);
    write_word(raw, F2FS_INODE_CTIME_NSEC_OFF, inode.i_ctime_nsec);
    write_word(raw, F2FS_INODE_MTIME_NSEC_OFF, inode.i_mtime_nsec);
    write_word(raw, F2FS_INODE_XATTR_NID_OFF, inode.i_xattr_nid);
    write_word(raw, F2FS_INODE_FLAGS_OFF, inode.i_flags);

    for (i, addr) in inode.i_addr.iter().enumerate() {
        write_word(raw, F2FS_INODE_ADDR_OFF + i * 4, *addr);
    }
}

// ── directory entries ────────────────────────────────────────────────────

/// A parsed directory entry.
pub(super) struct F2fsDirEntry {
    /// The child's NID.
    pub(super) ino: u32,
    /// The file-type code.
    pub(super) file_type: u8,
    /// The name, as the wire carried it.
    pub(super) name: String,
}

/// Parse every entry a raw data block holds.
///
/// The record is thirteen bytes of header plus the name, aligned to four:
/// `rec_len`, `name_len`, `file_type`, `hash`, `ino`, then the name.  An
/// entry whose `ino` is zero is deleted, and skipped.
pub(super) fn parse_f2fs_dir_entries(data: &[u8]) -> Vec<F2fsDirEntry> {
    let mut entries = Vec::new();
    let mut offset = 0usize;

    while offset + 13 <= data.len() {
        let rec_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
        if rec_len < 13 || rec_len == 0 {
            break;
        }
        let name_len = u16::from_le_bytes([data[offset + 2], data[offset + 3]]) as usize;
        let file_type = data[offset + 4];
        let ino = u32::from_le_bytes([
            data[offset + 9],
            data[offset + 10],
            data[offset + 11],
            data[offset + 12],
        ]);

        if ino != 0 && name_len <= rec_len.saturating_sub(13) {
            let name_end = offset + 13 + name_len;
            if name_end <= data.len() {
                let name_bytes = &data[offset + 13..name_end];
                let name = String::from_utf8_lossy(name_bytes).to_string();
                entries.push(F2fsDirEntry {
                    ino,
                    file_type,
                    name,
                });
            }
        }

        offset += rec_len;
    }

    entries
}

/// The on-disk size of a directory entry: thirteen bytes plus the name,
/// aligned to four.
pub(super) fn dir_entry_size(name_len: usize) -> usize {
    let raw = 13usize + name_len;
    (raw + 3) & !3
}

/// Serialise one directory entry, answering the bytes it wrote.
pub(super) fn write_f2fs_dir_entry(
    ino: u32,
    name: &str,
    file_type: u8,
    hash_code: u32,
    buf: &mut [u8],
) -> usize {
    let name_bytes = name.as_bytes();
    let name_len = name_bytes.len();
    let rec_len = dir_entry_size(name_len);

    buf[0..2].copy_from_slice(&(rec_len as u16).to_le_bytes());
    buf[2..4].copy_from_slice(&(name_len as u16).to_le_bytes());
    buf[4] = file_type;
    buf[5..9].copy_from_slice(&hash_code.to_le_bytes());
    buf[9..13].copy_from_slice(&ino.to_le_bytes());
    let copy_len = core::cmp::min(name_len, rec_len.saturating_sub(13));
    buf[13..13 + copy_len].copy_from_slice(&name_bytes[..copy_len]);
    for b in buf[13 + copy_len..rec_len].iter_mut() {
        *b = 0;
    }

    rec_len
}

// ── the memory caches ────────────────────────────────────────────────────

/// The NAT cache: entries indexed by NID, whose zero block address is what
/// "free" reads as.
#[derive(Debug, Clone)]
pub(super) struct F2fsNatCache {
    pub(super) entries: Vec<F2fsNatEntry>,
}

/// The SIT cache: validity per segment, and the segments that are free.
#[derive(Debug, Clone)]
pub(super) struct F2fsSitCache {
    pub(super) entries: Vec<F2fsSitEntry>,
    pub(super) free_segments: Vec<u32>,
}
