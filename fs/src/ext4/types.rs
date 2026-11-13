//! fs/src/ext4/types.rs
//!
//! ext4's on-disk structures, the in-memory forms this driver reads them
//! into, and the serialisation between the two.
//!
//! Every multi-byte field is little-endian on the disk, and the inode's
//! 256-byte extension fields (`size_high` at `0x6C`, `block_high` at `0x6A`)
//! are zero when the volume uses 128-byte inodes.  A field read at the wrong
//! offset would agree with itself all the way through a round trip, which is
//! why the vectors in the tests are the wire's own bytes and not this
//! module's writer read back through its own parser.

use alloc::string::String;

use crate::types::NodeKind;

use super::constants::*;

// The inode

/// A parsed inode.  The 256-byte extension fields are zero for a volume
/// whose inodes are 128 bytes.
#[derive(Debug, Clone)]
pub(super) struct Ext4Inode {
    pub(super) mode: u16,
    pub(super) uid: u16,
    pub(super) size_low: u32,
    pub(super) atime: u32,
    pub(super) ctime: u32,
    pub(super) mtime: u32,
    pub(super) gid: u16,
    pub(super) links_count: u16,
    pub(super) block: [u32; EXT4_TIND_BLOCK + 1],
    pub(super) uid_high: u16,
    pub(super) gid_high: u16,
    pub(super) flags: u32,
    pub(super) size_high: u32,
    pub(super) block_high: [u16; EXT4_TIND_BLOCK + 1],
}

impl Ext4Inode {
    /// The node's kind, from the mode word's type bits.
    pub(super) fn kind(&self) -> NodeKind {
        match self.mode & EXT4_S_IFMT {
            EXT4_S_IFDIR => NodeKind::Directory,
            EXT4_S_IFREG => NodeKind::File,
            EXT4_S_IFCHR | EXT4_S_IFBLK => NodeKind::Device,
            EXT4_S_IFLNK => NodeKind::Symlink,
            _ => NodeKind::File,
        }
    }

    /// The file's size: a 48-bit field split across `size_low`/`size_high`.
    pub(super) fn file_size(&self) -> u64 {
        ((self.size_high as u64) << 32) | self.size_low as u64
    }

    /// The owner's uid: a 32-bit field split across `uid`/`uid_high`.
    pub(super) fn owner_uid(&self) -> u32 {
        ((self.uid_high as u32) << 16) | self.uid as u32
    }

    /// The owner's gid, split the same way the uid is.
    pub(super) fn owner_gid(&self) -> u32 {
        ((self.gid_high as u32) << 16) | self.gid as u32
    }

    /// The mode word's permission bits.
    pub(super) fn permission_mode(&self) -> u16 {
        self.mode & 0o777
    }

    /// Whether the inode's blocks are mapped by an extent tree.
    pub(super) fn has_extents(&self) -> bool {
        self.flags & EXT4_EXTENTS_FL != 0
    }

    /// Whether the directory's names match case-insensitively.
    pub(super) fn has_casefold(&self) -> bool {
        self.flags & EXT4_CASEFOLD_FL != 0
    }

    /// The 48-bit block address at slot `idx`, from the two halves the
    /// format stores it in.
    pub(super) fn block_48(&self, idx: usize) -> u64 {
        ((self.block_high[idx] as u64) << 32) | self.block[idx] as u64
    }
}

// The superblock

/// A parsed superblock: the fields this driver serves, at the offsets the
/// format fixes.
#[derive(Debug, Clone)]
pub(super) struct Ext4Superblock {
    pub(super) inodes_count: u32,
    pub(super) blocks_count: u32,
    // Wire-format fields, parsed and kept for the layout's completeness; the
    // driver recomputes both counts from the bitmaps when it writes the
    // superblock back, so it never reads these.
    #[allow(dead_code)]
    pub(super) free_blocks_count: u32,
    #[allow(dead_code)]
    pub(super) free_inodes_count: u32,
    pub(super) log_block_size: u32,
    pub(super) blocks_per_group: u32,
    pub(super) inodes_per_group: u32,
    pub(super) magic: u16,
    pub(super) rev_level: u32,
    pub(super) inode_size: u16,
    pub(super) feature_compat: u32,
    pub(super) feature_incompat: u32,
}

impl Ext4Superblock {
    /// The block size in bytes: `1024 << log_block_size`.
    pub(super) fn block_size(&self) -> usize {
        (1024usize) << self.log_block_size
    }

    /// How many block groups the volume has.
    pub(super) fn block_group_count(&self) -> u32 {
        self.blocks_count.div_ceil(self.blocks_per_group)
    }

    /// The group that owns `ino`, which counts from one.
    pub(super) fn group_of_ino(&self, ino: u32) -> u32 {
        (ino - 1) / self.inodes_per_group
    }

    /// `ino`'s index within its group.
    pub(super) fn inode_index_in_group(&self, ino: u32) -> u32 {
        (ino - 1) % self.inodes_per_group
    }

    /// Whether the volume carries the extents feature.
    pub(super) fn has_extents(&self) -> bool {
        self.feature_incompat & EXT4_FEATURE_INCOMPAT_EXTENTS != 0
    }
}

// The block-group descriptor

/// A parsed block-group descriptor: where the group's bitmaps and inode
/// table sit, and the counts the allocator works from.
#[derive(Debug, Clone)]
pub(super) struct Ext4BgDescriptor {
    pub(super) bg_block_bitmap: u32,
    pub(super) bg_inode_bitmap: u32,
    pub(super) bg_inode_table: u32,
    pub(super) bg_free_blocks_count: u16,
    pub(super) bg_free_inodes_count: u16,
    pub(super) bg_used_dirs_count: u16,
}

// The extent tree

/// An extent-tree node header, twelve bytes.
#[derive(Debug, Clone, Copy)]
pub(super) struct Ext4ExtentHeader {
    pub(super) eh_magic: u16,
    pub(super) eh_entries: u16,
    pub(super) eh_max: u16,
    pub(super) eh_depth: u16,
    pub(super) eh_generation: u32,
}

/// A leaf extent entry, twelve bytes: where a run of contiguous blocks sits.
#[derive(Debug, Clone, Copy)]
pub(super) struct Ext4Extent {
    pub(super) ee_block: u32,
    pub(super) ee_len: u16,
    pub(super) ee_start_hi: u16,
    pub(super) ee_start_lo: u32,
}

impl Ext4Extent {
    /// The run's length, in blocks.
    pub(super) fn len(&self) -> u16 {
        self.ee_len
    }

    /// The run's 48-bit physical start block.
    pub(super) fn start_block(&self) -> u64 {
        ((self.ee_start_hi as u64) << 32) | self.ee_start_lo as u64
    }
}

/// An internal index entry, twelve bytes: which child node covers which
/// logical block range.
#[derive(Debug, Clone, Copy)]
pub(super) struct Ext4ExtentIdx {
    pub(super) ei_block: u32,
    ei_leaf_lo: u32,
    ei_leaf_hi: u16,
    _ei_unused: u16,
}

impl Ext4ExtentIdx {
    /// The child node's 48-bit block address.
    pub(super) fn leaf_block(&self) -> u64 {
        ((self.ei_leaf_hi as u64) << 32) | self.ei_leaf_lo as u64
    }
}

// Directory entries

/// A parsed directory entry: who it names, and what it names.
pub(super) struct Ext4DirEntry {
    pub(super) inode: u32,
    pub(super) name: String,
    pub(super) file_type: u8,
}

// Parsing and serialisation

/// Parse a raw inode — 128 or 256 bytes — into an [`Ext4Inode`].
pub(super) fn read_ext4_inode(raw: &[u8], inode_size: u16) -> Ext4Inode {
    let mode = u16::from_le_bytes([raw[0], raw[1]]);
    let uid = u16::from_le_bytes([raw[2], raw[3]]);
    let size_low = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
    let atime = u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]);
    let ctime = u32::from_le_bytes([raw[12], raw[13], raw[14], raw[15]]);
    let mtime = u32::from_le_bytes([raw[16], raw[17], raw[18], raw[19]]);
    let gid = u16::from_le_bytes([raw[24], raw[25]]);
    let links_count = u16::from_le_bytes([raw[26], raw[27]]);
    let flags = u32::from_le_bytes([raw[32], raw[33], raw[34], raw[35]]);

    let mut block = [0_u32; EXT4_TIND_BLOCK + 1];
    for (i, item) in block.iter_mut().enumerate() {
        let off = 40 + i * 4;
        *item = u32::from_le_bytes([raw[off], raw[off + 1], raw[off + 2], raw[off + 3]]);
    }

    let osd2_start = 40 + (EXT4_TIND_BLOCK + 1) * 4;
    let uid_high = u16::from_le_bytes([raw[osd2_start + 4], raw[osd2_start + 5]]);
    let gid_high = u16::from_le_bytes([raw[osd2_start + 6], raw[osd2_start + 7]]);

    // The 256-byte extension fields, which are zero for 128-byte inodes:
    // `size_high` lives at 0x6C and the `block_high` halves at 0x6A.
    let (size_high, block_high) = if inode_size >= 256 {
        let size_high = u32::from_le_bytes([raw[0x6C], raw[0x6D], raw[0x6E], raw[0x6F]]);
        let mut block_high = [0_u16; EXT4_TIND_BLOCK + 1];
        for (i, item) in block_high.iter_mut().enumerate().take(EXT4_TIND_BLOCK + 1) {
            let off = 0x6A + i * 2;
            *item = u16::from_le_bytes([raw[off], raw[off + 1]]);
        }
        (size_high, block_high)
    } else {
        (0, [0_u16; EXT4_TIND_BLOCK + 1])
    };

    Ext4Inode {
        mode,
        uid,
        size_low,
        atime,
        ctime,
        mtime,
        gid,
        links_count,
        block,
        uid_high,
        gid_high,
        flags,
        size_high,
        block_high,
    }
}

/// The inode's first sixty `i_block` bytes, which is where an extent tree's
/// root lives.
pub(super) fn inode_block_bytes(inode: &Ext4Inode) -> [u8; 60] {
    let mut out = [0_u8; 60];
    for (slot, word) in inode.block.iter().enumerate().take(15) {
        let off = slot * 4;
        out[off..off + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// Write sixty bytes back into the inode's `i_block` area.
pub(super) fn write_inode_block_bytes(inode: &mut Ext4Inode, bytes: &[u8; 60]) {
    for (slot, word) in inode.block.iter_mut().enumerate().take(15) {
        let off = slot * 4;
        *word = u32::from_le_bytes([bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]]);
    }
}

// The extent tree's own parsing

/// Parse a twelve-byte extent-tree node header.
pub(super) fn parse_extent_header(raw: &[u8]) -> Ext4ExtentHeader {
    Ext4ExtentHeader {
        eh_magic: u16::from_le_bytes([raw[0], raw[1]]),
        eh_entries: u16::from_le_bytes([raw[2], raw[3]]),
        eh_max: u16::from_le_bytes([raw[4], raw[5]]),
        eh_depth: u16::from_le_bytes([raw[6], raw[7]]),
        eh_generation: u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]),
    }
}

/// Parse a twelve-byte leaf extent entry.
pub(super) fn parse_extent(raw: &[u8]) -> Ext4Extent {
    Ext4Extent {
        ee_block: u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
        ee_len: u16::from_le_bytes([raw[4], raw[5]]),
        ee_start_hi: u16::from_le_bytes([raw[6], raw[7]]),
        ee_start_lo: u32::from_le_bytes([raw[8], raw[9], raw[10], raw[11]]),
    }
}

/// Parse a twelve-byte internal index entry.
pub(super) fn parse_extent_idx(raw: &[u8]) -> Ext4ExtentIdx {
    Ext4ExtentIdx {
        ei_block: u32::from_le_bytes([raw[0], raw[1], raw[2], raw[3]]),
        ei_leaf_lo: u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]),
        ei_leaf_hi: u16::from_le_bytes([raw[8], raw[9]]),
        _ei_unused: u16::from_le_bytes([raw[10], raw[11]]),
    }
}

/// Serialise an extent-tree node header into twelve bytes.
pub(super) fn write_extent_header(raw: &mut [u8], header: &Ext4ExtentHeader) {
    raw[0..2].copy_from_slice(&header.eh_magic.to_le_bytes());
    raw[2..4].copy_from_slice(&header.eh_entries.to_le_bytes());
    raw[4..6].copy_from_slice(&header.eh_max.to_le_bytes());
    raw[6..8].copy_from_slice(&header.eh_depth.to_le_bytes());
    raw[8..12].copy_from_slice(&header.eh_generation.to_le_bytes());
}

/// Serialise a leaf extent entry into twelve bytes.
pub(super) fn write_extent(raw: &mut [u8], ext: &Ext4Extent) {
    raw[0..4].copy_from_slice(&ext.ee_block.to_le_bytes());
    raw[4..6].copy_from_slice(&ext.ee_len.to_le_bytes());
    raw[6..8].copy_from_slice(&ext.ee_start_hi.to_le_bytes());
    raw[8..12].copy_from_slice(&ext.ee_start_lo.to_le_bytes());
}
