//! fs/src/f2fs/constants.rs
//!
//! f2fs's on-disk constants: the superblock's field offsets, the inode's
//! contiguous layout, and the structural numbers the format fixes —
//! segment geometry, the NAT's entry size, the root's node id, and the two
//! sentinel block addresses a hole and a fresh allocation read as.

// The inode's field offsets, contiguous from zero.

/// Offset of `i_mode` within the inode block (u16).
pub(super) const F2FS_INODE_MODE_OFF: usize = 0;
/// Offset of `i_uid` (u32).
pub(super) const F2FS_INODE_UID_OFF: usize = 4;
/// Offset of `i_gid` (u32).
pub(super) const F2FS_INODE_GID_OFF: usize = 8;
/// Offset of `i_links` (u32).
pub(super) const F2FS_INODE_LINKS_OFF: usize = 12;
/// Offset of `i_size` (u64).
pub(super) const F2FS_INODE_SIZE_OFF: usize = 16;
/// Offset of `i_blocks` (u64, in 512-byte sectors).
pub(super) const F2FS_INODE_BLOCKS_OFF: usize = 24;
/// Offset of `i_atime` (u64 seconds).
pub(super) const F2FS_INODE_ATIME_OFF: usize = 32;
/// Offset of `i_ctime` (u64 seconds).
pub(super) const F2FS_INODE_CTIME_OFF: usize = 40;
/// Offset of `i_mtime` (u64 seconds).
pub(super) const F2FS_INODE_MTIME_OFF: usize = 48;
/// Offset of `i_atime_nsec` (u32).
pub(super) const F2FS_INODE_ATIME_NSEC_OFF: usize = 56;
/// Offset of `i_ctime_nsec` (u32).
pub(super) const F2FS_INODE_CTIME_NSEC_OFF: usize = 60;
/// Offset of `i_mtime_nsec` (u32).
pub(super) const F2FS_INODE_MTIME_NSEC_OFF: usize = 64;
/// Offset of `i_xattr_nid`.
pub(super) const F2FS_INODE_XATTR_NID_OFF: usize = 72;
/// Offset of `i_flags`.
pub(super) const F2FS_INODE_FLAGS_OFF: usize = 76;
/// Start of the `i_addr` block-pointer array.
pub(super) const F2FS_INODE_ADDR_OFF: usize = 80;

// The mode word's file-type mask and the types this driver reads.

pub(super) const F2FS_S_IFMT: u16 = 0xF000;
pub(super) const F2FS_S_IFREG: u16 = 0x8000;
pub(super) const F2FS_S_IFDIR: u16 = 0x4000;
pub(super) const F2FS_S_IFCHR: u16 = 0x2000;
pub(super) const F2FS_S_IFBLK: u16 = 0x6000;
pub(super) const F2FS_S_IFLNK: u16 = 0xA000;

// Directory-entry file-type codes.

pub(super) const F2FS_FT_REG_FILE: u8 = 1;
pub(super) const F2FS_FT_DIR: u8 = 2;
pub(super) const F2FS_FT_CHRDEV: u8 = 3;
pub(super) const F2FS_FT_BLKDEV: u8 = 4;
pub(super) const F2FS_FT_SYMLINK: u8 = 7;

// The superblock's field offsets.  These match the f2fs superblock layout
// up to `F2FS_SB_META_INO_OFF`; the trailing fields use the packed layout
// this driver's own parser reads.

/// The superblock's magic.
pub(super) const F2FS_MAGIC: u32 = 0xF2F5_2010;

pub(super) const F2FS_SB_MAGIC_OFF: usize = 0;
pub(super) const F2FS_SB_MAJOR_VER_OFF: usize = 4;
pub(super) const F2FS_SB_MINOR_VER_OFF: usize = 6;
pub(super) const F2FS_SB_LOG_SECTORSIZE_OFF: usize = 8;
pub(super) const F2FS_SB_LOG_SECTORS_PER_BLOCK_OFF: usize = 12;
pub(super) const F2FS_SB_LOG_BLOCKSIZE_OFF: usize = 16;
pub(super) const F2FS_SB_LOG_BLOCKS_PER_SEG_OFF: usize = 20;
pub(super) const F2FS_SB_SEGS_PER_SEC_OFF: usize = 24;
pub(super) const F2FS_SB_SECS_PER_ZONE_OFF: usize = 28;
pub(super) const F2FS_SB_CHECKSUM_OFFSET_OFF: usize = 32;
pub(super) const F2FS_SB_BLOCK_COUNT_OFF: usize = 36;
pub(super) const F2FS_SB_SECTION_COUNT_OFF: usize = 44;
pub(super) const F2FS_SB_SEGMENT_COUNT_OFF: usize = 48;
pub(super) const F2FS_SB_SEGMENT_COUNT_MAIN_OFF: usize = 52;
pub(super) const F2FS_SB_SEGMENT0_BLKADDR_OFF: usize = 56;
pub(super) const F2FS_SB_CP_BLKADDR_OFF: usize = 60;
pub(super) const F2FS_SB_SIT_BLKADDR_OFF: usize = 64;
pub(super) const F2FS_SB_NAT_BLKADDR_OFF: usize = 68;
pub(super) const F2FS_SB_SSA_BLKADDR_OFF: usize = 72;
pub(super) const F2FS_SB_MAIN_BLKADDR_OFF: usize = 76;
pub(super) const F2FS_SB_ROOT_INO_OFF: usize = 80;
pub(super) const F2FS_SB_NODE_INO_OFF: usize = 84;
pub(super) const F2FS_SB_META_INO_OFF: usize = 88;
/// `cp_payload`: the fsync-inode blocks between the two checkpoint copies.
pub(super) const F2FS_SB_CP_PAYLOAD_OFF: usize = 209;
/// The enabled-features bitmask.
pub(super) const F2FS_SB_FEATURE_OFF: usize = 277;
/// NAT entry count (this layout's own field).
pub(super) const F2FS_SB_NAT_ENTRY_CNT_OFF: usize = 281;
/// SIT entry count (this layout's own field).
pub(super) const F2FS_SB_SIT_ENTRY_CNT_OFF: usize = 285;
/// Total node count (this layout's own field).
pub(super) const F2FS_SB_NODE_COUNT_OFF: usize = 289;

// The checkpoint's field offsets, contiguous.

pub(super) const F2FS_CP_CHECK_VER_OFF: usize = 0;
pub(super) const F2FS_CP_NAT_VER_OFF: usize = 8;
pub(super) const F2FS_CP_SIT_VER_OFF: usize = 16;
pub(super) const F2FS_CP_NEXT_FREE_NID_OFF: usize = 24;
pub(super) const F2FS_CP_VALID_BLOCK_COUNT_OFF: usize = 28;
pub(super) const F2FS_CP_VALID_NODE_COUNT_OFF: usize = 32;
pub(super) const F2FS_CP_VALID_INODE_COUNT_OFF: usize = 36;
pub(super) const F2FS_CP_NAT_JOURNAL_COUNT_OFF: usize = 40;
pub(super) const F2FS_CP_SIT_JOURNAL_COUNT_OFF: usize = 44;
/// Start of the inline NAT journal area, twelve bytes per entry.
pub(super) const F2FS_CP_NAT_JOURNAL_OFF: usize = 48;

// The structural numbers the format fixes.

/// The block size a formatted volume uses.
pub(super) const F2FS_DEFAULT_BLOCK_SIZE: usize = 4096;
/// Direct block addresses stored inline in an inode.
pub(super) const F2FS_ADDRS_PER_INODE: usize = 923;
/// A NAT entry's size: block address plus owner inode.
pub(super) const F2FS_NAT_ENTRY_SIZE: usize = 8;
/// NAT entries one block holds.
pub(super) const F2FS_NAT_ENTRIES_PER_BLOCK: usize = F2FS_DEFAULT_BLOCK_SIZE / F2FS_NAT_ENTRY_SIZE;
/// The most inline NAT journal entries a checkpoint block keeps.
pub(super) const F2FS_MAX_NAT_JOURNAL_ENTRIES: usize = 512;
/// The root's NID.
pub(super) const F2FS_NID_ROOT: u32 = 3;
/// The block address a hole reads as.
pub(super) const F2FS_NULL_ADDR: u32 = 0x0000_0000;
/// The block address a freshly reserved node reads as.
pub(super) const F2FS_NEW_ADDR: u32 = 0xFFFF_FFFF;
