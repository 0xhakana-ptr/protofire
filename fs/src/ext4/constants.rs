//! fs/src/ext4/constants.rs
//!
//! ext4's on-disk constants: the numbers the format fixes and this module's
//! arithmetic repeats.
//!
//! Each one is a fact about the format rather than a tuning of this driver:
//! the magic a volume answers with, where the superblock sits, the inode
//! model's block-pointer slots, and the feature bits this driver accepts.
//! A constant that moved would not be a tuning decision, it would be a
//! different format, which is why they are written once and named.

/// The magic a superblock answers with.
pub(super) const EXT4_MAGIC: u16 = 0xEF53;

/// Where the superblock sits, in bytes from the device's start: one
/// kilobyte, past the boot block the format reserves.
pub(super) const SUPERBLOCK_BYTE_OFFSET: u64 = 1024;

/// The superblock's length: one kilobyte, of which this driver reads the
/// fields it serves.
pub(super) const SUPERBLOCK_SIZE: usize = 1024;

/// The inode size a revision-zero volume uses.
pub(super) const EXT4_GOOD_OLD_INODE_SIZE: usize = 128;

/// The root directory's inode number.
pub(super) const EXT4_ROOT_INO: u32 = 2;

/// The reserved inode number the journal lives in.
pub(super) const EXT4_JOURNAL_INO: u32 = 8;

/// The block-pointer slots a direct block uses before the indirect ones
/// begin.
pub(super) const EXT4_NDIR_BLOCKS: usize = 12;

/// The slot that names the singly-indirect block.
pub(super) const EXT4_IND_BLOCK: usize = 12;

/// The slot that names the doubly-indirect block.
pub(super) const EXT4_DIND_BLOCK: usize = 13;

/// The slot that names the triply-indirect block.
pub(super) const EXT4_TIND_BLOCK: usize = 14;

/// Directory-entry file-type codes.
pub(super) const EXT4_FT_REG_FILE: u8 = 1;
pub(super) const EXT4_FT_DIR: u8 = 2;
pub(super) const EXT4_FT_CHRDEV: u8 = 3;
pub(super) const EXT4_FT_BLKDEV: u8 = 4;
pub(super) const EXT4_FT_SYMLINK: u8 = 7;

/// The mode word's file-type mask, and the types this driver reads.
pub(super) const EXT4_S_IFMT: u16 = 0xF000;
pub(super) const EXT4_S_IFREG: u16 = 0x8000;
pub(super) const EXT4_S_IFDIR: u16 = 0x4000;
pub(super) const EXT4_S_IFCHR: u16 = 0x2000;
pub(super) const EXT4_S_IFBLK: u16 = 0x6000;
pub(super) const EXT4_S_IFLNK: u16 = 0xA000;

/// Incompat features this driver reads: the directory entry's file-type
/// byte, the extent tree, a 64-bit block-number half, the flex-bg group
/// layout, and casefolded directories.
pub(super) const EXT4_FEATURE_INCOMPAT_FILETYPE: u32 = 0x0002;
pub(super) const EXT4_FEATURE_INCOMPAT_EXTENTS: u32 = 0x0040;
pub(super) const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x0080;
pub(super) const EXT4_FEATURE_INCOMPAT_FLEX_BG: u32 = 0x0200;
pub(super) const EXT4_FEATURE_INCOMPAT_CASEFOLD: u32 = 0x20000;

/// The whole set this driver accepts; anything else in the incompat word is
/// a volume this driver refuses, because an incompat feature it cannot read
/// would make every byte it read a guess.
pub(super) const EXT4_FEATURE_INCOMPAT_SUPPORTED: u32 = EXT4_FEATURE_INCOMPAT_FILETYPE
    | EXT4_FEATURE_INCOMPAT_EXTENTS
    | EXT4_FEATURE_INCOMPAT_64BIT
    | EXT4_FEATURE_INCOMPAT_FLEX_BG
    | EXT4_FEATURE_INCOMPAT_CASEFOLD;

/// Compat feature: the volume carries a journal in inode 8.
pub(super) const EXT4_FEATURE_COMPAT_HAS_JOURNAL: u32 = 0x0004;

/// `inode.flags` bit: the file's blocks are mapped by an extent tree.
pub(super) const EXT4_EXTENTS_FL: u32 = 0x0008_0000;

/// `inode.flags` bit: the directory's names match case-insensitively.
pub(super) const EXT4_CASEFOLD_FL: u32 = 0x4000_0000;

/// The extent-tree node header's magic.
pub(super) const EXT4_EXT_MAGIC: u16 = 0xF30A;

/// How many block pointers one indirect block holds.
pub(super) const fn ptrs_per_block(block_size: usize) -> usize {
    block_size / 4
}
