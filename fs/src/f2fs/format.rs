//! fs/src/f2fs/format.rs
//!
//! Making a volume: the on-disk structures a fresh f2fs needs, written onto
//! a device so [`super::F2fsVolume::open`] can mount it.
//!
//! The layout is the smallest the format allows and every field the driver
//! reads is real: a 4-kilobyte block, two 512-block segments, a
//! superblock, two checkpoint copies with the newer one winning, one SIT
//! block, one NAT block, an SSA block, and a root directory whose dot
//! entries ride in the main area's first two blocks.  A fresh volume's
//! append writes land in segment zero's third block, which is what makes
//! the write path's proof self-contained.

use alloc::vec;
use alloc::vec::Vec;

use crate::block_cache::BlockCache;

use abi::Result;

use super::constants::*;
use super::types::*;

/// How many NAT entries a fresh volume's table holds.
const NAT_ENTRIES: u32 = 64;
/// How many segments a fresh volume has.
const SEGMENTS: u32 = 2;

/// Write a fresh f2fs volume onto `device`.
pub(super) fn format(cache: &BlockCache) -> Result<()> {
    let block_size = F2FS_DEFAULT_BLOCK_SIZE;
    let blocks_per_seg = 512u32; // 2 ^ log_blocks_per_seg
    let sectors_per_block = (block_size / 512) as u64;

    // The layout: superblock, two checkpoints, SIT, NAT, SSA, main.
    let cp0_blkaddr: u32 = 1;
    let cp1_blkaddr: u32 = 2;
    let sit_blkaddr: u32 = 3;
    let nat_blkaddr: u32 = 4;
    let ssa_blkaddr: u32 = 5;
    let main_blkaddr: u32 = 6;
    let root_inode_block = main_blkaddr;
    let root_data_block = main_blkaddr + 1;
    let total_blocks: u64 = main_blkaddr as u64 + blocks_per_seg as u64 * SEGMENTS as u64;

    let put_block = |cache: &BlockCache, blkaddr: u32, data: &[u8]| -> Result<()> {
        let lba = blkaddr as u64 * sectors_per_block;
        for i in 0..sectors_per_block as usize {
            cache.write_through(lba + i as u64, &data[i * 512..(i + 1) * 512])?;
        }
        Ok(())
    };

    // ── the superblock ───────────────────────────────────────────────────

    let sb = F2fsSuperblock {
        magic: F2FS_MAGIC,
        major_ver: 1,
        minor_ver: 0,
        log_sectorsize: 9,
        log_sectors_per_block: 3,
        log_blocksize: 12,
        log_blocks_per_seg: 9,
        segs_per_sec: 1,
        secs_per_zone: 1,
        checksum_offset: 0,
        block_count: total_blocks,
        section_count: SEGMENTS,
        segment_count: SEGMENTS,
        segment_count_main: SEGMENTS,
        segment0_blkaddr: main_blkaddr,
        cp_blkaddr: cp0_blkaddr,
        sit_blkaddr,
        nat_blkaddr,
        ssa_blkaddr,
        main_blkaddr,
        root_ino: F2FS_NID_ROOT,
        node_ino: 1,
        meta_ino: 2,
        cp_payload: 0,
        feature: 0,
        nat_entry_cnt: NAT_ENTRIES,
        sit_entry_cnt: SEGMENTS,
        node_count: 1,
    };
    let mut block = vec![0u8; block_size];
    write_f2fs_superblock(&sb, &mut block);
    put_block(cache, 0, &block)?;

    // ── the checkpoints ──────────────────────────────────────────────────

    let cp_winner = F2fsCheckpoint {
        check_ver: 1,
        nat_ver: 1,
        sit_ver: 1,
        next_free_nid: F2FS_NID_ROOT + 1,
        valid_block_count: 2,
        valid_node_count: 1,
        valid_inode_count: 1,
        nat_journal_entries: 0,
        nat_journal: Vec::new(),
        sit_journal_entries: 0,
        cp_copy: 0,
    };
    {
        let mut block = vec![0u8; block_size];
        write_f2fs_checkpoint(&cp_winner, &mut block);
        put_block(cache, cp0_blkaddr, &block)?;

        let mut loser = cp_winner.clone();
        loser.check_ver = 0;
        block.fill(0);
        write_f2fs_checkpoint(&loser, &mut block);
        put_block(cache, cp1_blkaddr, &block)?;
    }

    // ── the SIT: segment zero holds the root's two blocks ────────────────

    {
        let mut block = vec![0u8; block_size];
        let mut seg0 = F2fsSitEntry {
            vblocks: 2,
            valid_map: [0u8; 64],
        };
        seg0.valid_map[0] = 0x03; // the root inode and its data block
        write_sit_entry(&seg0, &mut block[0..66]);
        let seg1 = F2fsSitEntry {
            vblocks: 0,
            valid_map: [0u8; 64],
        };
        write_sit_entry(&seg1, &mut block[66..132]);
        put_block(cache, sit_blkaddr, &block)?;
    }

    // ── the NAT: the root's NID names its block ──────────────────────────

    {
        let mut block = vec![0u8; block_size];
        for nid in 0..NAT_ENTRIES {
            let entry = F2fsNatEntry {
                block_addr: if nid == F2FS_NID_ROOT {
                    root_inode_block
                } else {
                    F2FS_NULL_ADDR
                },
                ino: if nid == F2FS_NID_ROOT {
                    F2FS_NID_ROOT
                } else {
                    0
                },
            };
            let off = nid as usize * F2FS_NAT_ENTRY_SIZE;
            write_nat_entry(&entry, &mut block[off..off + F2FS_NAT_ENTRY_SIZE]);
        }
        put_block(cache, nat_blkaddr, &block)?;
    }

    // ── the SSA: written zeroed, and never read by this driver ───────────

    {
        let block = vec![0u8; block_size];
        put_block(cache, ssa_blkaddr, &block)?;
    }

    // ── the root inode, and its data block with the dot entries ──────────

    let mut root_inode = empty_root_inode();
    root_inode.i_addr[0] = root_data_block;
    let mut inode_block = vec![0u8; block_size];
    write_f2fs_inode(&root_inode, &mut inode_block);
    put_block(cache, root_inode_block, &inode_block)?;

    let mut data_block = vec![0u8; block_size];
    let mut offset = 0usize;
    offset += write_f2fs_dir_entry(
        F2FS_NID_ROOT,
        ".",
        F2FS_FT_DIR,
        0,
        &mut data_block[offset..],
    );
    write_f2fs_dir_entry(
        F2FS_NID_ROOT,
        "..",
        F2FS_FT_DIR,
        0,
        &mut data_block[offset..],
    );
    put_block(cache, root_data_block, &data_block)?;

    cache.flush()?;
    Ok(())
}

/// The root directory's inode, as the formatter writes it: links for the
/// dot entries, a size for the dot entries' records, one sector's worth of
/// blocks, and the data block in `i_addr[0]`.
fn empty_root_inode() -> F2fsInode {
    let mut inode = F2fsInode {
        i_mode: F2FS_S_IFDIR | 0o755,
        i_uid: 0,
        i_gid: 0,
        i_links: 2,
        i_size: (dir_entry_size(1) + dir_entry_size(2)) as u64,
        i_blocks: (F2FS_DEFAULT_BLOCK_SIZE as u64).div_ceil(512),
        i_atime: 0,
        i_ctime: 0,
        i_mtime: 0,
        i_atime_nsec: 0,
        i_ctime_nsec: 0,
        i_mtime_nsec: 0,
        i_xattr_nid: 0,
        i_flags: 0,
        i_addr: [F2FS_NULL_ADDR; F2FS_ADDRS_PER_INODE],
    };
    inode.i_addr[0] = F2FS_NULL_ADDR;
    inode
}
