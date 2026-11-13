//! fs/src/ext4/format.rs
//!
//! Making a volume: the on-disk structures a fresh ext4 filesystem needs,
//! written onto a device so that [`super::Ext4Volume::open`] can mount it.
//!
//! ## Why the format lives here
//!
//! The write path proves itself on a host only if something can make the
//! volume it writes to, and this tree has no host tool to borrow: the tree
//! is the whole world, and a test that needs `mkfs.ext4` is a test the gate
//! cannot run.  So the formatter is here, next to the reader it makes
//! volumes for — a fresh volume is one superblock, one descriptor table per
//! group, the two bitmaps, the inode table, a root directory with its dot
//! entries, and a journal inode whose first block is a journal superblock.
//!
//! The layout is the smallest the format allows and every field the driver
//! reads is real: one kilobyte blocks, one group per few thousand blocks,
//! 128-byte inodes at revision one, the file-type and extents features set,
//! and the journal feature with inode 8 carrying a real journal
//! superblock — so a formatted volume exercises the write path's
//! write-ahead logging end to end.

use alloc::vec;
use alloc::vec::Vec;

use crate::block_cache::BlockCache;
use block::BLOCK_SIZE;

use abi::Error;
use abi::Result;

use super::constants::*;

/// How many journal blocks a fresh volume's journal gets.
const JOURNAL_BLOCKS: u32 = 64;

/// Write a fresh ext4 volume onto `device`.
///
/// The device is the queued half, because the cache writes through it; a
/// formatted volume is readable by [`super::Ext4Volume::open`] on the same
/// device, which is the round trip the tests run.
pub(super) fn format(device: &BlockCache, total_blocks: u32) -> Result<()> {
    // One kilobyte blocks: the smallest the format allows, which keeps a
    // test volume's group count and inode table small enough to read whole.
    const LOG_BLOCK_SIZE: u32 = 0;
    let block_size = 1024usize;
    assert_eq!(block_size, 1024);

    let blocks_per_group = (block_size * 8) as u32;
    let inodes_per_group: u32 = 128;
    let inode_size: u16 = 128;
    let groups = total_blocks.div_ceil(blocks_per_group);

    // The journal takes its blocks out of group zero's data area, before
    // anything else allocates there.
    let journal_blocks = JOURNAL_BLOCKS.max(2);

    // Per-group layout, in blocks: bitmap, inode bitmap, inode table, then
    // data.
    let inode_table_blocks =
        (inodes_per_group as usize * inode_size as usize).div_ceil(block_size) as u32;

    // Where each group's metadata starts.  Group zero carries the
    // superblock and descriptor table before its own bitmaps.
    let superblock_block: u32 = 1;
    let bgdt_block: u32 = 2;
    let mut next_block: u32 = bgdt_block + groups; // one 32-byte entry each, far under a block
    let mut group_starts: Vec<u32> = Vec::with_capacity(groups as usize);
    for _ in 0..groups {
        group_starts.push(next_block);
        next_block += 1 // block bitmap
            + 1 // inode bitmap
            + inode_table_blocks;
    }
    // The journal lives at the first group's data area.
    let journal_start = next_block;
    next_block += journal_blocks;
    // The root directory's data block.
    let root_data_block = next_block;
    next_block += 1;

    if next_block > total_blocks {
        return Err(Error::OutOfMemory);
    }

    let write_block = |device: &BlockCache, block: u32, data: &[u8]| -> Result<()> {
        let lba = block as u64 * (block_size as u64 / BLOCK_SIZE as u64);
        for i in 0..(block_size / BLOCK_SIZE) {
            device.write_through(lba + i as u64, &data[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE])?;
        }
        Ok(())
    };

    // ── the superblock ───────────────────────────────────────────────────

    let mut sb = vec![0_u8; block_size];
    sb[0x00..0x04].copy_from_slice(&total_blocks.to_le_bytes()); // inodes_count placeholder
    sb[0x04..0x08].copy_from_slice(&total_blocks.to_le_bytes());
    // free counts are written back by the driver's own flush, and a fresh
    // volume's numbers are computed below.
    let free_blocks = total_blocks - next_block;
    sb[0x0C..0x10].copy_from_slice(&free_blocks.to_le_bytes());
    let inodes_count = inodes_per_group * groups;
    let free_inodes = inodes_count - 3; // root, the bad-block inode, the journal
    sb[0x00..0x04].copy_from_slice(&inodes_count.to_le_bytes());
    sb[0x10..0x14].copy_from_slice(&free_inodes.to_le_bytes());
    sb[0x18..0x1C].copy_from_slice(&LOG_BLOCK_SIZE.to_le_bytes());
    sb[0x20..0x24].copy_from_slice(&blocks_per_group.to_le_bytes());
    sb[0x28..0x2C].copy_from_slice(&inodes_per_group.to_le_bytes());
    sb[0x38..0x3A].copy_from_slice(&EXT4_MAGIC.to_le_bytes());
    sb[0x4C..0x50].copy_from_slice(&1u32.to_le_bytes()); // rev_level
    sb[0x58..0x5A].copy_from_slice(&inode_size.to_le_bytes());
    sb[0x5C..0x60].copy_from_slice(&EXT4_FEATURE_COMPAT_HAS_JOURNAL.to_le_bytes());
    sb[0x60..0x64].copy_from_slice(
        &(EXT4_FEATURE_INCOMPAT_FILETYPE | EXT4_FEATURE_INCOMPAT_EXTENTS).to_le_bytes(),
    );
    // The first usable non-reserved inode for a rev-1 volume.
    sb[0x54..0x58].copy_from_slice(&11u32.to_le_bytes());
    write_block(device, superblock_block, &sb)?;

    // ── the group descriptors ────────────────────────────────────────────

    let mut bgdt = vec![0_u8; block_size];
    for (group, start) in group_starts.iter().enumerate() {
        let block_bitmap = *start;
        let inode_bitmap = start + 1;
        let inode_table = start + 2;
        let group_data_start = inode_table + inode_table_blocks;
        let journal_here = group == 0;
        let group_data_end = ((group as u32 + 1) * blocks_per_group).min(total_blocks);
        let data_blocks_in_group = group_data_end.saturating_sub(group_data_start);
        let free =
            data_blocks_in_group.saturating_sub(if journal_here { journal_blocks } else { 0 } + 1);
        let offset = group * 32;
        let e = &mut bgdt[offset..offset + 32];
        e[0x00..0x04].copy_from_slice(&block_bitmap.to_le_bytes());
        e[0x04..0x08].copy_from_slice(&inode_bitmap.to_le_bytes());
        e[0x08..0x0C].copy_from_slice(&inode_table.to_le_bytes());
        e[0x0C..0x0E].copy_from_slice(&(free as u16).to_le_bytes());
        e[0x0E..0x10].copy_from_slice(&((inodes_per_group as u16) - 3).to_le_bytes());
        e[0x10..0x12].copy_from_slice(&if journal_here { 1u16 } else { 0 }.to_le_bytes());
    }
    write_block(device, bgdt_block, &bgdt)?;

    // ── the bitmaps and inode tables ─────────────────────────────────────

    for (group, start) in group_starts.iter().enumerate() {
        let block_bitmap = *start;
        let inode_bitmap = start + 1;
        let inode_table = start + 2;
        let group_data_start = inode_table + inode_table_blocks;
        let journal_here = group == 0;

        // The block bitmap: everything through the metadata above, the
        // journal's blocks in group zero, and the root's data block.
        let mut bitmap = vec![0_u8; block_size];
        let used_through = group_data_start;
        for block in 0..used_through.min(total_blocks) {
            bitmap[(block / 8) as usize] |= 1 << (block % 8);
        }
        if journal_here {
            for block in journal_start..journal_start + journal_blocks {
                bitmap[(block / 8) as usize] |= 1 << (block % 8);
            }
            bitmap[(root_data_block / 8) as usize] |= 1 << (root_data_block % 8);
        }
        write_block(device, block_bitmap, &bitmap)?;

        // The inode bitmap: inodes 1 (the bad-block inode), 2 (root) and 8
        // (journal) are taken; bit N maps to inode N + 1.
        let mut ibitmap = vec![0_u8; block_size];
        for ino in [1u32, 2, EXT4_JOURNAL_INO] {
            let bit = (ino - 1) as usize;
            ibitmap[bit / 8] |= 1 << (bit % 8);
        }
        write_block(device, inode_bitmap, &ibitmap)?;

        // The inode table: zeroed, with the three reserved inodes filled.
        let mut table = vec![0_u8; inode_table_blocks as usize * block_size];
        for (i, chunk) in table.chunks_mut(block_size).enumerate() {
            write_block(device, inode_table + i as u32, chunk)?;
        }

        let write_inode = |device: &BlockCache, ino: u32, fill: &dyn Fn(&mut [u8])| -> Result<()> {
            let index = (ino - 1) as usize;
            let per_block = block_size / inode_size as usize;
            let block = inode_table + (index / per_block) as u32;
            let within = (index % per_block) * inode_size as usize;
            let mut buf = vec![0_u8; block_size];
            // Read back what the zero-fill wrote, so the other inodes in
            // this block survive.
            let lba = block as u64 * (block_size as u64 / BLOCK_SIZE as u64);
            for i in 0..(block_size / BLOCK_SIZE) {
                device.read_cached(
                    lba + i as u64,
                    &mut buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE],
                )?;
            }
            let raw = &mut buf[within..within + inode_size as usize];
            raw.fill(0);
            fill(raw);
            write_block(device, block, &buf)
        };

        // The bad-block inode, which the format reserves and nothing uses.
        write_inode(device, 1, &|raw| {
            raw[0x00..0x02].copy_from_slice(&EXT4_S_IFREG.to_le_bytes());
            raw[0x1A..0x1C].copy_from_slice(&1u16.to_le_bytes());
        })?;

        // The root directory: a directory inode whose one block holds the
        // dot entries.
        write_inode(device, 2, &|raw| {
            raw[0x00..0x02].copy_from_slice(&(EXT4_S_IFDIR | 0o755).to_le_bytes());
            raw[0x04..0x08].copy_from_slice(&(block_size as u32).to_le_bytes());
            raw[0x1A..0x1C].copy_from_slice(&3u16.to_le_bytes()); // ".", "..", the parent's view
            raw[40..44].copy_from_slice(&root_data_block.to_le_bytes());
        })?;

        // The journal inode: a regular file whose first block is the
        // journal's superblock.
        write_inode(device, EXT4_JOURNAL_INO, &|raw| {
            raw[0x00..0x02].copy_from_slice(&(EXT4_S_IFREG | 0o600).to_le_bytes());
            raw[0x04..0x08].copy_from_slice(&(journal_blocks * block_size as u32).to_le_bytes());
            raw[0x1A..0x1C].copy_from_slice(&1u16.to_le_bytes());
            raw[40..44].copy_from_slice(&journal_start.to_le_bytes());
        })?;
    }

    // ── the root directory's block: the dot entries ──────────────────────

    let mut root = vec![0_u8; block_size];
    // "." points at the root itself, and spans the whole block so that the
    // first real entry the write path adds rides in this block's slack —
    // which is what add_dir_entry's shrink-and-insert expects to find.
    root[0x00..0x04].copy_from_slice(&2u32.to_le_bytes());
    root[0x04..0x06].copy_from_slice(&12u16.to_le_bytes());
    root[0x06] = 1;
    root[0x07] = EXT4_FT_DIR;
    root[8] = b'.';
    // ".." also points at the root: the root's parent is itself.
    root[12..16].copy_from_slice(&2u32.to_le_bytes());
    root[16..18].copy_from_slice(&(block_size as u16 - 12).to_le_bytes());
    root[18] = 2;
    root[19] = EXT4_FT_DIR;
    root[20] = b'.';
    root[21] = b'.';
    write_block(device, root_data_block, &root)?;

    // ── the journal's superblock ─────────────────────────────────────────

    let mut jsb = vec![0_u8; block_size];
    super::journal::write_u32_be(
        &mut jsb,
        super::journal::J_S_MAGIC,
        super::journal::JBD2_MAGIC,
    );
    super::journal::write_u32_be(
        &mut jsb,
        super::journal::J_S_BLOCKTYPE,
        super::journal::JBD2_SUPERBLOCK_V2,
    );
    super::journal::write_u32_be(&mut jsb, super::journal::J_S_SEQUENCE, 0);
    super::journal::write_u32_be(&mut jsb, super::journal::J_S_MAXLEN, journal_blocks);
    super::journal::write_u32_be(&mut jsb, super::journal::J_S_BLOCKSIZE, block_size as u32);
    // A clean journal: start at the first block past the superblock, errno
    // zero, so the first mount replays nothing.
    super::journal::write_u32_be(&mut jsb, super::journal::J_S_START, 1);
    super::journal::write_u32_be(&mut jsb, super::journal::J_S_ERRNO, 0);
    write_block(device, journal_start, &jsb)?;

    device.flush()?;
    Ok(())
}
