//! fs/src/f2fs/data.rs
//!
//! File data writes: the log-structured read-modify-write.  Every affected
//! logical block's new content goes to a *fresh* physical block, and the
//! inode's pointer moves there, the old block is invalidated in the SIT,
//! never erased.

use abi::Result;

use super::constants::*;
use super::fs::F2fsFs;

impl F2fsFs {
    /// Write data to a file at `offset`.
    ///
    /// A block that already exists is read, modified, and written to a new
    /// physical block; a hole or a fresh block is built from zeroes with the
    /// data placed at its offset.  The inode's size moves when the write
    /// runs past the end, and its sector count with it.
    pub(super) fn write_file_data(&self, nid: u32, offset: u64, data: &[u8]) -> Result<usize> {
        self.check_writable()?;

        if data.is_empty() {
            return Ok(0);
        }

        let block_size = self.block_size() as u64;
        let mut inode = self.read_inode(nid)?;

        let start_block = (offset / block_size) as usize;
        let end_pos = offset + data.len() as u64;
        let end_block = end_pos.div_ceil(block_size) as usize;

        let mut data_pos = 0usize;

        for (blk_idx, addr_slot) in inode.i_addr.iter_mut().enumerate().skip(start_block) {
            if blk_idx >= end_block {
                break;
            }

            let block_start = blk_idx as u64 * block_size;
            let block_end = block_start + block_size;
            let seg_start = offset.max(block_start);
            let seg_end = end_pos.min(block_end);
            let seg_len = (seg_end - seg_start) as usize;

            let old_phys = *addr_slot;

            let mut buf = self.block_buf.lock();
            buf.resize(self.block_size(), 0);

            if old_phys != F2FS_NULL_ADDR && old_phys != F2FS_NEW_ADDR {
                // Read, modify, write, the old content around the written
                // range survives.
                self.read_fs_block(old_phys, &mut buf[..])?;
                let write_start = (seg_start - block_start) as usize;
                buf[write_start..write_start + seg_len]
                    .copy_from_slice(&data[data_pos..data_pos + seg_len]);
            } else {
                // A hole or a fresh block: zeroes, with the data at its
                // offset.
                buf.fill(0);
                let write_start = (seg_start - block_start) as usize;
                let copy_len = seg_len.min(block_size as usize - write_start);
                buf[write_start..write_start + copy_len]
                    .copy_from_slice(&data[data_pos..data_pos + copy_len]);
            }

            let new_phys = self.segment_alloc_block(&buf[..])?;
            *addr_slot = new_phys;

            data_pos += seg_len;
        }

        if end_pos > inode.i_size {
            inode.i_size = end_pos;
        }

        inode.i_blocks = inode.i_size.div_ceil(512);

        self.write_inode(nid, &inode)?;

        Ok(data.len())
    }
}
