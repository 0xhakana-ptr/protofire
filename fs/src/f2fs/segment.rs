//! fs/src/f2fs/segment.rs
//!
//! Segment management: the append-only allocation a log-structured volume
//! writes through, and the SIT invalidation that stands in for freeing.

use abi::Error;
use abi::Result;

use super::constants::*;
use super::fs::F2fsFs;

impl F2fsFs {
    /// Allocate the next block of the active segment and write `data` to it.
    ///
    /// A full segment hands the writer the next free one.  The address the
    /// call answers is where the data now lives — the caller's pointer moves
    /// there, because nothing is overwritten.
    pub(super) fn segment_alloc_block(&self, data: &[u8]) -> Result<u32> {
        self.check_writable()?;

        let blocks_per_seg = self.sb.blocks_per_seg();
        let mut cur_seg = self.cur_seg.lock();
        let mut cur_off = self.cur_seg_off.lock();

        if *cur_off as u32 >= blocks_per_seg {
            let mut sit = self.sit_cache.lock();
            if let Some(new_seg) = sit.free_segments.first().copied() {
                sit.free_segments.remove(0);
                drop(sit);
                *cur_seg = new_seg;
                *cur_off = 0;
            } else {
                return Err(Error::DeviceError);
            }
        }

        let phys = self.sb.segment0_blkaddr + *cur_seg * blocks_per_seg + *cur_off as u32;

        self.write_fs_block(phys, data)?;

        {
            let mut sit = self.sit_cache.lock();
            if (*cur_seg as usize) < sit.entries.len() {
                sit.entries[*cur_seg as usize].mark_valid(*cur_off as u16);
            }
            let mut dirty = self.dirty_sit.lock();
            if !dirty.contains(&*cur_seg) {
                dirty.push(*cur_seg);
            }
        }

        *cur_off += 1;

        Ok(phys)
    }

    /// Invalidate one mapped block: the truncation path's own mark, for a
    /// block the inode's pointer has already let go of.
    pub(super) fn invalidate_mapped_block(&self, phys: u32) {
        let blocks_per_seg = self.sb.blocks_per_seg();
        let segment0 = self.sb.segment0_blkaddr;
        if phys < segment0 {
            return;
        }
        let rel = phys - segment0;
        let segno = rel / blocks_per_seg;
        let offset = (rel % blocks_per_seg) as u16;
        let mut sit = self.sit_cache.lock();
        if (segno as usize) < sit.entries.len() {
            sit.entries[segno as usize].mark_invalid(offset);
        }
        drop(sit);
        let mut dirty = self.dirty_sit.lock();
        if !dirty.contains(&segno) {
            dirty.push(segno);
        }
    }

    /// Invalidate every data block an inode still maps — the SIT's bits go
    /// to zero, the segment joins the free list when its last valid block
    /// goes.  Nothing is erased: reclamation is the garbage collector's
    /// work, and this build has none.
    pub(super) fn free_inode_blocks(&self, nid: u32) -> Result<()> {
        let inode = self.read_inode(nid)?;
        let blocks_per_seg = self.sb.blocks_per_seg();
        let segment0 = self.sb.segment0_blkaddr;

        for addr in &inode.i_addr {
            if *addr == F2FS_NULL_ADDR || *addr == F2FS_NEW_ADDR {
                continue;
            }

            let phys = *addr;
            if phys < segment0 {
                continue;
            }

            let rel = phys - segment0;
            let segno = rel / blocks_per_seg;
            let offset = (rel % blocks_per_seg) as u16;

            let mut sit = self.sit_cache.lock();
            if (segno as usize) < sit.entries.len() {
                let was_valid = sit.entries[segno as usize].is_valid(offset);
                sit.entries[segno as usize].mark_invalid(offset);

                if was_valid
                    && sit.entries[segno as usize].vblocks == 0
                    && !sit.free_segments.contains(&segno)
                {
                    sit.free_segments.push(segno);
                }
            }

            let mut dirty = self.dirty_sit.lock();
            if !dirty.contains(&segno) {
                dirty.push(segno);
            }
        }

        Ok(())
    }
}
