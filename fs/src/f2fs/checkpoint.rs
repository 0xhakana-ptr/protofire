//! fs/src/f2fs/checkpoint.rs
//!
//! The checkpoint: two copies, the newer one wins, and a new one is written
//! to the *other* copy with its version bumped, which is what leaves a
//! valid copy on the disk no matter when the write is interrupted.
//!
//! The checkpoint also carries the NAT journal, and the NAT and SIT caches
//! are built from the disk areas plus that journal at mount.

use alloc::vec;
use alloc::vec::Vec;

use crate::block_cache::BlockCache;

use abi::Result;

use super::constants::*;
use super::fs::F2fsFs;
use super::types::*;

impl F2fsFs {
    /// Read both checkpoint copies and return the newer one.
    ///
    /// Copy 0 sits at `cp_blkaddr`, copy 1 at `cp_blkaddr + cp_payload + 1`;
    /// the larger `check_ver` is the one the crash left newer.
    pub(super) fn read_checkpoint(
        cache: &BlockCache,
        sb: &F2fsSuperblock,
    ) -> Result<F2fsCheckpoint> {
        let block_size = sb.block_size();
        let sector_count = block_size / 512;
        let cp1_blkaddr = sb.cp_blkaddr + sb.cp_payload + 1;

        let read_copy = |blkaddr: u32| -> Result<Vec<u8>> {
            let mut buf = vec![0u8; block_size];
            let lba = blkaddr as u64 * sector_count as u64;
            for i in 0..sector_count {
                cache.read_cached(lba + i as u64, &mut buf[i * 512..(i + 1) * 512])?;
            }
            Ok(buf)
        };

        let buf0 = read_copy(sb.cp_blkaddr)?;
        let ver0 = read_cp_version(&buf0);
        let buf1 = read_copy(cp1_blkaddr)?;
        let ver1 = read_cp_version(&buf1);

        if ver0 >= ver1 {
            Ok(parse_f2fs_checkpoint(&buf0, 0))
        } else {
            Ok(parse_f2fs_checkpoint(&buf1, 1))
        }
    }

    /// Write a new checkpoint to the *other* copy, version bumped.
    ///
    /// The dirty NAT entries flush to the NAT area first, the valid counts
    /// come from the caches, and the block goes through write-through, a
    /// checkpoint the cache held back would be a recovery point the disk
    /// never saw.
    pub(super) fn write_checkpoint(&self) -> Result<()> {
        let mut cp = self.checkpoint.lock().clone();

        self.flush_dirty_nat()?;

        cp.check_ver += 1;
        cp.nat_ver += 1;
        cp.sit_ver += 1;

        {
            let dirty = self.dirty_nat.lock();
            cp.nat_journal_entries = dirty.len() as u32;
        }

        {
            let nat = self.nat_cache.lock();
            let sit = self.sit_cache.lock();
            cp.valid_node_count = nat
                .entries
                .iter()
                .filter(|e| e.block_addr != F2FS_NULL_ADDR)
                .count() as u32;
            cp.valid_block_count = sit.entries.iter().map(|e| e.vblocks as u32).sum();
            cp.valid_inode_count = nat
                .entries
                .iter()
                .filter(|e| e.block_addr != F2FS_NULL_ADDR)
                .count() as u32;
        }
        cp.next_free_nid = *self.next_nid.lock();

        let new_copy = if cp.cp_copy == 0 { 1u8 } else { 0u8 };
        cp.cp_copy = new_copy;

        let block_size = self.block_size();
        let mut buf = vec![0u8; block_size];
        write_f2fs_checkpoint(&cp, &mut buf);

        let cp_blkaddr = if new_copy == 0 {
            self.sb.cp_blkaddr
        } else {
            self.sb.cp_blkaddr + self.sb.cp_payload + 1
        };

        let lba = self.block_to_lba(cp_blkaddr);
        let sector_count = self.sectors_per_block() as usize;
        for i in 0..sector_count {
            self.cache
                .write_through(lba + i as u64, &buf[i * 512..(i + 1) * 512])?;
        }

        *self.checkpoint.lock() = cp;

        Ok(())
    }

    /// Flush the dirty NAT entries to the NAT area, one block at a time.
    fn flush_dirty_nat(&self) -> Result<()> {
        let dirty: Vec<(u32, F2fsNatEntry)> = {
            let mut guard = self.dirty_nat.lock();
            let entries: Vec<_> = guard.iter().map(|(k, v)| (*k, *v)).collect();
            guard.clear();
            entries
        };

        if dirty.is_empty() {
            return Ok(());
        }

        let block_size = self.block_size();
        let mut buf = vec![0u8; block_size];

        for (nid, entry) in &dirty {
            let nat_block_idx = *nid / F2FS_NAT_ENTRIES_PER_BLOCK as u32;
            let nat_block = self.sb.nat_blkaddr + nat_block_idx;

            self.read_fs_block(nat_block, &mut buf)?;

            let entry_off = (*nid as usize % F2FS_NAT_ENTRIES_PER_BLOCK) * F2FS_NAT_ENTRY_SIZE;
            write_nat_entry(entry, &mut buf[entry_off..entry_off + F2FS_NAT_ENTRY_SIZE]);

            self.write_fs_block(nat_block, &buf)?;
        }

        Ok(())
    }

    /// Build the NAT cache from the NAT area, with the checkpoint's journal
    /// applied over it, the journal's entries are the newer facts.
    pub(super) fn init_nat_cache(
        cache: &BlockCache,
        sb: &F2fsSuperblock,
        cp: &F2fsCheckpoint,
    ) -> Result<F2fsNatCache> {
        let block_size = sb.block_size();
        let sector_count = block_size / 512;
        let nat_blocks = (sb.nat_entry_cnt as usize).div_ceil(F2FS_NAT_ENTRIES_PER_BLOCK);

        let total_entries = sb.nat_entry_cnt as usize;
        let mut entries = Vec::with_capacity(total_entries);

        for blk in 0..nat_blocks {
            let mut buf = vec![0u8; block_size];
            let phys = sb.nat_blkaddr as u64 + blk as u64;
            let lba = phys * sector_count as u64;
            for i in 0..sector_count {
                cache.read_cached(lba + i as u64, &mut buf[i * 512..(i + 1) * 512])?;
            }
            for j in 0..F2FS_NAT_ENTRIES_PER_BLOCK {
                let off = j * F2FS_NAT_ENTRY_SIZE;
                if off + F2FS_NAT_ENTRY_SIZE <= buf.len() {
                    entries.push(parse_nat_entry(&buf[off..off + F2FS_NAT_ENTRY_SIZE]));
                }
            }
        }

        entries.truncate(total_entries);

        let mut nat_cache = F2fsNatCache { entries };

        for entry in &cp.nat_journal {
            let nid = entry.nid as usize;
            if nid < nat_cache.entries.len() {
                nat_cache.entries[nid] = entry.ne;
            }
        }

        Ok(nat_cache)
    }

    /// Build the SIT cache from the SIT area, and the free-segment list
    /// from the entries whose valid count is zero.
    pub(super) fn init_sit_cache(cache: &BlockCache, sb: &F2fsSuperblock) -> Result<F2fsSitCache> {
        let block_size = sb.block_size();
        let sector_count = block_size / 512;

        // A SIT entry is sixty-six bytes; a block holds as many as fit.
        let entries_per_block = block_size / 66;
        let sit_blocks = (sb.sit_entry_cnt as usize).div_ceil(entries_per_block);

        let total_entries = sb.sit_entry_cnt as usize;
        let mut entries = Vec::with_capacity(total_entries);

        for blk in 0..sit_blocks {
            let mut buf = vec![0u8; block_size];
            let phys = sb.sit_blkaddr + blk as u32;
            let lba = phys as u64 * sector_count as u64;
            for i in 0..sector_count {
                cache.read_cached(lba + i as u64, &mut buf[i * 512..(i + 1) * 512])?;
            }
            let n_in_block = (total_entries - entries.len()).min(entries_per_block);
            for j in 0..n_in_block {
                let off = j * 66;
                if off + 66 <= buf.len() {
                    entries.push(parse_sit_entry(&buf[off..off + 66]));
                }
            }
        }

        entries.truncate(total_entries);

        let mut free_segments = Vec::new();
        for (i, entry) in entries.iter().enumerate() {
            if entry.vblocks == 0 {
                free_segments.push(i as u32);
            }
        }

        Ok(F2fsSitCache {
            entries,
            free_segments,
        })
    }

    /// The first free segment, for the append writes to land in.
    pub(super) fn find_first_free_segment(sit_cache: &F2fsSitCache) -> (u32, u16) {
        if let Some(&segno) = sit_cache.free_segments.first() {
            (segno, 0)
        } else {
            // No fully free segment: fall back to segment zero's start,
            // whose write fails the way a full volume should.
            (0, 0)
        }
    }

    /// Write the superblock back to block zero.
    pub(super) fn write_superblock(&self) -> Result<()> {
        let block_size = self.block_size();
        let mut buf = vec![0u8; block_size];
        write_f2fs_superblock(&self.sb, &mut buf);
        self.write_fs_block(0, &buf)
    }
}

/// A checkpoint copy's version, from its first eight bytes.
fn read_cp_version(raw: &[u8]) -> u64 {
    u64::from_le_bytes([
        raw[F2FS_CP_CHECK_VER_OFF],
        raw[F2FS_CP_CHECK_VER_OFF + 1],
        raw[F2FS_CP_CHECK_VER_OFF + 2],
        raw[F2FS_CP_CHECK_VER_OFF + 3],
        raw[F2FS_CP_CHECK_VER_OFF + 4],
        raw[F2FS_CP_CHECK_VER_OFF + 5],
        raw[F2FS_CP_CHECK_VER_OFF + 6],
        raw[F2FS_CP_CHECK_VER_OFF + 7],
    ])
}
