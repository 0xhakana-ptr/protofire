//! fs/src/f2fs/node.rs
//!
//! The NAT: node ids are allocated by scanning forward from the
//! checkpoint's hint, freed by zeroing their entry, and updated through the
//! cache with the dirty set recording what the next checkpoint must flush.

use abi::Error;
use abi::Result;

use super::constants::*;
use super::fs::F2fsFs;
use super::types::F2fsNatEntry;

impl F2fsFs {
    /// Allocate a NID, reserving it with `NEW_ADDR` until its inode block is
    /// actually written — a reservation a crash leaves behind is a NID the
    /// next scan finds and reuses, which is what the sentinel is for.
    pub(super) fn nat_alloc_nid(&self) -> Result<u32> {
        let mut next = self.next_nid.lock();
        let nat = self.nat_cache.lock();
        let total = nat.entries.len() as u32;

        let start = *next;
        loop {
            if *next >= total {
                *next = F2FS_NID_ROOT + 1;
            }
            let nid = *next;
            *next += 1;

            if let Some(entry) = nat.entries.get(nid as usize)
                && entry.block_addr == F2FS_NULL_ADDR
            {
                drop(nat);
                self.nat_update(nid, F2FS_NEW_ADDR)?;
                return Ok(nid);
            }

            // A whole lap with nothing free: the volume is out of nodes.
            if *next == start {
                break;
            }
        }

        Err(Error::DeviceError)
    }

    /// Free a NID, and point the allocator's hint at it so it is reused
    /// soon.
    pub(super) fn nat_free_nid(&self, nid: u32) -> Result<()> {
        self.nat_update(nid, F2FS_NULL_ADDR)?;
        let mut next = self.next_nid.lock();
        if nid < *next {
            *next = nid;
        }
        Ok(())
    }

    /// Point `nid`'s NAT entry at `block_addr`, in the cache now and in the
    /// dirty set for the checkpoint that will land it.
    pub(super) fn nat_update(&self, nid: u32, block_addr: u32) -> Result<()> {
        {
            let mut nat = self.nat_cache.lock();
            if (nid as usize) < nat.entries.len() {
                nat.entries[nid as usize].block_addr = block_addr;
            } else {
                return Err(Error::NotFound);
            }
        }

        {
            let mut dirty = self.dirty_nat.lock();
            dirty.insert(nid, F2fsNatEntry { block_addr, ino: 0 });
        }

        Ok(())
    }
}
