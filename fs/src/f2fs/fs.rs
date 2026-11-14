//! fs/src/f2fs/fs.rs
//!
//! The volume's core: mount, geometry, block input and output, inode input
//! and output, directory scan and mutation, path resolution with symlinks,
//! file reading, and the flush that checkpoints everything behind it.
//!
//! ## What this volume's model is
//!
//! f2fs is log-structured: a write never overwrites the block it names, it
//! appends a fresh one to the active segment and moves the pointer.  The
//! NAT says where each node's newest block is; the SIT says which blocks in
//! each segment are still valid; the checkpoint commits both.  Old blocks
//! are invalidated, never erased, reclamation is the garbage collector's
//! work, and this build has none, which is why freeing is a SIT mark and
//! the volume's writes are append-only.

use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use block::BLOCK_SIZE as DEV_BLOCK_SIZE;
use sync::Mutex;

use abi::Error;
use abi::Result;

use crate::block_cache::BlockCache;
use crate::types::Metadata;
use crate::types::NodeKind;
use crate::types::SecurityDescriptor;

use super::constants::*;
use super::types::*;

/// The volume's internal state, shared between the [`super::F2fsVolume`]
/// and every node it hands out.
pub(super) struct F2fsFs {
    pub(super) device: Arc<dyn block::QueuedBlockDevice>,
    pub(super) cache: BlockCache,
    pub(super) sb: F2fsSuperblock,
    pub(super) checkpoint: Mutex<F2fsCheckpoint>,
    pub(super) nat_cache: Mutex<F2fsNatCache>,
    pub(super) sit_cache: Mutex<F2fsSitCache>,
    pub(super) cur_seg: Mutex<u32>,
    pub(super) cur_seg_off: Mutex<usize>,
    pub(super) block_buf: Mutex<Vec<u8>>,
    /// Whether the device refused writes to begin with.
    pub(super) read_only: bool,
    /// NAT entries changed since the last checkpoint, by NID.
    pub(super) dirty_nat: Mutex<alloc::collections::BTreeMap<u32, F2fsNatEntry>>,
    /// Segment numbers changed since the last checkpoint.
    pub(super) dirty_sit: Mutex<Vec<u32>>,
    /// The allocator's hint for where to scan next.
    pub(super) next_nid: Mutex<u32>,
}

impl F2fsFs {
    /// Open a volume: validate the superblock, take the newer checkpoint
    /// copy, build the NAT and SIT caches, and find the first free segment.
    pub(super) fn open(device: Arc<dyn block::QueuedBlockDevice>) -> Result<Self> {
        let read_only = device.is_read_only();
        let cache = BlockCache::new(device.clone());

        let sb = Self::read_superblock(&cache)?;
        let checkpoint = Self::read_checkpoint(&cache, &sb)?;
        let nat_cache = Self::init_nat_cache(&cache, &sb, &checkpoint)?;
        let sit_cache = Self::init_sit_cache(&cache, &sb)?;
        let (cur_seg, cur_off) = Self::find_first_free_segment(&sit_cache);
        let cur_seg_off = cur_off as usize;

        let block_size = sb.block_size();
        let block_buf = Mutex::new(vec![0u8; block_size]);
        let next_nid = Mutex::new(checkpoint.next_free_nid.max(F2FS_NID_ROOT + 1));

        Ok(Self {
            device,
            cache,
            sb,
            checkpoint: Mutex::new(checkpoint),
            nat_cache: Mutex::new(nat_cache),
            sit_cache: Mutex::new(sit_cache),
            cur_seg: Mutex::new(cur_seg),
            cur_seg_off: Mutex::new(cur_seg_off),
            block_buf,
            read_only,
            dirty_nat: Mutex::new(alloc::collections::BTreeMap::new()),
            dirty_sit: Mutex::new(Vec::new()),
            next_nid,
        })
    }

    /// Read and validate the superblock from block zero.
    fn read_superblock(cache: &BlockCache) -> Result<F2fsSuperblock> {
        let block_size = F2FS_DEFAULT_BLOCK_SIZE;
        let sector_count = block_size / DEV_BLOCK_SIZE;
        let mut buf = vec![0u8; block_size];
        for i in 0..sector_count {
            cache.read_cached(
                i as u64,
                &mut buf[i * DEV_BLOCK_SIZE..(i + 1) * DEV_BLOCK_SIZE],
            )?;
        }

        let sb = parse_f2fs_superblock(&buf);
        if sb.magic != F2FS_MAGIC {
            return Err(Error::InvalidArgument);
        }

        Ok(sb)
    }

    // geometry

    pub(super) fn block_size(&self) -> usize {
        self.sb.block_size()
    }

    pub(super) fn sectors_per_block(&self) -> u64 {
        self.block_size() as u64 / DEV_BLOCK_SIZE as u64
    }

    pub(super) fn block_to_lba(&self, blkaddr: u32) -> u64 {
        blkaddr as u64 * self.sectors_per_block()
    }

    // block I/O

    /// Read one f2fs block whole.
    pub(super) fn read_fs_block(&self, blkaddr: u32, buffer: &mut [u8]) -> Result<()> {
        let lba = self.block_to_lba(blkaddr);
        let sector_count = self.sectors_per_block() as usize;
        for i in 0..sector_count {
            let sector_buf = &mut buffer[i * DEV_BLOCK_SIZE..(i + 1) * DEV_BLOCK_SIZE];
            self.cache.read_cached(lba + i as u64, sector_buf)?;
        }
        Ok(())
    }

    /// Write one f2fs block through the write-back cache.
    pub(super) fn write_fs_block(&self, blkaddr: u32, data: &[u8]) -> Result<()> {
        let lba = self.block_to_lba(blkaddr);
        let sector_count = self.sectors_per_block() as usize;
        for i in 0..sector_count {
            let chunk = &data[i * DEV_BLOCK_SIZE..(i + 1) * DEV_BLOCK_SIZE];
            self.cache.write_back(lba + i as u64, chunk)?;
        }
        Ok(())
    }

    // inode I/O

    /// Read the inode a NID names, through the NAT.
    pub(super) fn read_inode(&self, nid: u32) -> Result<F2fsInode> {
        let nat = self.nat_cache.lock();
        let entry = nat.entries.get(nid as usize).ok_or(Error::NotFound)?;
        if entry.block_addr == F2FS_NULL_ADDR {
            return Err(Error::NotFound);
        }
        let phys_block = entry.block_addr;
        drop(nat);

        let block_size = self.block_size();
        let mut buf = vec![0u8; block_size];
        self.read_fs_block(phys_block, &mut buf)?;
        Ok(parse_f2fs_inode(&buf))
    }

    /// Write an inode: append a fresh block to the active segment and move
    /// the NAT entry, the log-structured way an inode is updated.
    pub(super) fn write_inode(&self, nid: u32, inode: &F2fsInode) -> Result<()> {
        let block_size = self.block_size();
        let mut buf = vec![0u8; block_size];
        write_f2fs_inode(inode, &mut buf);

        let phys = self.segment_alloc_block(&buf)?;
        self.nat_update(nid, phys)?;

        Ok(())
    }

    /// The inode's facts, as the VFS's own record names them.
    pub(super) fn stat_inode(&self, inode: &F2fsInode) -> Metadata {
        Metadata::new(inode.kind(), inode.file_size() as usize).with_security(
            SecurityDescriptor::new(inode.i_uid, inode.i_gid, inode.permission_mode()),
        )
    }

    // directories

    /// Read every entry a directory holds, one data block at a time.
    pub(super) fn read_dir_entries(&self, dir_inode: &F2fsInode) -> Result<Vec<F2fsDirEntry>> {
        let block_size = self.block_size();
        let file_size = dir_inode.file_size();
        let num_blocks = if file_size == 0 {
            0
        } else {
            file_size.div_ceil(block_size as u64) as usize
        };

        let mut entries = Vec::new();
        let mut buf = vec![0u8; block_size];

        for addr_slot in dir_inode.i_addr.iter().take(num_blocks) {
            let phys = *addr_slot;
            if phys == F2FS_NULL_ADDR || phys == F2FS_NEW_ADDR {
                continue;
            }
            self.read_fs_block(phys, &mut buf)?;
            entries.extend(parse_f2fs_dir_entries(&buf));
        }

        Ok(entries)
    }

    /// Look up one name in a directory, answering the child's NID and type.
    pub(super) fn lookup_in_dir(&self, dir_nid: u32, name: &str) -> Result<(u32, u8)> {
        let dir_inode = self.read_inode(dir_nid)?;
        let entries = self.read_dir_entries(&dir_inode)?;
        for entry in &entries {
            if entry.name == name {
                return Ok((entry.ino, entry.file_type));
            }
        }
        Err(Error::NotFound)
    }

    /// Add one entry to a directory: in the last block's slack when there
    /// is room, in a fresh block when there is not.
    pub(super) fn add_dir_entry(
        &self,
        dir_nid: u32,
        child_nid: u32,
        name: &str,
        file_type: u8,
    ) -> Result<()> {
        let block_size = self.block_size();
        let mut dir_inode = self.read_inode(dir_nid)?;
        let file_size = dir_inode.file_size();
        let num_blocks = if file_size == 0 {
            0
        } else {
            file_size.div_ceil(block_size as u64) as usize
        };

        let new_entry_size = dir_entry_size(name.len());
        let hash_code = 0u32;
        let mut buf = vec![0u8; block_size];

        // The last existing block's slack takes the entry when it fits.
        if num_blocks > 0 && num_blocks <= F2FS_ADDRS_PER_INODE {
            let last_blk_idx = num_blocks - 1;
            let old_phys = dir_inode.i_addr[last_blk_idx];
            if old_phys != F2FS_NULL_ADDR && old_phys != F2FS_NEW_ADDR {
                self.read_fs_block(old_phys, &mut buf)?;

                let used = Self::dir_block_used_bytes(&buf, block_size);
                if used + new_entry_size <= block_size {
                    write_f2fs_dir_entry(child_nid, name, file_type, hash_code, &mut buf[used..]);
                    // The log-structured append: a new block carries the
                    // block's own content plus the entry.
                    let new_phys = self.segment_alloc_block(&buf)?;
                    dir_inode.i_addr[last_blk_idx] = new_phys;
                    dir_inode.i_size += new_entry_size as u64;
                    self.write_inode(dir_nid, &dir_inode)?;
                    return Ok(());
                }
            }
        }

        if num_blocks >= F2FS_ADDRS_PER_INODE {
            return Err(Error::DeviceError);
        }

        // A fresh block, whose one entry is the whole of it.
        let mut new_block = vec![0u8; block_size];
        let written = write_f2fs_dir_entry(child_nid, name, file_type, hash_code, &mut new_block);
        let new_phys = self.segment_alloc_block(&new_block)?;

        dir_inode.i_addr[num_blocks] = new_phys;
        dir_inode.i_size += written as u64;
        self.write_inode(dir_nid, &dir_inode)?;

        Ok(())
    }

    /// Remove one entry by name, by zeroing its `ino`, the deletion a
    /// parse skips, and appending the rewritten block.
    pub(super) fn remove_dir_entry(&self, dir_nid: u32, name: &str) -> Result<()> {
        let block_size = self.block_size();
        let dir_inode = self.read_inode(dir_nid)?;
        let file_size = dir_inode.file_size();
        let num_blocks = if file_size == 0 {
            0
        } else {
            file_size.div_ceil(block_size as u64) as usize
        };

        let mut buf = vec![0u8; block_size];

        for blk_idx in 0..num_blocks.min(F2FS_ADDRS_PER_INODE) {
            let old_phys = dir_inode.i_addr[blk_idx];
            if old_phys == F2FS_NULL_ADDR || old_phys == F2FS_NEW_ADDR {
                continue;
            }
            self.read_fs_block(old_phys, &mut buf)?;

            let mut offset = 0usize;
            let mut found = false;
            while offset + 13 <= block_size {
                let rec_len = u16::from_le_bytes([buf[offset], buf[offset + 1]]) as usize;
                if rec_len < 13 || rec_len == 0 {
                    break;
                }
                let name_len = u16::from_le_bytes([buf[offset + 2], buf[offset + 3]]) as usize;
                let ino = u32::from_le_bytes([
                    buf[offset + 9],
                    buf[offset + 10],
                    buf[offset + 11],
                    buf[offset + 12],
                ]);

                if ino != 0 && name_len == name.len() {
                    let entry_name = &buf[offset + 13..offset + 13 + name_len];
                    if entry_name == name.as_bytes() {
                        // The deletion: the entry's inode number goes to
                        // zero, which is what a parse skips.
                        buf[offset + 9] = 0;
                        buf[offset + 10] = 0;
                        buf[offset + 11] = 0;
                        buf[offset + 12] = 0;
                        found = true;
                        break;
                    }
                }
                offset += rec_len;
            }

            if found {
                let new_phys = self.segment_alloc_block(&buf)?;
                let mut updated_inode = self.read_inode(dir_nid)?;
                updated_inode.i_addr[blk_idx] = new_phys;
                self.write_inode(dir_nid, &updated_inode)?;
                return Ok(());
            }
        }

        Err(Error::NotFound)
    }

    /// The byte offset just past the last valid entry in a raw directory
    /// block, which is where the next entry appends.
    fn dir_block_used_bytes(data: &[u8], block_size: usize) -> usize {
        let mut offset = 0usize;
        while offset + 13 <= block_size {
            let rec_len = u16::from_le_bytes([data[offset], data[offset + 1]]) as usize;
            if rec_len < 13 || rec_len == 0 {
                break;
            }
            offset += rec_len;
        }
        offset
    }

    // path resolution

    /// Resolve a path to its node, following symlinks up to eight levels.
    pub(super) fn walk_path(&self, path: &str) -> Result<(u32, F2fsInode)> {
        self.walk_path_limited(path, 0)
    }

    fn walk_path_limited(&self, path: &str, depth: usize) -> Result<(u32, F2fsInode)> {
        const MAX_SYMLINK_DEPTH: usize = 8;
        if depth > MAX_SYMLINK_DEPTH {
            return Err(Error::InvalidArgument);
        }

        if path == "/" || path.is_empty() {
            let root_inode = self.read_inode(F2FS_NID_ROOT)?;
            return Ok((F2FS_NID_ROOT, root_inode));
        }

        let components: Vec<&str> = path
            .trim_start_matches('/')
            .split('/')
            .filter(|c| !c.is_empty())
            .collect();

        let mut current_nid = F2FS_NID_ROOT;
        let mut walked = String::new();

        for (i, component) in components.iter().enumerate() {
            let dir_inode = self.read_inode(current_nid)?;
            if dir_inode.kind() != NodeKind::Directory {
                return Err(Error::NotFound);
            }

            let (child_nid, _file_type) = self.lookup_in_dir(current_nid, component)?;
            let child_inode = self.read_inode(child_nid)?;

            walked.push('/');
            walked.push_str(component);

            if child_inode.kind() == NodeKind::Symlink {
                let target = self.read_symlink_target(&child_inode)?;
                let target_str =
                    core::str::from_utf8(&target).map_err(|_| Error::InvalidArgument)?;

                let suffix: String = if i + 1 < components.len() {
                    let mut s = String::from("/");
                    for c in &components[i + 1..] {
                        s.push_str(c);
                        s.push('/');
                    }
                    if s.len() > 1 {
                        s.pop();
                    }
                    s
                } else {
                    String::new()
                };

                let resolved = if target_str.starts_with('/') {
                    format!("{}{}", target_str, suffix)
                } else {
                    let parent = walked.rsplit_once('/').map(|(p, _)| p).unwrap_or("");
                    format!("{}/{}{}", parent, target_str, suffix)
                };

                return self.walk_path_limited(&resolved, depth + 1);
            }

            current_nid = child_nid;
        }

        let inode = self.read_inode(current_nid)?;
        Ok((current_nid, inode))
    }

    // file data

    /// Read a file's bytes at an offset, holes reading as zeros.
    pub(super) fn read_file_data(
        &self,
        inode: &F2fsInode,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize> {
        let file_size = inode.file_size();
        if offset >= file_size {
            return Ok(0);
        }

        let block_size = self.block_size() as u64;
        let bytes_to_read = buffer.len().min((file_size - offset) as usize);
        let start_block = (offset / block_size) as usize;
        let block_offset = (offset % block_size) as usize;

        let mut buf = vec![0u8; self.block_size()];
        let mut bytes_read = 0usize;
        let mut remaining = bytes_to_read;
        let mut buf_offset = 0usize;

        for (blk_idx, addr_slot) in inode.i_addr.iter().enumerate().skip(start_block) {
            if remaining == 0 {
                break;
            }

            let phys = *addr_slot;
            if phys == F2FS_NULL_ADDR || phys == F2FS_NEW_ADDR {
                // A hole reads as zeros.
                let n = remaining.min(block_size as usize);
                for b in buffer[buf_offset..buf_offset + n].iter_mut() {
                    *b = 0;
                }
                bytes_read += n;
                buf_offset += n;
                remaining -= n;
                continue;
            }

            self.read_fs_block(phys, &mut buf)?;

            let start = if blk_idx == start_block {
                block_offset
            } else {
                0
            };
            let n = remaining.min(self.block_size() - start);

            buffer[buf_offset..buf_offset + n].copy_from_slice(&buf[start..start + n]);

            bytes_read += n;
            buf_offset += n;
            remaining -= n;
        }

        Ok(bytes_read)
    }

    /// A fast symlink's target, read from the `i_addr` area's own bytes.
    pub(super) fn read_symlink_target(&self, inode: &F2fsInode) -> Result<Vec<u8>> {
        if inode.kind() != NodeKind::Symlink {
            return Err(Error::InvalidArgument);
        }

        let len = inode.file_size() as usize;
        if len == 0 {
            return Ok(Vec::new());
        }

        let addr_bytes = len.min(F2FS_ADDRS_PER_INODE * 4);
        let mut target = Vec::with_capacity(addr_bytes);

        // SAFETY: `i_addr` is a `[u32; N]`, no padding, and the byte length
        // is exactly the number of elements the array holds.
        let raw_addr: &[u8] = unsafe {
            core::slice::from_raw_parts(
                inode.i_addr.as_ptr() as *const u8,
                F2FS_ADDRS_PER_INODE * 4,
            )
        };

        target.extend_from_slice(&raw_addr[..len]);
        Ok(target)
    }

    // the write guard and the flush

    pub(super) fn check_writable(&self) -> Result<()> {
        if self.read_only {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }

    /// The flush everything ends with: a checkpoint commits the NAT and SIT
    /// state, the superblock follows it, and the cache's dirty blocks go to
    /// the device last.
    pub(super) fn flush_all(&self) -> Result<()> {
        self.write_checkpoint()?;
        self.write_superblock()?;
        self.cache.flush()?;
        self.device.flush()?;
        Ok(())
    }
}
