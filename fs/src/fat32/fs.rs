//! fs/src/fat32/fs.rs
//!
//! The volume's core: mount, the FAT table's read and write across all
//! three entry widths, cluster chains walked and allocated, FSInfo
//! bookkeeping, directory raw bytes read and written, path resolution, and
//! the flush that carries the FSInfo sector with it.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use block::BLOCK_SIZE;

use abi::Error;
use abi::Result;

use crate::block_cache::BlockCache;
use crate::profiler::FsProfiler;
use crate::types::NodeKind;
use unicode::OemCodePage;
use unicode::eq_unicode_insensitive;

use super::types::DIR_ENTRY_SIZE;
use super::types::FIRST_DATA_CLUSTER;
use super::types::FSINFO_FREE_COUNT_OFFSET;
use super::types::FSINFO_LEAD_OFFSET;
use super::types::FSINFO_LEAD_SIGNATURE;
use super::types::FSINFO_NEXT_FREE_OFFSET;
use super::types::FSINFO_STRUCT_OFFSET;
use super::types::FSINFO_STRUCT_SIGNATURE;
use super::types::FSINFO_TRAIL_SIGNATURE;
use super::types::FSINFO_UNKNOWN;
use super::types::FatDirEntry;
use super::types::FatGeometry;
use super::types::FatType;
use super::types::build_lfn_name;
use super::types::parse_lfn_fragment;
use super::types::parse_short_dir_entry;
use super::types::read_u16;
use super::types::read_u32;

/// The volume's internal state, shared between the [`super::FatVolume`]
/// and every node it hands out.
pub(super) struct FatFs {
    pub(super) cache: BlockCache,
    pub(super) device: Arc<dyn block::QueuedBlockDevice>,
    pub(super) geom: FatGeometry,
    pub(super) code_page: OemCodePage,
    pub(super) block_buf: [u8; BLOCK_SIZE],
    free_cluster_count: Option<u32>,
    next_free_cluster: u32,
    pub(super) profiler: FsProfiler,
}

impl FatFs {
    /// Open a volume: validate the boot sector's BPB, seed the free-cluster
    /// accounting from the FSInfo sector when it validates.
    pub(super) fn open(device: Arc<dyn block::QueuedBlockDevice>) -> Result<Self> {
        let cache = BlockCache::new(device.clone());
        let mut block_buf = [0u8; BLOCK_SIZE];

        cache
            .read_cached(0, &mut block_buf)
            .map_err(|_| Error::DeviceError)?;
        let geom = FatGeometry::from_boot_sector(&block_buf)?;

        let mut fs = Self {
            cache,
            device,
            geom,
            code_page: OemCodePage::Cp437,
            block_buf,
            free_cluster_count: None,
            next_free_cluster: FIRST_DATA_CLUSTER,
            profiler: FsProfiler::default(),
        };
        fs.read_fsinfo()?;
        Ok(fs)
    }

    /// Read a single-sector block through the cache.
    pub(super) fn read_block(&mut self, lba: u64) -> Result<&[u8; BLOCK_SIZE]> {
        self.cache
            .read_cached(lba, &mut self.block_buf)
            .map_err(|_| Error::DeviceError)?;
        Ok(&self.block_buf)
    }

    /// Write the prepared block buffer back through the cache.
    pub(super) fn write_block(&mut self, lba: u64) -> Result<()> {
        self.cache.write_back(lba, &self.block_buf)
    }

    /// Read the FAT entry for a cluster, in the width its type uses.
    pub(super) fn read_fat_entry(&mut self, cluster: u32) -> Result<u32> {
        match self.geom.fat_type {
            FatType::Fat12 => {
                // Two 12-bit entries share three bytes: the byte offset is
                // the cluster plus its half.
                let fat_offset = cluster as u64 + (cluster as u64 >> 1);
                let fat_lba = self.geom.fat_start_lba + fat_offset / BLOCK_SIZE as u64;
                let offset_in_block = (fat_offset % BLOCK_SIZE as u64) as usize;

                self.read_block(fat_lba)?;
                let word = read_u16(&self.block_buf, offset_in_block);
                if cluster & 1 == 0 {
                    Ok((word & 0x0FFF) as u32)
                } else {
                    Ok((word >> 4) as u32)
                }
            }
            FatType::Fat16 => {
                let fat_offset = cluster as u64 * 2;
                let fat_lba = self.geom.fat_start_lba + fat_offset / BLOCK_SIZE as u64;
                let offset_in_block = (fat_offset % BLOCK_SIZE as u64) as usize;

                self.read_block(fat_lba)?;
                Ok(read_u16(&self.block_buf, offset_in_block) as u32)
            }
            FatType::Fat32 => {
                let fat_offset = cluster as u64 * 4;
                let fat_lba = self.geom.fat_start_lba + fat_offset / BLOCK_SIZE as u64;
                let offset_in_block = (fat_offset % BLOCK_SIZE as u64) as usize;

                self.read_block(fat_lba)?;
                let entry = read_u32(&self.block_buf, offset_in_block);
                Ok(entry & self.geom.fat_type.eoc_mask())
            }
        }
    }

    /// Write a FAT entry into **both** FAT tables.
    ///
    /// FAT12's twelve-bit packing is a read-modify-write of the affected
    /// word: even clusters keep the word's high nibble, odd clusters the
    /// low one.
    pub(super) fn write_fat_entry(&mut self, cluster: u32, value: u32) -> Result<()> {
        match self.geom.fat_type {
            FatType::Fat12 => {
                let fat_offset = cluster as u64 + (cluster as u64 >> 1);
                let fat_lba = self.geom.fat_start_lba + fat_offset / BLOCK_SIZE as u64;
                let offset_in_block = (fat_offset % BLOCK_SIZE as u64) as usize;

                self.read_block(fat_lba)?;
                let mut word = read_u16(&self.block_buf, offset_in_block);
                if cluster & 1 == 0 {
                    word = (word & 0xF000) | (value as u16 & 0x0FFF);
                } else {
                    word = (word & 0x000F) | ((value as u16) << 4);
                }
                self.block_buf[offset_in_block] = word as u8;
                self.block_buf[offset_in_block + 1] = (word >> 8) as u8;
                self.write_block(fat_lba)?;

                if self.geom.num_fats > 1 {
                    let fat2_lba = fat_lba + self.geom.sectors_per_fat as u64;
                    self.read_block(fat2_lba)?;
                    self.block_buf[offset_in_block] = word as u8;
                    self.block_buf[offset_in_block + 1] = (word >> 8) as u8;
                    self.write_block(fat2_lba)?;
                }
            }
            FatType::Fat16 => {
                let fat_offset = cluster as u64 * 2;
                let fat_lba = self.geom.fat_start_lba + fat_offset / BLOCK_SIZE as u64;
                let offset_in_block = (fat_offset % BLOCK_SIZE as u64) as usize;

                for &lba in &[fat_lba, fat_lba + self.geom.sectors_per_fat as u64] {
                    self.read_block(lba)?;
                    self.block_buf[offset_in_block] = value as u8;
                    self.block_buf[offset_in_block + 1] = (value >> 8) as u8;
                    self.write_block(lba)?;
                }
            }
            FatType::Fat32 => {
                let fat_offset = cluster as u64 * 4;
                let fat_lba = self.geom.fat_start_lba + fat_offset / BLOCK_SIZE as u64;
                let offset_in_block = (fat_offset % BLOCK_SIZE as u64) as usize;

                for &lba in &[fat_lba, fat_lba + self.geom.sectors_per_fat as u64] {
                    self.read_block(lba)?;
                    self.block_buf[offset_in_block] = value as u8;
                    self.block_buf[offset_in_block + 1] = (value >> 8) as u8;
                    self.block_buf[offset_in_block + 2] = (value >> 16) as u8;
                    self.block_buf[offset_in_block + 3] = (value >> 24) as u8;
                    self.write_block(lba)?;
                }
            }
        }
        Ok(())
    }

    /// Adopt the FSInfo sector's free-cluster count and next-free hint when
    /// the structure validates.
    pub(super) fn read_fsinfo(&mut self) -> Result<()> {
        if self.geom.fat_type != FatType::Fat32 || self.geom.fsinfo_sector == 0 {
            return Ok(());
        }
        let mut buf = [0u8; BLOCK_SIZE];
        self.cache
            .read_cached(self.geom.fsinfo_sector as u64, &mut buf)
            .map_err(|_| Error::DeviceError)?;
        if read_u32(&buf, FSINFO_LEAD_OFFSET) != FSINFO_LEAD_SIGNATURE
            || read_u32(&buf, FSINFO_STRUCT_OFFSET) != FSINFO_STRUCT_SIGNATURE
            || buf[510] != FSINFO_TRAIL_SIGNATURE[0]
            || buf[511] != FSINFO_TRAIL_SIGNATURE[1]
        {
            return Ok(());
        }
        let free = read_u32(&buf, FSINFO_FREE_COUNT_OFFSET);
        if free != FSINFO_UNKNOWN {
            self.free_cluster_count = Some(free);
        }
        let next = read_u32(&buf, FSINFO_NEXT_FREE_OFFSET);
        if next != FSINFO_UNKNOWN && next >= FIRST_DATA_CLUSTER {
            self.next_free_cluster = next;
        }
        Ok(())
    }

    /// Count the free clusters by scanning the FAT, once, when the FSInfo
    /// sector did not seed a count.
    fn ensure_free_cluster_count(&mut self) -> Result<()> {
        if self.free_cluster_count.is_some() {
            return Ok(());
        }
        let mut count: u32 = 0;
        for cluster in FIRST_DATA_CLUSTER..FIRST_DATA_CLUSTER + self.geom.data_cluster_count {
            if self.read_fat_entry(cluster)? == 0x0000_0000 {
                count += 1;
            }
        }
        self.free_cluster_count = Some(count);
        Ok(())
    }

    /// Write the FSInfo sector — and its backup — reflecting the current
    /// accounting.
    pub(super) fn write_fsinfo(&mut self) -> Result<()> {
        if self.geom.fat_type != FatType::Fat32 || self.geom.fsinfo_sector == 0 {
            return Ok(());
        }
        let mut buf = [0u8; BLOCK_SIZE];
        buf[FSINFO_LEAD_OFFSET..FSINFO_LEAD_OFFSET + 4]
            .copy_from_slice(&FSINFO_LEAD_SIGNATURE.to_le_bytes());
        buf[FSINFO_STRUCT_OFFSET..FSINFO_STRUCT_OFFSET + 4]
            .copy_from_slice(&FSINFO_STRUCT_SIGNATURE.to_le_bytes());
        buf[FSINFO_FREE_COUNT_OFFSET..FSINFO_FREE_COUNT_OFFSET + 4].copy_from_slice(
            &self
                .free_cluster_count
                .unwrap_or(FSINFO_UNKNOWN)
                .to_le_bytes(),
        );
        buf[FSINFO_NEXT_FREE_OFFSET..FSINFO_NEXT_FREE_OFFSET + 4]
            .copy_from_slice(&self.next_free_cluster.to_le_bytes());
        buf[510] = FSINFO_TRAIL_SIGNATURE[0];
        buf[511] = FSINFO_TRAIL_SIGNATURE[1];
        self.cache
            .write_back(self.geom.fsinfo_sector as u64, &buf)
            .map_err(|_| Error::DeviceError)?;
        if self.geom.backup_boot_sector != 0 {
            self.cache
                .write_back(self.geom.backup_boot_sector as u64 + 1, &buf)
                .map_err(|_| Error::DeviceError)?;
        }
        Ok(())
    }

    /// Find a free cluster, scanning from the cached hint and wrapping.
    pub(super) fn find_free_cluster(&mut self) -> Result<u32> {
        let total = self.geom.data_cluster_count;
        if total == 0 {
            return Err(Error::NoSpace);
        }
        self.ensure_free_cluster_count()?;

        let last_cluster = FIRST_DATA_CLUSTER + total - 1;
        let mut cluster = self
            .next_free_cluster
            .clamp(FIRST_DATA_CLUSTER, last_cluster);

        for _ in 0..total {
            if cluster > last_cluster {
                cluster = FIRST_DATA_CLUSTER;
            }
            let entry = self.read_fat_entry(cluster)?;
            if entry == 0x0000_0000 {
                self.next_free_cluster = if cluster == last_cluster {
                    FIRST_DATA_CLUSTER
                } else {
                    cluster + 1
                };
                if let Some(count) = self.free_cluster_count.as_mut() {
                    *count = count.saturating_sub(1);
                }
                return Ok(cluster);
            }
            cluster += 1;
        }
        Err(Error::NoSpace)
    }

    /// Allocate a cluster and append it to a chain; `last_cluster == 0`
    /// allocates the chain's first cluster and marks it EOC.
    pub(super) fn append_cluster(&mut self, last_cluster: u32) -> Result<u32> {
        let new_cluster = self.find_free_cluster()?;
        let eoc_min = self.geom.fat_type.eoc_min();

        self.write_fat_entry(new_cluster, eoc_min)?;

        if last_cluster != 0 {
            self.write_fat_entry(last_cluster, new_cluster)?;
        }

        Ok(new_cluster)
    }

    /// Free a cluster chain, counting what came back and pointing the
    /// allocator's hint at it.
    pub(super) fn free_cluster_chain(&mut self, start_cluster: u32) -> Result<()> {
        let eoc_min = self.geom.fat_type.eoc_min();
        let mut cluster = start_cluster;
        let mut freed: u32 = 0;
        for _ in 0..65536 {
            if cluster < FIRST_DATA_CLUSTER || cluster >= eoc_min {
                break;
            }
            let next = self.read_fat_entry(cluster)?;
            self.write_fat_entry(cluster, 0x0000_0000)?;
            freed += 1;
            if next >= eoc_min {
                break;
            }
            cluster = next;
        }
        if freed > 0 {
            if let Some(count) = self.free_cluster_count.as_mut() {
                *count = count.saturating_add(freed);
            }
            self.next_free_cluster = start_cluster;
        }
        Ok(())
    }

    /// Walk a cluster chain and collect its cluster numbers, bounded so a
    /// corrupt FAT's cycle cannot loop for ever.
    pub(super) fn walk_cluster_chain(&mut self, start_cluster: u32) -> Result<Vec<u32>> {
        let eoc_min = self.geom.fat_type.eoc_min();
        let mut chain = Vec::new();
        let mut cluster = start_cluster;
        let max_clusters = (self.geom.data_cluster_count as usize).min(65536);
        for _ in 0..max_clusters {
            if cluster < FIRST_DATA_CLUSTER {
                break;
            }
            if cluster >= eoc_min {
                break;
            }
            chain.push(cluster);
            cluster = self.read_fat_entry(cluster)?;
        }
        Ok(chain)
    }

    /// Read a cluster chain's raw bytes.
    pub(super) fn read_cluster_chain_data(&mut self, start_cluster: u32) -> Result<Vec<u8>> {
        let chain = self.walk_cluster_chain(start_cluster)?;
        let cluster_size = self.geom.cluster_size_bytes as usize;
        let mut data = vec![0u8; chain.len() * cluster_size];

        for (i, &cluster) in chain.iter().enumerate() {
            let lba = self.geom.cluster_to_lba(cluster);
            let sectors = self.geom.sectors_per_cluster as u64;
            let dest = &mut data[i * cluster_size..(i + 1) * cluster_size];
            for s in 0..sectors {
                let block_start = s as usize * BLOCK_SIZE;
                let block_end = block_start + BLOCK_SIZE;
                self.cache
                    .read_cached(lba + s, &mut self.block_buf)
                    .map_err(|_| Error::DeviceError)?;
                dest[block_start..block_end].copy_from_slice(&self.block_buf);
            }
        }
        Ok(data)
    }

    /// Read a file's bytes, capped by its size.
    pub(super) fn read_file_data(&mut self, start_cluster: u32, size: u32) -> Result<Vec<u8>> {
        let mut all_data = self.read_cluster_chain_data(start_cluster)?;
        let len = (size as usize).min(all_data.len());
        all_data.truncate(len);
        Ok(all_data)
    }

    /// Write raw bytes to a cluster chain, overwriting from its start.
    pub(super) fn write_cluster_chain_data(
        &mut self,
        start_cluster: u32,
        data: &[u8],
    ) -> Result<()> {
        let cluster_size = self.geom.cluster_size_bytes as usize;
        let chain = self.walk_cluster_chain(start_cluster)?;
        let total_capacity = chain.len() * cluster_size;

        if data.len() > total_capacity {
            return Err(Error::InvalidArgument);
        }

        for (ci, &cluster) in chain.iter().enumerate() {
            let lba = self.geom.cluster_to_lba(cluster);
            let chunk_start = ci * cluster_size;
            let chunk_end = (chunk_start + cluster_size).min(data.len());
            for s in 0..self.geom.sectors_per_cluster as usize {
                let sector_start = chunk_start + s * BLOCK_SIZE;
                let sector_end = (sector_start + BLOCK_SIZE).min(chunk_end);
                if sector_start >= sector_end {
                    break;
                }
                let lba_s = lba + s as u64;
                self.cache
                    .read_cached(lba_s, &mut self.block_buf)
                    .map_err(|_| Error::DeviceError)?;
                self.block_buf[..sector_end - sector_start]
                    .copy_from_slice(&data[sector_start..sector_end]);
                self.write_block(lba_s)?;
            }
        }
        Ok(())
    }

    /// Write data to a file's chain, extending it as needed and freeing the
    /// tail when the data shrank.  A zero `start_cluster` allocates the
    /// first cluster.  Answers the chain's (possibly new) first cluster.
    pub(super) fn write_file_data_extend(
        &mut self,
        start_cluster: u32,
        data: &[u8],
    ) -> Result<u32> {
        let cluster_size = self.geom.cluster_size_bytes as usize;

        let first = if start_cluster == 0 {
            self.append_cluster(0)?
        } else {
            start_cluster
        };

        let mut chain = self.walk_cluster_chain(first)?;

        while chain.len() * cluster_size < data.len() {
            let last_cluster = chain.last().copied().unwrap_or(first);
            let new_cluster = self.append_cluster(last_cluster)?;
            chain.push(new_cluster);
        }

        self.write_cluster_chain_data(first, data)?;

        let needed_clusters = data.len().div_ceil(cluster_size).max(1);
        if needed_clusters < chain.len() {
            let first_extra = chain[needed_clusters - 1];
            let next_after_first_extra = self.read_fat_entry(first_extra)?;
            let eoc_min = self.geom.fat_type.eoc_min();
            let last_needed_cluster = chain[needed_clusters - 1];
            self.write_fat_entry(last_needed_cluster, eoc_min)?;
            if next_after_first_extra < eoc_min {
                self.free_cluster_chain(next_after_first_extra)?;
            }
        }

        Ok(first)
    }

    /// The FAT12/16 root directory's fixed region, read whole.
    pub(super) fn read_root_dir_raw(&mut self) -> Result<Vec<u8>> {
        let raw_len = self.geom.root_dir_sectors as usize * BLOCK_SIZE;
        let mut raw = vec![0u8; raw_len];
        for s in 0..self.geom.root_dir_sectors {
            let lba = self.geom.root_dir_lba + s;
            self.cache
                .read_cached(lba, &mut self.block_buf)
                .map_err(|_| Error::DeviceError)?;
            let start = s as usize * BLOCK_SIZE;
            let end = start + BLOCK_SIZE;
            raw[start..end].copy_from_slice(&self.block_buf);
        }
        Ok(raw)
    }

    /// Write the FAT12/16 root directory region back.
    pub(super) fn write_root_dir_raw(&mut self, data: &[u8]) -> Result<()> {
        for s in 0..self.geom.root_dir_sectors {
            let lba = self.geom.root_dir_lba + s;
            let start = s as usize * BLOCK_SIZE;
            let end = start + BLOCK_SIZE;
            if start >= data.len() {
                self.block_buf.fill(0);
            } else {
                let copy_end = end.min(data.len());
                let n = copy_end - start;
                self.block_buf[..n].copy_from_slice(&data[start..copy_end]);
                for b in &mut self.block_buf[n..] {
                    *b = 0;
                }
            }
            self.write_block(lba)?;
        }
        Ok(())
    }

    /// A cluster-based directory's raw bytes.
    pub(super) fn read_dir_cluster_raw(&mut self, start_cluster: u32) -> Result<Vec<u8>> {
        self.read_cluster_chain_data(start_cluster)
    }

    /// Write raw directory bytes into a cluster chain, extending as needed.
    pub(super) fn write_dir_raw(&mut self, start_cluster: u32, data: &[u8]) -> Result<u32> {
        self.write_file_data_extend(start_cluster, data)
    }

    /// A directory's raw bytes — the read-modify-write's read half.
    pub(super) fn get_dir_raw(
        &mut self,
        dir_cluster: u32,
        is_root: bool,
    ) -> Result<(Vec<u8>, u32)> {
        if is_root && self.geom.fat_type != FatType::Fat32 {
            let raw = self.read_root_dir_raw()?;
            Ok((raw, dir_cluster))
        } else {
            let raw = self.read_dir_cluster_raw(dir_cluster)?;
            Ok((raw, dir_cluster))
        }
    }

    /// Write raw directory content back — the modify-write half.
    pub(super) fn put_dir_raw(
        &mut self,
        dir_cluster: u32,
        is_root: bool,
        raw: &[u8],
    ) -> Result<u32> {
        if is_root && self.geom.fat_type != FatType::Fat32 {
            self.write_root_dir_raw(raw)?;
            Ok(dir_cluster)
        } else {
            self.write_dir_raw(dir_cluster, raw)
        }
    }

    /// The first free slot in a directory's raw bytes.
    pub(super) fn find_free_dir_offset(&self, raw: &[u8]) -> Option<usize> {
        let num_entries = raw.len() / DIR_ENTRY_SIZE;
        let mut found_free = None;
        for i in 0..num_entries {
            let offset = i * DIR_ENTRY_SIZE;
            let first_byte = raw[offset];
            if first_byte == 0xE5 && found_free.is_none() {
                found_free = Some(offset);
            }
            if first_byte == 0x00 {
                return Some(found_free.unwrap_or(offset));
            }
        }
        found_free
    }

    /// Read the FAT12/16 root directory's entries.
    pub(super) fn read_root_directory(&mut self) -> Result<Vec<FatDirEntry>> {
        let raw_len = self.geom.root_dir_sectors as usize * BLOCK_SIZE;
        let mut raw = vec![0u8; raw_len];
        for s in 0..self.geom.root_dir_sectors {
            let lba = self.geom.root_dir_lba + s;
            self.cache
                .read_cached(lba, &mut self.block_buf)
                .map_err(|_| Error::DeviceError)?;
            let start = s as usize * BLOCK_SIZE;
            let end = start + BLOCK_SIZE;
            raw[start..end].copy_from_slice(&self.block_buf);
        }
        Ok(parse_directory_entries(&raw, self.code_page))
    }

    /// Read a cluster-based directory's entries.
    pub(super) fn read_directory_cluster(
        &mut self,
        start_cluster: u32,
    ) -> Result<Vec<FatDirEntry>> {
        let raw = self.read_cluster_chain_data(start_cluster)?;
        Ok(parse_directory_entries(&raw, self.code_page))
    }

    /// Read a directory's entries: cluster-based for FAT32 and any
    /// subdirectory, fixed-region for a FAT12/16 root.
    pub(super) fn read_directory(
        &mut self,
        start_cluster: u32,
        is_root: bool,
    ) -> Result<Vec<FatDirEntry>> {
        if is_root && self.geom.fat_type != FatType::Fat32 {
            self.read_root_directory()
        } else {
            self.read_directory_cluster(start_cluster)
        }
    }

    /// Walk a path from the root, answering the matching entry.  Name
    /// comparison is Unicode case-insensitive.
    pub(super) fn walk_path(&mut self, path: &str) -> Result<FatDirEntry> {
        let path = path.strip_prefix('/').unwrap_or(path);
        let is_root = path.is_empty();

        if is_root {
            let root_cluster = self.geom.root_cluster;
            return Ok(FatDirEntry {
                name: String::from("/"),
                kind: NodeKind::Directory,
                first_cluster: root_cluster,
                file_size: 0,
                created: 0,
                modified: 0,
                accessed: 0,
            });
        }

        let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        let mut current_cluster = self.geom.root_cluster;
        let mut is_current_root = true;

        for (i, &component) in components.iter().enumerate() {
            let is_last = i == components.len() - 1;
            let entries = self.read_directory(current_cluster, is_current_root)?;

            let found = entries
                .iter()
                .find(|e| eq_unicode_insensitive(e.name.as_str(), component));

            match found {
                Some(entry) => {
                    if is_last {
                        return Ok(entry.clone());
                    }
                    if entry.kind == NodeKind::Directory {
                        current_cluster = entry.first_cluster;
                        is_current_root = false;
                    } else {
                        return Err(Error::InvalidArgument);
                    }
                }
                None => return Err(Error::NotFound),
            }
        }

        Err(Error::NotFound)
    }

    /// Write back every dirty cache block, without a device flush.
    pub(super) fn flush(&mut self) -> Result<()> {
        self.cache.flush()
    }

    /// The full flush: the FSInfo sector refreshed first, then the cache,
    /// then the device.
    pub(super) fn sync(&mut self) -> Result<()> {
        self.write_fsinfo()?;
        self.cache.flush()?;
        self.device.flush()
    }

    /// The aged write-back path the scheduler drives.
    pub(super) fn flush_aged(&mut self, age_ticks: u64) -> Result<usize> {
        self.cache.flush_aged(age_ticks)
    }
}

/// Parse raw directory entry bytes into [`FatDirEntry`] values, merging LFN
/// fragments with their short entries.
pub(super) fn parse_directory_entries(raw: &[u8], code_page: OemCodePage) -> Vec<FatDirEntry> {
    let mut entries = Vec::new();
    let mut lfn_buffer: Vec<(u8, [u16; 13])> = Vec::new();

    let num_entries = raw.len() / DIR_ENTRY_SIZE;
    for i in 0..num_entries {
        let offset = i * DIR_ENTRY_SIZE;
        let entry_data = &raw[offset..offset + DIR_ENTRY_SIZE];

        if entry_data[0] == 0x00 {
            break;
        }

        if let Some(lfn) = parse_lfn_fragment(entry_data) {
            if lfn.0 & 0x40 != 0 {
                lfn_buffer.clear();
            }
            lfn_buffer.push(lfn);
            continue;
        }

        if let Some(entry) = parse_short_dir_entry(entry_data, code_page) {
            let final_name = if !lfn_buffer.is_empty() {
                let name = build_lfn_name(&lfn_buffer);
                lfn_buffer.clear();
                if name.is_empty() { entry.name } else { name }
            } else {
                entry.name
            };

            entries.push(FatDirEntry {
                name: final_name,
                ..entry
            });
        }
    }

    entries
}
