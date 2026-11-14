//! fs/src/exfat/fs.rs
//!
//! The volume's core: mount with the boot region's checksum validation, the
//! 32-bit FAT's read and write, the allocation bitmap's bits, cluster
//! chains walked and allocated, the entry sets a create builds, path
//! resolution, and the flush.

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
use unicode::eq_unicode_insensitive;
use unicode::utf16le_code_unit_to_char;

use super::types::BOOT_REGION_SECTORS;
use super::types::DIR_ENTRY_SIZE;
use super::types::ENTRY_INUSE_MASK;
use super::types::EXFAT_ATTR_ARCHIVE;
use super::types::EXFAT_ATTR_DIRECTORY;
use super::types::EXFAT_ENTRY_BITMAP;
use super::types::EXFAT_ENTRY_EOD;
use super::types::EXFAT_ENTRY_FILE;
use super::types::EXFAT_ENTRY_FILENAME;
use super::types::EXFAT_ENTRY_STREAM;
use super::types::EXFAT_ENTRY_UPCASE;
use super::types::ExfatBootRegion;
use super::types::ExfatDirEntry;
use super::types::ExfatEntryType;
use super::types::F_ACCESS_TIME;
use super::types::F_ATTR;
use super::types::F_CREATE_TIME;
use super::types::F_MODIFY_TIME;
use super::types::FAT32_EOC;
use super::types::FIRST_DATA_CLUSTER;
use super::types::FN_CHARS_PER_ENTRY;
use super::types::FN_NAME_START;
use super::types::MAX_DIR_ENTRIES;
use super::types::S_DATA_LEN;
use super::types::S_FIRST_CLUSTER;
use super::types::S_FLAG_NO_FAT_CHAIN;
use super::types::S_FLAGS;
use super::types::S_NAME_LENGTH;
use super::types::S_VALID_DATA_LEN;
use super::types::read_u16_le;
use super::types::read_u32_le;
use super::types::write_u16_le;
use super::types::write_u32_le;

/// The volume's internal state, shared between the
/// [`super::ExfatVolume`] and every node it hands out.
pub(super) struct ExfatFs {
    pub(super) cache: BlockCache,
    pub(super) boot: ExfatBootRegion,
    pub(super) block_buf: [u8; BLOCK_SIZE],
    /// Where the allocation bitmap's cluster chain starts.
    bitmap_first_cluster: u32,
    bitmap_byte_count: u64,
    pub(super) profiler: FsProfiler,
}

impl ExfatFs {
    /// Open a volume: read the twelve boot sectors, validate the checksum,
    /// and locate the allocation bitmap in the root directory.
    pub(super) fn open(device: Arc<dyn block::QueuedBlockDevice>) -> Result<Self> {
        let cache = BlockCache::new(device.clone());

        let mut boot_raw = [0u8; BLOCK_SIZE * BOOT_REGION_SECTORS];
        for s in 0..BOOT_REGION_SECTORS {
            let mut buf = [0u8; BLOCK_SIZE];
            cache
                .read_cached(s as u64, &mut buf)
                .map_err(|_| Error::DeviceError)?;
            let start = s * BLOCK_SIZE;
            let end = start + BLOCK_SIZE;
            boot_raw[start..end].copy_from_slice(&buf);
        }

        let boot = ExfatBootRegion::parse(&boot_raw)?;

        let (bitmap_first_cluster, bitmap_byte_count) = {
            let mut raw_block_buf = [0u8; BLOCK_SIZE];
            cache
                .read_cached(
                    boot.cluster_to_lba(boot.root_dir_cluster),
                    &mut raw_block_buf,
                )
                .map_err(|_| Error::DeviceError)?;
            parse_exfat_bitmap_entry(&raw_block_buf[..])
        };

        Ok(Self {
            cache,
            boot,
            block_buf: [0u8; BLOCK_SIZE],
            bitmap_first_cluster,
            bitmap_byte_count,
            profiler: FsProfiler::default(),
        })
    }

    /// Read a single-sector block through the cache.
    pub(super) fn read_block(&mut self, lba: u64) -> Result<&[u8; BLOCK_SIZE]> {
        self.cache
            .read_cached(lba, &mut self.block_buf)
            .map_err(|_| Error::DeviceError)?;
        Ok(&self.block_buf)
    }

    /// Write a sector through the cache, making it dirty.
    pub(super) fn write_block_cached(&mut self, lba: u64, data: &[u8; BLOCK_SIZE]) -> Result<()> {
        self.cache
            .write_back(lba, data)
            .map_err(|_| Error::DeviceError)
    }

    /// Write back every dirty cache block to the device.
    pub(super) fn flush(&mut self) -> Result<()> {
        self.cache.flush().map_err(|_| Error::DeviceError)
    }

    /// Read one 32-bit FAT entry.
    pub(super) fn read_fat_entry(&mut self, cluster: u32) -> Result<u32> {
        let fat_offset_bytes = cluster as u64 * 4;
        let fat_lba =
            self.boot.offset_to_lba(self.boot.fat_offset) + fat_offset_bytes / BLOCK_SIZE as u64;
        let offset_in_block = (fat_offset_bytes % BLOCK_SIZE as u64) as usize;

        self.read_block(fat_lba)?;
        Ok(read_u32_le(&self.block_buf, offset_in_block))
    }

    /// Write one 32-bit FAT entry.
    pub(super) fn write_fat_entry(&mut self, cluster: u32, value: u32) -> Result<()> {
        let fat_offset_bytes = cluster as u64 * 4;
        let fat_lba = self.boot.fat_offset as u64 + fat_offset_bytes / BLOCK_SIZE as u64;
        let offset_in_block = (fat_offset_bytes % BLOCK_SIZE as u64) as usize;

        self.read_block(fat_lba)?;
        write_u32_le(&mut self.block_buf, offset_in_block, value);
        self.write_block_cached(fat_lba, &self.block_buf.clone())?;
        Ok(())
    }

    /// Walk a cluster chain, bounded against cycles and self-loops.
    pub(super) fn walk_cluster_chain(&mut self, start_cluster: u32) -> Result<Vec<u32>> {
        let mut chain = Vec::new();
        let mut cluster = start_cluster;
        let max = (self.boot.cluster_count as usize).min(65536);

        for _ in 0..max {
            if cluster < FIRST_DATA_CLUSTER {
                break;
            }
            if cluster >= 0xFFFF_FFF8 {
                break;
            }
            if cluster >= FIRST_DATA_CLUSTER + self.boot.cluster_count {
                break;
            }
            chain.push(cluster);
            let next = self.read_fat_entry(cluster)?;
            if next == FAT32_EOC || next == cluster {
                break;
            }
            if next < FIRST_DATA_CLUSTER || next >= FIRST_DATA_CLUSTER + self.boot.cluster_count {
                break;
            }
            cluster = next;
        }
        Ok(chain)
    }

    /// Read a cluster chain's raw bytes.
    pub(super) fn read_cluster_chain_data(&mut self, start_cluster: u32) -> Result<Vec<u8>> {
        let chain = self.walk_cluster_chain(start_cluster)?;
        let cluster_size = self.boot.cluster_size_bytes as usize;
        let mut data = vec![0u8; chain.len() * cluster_size];

        for (i, &cluster) in chain.iter().enumerate() {
            let lba = self.boot.cluster_to_lba(cluster);
            let sectors = self.boot.sectors_per_cluster as u64;
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

    /// Read a contiguous (NoFatChain) file's bytes.
    pub(super) fn read_contiguous_data(
        &mut self,
        start_cluster: u32,
        byte_count: u64,
    ) -> Result<Vec<u8>> {
        let lba = self.boot.cluster_to_lba(start_cluster);
        let sectors = byte_count.div_ceil(BLOCK_SIZE as u64);
        let mut data = vec![0u8; byte_count as usize];
        for s in 0..sectors {
            let block_start = s as usize * BLOCK_SIZE;
            let block_end = block_start + BLOCK_SIZE;
            let to_read = block_end.min(data.len());
            self.cache
                .read_cached(lba + s, &mut self.block_buf)
                .map_err(|_| Error::DeviceError)?;
            let n = to_read - block_start;
            data[block_start..to_read].copy_from_slice(&self.block_buf[..n]);
        }
        Ok(data)
    }

    /// Read a file's bytes, by the stream's own layout.
    pub(super) fn read_file_data(
        &mut self,
        start_cluster: u32,
        size: u64,
        no_fat_chain: bool,
    ) -> Result<Vec<u8>> {
        if no_fat_chain {
            self.read_contiguous_data(start_cluster, size)
        } else {
            let mut all_data = self.read_cluster_chain_data(start_cluster)?;
            let len = (size as usize).min(all_data.len());
            all_data.truncate(len);
            Ok(all_data)
        }
    }

    /// Parse every entry a directory cluster chain holds.
    pub(super) fn read_directory_entries(
        &mut self,
        start_cluster: u32,
    ) -> Result<Vec<ExfatDirEntry>> {
        let raw = self.read_cluster_chain_data(start_cluster)?;
        Ok(parse_exfat_directory(&raw))
    }

    /// Walk a path from the root, answering the matching entry.
    pub(super) fn walk_path(&mut self, path: &str) -> Result<ExfatDirEntry> {
        let path = path.strip_prefix('/').unwrap_or(path);
        let is_root = path.is_empty();

        if is_root {
            return Ok(ExfatDirEntry {
                name: String::from("/"),
                kind: NodeKind::Directory,
                first_cluster: self.boot.root_dir_cluster,
                valid_data_length: 0,
                data_length: 0,
                no_fat_chain: false,
                created: 0,
                modified: 0,
                accessed: 0,
            });
        }

        let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        let mut current_cluster = self.boot.root_dir_cluster;

        for (i, &component) in components.iter().enumerate() {
            let is_last = i == components.len() - 1;
            let entries = self.read_directory_entries(current_cluster)?;

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
                    } else {
                        return Err(Error::InvalidArgument);
                    }
                }
                None => return Err(Error::NotFound),
            }
        }

        Err(Error::NotFound)
    }

    // the allocation bitmap

    /// Read one bit of the allocation bitmap.
    pub(super) fn read_bitmap_bit(&mut self, cluster: u32) -> Result<bool> {
        if self.bitmap_first_cluster == 0 || self.bitmap_byte_count == 0 {
            return Err(Error::Unsupported);
        }
        let cluster_idx = cluster - FIRST_DATA_CLUSTER;
        let byte_idx = cluster_idx as u64 / 8;
        let bit_idx = (cluster_idx % 8) as u8;
        if byte_idx >= self.bitmap_byte_count {
            return Err(Error::InvalidArgument);
        }

        let cluster_size = self.boot.cluster_size_bytes as u64;
        let cluster_in_chain = (byte_idx / cluster_size) as usize;
        let byte_offset_in_cluster = (byte_idx % cluster_size) as usize;

        let chain = self.walk_cluster_chain(self.bitmap_first_cluster)?;
        let target_cluster = *chain.get(cluster_in_chain).ok_or(Error::InvalidArgument)?;
        let lba = self.boot.cluster_to_lba(target_cluster);
        self.read_block(lba)?;
        let byte_val = self.block_buf[byte_offset_in_cluster];
        Ok(byte_val & (1 << bit_idx) != 0)
    }

    /// Set or clear one bit of the allocation bitmap.
    pub(super) fn set_bitmap_bit(&mut self, cluster: u32, allocated: bool) -> Result<()> {
        if self.bitmap_first_cluster == 0 || self.bitmap_byte_count == 0 {
            return Err(Error::Unsupported);
        }
        let cluster_idx = cluster - FIRST_DATA_CLUSTER;
        let byte_idx = cluster_idx as u64 / 8;
        let bit_idx = (cluster_idx % 8) as u8;
        if byte_idx >= self.bitmap_byte_count {
            return Err(Error::InvalidArgument);
        }

        let cluster_size = self.boot.cluster_size_bytes as u64;
        let cluster_in_chain = (byte_idx / cluster_size) as usize;
        let byte_offset_in_cluster = (byte_idx % cluster_size) as usize;

        let chain = self.walk_cluster_chain(self.bitmap_first_cluster)?;
        let target_cluster = *chain.get(cluster_in_chain).ok_or(Error::InvalidArgument)?;
        let lba = self.boot.cluster_to_lba(target_cluster);

        self.read_block(lba)?;
        if allocated {
            self.block_buf[byte_offset_in_cluster] |= 1 << bit_idx;
        } else {
            self.block_buf[byte_offset_in_cluster] &= !(1 << bit_idx);
        }
        let block = self.block_buf;
        self.write_block_cached(lba, &block)?;
        Ok(())
    }

    /// Find the first free cluster in the bitmap.
    pub(super) fn find_free_cluster(&mut self) -> Result<u32> {
        if self.bitmap_first_cluster == 0 || self.bitmap_byte_count == 0 {
            return Err(Error::Unsupported);
        }
        for bit_idx in 0..self.boot.cluster_count {
            let cluster = FIRST_DATA_CLUSTER + bit_idx;
            if !self.read_bitmap_bit(cluster)? {
                return Ok(cluster);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Append a new cluster to a chain's end: linked in the FAT, EOC-marked,
    /// and allocated in the bitmap.
    pub(super) fn append_cluster_to_chain(&mut self, start_cluster: u32) -> Result<u32> {
        let new_cluster = self.find_free_cluster()?;

        let mut current = start_cluster;
        loop {
            let next = self.read_fat_entry(current)?;
            if next == FAT32_EOC
                || next < FIRST_DATA_CLUSTER
                || next >= FIRST_DATA_CLUSTER + self.boot.cluster_count
            {
                break;
            }
            current = next;
        }

        self.write_fat_entry(current, new_cluster)?;
        self.write_fat_entry(new_cluster, FAT32_EOC)?;
        self.set_bitmap_bit(new_cluster, true)?;

        Ok(new_cluster)
    }

    /// Free a cluster chain: every FAT entry to zero, every bitmap bit
    /// cleared.
    pub(super) fn free_cluster_chain(&mut self, start_cluster: u32) -> Result<()> {
        let chain = self.walk_cluster_chain(start_cluster)?;
        for &cluster in &chain {
            self.write_fat_entry(cluster, 0x0000_0000)?;
            self.set_bitmap_bit(cluster, false)?;
        }
        Ok(())
    }

    // cluster data writes

    /// Write bytes at an offset within a file's cluster chain, extending the
    /// chain as needed.  Answers the bytes written.
    pub(super) fn write_cluster_data(
        &mut self,
        first_cluster: u32,
        offset: u64,
        buffer: &[u8],
    ) -> Result<usize> {
        if first_cluster < FIRST_DATA_CLUSTER {
            return Err(Error::InvalidArgument);
        }

        let cluster_size = self.boot.cluster_size_bytes as u64;
        let mut current_cluster = first_cluster;
        let mut bytes_written = 0;

        let mut remaining_offset = offset;
        while remaining_offset >= cluster_size {
            let next = self.read_fat_entry(current_cluster)?;
            if next == FAT32_EOC
                || next < FIRST_DATA_CLUSTER
                || next >= FIRST_DATA_CLUSTER + self.boot.cluster_count
            {
                current_cluster = self.append_cluster_to_chain(current_cluster)?;
            } else {
                current_cluster = next;
            }
            remaining_offset -= cluster_size;
        }

        let mut buf_offset = 0;
        while buf_offset < buffer.len() {
            let cluster_offset = remaining_offset;
            let space_in_cluster = (cluster_size - cluster_offset) as usize;
            let to_write = (buffer.len() - buf_offset).min(space_in_cluster);

            let lba = self.boot.cluster_to_lba(current_cluster);
            let sectors = self.boot.sectors_per_cluster as usize;

            if cluster_offset == 0 && to_write >= cluster_size as usize {
                // A full-cluster overwrite writes whole sectors directly.
                for s in 0..sectors {
                    let block_start = s * BLOCK_SIZE;
                    if block_start >= to_write {
                        break;
                    }
                    let mut block = [0u8; BLOCK_SIZE];
                    let n = (to_write - block_start).min(BLOCK_SIZE);
                    block[..n].copy_from_slice(
                        &buffer[buf_offset + block_start..buf_offset + block_start + n],
                    );
                    self.write_block_cached(lba + s as u64, &block)?;
                }
                bytes_written += to_write;
                buf_offset += to_write;
            } else {
                // A partial write is a read-modify-write per sector.
                for s in 0..sectors {
                    let sector_start = s * BLOCK_SIZE;
                    let sector_end = sector_start + BLOCK_SIZE;

                    let cluster_read_start = sector_start;
                    let cluster_read_end = sector_end.min(cluster_size as usize);

                    if cluster_read_start as u64 >= cluster_offset + to_write as u64
                        || cluster_read_end <= cluster_offset as usize
                    {
                        if cluster_read_end > cluster_size as usize {
                            continue;
                        }
                        if buf_offset + bytes_written >= buffer.len() {
                            break;
                        }
                        continue;
                    }

                    self.read_block(lba + s as u64)?;

                    let write_start_in_cluster = cluster_read_start.max(cluster_offset as usize);
                    let write_end_in_cluster =
                        cluster_read_end.min(cluster_offset as usize + to_write);

                    let buf_src_start =
                        buf_offset + (write_start_in_cluster - cluster_offset as usize);
                    let buf_src_end = buf_offset + (write_end_in_cluster - cluster_offset as usize);
                    let n_copy = buf_src_end - buf_src_start;

                    let block_off = write_start_in_cluster - sector_start;
                    self.block_buf[block_off..block_off + n_copy]
                        .copy_from_slice(&buffer[buf_src_start..buf_src_end]);
                    let block = self.block_buf;
                    self.write_block_cached(lba + s as u64, &block)?;

                    bytes_written += n_copy;
                }
                buf_offset += to_write;
            }

            if buf_offset < buffer.len() {
                let next = self.read_fat_entry(current_cluster)?;
                if next == FAT32_EOC {
                    current_cluster = self.append_cluster_to_chain(current_cluster)?;
                } else {
                    current_cluster = next;
                }
                remaining_offset = 0;
            }
        }

        Ok(bytes_written)
    }

    // entry sets

    /// Build the raw entry set for a file or directory: File (0x85), Stream
    /// (0xC0), and Filename (0xC1) entries.
    pub(crate) fn build_entry_set(
        name: &str,
        kind: NodeKind,
        first_cluster: u32,
        valid_data_length: u64,
        data_length: u64,
        no_fat_chain: bool,
    ) -> Vec<[u8; DIR_ENTRY_SIZE]> {
        let name_utf16 = unicode::utf8_to_utf16le(name);
        let name_len = name_utf16.len();

        let fn_entries_needed = name_len.div_ceil(FN_CHARS_PER_ENTRY);
        let secondary_count = 1 + fn_entries_needed;

        let mut entries = Vec::with_capacity(1 + secondary_count);

        // The File entry.
        let mut file_entry = [0u8; DIR_ENTRY_SIZE];
        file_entry[0] = EXFAT_ENTRY_FILE;
        file_entry[1] = secondary_count as u8;
        let attrs: u16 = if kind == NodeKind::Directory {
            EXFAT_ATTR_DIRECTORY
        } else {
            EXFAT_ATTR_ARCHIVE
        };
        write_u16_le(&mut file_entry, F_ATTR, attrs);
        entries.push(file_entry);

        // The Stream extension.
        let mut stream_entry = [0u8; DIR_ENTRY_SIZE];
        stream_entry[0] = EXFAT_ENTRY_STREAM;
        let flags: u8 = if no_fat_chain { S_FLAG_NO_FAT_CHAIN } else { 0 };
        stream_entry[S_FLAGS] = flags;
        stream_entry[S_NAME_LENGTH] = name_len as u8;
        write_u32_le(
            &mut stream_entry,
            S_VALID_DATA_LEN,
            valid_data_length as u32,
        );
        write_u32_le(&mut stream_entry, S_FIRST_CLUSTER, first_cluster);
        write_u32_le(&mut stream_entry, S_DATA_LEN, data_length as u32);
        entries.push(stream_entry);

        // The Filename entries.
        for fn_idx in 0..fn_entries_needed {
            let mut fn_entry = [0u8; DIR_ENTRY_SIZE];
            fn_entry[0] = EXFAT_ENTRY_FILENAME;
            let char_start = fn_idx * FN_CHARS_PER_ENTRY;
            let char_end = (char_start + FN_CHARS_PER_ENTRY).min(name_len);

            for (local_idx, &cu) in name_utf16[char_start..char_end].iter().enumerate() {
                let byte_off = FN_NAME_START + local_idx * 2;
                let le_bytes = cu.to_le_bytes();
                fn_entry[byte_off] = le_bytes[0];
                fn_entry[byte_off + 1] = le_bytes[1];
            }
            entries.push(fn_entry);
        }

        entries
    }

    /// Find a free slot for `entry_bytes`, extending the directory by a
    /// cluster when no run of free entries is big enough.
    pub(super) fn find_free_dir_slot(
        &mut self,
        dir_cluster: u32,
        entry_bytes: usize,
    ) -> Result<usize> {
        let raw = self.read_cluster_chain_data(dir_cluster)?;

        let mut free_run_start: Option<usize> = None;
        let mut free_run_len = 0usize;

        for pos in (0..raw.len()).step_by(DIR_ENTRY_SIZE) {
            if pos + DIR_ENTRY_SIZE > raw.len() {
                break;
            }
            let entry_type = raw[pos];
            let in_use = entry_type & ENTRY_INUSE_MASK != 0;

            if entry_type == EXFAT_ENTRY_EOD || !in_use {
                if free_run_start.is_none() {
                    free_run_start = Some(pos);
                    free_run_len = 0;
                }
                free_run_len += DIR_ENTRY_SIZE;
                if free_run_len >= entry_bytes {
                    return Ok(free_run_start.unwrap());
                }
            } else {
                free_run_start = None;
                free_run_len = 0;
            }
        }

        // Nothing big enough: extend by one cluster and answer the EOD's
        // position.
        let eod_pos = raw
            .iter()
            .position(|&b| b == EXFAT_ENTRY_EOD)
            .unwrap_or(raw.len());
        let _needed = entry_bytes.saturating_sub(raw.len() - eod_pos);
        let new_cluster = self.append_cluster_to_chain(dir_cluster)?;
        let lba = self.boot.cluster_to_lba(new_cluster);
        let sectors = self.boot.sectors_per_cluster as u64;
        let zeros = [0u8; BLOCK_SIZE];
        for s in 0..sectors {
            self.write_block_cached(lba + s, &zeros)?;
        }
        let mut eod_block = zeros;
        eod_block[0] = EXFAT_ENTRY_EOD;
        self.write_block_cached(lba, &eod_block)?;

        Ok(eod_pos)
    }

    /// Update a stream entry's lengths and flags, in the parent directory.
    pub(super) fn update_stream_entry(
        &mut self,
        parent_dir_cluster: u32,
        entry_set_offset: usize,
        valid_data_length: u64,
        data_length: u64,
        no_fat_chain: bool,
    ) -> Result<()> {
        if parent_dir_cluster == 0 || entry_set_offset == 0 {
            return Ok(());
        }

        let stream_offset = entry_set_offset + DIR_ENTRY_SIZE;
        let cluster_size = self.boot.cluster_size_bytes as u64;
        let cluster_off = stream_offset as u64 / cluster_size;
        let intra_off = (stream_offset as u64 % cluster_size) as usize;

        let chain = self.walk_cluster_chain(parent_dir_cluster)?;
        let target_cluster = *chain.get(cluster_off as usize).ok_or(Error::OutOfMemory)?;
        let lba = self.boot.cluster_to_lba(target_cluster);
        let sector = intra_off / BLOCK_SIZE;
        let sec_off = intra_off % BLOCK_SIZE;

        self.read_block(lba + sector as u64)?;

        let flags: u8 = if no_fat_chain { S_FLAG_NO_FAT_CHAIN } else { 0 };
        self.block_buf[sec_off + S_FLAGS] = flags;
        write_u32_le(
            &mut self.block_buf,
            sec_off + S_VALID_DATA_LEN,
            valid_data_length as u32,
        );
        write_u32_le(
            &mut self.block_buf,
            sec_off + S_DATA_LEN,
            data_length as u32,
        );

        let block = self.block_buf;
        self.write_block_cached(lba + sector as u64, &block)?;
        Ok(())
    }
}

/// Parse an exFAT directory's raw bytes into entries, skipping the bitmap,
/// up-case and label entries and the deleted ones.
pub(super) fn parse_exfat_directory(raw: &[u8]) -> Vec<ExfatDirEntry> {
    let mut entries = Vec::new();
    let num_entries = (raw.len() / DIR_ENTRY_SIZE).min(MAX_DIR_ENTRIES);
    let mut i = 0;

    while i < num_entries {
        let offset = i * DIR_ENTRY_SIZE;
        let entry_data = &raw[offset..offset + DIR_ENTRY_SIZE];
        let entry_type = entry_data[0];

        if entry_type == EXFAT_ENTRY_EOD {
            break;
        }

        if entry_type & ENTRY_INUSE_MASK == 0 {
            i += 1;
            continue;
        }

        let parsed = ExfatEntryType::from_byte(entry_type);

        if parsed.type_code == 0x05 && !parsed._is_secondary {
            let primary = entry_data;
            let secondary_count = primary[1];
            let attrs = read_u16_le(primary, F_ATTR);

            let kind = if attrs & EXFAT_ATTR_DIRECTORY != 0 {
                NodeKind::Directory
            } else {
                NodeKind::File
            };

            let mut stream: Option<&[u8]> = None;
            let mut name_fragments: Vec<&[u8]> = Vec::new();
            let end = (i + 1 + secondary_count as usize).min(num_entries);

            for j in (i + 1)..end {
                let s_offset = j * DIR_ENTRY_SIZE;
                if s_offset + DIR_ENTRY_SIZE > raw.len() {
                    break;
                }
                let s_data = &raw[s_offset..s_offset + DIR_ENTRY_SIZE];
                let s_type = s_data[0];

                if s_type == EXFAT_ENTRY_STREAM {
                    stream = Some(s_data);
                } else if s_type == EXFAT_ENTRY_FILENAME {
                    name_fragments.push(s_data);
                } else {
                    break;
                }
            }

            let name = build_exfat_filename(&name_fragments);

            let (first_cluster, valid_data_length, data_length, no_fat_chain) = match stream {
                Some(s) => {
                    let flags = s[S_FLAGS];
                    let no_fat = flags & S_FLAG_NO_FAT_CHAIN != 0;
                    let first = read_u32_le(s, S_FIRST_CLUSTER);
                    let valid_len = read_u32_le(s, S_VALID_DATA_LEN) as u64;
                    let data_len = read_u32_le(s, S_DATA_LEN) as u64;
                    (first, valid_len, data_len, no_fat)
                }
                None => (0, 0, 0, false),
            };

            let create_ts = read_u32_le(primary, F_CREATE_TIME);
            let modify_ts = read_u32_le(primary, F_MODIFY_TIME);
            let access_ts = read_u32_le(primary, F_ACCESS_TIME);

            entries.push(ExfatDirEntry {
                name,
                kind,
                first_cluster,
                valid_data_length,
                data_length,
                no_fat_chain,
                created: super::types::dos_timestamp_to_unix(create_ts),
                modified: super::types::dos_timestamp_to_unix(modify_ts),
                accessed: super::types::dos_timestamp_to_unix(access_ts),
            });

            i = end;
        } else if (parsed.type_code == 0x03 && !parsed._is_secondary)
            || entry_type == EXFAT_ENTRY_BITMAP
            || entry_type == EXFAT_ENTRY_UPCASE
        {
            let secondary_count = entry_data[1];
            i = i + 1 + secondary_count as usize;
        } else {
            i += 1;
        }
    }

    entries
}

/// Build a filename from collected filename-extension fragments, decoding
/// UTF-16LE code units until a NUL.
pub(super) fn build_exfat_filename(fragments: &[&[u8]]) -> String {
    let mut name = String::new();

    for frag in fragments {
        for idx in 0..FN_CHARS_PER_ENTRY {
            let byte_off = FN_NAME_START + idx * 2;
            if byte_off + 2 > frag.len() {
                break;
            }
            let code_unit = u16::from_le_bytes([frag[byte_off], frag[byte_off + 1]]);
            if code_unit == 0 {
                return name;
            }
            name.push(utf16le_code_unit_to_char(code_unit));
        }
    }

    name
}

/// Scan raw directory bytes for a named entry set's byte offset.
pub(super) fn find_entry_set_position(raw: &[u8], name: &str) -> Option<usize> {
    let num_entries = (raw.len() / DIR_ENTRY_SIZE).min(MAX_DIR_ENTRIES);
    let mut i = 0;

    while i < num_entries {
        let offset = i * DIR_ENTRY_SIZE;
        if offset + DIR_ENTRY_SIZE > raw.len() {
            break;
        }
        let entry_type = raw[offset];
        if entry_type == EXFAT_ENTRY_EOD {
            break;
        }

        if entry_type & ENTRY_INUSE_MASK == 0 {
            i += 1;
            continue;
        }

        let parsed = ExfatEntryType::from_byte(entry_type);
        if parsed.type_code == 0x05 && !parsed._is_secondary {
            let secondary_count = raw[offset + 1];
            let end = (i + 1 + secondary_count as usize).min(num_entries);

            let mut name_frags: Vec<&[u8]> = Vec::new();
            for j in (i + 1)..end {
                let s_off = j * DIR_ENTRY_SIZE;
                if s_off + DIR_ENTRY_SIZE > raw.len() {
                    break;
                }
                let s_type = raw[s_off];
                if s_type == EXFAT_ENTRY_FILENAME {
                    name_frags.push(&raw[s_off..s_off + DIR_ENTRY_SIZE]);
                } else if s_type == EXFAT_ENTRY_STREAM {
                    // Skip.
                } else {
                    break;
                }
            }

            let entry_name = build_exfat_filename(&name_frags);
            if eq_unicode_insensitive(&entry_name, name) {
                return Some(offset);
            }

            i = end;
        } else if parsed.type_code == 0x03 && !parsed._is_secondary
            || entry_type == EXFAT_ENTRY_BITMAP
            || entry_type == EXFAT_ENTRY_UPCASE
        {
            let secondary_count = raw[offset + 1];
            i = i + 1 + secondary_count as usize;
        } else {
            i += 1;
        }
    }

    None
}

/// Scan the root directory for the allocation bitmap entry, answering
/// `(first cluster, byte count)`, `(0, 0)` when there is none.
pub(super) fn parse_exfat_bitmap_entry(raw: &[u8]) -> (u32, u64) {
    let num_entries = (raw.len() / DIR_ENTRY_SIZE).min(MAX_DIR_ENTRIES);
    let mut i = 0;

    while i < num_entries {
        let offset = i * DIR_ENTRY_SIZE;
        if offset + DIR_ENTRY_SIZE > raw.len() {
            break;
        }
        let entry_type = raw[offset];
        if entry_type == EXFAT_ENTRY_EOD {
            break;
        }

        if entry_type == EXFAT_ENTRY_BITMAP {
            // The bitmap's stream extension follows, carrying its cluster
            // and length.
            let stream_offset = offset + DIR_ENTRY_SIZE;
            if stream_offset + DIR_ENTRY_SIZE <= raw.len()
                && raw[stream_offset] == EXFAT_ENTRY_STREAM
            {
                let first_cluster = read_u32_le(raw, stream_offset + S_FIRST_CLUSTER);
                let data_length = read_u32_le(raw, stream_offset + S_DATA_LEN) as u64;
                return (first_cluster, data_length);
            }
            let secondary_count = raw[offset + 1];
            i = i + 1 + secondary_count as usize;
            continue;
        }

        let parsed = ExfatEntryType::from_byte(entry_type);
        if (parsed.type_code == 0x03 || parsed.type_code == 0x05) && !parsed._is_secondary
            || entry_type == EXFAT_ENTRY_UPCASE
        {
            let secondary_count = raw[offset + 1];
            i = i + 1 + secondary_count as usize;
        } else {
            i += 1;
        }
    }

    (0, 0)
}

/// Split a path into `(parent, leaf)`.
pub(super) fn split_path(path: &str) -> (String, String) {
    let stripped = path.strip_prefix('/').unwrap_or(path);
    match stripped.rfind('/') {
        Some(pos) => {
            let name = stripped[pos + 1..].into();
            let parent = if pos == 0 {
                "/".into()
            } else {
                let mut p = String::with_capacity(pos + 2);
                p.push('/');
                p.push_str(&stripped[..pos]);
                p
            };
            (parent, name)
        }
        None => ("/".into(), stripped.into()),
    }
}
