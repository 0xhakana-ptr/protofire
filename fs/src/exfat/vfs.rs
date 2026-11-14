//! fs/src/exfat/vfs.rs
//!
//! The volume as the VFS sees it: the [`FileSystem`] a mount table mounts
//! and the [`VNode`]s it hands out, each carrying its parent directory's
//! cluster and its entry set's offset so a write can update the stream
//! entry the file's lengths live in.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::Mutex;

use abi::Error;
use abi::Result;

use crate::stats::CacheStats;
use crate::types::DirectoryEntry;
use crate::types::Metadata;
use crate::types::NodeKind;
use crate::types::SecurityDescriptorMutationSupport;
use crate::types::VolumeCheckReport;
use crate::vnode::VNode;

use super::fs::ExfatFs;
use super::fs::find_entry_set_position;
use super::fs::split_path;
use super::types::DIR_ENTRY_SIZE;
use super::types::ENTRY_INUSE_MASK;
use super::types::FAT32_EOC;
use super::types::FIRST_DATA_CLUSTER;
use super::types::FN_CHARS_PER_ENTRY;

/// An exFAT volume, as the mount table holds one.
pub struct ExfatVolume {
    name: String,
    fs: Arc<Mutex<ExfatFs>>,
}

impl ExfatVolume {
    /// Open a volume from a device: the boot region validated.
    pub fn open(device: Arc<dyn block::QueuedBlockDevice>) -> Result<Arc<Self>> {
        let fs = ExfatFs::open(device.clone())?;
        let name = alloc::format!(
            "exfat:{}",
            device.name().rsplit(':').next().unwrap_or(device.name())
        );
        Ok(Arc::new(Self {
            name,
            fs: Arc::new(Mutex::new(fs)),
        }))
    }

    fn with_fs<T>(&self, f: impl FnOnce(&mut ExfatFs) -> Result<T>) -> Result<T> {
        f(&mut self.fs.lock())
    }
}

impl crate::filesystem::FileSystem for ExfatVolume {
    fn name(&self) -> &str {
        &self.name
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        self.fs.lock().profiler.inc_lookups();
        let entry = self.with_fs(|fs| fs.walk_path(path))?;

        // The entry set's position in the parent directory, for the write
        // path's stream update.
        let (parent_dir_cluster, entry_set_offset) = if path == "/" || path.is_empty() {
            (0, 0)
        } else {
            let (parent_path, name) = split_path(path);
            self.with_fs(|fs| {
                let parent_entry = fs.walk_path(&parent_path)?;
                let raw = fs.read_cluster_chain_data(parent_entry.first_cluster)?;
                let offset = find_entry_set_position(&raw, &name).unwrap_or(0);
                Ok((parent_entry.first_cluster, offset))
            })
            .unwrap_or((0, 0))
        };

        Ok(Arc::new(ExfatVNode {
            name: entry.name.clone(),
            kind: entry.kind,
            first_cluster: entry.first_cluster,
            parent_dir_cluster,
            entry_set_offset,
            fs: self.fs.clone(),
            valid_data_length: Mutex::new(entry.valid_data_length),
            data_length: Mutex::new(entry.data_length),
            no_fat_chain: Mutex::new(entry.no_fat_chain),
        }))
    }

    fn stat(&self, path: &str) -> Result<Metadata> {
        let entry = self.with_fs(|fs| fs.walk_path(path))?;
        let kind = entry.kind;
        let size = if kind == NodeKind::Directory {
            0
        } else {
            entry.valid_data_length as usize
        };
        Ok(
            Metadata::new(kind, size).with_timestamps(
                entry.created,
                entry.modified,
                entry.accessed,
            ),
        )
    }

    fn sync(&self) -> Result<()> {
        self.with_fs(|fs| fs.flush())
    }

    fn sync_data(&self) -> Result<()> {
        self.sync()
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        self.fs.lock().profiler.inc_lookups();
        let dir_entry = self.with_fs(|fs| fs.walk_path(path))?;
        if dir_entry.kind != NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }
        let entries = self.with_fs(|fs| fs.read_directory_entries(dir_entry.first_cluster))?;
        let entry = entries.get(index).ok_or(Error::NotFound)?;
        Ok(DirectoryEntry::new(
            entry.kind,
            if entry.kind == NodeKind::Directory {
                0
            } else {
                entry.valid_data_length as usize
            },
            entry.name.clone(),
        ))
    }

    fn create_file(&self, path: &str) -> Result<Arc<dyn VNode>> {
        let (parent_dir_cluster, name) = self.with_fs(|fs| {
            let (parent_path, name) = split_path(path);
            let parent_entry = fs.walk_path(&parent_path)?;
            if parent_entry.kind != NodeKind::Directory {
                return Err(Error::InvalidArgument);
            }
            Ok((parent_entry.first_cluster, name))
        })?;

        if name.is_empty() {
            return Err(Error::InvalidArgument);
        }

        // A create of a name the volume already holds is the create's own
        // refusal, as the other backends answer.
        if self.with_fs(|fs| fs.walk_path(path)).is_ok() {
            return Err(Error::AlreadyExists);
        }

        self.with_fs(|fs| {
            let new_cluster = fs.find_free_cluster()?;
            fs.set_bitmap_bit(new_cluster, true)?;
            fs.write_fat_entry(new_cluster, FAT32_EOC)?;

            let entry_set =
                ExfatFs::build_entry_set(&name, NodeKind::File, new_cluster, 0, 0, true);
            let entry_bytes = entry_set.len() * DIR_ENTRY_SIZE;

            let slot_offset = fs.find_free_dir_slot(parent_dir_cluster, entry_bytes)?;

            let cluster_size = fs.boot.cluster_size_bytes as u64;
            let cluster_off = slot_offset as u64 / cluster_size;
            let intra_off = (slot_offset as u64 % cluster_size) as usize;

            let chain = fs.walk_cluster_chain(parent_dir_cluster)?;
            let target_cluster = *chain.get(cluster_off as usize).ok_or(Error::OutOfMemory)?;
            let lba = fs.boot.cluster_to_lba(target_cluster);

            for (i, entry) in entry_set.iter().enumerate() {
                let byte_pos = intra_off + i * DIR_ENTRY_SIZE;
                let sector = byte_pos / 512;
                let sec_off = byte_pos % 512;
                fs.read_block(lba + sector as u64)?;
                fs.block_buf[sec_off..sec_off + DIR_ENTRY_SIZE].copy_from_slice(entry);
                let block = fs.block_buf;
                fs.write_block_cached(lba + sector as u64, &block)?;
            }

            fs.flush()?;
            Ok(())
        })?;

        self.lookup(path)
    }

    fn create_dir(&self, path: &str) -> Result<()> {
        let (parent_dir_cluster, name) = self.with_fs(|fs| {
            let (parent_path, name) = split_path(path);
            let parent_entry = fs.walk_path(&parent_path)?;
            if parent_entry.kind != NodeKind::Directory {
                return Err(Error::InvalidArgument);
            }
            Ok((parent_entry.first_cluster, name))
        })?;

        if name.is_empty() {
            return Err(Error::InvalidArgument);
        }

        if self.with_fs(|fs| fs.walk_path(path)).is_ok() {
            return Err(Error::AlreadyExists);
        }

        self.with_fs(|fs| {
            let dir_cluster = fs.find_free_cluster()?;
            fs.set_bitmap_bit(dir_cluster, true)?;
            fs.write_fat_entry(dir_cluster, FAT32_EOC)?;

            // The new directory's dot entries, chained to itself and its
            // parent.
            let dot_entry =
                ExfatFs::build_entry_set(".", NodeKind::Directory, dir_cluster, 0, 0, false);
            let dotdot_entry = ExfatFs::build_entry_set(
                "..",
                NodeKind::Directory,
                parent_dir_cluster,
                0,
                0,
                false,
            );

            let lba = fs.boot.cluster_to_lba(dir_cluster);

            let flatten = |entries: &[[u8; DIR_ENTRY_SIZE]]| -> Vec<u8> {
                let mut flat = Vec::with_capacity(entries.len() * DIR_ENTRY_SIZE);
                for entry in entries {
                    flat.extend_from_slice(entry);
                }
                flat
            };

            let dot_bytes = flatten(&dot_entry);
            let dotdot_bytes = flatten(&dotdot_entry);

            fs.read_block(lba)?;
            fs.block_buf[..dot_bytes.len()].copy_from_slice(&dot_bytes);
            let dd_start = dot_bytes.len();
            fs.block_buf[dd_start..dd_start + dotdot_bytes.len()].copy_from_slice(&dotdot_bytes);
            let eod_pos = dd_start + dotdot_bytes.len();
            if eod_pos < 512 {
                fs.block_buf[eod_pos] = super::types::EXFAT_ENTRY_EOD;
            }
            let block = fs.block_buf;
            fs.write_block_cached(lba, &block)?;

            let entry_set =
                ExfatFs::build_entry_set(&name, NodeKind::Directory, dir_cluster, 0, 0, false);
            let entry_bytes = entry_set.len() * DIR_ENTRY_SIZE;

            let slot_offset = fs.find_free_dir_slot(parent_dir_cluster, entry_bytes)?;
            let cluster_size = fs.boot.cluster_size_bytes as u64;
            let cluster_off = slot_offset as u64 / cluster_size;
            let intra_off = (slot_offset as u64 % cluster_size) as usize;

            let chain = fs.walk_cluster_chain(parent_dir_cluster)?;
            let target_cluster = *chain.get(cluster_off as usize).ok_or(Error::OutOfMemory)?;
            let parent_lba = fs.boot.cluster_to_lba(target_cluster);

            for (i, entry) in entry_set.iter().enumerate() {
                let byte_pos = intra_off + i * DIR_ENTRY_SIZE;
                let sector = byte_pos / 512;
                let sec_off = byte_pos % 512;
                fs.read_block(parent_lba + sector as u64)?;
                fs.block_buf[sec_off..sec_off + DIR_ENTRY_SIZE].copy_from_slice(entry);
                let block = fs.block_buf;
                fs.write_block_cached(parent_lba + sector as u64, &block)?;
            }

            fs.flush()?;
            Ok(())
        })
    }

    fn rename(&self, old_path: &str, new_path: &str) -> Result<()> {
        let (old_parent_cluster, old_name) = self.with_fs(|fs| {
            let (parent_path, name) = split_path(old_path);
            let parent_entry = fs.walk_path(&parent_path)?;
            Ok((parent_entry.first_cluster, name))
        })?;

        let (_new_parent_cluster, new_name) = self.with_fs(|fs| {
            let (parent_path, name) = split_path(new_path);
            let parent_entry = fs.walk_path(&parent_path)?;
            if parent_entry.first_cluster != old_parent_cluster {
                // A rename across directories asks for the entry set to
                // move, which this driver does not do.
                return Err(Error::Unsupported);
            }
            Ok((parent_entry.first_cluster, name))
        })?;

        if self.with_fs(|fs| fs.walk_path(new_path)).is_ok() {
            return Err(Error::AlreadyExists);
        }

        let target_entry = self.with_fs(|fs| fs.walk_path(old_path))?;

        self.with_fs(|fs| {
            let new_entry_set = ExfatFs::build_entry_set(
                &new_name,
                target_entry.kind,
                target_entry.first_cluster,
                target_entry.valid_data_length,
                target_entry.data_length,
                target_entry.no_fat_chain,
            );
            let new_byte_count = new_entry_set.len() * DIR_ENTRY_SIZE;

            let old_raw = fs.read_cluster_chain_data(old_parent_cluster)?;
            let old_name_utf16 = unicode::utf8_to_utf16le(&old_name);
            let old_fn_count = old_name_utf16.len().div_ceil(FN_CHARS_PER_ENTRY);
            let old_total = 2 + old_fn_count;

            if let Some(old_pos) = find_entry_set_position(&old_raw, &old_name) {
                let cluster_size = fs.boot.cluster_size_bytes as usize;
                let cluster_off = old_pos / cluster_size;
                let intra_off = old_pos % cluster_size;

                let chain = fs.walk_cluster_chain(old_parent_cluster)?;
                if let Some(&target_cluster) = chain.get(cluster_off) {
                    let lba = fs.boot.cluster_to_lba(target_cluster);
                    // The old set's entries lose their in-use bit.
                    for i in 0..old_total {
                        let byte_pos = intra_off + i * DIR_ENTRY_SIZE;
                        let sector = byte_pos / 512;
                        let sec_off = byte_pos % 512;
                        fs.read_block(lba + sector as u64)?;
                        fs.block_buf[sec_off] &= !ENTRY_INUSE_MASK;
                        let block = fs.block_buf;
                        fs.write_block_cached(lba + sector as u64, &block)?;
                    }
                }

                // The new set takes the old set's place when it fits.
                if new_byte_count <= old_total * DIR_ENTRY_SIZE {
                    let chain2 = fs.walk_cluster_chain(old_parent_cluster)?;
                    if let Some(&target_cluster2) = chain2.get(cluster_off) {
                        let lba2 = fs.boot.cluster_to_lba(target_cluster2);
                        for (i, entry) in new_entry_set.iter().enumerate() {
                            let byte_pos = intra_off + i * DIR_ENTRY_SIZE;
                            let sector = byte_pos / 512;
                            let sec_off = byte_pos % 512;
                            fs.read_block(lba2 + sector as u64)?;
                            fs.block_buf[sec_off..sec_off + DIR_ENTRY_SIZE].copy_from_slice(entry);
                            let block = fs.block_buf;
                            fs.write_block_cached(lba2 + sector as u64, &block)?;
                        }
                        fs.flush()?;
                        return Ok(());
                    }
                }
            }

            // The fallback: a fresh slot for the new set.
            let new_slot = fs.find_free_dir_slot(old_parent_cluster, new_byte_count)?;
            let cluster_size = fs.boot.cluster_size_bytes as u64;
            let cluster_off = new_slot as u64 / cluster_size;
            let intra_off = (new_slot as u64 % cluster_size) as usize;

            let chain = fs.walk_cluster_chain(old_parent_cluster)?;
            let target_cluster = *chain.get(cluster_off as usize).ok_or(Error::OutOfMemory)?;
            let lba = fs.boot.cluster_to_lba(target_cluster);

            for (i, entry) in new_entry_set.iter().enumerate() {
                let byte_pos = intra_off + i * DIR_ENTRY_SIZE;
                let sector = byte_pos / 512;
                let sec_off = byte_pos % 512;
                fs.read_block(lba + sector as u64)?;
                fs.block_buf[sec_off..sec_off + DIR_ENTRY_SIZE].copy_from_slice(entry);
                let block = fs.block_buf;
                fs.write_block_cached(lba + sector as u64, &block)?;
            }

            fs.flush()?;
            Ok(())
        })
    }

    fn remove_path(&self, path: &str) -> Result<()> {
        let target = self.with_fs(|fs| fs.walk_path(path))?;

        // A directory that still holds children is not removed.
        if target.kind == NodeKind::Directory {
            let entries = self.with_fs(|fs| fs.read_directory_entries(target.first_cluster))?;
            let non_dot_count = entries
                .iter()
                .filter(|e| e.name != "." && e.name != "..")
                .count();
            if non_dot_count > 0 {
                return Err(Error::PermissionDenied);
            }
        }

        let (parent_dir_cluster, name) = self.with_fs(|fs| {
            let (parent_path, name) = split_path(path);
            let parent_entry = fs.walk_path(&parent_path)?;
            Ok((parent_entry.first_cluster, name))
        })?;

        self.with_fs(|fs| {
            let raw = fs.read_cluster_chain_data(parent_dir_cluster)?;

            let pos = find_entry_set_position(&raw, &name).ok_or(Error::NotFound)?;
            let cluster_size = fs.boot.cluster_size_bytes as usize;
            let cluster_off = pos / cluster_size;
            let intra_off = pos % cluster_size;

            let chain = fs.walk_cluster_chain(parent_dir_cluster)?;
            let target_cluster = *chain.get(cluster_off).ok_or(Error::OutOfMemory)?;
            let lba = fs.boot.cluster_to_lba(target_cluster);

            // The file entry loses its in-use bit, the deletion this
            // format expresses.
            let byte_pos = intra_off;
            let sector = byte_pos / 512;
            let sec_off = byte_pos % 512;
            fs.read_block(lba + sector as u64)?;
            fs.block_buf[sec_off] &= !ENTRY_INUSE_MASK;
            let block = fs.block_buf;
            fs.write_block_cached(lba + sector as u64, &block)?;

            if target.first_cluster >= FIRST_DATA_CLUSTER {
                fs.free_cluster_chain(target.first_cluster)?;
            }

            fs.flush()?;
            Ok(())
        })
    }

    fn security_descriptor_mutation_support(&self) -> SecurityDescriptorMutationSupport {
        SecurityDescriptorMutationSupport::LayoutDerivedOnly
    }

    fn fs_profiler_snapshot(&self) -> crate::profiler::FsProfilerSnapshot {
        self.fs.lock().profiler.snapshot()
    }

    fn cache_stats(&self) -> CacheStats {
        self.fs.lock().cache.stats()
    }

    fn check_and_repair(&self) -> Result<VolumeCheckReport> {
        let mut issues = 0usize;

        let fs = self.fs.lock();
        if fs.boot.cluster_size_bytes == 0 {
            issues += 1;
        }
        if fs.boot.cluster_count < 2 {
            issues += 1;
        }
        if fs.boot.root_dir_cluster < FIRST_DATA_CLUSTER {
            issues += 1;
        }
        drop(fs);

        if self.lookup("/").is_err() {
            issues += 1;
        }

        Ok(VolumeCheckReport {
            issues_detected: issues,
            ..Default::default()
        })
    }
}

/// A VFS node backed by an exFAT entry set.
struct ExfatVNode {
    name: String,
    kind: NodeKind,
    first_cluster: u32,
    parent_dir_cluster: u32,
    entry_set_offset: usize,
    fs: Arc<Mutex<ExfatFs>>,
    valid_data_length: Mutex<u64>,
    data_length: Mutex<u64>,
    no_fat_chain: Mutex<bool>,
}

impl VNode for ExfatVNode {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> NodeKind {
        self.kind
    }

    fn size(&self) -> usize {
        *self.valid_data_length.lock() as usize
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let mut fs = self.fs.lock();
        let data = fs.read_file_data(
            self.first_cluster,
            *self.valid_data_length.lock(),
            *self.no_fat_chain.lock(),
        )?;
        let start = (offset as usize).min(data.len());
        let end = (start + buffer.len()).min(data.len());
        let n = end - start;
        buffer[..n].copy_from_slice(&data[start..end]);
        Ok(n)
    }

    fn write(&self, offset: u64, buffer: &[u8]) -> Result<usize> {
        let mut fs = self.fs.lock();
        let current_size = *self.valid_data_length.lock();
        let no_fat_chain = *self.no_fat_chain.lock();

        let new_end = offset + buffer.len() as u64;
        let final_size = new_end.max(current_size);

        // The bytes before `offset` are the file's; the write overlays them.
        let mut data = if current_size > 0 && self.first_cluster >= FIRST_DATA_CLUSTER {
            fs.read_file_data(self.first_cluster, current_size, no_fat_chain)?
        } else {
            Vec::new()
        };
        if final_size as usize > data.len() {
            data.resize(final_size as usize, 0);
        }
        data[offset as usize..offset as usize + buffer.len()].copy_from_slice(buffer);

        let written = fs.write_cluster_data(self.first_cluster, offset, buffer)?;

        // The stream entry's lengths move with the write.
        let new_data_length =
            (final_size.max(*self.data_length.lock())).max(self.first_cluster as u64);
        fs.update_stream_entry(
            self.parent_dir_cluster,
            self.entry_set_offset,
            final_size,
            new_data_length,
            no_fat_chain,
        )?;
        fs.flush()?;

        *self.valid_data_length.lock() = final_size;
        *self.data_length.lock() = new_data_length.max(final_size);
        let _ = written;
        Ok(buffer.len())
    }

    fn set_len(&self, length: u64) -> Result<()> {
        let mut fs = self.fs.lock();
        let current_size = *self.valid_data_length.lock();
        let no_fat_chain = *self.no_fat_chain.lock();

        if length == current_size {
            return Ok(());
        }

        let mut data = if current_size > 0 && self.first_cluster >= FIRST_DATA_CLUSTER {
            fs.read_file_data(self.first_cluster, current_size, no_fat_chain)?
        } else {
            Vec::new()
        };
        data.resize(length as usize, 0);
        if length > 0 {
            fs.write_cluster_data(self.first_cluster, 0, &data)?;
        }

        fs.update_stream_entry(
            self.parent_dir_cluster,
            self.entry_set_offset,
            length,
            length.max(*self.data_length.lock()),
            no_fat_chain,
        )?;
        fs.flush()?;

        *self.valid_data_length.lock() = length;
        Ok(())
    }

    fn sync(&self) -> Result<()> {
        self.fs.lock().flush()
    }

    fn sync_data(&self) -> Result<()> {
        self.sync()
    }
}
