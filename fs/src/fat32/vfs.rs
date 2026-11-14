//! fs/src/fat32/vfs.rs
//!
//! The volume as the VFS sees it: the [`FileSystem`] a mount table mounts
//! and the [`VNode`]s it hands out, each carrying its parent directory's
//! location so a write can update the on-disk entry its size and cluster
//! live in.
//!
//! ## Why a node remembers where its entry is
//!
//! A FAT file's size and first cluster are the directory entry's fields,
//! not the file's, so a write that changes either has to find the entry
//! again.  Resolving the parent and scanning it on every write would be
//! the same bytes read twice; the node records the entry's offset and LFN
//! count at lookup, and invalidates that record whenever the driver cannot
//! vouch for it.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
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

use super::fs::FatFs;
use super::types::ATTR_DIRECTORY;
use super::types::DIR_ENTRY_SIZE as ENTRY_SIZE;
use super::types::FIRST_DATA_CLUSTER;
use super::types::FatType;
use super::types::build_dir_entry_set;
use super::types::insert_dir_entry_set;
use super::types::write_short_entry;

/// A mounted FAT volume, as the mount table holds one.
pub struct FatVolume {
    name: String,
    fs: Arc<Mutex<FatFs>>,
}

impl FatVolume {
    /// Open a volume from a device: the BPB validated, the FAT type named
    /// in the volume's own name.
    pub fn open(device: Arc<dyn block::QueuedBlockDevice>) -> Result<Arc<Self>> {
        let fs = FatFs::open(device.clone())?;
        let fat_type = fs.geom.fat_type;
        let name = alloc::format!(
            "{}:{}",
            fat_type.label(),
            device.name().rsplit(':').next().unwrap_or(device.name())
        );
        Ok(Arc::new(Self {
            name,
            fs: Arc::new(Mutex::new(fs)),
        }))
    }

    fn with_fs<T>(&self, f: impl FnOnce(&mut FatFs) -> Result<T>) -> Result<T> {
        f(&mut self.fs.lock())
    }
}

impl crate::filesystem::FileSystem for FatVolume {
    fn name(&self) -> &str {
        &self.name
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        self.fs.lock().profiler.inc_lookups();
        let (entry, parent_dir_cluster, entry_offset, lfn_count, is_parent_root, has_entry_info) =
            self.with_fs(|fs| {
                let entry = fs.walk_path(path)?;

                let (parent_path, _) = split_parent(path);
                let is_root = parent_path == "/";

                let parent = fs.walk_path(parent_path)?;
                let parent_cluster = parent.first_cluster;

                let (raw, _) = fs.get_dir_raw(parent_cluster, is_root)?;
                let found = find_entry_by_cluster(&raw, entry.first_cluster, &entry.name);
                let (off, lfn) = found.unwrap_or((0, 0));
                let has_info = found.is_some();
                Ok((entry, parent_cluster, off, lfn, is_root, has_info))
            })?;
        Ok(Arc::new(FatVNode {
            name: entry.name,
            kind: entry.kind,
            first_cluster: AtomicU32::new(entry.first_cluster),
            file_size: AtomicU32::new(entry.file_size),
            fs: self.fs.clone(),
            parent_dir_cluster,
            entry_offset,
            lfn_count,
            is_parent_root,
            has_entry_info,
        }))
    }

    fn stat(&self, path: &str) -> Result<Metadata> {
        let entry = self.with_fs(|fs| fs.walk_path(path))?;
        let kind = entry.kind;
        let size = entry.file_size as usize;
        Ok(
            Metadata::new(kind, size).with_timestamps(
                entry.created,
                entry.modified,
                entry.accessed,
            ),
        )
    }

    fn sync(&self) -> Result<()> {
        self.with_fs(|fs| fs.sync())
    }

    fn sync_data(&self) -> Result<()> {
        self.sync()
    }

    fn flush_aged(&self, age_ticks: u64) -> Result<usize> {
        self.with_fs(|fs| fs.flush_aged(age_ticks))
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        self.fs.lock().profiler.inc_lookups();
        let dir_entry = self.with_fs(|fs| fs.walk_path(path))?;
        if dir_entry.kind != NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }
        let is_root = path.is_empty() || path == "/";
        // The dot entries are the format's bookkeeping, not children: a
        // listing answers the names a caller made.
        let entries: Vec<_> = self
            .with_fs(|fs| fs.read_directory(dir_entry.first_cluster, is_root))?
            .into_iter()
            .filter(|entry| entry.name != "." && entry.name != "..")
            .collect();
        let entry = entries.get(index).ok_or(Error::NotFound)?;
        Ok(DirectoryEntry::new(
            entry.kind,
            entry.file_size as usize,
            entry.name.clone(),
        ))
    }

    fn create_file(&self, path: &str) -> Result<Arc<dyn VNode>> {
        if self.fs.lock().cache.is_read_only() {
            return Err(Error::PermissionDenied);
        }
        self.with_fs(|fs| {
            let (parent_path, file_name) = split_parent(path);
            let parent_entry = fs.walk_path(parent_path)?;
            if parent_entry.kind != NodeKind::Directory {
                return Err(Error::InvalidArgument);
            }
            // A create of a name the volume already holds is the create's
            // own refusal, as the other backends answer.
            if fs.walk_path(path).is_ok() {
                return Err(Error::AlreadyExists);
            }
            let parent_cluster = parent_entry.first_cluster;
            let is_parent_root = parent_path.is_empty() || parent_path == "/";

            let first_cluster = fs.append_cluster(0)?;

            let (mut raw, _) = fs.get_dir_raw(parent_cluster, is_parent_root)?;

            let mut entry_buf = [0u8; 256];
            let num = build_dir_entry_set(
                &mut entry_buf,
                file_name,
                0x20,
                first_cluster,
                0,
                fs.code_page,
            );

            let free_offset = fs.find_free_dir_offset(&raw).ok_or(Error::OutOfMemory)?;
            insert_dir_entry_set(&mut raw, free_offset, num, &entry_buf);

            fs.put_dir_raw(parent_cluster, is_parent_root, &raw)?;

            let lfn_count = num.saturating_sub(1);

            Ok(Arc::new(FatVNode {
                name: String::from(file_name),
                kind: NodeKind::File,
                first_cluster: AtomicU32::new(first_cluster),
                file_size: AtomicU32::new(0),
                fs: self.fs.clone(),
                parent_dir_cluster: parent_cluster,
                entry_offset: free_offset,
                lfn_count,
                is_parent_root,
                has_entry_info: true,
            }) as Arc<dyn VNode>)
        })
    }

    fn create_dir(&self, path: &str) -> Result<()> {
        if self.fs.lock().cache.is_read_only() {
            return Err(Error::PermissionDenied);
        }
        self.with_fs(|fs| {
            let (parent_path, dir_name) = split_parent(path);
            let parent_entry = fs.walk_path(parent_path)?;
            if parent_entry.kind != NodeKind::Directory {
                return Err(Error::InvalidArgument);
            }
            let parent_cluster = parent_entry.first_cluster;
            let is_parent_root = parent_path.is_empty() || parent_path == "/";

            let dir_cluster = fs.append_cluster(0)?;

            // The new directory's own block: its dot entries, with the
            // double-dot's cluster pointing at the parent (zero for a
            // FAT12/16 root, which has no cluster to name).
            let cluster_size = fs.geom.cluster_size_bytes as usize;
            let sectors = fs.geom.sectors_per_cluster as u64;
            let lba = fs.geom.cluster_to_lba(dir_cluster);
            let dot_name = *b".          ";
            let dotdot_name = *b"..         ";
            let parent_cluster_for_dotdot = if is_parent_root && fs.geom.fat_type != FatType::Fat32
            {
                0
            } else {
                parent_cluster
            };

            let mut dir_content = alloc::vec![0u8; cluster_size];
            write_short_entry(
                &mut dir_content,
                0,
                &dot_name,
                ATTR_DIRECTORY,
                dir_cluster,
                0,
            );
            write_short_entry(
                &mut dir_content,
                32,
                &dotdot_name,
                ATTR_DIRECTORY,
                parent_cluster_for_dotdot,
                0,
            );

            for s in 0..sectors {
                let block_start = s as usize * 512;
                let block_end = block_start + 512;
                let chunk = &dir_content[block_start..block_end];
                fs.block_buf.copy_from_slice(chunk);
                fs.write_block(lba + s)?;
            }

            // The parent's entry for the new directory.
            let (mut raw, _) = fs.get_dir_raw(parent_cluster, is_parent_root)?;
            let mut entry_buf = [0u8; 256];
            let num = build_dir_entry_set(
                &mut entry_buf,
                dir_name,
                ATTR_DIRECTORY,
                dir_cluster,
                0,
                fs.code_page,
            );
            let free_offset = fs.find_free_dir_offset(&raw).ok_or(Error::OutOfMemory)?;
            insert_dir_entry_set(&mut raw, free_offset, num, &entry_buf);
            fs.put_dir_raw(parent_cluster, is_parent_root, &raw)?;

            Ok(())
        })
    }

    fn rename(&self, old_path: &str, new_path: &str) -> Result<()> {
        if self.fs.lock().cache.is_read_only() {
            return Err(Error::PermissionDenied);
        }
        self.with_fs(|fs| {
            let entry = fs.walk_path(old_path)?;

            let (parent_path, _) = split_parent(old_path);
            let parent_entry = fs.walk_path(parent_path)?;
            let parent_cluster = parent_entry.first_cluster;
            let is_parent_root = parent_path.is_empty() || parent_path == "/";

            let (_, new_name) = split_parent(new_path);

            let (mut raw, _) = fs.get_dir_raw(parent_cluster, is_parent_root)?;

            let found_pos = find_entry_by_cluster(&raw, entry.first_cluster, &entry.name);
            match found_pos {
                Some((entry_start, lfn_entries)) => {
                    // The old set goes deleted, the new set takes a free
                    // slot, the rename this format can express.
                    let total_old_entries = lfn_entries + 1;
                    for i in 0..total_old_entries {
                        let off = entry_start + i * ENTRY_SIZE;
                        raw[off] = 0xE5;
                    }

                    let mut entry_buf = [0u8; 256];
                    let attrs = if entry.kind == NodeKind::Directory {
                        ATTR_DIRECTORY
                    } else {
                        0x20
                    };
                    let num_new = build_dir_entry_set(
                        &mut entry_buf,
                        new_name,
                        attrs,
                        entry.first_cluster,
                        entry.file_size,
                        fs.code_page,
                    );

                    let free_offset = fs.find_free_dir_offset(&raw).ok_or(Error::OutOfMemory)?;
                    insert_dir_entry_set(&mut raw, free_offset, num_new, &entry_buf);
                }
                None => return Err(Error::NotFound),
            }

            fs.put_dir_raw(parent_cluster, is_parent_root, &raw)?;
            Ok(())
        })
    }

    fn remove_path(&self, path: &str) -> Result<()> {
        if self.fs.lock().cache.is_read_only() {
            return Err(Error::PermissionDenied);
        }
        self.with_fs(|fs| {
            let entry = fs.walk_path(path)?;
            if entry.kind == NodeKind::Directory {
                let is_root = path.is_empty() || path == "/";
                let sub_entries = fs.read_directory(entry.first_cluster, is_root)?;
                if !sub_entries.is_empty() {
                    return Err(Error::Busy);
                }
            }

            if entry.first_cluster >= FIRST_DATA_CLUSTER {
                fs.free_cluster_chain(entry.first_cluster)?;
            }

            let (parent_path, _) = split_parent(path);
            let parent_entry = fs.walk_path(parent_path)?;
            let parent_cluster = parent_entry.first_cluster;
            let is_parent_root = parent_path.is_empty() || parent_path == "/";

            let (mut raw, _) = fs.get_dir_raw(parent_cluster, is_parent_root)?;

            let found_pos = find_entry_by_cluster(&raw, entry.first_cluster, &entry.name);
            match found_pos {
                Some((entry_start, lfn_entries)) => {
                    let total = lfn_entries + 1;
                    for i in 0..total {
                        let off = entry_start + i * ENTRY_SIZE;
                        raw[off] = 0xE5;
                    }
                }
                None => return Err(Error::NotFound),
            }

            fs.put_dir_raw(parent_cluster, is_parent_root, &raw)?;
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
        if fs.geom.bytes_per_sector != 512 {
            issues += 1;
        }
        if fs.geom.sectors_per_cluster == 0 || !fs.geom.sectors_per_cluster.is_power_of_two() {
            issues += 1;
        }
        if fs.geom.cluster_size_bytes == 0 {
            issues += 1;
        }
        if fs.geom.data_cluster_count < 2 {
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

/// A VFS node backed by a FAT directory entry.
struct FatVNode {
    name: String,
    kind: NodeKind,
    first_cluster: AtomicU32,
    file_size: AtomicU32,
    fs: Arc<Mutex<FatFs>>,
    parent_dir_cluster: u32,
    entry_offset: usize,
    lfn_count: usize,
    is_parent_root: bool,
    /// Whether `entry_offset` and `lfn_count` are valid, write and
    /// `set_len` skip the on-disk entry update when it is not.
    has_entry_info: bool,
}

impl VNode for FatVNode {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> NodeKind {
        self.kind
    }

    fn size(&self) -> usize {
        self.file_size.load(Ordering::Relaxed) as usize
    }

    fn sync(&self) -> Result<()> {
        self.fs.lock().sync()
    }

    fn sync_data(&self) -> Result<()> {
        self.sync()
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        if self.kind == NodeKind::Directory {
            return Err(Error::PermissionDenied);
        }
        let data = self.fs.lock().read_file_data(
            self.first_cluster.load(Ordering::Relaxed),
            self.file_size.load(Ordering::Relaxed),
        )?;
        let start = (offset as usize).min(data.len());
        let end = (start + buffer.len()).min(data.len());
        let n = end - start;
        buffer[..n].copy_from_slice(&data[start..end]);
        Ok(n)
    }

    fn write(&self, offset: u64, buffer: &[u8]) -> Result<usize> {
        if self.fs.lock().cache.is_read_only() {
            return Err(Error::PermissionDenied);
        }
        if self.kind == NodeKind::Directory {
            return Err(Error::PermissionDenied);
        }

        let mut fs = self.fs.lock();
        let start_cluster = self.first_cluster.load(Ordering::Relaxed);
        let current_size = self.file_size.load(Ordering::Relaxed) as usize;

        // The bytes before `offset` are the file's; the write overlays them.
        let new_end = offset as usize + buffer.len();
        let final_size = new_end.max(current_size);

        let mut data = if current_size > 0 && start_cluster >= FIRST_DATA_CLUSTER {
            fs.read_file_data(start_cluster, current_size as u32)?
        } else {
            Vec::new()
        };

        if final_size > data.len() {
            data.resize(final_size, 0);
        }

        let copy_len = buffer.len().min(data.len() - offset as usize);
        data[offset as usize..offset as usize + copy_len].copy_from_slice(&buffer[..copy_len]);

        let new_start = fs.write_file_data_extend(start_cluster, &data)?;

        if new_start != start_cluster {
            self.first_cluster.store(new_start, Ordering::Relaxed);
        }

        // The on-disk entry moves when the file's size or cluster did.
        if self.has_entry_info
            && (new_start != start_cluster || final_size as u32 != current_size as u32)
        {
            let (mut raw, _) = fs.get_dir_raw(self.parent_dir_cluster, self.is_parent_root)?;
            let short_off = self.entry_offset + self.lfn_count * ENTRY_SIZE;
            if short_off + 32 <= raw.len() {
                raw[short_off + 28] = final_size as u8;
                raw[short_off + 29] = (final_size >> 8) as u8;
                raw[short_off + 30] = (final_size >> 16) as u8;
                raw[short_off + 31] = (final_size >> 24) as u8;
                raw[short_off + 26] = new_start as u8;
                raw[short_off + 27] = (new_start >> 8) as u8;
                raw[short_off + 20] = (new_start >> 16) as u8;
                raw[short_off + 21] = (new_start >> 24) as u8;
                let _ = fs.put_dir_raw(self.parent_dir_cluster, self.is_parent_root, &raw);
            }
        }
        drop(fs);

        self.file_size.store(final_size as u32, Ordering::Relaxed);

        // The write persists immediately, a crash after write() must not
        // lose bytes sitting in the block cache.
        self.fs.lock().flush()?;

        Ok(copy_len)
    }

    fn set_len(&self, length: u64) -> Result<()> {
        if self.fs.lock().cache.is_read_only() {
            return Err(Error::PermissionDenied);
        }
        if self.kind != NodeKind::File {
            return Err(Error::InvalidArgument);
        }

        let length = length as u32;
        let mut fs = self.fs.lock();
        let current_size = self.file_size.load(Ordering::Relaxed);

        if length == current_size {
            return Ok(());
        }

        let update_dir_entry = |fs: &mut FatFs, file_size: u32, first_cluster: u32| -> Result<()> {
            let (mut raw, _) = fs.get_dir_raw(self.parent_dir_cluster, self.is_parent_root)?;
            let short_off = self.entry_offset + self.lfn_count * ENTRY_SIZE;
            if short_off + 32 > raw.len() {
                return Err(Error::InvalidArgument);
            }
            raw[short_off + 28] = file_size as u8;
            raw[short_off + 29] = (file_size >> 8) as u8;
            raw[short_off + 30] = (file_size >> 16) as u8;
            raw[short_off + 31] = (file_size >> 24) as u8;
            raw[short_off + 26] = first_cluster as u8;
            raw[short_off + 27] = (first_cluster >> 8) as u8;
            raw[short_off + 20] = (first_cluster >> 16) as u8;
            raw[short_off + 21] = (first_cluster >> 24) as u8;
            fs.put_dir_raw(self.parent_dir_cluster, self.is_parent_root, &raw)?;
            Ok(())
        };

        if length < current_size {
            let start_cluster = self.first_cluster.load(Ordering::Relaxed);

            if length == 0 {
                // Truncate to zero: the whole chain goes back.
                if start_cluster >= FIRST_DATA_CLUSTER {
                    fs.free_cluster_chain(start_cluster)?;
                }
                self.first_cluster.store(0, Ordering::Relaxed);
                self.file_size.store(0, Ordering::Relaxed);
                if self.has_entry_info {
                    update_dir_entry(&mut fs, 0, 0)?;
                }
            } else {
                // A partial truncation reads what there is, shrinks it, and
                // lets the extend path free the chain's tail.
                let mut data = if start_cluster >= FIRST_DATA_CLUSTER {
                    fs.read_file_data(start_cluster, current_size)?
                } else {
                    Vec::new()
                };
                data.truncate(length as usize);
                let new_start = fs.write_file_data_extend(start_cluster, &data)?;
                if new_start != start_cluster {
                    self.first_cluster.store(new_start, Ordering::Relaxed);
                }
                self.file_size.store(length, Ordering::Relaxed);
                if self.has_entry_info {
                    update_dir_entry(&mut fs, length, new_start)?;
                }
            }
            fs.flush()?;
        } else {
            // An extension writes zeros beyond the current end, write()
            // updates the on-disk entry itself.
            drop(fs);
            let zeros = alloc::vec![0u8; (length - current_size) as usize];
            self.write(current_size as u64, &zeros)?;
        }
        Ok(())
    }
}

// helpers

/// Split a path into `(parent, leaf)`.
fn split_parent(path: &str) -> (&str, &str) {
    match path.rsplit_once('/') {
        Some((parent, name)) => {
            if parent.is_empty() {
                ("/", name)
            } else {
                (
                    path.strip_suffix(name)
                        .unwrap_or(path)
                        .trim_end_matches('/'),
                    name,
                )
            }
        }
        None => ("/", path),
    }
}

/// Find a directory entry set by its first cluster, answering the set's
/// start offset and its LFN entry count.
///
/// Cluster matching is ambiguous for a zero-cluster (empty) file, so the
/// expected name disambiguates against the entry's 8.3 short name there.
fn find_entry_by_cluster(
    raw: &[u8],
    target_cluster: u32,
    expected_name: &str,
) -> Option<(usize, usize)> {
    let num_entries = raw.len() / ENTRY_SIZE;
    let mut i = 0;
    let mut lfn_count = 0usize;
    let name_must_match = target_cluster < FIRST_DATA_CLUSTER;

    while i < num_entries {
        let offset = i * ENTRY_SIZE;
        let first_byte = raw[offset];

        if first_byte == 0x00 {
            break;
        }
        if first_byte == 0xE5 {
            lfn_count = 0;
            i += 1;
            continue;
        }

        let entry_data = &raw[offset..offset + ENTRY_SIZE];

        if entry_data[11] == 0x0F {
            lfn_count += 1;
            i += 1;
            continue;
        }

        let cluster_lo = u16::from_le_bytes([entry_data[26], entry_data[27]]) as u32;
        let cluster_hi = u16::from_le_bytes([entry_data[20], entry_data[21]]) as u32;
        let entry_cluster = cluster_lo | (cluster_hi << 16);

        if entry_cluster == target_cluster {
            if name_must_match && !short_name_matches(entry_data, expected_name) {
                lfn_count = 0;
                i += 1;
                continue;
            }
            let entry_start = offset - lfn_count * ENTRY_SIZE;
            return Some((entry_start, lfn_count));
        }

        lfn_count = 0;
        i += 1;
    }
    None
}

/// Whether an entry's 11-byte short name matches a user-visible name
/// case-insensitive, space-padded 8.3 against the name's own split.
fn short_name_matches(entry_data: &[u8], expected: &str) -> bool {
    let expected = expected.to_uppercase();
    let expected_bytes = expected.as_bytes();

    let dot = expected_bytes.iter().position(|&b| b == b'.');
    let (name_part, ext_part) = match dot {
        Some(pos) => (
            &expected_bytes[..pos.min(8)],
            &expected_bytes[pos + 1..][..3.min(expected_bytes.len().saturating_sub(pos + 1))],
        ),
        None => (expected_bytes, &expected_bytes[..0]),
    };

    let raw_name = &entry_data[0..8];
    let raw_ext = &entry_data[8..11];

    let name_match = raw_name
        .iter()
        .zip(name_part.iter().chain(core::iter::repeat(&b' ')))
        .all(|(r, e)| r == e || *r == b' ');
    let ext_match = raw_ext
        .iter()
        .zip(ext_part.iter().chain(core::iter::repeat(&b' ')))
        .all(|(r, e)| r == e || *r == b' ');
    name_match && ext_match
}
