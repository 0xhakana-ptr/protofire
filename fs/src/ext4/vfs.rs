//! fs/src/ext4/vfs.rs
//!
//! The volume as the VFS sees it: the [`FileSystem`] a mount table mounts,
//! the [`VNode`]s it hands out, and the path arithmetic both of them share.
//!
//! Every node records its inode number and resolves it from disk on demand
//! — a node is a handle into the volume, not a copy of its bytes — which is
//! why two nodes on one file are two handles onto one inode, and why a
//! node's kind and size are read fresh from the table each time.

use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::QueuedBlockDevice;

use abi::Error;
use abi::Result;

use crate::stats::CacheStats;
use crate::types::DirectoryEntry;
use crate::types::Metadata;
use crate::types::NodeKind;
use crate::types::SecurityDescriptor;
use crate::types::SecurityDescriptorMutationSupport;
use crate::types::VolumeCheckReport;
use crate::vnode::VNode;

use super::constants::*;
use super::fs::Ext4Fs;

/// An ext4 volume, as the mount table holds one.
pub struct Ext4Volume {
    name: String,
    fs: Arc<Ext4Fs>,
}

impl Ext4Volume {
    /// Open a volume from a device: the superblock is validated, the group
    /// descriptors cached, a dirty journal replayed, and the volume answers
    /// from what the disk holds.
    pub fn open(device: Arc<dyn QueuedBlockDevice>) -> Result<Arc<Self>> {
        let name = alloc::format!(
            "ext4:{}",
            device.name().rsplit(':').next().unwrap_or(device.name())
        );
        let fs = Arc::new(Ext4Fs::open(device)?);
        Ok(Arc::new(Self { name, fs }))
    }

    /// Whether this mount replayed a dirty journal — the fact a check
    /// reports and a boot line can carry.
    pub fn journal_replayed(&self) -> bool {
        self.fs.journal_replayed
    }

    /// Write a fresh volume onto a device, then open it.
    ///
    /// The formatter makes the on-disk structures, the open reads them back
    /// and validates them, and one call is the whole round trip the write
    /// path proves itself with.
    pub fn make(device: Arc<dyn QueuedBlockDevice>, total_blocks: u32) -> Result<Arc<Self>> {
        {
            let cache = crate::block_cache::BlockCache::new(device.clone());
            super::format::format(&cache, total_blocks)?;
            cache.flush()?;
        }
        Self::open(device)
    }
}

impl super::super::filesystem::FileSystem for Ext4Volume {
    fn name(&self) -> &str {
        &self.name
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        self.fs.profiler.inc_lookups();
        let (ino, _inode) = self.fs.walk_path(path)?;
        Ok(Arc::new(Ext4VNode {
            name: leaf_name(path),
            fs: self.fs.clone(),
            ino,
        }))
    }

    fn stat(&self, path: &str) -> Result<Metadata> {
        let (_ino, inode) = self.fs.walk_path(path)?;
        // ctime is the closest thing the format has to a creation time.
        Ok(self.fs.stat_inode(&inode).with_timestamps(
            inode.ctime as u64,
            inode.mtime as u64,
            inode.atime as u64,
        ))
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        let (_dir_ino, dir_inode) = self.fs.walk_path(path)?;
        if dir_inode.kind() != NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }
        // The dot entries are the format's bookkeeping, not children: a
        // listing answers the names a caller made, which is the convention
        // every other backend's listing keeps.
        let entries: Vec<_> = self
            .fs
            .read_dir_entries(&dir_inode)?
            .into_iter()
            .filter(|entry| entry.name != "." && entry.name != "..")
            .collect();
        let entry = entries.get(index).ok_or(Error::NotFound)?;
        let child_inode = self.fs.read_inode(entry.inode)?;
        Ok(DirectoryEntry::new(
            // The entry's own file-type byte is the disk's record, and the
            // one a listing answers from.
            to_node_kind(entry.file_type),
            child_inode.file_size() as usize,
            entry.name.clone(),
        ))
    }

    fn rename(&self, old_path: &str, new_path: &str) -> Result<()> {
        self.fs.check_writable()?;
        let (old_parent, old_name) = split_path(old_path)?;
        let (new_parent, new_name) = split_path(new_path)?;

        let (target_ino, target_inode) = self.fs.walk_path(old_path)?;
        let (old_parent_ino, old_parent_inode) = self.fs.walk_path(&old_parent)?;
        if old_parent_inode.kind() != NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }
        let (new_parent_ino, new_parent_inode) = self.fs.walk_path(&new_parent)?;
        if new_parent_inode.kind() != NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }

        // A rename over an existing name drops it first, which is POSIX's
        // rename-over.
        if self.fs.walk_path(new_path).is_ok() {
            self.remove_path(new_path)?;
        }

        self.fs.add_dir_entry(
            new_parent_ino,
            target_ino,
            &new_name,
            file_type_code(target_inode.kind()),
        )?;
        self.fs.remove_dir_entry(old_parent_ino, &old_name)?;
        self.fs.profiler.inc_renames();
        Ok(())
    }

    fn create_file(&self, path: &str) -> Result<Arc<dyn VNode>> {
        self.fs.check_writable()?;
        let (parent_path, name) = split_path(path)?;
        let (parent_ino, parent_inode) = self.fs.walk_path(&parent_path)?;
        if parent_inode.kind() != NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }
        if self.fs.walk_path(path).is_ok() {
            return Err(Error::AlreadyExists);
        }

        let ino = self.fs.allocate_inode(EXT4_S_IFREG | 0o644, 0, 0)?;
        self.fs
            .add_dir_entry(parent_ino, ino, &name, EXT4_FT_REG_FILE)?;
        self.fs.profiler.inc_creates();
        Ok(Arc::new(Ext4VNode {
            name,
            fs: self.fs.clone(),
            ino,
        }))
    }

    fn create_dir(&self, path: &str) -> Result<()> {
        self.fs.check_writable()?;
        let (parent_path, name) = split_path(path)?;
        let (parent_ino, parent_inode) = self.fs.walk_path(&parent_path)?;
        if parent_inode.kind() != NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }
        if self.fs.walk_path(path).is_ok() {
            return Err(Error::AlreadyExists);
        }

        let ino = self.fs.allocate_inode(EXT4_S_IFDIR | 0o755, 0, 0)?;
        self.fs.add_dir_entry(parent_ino, ino, &name, EXT4_FT_DIR)?;
        self.fs.profiler.inc_creates();
        Ok(())
    }

    fn create_symlink(&self, target: &str, link_path: &str) -> Result<Arc<dyn VNode>> {
        self.fs.check_writable()?;
        let (parent_path, name) = split_path(link_path)?;
        let (parent_ino, parent_inode) = self.fs.walk_path(&parent_path)?;
        if parent_inode.kind() != NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }
        if self.fs.walk_path(link_path).is_ok() {
            return Err(Error::AlreadyExists);
        }

        // Fast symlinks only: the target, sixty bytes or fewer, is stored in
        // the inode's pointer array.  A longer target is a slow symlink, and
        // this driver does not make those.
        let target_bytes = target.as_bytes();
        if target_bytes.len() > 60 {
            return Err(Error::Unsupported);
        }

        let ino = self.fs.allocate_inode(EXT4_S_IFLNK | 0o777, 0, 0)?;
        let mut inode = self.fs.read_inode(ino)?;
        inode.size_low = target_bytes.len() as u32;
        inode.block.fill(0);
        for (i, chunk) in target_bytes.chunks(4).enumerate() {
            let mut word = [0u8; 4];
            word[..chunk.len()].copy_from_slice(chunk);
            inode.block[i] = u32::from_le_bytes(word);
        }
        self.fs.write_inode_raw(ino, &inode)?;
        self.fs
            .add_dir_entry(parent_ino, ino, &name, EXT4_FT_SYMLINK)?;
        self.fs.profiler.inc_creates();
        Ok(Arc::new(Ext4VNode {
            name,
            fs: self.fs.clone(),
            ino,
        }))
    }

    fn create_device(&self, path: &str, major: u32, minor: u32) -> Result<Arc<dyn VNode>> {
        self.fs.check_writable()?;
        let (parent_path, name) = split_path(path)?;
        let (parent_ino, parent_inode) = self.fs.walk_path(&parent_path)?;
        if parent_inode.kind() != NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }
        if self.fs.walk_path(path).is_ok() {
            return Err(Error::AlreadyExists);
        }

        // The device number is `(major << 8) | minor`, in the pointer
        // array's first slot.
        let encoded = (major << 8) | minor;
        let ino = self.fs.allocate_inode(EXT4_S_IFCHR | 0o600, 0, 0)?;
        let mut inode = self.fs.read_inode(ino)?;
        inode.block[0] = encoded;
        self.fs.write_inode_raw(ino, &inode)?;
        self.fs
            .add_dir_entry(parent_ino, ino, &name, EXT4_FT_CHRDEV)?;
        self.fs.profiler.inc_creates();
        Ok(Arc::new(Ext4VNode {
            name,
            fs: self.fs.clone(),
            ino,
        }))
    }

    fn remove_path(&self, path: &str) -> Result<()> {
        self.fs.check_writable()?;
        let (parent_path, name) = split_path(path)?;
        let (parent_ino, parent_inode) = self.fs.walk_path(&parent_path)?;
        if parent_inode.kind() != NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }
        let (ino, inode) = self.fs.walk_path(path)?;

        // A directory that still has children is not removed: the entries
        // beside its dot entries are the refusal's reason.
        if inode.kind() == NodeKind::Directory {
            let entries = self.fs.read_dir_entries(&inode)?;
            let has_children = entries.iter().any(|e| e.name != "." && e.name != "..");
            if has_children {
                return Err(Error::Busy);
            }
        }

        self.fs.remove_dir_entry(parent_ino, &name)?;
        self.fs.free_inode_blocks(ino)?;
        self.fs.free_inode(ino)?;
        self.fs.profiler.inc_deletes();
        Ok(())
    }

    fn security_descriptor_mutation_support(&self) -> SecurityDescriptorMutationSupport {
        SecurityDescriptorMutationSupport::LayoutDerivedOnly
    }

    fn update_security_descriptor(&self, path: &str, security: SecurityDescriptor) -> Result<()> {
        self.fs.check_writable()?;
        let (ino, mut inode) = self.fs.walk_path(path)?;
        // The file-type bits stay; the permission bits are the caller's.
        inode.mode = (inode.mode & EXT4_S_IFMT) | security.mode;
        inode.uid = (security.owner_uid & 0xFFFF) as u16;
        inode.gid = (security.owner_gid & 0xFFFF) as u16;
        inode.uid_high = ((security.owner_uid >> 16) & 0xFFFF) as u16;
        inode.gid_high = ((security.owner_gid >> 16) & 0xFFFF) as u16;
        self.fs.write_inode_raw(ino, &inode)
    }

    fn check_and_repair(&self) -> Result<VolumeCheckReport> {
        let mut issues = 0usize;
        if self.fs.sb.magic != EXT4_MAGIC {
            issues += 1;
        }
        if self.fs.block_size() == 0 {
            issues += 1;
        }
        if self.fs.read_inode(EXT4_ROOT_INO).is_err() {
            issues += 1;
        }
        Ok(VolumeCheckReport {
            issues_detected: issues,
            ..Default::default()
        })
    }

    fn cache_stats(&self) -> CacheStats {
        self.fs.cache.stats()
    }

    fn fs_profiler_snapshot(&self) -> crate::profiler::FsProfilerSnapshot {
        self.fs.profiler.snapshot()
    }

    fn sync(&self) -> Result<()> {
        self.fs.flush_all()
    }
}

/// A VFS node backed by an ext4 inode.
pub(super) struct Ext4VNode {
    name: String,
    fs: Arc<Ext4Fs>,
    ino: u32,
}

impl VNode for Ext4VNode {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> NodeKind {
        self.fs
            .read_inode(self.ino)
            .map(|i| i.kind())
            .unwrap_or(NodeKind::File)
    }

    fn size(&self) -> usize {
        self.fs
            .read_inode(self.ino)
            .map(|i| i.file_size() as usize)
            .unwrap_or(0)
    }

    fn metadata(&self) -> Result<Metadata> {
        let inode = self.fs.read_inode(self.ino)?;
        Ok(self.fs.stat_inode(&inode).with_timestamps(
            inode.ctime as u64,
            inode.mtime as u64,
            inode.atime as u64,
        ))
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        self.fs.profiler.inc_reads();
        self.fs.profiler.inc_read_bytes(buffer.len() as u64);
        let inode = self.fs.read_inode(self.ino)?;
        if inode.kind() == NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }
        self.fs.read_inode_data(&inode, offset, buffer)
    }

    fn write(&self, offset: u64, buffer: &[u8]) -> Result<usize> {
        self.fs.check_writable()?;
        self.fs.profiler.inc_writes();
        self.fs.profiler.inc_write_bytes(buffer.len() as u64);
        self.fs.write_file_data(self.ino, offset, buffer)
    }

    fn set_len(&self, length: u64) -> Result<()> {
        self.fs.check_writable()?;
        let inode = self.fs.read_inode(self.ino)?;
        let current = inode.file_size();
        if length == current {
            return Ok(());
        }
        if length < current {
            // A truncation would free the blocks past the new end and move
            // the size; this driver does neither yet, and says so rather
            // than leaving the volume with a size its blocks contradict.
            return Err(Error::Unsupported);
        }
        // An extension writes zero padding, a block at a time.
        let block_size = self.fs.block_size();
        let mut pos = current;
        let mut remaining = length - current;
        while remaining > 0 {
            let chunk = remaining.min(block_size as u64) as usize;
            let zeros = alloc::vec![0u8; chunk];
            let written = self.fs.write_file_data(self.ino, pos, &zeros)?;
            if written == 0 {
                return Err(Error::DeviceError);
            }
            pos += written as u64;
            remaining -= written as u64;
        }
        Ok(())
    }

    fn readlink(&self) -> Result<Vec<u8>> {
        let inode = self.fs.read_inode(self.ino)?;
        if inode.kind() != NodeKind::Symlink {
            return Err(Error::InvalidArgument);
        }
        self.fs.read_symlink_target(&inode)
    }

    fn device_id(&self) -> Result<(u32, u32)> {
        let inode = self.fs.read_inode(self.ino)?;
        if inode.kind() != NodeKind::Device {
            return Err(Error::InvalidArgument);
        }
        self.fs.read_device_id(&inode)
    }

    fn sync(&self) -> Result<()> {
        self.fs.flush_all()
    }

    fn sync_data(&self) -> Result<()> {
        self.fs.flush_all()
    }
}

// ── the path arithmetic ──────────────────────────────────────────────────

/// Split a path into `(parent, leaf)`.
///
/// `/foo/bar/baz` splits into `("/foo/bar", "baz")`, and `/hello` into
/// `("/", "hello")`.
pub(super) fn split_path(path: &str) -> Result<(String, String)> {
    let trimmed = path.trim_end_matches('/');
    let (parent, leaf) = trimmed.rsplit_once('/').ok_or(Error::InvalidArgument)?;
    if leaf.is_empty() {
        return Err(Error::InvalidArgument);
    }
    let parent = if parent.is_empty() { "/" } else { parent };
    Ok((parent.to_string(), leaf.to_string()))
}

/// A directory entry's file-type code, as the VFS's kind names it.
pub(super) fn to_node_kind(ft: u8) -> NodeKind {
    match ft {
        EXT4_FT_DIR => NodeKind::Directory,
        EXT4_FT_REG_FILE => NodeKind::File,
        EXT4_FT_CHRDEV | EXT4_FT_BLKDEV => NodeKind::Device,
        EXT4_FT_SYMLINK => NodeKind::Symlink,
        _ => NodeKind::File,
    }
}

/// The last component of a path.
fn leaf_name(path: &str) -> String {
    if path == "/" || path.is_empty() {
        return "/".into();
    }
    path.rsplit('/')
        .find(|s| !s.is_empty())
        .unwrap_or("/")
        .into()
}

/// The file-type code a new directory entry carries, for the kind it names.
fn file_type_code(kind: NodeKind) -> u8 {
    match kind {
        NodeKind::Directory => EXT4_FT_DIR,
        NodeKind::File => EXT4_FT_REG_FILE,
        NodeKind::Symlink => EXT4_FT_SYMLINK,
        NodeKind::Device => EXT4_FT_CHRDEV,
    }
}
