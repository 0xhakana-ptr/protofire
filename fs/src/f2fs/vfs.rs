//! fs/src/f2fs/vfs.rs
//!
//! The volume as the VFS sees it: the [`FileSystem`] a mount table mounts,
//! the [`VNode`]s it hands out, and the path arithmetic both share.

use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::QueuedBlockDevice;
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

use super::constants::*;
use super::fs::F2fsFs;
use super::types::*;

/// An f2fs volume, as the mount table holds one.
pub struct F2fsVolume {
    name: String,
    fs: Arc<F2fsFs>,
}

impl F2fsVolume {
    /// Open a volume from a device.
    pub fn open(device: Arc<dyn QueuedBlockDevice>) -> Result<Arc<Self>> {
        let name = format!(
            "f2fs:{}",
            device.name().rsplit(':').next().unwrap_or(device.name())
        );
        let fs = Arc::new(F2fsFs::open(device)?);
        Ok(Arc::new(Self { name, fs }))
    }

    /// Write a fresh volume onto a device, then open it: the layout the
    /// mount reads is the formatter's own product — a superblock, two
    /// checkpoints with the newer one winning, SIT, NAT, SSA, and a root
    /// directory with its dot entries.
    pub fn make(device: Arc<dyn QueuedBlockDevice>) -> Result<Arc<Self>> {
        {
            let cache = crate::block_cache::BlockCache::new(device.clone());
            super::format::format(&cache)?;
            cache.flush()?;
        }
        Self::open(device)
    }
}

impl crate::filesystem::FileSystem for F2fsVolume {
    fn name(&self) -> &str {
        &self.name
    }

    fn cache_stats(&self) -> CacheStats {
        self.fs.cache.stats()
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        let (nid, inode) = self.fs.walk_path(path)?;
        let fname = path
            .rsplit_once('/')
            .map(|(_, leaf)| if leaf.is_empty() { "root" } else { leaf })
            .unwrap_or("root");
        Ok(Arc::new(F2VNode {
            name: fname.to_string(),
            nid,
            inode: Mutex::new(inode),
            fs: self.fs.clone(),
        }))
    }

    fn stat(&self, path: &str) -> Result<Metadata> {
        let (_nid, inode) = self.fs.walk_path(path)?;
        Ok(self.fs.stat_inode(&inode))
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        let (_nid, dir_inode) = self.fs.walk_path(path)?;
        let kind = dir_inode.kind();
        if kind != NodeKind::Directory {
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
        let child_nid = entry.ino;

        let child_kind = f2fs_ft_to_kind(entry.file_type);
        let child_size = match self.fs.read_inode(child_nid) {
            Ok(child_inode) => child_inode.file_size() as usize,
            Err(_) => 0,
        };

        Ok(DirectoryEntry::new(
            child_kind,
            child_size,
            entry.name.clone(),
        ))
    }

    fn rename(&self, old_path: &str, new_path: &str) -> Result<()> {
        self.fs.check_writable()?;

        let (old_nid, old_inode) = self.fs.walk_path(old_path)?;

        let (old_parent_path, old_name) = split_path(old_path)?;
        let (old_parent_nid, _) = self.fs.walk_path(&old_parent_path)?;

        let (new_parent_path, new_name) = split_path(new_path)?;
        let (new_parent_nid, _) = self.fs.walk_path(&new_parent_path)?;

        // A rename over an existing name drops it first — a directory with
        // children is refused, the same refusal a removal makes.
        if let Ok((existing_nid, existing_inode)) = self.fs.walk_path(new_path) {
            if existing_nid == old_nid {
                if old_path == new_path {
                    return Ok(());
                }
            } else if existing_inode.kind() == NodeKind::Directory {
                let entries = self.fs.read_dir_entries(&existing_inode)?;
                let non_dot_entries = entries
                    .iter()
                    .filter(|e| e.name != "." && e.name != "..")
                    .count();
                if non_dot_entries > 0 {
                    return Err(Error::Busy);
                }
            }
            self.fs.remove_dir_entry(new_parent_nid, &new_name)?;
            self.fs.free_inode_blocks(existing_nid)?;
            self.fs.nat_free_nid(existing_nid)?;
        }

        self.fs.remove_dir_entry(old_parent_nid, &old_name)?;

        let file_type = match old_inode.kind() {
            NodeKind::Directory => F2FS_FT_DIR,
            NodeKind::File => F2FS_FT_REG_FILE,
            NodeKind::Device => F2FS_FT_CHRDEV,
            NodeKind::Symlink => F2FS_FT_SYMLINK,
        };
        self.fs
            .add_dir_entry(new_parent_nid, old_nid, &new_name, file_type)?;

        // A directory renamed across parents moves its ".."'s link count.
        if old_inode.kind() == NodeKind::Directory && old_parent_nid != new_parent_nid {
            let mut old_parent_inode = self.fs.read_inode(old_parent_nid)?;
            old_parent_inode.i_links = old_parent_inode.i_links.saturating_sub(1);
            self.fs.write_inode(old_parent_nid, &old_parent_inode)?;

            let mut new_parent_inode = self.fs.read_inode(new_parent_nid)?;
            new_parent_inode.i_links = new_parent_inode.i_links.saturating_add(1);
            self.fs.write_inode(new_parent_nid, &new_parent_inode)?;
        }

        self.fs.flush_all()
    }

    fn create_file(&self, path: &str) -> Result<Arc<dyn VNode>> {
        self.fs.check_writable()?;

        let (parent_path, child_name) = split_path(path)?;
        let (parent_nid, _) = self.fs.walk_path(&parent_path)?;

        // A create of a name the volume already holds is the create's own
        // refusal, the same answer the ext4 driver gives: two entries for
        // one name would make a lookup's answer order-dependent.
        if self.fs.walk_path(path).is_ok() {
            return Err(Error::AlreadyExists);
        }

        let file_nid = self.fs.nat_alloc_nid()?;

        let file_inode = empty_inode(F2FS_S_IFREG | 0o644);

        self.fs.write_inode(file_nid, &file_inode)?;
        self.fs
            .add_dir_entry(parent_nid, file_nid, &child_name, F2FS_FT_REG_FILE)?;

        self.fs.flush_all()?;

        let inode = self.fs.read_inode(file_nid)?;
        Ok(Arc::new(F2VNode {
            name: child_name.to_string(),
            nid: file_nid,
            inode: Mutex::new(inode),
            fs: self.fs.clone(),
        }))
    }

    fn create_dir(&self, path: &str) -> Result<()> {
        self.fs.check_writable()?;

        let (parent_path, child_name) = split_path(path)?;
        let (parent_nid, _) = self.fs.walk_path(&parent_path)?;

        if self.fs.walk_path(path).is_ok() {
            return Err(Error::AlreadyExists);
        }

        let dir_nid = self.fs.nat_alloc_nid()?;
        let block_size = self.fs.block_size();

        // The dot entries, whose sizes are the directory's own first size.
        let mut data_block = alloc::vec![0u8; block_size];
        let mut offset = 0usize;
        offset += write_f2fs_dir_entry(dir_nid, ".", F2FS_FT_DIR, 0, &mut data_block[offset..]);
        write_f2fs_dir_entry(parent_nid, "..", F2FS_FT_DIR, 0, &mut data_block[offset..]);

        let data_phys = self.fs.segment_alloc_block(&data_block)?;

        let mut dir_inode = empty_inode(F2FS_S_IFDIR | 0o755);
        dir_inode.i_links = 2;
        dir_inode.i_size = (dir_entry_size(1) + dir_entry_size(2)) as u64;
        dir_inode.i_blocks = (block_size as u64).div_ceil(512);
        dir_inode.i_addr[0] = data_phys;

        self.fs.write_inode(dir_nid, &dir_inode)?;

        // The parent's link count rises with the child it now holds.
        {
            let mut parent_inode = self.fs.read_inode(parent_nid)?;
            parent_inode.i_links = parent_inode.i_links.saturating_add(1);
            self.fs.write_inode(parent_nid, &parent_inode)?;
        }

        self.fs
            .add_dir_entry(parent_nid, dir_nid, &child_name, F2FS_FT_DIR)?;

        self.fs.flush_all()
    }

    fn create_symlink(&self, target: &str, link_path: &str) -> Result<Arc<dyn VNode>> {
        self.fs.check_writable()?;

        let target_bytes = target.as_bytes();
        // Fast symlinks only: the target rides in `i_addr`, whose byte
        // length is the array's.
        let max_fast = F2FS_ADDRS_PER_INODE * 4;
        if target_bytes.len() > max_fast {
            return Err(Error::InvalidArgument);
        }

        let (parent_path, child_name) = split_path(link_path)?;
        let (parent_nid, _) = self.fs.walk_path(&parent_path)?;

        let sym_nid = self.fs.nat_alloc_nid()?;

        let mut sym_inode = empty_inode(F2FS_S_IFLNK | 0o777);
        sym_inode.i_size = target_bytes.len() as u64;

        // SAFETY: as the read side — the same `u32` array, viewed mutably
        // for the length it actually has.
        let addr_bytes: &mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(
                sym_inode.i_addr.as_mut_ptr() as *mut u8,
                F2FS_ADDRS_PER_INODE * 4,
            )
        };
        addr_bytes[..target_bytes.len()].copy_from_slice(target_bytes);

        self.fs.write_inode(sym_nid, &sym_inode)?;
        self.fs
            .add_dir_entry(parent_nid, sym_nid, &child_name, F2FS_FT_SYMLINK)?;
        self.fs.flush_all()?;

        let inode = self.fs.read_inode(sym_nid)?;
        Ok(Arc::new(F2VNode {
            name: child_name.to_string(),
            nid: sym_nid,
            inode: Mutex::new(inode),
            fs: self.fs.clone(),
        }))
    }

    fn create_device(&self, path: &str, major: u32, minor: u32) -> Result<Arc<dyn VNode>> {
        self.fs.check_writable()?;

        let (parent_path, child_name) = split_path(path)?;
        let (parent_nid, _) = self.fs.walk_path(&parent_path)?;

        let dev_nid = self.fs.nat_alloc_nid()?;

        let mut dev_inode = empty_inode(F2FS_S_IFCHR | 0o660);
        // The device number is `(major << 8) | minor`, in the pointer
        // array's first slot.
        dev_inode.i_addr[0] = (major << 8) | minor;

        self.fs.write_inode(dev_nid, &dev_inode)?;
        self.fs
            .add_dir_entry(parent_nid, dev_nid, &child_name, F2FS_FT_CHRDEV)?;
        self.fs.flush_all()?;

        let inode = self.fs.read_inode(dev_nid)?;
        Ok(Arc::new(F2VNode {
            name: child_name.to_string(),
            nid: dev_nid,
            inode: Mutex::new(inode),
            fs: self.fs.clone(),
        }))
    }

    fn remove_path(&self, path: &str) -> Result<()> {
        self.fs.check_writable()?;

        if path == "/" {
            return Err(Error::Busy);
        }

        let (nid, inode) = self.fs.walk_path(path)?;

        // A directory's children go first, depth-first: a removal that
        // left them would leave them unreachable.
        if inode.kind() == NodeKind::Directory {
            let entries = self.fs.read_dir_entries(&inode)?;
            for entry in &entries {
                if entry.name != "." && entry.name != ".." {
                    let child_path = if path.ends_with('/') {
                        format!("{}{}", path, entry.name)
                    } else {
                        format!("{}/{}", path, entry.name)
                    };
                    self.remove_path(&child_path)?;
                }
            }
        }

        let (parent_path, child_name) = split_path(path)?;
        let (parent_nid, mut parent_inode) = self.fs.walk_path(&parent_path)?;

        self.fs.remove_dir_entry(parent_nid, &child_name)?;
        self.fs.free_inode_blocks(nid)?;
        self.fs.nat_free_nid(nid)?;

        if inode.kind() == NodeKind::Directory {
            parent_inode.i_links = parent_inode.i_links.saturating_sub(1);
            self.fs.write_inode(parent_nid, &parent_inode)?;
        }

        self.fs.flush_all()
    }

    fn security_descriptor_mutation_support(&self) -> SecurityDescriptorMutationSupport {
        SecurityDescriptorMutationSupport::LayoutDerivedOnly
    }

    fn check_and_repair(&self) -> Result<VolumeCheckReport> {
        Ok(VolumeCheckReport::default())
    }

    fn sync(&self) -> Result<()> {
        self.fs.flush_all()
    }
}

/// A VFS node backed by an f2fs node.
struct F2VNode {
    name: String,
    nid: u32,
    inode: Mutex<F2fsInode>,
    fs: Arc<F2fsFs>,
}

impl VNode for F2VNode {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> NodeKind {
        self.fs
            .read_inode(self.nid)
            .map(|inode| inode.kind())
            .unwrap_or_else(|_| self.inode.lock().kind())
    }

    fn size(&self) -> usize {
        self.fs
            .read_inode(self.nid)
            .map(|inode| inode.file_size() as usize)
            .unwrap_or_else(|_| self.inode.lock().file_size() as usize)
    }

    fn metadata(&self) -> Result<Metadata> {
        let inode = self.fs.read_inode(self.nid)?;
        Ok(self.fs.stat_inode(&inode))
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        let inode = self.fs.read_inode(self.nid)?;
        self.fs.read_file_data(&inode, offset, buffer)
    }

    fn write(&self, offset: u64, buffer: &[u8]) -> Result<usize> {
        let written = self.fs.write_file_data(self.nid, offset, buffer)?;
        if let Ok(fresh) = self.fs.read_inode(self.nid) {
            *self.inode.lock() = fresh;
        }
        Ok(written)
    }

    fn set_len(&self, length: u64) -> Result<()> {
        self.fs.check_writable()?;
        let mut inode = self.fs.read_inode(self.nid)?;

        if length < inode.i_size {
            // A truncation invalidates every block past the new end.
            let block_size = self.fs.block_size() as u64;
            let new_end_block = if length == 0 {
                0
            } else {
                length.div_ceil(block_size) as usize
            };
            for addr_slot in &mut inode.i_addr[new_end_block..] {
                if *addr_slot != F2FS_NULL_ADDR && *addr_slot != F2FS_NEW_ADDR {
                    self.fs.invalidate_mapped_block(*addr_slot);
                    *addr_slot = F2FS_NULL_ADDR;
                }
            }
        }

        inode.i_size = length;
        inode.i_blocks = length.div_ceil(512);
        self.fs.write_inode(self.nid, &inode)?;
        *self.inode.lock() = inode;
        Ok(())
    }

    fn sync(&self) -> Result<()> {
        self.fs.flush_all()
    }

    fn sync_data(&self) -> Result<()> {
        self.fs.cache.flush()
    }

    fn readlink(&self) -> Result<Vec<u8>> {
        let inode = self.fs.read_inode(self.nid)?;
        self.fs.read_symlink_target(&inode)
    }

    fn device_id(&self) -> Result<(u32, u32)> {
        let inode = self.fs.read_inode(self.nid)?;
        if inode.kind() != NodeKind::Device {
            return Err(Error::InvalidArgument);
        }
        let encoded = inode.i_addr[0];
        let major = (encoded >> 8) & 0xFF;
        let minor = encoded & 0xFF;
        Ok((major, minor))
    }
}

// ── helpers ──────────────────────────────────────────────────────────────

/// A fresh inode, `i_addr` all holes.
fn empty_inode(mode: u16) -> F2fsInode {
    F2fsInode {
        i_mode: mode,
        i_uid: 0,
        i_gid: 0,
        i_links: 1,
        i_size: 0,
        i_blocks: 0,
        i_atime: 0,
        i_ctime: 0,
        i_mtime: 0,
        i_atime_nsec: 0,
        i_ctime_nsec: 0,
        i_mtime_nsec: 0,
        i_xattr_nid: 0,
        i_flags: 0,
        i_addr: [F2FS_NULL_ADDR; F2FS_ADDRS_PER_INODE],
    }
}

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
pub(super) fn f2fs_ft_to_kind(ft: u8) -> NodeKind {
    match ft {
        F2FS_FT_DIR => NodeKind::Directory,
        F2FS_FT_REG_FILE => NodeKind::File,
        F2FS_FT_CHRDEV | F2FS_FT_BLKDEV => NodeKind::Device,
        F2FS_FT_SYMLINK => NodeKind::Symlink,
        _ => NodeKind::File,
    }
}
