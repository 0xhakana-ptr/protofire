//! fs/src/xfs/mod.rs
//!
//! XFS, read-only: the superblock's v4 and v5 generations, inode lookup
//! through the allocation-group addressing, directories in their shortform,
//! block, leaf and node formats, files through extents or inline, symlinks,
//! and the extended attributes an inode's attribute fork carries.
//!
//! ## Why this volume is read-only
//!
//! The write path a mutating filesystem needs, allocation, transaction,
//! journal commit, is the format's hardest third, and the read path this
//! module carries is complete without it: a read-only volume answers
//! lookups, listings, reads and xattrs, and its mutation half is fixed by
//! [`crate::filesystem::ReadOnlyFileSystem`]'s blanket implementation, so
//! there is nowhere to forget a refusal.
//!
//! ## What is not read
//!
//! Directories past the B+tree's node format (large dirs are read only
//! through their tree), files past the BMAP tree's depth bound, journal
//! replay on a read-only device, and the attribute fork's remote-value
//! entries.  Each says so at its dispatch.

pub(super) mod btree;
pub(super) mod fs;
pub(super) mod journal;
#[cfg(test)]
mod tests;
pub(super) mod types;

use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::BlockDevice;

use abi::Error;
use abi::Result;

use crate::types::DirectoryEntry;
use crate::types::Metadata;
use crate::types::NodeKind;
use crate::types::VolumeCheckReport;
use crate::types::XattrEntry;
use crate::vnode::VNode;

use types::Extent;
use types::InodeCore;
use types::Superblock;

/// An XFS volume, as the mount table holds one.
pub struct XfsVolume {
    device: Arc<dyn BlockDevice>,
    sb: Superblock,
}

impl XfsVolume {
    /// Open an XFS volume from a device: the superblock is read from the
    /// first sector and validated by its magic.
    pub fn open(device: Arc<dyn BlockDevice>) -> Result<Arc<Self>> {
        let sb = fs::read_superblock(&device)?;
        Ok(Arc::new(Self { device, sb }))
    }

    /// Resolve a path to its `(ino, core, inode buffer)` triple.
    fn resolve(&self, path: &str) -> Result<(u64, InodeCore, Vec<u8>)> {
        let clean = clean_xfs_path(path);
        if clean.is_empty() || clean == "/" {
            let ino = self.sb.root_ino;
            let (core, buf) = fs::read_inode_buf(&self.device, &self.sb, ino)?;
            return Ok((ino, core, buf));
        }

        let segments: Vec<&str> = clean
            .strip_prefix('/')
            .unwrap_or(&clean)
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();

        let mut current_ino = self.sb.root_ino;
        for name in &segments {
            let (dc, db) = fs::read_inode_buf(&self.device, &self.sb, current_ino)?;
            current_ino =
                fs::lookup_dir_entry_by_name(&self.device, &self.sb, &dc, &db, name.as_bytes())?
                    .ok_or(Error::NotFound)?;
        }

        let (core, buf) = fs::read_inode_buf(&self.device, &self.sb, current_ino)?;
        Ok((current_ino, core, buf))
    }

    /// The kind an inode's mode word names.
    fn kind_of(core: &InodeCore) -> NodeKind {
        if core.is_dir() {
            NodeKind::Directory
        } else if core.file_type() == 0o120000 {
            NodeKind::Symlink
        } else {
            NodeKind::File
        }
    }
}

impl crate::filesystem::FileSystem for XfsVolume {
    fn name(&self) -> &str {
        "xfs"
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        let clean = clean_xfs_path(path);
        let (ino, core, buf) = self.resolve(path)?;

        let name = if clean == "/" {
            "/".to_string()
        } else {
            extract_name(path)
        };

        Ok(Arc::new(XfsVNode {
            name,
            kind: Self::kind_of(&core),
            ino,
            size: core.size as usize,
            format: core.format,
            extents: fs::get_extents(&self.device, &self.sb, &core, &buf)?,
            buf,
            device: self.device.clone(),
            sb: self.sb.clone(),
        }))
    }

    fn stat(&self, path: &str) -> Result<Metadata> {
        let (_ino, core, _buf) = self.resolve(path)?;
        Ok(Metadata::new(Self::kind_of(&core), core.size as usize))
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        let clean = clean_xfs_path(path);
        let ino = if clean.is_empty() || clean == "/" {
            self.sb.root_ino
        } else {
            let mut cur = self.sb.root_ino;
            for name in &segments_of(&clean) {
                let (dc, db) = fs::read_inode_buf(&self.device, &self.sb, cur)?;
                cur = fs::lookup_dir_entry_by_name(
                    &self.device,
                    &self.sb,
                    &dc,
                    &db,
                    name.as_bytes(),
                )?
                .ok_or(Error::NotFound)?;
            }
            cur
        };

        let entries = fs::read_directory(&self.device, &self.sb, ino)?;
        let entry = entries.get(index).ok_or(Error::NotFound)?;

        let name = String::from_utf8_lossy(&entry.name).into_owned();
        let child_core = fs::read_inode_buf(&self.device, &self.sb, entry.inode)
            .map(|(c, _)| c)
            .unwrap_or_else(|_| InodeCore {
                mode: 0,
                version: 0,
                format: 0,
                attr_format: 0,
                uid: 0,
                gid: 0,
                nlink: 0,
                size: 0,
                num_extents: 0,
                attr_num_extents: 0,
                fork_offset: 0,
                is_v5: false,
            });

        Ok(DirectoryEntry::new(
            Self::kind_of(&child_core),
            child_core.size as usize,
            name,
        ))
    }

    fn list_xattrs(&self, path: &str) -> Result<Vec<XattrEntry>> {
        let (_ino, core, buf) = self.resolve(path)?;
        fs::list_xattrs_for_inode(
            &self.device,
            &self.sb,
            &core,
            &buf,
            self.sb.inode_size as usize,
        )
    }

    // Every mutation answers the same refusal, spelled here rather than
    // inherited: this driver is read-only, and the refusal is its own claim.
    fn rename(&self, _old_path: &str, _new_path: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn create_file(&self, _path: &str) -> Result<Arc<dyn VNode>> {
        Err(Error::PermissionDenied)
    }

    fn create_dir(&self, _path: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn create_symlink(&self, _target: &str, _link_path: &str) -> Result<Arc<dyn VNode>> {
        Err(Error::PermissionDenied)
    }

    fn create_device(&self, _path: &str, _major: u32, _minor: u32) -> Result<Arc<dyn VNode>> {
        Err(Error::PermissionDenied)
    }

    fn hard_link(&self, _target: &str, _link_path: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn remove_path(&self, _path: &str) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn update_security_descriptor(
        &self,
        _path: &str,
        _security: crate::types::SecurityDescriptor,
    ) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn check_and_repair(&self) -> Result<VolumeCheckReport> {
        // A dirty journal is the issue; the replay, when it applies, is the
        // repair.  On a read-only device the replay declines and the issue
        // stands reported.
        let dirty = fs::check_journal(&self.sb).is_dirty;
        let mut repairs_applied = 0;
        if dirty && journal::replay_xfs_journal(&self.device, &self.sb).unwrap_or(false) {
            repairs_applied = 1;
        }
        Ok(VolumeCheckReport {
            issues_detected: usize::from(dirty),
            repairs_applied,
            orphan_data_blocks: 0,
            checksum_failures: 0,
            staging_orphans_cleaned: 0,
            orphan_blocks_cleaned: 0,
            interrupted_commits: usize::from(dirty),
        })
    }
}

/// A VFS node backed by an XFS inode.
struct XfsVNode {
    name: String,
    kind: NodeKind,
    /// The inode number the node was resolved to, for a reader that wants
    /// to re-read it; the read paths carry their own buffers.
    #[allow(dead_code)]
    ino: u64,
    size: usize,
    format: u8,
    extents: Vec<Extent>,
    buf: Vec<u8>,
    device: Arc<dyn BlockDevice>,
    sb: Superblock,
}

impl VNode for XfsVNode {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> NodeKind {
        self.kind
    }

    fn size(&self) -> usize {
        self.size
    }

    fn metadata(&self) -> Result<Metadata> {
        Ok(Metadata::new(self.kind, self.size))
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        if self.kind != NodeKind::File {
            return Err(Error::InvalidArgument);
        }
        if self.format == types::XFS_DINODE_FMT_LOCAL {
            fs::read_inline_file(
                &InodeCore {
                    mode: 0,
                    version: 0,
                    format: self.format,
                    attr_format: 0,
                    uid: 0,
                    gid: 0,
                    nlink: 0,
                    size: self.size as u64,
                    num_extents: 0,
                    attr_num_extents: 0,
                    fork_offset: 0,
                    is_v5: false,
                },
                &self.buf,
                offset,
                buffer,
            )
        } else {
            fs::read_file(
                &self.device,
                &self.sb,
                &self.extents,
                self.size as u64,
                offset,
                buffer,
            )
        }
    }

    fn readlink(&self) -> Result<Vec<u8>> {
        if self.format == types::XFS_DINODE_FMT_LOCAL {
            // The target rides inline in the data fork, from its start to
            // the target's own length.
            let start = self.sb.inode_data_offset();
            let data = self.buf.get(start..).unwrap_or(&[]);
            let len = self.size.min(data.len());
            Ok(data[..len].to_vec())
        } else {
            // A long symlink's target is extent-mapped like any file.
            let mut target = alloc::vec![0u8; self.size.min(4096)];
            fs::read_file(
                &self.device,
                &self.sb,
                &self.extents,
                self.size as u64,
                0,
                &mut target,
            )?;
            Ok(target)
        }
    }
}

// helpers

/// A path's segments, cleaned.
fn segments_of(clean: &str) -> Vec<&str> {
    clean
        .strip_prefix('/')
        .unwrap_or(clean)
        .split('/')
        .filter(|s| !s.is_empty())
        .collect()
}

/// A path normalized to its clean absolute form.
fn clean_xfs_path(path: &str) -> String {
    if path.is_empty() || path == "/" {
        return "/".into();
    }
    let mut out = String::with_capacity(path.len());
    for seg in path.split('/').filter(|s| !s.is_empty()) {
        out.push('/');
        out.push_str(seg);
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

/// The leaf (final component) of a path.
fn extract_name(path: &str) -> String {
    let clean = clean_xfs_path(path);
    if clean == "/" {
        return "/".into();
    }
    clean
        .rsplit('/')
        .find(|s| !s.is_empty())
        .unwrap_or("/")
        .into()
}
