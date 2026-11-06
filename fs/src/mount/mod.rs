//! fs/src/mount/mod.rs
//!
//! The mount table: which filesystem answers for which path.
//!
//! ## What a mount is
//!
//! A mounted filesystem owns a *prefix* of the path namespace.  `/` is one
//! filesystem's root; `/data` is another's; a path is answered by the
//! filesystem whose prefix is the longest one that matches.  That rule is what
//! makes nested mounts work in the order a reader expects: with a volume at
//! `/` and another at `/data`, the path `/data/file` belongs to the second even
//! though the first would also have answered it.
//!
//! ## Why this is here and not in a filesystem
//!
//! It is the one piece of the namespace that every filesystem shares and none
//! of them owns.  A filesystem answers for paths *relative to its own root*, so
//! `PyroFs` sees `/greeting.txt` whether that file is at `/greeting.txt` or at
//! `/data/greeting.txt`, the table strips the prefix and the filesystem never
//! learns where it was mounted.
//!
//! ## What is not here
//!
//! Security, overlay and the zone layout.  The previous tree's mount layer had
//! all three, and they are decisions about *this* kernel's policy rather than
//! about what a mount table is: an overlay is two filesystems standing where
//! one was, and a zone is a partition of the boot disk.  They arrive with the
//! code that needs them.

use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::Error;
use abi::Result;

use crate::FileSystem;
use crate::path::normalize_path;
use crate::vnode::VNode;

/// One filesystem at one prefix.
struct MountPoint {
    /// Where this filesystem starts answering.
    path: String,
    /// What it calls itself.
    name: String,
    /// The device it was mounted from, for a boot line that names it.
    device: String,
    fs: Arc<dyn FileSystem>,
}

/// What a mount reports about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountInfo {
    pub path: String,
    pub fs_name: String,
    pub device: String,
}

/// The namespace: every mounted filesystem, by the prefix it owns.
pub struct MountTable {
    mounts: Vec<MountPoint>,
}

impl MountTable {
    /// An empty namespace.  Every lookup answers `NotFound` until something is
    /// mounted.
    pub fn new() -> Self {
        Self { mounts: Vec::new() }
    }

    /// Mount `fs` at `path`.
    ///
    /// The path is normalised first, so `/data/` and `/data` name the same
    /// mount point and a caller that spelled it either way gets one table
    /// entry rather than two.
    ///
    /// Mounting over an existing mount replaces it, which is what a boot that
    /// tried one volume and then a better one needs.  The replacement is
    /// reported rather than silent: a mount that quietly disappeared is a
    /// volume whose files are gone with nothing to point at.
    pub fn mount(
        &mut self,
        path: &str,
        name: &str,
        device: &str,
        fs: Arc<dyn FileSystem>,
    ) -> Result<bool> {
        let path = normalize_path(path, "/")?;
        let replaced = self.unmount(&path).is_ok();
        self.mounts.push(MountPoint {
            path,
            name: name.to_string(),
            device: device.to_string(),
            fs,
        });
        Ok(replaced)
    }

    /// Remove the mount at `path`, and answer whether there was one.
    pub fn unmount(&mut self, path: &str) -> Result<()> {
        let path = normalize_path(path, "/")?;
        let before = self.mounts.len();
        self.mounts.retain(|mount| mount.path != path);
        if self.mounts.len() == before {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    /// The filesystem that answers for `path`, and the path relative to its
    /// root.
    ///
    /// Longest prefix wins.  The match is on *components*, not on bytes: a
    /// volume at `/data` owns `/data/file` and does not own `/database`, which
    /// a prefix comparison would have claimed.
    pub fn resolve(&self, path: &str) -> Result<(Arc<dyn FileSystem>, String)> {
        let path = normalize_path(path, "/")?;
        let mount = self
            .mounts
            .iter()
            .filter(|mount| owns(&mount.path, &path))
            .max_by_key(|mount| mount.path.len())
            .ok_or(Error::NotFound)?;

        let relative = if mount.path == "/" {
            path
        } else if path.len() == mount.path.len() {
            "/".to_string()
        } else {
            path[mount.path.len()..].to_string()
        };

        Ok((mount.fs.clone(), relative))
    }

    /// Look a path up, answering the node it names.
    pub fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        let (fs, relative) = self.resolve(path)?;
        fs.lookup(&relative)
    }

    /// Every mount, in the order a boot line should name them.
    pub fn mounts(&self) -> Vec<MountInfo> {
        self.mounts
            .iter()
            .map(|mount| MountInfo {
                path: mount.path.clone(),
                fs_name: mount.name.clone(),
                device: mount.device.clone(),
            })
            .collect()
    }

    /// How many filesystems are mounted.
    pub fn len(&self) -> usize {
        self.mounts.len()
    }

    /// Whether nothing is mounted.
    pub fn is_empty(&self) -> bool {
        self.mounts.is_empty()
    }
}

impl Default for MountTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Whether a mount at `prefix` owns a path.
///
/// A component boundary, not a byte prefix: `/data` owns `/data` and
/// `/data/file`, and does not own `/database`.  The distinction is the whole
/// reason this is a function rather than a `starts_with`.
fn owns(prefix: &str, path: &str) -> bool {
    if prefix == "/" {
        return true;
    }
    if !path.starts_with(prefix) {
        return false;
    }
    matches!(path.as_bytes().get(prefix.len()), None | Some(b'/'))
}

/// A one-line summary of the namespace, for a boot that has to say what it
/// mounted.
///
/// A `String` rather than a write to the console: this crate does not own one,
/// and a caller that has a console formats this where it is convenient.
pub fn describe(table: &MountTable) -> String {
    let mounts = table.mounts();
    if mounts.is_empty() {
        return "nothing mounted".to_string();
    }
    let mut text = String::new();
    for (index, mount) in mounts.iter().enumerate() {
        if index > 0 {
            text.push_str(", ");
        }
        text.push_str(&format!(
            "{} on {} ({})",
            mount.fs_name, mount.path, mount.device
        ));
    }
    text
}

#[cfg(test)]
mod tests;
