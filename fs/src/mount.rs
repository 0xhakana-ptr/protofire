//! fs/src/mount.rs
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
//! Security, overlay and the zone layout.  All three are decisions about
//! *this* kernel's policy rather than about what a mount table is: an overlay
//! is two filesystems standing where one was, and a zone is a partition of the
//! boot disk.  They arrive with the code that needs them.

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

    /// Flush every mounted filesystem to its device, answering how many were
    /// asked.
    ///
    /// What `Sync` is: the explicit half of durability, where a descriptor's
    /// `Fsync` is the per-file half.  Each entry point is the filesystem's own
    /// `sync`, which for a volume with a block cache is "write the dirty blocks
    /// and flush the device" and for the tmpfs is nothing, because its bytes
    /// are the only copy there is.
    ///
    /// A filesystem that refuses does not stop the others: the answer is the
    /// first error, and the count is of the ones that were asked.  Stopping at
    /// the first failure would leave the rest dirty for a reason a caller
    /// cannot see, and "one of them refused" is the fact that matters.
    ///
    /// The answer is a `Result` of the count rather than of `()` because a
    /// caller wants both: whether everything flushed, and how many there were.
    pub fn sync_all(&self) -> abi::Result<usize> {
        let mut asked = 0;
        let mut first_error = None;
        for mount in &self.mounts {
            asked += 1;
            if let Err(error) = mount.fs.sync() {
                first_error.get_or_insert(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(asked),
        }
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
mod tests {
    //! The tests for this module.
    //!
    //! The mount table: the longest prefix a path resolves against, and the
    //! mounts that overlap.
    //!
    //! Extracted from the module so that a reader following the mechanism does
    //! not have to scroll past every case it has to satisfy; see
    //! `docs/fmts/testing.md` §1.

    use crate::StaticFileSystem;
    use crate::mount::MountTable;
    use crate::mount::owns;
    use crate::types::NodeKind;
    use alloc::string::ToString;
    use alloc::sync::Arc;

    fn volume(name: &'static str, file: &'static str) -> Arc<StaticFileSystem> {
        Arc::new(StaticFileSystem::with_entries(
            name,
            &[(file, NodeKind::File, b"contents")],
        ))
    }

    /// A mount owns paths below it, and the root owns everything.
    ///
    /// The component boundary is the point: `/data` owns `/data/file` and does
    /// not own `/database`, which a byte-prefix comparison would have claimed,
    /// /// and claiming it means a file in one volume is answered by another.
    #[test]
    fn a_mount_owns_paths_below_it_and_not_its_siblings() {
        assert!(owns("/", "/anything"));
        assert!(owns("/data", "/data"));
        assert!(owns("/data", "/data/file"));
        assert!(!owns("/data", "/database"));
        assert!(!owns("/data", "/"));
        assert!(!owns("/data", "/dat"));
    }

    /// A path is answered by the filesystem whose prefix is longest.
    ///
    /// This is what makes a nested mount work: `/data/file` belongs to the
    /// volume at `/data` even though the root volume would also have answered.
    #[test]
    fn the_longest_prefix_wins() {
        let mut table = MountTable::new();
        table
            .mount("/", "root-fs", "root-dev", volume("root-fs", "/root.txt"))
            .expect("mount root");
        table
            .mount(
                "/data",
                "data-fs",
                "data-dev",
                volume("data-fs", "/file.txt"),
            )
            .expect("mount data");

        let (fs, relative) = table.resolve("/data/file.txt").expect("resolve");
        assert_eq!(fs.name(), "data-fs");
        assert_eq!(relative, "/file.txt");

        let (fs, relative) = table.resolve("/root.txt").expect("resolve");
        assert_eq!(fs.name(), "root-fs");
        assert_eq!(relative, "/root.txt");
    }

    /// The mount point itself resolves to the mounted filesystem's root.
    #[test]
    fn the_mount_point_resolves_to_its_own_root() {
        let mut table = MountTable::new();
        table
            .mount(
                "/data",
                "data-fs",
                "data-dev",
                volume("data-fs", "/file.txt"),
            )
            .expect("mount");
        let (_, relative) = table.resolve("/data").expect("resolve");
        assert_eq!(relative, "/");
    }

    /// A lookup through the table reaches the file the volume holds.
    ///
    /// The end-to-end shape: a path names a mount, the mount names a
    /// filesystem, and the filesystem answers a path relative to its own root,
    /// /// which it never learns.
    #[test]
    fn a_lookup_reaches_the_file_the_volume_holds() {
        let mut table = MountTable::new();
        table
            .mount(
                "/data",
                "data-fs",
                "data-dev",
                volume("data-fs", "/file.txt"),
            )
            .expect("mount");

        let node = table.lookup("/data/file.txt").expect("lookup");
        assert_eq!(node.name(), "file.txt");
        assert_eq!(node.size(), 8);
    }

    /// Any path with nothing mounted at or above it answers `NotFound`.
    #[test]
    fn an_unmounted_path_is_not_found() {
        let table = MountTable::new();
        assert_eq!(table.resolve("/anything").err(), Some(abi::Error::NotFound));
    }

    /// A second mount at one path replaces the first, and says so.
    #[test]
    fn mounting_twice_replaces_and_reports_it() {
        let mut table = MountTable::new();
        assert!(
            !table
                .mount("/", "first", "dev-a", volume("first", "/a.txt"))
                .expect("first"),
            "the first mount replaced nothing"
        );
        assert!(
            table
                .mount("/", "second", "dev-b", volume("second", "/b.txt"))
                .expect("second"),
            "the second mount replaced the first, and says so"
        );
        assert_eq!(table.len(), 1);
        assert_eq!(table.mounts()[0].fs_name, "second");
    }

    /// A path with a trailing slash names the same mount as one without.
    ///
    /// The normalization is what keeps a table with one entry out of having
    /// two, and it is why `mount` normalizes before it compares.
    #[test]
    fn a_trailing_slash_names_the_same_mount() {
        let mut table = MountTable::new();
        table
            .mount(
                "/data/",
                "data-fs",
                "data-dev",
                volume("data-fs", "/file.txt"),
            )
            .expect("mount");
        assert_eq!(table.len(), 1);
        assert!(table.resolve("/data/file.txt").is_ok());
    }

    /// Unmounting a path that has no mount answers `NotFound` rather than
    /// succeeding at nothing.
    #[test]
    fn unmounting_nothing_is_not_found() {
        let mut table = MountTable::new();
        assert_eq!(table.unmount("/nothing").err(), Some(abi::Error::NotFound));
    }

    /// The description names every mount, and a caller with a console prints
    /// it without the crate owning one.
    #[test]
    fn the_description_names_the_namespace() {
        let mut table = MountTable::new();
        assert_eq!(crate::mount::describe(&table), "nothing mounted");
        table
            .mount("/", "root-fs", "root-dev", volume("root-fs", "/a.txt"))
            .expect("mount");
        table
            .mount("/data", "data-fs", "data-dev", volume("data-fs", "/b.txt"))
            .expect("mount");
        let text = crate::mount::describe(&table);
        assert!(text.contains("root-fs on / (root-dev)"));
        assert!(text.contains("data-fs on /data (data-dev)"));
    }

    /// `to_string` on a mount path is the path, so a caller can name one.
    #[test]
    fn a_mount_info_path_is_the_normalized_one() {
        let mut table = MountTable::new();
        table
            .mount("/data/./sub", "fs", "dev", volume("fs", "/x"))
            .expect("mount");
        assert_eq!(table.mounts()[0].path.to_string(), "/data/sub");
    }
}
