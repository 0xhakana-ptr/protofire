//! fs/src/mount/tests.rs
//!
//! The mount table: the longest prefix a path resolves against, and the mounts
//! that overlap.
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
/// not own `/database`, which a byte-prefix comparison would have claimed —
/// and claiming it means a file in one volume is answered by another.
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
/// filesystem, and the filesystem answers a path relative to its own root —
/// which it never learns.
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
