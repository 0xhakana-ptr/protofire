//! fs/src/lib.rs
//!
//! The filesystem interface: what a node is, what metadata it carries, and the
//! two traits a filesystem implements.
//!
//! ## What is here, and why
//!
//! `VNode` and `FileSystem` are the contract every filesystem in this tree is
//! written against, and they are what `pipe`'s endpoints implement so that a
//! pipe is a file.  Neither names a filesystem, a device or a scheduler, the
//! first because it is the interface, the second because the trait's whole
//! purpose is to be implemented by something that does.
//!
//! The types beside them, `Metadata`, `NodeKind`, `DirectoryEntry`,
//! `XattrEntry`, are the vocabulary the contract is stated in.
//!
//! ## What is not here yet
//!
//! The mount table, the path walk and the handle table.  Those are the
//! *implementation* of a filesystem namespace rather than its interface, and
//! they arrive with the first filesystem that needs them.  The split matters
//! for the same reason `ipc`'s ring does: a contract can be tested with a
//! twenty-line mock, which the tests here do, while an implementation needs a
//! device.
//!
//! ## What this crate names
//!
//! `abi` for the wire format and the error type, `security` for the token a
//! metadata record carries.  Not `sync`: nothing here is shared mutable state.
//! Not `arch`: a filesystem does not know what a page is.

#![no_std]

extern crate alloc;
// The host tests — the NTFS harness's own, which drive the driver against a
// volume mkntfs makes — read files and environment from the host, and the
// kernel target compiles none of this.
#[cfg(not(target_os = "none"))]
extern crate std;

pub mod block_cache;
pub mod exfat;
pub mod ext4;
pub mod f2fs;
pub mod fat32;
pub mod filesystem;
pub mod iso9660;
pub mod mount;
pub mod ntfs;
pub mod path;
pub mod profiler;
pub mod pyrofs;
pub mod stats;
pub mod tmpfs;
pub mod types;
pub mod vnode;
pub mod xfs;

// Everything the type module publishes, because the contract's vocabulary is
// its whole surface and a reader of `VNode` needs all of it.  Enumerating the
// names here would be a second list to keep in step with the first, and the
// first version of this file left `SecurityDescriptor` out of it, which the
// tests caught, and which is the reason the re-export is a glob.
pub use filesystem::*;
pub use mount::MountInfo;
pub use mount::MountTable;
pub use profiler::FsProfiler;
pub use profiler::FsProfilerSnapshot;
pub use stats::CacheStats;
pub use tmpfs::TmpFsVolume;
pub use types::*;
pub use vnode::VNode;

#[cfg(test)]
mod vfs_tests;
