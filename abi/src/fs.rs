//! abi/src/fs.rs
//!
//! Shared filesystem ABI records, file kinds, and directory entry layouts.

use core::mem::offset_of;
use core::mem::size_of;

// These numeric tags cross the kernel/user boundary and therefore must remain
// stable.
pub const FILE_KIND_UNKNOWN: usize = 0;
pub const FILE_KIND_DIRECTORY: usize = 1;
pub const FILE_KIND_FILE: usize = 2;
pub const FILE_KIND_DEVICE: usize = 3;
pub const FILE_KIND_SYMLINK: usize = 4;
// Match the conventional "use current working directory as dirfd base"
// sentinel.
pub const AT_FDCWD: usize = (-100_isize) as usize;
pub const ACCESS_READ_BIT: u16 = 0b100;
pub const ACCESS_WRITE_BIT: u16 = 0b010;
pub const ACCESS_EXECUTE_BIT: u16 = 0b001;
pub const ACCESS_QUERY_KNOWN_ACCESS_MASK: u16 =
    ACCESS_READ_BIT | ACCESS_WRITE_BIT | ACCESS_EXECUTE_BIT;
pub const ACCESS_QUERY_FLAG_ALLOWED: u32 = 1 << 0;
pub const ACCESS_QUERY_FLAG_CAN_READ: u32 = 1 << 1;
pub const ACCESS_QUERY_FLAG_CAN_WRITE: u32 = 1 << 2;
pub const ACCESS_QUERY_FLAG_CAN_EXECUTE: u32 = 1 << 3;
pub const ACCESS_QUERY_FLAG_BYPASSES_DISCRETIONARY_PERMISSIONS: u32 = 1 << 4;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Fixed-size metadata record returned by `stat`.
pub struct FileStat {
    pub kind: usize,
    pub size: usize,
}

impl FileStat {
    pub const fn new(kind: usize, size: usize) -> Self {
        Self { kind, size }
    }
}

pub const FILE_STAT_SIZE: usize = size_of::<FileStat>();
pub const FILE_STAT_KIND_OFFSET: usize = offset_of!(FileStat, kind);
pub const FILE_STAT_SIZE_OFFSET: usize = offset_of!(FileStat, size);

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Fixed-size effective-access record returned by `access_query`.
pub struct AccessQueryRecord {
    pub required_access: u16,
    pub granted_mode_bits: u16,
    pub flags: u32,
}

impl AccessQueryRecord {
    pub const fn new(required_access: u16, granted_mode_bits: u16, flags: u32) -> Self {
        Self {
            required_access,
            granted_mode_bits,
            flags,
        }
    }
}

pub const ACCESS_QUERY_RECORD_SIZE: usize = size_of::<AccessQueryRecord>();
pub const ACCESS_QUERY_RECORD_REQUIRED_ACCESS_OFFSET: usize =
    offset_of!(AccessQueryRecord, required_access);
pub const ACCESS_QUERY_RECORD_GRANTED_MODE_BITS_OFFSET: usize =
    offset_of!(AccessQueryRecord, granted_mode_bits);
pub const ACCESS_QUERY_RECORD_FLAGS_OFFSET: usize = offset_of!(AccessQueryRecord, flags);

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Fixed-size ownership/mode record returned by `permission_metadata`.
pub struct PermissionMetadataRecord {
    pub owner_uid: u32,
    pub owner_gid: u32,
    pub mode: u16,
    pub reserved: u16,
}

impl PermissionMetadataRecord {
    pub const fn new(owner_uid: u32, owner_gid: u32, mode: u16) -> Self {
        Self {
            owner_uid,
            owner_gid,
            mode,
            reserved: 0,
        }
    }
}

pub const PERMISSION_METADATA_RECORD_SIZE: usize = size_of::<PermissionMetadataRecord>();
pub const PERMISSION_METADATA_RECORD_OWNER_UID_OFFSET: usize =
    offset_of!(PermissionMetadataRecord, owner_uid);
pub const PERMISSION_METADATA_RECORD_OWNER_GID_OFFSET: usize =
    offset_of!(PermissionMetadataRecord, owner_gid);
pub const PERMISSION_METADATA_RECORD_MODE_OFFSET: usize =
    offset_of!(PermissionMetadataRecord, mode);
pub const PERMISSION_METADATA_RECORD_RESERVED_OFFSET: usize =
    offset_of!(PermissionMetadataRecord, reserved);

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Fixed-size header written at the start of a `read_dir` output buffer.
///
/// The entry name bytes follow immediately after the header at `name_offset`
/// and occupy `name_len` UTF-8 bytes without a trailing NUL.
pub struct DirectoryEntryRecord {
    pub kind: usize,
    pub size: usize,
    pub name_offset: usize,
    pub name_len: usize,
}

impl DirectoryEntryRecord {
    pub const fn new(kind: usize, size: usize, name_len: usize) -> Self {
        Self {
            kind,
            size,
            // The variable-length UTF-8 name bytes are packed immediately after
            // the header.
            name_offset: DIRECTORY_ENTRY_RECORD_SIZE,
            name_len,
        }
    }
}

pub const DIRECTORY_ENTRY_RECORD_SIZE: usize = size_of::<DirectoryEntryRecord>();
pub const DIRECTORY_ENTRY_RECORD_KIND_OFFSET: usize = offset_of!(DirectoryEntryRecord, kind);
pub const DIRECTORY_ENTRY_RECORD_SIZE_OFFSET: usize = offset_of!(DirectoryEntryRecord, size);
pub const DIRECTORY_ENTRY_RECORD_NAME_OFFSET_OFFSET: usize =
    offset_of!(DirectoryEntryRecord, name_offset);
pub const DIRECTORY_ENTRY_RECORD_NAME_LEN_OFFSET: usize =
    offset_of!(DirectoryEntryRecord, name_len);

// Extended attribute (xattr) limits

/// Maximum byte length of an xattr name.
pub const XATTR_NAME_MAX: usize = 64;
/// Maximum byte length of an xattr value.
pub const XATTR_VALUE_MAX: usize = 256;

// Open flags
//
// A program passes one of these as `open`'s second argument and the kernel
// decodes them; the numbers are the wire format, so a program compiled against
// different ones would ask for an access mode it did not get.

/// Open for reading only, which is what a caller that names no flag gets.
pub const OPEN_FLAG_NONE: usize = 0;
/// Open for reading.
pub const OPEN_FLAG_READ: usize = 1 << 0;
/// Open for writing.
pub const OPEN_FLAG_WRITE: usize = 1 << 1;
/// Create the file if it does not exist.
pub const OPEN_FLAG_CREATE: usize = 1 << 2;
/// The flags this build understands.
///
/// A handler validates against this set rather than masking the unknown bits
/// off: a caller asking for a flag a newer ABI defines should be told this
/// kernel does not have it, not silently given the behaviour it did not ask
/// for.
pub const OPEN_KNOWN_FLAGS: usize = OPEN_FLAG_READ | OPEN_FLAG_WRITE | OPEN_FLAG_CREATE;

// fcntl command constants
//
// These are wire values: a program's headers carry them, and the kernel serves
// them by number.  Their numbers are therefore pinned by the ABI tests rather
// than chosen here, which is the same reason every other number in this crate
// is written with its value spelled out.

/// Duplicate `fd` to the lowest free descriptor `>= arg`.
pub const F_DUPFD: usize = 0;
/// Return the per-fd flags (see [`FD_CLOEXEC`]).
pub const F_GETFD: usize = 1;
/// Set the per-fd flags to `arg` (bitmask of [`FD_CLOEXEC`]).
pub const F_SETFD: usize = 2;
/// Return the open file status flags (access mode | [`O_NONBLOCK`]).
pub const F_GETFL: usize = 3;
/// Set the open file status flags.  Only [`O_NONBLOCK`] is settable.
pub const F_SETFL: usize = 4;
/// Grow/shrink the pipe buffer to `arg` bytes (rounded, clamped).
pub const F_SETPIPE_SZ: usize = 1031;
/// Return the current pipe buffer capacity in bytes.
pub const F_GETPIPE_SZ: usize = 1032;

/// Close-on-exec per-fd flag (bit 0 of the [`F_GETFD`]/[`F_SETFD`] value).
pub const FD_CLOEXEC: usize = 1;

/// Non-blocking I/O status flag.
///
/// `0o4000`, and the value is the wire format's: a program compiled against a
/// different bit would have its `F_SETFL` silently do nothing.
pub const O_NONBLOCK: usize = 0o4000;

// fallocate modes

/// The range reads as zeros, and the clusters behind it go back to the volume.
pub const FALLOC_FL_PUNCH_HOLE: usize = 0x02;
/// The length of the file does not change.
pub const FALLOC_FL_KEEP_SIZE: usize = 0x01;

// lseek whence values

/// The offset is absolute.
pub const SEEK_SET: usize = 0;
/// The offset is taken from the current position.
pub const SEEK_CUR: usize = 1;
/// The offset is taken from the end of the file.
pub const SEEK_END: usize = 2;
/// The offset is absolute, and the answer is the first byte of **data** at or
/// after it; `NotFound` when there is none.
///
/// The two extents a file is made of are [RFC 0017](../../docs/rfcs/
/// 0017-ask-a-file-where-its-holes-are.md)'s: a hole is a range that reads as
/// zeros and is not held, and the end of a file is a hole.
pub const SEEK_DATA: usize = 3;
/// The offset is absolute, and the answer is the first byte of a **hole** at
/// or after it.
pub const SEEK_HOLE: usize = 4;

// File flags (SetFileFlags / GetFileFlags)

/// Per-file transparent compression (SimpleFs V4+).
pub const FILE_FLAG_COMPRESSED: u32 = 1 << 0;
/// Per-file dedup-pool membership (informational; SimpleFs V4+).
pub const FILE_FLAG_DEDUPED: u32 = 1 << 1;
/// All known file flags.
pub const FILE_FLAG_KNOWN_MASK: u32 = FILE_FLAG_COMPRESSED | FILE_FLAG_DEDUPED;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Fixed-size file-flags record returned by `get_file_flags`.
pub struct FileFlagsRecord {
    pub flags: u32,
}

impl FileFlagsRecord {
    pub const fn new(flags: u32) -> Self {
        Self { flags }
    }
}

pub const FILE_FLAGS_RECORD_SIZE: usize = size_of::<FileFlagsRecord>();
pub const FILE_FLAGS_RECORD_FLAGS_OFFSET: usize = offset_of!(FileFlagsRecord, flags);

// Security descriptor update flags

/// Update file mode bits.
pub const SECURITY_DESCRIPTOR_UPDATE_MODE: usize = 1 << 0;
/// Update owner UID.
pub const SECURITY_DESCRIPTOR_UPDATE_OWNER_UID: usize = 1 << 1;
/// Update owner GID.
pub const SECURITY_DESCRIPTOR_UPDATE_OWNER_GID: usize = 1 << 2;
/// All known security descriptor update flags.
pub const SECURITY_DESCRIPTOR_UPDATE_KNOWN_FLAGS: usize = SECURITY_DESCRIPTOR_UPDATE_MODE
    | SECURITY_DESCRIPTOR_UPDATE_OWNER_UID
    | SECURITY_DESCRIPTOR_UPDATE_OWNER_GID;

// Mount / block-device enumeration constants

/// Maximum length of a block device name (not including NUL terminator).
pub const BLOCK_DEVICE_NAME_MAX: usize = 63;
/// Maximum length of a mount-source device string.
pub const MOUNT_DEVICE_MAX: usize = 63;
/// Maximum length of a filesystem-type name string.
pub const MOUNT_FS_NAME_MAX: usize = 31;
/// Maximum length of a mount-point path.
pub const MOUNT_PATH_MAX: usize = 255;

// Mount / block-device enumeration records

#[repr(C)]
#[derive(Debug, Clone, Copy)]
/// Fixed-size block device info record.
pub struct BlockDeviceInfoRecord {
    /// NUL-terminated UTF-8 device name.
    pub name: [u8; BLOCK_DEVICE_NAME_MAX],
    /// Block size in bytes.
    pub block_size: u64,
    /// Total number of blocks.
    pub block_count: u64,
    /// Non-zero if the device is read-only.
    pub read_only: u64,
}

impl Default for BlockDeviceInfoRecord {
    fn default() -> Self {
        Self {
            name: [0u8; BLOCK_DEVICE_NAME_MAX],
            block_size: 0,
            block_count: 0,
            read_only: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
/// Fixed-size mount info record.
pub struct MountInfoRecord {
    /// NUL-terminated UTF-8 mount-point path.
    pub path: [u8; MOUNT_PATH_MAX],
    /// NUL-terminated UTF-8 filesystem type name.
    pub fs_name: [u8; MOUNT_FS_NAME_MAX],
    /// NUL-terminated UTF-8 device.
    pub device: [u8; MOUNT_DEVICE_MAX],
    /// Mount flags.
    pub flags: u64,
    /// Reserved for alignment.
    pub reserved: u64,
}

impl Default for MountInfoRecord {
    fn default() -> Self {
        Self {
            path: [0u8; MOUNT_PATH_MAX],
            fs_name: [0u8; MOUNT_FS_NAME_MAX],
            device: [0u8; MOUNT_DEVICE_MAX],
            flags: 0,
            reserved: 0,
        }
    }
}

#[cfg(test)]
mod tests;
