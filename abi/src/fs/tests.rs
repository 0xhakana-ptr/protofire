//! abi/src/fs/tests.rs
//!
//! The filesystem wire format: the open flags, the descriptor stat, and the
//! directory record.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

use crate::fs::ACCESS_EXECUTE_BIT;
use crate::fs::ACCESS_QUERY_FLAG_ALLOWED;
use crate::fs::AccessQueryRecord;
use crate::fs::DirectoryEntryRecord;
use crate::fs::FileStat;
use crate::fs::PermissionMetadataRecord;

/// The record sizes `docs/kernel/user-runtime.md`
/// states, checked against the records themselves.
///
/// The document is where a reader looks for the wire sizes, and those
/// numbers are copies of facts these types own — two of them were wrong
/// (a mount record with the wrong arithmetic, a termination record missing
/// a field) until this test was written.  A number a document copies is a
/// number that can drift, so the copy is what is pinned here.
#[test]
fn documented_record_sizes_match_the_records() {
    use crate::fs::BlockDeviceInfoRecord;
    use crate::fs::MountInfoRecord;
    use crate::process::ProcessSignalRecord;
    use crate::process::ProcessSpawnOptions;
    use crate::process::ProcessSpawnStringRef;
    use crate::process::ProcessTerminationRecord;
    use core::mem::size_of;
    let actual = (
        size_of::<FileStat>(),
        size_of::<AccessQueryRecord>(),
        size_of::<PermissionMetadataRecord>(),
        size_of::<DirectoryEntryRecord>(),
        size_of::<MountInfoRecord>(),
        size_of::<BlockDeviceInfoRecord>(),
        size_of::<ProcessTerminationRecord>(),
        size_of::<ProcessSignalRecord>(),
        size_of::<ProcessSpawnOptions>(),
        size_of::<ProcessSpawnStringRef>(),
    );
    // The numbers as `docs/kernel/user-runtime.md`
    // states them, in the same order.
    let documented = (16usize, 8, 12, 32, 368, 88, 48, 24, 56, 16);
    assert_eq!(actual, documented);
}
use crate::fs::ACCESS_QUERY_FLAG_BYPASSES_DISCRETIONARY_PERMISSIONS;
use crate::fs::ACCESS_QUERY_FLAG_CAN_EXECUTE;
use crate::fs::ACCESS_QUERY_FLAG_CAN_READ;
use crate::fs::ACCESS_QUERY_FLAG_CAN_WRITE;
use crate::fs::ACCESS_QUERY_KNOWN_ACCESS_MASK;
use crate::fs::ACCESS_QUERY_RECORD_FLAGS_OFFSET;
use crate::fs::ACCESS_QUERY_RECORD_GRANTED_MODE_BITS_OFFSET;
use crate::fs::ACCESS_QUERY_RECORD_REQUIRED_ACCESS_OFFSET;
use crate::fs::ACCESS_QUERY_RECORD_SIZE;
use crate::fs::ACCESS_READ_BIT;
use crate::fs::ACCESS_WRITE_BIT;
use crate::fs::AT_FDCWD;
use crate::fs::DIRECTORY_ENTRY_RECORD_KIND_OFFSET;
use crate::fs::DIRECTORY_ENTRY_RECORD_NAME_LEN_OFFSET;
use crate::fs::DIRECTORY_ENTRY_RECORD_NAME_OFFSET_OFFSET;
use crate::fs::DIRECTORY_ENTRY_RECORD_SIZE;
use crate::fs::DIRECTORY_ENTRY_RECORD_SIZE_OFFSET;
use crate::fs::F_DUPFD;
use crate::fs::F_GETFD;
use crate::fs::F_GETFL;
use crate::fs::F_GETPIPE_SZ;
use crate::fs::F_SETFD;
use crate::fs::F_SETFL;
use crate::fs::F_SETPIPE_SZ;
use crate::fs::FD_CLOEXEC;
use crate::fs::FILE_KIND_DEVICE;
use crate::fs::FILE_KIND_DIRECTORY;
use crate::fs::FILE_KIND_FILE;
use crate::fs::FILE_KIND_UNKNOWN;
use crate::fs::FILE_STAT_KIND_OFFSET;
use crate::fs::FILE_STAT_SIZE;
use crate::fs::FILE_STAT_SIZE_OFFSET;
use crate::fs::O_NONBLOCK;
use crate::fs::PERMISSION_METADATA_RECORD_MODE_OFFSET;
use crate::fs::PERMISSION_METADATA_RECORD_OWNER_GID_OFFSET;
use crate::fs::PERMISSION_METADATA_RECORD_OWNER_UID_OFFSET;
use crate::fs::PERMISSION_METADATA_RECORD_RESERVED_OFFSET;
use crate::fs::PERMISSION_METADATA_RECORD_SIZE;

#[test]
fn file_kind_values_are_stable() {
    assert_eq!(FILE_KIND_UNKNOWN, 0);
    assert_eq!(FILE_KIND_DIRECTORY, 1);
    assert_eq!(FILE_KIND_FILE, 2);
    assert_eq!(FILE_KIND_DEVICE, 3);
}

#[test]
fn at_fdcwd_matches_compatibility_sentinel() {
    assert_eq!(AT_FDCWD, (-100_isize) as usize);
}

#[test]
fn access_query_bits_and_flags_are_stable() {
    assert_eq!(ACCESS_READ_BIT, 0b100);
    assert_eq!(ACCESS_WRITE_BIT, 0b010);
    assert_eq!(ACCESS_EXECUTE_BIT, 0b001);
    assert_eq!(ACCESS_QUERY_KNOWN_ACCESS_MASK, 0b111);
    assert_eq!(ACCESS_QUERY_FLAG_ALLOWED, 1);
    assert_eq!(ACCESS_QUERY_FLAG_CAN_READ, 2);
    assert_eq!(ACCESS_QUERY_FLAG_CAN_WRITE, 4);
    assert_eq!(ACCESS_QUERY_FLAG_CAN_EXECUTE, 8);
    assert_eq!(ACCESS_QUERY_FLAG_BYPASSES_DISCRETIONARY_PERMISSIONS, 16);
}

#[test]
fn file_stat_layout_matches_public_offsets() {
    let stat = FileStat::new(FILE_KIND_FILE, 42);
    assert_eq!(FILE_STAT_SIZE, core::mem::size_of::<FileStat>());
    assert_eq!(FILE_STAT_KIND_OFFSET, 0);
    assert_eq!(FILE_STAT_SIZE_OFFSET, core::mem::size_of::<usize>());
    assert_eq!(stat.kind, FILE_KIND_FILE);
    assert_eq!(stat.size, 42);
}

#[test]
fn access_query_record_layout_matches_public_offsets() {
    let record = AccessQueryRecord::new(
        ACCESS_READ_BIT | ACCESS_WRITE_BIT,
        ACCESS_READ_BIT,
        ACCESS_QUERY_FLAG_ALLOWED | ACCESS_QUERY_FLAG_CAN_READ,
    );
    assert_eq!(
        ACCESS_QUERY_RECORD_SIZE,
        core::mem::size_of::<AccessQueryRecord>()
    );
    assert_eq!(ACCESS_QUERY_RECORD_REQUIRED_ACCESS_OFFSET, 0);
    assert_eq!(
        ACCESS_QUERY_RECORD_GRANTED_MODE_BITS_OFFSET,
        core::mem::size_of::<u16>()
    );
    assert_eq!(
        ACCESS_QUERY_RECORD_FLAGS_OFFSET,
        core::mem::size_of::<u16>() * 2
    );
    assert_eq!(record.required_access, ACCESS_READ_BIT | ACCESS_WRITE_BIT);
    assert_eq!(record.granted_mode_bits, ACCESS_READ_BIT);
    assert_eq!(
        record.flags,
        ACCESS_QUERY_FLAG_ALLOWED | ACCESS_QUERY_FLAG_CAN_READ
    );
}

#[test]
fn permission_metadata_record_layout_matches_public_offsets() {
    let record = PermissionMetadataRecord::new(1000, 1001, 0o664);
    assert_eq!(
        PERMISSION_METADATA_RECORD_SIZE,
        core::mem::size_of::<PermissionMetadataRecord>()
    );
    assert_eq!(PERMISSION_METADATA_RECORD_OWNER_UID_OFFSET, 0);
    assert_eq!(
        PERMISSION_METADATA_RECORD_OWNER_GID_OFFSET,
        core::mem::size_of::<u32>()
    );
    assert_eq!(
        PERMISSION_METADATA_RECORD_MODE_OFFSET,
        core::mem::size_of::<u32>() * 2
    );
    assert_eq!(
        PERMISSION_METADATA_RECORD_RESERVED_OFFSET,
        PERMISSION_METADATA_RECORD_MODE_OFFSET + core::mem::size_of::<u16>()
    );
    assert_eq!(record.owner_uid, 1000);
    assert_eq!(record.owner_gid, 1001);
    assert_eq!(record.mode, 0o664);
    assert_eq!(record.reserved, 0);
}

#[test]
fn fcntl_command_values_are_stable() {
    assert_eq!(F_DUPFD, 0);
    assert_eq!(F_GETFD, 1);
    assert_eq!(F_SETFD, 2);
    assert_eq!(F_GETFL, 3);
    assert_eq!(F_SETFL, 4);
    assert_eq!(F_SETPIPE_SZ, 1031);
    assert_eq!(F_GETPIPE_SZ, 1032);
    assert_eq!(FD_CLOEXEC, 1);
    assert_eq!(O_NONBLOCK, 0o4000);
}

#[test]
fn directory_entry_record_defaults_name_payload_after_header() {
    let record = DirectoryEntryRecord::new(FILE_KIND_DIRECTORY, 3, 5);
    assert_eq!(
        DIRECTORY_ENTRY_RECORD_SIZE,
        core::mem::size_of::<DirectoryEntryRecord>()
    );
    assert_eq!(DIRECTORY_ENTRY_RECORD_KIND_OFFSET, 0);
    assert_eq!(
        DIRECTORY_ENTRY_RECORD_SIZE_OFFSET,
        core::mem::size_of::<usize>()
    );
    assert_eq!(
        DIRECTORY_ENTRY_RECORD_NAME_OFFSET_OFFSET,
        core::mem::size_of::<usize>() * 2
    );
    assert_eq!(
        DIRECTORY_ENTRY_RECORD_NAME_LEN_OFFSET,
        core::mem::size_of::<usize>() * 3
    );
    assert_eq!(record.name_offset, DIRECTORY_ENTRY_RECORD_SIZE);
    assert_eq!(record.name_len, 5);
    assert_eq!(record.size, 3);
}

/// The open flags keep their values, and the known set covers exactly them.
///
/// These cross the boundary: a program compiled against `1 << 1` asking for
/// write would be given read if this moved, and nothing would fail to
/// compile.  The known mask is asserted here because a flag added to the
/// list below without joining the mask is a flag every handler will refuse.
#[test]
fn open_flags_keep_their_values() {
    use crate::fs::OPEN_FLAG_CREATE;
    use crate::fs::OPEN_FLAG_NONE;
    use crate::fs::OPEN_FLAG_READ;
    use crate::fs::OPEN_FLAG_WRITE;
    use crate::fs::OPEN_KNOWN_FLAGS;
    assert_eq!(OPEN_FLAG_NONE, 0);
    assert_eq!(OPEN_FLAG_READ, 1);
    assert_eq!(OPEN_FLAG_WRITE, 2);
    assert_eq!(OPEN_FLAG_CREATE, 4);
    assert_eq!(OPEN_KNOWN_FLAGS, 7);
}

/// The fcntl numbers are the wire format and are pinned.
#[test]
fn fcntl_numbers_keep_their_values() {
    use crate::fs::F_DUPFD;
    use crate::fs::F_GETFD;
    use crate::fs::F_GETFL;
    use crate::fs::F_GETPIPE_SZ;
    use crate::fs::F_SETFD;
    use crate::fs::F_SETFL;
    use crate::fs::F_SETPIPE_SZ;
    assert_eq!(F_DUPFD, 0);
    assert_eq!(F_GETFD, 1);
    assert_eq!(F_SETFD, 2);
    assert_eq!(F_GETFL, 3);
    assert_eq!(F_SETFL, 4);
    assert_eq!(F_SETPIPE_SZ, 1031);
    assert_eq!(F_GETPIPE_SZ, 1032);
    assert_eq!(crate::fs::O_NONBLOCK, 0o4000);
}
