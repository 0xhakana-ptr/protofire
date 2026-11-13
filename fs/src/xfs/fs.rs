//! fs/src/xfs/fs.rs
//!
//! XFS's low-level operations: the superblock's read and validation, the
//! AG-relative inode addressing, directory reading and name lookup, the
//! extent and file reading, and the attribute listing.
//!
//! ## The addressing
//!
//! An inode number names its allocation group in the upper bits and its
//! position within the group below — which is why the volume's geometry is
//! the superblock's to give, and every read goes through
//! [`inode_addr`] rather than an offset a caller computed.

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use block::BlockDevice;

use abi::Error;
use abi::Result;

use crate::types::XattrEntry;

use super::btree::lookup_leaf_dir_by_hash;
use super::btree::lookup_node_dir_by_hash;
use super::btree::parse_leaf_dir;
use super::btree::read_device_bytes;
use super::btree::read_extent_btree;
use super::btree::read_node_dir_entries;
use super::btree::xfs_dir_hash;
use super::types::DirEntry;
use super::types::Extent;
use super::types::InodeCore;
use super::types::JournalInfo;
use super::types::Superblock;
use super::types::XFS_DA_NODE_MAGIC;
use super::types::XFS_DINODE_FMT_BTREE;
use super::types::XFS_DINODE_FMT_EXTENTS;
use super::types::XFS_DINODE_FMT_LOCAL;
use super::types::XFS_DIR2_LEAF1_MAGIC;
use super::types::XFS_DIR2_LEAFN_MAGIC;
use super::types::parse_block_dir;
use super::types::parse_extents;
use super::types::parse_shortform_dir;

// ── the superblock ───────────────────────────────────────────────────────

/// Read and validate the superblock from the device's first sector.
pub(super) fn read_superblock(device: &Arc<dyn BlockDevice>) -> Result<Superblock> {
    let mut buf = vec![0u8; 512];
    read_device_bytes(device, 0, &mut buf)?;
    Superblock::parse(&buf).ok_or(Error::InvalidArgument)
}

/// The journal's own facts, as the superblock states them: whether the
/// volume carries one, and whether an unclean unmount left it dirty.
///
/// The dirty check is the format's own convention — v4's clean-unmount
/// flag in `features_log` bit 0, v5's log incompat bit — read rather than
/// guessed, because replaying a clean journal would be recovery the
/// volume never asked for.
pub(super) fn check_journal(sb: &Superblock) -> JournalInfo {
    let has_journal = sb.log_blocks > 0 && sb.log_start != 0;

    let is_v5 = sb.versionnum & 0x0008 != 0;
    let log_version = if is_v5 {
        (sb.features_log & 0xF) as u8
    } else {
        ((sb.features2 >> 16) & 0xF) as u8
    };

    let is_dirty = if !has_journal {
        false
    } else if is_v5 {
        sb.features_incompat & 1 != 0 && sb.features_log & 0x2 == 0
    } else {
        log_version >= 2 && sb.features_log & 0x1 == 0
    };

    JournalInfo {
        has_journal,
        is_dirty,
        log_start: sb.log_start,
        log_blocks: sb.log_blocks,
        log_version,
    }
}

// ── inode addressing and reading ─────────────────────────────────────────

/// The byte offset of an inode on disk: the allocation group from the
/// number's upper bits, the position within the group from the lower.
pub(super) fn inode_addr(sb: &Superblock, ino: u64) -> (u64, u32) {
    let ag = ino >> 32;
    let rel = ino & 0xFFFF_FFFF;
    let ag_start = ag * sb.blocks_per_ag as u64;
    if sb.inode_size == 0 || sb.block_size == 0 {
        return (0, rel as u32);
    }
    let inodes_per_block = sb.block_size as u64 / sb.inode_size as u64;
    if inodes_per_block == 0 {
        return (0, rel as u32);
    }
    let block_off = ag_start + rel / inodes_per_block;
    let offset_in_block = (rel % inodes_per_block) * sb.inode_size as u64;
    let byte_off = block_off * sb.block_size as u64 + offset_in_block;
    (byte_off, rel as u32)
}

/// Read an inode's raw buffer and its parsed core.
pub(super) fn read_inode_buf(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    ino: u64,
) -> Result<(InodeCore, Vec<u8>)> {
    let (byte_off, _rel) = inode_addr(sb, ino);
    let inode_size = sb.inode_size as usize;
    let mut buf = vec![0u8; inode_size];
    read_device_bytes(device, byte_off, &mut buf)?;
    let core = InodeCore::parse(&buf, inode_size).ok_or(Error::InvalidArgument)?;
    Ok((core, buf))
}

// ── directories ──────────────────────────────────────────────────────────

/// Read a directory's entries from its inode, dispatching on the data
/// fork's format: shortform inline, extent-mapped blocks, or a B+tree.
pub(super) fn read_dir_from_inode(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    core: &InodeCore,
    buf: &[u8],
) -> Result<Vec<DirEntry>> {
    let data_fork_off = sb.inode_data_offset();
    match core.format {
        XFS_DINODE_FMT_LOCAL => Ok(parse_shortform_dir(buf, data_fork_off)),
        XFS_DINODE_FMT_EXTENTS => {
            let extents = parse_extents(buf, data_fork_off, core.num_extents);
            read_block_dir_entries(device, sb, &extents, core.size)
        }
        XFS_DINODE_FMT_BTREE => {
            let extents = read_extent_btree(device, sb, buf, data_fork_off)?;
            read_block_dir_entries(device, sb, &extents, core.size)
        }
        _ => Err(Error::InvalidArgument),
    }
}

/// Read a whole directory, from the inode the number names.
pub(super) fn read_directory(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    ino: u64,
) -> Result<Vec<DirEntry>> {
    let (core, buf) = read_inode_buf(device, sb, ino)?;
    read_dir_from_inode(device, sb, &core, &buf)
}

/// Look up one name in a directory by the hash index where the format
/// carries one — leaf and node formats binary-search; shortform and
/// block-format directories fall back to the linear scan, which is equally
/// fast for the sizes those formats exist at.
///
/// `Ok(Some(ino))` answers the match, `Ok(None)` the miss.
pub(super) fn lookup_dir_entry_by_name(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    core: &InodeCore,
    buf: &[u8],
    name: &[u8],
) -> Result<Option<u64>> {
    let data_fork_off = sb.inode_data_offset();
    match core.format {
        XFS_DINODE_FMT_LOCAL => {
            let entries = parse_shortform_dir(buf, data_fork_off);
            Ok(entries.iter().find(|e| e.name == name).map(|e| e.inode))
        }
        XFS_DINODE_FMT_EXTENTS | XFS_DINODE_FMT_BTREE => {
            let extents = match core.format {
                XFS_DINODE_FMT_EXTENTS => parse_extents(buf, data_fork_off, core.num_extents),
                XFS_DINODE_FMT_BTREE => read_extent_btree(device, sb, buf, data_fork_off)?,
                _ => unreachable!(),
            };

            if extents.is_empty() {
                return Ok(None);
            }

            let target_hash = xfs_dir_hash(name);

            // The first block's magic says which format the directory takes.
            if let Some(first_ext) = extents.first()
                && first_ext.block_count > 0
            {
                let bs = sb.block_size as u64;
                let first_block = first_ext.start_block * bs;
                let mut first_buf = vec![0u8; bs as usize];
                read_device_bytes(device, first_block, &mut first_buf)?;
                if first_buf.len() >= 10 {
                    let magic = u16::from_be_bytes([first_buf[8], first_buf[9]]);
                    if magic == XFS_DA_NODE_MAGIC {
                        return lookup_node_dir_by_hash(device, sb, &extents, target_hash, name);
                    }
                    if magic == XFS_DIR2_LEAF1_MAGIC || magic == XFS_DIR2_LEAFN_MAGIC {
                        return lookup_leaf_dir_by_hash(device, sb, &extents, target_hash, name);
                    }
                }
            }

            // Block format, no hash index: read everything, scan linearly.
            let entries = read_block_dir_entries(device, sb, &extents, core.size)?;
            Ok(entries.iter().find(|e| e.name == name).map(|e| e.inode))
        }
        _ => Ok(None),
    }
}

/// Read a directory's entries from extent-mapped blocks, dispatching on
/// the first block's magic: node-format tree, leaf format, or plain block
/// format.
fn read_block_dir_entries(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    extents: &[Extent],
    dir_size: u64,
) -> Result<Vec<DirEntry>> {
    if let Some(first_ext) = extents.first()
        && first_ext.block_count > 0
    {
        let bs = sb.block_size as u64;
        let first_block = first_ext.start_block * bs;
        let mut first_buf = vec![0u8; bs as usize];
        read_device_bytes(device, first_block, &mut first_buf)?;
        if first_buf.len() >= 10 {
            let magic = u16::from_be_bytes([first_buf[8], first_buf[9]]);
            if magic == XFS_DA_NODE_MAGIC {
                return read_node_dir_entries(device, sb, extents);
            }
        }
    }

    let mut entries = Vec::new();
    let mut bytes_read = 0u64;

    for ext in extents {
        if bytes_read >= dir_size {
            break;
        }
        let blocks = ext.block_count;
        let bs = sb.block_size as u64;
        for i in 0..blocks {
            if bytes_read >= dir_size {
                break;
            }
            let block_addr = (ext.start_block + i) * bs;
            let mut block_buf = vec![0u8; bs as usize];
            read_device_bytes(device, block_addr, &mut block_buf)?;

            // A leaf-format directory carries its own hash index; its
            // entries come from the leaf parser rather than the block walk.
            if block_buf.len() >= 16 {
                let da_magic = u16::from_be_bytes([block_buf[8], block_buf[9]]);
                if da_magic == XFS_DIR2_LEAF1_MAGIC || da_magic == XFS_DIR2_LEAFN_MAGIC {
                    entries.extend(parse_leaf_dir(&block_buf));
                    bytes_read += bs;
                    continue;
                }
            }
            entries.extend(parse_block_dir(&block_buf));
            bytes_read += bs;
        }
    }
    Ok(entries)
}

// ── file reading ─────────────────────────────────────────────────────────

/// A file inode's extent list, by its data fork's format.
pub(super) fn get_extents(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    core: &InodeCore,
    buf: &[u8],
) -> Result<Vec<Extent>> {
    let data_fork_off = sb.inode_data_offset();
    match core.format {
        XFS_DINODE_FMT_EXTENTS => Ok(parse_extents(buf, data_fork_off, core.num_extents)),
        XFS_DINODE_FMT_BTREE => super::btree::read_extent_btree(device, sb, buf, data_fork_off),
        _ => Ok(Vec::new()),
    }
}

/// Read a file's bytes through its extent list: each extent that covers the
/// requested range is read from its physical blocks, holes between extents
/// simply contribute nothing.
pub(super) fn read_file(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    extents: &[Extent],
    file_size: u64,
    offset: u64,
    buffer: &mut [u8],
) -> Result<usize> {
    if offset >= file_size || buffer.is_empty() {
        return Ok(0);
    }

    let bs = sb.block_size as u64;
    let end_off = (offset + buffer.len() as u64).min(file_size);
    let mut total = 0usize;

    for ext in extents {
        let ext_start = ext.start_offset;
        let ext_end = ext_start + ext.block_count * bs;

        if offset >= ext_end || end_off <= ext_start {
            continue;
        }

        let seg_start = offset.max(ext_start);
        let seg_end = end_off.min(ext_end);
        let seg_len = (seg_end - seg_start) as usize;
        let phys = ext.start_block * bs + (seg_start - ext_start);
        let dest_off = (seg_start - offset) as usize;

        read_device_bytes(device, phys, &mut buffer[dest_off..dest_off + seg_len])?;
        total += seg_len;
    }

    Ok(total)
}

/// Read an inline file's bytes — the data rides in the inode itself, after
/// the core.
pub(super) fn read_inline_file(
    core: &InodeCore,
    buf: &[u8],
    offset: u64,
    buffer: &mut [u8],
) -> Result<usize> {
    // The data fork's start is the generation's: 100 for v4, 176 for v5.
    // The caller's node carries no superblock, so the inode's own version
    // answers.
    let data_offset = if core.is_v5 { 176usize } else { 100usize };
    if buf.len() < data_offset {
        return Err(Error::InvalidArgument);
    }
    let inline_data = &buf[data_offset..];
    let file_size = core.size as usize;
    let off = offset as usize;
    if off >= file_size || buffer.is_empty() {
        return Ok(0);
    }
    let n = buffer.len().min(file_size - off);
    let avail = inline_data
        .len()
        .saturating_sub(off)
        .min(file_size.saturating_sub(off));
    let n = n.min(avail);
    if off + n > inline_data.len() {
        return Ok(0);
    }
    buffer[..n].copy_from_slice(&inline_data[off..off + n]);
    Ok(n)
}

// ── extended attributes ──────────────────────────────────────────────────

/// List an inode's extended attributes, dispatching on the attribute
/// fork's format: shortform inline, extent-mapped leaf blocks, or the
/// attribute B+tree.
pub(super) fn list_xattrs_for_inode(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    core: &InodeCore,
    buf: &[u8],
    inode_size: usize,
) -> Result<Vec<XattrEntry>> {
    let attr_range = match core.attr_fork_range(inode_size) {
        Some(range) => range,
        None => return Ok(Vec::new()),
    };
    let (fork_off, _fork_end) = attr_range;

    let pairs = match core.attr_format {
        XFS_DINODE_FMT_LOCAL => super::btree::parse_attr_sf_entries(buf, fork_off, inode_size),
        XFS_DINODE_FMT_EXTENTS => {
            let num_extents = core.attr_num_extents as usize;
            if num_extents == 0 || fork_off + num_extents * 16 > buf.len() {
                return Ok(Vec::new());
            }
            let extents = parse_extents(buf, fork_off, num_extents as u32);
            super::btree::walk_attr_tree(device, sb, &extents, 0).unwrap_or_default()
        }
        XFS_DINODE_FMT_BTREE => {
            let extents = super::btree::read_extent_btree(device, sb, buf, fork_off)?;
            super::btree::walk_attr_tree(device, sb, &extents, 0).unwrap_or_default()
        }
        _ => return Ok(Vec::new()),
    };

    Ok(pairs
        .into_iter()
        .map(|(name, value)| XattrEntry::new(name, value))
        .collect())
}
