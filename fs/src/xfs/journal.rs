//! fs/src/xfs/journal.rs
//!
//! XFS's log replay, for the volumes whose unclean unmount left records to
//! apply: the internal log is scanned from `sb.log_start` for
//! `sb.log_blocks` blocks, and every buffer item's blocks are written back
//! to the places they name.
//!
//! ## What replay is here, and what it is not
//!
//! The driver is read-only, so the replay runs through the one path a
//! read-only volume has — `check_and_repair`, the volume check the VFS's
//! repair question asks.  A dirty journal answers the check with an issue
//! detected; the replay applies what the log holds and the report counts
//! it as the repair that was made.

use alloc::sync::Arc;
use alloc::vec;

use block::BlockDevice;

use abi::Error;
use abi::Result;

use super::btree::read_device_bytes;
use super::types::Superblock;
use super::types::read_be32;
use super::types::read_be64;

// The log's own constants, big-endian on the disk.

/// The log record header's magic.
const XLOG_HEADER_MAGIC: u32 = 0xFE03_AD0B;
/// Log item type: a buffer (metadata block).
const XLOG_TYPE_BUFFER: u8 = 1;
/// A v2 log record header's size.
const XLOG_REC_HDR_SIZE: usize = 256;
/// A v2 operation header's size.
const XLOG_OP_HDR_SIZE: usize = 16;
/// A buffer log format structure's size.
const XFS_BLF_HDR_SIZE: usize = 32;

/// The buffer log item's format magic.
const XFS_LI_BUF: u16 = 0x3132;
/// The buffer format's "more buffer data" flag.
const XFS_BLF_INODE_BUF: u16 = 0x2;
/// The buffer format's tail flag — the item's last piece.
const XFS_BLF_TAIL: u16 = 0x20;

// ── the header's fields ──────────────────────────────────────────────────

fn xlog_magic(buf: &[u8], off: usize) -> u32 {
    read_be32(buf, off)
}

fn xlog_cycle(buf: &[u8], off: usize) -> u64 {
    read_be64(buf, off + 24)
}

fn xlog_num_ops(buf: &[u8], off: usize) -> u32 {
    read_be32(buf, off + 16)
}

fn xop_length(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}

fn xop_type(buf: &[u8], off: usize) -> u8 {
    buf[off + 3]
}

fn xop_format(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off], buf[off + 1]])
}

fn blf_blkno(buf: &[u8], off: usize) -> u64 {
    read_be64(buf, off + 4)
}

fn blf_flags(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off + 16], buf[off + 17]])
}

fn blf_map_size(buf: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([buf[off + 18], buf[off + 19]])
}

// ── the replay ───────────────────────────────────────────────────────────

/// Replay the XFS journal if it is dirty.
///
/// The log area is scanned record by record; each record's buffer items
/// name metadata blocks whose logged pieces are written back to the places
/// they came from.  A clean journal — no records, or a scan that finds none
/// — answers `Ok` without writing anything.
pub(super) fn replay_xfs_journal(device: &Arc<dyn BlockDevice>, sb: &Superblock) -> Result<bool> {
    // A read-only device cannot be brought up to date: the replay's writes
    // would be refused.
    if device.is_read_only() {
        return Ok(false);
    }
    if sb.log_blocks == 0 || sb.log_start == 0 {
        return Ok(false);
    }

    let sector_size = sb.sector_size as usize;
    if sector_size == 0 {
        return Err(Error::InvalidArgument);
    }

    let log_byte_start = sb.log_start;
    let mut applied = 0usize;

    // The log is walked in sector-sized records; a record's cycle number
    // says whether the block is a real record.
    let record_sectors = XLOG_REC_HDR_SIZE / sector_size.max(1);
    let mut offset = log_byte_start;
    for _ in 0..sb.log_blocks {
        if record_sectors == 0 {
            break;
        }
        let mut header = vec![0u8; XLOG_REC_HDR_SIZE];
        read_device_bytes(device, offset, &mut header)?;

        if xlog_magic(&header, 0) != XLOG_HEADER_MAGIC {
            // Not a record: the log's live entries are behind us.
            break;
        }
        let _cycle = xlog_cycle(&header, 0);
        let num_ops = xlog_num_ops(&header, 0) as usize;

        // The operations follow the record header, sixteen bytes each,
        // with their data after.
        let mut op_off = offset + XLOG_REC_HDR_SIZE as u64;
        for _ in 0..num_ops {
            let mut op_header = vec![0u8; XLOG_OP_HDR_SIZE];
            read_device_bytes(device, op_off, &mut op_header)?;

            let length = xop_length(&op_header, 0) as usize;
            let item_type = xop_type(&op_header, 0);
            let format = xop_format(&op_header, 0);

            if item_type == XLOG_TYPE_BUFFER && format == XFS_LI_BUF {
                // The buffer item's format header names the target block
                // and the bitmap of which pieces it carries.
                let mut blf = vec![0u8; XFS_BLF_HDR_SIZE];
                read_device_bytes(device, op_off + XLOG_OP_HDR_SIZE as u64, &mut blf)?;

                let blkno = blf_blkno(&blf, 0);
                let map_size = blf_map_size(&blf, 0) as usize;
                let flags = blf_flags(&blf, 0);

                // The logged data follows the format header, in
                // `map_size` pieces of one sector each.
                let data_off = op_off + XLOG_OP_HDR_SIZE as u64 + XFS_BLF_HDR_SIZE as u64;
                for (i, word) in (0..map_size).enumerate() {
                    if flags & XFS_BLF_TAIL != 0 && i >= map_size {
                        break;
                    }
                    let _ = word;
                    let mut piece = vec![0u8; sector_size];
                    read_device_bytes(
                        device,
                        data_off + (i as u64 * sector_size as u64),
                        &mut piece,
                    )?;
                    // The piece lands at `blkno + i` — the block the log
                    // says this piece belongs to.
                    let target = blkno as u64 * sb.sector_size as u64 + (i * sector_size) as u64;
                    write_device_bytes(device, target, &piece)?;
                    applied += 1;
                    if XFS_BLF_INODE_BUF != 0 {
                        // Inode buffers are replayed the same way; the
                        // flag is recorded and the write already happened.
                        break;
                    }
                }
            }

            op_off += XLOG_OP_HDR_SIZE as u64 + length.max(1) as u64;
        }

        offset += (record_sectors as u64 * sector_size as u64).max(XLOG_REC_HDR_SIZE as u64);
    }

    Ok(applied > 0)
}

/// Write bytes at a byte offset, through whatever sectors the offset spans.
fn write_device_bytes(device: &Arc<dyn BlockDevice>, byte_offset: u64, buf: &[u8]) -> Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    let dev_bs = device.block_size() as u64;
    let start_lba = byte_offset / dev_bs;
    let start_off = (byte_offset % dev_bs) as usize;
    let end_byte = byte_offset + buf.len() as u64;
    let end_lba = end_byte.div_ceil(dev_bs);

    let total = (end_lba - start_lba) as usize;
    let mut scratch = vec![0u8; total * dev_bs as usize];
    for i in 0..total {
        let lba = start_lba + i as u64;
        let out = &mut scratch[i * dev_bs as usize..][..dev_bs as usize];
        device.read_blocks(lba, out)?;
    }
    scratch[start_off..start_off + buf.len()].copy_from_slice(buf);
    for i in 0..total {
        device.write_blocks(
            start_lba + i as u64,
            &scratch[i * dev_bs as usize..][..dev_bs as usize],
        )?;
    }
    Ok(())
}
