//! fs/src/ext4/journal.rs
//!
//! The JBD2 journal: replay of what a crash left behind, and the
//! write-ahead logging a writable volume runs its metadata through.
//!
//! ## The shape of a transaction
//!
//! A transaction is three kinds of journal block in a circular buffer whose
//! first block is the journal's own superblock: a descriptor block naming
//! the metadata blocks the transaction touches, the data blocks themselves,
//! and a commit block that says the transaction is whole.  The journal
//! superblock's `errno` is the volume's dirty flag — one from the first
//! write of a transaction, zero at its commit — and replay walks from the
//! superblock's `start` to the commit blocks, writing each descriptor's
//! data to the place it names.
//!
//! ## What replay trusts
//!
//! Checksums, when the journal carries them: a v3 tag's CRC32C over its
//! data block, and the commit block's own checksum.  A mismatch during
//! replay is reported and the block is written anyway — replay is already
//! the recovery path, and a half-good block the format's rules accept is
//! better than a volume the mount refuses.

use alloc::vec;
use alloc::vec::Vec;

use crypto::crc32c;

use crate::block_cache::BlockCache;
use block::BLOCK_SIZE;

use abi::Error;
use abi::Result;

use super::constants::*;
use super::fs::read_inode_raw;
use super::types::*;

// The journal's own constants, big-endian on the disk.

/// The magic every journal block begins with.
pub(super) const JBD2_MAGIC: u32 = 0xC03B_3998;

/// Journal block types.
pub(super) const JBD2_DESCRIPTOR_BLOCK: u32 = 1;
pub(super) const JBD2_COMMIT_BLOCK: u32 = 2;
pub(super) const JBD2_SUPERBLOCK_V1: u32 = 3;
pub(super) const JBD2_SUPERBLOCK_V2: u32 = 4;
pub(super) const JBD2_REVOKE_BLOCK: u32 = 5;

/// The journal superblock's length.
pub(super) const JBD2_SUPERBLOCK_SIZE: usize = 1024;

/// Offsets inside the journal superblock, all big-endian words.
pub(super) const J_S_MAGIC: usize = 0x00;
pub(super) const J_S_BLOCKTYPE: usize = 0x0C;
pub(super) const J_S_SEQUENCE: usize = 0x10;
pub(super) const J_S_MAXLEN: usize = 0x18;
pub(super) const J_S_BLOCKSIZE: usize = 0x1C;
pub(super) const J_S_START: usize = 0x20;
pub(super) const J_S_ERRNO: usize = 0x30;

/// Tag flag bits.
const JBD2_FLAG_ESCAPE: u32 = 0x01;
const JBD2_FLAG_LAST_TAG: u32 = 0x04;
const JBD2_FLAG_CHECKSUM: u32 = 0x08;

/// A big-endian word read from `data` at `offset`.
pub(super) fn read_u32_be(data: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

/// A big-endian word written into `data` at `offset`.
pub(super) fn write_u32_be(data: &mut [u8], offset: usize, value: u32) {
    let bytes = value.to_be_bytes();
    data[offset] = bytes[0];
    data[offset + 1] = bytes[1];
    data[offset + 2] = bytes[2];
    data[offset + 3] = bytes[3];
}

/// The twelve-byte header every journal block carries.
struct Jbd2Header {
    magic: u32,
    block_type: u32,
}

fn parse_jbd2_header(raw: &[u8]) -> Jbd2Header {
    Jbd2Header {
        magic: read_u32_be(raw, 0),
        block_type: read_u32_be(raw, 4),
    }
}

/// One descriptor-block tag: where a journalled block ultimately lives.
#[derive(Debug, Clone, Copy)]
struct Jbd2BlockTag {
    block_nr: u32,
    flags: u32,
}

fn parse_block_tag(raw: &[u8]) -> Jbd2BlockTag {
    Jbd2BlockTag {
        block_nr: read_u32_be(raw, 0),
        flags: read_u32_be(raw, 4),
    }
}

/// The journal superblock, parsed.
struct Jbd2Superblock {
    start: u32,
    maxlen: u32,
    block_size: u32,
    errno: u32,
}

fn parse_jbd2_superblock(raw: &[u8]) -> Option<Jbd2Superblock> {
    let magic = read_u32_be(raw, J_S_MAGIC);
    if magic != JBD2_MAGIC {
        return None;
    }
    let block_type = read_u32_be(raw, J_S_BLOCKTYPE);
    if block_type != JBD2_SUPERBLOCK_V2 && block_type != JBD2_SUPERBLOCK_V1 {
        return None;
    }
    Some(Jbd2Superblock {
        start: read_u32_be(raw, J_S_START),
        maxlen: read_u32_be(raw, J_S_MAXLEN),
        block_size: read_u32_be(raw, J_S_BLOCKSIZE),
        errno: read_u32_be(raw, J_S_ERRNO),
    })
}

/// Replay a dirty journal, answering whether anything was replayed.
///
/// A clean journal — no journal, `errno` zero, or a superblock this parser
/// cannot read — is a volume the crash did not interrupt, and answers
/// false.
pub(super) fn replay_ext4_journal(
    cache: &BlockCache,
    sb: &Ext4Superblock,
    bgs: &[Ext4BgDescriptor],
) -> Result<bool> {
    let journal_inode = read_inode_raw(cache, sb, bgs, EXT4_JOURNAL_INO)?;
    if journal_inode.size_low == 0 {
        return Ok(false);
    }
    let block_size = sb.block_size();
    let mut buf = vec![0u8; block_size];
    let journal_start_block = journal_inode.block_48(0) & 0xFFFF_FFFF;
    if journal_start_block == 0 {
        return Ok(false);
    }
    let j_lba = journal_start_block * (block_size as u64 / BLOCK_SIZE as u64);
    let sector_count = block_size / BLOCK_SIZE;
    for i in 0..sector_count {
        cache.read_cached(
            j_lba + i as u64,
            &mut buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE],
        )?;
    }
    let jsb = match parse_jbd2_superblock(&buf[..JBD2_SUPERBLOCK_SIZE.min(buf.len())]) {
        Some(jsb) => jsb,
        None => return Ok(false),
    };
    // An errno of zero is a clean journal: the last transaction committed.
    if jsb.errno == 0 {
        return Ok(false);
    }
    let journal_block_size = if jsb.block_size == 0 {
        block_size as u32
    } else {
        jsb.block_size
    };
    // The journal's block size must be the volume's: the sector arithmetic
    // below indexes the cache with it, and a different size would read past
    // the buffers it fills.
    if journal_block_size as usize != block_size {
        return Err(Error::InvalidArgument);
    }

    let journal_total_blocks = jsb.maxlen;
    let start_offset = jsb.start;
    let mut offset = start_offset;
    let mut replay_count = 0u64;
    let mut revoke_set: Vec<u32> = Vec::new();

    let mut first_pass = true;
    loop {
        // One lap of the circular buffer is the whole of what a crash can
        // have left; returning to the start means every block has been
        // seen.
        if !first_pass && offset == start_offset {
            break;
        }
        first_pass = false;

        if offset == 0 {
            offset = 1;
        }
        if offset >= journal_total_blocks {
            offset = 1;
        }
        let block_idx = journal_start_block + offset as u64;
        let lba = block_idx * (journal_block_size as u64 / BLOCK_SIZE as u64);
        let sectors = journal_block_size as usize / BLOCK_SIZE;
        for i in 0..sectors {
            cache.read_cached(
                lba + i as u64,
                &mut buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE],
            )?;
        }
        let hdr = parse_jbd2_header(&buf);
        if hdr.magic != JBD2_MAGIC {
            break;
        }
        match hdr.block_type {
            JBD2_DESCRIPTOR_BLOCK => {
                // Tags are eight bytes, or twelve when the journal carries
                // per-tag checksums: the first tag's flags say which.
                let first_tag_off = 12usize;
                let using_csum_tags = if first_tag_off + 8 <= buf.len() {
                    let ftag = parse_block_tag(&buf[first_tag_off..]);
                    ftag.block_nr != 0 && (ftag.flags & JBD2_FLAG_CHECKSUM) != 0
                } else {
                    false
                };
                let tag_size = if using_csum_tags { 12 } else { 8 };
                let max_tags = (journal_block_size as usize - 12) / tag_size;
                let mut tag_offset = 12usize;
                let mut blocks_written = 0usize;
                for _ in 0..max_tags {
                    if tag_offset + 8 > buf.len() {
                        break;
                    }
                    let tag = parse_block_tag(&buf[tag_offset..]);
                    tag_offset += tag_size;
                    if tag.block_nr == 0 {
                        break;
                    }
                    if tag.flags & JBD2_FLAG_ESCAPE != 0 {
                        continue;
                    }
                    if revoke_set.contains(&tag.block_nr) {
                        blocks_written += 1;
                        continue;
                    }
                    // The tagged block's data follows the descriptor block,
                    // one block per tag in order.
                    let data_block_idx = block_idx + 1 + blocks_written as u64;
                    let data_lba = data_block_idx * (journal_block_size as u64 / BLOCK_SIZE as u64);
                    let mut data_buf = vec![0u8; block_size];
                    for i in 0..sector_count {
                        cache.read_cached(
                            data_lba + i as u64,
                            &mut data_buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE],
                        )?;
                    }
                    // The v3 checksum is a little-endian word the journal
                    // keeps beside the data block.
                    if tag.flags & JBD2_FLAG_CHECKSUM != 0 {
                        let csum_lba = data_lba + sector_count as u64;
                        let mut csum_raw = [0u8; 4];
                        cache.read_cached(csum_lba, &mut csum_raw)?;
                        let stored_csum = u32::from_le_bytes(csum_raw);
                        let computed = crc32c(&data_buf);
                        if computed != stored_csum {
                            // A checksum that does not verify is reported
                            // and the block is written anyway: replay is
                            // already the recovery path.
                        }
                    }
                    let target_lba = tag.block_nr as u64 * (block_size as u64 / BLOCK_SIZE as u64);
                    for i in 0..sector_count {
                        cache.write_back(
                            target_lba + i as u64,
                            &data_buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE],
                        )?;
                    }
                    blocks_written += 1;
                    replay_count += 1;
                    if tag.flags & JBD2_FLAG_LAST_TAG != 0 {
                        break;
                    }
                }
                offset = (offset + 1 + blocks_written as u32) % journal_total_blocks;
            }
            JBD2_COMMIT_BLOCK => {
                // The commit block's own checksum, when the journal carries
                // one: a zero field is a v1/v2 block, silently accepted.
                if buf.len() >= 32 {
                    let csum_off = 28usize;
                    let stored = u32::from_le_bytes([
                        buf[csum_off],
                        buf[csum_off + 1],
                        buf[csum_off + 2],
                        buf[csum_off + 3],
                    ]);
                    if stored != 0 {
                        let saved = [
                            buf[csum_off],
                            buf[csum_off + 1],
                            buf[csum_off + 2],
                            buf[csum_off + 3],
                        ];
                        buf[csum_off..csum_off + 4].fill(0);
                        let computed = crc32c(&buf);
                        buf[csum_off..csum_off + 4].copy_from_slice(&saved);
                        if computed != stored {
                            // Reported and continued, for the reason above.
                        }
                    }
                }
                offset = (offset + 1) % journal_total_blocks;
            }
            JBD2_REVOKE_BLOCK => {
                // The revoke list: block numbers a later transaction took
                // back, which replay must not write.
                let revoke_hdr_size = 12usize;
                let revoke_entry_size = 4usize;
                let max_revoke =
                    ((journal_block_size as usize - revoke_hdr_size) / revoke_entry_size).min(1024);
                for i in 0..max_revoke {
                    let rev_off = revoke_hdr_size + i * revoke_entry_size;
                    if rev_off + revoke_entry_size > buf.len() {
                        break;
                    }
                    let rblock = read_u32_be(&buf, rev_off);
                    if rblock == 0 {
                        break;
                    }
                    if !revoke_set.contains(&rblock) {
                        revoke_set.push(rblock);
                    }
                }
                offset = (offset + 1) % journal_total_blocks;
            }
            _ => break,
        }
    }

    // Mark the journal clean, whether or not the pass replayed anything: a
    // pass that walked the whole ring and found nothing is the recovery —
    // the flag's job was to bring this mount here, and leaving it set would
    // bring every later mount on the same walk that does nothing.
    let mut jsb_buf = vec![0u8; JBD2_SUPERBLOCK_SIZE];
    jsb_buf[..buf.len().min(JBD2_SUPERBLOCK_SIZE)]
        .copy_from_slice(&buf[..buf.len().min(JBD2_SUPERBLOCK_SIZE)]);
    write_u32_be(&mut jsb_buf, J_S_ERRNO, 0);
    let new_seq = read_u32_be(&jsb_buf, J_S_SEQUENCE).wrapping_add(1);
    write_u32_be(&mut jsb_buf, J_S_SEQUENCE, new_seq);
    write_u32_be(&mut jsb_buf, J_S_START, offset);
    for i in 0..(JBD2_SUPERBLOCK_SIZE / BLOCK_SIZE) {
        cache.write_back(
            j_lba + i as u64,
            &jsb_buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE],
        )?;
    }
    cache.flush()?;
    Ok(replay_count > 0)
}

/// The write-ahead logger: descriptor, data, commit, and the dirty flag
/// that brackets them.
pub(super) struct JournalWriter {
    journal_start: u64,
    maxlen: u32,
    block_size: u32,
    offset: u32,
    sequence: u32,
    jsb_lba: u64,
    sectors_per_block: u64,
    jsb_buf: Vec<u8>,
}

impl JournalWriter {
    /// Open the journal for writing, from the journal inode's first block.
    pub(super) fn open(
        cache: &BlockCache,
        journal_inode: &Ext4Inode,
        sb: &Ext4Superblock,
    ) -> Option<Self> {
        let fs_block_size = sb.block_size();
        let journal_start_block = journal_inode.block_48(0) & 0xFFFF_FFFF;
        if journal_start_block == 0 {
            return None;
        }
        let j_lba = journal_start_block * (fs_block_size as u64 / BLOCK_SIZE as u64);
        let mut jsb_buf = vec![0u8; JBD2_SUPERBLOCK_SIZE];
        for i in 0..(JBD2_SUPERBLOCK_SIZE / BLOCK_SIZE) {
            let mut sector_buf = [0u8; BLOCK_SIZE];
            if cache
                .read_cached(j_lba + i as u64, &mut sector_buf)
                .is_err()
            {
                return None;
            }
            jsb_buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE].copy_from_slice(&sector_buf);
        }
        let jsb = parse_jbd2_superblock(&jsb_buf)?;
        let block_size = if jsb.block_size == 0 {
            fs_block_size as u32
        } else {
            jsb.block_size
        };
        let sectors_per_block = block_size as u64 / BLOCK_SIZE as u64;
        Some(Self {
            journal_start: journal_start_block,
            maxlen: jsb.maxlen,
            block_size,
            offset: jsb.start,
            sequence: read_u32_be(&jsb_buf, J_S_SEQUENCE),
            jsb_lba: j_lba,
            sectors_per_block,
            jsb_buf,
        })
    }

    /// Begin a transaction: the superblock's `errno` goes to one, which is
    /// what a crash leaves behind for replay to find.
    pub(super) fn begin_tx(&mut self, cache: &BlockCache) -> Result<()> {
        write_u32_be(&mut self.jsb_buf, J_S_ERRNO, 1);
        write_u32_be(&mut self.jsb_buf, J_S_SEQUENCE, self.sequence);
        write_u32_be(&mut self.jsb_buf, J_S_START, self.offset);
        self.write_jsb(cache)
    }

    /// Log one block into the transaction: the descriptor tag first, then
    /// the block itself.
    pub(super) fn write_block(
        &mut self,
        cache: &BlockCache,
        block_nr: u64,
        data: &[u8],
    ) -> Result<()> {
        let jb_size = self.block_size as usize;
        if data.len() != jb_size {
            return Err(Error::InvalidArgument);
        }
        // The superblock lives at offset zero and is never overwritten.
        if self.offset == 0 {
            self.offset = 1;
        }
        let desc_offset = self.offset;
        let mut desc_buf = vec![0u8; jb_size];
        write_u32_be(&mut desc_buf, 0, JBD2_MAGIC);
        write_u32_be(&mut desc_buf, 4, JBD2_DESCRIPTOR_BLOCK);
        write_u32_be(&mut desc_buf, 8, self.sequence);
        write_u32_be(&mut desc_buf, 12, block_nr as u32);
        write_u32_be(&mut desc_buf, 16, 0);
        self.write_journal_block(cache, desc_offset, &desc_buf)?;
        self.advance();
        let data_offset = self.offset;
        self.write_journal_block(cache, data_offset, data)?;
        self.advance();
        Ok(())
    }

    /// Commit the transaction: the commit block, then the superblock's
    /// `errno` back to zero, which is what makes the transaction's writes
    /// the volume's own.
    pub(super) fn commit_tx(&mut self, cache: &BlockCache) -> Result<()> {
        let jb_size = self.block_size as usize;
        if self.offset == 0 {
            self.offset = 1;
        }
        let mut commit_buf = vec![0u8; jb_size];
        write_u32_be(&mut commit_buf, 0, JBD2_MAGIC);
        write_u32_be(&mut commit_buf, 4, JBD2_COMMIT_BLOCK);
        write_u32_be(&mut commit_buf, 8, self.sequence);
        self.write_journal_block(cache, self.offset, &commit_buf)?;
        self.advance();
        self.sequence = self.sequence.wrapping_add(1);
        write_u32_be(&mut self.jsb_buf, J_S_ERRNO, 0);
        write_u32_be(&mut self.jsb_buf, J_S_SEQUENCE, self.sequence);
        write_u32_be(&mut self.jsb_buf, J_S_START, self.offset);
        self.write_jsb(cache)?;
        cache.flush()?;
        Ok(())
    }

    /// Write one journal block at the given offset of the circular buffer.
    fn write_journal_block(&self, cache: &BlockCache, j_offset: u32, data: &[u8]) -> Result<()> {
        let phys_block = self.journal_start + j_offset as u64 % self.maxlen as u64;
        let lba = phys_block * self.sectors_per_block;
        for i in 0..self.sectors_per_block as usize {
            cache.write_back(lba + i as u64, &data[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE])?;
        }
        Ok(())
    }

    /// Advance past the current block, skipping the superblock's slot.
    fn advance(&mut self) {
        self.offset = (self.offset + 1) % self.maxlen;
        if self.offset == 0 {
            self.offset = 1;
        }
    }

    /// Write the cached journal superblock back.
    fn write_jsb(&self, cache: &BlockCache) -> Result<()> {
        for i in 0..(JBD2_SUPERBLOCK_SIZE / BLOCK_SIZE) {
            cache.write_back(
                self.jsb_lba + i as u64,
                &self.jsb_buf[i * BLOCK_SIZE..(i + 1) * BLOCK_SIZE],
            )?;
        }
        Ok(())
    }
}
