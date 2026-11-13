//! fs/src/xfs/btree.rs
//!
//! XFS's B+tree readers: the BMAP extent tree a large file's mapping walks,
//! the directory hash a name lookup keys on, and the attribute tree the
//! xattr listing walks.
//!
//! ## The one reader, three trees
//!
//! XFS's long-format B+tree blocks share one header shape whatever they
//! carry, so one reader — [`BtreeReader64`], over 64-bit keys — collects
//! extent records from a BMAP tree, and the directory and attribute trees
//! walk through the same helpers' node arithmetic.  The short formats
//! (shortform dirs, shortform attrs) never touch a block and are parsed in
//! [`super::types`].

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use block::BlockDevice;

use abi::Error;
use abi::Result;

use super::types::DirEntry;
use super::types::Extent;
use super::types::Superblock;
use super::types::XFS_ATTR_LEAF_MAGIC;
use super::types::XFS_BMAP_MAGIC_V4;
use super::types::XFS_DA_NODE_MAGIC;
use super::types::XFS_DIR2_LEAF1_MAGIC;
use super::types::XFS_DIR2_LEAFN_MAGIC;
use super::types::read_be32;
use super::types::read_be64;

/// How deep a B+tree walk goes before declaring the metadata cyclic.
const XFS_BTREE_MAX_DEPTH: usize = 32;

/// Parse BMAP leaf records — twenty-four bytes each — into extents.
pub(super) fn parse_bmap_leaf(data: &[u8], num_recs: usize) -> Vec<Extent> {
    let mut extents = Vec::with_capacity(num_recs);
    for i in 0..num_recs {
        let off = i * 24;
        if off + 24 > data.len() {
            break;
        }
        let start_offset = read_be64(data, off);
        let start_block = read_be64(data, off + 8);
        let block_count = read_be32(data, off + 16) as u64;
        extents.push(Extent {
            start_offset,
            start_block,
            block_count,
        });
    }
    extents
}

/// Parse BMAP internal-node records — sixteen bytes each — into
/// `(key, child block)` pairs.
pub(super) fn parse_bmap_internal(data: &[u8], num_recs: usize) -> Vec<(u64, u64)> {
    let mut recs = Vec::with_capacity(num_recs);
    for i in 0..num_recs {
        let off = i * 16;
        if off + 16 > data.len() {
            break;
        }
        let key = read_be64(data, off);
        let block = read_be64(data, off + 8);
        recs.push((key, block));
    }
    recs
}

// ── the directory hash ───────────────────────────────────────────────────

/// XFS's directory name hash, the lookup key in the leaf and node formats.
///
/// The arithmetic is the format's own fold: four bits of shift per byte,
/// with the high nibble folded back in when it overflows — the same
/// computation a peer's `mkfs` tool ran when it wrote the leaf entries,
/// which is why a hash this side computes must match the hash on the wire.
pub(super) fn xfs_dir_hash(name: &[u8]) -> u32 {
    let mut hash: u32 = 0;
    for &byte in name {
        hash = hash.wrapping_shl(4).wrapping_add(byte as u32);
        let high = hash & 0xF000_0000;
        if high != 0 {
            hash ^= high >> 24;
            hash &= !high;
        }
    }
    hash
}

// ── the 64-bit-key B+tree reader ─────────────────────────────────────────

/// A reader for XFS's long-format B+tree blocks, parameterised by the
/// generation's record offset and magic.
pub(super) struct BtreeReader64 {
    device: Arc<dyn BlockDevice>,
    block_size: u32,
    rec_offset: usize,
    bmap_magic: u32,
}

impl BtreeReader64 {
    pub(super) fn new(
        device: Arc<dyn BlockDevice>,
        block_size: u32,
        rec_offset: usize,
        bmap_magic: u32,
    ) -> Self {
        Self {
            device,
            block_size,
            rec_offset,
            bmap_magic,
        }
    }

    /// Collect every extent a BMAP B+tree names, from the BMDR root the
    /// inode's data fork holds:
    ///
    /// ```text
    /// u16 level
    /// u16 numrecs
    /// … numrecs × (16 bytes internal / 24 bytes leaf)
    /// ```
    pub(super) fn collect_extents(&self, buf: &[u8], fork_off: usize) -> Result<Vec<Extent>> {
        if fork_off + 4 > buf.len() {
            return Err(Error::InvalidArgument);
        }
        let root_level = u16::from_be_bytes([buf[fork_off], buf[fork_off + 1]]);
        let root_numrecs = u16::from_be_bytes([buf[fork_off + 2], buf[fork_off + 3]]) as usize;
        let root_data = &buf[fork_off + 4..];

        if root_level == 0 {
            return Ok(parse_bmap_leaf(root_data, root_numrecs));
        }

        // The root is internal: descend, children pushed in reverse so the
        // leftmost is processed first.
        let root_recs = parse_bmap_internal(root_data, root_numrecs);
        let mut stack: Vec<(u64, usize)> = root_recs
            .iter()
            .rev()
            .map(|(_, block)| (*block, 1))
            .collect();

        let mut all_extents = Vec::new();
        let block_size = self.block_size as u64;

        while let Some((block_num, depth)) = stack.pop() {
            if depth > XFS_BTREE_MAX_DEPTH {
                continue;
            }

            let byte_off = block_num * block_size;
            let mut node_buf = vec![0u8; block_size as usize];
            read_device_bytes(&self.device, byte_off, &mut node_buf)?;

            if node_buf.len() < self.rec_offset {
                continue;
            }
            let magic = read_be32(&node_buf, 0);
            if magic != self.bmap_magic {
                // Not a BMAP block of this generation: corruption or another
                // tree — skipped rather than parsed at the wrong offsets.
                continue;
            }
            let level = u16::from_be_bytes([node_buf[4], node_buf[5]]);
            let numrecs = u16::from_be_bytes([node_buf[6], node_buf[7]]) as usize;
            let data = &node_buf[self.rec_offset..];

            if level == 0 {
                all_extents.extend(parse_bmap_leaf(data, numrecs));
            } else {
                for (_, child_block) in parse_bmap_internal(data, numrecs).iter().rev() {
                    stack.push((*child_block, depth + 1));
                }
            }
        }

        Ok(all_extents)
    }
}

/// Read the extents of a file whose data fork is in B+tree format.
pub(super) fn read_extent_btree(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    buf: &[u8],
    fork_off: usize,
) -> Result<Vec<Extent>> {
    let reader = BtreeReader64::new(
        Arc::clone(device),
        sb.block_size,
        sb.btree_lblock_rec_offset(),
        sb.bmap_magic(),
    );
    reader.collect_extents(buf, fork_off)
}

// ── directory leaf blocks ────────────────────────────────────────────────

/// Parse a leaf block's directory hash entries — eight bytes each:
/// `(hash, address)`.
pub(super) fn parse_dir_leaf_entries(data: &[u8], num_entries: usize) -> Vec<(u32, u32)> {
    let mut entries = Vec::with_capacity(num_entries);
    for i in 0..num_entries {
        let off = i * 8;
        if off + 8 > data.len() {
            break;
        }
        let hash = read_be32(data, off);
        let address = read_be32(data, off + 4);
        entries.push((hash, address));
    }
    entries
}

/// Parse a leaf-format directory block, whole.
///
/// The v4 leaf header is twelve bytes of blkinfo, then count and stale; its
/// entries name byte offsets within the directory's data area.  A v5 block
/// carries a longer header this reader does not claim to read, and answers
/// nothing rather than parsing at v4's offsets.
pub(super) fn parse_leaf_dir(data: &[u8]) -> Vec<DirEntry> {
    let mut entries = Vec::new();
    if data.len() < 16 {
        return entries;
    }

    let magic = u16::from_be_bytes([data[8], data[9]]);
    let (count, leaf_entries_start): (usize, usize) = match magic {
        XFS_DIR2_LEAF1_MAGIC | XFS_DIR2_LEAFN_MAGIC => {
            let cnt = u16::from_be_bytes([data[12], data[13]]) as usize;
            (cnt, 16)
        }
        _ => return entries,
    };

    if count == 0 {
        return entries;
    }

    let leaf_entries = parse_dir_leaf_entries(&data[leaf_entries_start..], count);

    for (_hash, address) in leaf_entries {
        let addr = address as usize;
        if addr >= data.len() {
            continue;
        }
        if let Some(entry) = super::types::parse_data_entry_at(data, addr) {
            entries.push(entry);
        }
    }

    entries
}

// ── node-format directories ──────────────────────────────────────────────

/// Map a directory logical block number to its physical byte offset,
/// through the extent list.
fn logical_block_to_phys(lbn: u32, extents: &[Extent], bs: u64) -> Option<u64> {
    let mut remaining = lbn as u64 * bs;
    for ext in extents {
        let ext_bytes = ext.block_count * bs;
        if remaining < ext_bytes {
            let block_idx = remaining / bs;
            return Some((ext.start_block + block_idx) * bs);
        }
        remaining -= ext_bytes;
    }
    None
}

/// Parse a directory node block: its level and its `(hash, before)`
/// entries, where entry i's `before` covers hashes at or below hash_i.
fn parse_node_block(data: &[u8]) -> Option<(u16, Vec<(u32, u32)>)> {
    if data.len() < 16 {
        return None;
    }
    let magic = u16::from_be_bytes([data[8], data[9]]);
    if magic != XFS_DA_NODE_MAGIC {
        return None;
    }
    let count = u16::from_be_bytes([data[12], data[13]]) as usize;
    let level = u16::from_be_bytes([data[14], data[15]]);

    let node_data = &data[16..];
    let mut entries = Vec::with_capacity(count);
    for i in 0..count {
        let off = i * 8;
        if off + 8 > node_data.len() {
            break;
        }
        let hash = read_be32(node_data, off);
        let before = read_be32(node_data, off + 4);
        entries.push((hash, before));
    }
    Some((level, entries))
}

/// Traverse a node-format directory and collect every entry, depth-first
/// from logical block zero.  A LEAFN leaf entry's address encodes the data
/// block (upper half) and byte offset (lower half) the entry lives at.
pub(super) fn read_node_dir_entries(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    extents: &[Extent],
) -> Result<Vec<DirEntry>> {
    let bs = sb.block_size as u64;
    let mut entries = Vec::new();
    let mut stack: Vec<u32> = vec![0];

    while let Some(lbn) = stack.pop() {
        let phys = logical_block_to_phys(lbn, extents, bs).ok_or(Error::InvalidArgument)?;
        let mut buf = vec![0u8; bs as usize];
        read_device_bytes(device, phys, &mut buf)?;

        if buf.len() < 16 {
            continue;
        }
        let magic = u16::from_be_bytes([buf[8], buf[9]]);

        match magic {
            XFS_DA_NODE_MAGIC => {
                if let Some((_level, node_entries)) = parse_node_block(&buf) {
                    // Children pushed in reverse for left-to-right traversal.
                    for child in node_entries
                        .iter()
                        .map(|&(_, before)| before)
                        .collect::<Vec<_>>()
                        .iter()
                        .rev()
                    {
                        stack.push(*child);
                    }
                }
            }
            XFS_DIR2_LEAFN_MAGIC => {
                let count = u16::from_be_bytes([buf[12], buf[13]]) as usize;
                let leaf_entries = parse_dir_leaf_entries(&buf[16..], count);

                for (_hash, address) in leaf_entries {
                    let data_lbn = address >> 16;
                    let byte_off = (address & 0xFFFF) as usize;

                    let data_phys = logical_block_to_phys(data_lbn, extents, bs)
                        .ok_or(Error::InvalidArgument)?;
                    let mut data_buf = vec![0u8; bs as usize];
                    read_device_bytes(device, data_phys, &mut data_buf)?;

                    if let Some(entry) = super::types::parse_data_entry_at(&data_buf, byte_off) {
                        entries.push(entry);
                    }
                }
            }
            XFS_DIR2_LEAF1_MAGIC => {
                // A LEAF1 inside a node tree is unusual; handle it
                // gracefully through the leaf parser.
                entries.extend(parse_leaf_dir(&buf));
            }
            _ => {
                // An unknown block type falls back to block-format.
                entries.extend(super::types::parse_block_dir(&buf));
            }
        }
    }

    Ok(entries)
}

// ── hash-indexed lookup ──────────────────────────────────────────────────

/// Map a directory byte offset to its physical byte offset, through the
/// extent list.
fn dir_byte_to_phys(byte_off: u64, extents: &[Extent], bs: u64) -> Option<(u64, usize)> {
    let mut remaining = byte_off;
    for ext in extents {
        let ext_bytes = ext.block_count * bs;
        if remaining < ext_bytes {
            let block_idx = remaining / bs;
            let block_off = (remaining % bs) as usize;
            let phys = (ext.start_block + block_idx) * bs;
            return Some((phys, block_off));
        }
        remaining -= ext_bytes;
    }
    None
}

/// Look up a name in a leaf-format directory, by hash.
///
/// The leaf entries are sorted by hash, so the binary search lands on the
/// hash's run and the name comparison walks it — the collision guard: a
/// hash match alone would answer the wrong file.
pub(super) fn lookup_leaf_dir_by_hash(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    extents: &[Extent],
    target_hash: u32,
    target_name: &[u8],
) -> Result<Option<u64>> {
    let bs = sb.block_size as u64;

    for ext in extents {
        for i in 0..ext.block_count {
            let block_addr = (ext.start_block + i) * bs;
            let mut buf = vec![0u8; bs as usize];
            read_device_bytes(device, block_addr, &mut buf)?;

            if buf.len() < 16 {
                continue;
            }
            let magic = u16::from_be_bytes([buf[8], buf[9]]);
            if magic != XFS_DIR2_LEAF1_MAGIC {
                continue;
            }

            let count = u16::from_be_bytes([buf[12], buf[13]]) as usize;
            if count == 0 {
                return Ok(None);
            }

            let leaf_entries = parse_dir_leaf_entries(&buf[16..], count);

            if let Ok(idx) = leaf_entries.binary_search_by_key(&target_hash, |(hash, _addr)| *hash)
            {
                let mut first = idx;
                while first > 0 && leaf_entries[first - 1].0 == target_hash {
                    first -= 1;
                }
                let mut pos = first;
                while pos < leaf_entries.len() && leaf_entries[pos].0 == target_hash {
                    let address = leaf_entries[pos].1 as u64;
                    if let Some((phys, block_off)) = dir_byte_to_phys(address, extents, bs) {
                        let mut data_buf = vec![0u8; bs as usize];
                        read_device_bytes(device, phys, &mut data_buf)?;
                        if let Some(entry) = super::types::parse_data_entry_at(&data_buf, block_off)
                            && entry.name == target_name
                        {
                            return Ok(Some(entry.inode));
                        }
                    }
                    pos += 1;
                }
            }
            // The LEAF1 block was found and searched — done either way.
            return Ok(None);
        }
    }
    Ok(None)
}

/// Look up a name in a node-format directory B+tree, by hash, from the
/// root at logical block zero.
pub(super) fn lookup_node_dir_by_hash(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    extents: &[Extent],
    target_hash: u32,
    target_name: &[u8],
) -> Result<Option<u64>> {
    let bs = sb.block_size as u64;
    let mut lbn: u32 = 0;

    loop {
        let phys = logical_block_to_phys(lbn, extents, bs).ok_or(Error::InvalidArgument)?;
        let mut buf = vec![0u8; bs as usize];
        read_device_bytes(device, phys, &mut buf)?;

        if buf.len() < 16 {
            return Ok(None);
        }
        let magic = u16::from_be_bytes([buf[8], buf[9]]);

        match magic {
            XFS_DA_NODE_MAGIC => {
                // The child whose `before` covers this hash, or the
                // rightmost when the hash is past every entry's.
                if let Some((_level, node_entries)) = parse_node_block(&buf) {
                    if node_entries.is_empty() {
                        return Ok(None);
                    }
                    let child = node_entries
                        .iter()
                        .find(|(hashval, _before)| target_hash <= *hashval)
                        .map(|(_, before)| *before)
                        .unwrap_or_else(|| node_entries.last().unwrap().1);
                    lbn = child;
                } else {
                    return Ok(None);
                }
            }
            XFS_DIR2_LEAFN_MAGIC => {
                let count = u16::from_be_bytes([buf[12], buf[13]]) as usize;
                if count == 0 {
                    return Ok(None);
                }
                let leaf_entries = parse_dir_leaf_entries(&buf[16..], count);

                if let Ok(idx) =
                    leaf_entries.binary_search_by_key(&target_hash, |(hash, _addr)| *hash)
                {
                    let mut first = idx;
                    while first > 0 && leaf_entries[first - 1].0 == target_hash {
                        first -= 1;
                    }
                    let mut pos = first;
                    while pos < leaf_entries.len() && leaf_entries[pos].0 == target_hash {
                        let address = leaf_entries[pos].1;
                        let data_lbn = address >> 16;
                        let byte_off = (address & 0xFFFF) as usize;

                        let data_phys = logical_block_to_phys(data_lbn, extents, bs)
                            .ok_or(Error::InvalidArgument)?;
                        let mut data_buf = vec![0u8; bs as usize];
                        read_device_bytes(device, data_phys, &mut data_buf)?;

                        if let Some(entry) = super::types::parse_data_entry_at(&data_buf, byte_off)
                            && entry.name == target_name
                        {
                            return Ok(Some(entry.inode));
                        }
                        pos += 1;
                    }
                }
                return Ok(None);
            }
            XFS_DIR2_LEAF1_MAGIC => {
                return lookup_leaf_dir_by_hash(device, sb, extents, target_hash, target_name);
            }
            _ => return Ok(None),
        }
    }
}

// ── extended attributes ──────────────────────────────────────────────────

/// Parse shortform (inline) attribute entries from the attribute fork.
pub(super) fn parse_attr_sf_entries(
    buf: &[u8],
    fork_off: usize,
    inode_size: usize,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut result = Vec::new();
    if fork_off + 2 > inode_size || fork_off + 2 > buf.len() {
        return result;
    }
    let count = u16::from_be_bytes([buf[fork_off], buf[fork_off + 1]]) as usize;
    let mut pos = fork_off + 4;
    for _ in 0..count {
        if pos + 3 > buf.len() || pos + 3 > inode_size {
            break;
        }
        let namelen = buf[pos] as usize;
        let valuelen = buf[pos + 1] as usize;
        let _flags = buf[pos + 2];
        pos += 3;
        if pos + namelen + valuelen > buf.len() || pos + namelen + valuelen > inode_size {
            break;
        }
        let name = buf[pos..pos + namelen].to_vec();
        pos += namelen;
        let value = buf[pos..pos + valuelen].to_vec();
        pos += valuelen;
        result.push((name, value));
    }
    result
}

/// Parse name/value pairs from a single attribute leaf block.
pub(super) fn parse_attr_leaf_entries(
    data: &[u8],
    sb_block_size: usize,
) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut result = Vec::new();
    if data.len() < 18 {
        return result;
    }
    let magic = u16::from_be_bytes([data[8], data[9]]);
    if magic != XFS_ATTR_LEAF_MAGIC {
        return result;
    }
    let count = u16::from_be_bytes([data[12], data[13]]) as usize;
    if count == 0 {
        return result;
    }
    let entries_start = 20usize;
    if entries_start + count * 8 > sb_block_size || entries_start + count * 8 > data.len() {
        return result;
    }
    for i in 0..count {
        let off = entries_start + i * 8;
        if off + 6 > data.len() {
            break;
        }
        let _hash = read_be32(data, off);
        let nameidx = u16::from_be_bytes([data[off + 4], data[off + 5]]) as usize;
        if nameidx + 3 > data.len() || nameidx + 3 > sb_block_size {
            continue;
        }
        let namelen = data[nameidx] as usize;
        let valuelen = data[nameidx + 1] as usize;
        let _flags = data[nameidx + 2];
        let name_start = nameidx + 3;
        if name_start + namelen + valuelen > data.len()
            || name_start + namelen + valuelen > sb_block_size
        {
            continue;
        }
        let name = data[name_start..name_start + namelen].to_vec();
        let value = data[name_start + namelen..name_start + namelen + valuelen].to_vec();
        result.push((name, value));
    }
    result
}

/// Walk an attribute B+tree and collect every name/value pair.
pub(super) fn walk_attr_tree(
    device: &Arc<dyn BlockDevice>,
    sb: &Superblock,
    extents: &[Extent],
    root_lbn: u32,
) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
    let bs = sb.block_size as u64;
    let bs_usize = sb.block_size as usize;
    let mut result = Vec::new();
    let mut stack: Vec<u32> = vec![root_lbn];

    while let Some(lbn) = stack.pop() {
        let phys = logical_block_to_phys(lbn, extents, bs).ok_or(Error::InvalidArgument)?;
        let mut buf = vec![0u8; bs_usize];
        read_device_bytes(device, phys, &mut buf)?;

        if buf.len() < 16 {
            continue;
        }
        let magic = u16::from_be_bytes([buf[8], buf[9]]);

        match magic {
            XFS_DA_NODE_MAGIC => {
                if let Some((_level, node_entries)) = parse_node_block(&buf) {
                    for child in node_entries
                        .iter()
                        .map(|&(_, before)| before)
                        .collect::<Vec<_>>()
                        .iter()
                        .rev()
                    {
                        stack.push(*child);
                    }
                }
            }
            XFS_ATTR_LEAF_MAGIC => {
                result.extend(parse_attr_leaf_entries(&buf, bs_usize));
            }
            _ => {}
        }
    }

    Ok(result)
}

// ── raw byte I/O ─────────────────────────────────────────────────────────

/// Read `buf.len()` bytes at a byte offset, through whatever device sectors
/// the offset spans.
pub(super) fn read_device_bytes(
    device: &Arc<dyn BlockDevice>,
    byte_offset: u64,
    buf: &mut [u8],
) -> Result<()> {
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
    buf.copy_from_slice(&scratch[start_off..start_off + buf.len()]);
    Ok(())
}

// The btree reader is used by fs.rs's extent and directory paths; the two
// constant aliases below keep the format's magics named beside their v4/v5
// pairs in types.rs.
const _: () = {
    assert!(XFS_BMAP_MAGIC_V4 != 0, "the v4 BMAP magic is named");
};
