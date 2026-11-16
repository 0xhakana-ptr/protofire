//! fs/src/ntfs/volume/index.rs
//!
//! The index: the B-tree a directory's names live in, its blocks, its bitmap,
//! and the splits and merges a name being added or removed produces.
//!
//! One `impl NtfsFs` block of several: Rust lets a type's inherent methods be
//! spread across the files of a module, and this module is split by what the
//! methods do rather than by how long the file is.  Nothing here is gated, the
//! whole volume is one `impl` family, and the fields these methods reach are
//! private to `volume/mod.rs` and visible here because a child module sees its
//! parent's items.

use alloc::string::String;
use alloc::vec::Vec;

use abi::Error;
use abi::Result;

use super::super::fs;
use super::super::fs::parse_attributes;
use super::super::fs::parse_index_node;
use super::super::types::*;

use super::IndexHome;
use super::IndexKey;
use super::IndexLeaf;
use super::IndexParent;
use super::MAX_ANCESTORS;
use super::MAX_INDEX_DEPTH;
use super::NtfsFs;
use super::ROOT_RECORD;
use super::allocation_list_value;
use super::bytes_in_use;
use super::compare_names;
use super::node_entries_with;
use super::own_attribute;
use super::refuse_a_stream_this_driver_cannot_read;

use super::NewRecord;

impl NtfsFs {
    /// The entries a directory holds, whatever shape its index is in.
    ///
    /// A directory's index is a tree.  Its root lives in the record's
    /// `$INDEX_ROOT`, and a directory that has children keeps the entries
    /// themselves in an `$INDEX_ALLOCATION` whose blocks the root's last entry
    /// points at by virtual cluster number, which is the shape a real volume
    /// uses even for a single file, so this walks the tree rather than reading
    /// one node.
    pub(crate) fn directory_entries(&self, record_number: u64) -> Result<Vec<(String, u64)>> {
        let attributes = self.attributes_of(record_number)?;
        let root = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_INDEX_ROOT)
            .ok_or(Error::NotFound)?;
        let mut found: Vec<(FileName, u64)> = Vec::new();
        self.walk_index(&attributes, &root.content, 16, 0, &mut found)?;

        // One file can have more than one name, a short one and a long one
        // and the listing keeps the preferred of them.
        let mut best: Vec<(FileName, u64)> = Vec::new();
        for (name, record) in found {
            match best.iter().position(|(_, held)| *held == record) {
                Some(index) => {
                    if name.preferred_namespace() && !best[index].0.preferred_namespace() {
                        best[index] = (name, record);
                    }
                }
                None => best.push((name, record)),
            }
        }
        Ok(best
            .into_iter()
            .map(|(name, record)| (name.name, record))
            .collect())
    }

    /// Every name an index node holds, in the order the tree keeps them.
    ///
    /// A node's entries hold its children between its own keys: an entry that
    /// points at a child carries a key, that child holds the keys *less than*
    /// it, and the key is the child's successor, so a walk takes the child
    /// first and the key after it, which is the order the names sort in.  The
    /// last entry of an internal node has no key and points at the child with
    /// the largest names.  A directory's own "." and ".." are links and not
    /// names in it, whichever of them a volume stores.
    fn walk_index(
        &self,
        attributes: &[ParsedAttr],
        buffer: &[u8],
        node: usize,
        depth: u32,
        found: &mut Vec<(FileName, u64)>,
    ) -> Result<()> {
        if depth > MAX_INDEX_DEPTH {
            return Err(Error::InvalidArgument);
        }
        for entry in parse_index_node(buffer, node).entries {
            if let Some(child) = entry.child {
                let block = self.read_index_block(attributes, child)?;
                self.walk_index(attributes, &block, 24, depth + 1, found)?;
            }
            if let Some(name) = entry.name
                && name.name != "."
                && name.name != ".."
            {
                found.push((name, entry.reference));
            }
        }
        Ok(())
    }

    pub(crate) fn read_index_block(&self, attributes: &[ParsedAttr], vcn: u64) -> Result<Vec<u8>> {
        let info = self.info.lock();
        let allocation = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_INDEX_ALLOC && !attr.data_runs.is_empty())
            .ok_or(Error::NotFound)?;
        // A **compressed** (or encrypted) index is the same flag a file's
        // `$DATA` carries, and what its runs hold is not index blocks: it is
        // an LZNT1 stream, so a reader that followed them would answer with
        // blocks that are not there.  RFC 0013 named the question and left it;
        // the answer is the stream's own, refuse it, rather than misread it.
        refuse_a_stream_this_driver_cannot_read(allocation)?;
        let mut block = alloc::vec![0u8; info.index_block_size as usize];
        fs::read_from_runs(
            &self.device,
            &info,
            &allocation.data_runs,
            allocation.data_size as u64,
            vcn * info.cluster_size as u64,
            &mut block,
        )?;

        // The block carries its own update sequence array, and the volume's
        // sector size says where its sectors end.
        let usa_offset = u16::from_le_bytes([block[4], block[5]]) as usize;
        let usa_count = u16::from_le_bytes([block[6], block[7]]) as usize;
        fs::apply_usa_fixup(
            &mut block,
            usa_offset,
            usa_count,
            info.bs.bytes_per_sector as usize,
        )?;
        Ok(block)
    }

    /// One of a directory's index blocks, and the home a change to its entries
    /// is written back through.
    fn read_index_block_home(
        &self,
        attributes: &[ParsedAttr],
        vcn: u64,
    ) -> Result<(Vec<u8>, IndexHome)> {
        let allocation = attributes
            .iter()
            .find(|attribute| {
                attribute.attr_type == ATTR_TYPE_INDEX_ALLOC && !attribute.data_runs.is_empty()
            })
            .ok_or(Error::NotFound)?;
        // A block's node begins after `INDX`, its update sequence array and its
        // virtual cluster number, and it has the rest of the block.
        let block = self.read_index_block(attributes, vcn)?;
        let usa_offset = u16::from_le_bytes([block[4], block[5]]) as usize;
        let usa_count = u16::from_le_bytes([block[6], block[7]]) as usize;
        Ok((
            block,
            IndexHome::Block {
                vcn,
                runs: allocation.data_runs.clone(),
                usa_offset,
                usa_count,
            },
        ))
    }

    /// How many clusters one index block is, which is what a block's virtual
    /// cluster number counts in.
    fn clusters_per_index_block(&self) -> u64 {
        let info = self.info.lock();
        u64::from(info.index_block_size / info.cluster_size.max(1))
    }

    /// The node a directory's entries are in, as the buffer it lives in.
    ///
    /// A directory's entries are in its index root, or in the
    /// `$INDEX_ALLOCATION` block its root points at, and a block that has
    /// children points at another.  The entries are in the node that has *no*
    /// children, which is where this descends to; the buffer comes back with
    /// the node's place and its room, so a change to the entries can be
    /// written back where they belong.
    /// A tree routes by key: an internal node's entry carries a key and the
    /// child it points at, that child holds the keys *less than* the entry's,
    /// and the last entry has no key and points at the child with the largest
    /// ones.  A name that *is* a key lives in the node above the blocks, which
    /// is where a promoted key goes when a block is split, and that is the one
    /// answer this walk does not give.
    /// The record a directory's index *root* lives in, and where its node
    /// begins in those bytes.
    ///
    /// The node's place is worked out from a **fresh** read of the record
    /// every time rather than remembered, because a change to another
    /// attribute of the same record moves it: a run list that outgrows the
    /// room its attribute has moves that attribute to the end, which is what
    /// growing `$INDEX_ALLOCATION` does, and the root's node goes with it.
    /// Writing a node back at the offset a walk once measured would put the
    /// record back the way it was and undo the growth.
    fn index_root_node(&self, holder: u64) -> Result<(Vec<u8>, usize)> {
        let record = self.read_mft_record(holder)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        // An index *root*'s node begins after the root header, the indexed
        // attribute's type, the collation rule and the buffer size, and the
        // value it sits in is the resident attribute the record gives it.
        let root = self
            .attributes_of(holder)?
            .into_iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_INDEX_ROOT)
            .ok_or(Error::InvalidArgument)?;
        let node = header.size() as usize + root.offset + root.value_offset + 16;
        Ok((record, node))
    }

    /// The record a directory's index root lives in, which an
    /// `$ATTRIBUTE_LIST` can have made an extension record of the directory's.
    fn index_root_holder(&self, parent_record: u64) -> Result<u64> {
        Ok(self
            .attributes_of(parent_record)?
            .into_iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_INDEX_ROOT)
            .ok_or(Error::NotFound)?
            .holder)
    }

    /// Whether the record an index root lives in has the room for the entries
    /// the node would hold: the value's own bytes, and what the record has
    /// left.
    ///
    /// This is [`Self::write_index_leaf`]'s measurement, taken on its own so a
    /// split can settle it **before** it claims anything.
    fn index_root_has_room(
        &self,
        holder: u64,
        buffer: &[u8],
        node: usize,
        entries: &[Vec<u8>],
    ) -> Result<bool> {
        let entries_offset = u32::from_le_bytes([
            buffer[node],
            buffer[node + 1],
            buffer[node + 2],
            buffer[node + 3],
        ]) as usize;
        let used = entries_offset + entries.iter().map(|entry| entry.len()).sum::<usize>();
        let record = self.read_mft_record(holder)?;
        let attributes = self.attributes_of(holder)?;
        let root = own_attribute(holder, &attributes, ATTR_TYPE_INDEX_ROOT)?;
        Ok(16 + used <= root.content.len() + (record.len() - bytes_in_use(&record)))
    }

    fn index_leaf(&self, parent_record: u64, name: &str) -> Result<IndexLeaf> {
        let upcase = self.upcase_table();
        let attributes = self.attributes_of(parent_record)?;
        let root = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_INDEX_ROOT)
            .ok_or(Error::NotFound)?;
        // The node's own offset is an offset in the bytes of the record that
        // holds the attribute, which an `$ATTRIBUTE_LIST` can have made an
        // extension record of the parent's.
        let holder = root.holder;
        if holder == u64::MAX {
            // A root split across records is one no single record's bytes are.
            return Err(Error::NotImplemented);
        }
        let (mut buffer, mut node) = self.index_root_node(holder)?;
        let mut home = IndexHome::Record { holder };
        let mut ancestors: Vec<IndexParent> = Vec::new();

        let mut depth = 0;
        while parse_index_node(&buffer, node).has_children {
            if depth >= MAX_INDEX_DEPTH {
                return Err(Error::InvalidArgument);
            }
            depth += 1;
            let parsed = parse_index_node(&buffer, node);
            // The first child whose key is *greater* than the name holds it:
            // that child keeps the keys less than its key.  A name equal to a
            // key is that key, and lives here in the node.
            let mut chosen = None;
            for entry in &parsed.entries {
                let Some(key) = &entry.name else { continue };
                if compare_names(&key.name, name, &upcase).is_gt() {
                    chosen = Some((entry.child, entry.offset));
                    break;
                }
                if compare_names(&key.name, name, &upcase).is_eq() {
                    // The name is this node's own key: it lives here, above the
                    // blocks, and the walk does not go past it.  Where that is
                    // is what a change needs, so the node comes back with the
                    // entry it carries.
                    let key = IndexKey {
                        buffer: buffer.clone(),
                        node,
                        home: home.clone(),
                        offset: entry.offset,
                        length: entry.length,
                    };
                    return Ok(IndexLeaf {
                        ancestors,
                        buffer,
                        node,
                        home,
                        key: Some(key),
                    });
                }
            }
            // Nothing greater: the last child, the one with no key, holds the
            // largest names.
            let (pointer, before) = match chosen {
                Some(chosen) => chosen,
                None => {
                    let last = parsed
                        .entries
                        .iter()
                        .rfind(|entry| entry.child.is_some())
                        .ok_or(Error::InvalidArgument)?;
                    (last.child, last.offset)
                }
            };
            let pointer = pointer.ok_or(Error::InvalidArgument)?;
            ancestors.push(IndexParent {
                buffer: buffer.clone(),
                node,
                before,
                home: home.clone(),
            });
            let (block, block_home) = self.read_index_block_home(&attributes, pointer)?;
            home = block_home;
            node = 24;
            buffer = block;
        }
        Ok(IndexLeaf {
            buffer,
            node,
            home,
            ancestors,
            key: None,
        })
    }

    /// Write a directory's index entries back where they live.
    ///
    /// A node's entries are replaced as a run, so what a caller hands over is
    /// the run itself, the entries that were there, or the ones that should
    /// be, with the node's own terminator last.
    ///
    /// The two places an index lives differ in what "room" means.  A block has
    /// what is left of the block.  An index *root* has the value the record
    /// gives it, and that value **grows** when it has to: an attribute inside a
    /// record can be as long as the record has room for, so the value's bytes
    /// extend, everything after the attribute shifts up with the end marker,
    /// and the record goes back whole.  The record that holds the attribute is
    /// the buffer, which an `$ATTRIBUTE_LIST` can have made an extension record
    /// of the parent's.  A record with no room refuses (`NoSpace`), and the
    /// caller makes room by moving attributes out of it.
    fn write_index_leaf(
        &self,
        _parent_record: u64,
        buffer: &mut [u8],
        node: usize,
        entries: &[Vec<u8>],
        home: &IndexHome,
    ) -> Result<()> {
        match home {
            IndexHome::Record { holder } => {
                let header = MftRecordHeader::parse(buffer).ok_or(Error::InvalidArgument)?;
                let attributes = self.attributes_of(*holder)?;
                let root = own_attribute(*holder, &attributes, ATTR_TYPE_INDEX_ROOT)?;
                let attr_at = header.size() as usize + root.offset;

                // What the node's entries come to, and whether the record has
                // the room for that much value.
                let entries_offset = u32::from_le_bytes([
                    buffer[node],
                    buffer[node + 1],
                    buffer[node + 2],
                    buffer[node + 3],
                ]) as usize;
                let used = entries_offset
                    + entries
                        .iter()
                        .try_fold(0usize, |total, entry| total.checked_add(entry.len()))
                        .ok_or(Error::InvalidArgument)?;
                let value_len = 16 + used;
                if !self.index_root_has_room(*holder, buffer, node, entries)? {
                    return Err(Error::NoSpace);
                }

                // The attribute as it should be: the longer value, its node's
                // sizes following, and the entries inside it.
                let mut attribute = buffer[attr_at..attr_at + root.attr_len].to_vec();
                let attr_len = (root.value_offset + value_len).div_ceil(8) * 8;
                attribute.resize(attr_len, 0);
                attribute[4..8].copy_from_slice(&(attr_len as u32).to_le_bytes());
                attribute[16..20].copy_from_slice(&(value_len as u32).to_le_bytes());
                fs::write_index_entries(
                    &mut attribute[root.value_offset..root.value_offset + value_len],
                    16,
                    value_len - 16,
                    entries,
                )?;

                // Everything after the attribute, the end marker included
                // shifts up by what it grew.
                let end = bytes_in_use(buffer);
                let mut rebuilt = buffer[..attr_at].to_vec();
                rebuilt.extend_from_slice(&attribute);
                rebuilt.extend_from_slice(&buffer[attr_at + root.attr_len..end]);
                let rebuilt_used = rebuilt.len();
                rebuilt.resize(buffer.len(), 0);
                rebuilt[24..28].copy_from_slice(&(rebuilt_used as u32).to_le_bytes());

                let (at, sector) = {
                    let info = self.info.lock();
                    (
                        self.record_offset(&info, *holder)?,
                        info.bs.bytes_per_sector as usize,
                    )
                };
                fs::pack_usa(
                    &mut rebuilt,
                    header.usa_offset as usize,
                    header.usa_count as usize,
                    sector,
                );
                fs::write_device_bytes(&self.device, at, &rebuilt)?;
                self.mft_cache.lock().insert(*holder, rebuilt);
            }
            IndexHome::Block {
                vcn,
                runs,
                usa_offset,
                usa_count,
            } => {
                fs::write_index_entries(buffer, node, buffer.len() - 24, entries)?;
                let (cluster_size, sector) = {
                    let info = self.info.lock();
                    (
                        u64::from(info.cluster_size),
                        info.bs.bytes_per_sector as usize,
                    )
                };
                fs::pack_usa(buffer, *usa_offset, *usa_count, sector);
                let info = self.info.lock();
                fs::write_to_runs(&self.device, &info, runs, vcn * cluster_size, buffer)?;
            }
        }
        Ok(())
    }

    /// Move one bit of a directory's `$INDEX_ALLOCATION` bitmap, which is the
    /// list of which of its blocks hold a node in use.
    ///
    /// A block a split makes needs a bit the bitmap may not have a *byte* for:
    /// the bitmap names eight blocks per byte, so the block numbered `bit`
    /// needs `bit / 8 + 1` bytes of it.  A bitmap that is short **grows** to
    /// what the bit needs, the value longer where it lives, and the record
    /// that holds it makes room for the growth when it has none, the way any
    /// record with no room does.  A bitmap that is a *file* of its own would be
    /// grown by a step of its own, and refuses (`NotImplemented`).
    ///
    /// Lowering a bit is the same walk without the growth: a byte the bitmap
    /// does not have names no block, so there is nothing there to lower.  A
    /// block that goes back is also the moment the allocation's **tail** may be
    /// given back, which is [`Self::shrink_index_allocation_tail`]'s.
    pub(crate) fn set_index_block_bit(
        &self,
        parent_record: u64,
        bit: u64,
        in_use: bool,
    ) -> Result<()> {
        self.write_index_block_bit(parent_record, bit, in_use)?;
        if !in_use {
            self.shrink_index_allocation_tail(parent_record)?;
        }
        Ok(())
    }

    /// Move the bit itself, without the shrink a lowering may allow.
    fn write_index_block_bit(&self, parent_record: u64, bit: u64, in_use: bool) -> Result<()> {
        let byte = (bit / 8) as usize;
        let mask = 1u8 << (bit % 8);
        for attempt in 0..2 {
            let bitmap = self
                .attributes_of(parent_record)?
                .into_iter()
                .find(|attribute| attribute.attr_type == ATTR_TYPE_BITMAP)
                .ok_or(Error::NotFound)?;
            let mut bits = self.index_bitmap_bytes(&bitmap)?;
            if byte >= bits.len() && !in_use {
                return Ok(());
            }
            let grew = byte >= bits.len();
            if grew {
                bits.resize(byte + 1, 0);
            }
            if in_use {
                bits[byte] |= mask;
            } else {
                bits[byte] &= !mask;
            }
            if bitmap.data_runs_offset.is_some() {
                // A bitmap that is a **file** of its own: the bit goes where
                // its runs say, and a byte it did not have grows the value and
                // its sizes with it, taking clusters for it when the runs it
                // has are full.
                self.write_index_bitmap(&bitmap, &bits, grew)?;
                return Ok(());
            }
            match self.replace_value(parent_record, ATTR_TYPE_BITMAP, &bits) {
                Ok(()) => return Ok(()),
                Err(Error::NoSpace) if attempt == 0 => {
                    // The value is longer than the record has room for: the
                    // record makes room, and the bit goes in where the value
                    // landed.
                    self.make_room(bitmap.holder, ATTR_TYPE_BITMAP)?;
                }
                Err(error) => return Err(error),
            }
        }
        Err(Error::NoSpace)
    }

    /// A directory's index bitmap, as the attribute holds it: the value in the
    /// record, or the bytes where the runs of a bitmap that is a file say.
    fn index_bitmap_bytes(&self, bitmap: &ParsedAttr) -> Result<Vec<u8>> {
        if bitmap.data_runs_offset.is_none() {
            return Ok(bitmap.content.clone());
        }
        let info = self.info.lock();
        let mut bits = alloc::vec![0u8; bitmap.data_size as usize];
        fs::read_from_runs(
            &self.device,
            &info,
            &bitmap.data_runs,
            u64::from(bitmap.data_size),
            0,
            &mut bits,
        )?;
        Ok(bits)
    }

    /// Write an index bitmap that is a file back where its runs say, growing
    /// the value, and the clusters behind it, when it needs a byte it did
    /// not have.
    ///
    /// A growth takes clusters of its own when the runs the bitmap has cannot
    /// hold the new length: the bitmap is a file like any other, so its run
    /// list is extended the way [`Self::write_grown_data`] extends one, and the
    /// bytes between the old length and the new are written as zeros, a
    /// bitmap's bytes are its bits, so what it never wrote reads as free.
    fn write_index_bitmap(&self, bitmap: &ParsedAttr, bits: &[u8], grew: bool) -> Result<()> {
        let cluster_size = u64::from(self.info.lock().cluster_size);
        if !grew {
            // The same length: the value as it is, back where it lives.
            return self.write_index_bitmap_bytes(bitmap, bits);
        }

        let held: u64 = bitmap
            .data_runs
            .iter()
            .map(|run| run.cluster_count)
            .sum::<u64>();
        let wanted = (bits.len() as u64).div_ceil(cluster_size);
        let mut runs = bitmap.data_runs.clone();
        if wanted > held {
            let claim = wanted - held;
            let first = self.claim_clusters(claim)?;
            let continues = runs
                .last()
                .is_some_and(|last| last.lcn >= 0 && last.lcn as u64 + last.cluster_count == first);
            if continues {
                runs.last_mut()
                    .expect("a last run that was just looked at")
                    .cluster_count += claim;
            } else {
                runs.push(DataRun {
                    lcn: first as i64,
                    cluster_count: claim,
                });
            }
        }
        let allocated = (held.max(wanted) * cluster_size) as u32;
        let zeros = alloc::vec![0u8; bits.len() - bitmap.data_size as usize];
        self.write_grown_data(
            bitmap.holder,
            bitmap,
            &runs,
            allocated,
            bits.len() as u32,
            &zeros,
        )?;
        self.write_index_bitmap_bytes(bitmap, bits)
    }

    /// Put the bitmap's bytes where its runs say.
    fn write_index_bitmap_bytes(&self, bitmap: &ParsedAttr, bits: &[u8]) -> Result<()> {
        let info = self.info.lock();
        fs::write_to_runs(&self.device, &info, &bitmap.data_runs, 0, bits)?;
        Ok(())
    }

    /// The first block the directory's index bitmap says is **free**, among the
    /// blocks its allocation has.
    ///
    /// A block that a deletion gave back is a block the tree takes again before
    /// it grows the allocation: a directory whose index only ever grew would
    /// keep the volume's clusters claimed for blocks that nothing is stored in,
    /// and a block that is already the allocation's costs nothing to use again.
    /// A byte the bitmap does not have names no block, and a block nothing
    /// names is free.
    ///
    /// The bitmap is read where it lives: the value in the record, or the bytes
    /// a bitmap that is a *file* of its own keeps where its runs say.
    fn first_free_index_block(&self, parent_record: u64, blocks: u64) -> Result<Option<u64>> {
        let Some(bitmap) = self
            .attributes_of(parent_record)?
            .into_iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_BITMAP)
        else {
            return Ok(None);
        };
        let bits = self.index_bitmap_bytes(&bitmap)?;
        for block in 0..blocks {
            let byte = (block / 8) as usize;
            if byte >= bits.len() || bits[byte] & (1 << (block % 8)) == 0 {
                return Ok(Some(block));
            }
        }
        Ok(None)
    }

    /// Give the **tail** of a directory's `$INDEX_ALLOCATION` back to the
    /// volume, once the blocks it names are free.
    ///
    /// A block that goes back keeps its clusters, they stay part of the
    /// allocation, a free block inside it, until the blocks at *its* end are
    /// the free ones: the allocation's last blocks are then not ones the tree
    /// can reach, and the clusters behind them are clusters the volume is
    /// holding for nothing.  What leaves is one whole block's worth of trailing
    /// free blocks at a time, the allocation's data size always divides into
    /// whole blocks, which is the shape a split writes and a reader checks
    /// and the run list shortens by what they held.
    ///
    /// Only blocks the bitmap says are **free** go back.  A block the bitmap
    /// says is in use but the tree does not point at is left alone, for the
    /// same reason [`Self::first_free_index_block`] leaves one to a split:
    /// telling a leaked block from a live one is a walk of the whole tree, a
    /// repair rather than a write.  The bitmap keeps whatever bytes it has,
    /// so a block past the new end is re-taken by the next split the way any
    /// byte it already holds is.
    ///
    /// The record goes first and the clusters second, which is the order every
    /// other shrink takes: the write drops the run list, so a crash between
    /// the two leaves clusters nothing names, a leak, rather than an
    /// attribute naming clusters the volume has handed out again.
    fn shrink_index_allocation_tail(&self, parent_record: u64) -> Result<()> {
        let per_block = self.clusters_per_index_block();
        if per_block == 0 {
            return Ok(());
        }
        let (block_size, cluster_size) = {
            let info = self.info.lock();
            (
                u64::from(info.index_block_size),
                u64::from(info.cluster_size),
            )
        };
        let attributes = self.attributes_of(parent_record)?;
        let Some(allocation) = attributes.iter().find(|attribute| {
            attribute.attr_type == ATTR_TYPE_INDEX_ALLOC && !attribute.data_runs.is_empty()
        }) else {
            return Ok(());
        };
        let data_size = u64::from(allocation.data_size);
        if allocation.holder == u64::MAX
            || data_size == 0
            || data_size % block_size != 0
            || allocation.data_runs.iter().any(|run| run.lcn < 0)
        {
            // A split across records is no one record's to rewrite, and an
            // allocation whose size is not whole blocks, or that names a hole
            //, is not the shape a split writes.
            return Ok(());
        }
        let blocks = data_size / block_size;
        let Some(bitmap) = attributes
            .iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_BITMAP)
        else {
            return Ok(());
        };
        let bits = self.index_bitmap_bytes(bitmap)?;

        // How many of the **leading** blocks are still live: the allocation
        // keeps them, and the free run at its end is what goes.  A block is
        // what goes only when the bitmap says it is free *and* the bitmap
        // reaches it: a byte the bitmap does not have names no block, but it
        // also does not say the block is free, and freeing the clusters of a
        // block on a bitmap that does not cover it is the direction a shrink
        // must not take, a split taking such a block is harmless, giving its
        // clusters back is not.
        let mut keep = blocks;
        while keep > 0 {
            let block = keep - 1;
            let byte = (block / 8) as usize;
            let free = byte < bits.len() && bits[byte] & (1 << (block % 8)) == 0;
            if !free {
                break;
            }
            keep -= 1;
        }
        // Nothing free at the end, or every block free, and a tree whose root
        // points at a block keeps at least one, which is a conversion of its
        // own and not this shrink.
        if keep == blocks || keep == 0 {
            return Ok(());
        }

        // The clusters that stay, and the runs that leave with the tail.  A
        // block is `per_block` clusters of the allocation's virtual space, so
        // the boundary is a cluster count.
        let keep_clusters = keep * per_block;
        let mut runs: Vec<DataRun> = Vec::new();
        let mut freed: Vec<DataRun> = Vec::new();
        let mut left = keep_clusters;
        for run in &allocation.data_runs {
            if left == 0 {
                freed.push(run.clone());
                continue;
            }
            if run.cluster_count <= left {
                runs.push(run.clone());
                left -= run.cluster_count;
            } else {
                runs.push(DataRun {
                    lcn: run.lcn,
                    cluster_count: left,
                });
                freed.push(DataRun {
                    lcn: run.lcn + left as i64,
                    cluster_count: run.cluster_count - left,
                });
                left = 0;
            }
        }
        if left > 0 || freed.is_empty() {
            return Ok(());
        }

        let allocated = keep_clusters * cluster_size;
        let length = keep * block_size;
        self.write_grown_data(
            allocation.holder,
            allocation,
            &runs,
            allocated as u32,
            length as u32,
            &[],
        )?;
        self.free_clusters(&freed)
    }

    /// Put a name into a directory's index, where the index's order puts it.
    ///
    /// The entries a node holds are rewritten as a run, with the new one in
    /// the place its folded name sorts to and the node's terminator last: an
    /// index is ordered, and an entry that breaks the order is not one a real
    /// NTFS would have written.  A node that has no room for the entry
    /// refuses (`NoSpace`) rather than writing past what it owns.
    ///
    /// What answers that refusal is the shape of the node.  A root whose
    /// record has something to spare moves into a record of its own
    /// ([`Self::make_room`]), and the insertion is worked out again there.  A
    /// root that cannot grow in *any* record, one already in a record of its
    /// own, or one that filled the record it was moved to, hands its entries
    /// to an [`Self::entries_leave_for_a_block`] of their own, and the
    /// insertion lands in the block.  A *block* with no room is a split,
    /// which is not built, and refuses.
    pub(crate) fn index_insert(
        &self,
        parent_record: u64,
        name: &str,
        reference: u64,
        directory: bool,
        size: u64,
    ) -> Result<()> {
        let parent = self.read_mft_record(parent_record)?;
        let parent_sequence = u16::from_le_bytes([parent[16], parent[17]]);
        let upcase = self.upcase_table();
        let entry = fs::index_entry(
            name,
            reference,
            parent_record | (u64::from(parent_sequence) << 48),
            directory,
            size,
        );

        // Two attempts: a directory whose record has no room for the longer
        // value makes it the way a file does, the index root moves into a
        // record of its own, and that changes the node's place, so the whole
        // insertion is worked out again.
        for attempt in 0..2 {
            let mut leaf = self.index_leaf(parent_record, name)?;
            if leaf.key.is_some() {
                // The name is one of the nodes' own keys, which is where a
                // promoted key lives: it is there.
                return Err(Error::AlreadyExists);
            }
            let parsed = parse_index_node(&leaf.buffer, leaf.node);
            let Some((terminator, rest)) = parsed.entries.split_last() else {
                return Err(Error::InvalidArgument);
            };
            // The terminator is the entry no name follows, and it stays last.
            if terminator.name.is_some() {
                return Err(Error::InvalidArgument);
            }

            let mut raws: Vec<Vec<u8>> = rest
                .iter()
                .map(|entry| leaf.buffer[entry.offset..entry.offset + entry.length].to_vec())
                .collect();
            let place = rest
                .iter()
                .position(|existing| {
                    existing.name.as_ref().is_some_and(|existing| {
                        compare_names(name, &existing.name, &upcase).is_lt()
                    })
                })
                .unwrap_or(rest.len());
            raws.insert(place, entry.clone());
            raws.push(
                leaf.buffer[terminator.offset..terminator.offset + terminator.length].to_vec(),
            );

            match self.write_index_leaf(
                parent_record,
                &mut leaf.buffer,
                leaf.node,
                &raws,
                &leaf.home,
            ) {
                Ok(()) => return Ok(()),
                Err(Error::NoSpace) if attempt == 0 => match &leaf.home {
                    IndexHome::Record { holder } => {
                        let holder = *holder;
                        if self.base_record(holder).is_some() {
                            // The root already lives in a record of its own,
                            // and no extension extends another: the entries
                            // leave for a block, which is the format's answer
                            // to a root that cannot grow anywhere.
                            self.entries_leave_for_a_block(parent_record, &raws)?;
                            return Ok(());
                        }
                        self.make_room(holder, ATTR_TYPE_INDEX_ROOT)?;
                    }
                    // A block that has no room is split: its middle key is
                    // promoted into the node above it, and half its entries
                    // move to a block of their own.
                    IndexHome::Block { .. } => {
                        return self.split_index_block(parent_record, name, &raws);
                    }
                },
                Err(Error::NoSpace) if attempt == 1 => match leaf.home {
                    IndexHome::Record { .. } => {
                        // The root moved into a record of its own and filled
                        // that too: the entries leave for a block.
                        self.entries_leave_for_a_block(parent_record, &raws)?;
                        return Ok(());
                    }
                    IndexHome::Block { .. } => {
                        return self.split_index_block(parent_record, name, &raws);
                    }
                },
                Err(error) => return Err(error),
            }
        }
        Err(Error::NoSpace)
    }

    /// Split a full index block in two, promoting the key between the halves.
    ///
    /// A block with no room for a name is what the format splits: half the
    /// entries go to a block of their own, the entry between the halves becomes
    /// a **key of the node above**, the entry the walk came through keeps that
    /// node's keys *greater* than it, and the index bitmap gains a bit for the
    /// new block.
    ///
    /// A node above that cannot hold the key is the node above's own turn: a
    /// **record**'s index root with no room makes room in its record, and a
    /// **block** with no room is split in turn, which is
    /// [`Self::split_a_block`] called on it.
    fn split_index_block(&self, parent_record: u64, name: &str, entries: &[Vec<u8>]) -> Result<()> {
        for attempt in 0..2 {
            // The walk is done again for the second attempt rather than kept:
            // making room moves the attributes the record holds, and with them
            // every offset the walk's buffers were read at.
            let leaf = self.index_leaf(parent_record, name)?;
            if leaf.key.is_some() {
                return Err(Error::AlreadyExists);
            }
            let IndexHome::Block { .. } = &leaf.home else {
                return Err(Error::InvalidArgument);
            };
            match self.room_above(&leaf, entries)? {
                None => return self.split_a_block(parent_record, &leaf, entries),
                Some(holder) if attempt == 0 => {
                    self.make_room(holder, ATTR_TYPE_INDEX_ROOT)?;
                }
                Some(_) => return Err(Error::NoSpace),
            }
        }
        Err(Error::NoSpace)
    }

    /// Whether the split will have the room it needs **above** the leaf, and
    /// which record has to make room when it will not.
    ///
    /// A split promotes one entry per level: the leaf's middle key goes into
    /// the node above it, and a node above that is a **block** with no room is
    /// split in turn, so *its* middle key goes into the node above that, and so
    /// on up.  What each level would hold is therefore known before anything is
    /// written, the level's own entries, and the one key it takes from below
    /// and so is whether it fits.
    ///
    /// This is asked **before** the split claims anything, because a claim is
    /// not something this driver can hand back: shrinking an allocation is a
    /// step it does not take.  A **record**'s index root with no room is that
    /// record's, which the caller makes room in before the split is worked out
    /// again.
    fn room_above(&self, leaf: &IndexLeaf, entries: &[Vec<u8>]) -> Result<Option<u64>> {
        let Some((_, names)) = entries.split_last() else {
            return Err(Error::InvalidArgument);
        };
        if names.is_empty() {
            return Err(Error::NoSpace);
        }
        let mut promoted = names[names.len() / 2].clone();
        for parent in leaf.ancestors.iter().rev() {
            // Its own entries, and the key this split would put in it.  The
            // key's own bytes are what the room is measured in, so the child it
            // points at does not matter here.
            let separator = fs::index_separator(&promoted, 0)?;
            let (wanted, inserted) = node_entries_with(parent, &separator)?;
            if !inserted {
                return Err(Error::InvalidArgument);
            }
            let fits = match &parent.home {
                IndexHome::Record { holder } => {
                    let (buffer, node) = self.index_root_node(*holder)?;
                    self.index_root_has_room(*holder, &buffer, node, &wanted)?
                }
                IndexHome::Block { .. } => {
                    let entries_offset = u32::from_le_bytes([
                        parent.buffer[parent.node],
                        parent.buffer[parent.node + 1],
                        parent.buffer[parent.node + 2],
                        parent.buffer[parent.node + 3],
                    ]) as usize;
                    entries_offset + wanted.iter().map(|entry| entry.len()).sum::<usize>()
                        <= parent.buffer.len() - 24
                }
            };
            if fits {
                return Ok(None);
            }
            match &parent.home {
                IndexHome::Record { holder } => return Ok(Some(*holder)),
                // A block that does not fit is split in turn, and the key *it*
                // promotes is the middle of what it would have held.
                IndexHome::Block { .. } => {
                    let Some((_, names)) = wanted.split_last() else {
                        return Err(Error::InvalidArgument);
                    };
                    if names.is_empty() {
                        return Err(Error::NoSpace);
                    }
                    promoted = names[names.len() / 2].clone();
                }
            }
        }
        Ok(None)
    }

    /// The split itself: the block `leaf` is in is halved, its middle key goes
    /// to the node above it, and a node above that is a full **block** is split
    /// in turn, the key it promotes is carried up into the node above *it*.
    ///
    /// The writes are ordered by what a crash leaves, and every window is one a
    /// mount reads.  The allocation and the bitmap first: a block nothing
    /// points at is a leak, the harmless direction.  The new block next,
    /// still unreachable, so its entries are in the old block *too* and a
    /// listing shows each name once (one name, one record) while a lookup
    /// finds the copy that is reachable.  The node above after that, whose
    /// new key is what makes the new block reachable; a node above that is
    /// itself split carries this block's key in its entries, so this block's
    /// new block stays unreachable until the whole chain above it is written.
    /// The old block last, with the half that stayed in it.
    ///
    /// The room the key needs is settled **before** anything is claimed: what
    /// this claims it cannot hand back, because shrinking an allocation is a
    /// step this driver does not take.  A node above that is a **record**'s
    /// index root makes room in its record first when it has none; a block is
    /// split in turn, and the key *it* promotes is the next level's problem.
    fn split_a_block(
        &self,
        parent_record: u64,
        leaf: &IndexLeaf,
        entries: &[Vec<u8>],
    ) -> Result<()> {
        let Some(parent) = leaf.ancestors.last() else {
            return Err(Error::InvalidArgument);
        };
        let (block_size, cluster_size, sector_size) = {
            let info = self.info.lock();
            (
                info.index_block_size,
                info.cluster_size,
                usize::from(info.bs.bytes_per_sector),
            )
        };
        let per_block = u64::from(block_size / cluster_size.max(1));
        if per_block == 0 {
            return Err(Error::NotImplemented);
        }

        // The names, and the terminator that is not one.  The entry between
        // the halves is the key the node above learns, and it leaves both.
        let Some((terminator, names)) = entries.split_last() else {
            return Err(Error::InvalidArgument);
        };
        if names.is_empty() {
            return Err(Error::NoSpace);
        }
        let middle = names.len() / 2;
        let promoted = names[middle].clone();

        // Where the half that leaves goes: a block the bitmap says is free
        // is one a deletion gave back, and the tree takes it before the
        // allocation grows.  With none to take, the block is the
        // allocation's *next*, which is the number its size names, the
        // leaf's own number plus one is that only while the leaf is the last
        // block, and a tree's blocks are reached in key order, which need
        // not be number order.
        let allocation = self
            .attributes_of(parent_record)?
            .into_iter()
            .find(|attribute| {
                attribute.attr_type == ATTR_TYPE_INDEX_ALLOC && !attribute.data_runs.is_empty()
            })
            .ok_or(Error::NotFound)?;
        if u64::from(allocation.data_size) % u64::from(block_size) != 0 {
            return Err(Error::InvalidArgument);
        }
        let blocks = u64::from(allocation.data_size) / u64::from(block_size);
        let taken = self.first_free_index_block(parent_record, blocks)?;
        let new_vcn = taken.map_or(blocks * per_block, |block| block * per_block);
        let bit = new_vcn / per_block;
        let separator = fs::index_separator(&promoted, new_vcn)?;

        // The node above, with the key where its own order puts it.  Its room
        // is what the caller settled before anything here was claimed, so what
        // the write below does with it is a write and not a measurement.
        let (parent_entries, inserted) = node_entries_with(parent, &separator)?;
        if !inserted {
            return Err(Error::InvalidArgument);
        }

        // The clusters the block lives in.  A block that was already the
        // allocation's has them; one past the end of it takes a block's
        // worth from the volume and moves the allocation with it.
        let runs = match taken {
            Some(_) => allocation.data_runs.clone(),
            None => {
                let first = self.claim_clusters(per_block)?;
                let mut runs = allocation.data_runs.clone();
                let merged = runs.last().is_some_and(|last| {
                    last.lcn >= 0 && last.lcn as u64 + last.cluster_count == first
                });
                if merged {
                    runs.last_mut()
                        .expect("the last run that was just looked at")
                        .cluster_count += per_block;
                } else {
                    runs.push(DataRun {
                        lcn: first as i64,
                        cluster_count: per_block,
                    });
                }
                let grown = allocation.data_size + block_size;
                self.write_grown_data(allocation.holder, &allocation, &runs, grown, grown, &[])?;
                runs
            }
        };

        // The bitmap's bit for the block, which is the block's own number.
        self.set_index_block_bit(parent_record, bit, true)?;

        // The new block, with the half that left and its own terminator.
        let mut left: Vec<Vec<u8>> = names[..middle].to_vec();
        // Which terminator that is depends on what the node is.  A leaf ends
        // with an entry that points at nothing, and both halves can carry that
        // one along.  A **block** split in turn is an internal node, and there
        // the entry between the halves is a key *and* a child: that child holds
        // the names between the two halves, so the new block ends with a
        // pointer to it, the same entry with its key taken off.
        left.push(match fs::index_entry_child(&promoted) {
            Some(child) => fs::index_child_pointer(child),
            None => terminator.clone(),
        });
        let block = fs::index_allocation_block(block_size as usize, sector_size, new_vcn, &left)?;
        {
            let info = self.info.lock();
            fs::write_to_runs(
                &self.device,
                &info,
                &runs,
                new_vcn * u64::from(cluster_size),
                &block,
            )?;
        }

        // The node above, whose key makes the new block reachable.
        //
        // It is written from a fresh read of its record, not the copy the
        // walk started with: growing the allocation above may have moved
        // the attribute the root lives in, and a record written from that
        // copy would undo the growth and the bitmap bit with it.
        //
        // A node above that is a *record*'s index root is read again,
        // because growing the allocation below may have moved it; one that
        // is a *block* is where the walk found it, because nothing in this
        // split writes it before this point.
        let (mut parent_buffer, parent_node, parent_home) = match &parent.home {
            IndexHome::Record { .. } => {
                let holder = self.index_root_holder(parent_record)?;
                let (buffer, node) = self.index_root_node(holder)?;
                (buffer, node, IndexHome::Record { holder })
            }
            IndexHome::Block { .. } => (parent.buffer.clone(), parent.node, parent.home.clone()),
        };
        match self.write_index_leaf(
            parent_record,
            &mut parent_buffer,
            parent_node,
            &parent_entries,
            &parent_home,
        ) {
            Ok(()) => {}
            // A node above that is a **block** with no room for the key is
            // split in turn, and the entries it would have held, this
            // split's key among them, are what it is split by.  The node
            // above *it* is one level further up the same walk, so that is
            // where its own key has to go; a record up there with no room
            // is the caller's to make room in, like any other.
            Err(Error::NoSpace) if matches!(parent_home, IndexHome::Block { .. }) => {
                let above = IndexLeaf {
                    buffer: parent.buffer.clone(),
                    node: parent.node,
                    home: parent.home.clone(),
                    ancestors: leaf.ancestors[..leaf.ancestors.len() - 1].to_vec(),
                    key: None,
                };
                // And the block that stayed **below** this one is still
                // written last, all the same: the half that stayed in it is
                // the only copy which is not already on the volume.
                self.split_a_block(parent_record, &above, &parent_entries)?;
            }
            Err(error) => return Err(error),
        }

        // And the block that stayed, with the half that stayed in it.
        let mut right: Vec<Vec<u8>> = names[middle + 1..].to_vec();
        right.push(terminator.clone());
        let mut leaf_buffer = leaf.buffer.clone();
        self.write_index_leaf(
            parent_record,
            &mut leaf_buffer,
            leaf.node,
            &right,
            &leaf.home,
        )?;
        Ok(())
    }

    /// This is the format's answer to a root that cannot grow in any record
    /// the one a record full of *entries* needs, where the root's move into a
    /// record of its own has already been spent.  Every entry leaves the
    /// root's value for a **block**; the two attributes that describe the
    /// allocation, the runs and the bitmap of the blocks, both named `$I30`
    ///, go into an extension record of their own, the base's
    /// `$ATTRIBUTE_LIST` names them where they went, and the root's node
    /// keeps only the pointer to the block, whose virtual cluster number is
    /// the pointer's last eight bytes.
    ///
    /// The writes are ordered by what a crash between them leaves, and every
    /// window is one a mount reads.  The record and the block go down first
    /// a record in use that nothing names and a block nothing points at are
    /// leaks, the harmless direction.  The base's list second: the root still
    /// holds its entries as a value, so a listing reads them where they were.
    /// The root's node last, and that write is the one that turns the index
    /// into a tree.
    ///
    /// A block smaller than a cluster is one no virtual cluster number can
    /// address (`NotImplemented`), a set of entries that does not fit one
    /// block refuses (`NoSpace`), and so does a base whose list cannot take
    /// two more entries, refused before anything is claimed, so nothing is
    /// half-spent.
    fn entries_leave_for_a_block(&self, parent_record: u64, entries: &[Vec<u8>]) -> Result<()> {
        let (index_block_size, cluster_size, sector_size) = {
            let info = self.info.lock();
            (
                info.index_block_size,
                info.cluster_size,
                usize::from(info.bs.bytes_per_sector),
            )
        };
        let clusters = u64::from(index_block_size / cluster_size.max(1));
        if clusters == 0 {
            return Err(Error::NotImplemented);
        }

        let attributes = self.attributes_of(parent_record)?;
        let root = attributes
            .iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_INDEX_ROOT)
            .ok_or(Error::NotFound)?;
        // A root still in its own record is one the move answers: the block is
        // for a root whose move has been spent, which is the only way this is
        // reached.
        let holder = root.holder;
        if holder == u64::MAX || holder == parent_record {
            return Err(Error::NotImplemented);
        }
        if attributes.iter().any(|attribute| {
            attribute.attr_type == ATTR_TYPE_INDEX_ALLOC && !attribute.data_runs.is_empty()
        }) {
            return Err(Error::InvalidArgument);
        }

        // The base's list is what says where the root went, so it is what will
        // say where the two attributes went, a list that is a file of its own
        // is grown by a step of its own, and is refused here.
        let mut base = self.read_mft_record(parent_record)?;
        let mut base_header = MftRecordHeader::parse(&base).ok_or(Error::InvalidArgument)?;
        let base_at = base_header.size() as usize;
        let mut base_attributes = parse_attributes(&base[base_at..]);
        let mut list = base_attributes
            .iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_ATTRIBUTE_LIST)
            .ok_or(Error::InvalidArgument)?
            .clone();
        if list.data_runs_offset.is_some() {
            return Err(Error::NotImplemented);
        }
        let mut listed = self.list_entries(&list)?;
        let instance = u16::from_le_bytes([base[40], base[41]]);

        // The base as the list will leave it: two entries longer than it is
        // now, each where its own type sorts.  The entries' lengths do not
        // depend on the record they name, so the fit is measured against a
        // list built around a placeholder before anything is claimed, and a
        // base that cannot hold the growth makes room first, its largest
        // attribute that is not the list moving into a record of its own,
        // which is what the list's entry for it then names.
        let measured = |listed: &[fs::AttributeListEntry], value_offset: usize| -> usize {
            let value = allocation_list_value(listed, instance, 0);
            (value_offset + value.len()).div_ceil(8) * 8
        };
        let mut room = measured(&listed, list.value_offset);
        let mut new_used = bytes_in_use(&base) + room - list.attr_len;
        if new_used + 8 > base.len() {
            let largest = base_attributes
                .iter()
                .filter(|attribute| attribute.attr_type != ATTR_TYPE_ATTRIBUTE_LIST)
                .max_by_key(|attribute| attribute.attr_len)
                .ok_or(Error::NoSpace)?;
            let growing = largest.attr_type;
            self.make_room(parent_record, growing)?;
            base = self.read_mft_record(parent_record)?;
            base_header = MftRecordHeader::parse(&base).ok_or(Error::InvalidArgument)?;
            base_attributes = parse_attributes(&base[base_at..]);
            list = base_attributes
                .iter()
                .find(|attribute| attribute.attr_type == ATTR_TYPE_ATTRIBUTE_LIST)
                .ok_or(Error::InvalidArgument)?
                .clone();
            listed = self.list_entries(&list)?;
            room = measured(&listed, list.value_offset);
            new_used = bytes_in_use(&base) + room - list.attr_len;
            if new_used + 8 > base.len() {
                return Err(Error::NoSpace);
            }
        }

        // What the block and its two attributes are, and where: the clusters
        // first, then the block's own bytes, then the record that carries the
        // two attributes, each of the three refused with what it took given
        // straight back.
        let first = match self.claim_clusters(clusters) {
            Ok(first) => first,
            Err(error) => {
                return Err(error);
            }
        };
        let runs = alloc::vec![DataRun {
            lcn: first as i64,
            cluster_count: clusters,
        }];
        let block =
            match fs::index_allocation_block(index_block_size as usize, sector_size, 0, entries) {
                Ok(block) => block,
                Err(error) => {
                    self.free_clusters(&runs)?;
                    return Err(error);
                }
            };
        let allocation = fs::non_resident_attribute(
            ATTR_TYPE_INDEX_ALLOC,
            "$I30",
            instance,
            &runs,
            u64::from(index_block_size),
            u64::from(index_block_size),
            u64::from(index_block_size),
        );
        let mut bits = alloc::vec![0u8; 8];
        bits[0] = 1; // the one block is in use
        let bitmap =
            fs::resident_attribute(ATTR_TYPE_BITMAP, "$I30", instance.wrapping_add(1), &bits);
        let (home_of_the_two, _) = match self.claim_record(NewRecord::Extension {
            base: parent_record,
            attributes: alloc::vec![allocation, bitmap],
        }) {
            Ok(claimed) => claimed,
            Err(error) => {
                self.free_clusters(&runs)?;
                return Err(error);
            }
        };
        {
            let info = self.info.lock();
            fs::write_to_runs(&self.device, &info, &runs, 0, &block)?;
        }

        // The base's list, with the entries that name where the two
        // attributes went.  The root still holds the entries as a value, so a
        // mount here lists them where they were.
        let home_reference = {
            let record = self.read_mft_record(home_of_the_two)?;
            let sequence = u16::from_le_bytes([record[16], record[17]]);
            home_of_the_two | (u64::from(sequence) << 48)
        };
        let list_value = allocation_list_value(&listed, instance, home_reference);
        let at = base_at + list.offset;
        let mut new_list = base[at..at + list.attr_len].to_vec();
        new_list.resize(room, 0);
        new_list[4..8].copy_from_slice(&(room as u32).to_le_bytes());
        new_list[16..20].copy_from_slice(&(list_value.len() as u32).to_le_bytes());
        new_list[list.value_offset..list.value_offset + list_value.len()]
            .copy_from_slice(&list_value);

        let mut rebuilt_base = base[..base_at].to_vec();
        for attribute in &base_attributes {
            let at = base_at + attribute.offset;
            if attribute.offset == list.offset {
                rebuilt_base.extend_from_slice(&new_list);
            } else {
                rebuilt_base.extend_from_slice(&base[at..at + attribute.attr_len]);
            }
        }
        rebuilt_base.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let used = rebuilt_base.len();
        rebuilt_base.resize(base.len(), 0);
        rebuilt_base[24..28].copy_from_slice(&(used as u32).to_le_bytes());
        rebuilt_base[40..42].copy_from_slice(&instance.wrapping_add(2).to_le_bytes());
        {
            let (at, sector) = {
                let info = self.info.lock();
                (
                    self.record_offset(&info, parent_record)?,
                    usize::from(info.bs.bytes_per_sector),
                )
            };
            fs::pack_usa(
                &mut rebuilt_base,
                base_header.usa_offset as usize,
                base_header.usa_count as usize,
                sector,
            );
            fs::write_device_bytes(&self.device, at, &rebuilt_base)?;
            self.mft_cache.lock().insert(parent_record, rebuilt_base);
        }

        // The root, reduced to the node that points at the block: its own
        // header is the value's first sixteen bytes and stays, and the node's
        // only entry is the pointer, whose last eight bytes are where the
        // format puts the child's virtual cluster number.  This write is what
        // turns the index into a tree, so it is the last.
        let home = self.read_mft_record(holder)?;
        let home_header = MftRecordHeader::parse(&home).ok_or(Error::InvalidArgument)?;
        let home_at = home_header.size() as usize;
        let home_attributes = parse_attributes(&home[home_at..]);
        let root_here = home_attributes
            .iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_INDEX_ROOT)
            .ok_or(Error::InvalidArgument)?;
        let attr_len = root_here.value_offset + 56;
        let mut new_root = home
            [home_at + root_here.offset..home_at + root_here.offset + root_here.attr_len]
            .to_vec();
        new_root.resize(attr_len, 0);
        new_root[4..8].copy_from_slice(&(attr_len as u32).to_le_bytes());
        new_root[16..20].copy_from_slice(&56u32.to_le_bytes());
        let value_at = root_here.value_offset;
        new_root[value_at + 16..value_at + 20].copy_from_slice(&16u32.to_le_bytes());
        new_root[value_at + 20..value_at + 24].copy_from_slice(&40u32.to_le_bytes());
        new_root[value_at + 24..value_at + 28].copy_from_slice(&40u32.to_le_bytes());
        new_root[value_at + 28..value_at + 32].copy_from_slice(&1u32.to_le_bytes());
        new_root[value_at + 32..value_at + 56].copy_from_slice(&fs::index_child_pointer(0));

        let mut rebuilt_home = home[..home_at].to_vec();
        for attribute in &home_attributes {
            let at = home_at + attribute.offset;
            if attribute.offset == root_here.offset {
                rebuilt_home.extend_from_slice(&new_root);
            } else {
                rebuilt_home.extend_from_slice(&home[at..at + attribute.attr_len]);
            }
        }
        rebuilt_home.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        // The value only ever *shrinks* here, so the record it leaves has the
        // room by construction; the sizes follow the layout all the same.
        let used = rebuilt_home.len();
        rebuilt_home.resize(home.len(), 0);
        rebuilt_home[24..28].copy_from_slice(&(used as u32).to_le_bytes());
        {
            let (at, sector) = {
                let info = self.info.lock();
                (
                    self.record_offset(&info, holder)?,
                    usize::from(info.bs.bytes_per_sector),
                )
            };
            fs::pack_usa(
                &mut rebuilt_home,
                home_header.usa_offset as usize,
                home_header.usa_count as usize,
                sector,
            );
            fs::write_device_bytes(&self.device, at, &rebuilt_home)?;
            self.mft_cache.lock().insert(holder, rebuilt_home);
        }
        Ok(())
    }

    /// Refuse a record a name cannot be put in: one that is not a directory.
    pub(crate) fn check_directory(&self, record_number: u64) -> Result<()> {
        let record = self.read_mft_record(record_number)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        if !header.is_dir() {
            return Err(Error::InvalidArgument);
        }
        Ok(())
    }

    /// Whether `ancestor` is the record `start` is inside.
    ///
    /// The only link from a record to its parent is the parent's reference in
    /// its own `$FILE_NAME`, so this walks those up, which is what makes
    /// moving a directory into itself a refusal rather than a tree no walk can
    /// leave.
    pub(crate) fn is_inside(&self, ancestor: u64, start: u64) -> Result<bool> {
        let mut at = start;
        for _ in 0..MAX_ANCESTORS {
            if at == ancestor {
                return Ok(true);
            }
            if at == ROOT_RECORD {
                return Ok(false);
            }
            let attributes = self.attributes_of(at)?;
            let name = own_attribute(at, &attributes, ATTR_TYPE_FILENAME)?;
            if name.content.len() < 8 {
                return Err(Error::InvalidArgument);
            }
            let parent = u64::from_le_bytes([
                name.content[0],
                name.content[1],
                name.content[2],
                name.content[3],
                name.content[4],
                name.content[5],
                name.content[6],
                name.content[7],
            ]) & 0x0000_FFFF_FFFF_FFFF;
            if parent == at {
                // A record that names itself is a root, and a root has no
                // parent to walk to.
                return Ok(false);
            }
            at = parent;
        }
        Err(Error::InvalidArgument)
    }

    /// Take a name out of a directory's index.
    ///
    /// The entry that goes is the one that names this record *and* this name:
    /// a file can have more than one name, and a number alone would take the
    /// wrong one.
    ///
    /// A name the *node above* the blocks holds is a key a split promoted, and
    /// it comes out the way a key does, see [`Self::remove_index_key`].  A
    /// name a block holds comes out of the block, and the block it left may
    /// then be one the tree does not have to keep, see
    /// [`Self::merge_block_if_it_fits`].
    pub(crate) fn index_remove(
        &self,
        parent_record: u64,
        name: &str,
        reference: u64,
    ) -> Result<()> {
        let leaf = self.index_leaf(parent_record, name)?;
        if let Some(key) = leaf.key.clone() {
            return self.remove_index_key(parent_record, &key);
        }
        let raws = self.entries_without(&leaf.buffer, leaf.node, name, reference)?;
        let mut buffer = leaf.buffer.clone();
        self.write_index_leaf(parent_record, &mut buffer, leaf.node, &raws, &leaf.home)?;

        // The entries are in the index root itself when the directory has no
        // blocks: a record has nothing to be merged with, and a block has the
        // node above it, wherever that node lives.
        let IndexHome::Block { vcn, .. } = leaf.home else {
            return Ok(());
        };
        // The node above, read now: the write above touched the block and not
        // it, and reading it here is what keeps a change from starting at a
        // copy some other write has already gone past.
        let Some(parent_home) = leaf.ancestors.last().map(|parent| parent.home.clone()) else {
            return Ok(());
        };
        let attributes = self.attributes_of(parent_record)?;
        let parent = self.index_node_above(&attributes, &parent_home, vcn)?;
        self.merge_block_if_it_fits(parent_record, parent, vcn)
    }

    /// One node's entries with one name taken out of them, and the node's
    /// terminator still last.
    fn entries_without(
        &self,
        buffer: &[u8],
        node: usize,
        name: &str,
        reference: u64,
    ) -> Result<Vec<Vec<u8>>> {
        let upcase = self.upcase_table();
        let parsed = parse_index_node(buffer, node);
        let last = parsed.entries.len().saturating_sub(1);

        let mut raws: Vec<Vec<u8>> = Vec::new();
        let mut removed = false;
        for (index, entry) in parsed.entries.iter().enumerate() {
            let bytes = buffer[entry.offset..entry.offset + entry.length].to_vec();
            if index == last {
                // The terminator stays, wherever the removal left it.
                raws.push(bytes);
                continue;
            }
            let matches = entry.reference == reference
                && entry
                    .name
                    .as_ref()
                    .is_some_and(|existing| compare_names(name, &existing.name, &upcase).is_eq());
            if matches && !removed {
                removed = true;
                continue;
            }
            raws.push(bytes);
        }
        if !removed {
            return Err(Error::NotFound);
        }
        Ok(raws)
    }

    /// Take out a name that lives in the node **above** the blocks, which is a
    /// key a split promoted.
    ///
    /// A key's entry carries the child whose keys are *less* than it, so the
    /// entry cannot simply go: that child would be left unreachable.  What
    /// takes its place is the key's **predecessor**, the largest name the child
    /// holds, which keeps the child where it is, keeps every other name where
    /// it was, and leaves the name that is going nowhere at all.  The
    /// predecessor is then taken out of the block it came from, which is the
    /// removal a block's name takes, and that block may then be one the tree
    /// does not have to keep.
    ///
    /// The node above goes first.  Written with the predecessor's key in it,
    /// the removed name is gone and the predecessor appears **twice**, in the
    /// node and still in the block, which a walk reads as one name, because
    /// both copies name the same record.  Taking it out of the block is the
    /// write that follows, and the other order would leave the name in neither.
    ///
    /// A key whose child holds **nothing** is the case where the entry can go
    /// as it is: the child has no names that would be left behind, and the
    /// block it is in is given back.
    fn remove_index_key(&self, parent_record: u64, key: &IndexKey) -> Result<()> {
        let attributes = self.attributes_of(parent_record)?;
        let parsed = parse_index_node(&key.buffer, key.node);
        let position = parsed
            .entries
            .iter()
            .position(|entry| entry.offset == key.offset && entry.length == key.length)
            .ok_or(Error::NotFound)?;
        let child = parsed.entries[position]
            .child
            .ok_or(Error::InvalidArgument)?;

        let (block, home) = self.read_index_block_home(&attributes, child)?;
        let picked = parse_index_node(&block, 24)
            .entries
            .into_iter()
            .rev()
            .find(|entry| entry.name.is_some());
        let predecessor = picked
            .as_ref()
            .map(|entry| block[entry.offset..entry.offset + entry.length].to_vec());

        let mut parent_entries: Vec<Vec<u8>> = Vec::new();
        for (index, entry) in parsed.entries.iter().enumerate() {
            if index == position {
                if let Some(predecessor) = &predecessor {
                    parent_entries.push(fs::index_separator(predecessor, child)?);
                }
                continue;
            }
            parent_entries.push(key.buffer[entry.offset..entry.offset + entry.length].to_vec());
        }

        // A predecessor whose name is longer than the one that goes makes the
        // node above longer, and a record with no room makes room first, which
        // moves the node, so the write is worked out again from where it is
        // now. A *block* has what is left of itself, and a name that does not
        // fit one is refused rather than moved anywhere.
        let mut written = false;
        for attempt in 0..2 {
            let (mut buffer, node) = match &key.home {
                IndexHome::Record { holder } => self.index_root_node(*holder)?,
                IndexHome::Block { .. } => (key.buffer.clone(), key.node),
            };
            match self.write_index_leaf(
                parent_record,
                &mut buffer,
                node,
                &parent_entries,
                &key.home,
            ) {
                Ok(()) => {
                    written = true;
                    break;
                }
                Err(Error::NoSpace) if attempt == 0 => match &key.home {
                    IndexHome::Record { holder } => {
                        self.make_room(*holder, ATTR_TYPE_INDEX_ROOT)?;
                    }
                    IndexHome::Block { .. } => return Err(Error::NoSpace),
                },
                Err(error) => return Err(error),
            }
        }
        if !written {
            return Err(Error::NoSpace);
        }

        let Some(predecessor) = picked else {
            // The child held nothing, so the block the key pointed at holds
            // nothing either: nothing points at it now, and its bit goes.
            let bit = child / self.clusters_per_index_block().max(1);
            return self.set_index_block_bit(parent_record, bit, false);
        };
        let predecessor_name = predecessor.name.expect("a name that was looked for");
        let raws =
            self.entries_without(&block, 24, &predecessor_name.name, predecessor.reference)?;
        let mut buffer = block;
        self.write_index_leaf(parent_record, &mut buffer, 24, &raws, &home)?;
        // The node the key was in, **read again**: the swing above wrote it,
        // and a merge that started from the copy the walk made would put the
        // key it replaced back, the same staleness a split's node above has
        // when the allocation it names grows.
        let parent = self.index_node_above(&attributes, &key.home, child)?;
        self.merge_block_if_it_fits(parent_record, parent, child)
    }

    /// The node a block hangs from, read **now**, with the entry the block is
    /// the child of: a record's index root from its record, and a block from
    /// the bytes its runs name.
    fn index_node_above(
        &self,
        attributes: &[ParsedAttr],
        home: &IndexHome,
        child: u64,
    ) -> Result<IndexParent> {
        let (buffer, node, home) = match home {
            IndexHome::Record { holder } => {
                let (buffer, node) = self.index_root_node(*holder)?;
                (buffer, node, home.clone())
            }
            IndexHome::Block { vcn, .. } => {
                let (buffer, home) = self.read_index_block_home(attributes, *vcn)?;
                (buffer, 24, home)
            }
        };
        let before = parse_index_node(&buffer, node)
            .entries
            .iter()
            .find(|entry| entry.child == Some(child))
            .map_or(0, |entry| entry.offset);
        Ok(IndexParent {
            buffer,
            node,
            before,
            home,
        })
    }

    /// Merge a block with the one next to it, when what the two hold still fits
    /// one block again.
    ///
    /// A block that has lost names is a block the tree does not have to keep,
    /// and the key that separated the pair is what goes with it: it moves
    /// **down** into the merged node, where it belongs between the two halves
    /// every name the two hold is on one side of it or the other, and the
    /// entry that carried it is dropped.  What stays is the block whose key
    /// order came first, so the entry *after* the one that goes is the entry
    /// that points at it afterwards, with its own key unchanged.
    ///
    /// A pair that does not fit one block is not merged, and that is an answer
    /// rather than a refusal (`Ok(())`): the block keeps its names and the tree
    /// keeps its shape, which is what a removal that left a block *nearly* full
    /// should do.
    ///
    /// The writes are ordered by what a crash leaves.  The merged block first:
    /// its names are then reachable twice, and a walk counts them once because
    /// both copies name the same record.  The node above next, after which the
    /// block that lost its names is not reachable at all.  Its bit in the index
    /// bitmap last, which is what gives the block back, the clusters stay part
    /// of the allocation, a free block inside it, because taking the tail of an
    /// allocation back is a step of its own.
    fn merge_block_if_it_fits(
        &self,
        parent_record: u64,
        parent: IndexParent,
        vcn: u64,
    ) -> Result<()> {
        // The node the block hangs from, from the walk that found it: the index
        // root for a directory of one level, and a *block* for a tree deeper
        // than that.  Nothing here reads the directory's own record to find it,
        // which is what makes both shapes the same job.
        let attributes = self.attributes_of(parent_record)?;
        let parsed = parse_index_node(&parent.buffer, parent.node);
        let Some(position) = parsed
            .entries
            .iter()
            .position(|entry| entry.child == Some(vcn))
        else {
            // The node above does not point at the block: nothing to merge.
            return Ok(());
        };
        // The pair, and which of the two keeps its block: the entry whose child
        // is the block that came first, and the entry after it.  A block that
        // is the *last* child has no entry after it, and the pair is the one
        // before it.
        let (left_at, right_at) = if position + 1 < parsed.entries.len() {
            (position, position + 1)
        } else if position > 0 {
            (position - 1, position)
        } else {
            // A node with one child and no keys has no pair to merge, and a
            // tree of one block is a tree.
            return Ok(());
        };
        let left = parsed.entries[left_at]
            .child
            .ok_or(Error::InvalidArgument)?;
        let right = parsed.entries[right_at]
            .child
            .ok_or(Error::InvalidArgument)?;
        let at = parsed.entries[left_at].offset;
        let separator = parent.buffer[at..at + parsed.entries[left_at].length].to_vec();
        let separator = fs::index_leaf_entry(&separator)?;

        let (left_block, left_home) = self.read_index_block_home(&attributes, left)?;
        let (right_block, _) = self.read_index_block_home(&attributes, right)?;

        // What the merged block holds, in the order the tree keeps them: the
        // left block's names, the key that separated the pair, the right
        // block's names, and the terminator the left block already ended with.
        let mut merged: Vec<Vec<u8>> = Vec::new();
        let mut terminator = None;
        for entry in parse_index_node(&left_block, 24).entries {
            let bytes = left_block[entry.offset..entry.offset + entry.length].to_vec();
            if entry.name.is_some() {
                merged.push(bytes);
            } else {
                terminator = Some(bytes);
            }
        }
        merged.push(separator);
        for entry in parse_index_node(&right_block, 24).entries {
            if entry.name.is_some() {
                merged.push(right_block[entry.offset..entry.offset + entry.length].to_vec());
            }
        }
        merged.push(terminator.ok_or(Error::InvalidArgument)?);

        let mut buffer = left_block;
        match self.write_index_leaf(parent_record, &mut buffer, 24, &merged, &left_home) {
            Ok(()) => {}
            // The two still do not fit one block: the tree keeps its shape.
            Err(Error::NoSpace) => return Ok(()),
            Err(error) => return Err(error),
        }

        let mut parent_entries: Vec<Vec<u8>> = Vec::new();
        for (index, entry) in parsed.entries.iter().enumerate() {
            if index == left_at {
                continue;
            }
            let mut bytes = parent.buffer[entry.offset..entry.offset + entry.length].to_vec();
            if index == right_at {
                // The entry that pointed at the block that went points at the
                // one that stayed.  A child's number ends the entry, keyed or
                // not, which is where a reader looks for it.
                let at = bytes.len() - 8;
                bytes[at..].copy_from_slice(&left.to_le_bytes());
            }
            parent_entries.push(bytes);
        }
        // Written from a fresh read when it is a record's index root, a
        // growth of this change's may have moved it, and where it is when the
        // node is a block.
        let (mut parent_buffer, parent_node) = match &parent.home {
            IndexHome::Record { holder } => self.index_root_node(*holder)?,
            IndexHome::Block { .. } => (parent.buffer.clone(), parent.node),
        };
        self.write_index_leaf(
            parent_record,
            &mut parent_buffer,
            parent_node,
            &parent_entries,
            &parent.home,
        )?;

        let bit = right / self.clusters_per_index_block().max(1);
        self.set_index_block_bit(parent_record, bit, false)
    }
}
