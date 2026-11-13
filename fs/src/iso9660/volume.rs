//! fs/src/iso9660/volume.rs
//!
//! A mounted ISO 9660 volume: the descriptor set, the tree it describes, the
//! entries the tree holds, and — on a writable device — the places the format
//! and the volume allow a write.
//!
//! ## What mounting does
//!
//! Reads the descriptor set from sector 16, picks the tree a reader should see
//! — Joliet's when there is one, because its names are the author's — and
//! keeps where that tree's descriptor sits.  Nothing else is read: a
//! directory's extent is read when someone asks what is in it, and a file's
//! extent when someone reads it.  Even the root's own record is read from its
//! descriptor every time rather than kept, because a writable volume's root
//! can *move* — the extension reference rebuilds it — and a copy taken at
//! open would name the extent it left.
//!
//! That laziness is not an optimisation.  A disc can hold a hundred thousand
//! entries in a tree deeper than a computer's stack, and a mount that walked it
//! would be a mount that took minutes and a heap nobody bounded.
//!
//! ## What is refused
//!
//! Three things this driver will not pretend to handle, and each is reported
//! rather than half-read:
//!
//! - **An extended attribute record.**  A record may name blocks in front of
//!   its data, which this driver does not skip, so a file with one would be
//!   read from the wrong place — and, for the write path, its blocks are ones
//!   the map cannot name.
//! - **A multi-extent file.**  One file in several pieces; reading the first
//!   piece as the whole file returns a truncated file that looks complete.
//! - **An interleaved file.**  Units with gaps between them, where reading it
//!   as one extent returns the gaps as data.
//!
//! ## What a writable device gets
//!
//! A file's data, its length, and space from the allocator; a record appended
//! to or taken out of a directory; a rename; and the path tables rebuilt from
//! the tree rather than edited in place.  The order each mutation writes its
//! fields in is chosen so a crash leaves either the old state or the new one,
//! whole — a file that grows by moving copies its data before its record is
//! repointed, and a directory's tables are rebuilt last, because they are
//! derived from the tree.
//!
//! A volume with **two trees** — a Joliet one beside the primary — is written
//! only where the two agree, which is the file's data: an overwrite inside its
//! length is the same bytes under both records.  A length change and
//! everything structural is refused, because each would have to appear in
//! both trees and the trees spell a name differently by design, so nothing on
//! the volume says which record in the other tree is the same file's.
//!
//! A writable mount also **writes**, once, at open: a volume whose System Use
//! areas carry Rock Ridge entries is required to name the extension in an `ER`
//! entry, and this driver has been writing such entries since names stopped
//! having to be ISO 9660 identifiers.  It happens at open because the root's
//! "." record grows by the area and every record after it moves, and at open
//! no node holds a record offset that could be left pointing at another
//! file's bytes.  It is best-effort: a volume this cannot be written to still
//! mounts, because reading the disc is the larger thing not to lose.

use alloc::collections::VecDeque;
use alloc::format;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use abi::Error;
use abi::Result;

use block::BlockDevice;
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;

use super::allocate;
use super::allocate::Allocator;
use super::record::Record;
use super::susp;
use super::susp::SystemUse;
use super::volume_descriptor::DESCRIPTOR_SET_START;
use super::volume_descriptor::MAX_DESCRIPTORS;
use super::volume_descriptor::OFFSET_ROOT_RECORD;
use super::volume_descriptor::SECTOR_SIZE;
use super::volume_descriptor::VolumeDescriptor;
use super::write;
use super::write::PathTableEntry;

use crate::FileSystem;
use crate::types::DirectoryEntry;
use crate::types::MAX_PERMISSION_MODE;
use crate::types::Metadata;
use crate::types::NodeKind;
use crate::types::SecurityDescriptor;
use crate::types::SecurityDescriptorMutationSupport;
use crate::types::VolumeCheckReport;
use crate::vnode::VNode;

/// One tree on a disc: the primary or a supplementary one.
#[derive(Debug, Clone, Copy)]
struct Tree {
    /// The sector the tree's descriptor sits in.
    ///
    /// The root's record is a field of that descriptor, and a root that grows
    /// or moves rewrites it there — so this, not the root's extent, is what
    /// the tree keeps.
    descriptor_sector: u64,
    /// Whether names in this tree are UCS-2 big-endian.
    joliet: bool,
}

/// A mounted ISO 9660 volume.
pub struct Iso9660Volume {
    device: Arc<dyn BlockDevice>,
    label: String,
    block_size: u16,
    /// The tree a reader answers from — the last usable one the set held,
    /// Joliet's when there is one.
    tree: Tree,
    /// Every tree descriptor the set held, in the order the set does.
    ///
    /// One entry means every record this volume answers from is the only
    /// copy.  More than one means the same file is named in a tree this
    /// driver does not follow, and a change that would half-happen is refused
    /// rather than made in one tree and not the other.  The whole list is
    /// what the path tables' rebuild walks, because an upgrade that moves the
    /// primary's root leaves its tables naming the extent it left.
    trees: Vec<Tree>,
    /// The size the volume declared when it was opened.
    ///
    /// It is the floor a **shrink** may not take the volume's end below: the
    /// blocks the image came with are the image's, and the one rule this
    /// driver can apply without knowing what is on the volume is that
    /// everything past the size it declares belongs to nobody.
    ///
    /// It is *not* a floor on what the allocator may hand out: a block inside
    /// the volume is free when the block map says nothing names it, and the
    /// map is what lets a hole left by a removal be reused.
    volume_floor: u32,
}

impl Iso9660Volume {
    /// Mount the disc on `device`.
    ///
    /// Walks the descriptor set and takes the last usable tree it finds, which
    /// is what makes a Joliet disc readable under the names its author meant:
    /// the set puts the primary descriptor first and a supplementary one after
    /// it, and the later one is the tree a reader should see.
    pub fn open(device: Arc<dyn BlockDevice>) -> Result<Arc<Self>> {
        let mut found: Vec<Tree> = Vec::new();
        let mut selected: Option<(VolumeDescriptor, Tree)> = None;
        for sector in (DESCRIPTOR_SET_START..).take(MAX_DESCRIPTORS as usize) {
            let Some(descriptor) = read_descriptor(&*device, sector)? else {
                break;
            };
            if descriptor.is_terminator() {
                break;
            }
            if descriptor.describes_a_tree()
                && let Some(tree) = Tree::of(&descriptor)
            {
                found.push(tree);
                // A later tree replaces an earlier one: the set's order is the
                // reader's preference order.
                selected = Some((descriptor, tree));
            }
        }

        let (descriptor, tree) = selected.ok_or(Error::InvalidArgument)?;
        if descriptor.block_size as usize != SECTOR_SIZE {
            // The format allows other block sizes; this driver does not
            // implement them, and a disc at one would be read at the wrong
            // offsets rather than fail.
            return Err(Error::Unsupported);
        }
        // The floor is the primary descriptor's own statement of the volume's
        // extent, read from where it lives rather than from whichever tree was
        // selected: the two carry the same number on a well-formed disc, and
        // the primary's is the one the tail rule is written against.
        let volume_floor = allocate::volume_blocks(&*device)?;

        let volume = Arc::new(Self {
            device,
            label: descriptor.volume_id,
            block_size: descriptor.block_size,
            tree,
            trees: found,
            volume_floor,
        });

        // A volume this driver is going to write entries into has to say which
        // extension they belong to, and a read-only device is not one to do it
        // on (`declare_extension` explains why it happens here).
        if !volume.device.is_read_only() {
            let _ = volume.declare_extension();
        }

        Ok(volume)
    }

    /// The size of a logical block, in bytes.
    fn block_size_bytes(&self) -> u64 {
        self.block_size as u64
    }

    /// How many trees the disc has, which is what says whether a length is
    /// one record's to change.
    fn tree_count(&self) -> u8 {
        u8::try_from(self.trees.len()).unwrap_or(u8::MAX)
    }

    /// Refuse a change that would alter a *directory* on a disc with two
    /// trees.
    ///
    /// A create, a removal and a rename each add or take away a record in a
    /// directory, and a disc's trees do not share their directories: the
    /// entry would have to be made in every tree, with an identifier encoded
    /// for each, and this driver makes it in one.
    fn refuse_a_change_to_one_of_two_trees(&self) -> Result<()> {
        if self.trees.len() > 1 {
            return Err(Error::Unsupported);
        }
        Ok(())
    }

    /// Every entry in the directory `record` names, its `.` and `..` removed.
    fn read_directory(&self, record: &Record) -> Result<Vec<Record>> {
        write::read_records(
            &*self.device,
            self.block_size,
            record.extent,
            record.data_length,
            self.tree.joliet,
            false,
        )
    }

    /// The root directory's record, from its descriptor.
    ///
    /// Read from the tree rather than kept: a writable volume's root can
    /// *move* — the extension reference rebuilds it — and a copy taken at open
    /// would name the extent it left.  This driver has no state that could go
    /// stale.
    fn root_record(&self) -> Result<Record> {
        self.tree_root(&self.tree)
    }

    /// One tree's root record, from that tree's own descriptor.
    fn tree_root(&self, tree: &Tree) -> Result<Record> {
        let descriptor = read_descriptor(&*self.device, tree.descriptor_sector)?
            .ok_or(Error::InvalidArgument)?;
        Record::parse(&descriptor.root_record, 0, tree.joliet)
            .map(|(record, _next)| record)
            .ok_or(Error::InvalidArgument)
    }

    /// A tree's root directory's entries, in that tree's own encoding.
    fn tree_directory(&self, tree: &Tree, root: &Record) -> Result<Vec<Record>> {
        write::read_records(
            &*self.device,
            self.block_size,
            root.extent,
            root.data_length,
            tree.joliet,
            false,
        )
    }

    /// Where the root's own record sits on the volume, in bytes.
    ///
    /// It is a field of the descriptor that names the tree, and a root that
    /// grows or moves rewrites its length there.
    fn root_record_offset(&self) -> u64 {
        self.tree.descriptor_sector * SECTOR_SIZE as u64 + OFFSET_ROOT_RECORD as u64
    }

    /// The record a path names, and where its own record sits on the volume.
    ///
    /// Path components are matched against each directory's entries as they
    /// are read, so a deep path costs one directory read per step and nothing
    /// more.  A component that matches no entry is `NotFound`, which is the
    /// answer the format gives, a disc has no "maybe" between two names.
    ///
    /// The offset is what a resize rewrites: a record carries the length of
    /// the file it describes, and the record's position is not something a
    /// lookup can recover later without walking the path again.
    fn resolve(&self, path: &str) -> Result<(Record, u64)> {
        let mut current = self.root_record()?;
        let mut current_offset = self.root_record_offset();

        for component in path.split('/').filter(|part| !part.is_empty()) {
            if !current.is_directory() {
                // A path continued past a file: the file cannot hold it.
                return Err(Error::NotFound);
            }
            let entries = self.read_directory(&current)?;
            // The parser recorded the offset it found the record at *inside
            // the extent it walked*; the volume is what knows where that
            // extent is.
            let extent_base = current.extent as u64 * self.block_size_bytes();
            let found = entries
                .into_iter()
                .find(|entry| entry.name() == component)
                .ok_or(Error::NotFound)?;
            current_offset = extent_base + found.source_offset as u64;
            current = found;
        }
        Ok((current, current_offset))
    }

    /// The directory a path names a child of, and the child's own name.
    ///
    /// A path is resolved one segment at a time, and a create or a remove needs
    /// the *parent*: its extent is where a child's record goes, and its own
    /// record is where the directory's length lives.
    fn resolve_child(&self, path: &str) -> Result<(Record, u64, String)> {
        let (parent_path, child) = match path.rfind('/') {
            Some(0) => ("", &path[1..]),
            Some(index) => (&path[..index], &path[index + 1..]),
            None => ("", path),
        };
        if child.is_empty() {
            // The root has no parent to add it to or take it from.
            return Err(Error::InvalidArgument);
        }

        let (parent, parent_record_offset) = self.resolve(parent_path)?;
        if !parent.is_directory() {
            return Err(Error::InvalidArgument);
        }
        Ok((parent, parent_record_offset, String::from(child)))
    }

    /// Where a directory's own ".." record sits on the volume.
    ///
    /// It is the second record in the directory's extent, and the parser finds
    /// it by its identifier — one byte, `0x01` — so this does not have to
    /// assume how long the first record is.
    fn parent_record_of(&self, extent_location: u32, extent_size: u32) -> Result<u64> {
        let mut data = vec![0u8; extent_size as usize];
        allocate::read_extent_bytes(
            &*self.device,
            self.block_size,
            extent_location,
            extent_size,
            0,
            &mut data,
        )?;

        let mut at = 0usize;
        while let Some((record, next)) = Record::parse(&data, at, false) {
            if record.identifier == [0x01] {
                return Ok(extent_location as u64 * self.block_size_bytes() + at as u64);
            }
            at = next;
        }
        Err(Error::InvalidArgument)
    }

    /// Add a record to a directory, and answer where it landed.
    ///
    /// A directory that has to grow can **move**: an extent is one contiguous
    /// run, and the blocks after it may be taken.  When it does, its children's
    /// own ".." records — which name it by where it was — are stale, so they
    /// are rewritten here, at the one place a directory grows.
    ///
    /// The children are read out of the extent the directory *left*, which the
    /// move copied rather than changed: that copy is the directory as it was
    /// before this record joined it, which is exactly the list to correct.
    ///
    /// Three things name a directory by its address, and a move leaves all
    /// three behind: its parent's record for it, its children's "..", and both
    /// path tables.  Correcting them here is what keeps a create that happens
    /// to fill a full directory from writing a volume whose tree and whose
    /// tables disagree.
    fn append_to_directory(
        &self,
        parent: &Record,
        parent_record_offset: u64,
        record: &[u8],
    ) -> Result<u64> {
        let (location, new_size, record_offset) = write::append_record(
            &*self.device,
            self.block_size,
            parent.extent,
            parent.data_length,
            record,
            &mut Allocator::of(&self.device, self.block_size),
        )?;

        if location != parent.extent {
            let children = self.read_directory(parent)?;
            for child in children.iter().filter(|child| child.is_directory()) {
                let child_parent = self.parent_record_of(child.extent, child.data_length)?;
                write::rewrite_record_placement(&*self.device, child_parent, location, new_size)?;
            }
            write::rewrite_record_placement(
                &*self.device,
                parent_record_offset,
                location,
                new_size,
            )?;
            // Last, because the tables are rebuilt from the tree: the walk that
            // derives them starts at the root's record, which the line above
            // just moved when the directory that grew *is* the root.
            self.rewrite_path_tables()?;
            return Ok(record_offset);
        }

        write::rewrite_record_placement(&*self.device, parent_record_offset, location, new_size)?;
        Ok(record_offset)
    }

    /// Every directory the volume has, in the order a path table keeps them.
    ///
    /// The standard's order is by hierarchy level, then by the parent's number,
    /// then by identifier.  A level-order walk gives the first two for free —
    /// a parent is always numbered before its children — so this walks the
    /// levels in turn and sorts each directory's children by identifier.
    fn path_table_entries(&self, tree: &Tree) -> Result<Vec<PathTableEntry>> {
        let root = self.tree_root(tree)?;
        let root_entries = self.tree_directory(tree, &root)?;
        let mut entries = vec![PathTableEntry {
            identifier: vec![0x00],
            extent_location: root.extent,
            number: 1,
            parent_number: 1,
        }];

        let mut pending: VecDeque<(u16, Vec<Record>)> = VecDeque::new();
        pending.push_back((1, root_entries));
        while let Some((parent_number, records)) = pending.pop_front() {
            let mut children: Vec<Record> = records
                .into_iter()
                .filter(|record| record.is_directory() && !record.is_dot_entry())
                .collect();
            children.sort_by(|left, right| left.identifier.cmp(&right.identifier));

            for child in children {
                let number = u16::try_from(entries.len() + 1).map_err(|_| Error::NoSpace)?;
                entries.push(PathTableEntry {
                    identifier: child.identifier.clone(),
                    extent_location: child.extent,
                    number,
                    parent_number,
                });
                let sub = self.tree_directory(tree, &child)?;
                pending.push_back((number, sub));
            }
        }
        Ok(entries)
    }

    /// Rebuild the path tables from the tree, and write them.
    ///
    /// The tables are *derived* rather than edited: a directory's number is its
    /// position, so inserting one renumbers everything after it, and rebuilding
    /// the list is the same work with fewer ways to be wrong.  Two are
    /// required — one per byte order — and a volume may also carry optional
    /// copies, which are rewritten to the same content because a reader is
    /// allowed to follow them.  Every one of them goes in the descriptor that
    /// names the tree.
    fn rewrite_path_tables(&self) -> Result<()> {
        for tree in &self.trees {
            self.rewrite_path_tables_in(tree)?;
        }
        Ok(())
    }

    /// Rebuild one tree's path tables from that tree, and write them.
    ///
    /// Every one of them goes in the descriptor that names the tree: a second
    /// tree's tables are its own, and a reader that follows them must not be
    /// handed the first tree's directories.
    fn rewrite_path_tables_in(&self, tree: &Tree) -> Result<()> {
        let entries = self.path_table_entries(tree)?;
        let little = write::build_path_table(&entries, false);
        let big = write::build_path_table(&entries, true);
        debug_assert_eq!(little.len(), big.len());
        let size = u32::try_from(little.len()).map_err(|_| Error::NoSpace)?;

        let descriptor = read_descriptor(&*self.device, tree.descriptor_sector)?
            .ok_or(Error::InvalidArgument)?;
        let old_size = descriptor.path_table_size;
        let blocks = |bytes: u32| (bytes as u64).div_ceil(self.block_size as u64) as u32;

        let mut l_location = descriptor.l_path_table_loc;
        let mut m_location = descriptor.m_path_table_loc;
        if blocks(size) > blocks(old_size) {
            // A path table is one contiguous extent like any other, so more
            // room than it has means moving it to free blocks — one allocator
            // for both, so the second table cannot be handed the first's.
            let mut allocate = Allocator::of(&self.device, self.block_size);
            l_location = allocate.take(blocks(size))?;
            m_location = allocate.take(blocks(size))?;
        }

        let write_at = |location: u32, table: &[u8]| -> Result<()> {
            write::write_exact(
                &*self.device,
                location as u64 * self.block_size as u64,
                table,
            )
        };
        write_at(l_location, &little)?;
        write_at(m_location, &big)?;
        let opt_l = if descriptor.opt_l_path_table_loc == 0 {
            0
        } else {
            write_at(l_location, &little)?;
            l_location
        };
        let opt_m = if descriptor.opt_m_path_table_loc == 0 {
            0
        } else {
            write_at(m_location, &big)?;
            m_location
        };

        write::rewrite_path_table_fields(
            &*self.device,
            tree.descriptor_sector,
            size,
            l_location,
            opt_l,
            m_location,
            opt_m,
        )
    }

    /// Make a writable volume say which extension its entries belong to.
    ///
    /// A volume whose System Use areas carry Rock Ridge entries is required to
    /// name the extension in an `ER` entry, or a reader is entitled to ignore
    /// every one of them — and this driver has been *writing* such entries
    /// since names stopped having to be ISO 9660 identifiers.  The entry's own
    /// mandated text makes it 237 bytes, and a directory record's length is one
    /// byte, so the root's own "." record carries an `SP` marker and a `CE`
    /// naming a **continuation area** in a block of its own, where the entry
    /// goes.
    ///
    /// This runs **at open**, because the root's "." record grows by the area
    /// and every record after it moves: a node that had already been handed a
    /// record offset would then point at the wrong bytes, and at open no node
    /// exists yet.
    ///
    /// The root is built **elsewhere** and the volume repointed at it — the
    /// descriptor first, then the path tables, which name it too — so a crash
    /// leaves either the old root or the new one, whole.  That is the shape a
    /// file takes when it grows by moving, and it costs the same thing: the
    /// blocks the old root held are not reclaimed, because the allocator
    /// appends.  A failure between those two writes leaves the tables naming
    /// the extent the root left, which still holds exactly the entries it
    /// held, so a reader that follows a table reads the old list rather than a
    /// broken one.
    ///
    /// It is best-effort.  A volume this cannot be written to still mounts:
    /// reading the disc is the larger thing not to lose, and an entry written
    /// without the reference is still one this driver's own reader reads.
    fn declare_extension(&self) -> Result<()> {
        // The reference belongs in the primary tree's root, whose descriptor
        // is the one at sector 16: a Joliet tree is the second spelling of the
        // same entries, and the primary's is the one a reader looks at first.
        let primary =
            read_descriptor(&*self.device, DESCRIPTOR_SET_START)?.ok_or(Error::InvalidArgument)?;
        let (root, _next) =
            Record::parse(&primary.root_record, 0, false).ok_or(Error::InvalidArgument)?;
        if root.data_length as u64 > write::MAX_DIRECTORY_BYTES {
            return Err(Error::InvalidArgument);
        }
        let mut extent = vec![0u8; root.data_length as usize];
        allocate::read_extent_bytes(
            &*self.device,
            self.block_size,
            root.extent,
            root.data_length,
            0,
            &mut extent,
        )?;
        let (first, first_len) = Record::parse(&extent, 0, false).ok_or(Error::InvalidArgument)?;

        // The reference may be in the area itself or in the continuation a
        // `CE` entry names, which is where a writer that has one puts it.
        let declared = {
            let area = first.system_use();
            if area.has_extension_reference {
                true
            } else if let Some(continuation) = area.continuation {
                let mut bytes = vec![0u8; continuation.length as usize];
                allocate::read_extent_bytes(
                    &*self.device,
                    self.block_size,
                    continuation.block,
                    continuation.offset + continuation.length,
                    continuation.offset as u64,
                    &mut bytes,
                )
                .is_ok()
                    && SystemUse::parse(&bytes).has_extension_reference
            } else {
                false
            }
        };
        if declared {
            return Ok(());
        }

        // The continuation area first: nothing names it until the record below
        // does, so a failure or a crash here changes nothing that is read.
        let reference = susp::extensions_reference_entry();
        let mut allocate_ext = Allocator::of(&self.device, self.block_size);
        let continuation = allocate_ext.take(1)?;
        write::write_exact(
            &*self.device,
            continuation as u64 * self.block_size as u64,
            &reference,
        )?;

        // The root, rebuilt whole: its "." record grows by the area above and
        // every record after it moves, so the extent is written somewhere else
        // rather than edited where it is.
        let area = root_extension_area(continuation, reference.len() as u32);
        let tail = &extent[first_len..];
        // A record's length does not depend on the length it reports, so one
        // built with no size is what says how long the real one will be.
        let first_record_len = build_record(&[0x00], root.extent, 0, true, &area)?.len();
        let new_size = u32::try_from(first_record_len + tail.len()).map_err(|_| Error::NoSpace)?;
        let new_blocks = (new_size as u64).div_ceil(self.block_size as u64) as u32;
        let location = allocate_ext.take(new_blocks)?;

        let record = build_record(&[0x00], location, new_size, true, &area)?;
        let mut rebuilt = Vec::with_capacity(new_size as usize);
        rebuilt.extend_from_slice(&record);
        rebuilt.extend_from_slice(tail);
        debug_assert_eq!(rebuilt.len(), new_size as usize);

        // The root's own ".." names the root, and the root has moved: the copy
        // above took the record that said the old address.
        let placement = write::placement_field(location, new_size);
        let mut at = record.len();
        while let Some((entry, next)) = Record::parse(&rebuilt, at, false) {
            if entry.identifier == [0x01] {
                rebuilt[at + super::record::OFFSET_EXTENT..][..16].copy_from_slice(&placement);
                break;
            }
            at = next;
        }

        write::write_exact(
            &*self.device,
            location as u64 * self.block_size as u64,
            &rebuilt,
        )?;

        // Every directory the root holds names it in its own ".." record too,
        // and those records are in *other* extents — the copy above did not
        // touch them.  This is the same work [`Self::append_to_directory`]
        // does when a directory grows into a move, and for the same reason.
        for child in subdirectories(&extent, first_len) {
            let child_parent = self.parent_record_of(child.extent, child.data_length)?;
            write::rewrite_record_placement(&*self.device, child_parent, location, new_size)?;
        }

        // The commit: one write of the descriptor's own root record, which is
        // the thing that says where the root is.
        write::rewrite_record_placement(
            &*self.device,
            DESCRIPTOR_SET_START * SECTOR_SIZE as u64 + OFFSET_ROOT_RECORD as u64,
            location,
            new_size,
        )?;
        // The tables name the root too, and a reader may follow them instead of
        // walking the tree; rebuilding them is what the tree above decides.
        self.rewrite_path_tables()
    }

    /// Return the volume label.
    pub fn volume_label(&self) -> &str {
        &self.label
    }
}

impl Tree {
    /// The tree a descriptor describes, if it describes one this driver can
    /// use.
    fn of(descriptor: &VolumeDescriptor) -> Option<Tree> {
        // The root record is a directory record, and its extent and length are
        // the two fields a mount has to find before it can walk anything.
        let extent = u32::from_le_bytes([
            descriptor.root_record[2],
            descriptor.root_record[3],
            descriptor.root_record[4],
            descriptor.root_record[5],
        ]);
        let length = u32::from_le_bytes([
            descriptor.root_record[10],
            descriptor.root_record[11],
            descriptor.root_record[12],
            descriptor.root_record[13],
        ]);
        if extent == 0 || length == 0 {
            return None;
        }
        Some(Tree {
            descriptor_sector: descriptor.sector,
            joliet: descriptor.joliet,
        })
    }
}

/// Read one descriptor sector, or `None` when it is not one.
fn read_descriptor(device: &dyn BlockDevice, sector: u64) -> Result<Option<VolumeDescriptor>> {
    let mut bytes = [0u8; SECTOR_SIZE];
    let offset = sector * SECTOR_SIZE as u64;
    if write::read_exact(device, offset, &mut bytes).is_err() {
        return Ok(None);
    }
    Ok(VolumeDescriptor::parse(sector, &bytes))
}

// ── the mutations ────────────────────────────────────────────────────────

/// The bytes an empty directory's extent holds: its own two records, which
/// have one-byte identifiers and so are 34 bytes each.
const EMPTY_DIRECTORY_BYTES: u32 = 2 * (33 + 1);

/// Assemble a directory record from its parts, refusing one too long to write.
///
/// A record's own length is a single byte, so its identifier, its padding and
/// its System Use area together have to fit in 255 of them.  The name a caller
/// chose is in that area and is the part they control, so a name too long to
/// fit is refused — rather than written in part, which a reader would read
/// back as a different name.
fn build_record(
    identifier: &[u8],
    extent: u32,
    data_length: u32,
    directory: bool,
    system_use: &[u8],
) -> Result<Vec<u8>> {
    Record::build(identifier, extent, data_length, directory, system_use)
        .ok_or(Error::InvalidArgument)
}

/// The attributes a created entry gets out of the POSIX entry.
///
/// The mode is a POSIX one, file type included, which is what Rock Ridge
/// records and what a POSIX reader applies whole: a file its owner may write,
/// a directory it may enter, and everyone else may read.
fn default_posix(directory: bool) -> (u32, u32, u32, u32) {
    if directory {
        (0o040755, 2, 0, 0)
    } else {
        (0o100644, 1, 0, 0)
    }
}

/// The System Use area a created entry carries.
///
/// `PX` gives it the attributes a POSIX reader reports, `NM` the name its
/// caller used, and `ST` ends the area — which is what says the entries are
/// complete rather than truncated by the record that holds them.
fn rock_ridge_area(name: &str, posix: (u32, u32, u32, u32)) -> Vec<u8> {
    let (mode, links, uid, gid) = posix;
    let mut area = susp::posix_entry(mode, links, uid, gid);
    area.extend_from_slice(&susp::name_entry(name.as_bytes()));
    area.extend_from_slice(&susp::terminator_entry());
    area
}

/// The System Use area the root directory's own "." record carries.
///
/// It is the one record that declares what the volume's areas are: `SP` says
/// they are SUSP's at all, `PX` gives the root its attributes, and `CE` names
/// the block the extension reference continues in — because that entry does
/// not fit in a record, whose own length is one byte.
fn root_extension_area(continuation: u32, reference_size: u32) -> Vec<u8> {
    let (mode, links, uid, gid) = default_posix(true);
    let mut area = susp::sharing_protocol_entry();
    area.extend_from_slice(&susp::posix_entry(mode, links, uid, gid));
    area.extend_from_slice(&susp::continuation_entry(continuation, 0, reference_size));
    area.extend_from_slice(&susp::terminator_entry());
    area
}

/// The directories an extent holds, read out of bytes already in memory.
///
/// A directory's own "." and ".." are not children of it, so they are not
/// among the records a move has to correct.
fn subdirectories(extent: &[u8], from: usize) -> Vec<Record> {
    let mut children = Vec::new();
    let mut at = from;
    while let Some((record, next)) = Record::parse(extent, at, false) {
        if record.is_directory() && !record.is_dot_entry() {
            children.push(record);
        }
        at = next;
    }
    children
}

/// The identifier a directory record carries for the name a caller used.
///
/// The identifier is what a reader **without** Rock Ridge sees, and the rule
/// for one is level 2: upper case letters, digits, underscores and at most one
/// dot, inside thirty bytes, with the `;1` version a file has and a directory
/// does not.  The name itself is kept instead in the record's `NM` entry
/// ([`susp::name_entry`]), so the identifier is only the fallback a reader
/// that ignores Rock Ridge falls back to: a name with none of those characters
/// in it is *mangled* to the nearest identifier rather than refused.
///
/// Mangling is many-to-one — `a b` and `a_b` both want `A_B` — and two records
/// with one identifier are two entries only one of which a lookup can reach,
/// so the identifiers the directory already holds decide a numbered suffix.
fn identifier_for(name: &str, directory: bool, taken: &[Vec<u8>]) -> Result<Vec<u8>> {
    /// A level-2 identifier is at most thirty bytes, version included.
    const MAX_IDENTIFIER: usize = 30;
    /// How many suffixes a collision is worth trying before giving up.
    const SUFFIX_LIMIT: u32 = 9999;

    let room = if directory {
        MAX_IDENTIFIER
    } else {
        MAX_IDENTIFIER - 2 // the ";1" every file identifier carries
    };

    let mut stem = Vec::with_capacity(name.len().min(room));
    let mut dotted = false;
    for character in name.chars() {
        match character.to_ascii_uppercase() {
            upper @ ('A'..='Z' | '0'..='9' | '_') => stem.push(upper as u8),
            '.' if !dotted => {
                dotted = true;
                stem.push(b'.');
            }
            _ => stem.push(b'_'),
        }
    }
    if stem.is_empty() {
        stem.push(b'_');
    }
    stem.truncate(room);

    let versioned = |stem: &[u8]| -> Vec<u8> {
        let mut out = Vec::with_capacity(stem.len() + 2);
        out.extend_from_slice(stem);
        if !directory {
            out.extend_from_slice(b";1");
        }
        out
    };
    let taken_holds = |candidate: &[u8]| taken.iter().any(|held| held == candidate);

    let candidate = versioned(&stem);
    if !taken_holds(&candidate) {
        return Ok(candidate);
    }

    // A suffix has to fit inside the identifier too, so the stem gives back as
    // many bytes as the number takes.
    for suffix in 1..=SUFFIX_LIMIT {
        let text = format!("_{suffix}");
        let keep = room.saturating_sub(text.len()).min(stem.len());
        let mut numbered = stem[..keep].to_vec();
        numbered.extend_from_slice(text.as_bytes());
        let candidate = versioned(&numbered);
        if !taken_holds(&candidate) {
            return Ok(candidate);
        }
    }
    Err(Error::NoSpace)
}

/// The identifiers a directory holds, which is what a name is mangled against.
fn identifiers_in(entries: &[Record]) -> Vec<Vec<u8>> {
    entries
        .iter()
        .map(|entry| entry.identifier.clone())
        .collect()
}

/// The path of the directory a path names a child of.
fn parent_path_of(path: &str) -> &str {
    match path.rfind('/') {
        Some(0) | None => "/",
        Some(index) => &path[..index],
    }
}

/// The attributes a record's `PX` entry carries, as the VFS's descriptor.
fn rr_to_security(posix: &Option<susp::PosixAttributes>) -> SecurityDescriptor {
    match posix {
        // A Rock Ridge `PX` mode is a POSIX one, file type included, and the
        // VFS's is the permission bits alone (`MAX_PERMISSION_MODE`), which is
        // what every other filesystem here reports.
        Some(attributes) => SecurityDescriptor {
            owner_uid: attributes.uid,
            owner_gid: attributes.gid,
            mode: (attributes.mode & u32::from(MAX_PERMISSION_MODE)) as u16,
        },
        None => SecurityDescriptor {
            owner_uid: 0,
            owner_gid: 0,
            mode: 0o555,
        },
    }
}

impl FileSystem for Iso9660Volume {
    fn name(&self) -> &str {
        &self.label
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        let (record, record_offset) = self.resolve(path)?;
        let kind = if record.is_directory() {
            NodeKind::Directory
        } else if record.system_use().symlink.is_some() {
            NodeKind::Symlink
        } else {
            NodeKind::File
        };
        Ok(Arc::new(Iso9660VNode {
            device: self.device.clone(),
            name: record.name(),
            kind,
            extent: AtomicU32::new(record.extent),
            length: AtomicU32::new(record.data_length),
            record_offset,
            trees: self.tree_count(),
            volume_floor: self.volume_floor,
            rr_posix: record.system_use().posix,
            rr_symlink: record
                .system_use()
                .symlink
                .map(|components| susp::render_link(&components).into_bytes()),
            block_size: self.block_size,
        }))
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        let (record, _offset) = self.resolve(path)?;
        if !record.is_directory() {
            return Err(Error::InvalidArgument);
        }
        let entries = self.read_directory(&record)?;
        let entry = entries.get(index).ok_or(Error::NotFound)?;
        let kind = if entry.is_directory() {
            NodeKind::Directory
        } else if entry.system_use().symlink.is_some() {
            NodeKind::Symlink
        } else {
            NodeKind::File
        };
        Ok(
            DirectoryEntry::new(kind, entry.data_length as usize, entry.name())
                .with_security(rr_to_security(&entry.system_use().posix)),
        )
    }

    /// Move or rename an entry.
    ///
    /// This is a removal and a create the caller sees as one: the record leaves
    /// its directory, and an identical one — the same extent and the same
    /// length — joins the destination's under the new name.  A directory also
    /// carries ".." pointing at its parent, so a move rewrites that, and both
    /// path tables are rebuilt because a directory's level and number are
    /// properties of where it sits.
    fn rename(&self, old_path: &str, new_path: &str) -> Result<()> {
        if old_path == new_path {
            return Ok(());
        }
        self.refuse_a_change_to_one_of_two_trees()?;
        if self.device.is_read_only() {
            return Err(Error::PermissionDenied);
        }

        let (record, record_offset) = self.resolve(old_path)?;
        if self.resolve(new_path).is_ok() {
            return Err(Error::AlreadyExists);
        }
        let (old_parent, old_parent_record_offset, _old_name) = self.resolve_child(old_path)?;
        let new_name = self.resolve_child(new_path)?.2;

        if record.is_directory() {
            // A directory cannot move inside itself: the records a move would
            // rewrite are the ones it is made of.
            let old_prefix = format!("{old_path}/");
            let new_parent_path = parent_path_of(new_path);
            if new_parent_path == old_path || new_parent_path.starts_with(&old_prefix) {
                return Err(Error::InvalidArgument);
            }
        }

        // Out of the old directory first, and then the destination is resolved
        // again: when both are the same directory, the removal shortened it and
        // the append has to see the length that leaves.
        write::remove_child_record(
            &*self.device,
            self.block_size,
            old_parent.extent,
            old_parent.data_length,
            old_parent_record_offset,
            record_offset,
            record.record_len,
        )?;
        let (new_parent, new_parent_record_offset, _new_name) = self.resolve_child(new_path)?;

        let entries = self.read_directory(&new_parent)?;
        let identifier =
            identifier_for(&new_name, record.is_directory(), &identifiers_in(&entries))?;
        // The entry keeps everything its record said about it — its POSIX
        // attributes, a symlink's target, whatever else its System Use area
        // holds — except the name entries, which are the one thing a rename
        // changes.
        let bytes = build_record(
            &identifier,
            record.extent,
            record.data_length,
            record.is_directory(),
            &susp::with_name(&record.system_use, new_name.as_bytes()),
        )?;
        let _record_offset =
            self.append_to_directory(&new_parent, new_parent_record_offset, &bytes)?;

        if record.is_directory() {
            if old_parent.extent != new_parent.extent {
                // ".." is the directory's own record of its parent, and this is
                // the one thing about it that a move changes.
                let parent_record = self.parent_record_of(record.extent, record.data_length)?;
                write::rewrite_record_placement(
                    &*self.device,
                    parent_record,
                    new_parent.extent,
                    new_parent.data_length,
                )?;
            }
            self.rewrite_path_tables()?;
        }
        Ok(())
    }

    /// Add a regular file to a directory.
    ///
    /// The file is *empty*: its record points at where the volume's space ends
    /// and says its length is zero, so creating one costs the record and
    /// nothing else, and the first write is what gives it blocks.
    ///
    /// The name the caller used is what its record's `NM` entry holds, so a
    /// name the identifier cannot spell — lower case, spaces, anything — is
    /// stored as itself and read back as itself, while the identifier is the
    /// mangled form a reader without Rock Ridge sees.
    fn create_file(&self, path: &str) -> Result<Arc<dyn VNode>> {
        self.refuse_a_change_to_one_of_two_trees()?;
        if self.device.is_read_only() {
            return Err(Error::PermissionDenied);
        }
        if self.resolve(path).is_ok() {
            return Err(Error::AlreadyExists);
        }
        let (parent, parent_record_offset, child) = self.resolve_child(path)?;
        let entries = self.read_directory(&parent)?;
        let identifier = identifier_for(&child, false, &identifiers_in(&entries))?;

        let extent_location = allocate::volume_blocks(&*self.device)?;
        let (mode, links, uid, gid) = default_posix(false);
        let record = build_record(
            &identifier,
            extent_location,
            0,
            false,
            &rock_ridge_area(&child, (mode, links, uid, gid)),
        )?;
        let record_offset = self.append_to_directory(&parent, parent_record_offset, &record)?;

        Ok(Arc::new(Iso9660VNode {
            // The record's name entry holds what the caller asked for, so the
            // node is named that and a second mount agrees.
            device: self.device.clone(),
            name: child,
            kind: NodeKind::File,
            extent: AtomicU32::new(extent_location),
            length: AtomicU32::new(0),
            record_offset,
            trees: self.tree_count(),
            volume_floor: self.volume_floor,
            // The attributes are what the record this call wrote carries, so
            // the node answers with them rather than with the default a record
            // without them would get.
            rr_posix: Some(susp::PosixAttributes {
                mode,
                links,
                uid,
                gid,
            }),
            rr_symlink: None,
            block_size: self.block_size,
        }))
    }

    fn create_dir(&self, path: &str) -> Result<()> {
        self.refuse_a_change_to_one_of_two_trees()?;
        if self.device.is_read_only() {
            return Err(Error::PermissionDenied);
        }
        if self.resolve(path).is_ok() {
            return Err(Error::AlreadyExists);
        }
        let (parent, parent_record_offset, child) = self.resolve_child(path)?;
        let entries = self.read_directory(&parent)?;
        let identifier = identifier_for(&child, true, &identifiers_in(&entries))?;

        // A directory's extent holds its own two records before anything else:
        // "." is itself and ".." is its parent, and they are what makes it a
        // directory at all.
        let extent_location = Allocator::of(&self.device, self.block_size).take(1)?;
        let mut extent = Record::build(&[0x00], extent_location, EMPTY_DIRECTORY_BYTES, true, &[])
            .ok_or(Error::InvalidArgument)?;
        extent.extend_from_slice(
            &Record::build(&[0x01], parent.extent, parent.data_length, true, &[])
                .ok_or(Error::InvalidArgument)?,
        );
        debug_assert_eq!(extent.len(), EMPTY_DIRECTORY_BYTES as usize);
        write::write_exact(
            &*self.device,
            extent_location as u64 * self.block_size as u64,
            &extent,
        )?;

        // The parent's own record for it, appended to the parent's extent the
        // way any other child is.
        let record = build_record(
            &identifier,
            extent_location,
            EMPTY_DIRECTORY_BYTES,
            true,
            &rock_ridge_area(&child, default_posix(true)),
        )?;
        let _record_offset = self.append_to_directory(&parent, parent_record_offset, &record)?;

        // And the path tables, which are how a reader finds a directory without
        // walking the tree.  They come last on purpose: a crash between the two
        // leaves a directory the *tree* has and the table does not, which a
        // walk still finds, rather than an entry for a directory that is not
        // there at all.
        self.rewrite_path_tables()
    }

    /// Take a regular file out of its directory.
    ///
    /// The records after it move down over it rather than being re-serialised:
    /// a record carries whatever its writer put in the System Use area, and
    /// this driver does not parse all of it, so the bytes are the only honest
    /// copy.  What the file's blocks were are free again the moment its record
    /// is gone: the volume's declared size comes down over them when they were
    /// its last, and the block map finds them wherever they are.
    fn remove_path(&self, path: &str) -> Result<()> {
        self.refuse_a_change_to_one_of_two_trees()?;
        if self.device.is_read_only() {
            return Err(Error::PermissionDenied);
        }
        let (record, record_offset) = self.resolve(path)?;
        if record.is_directory() {
            // A directory that still holds something cannot go: its children's
            // records would be pointing at a parent nothing names, and the
            // path tables would have to lose their entries one by one.  An
            // empty one is exactly its own two records.
            if record.data_length != EMPTY_DIRECTORY_BYTES {
                return Err(Error::Busy);
            }
        }
        let (parent, parent_record_offset, _child) = self.resolve_child(path)?;
        write::remove_child_record(
            &*self.device,
            self.block_size,
            parent.extent,
            parent.data_length,
            parent_record_offset,
            record_offset,
            record.record_len,
        )?;

        // The record is gone, so whatever the entry held is free — and if it
        // was the last thing the volume held, its blocks are the volume's last
        // and it takes them back.  A removal in the middle gives nothing back,
        // because what is free there is not something this driver can see
        // without walking every extent on the volume.
        allocate::release_volume_tail(
            &*self.device,
            self.block_size,
            self.volume_floor,
            record.extent,
            record.data_length,
            0,
        )?;

        if record.is_directory() {
            // The tables still name it, and a table that names a directory the
            // tree does not have is the worse half of the same crash.
            self.rewrite_path_tables()?;
        }
        Ok(())
    }

    fn security_descriptor_mutation_support(&self) -> SecurityDescriptorMutationSupport {
        SecurityDescriptorMutationSupport::LayoutDerivedOnly
    }

    fn update_security_descriptor(&self, _path: &str, _security: SecurityDescriptor) -> Result<()> {
        Err(Error::PermissionDenied)
    }

    fn check_and_repair(&self) -> Result<VolumeCheckReport> {
        let mut issues = 0usize;

        if self.block_size == 0 {
            issues += 1;
        }

        if self.lookup("/").is_err() {
            issues += 1;
        }

        Ok(VolumeCheckReport {
            issues_detected: issues,
            ..Default::default()
        })
    }

    fn sync(&self) -> Result<()> {
        self.device.flush()
    }

    fn sync_data(&self) -> Result<()> {
        self.sync()
    }
}

/// A node on an ISO 9660 disc.
struct Iso9660VNode {
    device: Arc<dyn BlockDevice>,
    name: String,
    kind: NodeKind,
    /// The file's first logical block, as its record says.
    ///
    /// Atomic because a growth that has to move the file rewrites it: an
    /// extent is one contiguous run, so a file with something after it moves
    /// to new space rather than growing in place.
    extent: AtomicU32,
    /// The length the file's directory record carries.
    ///
    /// Atomic because [`VNode::set_len`] changes it: the record on the
    /// volume is the authority, and this is the copy the node answers with
    /// while it lives.
    length: AtomicU32,
    /// Where this node's own directory record sits on the volume, in bytes.
    ///
    /// A resize rewrites the length *in that record*, and nothing else on the
    /// volume knows the file's size.
    record_offset: u64,
    /// How many directory trees the disc has.
    ///
    /// One means the record above is the only copy of the file's length.  More
    /// than one means every tree has a copy, and the trees do not spell the
    /// file's name the same way — so which record in the other tree is *this*
    /// file's is not a question the volume answers, and a length is not
    /// something to write into a guess.
    trees: u8,
    /// The size the volume declared when it was opened, which is the floor a
    /// shrink may not take blocks back below.
    volume_floor: u32,
    rr_posix: Option<susp::PosixAttributes>,
    rr_symlink: Option<Vec<u8>>,
    block_size: u16,
}

impl VNode for Iso9660VNode {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> NodeKind {
        self.kind
    }

    fn size(&self) -> usize {
        self.length.load(Ordering::Relaxed) as usize
    }

    fn metadata(&self) -> Result<Metadata> {
        Ok(Metadata::new(self.kind, self.size()).with_security(rr_to_security(&self.rr_posix)))
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        if self.kind == NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }
        let length = self.length.load(Ordering::Relaxed) as u64;
        if offset >= length {
            return Ok(0);
        }
        let available = (length - offset) as usize;
        let count = available.min(buffer.len());
        // The read is from the file's own extent, which is contiguous by the
        // format; a file that is not is refused at mount or at directory read,
        // not here.
        let start = self.extent.load(Ordering::Relaxed) as u64 * self.block_size as u64 + offset;
        write::read_exact(&*self.device, start, &mut buffer[..count])?;
        Ok(count)
    }

    /// Overwrite bytes the file already has.
    ///
    /// A write inside the file's length changes no metadata at all.  One that
    /// runs past the end grows the file first — the same `set_len` a caller
    /// could ask for — so a caller can create a file and write it the way it
    /// writes any other.  When the file cannot grow, the write is **short**
    /// rather than failing, which is the answer this call has always given for
    /// a byte it could not take.
    fn write(&self, offset: u64, buffer: &[u8]) -> Result<usize> {
        if self.kind != NodeKind::File {
            return Err(Error::InvalidArgument);
        }
        if self.device.is_read_only() {
            return Err(Error::PermissionDenied);
        }
        let end = offset.saturating_add(buffer.len() as u64);
        if end > self.size() as u64 {
            // A refusal here is not this write's answer: the short write below
            // is.
            let _ = self.set_len(end);
        }
        write::write_extent(
            &*self.device,
            self.block_size,
            self.extent.load(Ordering::Relaxed),
            self.length.load(Ordering::Relaxed),
            offset,
            buffer,
        )
    }

    /// Change the length the file's directory record carries.
    ///
    /// The record is the file's only metadata — its extent start and its
    /// length, both fields of the record — so a resize in place is one 16-byte
    /// write that covers both.
    ///
    /// A file's extent starts on a logical block boundary and its blocks are
    /// its own, so a length up to the end of the block the current one ends in
    /// needs no allocation: growing into that block's tail is free, and
    /// shrinking is free.  Past that block the file needs more blocks, and a
    /// file's extent is **one contiguous run**, so there are two ways to get
    /// them: take the blocks that follow, when the file is the last thing the
    /// volume holds, or move the file — into the free space the allocator
    /// finds, which is where a hole a removal left is handed out again.
    fn set_len(&self, length: u64) -> Result<()> {
        if self.kind != NodeKind::File {
            return Err(Error::InvalidArgument);
        }
        if self.device.is_read_only() {
            return Err(Error::PermissionDenied);
        }
        let length = u32::try_from(length).map_err(|_| Error::InvalidArgument)?;
        let current = self.length.load(Ordering::Relaxed);
        if length == current {
            return Ok(());
        }
        // A file's *length* is a field of a record in every tree, and a
        // volume's trees do not spell the file's name the same way: which
        // record in the other tree is this file's is not something the volume
        // says.  What a change to the length would leave behind is one tree
        // that has it and one that does not, so it is refused — and an
        // overwrite *inside* the length is not, because the data both trees
        // point at is the same data.
        if self.trees > 1 {
            return Err(Error::Unsupported);
        }

        // Past the block the file has, the extent needs blocks; `place_extent`
        // grows it where the volume ends and moves it to free blocks where it
        // cannot — which is what puts a moved file into a hole a removal left.
        let extent_location = self.extent.load(Ordering::Relaxed);
        let mut allocate = Allocator::of(&self.device, self.block_size);
        let extent = allocate::place_extent(
            &*self.device,
            self.block_size,
            extent_location,
            current,
            length,
            &mut allocate,
        )?;

        // Where the file is and how long it is, in one write: the two fields
        // are adjacent in the record and each is stored twice.
        write::rewrite_record_placement(&*self.device, self.record_offset, extent, length)?;

        // A shrink that gives up whole blocks at the very end of the volume
        // hands them back to it, which is the one place this driver can tell
        // what is free without walking the tree.
        if length < current {
            allocate::release_volume_tail(
                &*self.device,
                self.block_size,
                self.volume_floor,
                extent,
                current,
                length,
            )?;
        }

        self.extent.store(extent, Ordering::Relaxed);
        self.length.store(length, Ordering::Relaxed);
        Ok(())
    }

    fn readlink(&self) -> Result<Vec<u8>> {
        match &self.rr_symlink {
            Some(data) => Ok(data.clone()),
            None => Err(Error::InvalidArgument),
        }
    }
}
