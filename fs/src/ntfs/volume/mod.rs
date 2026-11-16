//! fs/src/ntfs/volume/mod.rs
//!
//! The NTFS volume: mounting, path resolution, the attributes a record holds
//! wherever an attribute list has moved them, the index a directory's names
//! live in, and the write path that keeps the bitmap, the index and the
//! MFT's own size in step with what a write claims.

use alloc::collections::btree_map::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::filesystem::FileSystem;
use block::BlockDevice;

use crate::types::DirectoryEntry;
use crate::types::NodeKind;
use crate::vnode::ExtentKind;
use crate::vnode::VNode;
use abi::Error;
use abi::Result;
use sync::Mutex;
use sync::SpinLock;

use super::fs;
use super::fs::parse_index_node;
use super::types::*;

// The module is split by what the methods do; each child adds one
// `impl NtfsFs` block.  A child sees these constants, helpers and the
// struct's private fields because a child module may reach its parent's
// items, which is why nothing had to be made `pub(crate)` for the split.
mod index;
mod metadata;
mod mft;
mod mount;
mod records;
mod streams;

// NTFS filesystem handle

/// The root directory's record, which the standard fixes at the fifth.
const ROOT_RECORD: u64 = 5;

/// The volume's own record, which the standard fixes at the third.
const VOLUME_RECORD: u64 = 3;

/// The volume's cluster bitmap, which the standard fixes at the sixth.
const BITMAP_RECORD: u64 = 6;

/// The `$MFT`'s own record, whose `$DATA` is the records themselves.
const MFT_RECORD: u64 = 0;

/// The `$MFTMirr`'s record, which the standard fixes at the second.  Its
/// `$DATA` names where the mirror of the volume's first records lives.
pub(crate) const MFT_MIRR_RECORD: u64 = 1;

/// How many of the MFT's **first records** the mirror holds.  The format fixes
/// the count at four; a volume whose record size is a whole number of clusters
/// mirrors one cluster instead, which is the same four records whenever a
/// record is a cluster wide, and more bytes than four when it is wider.  This
/// driver mirrors four records and never claims more.
const MFT_MIRR_RECORDS: u64 = 4;

/// The volume's `$UpCase` table, which the standard fixes at the tenth.
const UPCASE_RECORD: u64 = 10;

/// Where a volume's flags are inside its `$VOLUME_INFORMATION` value: eight
/// reserved bytes, then a major and a minor version.
const VOLUME_FLAGS_OFFSET: usize = 10;

/// The first record a new file's own can come from.
///
/// The volume keeps its first sixteen records for itself; the free space a
/// file's record comes from is what follows them.  Which of those is free is
/// the record header's own business: a record that is formatted but not in use
/// is one nothing names.
const FIRST_FREE_RECORD: u64 = 16;

/// How deep an index tree this driver will follow before it gives up.
///
/// A directory's index is a B-tree, and a volume can make one deeper than a
/// reader should walk looking for a name: the bound is what keeps a damaged
/// pointer from being a loop.
const MAX_INDEX_DEPTH: u32 = 8;

/// How far up a parent chain this driver will walk.
///
/// A name's `$FILE_NAME` is the only link from a record to the record it is in,
/// so a walk upward is a walk of those, and the bound is what keeps a loop
/// written by something else from being this driver's loop.
const MAX_ANCESTORS: u32 = 64;

/// A path's last segment, and the directory it is in.
///
/// A path here begins at the root and is separated by one byte, so the last
/// separator is what tells a name from the path above it.
fn split_parent(path: &str) -> (&str, &str) {
    match path.rfind('/') {
        Some(at) => {
            let parent = if at == 0 { "/" } else { &path[..at] };
            (parent, &path[at + 1..])
        }
        None => ("/", path),
    }
}

/// Compare two names the way the volume's index does.
///
/// NTFS orders an index through the `$UpCase` table the volume carries: names
/// are compared uppercased, character by character, and a name that is a
/// prefix of another sorts first.  A volume whose table cannot be read is
/// compared as its names are stored, which is this driver's own order and not
/// the format's.
fn compare_names(left: &str, right: &str, upcase: &[u16]) -> core::cmp::Ordering {
    let folded = |code: u16| upcase.get(code as usize).copied().unwrap_or(code);
    let mut left = left.encode_utf16();
    let mut right = right.encode_utf16();
    loop {
        match (left.next(), right.next()) {
            (Some(a), Some(b)) => {
                let (a, b) = (folded(a), folded(b));
                if a != b {
                    return a.cmp(&b);
                }
            }
            (None, Some(_)) => return core::cmp::Ordering::Less,
            (Some(_), None) => return core::cmp::Ordering::Greater,
            (None, None) => return core::cmp::Ordering::Equal,
        }
    }
}

/// Where a directory keeps its index entries, so a change can be written back
/// to the place it belongs.
#[derive(Clone)]
enum IndexHome {
    /// In the `$INDEX_ROOT`'s value: the record that *holds* that attribute is
    /// the buffer, the parent record itself, or an extension record an
    /// `$ATTRIBUTE_LIST` moved the root into, and writing it back means
    /// writing that record whole, its update sequence array packed again.
    Record { holder: u64 },
    /// In an `$INDEX_ALLOCATION` block at a virtual cluster number: the block
    /// is the buffer, and it carries an update sequence array of its own.
    Block {
        vcn: u64,
        runs: Vec<DataRun>,
        usa_offset: usize,
        usa_count: usize,
    },
}

/// Whether a bitmap says a particular number is in use.
fn bit_is_set(bits: &[u8], number: u64) -> bool {
    let index = (number / 8) as usize;
    index < bits.len() && bits[index] & (1 << (number % 8)) != 0
}

/// Whether two list entries are parts of the same attribute.
fn names_the_same(left: &fs::AttributeListEntry, right: &fs::AttributeListEntry) -> bool {
    left.attr_type == right.attr_type
        && left.instance == right.instance
        && left.name.as_deref() == right.name.as_deref()
}

/// Whether a list entry names an attribute, wherever it lives.
fn names_the_same_attribute(entry: &fs::AttributeListEntry, attribute: &ParsedAttr) -> bool {
    entry.attr_type == attribute.attr_type
        && entry.instance == attribute.instance
        && entry.name.as_deref() == attribute.name.as_deref()
}

/// The attribute a record holds *in its own* bytes.
///
/// A writer patches a field where it lies, so an attribute that lives in
/// another record, an `$ATTRIBUTE_LIST` moved it, or in several, a run list
/// *split* by virtual cluster number, is `NotImplemented`: there is no one
/// place the field is, and half a patch is worse than none.
fn own_attribute(
    record_number: u64,
    attributes: &[ParsedAttr],
    attr_type: u32,
) -> Result<&ParsedAttr> {
    let attribute = attributes
        .iter()
        .find(|attribute| attribute.attr_type == attr_type)
        .ok_or(Error::NotFound)?;
    if attribute.holder != record_number {
        return Err(Error::NotImplemented);
    }
    Ok(attribute)
}

/// How many bytes of a record are in use, from its own header.
fn bytes_in_use(record: &[u8]) -> usize {
    u32::from_le_bytes([record[24], record[25], record[26], record[27]]) as usize
}

/// Refuse a stream this driver cannot read, rather than returning bytes that
/// are not the file's.
///
/// A `$DATA` whose flags say it is **compressed** has runs that name clusters
/// holding an LZNT1 bitstream, and one whose flags say it is **encrypted**
/// holds ciphertext; either read as a plain runlist answers a caller with
/// something file-shaped and false, and a read that succeeds and is wrong is
/// the one failure a filesystem cannot report.  `NotImplemented` can be
/// reported, and [RFC
/// 0013](../../docs/rfcs/0013-refuse-the-ntfs-streams-this-driver-cannot-read.
/// md) decides it is the answer: the file stays listed, its name and sizes are
/// in its parent's index, and the operation that asks for its bytes is what
/// fails.
fn refuse_a_stream_this_driver_cannot_read(attribute: &ParsedAttr) -> Result<()> {
    if attribute.flags & (ATTR_FLAG_COMPRESSED | ATTR_FLAG_ENCRYPTED) != 0 {
        return Err(Error::NotImplemented);
    }
    Ok(())
}

/// The value of a record's `$ATTRIBUTE_LIST`, with an entry added for the
/// attribute that is about to join an extension record of its own, and one
/// for the index bitmap beside it, each where its own type sorts.
///
/// `home` is the record the two new entries name, which is only known for
/// certain once the record has been claimed; the measurement that decides
/// whether it can be claimed builds the value around a placeholder, because
/// the entries' lengths do not depend on the record they name.
fn allocation_list_value(listed: &[fs::AttributeListEntry], instance: u16, home: u64) -> Vec<u8> {
    let allocation = fs::list_entry(ATTR_TYPE_INDEX_ALLOC, "$I30", instance, 0, home);
    let bitmap = fs::list_entry(ATTR_TYPE_BITMAP, "$I30", instance.wrapping_add(1), 0, home);
    let mut value = Vec::new();
    let (mut named_allocation, mut named_bitmap) = (false, false);
    for entry in listed {
        if !named_allocation && entry.attr_type > ATTR_TYPE_INDEX_ALLOC {
            value.extend_from_slice(&allocation);
            named_allocation = true;
        }
        if !named_bitmap && entry.attr_type > ATTR_TYPE_BITMAP {
            value.extend_from_slice(&bitmap);
            named_bitmap = true;
        }
        value.extend_from_slice(&fs::list_entry(
            entry.attr_type,
            entry.name.as_deref().unwrap_or(""),
            entry.instance,
            entry.lowest_vcn,
            entry.holder | (u64::from(entry.sequence) << 48),
        ));
    }
    if !named_allocation {
        value.extend_from_slice(&allocation);
    }
    if !named_bitmap {
        value.extend_from_slice(&bitmap);
    }
    value
}

/// The attributes a new record holds.
/// Where a change to a directory's index is about to happen.
#[derive(Clone)]
struct IndexLeaf {
    /// The buffer the leaf's node is in: a block, or the record that holds the
    /// index root.
    buffer: Vec<u8>,
    /// Where the leaf's node begins in it.
    node: usize,
    /// Where that buffer lives, so the change can be written back.
    home: IndexHome,
    /// The nodes the walk went through, from the index **root** down: the last
    /// is the one the leaf hangs from, and a node above a *block* is the shape
    /// a tree deeper than one level of blocks has.
    ancestors: Vec<IndexParent>,
    /// The name the walk is about, where a node holds it as a **key** rather
    /// than the leaf holding it as an entry: any node on the way down can, and
    /// the node that does is the one a change takes it out of.
    key: Option<IndexKey>,
}

/// The node above a leaf block, and the entry the walk descended through.
#[derive(Clone)]
struct IndexParent {
    buffer: Vec<u8>,
    node: usize,
    /// Where that entry begins in the buffer: the promoted key goes before it.
    before: usize,
    /// Where the parent's buffer lives, so its growth is written back the same
    /// way any index node's is.
    home: IndexHome,
}

/// A node above a leaf, with one more entry in it: the key a split promotes,
/// where the node's own order puts it.
///
/// The key goes **before** the entry the walk descended through, because that
/// entry keeps the greater names: the child a keyed entry points at holds the
/// keys *less* than the one the entry carries.  `false` is the answer when the
/// entry the walk came through is not in the node at all, the buffers are
/// stale, and the change has to be worked out again.
fn node_entries_with(parent: &IndexParent, separator: &[u8]) -> Result<(Vec<Vec<u8>>, bool)> {
    let mut entries: Vec<Vec<u8>> = Vec::new();
    let mut inserted = false;
    for entry in parse_index_node(&parent.buffer, parent.node).entries {
        if !inserted && entry.offset >= parent.before {
            entries.push(separator.to_vec());
            inserted = true;
        }
        entries.push(parent.buffer[entry.offset..entry.offset + entry.length].to_vec());
    }
    Ok((entries, inserted))
}

/// The name a change is about, where a node holds it as a key.
#[derive(Clone)]
struct IndexKey {
    /// The node's bytes, and where its node begins in them.
    buffer: Vec<u8>,
    node: usize,
    /// Where those bytes live, so the change can be written back.
    home: IndexHome,
    /// Where the entry that carries the name begins in the buffer, and how long
    /// it is, the entry a change replaces or drops.
    offset: usize,
    length: usize,
}

/// What a new record is for, which is what decides what it holds.
pub(crate) enum NewRecord<'a> {
    /// A file or a directory of its own: where it came from, its own name, and
    /// either an empty `$DATA` or an empty index.
    Named {
        parent: u64,
        name: &'a str,
        directory: bool,
    },
    /// An *extension* record: attributes another record's `$ATTRIBUTE_LIST`
    /// names, and a reference back to the record they belong to.
    Extension { base: u64, attributes: Vec<Vec<u8>> },
}

/// The attributes a new record holds.
///
/// What a real one carries at the moment it is made: where it came from, its
/// own name, the timestamps a volume with no clock leaves zero, and then
/// either an empty `$DATA`, which is *resident*, because that is where an
/// empty file's bytes live, or, for a directory, the empty index it grows
/// into.  A file that grows out of its record has to convert that attribute,
/// which is a step this driver does not take yet.
fn record_attributes(
    parent: u64,
    name: &str,
    directory: bool,
    index_block_size: u32,
    cluster_size: u32,
) -> Vec<Vec<u8>> {
    // A record's own standard information is where the file-attribute bits
    // live, and archive is what a real volume writes there, for a directory
    // too, whose "is a directory" bit lives in its name and its record header.
    let mut standard = alloc::vec![0u8; 48];
    standard[32..36].copy_from_slice(&0x20u32.to_le_bytes());
    let filename = fs::file_name_value(parent, name, directory, 0);
    let mut attributes = alloc::vec![
        fs::resident_attribute(ATTR_TYPE_STANDARD_INFO, "", 0, &standard),
        fs::resident_attribute(ATTR_TYPE_FILENAME, "", 1, &filename),
    ];
    if directory {
        attributes.push(fs::resident_attribute(
            ATTR_TYPE_INDEX_ROOT,
            "$I30",
            2,
            &fs::empty_index_root(index_block_size, cluster_size),
        ));
    } else {
        attributes.push(fs::resident_attribute(ATTR_TYPE_DATA, "", 2, &[]));
    }
    attributes
}

pub struct NtfsFs {
    pub(crate) device: Arc<dyn BlockDevice>,
    /// The mount's own state, **shared by every clone of it**.
    ///
    /// A vnode is handed a clone of the filesystem, so a cache and a record
    /// size that each clone kept to itself would be two views of one volume:
    /// a write through a vnode would leave the mount that made it answering
    /// with the record it had.  The locks are the shared things, and a clone
    /// is another handle to them.
    info: Arc<Mutex<fs::NtfsInfo>>,
    mft_cache: Arc<Mutex<BTreeMap<u64, Vec<u8>>>>,
    /// The volume's sector size, which is where a record's update sequence
    /// numbers sit.
    ///
    /// Kept beside the device rather than read out of `info` on every record,
    /// because a *read* of a cached record has to check those numbers, and
    /// taking the info lock there would be taking it inside a caller that
    /// already holds it, the lock the reader is documented to keep *outside*
    /// the reads below it.
    sector_size: usize,
}

impl FileSystem for NtfsFs {
    fn name(&self) -> &str {
        "ntfs"
    }

    fn lookup(&self, _path: &str) -> Result<Arc<dyn VNode>> {
        let (record_number, name) = self.resolve(_path)?;
        self.vnode(record_number, name)
    }

    fn read_dir(&self, _path: &str, _index: usize) -> Result<DirectoryEntry> {
        let (record_number, _name) = self.resolve(_path)?;
        let record = self.read_mft_record(record_number)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        if !header.is_dir() {
            return Err(Error::InvalidArgument);
        }

        let (name, child) = self
            .directory_entries(record_number)?
            .into_iter()
            .nth(_index)
            .ok_or(Error::NotFound)?;
        let child_record = self.read_mft_record(child)?;
        let child_header = MftRecordHeader::parse(&child_record).ok_or(Error::InvalidArgument)?;
        let kind = if child_header.is_dir() {
            NodeKind::Directory
        } else {
            NodeKind::File
        };
        let size = if kind == NodeKind::Directory {
            0
        } else {
            self.data_size(child) as usize
        };
        Ok(DirectoryEntry::new(kind, size, name))
    }

    /// Give a file or a directory another name, in the directory it is in or
    /// another one.
    ///
    /// A name lives in two places and both move: the parent's **index** gains
    /// the new name and loses the old, and the record's own **`$FILE_NAME`**
    /// takes the name and the parent it now has.  The new name goes in first
    /// and the old one leaves last, so a crash between the two leaves two names
    /// for one record, which a walk reads, rather than a file nothing names.
    /// The one order that cannot hold to that is a change of *spelling*: two
    /// names that fold together are one key, so the old one has to go before
    /// the new one arrives.
    ///
    /// The record itself does not move and its number does not change, which is
    /// what lets a directory be renamed with nothing inside it touched.
    fn rename(&self, _old_path: &str, _new_path: &str) -> Result<()> {
        if _old_path == _new_path {
            return Ok(());
        }
        let (old_parent_path, old_name) = split_parent(_old_path);
        let (new_parent_path, new_name) = split_parent(_new_path);
        if old_name.is_empty() || new_name.is_empty() || new_name.encode_utf16().count() > 255 {
            return Err(Error::InvalidArgument);
        }

        let (record_number, _) = self.resolve(_old_path)?;
        if record_number == ROOT_RECORD {
            return Err(Error::InvalidArgument);
        }
        let record = self.read_mft_record(record_number)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let directory = header.is_dir();

        // The name it is going to have, or the same record under a different
        // spelling, or a name already taken.
        let spelling = match self.resolve(_new_path) {
            Ok((existing, _)) if existing == record_number => true,
            Ok(_) => return Err(Error::AlreadyExists),
            Err(Error::NotFound) => false,
            Err(error) => return Err(error),
        };

        let (new_parent, _) = self.resolve(new_parent_path)?;
        self.check_directory(new_parent)?;
        if directory && self.is_inside(record_number, new_parent)? {
            // Moving a directory into itself would make a tree no walk can
            // leave.
            return Err(Error::InvalidArgument);
        }

        // The flag goes up before the change, and before the reads below:
        // setting it reads a record.
        self.set_dirty(true)?;

        let (old_parent, _) = self.resolve(old_parent_path)?;
        let sequence = u16::from_le_bytes([record[16], record[17]]);
        let reference = record_number | (u64::from(sequence) << 48);
        let size = if directory {
            0
        } else {
            self.data_size(record_number)
        };
        let new_parent_sequence = {
            let parent = self.read_mft_record(new_parent)?;
            u16::from_le_bytes([parent[16], parent[17]])
        };
        let name = fs::file_name_value(
            new_parent | (u64::from(new_parent_sequence) << 48),
            new_name,
            directory,
            size,
        );

        if spelling {
            // The spelling's own order, for the reason the doc above gives: two
            // names that fold together are one key, so the old one goes first.
            self.index_remove(old_parent, old_name, record_number)?;
        }
        self.index_insert(new_parent, new_name, reference, directory, size)?;
        // The record's own name follows the name that is now its, and the old
        // index entry, the one copy that now disagrees, goes last.  A name
        // that does not fit the record makes room the way any growth does, the
        // largest attribute that is not the name moving into a record of its
        // own.
        let mut attempt = 0;
        loop {
            match self.replace_value(record_number, ATTR_TYPE_FILENAME, &name) {
                Ok(()) => break,
                Err(Error::NoSpace) if attempt == 0 => {
                    let holder = self
                        .attributes_of(record_number)?
                        .iter()
                        .find(|attribute| attribute.attr_type == ATTR_TYPE_FILENAME)
                        .map(|attribute| attribute.holder)
                        .unwrap_or(record_number);
                    self.make_room(holder, ATTR_TYPE_FILENAME)?;
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        }
        if !spelling {
            self.index_remove(old_parent, old_name, record_number)?;
        }
        Ok(())
    }

    /// Make a file: a record from the MFT's free space, and its name in the
    /// parent's index.
    ///
    /// The record goes down first and the name second, so a crash between them
    /// leaves a record in use that nothing names, a leak, which is the
    /// direction that does not break a walk, rather than a name pointing at a
    /// record that is not a file.
    fn create_file(&self, path: &str) -> Result<Arc<dyn VNode>> {
        let (parent_path, name) = split_parent(path);
        if name.is_empty() || name.encode_utf16().count() > 255 {
            return Err(Error::InvalidArgument);
        }
        if self.resolve(path).is_ok() {
            return Err(Error::AlreadyExists);
        }

        // The flag goes up before the change, and before the locks the work
        // below takes: setting it reads a record, and a lock held across that
        // is a lock held against itself.
        self.set_dirty(true)?;

        let (parent_record, _) = self.resolve(parent_path)?;
        let (number, sequence) = self.claim_mft_record(parent_record, name, false)?;
        let reference = number | (u64::from(sequence) << 48);
        if let Err(error) = self.index_insert(parent_record, name, reference, false, 0) {
            // A record nothing names is a leak rather than a break, but it is
            // still a record given up for nothing, so it is handed back.
            let _ = self.release_mft_record(number);
            return Err(error);
        }
        self.vnode(number, String::from(name))
    }

    /// Make a directory: a record of its own, and its name in the parent's
    /// index.
    ///
    /// The record a directory gets differs from a file's in one attribute: an
    /// empty `$INDEX_ROOT` in the place of `$DATA`, which is what its children
    /// are later added to.  The order is a creation's, the record down
    /// first, and for the same reason.
    fn create_dir(&self, path: &str) -> Result<()> {
        let (parent_path, name) = split_parent(path);
        if name.is_empty() || name.encode_utf16().count() > 255 {
            return Err(Error::InvalidArgument);
        }
        if self.resolve(path).is_ok() {
            return Err(Error::AlreadyExists);
        }

        // Raised before the work below: setting the flag reads a record.
        self.set_dirty(true)?;

        let (parent_record, _) = self.resolve(parent_path)?;
        let (number, sequence) = self.claim_mft_record(parent_record, name, true)?;
        let reference = number | (u64::from(sequence) << 48);
        if let Err(error) = self.index_insert(parent_record, name, reference, true, 0) {
            let _ = self.release_mft_record(number);
            return Err(error);
        }
        Ok(())
    }

    /// Take an entry out: its name from the parent's index, its clusters back
    /// to the volume, and its record back to the MFT's free space.
    ///
    /// The name goes first, which is the reverse of a creation and for the
    /// same reason: a name that a walk finds and a record that is already free
    /// is the worse half of the two, and what is left after a crash is a
    /// cluster claimed by a record nothing names.
    ///
    /// A directory that still holds something cannot go: its children's names
    /// are in *its* index, and a walk that reaches it would find entries whose
    /// parent the volume no longer has.  An empty one goes the same way a file
    /// does.
    fn remove_path(&self, path: &str) -> Result<()> {
        let (parent_path, _) = split_parent(path);
        let (record_number, name) = self.resolve(path)?;
        if record_number == ROOT_RECORD {
            return Err(Error::InvalidArgument);
        }
        let record = self.read_mft_record(record_number)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        if header.is_dir() && !self.directory_entries(record_number)?.is_empty() {
            return Err(Error::Busy);
        }

        // Raised before the work below, for the same reason a creation raises
        // it there: setting the flag reads a record.
        self.set_dirty(true)?;

        let (parent_record, _) = self.resolve(parent_path)?;
        self.index_remove(parent_record, &name, record_number)?;

        // The clusters go back before the record stops naming them, so a crash
        // between the two leaves them claimed and unused rather than free and
        // spoken for.  Every non-resident attribute's runs go back, not only
        // `$DATA`'s: a directory keeps its entries, and the bitmap of the
        // blocks they are in, in files of their own.  The merged view is what
        // is walked, so a part an `$ATTRIBUTE_LIST` put in an extension record
        // gives its clusters back too.
        let attributes = self.attributes_of(record_number)?;
        for attribute in attributes
            .iter()
            .filter(|attribute| attribute.data_runs_offset.is_some())
        {
            self.free_clusters(&attribute.data_runs)?;
        }

        // And the extension records themselves: a record that holds a moved
        // attribute is a record the volume has spoken for, and the removal is
        // what gives it back.
        self.release_mft_record(record_number)?;
        for holder in self.extension_records(record_number, &record)? {
            self.release_mft_record(holder)?;
        }
        Ok(())
    }

    /// Settle the volume.
    ///
    /// A volume this driver has changed is left **dirty** until it is told it
    /// is done: that flag is what tells a checker to look rather than trust,
    /// and clearing it is the one honest thing this driver can say about the
    /// changes it made, since it writes no `$LogFile`
    /// ([RFC 0012](../../docs/rfcs/0012-the-harness-an-ntfs-write-is-proven-on.
    /// md)).
    ///
    /// Settling is also when the **`$MFTMirr`** is brought back in step.  The
    /// mirror is the volume's own recovery copy of the MFT's first four
    /// records, the records that say where the rest of them are, so a
    /// checker that finds them whole can walk the volume, and a driver that
    /// moves any of them leaves the copy disagreeing with the original until
    /// something rewrites it.  This driver moves record 0 whenever the MFT
    /// **grows** (its run list gains a run) and record 3 whenever the volume's
    /// flags change, and both happen inside a mount that then says it is
    /// done.  The write goes **last**, after the dirty flag is cleared, for
    /// the same reason the flag exists: a checker reads the mirror next to
    /// the MFT, so the one moment it is allowed to look is the moment both
    /// agree, and a crash before that moment leaves the volume dirty with
    /// the mirror stale, which is what a checker is told to expect.
    ///
    /// A volume whose `$MFTMirr` record is one this driver cannot read, a
    /// resident value, a list that moved it, fewer than four whole records of
    /// room, is left alone: the volatile dirty flag is cleared, the mirror
    /// is not touched, and the mount says so rather than writing a copy that
    /// does not match.  That is the same shape as every other refusal here:
    /// what cannot be done whole is not half done.
    fn sync(&self) -> Result<()> {
        // The flag comes down **first**: record 3, whose flags these are, is
        // one of the four records the mirror copies, so a copy taken before
        // the clear would disagree with the original on the flag byte alone.
        // The order costs one window, a crash between the two leaves a
        // volume that reads clean with a stale copy, and a copy that fails
        // for any other reason puts the flag *back*, so "clean" is only ever
        // said about a volume whose copy was written or legitimately left.
        self.set_dirty(false)?;
        match self.sync_mft_mirror() {
            Ok(()) => Ok(()),
            Err(error) => {
                let _ = self.set_dirty(true);
                Err(error)
            }
        }
    }
}

impl NtfsFs {
    /// Bring the `$MFTMirr`'s four records in step with the MFT's, when the
    /// volume's own mirror is one this driver can write.
    ///
    /// The bytes written are the volume's **own** record bytes, read back
    /// through the device, so they are already USA-packed and already what a
    /// checker compares against, rather than the cache's unpacked copies.
    /// That matters: the fixup array a record carries is part of what the
    /// mirror compares, and a mirror written from unpacked bytes would
    /// disagree with the original on every sector end.
    fn sync_mft_mirror(&self) -> Result<()> {
        let (record_size, cluster_size) = {
            let info = self.info.lock();
            (
                u64::from(info.mft_record_size),
                u64::from(info.cluster_size),
            )
        };
        let mirror_bytes = record_size * MFT_MIRR_RECORDS;

        // Where the mirror is, out of its own record's `$DATA`.  A record
        // that does not parse, a volume whose mirror record was never
        // formatted, or one a torn write left, is a shape the driver does
        // not write: the copy is left alone, and the mount still settles the
        // volume.  An error *reading* the record is not a shape, and it
        // propagates: a device that cannot answer is not a volume to call
        // settled.
        let attributes = match self.attributes_of(MFT_MIRR_RECORD) {
            Ok(attributes) => attributes,
            Err(Error::InvalidArgument) => return Ok(()),
            Err(error) => return Err(error),
        };
        let Some(data) = attributes
            .iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_DATA)
        else {
            return Ok(());
        };
        if data.data_runs_offset.is_none() || data.holder != MFT_MIRR_RECORD {
            // A resident value is bytes in the record, and one an
            // `$ATTRIBUTE_LIST` moved is not this record's to write.
            return Ok(());
        }
        let held = data
            .data_runs
            .iter()
            .map(|run| run.cluster_count)
            .sum::<u64>()
            * cluster_size;
        if data.data_runs.is_empty()
            || held < mirror_bytes
            || u64::from(data.data_size) < mirror_bytes
            || data.data_runs.iter().any(|run| run.lcn < 0)
        {
            // Fewer than four whole records of room, or runs that name holes:
            // leave the copy alone rather than write a short one or claim
            // clusters a hole says are not there.
            return Ok(());
        }

        // The originals, as the volume holds them, from the first record on
        // and the mirror beside them.  Reading through the *device* is what
        // makes these bytes the packed ones, and it also means a record the
        // cache is holding unpacked is not what lands here.
        let (mft_runs, mft_size) = {
            let mut info = self.info.lock();
            let runs = info.resolve_mft_runs(&self.device)?;
            (runs, info.mft_data_size)
        };
        if mft_size < mirror_bytes {
            return Ok(());
        }
        let mut originals = alloc::vec![0u8; mirror_bytes as usize];
        let read = fs::read_from_runs(
            &self.device,
            &self.info.lock(),
            &mft_runs,
            mft_size,
            0,
            &mut originals,
        )?;
        if read < originals.len() {
            return Ok(());
        }

        // What the volume's copy says now, read through its own runs.  A copy
        // already in step is **not rewritten**: `sync` is called on every
        // mounted volume, including one mounted read-only, whose copy is
        // whatever the last writer left, and a settle that has nothing to
        // settle must not become a write that can fail.
        let info = self.info.lock();
        let mut current = alloc::vec![0u8; originals.len()];
        let read = fs::read_from_runs(
            &self.device,
            &info,
            &data.data_runs,
            u64::from(data.data_size),
            0,
            &mut current,
        )?;
        if read == originals.len() && current == originals {
            return Ok(());
        }

        // A copy that really is stale is written whole or not at all: the
        // run list was checked to hold four whole records, and `write_to_runs`
        // stops at the end of what it can reach, so a count short of the
        // copy is a volume that would be left half-mirrored, which the caller
        // answers by raising the dirty flag again.
        let written = fs::write_to_runs(&self.device, &info, &data.data_runs, 0, &originals)?;
        if written != originals.len() {
            return Err(Error::DeviceError);
        }
        Ok(())
    }
}

// NTFS vnode

pub struct NtfsVnode {
    /// The name its parent's index gives it.
    pub name: String,
    pub fs: Arc<NtfsFs>,
    pub mft_record_number: SpinLock<u64>,
    pub file_size: SpinLock<u64>,
    pub kind: SpinLock<NodeKind>,
}

impl VNode for NtfsVnode {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> NodeKind {
        *self.kind.lock()
    }

    fn size(&self) -> usize {
        *self.file_size.lock() as usize
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        // The attributes a record holds *wherever they live*: a `$DATA` an
        // `$ATTRIBUTE_LIST` split across records is one attribute again here,
        // which is what makes the file read whole rather than to its first
        // part.
        let attributes = self.fs.attributes_of(*self.mft_record_number.lock())?;
        let info = self.fs.info.lock();

        // Find the data attribute
        let data_attr = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA)
            .ok_or(Error::NotFound)?;
        // A stream this driver cannot read is refused rather than answered with
        // bytes that are not the file's: an **encrypted** one is ciphertext
        // (RFC 0013), and a **compressed** one is the units of RFC 0014, which
        // are decoded rather than refused.
        if data_attr.flags & ATTR_FLAG_ENCRYPTED != 0 {
            return Err(Error::NotImplemented);
        }
        if data_attr.flags & ATTR_FLAG_COMPRESSED != 0 {
            // The lock is the driver's own, and the walk takes it: it is let go
            // before the stream is read.
            drop(info);
            return self.fs.read_a_compressed_stream(data_attr, offset, buffer);
        }

        let file_size = data_attr.data_size as u64;
        let data_runs = &data_attr.data_runs;

        // A *resident* attribute has no runs: its bytes are in the record the
        // node already holds, which is where a small file lives.
        if data_attr.data_runs_offset.is_none() {
            let content = &data_attr.content;
            let start = (offset as usize).min(content.len());
            let end = (start + buffer.len()).min(content.len());
            buffer[..end - start].copy_from_slice(&content[start..end]);
            return Ok(end - start);
        }

        // Calculate how much data to read
        let end_offset = (offset + buffer.len() as u64).min(file_size);
        let read_size = (end_offset - offset) as usize;

        if read_size == 0 {
            return Ok(0);
        }

        // Use read_from_runs to handle data runs properly
        fs::read_from_runs(&self.fs.device, &info, data_runs, file_size, offset, buffer)
    }

    fn write(&self, offset: u64, buffer: &[u8]) -> Result<usize> {
        if self.kind() == NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }
        let end = offset.saturating_add(buffer.len() as u64);
        if end > self.size() as u64 {
            // A write past the end grows the file first, and a growth this
            // driver cannot make is a *short* write rather than an error: the
            // contract's own answer for bytes it could not take.
            if self.set_len(end).is_err() {
                let room = self.size().saturating_sub(offset as usize);
                if room == 0 {
                    return Ok(0);
                }
                return self.write(offset, &buffer[..room]);
            }
        }

        // The flag goes up before the change, and before the locks below are
        // taken: setting it reads a record, and reading a record takes the lock
        // this write is about to hold.
        self.fs.set_dirty(true)?;

        // The attributes a record holds *wherever they live*, and before the
        // locks below: reading a record takes the same lock `info` is.
        let number = *self.mft_record_number.lock();
        let attributes = self.fs.attributes_of(number)?;
        let data = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA)
            .ok_or(Error::NotFound)?;
        if data.flags & ATTR_FLAG_ENCRYPTED != 0 {
            return Err(Error::NotImplemented);
        }
        if data.flags & ATTR_FLAG_COMPRESSED != 0 {
            // A compressed stream is a shape of its own, so the bytes go
            // through the encoder rather than through the runs
            // ([RFC 0015](../../docs/rfcs/
            // 0015-compress-an-ntfs-stream-on-write.md)).
            if end > u64::from(data.data_size) {
                // Growing one is a length change as well, and that is not
                // built: `set_len` refuses a compressed attribute.
                return Err(Error::NotImplemented);
            }
            return self
                .fs
                .write_to_a_compressed_stream(number, data, offset, buffer);
        }

        if data.data_runs_offset.is_none() {
            // A resident file's bytes are in the record itself, so the field
            // write is the data write, and the volume is where the record is.
            let data = own_attribute(number, &attributes, ATTR_TYPE_DATA)?;
            let info = self.fs.info.lock();
            let mut record = self.fs.read_mft_record(number)?;
            let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
            let length = self.size().min(data.content.len());
            let start = (offset as usize).min(length);
            let take = (length - start).min(buffer.len());
            if take == 0 {
                return Ok(0);
            }
            let record_at = self.fs.record_offset(&info, number)?;
            let field = record_at
                + (header.size() as u64 + data.offset as u64 + data.value_offset as u64)
                + start as u64;
            fs::write_device_bytes(&self.fs.device, field, &buffer[..take])?;
            // The bytes are the file's now, in the mount's copy of the record
            // as well: a read asks for the record by number, and a copy left
            // behind would answer with the bytes it had.
            let at = header.size() as usize + data.offset + data.value_offset + start;
            record[at..at + take].copy_from_slice(&buffer[..take]);
            // The cache keeps the volume's form of the record, which is the one
            // a reader checks: its sectors end with the sequence number, so a
            // copy held the other way round would fail the check that a torn
            // write is caught by.
            fs::pack_usa(
                &mut record,
                header.usa_offset as usize,
                header.usa_count as usize,
                info.bs.bytes_per_sector as usize,
            );
            self.fs.mft_cache.lock().insert(number, record);
            return Ok(take);
        }

        // A **hole** the write reaches is filled first: what a sparse run names
        // is no cluster at all, so the bytes have to be given some.  The
        // attributes come back afterwards, because the claim put a run where
        // the hole was and the bytes go where the runs now say.
        let attributes = if data.data_runs.iter().any(|run| run.lcn < 0)
            && self.fill_the_holes(number, data, offset, end)?
        {
            self.fs.attributes_of(number)?
        } else {
            attributes
        };
        let data = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA)
            .ok_or(Error::NotFound)?;

        let info = self.fs.info.lock();
        let written = fs::write_to_runs(&self.fs.device, &info, &data.data_runs, offset, buffer)?;
        Ok(written)
    }

    /// Punch a hole a caller asked for: the zeros, and the clusters the range
    /// wholly covers back to the volume.
    ///
    /// A stream this driver does not have the bytes of, compressed or
    /// encrypted, is one it cannot make zeros in, and so is a directory: both
    /// refuse with the answer their own kind gives.
    fn punch_hole(&self, offset: u64, length: u64) -> Result<()> {
        if self.kind() == NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }
        let number = *self.mft_record_number.lock();
        let attributes = self.fs.attributes_of(number)?;
        let data = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA)
            .ok_or(Error::NotFound)?;
        if data.flags & (ATTR_FLAG_COMPRESSED | ATTR_FLAG_ENCRYPTED) != 0 {
            // A hole in a compressed stream is the stream's own shape again,
            // and an encrypted one has no bytes this driver has.
            return Err(Error::NotImplemented);
        }
        self.fs.punch_a_hole(number, data, offset, length)
    }

    fn next_extent(&self, offset: u64, kind: ExtentKind) -> Result<Option<u64>> {
        if self.kind() == NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }
        let number = *self.mft_record_number.lock();
        let attributes = self.fs.attributes_of(number)?;
        let data = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA)
            .ok_or(Error::NotFound)?;
        if data.flags & (ATTR_FLAG_COMPRESSED | ATTR_FLAG_ENCRYPTED) != 0 {
            // A compressed stream's runs are in compression units, so the byte
            // arithmetic a hole question needs is the unit walk's, and a hole
            // inside a unit is the unit's own business; an encrypted one has no
            // bytes this driver has, so it has no map of them either.
            return Err(Error::NotImplemented);
        }
        if data.data_runs_offset.is_none() {
            // A resident value's bytes are all there, its initialized size is
            // its size, so it has no holes, and the trait's own default is the
            // answer.
            let size = u64::from(data.data_size);
            return Ok(match kind {
                ExtentKind::Data if offset < size => Some(offset),
                ExtentKind::Hole => Some(size),
                _ => None,
            });
        }
        let info = self.fs.info.lock();
        Ok(fs::next_extent_in_runs(
            &info,
            &data.data_runs,
            u64::from(data.initialized_size),
            u64::from(data.data_size),
            offset,
            kind,
        ))
    }

    /// Change how long a file is, claiming clusters for a growth and moving
    /// the attribute into a record of its own when the one it is in has no room
    /// left.
    fn set_len(&self, len: u64) -> Result<()> {
        if self.kind() != NodeKind::File {
            return Err(Error::InvalidArgument);
        }
        let length = u32::try_from(len).map_err(|_| Error::InvalidArgument)?;
        let current = *self.file_size.lock() as u32;
        if length == current {
            return Ok(());
        }

        // Raised before the work below, for the same reason the write raises it
        // there: setting the flag reads a record.
        self.fs.set_dirty(true)?;

        let number = *self.mft_record_number.lock();
        let attributes = self.fs.attributes_of(number)?;
        let data = attributes
            .iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_DATA)
            .ok_or(Error::NotFound)?
            .clone();
        refuse_a_stream_this_driver_cannot_read(&data)?;

        // A growth's clusters are taken **before** the record is touched:
        // claiming reads and writes the volume's bitmap, which are record
        // reads.
        let needs = {
            if data.data_runs_offset.is_none() {
                None
            } else {
                let info = self.fs.info.lock();
                let held: u64 = data
                    .data_runs
                    .iter()
                    .map(|run| run.cluster_count)
                    .sum::<u64>()
                    * u64::from(info.cluster_size);
                (u64::from(length) > held)
                    .then(|| (u64::from(length) - held).div_ceil(u64::from(info.cluster_size)))
            }
        };
        let claim = match needs {
            Some(needed) => Some((needed, self.fs.claim_clusters(needed)?)),
            None => None,
        };

        let growth = self.grow_data(&data, claim, length, current);
        // A record with no room for the longer run list is what the format
        // gives an attribute list for: the attribute goes into a record of its
        // own, which has the room the old one did not, and the run list follows
        // it there.
        let growth = match growth {
            Err(Error::NoSpace) if data.holder == number => {
                self.fs.make_room(number, ATTR_TYPE_DATA)?;
                let attributes = self.fs.attributes_of(number)?;
                let data = attributes
                    .iter()
                    .find(|attribute| attribute.attr_type == ATTR_TYPE_DATA)
                    .ok_or(Error::NotFound)?
                    .clone();
                self.grow_data(&data, claim, length, current)
            }
            other => other,
        };
        growth?;

        *self.file_size.lock() = u64::from(length);
        Ok(())
    }
}

impl NtfsVnode {
    /// Take a grown `$DATA` to the record that holds it.
    ///
    /// The runs are the file's own runs with the claimed one appended, the
    /// allocated size is what they add up to, and the clusters the growth took
    /// are written as zeros, they have never held the file's bytes.
    fn grow_data(
        &self,
        data: &ParsedAttr,
        claim: Option<(u64, u64)>,
        length: u32,
        current: u32,
    ) -> Result<()> {
        // An attribute split across records has no one record its fields are
        // in, so it is not one of these writes can patch.
        if data.holder == u64::MAX {
            return Err(Error::NotImplemented);
        }
        let holder = data.holder;
        let cluster_size = {
            let info = self.fs.info.lock();
            u64::from(info.cluster_size)
        };

        if data.data_runs_offset.is_none() {
            // A resident value *shrinks* where it lies, and grows into the
            // record's own room, and a growth the record has no room for is
            // what the conversion is for: the value leaves the record for runs
            // of its own, which is where a file that has outgrown its record
            // lives.
            if length <= current {
                return self
                    .fs
                    .write_grown_data(holder, data, &[], current, length, &[]);
            }
            let mut value = data.content.clone();
            value.resize(length as usize, 0);
            match self.fs.replace_value(holder, ATTR_TYPE_DATA, &value) {
                Ok(()) => return Ok(()),
                Err(Error::NoSpace) => {}
                Err(error) => return Err(error),
            }
            return self.convert_to_runs(holder, data, length, current, cluster_size);
        }

        let mut runs = data.data_runs.clone();
        // A value that has come back **into the record** keeps nothing in
        // clusters: the attribute becomes one whose bytes are in the record
        // again, the run list it no longer needs is room the value takes
        // and the clusters it held go back to the volume.  This is the order
        // the two writes go in: the other one leaves an attribute naming
        // clusters the volume has handed out again, and this one leaves
        // clusters nothing names if it stops in between, which is a leak and
        // the harmless direction.  A value the record cannot hold stays where
        // it is (`NoSpace`), and a sparse stream keeps its runs.
        if length < current && data.flags & ATTR_FLAG_SPARSE == 0 {
            match self.convert_to_resident(data, length) {
                Ok(()) => return Ok(()),
                Err(Error::NoSpace) | Err(Error::NotImplemented) => {}
                Err(error) => return Err(error),
            }
        }
        // What the runs hold **now**, and what they will: what the length can
        // live in is the whole run list, sparse runs included, and the room the
        // attribute is *said* to have is only the clusters behind it.
        let spanned: u64 = data
            .data_runs
            .iter()
            .map(|run| run.cluster_count)
            .sum::<u64>()
            * cluster_size;
        let held: u64 = data
            .data_runs
            .iter()
            .filter(|run| run.lcn >= 0)
            .map(|run| run.cluster_count)
            .sum::<u64>()
            * cluster_size;
        let allocated = {
            let mut allocated = held;
            if let Some((needed, first)) = claim {
                runs.push(DataRun {
                    lcn: first as i64,
                    cluster_count: needed,
                });
                allocated += needed * cluster_size;
            }
            allocated as u32
        };
        // The zeros are what the claim added **that the length reaches**, which
        // is `[the run list's end, length)`, not the whole claim, and not a
        // region measured back from the length.  The bytes below that are the
        // file's own: a shrink leaves them there on purpose (they are what a
        // growth back reads), and a growth that zeroed them would answer a read
        // with zeros where the file's bytes were.  The writer puts the zeros at
        // `length` less their own length, which is where the run list ended.
        let zeros = if u64::from(length) > spanned {
            alloc::vec![0u8; (u64::from(length) - spanned) as usize]
        } else {
            Vec::new()
        };
        self.fs
            .write_grown_data(holder, data, &runs, allocated, length, &zeros)
    }

    /// Fill the **holes** a write reaches, and answer whether it filled any.
    ///
    /// A sparse run names no cluster: its bytes read as zeros and a write that
    /// lands in it has nowhere to go.  What the format does is make the part
    /// the write reaches real, the clusters those bytes *touch* are claimed
    /// from the volume, the sparse run is split into the hole before the claim,
    /// the claim, and the hole after it, and the run list goes back with the
    /// room the new clusters add.  A cluster is claimed **whole**: a hole is
    /// zeros throughout, so the rest of the cluster is those zeros.
    ///
    /// The order is the growth path's.  The clusters are claimed, and written
    /// as zeros, because nothing has ever put a byte there, **before** the
    /// record names them, so a machine that stops in between leaves clusters
    /// nothing points at rather than a file whose bytes are not its own.
    fn fill_the_holes(
        &self,
        number: u64,
        data: &ParsedAttr,
        offset: u64,
        end: u64,
    ) -> Result<bool> {
        let cluster_size = u64::from(self.fs.info.lock().cluster_size);
        let mut runs: Vec<DataRun> = Vec::new();
        let mut filled = false;
        let mut start = 0u64;
        for run in &data.data_runs {
            let run_start = start;
            let run_end = run_start + run.cluster_count * cluster_size;
            start = run_end;
            if run.lcn >= 0 || run_end <= offset || run_start >= end {
                runs.push(run.clone());
                continue;
            }
            // The part of the hole the write reaches, in whole clusters: what
            // is left of it on either side stays a hole.
            let from = offset.max(run_start) / cluster_size * cluster_size;
            let to = end.min(run_end).div_ceil(cluster_size) * cluster_size;
            let before = (from - run_start) / cluster_size;
            let took = (to - from) / cluster_size;
            let after = (run_end - to) / cluster_size;
            if before > 0 {
                runs.push(DataRun {
                    lcn: -1,
                    cluster_count: before,
                });
            }
            let first = self.fs.claim_clusters(took)?;
            let claim = DataRun {
                lcn: first as i64,
                cluster_count: took,
            };
            // Clusters the volume has never written hold whatever an earlier
            // file left there; what this file's hole reads as is zeros, so
            // they go down before the record names them.
            let zeros = alloc::vec![0u8; (took * cluster_size) as usize];
            {
                let info = self.fs.info.lock();
                fs::write_to_runs(
                    &self.fs.device,
                    &info,
                    core::slice::from_ref(&claim),
                    0,
                    &zeros,
                )?;
            }
            runs.push(claim);
            if after > 0 {
                runs.push(DataRun {
                    lcn: -1,
                    cluster_count: after,
                });
            }
            filled = true;
        }
        if !filled {
            return Ok(false);
        }

        // The record, with the longer run list and the room its real clusters
        // add.  The length does not move: a write into a hole is a write inside
        // the file, which is what makes a hole a hole.  A record with no room
        // for the list makes room first, which is the growth path's answer too.
        let length = data.data_size;
        let allocated = runs
            .iter()
            .filter(|run| run.lcn >= 0)
            .map(|run| run.cluster_count)
            .sum::<u64>()
            * cluster_size;
        let mut attributes = self.fs.attributes_of(number)?;
        loop {
            let data = attributes
                .iter()
                .find(|attribute| attribute.attr_type == ATTR_TYPE_DATA)
                .ok_or(Error::NotFound)?;
            match self
                .fs
                .write_grown_data(data.holder, data, &runs, allocated as u32, length, &[])
            {
                Ok(()) => return Ok(true),
                Err(Error::NoSpace) if data.holder == number => {
                    self.fs.make_room(number, ATTR_TYPE_DATA)?;
                    attributes = self.fs.attributes_of(number)?;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Take a value that has come back into its record: the bytes the runs
    /// held are written where the record keeps its values, and the clusters
    /// they were in go back to the volume.
    ///
    /// The record goes first and the clusters second, because the two orders
    /// leave different things behind: writing the record drops the run list (so
    /// the clusters are named by nothing), and freeing them first would leave
    /// an attribute naming clusters the volume has handed out again, a
    /// leak in the first case, and a volume that reads another file's bytes
    /// in the second.
    ///
    /// A record with no room for the value refuses (`NoSpace`) and the caller
    /// leaves the value where it is; an attribute an `$ATTRIBUTE_LIST` split
    /// across records is no one record's to rewrite (`NotImplemented`).
    fn convert_to_resident(&self, data: &ParsedAttr, length: u32) -> Result<()> {
        let holder = data.holder;
        if holder == u64::MAX {
            return Err(Error::NotImplemented);
        }

        // What lies past the **initialized** size was never written, and the
        // format says it reads as zeros: a record that holds the value has no
        // way to say that, so those bytes are made explicit here rather than
        // left as whatever the clusters happened to hold.
        let written = length.min(data.initialized_size);
        let mut value = alloc::vec![0u8; length as usize];
        {
            let info = self.fs.info.lock();
            fs::read_from_runs(
                &self.fs.device,
                &info,
                &data.data_runs,
                u64::from(data.data_size),
                0,
                &mut value[..written as usize],
            )?;
        }

        let resident = fs::resident_attribute(
            ATTR_TYPE_DATA,
            data.name.as_deref().unwrap_or(""),
            data.instance,
            &value,
        );
        let record = self.fs.read_mft_record(holder)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let at = header.size() as usize + data.offset;
        self.fs
            .replace_attribute(holder, at, data.attr_len, &resident)?;

        // And the clusters, now that nothing names them.
        self.fs.free_clusters(&data.data_runs)?;
        Ok(())
    }

    /// Give a resident `$DATA` runs, which is what a value that has outgrown
    /// its record takes.
    ///
    /// The clusters are claimed for the whole length, the value's own bytes are
    /// written into them, and the attribute, which keeps its instance number
    /// becomes one whose value is where the runs say.  The record that holds it
    /// has to have the room for the longer header, and one that has not makes
    /// room the way any record does, its largest attribute that is not the data
    /// moving into a record of its own.
    fn convert_to_runs(
        &self,
        holder: u64,
        data: &ParsedAttr,
        length: u32,
        current: u32,
        cluster_size: u64,
    ) -> Result<()> {
        let clusters = u64::from(length).div_ceil(cluster_size);
        let first = self.fs.claim_clusters(clusters)?;
        let runs = alloc::vec![DataRun {
            lcn: first as i64,
            cluster_count: clusters,
        }];
        let allocated = clusters * cluster_size;
        let value = data.content.clone();

        let mut attempt = 0;
        loop {
            let attributes = self.fs.attributes_of(holder)?;
            let attribute = attributes
                .iter()
                .find(|attribute| {
                    attribute.attr_type == ATTR_TYPE_DATA
                        && attribute.instance == data.instance
                        && attribute.data_runs_offset.is_none()
                })
                .ok_or(Error::NotFound)?;
            let record = self.fs.read_mft_record(attribute.holder)?;
            let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
            let at = header.size() as usize + attribute.offset;

            let replacement = fs::non_resident_attribute(
                ATTR_TYPE_DATA,
                "",
                attribute.instance,
                &runs,
                allocated,
                u64::from(length),
                u64::from(length),
            );
            match self
                .fs
                .replace_attribute(attribute.holder, at, attribute.attr_len, &replacement)
            {
                Ok(()) => break,
                Err(Error::NoSpace) if attempt == 0 => {
                    self.fs.make_room(attribute.holder, ATTR_TYPE_DATA)?;
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        }

        // The value the record held is the file's first bytes; the clusters
        // past the length have never held anything, and read as zeros.
        let mut content = alloc::vec![0u8; allocated as usize];
        let held = (current as usize).min(content.len());
        content[..held].copy_from_slice(&value[..held.min(value.len())]);
        let info = self.fs.info.lock();
        fs::write_to_runs(&self.fs.device, &info, &runs, 0, &content)?;
        Ok(())
    }
}

impl Clone for NtfsFs {
    /// Another handle to the same mount: the device, the volume's own state
    /// and the record cache are the ones every handle shares.
    fn clone(&self) -> Self {
        Self {
            device: self.device.clone(),
            info: self.info.clone(),
            mft_cache: self.mft_cache.clone(),
            sector_size: self.sector_size,
        }
    }
}
