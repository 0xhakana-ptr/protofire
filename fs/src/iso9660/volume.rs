//! fs/src/iso9660/volume.rs
//!
//! A mounted ISO 9660 volume: the descriptor set, the tree it describes, and
//! the entries the tree holds.
//!
//! ## What mounting does
//!
//! Reads the descriptor set from sector 16, picks the tree a reader should see
//!, Joliet's when there is one, because its names are the author's, and keeps
//! the root record.  Nothing else is read: a directory's extent is read when
//! someone asks what is in it, and a file's extent when someone reads it.
//!
//! That laziness is not an optimisation.  A disc can hold a hundred thousand
//! entries in a tree deeper than a computer's stack, and a mount that walked it
//! would be a mount that took minutes and a heap nobody bounded.
//!
//! ## What is refused
//!
//! Three things this reader will not pretend to handle, and each is reported
//! rather than half-read:
//!
//! - **An extended attribute record.**  A record may name blocks in front of
//!   its data, which this reader does not skip, so a file with one would be
//!   read from the wrong place.
//! - **A multi-extent file.**  One file in several pieces; reading the first
//!   piece as the whole file returns a truncated file that looks complete.
//! - **An interleaved file.**  Units with gaps between them, where reading it
//!   as one extent returns the gaps as data.
//!
//! ## Read-only
//!
//! There is no write path.  A CD-ROM is not writable, and the previous tree's
//! writer existed for a special requirement, a writable ISO image, rather
//! than for the format.  `VNode`'s default `write` refuses, which is exactly
//! the answer a disc should give.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use abi::Error;
use abi::Result;

use block::BlockDevice;

use super::record::Record;
use super::volume_descriptor::DESCRIPTOR_SET_START;
use super::volume_descriptor::MAX_DESCRIPTORS;
use super::volume_descriptor::SECTOR_SIZE;
use super::volume_descriptor::VolumeDescriptor;

use crate::FileSystem;
use crate::types::DirectoryEntry;
use crate::types::Metadata;
use crate::types::NodeKind;
use crate::vnode::VNode;

/// The most a directory extent may be, so a corrupt record cannot make the
/// reader allocate without bound.
///
/// 8 MiB is far more than any real directory and small enough that a disc
/// claiming otherwise is refused rather than trusted.
const MAX_DIRECTORY_BYTES: u64 = 8 * 1024 * 1024;

/// The most an extent may be for a file this reader will read at once.
const MAX_READ_BYTES: usize = 1024 * 1024;

/// One tree on a disc: the primary or a supplementary one.
#[derive(Debug, Clone, Copy)]
struct Tree {
    /// The root directory's extent, in logical blocks.
    root_extent: u32,
    /// The root directory's length, in bytes.
    root_length: u32,
    /// Whether names in this tree are UCS-2 big-endian.
    joliet: bool,
}

/// A mounted ISO 9660 volume.
pub struct Iso9660Volume {
    device: Arc<dyn BlockDevice>,
    label: String,
    block_size: u16,
    tree: Tree,
}

impl Iso9660Volume {
    /// Mount the disc on `device`.
    ///
    /// Walks the descriptor set and takes the last usable tree it finds, which
    /// is what makes a Joliet disc readable under the names its author meant:
    /// the set puts the primary descriptor first and a supplementary one after
    /// it, and the later one is the tree a reader should see.
    pub fn open(device: Arc<dyn BlockDevice>) -> Result<Arc<Self>> {
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
                // A later tree replaces an earlier one: the set's order is the
                // reader's preference order.
                selected = Some((descriptor, tree));
            }
        }

        let (descriptor, tree) = selected.ok_or(Error::InvalidArgument)?;
        if descriptor.block_size as usize != SECTOR_SIZE {
            // The format allows other block sizes; this reader does not
            // implement them, and a disc at one would be read at the wrong
            // offsets rather than fail.
            return Err(Error::Unsupported);
        }

        Ok(Arc::new(Self {
            device,
            label: descriptor.volume_id,
            block_size: descriptor.block_size,
            tree,
        }))
    }

    /// The number of logical blocks the volume's root claims.
    fn block_size_bytes(&self) -> u64 {
        self.block_size as u64
    }

    /// Read `length` bytes of a file from `extent`.
    ///
    /// The read is bounded: a record claiming a length no disc could hold is
    /// refused rather than allocated for.
    fn read_extent(&self, extent: u32, length: u32) -> Result<Vec<u8>> {
        let length = length as usize;
        if length > MAX_READ_BYTES {
            return Err(Error::Unsupported);
        }
        let mut data = vec![0u8; length];
        let offset = extent as u64 * self.block_size_bytes();
        read_exact(&*self.device, offset, &mut data)?;
        Ok(data)
    }

    /// Every entry in the directory `record` names, its `.` and `..` removed.
    fn read_directory(&self, record: &Record) -> Result<Vec<Record>> {
        self.read_directory_records(record, false)
    }

    fn read_directory_records(&self, record: &Record, with_dots: bool) -> Result<Vec<Record>> {
        if record.has_extended_attributes() {
            return Err(Error::Unsupported);
        }
        if record.is_multi_extent() {
            return Err(Error::Unsupported);
        }
        if record.is_interleaved() {
            return Err(Error::Unsupported);
        }
        if record.data_length as u64 > MAX_DIRECTORY_BYTES {
            return Err(Error::InvalidArgument);
        }

        let data = self.read_extent(record.extent, record.data_length)?;
        let mut records = Vec::new();
        let mut offset = 0usize;

        while offset < data.len() {
            match Record::parse(&data, offset, self.tree.joliet) {
                Some((parsed, next)) => {
                    if with_dots || !parsed.is_dot_entry() {
                        records.push(parsed);
                    }
                    offset = next;
                }
                None => {
                    // A zero length does not mean an empty record: it means
                    // the rest of this sector holds nothing.  The next record
                    // is in the next sector, which is what this steps to.
                    let sector_end = (offset / SECTOR_SIZE + 1) * SECTOR_SIZE;
                    if sector_end <= offset || sector_end >= data.len() {
                        break;
                    }
                    offset = sector_end;
                }
            }
        }

        Ok(records)
    }

    /// The record a path names.
    ///
    /// Path components are matched against each directory's entries as they
    /// are read, so a deep path costs one directory read per step and nothing
    /// more.  A component that matches no entry is `NotFound`, which is the
    /// answer the format gives, a disc has no "maybe" between two names.
    fn resolve(&self, path: &str) -> Result<Record> {
        let mut current = self.root_record()?;
        for component in path.split('/').filter(|part| !part.is_empty()) {
            if !current.is_directory() {
                // A path continued past a file: the file cannot hold it.
                return Err(Error::NotFound);
            }
            let entries = self.read_directory(&current)?;
            current = entries
                .into_iter()
                .find(|entry| entry.name() == component)
                .ok_or(Error::NotFound)?;
        }
        Ok(current)
    }

    /// The root directory's record, from the descriptor.
    ///
    /// Read from the tree rather than kept: a disc's root record is a field of
    /// its descriptor, and this reader has no state that could go stale.
    fn root_record(&self) -> Result<Record> {
        Ok(Record {
            extent: self.tree.root_extent,
            data_length: self.tree.root_length,
            extended_attribute_blocks: 0,
            flags: super::record::FLAG_DIRECTORY,
            identifier: vec![0u8],
            system_use: Vec::new(),
            joliet: self.tree.joliet,
            record_len: 34,
            file_unit_size: 0,
        })
    }
}

impl Tree {
    /// The tree a descriptor describes, if it describes one this reader can
    /// use.
    fn of(descriptor: &VolumeDescriptor) -> Option<Tree> {
        // The root record is a directory record, and its extent and length are
        // the two fields the reader needs.
        let root = &descriptor.root_record;
        let extent = u32::from_le_bytes([root[2], root[3], root[4], root[5]]);
        let length = u32::from_le_bytes([root[10], root[11], root[12], root[13]]);
        if length == 0 {
            return None;
        }
        Some(Tree {
            root_extent: extent,
            root_length: length,
            joliet: descriptor.joliet,
        })
    }
}

/// Read one descriptor sector, or `None` when it is not one.
fn read_descriptor(device: &dyn BlockDevice, sector: u64) -> Result<Option<VolumeDescriptor>> {
    let mut bytes = [0u8; SECTOR_SIZE];
    let offset = sector * SECTOR_SIZE as u64;
    if read_exact(device, offset, &mut bytes).is_err() {
        return Ok(None);
    }
    Ok(VolumeDescriptor::parse(sector, &bytes))
}

/// Read `buffer.len()` bytes from `offset`, which is a byte offset into the
/// disc.
///
/// ## Two block sizes
///
/// ISO 9660 counts in 2048-byte *logical blocks*, and a `BlockDevice` counts in
/// its own blocks, 512 for every device this tree has.  They are not the same
/// unit, and a reader that used one for the other reads from the wrong place:
/// logical block 16 is a device block 64, and a `read_blocks(16, …)` returns
/// the bytes of a different part of the medium.
///
/// So the arithmetic here is in bytes, and the conversion to device blocks
/// happens once, at the call.
fn read_exact(device: &dyn BlockDevice, offset: u64, buffer: &mut [u8]) -> Result<()> {
    if buffer.is_empty() {
        return Ok(());
    }
    let device_block = device.block_size() as u64;
    let first = offset / device_block;
    let within = (offset % device_block) as usize;
    let device_blocks = (within + buffer.len()).div_ceil(device_block as usize);
    let mut scratch = vec![0u8; device_blocks * device_block as usize];
    device.read_blocks(first, &mut scratch)?;
    buffer.copy_from_slice(&scratch[within..within + buffer.len()]);
    Ok(())
}

impl FileSystem for Iso9660Volume {
    fn name(&self) -> &str {
        &self.label
    }

    fn lookup(&self, path: &str) -> Result<Arc<dyn VNode>> {
        let record = self.resolve(path)?;
        let kind = if record.is_directory() {
            NodeKind::Directory
        } else if record.system_use().symlink.is_some() {
            NodeKind::Symlink
        } else {
            NodeKind::File
        };
        Ok(Arc::new(Iso9660VNode {
            volume: Arc::new(Iso9660Volume {
                device: self.device.clone(),
                label: self.label.clone(),
                block_size: self.block_size,
                tree: self.tree,
            }),
            name: record.name(),
            kind,
            extent: record.extent,
            length: record.data_length,
        }))
    }

    fn read_dir(&self, path: &str, index: usize) -> Result<DirectoryEntry> {
        let record = self.resolve(path)?;
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
        Ok(DirectoryEntry::new(
            kind,
            entry.data_length as usize,
            entry.name(),
        ))
    }

    fn rename(&self, _old_path: &str, _new_path: &str) -> Result<()> {
        Err(Error::Unsupported)
    }

    fn create_file(&self, _path: &str) -> Result<Arc<dyn VNode>> {
        Err(Error::Unsupported)
    }

    fn create_dir(&self, _path: &str) -> Result<()> {
        Err(Error::Unsupported)
    }

    fn remove_path(&self, _path: &str) -> Result<()> {
        Err(Error::Unsupported)
    }
}

/// A node on an ISO 9660 disc.
struct Iso9660VNode {
    volume: Arc<Iso9660Volume>,
    name: String,
    kind: NodeKind,
    extent: u32,
    length: u32,
}

impl VNode for Iso9660VNode {
    fn name(&self) -> &str {
        &self.name
    }

    fn kind(&self) -> NodeKind {
        self.kind
    }

    fn size(&self) -> usize {
        self.length as usize
    }

    fn metadata(&self) -> Result<Metadata> {
        Ok(Metadata::new(self.kind, self.length as usize))
    }

    fn read(&self, offset: u64, buffer: &mut [u8]) -> Result<usize> {
        if self.kind == NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }
        if offset >= self.length as u64 {
            return Ok(0);
        }
        let available = (self.length as u64 - offset) as usize;
        let count = available.min(buffer.len());
        // The read is from the file's own extent, which is contiguous by the
        // format, a file that is not, is refused at mount or at directory
        // read, not here.
        let start = self.extent as u64 * self.volume.block_size_bytes() + offset;
        read_exact(&*self.volume.device, start, &mut buffer[..count])?;
        Ok(count)
    }
}
