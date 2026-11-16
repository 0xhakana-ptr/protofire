//! fs/src/ntfs/volume/mount.rs
//!
//! Mounting and the handle: the constructor, the accessors, and the vnode a
//! record number turns into.
//!
//! One `impl NtfsFs` block of several: Rust lets a type's inherent methods be
//! spread across the files of a module, and this module is split by what the
//! methods do rather than by how long the file is.  Nothing here is gated, the
//! whole volume is one `impl` family, and the fields these methods reach are
//! private to `volume/mod.rs` and visible here because a child module sees its
//! parent's items.

use alloc::collections::btree_map::BTreeMap;
use alloc::string::String;
use alloc::sync::Arc;

use block::BlockDevice;

use crate::types::NodeKind;
use crate::vnode::VNode;
use abi::Error;
use abi::Result;
use sync::Mutex;
use sync::SpinLock;

use super::super::fs;
use super::super::types::*;

use super::NtfsFs;

use super::NtfsVnode;

impl NtfsFs {
    pub fn new(device: Arc<dyn BlockDevice>) -> Result<Self> {
        let bs = fs::read_boot_sector(&device)?;
        let sector_size = bs.bytes_per_sector as usize;
        let info = fs::NtfsInfo::new(bs);
        Ok(Self {
            device,
            info: Arc::new(Mutex::new(info)),
            mft_cache: Arc::new(Mutex::new(BTreeMap::new())),
            sector_size,
        })
    }

    pub fn info(&self) -> &Mutex<fs::NtfsInfo> {
        &self.info
    }

    pub fn device(&self) -> &Arc<dyn BlockDevice> {
        &self.device
    }

    /// The vnode for a record, named the way its parent's index names it.
    pub(crate) fn vnode(&self, record_number: u64, name: String) -> Result<Arc<dyn VNode>> {
        let record = self.read_mft_record(record_number)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        // The size and the first cluster are the *merged* attributes': a
        // `$DATA` an `$ATTRIBUTE_LIST` split or moved answers with the whole
        // file, not with the part this record happens to hold.
        let attributes = self.attributes_of(record_number)?;
        let data = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA);
        Ok(Arc::new(NtfsVnode {
            fs: Arc::new(self.clone()),
            mft_record_number: SpinLock::new(record_number),
            file_size: SpinLock::new(if header.is_dir() {
                0
            } else {
                data.map(|attr| attr.data_size as u64).unwrap_or(0)
            }),
            kind: SpinLock::new(if header.is_dir() {
                NodeKind::Directory
            } else {
                NodeKind::File
            }),
            name,
        }))
    }
}
