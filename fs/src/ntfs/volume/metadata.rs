//! fs/src/ntfs/volume/metadata.rs
//!
//! The volume's own metadata: its bitmap, the clusters it claims, the upcase
//! table, path resolution, and the flags that say it is being changed.
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
use super::super::types::*;

use super::BITMAP_RECORD;
use super::NtfsFs;
use super::ROOT_RECORD;
use super::UPCASE_RECORD;
use super::VOLUME_FLAGS_OFFSET;
use super::VOLUME_RECORD;
use super::bytes_in_use;
use super::compare_names;
use super::own_attribute;

impl NtfsFs {
    /// The record a path names, from the root down, and the name it has.
    ///
    /// A name is matched the way the volume's index orders names: through the
    /// folding table it carries (`$UpCase`), so a name is found by the case a
    /// real NTFS would find it by, and by the bytes it is stored as, for a
    /// volume whose table cannot be read ([RFC 0012]).
    pub(crate) fn resolve(&self, path: &str) -> Result<(u64, String)> {
        let upcase = self.upcase_table();
        let mut record_number = ROOT_RECORD;
        let mut name = String::from("/");
        for segment in path.split('/').filter(|segment| !segment.is_empty()) {
            let entries = self.directory_entries(record_number)?;
            let (found_name, found_record) = entries
                .into_iter()
                .find(|(entry_name, _)| compare_names(entry_name, segment, &upcase).is_eq())
                .ok_or(Error::NotFound)?;
            record_number = found_record;
            name = found_name;
        }
        Ok((record_number, name))
    }

    /// The volume's `$UpCase` table, when it has one this driver can read.
    ///
    /// The table is a file like any other, the tenth record's `$DATA`, 128
    /// KiB of code units, and it is what a name is folded through.  A volume
    /// whose table is missing or unreadable answers with none, and names are
    /// then compared as they are stored.
    pub(crate) fn upcase_table(&self) -> Vec<u16> {
        self.read_upcase_table().unwrap_or_default()
    }

    fn read_upcase_table(&self) -> Option<Vec<u16>> {
        let attributes = self.attributes_of(UPCASE_RECORD).ok()?;
        let data = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA)?;

        let units = |bytes: &[u8]| -> Vec<u16> {
            bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect()
        };
        if data.data_runs_offset.is_none() {
            return Some(units(&data.content));
        }

        let info = self.info.lock();
        let mut bytes = alloc::vec![0u8; 0x1_0000 * 2];
        let size = (data.data_size as usize).min(bytes.len());
        fs::read_from_runs(
            &self.device,
            &info,
            &data.data_runs,
            u64::from(data.data_size),
            0,
            &mut bytes[..size],
        )
        .ok()?;
        Some(units(&bytes[..size]))
    }

    /// The bytes a record's `$DATA` says it holds.
    ///
    /// The `$DATA` an `$ATTRIBUTE_LIST` moved is a `$DATA` like any other, so
    /// this is the merged view's answer and not the record's own.
    pub(crate) fn data_size(&self, record_number: u64) -> u64 {
        self.attributes_of(record_number)
            .unwrap_or_default()
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA)
            .map(|attr| attr.data_size as u64)
            .unwrap_or(0)
    }

    /// Where a record's own bytes are on the volume.
    ///
    /// The MFT is a file: a record's position is its number's offset inside
    /// that file, mapped through the file's own runs.
    pub(crate) fn record_offset(&self, info: &fs::NtfsInfo, record_number: u64) -> Result<u64> {
        let runs = info.mft_runs.as_ref().ok_or(Error::InvalidArgument)?;
        let offset = record_number
            .checked_mul(u64::from(info.mft_record_size))
            .ok_or(Error::InvalidArgument)?;
        fs::byte_offset_in_runs(runs, info.cluster_size, offset).ok_or(Error::InvalidArgument)
    }

    /// How many clusters the volume holds.
    fn volume_clusters(&self, info: &fs::NtfsInfo) -> u64 {
        info.bs.total_sectors / u64::from(info.bs.sectors_per_cluster.max(1))
    }

    /// The volume's cluster bitmap, as many bytes of it as the volume needs.
    ///
    /// The bitmap is a *file*, the sixth record's `$DATA`, with its own
    /// runs, so reading it is the same walk as reading any other file's data.
    pub(crate) fn read_bitmap(&self) -> Result<Vec<u8>> {
        let attributes = self.attributes_of(BITMAP_RECORD)?;
        let data = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA)
            .ok_or(Error::NotFound)?;

        // The lock goes on after the record has been read: reading a record
        // takes the same one, and a lock held across that is a lock held
        // against itself.
        let info = self.info.lock();
        let wanted = self.volume_clusters(&info).div_ceil(8) as usize;
        let size = wanted.min(data.data_size as usize);
        let mut bitmap = alloc::vec![0u8; size];
        if data.data_runs_offset.is_none() {
            bitmap.copy_from_slice(&data.content[..size.min(data.content.len())]);
            return Ok(bitmap);
        }
        fs::read_from_runs(
            &self.device,
            &info,
            &data.data_runs,
            u64::from(data.data_size),
            0,
            &mut bitmap,
        )?;
        Ok(bitmap)
    }

    /// Write the bitmap back where it came from.
    fn write_bitmap(&self, bitmap: &[u8]) -> Result<()> {
        // A bitmap that has moved to an extension record is written through
        // its runs like any other file; a *resident* one is a field inside the
        // record, and writing that is only this record's to do.
        let attributes = self.attributes_of(BITMAP_RECORD)?;
        let data = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_DATA)
            .ok_or(Error::NotFound)?;

        let info = self.info.lock();
        if data.data_runs_offset.is_none() {
            // A resident bitmap is a value inside the record, so the field
            // write and the record it lives in go together, which only a
            // record whose attributes are not listed is a writer's to make.
            let data = own_attribute(BITMAP_RECORD, &attributes, ATTR_TYPE_DATA)?;
            let record = self.read_mft_record(BITMAP_RECORD)?;
            let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
            let record_at = self.record_offset(&info, BITMAP_RECORD)?;
            let at =
                record_at + header.size() as u64 + data.offset as u64 + data.value_offset as u64;
            return fs::write_device_bytes(&self.device, at, bitmap);
        }
        fs::write_to_runs(&self.device, &info, &data.data_runs, 0, bitmap)?;
        Ok(())
    }

    /// Take `count` clusters from the volume's free space.
    ///
    /// The bitmap is the free list: the first run of `count` clear bits is
    /// what a growth gets, and the bits it took are set before the cluster is
    /// handed out, so a crash after the answer leaves a cluster claimed and
    /// unused, which is the harmless direction to be wrong in.
    pub(crate) fn claim_clusters(&self, count: u64) -> Result<u64> {
        let volume_clusters = {
            let info = self.info.lock();
            self.volume_clusters(&info)
        };
        let mut bitmap = self.read_bitmap()?;

        let mut found = None;
        let mut run_start = 0u64;
        let mut run = 0u64;
        for cluster in 0..volume_clusters {
            let used = bitmap[cluster as usize / 8] & (1 << (cluster % 8)) != 0;
            if used {
                run = 0;
                continue;
            }
            if run == 0 {
                run_start = cluster;
            }
            run += 1;
            if run == count {
                found = Some(run_start);
                break;
            }
        }
        let first = found.ok_or(Error::NoSpace)?;

        for cluster in first..first + count {
            bitmap[cluster as usize / 8] |= 1 << (cluster % 8);
        }
        self.set_dirty(true)?;
        self.write_bitmap(&bitmap)?;
        Ok(first)
    }

    /// Give a file's clusters back to the volume's free space.
    ///
    /// The bitmap is the free list in the other direction: the bits a file's
    /// runs name go clear, which is what the next claim then hands out again.
    /// A sparse run names no cluster and has nothing to give back.
    pub(crate) fn free_clusters(&self, runs: &[DataRun]) -> Result<()> {
        let mut bitmap = self.read_bitmap()?;
        for run in runs {
            if run.lcn < 0 {
                continue;
            }
            let first = run.lcn as u64;
            for cluster in first..first + run.cluster_count {
                let byte = cluster as usize / 8;
                if byte >= bitmap.len() {
                    break;
                }
                bitmap[byte] &= !(1 << (cluster % 8));
            }
        }
        self.set_dirty(true)?;
        self.write_bitmap(&bitmap)
    }

    /// Replace a resident attribute's value in the record that holds it, and
    /// write the record whole.
    ///
    /// A value that has grown shifts everything after it up by the difference,
    /// which crosses sector ends, so the record goes back in one piece, with
    /// its update sequence array packed again.  A record with no room for the
    /// shift refuses (`NoSpace`), which is where the caller makes room; a value
    /// that lives in another record is patched there, and one that is split
    /// across records is not this writer's to patch at all.
    pub(crate) fn replace_value(
        &self,
        record_number: u64,
        attr_type: u32,
        value: &[u8],
    ) -> Result<()> {
        let attributes = self.attributes_of(record_number)?;
        let attribute = attributes
            .iter()
            .find(|attribute| attribute.attr_type == attr_type)
            .ok_or(Error::NotFound)?;
        if attribute.holder == u64::MAX || attribute.data_runs_offset.is_some() {
            return Err(Error::NotImplemented);
        }
        let holder = attribute.holder;
        let record = self.read_mft_record(holder)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let attr_at = header.size() as usize + attribute.offset;

        // The attribute as it should be: its own header, and the value where
        // that header points.
        let mut bytes = record[attr_at..attr_at + attribute.attr_len].to_vec();
        let attr_len = (attribute.value_offset + value.len()).next_multiple_of(8);
        bytes.resize(attr_len, 0);
        bytes[4..8].copy_from_slice(&(attr_len as u32).to_le_bytes());
        bytes[16..20].copy_from_slice(&(value.len() as u32).to_le_bytes());
        bytes[attribute.value_offset..attribute.value_offset + value.len()].copy_from_slice(value);

        self.replace_attribute(holder, attr_at, attribute.attr_len, &bytes)
    }

    /// Put bytes where one of a record's attributes is, and write the record
    /// whole.
    ///
    /// `at` is where the attribute begins in the record, and `old_len` what it
    /// occupies now.  The bytes may be longer or shorter than those, which
    /// shifts everything after them, so the record goes back in one piece, its
    /// update sequence array packed again; a record with no room for the shift
    /// refuses (`NoSpace`), which is where the caller makes room, and a record
    /// that cannot be addressed at all refuses too.
    pub(crate) fn replace_attribute(
        &self,
        holder: u64,
        at: usize,
        old_len: usize,
        replacement: &[u8],
    ) -> Result<()> {
        let record = self.read_mft_record(holder)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        if at < header.size() as usize || at + old_len > bytes_in_use(&record) {
            return Err(Error::InvalidArgument);
        }

        let end = bytes_in_use(&record);
        let mut rebuilt = record[..at].to_vec();
        rebuilt.extend_from_slice(replacement);
        rebuilt.extend_from_slice(&record[at + old_len..end]);
        let used = rebuilt.len();
        if used + 8 > record.len() {
            return Err(Error::NoSpace);
        }
        rebuilt.resize(record.len(), 0);
        rebuilt[24..28].copy_from_slice(&(used as u32).to_le_bytes());

        let (device_at, sector) = {
            let info = self.info.lock();
            (
                self.record_offset(&info, holder)?,
                usize::from(info.bs.bytes_per_sector),
            )
        };
        fs::pack_usa(
            &mut rebuilt,
            header.usa_offset as usize,
            header.usa_count as usize,
            sector,
        );
        fs::write_device_bytes(&self.device, device_at, &rebuilt)?;
        self.mft_cache.lock().insert(holder, rebuilt);
        Ok(())
    }

    /// Where the volume's `$VOLUME_INFORMATION` flags are, if it has them.
    ///
    /// The flags are the last two bytes of a twelve-byte value in the third
    /// record, and bit zero is the one that says the volume is dirty, which is
    /// what a reader that finds it left set is supposed to check rather than
    /// trust.
    pub(crate) fn volume_flags_offset(&self) -> Result<u64> {
        let record = self.read_mft_record(VOLUME_RECORD)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let attributes = self.attributes_of(VOLUME_RECORD)?;
        // The flags are a field in this record: keeping them in step is a
        // rewrite of the record, so an attribute that has moved out of it is
        // not one this driver can keep in step.
        let information = own_attribute(VOLUME_RECORD, &attributes, ATTR_TYPE_VOLUME_INFORMATION)?;
        // The lock is taken here and not around the read above: reading a
        // record takes it too, and a lock held across that is a lock held
        // against itself.
        let info = self.info.lock();
        let record_at = self.record_offset(&info, VOLUME_RECORD)?;
        Ok(record_at
            + header.size() as u64
            + information.offset as u64
            + information.value_offset as u64
            + VOLUME_FLAGS_OFFSET as u64)
    }

    /// Say whether the volume is in the middle of being changed.
    pub fn set_dirty(&self, dirty: bool) -> Result<()> {
        let info = self.info.lock();
        if info.bs.bytes_per_sector == 0 {
            return Err(Error::InvalidArgument);
        }
        drop(info);

        let at = self.volume_flags_offset()?;
        let mut field = [0u8; 2];
        fs::read_device_bytes(&self.device, at, &mut field)?;
        let flags = u16::from_le_bytes(field);
        let wanted = if dirty {
            flags | 0x0001
        } else {
            flags & !0x0001
        };
        if wanted == flags {
            return Ok(());
        }
        fs::write_device_bytes(&self.device, at, &wanted.to_le_bytes())
    }
}
