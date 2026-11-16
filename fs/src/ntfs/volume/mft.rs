//! fs/src/ntfs/volume/mft.rs
//!
//! The MFT: claiming a record, growing the table, and its own bitmap.
//!
//! One `impl NtfsFs` block of several: Rust lets a type's inherent methods be
//! spread across the files of a module, and this module is split by what the
//! methods do rather than by how long the file is.  Nothing here is gated, the
//! whole volume is one `impl` family, and the fields these methods reach are
//! private to `volume/mod.rs` and visible here because a child module sees its
//! parent's items.

use alloc::vec::Vec;

use abi::Error;
use abi::Result;

use super::super::fs;
use super::super::types::*;

use super::FIRST_FREE_RECORD;
use super::MFT_RECORD;
use super::NewRecord;
use super::NtfsFs;
use super::bit_is_set;
use super::own_attribute;
use super::record_attributes;

impl NtfsFs {
    /// Put a new file's record into the MFT's first free slot, and answer its
    /// number and its sequence.
    ///
    /// A record that is formatted but not in use is free: its own header says
    /// so, and a record a volume has never written is all zeros and free too.
    /// Where `$MFT` carries its own `$BITMAP`, the bit is the volume's word on
    /// it and is read first; the header is then a second one.
    ///
    /// A volume whose records are all spoken for **grows the MFT** by a
    /// cluster and looks again, once: a growth that cannot be made is the
    /// volume being full.
    pub(crate) fn claim_mft_record(
        &self,
        parent: u64,
        name: &str,
        directory: bool,
    ) -> Result<(u64, u16)> {
        self.claim_record(NewRecord::Named {
            parent,
            name,
            directory,
        })
    }

    /// Put a record into the MFT's first free slot, and answer its number and
    /// its sequence.
    ///
    /// What the record *is* is the caller's: a file's own record carries its
    /// name and the attributes a new file has, and an extension record carries
    /// attributes another record's list names and a reference back to it.
    pub(crate) fn claim_record(&self, what: NewRecord<'_>) -> Result<(u64, u16)> {
        let base_reference = {
            let base = match &what {
                NewRecord::Named { parent, .. } => *parent,
                NewRecord::Extension { base, .. } => *base,
            };
            let base_record = self.read_mft_record(base)?;
            let sequence = u16::from_le_bytes([base_record[16], base_record[17]]);
            base | (u64::from(sequence) << 48)
        };

        // One growth is enough for one record: the MFT grows by at least a
        // cluster's worth of records, and a volume that grew and still has no
        // free record is a volume with no room.
        let mut grown = false;
        loop {
            let (record_size, sector_size, records, runs, cluster_size, index_block_size) = {
                let mut info = self.info.lock();
                let runs = info.resolve_mft_runs(&self.device)?;
                let record_size = u64::from(info.mft_record_size);
                (
                    record_size,
                    info.bs.bytes_per_sector as usize,
                    info.mft_data_size / record_size,
                    runs,
                    info.cluster_size,
                    info.index_block_size,
                )
            };
            let bitmap = self.mft_bitmap()?;

            for number in FIRST_FREE_RECORD..records {
                if bitmap.as_ref().is_some_and(|bits| bit_is_set(bits, number)) {
                    continue;
                }
                let offset = number * record_size;
                let Some(at) = fs::byte_offset_in_runs(&runs, cluster_size, offset) else {
                    continue;
                };
                let mut raw = alloc::vec![0u8; record_size as usize];
                fs::read_device_bytes(&self.device, at, &mut raw)?;

                // A record that was used before keeps its number unusable
                // through its sequence, which only ever goes up; a record a
                // volume has never written is all zeros, and its sequence
                // starts at one.
                let sequence = match MftRecordHeader::parse(&raw) {
                    Some(header) if header.flags & MFT_RECORD_IN_USE == 0 => {
                        u16::from_le_bytes([raw[16], raw[17]]).wrapping_add(1)
                    }
                    Some(_) => continue,
                    None if raw.iter().all(|byte| *byte == 0) => 1,
                    None => continue,
                };

                // The volume's word on it goes first: a record the volume says
                // is in use and nothing names is a leak, and the other order
                // would leave a record in use that the volume would hand out
                // again.
                self.set_mft_bitmap(number, true)?;
                let (flags, link_count, attributes, extension) = match &what {
                    NewRecord::Named {
                        name, directory, ..
                    } => (
                        if *directory { 0x03 } else { 0x01 },
                        1,
                        record_attributes(
                            base_reference,
                            name,
                            *directory,
                            index_block_size,
                            cluster_size,
                        ),
                        false,
                    ),
                    NewRecord::Extension { attributes, .. } => (0x01, 0, attributes.clone(), true),
                };
                let mut record = fs::build_record(
                    record_size as usize,
                    sector_size,
                    number,
                    sequence,
                    flags,
                    link_count,
                    &attributes,
                );
                if extension {
                    // The record names the record it belongs to: the base
                    // reference is the field that says so, and a record that
                    // has one has no name of its own for a directory to list.
                    record[32..40].copy_from_slice(&base_reference.to_le_bytes());
                }
                fs::write_device_bytes(&self.device, at, &record)?;
                // Whatever the mount had of this number is not what is there
                // now.
                self.mft_cache.lock().remove(&number);
                return Ok((number, sequence));
            }

            if grown {
                return Err(Error::NoSpace);
            }
            self.grow_mft()?;
            grown = true;
        }
    }

    /// Grow the MFT by at least one more record.
    ///
    /// The MFT is a file whose content is its records, so growing it is
    /// growing a file: clusters come from the volume's `$Bitmap`, the run list
    /// in `$MFT`'s own record gains a run, or the last one gets longer, when
    /// the clusters continue it, and the sizes that say how much of it is
    /// spoken for follow.  A record a volume has never written is all zeros,
    /// so the new clusters are **written as zeros**: that is what makes the
    /// records they hold free rather than whatever they held before.
    ///
    /// Its own `$BITMAP` grows with it, because a record past the bitmap's
    /// last byte is a record nothing could say was in use.
    ///
    /// The step is a whole cluster's worth of records, so one growth answers
    /// the one record that asked for it.  A volume with no free *cluster*
    /// refuses (`NoSpace`), and so does a `$MFT` whose `$DATA` run list has no
    /// room for another run: that attribute would have to move inside the
    /// record, which is the relocation the attribute list is for.
    fn grow_mft(&self) -> Result<()> {
        let (record_size, sector_size, cluster_size) = {
            let info = self.info.lock();
            (
                u64::from(info.mft_record_size),
                info.bs.bytes_per_sector as usize,
                u64::from(info.cluster_size),
            )
        };
        let record = self.read_mft_record(MFT_RECORD)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let base = header.size() as usize;
        let attributes = self.attributes_of(MFT_RECORD)?;
        // Growing the MFT rewrites the record that holds its runs, so an
        // attribute an `$ATTRIBUTE_LIST` moved is out of this one's reach.
        let data = own_attribute(MFT_RECORD, &attributes, ATTR_TYPE_DATA)?;
        // A resident `$MFT` is a volume whose records are inside its own
        // record, and growing that is a conversion this driver does not make.
        let data_runs_offset = data.data_runs_offset.ok_or(Error::NotImplemented)?;
        let bitmap = match own_attribute(MFT_RECORD, &attributes, ATTR_TYPE_BITMAP) {
            Ok(bitmap) => Some(bitmap.clone()),
            Err(Error::NotFound) => None,
            Err(error) => return Err(error),
        };

        // How much longer the MFT has to be, and where the new records are.
        let step = cluster_size.max(record_size).div_ceil(record_size) * record_size;
        let old_data = u64::from(data.data_size);
        let new_data = old_data + step;
        let records = new_data / record_size;
        let mut runs = data.data_runs.clone();
        let held: u64 = runs.iter().map(|run| run.cluster_count).sum::<u64>() * cluster_size;
        let claim = if held >= new_data {
            0
        } else {
            (new_data - held).div_ceil(cluster_size)
        };

        // The bitmap has to be able to name the new records, and its own bytes
        // to reach them, before anything is taken from the volume.
        let bitmap_growth = match &bitmap {
            Some(bitmap) => {
                let wanted = records.div_ceil(8);
                if wanted <= u64::from(bitmap.data_size) {
                    None
                } else {
                    let runs = bitmap.data_runs_offset.is_some();
                    let capacity = bitmap
                        .data_runs
                        .iter()
                        .map(|run| run.cluster_count)
                        .sum::<u64>()
                        * cluster_size;
                    if !runs || wanted > capacity {
                        return Err(Error::NoSpace);
                    }
                    Some(wanted)
                }
            }
            None => None,
        };

        let claimed = if claim > 0 {
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
            Some((first, claim))
        } else {
            None
        };

        // A run list that no longer fits where it is would have to move, and
        // that is not this driver's to do inside the MFT's own record: the
        // clusters just taken go back rather than being half-used.
        let encoded = fs::encode_runs(&runs);
        let room = data.attr_len - (data_runs_offset - data.offset);
        if encoded.len() > room {
            if let Some((first, count)) = claimed {
                let _ = self.free_clusters(&[DataRun {
                    lcn: first as i64,
                    cluster_count: count,
                }]);
            }
            return Err(Error::NoSpace);
        }

        // A record a volume has never written is all zeros.
        if let Some((first, count)) = claimed {
            let zeros = alloc::vec![0u8; cluster_size as usize];
            for cluster in first..first + count {
                fs::write_device_bytes(&self.device, cluster * cluster_size, &zeros)?;
            }
        }
        if let Some(wanted) = bitmap_growth {
            let bitmap = bitmap.as_ref().expect("a bitmap that was just looked at");
            let zeros = alloc::vec![0u8; (wanted - u64::from(bitmap.data_size)) as usize];
            let info = self.info.lock();
            fs::write_to_runs(
                &self.device,
                &info,
                &bitmap.data_runs,
                u64::from(bitmap.data_size),
                &zeros,
            )?;
        }

        // The record that holds the run list, written whole with the sizes the
        // runs now add up to.
        let mut raw = record.clone();
        let attr = base + data.offset;
        let runs_at = attr + (data_runs_offset - data.offset);
        raw[runs_at..runs_at + encoded.len()].copy_from_slice(&encoded);
        raw[runs_at + encoded.len()..attr + data.attr_len].fill(0);
        let allocated = held + claim * cluster_size;
        let last_vcn = allocated / cluster_size - 1;
        raw[attr + 24..attr + 32].copy_from_slice(&last_vcn.to_le_bytes());
        raw[attr + 40..attr + 48].copy_from_slice(&allocated.to_le_bytes());
        raw[attr + 48..attr + 56].copy_from_slice(&new_data.to_le_bytes());
        raw[attr + 56..attr + 64].copy_from_slice(&new_data.to_le_bytes());
        if let Some(wanted) = bitmap_growth {
            let bitmap = bitmap.as_ref().expect("a bitmap that was just looked at");
            // The bitmap is a *file* too, so its sizes are a non-resident
            // attribute's: what it uses at +48, what it has at +40.  A
            // resident value's length is the field at +16, and writing there
            // would have rewritten the attribute's first VCN.
            let attr = base + bitmap.offset;
            let allocated = bitmap
                .data_runs
                .iter()
                .map(|run| run.cluster_count)
                .sum::<u64>()
                * cluster_size;
            raw[attr + 40..attr + 48].copy_from_slice(&allocated.to_le_bytes());
            raw[attr + 48..attr + 56].copy_from_slice(&wanted.to_le_bytes());
            raw[attr + 56..attr + 64].copy_from_slice(&wanted.to_le_bytes());
        }
        let (at, sector) = {
            let info = self.info.lock();
            (
                self.record_offset(&info, MFT_RECORD)?,
                info.bs.bytes_per_sector as usize,
            )
        };
        let _ = sector_size;
        fs::pack_usa(
            &mut raw,
            header.usa_offset as usize,
            header.usa_count as usize,
            sector,
        );
        fs::write_device_bytes(&self.device, at, &raw)?;
        self.mft_cache.lock().insert(MFT_RECORD, raw);

        // The mount's own idea of the MFT is what it just changed.
        let mut info = self.info.lock();
        info.mft_runs = Some(runs);
        info.mft_data_size = new_data;
        Ok(())
    }

    /// `$MFT`'s own `$BITMAP`, as many bytes of it as the volume's records
    /// need.
    ///
    /// The MFT is a file whose content is its records, and its `$BITMAP` is
    /// the volume's own list of which of them are in use, the thing a real
    /// NTFS allocates from.  A volume that does not carry one answers with
    /// none, and the record headers are then the only word on what is free.
    pub(crate) fn mft_bitmap(&self) -> Result<Option<Vec<u8>>> {
        let attributes = self.attributes_of(MFT_RECORD)?;
        let Some(bitmap) = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_BITMAP)
        else {
            return Ok(None);
        };
        let wanted = {
            let mut info = self.info.lock();
            info.resolve_mft_runs(&self.device)?;
            (info.mft_data_size / u64::from(info.mft_record_size)).div_ceil(8) as usize
        };

        if bitmap.data_runs_offset.is_none() {
            return Ok(Some(
                bitmap.content[..wanted.min(bitmap.content.len())].to_vec(),
            ));
        }
        let info = self.info.lock();
        let mut bits = alloc::vec![0u8; wanted];
        fs::read_from_runs(
            &self.device,
            &info,
            &bitmap.data_runs,
            u64::from(bitmap.data_size),
            0,
            &mut bits,
        )?;
        Ok(Some(bits))
    }

    /// Move a record's bit in `$MFT`'s own bitmap, where the volume keeps one.
    ///
    /// A claim raises the bit and a release lowers it, and the bit is what a
    /// volume that mounts this one afterwards will believe: a record this
    /// driver took and did not name there is one that would be handed out
    /// twice.
    fn set_mft_bitmap(&self, number: u64, in_use: bool) -> Result<()> {
        let attributes = self.attributes_of(MFT_RECORD)?;
        let Some(bitmap) = attributes
            .iter()
            .find(|attr| attr.attr_type == ATTR_TYPE_BITMAP)
        else {
            return Ok(());
        };
        let index = (number / 8) as usize;
        let mask = 1u8 << (number % 8);

        if bitmap.data_runs_offset.is_none() {
            // A bitmap the record holds itself: the field change and the
            // record it lives in go together.
            let bitmap = own_attribute(MFT_RECORD, &attributes, ATTR_TYPE_BITMAP)?;
            let record = self.read_mft_record(MFT_RECORD)?;
            if index >= bitmap.content.len() {
                return Err(Error::InvalidArgument);
            }
            let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
            let at = header.size() as usize + bitmap.offset + bitmap.value_offset + index;
            let mut raw = record.clone();
            if in_use {
                raw[at] |= mask;
            } else {
                raw[at] &= !mask;
            }
            let (device_at, sector) = {
                let info = self.info.lock();
                (
                    self.record_offset(&info, MFT_RECORD)?,
                    info.bs.bytes_per_sector as usize,
                )
            };
            fs::pack_usa(
                &mut raw,
                header.usa_offset as usize,
                header.usa_count as usize,
                sector,
            );
            fs::write_device_bytes(&self.device, device_at, &raw)?;
            self.mft_cache.lock().insert(MFT_RECORD, raw);
            return Ok(());
        }

        if index as u64 >= u64::from(bitmap.data_size) {
            return Err(Error::InvalidArgument);
        }
        let info = self.info.lock();
        let mut byte = [0u8; 1];
        fs::read_from_runs(
            &self.device,
            &info,
            &bitmap.data_runs,
            u64::from(bitmap.data_size),
            index as u64,
            &mut byte,
        )?;
        if in_use {
            byte[0] |= mask;
        } else {
            byte[0] &= !mask;
        }
        fs::write_to_runs(&self.device, &info, &bitmap.data_runs, index as u64, &byte)?;
        Ok(())
    }

    /// Take a record back: it stops being in use, and its number stops being
    /// usable, the sequence number goes up, which is what makes a reference
    /// that still named it stop matching.
    pub(crate) fn release_mft_record(&self, number: u64) -> Result<()> {
        let record = self.read_mft_record(number)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let mut raw = record.clone();

        let sequence = u16::from_le_bytes([raw[16], raw[17]]).wrapping_add(1);
        raw[16..18].copy_from_slice(&sequence.to_le_bytes());
        raw[18..20].copy_from_slice(&0u16.to_le_bytes()); // link count
        let flags = u16::from_le_bytes([raw[22], raw[23]]) & !MFT_RECORD_IN_USE;
        raw[22..24].copy_from_slice(&flags.to_le_bytes());

        let (at, sector) = {
            let info = self.info.lock();
            (
                self.record_offset(&info, number)?,
                info.bs.bytes_per_sector as usize,
            )
        };
        fs::pack_usa(
            &mut raw,
            header.usa_offset as usize,
            header.usa_count as usize,
            sector,
        );
        fs::write_device_bytes(&self.device, at, &raw)?;
        self.mft_cache.lock().insert(number, raw);

        // The volume's word last, so a crash between the two leaves a record
        // the volume still calls used and nothing names: a leak, rather than a
        // number the volume would hand out while this driver's record is here.
        self.set_mft_bitmap(number, false)
    }
}
