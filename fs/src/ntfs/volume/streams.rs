//! fs/src/ntfs/volume/streams.rs
//!
//! Compressed and sparse streams: the compression unit, the hole a sparse
//! write leaves, and the two paths that read and write one unit at a time.
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
use super::super::lznt1;
use super::super::types::*;

use super::NtfsFs;

impl NtfsFs {
    /// Read the index allocation block a virtual cluster number names.
    /// Read a stream the volume **compressed**, one LZNT1 unit at a time
    /// ([RFC 0014](../../docs/rfcs/0014-read-the-ntfs-streams-lznt1-compressed.
    /// md)).
    ///
    /// The units are independent, so a read needs only the units its range
    /// touches: the walk reads each unit's two-byte header, skips its payload
    /// by the length that header gives, and decodes from the unit the range
    /// begins in.  A unit holds 4096 bytes of the file, which is what makes
    /// the skip a count rather than a guess.
    ///
    /// A stream that ends before it has answered its length is
    /// `InvalidArgument`: a read that succeeds and is wrong is the one failure
    /// this driver does not have.
    /// The **compression unit** a compressed attribute's stream is divided
    /// into, in bytes.
    ///
    /// A volume compresses a *unit* at a time, sixteen clusters by the
    /// standard's own maximum, and the exponent is a byte of the attribute
    /// itself, and inside it the bytes are a sequence of 4096-byte LZNT1
    /// **chunks**.  What a squeezed unit did not need of its clusters is left a
    /// **sparse run**, so a unit's bytes are at the unit's own place in the
    /// stream: the 4096 bytes above is the chunk, not the unit.
    fn compression_unit_bytes(&self, data: &ParsedAttr) -> Result<u64> {
        let record = self.read_mft_record(data.holder)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let at = header.size() as usize + data.offset + 34;
        let exponent = *record.get(at).ok_or(Error::InvalidArgument)?;
        if exponent == 0 || exponent > 8 {
            return Err(Error::InvalidArgument);
        }
        let info = self.info.lock();
        Ok((1u64 << exponent) * u64::from(info.cluster_size))
    }

    /// How many clusters each compression unit of a compressed attribute has
    /// behind it: the runs read in the unit's own numbering, which is how a
    /// reader tells a squeezed unit from one that was stored as it is, the
    /// latter covers the whole unit with real clusters.
    fn compression_units_held(&self, data: &ParsedAttr, unit_clusters: u64) -> Result<Vec<u64>> {
        let mut held: Vec<u64> = Vec::new();
        let mut vcn = 0u64;
        for run in &data.data_runs {
            let mut left = run.cluster_count;
            while left > 0 {
                let index = (vcn / unit_clusters) as usize;
                let room = unit_clusters - vcn % unit_clusters;
                let take = left.min(room);
                while held.len() <= index {
                    held.push(0);
                }
                if run.lcn >= 0 {
                    held[index] += take;
                }
                vcn += take;
                left -= take;
            }
        }
        Ok(held)
    }

    /// Punch a hole in a file: the range reads as zeros, and the clusters it
    /// wholly covers go back to the volume
    /// ([RFC 0016](../../docs/rfcs/0016-punch-a-hole-in-an-ntfs-file.md)).
    ///
    /// The clusters the range only **partly** covers cannot go back, the bytes
    /// beside the range are the file's, so those are written as the zeros the
    /// hole reads as.  What the file *is* does not change: its length stays,
    /// and its length is why a punch takes `KEEP_SIZE` with it.
    ///
    /// The order is stage 19's lesson: a punch **adds** runs to the list, so
    /// the list it will have is built and its room settled before a single
    /// cluster is freed, a freed cluster cannot be taken again in the same
    /// operation, and a refusal that spends the volume's space is worse
    /// than one that does not.  The zeros go down first, the record names
    /// the runs second, and the clusters the hole replaced go last.
    pub(crate) fn punch_a_hole(
        &self,
        number: u64,
        data: &ParsedAttr,
        offset: u64,
        length: u64,
    ) -> Result<()> {
        let cluster = u64::from(self.info.lock().cluster_size);
        let file_size = u64::from(data.data_size);
        if length == 0 {
            return Ok(());
        }
        if offset >= file_size {
            // There is nothing there to make zeros of.
            return Err(Error::InvalidArgument);
        }
        let end = offset
            .checked_add(length)
            .ok_or(Error::InvalidArgument)?
            .min(file_size);
        if data.data_runs_offset.is_none() {
            // A resident value's bytes are in the record, and a hole in it is
            // not a run list: that is a shape of its own.
            return Err(Error::NotImplemented);
        }

        // The whole clusters inside the range, and the ends a cluster only
        // partly covers.
        let whole_from = offset.div_ceil(cluster) * cluster;
        let whole_to = end / cluster * cluster;
        let head = offset..whole_from.min(end);
        let tail = whole_to.max(whole_from)..end;

        // The zeros: only the clusters *behind* the file have bytes to zero, so
        // each run's own part of the range is what is written.
        let mut zeros: Vec<u8> = Vec::new();
        for range in [head, tail] {
            if range.start >= range.end {
                continue;
            }
            zeros.resize((range.end - range.start) as usize, 0);
            let mut vcn = 0u64;
            for run in &data.data_runs {
                let run_start = vcn * cluster;
                let run_end = run_start + run.cluster_count * cluster;
                let from = range.start.max(run_start);
                let to = range.end.min(run_end);
                if to > from && run.lcn >= 0 {
                    let at = run.lcn as u64 * cluster + (from - run_start);
                    let take = (to - from) as usize;
                    fs::write_device_bytes(&self.device, at, &zeros[..take])?;
                }
                vcn += run.cluster_count;
            }
        }

        // The runs the file has afterwards: each run split into what is outside
        // the range and a hole where the range is.
        let mut runs: Vec<DataRun> = Vec::new();
        let mut freed: Vec<DataRun> = Vec::new();
        let mut vcn = 0u64;
        for run in &data.data_runs {
            let run_start = vcn * cluster;
            let run_end = run_start + run.cluster_count * cluster;
            let from = whole_from.max(run_start);
            let to = whole_to.min(run_end);
            if whole_to <= whole_from || to <= from {
                runs.push(run.clone());
                vcn += run.cluster_count;
                continue;
            }
            let before = (from - run_start) / cluster;
            let hole = (to - from) / cluster;
            let after = (run_end - to) / cluster;
            if before > 0 {
                runs.push(DataRun {
                    lcn: run.lcn,
                    cluster_count: before,
                });
            }
            if run.lcn >= 0 {
                freed.push(DataRun {
                    lcn: run.lcn + before as i64,
                    cluster_count: hole,
                });
            }
            runs.push(DataRun {
                lcn: -1,
                cluster_count: hole,
            });
            if after > 0 {
                runs.push(DataRun {
                    lcn: if run.lcn >= 0 {
                        run.lcn + (before + hole) as i64
                    } else {
                        -1
                    },
                    cluster_count: after,
                });
            }
            vcn += run.cluster_count;
        }
        if freed.is_empty() {
            // A range that is inside one cluster makes no hole at all: the
            // zeros are the whole of it.
            return Ok(());
        }

        let allocated = runs
            .iter()
            .filter(|run| run.lcn >= 0)
            .map(|run| run.cluster_count)
            .sum::<u64>()
            * cluster;
        let length_field = data.data_size;
        let mut attributes = self.attributes_of(number)?;
        loop {
            let data = attributes
                .iter()
                .find(|attribute| attribute.attr_type == ATTR_TYPE_DATA)
                .ok_or(Error::NotFound)?;
            match self.write_grown_data(
                data.holder,
                data,
                &runs,
                allocated as u32,
                length_field,
                &[],
            ) {
                Ok(()) => break,
                Err(Error::NoSpace) => {
                    self.make_room(number, ATTR_TYPE_DATA)?;
                    attributes = self.attributes_of(number)?;
                }
                Err(error) => return Err(error),
            }
        }
        // The stream says a hole is possible, which is what the flag is for.
        self.set_stream_sparse(number)?;

        self.free_clusters(&freed)?;
        Ok(())
    }

    /// Mark a file's `$DATA` as **sparse**: the flag that says a run may name
    /// no cluster.  The record goes back whole, its sectors' numbers packed
    /// again.
    fn set_stream_sparse(&self, number: u64) -> Result<()> {
        let data = self
            .attributes_of(number)?
            .into_iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_DATA)
            .ok_or(Error::NotFound)?;
        if data.flags & ATTR_FLAG_SPARSE != 0 {
            return Ok(());
        }
        let mut record = self.read_mft_record(data.holder)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let at = header.size() as usize + data.offset + 12;
        if at + 2 > record.len() {
            return Err(Error::InvalidArgument);
        }
        let flags = u16::from_le_bytes([record[at], record[at + 1]]) | ATTR_FLAG_SPARSE;
        record[at..at + 2].copy_from_slice(&flags.to_le_bytes());
        let (where_at, sector) = {
            let info = self.info.lock();
            (
                self.record_offset(&info, data.holder)?,
                info.bs.bytes_per_sector as usize,
            )
        };
        fs::pack_usa(
            &mut record,
            header.usa_offset as usize,
            header.usa_count as usize,
            sector,
        );
        fs::write_device_bytes(&self.device, where_at, &record)?;
        self.mft_cache.lock().insert(data.holder, record);
        Ok(())
    }

    /// Write a compressed attribute's **compressed size**, the fourth of the
    /// four sizes a non-resident attribute carries, and the one a reader bounds
    /// the stream by.  The record goes back whole, its sectors' numbers packed
    /// again, like every other writer here.
    fn set_compressed_size(&self, number: u64, bytes: u64) -> Result<()> {
        let data = self
            .attributes_of(number)?
            .into_iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_DATA)
            .ok_or(Error::NotFound)?;
        let mut record = self.read_mft_record(data.holder)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let at = header.size() as usize + data.offset + 64;
        if at + 8 > record.len() {
            return Err(Error::InvalidArgument);
        }
        record[at..at + 8].copy_from_slice(&bytes.to_le_bytes());
        let (where_at, sector) = {
            let info = self.info.lock();
            (
                self.record_offset(&info, data.holder)?,
                info.bs.bytes_per_sector as usize,
            )
        };
        fs::pack_usa(
            &mut record,
            header.usa_offset as usize,
            header.usa_count as usize,
            sector,
        );
        fs::write_device_bytes(&self.device, where_at, &record)?;
        self.mft_cache.lock().insert(data.holder, record);
        Ok(())
    }

    /// Write into a stream the volume **compressed**
    /// ([RFC 0015](../../docs/rfcs/0015-compress-an-ntfs-stream-on-write.md)).
    ///
    /// A compressed stream is not a byte sequence a write can patch: a
    /// compression unit's stored bytes are as long as they came out, and what a
    /// squeezed unit did not need of its clusters is a sparse run, so the units
    /// after a change move.  What this does is rewrite **whole compression
    /// units** from the one the write lands in to the end of the file: decode
    /// the unit, splice the bytes in, encode it into chunks, or store it as it
    /// is, when squeezing does not pay, and write its clusters where they were
    /// claimed.  The units before it keep their bytes and their places.
    ///
    /// Growing the file is a length change as well, and that is not built: a
    /// write past the end is `NotImplemented`, and so is one into a file whose
    /// stream is nothing but zeros.
    pub(crate) fn write_to_a_compressed_stream(
        &self,
        number: u64,
        data: &ParsedAttr,
        offset: u64,
        buffer: &[u8],
    ) -> Result<usize> {
        let cluster = u64::from(self.info.lock().cluster_size);
        let file_size = u64::from(data.data_size);
        if offset + buffer.len() as u64 > file_size {
            return Err(Error::NotImplemented);
        }
        if data.data_runs.is_empty() {
            return Err(Error::NotImplemented);
        }
        let unit_bytes = self.compression_unit_bytes(data)?;
        let unit_clusters = unit_bytes / cluster;
        if unit_clusters == 0 {
            return Err(Error::InvalidArgument);
        }
        let stream: u64 = data
            .data_runs
            .iter()
            .map(|run| run.cluster_count)
            .sum::<u64>()
            * cluster;
        let held = self.compression_units_held(data, unit_clusters)?;

        // The units before the write keep their clusters; the ones from it on
        // are rewritten, and their old clusters go back once nothing names
        // them.
        let first_unit = offset / unit_bytes;
        let boundary = first_unit * unit_clusters;
        let mut runs: Vec<DataRun> = Vec::new();
        let mut vcn = 0u64;
        for run in &data.data_runs {
            if vcn >= boundary {
                break;
            }
            let take = (boundary - vcn).min(run.cluster_count);
            runs.push(DataRun {
                lcn: run.lcn,
                cluster_count: take,
            });
            vcn += take;
        }
        let mut old: Vec<DataRun> = Vec::new();
        let mut vcn = 0u64;
        for run in &data.data_runs {
            let run_end = vcn + run.cluster_count;
            if run_end > boundary {
                let skip = boundary.saturating_sub(vcn);
                old.push(DataRun {
                    lcn: run.lcn,
                    cluster_count: run.cluster_count - skip,
                });
            }
            vcn = run_end;
        }

        // The worst the units can be is every one of them stored as it is, and
        // what the encoding does not need goes back at the end.
        let units = file_size.div_ceil(unit_bytes);
        let worst = (units - first_unit) * unit_clusters;
        let first = self.claim_clusters(worst)?;

        let mut plain = alloc::vec![0u8; unit_bytes as usize];
        let mut stored: Vec<u8> = Vec::new();
        let mut encoded: Vec<u8> = Vec::new();
        let mut block = alloc::vec![0u8; cluster as usize];
        let mut went = 0u64;
        let mut real_bytes = 0u64;
        let mut unit = first_unit;
        while unit < units {
            let plain_len = (file_size - unit * unit_bytes).min(unit_bytes) as usize;
            let bytes_at = unit * unit_bytes;
            // What the unit holds: stored as it is, or the chunks of a squeezed
            // one, which follow each other from the unit's own place.
            if held.get(unit as usize).copied().unwrap_or(0) == unit_clusters {
                let info = self.info.lock();
                fs::read_from_runs(
                    &self.device,
                    &info,
                    &data.data_runs,
                    stream,
                    bytes_at,
                    &mut plain[..plain_len],
                )?;
            } else {
                let mut at = bytes_at;
                let mut got = 0usize;
                while got < plain_len {
                    let info = self.info.lock();
                    let mut header = [0u8; 2];
                    fs::read_from_runs(
                        &self.device,
                        &info,
                        &data.data_runs,
                        stream,
                        at,
                        &mut header,
                    )?;
                    if lznt1::is_padding(header) {
                        return Err(Error::InvalidArgument);
                    }
                    let chunk = lznt1::parse_unit(header);
                    let payload_at = at + 2;
                    let payload_len = chunk.length - 2;
                    let mut payload = alloc::vec![0u8; payload_len];
                    fs::read_from_runs(
                        &self.device,
                        &info,
                        &data.data_runs,
                        stream,
                        payload_at,
                        &mut payload,
                    )?;
                    drop(info);
                    let produced = lznt1::expand(&chunk, &payload, &mut plain[got..])?;
                    if produced == 0 {
                        return Err(Error::InvalidArgument);
                    }
                    got += produced.min(plain_len - got);
                    at = payload_at + payload_len as u64;
                }
            }
            // The write's bytes, where they belong in this unit.
            let from = offset.max(bytes_at);
            let to = (offset + buffer.len() as u64).min(bytes_at + plain_len as u64);
            if to > from {
                let start = (from - bytes_at) as usize;
                let take = (to - from) as usize;
                plain[start..start + take]
                    .copy_from_slice(&buffer[(from - offset) as usize..][..take]);
            }

            // Encode it: the unit's chunks, or the unit as it is.
            stored.clear();
            let mut chunk_at = 0usize;
            while chunk_at < plain_len {
                let take = (plain_len - chunk_at).min(lznt1::UNIT_SIZE);
                encoded.clear();
                lznt1::compress_unit(&plain[chunk_at..chunk_at + take], &mut encoded)?;
                stored.extend_from_slice(&encoded);
                chunk_at += take;
            }
            let raw = unit_clusters * cluster;
            let real = if stored.len() as u64 >= raw {
                stored.clear();
                stored.extend_from_slice(&plain[..plain_len]);
                unit_clusters
            } else {
                (stored.len() as u64).div_ceil(cluster)
            };
            let mut wrote = 0u64;
            while wrote < real {
                let at = (wrote * cluster) as usize;
                let take = (stored.len().saturating_sub(at)).min(cluster as usize);
                block.fill(0);
                block[..take].copy_from_slice(&stored[at..at + take]);
                fs::write_device_bytes(&self.device, (first + went + wrote) * cluster, &block)?;
                wrote += 1;
            }
            runs.push(DataRun {
                lcn: (first + went) as i64,
                cluster_count: real,
            });
            if unit_clusters > real {
                runs.push(DataRun {
                    lcn: -1,
                    cluster_count: unit_clusters - real,
                });
            }
            went += real;
            real_bytes += real * cluster;
            unit += 1;
        }
        if went < worst {
            self.free_clusters(&[DataRun {
                lcn: (first + went) as i64,
                cluster_count: worst - went,
            }])?;
        }

        // The record: the units before the write as they were, the ones from it
        // on as the runs above say.  The size the attribute is *said* to have
        // is the virtual, unit-aligned one; the length does not move; and the
        // fourth size, what the stream really holds, is written after,
        // because it is not one of the fields the growth path knows.
        let virtual_size = units * unit_bytes;
        let length = data.data_size;
        let mut attributes = self.attributes_of(number)?;
        loop {
            let data = attributes
                .iter()
                .find(|attribute| attribute.attr_type == ATTR_TYPE_DATA)
                .ok_or(Error::NotFound)?;
            match self.write_grown_data(data.holder, data, &runs, virtual_size as u32, length, &[])
            {
                Ok(()) => break,
                Err(Error::NoSpace) => {
                    self.make_room(number, ATTR_TYPE_DATA)?;
                    attributes = self.attributes_of(number)?;
                }
                Err(error) => return Err(error),
            }
        }
        self.set_compressed_size(number, real_bytes)?;

        // And the clusters the old units held, once nothing names them.
        if !old.is_empty() {
            self.free_clusters(&old)?;
        }
        Ok(buffer.len())
    }

    /// Read a stream the volume **compressed**, one compression unit at a time.
    ///
    /// A unit stored **as it is**, its real clusters cover it whole, is
    /// copied outright, and a squeezed one is decoded chunk by chunk.  The unit
    /// a range begins in is a count rather than a walk, because a unit's bytes
    /// are at the unit's own place.  A stream that ends before it has answered
    /// its length is `InvalidArgument`: a read that succeeds and is wrong is
    /// the one failure this driver does not have.
    pub(crate) fn read_a_compressed_stream(
        &self,
        data: &ParsedAttr,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize> {
        let file_size = u64::from(data.data_size);
        let end = (offset + buffer.len() as u64).min(file_size);
        let wanted = end.saturating_sub(offset) as usize;
        if wanted == 0 {
            return Ok(0);
        }
        let unit_bytes = self.compression_unit_bytes(data)?;
        let info = self.info.lock();
        let cluster = u64::from(info.cluster_size);
        let unit_clusters = unit_bytes / cluster;
        if unit_clusters == 0 {
            return Err(Error::InvalidArgument);
        }
        let spanned: u64 = data.data_runs.iter().map(|run| run.cluster_count).sum();
        if spanned == 0 {
            // A stream with no cluster at all is a file of zeros: it is the
            // shape the reference's encoder leaves for an input that was all
            // zeros, and there is nothing to walk.
            buffer[..wanted].fill(0);
            return Ok(wanted);
        }
        let stream = spanned * cluster;
        let held = self.compression_units_held(data, unit_clusters)?;

        let mut expanded = alloc::vec![0u8; lznt1::UNIT_SIZE];
        let mut read = 0usize;
        let mut file_at = offset / unit_bytes * unit_bytes;
        let mut at = file_at;
        while read < wanted {
            let index = (file_at / unit_bytes) as usize;
            let unit_end = (file_at / unit_bytes + 1) * unit_bytes;
            if held.get(index).copied().unwrap_or(0) == unit_clusters {
                // Stored as it is: its bytes are the file's, and the file's
                // length is what says how many of them there are.
                let from = file_at.max(offset);
                let to = end.min(unit_end).min(file_size);
                if to > from {
                    let start = (from - file_at) as usize;
                    let want = (to - from) as usize;
                    fs::read_from_runs(
                        &self.device,
                        &info,
                        &data.data_runs,
                        stream,
                        at + start as u64,
                        &mut buffer[read..read + want],
                    )?;
                    read += want;
                }
                file_at = unit_end.min(file_size);
                at = unit_end;
                continue;
            }
            if at + 2 > stream {
                return Err(Error::InvalidArgument);
            }
            let mut bytes = [0u8; 2];
            fs::read_from_runs(&self.device, &info, &data.data_runs, stream, at, &mut bytes)?;
            if lznt1::is_padding(bytes) {
                // The padding an encoder leaves after its last chunk, with the
                // file still wanting bytes: the stream is short.
                return Err(Error::InvalidArgument);
            }
            let chunk = lznt1::parse_unit(bytes);
            let payload_at = at + 2;
            let payload_len = chunk.length - 2;
            if payload_at + payload_len as u64 > stream {
                return Err(Error::InvalidArgument);
            }
            let mut payload = alloc::vec![0u8; payload_len];
            fs::read_from_runs(
                &self.device,
                &info,
                &data.data_runs,
                stream,
                payload_at,
                &mut payload,
            )?;
            let produced = lznt1::expand(&chunk, &payload, &mut expanded)?;
            if produced == 0 {
                return Err(Error::InvalidArgument);
            }
            let chunk_end = file_at + produced as u64;
            if chunk_end > offset {
                let from = offset.max(file_at);
                let to = end.min(chunk_end);
                let start = (from - file_at) as usize;
                let take = ((to - from) as usize).min(produced - start);
                buffer[read..read + take].copy_from_slice(&expanded[start..start + take]);
                read += take;
            }
            file_at = chunk_end;
            // Within a unit the chunks follow each other; the next unit is at
            // its own place, because the rest of this one is a sparse run.
            at = if file_at >= unit_end {
                unit_end
            } else {
                payload_at + payload_len as u64
            };
        }
        Ok(read)
    }
}
