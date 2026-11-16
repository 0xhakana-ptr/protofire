//! fs/src/ntfs/volume/records.rs
//!
//! The records: a record's bytes, its attributes wherever an attribute list
//! moved them, and the room a growing attribute needs.
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
use super::super::types::*;

use super::NtfsFs;
use super::bytes_in_use;
use super::names_the_same;
use super::names_the_same_attribute;

use super::NewRecord;

impl NtfsFs {
    pub fn read_mft_record(&self, record_number: u64) -> Result<Vec<u8>> {
        let mut cache = self.mft_cache.lock();
        if let Some(cached_record) = cache.get(&record_number) {
            // A cached record is kept the way the **volume** holds it, its
            // sectors ending in the sequence number, so reading it is
            // unpacking it, and a record whose sectors disagree with its own
            // array is one a write did not finish: refused here rather than
            // handed over as bytes that are half new and half old.
            let mut record = cached_record.clone();
            let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
            fs::apply_usa_fixup(
                &mut record,
                header.usa_offset as usize,
                header.usa_count as usize,
                self.sector_size,
            )?;
            return Ok(record);
        }

        let mut info = self.info.lock();
        let record_size = info.mft_record_size as usize;
        let mut record = alloc::vec![0u8; record_size];
        let runs = info.resolve_mft_runs(&self.device)?;
        let data_size = info.mft_data_size;
        let offset = record_number
            .checked_mul(info.mft_record_size as u64)
            .ok_or(Error::InvalidArgument)?;
        if offset + record_size as u64 > data_size {
            return Err(Error::NotFound);
        }
        fs::read_from_runs(&self.device, &info, &runs, data_size, offset, &mut record)?;

        // The cache keeps the volume's form of the record; the caller gets the
        // record's own bytes, which is the same bytes with each sector's
        // sequence number put back, and a record whose sectors disagree with
        // that array is one a write did not finish, so it is refused here.
        cache.insert(record_number, record.clone());
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        fs::apply_usa_fixup(
            &mut record,
            header.usa_offset as usize,
            header.usa_count as usize,
            self.sector_size,
        )?;
        Ok(record)
    }

    /// Whether the volume is writable. NTFS is currently read-only, so this
    /// is informational for the VFS layer.
    #[allow(dead_code)]
    fn read_only(&self) -> bool {
        false // Enable write support
    }

    /// The attributes a record holds, wherever they live.
    ///
    /// A record whose own bytes are not enough carries an **`$ATTRIBUTE_LIST`**
    /// naming each of its attributes and the record that holds it, which is
    /// the record itself, or an *extension* record of its, one with a base
    /// reference to the record it belongs to and no name of its own in any
    /// directory.  A non-resident attribute whose mapping pairs did not fit one
    /// record is **split** by virtual cluster number, so the parts of one
    /// attribute are put back together in the order their entries give them:
    /// what a reader wants is the one attribute the parts are.
    ///
    /// The list does not name itself, the volume this was measured against
    /// leaves its own entry out, so the attributes a record holds *in its own
    /// bytes* are kept as well, where the list does not name them.
    pub(crate) fn attributes_of(&self, record_number: u64) -> Result<Vec<ParsedAttr>> {
        let record = self.read_mft_record(record_number)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let mut inline = parse_attributes(&record[header.size() as usize..]);
        for attribute in &mut inline {
            attribute.holder = record_number;
        }
        let Some(list) = inline
            .iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_ATTRIBUTE_LIST)
        else {
            return Ok(inline);
        };
        let entries = self.list_entries(list)?;

        // One group per attribute the list names, in the order it names them.
        let mut groups: Vec<Vec<fs::AttributeListEntry>> = Vec::new();
        for entry in entries {
            match groups
                .iter_mut()
                .find(|group| names_the_same(&group[0], &entry))
            {
                Some(group) => group.push(entry),
                None => groups.push(alloc::vec![entry]),
            }
        }

        let mut attributes: Vec<ParsedAttr> = Vec::new();
        for group in &mut groups {
            group.sort_by_key(|entry| entry.lowest_vcn);
            if group[0].lowest_vcn != 0 {
                // A part that starts past the first is a list with no
                // beginning, and the attribute it belongs to is not here.
                return Err(Error::InvalidArgument);
            }
            let mut merged = self.attribute_in(&group[0])?;
            // One entry is one record's worth of attribute; more than one is an
            // attribute split across records, which is no one record's bytes.
            let whole = group.len() == 1;
            for part in &group[1..] {
                let part = self.attribute_in(part)?;
                merged.data_runs.extend(part.data_runs);
                if merged.data_runs_offset.is_none() {
                    merged.data_runs_offset = part.data_runs_offset;
                }
            }
            if !whole {
                merged.holder = u64::MAX;
            }
            attributes.push(merged);
        }
        // And an attribute the record holds itself that the list did not name.
        for attribute in inline {
            if !groups
                .iter()
                .any(|group| names_the_same_attribute(&group[0], &attribute))
            {
                attributes.push(attribute);
            }
        }
        Ok(attributes)
    }

    /// The entries of an `$ATTRIBUTE_LIST`, wherever its own bytes are.
    ///
    /// A list is usually resident in the record that carries it, and can be a
    /// file of its own, the volume this was measured against writes one that
    /// is, in which case its entries are read through its own runs.
    pub(crate) fn list_entries(&self, list: &ParsedAttr) -> Result<Vec<fs::AttributeListEntry>> {
        if list.data_runs_offset.is_none() {
            return Ok(fs::parse_attribute_list(&list.content));
        }
        let info = self.info.lock();
        let mut value = alloc::vec![0u8; list.data_size as usize];
        fs::read_from_runs(
            &self.device,
            &info,
            &list.data_runs,
            u64::from(list.data_size),
            0,
            &mut value,
        )?;
        Ok(fs::parse_attribute_list(&value))
    }

    /// The attribute one list entry names, from the record it says holds it.
    ///
    /// The entry is matched by the attribute's type, its name and its instance
    /// number: a record can hold two attributes of the same type, and a name
    /// alone would not tell them apart.
    fn attribute_in(&self, entry: &fs::AttributeListEntry) -> Result<ParsedAttr> {
        let record = self.read_mft_record(entry.holder)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        // The sequence number is what says this is the record the list was
        // written about, and not one that has since been handed out again.
        if u16::from_le_bytes([record[16], record[17]]) != entry.sequence {
            return Err(Error::InvalidArgument);
        }
        let mut attributes = parse_attributes(&record[header.size() as usize..]);
        for attribute in &mut attributes {
            attribute.holder = entry.holder;
        }
        attributes
            .into_iter()
            .find(|attribute| {
                attribute.attr_type == entry.attr_type
                    && attribute.instance == entry.instance
                    && attribute.name.as_deref() == entry.name.as_deref()
            })
            .ok_or(Error::InvalidArgument)
    }

    /// The record an extension record belongs to, from its own header.
    ///
    /// The base reference is the field that says so: a record whose header
    /// names a base record is an extension of it, and a record whose header
    /// names none is not, the volume this was measured against marks such a
    /// record as in use and nothing else, with a link count of zero.
    pub(crate) fn base_record(&self, record_number: u64) -> Option<u64> {
        let record = self.read_mft_record(record_number).ok()?;
        MftRecordHeader::parse(&record)?;
        let base = u64::from_le_bytes([
            record[32], record[33], record[34], record[35], record[36], record[37], record[38],
            record[39],
        ]) & 0x0000_FFFF_FFFF_FFFF;
        (base != 0 && base != record_number).then_some(base)
    }

    /// The extension records a record's `$ATTRIBUTE_LIST` puts its attributes
    /// in.
    /// Make room in a record by moving attributes into a record of their own.
    ///
    /// This is the format's answer to a record with no room, and the answer the
    /// measured volume gave: the attribute that needs the room **moves out**
    /// into an *extension* record, and an `$ATTRIBUTE_LIST` names every
    /// attribute of the file and which record holds it.  When the attribute
    /// does not free enough room by itself, the largest others go with it,
    /// until the list fits where they were.
    ///
    /// `growing` is the attribute that asked for the room, an index root whose
    /// value has to be longer, or a `$DATA` whose run list does not fit.  It
    /// goes first, and the caller follows it to the record it lands in.
    ///
    /// A record that is *itself* an extension is a step of its own: its list is
    /// the **base** record's, so what leaves goes into another extension of the
    /// same base and the base's list is what learns where, see
    /// [`Self::make_room_in_an_extension`].
    pub(crate) fn make_room(&self, record_number: u64, growing: u32) -> Result<()> {
        if let Some(base) = self.base_record(record_number) {
            return self.make_room_in_an_extension(record_number, base, growing);
        }
        let record = self.read_mft_record(record_number)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let base = header.size() as usize;
        let attributes = parse_attributes(&record[base..]);
        let list = attributes
            .iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_ATTRIBUTE_LIST);
        let base_reference = {
            let sequence = u16::from_le_bytes([record[16], record[17]]);
            record_number | (u64::from(sequence) << 48)
        };

        // The entries the list has, or would have: one per attribute of the
        // file, in the order the record holds them, and the entries that name
        // an attribute in a record of its own keep the record they name.
        let mut entries: Vec<(u32, Option<String>, u16, u64, u64)> = match list {
            Some(list) => self
                .list_entries(list)?
                .into_iter()
                .map(|entry| {
                    (
                        entry.attr_type,
                        entry.name,
                        entry.instance,
                        entry.lowest_vcn,
                        entry.holder | (u64::from(entry.sequence) << 48),
                    )
                })
                .collect(),
            None => attributes
                .iter()
                .map(|attribute| {
                    (
                        attribute.attr_type,
                        attribute.name.clone(),
                        attribute.instance,
                        0,
                        base_reference,
                    )
                })
                .collect(),
        };
        // A list that is not there yet is an attribute like any other, and its
        // room has to be found where the attributes that move were.
        let list_attr_len = match list {
            Some(list) => list.attr_len,
            None => {
                let value: usize = entries
                    .iter()
                    .map(|(attr_type, name, instance, vcn, holder)| {
                        fs::list_entry(
                            *attr_type,
                            name.as_deref().unwrap_or(""),
                            *instance,
                            *vcn,
                            *holder,
                        )
                        .len()
                    })
                    .sum();
                (24 + value).next_multiple_of(8)
            }
        };
        let fits = |moved_len: usize| -> bool {
            let used =
                bytes_in_use(&record) - moved_len + if list.is_some() { 0 } else { list_attr_len };
            used + 8 <= record.len()
        };

        // The attribute that asked for the room goes first, and the largest
        // others follow until what is left of the record fits the list.
        let mut moved: Vec<&ParsedAttr> = Vec::new();
        let mut moved_len = 0usize;
        let grower = attributes
            .iter()
            .find(|attribute| attribute.attr_type == growing);
        if let Some(grower) = grower {
            moved.push(grower);
            moved_len += grower.attr_len;
        }
        let mut others: Vec<&ParsedAttr> = attributes
            .iter()
            .filter(|attribute| {
                attribute.attr_type != ATTR_TYPE_ATTRIBUTE_LIST
                    && grower.is_none_or(|grower| grower.offset != attribute.offset)
            })
            .collect();
        others.sort_by_key(|attribute| core::cmp::Reverse(attribute.attr_len));
        for other in others {
            if fits(moved_len) {
                break;
            }
            moved.push(other);
            moved_len += other.attr_len;
        }
        if moved.is_empty() || !fits(moved_len) {
            return Err(Error::NoSpace);
        }

        // One record for all of them, whose own header will name the record
        // they belong to, and whose own room has to hold them.
        if moved_len + 64 > record.len() {
            return Err(Error::NoSpace);
        }
        // The attributes the extension record receives, in ascending **type**
        // order: a record's attributes are kept in that order and a checker
        // reads the chain until a type does not ascend, extension records
        // included.  The selection above picks by *size*, the largest first,
        // because that is what frees the most room, so the order they were
        // chosen in is not the order they may be written in.
        let mut to_go: Vec<Vec<u8>> = Vec::new();
        for attribute in &moved {
            let at = base + attribute.offset;
            to_go.push(record[at..at + attribute.attr_len].to_vec());
        }
        to_go.sort_by_key(|bytes| {
            bytes
                .get(..4)
                .and_then(|type_bytes| type_bytes.try_into().ok())
                .map(u32::from_le_bytes)
                .unwrap_or(u32::MAX)
        });
        let (extension, _) = self.claim_record(NewRecord::Extension {
            base: record_number,
            attributes: to_go,
        })?;
        let extension_reference = {
            let extension_record = self.read_mft_record(extension)?;
            let sequence = u16::from_le_bytes([extension_record[16], extension_record[17]]);
            extension | (u64::from(sequence) << 48)
        };
        for (attr_type, name, instance, _, holder) in entries.iter_mut() {
            if moved.iter().any(|attribute| {
                attribute.attr_type == *attr_type
                    && attribute.instance == *instance
                    && attribute.name == *name
            }) {
                *holder = extension_reference;
            }
        }
        let mut list_value: Vec<u8> = Vec::new();
        for (attr_type, name, instance, lowest_vcn, holder) in &entries {
            list_value.extend_from_slice(&fs::list_entry(
                *attr_type,
                name.as_deref().unwrap_or(""),
                *instance,
                *lowest_vcn,
                *holder,
            ));
        }

        // The list itself: the one the record has, with the holders it just
        // learnt, its value written through its own runs when it is a file of
        // its own, or a new one, where its own type sorts.
        let list_attribute = match list {
            Some(list) => {
                let mut bytes =
                    record[base + list.offset..base + list.offset + list.attr_len].to_vec();
                if list.data_runs_offset.is_none() {
                    let start = list.value_offset;
                    bytes[start..start + list_value.len()].copy_from_slice(&list_value);
                } else {
                    let info = self.info.lock();
                    fs::write_to_runs(&self.device, &info, &list.data_runs, 0, &list_value)?;
                }
                bytes
            }
            None => {
                let instance = u16::from_le_bytes([record[40], record[41]]);
                fs::resident_attribute(ATTR_TYPE_ATTRIBUTE_LIST, "", instance, &list_value)
            }
        };

        // The record, rebuilt: the attributes that stayed, and the list where
        // it was, or where its own type sorts among them.
        let mut rebuilt = record[..base].to_vec();
        let mut placed = false;
        for attribute in &attributes {
            if list.is_some_and(|list| list.offset == attribute.offset) {
                rebuilt.extend_from_slice(&list_attribute);
                placed = true;
                continue;
            }
            if moved.iter().any(|moved| moved.offset == attribute.offset) {
                continue;
            }
            if !placed && list.is_none() && attribute.attr_type > ATTR_TYPE_ATTRIBUTE_LIST {
                rebuilt.extend_from_slice(&list_attribute);
                placed = true;
            }
            let at = base + attribute.offset;
            rebuilt.extend_from_slice(&record[at..at + attribute.attr_len]);
        }
        if !placed {
            rebuilt.extend_from_slice(&list_attribute);
        }
        rebuilt.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

        let used = rebuilt.len();
        if used + 8 > record.len() {
            return Err(Error::NoSpace);
        }
        rebuilt.resize(record.len(), 0);
        rebuilt[24..28].copy_from_slice(&(used as u32).to_le_bytes());
        if list.is_none() {
            let instance = u16::from_le_bytes([record[40], record[41]]);
            rebuilt[40..42].copy_from_slice(&instance.wrapping_add(1).to_le_bytes());
        }

        let (at, sector) = {
            let info = self.info.lock();
            (
                self.record_offset(&info, record_number)?,
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
        self.mft_cache.lock().insert(record_number, rebuilt);
        Ok(())
    }

    /// Make room in a record that is itself an **extension** of another.
    ///
    /// The file's `$ATTRIBUTE_LIST` is the *base* record's, so an extension
    /// cannot grow a list of its own: what leaves the record goes into another
    /// extension of the same base, and the base's list learns where by the one
    /// field that says which record holds an attribute.  The entries keep their
    /// order and their length, so the list is the same length it was and goes
    /// back where it lives.
    ///
    /// The attribute that asked for the room **stays**: it is the one whose
    /// value has to grow, and an extension with room for it is what the others
    /// leaving behind leaves.  The largest others go first, and one goes even
    /// when the record's own bytes already fit, because what the caller needs
    /// is room for a *growth* no one has measured yet.
    ///
    /// The order is what a crash leaves.  The new extension goes down first,
    /// carrying the attributes the list still says are in the old one, a
    /// record in use that nothing names is a leak, the harmless direction.  The
    /// base's list second, which is the write that moves them.  The old record
    /// last, cleaned of attributes nothing names any more.
    fn make_room_in_an_extension(&self, record_number: u64, base: u64, growing: u32) -> Result<()> {
        let record = self.read_mft_record(record_number)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let at = header.size() as usize;
        let attributes = parse_attributes(&record[at..]);
        let fits = |moved_len: usize| bytes_in_use(&record) - moved_len + 8 <= record.len();

        // What may move is what the base's list says lives **here**, and only
        // whole attributes.  The list is the file's word on where each
        // attribute is, so an attribute it does not name is one this writer
        // cannot repoint and must not touch; and an attribute whose entries
        // number more than one is *split* across records, a part here and a
        // part elsewhere, so moving this part would corrupt it, and its parts
        // are not one record's to rewrite.  The attribute that asked for the
        // room stays: moving it is what the move is for.
        let base_attributes = self.attributes_of(base)?;
        let list = base_attributes
            .iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_ATTRIBUTE_LIST)
            .ok_or(Error::InvalidArgument)?;
        let entries = self.list_entries(list)?;
        let whole = |entry: &fs::AttributeListEntry| {
            entries
                .iter()
                .filter(|other| names_the_same(other, entry))
                .count()
                == 1
        };

        let mut moved: Vec<&ParsedAttr> = Vec::new();
        let mut moved_len = 0usize;
        let mut others: Vec<&ParsedAttr> = attributes
            .iter()
            .filter(|attribute| {
                attribute.attr_type != growing
                    && entries.iter().any(|entry| {
                        entry.holder == record_number
                            && entry.attr_type == attribute.attr_type
                            && entry.instance == attribute.instance
                            && entry.name.as_deref() == attribute.name.as_deref()
                            && whole(entry)
                    })
            })
            .collect();
        others.sort_by_key(|attribute| core::cmp::Reverse(attribute.attr_len));
        for other in others {
            if !moved.is_empty() && fits(moved_len) {
                break;
            }
            moved.push(other);
            moved_len += other.attr_len;
        }
        if moved.is_empty() || !fits(moved_len) {
            // The record holds nothing but the attribute that has to grow, and
            // is still too full for it.
            return Err(Error::NoSpace);
        }
        // The new record holds the attributes and its own header and marker.
        if moved_len + 64 > record.len() {
            return Err(Error::NoSpace);
        }

        // The attributes the new record receives, in ascending **type** order:
        // a record's attributes are kept in that order and the selection picked
        // by *size*.
        let mut to_go: Vec<Vec<u8>> = Vec::new();
        for attribute in &moved {
            let start = at + attribute.offset;
            to_go.push(record[start..start + attribute.attr_len].to_vec());
        }
        to_go.sort_by_key(|bytes| {
            bytes
                .get(..4)
                .and_then(|type_bytes| type_bytes.try_into().ok())
                .map(u32::from_le_bytes)
                .unwrap_or(u32::MAX)
        });
        let (extension, _) = self.claim_record(NewRecord::Extension {
            base,
            attributes: to_go,
        })?;
        let extension_reference = {
            let extension_record = self.read_mft_record(extension)?;
            let sequence = u16::from_le_bytes([extension_record[16], extension_record[17]]);
            extension | (u64::from(sequence) << 48)
        };

        // The base's list, which is what says the attributes moved.  It goes
        // before the old record is cleaned, so no window has an attribute the
        // list says is in a record that no longer holds it.
        self.repoint_list_entries(base, &moved, extension_reference)?;

        // And the record that made room, with the moved attributes gone.
        let mut rebuilt = record[..at].to_vec();
        for attribute in &attributes {
            if moved.iter().any(|moved| moved.offset == attribute.offset) {
                continue;
            }
            let start = at + attribute.offset;
            rebuilt.extend_from_slice(&record[start..start + attribute.attr_len]);
        }
        rebuilt.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());
        let used = rebuilt.len();
        rebuilt.resize(record.len(), 0);
        rebuilt[24..28].copy_from_slice(&(used as u32).to_le_bytes());

        let (device_at, sector) = {
            let info = self.info.lock();
            (
                self.record_offset(&info, record_number)?,
                info.bs.bytes_per_sector as usize,
            )
        };
        fs::pack_usa(
            &mut rebuilt,
            header.usa_offset as usize,
            header.usa_count as usize,
            sector,
        );
        fs::write_device_bytes(&self.device, device_at, &rebuilt)?;
        self.mft_cache.lock().insert(record_number, rebuilt);
        Ok(())
    }

    /// Point the entries of a file's `$ATTRIBUTE_LIST` that name the attributes
    /// just moved out of an extension record at the record they moved to.
    ///
    /// An entry names the record that holds its attribute, so an attribute that
    /// changes record changes one field of its entry and nothing else, the
    /// order and the length stay, which is what lets the list go back where it
    /// lives: the base record's own bytes, or the runs of a list that is a file
    /// of its own.
    fn repoint_list_entries(&self, base: u64, moved: &[&ParsedAttr], holder: u64) -> Result<()> {
        let attributes = self.attributes_of(base)?;
        let list = attributes
            .iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_ATTRIBUTE_LIST)
            .ok_or(Error::InvalidArgument)?;
        let mut entries = self.list_entries(list)?;
        for entry in &mut entries {
            if moved.iter().any(|attribute| {
                attribute.attr_type == entry.attr_type
                    && attribute.instance == entry.instance
                    && attribute.name.as_deref() == entry.name.as_deref()
            }) {
                entry.holder = holder & 0x0000_FFFF_FFFF_FFFF;
                entry.sequence = (holder >> 48) as u16;
            }
        }
        let mut value: Vec<u8> = Vec::new();
        for entry in &entries {
            value.extend_from_slice(&fs::list_entry(
                entry.attr_type,
                entry.name.as_deref().unwrap_or(""),
                entry.instance,
                entry.lowest_vcn,
                entry.holder | (u64::from(entry.sequence) << 48),
            ));
        }
        if list.data_runs_offset.is_none() {
            return self.replace_value(base, ATTR_TYPE_ATTRIBUTE_LIST, &value);
        }
        let info = self.info.lock();
        fs::write_to_runs(&self.device, &info, &list.data_runs, 0, &value)?;
        Ok(())
    }

    /// Write a grown `$DATA` where it lives: the run list, the allocated, data
    /// and initialized sizes, and the last virtual cluster number, in the
    /// record that holds the attribute.
    ///
    /// The record that holds it need not be the one the node was opened on: an
    /// `$ATTRIBUTE_LIST` can have put the attribute in an extension record, and
    /// the fields are written wherever that record's bytes are.  A run list
    /// that no longer fits the room the attribute has *moves within* the record
    ///, and a record with no room for that answers `NoSpace`, which is where
    /// the caller moves the attribute into a record of its own.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn write_grown_data(
        &self,
        holder: u64,
        data: &ParsedAttr,
        runs: &[DataRun],
        allocated: u32,
        length: u32,
        zeros: &[u8],
    ) -> Result<()> {
        let record = self.read_mft_record(holder)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let base = header.size() as usize;
        let Some(runs_offset) = data.data_runs_offset else {
            // A resident value carries its length in its own header, and there
            // is no run list and no allocated size to write: a resident file
            // can only shrink here, which the caller has already checked.
            let info = self.info.lock();
            let record_at = self.record_offset(&info, holder)?;
            fs::write_device_bytes(
                &self.device,
                record_at + (base + data.offset + 16) as u64,
                &length.to_le_bytes(),
            )?;
            let mut raw = record.clone();
            raw[base + data.offset + 16..base + data.offset + 20]
                .copy_from_slice(&length.to_le_bytes());
            self.mft_cache.lock().insert(holder, raw);
            return Ok(());
        };
        let runs_relative = runs_offset - data.offset;
        let encoded = fs::encode_runs(runs);
        if runs_relative + encoded.len() > data.attr_len {
            return self.relocate_run_list(holder, data, runs, allocated, length, zeros);
        }

        let info = self.info.lock();
        let record_at = self.record_offset(&info, holder)?;
        let mut raw = record.clone();

        // The run list, in the room the attribute has for it, written whether
        // or not the *number* of runs changed.  A claim that lands in the
        // cluster beside the last run extends that run: the list is as long as
        // it was and says more, and a record that kept the shorter one would
        // name less of the allocation than the sizes beside it claim.
        let room = data.attr_len - runs_relative;
        let mut field = alloc::vec![0u8; room];
        field[..encoded.len()].copy_from_slice(&encoded);
        let at = base + data.offset + runs_relative;
        raw[at..at + room].copy_from_slice(&field);

        // The clusters the file just took have never held its bytes.  A run
        // the caller *added* is where they are, an allocation that grew inside
        // a run it already had has no new clusters and nothing to zero.
        if runs.len() > data.data_runs.len() {
            fs::write_to_runs(
                &self.device,
                &info,
                runs,
                u64::from(length) - zeros.len() as u64,
                zeros,
            )?;
        }

        // What the runs add up to: the last **virtual** cluster number the
        // attribute covers, which is the length of the run list in clusters,
        // and the room its **real** clusters are said to have.  A sparse run
        // is virtual room with no cluster behind it, so for a file with a hole
        // in it the two are not the same number.
        let spanned: u64 = runs.iter().map(|run| run.cluster_count).sum();
        let last_vcn = spanned.saturating_sub(1);
        raw[base + data.offset + 24..base + data.offset + 32]
            .copy_from_slice(&last_vcn.to_le_bytes());
        raw[base + data.offset + 40..base + data.offset + 48]
            .copy_from_slice(&u64::from(allocated).to_le_bytes());

        // The data size and the initialized size, adjacent in a non-resident
        // header: a shorter file has no initialized bytes beyond its length.
        raw[base + data.offset + 48..base + data.offset + 56]
            .copy_from_slice(&u64::from(length).to_le_bytes());
        raw[base + data.offset + 56..base + data.offset + 64]
            .copy_from_slice(&u64::from(length).to_le_bytes());

        // Written **whole**, and its sequence array packed again.  Each field
        // here lives in the record's own bytes, and a run list long enough to
        // reach the end of a sector would write over the number that says which
        // write put that sector there, the one thing the reader checks, and
        // what this function's own field-at-a-time writes were doing.
        let header = MftRecordHeader::parse(&raw).ok_or(Error::InvalidArgument)?;
        fs::pack_usa(
            &mut raw,
            header.usa_offset as usize,
            header.usa_count as usize,
            info.bs.bytes_per_sector as usize,
        );
        drop(info);
        fs::write_device_bytes(&self.device, record_at, &raw)?;
        self.mft_cache.lock().insert(holder, raw);
        Ok(())
    }

    /// Give an attribute a longer run list than its room holds, and write the
    /// record whole.
    ///
    /// A run list that no longer fits the room its attribute has means the
    /// attribute **grows in place**: the bytes after it shift up by the
    /// difference, and the record changes from end to end, so it is written in
    /// one piece with the update sequence array packed again, the shift
    /// crosses sector ends, and a field write could not leave those as they
    /// were.
    ///
    /// It keeps its **place**, which is not a detail: a record's attributes are
    /// kept in ascending **type** order and a checker reads the chain until it
    /// meets a type that does not ascend, `ntfs-3g` failing a record there is
    /// where this was caught on a volume it had written (`Bad end of MFT
    /// record`): moving the attribute last put the index allocation after the
    /// bitmap, and no reader this tree has checks the order.  The attributes
    /// after the grown one shift, and none of them changes place among
    /// themselves.
    #[allow(clippy::too_many_arguments)]
    fn relocate_run_list(
        &self,
        holder: u64,
        data: &ParsedAttr,
        runs: &[DataRun],
        allocated: u32,
        length: u32,
        zeros: &[u8],
    ) -> Result<()> {
        let record = self.read_mft_record(holder)?;
        let header = MftRecordHeader::parse(&record).ok_or(Error::InvalidArgument)?;
        let info = self.info.lock();
        let base = header.size() as usize;
        let runs_relative = data.data_runs_offset.ok_or(Error::InvalidArgument)? - data.offset;
        let encoded = fs::encode_runs(runs);

        // The attribute as it will be, built first so it can be put back
        // **where it was**: its own header with a longer run list, and the
        // sizes that follow from what the runs cover.
        let mut grown = record[base + data.offset..base + data.offset + runs_relative].to_vec();
        grown.resize((runs_relative + encoded.len()).div_ceil(8) * 8, 0);
        grown[runs_relative..runs_relative + encoded.len()].copy_from_slice(&encoded);
        let grown_len = grown.len() as u32;
        grown[4..8].copy_from_slice(&grown_len.to_le_bytes());
        grown[40..48].copy_from_slice(&u64::from(allocated).to_le_bytes());
        grown[48..56].copy_from_slice(&u64::from(length).to_le_bytes());
        grown[56..64].copy_from_slice(&u64::from(length).to_le_bytes());
        let last_vcn = u64::from(allocated) / u64::from(info.cluster_size) - 1;
        grown[24..32].copy_from_slice(&last_vcn.to_le_bytes());

        // Every attribute as it is, this one grown, the rest shifted by the
        // difference, and the order untouched.
        let attributes = parse_attributes(&record[base..]);
        let mut rebuilt = record[..base].to_vec();
        for attribute in &attributes {
            if attribute.attr_type == data.attr_type
                && attribute.offset == data.offset
                && attribute.instance == data.instance
            {
                rebuilt.extend_from_slice(&grown);
                continue;
            }
            let at = base + attribute.offset;
            rebuilt.extend_from_slice(&record[at..at + attribute.attr_len]);
        }
        rebuilt.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes());

        let used = rebuilt.len();
        if used + 8 > record.len() {
            return Err(Error::NoSpace);
        }
        rebuilt.resize(record.len(), 0);
        rebuilt[24..28].copy_from_slice(&(used as u32).to_le_bytes());
        fs::pack_usa(
            &mut rebuilt,
            header.usa_offset as usize,
            header.usa_count as usize,
            info.bs.bytes_per_sector as usize,
        );

        // The clusters the file just took have never held its bytes.
        fs::write_to_runs(
            &self.device,
            &info,
            runs,
            u64::from(length) - zeros.len() as u64,
            zeros,
        )?;
        let at = self.record_offset(&info, holder)?;
        fs::write_device_bytes(&self.device, at, &rebuilt)?;
        self.mft_cache.lock().insert(holder, rebuilt);
        Ok(())
    }

    /// The extension records a record's `$ATTRIBUTE_LIST` puts its attributes
    /// in.
    pub(crate) fn extension_records(&self, record_number: u64, record: &[u8]) -> Result<Vec<u64>> {
        let header = MftRecordHeader::parse(record).ok_or(Error::InvalidArgument)?;
        let inline = parse_attributes(&record[header.size() as usize..]);
        let Some(list) = inline
            .iter()
            .find(|attribute| attribute.attr_type == ATTR_TYPE_ATTRIBUTE_LIST)
        else {
            return Ok(Vec::new());
        };

        let mut holders: Vec<u64> = Vec::new();
        for entry in self.list_entries(list)? {
            if entry.holder == record_number
                || holders.contains(&entry.holder)
                || self.base_record(entry.holder) != Some(record_number)
            {
                continue;
            }
            holders.push(entry.holder);
        }
        Ok(holders)
    }
}
