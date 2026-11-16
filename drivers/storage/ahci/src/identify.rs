//! drivers/storage/ahci/src/identify.rs
//!
//! What a SATA device answers when asked to describe itself: an ATA IDENTIFY
//! DEVICE structure, 256 16-bit words in a 512-byte sector.
//!
//! ## The three facts a block driver needs
//!
//! How many blocks the disk is, how big one block is (512, for every disk
//! this driver speaks to), and the model string a boot line can report.  The
//! capacity is the one with a fork in it: an ATA disk answers its 28-bit
//! capacity in words 60 and 61, and its 48-bit capacity in words 100 to 103,
//! and a driver that read the narrow pair of a disk whose capacity is beyond
//! 128 GiB would see the count wrap and report a disk smaller than its own
//! filesystem.  Word 83's bit 10 says whether the wide pair is there, and the
//! fork is that bit's.
//!
//! The model string is the other place a byte order bites: ATA defines the
//! words 27 to 46 as big-endian inside a structure the controller DMA-writes
//! as little-endian words, so every pair of bytes arrives swapped and a
//! driver that printed the raw 40 bytes printed gibberish.

/// Words of the IDENTIFY DEVICE structure.
pub const IDENTIFY_WORDS: usize = 256;

/// The structure's size in bytes.
pub const IDENTIFY_BYTES: usize = IDENTIFY_WORDS * 2;

/// Word 83, whose bit 10 says the 48-bit capacity words are there.
pub const CAPABILITIES_WORD: usize = 83;

/// The bit of word 83 that answers "48-bit addressing is supported".
pub const LBA48_SUPPORTED_BIT: u16 = 1 << 10;

/// Where the 28-bit capacity is, words 60 and 61.
pub const LBA28_CAPACITY_WORD: usize = 60;

/// Where the 48-bit capacity is, words 100 to 103.
pub const LBA48_CAPACITY_WORD: usize = 100;

/// Where the model string is, words 27 to 46: 20 words, 40 bytes.
pub const MODEL_WORD: usize = 27;
/// The model string's length in bytes.
pub const MODEL_BYTES: usize = 40;

/// The bits of a word that are the signature of an ATAPI device.
///
/// Word 0's bits 15:14 are `00` for ATA, `01` for ATAPI.  A packet device is
/// not a block device this driver can read, and answering its model string as
/// if it were a disk would be one a mount would fail on for a reason nothing
/// had named.
pub const CONFIG_ATAPI: u16 = 0x8000;

/// Read one word of an identify structure.
///
/// `None` past the end, which is a caller that built a shorter buffer rather
/// than a device that answered badly: the two deserve different answers and
/// this is the one a caller can act on.
fn word(structure: &[u8], index: usize) -> Option<u16> {
    let at = index * 2;
    let bytes = structure.get(at..at + 2)?;
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}

/// Whether the structure describes an ATA disk rather than an ATAPI packet
/// device.
///
/// The check is word 0's top two bits.  Every one of this crate's later reads
/// is a read an ATAPI device answers with something else, so refusing here is
/// what keeps a CD-ROM from being reported as a disk with a garbage capacity.
pub fn is_ata(structure: &[u8]) -> bool {
    let Some(config) = word(structure, 0) else {
        return false;
    };
    config & CONFIG_ATAPI == 0
}

/// The disk's capacity, in 512-byte blocks.
///
/// The 48-bit words when the disk says it supports them and the 28-bit pair
/// otherwise, masked to the 28 bits the narrow encoding can hold.  `None` on
/// a structure too short to hold the words, which is a caller's bug rather
/// than a disk's answer.
pub fn capacity_blocks(structure: &[u8]) -> Option<u64> {
    let lba48 = word(structure, CAPABILITIES_WORD)?;
    if lba48 & LBA48_SUPPORTED_BIT != 0 {
        let low = word(structure, LBA48_CAPACITY_WORD)? as u64;
        let mid = word(structure, LBA48_CAPACITY_WORD + 1)? as u64;
        let high = word(structure, LBA48_CAPACITY_WORD + 2)? as u64;
        let top = word(structure, LBA48_CAPACITY_WORD + 3)? as u64;
        Some(low | (mid << 16) | (high << 32) | (top << 48))
    } else {
        let low = word(structure, LBA28_CAPACITY_WORD)? as u64;
        let high = word(structure, LBA28_CAPACITY_WORD + 1)? as u64;
        // The 28-bit capacity is 28 bits wide: the top nibble of the second
        // word is type, not capacity, and a driver that kept it would report a
        // disk four gigabytes past its end.
        Some((low | (high << 16)) & 0x0FFF_FFFF)
    }
}

/// The model string, byte-swapped back into reading order.
///
/// ATA packs the string big-endian into its words, so the bytes arrive in
/// pairs of `(second, first)` and the answer puts them back.  Trailing
/// spaces, which the specification says pad the string, are kept: a boot line
/// that trims them prints a model that is easier to match and one that is no
/// longer the device's own bytes.
pub fn model(structure: &[u8]) -> Option<[u8; MODEL_BYTES]> {
    let at = MODEL_WORD * 2;
    let bytes = structure.get(at..at + MODEL_BYTES)?;
    let mut out = [0u8; MODEL_BYTES];
    for (index, pair) in bytes.as_chunks::<2>().0.iter().enumerate() {
        out[index * 2] = pair[1];
        out[index * 2 + 1] = pair[0];
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    //! The capacity's fork, the model's byte order, and the ATAPI refusal,
    //! each against a structure built the way a controller answers.

    use super::*;

    /// An identify structure of zeroed words, with `word` set to a value.
    fn structure() -> alloc::vec::Vec<u8> {
        alloc::vec![0u8; IDENTIFY_BYTES]
    }

    fn set_word(at: usize, value: u16) -> impl Fn(&mut [u8]) {
        move |s: &mut [u8]| s[at * 2..at * 2 + 2].copy_from_slice(&value.to_le_bytes())
    }

    /// An ATA disk: word 0's top two bits are clear.
    #[test]
    fn an_ata_disk_is_not_atapi() {
        let mut s = structure();
        assert!(is_ata(&s), "a zeroed word 0 is an ATA device");

        set_word(0, CONFIG_ATAPI)(&mut s);
        assert!(!is_ata(&s), "word 0 bits 15:14 set is an ATAPI device");
    }

    /// A structure shorter than the word it is asked for answers nothing.
    #[test]
    fn a_short_structure_answers_nothing() {
        assert!(!is_ata(&[0u8; 1]));
        assert_eq!(capacity_blocks(&[0u8; 8]), None);
        assert_eq!(model(&[0u8; 4]), None);
    }

    /// The 48-bit capacity is four words, low word first.
    #[test]
    fn the_lba48_capacity_is_four_words() {
        let mut s = structure();
        set_word(CAPABILITIES_WORD, LBA48_SUPPORTED_BIT)(&mut s);
        set_word(100, 0x1234)(&mut s);
        set_word(101, 0x5678)(&mut s);
        set_word(102, 0x9ABC)(&mut s);
        set_word(103, 0x0001)(&mut s);

        let expected = 0x0001_9ABC_5678_1234u64;
        assert_eq!(capacity_blocks(&s), Some(expected));
    }

    /// The 28-bit capacity is two words masked to 28 bits.
    ///
    /// The top nibble of word 61 is not capacity: a driver that kept it reads
    /// a disk 4 GiB past its end, and a filesystem that mounts that reads
    /// blocks the disk does not have.
    #[test]
    fn the_lba28_capacity_is_masked_to_28_bits() {
        let mut s = structure();
        // Word 83 clears the LBA48 bit.
        set_word(CAPABILITIES_WORD, 0)(&mut s);
        set_word(60, 0xFFFF)(&mut s);
        set_word(61, 0xFFFF)(&mut s);

        assert_eq!(capacity_blocks(&s), Some(0x0FFF_FFFF));
    }

    /// A disk that says it supports 48-bit addressing is read wide, even when
    /// the wide words are zero: the narrow pair of such a disk is defined to
    /// hold a wrapped count and cannot be trusted.
    #[test]
    fn a_lba48_disk_is_not_read_through_the_narrow_words() {
        let mut s = structure();
        set_word(CAPABILITIES_WORD, LBA48_SUPPORTED_BIT)(&mut s);
        // Words 60/61 hold the wrapped 28-bit count the specification warns
        // about; words 100/101 hold the real answer.
        set_word(60, 0xFFFF)(&mut s);
        set_word(61, 0xFFFF)(&mut s);
        set_word(100, 0x0002)(&mut s);

        assert_eq!(capacity_blocks(&s), Some(2));
    }

    /// The model string arrives byte-swapped and leaves in reading order.
    #[test]
    fn the_model_string_is_byte_swapped_back() {
        let mut s = structure();
        // "QEMU" packed big-endian per word: each word's low byte holds the
        // string's *second* character, so word 27 is [E, Q] and word 28 is
        // [U, M], and the swap puts the string back.
        s[MODEL_WORD * 2..MODEL_WORD * 2 + 8].copy_from_slice(b"EQUM    ");
        let model = model(&s).expect("forty bytes");
        assert_eq!(&model[..8], b"QEMU    ");
    }

    /// The model is forty bytes, even when the device's string is shorter:
    /// the specification pads it with spaces, and a driver that trimmed here
    /// would compare against bytes the device did not send.
    #[test]
    fn the_model_string_is_the_full_forty_bytes() {
        let s = structure();
        let model = model(&s).expect("forty bytes");
        assert_eq!(model.len(), MODEL_BYTES);
        assert!(model.iter().all(|&byte| byte == 0));
    }
}
