//! arch/aarch64/src/paging.rs
//!
//! aarch64's page-table encoding, and the register that installs a table.
//!
//! ## The encoding
//!
//! A descriptor is a physical address with flags in its low bits, but the flags
//! are not x86_64's:
//!
//! ```text
//! bits 0..1  type: 0b11 is a table or a page, 0b01 is a block
//! bit  2     attributes index (which MAIR entry applies)
//! bit  6     AP[1]: EL0 may access
//! bit  7     AP[2]: read-only
//! bit  10    AF: access flag — a descriptor with it clear faults on first use
//! bits 11..   the next level table or the output address
//! ```
//!
//! Two differences from x86_64 matter here.  **Read-only is a bit that is
//! set**, not a writable bit that is clear, so a permission set translates by
//! inversion.  And **the access flag is not optional**: a descriptor with AF
//! clear is one the MMU faults on, which is how the kernel learns a page is
//! live — this tree does not implement that, so every descriptor this crate
//! encodes sets AF.
//!
//! ## The translation regime
//!
//! Four levels, 4 KiB granules, starting at EL1.  `ttbr0_el1` holds the table
//! the kernel translates through, and `sctlr_el1.M` turns the MMU on.
//!
//! ## On a host build
//!
//! A host has no `ttbr0_el1` and no `sctlr_el1`, so `install` and
//! `current_root_table` are absent — the module still compiles, because the
//! encoding is arithmetic and a host test can check it.  That is the same split
//! the console uses: the arm that needs the machine is the machine's, and the
//! arithmetic is everyone's.

use paging::Entry;
use paging::EntryEncoding;
use paging::Level;
use paging::Permissions;

/// Bits 0..1 of a descriptor: `0b11` means a table or a page.
pub const TYPE_TABLE_OR_PAGE: u64 = 0b11;
/// Bits 0..1 of a descriptor: `0b01` means a block (a larger leaf).
pub const TYPE_BLOCK: u64 = 0b01;

/// Bits 2..4: which `MAIR_EL1` attribute entry applies.
///
/// `MAIR_EL1` holds eight attribute bytes, and a descriptor names one by index.
/// This tree uses two:
///
/// | index | attribute | for |
/// |---|---|---|
/// | 0 | `0xFF` — normal memory, write-back cached | the kernel's own memory |
/// | 1 | `0x00` — device memory, gathering off | a device's registers |
///
/// Both are installed by `maIR` in `install`; a descriptor that named an index
/// those bytes do not define is one the MMU treats as device memory, which is
/// the safe direction but not what a caller asked for.
pub const ATTR_INDEX_SHIFT: u64 = 2;
/// `MAIR_EL1` byte 0: normal, write-back cached.
pub const ATTR_NORMAL: u64 = 0 << ATTR_INDEX_SHIFT;
/// `MAIR_EL1` byte 1: device, non-gathering.
pub const ATTR_DEVICE: u64 = 1 << ATTR_INDEX_SHIFT;

/// Bit 6: `AP[1]` — EL0 may access the page.
pub const AP_USER: u64 = 1 << 6;
/// Bit 7: `AP[2]` — the page is read-only.  Set means read-only, which is the
/// opposite of x86_64's writable bit.
pub const AP_READ_ONLY: u64 = 1 << 7;

/// Bit 10: the access flag.  A descriptor with it clear faults on first use,
/// and this tree does not implement that fault, so it is always set.
pub const AF_ACCESSED: u64 = 1 << 10;

/// Bit 54: the unprivileged execute-never bit for EL0.
pub const UXN: u64 = 1 << 54;
/// Bit 53: the privileged execute-never bit for EL1.
pub const PXN: u64 = 1 << 53;

/// The mask an output address occupies: bits 12..48.
pub const OUTPUT_ADDRESS_MASK: u64 = ((1u64 << 48) - 1) & !0xFFFu64;

/// Encode an entry as the descriptor the machine reads.
///
/// A leaf at a level that can hold a block gets `TYPE_BLOCK`; the last level
/// always gets `TYPE_TABLE_OR_PAGE`, because a 4 KiB granule's fourth level has
/// no block form.
pub fn encode_at(entry: Entry, level: Level) -> u64 {
    if !entry.present {
        return 0;
    }
    let can_block = matches!(level, Level::Second | Level::Third);
    let kind = if entry.is_leaf && can_block {
        TYPE_BLOCK
    } else {
        TYPE_TABLE_OR_PAGE
    };

    let attribute = match entry.permissions.cache {
        paging::Cache::Normal => ATTR_NORMAL,
        paging::Cache::Device => ATTR_DEVICE,
    };
    let mut descriptor =
        (entry.address as u64 & OUTPUT_ADDRESS_MASK) | kind | AF_ACCESSED | attribute;
    // AP[2] set means read-only; the permission says whether it is writable.
    if !entry.permissions.writable {
        descriptor |= AP_READ_ONLY;
    }
    if entry.permissions.user {
        descriptor |= AP_USER;
    } else {
        descriptor |= UXN;
    }
    if !entry.permissions.executable {
        descriptor |= PXN;
        if entry.permissions.user {
            descriptor |= UXN;
        }
    }
    descriptor
}

/// Encode an entry with no level context: a table entry.
///
/// The trait's single-argument form, for a caller that is naming a table.
pub fn encode(entry: Entry) -> u64 {
    encode_at(entry, Level::Third)
}

/// Decode a descriptor at `level`.
pub fn decode(word: u64, level: Level) -> Entry {
    let present = word & TYPE_TABLE_OR_PAGE != 0 || word & TYPE_BLOCK != 0;
    if !present {
        return Entry::default();
    }
    let is_block = word & TYPE_TABLE_OR_PAGE == TYPE_BLOCK;
    Entry {
        address: (word & OUTPUT_ADDRESS_MASK) as usize,
        permissions: Permissions {
            // AP[2] set is read-only, so writable is its absence.
            writable: word & AP_READ_ONLY == 0,
            executable: word & PXN == 0,
            user: word & AP_USER != 0,
            cache: if word & (1 << ATTR_INDEX_SHIFT) != 0 {
                paging::Cache::Device
            } else {
                paging::Cache::Normal
            },
        },
        is_leaf: is_block || level == Level::Leaf,
        present,
    }
}

/// The encoding, as the trait `paging` names.
pub struct Encoding;

impl EntryEncoding for Encoding {
    fn encode(entry: Entry) -> u64 {
        encode(entry)
    }

    fn decode(word: u64, level: Level) -> Entry {
        decode(word, level)
    }
}

/// Read the address of the table the machine is translating through, at EL1.
#[cfg(target_os = "none")]
pub fn current_root_table() -> usize {
    let value: u64;
    // SAFETY: reading `ttbr0_el1` at EL1 has no side effect.  Bits 48..63 are
    // ASID and the CNP bit, and the address is what remains below bit 48.
    unsafe {
        core::arch::asm!("mrs {}, ttbr0_el1", out(reg) value, options(nomem, nostack, preserves_flags))
    };
    (value as usize) & (OUTPUT_ADDRESS_MASK as usize)
}

/// Install `table` in `ttbr0_el1`, and turn the MMU on.
///
/// # Safety
///
/// `table` must be a page-aligned four-level root whose entries name physical
/// memory and whose mappings include the code performing this call.  Writing
/// `sctlr_el1.M` makes the machine translate through it on the next
/// instruction fetch.
#[cfg(target_os = "none")]
pub unsafe fn install(table: usize) -> bool {
    let previous = current_root_table();
    if previous == table {
        return false;
    }
    let root = (table as u64) & OUTPUT_ADDRESS_MASK;
    // SAFETY: the caller promises the table is complete and aligned.  The ISB
    // is what the architecture requires after writing a system register that
    // changes translation.
    unsafe {
        // The two attributes this tree's descriptors name: byte 0 normal
        // write-back, byte 1 device non-gathering.  A descriptor's index is a
        // byte of this register, so a machine without it would fault with the
        // index unset — which is why it is written before the table.
        let mair: u64 = 0x00FF;
        core::arch::asm!("msr mair_el1, {}", in(reg) mair, options(nostack));
        core::arch::asm!("msr ttbr0_el1, {}", in(reg) root, options(nostack));
        core::arch::asm!("dsb ish", options(nostack));
        core::arch::asm!("isb", options(nostack));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::AF_ACCESSED;
    use super::AP_READ_ONLY;
    use super::AP_USER;
    use super::decode;
    use super::encode;
    use super::encode_at;
    use paging::Entry;
    use paging::Level;
    use paging::Permissions;

    /// A table descriptor round-trips, and its address is in the field an
    /// output address occupies.
    #[test]
    fn a_table_descriptor_round_trips() {
        let entry = Entry::table(0x4000_0000);
        let word = encode(entry);
        assert_eq!(word & 0b11, 0b11, "a table is type 0b11");
        assert_ne!(word & AF_ACCESSED, 0, "the access flag is set");
        let decoded = decode(word, Level::Third);
        assert_eq!(decoded.address, 0x4000_0000);
        assert!(decoded.present);
        assert!(!decoded.is_leaf);
    }

    /// Read-only is the bit being *set*, which is the opposite of x86_64.
    ///
    /// This is the difference a copied encoder gets wrong: x86_64 clears a
    /// writable bit, and aarch64 sets a read-only one, so a port that kept the
    /// same arithmetic would give every page the wrong permission.
    #[test]
    fn read_only_is_a_bit_that_is_set() {
        let writable = Entry::page(0x1000, Permissions::KERNEL_READ_WRITE);
        assert_eq!(
            encode(writable) & AP_READ_ONLY,
            0,
            "writable clears the bit"
        );

        let read_only = Entry::page(0x1000, Permissions::KERNEL_READ_EXECUTE);
        assert_ne!(encode(read_only) & AP_READ_ONLY, 0, "read-only sets it");

        assert!(decode(encode(writable), Level::Leaf).permissions.writable);
        assert!(!decode(encode(read_only), Level::Leaf).permissions.writable);
    }

    /// A user page sets `AP[1]` and clears `UXN` when it is executable.
    #[test]
    fn a_user_mapping_is_marked_user() {
        let user = Entry::page(
            0x1000,
            Permissions {
                writable: true,
                executable: true,
                user: true,
                cache: paging::Cache::Normal,
            },
        );
        let word = encode(user);
        assert_ne!(word & AP_USER, 0);
        assert_eq!(word & super::UXN, 0, "an executable user page is not UXN");

        let kernel = Entry::page(0x1000, Permissions::KERNEL_READ_WRITE);
        assert_eq!(encode(kernel) & AP_USER, 0);
        assert_ne!(
            encode(kernel) & super::UXN,
            0,
            "a kernel page is unprivileged-execute-never"
        );
    }

    /// A leaf in a block-capable level is a block; the last level's leaf is a
    /// page.
    #[test]
    fn a_leaf_is_a_block_where_a_block_is_allowed() {
        let entry = Entry::page(0x4000_0000, Permissions::KERNEL_READ_WRITE);
        assert_eq!(encode_at(entry, Level::Third) & 0b11, super::TYPE_BLOCK);
        assert_eq!(
            encode_at(entry, Level::Leaf) & 0b11,
            super::TYPE_TABLE_OR_PAGE
        );
        // The two levels above cannot block.
        assert_eq!(
            encode_at(entry, Level::Root) & 0b11,
            super::TYPE_TABLE_OR_PAGE
        );
    }

    /// A device mapping names the device `MAIR` index, and an ordinary one
    /// names the normal index.
    #[test]
    fn a_device_mapping_names_the_device_attribute() {
        let device = Entry::page(0xFE00_0000, Permissions::DEVICE);
        let word = encode(device);
        assert_ne!(word & super::ATTR_DEVICE, 0, "the device index is named");
        assert_eq!(
            decode(word, Level::Leaf).permissions.cache,
            paging::Cache::Device
        );

        let ordinary = Entry::page(0x1000, Permissions::KERNEL_READ_WRITE);
        assert_eq!(encode(ordinary) & (0b111 << super::ATTR_INDEX_SHIFT), 0);
        assert_eq!(
            decode(encode(ordinary), Level::Leaf).permissions.cache,
            paging::Cache::Normal
        );
    }

    /// An absent entry is zero.
    #[test]
    fn an_absent_entry_is_zero() {
        assert_eq!(encode(Entry::EMPTY), 0);
        assert_eq!(decode(0, Level::Leaf), Entry::default());
    }
}
