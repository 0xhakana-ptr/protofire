//! arch/x86_64/src/paging.rs
//!
//! x86_64's page-table encoding, and the register that installs a table.
//!
//! ## The encoding
//!
//! An entry is a physical address with flags in its low bits:
//!
//! ```text
//! bit 0   present
//! bit 1   writable
//! bit 2   user-accessible
//! bit 7   huge (this entry covers 2 MiB, not one page)
//! bit 63  no-execute
//! ```
//!
//! The four-level walk is PML4 → PDPT → PD → PT.  A `PD` entry with bit 7 set
//! names 2 MiB directly, which is what the boot assembly uses to map the first
//! gigabyte without allocating a table per 2 MiB.
//!
//! ## What is here and what is not
//!
//! The encoding, and `install` — a `cr3` write.  The arithmetic that decides
//! which index selects which level is `memory::paging`'s, and it is tested on a
//! host because a shift off by one is the kind of bug a machine shows as
//! corruption far from its cause.

use paging::Cache;
use paging::Entry;
use paging::EntryEncoding;
use paging::Level;
use paging::Permissions;
use paging::index::FLAG_HUGE;
use paging::index::FLAG_NO_EXECUTE;
use paging::index::FLAG_PRESENT;
use paging::index::FLAG_USER;
use paging::index::FLAG_WRITABLE;

/// The bit that says this entry names 2 MiB rather than one page.
pub const FLAG_PAGE_SIZE: u64 = FLAG_HUGE;

/// Bit 3: page-level write-through.
pub const FLAG_PAGE_WRITE_THROUGH: u64 = 1 << 3;
/// Bit 4: page-level cache disable.
pub const FLAG_PAGE_CACHE_DISABLE: u64 = 1 << 4;

/// The cache-disabling bits a device mapping needs.
///
/// Both, and that is not belt and braces.  `PCD` alone says the CPU must not
/// cache the page; `PWT` says a write goes through to memory rather than being
/// buffered.  A device's registers need both: a read of a status register
/// through a cached mapping returns whatever was true when the line was
/// fetched, and a store that sits in a write-combining buffer is a command the
/// device has not received.
pub const FLAG_UNCACHED: u64 = FLAG_PAGE_WRITE_THROUGH | FLAG_PAGE_CACHE_DISABLE;

/// The mask a physical address occupies in an entry.
///
/// Bits 12..52 — forty bits, which is the widest physical address x86_64's page
/// tables can name.  Bits 52..63 hold flags on a 64-bit entry: no-execute is
/// bit 63, and bits 52..63 are reserved.  A mask of `!0xFFF` would keep
/// no-execute in the address, and an address with bit 63 set is one no machine
/// has.
///
/// This is x86_64's width and not `usize`'s caution: on a 64-bit build
/// `usize`'s mask would carry the flag bits, and on a 32-bit build it would
/// drop half the address.
pub const PHYSICAL_ADDRESS_MASK: u64 = ((1u64 << 52) - 1) & !0xFFFu64;

/// Encode an entry as the word the machine reads.
///
/// The level is accepted and unused, so that all three machines answer the same
/// signature: x86_64's word does not vary by level — the `PS` bit that makes a
/// 2 MiB mapping is the caller's to set — while aarch64's page and block
/// descriptors differ in their low bits.  A kernel that had to pass a level on
/// one machine and not another would need to know which one it was running on.
pub fn encode(entry: Entry, _level: Level) -> u64 {
    if !entry.present {
        return 0;
    }
    let mut word = entry.address as u64 & PHYSICAL_ADDRESS_MASK;
    word |= FLAG_PRESENT;
    if entry.permissions.writable {
        word |= FLAG_WRITABLE;
    }
    if entry.permissions.user {
        word |= FLAG_USER;
    }
    if !entry.permissions.executable {
        word |= FLAG_NO_EXECUTE;
    }
    if entry.permissions.cache == Cache::Device {
        word |= FLAG_UNCACHED;
    }
    word
}

/// Decode a word the machine wrote at `level`.
///
/// Whether the entry is a leaf follows from the level and one bit: only a page
/// directory's entries may name 2 MiB (bit 7, PS), and the two levels above
/// ignore that bit.  A word alone does not say whether it is a leaf — bit 7
/// means "large page" in a page directory and "pat" in a page table — so a
/// decoder that guessed from the word would call a 4 KiB page a table.
pub fn decode(word: u64, level: Level) -> Entry {
    let present = word & FLAG_PRESENT != 0;
    if !present {
        return Entry::default();
    }
    Entry {
        address: (word & PHYSICAL_ADDRESS_MASK) as usize,
        permissions: Permissions {
            writable: word & FLAG_WRITABLE != 0,
            executable: word & FLAG_NO_EXECUTE == 0,
            user: word & FLAG_USER != 0,
            cache: if word & FLAG_UNCACHED != 0 {
                Cache::Device
            } else {
                Cache::Normal
            },
        },
        is_leaf: level == Level::Leaf || (level == Level::Third && word & FLAG_PAGE_SIZE != 0),
        present,
    }
}

/// The encoding, as the trait `memory` names.
pub struct Encoding;

impl EntryEncoding for Encoding {
    /// x86_64's word is the same at every level, so the level is not used.
    ///
    /// The one bit that differs — `PS`, bit 7, which says "this entry covers
    /// 2 MiB" — is set by whoever builds a large-page mapping, not by the
    /// encoder: a `Entry::page` at a page-directory level with `FLAG_PAGE_SIZE`
    /// already in its address is how this tree writes one.  aarch64 needs the
    /// level because its page and block descriptors differ in bits `[1:0]`;
    /// this machine does not, and an ignored parameter says so better than a
    /// second entry point that pretends to be level-aware.
    fn encode(entry: Entry, level: Level) -> u64 {
        encode(entry, level)
    }

    fn decode(word: u64, level: Level) -> Entry {
        decode(word, level)
    }
}

/// The address ranges on this machine that are *not* ordinary memory.
///
/// Empty, and that is a fact about the machine rather than a gap.  x86_64 has
/// no fixed peripheral window: a device's registers arrive as a PCI BAR, whose
/// address the bus reports, and `map_device` re-maps that range once it is
/// known.  What the firmware's identity map covers is ordinary memory
/// everywhere, which is what this says.
///
/// The contrast is the machine that answers differently.  A device-tree
/// platform puts its UART and its interrupt controller at addresses fixed by
/// the platform — before anything has been discovered — so "everything is
/// ordinary memory" is false there and the answer is a range.  That difference
/// is the machine's, which is why the question is asked here and not in the
/// code that builds a table.
pub fn device_windows() -> Windows {
    Windows::new()
}

/// A small set of address ranges that are a device's rather than memory's.
///
/// Empty on this machine, and the type is shared with the ones whose answer is
/// not: `kernel::address_space` asks every machine the same question and gets
/// the same shape back, which is what keeps the caller from knowing which
/// machine answered.
#[derive(Debug, Clone, Copy)]
pub struct Windows {
    length: usize,
}

impl Windows {
    /// No windows.
    pub const fn new() -> Windows {
        Windows { length: 0 }
    }

    /// The ranges, in no order.  Empty here.
    pub fn as_slice(&self) -> &[(usize, usize)] {
        let _ = self.length;
        &[]
    }
}

impl Default for Windows {
    fn default() -> Self {
        Self::new()
    }
}

/// Read the address of the table the machine is translating through.
pub fn current_root_table() -> usize {
    let value: usize;
    // SAFETY: reading `cr3` is unprivileged at ring 0 and has no side effect.
    // The low twelve bits are flags — PCID and the cache-disable bit — and the
    // address is what remains.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags))
    };
    value & paging::index::ADDRESS_MASK
}

/// Install `table` as the root, and answer whether this was a change.
///
/// The `invlpg` is not needed for a `cr3` write — writing `cr3` flushes the
/// whole non-global TLB — but the table's own page must be reachable through
/// it, which is why the caller maps the table before installing it.
///
/// # Safety
///
/// `table` must be a page-aligned, fully initialised four-level root whose
/// entries name physical memory.  Installing a partial table unmaps whatever
/// the walk reaches, including the instruction after this one.
pub unsafe fn install(table: usize) -> bool {
    debug_assert_eq!(table & (paging::PAGE_SIZE - 1), 0);
    let previous = current_root_table();
    if previous == table {
        return false;
    }
    // SAFETY: the caller promises the table is complete and aligned.  Writing
    // `cr3` makes the machine translate through it on the next memory access.
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) table, options(nostack, preserves_flags));
    }
    true
}

#[cfg(test)]
mod tests {
    use super::decode;
    use super::encode;
    use paging::Cache;
    use paging::Entry;
    use paging::Level;
    use paging::Permissions;

    /// A page entry round-trips through the encoding.
    #[test]
    fn a_page_entry_round_trips() {
        let entry = Entry::page(0x1234_5000, Permissions::KERNEL_READ_WRITE);
        let word = encode(entry, Level::Leaf);
        let decoded = decode(word, Level::Leaf);
        assert_eq!(decoded.address, 0x1234_5000);
        assert!(decoded.present);
        assert!(decoded.is_leaf, "a 4 KiB page is a leaf");
        assert!(decoded.permissions.writable);
        assert!(!decoded.permissions.executable);
        assert!(!decoded.permissions.user);
    }

    /// The flags land in the bits the machine reads.
    #[test]
    fn the_flags_are_in_the_machines_bits() {
        let read_write = encode(
            Entry::page(0x1000, Permissions::KERNEL_READ_WRITE),
            Level::Leaf,
        );
        assert_eq!(read_write & 0b111, 0b011, "present and writable");
        assert_ne!(read_write & (1 << 63), 0, "no-execute is bit 63");

        let read_execute = encode(
            Entry::page(0x1000, Permissions::KERNEL_READ_EXECUTE),
            Level::Leaf,
        );
        assert_eq!(read_execute & 0b111, 0b001, "present only");
        assert_eq!(
            read_execute & (1 << 63),
            0,
            "execute is the absence of no-execute"
        );
    }

    /// A device mapping sets both cache bits, and an ordinary one sets
    /// neither.
    ///
    /// The boot's identity map set neither, so every BAR the kernel reached
    /// was mapped as cached memory — which works on an emulator and is wrong
    /// on hardware.
    #[test]
    fn a_device_mapping_disables_the_cache() {
        let device = Entry::page(0xFE00_0000, Permissions::DEVICE);
        let word = encode(device, Level::Leaf);
        assert_ne!(word & super::FLAG_PAGE_CACHE_DISABLE, 0, "PCD is set");
        assert_ne!(word & super::FLAG_PAGE_WRITE_THROUGH, 0, "PWT is set");
        assert_eq!(decode(word, Level::Leaf).permissions.cache, Cache::Device);

        let ordinary = Entry::page(0x1000, Permissions::KERNEL_READ_WRITE);
        assert_eq!(encode(ordinary, Level::Leaf) & super::FLAG_UNCACHED, 0);
        assert_eq!(
            decode(encode(ordinary, Level::Leaf), Level::Leaf)
                .permissions
                .cache,
            Cache::Normal
        );
    }

    /// An absent entry encodes to zero, which is what the machine reads as
    /// "nothing here".
    #[test]
    fn an_absent_entry_is_zero() {
        assert_eq!(encode(Entry::EMPTY, Level::Leaf), 0);
        assert_eq!(decode(0, Level::Leaf), Entry::default());
    }

    /// The address's low twelve bits are flags, so an address that used them
    /// would set a permission nobody asked for.
    #[test]
    fn the_address_does_not_reach_the_flags() {
        let entry = Entry::page(0xABC0_0000, Permissions::KERNEL_READ_EXECUTE);
        let word = encode(entry, Level::Leaf);
        assert_eq!(word & 0xFFF, 0b001, "only present, no address bits");
    }

    /// No-execute is bit 63, and a decoded address does not carry it.
    ///
    /// This is the bug the first version had: the address mask was `!0xFFF`,
    /// which kept bit 63, so every non-executable mapping decoded to an
    /// address above 2^63 — a number no machine has.  The mask is the
    /// forty bits a physical address occupies, not everything that is not a
    /// flag.
    #[test]
    fn no_execute_does_not_leak_into_the_address() {
        let entry = Entry::page(0x1234_5000, Permissions::KERNEL_READ_WRITE);
        let word = encode(entry, Level::Leaf);
        assert_ne!(word >> 63, 0, "the entry is non-executable");
        let decoded = decode(word, Level::Leaf);
        assert_eq!(decoded.address, 0x1234_5000);
        assert!(decoded.address < (1usize << 52));
    }

    /// A user mapping carries the user bit and a kernel one does not.
    #[test]
    fn the_user_bit_is_what_says_who_may_reach() {
        let user = Entry::page(
            0x1000,
            Permissions {
                writable: true,
                executable: false,
                user: true,
                cache: Cache::Normal,
            },
        );
        assert_ne!(encode(user, Level::Leaf) & 0b100, 0);
        assert_eq!(
            encode(
                Entry::page(0x1000, Permissions::KERNEL_READ_WRITE),
                Level::Leaf
            ) & 0b100,
            0
        );
    }
}
