//! paging/src/index.rs
//!
//! Page-table structures: what a table is, what an entry says, and the
//! arithmetic that turns an address into an index.
//!
//! ## Why this is a crate of its own
//!
//! The *encoding* of an entry is the machine's: x86_64 puts present, writable
//! and user in bits 0..3 and no-execute in bit 63, and aarch64 puts a
//! different set of bits in a different order.  What is **not** the machine's
//! is the arithmetic — which bits of an address select which level, how large
//! a leaf covers, and how a table's entries are walked.
//!
//! That arithmetic is where the bugs are: a shift off by one maps the wrong
//! page, and the failure looks like memory corruption a long way from here.
//!
//! It is a crate rather than a module because two crates below the machine
//! need it and may not depend on each other: `arch` encodes an entry and
//! installs a table, and `memory` hands out the frames a table is built in.
//! Putting this in either would make the other reach across, and `arch` is at
//! layer 3 while `memory` is at 4 — an upward edge, which the layering gate
//! refuses and is right to.
//!
//! So this crate names nothing at all.  A page table is a page of numbers and
//! a walk over it is arithmetic; nothing here is privileged, locked or
//! allocated.
//!
//! ## The shape of a table
//!
//! A table is 512 entries of eight bytes: 4 KiB, one page.  An entry is a
//! physical address and a bitfield.  The bottom bits say what the entry is —
//! present, writable, user-accessible — and whether it names another table or
//! a page of memory.
//!
//! ```text
//! bits 0..11   flags
//! bit  0       present
//! bit  1       writable
//! bit  2       user-accessible
//! bit  7       huge page (the entry covers more than one page)
//! bit 63       no-execute
//! bits 12..    the physical address, page-aligned
//! ```
//!
//! This is x86_64's arrangement.  aarch64's differs — its flags are in the low
//! bits too but mean different things and it calls a leaf a "block" — and the
//! two do not share an encoder.  What they *do* share is the index arithmetic
//! and the walk, which is what that part of this module is.

/// The entries in one table.
pub const ENTRIES_PER_TABLE: usize = 512;

/// How many bits one level's index takes.
///
/// Nine, because a table holds 512 entries.  Every machine this tree supports
/// uses nine, which is why the arithmetic here is not generic over it.
pub const INDEX_BITS: u32 = 9;

/// The size of one page, which is also the size of one table.
pub const PAGE_SIZE: usize = 4096;

/// Bits 0..12 of an address are flags rather than address bits.
pub const ADDRESS_MASK: usize = !(PAGE_SIZE - 1);

/// Entry flag: the entry is present.
pub const FLAG_PRESENT: u64 = 1 << 0;
/// Entry flag: writes are permitted.
pub const FLAG_WRITABLE: u64 = 1 << 1;
/// Entry flag: user-mode access is permitted.
pub const FLAG_USER: u64 = 1 << 2;
/// Entry flag: this entry covers more than one page.
pub const FLAG_HUGE: u64 = 1 << 7;
/// Entry flag: execution is refused.
pub const FLAG_NO_EXECUTE: u64 = 1 << 63;

/// What an entry permits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Permissions {
    pub writable: bool,
    pub executable: bool,
    /// Whether a user-mode program may reach through this entry.
    pub user: bool,
}

impl Permissions {
    /// Read, execute, supervisor only — what the kernel's own code has.
    pub const KERNEL_READ_EXECUTE: Permissions = Permissions {
        writable: false,
        executable: true,
        user: false,
    };

    /// Read, write, no execute, supervisor only — what the kernel's data has.
    pub const KERNEL_READ_WRITE: Permissions = Permissions {
        writable: true,
        executable: false,
        user: false,
    };

    /// The flags this permission set contributes to an entry.
    pub const fn flags(self) -> u64 {
        let mut flags = FLAG_PRESENT;
        if self.writable {
            flags |= FLAG_WRITABLE;
        }
        if self.user {
            flags |= FLAG_USER;
        }
        if !self.executable {
            flags |= FLAG_NO_EXECUTE;
        }
        flags
    }
}

/// Which level of the walk an index belongs to.
///
/// Named from the top down, as the walk goes: the first index read is the
/// highest level.  x86_64 calls them PML4, PDPT, PD and PT; this names them by
/// position so a machine that has three levels uses the bottom three.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    /// The topmost table, whose address the machine's register holds.
    Root = 0,
    /// The second table.
    Second = 1,
    /// The third table.
    Third = 2,
    /// The table whose entries name pages.
    Leaf = 3,
}

impl Level {
    /// The shift a virtual address needs for this level's index.
    ///
    /// The leaf's index is bits 12..21, the third's is 21..30, and so on: each
    /// level up takes the next nine bits.
    pub const fn shift(self) -> u32 {
        let from_bottom = 3 - self as u32;
        12 + from_bottom * INDEX_BITS
    }
}

/// The index into the table at `level` that a virtual address selects.
pub fn index(level: Level, virtual_address: usize) -> usize {
    (virtual_address >> level.shift()) & (ENTRIES_PER_TABLE - 1)
}

/// The address a virtual address's leaf index covers, at the start of its page.
pub fn page_base(address: usize) -> usize {
    address & ADDRESS_MASK
}

/// How many bytes one level's slot covers.
///
/// The leaf's slot is one page; each level up multiplies by the entries in the
/// table below, which is why a root slot covers half a gigabyte on a four-level
/// machine.
pub const fn span(level: Level) -> usize {
    PAGE_SIZE << ((3 - level as u32) * INDEX_BITS)
}

#[cfg(test)]
mod tests {
    use super::ENTRIES_PER_TABLE;
    use super::Level;
    use super::PAGE_SIZE;
    use super::Permissions;
    use super::index;
    use super::page_base;
    use super::span;

    /// The four levels' shifts are the ones the arithmetic gives, and they
    /// partition a 48-bit address.
    ///
    /// A shift off by one maps the wrong page, and the failure shows up as
    /// corruption somewhere else entirely — which is why this is pinned.
    #[test]
    fn the_levels_shift_by_nine_bits_each() {
        assert_eq!(Level::Leaf.shift(), 12);
        assert_eq!(Level::Third.shift(), 21);
        assert_eq!(Level::Second.shift(), 30);
        assert_eq!(Level::Root.shift(), 39);
    }

    /// A virtual address's indices are its nine-bit fields, from the top down.
    ///
    /// The address `0x0000_7f00_1234_5000` is chosen so every level's index is
    /// a different number: a test that used an address whose fields repeated
    /// would pass with the fields swapped.
    #[test]
    fn an_address_is_split_into_nine_bit_indices() {
        let address = 0x0000_7f00_1234_5000usize;
        assert_eq!(index(Level::Root, address), 0x0FE);
        assert_eq!(index(Level::Second, address), 0x000);
        assert_eq!(index(Level::Third, address), 0x091);
        assert_eq!(index(Level::Leaf, address), 0x145);
    }

    /// Every index is inside a table, for every address a 48-bit machine can
    /// produce.
    ///
    /// The mask is what makes that true: an index is nine bits, and an address
    /// whose high bits are set would otherwise ask for entry 512 of a table of
    /// 512 entries.
    #[test]
    fn every_index_fits_in_a_table() {
        for address in [
            0usize,
            0xFFF,
            0x1000,
            usize::MAX,
            0x0000_FFFF_FFFF_FFFF,
            0xFFFF_8000_0000_0000,
        ] {
            for level in [Level::Root, Level::Second, Level::Third, Level::Leaf] {
                assert!(
                    index(level, address) < ENTRIES_PER_TABLE,
                    "index {} for {level:?} at {address:#x}",
                    index(level, address)
                );
            }
        }
    }

    /// Each level's span is the one below it times the entries in a table.
    #[test]
    fn a_level_covers_what_the_level_below_holds() {
        assert_eq!(span(Level::Leaf), PAGE_SIZE);
        assert_eq!(span(Level::Third), PAGE_SIZE * ENTRIES_PER_TABLE);
        assert_eq!(span(Level::Second), span(Level::Third) * ENTRIES_PER_TABLE);
        assert_eq!(span(Level::Root), span(Level::Second) * ENTRIES_PER_TABLE);
        // A root slot covers 512 GiB, which is what a four-level table reaches.
        assert_eq!(span(Level::Root), 512 * 1024 * 1024 * 1024);
    }

    /// An address's page base drops the offset within the page.
    #[test]
    fn the_page_base_drops_the_offset() {
        assert_eq!(page_base(0x1234_5678), 0x1234_5000);
        assert_eq!(page_base(0x1000), 0x1000);
        assert_eq!(page_base(0xFFF), 0);
    }

    /// The permission flags are the ones an entry carries.
    #[test]
    fn permissions_become_entry_flags() {
        let read_write = Permissions::KERNEL_READ_WRITE.flags();
        assert_eq!(read_write & super::FLAG_PRESENT, super::FLAG_PRESENT);
        assert_eq!(read_write & super::FLAG_WRITABLE, super::FLAG_WRITABLE);
        assert_eq!(read_write & super::FLAG_NO_EXECUTE, super::FLAG_NO_EXECUTE);

        let read_execute = Permissions::KERNEL_READ_EXECUTE.flags();
        assert_eq!(read_execute & super::FLAG_PRESENT, super::FLAG_PRESENT);
        assert_eq!(read_execute & super::FLAG_WRITABLE, 0);
        assert_eq!(read_execute & super::FLAG_NO_EXECUTE, 0);
    }

    /// A kernel mapping is not user-accessible, and that is not incidental.
    ///
    /// If the flag were always set, a user program could read the kernel's
    /// memory — and nothing in a boot would notice.
    #[test]
    fn a_kernel_mapping_is_not_user_accessible() {
        assert_eq!(Permissions::KERNEL_READ_WRITE.flags() & super::FLAG_USER, 0);
        assert_eq!(
            Permissions::KERNEL_READ_EXECUTE.flags() & super::FLAG_USER,
            0
        );
    }
}
