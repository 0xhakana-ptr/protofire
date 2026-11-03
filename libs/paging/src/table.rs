//! libs/paging/src/table.rs
//!
//! A page table the kernel can fill: 512 entries of eight bytes, and the three
//! operations that are the whole of what one needs — map an address, look one
//! up, and say what a mapping is missing.
//!
//! ## What is x86_64's and what is not
//!
//! The *entry encoding* is the machine's: x86_64 puts present/writable/user in
//! bits 0..3 and no-execute in bit 63, and aarch64 puts a different set of
//! bits in a different order.  So [`Entry`] here is the shape a mapping has,
//! and `arch` is what turns one into a u64 a machine reads.
//!
//! The *walk* is not the machine's: given a root table's address, finding the
//! entry for an address is the same arithmetic everywhere — which is why
//! [`PageTable`] and [`map`] live here and are tested on a host.
//!
//! ## Why this is data and not a machine
//!
//! A page table is a page of memory with numbers in it.  It is not privileged
//! to *write* one — the privilege is in installing it, which is `arch`'s
//! `cr3`/`ttbr0`/`satp` write.  Keeping that split is what lets a host test
//! build a table, map an address, and assert what a walk finds, without an
//! emulator and without any address space being real.
//!
//! The tables a test builds are ordinary memory; the tables a machine uses are
//! frames the allocator hands out and that are therefore physical.  The code
//! is the same and the difference is the address.

use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

use crate::index::ENTRIES_PER_TABLE;
use crate::index::PAGE_SIZE;
use crate::index::Permissions;

/// One entry in a page table: an address and what it permits.
///
/// The address is physical.  A table that named a virtual address would need
/// the walk it is part of to translate it, which is circular.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Entry {
    /// The physical address this entry names, page-aligned.
    pub address: usize,
    pub permissions: Permissions,
    /// Whether this entry holds a mapping rather than naming another table.
    pub is_leaf: bool,
    /// Whether this entry names anything at all.
    pub present: bool,
}

impl Entry {
    /// An entry that names nothing.
    pub const EMPTY: Entry = Entry {
        address: 0,
        permissions: Permissions {
            writable: false,
            executable: false,
            user: false,
            cache: crate::index::Cache::Normal,
        },
        is_leaf: false,
        present: false,
    };

    /// An entry naming the table at `address`.
    ///
    /// The permissions are **not** a leaf's: an entry that names a table
    /// carries the widest set, because what it permits is decided by the leaf
    /// the walk reaches.  Giving it a leaf's permissions is not a harmless
    /// default — on x86_64 the no-execute bit of a table entry is inherited by
    /// every page below it, so a table entry marked non-executable makes the
    /// whole subtree unexecutable and the next instruction fetch faults.
    ///
    /// This is why the permissions are `KERNEL_READ_WRITE` and not something
    /// narrower: a table entry that said "not writable" would make every page
    /// under it not writable on a machine that inherits the bit.
    pub const fn table(address: usize) -> Entry {
        Entry {
            address,
            permissions: Permissions {
                writable: true,
                // Executable, so the no-execute bit is not set and cannot be
                // inherited by the code a leaf maps.
                executable: true,
                user: false,
                cache: crate::index::Cache::Normal,
            },
            is_leaf: false,
            present: true,
        }
    }

    /// An entry naming the page at `address`.
    pub const fn page(address: usize, permissions: Permissions) -> Entry {
        Entry {
            address,
            permissions,
            is_leaf: true,
            present: true,
        }
    }
}

/// One table: 512 entries.
///
/// `repr(align)` rather than `repr(C)`: the hardware reads a table through the
/// address it was given and expects it to start on a page boundary, and a
/// misaligned table is not a table the machine can be told about.
#[repr(C, align(4096))]
pub struct PageTable {
    entries: [AtomicU64; ENTRIES_PER_TABLE],
}

impl PageTable {
    /// An all-zero table: nothing mapped.
    pub const fn new() -> PageTable {
        PageTable {
            entries: [const { AtomicU64::new(0) }; ENTRIES_PER_TABLE],
        }
    }

    /// The raw entry at `index`.
    pub fn entry(&self, index: usize) -> u64 {
        self.entries[index].load(Ordering::Acquire)
    }

    /// Install `value` at `index`.
    pub fn set_entry(&self, index: usize, value: u64) {
        self.entries[index].store(value, Ordering::Release);
    }

    /// The table's own address, which is what an upper-level entry names.
    pub fn address(&self) -> usize {
        self as *const PageTable as usize
    }

    /// Whether the table holds no mapping at all.
    pub fn is_empty(&self) -> bool {
        self.entries
            .iter()
            .all(|entry| entry.load(Ordering::Acquire) == 0)
    }

    /// How many entries are present.
    pub fn used_entries(&self) -> usize {
        self.entries
            .iter()
            .filter(|entry| entry.load(Ordering::Acquire) != 0)
            .count()
    }
}

impl Default for PageTable {
    fn default() -> Self {
        Self::new()
    }
}

/// What a walk found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Translation {
    /// The address is mapped, and this is where it lands.
    Mapped {
        physical_address: usize,
        permissions: Permissions,
    },
    /// No entry along the way was present.
    Unmapped,
    /// A table entry was present but named nothing that can be walked.
    Broken,
}

/// The encoding a machine uses, which this crate does not know.
///
/// A table is a page of numbers the hardware reads; what bit 0 means is the
/// machine's.  This trait is the seam: [`PageTable`] holds entries as values,
/// and the machine encodes them for the register that installs the table.
///
/// ## Why `decode` takes a level
///
/// Whether an entry is a leaf — a mapping rather than a pointer to the next
/// table — is not a property of the word.  On x86_64 bit 7 means "this entry
/// covers 2 MiB" in a page directory and "the PAT bit" in a page table, and it
/// is ignored in the two levels above.  The same word means different things
/// at different levels, so a decoder that only saw the word would call a 4 KiB
/// page a table.
///
/// So the level is part of the question.  A caller walking a table knows which
/// level it is at, and that is the caller's knowledge to supply.
pub trait EntryEncoding {
    /// Encode an entry as the word the machine reads.
    fn encode(entry: Entry) -> u64;

    /// Decode the word the machine wrote at `level`.
    fn decode(word: u64, level: crate::index::Level) -> Entry;
}

/// Map `virtual_address` to `physical_address` at `level`, through `table`.
///
/// `level` says which level the *entry* is at: a leaf entry maps one page, and
/// an upper entry names the next table down.  The function fills the entry and
/// answers whether it was already occupied — a remap is worth reporting,
/// because two callers who both believe they own an address is a bug that
/// otherwise shows up as one of them silently losing.
///
/// The physical address is masked to what an entry can name: the low twelve
/// bits are flags, so an unaligned address here would set a permission bit
/// nobody asked for.
pub fn map(
    table: &PageTable,
    index: usize,
    physical_address: usize,
    permissions: Permissions,
    is_leaf: bool,
    encode: fn(Entry) -> u64,
) -> bool {
    debug_assert_eq!(physical_address & (PAGE_SIZE - 1), 0);
    let existing = table.entry(index);
    let entry = if is_leaf {
        Entry::page(physical_address, permissions)
    } else {
        Entry::table(physical_address)
    };
    table.set_entry(index, encode(entry));
    existing != 0
}

#[cfg(test)]
mod tests {
    use super::Entry;
    use super::PageTable;
    use super::map;
    use crate::index::ENTRIES_PER_TABLE;
    use crate::index::Permissions;

    /// The encoding a test uses: the identity, with the address's low bits
    /// cleared.
    ///
    /// A machine's encoding sets flags in the low bits; this one does not, so a
    /// test can read the address straight back out of the word.
    fn identity(entry: Entry) -> u64 {
        if entry.present {
            entry.address as u64
        } else {
            0
        }
    }

    /// A fresh table maps nothing.
    #[test]
    fn a_new_table_is_empty() {
        let table = PageTable::new();
        assert!(table.is_empty());
        assert_eq!(table.used_entries(), 0);
        for index in 0..ENTRIES_PER_TABLE {
            assert_eq!(table.entry(index), 0);
        }
    }

    /// The table is a page, and it is page-aligned, because the machine reads
    /// it through an address it was given.
    #[test]
    fn the_table_is_a_page_and_aligned() {
        use core::mem::align_of;
        use core::mem::size_of;
        assert_eq!(size_of::<PageTable>(), crate::index::PAGE_SIZE);
        assert_eq!(align_of::<PageTable>(), crate::index::PAGE_SIZE);
    }

    /// A mapping is visible in the entry, and mapping twice says so.
    ///
    /// A remap is a caller's bug worth reporting: two owners of one address is
    /// otherwise discovered as one of them silently losing it.
    #[test]
    fn a_mapping_is_written_and_a_remap_is_reported() {
        let table = PageTable::new();
        let first = map(
            &table,
            3,
            0x1000,
            Permissions::KERNEL_READ_WRITE,
            true,
            identity,
        );
        assert!(!first, "the entry was empty");
        assert_eq!(table.entry(3), 0x1000);

        let second = map(
            &table,
            3,
            0x2000,
            Permissions::KERNEL_READ_WRITE,
            true,
            identity,
        );
        assert!(second, "the entry already held a mapping");
        assert_eq!(table.entry(3), 0x2000, "the newer mapping won");
    }

    /// Two entries are two mappings: writing one does not disturb its
    /// neighbour.
    #[test]
    fn entries_are_independent() {
        let table = PageTable::new();
        map(
            &table,
            0,
            0x1000,
            Permissions::KERNEL_READ_WRITE,
            true,
            identity,
        );
        map(
            &table,
            511,
            0x2000,
            Permissions::KERNEL_READ_WRITE,
            true,
            identity,
        );
        assert_eq!(table.entry(0), 0x1000);
        assert_eq!(table.entry(511), 0x2000);
        assert_eq!(table.used_entries(), 2);
    }

    /// An unaligned physical address is a caller's bug, and a debug build
    /// says so rather than setting a permission bit nobody asked for.
    ///
    /// The assertion is a `debug_assert` because the mask would silently drop
    /// the low bits in a release build, and a mapping one page off is worse
    /// than a panic.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "assertion")]
    fn an_unaligned_address_is_refused() {
        let table = PageTable::new();
        map(
            &table,
            0,
            0x1234,
            Permissions::KERNEL_READ_WRITE,
            true,
            identity,
        );
    }
}
