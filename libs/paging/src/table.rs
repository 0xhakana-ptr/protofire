//! libs/paging/src/table.rs
//!
//! A page table the kernel can fill: 512 entries of eight bytes, and the three
//! operations that are the whole of what one needs, map an address, look one
//! up, and say what a mapping is missing.
//!
//! The *entry encoding* is the machine's: x86_64 puts present/writable/user in
//! bits 0..3 and no-execute in bit 63, and aarch64 puts a different set of
//! bits in a different order.  So [`Entry`] here is the shape a mapping has,
//! and `arch` is what turns one into a u64 a machine reads.
//!
//! The *walk* is not the machine's: given a root table's address, finding the
//! entry for an address is the same arithmetic everywhere, which is why
//! [`PageTable`] and [`map`] live here and are tested on a host.
//!
//! A page table is a page of memory with numbers in it.  It is not privileged
//! to *write* one, the privilege is in installing it, which is `arch`'s
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
    /// default, on x86_64 the no-execute bit of a table entry is inherited by
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

    /// An entry naming the table at `address`, reachable from a user program.
    ///
    /// x86_64 checks the user bit at **every** level of the walk, not only at
    /// the leaf: an access from ring 3 to an address under a supervisor-only
    /// table entry is refused with a protection fault even when the leaf is
    /// marked user.  So a program's pages need their whole path, root, second,
    /// third and leaf, to carry the bit, and a table entry built by
    /// [`Entry::table`] would break every mapping under it.
    ///
    /// aarch64 ignores the permission bits of a table descriptor entirely, so
    /// this entry and [`Entry::table`] produce the same word there.  The name
    /// says what the entry is *for* rather than which machine needs it.
    pub const fn user_table(address: usize) -> Entry {
        Entry {
            address,
            permissions: Permissions {
                writable: true,
                executable: true,
                user: true,
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
/// Whether an entry is a leaf, a mapping rather than a pointer to the next
/// table, is not a property of the word.  On x86_64 bit 7 means "this entry
/// covers 2 MiB" in a page directory and "the PAT bit" in a page table, and it
/// is ignored in the two levels above.  The same word means different things
/// at different levels, so a decoder that only saw the word would call a 4 KiB
/// page a table.
///
/// **Encoding needs the level for the same reason, and the version of this
/// trait that took only the entry was wrong.**  aarch64 writes a 4 KiB page
/// descriptor and a 1 GiB block descriptor with different bits at `[1:0]`, so
/// an encoder with no level has to pick one and is wrong about the other.
/// `arch_aarch64`'s implementation hard-coded `Level::Third` to fill the gap;
/// the kernel builds four levels, so every 4 KiB page came out as a block
/// descriptor and the first instruction fetch after the MMU came on was a
/// section fault at an address the walk had just been told was a 1 GiB region.
///
/// The level is therefore part of the question in both directions.  A caller
/// writing an entry knows which table it is writing into, and that is the
/// caller's knowledge to supply.
pub trait EntryEncoding {
    /// Encode an entry for a table at `level`, as the word the machine reads.
    fn encode(entry: Entry, level: crate::index::Level) -> u64;

    /// Decode the word the machine wrote at `level`.
    fn decode(word: u64, level: crate::index::Level) -> Entry;
}

/// Map `virtual_address` to `physical_address` at `level`, through `table`.
///
/// `level` says which level the *entry* is at: a leaf entry maps one page, and
/// an upper entry names the next table down.  The function fills the entry and
/// answers whether it was already occupied, a remap is worth reporting,
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
mod tests;
