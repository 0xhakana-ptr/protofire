//! libs/paging/src/index/mod.rs
//!
//! Page-table structures: what a table is, what an entry says, and the
//! arithmetic that turns an address into an index.
//!
//! ## Why this is a crate of its own
//!
//! The *encoding* of an entry is the machine's: x86_64 puts present, writable
//! and user in bits 0..3 and no-execute in bit 63, and aarch64 puts a
//! different set of bits in a different order.  What is **not** the machine's
//! is the arithmetic, which bits of an address select which level, how large
//! a leaf covers, and how a table's entries are walked.
//!
//! That arithmetic is where the bugs are: a shift off by one maps the wrong
//! page, and the failure looks like memory corruption a long way from here.
//!
//! It is a crate rather than a module because two crates below the machine
//! need it and may not depend on each other: `arch` encodes an entry and
//! installs a table, and `memory` hands out the frames a table is built in.
//! Putting this in either would make the other reach across, and `arch` is at
//! layer 3 while `memory` is at 4, an upward edge, which the layering gate
//! refuses and is right to.
//!
//! So this crate names nothing at all.  A page table is a page of numbers and
//! a walk over it is arithmetic; nothing here is privileged, locked or
//! allocated.
//!
//! ## The shape of a table
//!
//! A table is 512 entries of eight bytes: 4 KiB, one page.  An entry is a
//! physical address and a bitfield.  The bottom bits say what the entry is,
//! present, writable, user-accessible, and whether it names another table or
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
//! This is x86_64's arrangement.  aarch64's differs, its flags are in the low
//! bits too but mean different things and it calls a leaf a "block", and the
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

/// How a mapping's memory may be cached.
///
/// This is part of what a mapping says, and it is not decoration: a device's
/// registers read through a cached mapping return stale values, and a store to
/// one may never reach the device at all.  The boot's own identity map sets
/// neither of the cache bits, so every BAR the kernel reaches today is mapped
/// as ordinary cached memory, which works on an emulator whose MMIO happens to
/// behave and is wrong on hardware.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Cache {
    /// Ordinary memory: the CPU may cache it, and a write may be buffered.
    #[default]
    Normal,
    /// A device's registers: never cached, and a read is not reordered ahead of
    /// one that came before it.
    Device,
}

/// What an entry permits, and how its memory may be cached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Permissions {
    pub writable: bool,
    pub executable: bool,
    /// Whether a user-mode program may reach through this entry.
    pub user: bool,
    /// Whether the memory behind this entry may be cached.
    pub cache: Cache,
}

impl Permissions {
    /// Read, execute, supervisor only, what the kernel's own code has.
    pub const KERNEL_READ_EXECUTE: Permissions = Permissions {
        writable: false,
        executable: true,
        user: false,
        cache: Cache::Normal,
    };

    /// Read, write, no execute, supervisor only, what the kernel's data has.
    pub const KERNEL_READ_WRITE: Permissions = Permissions {
        writable: true,
        executable: false,
        user: false,
        cache: Cache::Normal,
    };

    /// Read, write, no execute, supervisor only, **uncached**, what a
    /// device's registers have.
    ///
    /// A barrier question and a caching question are different: this says the
    /// memory behind the mapping is a device's, so the CPU must not cache a
    /// read of it and must not defer a write to it.  The machine encodes it,
    /// /// x86_64 with `PCD`, `PWT` and `PAT`, aarch64 with its `MAIR` index,
    /// and a machine that had no such encoding would have to say so.
    pub const DEVICE: Permissions = Permissions {
        writable: true,
        executable: false,
        user: false,
        cache: Cache::Device,
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
mod tests;
