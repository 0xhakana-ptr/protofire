//! arch/x86_64/src/paging/mod.rs
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
//! The encoding, and `install`, a `cr3` write.  The arithmetic that decides
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
/// Bits 12..52, forty bits, which is the widest physical address x86_64's page
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
/// signature: x86_64's word does not vary by level, the `PS` bit that makes a
/// 2 MiB mapping is the caller's to set, while aarch64's page and block
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
/// ignore that bit.  A word alone does not say whether it is a leaf, bit 7
/// means "large page" in a page directory and "pat" in a page table, so a
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
    /// The one bit that differs, `PS`, bit 7, which says "this entry covers
    /// 2 MiB", is set by whoever builds a large-page mapping, not by the
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

/// Make a change to the page tables visible to the walk.
///
/// A `cr3` write flushes the whole non-global TLB, so a change made after
/// `install` is invisible until something invalidates.  `invlpg` on the changed
/// address is the narrow form; this kernel's tables change rarely enough that
/// the whole-TLB flush a `cr3` rewrite performs is the simpler answer.
///
/// # Safety
///
/// Called after a page-table change on this CPU.
#[cfg(target_os = "none")]
pub fn flush_translation() {
    let root = current_root_table();
    // SAFETY: rewriting `cr3` with the value it already holds invalidates the
    // TLB and changes nothing else, the table it names is the one in use.
    unsafe {
        core::arch::asm!("mov cr3, {}", in(reg) root, options(nostack, preserves_flags));
    }
}

/// The host form: nothing, because a host has no address space to flush.
#[cfg(not(target_os = "none"))]
pub fn flush_translation() {}

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
/// the platform, before anything has been discovered, so "everything is
/// ordinary memory" is false there and the answer is a range.  That difference
/// is the machine's, which is why the question is asked here and not in the
/// code that builds a table.
pub fn device_windows() -> Windows {
    // The page a started CPU is entered at.  The boot CPU writes the per-start
    // handoff into it before every start-up interrupt, and the target CPU
    // executes the page once, through the boot page table.  Uncached, so the
    // words the boot CPU wrote are the words the target reads; the code runs
    // exactly once per CPU and nothing on this machine touches the page after
    // the handoff is read.
    let mut windows = Windows::new();
    windows.push(
        crate::smp::TRAMPOLINE_ADDRESS,
        crate::smp::TRAMPOLINE_ADDRESS + 0x1000,
    );
    windows
}

/// A small set of address ranges that are a device's rather than memory's.
///
/// The trampoline page is this machine's one entry, and the type is shared with
/// the machines whose answer is longer: `kernel::address_space` asks every
/// machine the same question and gets the same shape back, which is what keeps
/// the caller from knowing which machine answered.
#[derive(Debug, Clone, Copy)]
pub struct Windows {
    entries: [(usize, usize); 4],
    length: usize,
}

impl Windows {
    /// No windows: every address keeps its rule.
    pub const fn new() -> Windows {
        Windows {
            entries: [(0, 0); 4],
            length: 0,
        }
    }

    /// Add one half-open range.  A full set drops it rather than growing.
    pub fn push(&mut self, start: usize, end: usize) {
        if self.length < self.entries.len() {
            self.entries[self.length] = (start, end);
            self.length += 1;
        }
    }

    /// The ranges, in the order they were added.
    pub fn as_slice(&self) -> &[(usize, usize)] {
        &self.entries[..self.length]
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
    // The low twelve bits are flags, PCID and the cache-disable bit, and the
    // address is what remains.
    unsafe {
        core::arch::asm!("mov {}, cr3", out(reg) value, options(nomem, nostack, preserves_flags))
    };
    value & paging::index::ADDRESS_MASK
}

/// Install `table` as the root, and answer whether this was a change.
///
/// The `invlpg` is not needed for a `cr3` write, writing `cr3` flushes the
/// whole non-global TLB, but the table's own page must be reachable through
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
mod tests;
