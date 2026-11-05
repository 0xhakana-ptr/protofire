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
//! bit  10    AF: access flag, a descriptor with it clear faults on first use
//! bits 11..   the next level table or the output address
//! ```
//!
//! Two differences from x86_64 matter here.  **Read-only is a bit that is
//! set**, not a writable bit that is clear, so a permission set translates by
//! inversion.  And **the access flag is not optional**: a descriptor with AF
//! clear is one the MMU faults on, which is how the kernel learns a page is
//! live, this tree does not implement that, so every descriptor this crate
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
//! `current_root_table` are absent, the module still compiles, because the
//! encoding is arithmetic and a host test can check it.  That is the same split
//! the console uses: the arm that needs the machine is the machine's, and the
//! arithmetic is everyone's.

use fdt::Node;
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
/// | 0 | `0xFF`, normal memory, write-back cached | the kernel's own memory |
/// | 1 | `0x00`, device memory, gathering off | a device's registers |
///
/// Both are installed by `maIR` in `install`; a descriptor that named an index
/// those bytes do not define is one the MMU treats as device memory, which is
/// the safe direction but not what a caller asked for.
pub const ATTR_INDEX_SHIFT: u64 = 2;
/// `MAIR_EL1` byte 0: normal, write-back cached.
pub const ATTR_NORMAL: u64 = 0 << ATTR_INDEX_SHIFT;
/// `MAIR_EL1` byte 1: device, non-gathering.
pub const ATTR_DEVICE: u64 = 1 << ATTR_INDEX_SHIFT;

/// Bit 6: `AP[1]`, EL0 may access the page.
pub const AP_USER: u64 = 1 << 6;
/// Bit 7: `AP[2]`, the page is read-only.  Set means read-only, which is the
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

/// A leaf at a level that can hold a block gets `TYPE_BLOCK`; the last level
/// always gets `TYPE_TABLE_OR_PAGE`, because a 4 KiB granule's fourth level has
/// no block form.
///
/// ## A table descriptor carries an address and a type, and nothing else
///
/// This is not tidiness.  In a stage-1 translation-table descriptor the bits
/// `[11:2]` and `[58:48]` are **Ignored**, the architecture says the hardware
/// must not act on them, but the fields this crate sets for a *leaf* live in
/// exactly those ranges: `AF` at 10, `AP` at 6 and 7, the attribute index at
/// 2..4, `UXN` at 54, `PXN` at 53.
///
/// The first version of this function set them on every descriptor, table or
/// leaf.  On a machine whose MMU was off that is invisible, which is why it
/// survived: `install` wrote `TTBR0_EL1` and never set `SCTLR_EL1.M`, so no
/// descriptor was ever read.
///
/// ## Whether an entry is a leaf is the entry's, not the level's
///
/// Whether a descriptor is a *leaf* is `Entry::is_leaf`, and whether a leaf may
/// cover more than one page is the level's.  Conflating the two is what made a
/// 4 KiB page come out as a block descriptor: the caller encoded every entry
/// with one level, and a leaf at a block-capable level is a block.
pub fn encode_at(entry: Entry, level: Level) -> u64 {
    if !entry.present {
        return 0;
    }

    // A table entry names the next level and stops there.
    if !entry.is_leaf {
        return (entry.address as u64 & OUTPUT_ADDRESS_MASK) | TYPE_TABLE_OR_PAGE;
    }

    // A leaf: a block where the level has one, a page at the last level.
    let is_block = matches!(level, Level::Second | Level::Third);
    let attribute = match entry.permissions.cache {
        paging::Cache::Normal => ATTR_NORMAL,
        paging::Cache::Device => ATTR_DEVICE,
    };
    let kind = if is_block {
        TYPE_BLOCK
    } else {
        TYPE_TABLE_OR_PAGE
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

/// A leaf at `Level::Leaf` is a 4 KiB page descriptor; anywhere higher it is a
/// block.  The level is a parameter rather than a default because the two are
/// different descriptors, and a caller that did not say which it meant would
/// get a block where it wanted a page.
pub fn encode(entry: Entry, level: Level) -> u64 {
    encode_at(entry, level)
}

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

pub struct Encoding;

impl EntryEncoding for Encoding {
    fn encode(entry: Entry, level: Level) -> u64 {
        encode(entry, level)
    }

    fn decode(word: u64, level: Level) -> Entry {
        decode(word, level)
    }
}

/// `TCR_EL1.T0SZ`: 16, which is a **48-bit** virtual address space.
///
/// The input address size is `64 - T0SZ` bits, and the value has to match the
/// **depth** of the table the walk starts in.  This is the number that failed
/// first:
///
/// | `T0SZ` | VA bits | levels | what the walk starts at |
/// |---|---|---|---|
/// | 25 | 39 | 3 | the table in `TTBR0_EL1` is a **level 1** table |
/// | 16 | 48 | 4 | the table in `TTBR0_EL1` is a **level 0** table |
///
/// The kernel builds four levels, root, second, third, leaf, so the root is a
/// level 0 table and `T0SZ` must be 16.  A 39-bit `T0SZ` over a four-level
/// table has the machine treat the root as level 1, index it with address bits
/// `[38:30]`, and never read the root's entry 0 at all: the first instruction
/// fetch then faults with `DFSC = 0b000101`, *translation fault, level 1*, ///
/// which is what the boot log said, and what named this constant.
///
/// `Level::Root`'s shift is 39, which is the 48-bit arrangement: the root's
/// index is bits `[47:39]`.
pub const TCR_T0SZ: u64 = 16;

/// `TCR_EL1.TG0`: 4 KiB granule.
pub const TCR_TG0_4K: u64 = 0b00;

/// `TCR_EL1.IRGN0` and `ORGN0`: normal memory, write-back write-allocate.
pub const TCR_RGN_WRITE_BACK: u64 = 0b01;

/// `TCR_EL1.SH0`: inner shareable.
pub const TCR_SH_INNER: u64 = 0b11;

/// The `TCR_EL1` value this tree installs.
///
/// Only the fields the walk needs are set:
///
/// | field | value | why |
/// |---|---|---|
/// | `T0SZ` | 25 | a 39-bit space, matching a four-level table |
/// | `IRGN0`/`ORGN0` | `0b01` | write-back, so a table read caches |
/// | `SH0` | `0b11` | inner shareable, because a second CPU must see a table |
/// | `TG0` | `0b00` | 4 KiB, the granule `paging` encodes |
/// | `IPS` | from `PARange` | see [`ips_for_parange`] |
/// | `EPD0` | 0 | walks through `TTBR0_EL1` are enabled |
///
/// `A1`/`AS`/`TBI`/`TG1` are left at zero: this kernel does not use the
/// top-half table (`TTBR1_EL1`), tagged addresses, or an ASID.
pub const fn tcr_el1(ips: u64) -> u64 {
    TCR_T0SZ
        | ((TCR_RGN_WRITE_BACK) << 8)
        | ((TCR_RGN_WRITE_BACK) << 10)
        | (TCR_SH_INNER << 12)
        | (TCR_TG0_4K << 14)
        | (ips << 32)
}

/// The `TCR_EL1.IPS` value for a `ID_AA64MMFR0_EL1.PARange` encoding.
///
/// The two registers number the same sizes the same way, so this is the
/// identity, and the version of this function that was not the identity is the
/// bug that stopped the boot on its first ECAM access.
///
/// | encoding | size | in |
/// |---|---|---|
/// | `0b000` | 32 bits | 4 GiB |
/// | `0b001` | 36 bits | 64 GiB |
/// | `0b010` | 40 bits | 1 TiB |
/// | `0b011` | 42 bits | 4 TiB |
/// | `0b100` | 44 bits | 16 TiB |
/// | `0b101` | 48 bits | 256 TiB |
/// | `0b110` | 52 bits | 4 PiB |
///
/// `PARange` says how many physical address bits the machine has and `IPS` says
/// how many the table may use; because the encodings agree, "use what the
/// machine has" is a copy.
///
/// The non-identity version swapped the two low pairs on the belief that the
/// registers disagreed, ///
/// `0b001` to `0b010` and back, which is a belief no table supports.  On a
/// machine reporting `PARange = 0b010` (40 bits, 1 TiB) it programmed
/// `IPS = 0b001` (36 bits, **64 GiB**), and the first access above 64 GiB was a
/// fault: a PCIe ECAM window at `0x40_1000_0000` is 275 GiB, so the walk
/// reported `DFSC = 0b000010`, *address size fault, level 2*, at an address
/// that is inside the machine's physical memory and outside the range the table
/// claimed.
///
/// An unrecognised `PARange`, `0b110` and above are sizes this tree does not
/// name, falls back to 32 bits, because a table naming physical bits the CPU
/// does not have is a fault and naming fewer is only a smaller address space.
pub const fn ips_for_parange(parange: u64) -> u64 {
    match parange {
        0b000..=0b110 => parange,
        _ => 0b000,
    }
}

#[cfg(target_os = "none")]
fn physical_address_range() -> u64 {
    let value: u64;
    // SAFETY: reading an ID register at EL1 has no side effect.
    unsafe {
        core::arch::asm!(
            "mrs {}, id_aa64mmfr0_el1",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        )
    };
    value & 0b1111
}

/// The address ranges on this machine that are *not* ordinary memory.
///
/// One range on each side of RAM, and the split is the device tree's answer.
///
/// The tree could be enumerated: a GIC at `0x0800_0000`, a PL011 at
/// `0x0900_0000`, thirty-two `virtio_mmio` windows, a PCIe ECAM at
/// `0x40_1000_0000`.  That list would be precise and it would be a list that
/// has to grow before the device it is missing can work, and the failure of a
/// missing entry is not a visible one.  It is a cached read of a register,
/// which returns whatever was true when the line was fetched.
///
/// So the question is inverted: the tree says where **memory** is, and
/// everything else is a device.  That is correct in the safe direction.  An
/// ordinary page marked `Device` is uncached and slow, which nothing breaks on;
/// a device register marked Normal is the defect this whole function exists to
/// prevent.
///
/// Two ranges, not forty.  [`build`](crate) asks this once and then asks
/// the kernel's permission lookup per page of a four-gigabyte identity map; a
/// list of forty device windows would make that a million times forty
/// comparisons at boot.
///
/// With translation off every access is device-like: no caching, no
/// speculation, the access arrives.  With it on and no rule, the same address
/// becomes Normal memory, cached, reordered, prefetchable, and the PL011's
/// status register read out of a stale cache line is a console that prints
/// nothing for a reason that looks like a dead UART.
///
/// A boot whose tree did not parse keeps the emulated platform's answer, which
/// is the state a machine with a broken blob is in: it has a console because
/// `PL011_FALLBACK` is what `serial` uses, and the window below RAM is what
/// makes that console's registers uncached.
pub fn device_windows() -> Windows {
    let mut windows = Windows::new();
    let Some(tree) = crate::boot::device_tree() else {
        // No tree: the constant, which is `virt`'s memory map.
        windows.push(0, VIRT_RAM_START);
        return windows;
    };

    let Some(root) = tree.root().ok() else {
        windows.push(0, VIRT_RAM_START);
        return windows;
    };

    // Every `memory` node, which a machine may have several of.  A memory node
    // is identified by `device_type`, not by `compatible`: the specification
    // says so, and QEMU's tree has no `compatible` on `memory@40000000` at all.
    let mut ram: [(u64, u64); MAX_MEMORY_NODES] = [(0, 0); MAX_MEMORY_NODES];
    let mut memory_nodes = 0;
    collect_memory(root, &mut ram, &mut memory_nodes);

    if memory_nodes == 0 {
        windows.push(0, VIRT_RAM_START);
        return windows;
    }

    // The lowest memory start and the highest memory end define the gap.  A
    // machine with two discontiguous RAM banks has a device range between them,
    // and treating that as memory is the unsafe direction, but so is *not*
    // treating it as a device, which is what a single gap cannot express.
    // Sorting the banks and emitting a window between each pair is the general
    // answer; this machine has one bank and the loop below is written so a
    // second would still be correct for the range below the first and above the
    // last.
    let mut lowest = ram[0].0;
    let mut highest = ram[0].1;
    for node in &ram[..memory_nodes] {
        lowest = lowest.min(node.0);
        highest = highest.max(node.1);
    }
    windows.push(0, lowest as usize);
    windows.push(highest as usize, usize::MAX);
    windows
}

const MAX_MEMORY_NODES: usize = 4;

/// Where `qemu-system-aarch64 -machine virt` puts its RAM.
const VIRT_RAM_START: usize = 0x4000_0000;

pub(crate) fn collect_memory(
    node: Node<'_>,
    out: &mut [(u64, u64); MAX_MEMORY_NODES],
    count: &mut usize,
) {
    if node.property("device_type").and_then(|p| p.as_str()) == Some("memory") {
        for region in node.reg() {
            if *count < MAX_MEMORY_NODES {
                out[*count] = (region.address, region.address.saturating_add(region.size));
                *count += 1;
            }
        }
    }
    for child in node.children() {
        if *count < MAX_MEMORY_NODES {
            collect_memory(child, out, count);
        }
    }
}

/// A small set of address ranges.
///
/// A fixed array rather than a slice because the ranges come from a device
/// tree, which is data: a `const fn` returning `&'static [(usize, usize)]`
/// could only ever describe a constant, and the point of this change is that it
/// no longer does.
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

    /// Add one range.  A full set drops it rather than growing.
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

/// The machine caches translations in the TLB, and a table changed underneath a
/// cached translation is a change nothing observes.  A newly created mapping is
/// the case that bites hardest: the TLB holds no entry for the address, but the
/// **absence** of one is cached too on an implementation that remembers a
/// fault, and a device window mapped for the first time reads as all ones.
///
/// That is exactly how this was found: the PCIe ECAM window was mapped, the
/// mapping was correct, and every read through it returned `0xFFFF_FFFF`, the
/// value a faulted load returns, while QEMU's monitor read the same physical
/// addresses perfectly.  `diff`ing the two answers is what named the TLB.
///
/// `DSB` before the invalidate ensures the table writes are visible, and `ISB`
/// after ensures the invalidation has taken effect before the next instruction
/// fetches or loads.
///
/// # Safety
///
/// Called after a page-table change on this CPU.  A second CPU translating
/// through the same table would need a broadcast invalidate, which this kernel
/// does not yet have, it runs on one core.
#[cfg(target_os = "none")]
pub fn flush_translation() {
    // SAFETY: both are architectural maintenance operations with no memory
    // operand of their own.
    unsafe {
        core::arch::asm!("dsb sy", options(nostack));
        core::arch::asm!("tlbi vmalle1", options(nostack));
        core::arch::asm!("dsb sy", options(nostack));
        core::arch::asm!("isb", options(nostack));
    }
}

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

#[cfg(target_os = "none")]
pub fn is_enabled() -> bool {
    let value: u64;
    // SAFETY: reading `SCTLR_EL1` at EL1 has no side effect.
    unsafe {
        core::arch::asm!(
            "mrs {}, sctlr_el1",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        )
    };
    value & 1 != 0
}

/// Returns `false` when the machine was already translating through this table
/// **with translation enabled**, which a second call would be.  Reporting
/// success for a table that is in `TTBR0_EL1` but not in use was the bug this
/// function was rewritten for: the register was written, `SCTLR_EL1.M` was
/// never set, and the boot line said "installed" about a table no access went
/// through.
///
/// ## The order, and why it is this one
///
/// 1. `MAIR_EL1` and `TCR_EL1` first.  A descriptor names an attribute index
///    and a granule; installing a table before saying what those mean leaves a
///    window, however small, where the walk reads a descriptor under the wrong
///    rules.
/// 2. `TLBI VMALLE1`.  The MMU has not been on, so there should be no entry to
///    flush; a stale one is a translation to an address nothing chose, and the
///    cost of the instruction is nothing next to the cost of being wrong.
/// 3. `TTBR0_EL1`, then a barrier pair.  `DSB` is what the architecture
///    requires before a register change is visible to the walk.
/// 4. `SCTLR_EL1.M`, read-modify-write.  The register's reset value carries
///    alignment and exception-order bits (`A`, `SA`, `SPAN`) whose meaning is
///    not this function's to change, so only bit 0 is touched.
/// 5. Read `M` back.  A register written and never re-read is a value the next
///    change can break silently, and the answer this function returns is
///    checked against what the machine actually reports.
///
/// ## Caches are left alone
///
/// `SCTLR_EL1.C` and `SCTLR_EL1.I` stay as the firmware left them.  Turning
/// them on is a speed decision whose failure mode is a stale instruction, and
/// mixing it into this function would make a fault here mean either "the table
/// is wrong" or "the cache was invalidated at the wrong point".
///
/// # Safety
///
/// `table` must be a page-aligned four-level root whose entries name physical
/// memory and whose mappings include the code performing this call, the stack
/// it is using, and every device the code will touch.  After this returns the
/// machine translates every address through it, so a missing mapping is a
/// fault at the first access that needs it.
#[cfg(target_os = "none")]
pub unsafe fn install(table: usize) -> bool {
    if is_enabled() && current_root_table() == table {
        return false;
    }
    let root = (table as u64) & OUTPUT_ADDRESS_MASK;
    let tcr = tcr_el1(ips_for_parange(physical_address_range()));
    // The two attributes this tree's descriptors name: byte 0 normal
    // write-back, byte 1 device non-gathering.
    let mair: u64 = 0x00FF;

    // SAFETY: the caller promises the table is complete, aligned and covers the
    // code performing this call.  The barriers are the ones the architecture
    // requires around a change to translation.
    unsafe {
        core::arch::asm!("msr mair_el1, {}", in(reg) mair, options(nostack));
        core::arch::asm!("msr tcr_el1, {}", in(reg) tcr, options(nostack));
        core::arch::asm!("dsb sy", options(nostack));
        core::arch::asm!("isb", options(nostack));

        core::arch::asm!("msr ttbr0_el1, {}", in(reg) root, options(nostack));
        core::arch::asm!("tlbi vmalle1", options(nostack));
        core::arch::asm!("dsb sy", options(nostack));
        core::arch::asm!("isb", options(nostack));

        // Read-modify-write: only `M` belongs to this function.
        let mut sctlr: u64;
        core::arch::asm!(
            "mrs {sctlr}, sctlr_el1",
            sctlr = out(reg) sctlr,
            options(nomem, nostack, preserves_flags)
        );
        sctlr |= 1;
        core::arch::asm!("msr sctlr_el1, {sctlr}", sctlr = in(reg) sctlr, options(nostack));
        core::arch::asm!("isb", options(nostack));
    }

    // The claim this function makes is the machine's, read back.
    is_enabled() && current_root_table() == table
}

#[cfg(test)]
mod tests;
