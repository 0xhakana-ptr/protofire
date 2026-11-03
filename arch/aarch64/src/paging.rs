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
///
/// ## A table descriptor carries an address and a type, and nothing else
///
/// This is not tidiness.  In a stage-1 translation-table descriptor the bits
/// `[11:2]` and `[58:48]` are **Ignored** — the architecture says the hardware
/// must not act on them — but the fields this crate sets for a *leaf* live in
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

/// Encode an entry at the level it will be stored in.
///
/// A leaf at `Level::Leaf` is a 4 KiB page descriptor; anywhere higher it is a
/// block.  The level is a parameter rather than a default because the two are
/// different descriptors, and a caller that did not say which it meant would
/// get a block where it wanted a page.
pub fn encode(entry: Entry, level: Level) -> u64 {
    encode_at(entry, level)
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
/// The kernel builds four levels — root, second, third, leaf — so the root is a
/// level 0 table and `T0SZ` must be 16.  A 39-bit `T0SZ` over a four-level
/// table has the machine treat the root as level 1, index it with address bits
/// `[38:30]`, and never read the root's entry 0 at all: the first instruction
/// fetch then faults with `DFSC = 0b000101`, *translation fault, level 1* —
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
/// `PARange` names how many physical address bits the machine has, and `IPS`
/// says how many the table may use.  The two encodings are not the same
/// numbering — `IPS` is `0b010` for 40 bits and `PARange` reports it as
/// `0b001` — which is exactly the kind of table a kernel should not restate
/// from memory.
///
/// This maps by *size*, so an unrecognised `PARange` falls back to the largest
/// value it can justify rather than to zero: a machine reporting more range
/// than this tree knows about is one where the safest read is "use 32 bits",
/// because a table naming physical bits the CPU does not have is a fault and a
/// table naming fewer is merely a smaller address space.
pub const fn ips_for_parange(parange: u64) -> u64 {
    match parange {
        0b000 => 0b000, // 32 bits, 4 GiB
        0b001 => 0b010, // 36 bits, 64 GiB
        0b010 => 0b001, // 40 bits, 1 TiB
        0b011 => 0b011, // 42 bits, 4 TiB
        0b100 => 0b100, // 44 bits, 16 TiB
        0b101 => 0b101, // 48 bits, 256 TiB
        _ => 0b000,
    }
}

/// Read `ID_AA64MMFR0_EL1.PARange`, bits 3..0.
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
/// One range: `0x0000_0000..0x4000_0000`, everything below RAM.
///
/// This exists because turning the MMU on changes what an unmapped-looking
/// address *means*.  With translation off, every access is device-like: no
/// caching, no speculation through it, the access arrives.  With translation on
/// and no rule of its own, the same address becomes Normal memory — cached,
/// reordered, and prefetchable — and the PL011's status register read out of a
/// stale cache line is a console that prints nothing for reasons that look like
/// a dead UART.
///
/// The range is `qemu-system-aarch64 -machine virt`'s memory map, which is the
/// machine this tree boots: RAM begins at `0x4000_0000`, so everything below it
/// is a peripheral —
///
/// | address | device |
/// |---|---|
/// | `0x0800_0000` | the GIC |
/// | `0x0900_0000` | the PL011 the console writes through |
/// | `0x0A00_0000` | the virtio-mmio transports |
/// | `0x3F00_0000` | the PCIe ECAM window |
///
/// Naming the whole span rather than those four is deliberate.  A rule per
/// device would be a list that has to grow before the device it is missing can
/// work, and the failure of a missing entry — a cached read of a register — is
/// intermittent.  Below RAM there is nothing a cache could usefully hold.
///
/// **This is the part that a device tree replaces.**  The constant is the
/// statement "this is the machine the boot gates run on"; a board that put RAM
/// or a UART elsewhere gets the wrong answer, and the way it learns that is by
/// reading this function.  Parsing the tree is what turns the constant into a
/// query, and it is the same change that gives this machine a PCI bus.
pub const fn device_windows() -> &'static [(usize, usize)] {
    &[(0x0000_0000, 0x4000_0000)]
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

/// Read `SCTLR_EL1.M`, which says whether translation is on.
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

/// Install `table` in `ttbr0_el1` and turn the MMU on.
///
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
///    window — however small — where the walk reads a descriptor under the
///    wrong rules.
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

    /// A table descriptor is an address and a type, and **nothing else**.
    ///
    /// The bits a leaf uses for `AF`, `AP`, the attribute index and `UXN`/`PXN`
    /// are the bits the architecture calls Ignored in a table descriptor.  This
    /// test is the one that would have caught the first encoder: it set them on
    /// every descriptor, and it survived only because the MMU was never turned
    /// on, so no descriptor was ever read.
    ///
    /// A byte-for-byte check rather than a mask of the interesting fields,
    /// because the point is that no field is interesting: the whole word is the
    /// address or period.
    #[test]
    fn a_table_descriptor_is_an_address_and_a_type() {
        let entry = Entry::table(0x4000_0000);
        let word = encode(entry, Level::Third);
        assert_eq!(
            word, 0x4000_0003,
            "the address and type 0b11, and nothing more"
        );

        assert_eq!(
            word & AF_ACCESSED,
            0,
            "a table descriptor has no access flag"
        );
        assert_eq!(word & AP_READ_ONLY, 0, "no AP[2]");
        assert_eq!(word & AP_USER, 0, "no AP[1]");
        assert_eq!(word & super::UXN, 0, "no UXN");
        assert_eq!(word & super::PXN, 0, "no PXN");
        assert_eq!(
            word & (0b111 << super::ATTR_INDEX_SHIFT),
            0,
            "no attribute index"
        );

        let decoded = decode(word, Level::Third);
        assert_eq!(decoded.address, 0x4000_0000);
        assert!(decoded.present);
        assert!(!decoded.is_leaf);
    }

    /// A leaf *does* carry those fields, which is what the test above is
    /// distinguishing it from.
    #[test]
    fn a_leaf_carries_the_fields_a_table_does_not() {
        let leaf = Entry::page(0x4000_0000, Permissions::KERNEL_READ_EXECUTE);
        let word = encode_at(leaf, Level::Leaf);
        assert_ne!(word & AF_ACCESSED, 0, "a leaf sets the access flag");
        assert_ne!(word & AP_READ_ONLY, 0, "read-only sets AP[2]");
        assert_eq!(
            word & 0b11,
            super::TYPE_TABLE_OR_PAGE,
            "the fourth level's leaf is a page"
        );
    }

    /// `TCR_EL1` says a 39-bit space, a 4 KiB granule, inner shareable, and the
    /// physical address size the machine reported.
    ///
    /// The fields are checked by shift because that is where they live, and a
    /// field written to the wrong shift is a value the walk reads as something
    /// else entirely.
    #[test]
    fn the_translation_control_says_what_the_table_is() {
        let tcr = super::tcr_el1(super::ips_for_parange(0b010));
        assert_eq!(tcr & 0x3F, super::TCR_T0SZ, "bits 0..6: T0SZ = 16");
        assert_eq!((tcr >> 8) & 0b11, super::TCR_RGN_WRITE_BACK, "IRGN0");
        assert_eq!((tcr >> 10) & 0b11, super::TCR_RGN_WRITE_BACK, "ORGN0");
        assert_eq!((tcr >> 12) & 0b11, super::TCR_SH_INNER, "SH0");
        assert_eq!((tcr >> 14) & 0b11, super::TCR_TG0_4K, "TG0 = 4 KiB");
        assert_eq!(
            (tcr >> 32) & 0b111,
            super::ips_for_parange(0b010),
            "IPS is the field it maps to"
        );
        assert_eq!(tcr & (1 << 7), 0, "EPD0 clear: walks through TTBR0 are on");
    }

    /// The physical address size mapping is by *size*, not by sharing the
    /// encoding.
    ///
    /// `PARange` and `IPS` number the same sizes differently — 40 bits is
    /// `0b010` as `PARange` and `0b001` as `IPS` — so a kernel that copied one
    /// number into the other would claim a 1 TiB physical address space on a
    /// machine with 4 GiB.  The test names both sides of that pair.
    #[test]
    fn the_physical_range_is_translated_rather_than_copied() {
        assert_eq!(super::ips_for_parange(0b000), 0b000, "32 bits");
        assert_eq!(super::ips_for_parange(0b001), 0b010, "36 bits");
        assert_eq!(super::ips_for_parange(0b010), 0b001, "40 bits");
        assert_eq!(super::ips_for_parange(0b011), 0b011, "42 bits");
        assert_eq!(super::ips_for_parange(0b100), 0b100, "44 bits");
        assert_eq!(super::ips_for_parange(0b101), 0b101, "48 bits");
        // A machine reporting more range than this table knows about gets the
        // most conservative answer, because a table naming physical bits the
        // CPU does not have is a fault and naming fewer is only a smaller
        // space.
        assert_eq!(super::ips_for_parange(0b1110), 0b000);
    }

    /// `T0SZ` names a virtual address space whose top level is the level the
    /// kernel's root table is.
    ///
    /// This is the test that was missing, and the bug it would have caught is
    /// the one that stopped the first boot with the MMU on: `T0SZ` was 25,
    /// which is 39 bits and three levels, so the machine treated the root as a
    /// **level 1** table and never read its entry 0.  The first fetch faulted
    /// with `DFSC = translation fault, level 1`.
    ///
    /// The assertion is arithmetic rather than a literal: `64 - T0SZ` has to
    /// equal the width the root's index reaches, which is
    /// `Level::Root::shift() + 9`.  A `T0SZ` that disagreed with the table's
    /// depth is exactly the state that produced the fault.
    #[test]
    fn the_address_size_matches_the_table_depth() {
        let va_bits = 64 - super::TCR_T0SZ;
        let root_reaches = (Level::Root.shift() + paging::index::INDEX_BITS) as u64;
        assert_eq!(
            va_bits, root_reaches,
            "T0SZ must describe a space whose top index is the root's"
        );
        // And the numbers that failure is: 48 bits is four levels, 39 is three.
        assert_eq!(va_bits, 48);
        assert_eq!(
            64 - 25,
            39,
            "the value that failed: three levels for a four-level table"
        );
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
            encode(writable, Level::Leaf) & AP_READ_ONLY,
            0,
            "writable clears the bit"
        );

        let read_only = Entry::page(0x1000, Permissions::KERNEL_READ_EXECUTE);
        assert_ne!(
            encode(read_only, Level::Leaf) & AP_READ_ONLY,
            0,
            "read-only sets it"
        );

        assert!(
            decode(encode(writable, Level::Leaf), Level::Leaf)
                .permissions
                .writable
        );
        assert!(
            !decode(encode(read_only, Level::Leaf), Level::Leaf)
                .permissions
                .writable
        );
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
        let word = encode(user, Level::Leaf);
        assert_ne!(word & AP_USER, 0);
        assert_eq!(word & super::UXN, 0, "an executable user page is not UXN");

        let kernel = Entry::page(0x1000, Permissions::KERNEL_READ_WRITE);
        assert_eq!(encode(kernel, Level::Leaf) & AP_USER, 0);
        assert_ne!(
            encode(kernel, Level::Leaf) & super::UXN,
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
            encode_at(entry, Level::Second) & 0b11,
            super::TYPE_BLOCK,
            "a second-level block is a 1 GiB mapping"
        );
        assert_eq!(
            encode_at(entry, Level::Leaf) & 0b11,
            super::TYPE_TABLE_OR_PAGE,
            "the fourth level's leaf is a 4 KiB page, not a block"
        );
        // A leaf at the root would be a block the root cannot hold, so the
        // encoder writes a page descriptor — the one encoding that is at least
        // not a block.  Nothing builds such a table: the kernel places leaves
        // at `Level::Leaf`.  This records what the function does rather than
        // what a caller should ask for.
        assert_eq!(
            encode_at(entry, Level::Root) & 0b11,
            super::TYPE_TABLE_OR_PAGE,
            "the root has no block form"
        );
    }

    /// A device mapping names the device `MAIR` index, and an ordinary one
    /// names the normal index.
    #[test]
    fn a_device_mapping_names_the_device_attribute() {
        let device = Entry::page(0xFE00_0000, Permissions::DEVICE);
        let word = encode(device, Level::Leaf);
        assert_ne!(word & super::ATTR_DEVICE, 0, "the device index is named");
        assert_eq!(
            decode(word, Level::Leaf).permissions.cache,
            paging::Cache::Device
        );

        let ordinary = Entry::page(0x1000, Permissions::KERNEL_READ_WRITE);
        assert_eq!(
            encode(ordinary, Level::Leaf) & (0b111 << super::ATTR_INDEX_SHIFT),
            0
        );
        assert_eq!(
            decode(encode(ordinary, Level::Leaf), Level::Leaf)
                .permissions
                .cache,
            paging::Cache::Normal
        );
    }

    /// An absent entry is zero.
    #[test]
    fn an_absent_entry_is_zero() {
        assert_eq!(encode(Entry::EMPTY, Level::Leaf), 0);
        assert_eq!(decode(0, Level::Leaf), Entry::default());
    }
}
