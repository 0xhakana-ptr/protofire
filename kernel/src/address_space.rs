//! kernel/src/address_space.rs
//!
//! The kernel's own page table: what it maps, with what permissions, and the
//! one call that installs it.
//!
//! ## Why this replaces the boot's table rather than extending it
//!
//! The boot assembly builds a table so that Rust can run at all: four gigabytes
//! of 2 MiB pages, identity-mapped, every one present, writable and *cached*.
//! It is the smallest thing that lets the first instruction after
//! `long_mode_start` work, and it says nothing about what a kernel wants.
//!
//! Three things it gets wrong for anything past that first instruction:
//!
//! - **Everything is cached.**  A device's registers reached through a cached
//!   mapping return stale values, and a store to one may never arrive.  Every
//!   PCI BAR this boot touches today is mapped that way, which works on an
//!   emulator whose MMIO happens to behave.
//! - **Everything is writable.**  The kernel's text is a writable page, so a
//!   stray store into it succeeds instead of faulting.
//! - **Nothing can be added.**  A table the kernel cannot name is a table it
//!   cannot extend, so mapping a frame or a BAR is impossible.
//!
//! So this builds a second table and installs it.  For every address the boot
//! already touches the translation is the same — which is what makes the swap
//! invisible — and this one knows what each region is for.
//!
//! ## What it maps
//!
//! The boot's four gigabytes stay identity-mapped, because something may still
//! be reading them: firmware tables, the multiboot structure, whatever the
//! loader left below the image.  What this table adds is *what a region is
//! for*, at a 4 KiB granularity where the boot used 2 MiB:
//!
//! | Region | Permissions |
//! |---|---|
//! | text | read, execute |
//! | rodata | read |
//! | data, bss, the frame pool | read, write |
//! | a device BAR | read, write, **uncached** |
//!
//! ## Where the tables live
//!
//! In `.bss`, as a fixed array, before the frame allocator exists.  A table
//! built out of allocated frames would have to be built before the thing that
//! allocates them, which is circular; the fixed array is the boot's own
//! concession to that and is sized for what this table needs.

#[cfg(any(target_os = "none", test))]
use paging::Permissions;

#[cfg(target_os = "none")]
use paging::PageTable;

#[cfg(target_os = "none")]
use paging::Entry;
#[cfg(target_os = "none")]
use paging::Level;
#[cfg(target_os = "none")]
use paging::PAGE_SIZE;
#[cfg(target_os = "none")]
use paging::index;

/// The page size every mapping here uses.
///
/// 4 KiB, where the boot used 2 MiB: a region's edge is where the linker put
/// it, and a 2 MiB granule would round every permission to the nearest two
/// megabytes — which for this kernel means text and rodata would share one.
#[cfg(target_os = "none")]
const GRANULE: usize = PAGE_SIZE;

/// The largest identity map this table builds: four gigabytes, which is what
/// the boot's table covers and therefore what the swap has to preserve.
#[cfg(target_os = "none")]
const IDENTITY_LIMIT: usize = 4 * 1024 * 1024 * 1024;

/// How many page tables the fixed array holds.
///
/// The identity map is four gigabytes: one root, one table of tables, four page
/// directories, and — for the 4 KiB granule — one page table per 2 MiB, which
/// is 2048 of them.  The array is exactly that, and the constants below assert
/// the relation rather than restating it.
#[cfg(target_os = "none")]
const ROOT_TABLES: usize = 1;
#[cfg(target_os = "none")]
const SECOND_LEVEL: usize = 1;
#[cfg(target_os = "none")]
const THIRD_LEVEL: usize = 4;
#[cfg(target_os = "none")]
const LEAF_TABLES: usize = IDENTITY_LIMIT / (512 * GRANULE);

/// Spare tables for device windows above the identity map.
///
/// A device's registers are not memory and do not want a 4 KiB granule: one
/// 2 MiB block per the level that has one covers a device region with a single
/// entry, and a device region is a whole number of them in practice.  Each
/// spare table is one 1 GiB span of block entries, which is what a PCIe ECAM
/// window needs — QEMU's is 256 MiB and sits at `0x40_1000_0000`, three hundred
/// gigabytes past the identity map's end.
#[cfg(target_os = "none")]
const DEVICE_THIRD_LEVEL: usize = 2;

/// The tables this table is built from.
#[cfg(target_os = "none")]
#[repr(C, align(4096))]
struct Tables {
    root: PageTable,
    second: [PageTable; SECOND_LEVEL],
    third: [PageTable; THIRD_LEVEL],
    leaf: [PageTable; LEAF_TABLES],
    /// Third-level tables for regions above [`IDENTITY_LIMIT`].
    device: [PageTable; DEVICE_THIRD_LEVEL],
}

#[cfg(target_os = "none")]
static TABLES: cell::SyncUnsafeCell<Tables> = cell::SyncUnsafeCell::new(Tables {
    root: PageTable::new(),
    second: [const { PageTable::new() }; SECOND_LEVEL],
    third: [const { PageTable::new() }; THIRD_LEVEL],
    leaf: [const { PageTable::new() }; LEAF_TABLES],
    device: [const { PageTable::new() }; DEVICE_THIRD_LEVEL],
});

// The relations between the constants above, checked rather than restated: a
// second-level table has 512 entries, and the identity map needs as many page
// directories as it has 1 GiB spans, and as many page tables as it has 2 MiB
// spans.
#[cfg(target_os = "none")]
const _: () = assert!(SECOND_LEVEL == ROOT_TABLES);
#[cfg(target_os = "none")]
const _: () = assert!(THIRD_LEVEL * 512 * 512 * GRANULE == IDENTITY_LIMIT);
#[cfg(target_os = "none")]
const _: () = assert!(LEAF_TABLES * 512 * GRANULE == IDENTITY_LIMIT);

/// The address of a linker symbol, by name.
///
/// The five names are the linker script's own, and a name that is not one of
/// them is a call this module does not make: the match has no fallthrough, so a
/// typo is a compile error rather than a wrong address.
#[cfg(target_os = "none")]
fn symbol(name: Symbol) -> usize {
    // `addr_of!` takes an address without creating a reference, which is what
    // a linker address marker needs: there is no value there, only a position.
    // In edition 2024 that is not an `unsafe` operation, and the symbols are
    // declared `extern` so the linker resolves each to its own section's edge.
    match name {
        Symbol::TextStart => core::ptr::addr_of!(__text_start) as usize,
        Symbol::TextEnd => core::ptr::addr_of!(__text_end) as usize,
        Symbol::RodataStart => core::ptr::addr_of!(__rodata_start) as usize,
        Symbol::RodataEnd => core::ptr::addr_of!(__rodata_end) as usize,
    }
}

/// The linker symbols this module reads.
///
/// Only the four that a permission rule names: data, bss and the frame pool are
/// all writable, which is what an address in no rule gets, so naming them here
/// would be a rule that changed nothing.  The `extern` block below declares all
/// ten because the linker resolves them by name and a symbol a rule does not
/// name still marks where its section ends — but a variant is a *reader* of
/// one, and this enum has only the readers there are.
#[cfg(target_os = "none")]
#[derive(Clone, Copy)]
enum Symbol {
    TextStart,
    TextEnd,
    RodataStart,
    RodataEnd,
}

#[cfg(target_os = "none")]
unsafe extern "C" {
    static __text_start: u8;
    static __text_end: u8;
    static __rodata_start: u8;
    static __rodata_end: u8;
}

/// One permission change: from `start` up to `end`, an address has
/// `permissions`.
#[cfg(any(target_os = "none", test))]
#[derive(Clone, Copy)]
struct Rule {
    start: usize,
    end: usize,
    permissions: Permissions,
}

/// The permission an address has, given the rules.
///
/// A free function over a slice rather than one that reads the linker's symbols
/// itself: the rules are the kernel's answer and the ranges are the image's,
/// and separating them is what lets a host test give the function ranges it can
/// see.  A host has no linker script and therefore no `__text_start`, so a
/// function that read one could not be tested at all.
#[cfg(any(target_os = "none", test))]
fn permissions_at(rules: &[Rule], address: usize) -> Permissions {
    for rule in rules {
        if (rule.start..rule.end).contains(&address) {
            return rule.permissions;
        }
    }
    // The boot's answer, for an address this kernel has no opinion about.
    Permissions::KERNEL_READ_WRITE
}

/// The rules this image's linker script produces, plus the machine's device
/// windows.
///
/// The two halves come from different places on purpose.  Where this image's
/// sections begin and end is the linker script's answer, and the rules for them
/// are this kernel's policy.  Which addresses are a device's registers is the
/// **machine's** answer — `arch::paging::device_windows` — because an x86_64
/// finds its devices on a bus and a device-tree machine knows their addresses
/// from the platform, and a kernel that spelled either would be naming a
/// machine.
#[cfg(target_os = "none")]
fn image_rules() -> ([Rule; 2], arch::paging::Windows) {
    (
        [
            Rule {
                start: symbol(Symbol::TextStart),
                end: symbol(Symbol::TextEnd),
                permissions: Permissions::KERNEL_READ_EXECUTE,
            },
            Rule {
                start: symbol(Symbol::RodataStart),
                end: symbol(Symbol::RodataEnd),
                permissions: Permissions {
                    writable: false,
                    executable: false,
                    user: false,
                    cache: paging::Cache::Normal,
                },
            },
        ],
        arch::paging::device_windows(),
    )
}

/// The permission an address has, given the image's rules and the machine's
/// device windows.
///
/// A device window wins over an image rule, and the order is not arbitrary: an
/// image overlapping a device's registers would be an image the firmware had
/// loaded on top of a device, which is not a state a permission rule could
/// repair.  A rule that won there would map a register as ordinary memory, and
/// the failure would appear inside whatever device it was.
///
/// A free function over two slices for the reason [`permissions_at`] is: the
/// machine's windows and the image's rules are both values a host test can
/// supply, and a version that read `arch` could not be tested where `arch` is
/// not the machine being built.
#[cfg(any(target_os = "none", test))]
fn permissions_for(rules: &[Rule], windows: &[(usize, usize)], address: usize) -> Permissions {
    for &(start, end) in windows {
        if (start..end).contains(&address) {
            return Permissions::DEVICE;
        }
    }
    permissions_at(rules, address)
}

/// Build the kernel's table and install it.
///
/// Returns `false` when the machine is already translating through it, which a
/// second call would be.  A boot calls this once.
///
/// # Safety
///
/// Called once, from the kernel's own entry, after the console is up: a failure
/// after this returns is one the machine may fault on, and a console that is
/// already writing is what makes that visible.
#[cfg(target_os = "none")]
pub unsafe fn install() -> bool {
    let tables = TABLES.get();
    // SAFETY: the static is this module's, and `install` is called once before
    // anything else can touch it.
    let tables = unsafe { &mut *tables };

    build(tables);

    let root = tables.root.address();
    // SAFETY: `build` filled every entry the identity map covers, and the root
    // is a page-aligned static.  The caller's contract is that this is the only
    // call.
    unsafe { arch::paging::install(root) }
}

/// Fill the tables with the identity map the boot has, with permissions this
/// kernel chose.
#[cfg(target_os = "none")]
fn build(tables: &mut Tables) {
    let (rules, windows) = image_rules();
    let windows = windows.as_slice();
    // The index of each level of the walk, hoisted: a loop that recomputed them
    // per page would be arithmetic on every one of a million pages.
    let root_index = index(Level::Root, 0);
    let second_index = index(Level::Second, 0);

    let root_entry = Entry::table(tables.second.as_ptr() as usize);
    tables
        .root
        .set_entry(root_index, encode(root_entry, Level::Root));

    // One 1 GiB span per third-level table; the identity map is four of them.
    //
    // The second-level index *is* the slot: a 1 GiB span is one entry of a
    // table whose entries each cover 1 GiB.  Deriving it by dividing the span
    // by the span of a third-level entry gives 0 for all four — the first
    // version did that, so the four spans overwrote each other and only the
    // last was mapped.
    for (third_slot, third) in tables.third.iter().enumerate() {
        let span = third_slot * (512 * 512 * GRANULE);
        let second_entry = Entry::table(third.address());
        tables.second[second_index].set_entry(third_slot, encode(second_entry, Level::Second));

        // Within a 1 GiB span, one page table per 2 MiB.
        for (leaf_slot, leaf) in tables.leaf[third_slot * 512..(third_slot + 1) * 512]
            .iter()
            .enumerate()
        {
            let leaf_span = span + leaf_slot * (512 * GRANULE);
            let third_entry = Entry::table(leaf.address());
            third.set_entry(leaf_slot, encode(third_entry, Level::Third));

            // And one entry per 4 KiB page.
            for page in 0..512 {
                let address = leaf_span + page * GRANULE;
                if address >= IDENTITY_LIMIT {
                    break;
                }
                let entry = Entry::page(address, permissions_for(&rules, windows, address));
                leaf.set_entry(page, encode(entry, Level::Leaf));
            }
        }
    }
}

/// Map a device region uncached, at the 4 KiB granule.
///
/// ## Why a BAR needs this and the identity map does not
///
/// The boot's table maps everything cached.  A device's registers read through
/// a cached mapping return whatever was true when the line was fetched, and a
/// store to one may sit in a write-combining buffer instead of reaching the
/// device — which works on an emulator whose MMIO happens to behave and is
/// wrong on hardware.
///
/// So a region a driver reaches through `RegisterFile` is re-mapped here with
/// [`Permissions::DEVICE`]: read, write, never cached.  The boot's identity
/// translation is unchanged — the same address still means the same physical
/// page — and what changes is what the CPU may do with it.
///
/// # Safety
///
/// `start` and `length` must name a device's memory and nothing else.  Marking
/// ordinary memory uncached is slow rather than wrong; marking a device's
/// registers cached is wrong rather than slow.
#[cfg(target_os = "none")]
pub unsafe fn map_device(start: usize, length: usize) -> bool {
    map_region(start, length, Permissions::DEVICE)
}

/// Re-map a region with `permissions`, at the 4 KiB granule.
///
/// ## Two kinds of region
///
/// Below [`IDENTITY_LIMIT`] the walk was built by [`build`], and this only
/// re-encodes leaf entries that already exist.  Above it there is no table —
/// the identity map stops at four gigabytes — so this **creates** one: a
/// third-level table of 2 MiB block entries, installed under the root.
///
/// The two are different operations on purpose.  Below the limit the region is
/// already mapped and the question is what it permits; above it the region is
/// not mapped at all and the question is whether a driver asked for it.  Device
/// registers are what asks: a PCIe ECAM window sits wherever the firmware put
/// it, which on the machine this tree boots is three hundred gigabytes past the
/// identity map's end.
///
/// ## Why a 2 MiB block above the limit
///
/// A device region is not memory and has no use for a 4 KiB granule.  One block
/// per 2 MiB covers a whole ECAM window with a handful of entries, where a page
/// table per 2 MiB would be a thousand tables for the same span and the same
/// permissions throughout.
#[cfg(target_os = "none")]
fn map_region(start: usize, length: usize, permissions: Permissions) -> bool {
    let tables = TABLES.get();
    // SAFETY: the static is this module's; `install` is the only writer and
    // this runs after it.
    let tables = unsafe { &mut *tables };

    if start >= IDENTITY_LIMIT {
        return map_device_blocks(tables, start, length, permissions);
    }

    let mut changed = false;
    let end = start.saturating_add(length).min(IDENTITY_LIMIT);
    let mut address = start & !(GRANULE - 1);
    while address < end {
        if let Some(leaf) = leaf_for(&tables.root, address) {
            let word = encode(Entry::page(address, permissions), Level::Leaf);
            if leaf.entry(index(Level::Leaf, address)) != word {
                changed = true;
            }
            leaf.set_entry(index(Level::Leaf, address), word);
        }
        address = address.saturating_add(GRANULE);
    }
    if changed {
        // A table write the machine does not observe is a write that did not
        // happen: the TLB may hold the absence of a translation as firmly as it
        // holds one.
        arch::flush_translation();
    }
    changed
}

/// Map a region above the identity map with 2 MiB block entries.
///
/// The root's entry for a 512 GiB span names a third-level table, and that
/// table's entries are blocks.  One spare table per such span, from
/// [`Tables::device`]; a machine with more than two windows past four gigabytes
/// has a map this boot does not describe, and the second window is reported by
/// [`map_device`]'s return value rather than silently dropped.
///
/// The 2 MiB rounding is the honest part: a device window's edges are the
/// firmware's, and a region whose end is not 2 MiB aligned has its last block
/// cover bytes past the window.  Those bytes belong to no device and nothing
/// reaches them; the alternative — a page table per 2 MiB — is a thousand
/// tables to describe one window.
#[cfg(target_os = "none")]
fn map_device_blocks(
    tables: &mut Tables,
    start: usize,
    length: usize,
    permissions: Permissions,
) -> bool {
    const BLOCK: usize = 2 * 1024 * 1024;
    let end = start.saturating_add(length);
    let mut changed = false;
    let mut address = start & !(BLOCK - 1);

    while address < end {
        // Which 512 GiB span of the root this address is in.
        let span_index = index(Level::Second, address);
        let Some(slot) = device_table_for(tables, span_index) else {
            // No table left for this span.  Stopping leaves the rest of the
            // window unmapped, which faults at the first access — a fault a
            // reader can trace to this bound rather than to a driver.
            break;
        };
        let slot_in_third = index(Level::Third, address);
        let word = encode(Entry::page(address, permissions), Level::Third);
        if slot.entry(slot_in_third) != word {
            changed = true;
        }
        slot.set_entry(slot_in_third, word);
        address = address.saturating_add(BLOCK);
    }
    if changed {
        arch::flush_translation();
    }
    changed
}

/// The third-level table for root span `span_index`, created on first use.
#[cfg(target_os = "none")]
fn device_table_for(tables: &mut Tables, span_index: usize) -> Option<&'static PageTable> {
    // The root's entry names a second-level table; that table's entry for this
    // span names a third-level one.  This boot has one second-level table.
    let second = &tables.second[0];
    let existing = second.entry(span_index);
    if existing != 0 {
        let address = arch::paging::decode(existing, Level::Second).address;
        // SAFETY: every entry this module writes names a table in this array.
        return Some(unsafe { &*(address as *const PageTable) });
    }

    // No table yet: take the next unused spare.
    let free = tables.device.iter().position(|table| table.is_empty())?;
    // The tables live in a `static`, so an address into the array outlives the
    // borrow of the array itself — which is what `'static` says here.
    let address = tables.device[free].address();
    let entry = encode(Entry::table(address), Level::Second);
    second.set_entry(span_index, entry);
    // SAFETY: `address` names the entry of a `static` array.
    Some(unsafe { &*(address as *const PageTable) })
}

/// The leaf table that holds `address`, if the walk reaches one.
#[cfg(target_os = "none")]
fn leaf_for(root: &PageTable, address: usize) -> Option<&'static PageTable> {
    let mut table: &'static PageTable = unsafe { &*(root as *const PageTable) };
    for level in [Level::Root, Level::Second, Level::Third] {
        let word = table.entry(index(level, address));
        if word == 0 {
            return None;
        }
        // SAFETY: `build` placed every table in the static array, and each
        // entry's address names one of them.
        table = unsafe { &*(arch::paging::decode(word, level).address as *const PageTable) };
    }
    Some(table)
}

/// The machine's entry encoding, for an entry going into a table at `level`.
///
/// Reached through `arch` rather than named here: what an entry's bits mean is
/// the machine's, and this module is the one that decides *which* mapping, not
/// how to write it down.
///
/// The level is passed through rather than defaulted.  aarch64 writes a 4 KiB
/// page descriptor and a 1 GiB block descriptor with different bits, and the
/// version of this function that took only the entry had `arch` assume
/// `Level::Third` — which turned every page in this four-level table into a
/// block, and the first fetch after the MMU came on faulted in a region the
/// walk believed covered a gigabyte.
#[cfg(target_os = "none")]
fn encode(entry: Entry, level: Level) -> u64 {
    arch::paging::encode(entry, level)
}

#[cfg(test)]
mod tests {
    use super::Rule;
    use super::permissions_at;
    use super::permissions_for;
    use paging::Cache;
    use paging::Permissions;

    /// The rules a host test can see, standing in for an image's linker
    /// script.
    ///
    /// The numbers are made up and the *shape* is what the image has: text
    /// first, then read-only data, then writable data — a `BTreeMap` of ranges
    /// would be a different test.
    const TEXT: u64 = 0x1000;
    const TEXT_END: u64 = 0x8000;
    const RODATA: u64 = 0x8000;
    const RODATA_END: u64 = 0xC000;

    const RULES: [Rule; 2] = [
        Rule {
            start: TEXT as usize,
            end: TEXT_END as usize,
            permissions: Permissions::KERNEL_READ_EXECUTE,
        },
        Rule {
            start: RODATA as usize,
            end: RODATA_END as usize,
            permissions: Permissions {
                writable: false,
                executable: false,
                user: false,
                cache: Cache::Normal,
            },
        },
    ];

    /// Text is executable and not writable; rodata is neither.
    ///
    /// The whole reason this table exists: the boot maps every page writable
    /// and executable, so a store into a `const` succeeds instead of faulting
    /// and an instruction fetched from a data page runs.
    #[test]
    fn the_permissions_are_what_the_sections_are_for() {
        let text = permissions_at(&RULES, TEXT as usize);
        assert!(text.executable);
        assert!(!text.writable);

        let rodata = permissions_at(&RULES, RODATA as usize);
        assert!(!rodata.executable);
        assert!(!rodata.writable);
    }

    /// A region owns its start and not its end: the two ranges meet and do not
    /// overlap.
    ///
    /// `end` is exclusive because that is how a linker places the next section
    /// — `__text_end` and `__rodata_start` are the same address — and a rule
    /// that claimed its end would give that address two permissions.
    #[test]
    fn a_region_owns_its_start_and_not_its_end() {
        assert!(permissions_at(&RULES, TEXT as usize).executable);
        assert!(
            !permissions_at(&RULES, TEXT_END as usize).executable,
            "the byte at the end of text belongs to rodata, which is not code"
        );
        assert!(!permissions_at(&RULES, TEXT_END as usize).writable);
    }

    /// An address in no rule keeps the boot's answer.
    ///
    /// A region this kernel has no opinion about is one it must not newly
    /// forbid: firmware tables and the loader's structures are still being
    /// read, and a page that started faulting would stop the boot.
    #[test]
    fn an_unclaimed_address_keeps_the_boots_permissions() {
        let unclaimed = permissions_at(&RULES, 0);
        assert_eq!(unclaimed, Permissions::KERNEL_READ_WRITE);
        assert!(unclaimed.writable);
    }

    /// An empty rule set leaves every address as the boot left it.
    #[test]
    fn no_rules_means_no_changes() {
        assert_eq!(permissions_at(&[], 0x1000), Permissions::KERNEL_READ_WRITE);
    }

    /// A device window makes its range uncached, and everything else keeps the
    /// rule it would have had.
    ///
    /// This is the rule the aarch64 boot needed the moment translation went
    /// on: with no entry of its own, the PL011 at `0x0900_0000` is Normal
    /// memory, and a cached read of a status register is a console that stops
    /// printing for a reason that looks like a dead UART.
    ///
    /// The two addresses either side of the boundary are the test's point: a
    /// window owns its start and not its end, so `0x0800_0000` is a device and
    /// `0x4000_0000` — where RAM begins — is not.
    #[test]
    fn a_device_window_is_uncached_and_ends_where_it_ends() {
        let windows: &[(usize, usize)] = &[(0x0000_0000, 0x4000_0000)];

        let uart = permissions_for(&RULES, windows, 0x0900_0000);
        assert_eq!(uart, Permissions::DEVICE);
        assert_eq!(uart.cache, Cache::Device);
        assert!(uart.writable && !uart.executable);

        assert_eq!(
            permissions_for(&RULES, windows, 0x3FFF_F000),
            Permissions::DEVICE,
            "the last page below RAM is still a device"
        );
        assert_eq!(
            permissions_for(&RULES, windows, 0x4000_0000),
            Permissions::KERNEL_READ_WRITE,
            "RAM itself is ordinary memory again"
        );
    }

    /// A device window wins over an image rule.
    ///
    /// The two overlap only if the firmware loaded the image on top of a
    /// device, which is not a state a permission rule can repair — but the
    /// ordering has to be decided rather than left to whichever loop runs
    /// first, and the decision is that a register is a register.
    #[test]
    fn a_device_window_beats_an_image_rule() {
        let windows: &[(usize, usize)] = &[(TEXT as usize, TEXT_END as usize)];
        let in_text = permissions_for(&RULES, windows, TEXT as usize);
        assert!(
            !in_text.executable,
            "the window's answer, not the text rule"
        );
        assert_eq!(in_text.cache, Cache::Device);
    }

    /// A machine with no device windows behaves exactly as it did before the
    /// question was asked.
    ///
    /// x86_64 answers with an empty slice — it has no fixed peripheral
    /// window — so this is that machine's case, and the assertion is that
    /// introducing the question changed nothing for it.
    #[test]
    fn no_windows_leaves_the_rules_alone() {
        assert_eq!(
            permissions_for(&RULES, &[], TEXT as usize),
            permissions_at(&RULES, TEXT as usize)
        );
        assert_eq!(
            permissions_for(&RULES, &[], 0x0900_0000),
            Permissions::KERNEL_READ_WRITE
        );
    }
}
