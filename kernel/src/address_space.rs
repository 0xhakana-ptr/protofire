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

/// The tables this table is built from.
#[cfg(target_os = "none")]
#[repr(C, align(4096))]
struct Tables {
    root: PageTable,
    second: [PageTable; SECOND_LEVEL],
    third: [PageTable; THIRD_LEVEL],
    leaf: [PageTable; LEAF_TABLES],
}

#[cfg(target_os = "none")]
static TABLES: cell::SyncUnsafeCell<Tables> = cell::SyncUnsafeCell::new(Tables {
    root: PageTable::new(),
    second: [const { PageTable::new() }; SECOND_LEVEL],
    third: [const { PageTable::new() }; THIRD_LEVEL],
    leaf: [const { PageTable::new() }; LEAF_TABLES],
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

/// The rules this image's linker script produces.
#[cfg(target_os = "none")]
fn image_rules() -> [Rule; 2] {
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
    ]
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
    let rules = image_rules();
    // The index of each level of the walk, hoisted: a loop that recomputed them
    // per page would be arithmetic on every one of a million pages.
    let root_index = index(Level::Root, 0);
    let second_index = index(Level::Second, 0);

    let root_entry = Entry::table(tables.second.as_ptr() as usize);
    tables.root.set_entry(root_index, encode(root_entry));

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
        tables.second[second_index].set_entry(third_slot, encode(second_entry));

        // Within a 1 GiB span, one page table per 2 MiB.
        for (leaf_slot, leaf) in tables.leaf[third_slot * 512..(third_slot + 1) * 512]
            .iter()
            .enumerate()
        {
            let leaf_span = span + leaf_slot * (512 * GRANULE);
            let third_entry = Entry::table(leaf.address());
            third.set_entry(leaf_slot, encode(third_entry));

            // And one entry per 4 KiB page.
            for page in 0..512 {
                let address = leaf_span + page * GRANULE;
                if address >= IDENTITY_LIMIT {
                    break;
                }
                let entry = Entry::page(address, permissions_at(&rules, address));
                leaf.set_entry(page, encode(entry));
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
/// A region that crosses a 2 MiB boundary is walked one 4 KiB page at a time,
/// because the table has a page table per 2 MiB and the mapping has to be found
/// through all four levels.
#[cfg(target_os = "none")]
fn map_region(start: usize, length: usize, permissions: Permissions) -> bool {
    let tables = TABLES.get();
    // SAFETY: the static is this module's; `install` is the only writer and
    // this runs after it.
    let tables = unsafe { &mut *tables };
    let mut changed = false;
    let end = start.saturating_add(length);
    let mut address = start & !(GRANULE - 1);

    while address < end {
        if address >= IDENTITY_LIMIT {
            // Past the identity map there is no table to walk: the root has one
            // entry and it covers four gigabytes.
            break;
        }
        if let Some(leaf) = leaf_for(&tables.root, address) {
            let word = encode(Entry::page(address, permissions));
            if leaf.entry(index(Level::Leaf, address)) != word {
                changed = true;
            }
            leaf.set_entry(index(Level::Leaf, address), word);
        }
        address = address.saturating_add(GRANULE);
    }
    changed
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

/// The machine's entry encoding.
///
/// Reached through `arch` rather than named here: what an entry's bits mean is
/// the machine's, and this module is the one that decides *which* mapping, not
/// how to write it down.
#[cfg(target_os = "none")]
fn encode(entry: Entry) -> u64 {
    arch::paging::encode(entry)
}

#[cfg(test)]
mod tests {
    use super::Rule;
    use super::permissions_at;
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
}
