//! kernel/src/address_space/table.rs
//!
//! The kernel's identity map: the tables it lives in, and the walk that
//! re-maps a region.
//!
//! The boot assembly builds a table so that Rust can run at all: four gigabytes
//! of 2 MiB pages, identity-mapped, every one present, writable and *cached*.
//! Three things it gets wrong past the first instruction: everything is cached
//! (a device's registers read stale), everything is writable (a store into text
//! succeeds instead of faulting), and nothing can be added (a table the kernel
//! cannot name is one it cannot extend).
//!
//! The tables live in `.bss`, as a fixed array, before the frame allocator
//! exists.  A table built out of allocated frames would have to be built
//! before the thing that allocates them, which is circular; the fixed array is
//! the boot's own concession to that and is sized for what this table needs.

#[cfg(target_os = "none")]
use paging::PageTable;

#[cfg(target_os = "none")]
use paging::Entry;
#[cfg(target_os = "none")]
use paging::Level;
#[cfg(target_os = "none")]
use paging::PAGE_SIZE;
#[cfg(target_os = "none")]
use paging::Permissions;
#[cfg(target_os = "none")]
use paging::index;

#[cfg(target_os = "none")]
use super::image_rules;
#[cfg(target_os = "none")]
use super::permissions_for;

/// The page size every mapping here uses.
///
/// 4 KiB, where the boot used 2 MiB: a region's edge is where the linker put
/// it, and a 2 MiB granule would round every permission to the nearest two
/// megabytes, which for this kernel means text and rodata would share one.
#[cfg(target_os = "none")]
pub(crate) const GRANULE: usize = PAGE_SIZE;

/// The largest identity map this table builds: four gigabytes, which is what
/// the boot's table covers and therefore what the swap has to preserve.
#[cfg(target_os = "none")]
pub(crate) const IDENTITY_LIMIT: usize = 4 * 1024 * 1024 * 1024;

/// How many page tables the fixed array holds.
///
/// The identity map is four gigabytes: one root, one table of tables, four page
/// directories, and, for the 4 KiB granule, one page table per 2 MiB, which
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
/// window needs, QEMU's is 256 MiB and sits at `0x40_1000_0000`, three hundred
/// gigabytes past the identity map's end.
#[cfg(target_os = "none")]
const DEVICE_THIRD_LEVEL: usize = 2;

/// The tables this table is built from.
#[cfg(target_os = "none")]
#[repr(C, align(4096))]
pub(crate) struct Tables {
    pub(crate) root: PageTable,
    pub(crate) second: [PageTable; SECOND_LEVEL],
    pub(crate) third: [PageTable; THIRD_LEVEL],
    pub(crate) leaf: [PageTable; LEAF_TABLES],
    /// Third-level tables for regions above [`IDENTITY_LIMIT`].
    ///
    /// The first two windows come from here because they are always needed and
    /// a `static` is cheaper than a frame.  A third takes a frame from the
    /// pool, which is the point of the allocator existing: this array is a
    /// bound nobody could justify, and a machine that needed a third window
    /// would have found it.
    pub(crate) device: [PageTable; DEVICE_THIRD_LEVEL],
    /// Frames for tables beyond the spares.
    pub(crate) frames: memory::FrameAllocator,
    /// How many page tables came from a frame rather than a spare.
    pub(crate) frames_taken: usize,
}

/// Every field here is mutable state one walk updates: the tables' entries, the
/// frame allocator's bitmap, and the count of frames taken.  A program's space
/// is built and released by whichever CPU is serving that program's calls, so
/// two CPUs mapping or forking at once would be two writers to one bitmap, and
/// the failure, two programs handed the same frame, is silent until one writes
/// over the other.
///
/// The lock masks interrupts while held, so a tick cannot arrive on this CPU
/// and re-enter a walk.  It is taken by every entry point and never while
/// another lock of this module's is held, so there is no nesting to order.
#[cfg(target_os = "none")]
pub(crate) static TABLES: sync::Mutex<Tables> = sync::Mutex::new(Tables {
    root: PageTable::new(),
    second: [const { PageTable::new() }; SECOND_LEVEL],
    third: [const { PageTable::new() }; THIRD_LEVEL],
    leaf: [const { PageTable::new() }; LEAF_TABLES],
    device: [const { PageTable::new() }; DEVICE_THIRD_LEVEL],
    frames: memory::FrameAllocator::new(),
    frames_taken: 0,
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

/// Fill the tables with the identity map the boot has, with permissions this
/// kernel chose.
#[cfg(target_os = "none")]
pub(crate) fn build(tables: &mut Tables) {
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
    // by the span of a third-level entry gives 0 for all four, the first
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
/// The boot's table maps everything cached.  A device's registers read through
/// a cached mapping return whatever was true when the line was fetched, and a
/// store to one may sit in a write-combining buffer instead of reaching the
/// device, which works on an emulator whose MMIO happens to behave and is
/// wrong on hardware.
///
/// So a region a driver reaches through `RegisterFile` is re-mapped here with
/// [`Permissions::DEVICE`]: read, write, never cached.  The boot's identity
/// translation is unchanged, the same address still means the same physical
/// page, and what changes is what the CPU may do with it.
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
/// re-encodes leaf entries that already exist.  Above it there is no table, ///
/// the identity map stops at four gigabytes, so this **creates** one: a
/// third-level table of 2 MiB block entries, installed under the root.
///
/// The two are different operations on purpose.  Below the limit the region is
/// already mapped and the question is what it permits; above it the region is
/// not mapped at all and the question is whether a driver asked for it.  Device
/// registers are what asks: a PCIe ECAM window sits wherever the firmware put
/// it, which on the machine this tree boots is three hundred gigabytes past the
/// identity map's end.
///
/// A device region is not memory and has no use for a 4 KiB granule.  One block
/// per 2 MiB covers a whole ECAM window with a handful of entries, where a page
/// table per 2 MiB would be a thousand tables for the same span and the same
/// permissions throughout.
///
/// ## Every CPU, not this one
///
/// These are the **kernel's** tables.  Every program root copies this root's
/// entry 0, so the identity map and the device windows are one set of tables
/// that every CPU walks, and a change made here is invisible to the CPUs that
/// did not make it.  The boot has a live case: the second CPU is online before
/// the first one remaps a device window uncached, so without the broadcast the
/// second CPU keeps the cached translation and its stores to the device's
/// registers may never arrive.
///
/// The broadcast is sent **after the lock is dropped**, which is why the two
/// halves are separate statements here.  A receiver flushes and returns without
/// taking this lock, so sending while holding it would only cost the sender the
/// wait, but the lock's guard is also this function's borrow of the allocator
/// and the tables, and a second CPU's scheduling decision waits behind it.
#[cfg(target_os = "none")]
pub fn map_region(start: usize, length: usize, permissions: Permissions) -> bool {
    let changed = {
        let mut guard = TABLES.lock();
        let tables = &mut *guard;
        if start >= IDENTITY_LIMIT {
            map_device_blocks(tables, start, length, permissions)
        } else {
            re_encode(tables, start, length, permissions)
        }
    };
    if changed {
        crate::shootdown::invalidate_others();
    }
    changed
}

/// Re-encode the leaf entries of an already-mapped region, answering whether
/// any entry changed.
///
/// The sender's own TLB is flushed here, before the caller broadcasts: a change
/// this CPU cannot see is one it would report as made.
#[cfg(target_os = "none")]
fn re_encode(tables: &mut Tables, start: usize, length: usize, permissions: Permissions) -> bool {
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
/// reaches them; the alternative, a page table per 2 MiB, is a thousand
/// tables to describe one window.
#[cfg(target_os = "none")]
pub(crate) fn map_device_blocks(
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
            // window unmapped, which faults at the first access, a fault a
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
pub(crate) fn device_table_for(
    tables: &mut Tables,
    span_index: usize,
) -> Option<&'static PageTable> {
    // The root's entry names a second-level table; that table's entry for this
    // span names a third-level one.  This boot has one second-level table.
    let second = &tables.second[0];
    let existing = second.entry(span_index);
    if existing != 0 {
        let address = arch::paging::decode(existing, Level::Second).address;
        // SAFETY: every entry this module writes names a table in this array.
        return Some(unsafe { &*(address as *const PageTable) });
    }

    // The count of frames taken is what the boot reports, and it is the number
    // that says whether this branch has ever run: a machine whose spares were
    // always enough has an allocator here that nothing exercised, which is the
    // defect this tree keeps recording.
    let address = match tables.device.iter().position(|table| table.is_empty()) {
        // The tables live in a `static`, so an address into the array outlives
        // the borrow of the array itself, which is what `'static` says here.
        Some(free) => tables.device[free].address(),
        None => {
            // Past the spares, a page table comes from the frame allocator, //
            // the same frames the allocator exists to hand out, and the reason
            // it had to work before the heap.
            let frame = tables.frames.allocate(1)? as usize;
            if frame == 0 {
                return None;
            }
            tables.frames_taken += 1;
            frame
        }
    };
    let entry = encode(Entry::table(address), Level::Second);
    second.set_entry(span_index, entry);
    // SAFETY: `address` names either an entry of a `static` array or a frame
    // the allocator just handed out and zeroed, and both are a whole page.
    Some(unsafe { &*(address as *const PageTable) })
}

/// The leaf table that holds `address`, if the walk reaches one.
#[cfg(target_os = "none")]
pub(crate) fn leaf_for(root: &PageTable, address: usize) -> Option<&'static PageTable> {
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

/// What a faulting address is mapped as, in the root a CPU is running.
///
/// The question a fault handler asks before it decides what to say.  Two
/// answers are not a permission at all, and they are different failures:
///
/// - `None` when the walk finds no leaf, which is a program reaching an address
///   nothing ever mapped;
/// - `Some(None)` when the walk finds a **block** entry above the leaf level,
///   which on a machine with 2 MiB or 1 GiB blocks is a mapping this kernel's 4
///   KiB walk cannot describe to a fault handler.
///
/// `Some(Some(permissions))` is the ordinary answer, and it is what lets a
/// diagnostic say "the page is there and not writable" rather than "the program
/// faulted".
///
/// The root is an argument rather than read from the register, because the
/// fault handler runs on whatever CPU took the fault and its own register is
/// the one that matters, not the boot CPU's.
#[cfg(target_os = "none")]
pub(crate) fn permissions_of(root: usize, address: usize) -> Option<Option<Permissions>> {
    // SAFETY: the caller passes a root table this kernel installed.
    let root = unsafe { &*(root as *const PageTable) };
    let mut table: &'static PageTable = root;
    for level in [Level::Root, Level::Second, Level::Third] {
        let word = table.entry(index(level, address));
        if word == 0 {
            return None;
        }
        let entry = arch::paging::decode(word, level);
        if entry.is_leaf {
            // A block mapping: the walk stops above the 4 KiB level and this
            // function cannot describe the permissions of a page inside it.
            return Some(None);
        }
        // SAFETY: an entry this kernel wrote, naming a table it allocated.
        table = unsafe { &*(entry.address as *const PageTable) };
    }
    let word = table.entry(index(Level::Leaf, address));
    if word == 0 {
        return None;
    }
    Some(Some(arch::paging::decode(word, Level::Leaf).permissions))
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
/// `Level::Third`, which turned every page in this four-level table into a
/// block, and the first fetch after the MMU came on faulted in a region the
/// walk believed covered a gigabyte.
#[cfg(target_os = "none")]
pub(crate) fn encode(entry: Entry, level: Level) -> u64 {
    arch::paging::encode(entry, level)
}
