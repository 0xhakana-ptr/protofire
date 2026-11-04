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
    ///
    /// The first two windows come from here because they are always needed and
    /// a `static` is cheaper than a frame.  A third takes a frame from the
    /// pool — which is the point of the allocator existing: this array is a
    /// bound nobody could justify, and a machine that needed a third window
    /// would have found it.
    device: [PageTable; DEVICE_THIRD_LEVEL],
    /// Frames for tables beyond the spares.
    frames: memory::FrameAllocator,
    /// How many page tables came from a frame rather than a spare.
    frames_taken: usize,
}

#[cfg(target_os = "none")]
static TABLES: cell::SyncUnsafeCell<Tables> = cell::SyncUnsafeCell::new(Tables {
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

/// How much of the user window one program owns.
///
/// A gigabyte, which is what `process::program_base` spaces programs by.  The
/// number is here rather than there because this is the module that knows what
/// a user address is, and a validator with its own copy would be a second
/// opinion about the same fact.
pub const USER_WINDOW: usize = 0x4000_0000;

/// How many programs the window has room for.
///
/// The boot runs two and the space is four; the number is a bound on the
/// validator, not a policy about how many programs a boot may start.  A
/// program numbered past it would map above this end, and `AddressSpace::map`
/// would have to say so.
pub const USER_WINDOWS: usize = 4;

/// The first address above the user window.
pub const USER_LIMIT: usize = USER_BASE + USER_WINDOW * USER_WINDOWS;

/// Whether `address` is one a program of this kernel could have mapped.
///
/// ## Why this is the only check a syscall needs
///
/// A pointer from ring 3 is a number, and a number is not an address: the
/// kernel must not dereference one because the program said so.  Three things
/// have to hold together, and this checks all three:
///
/// 1. The range is the user window — `USER_BASE` up to a program's end — so a
///    program cannot hand the kernel a kernel address and have it written to.
/// 2. The range does not wrap.  `start + length` overflows for an address near
///    the top, and a wrapped end would pass a naive `end > start` test.
/// 3. The whole range is inside the window, not merely its start.  A read of
///    one byte at the last valid address is fine; a read of four that crosses
///    the boundary is not.
///
/// What it does **not** check is that the pages are mapped.  A valid-looking
/// address into an unmapped page faults when the kernel touches it, and that
/// fault is the program's — the kernel would have to copy the page tables into
/// a walk to know, and a fault is the machine's own answer.
pub fn is_user_range(address: usize, length: usize) -> bool {
    let Some(end) = address.checked_add(length) else {
        return false;
    };
    address >= USER_BASE && end <= USER_LIMIT
}

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

    // Frames for the tables past the spare ones.
    //
    // The pool is a linker-reserved span and the machine's answer clamps it: a
    // machine whose RAM ends inside the span must manage only the frames that
    // are really there, and one that managed the whole span would hand out
    // pages past the end of memory.  `managed_pool_bytes` is that answer, and
    // `None` means the machine cannot say — then the span is all there is.
    let machine = arch::managed_pool_bytes().unwrap_or(memory::frame::physical_pool_size());
    tables.frames.init(machine);

    build(tables);

    let root = tables.root.address();
    // SAFETY: `build` filled every entry the identity map covers, and the root
    // is a page-aligned static.  The caller's contract is that this is the only
    // call.
    unsafe { arch::paging::install(root) }
}

/// How many frames the pool manages, for a boot line that reports it.
///
/// A machine whose RAM is smaller than the linker's span manages fewer, and
/// that difference is the one thing a reader of the boot log needs to see.
#[cfg(target_os = "none")]
pub fn managed_frames() -> usize {
    let tables = TABLES.get();
    // SAFETY: the static is this module's; `install` is the only writer and
    // this read happens after it.
    let tables = unsafe { &*tables };
    tables.frames.total_frames()
}

/// Where a program's pages live: above 512 GiB.
///
/// ## Why that address
///
/// A four-level walk on a 48-bit space has 512 entries in its root, and this
/// kernel's identity map fills entry 0 — the whole first 512 GiB.  A program's
/// pages in a *separate* root then need only that root's entries 1 and above to
/// differ, and everything below is the same shared second-level table.
///
/// That is the whole trick of a per-process address space here: a program gets
/// a root of its own whose entry 0 is the kernel's, so the kernel's code, data
/// and device windows are reachable from every process identically and cost
/// nothing to switch.  A root that copied the identity map instead would spend
/// a hundred and thirty thousand frames per process to share what is already
/// shared.
///
/// `0x80_0000_0000` is root entry 1: 512 GiB, one entry past the identity map.
pub const USER_BASE: usize = 0x80_0000_0000;

/// A program's address space: a root of its own, sharing the kernel's entry 0.
#[cfg(target_os = "none")]
#[derive(Debug, Clone, Copy)]
pub struct AddressSpace {
    /// The root table's frame.
    root: usize,
    /// The frames the program owns: its image and its stack.
    frames: [usize; 2],
    /// How many of `frames` are in use.
    used: usize,
}

#[cfg(target_os = "none")]
impl AddressSpace {
    /// A new address space with the kernel's mappings and nothing else.
    ///
    /// The root is a frame the allocator hands out; its entry 0 is copied from
    /// the kernel's root, which is the one entry that makes every kernel
    /// address reachable from the program without a second identity map.
    ///
    /// # Safety
    ///
    /// The caller must own the root — no other address space may share it,
    /// because the first `map` into it writes its entries.  The kernel's own
    /// root is never one of them: its entry 0 is *read* here.
    #[cfg(target_os = "none")]
    pub unsafe fn new() -> Option<AddressSpace> {
        let tables = TABLES.get();
        // SAFETY: the static is this module's, and this runs after `install`.
        let tables = unsafe { &mut *tables };

        let frame = tables.frames.allocate(1)?;
        if frame.is_null() {
            return None;
        }
        let root = frame as usize;
        let root_table = root as *mut PageTable;

        // SAFETY: the frame is a whole zeroed page the allocator just handed
        // out, and a `PageTable` is exactly one page.
        let program_root = unsafe { &*root_table };
        // Entry 0 is the kernel's: the same second-level table, so every
        // address below 512 GiB translates identically in both spaces.
        program_root.set_entry(0, tables.root.entry(0));

        Some(AddressSpace {
            root,
            frames: [0; 2],
            used: 0,
        })
    }

    /// The root table's address, which is what `TTBR0_EL1` takes.
    pub const fn root(&self) -> usize {
        self.root
    }

    /// Map `physical` at `virtual_address` in this space, reachable from EL0.
    ///
    /// Only `USER_BASE` and above, because everything below is the shared
    /// kernel region: a program mapping over it would give itself the kernel's
    /// addresses with `user: true`, which is the one mapping that must not
    /// exist.
    ///
    /// # Safety
    ///
    /// `virtual_address` must be in the program's range, page-aligned, and not
    /// already mapped; `physical` must be a live frame.
    pub unsafe fn map(&mut self, virtual_address: usize, physical: usize, writable: bool) -> bool {
        if virtual_address < USER_BASE || !virtual_address.is_multiple_of(GRANULE) {
            return false;
        }
        let tables = TABLES.get();
        // SAFETY: the static is this module's; the frames it reaches are this
        // address space's own root.
        let tables = unsafe { &mut *tables };

        // The root's entry for this address, and a second-level table under it.
        let root_index = index(Level::Root, virtual_address);
        let entry = decode_root(self.root, root_index);
        let second = if entry == 0 {
            let Some(frame) = tables.frames.allocate(1) else {
                return false;
            };
            if frame.is_null() {
                return false;
            }
            let address = frame as usize;
            // SAFETY: `self.root` is a live root frame; writing one of its
            // entries is what installing a table is.
            //
            // `user_table` and not `table`: x86_64 checks the user bit at every
            // level, so a supervisor-only entry here would refuse ring 3 access
            // to everything below it even with user leaves.
            unsafe {
                (&*(self.root as *const PageTable))
                    .set_entry(root_index, encode(Entry::user_table(address), Level::Root))
            };
            address
        } else {
            entry
        };

        // Below it, three more levels: this reuses the kernel's own walk
        // arithmetic rather than a second copy of it.
        let Some(leaf) = walk_or_create(tables, second, virtual_address) else {
            return false;
        };
        let permissions = Permissions {
            writable,
            executable: true,
            user: true,
            cache: paging::Cache::Normal,
        };
        leaf.set_entry(
            index(Level::Leaf, virtual_address),
            encode(Entry::page(physical, permissions), Level::Leaf),
        );
        arch::flush_translation();
        true
    }

    /// Record a frame this space owns, so freeing the space frees it.
    pub fn own(&mut self, frame: usize) {
        if self.used < self.frames.len() {
            self.frames[self.used] = frame;
            self.used += 1;
        }
    }

    /// Give every frame back.
    ///
    /// The frames are the program's, and a program that exited is one whose
    /// memory is available — which is the whole point of a process ending
    /// rather than the machine stopping.
    ///
    /// # Safety
    ///
    /// `self` must not be the installed address space: freeing the root the
    /// machine is translating through is a fault on the next instruction.
    pub unsafe fn release(self) {
        let tables = TABLES.get();
        // SAFETY: the static is this module's, and the caller promises this
        // space is not the installed one.
        let tables = unsafe { &mut *tables };
        for frame in &self.frames[..self.used] {
            let _ = tables.frames.deallocate(*frame as *mut u8, 1);
        }
        let _ = tables.frames.deallocate(self.root as *mut u8, 1);
    }
}

/// The address a root's entry names, or zero.
#[cfg(target_os = "none")]
fn decode_root(root: usize, root_index: usize) -> usize {
    // SAFETY: `root` is a root table's frame, which every caller holds.
    let table = unsafe { &*(root as *const PageTable) };
    let word = table.entry(root_index);
    if word == 0 {
        0
    } else {
        arch::paging::decode(word, Level::Root).address
    }
}

/// Walk from `second` to the leaf table for `address`, creating tables.
///
/// A program's address space starts empty above [`USER_BASE`], so every level
/// below the root is one this creates the first time the program maps there.
#[cfg(target_os = "none")]
fn walk_or_create(
    tables: &mut Tables,
    second: usize,
    address: usize,
) -> Option<&'static PageTable> {
    let mut current = second;
    for level in [Level::Second, Level::Third] {
        // SAFETY: `current` is a table frame this walk reached and holds.
        let table = unsafe { &*(current as *const PageTable) };
        let slot = index(level, address);
        let word = table.entry(slot);
        if word != 0 {
            current = arch::paging::decode(word, level).address;
            continue;
        }

        let frame = tables.frames.allocate(1)?;
        if frame.is_null() {
            return None;
        }
        let created = frame as usize;
        let kind = match level {
            Level::Second => Level::Root,
            _ => Level::Third,
        };
        // `user_table` for the reason `AddressSpace::map` gives: every level of
        // a user mapping's path carries the user bit on x86_64.
        table.set_entry(slot, encode(Entry::user_table(created), kind));
        current = created;
    }
    // SAFETY: the walk ended at the level above a leaf table, and that table
    // is a frame this created or found.
    Some(unsafe { &*(current as *const PageTable) })
}

/// Map `physical` at `virtual_address`, reachable from EL0.
///
/// ## Why this is not `map_region`
///
/// `map_region` re-encodes an existing identity-mapped page with different
/// permissions: the virtual address and the physical one are the same number.
/// A program's text is not identity mapped — it lives in a frame the allocator
/// handed out, at an address of the kernel's choosing — so the two differ and
/// the entry has to say so.
///
/// The permissions are `user: true` and executable: this is code a ring-3
/// program runs, which is the whole point of the mapping.  The kernel's own
/// text is `user: false`, and an entry that was not would let a program read
/// the kernel through the address it happens to be at.
///
/// # Safety
///
/// `virtual_address` and `physical` must be page-aligned, `physical` must be a
/// live frame, and the caller must have chosen a virtual address no other
/// mapping owns.
#[cfg(target_os = "none")]
pub unsafe fn map_user_page(virtual_address: usize, physical: usize) -> bool {
    let tables = TABLES.get();
    // SAFETY: the static is this module's, and this runs after `install`.
    let tables = unsafe { &mut *tables };

    if virtual_address >= IDENTITY_LIMIT || !virtual_address.is_multiple_of(GRANULE) {
        return false;
    }
    let Some(leaf) = leaf_for(&tables.root, virtual_address) else {
        return false;
    };

    let entry = Entry::page(
        physical,
        Permissions {
            writable: true,
            executable: true,
            user: true,
            cache: paging::Cache::Normal,
        },
    );
    leaf.set_entry(
        index(Level::Leaf, virtual_address),
        encode(entry, Level::Leaf),
    );
    arch::flush_translation();
    true
}

/// A frame for a program's image, zeroed and owned by the caller.
///
/// `None` when the pool is empty or the machine's tables cannot describe the
/// page.  The frame is not freed by the kernel: a program's image lives as long
/// as the program does.
#[cfg(target_os = "none")]
pub fn allocate_image_frame() -> Option<usize> {
    let tables = TABLES.get();
    // SAFETY: the static is this module's, and this runs after `install`.
    let tables = unsafe { &mut *tables };
    let frame = tables.frames.allocate(1)?;
    (!frame.is_null()).then_some(frame as usize)
}

/// Take one frame, as a page table would, and report whether it worked.
///
/// ## Why the boot calls this
///
/// The spare tables are enough for every window this machine has, so
/// `frames_taken_for_tables` is zero on a real boot and the branch that asks
/// the allocator for a table has never run.  A count of zero is honest and is
/// not evidence — this tree's recurring defect is code that is written, wired
/// and never executed, and "zero" cannot be told from "unreachable".
///
/// So the boot takes one frame through the same call the branch makes and
/// releases it.  That is not the branch itself; it is the one thing on the
/// branch's only external dependency.  What it cannot show is that the branch
/// is reached, which is why the boot line reports both numbers rather than one.
///
/// # Safety
///
/// Called once, after the pool is initialised and before anything else
/// allocates from it.  The frame is released before this returns.
#[cfg(target_os = "none")]
pub unsafe fn self_check_frame_pool() -> bool {
    let tables = TABLES.get();
    // SAFETY: the static is this module's, and this runs after `install`.
    let tables = unsafe { &mut *tables };

    let before = tables.frames.free_frames() + tables.frames.available_frames();
    let Some(frame) = tables.frames.allocate(1) else {
        return false;
    };
    if frame.is_null() {
        return false;
    }

    // A frame the allocator hands out is zeroed, and a page table that was not
    // would carry whatever the last owner wrote.
    // SAFETY: `frame` is a live frame inside the pool the allocator manages,
    // and one frame is `FRAME_SIZE` bytes.
    let zeroed = unsafe { core::slice::from_raw_parts(frame, paging::PAGE_SIZE) }
        .iter()
        .all(|byte| *byte == 0);
    let released = tables.frames.deallocate(frame, 1);
    // And the frame came back: a `deallocate` that answers `true` and loses the
    // frame leaves the pool one frame smaller on every pass, which is a leak
    // that reports success.  Comparing the count before and after is what makes
    // "released" mean something rather than repeat what the function said.
    let after = tables.frames.free_frames() + tables.frames.available_frames();
    zeroed && released && after == before
}

/// How many page tables came from the frame pool.
///
/// Zero on a boot whose spares were enough — which is the honest state of this
/// kernel rather than a failure, and the number that says whether the frame
/// allocator is exercised by a boot or only by its tests.
#[cfg(target_os = "none")]
pub fn frames_taken_for_tables() -> usize {
    let tables = TABLES.get();
    // SAFETY: as `managed_frames`.
    let tables = unsafe { &*tables };
    tables.frames_taken
}

/// How many of those frames can still be handed out.
///
/// The recycled holes plus the bump tail.  `free_frames` alone counts only the
/// holes, which is zero on a pool nothing has been freed from and reads as "no
/// memory left" — the opposite of the truth on a fresh boot.
#[cfg(target_os = "none")]
pub fn free_frames() -> usize {
    let tables = TABLES.get();
    // SAFETY: as `managed_frames`.
    let tables = unsafe { &*tables };
    tables.frames.free_frames() + tables.frames.available_frames()
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

    // No table yet: take an unused spare, or a frame when the spares are gone.
    //
    // The count of frames taken is what the boot reports, and it is the number
    // that says whether this branch has ever run: a machine whose spares were
    // always enough has an allocator here that nothing exercised, which is the
    // defect this tree keeps recording.
    let address = match tables.device.iter().position(|table| table.is_empty()) {
        // The tables live in a `static`, so an address into the array outlives
        // the borrow of the array itself — which is what `'static` says here.
        Some(free) => tables.device[free].address(),
        None => {
            // Past the spares, a page table comes from the frame allocator —
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

    /// The user window is above the kernel and a range has to fit inside it.
    ///
    /// The three things this tests are the three a syscall depends on: a
    /// kernel address is refused, a range that wraps is refused, and a range
    /// whose end crosses the boundary is refused.  A validator that got any of
    /// them wrong would let a program write one byte past its own pages.
    #[test]
    fn the_user_window_refuses_what_is_not_in_it() {
        use super::USER_BASE;
        use super::USER_WINDOW;
        use super::is_user_range;

        let first = USER_BASE;
        assert!(
            is_user_range(first, 1),
            "the first user byte is a user byte"
        );
        assert!(!is_user_range(first - 1, 1), "the last kernel byte is not");
        assert!(
            !is_user_range(0x4000_0000, 16),
            "a kernel address is refused"
        );

        assert!(
            is_user_range(first, USER_WINDOW),
            "a whole window from its start fits"
        );
        assert!(
            is_user_range(super::USER_LIMIT - 1, 1),
            "the last user byte is a user byte"
        );
        assert!(
            !is_user_range(super::USER_LIMIT, 1),
            "and the byte after it is not"
        );

        // A range that wraps must be refused rather than read as "ends before
        // it starts, so it is fine".
        assert!(
            !is_user_range(usize::MAX - 1, 8),
            "an overflowing range is not a user range"
        );
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
