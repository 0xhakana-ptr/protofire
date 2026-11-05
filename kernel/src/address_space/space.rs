//! kernel/src/address_space/space.rs
//!
//! A program's address space: a root of its own that shares the kernel's, and
//! the mapping a program's pages go through.
//!
//! ## Why a program gets a root of its own
//!
//! A four-level walk on a 48-bit space has 512 entries in its root, and this
//! kernel's identity map fills entry 0 — the whole first 512 GiB.  A program's
//! pages in a *separate* root then need only that root's entries 1 and above to
//! differ, and everything below is the same shared second-level table.  That is
//! the whole trick: a program gets a root of its own whose entry 0 is the
//! kernel's, so the kernel's code, data and device windows are reachable from
//! every process identically and cost nothing to switch.  A root that copied
//! the identity map instead would spend a hundred and thirty thousand frames
//! per process to share what is already shared.

#[cfg(target_os = "none")]
use paging::Entry;
#[cfg(target_os = "none")]
use paging::Level;
#[cfg(target_os = "none")]
use paging::PageTable;
#[cfg(target_os = "none")]
use paging::Permissions;
#[cfg(target_os = "none")]
use paging::index;

#[cfg(target_os = "none")]
use super::table::GRANULE;
#[cfg(target_os = "none")]
use super::table::IDENTITY_LIMIT;
#[cfg(target_os = "none")]
use super::table::TABLES;
#[cfg(target_os = "none")]
use super::table::Tables;
#[cfg(target_os = "none")]
use super::table::encode;
#[cfg(target_os = "none")]
use super::table::leaf_for;

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
pub(crate) fn decode_root(root: usize, root_index: usize) -> usize {
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
pub(crate) fn walk_or_create(
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
