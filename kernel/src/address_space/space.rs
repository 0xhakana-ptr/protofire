//! kernel/src/address_space/space.rs
//!
//! A program's address space: a root of its own that shares the kernel's, and
//! the mapping a program's pages go through.
//!
//! ## Why a program gets a root of its own
//!
//! A four-level walk on a 48-bit space has 512 entries in its root, and this
//! kernel's identity map fills entry 0, the whole first 512 GiB.  A program's
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
/// kernel's identity map fills entry 0, the whole first 512 GiB.  A program's
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

/// The most frames one address space records as its own.
///
/// An image and a stack, and the pair a `fork` copies.  A program that forks
/// twice is one this bound refuses rather than silently forgetting, the
/// refusal is `own` answering `false`, which the caller reports.
pub const MAX_OWNED_FRAMES: usize = 4;

/// A program's address space: a root of its own, sharing the kernel's entry 0.
#[cfg(target_os = "none")]
#[derive(Debug, Clone, Copy)]
pub struct AddressSpace {
    /// The root table's frame.
    root: usize,
    /// The frames the program owns: its image, its stack, and, for a program
    /// that forked, a copy of each of those per child it made.
    ///
    /// Four rather than two because `fork` copies both frames, and a limit that
    /// silently dropped the third would be a leak whose symptom is a pool that
    /// shrinks with no line in the log to say why.  A `Vec` would grow past
    /// this, and a `Vec` in a `Copy` type is not one: the fixed bound is the
    /// honest statement of what this kernel has decided to own per process.
    frames: [usize; MAX_OWNED_FRAMES],
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
    /// The caller must own the root, no other address space may share it,
    /// because the first `map` into it writes its entries.  The kernel's own
    /// root is never one of them: its entry 0 is *read* here.
    #[cfg(target_os = "none")]
    pub unsafe fn new() -> Option<AddressSpace> {
        let mut guard = TABLES.lock();
        let tables = &mut *guard;

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
            frames: [0; MAX_OWNED_FRAMES],
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
        let mut guard = TABLES.lock();
        let tables = &mut *guard;

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
    ///
    /// Answers whether it did: a space at its bound refuses the frame rather
    /// than dropping it, because a frame nobody records is a leak the pool
    /// will report as exhaustion much later.
    pub fn own(&mut self, frame: usize) -> bool {
        if self.used == self.frames.len() {
            return false;
        }
        self.frames[self.used] = frame;
        self.used += 1;
        true
    }

    /// The frames this space owns, in the order it took them.
    pub fn owned(&self) -> &[usize] {
        &self.frames[..self.used]
    }

    /// Give every frame back.
    ///
    /// The frames are the program's, and a program that exited is one whose
    /// memory is available, which is the whole point of a process ending
    /// rather than the machine stopping.
    ///
    /// # Safety
    ///
    /// `self` must not be the installed address space: freeing the root the
    /// machine is translating through is a fault on the next instruction.
    pub unsafe fn release(self) {
        let mut guard = TABLES.lock();
        let tables = &mut *guard;
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
/// A program's text is not identity mapped, it lives in a frame the allocator
/// handed out, at an address of the kernel's choosing, so the two differ and
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
    let mut guard = TABLES.lock();
    let tables = &mut *guard;

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
    let mut guard = TABLES.lock();
    let frame = guard.frames.allocate(1)?;
    (!frame.is_null()).then_some(frame as usize)
}

/// Take one frame, as a page table would, and report whether it worked.
///
/// ## Why the boot calls this
///
/// The spare tables are enough for every window this machine has, so
/// `frames_taken_for_tables` is zero on a real boot and the branch that asks
/// the allocator for a table has never run.  A count of zero is honest and is
/// not evidence, this tree's recurring defect is code that is written, wired
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
    let mut guard = TABLES.lock();
    let tables = &mut *guard;

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

/// One page a program has mapped, as the walk found it.
///
/// The virtual address, the frame behind it, and whether it is writable, ///
/// everything a copy needs and nothing about the page tables themselves, so a
/// caller that only reads this list cannot corrupt a walk by holding a
/// reference into it.
#[cfg(target_os = "none")]
#[derive(Debug, Clone, Copy)]
pub struct MappedPage {
    /// Where the program sees it.
    pub virtual_address: usize,
    /// The frame behind it.
    pub physical: usize,
    /// Whether writes are permitted, which a copy carries over.
    pub writable: bool,
}

/// The pages `space` maps in the user window, in address order.
///
/// ## Why this walks the tables rather than recording a list
///
/// A list of mappings kept beside the table is a second record of the same
/// fact, and the first thing to diverge is the one nobody updates.  The table
/// is the truth; this reads it.
///
/// Only the user window is read: everything below it is the kernel's shared
/// entry, identical in every root, and copying it would be copying the kernel.
///
/// `None` when the walk finds a table it cannot descend, a root entry naming
/// something that is not a table, which is a bug in whoever wrote it rather
/// than a state to tolerate.
#[cfg(target_os = "none")]
pub fn mapped_pages(space: &AddressSpace, out: &mut [MappedPage]) -> Option<usize> {
    let root = unsafe { &*(space.root() as *const PageTable) };
    let mut count = 0;

    // The user window's root entry is `index(Root, USER_BASE)` and everything a
    // program maps lives under it, so the walk starts there rather than at
    // entry zero, which is the kernel's.
    let base_root_index = index(Level::Root, USER_BASE);
    for root_index in base_root_index..paging::ENTRIES_PER_TABLE {
        let word = root.entry(root_index);
        if word == 0 {
            continue;
        }
        let second = arch::paging::decode(word, Level::Root);
        if !second.present || second.is_leaf {
            return None;
        }
        let second_table = unsafe { &*(second.address as *const PageTable) };
        for second_index in 0..paging::ENTRIES_PER_TABLE {
            let word = second_table.entry(second_index);
            if word == 0 {
                continue;
            }
            let third = arch::paging::decode(word, Level::Second);
            if !third.present || third.is_leaf {
                return None;
            }
            let third_table = unsafe { &*(third.address as *const PageTable) };
            for third_index in 0..paging::ENTRIES_PER_TABLE {
                let word = third_table.entry(third_index);
                if word == 0 {
                    continue;
                }
                let leaf_table_entry = arch::paging::decode(word, Level::Third);
                if !leaf_table_entry.present || leaf_table_entry.is_leaf {
                    return None;
                }
                let leaf_table = unsafe { &*(leaf_table_entry.address as *const PageTable) };
                for leaf_index in 0..paging::ENTRIES_PER_TABLE {
                    let word = leaf_table.entry(leaf_index);
                    if word == 0 {
                        continue;
                    }
                    let page = arch::paging::decode(word, Level::Leaf);
                    if !page.present || !page.is_leaf {
                        continue;
                    }
                    if count == out.len() {
                        return None;
                    }
                    // The address is the four indices the walk just read, put
                    // back together, not a counter, so a hole in the range is
                    // a hole in the answer too.
                    let virtual_address = (root_index << Level::Root.shift())
                        | (second_index << Level::Second.shift())
                        | (third_index << Level::Third.shift())
                        | (leaf_index << Level::Leaf.shift());
                    out[count] = MappedPage {
                        virtual_address,
                        physical: page.address,
                        writable: page.permissions.writable,
                    };
                    count += 1;
                }
            }
        }
    }
    Some(count)
}

/// A new address space holding a copy of `parent`'s user pages.
///
/// ## What is copied, and what is shared
///
/// Every page the parent maps in the user window gets a **new frame**, and the
/// bytes are copied into it.  That is `fork`'s contract: a child that wrote to
/// a page would otherwise change the parent's, and the first program to do that
/// would corrupt the program it came from, a defect whose symptom is a
/// corrupted value much later, in a process that never wrote it.
///
/// Copy-on-write would be the answer a kernel with a fault path for writes
/// uses, and this kernel has no such path: a write to a read-only page is a
/// fault nobody handles.  Whole-page copy is the honest version of what this
/// tree can do, and it is correct, only slower than it needs to be once a
/// program maps many pages.
///
/// The kernel's own entry 0 is shared, not copied: it is the same table in
/// every root, which is what makes a switch cost one register write.
///
/// # Safety
///
/// `parent` must be a live space whose pages are readable, and the caller must
/// own the result, the new root is a frame nothing else holds.
#[cfg(target_os = "none")]
pub unsafe fn fork_from(parent: &AddressSpace) -> Option<AddressSpace> {
    // The parent's page table lists the pages; a copy needs them all in a
    // buffer first, because allocating while the walk holds a borrow of the
    // allocator's own state would be a second borrow of the same static.
    let mut pages = [MappedPage {
        virtual_address: 0,
        physical: 0,
        writable: false,
    }; MAX_FORK_PAGES];
    let count = mapped_pages(parent, &mut pages)?;

    let mut child = unsafe { AddressSpace::new() }?;

    for page in &pages[..count] {
        // A frame of its own, and the parent's bytes into it.
        let Some(frame) = allocate_image_frame() else {
            // The child is abandoned: its root and every frame taken so far go
            // back, so a failed fork does not shrink the pool by a program.
            unsafe { child.release() };
            return None;
        };
        // SAFETY: both frames are live, and one frame is `GRANULE` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(page.physical as *const u8, frame as *mut u8, GRANULE);
        }
        if !child.own(frame) {
            unsafe { child.release() };
            return None;
        }
        // SAFETY: the frame is the child's, and the address is the parent's own
        // user address, which this space does not map yet.
        if !unsafe { child.map(page.virtual_address, frame, page.writable) } {
            unsafe { child.release() };
            return None;
        }
    }

    Some(child)
}

/// The most pages one `fork` copies.
///
/// The boot's programs map two each, an image and a stack, and this bound is
/// generous relative to that.  A program with more pages than this is one whose
/// fork is refused rather than one whose copy is silently partial, which is the
/// only other way this could go wrong.
#[cfg(target_os = "none")]
pub const MAX_FORK_PAGES: usize = 8;
