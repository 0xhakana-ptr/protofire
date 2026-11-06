//! kernel/src/address_space/space.rs
//!
//! A program's address space: a root of its own that shares the kernel's, and
//! the mapping a program's pages go through.
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
use super::USER_LIMIT;
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
/// An image and a stack, and the frames a `fork` shares.  Sharing does not
/// copy, so a child records the same frames its parent does, each once: the
/// bound is a bound on the *records* and not on the pages, and a program that
/// forks twice is one this bound refuses rather than silently forgetting, the
/// refusal is `own` answering `false`, which the caller reports.
pub const MAX_OWNED_FRAMES: usize = 4;

/// A program's address space: a root of its own, sharing the kernel's entry 0.
#[cfg(target_os = "none")]
#[derive(Debug, Clone, Copy)]
pub struct AddressSpace {
    /// The root table's frame.
    root: usize,
    /// The frames the program owns: its image, its stack, and, for a program
    /// that forked, the shared frame behind each page it inherited.
    ///
    /// Ownership is one *record* per frame this space holds a reference to, and
    /// a frame two spaces share is recorded by both: the pool's co-owner count
    /// is what makes that sound, and `release` is what consults it.  Four
    /// rather than two because a fork's child records both frames it inherited,
    /// and a limit that silently dropped the third would be a leak whose
    /// symptom is a pool that shrinks with no line in the log to say why.  A
    /// `Vec` would grow past this, and a `Vec` in a `Copy` type is not one: the
    /// fixed bound is the honest statement of what this kernel has decided to
    /// own per process.
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

    /// Record a frame this space owns, so freeing the space frees its share.
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

    /// Stop owning `old_frame` and own `new_frame` in its place.
    ///
    /// The copy-on-write resolver's bookkeeping: the faulting space copied the
    /// shared frame away, so what it owns now is its private copy.  One record
    /// out, one in — the bound does not move, and the count in the pool moves
    /// with it, because the resolver released the shared frame's reference
    /// when it copied and this records the copy's ownership in the same
    /// breath.  `false` means this space never owned `old_frame`, which is not
    /// a state the resolver can reach and is a bug report rather than a silent
    /// swap of nothing.
    pub fn replace_owned(&mut self, old_frame: usize, new_frame: usize) -> bool {
        for slot in &mut self.frames[..self.used] {
            if *slot == old_frame {
                *slot = new_frame;
                return true;
            }
        }
        false
    }

    /// The frames this space owns, in the order it took them.
    pub fn owned(&self) -> &[usize] {
        &self.frames[..self.used]
    }

    /// Give every frame this space holds a reference to its share back.
    ///
    /// The frames are the program's, and a program that exited is one whose
    /// memory is available, which is the whole point of a process ending
    /// rather than the machine stopping.  Ownership is shared since the copy-
    /// on-write fork: a frame two spaces hold is returned by the *last* space
    /// to let go, and each release before that is one reference fewer.  The
    /// pool answers whether a release was the last, and the frame goes back
    /// only then — a release that freed unconditionally would hand a live
    /// frame to the next allocation while its other owner still mapped it.
    ///
    /// # Safety
    ///
    /// `self` must not be the installed address space: freeing the root the
    /// machine is translating through is a fault on the next instruction.
    pub unsafe fn release(self) {
        let mut guard = TABLES.lock();
        let tables = &mut *guard;
        for frame in &self.frames[..self.used] {
            // The protocol, in two lines: release asks whether this was the
            // last owner, and only a `true` returns the frame.  A frame no
            // fork ever shared counts zero co-owners, so its first release is
            // its last, and the ordinary path is unchanged.
            if tables.frames.release_reference(*frame) {
                let _ = tables.frames.deallocate(*frame as *mut u8, 1);
            }
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

/// A new address space holding one program: `bytes` at `image_va`, a stack at
/// `stack_va`, and nothing else.
///
/// `exec`'s builder.  The mapping is the boot's own [`map_user_page`]-shaped
/// pair — image read-only and executable, stack writable — and the addresses
/// are the **caller's**, not this function's choice: `exec` swaps the frames
/// behind the window a task already owns rather than giving the task a new
/// window, because the window is the one thing about a process that its
/// callers may have come to rely on.
///
/// Every failure returns with the space released: the root and each frame the
/// builder recorded go back, so a failed `exec` does not shrink the pool by a
/// program.  The image frame is recorded **before** the stack is taken, which
/// is the order that makes that true — a builder that took both frames first
/// and recorded them after would leak the image frame of every `exec` that
/// found the pool empty at its second ask.
///
/// # Safety
///
/// `image_va` and `stack_va` must be page-aligned addresses in the caller's
/// user window that are not already mapped by the returned space, and `bytes`
/// must fit in one page.  The frames the pool hands out are zeroed and live.
#[cfg(target_os = "none")]
pub unsafe fn image_space(bytes: &[u8], image_va: usize, stack_va: usize) -> Option<AddressSpace> {
    let mut space = unsafe { AddressSpace::new() }?;
    let Some(image_frame) = allocate_image_frame() else {
        unsafe { space.release() };
        return None;
    };
    if !space.own(image_frame) {
        unsafe { space.release() };
        return None;
    }
    let Some(stack_frame) = allocate_image_frame() else {
        // The image frame is recorded, so the release takes it back with the
        // root, which is the whole of why the order above is the order.
        unsafe { space.release() };
        return None;
    };
    if !space.own(stack_frame) {
        unsafe { space.release() };
        return None;
    }
    // SAFETY: `image_frame` is a live frame the pool handed out and zeroed,
    // the image is smaller than one page, and the boot is identity mapped, so
    // the frame's physical address is one the kernel can write.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), image_frame as *mut u8, bytes.len());
    }
    // SAFETY: both frames belong to this space, and the two addresses are the
    // caller's own window, which this space does not map yet.
    let mapped = unsafe { space.map(image_va, image_frame, false) }
        && unsafe { space.map(stack_va, stack_frame, true) };
    if !mapped {
        unsafe { space.release() };
        return None;
    }
    Some(space)
}

/// Take one frame, as a page table would, and report whether it worked.
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

/// A new address space sharing `parent`'s user pages.
///
/// Every page the parent maps in the user window, the child maps as **the same
/// frame**.  A page the parent could write is demoted first: the parent's
/// entry is rewritten read-only and the frame is marked for copy-on-write, so
/// the first write on either side faults, and the fault handler — the reason
/// this kernel has a write-fault path at all — copies the frame while the
/// other owner still holds it and hands it over outright when it does not.  A
/// page the parent could not write is shared as it stands: it was already
/// read-only, there is nothing to demote, and a write to it is the program
/// faulting on its own code, which is a real fault and stays one.
///
/// That is `fork`'s contract kept by other means.  The first version copied
/// every page into a new frame, which is correct, and slower in exactly the
/// case a fork exists for: most of the pages a fork shares are never written
/// by either side, and the copy paid for all of them.  The shared version
/// pays, per page, for the pages someone actually writes, which is what the
/// fault handler counts.
///
/// ## The TLB, and why a local flush is the whole of the invalidation
///
/// The demotion happens on the CPU serving the fork, which is the parent's
/// own: a fork is a supervisor call, and the CPU that took it is the one the
/// parent runs on.  Every machine's `switch_address_space` is a whole-TLB
/// flush, so a CPU that is not running the parent holds no translations for
/// the parent's pages — it discarded them at its last switch and has not
/// re-fetched them through this root since.  The parent cannot write between
/// the demotion and the share either: it is suspended inside its own syscall.
/// One local flush is therefore the whole of the invalidation, and the
/// machine's answer to a change in a *shared kernel table*,
/// [`crate::shootdown`], is not what this needs.
///
/// ## Failure, and why the demotions it leaves behind need no repair
///
/// A fork that fails midway leaves the parent's earlier pages demoted, marked
/// and counted.  That state is correct on its own: the next write on such a
/// page faults, the handler reads the count and copies or hands over, and the
/// parent continues.  The failed fork costs the parent copies it would have
/// paid on its first writes anyway, and nothing else.
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
    // The parent's page table lists the pages; a fork needs them all in a
    // buffer first, because mutating entries while the walk holds a borrow of
    // the allocator's own state would be a second borrow of the same static.
    let mut pages = [MappedPage {
        virtual_address: 0,
        physical: 0,
        writable: false,
    }; MAX_FORK_PAGES];
    let count = mapped_pages(parent, &mut pages)?;

    let mut child = unsafe { AddressSpace::new() }?;

    for page in &pages[..count] {
        // Demote the parent's entry when the page was writable, and record the
        // child as one more owner, in one pool critical section.
        if !share_frame(
            parent.root(),
            page.virtual_address,
            page.physical,
            page.writable,
        ) {
            // The share is the child's first claim on the frame, so there is
            // nothing of this page to undo: the child owns nothing yet.
            unsafe { child.release() };
            return None;
        }
        if !child.own(page.physical) {
            // The child counted itself an owner but cannot record the frame:
            // undo that one share before the release, or the count would name
            // a co-owner that no longer exists.
            unshare_frame(page.physical);
            unsafe { child.release() };
            return None;
        }
        // SAFETY: the frame is shared with the parent, and the address is the
        // parent's own user address, which this space does not map yet.
        if !unsafe { child.map(page.virtual_address, page.physical, false) } {
            unsafe { child.release() };
            return None;
        }
    }

    Some(child)
}

/// Demote `address` in `root` when the page must be shared read-only, and
/// record one more co-owner of `frame`.
///
/// One pool critical section for the pair, because they are one fact: the
/// demotion is what makes the *next* write fault, and the mark is what makes
/// that fault resolvable.  A demotion whose mark landed in a later section
/// would leave a window in which the parent faults and the handler has
/// nothing to read.  Nothing can actually take the window — the fork runs on
/// the parent's own CPU, the task is suspended inside its syscall, and no
/// other CPU walks this root — but the single section is cheaper than the
/// argument it saves.
///
/// The walk also checks the frame it lands on: `frame` was read out of this
/// root by [`mapped_pages`] a moment ago, and a walk that lands somewhere
/// else means one of them is wrong, which is a refusal here rather than a
/// demotion of the wrong page.
///
/// Answers whether the page is now shared: the parent read-only when it was
/// not already, the frame counted, the mark set when the page was demoted.
#[cfg(target_os = "none")]
fn share_frame(root: usize, address: usize, frame: usize, demote: bool) -> bool {
    let mut guard = TABLES.lock();
    let tables = &mut *guard;

    if demote {
        // SAFETY: `root` is a root table's frame this space owns, and the
        // walk reads entries this kernel wrote.
        let root_table = unsafe { &*(root as *const PageTable) };
        let Some(leaf) = leaf_for(root_table, address) else {
            return false;
        };
        let slot = index(Level::Leaf, address);
        let word = leaf.entry(slot);
        let entry = arch::paging::decode(word, Level::Leaf);
        if entry.address != frame || !entry.permissions.user {
            return false;
        }
        let permissions = Permissions {
            writable: false,
            ..entry.permissions
        };
        leaf.set_entry(
            slot,
            encode(Entry::page(entry.address, permissions), Level::Leaf),
        );
        // The demotion is invisible to this CPU's TLB until it is flushed, and
        // a stale writable entry would let the parent write the shared frame
        // with no fault at all, which is the corruption the whole scheme
        // exists to prevent.
        arch::flush_translation();
    }

    if !tables.frames.add_reference(frame) {
        return false;
    }
    if demote {
        tables.frames.set_cow(frame, true);
    }
    true
}

/// Drop one co-owner of `frame`, returning the frame if that was the last.
///
/// For undoing a share that a caller cannot carry through — a fork whose child
/// ran out of records mid-page.  The release answers whether the frame still
/// has owners, and a frame it does not goes back; the share this undoes
/// always had the child as its second owner, so the answer is always "still
/// owned" and the deallocate below is the protocol's dead branch, kept for
/// the same reason the protocol spells it: the two lines are one fact.
#[cfg(target_os = "none")]
fn unshare_frame(frame: usize) {
    let mut guard = TABLES.lock();
    let tables = &mut *guard;
    if tables.frames.release_reference(frame) {
        let _ = tables.frames.deallocate(frame as *mut u8, 1);
    }
}

/// Resolve a write fault on a copy-on-write page of `space`.
///
/// Called from the fault path with the space the faulting CPU is running and
/// the address the fault named.  The page must be one a fork demoted — the
/// pool's mark says so — and the count decides the answer:
///
/// - **Co-owners remain.** The faulting space gets a private copy: a new frame,
///   the bytes moved, the entry rewritten writable, and the shared frame's
///   count dropped by one, because the faulting owner's claim went with the
///   copy.  [`AddressSpace::replace_owned`] records the swap.
/// - **No co-owners.** The faulting space is the last holder, so the frame is
///   promoted in place: the mark clears and the entry turns writable.  Nothing
///   is copied, because nobody else will ever read the old bytes.
///
/// Anything else is not a copy-on-write fault and answers `false`: the caller
/// prints its diagnostic and stops the machine, which is the honest answer
/// for a program writing a page that was never meant to be written — its own
/// code, most likely.  The mark is what separates those: a fork demoted a
/// writable page, so the fault is repairable; a page mapped read-only from
/// the start was never writable at all, and no copy changes that.
///
/// The walk is the space's own root, compared first against the register the
/// faulting CPU was translating through: a fault served against a different
/// root than the one it happened in would rewrite an entry nobody faulted on.
///
/// The caller holds the scheduler's lock and this takes the pool's inside it —
/// the order a fork holds the two, and the only order any code in this kernel
/// takes them.
#[cfg(target_os = "none")]
pub(crate) fn resolve_copy_on_write(space: &mut AddressSpace, fault_address: usize) -> bool {
    let root = space.root();
    if arch::installed_root_table() != Some(root) {
        return false;
    }
    if !(USER_BASE..USER_LIMIT).contains(&fault_address) {
        return false;
    }

    let mut guard = TABLES.lock();
    let tables = &mut *guard;

    // SAFETY: `root` is a root table's frame this space owns, and the walk
    // reads entries this kernel wrote.
    let root_table = unsafe { &*(root as *const PageTable) };
    let Some(leaf) = leaf_for(root_table, fault_address) else {
        return false;
    };
    let slot = index(Level::Leaf, fault_address);
    let word = leaf.entry(slot);
    let entry = arch::paging::decode(word, Level::Leaf);
    // A fault on a page that is already writable, or on one the walk says is
    // not a user page, is not a copy-on-write fault; the second is also the
    // guard that keeps the resolver's hands off the kernel's own mappings.
    if !entry.permissions.user || entry.permissions.writable {
        return false;
    }
    let frame = entry.address;
    if !tables.frames.is_cow(frame) {
        return false;
    }

    let permissions = Permissions {
        writable: true,
        ..entry.permissions
    };
    let resolved = if tables.frames.co_owners(frame) > 0 {
        let Some(new_frame) = tables.frames.allocate(1) else {
            return false;
        };
        if new_frame.is_null() {
            return false;
        }
        // SAFETY: both frames are live frames inside the pool, and one frame
        // is `GRANULE` bytes.
        unsafe {
            core::ptr::copy_nonoverlapping(frame as *const u8, new_frame, GRANULE);
        }
        // The faulting owner's claim on the shared frame goes with the copy.
        // The answer is `false` by construction — this branch ran because a
        // co-owner remained — so nothing is deallocated, and the count that
        // stays is whoever is left.
        let _ = tables.frames.release_reference(frame);
        leaf.set_entry(
            slot,
            encode(Entry::page(new_frame as usize, permissions), Level::Leaf),
        );
        // The protocol says this space owns the frame it faulted on, so the
        // swap cannot fail; a `false` here is a bug report, and the machine
        // stops with the diagnostic rather than running on half-torn state.
        if !space.replace_owned(frame, new_frame as usize) {
            return false;
        }
        arch::serial::write_str("protofire: copy-on-write copy at ");
        arch::serial::write_hex(fault_address as u64);
        arch::serial::write_str(" from frame ");
        arch::serial::write_hex(frame as u64);
        arch::serial::write_str(" to frame ");
        arch::serial::write_hex(new_frame as u64);
        arch::serial::write_str("\n");
        true
    } else {
        tables.frames.set_cow(frame, false);
        leaf.set_entry(slot, encode(Entry::page(frame, permissions), Level::Leaf));
        arch::serial::write_str("protofire: copy-on-write promote at ");
        arch::serial::write_hex(fault_address as u64);
        arch::serial::write_str(" on frame ");
        arch::serial::write_hex(frame as u64);
        arch::serial::write_str("\n");
        true
    };

    if resolved {
        // The entry this CPU will next translate through changed under it: a
        // stale read-only entry would fault the very same instruction all
        // over again.  Every machine's flush is whole-TLB, which is also why
        // no other CPU needs telling — none of them translates through this
        // root.
        arch::flush_translation();
    }
    resolved
}

/// The most pages one `fork` shares.
///
/// The boot's programs map two each, an image and a stack, and this bound is
/// generous relative to that.  A program with more pages than this is one whose
/// fork is refused rather than one whose share is silently partial, which is
/// the only other way this could go wrong.
#[cfg(target_os = "none")]
pub const MAX_FORK_PAGES: usize = 8;
