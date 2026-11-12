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

/// The most frames one loaded image may occupy, plus its stack.
///
/// The loader's budget, not the space's: `MAX_IMAGE_BYTES` is a quarter of the
/// boot disk and admits a 64-page image, and one slot past the pages is the
/// stack the exec path adds.  It is derived rather than written down because
/// the two have to agree and they did not once — a legal 64 KiB program was
/// refused by a bound whose own documentation described a smaller thing.
///
/// This is the number the **exec** path checks; a space's total ownership has
/// its own bound below.
pub const MAX_IMAGE_FRAMES: usize = crate::loader::MAX_IMAGE_BYTES / paging::PAGE_SIZE + 1;

/// The most frames one address space may record as its own.
///
/// An image, its stack, the frames a `fork` shares and the pages a program
/// obtained at run time.  The last is why this is no longer the image budget:
/// a `Brk` or an `Mmap` adds pages to a space that has already loaded, and
/// bounding the total by what an image may weigh would have refused a program
/// a heap the moment its image was large.
///
/// 4096 pages is 16 MiB per process, which is a bound this kernel states
/// rather than one it discovers: the free pool on the smallest machine is
/// 64 MiB, so four processes may each hold a sixteenth of it and the boot's
/// own test still has room.
pub const MAX_OWNED_FRAMES: usize = 4096;

/// A program's address space: a root of its own, sharing the kernel's entry 0.
///
/// Not `Copy`, and the reason is the frame list below.  It was `Copy` while the
/// list was a fixed array, and two call sites relied on that: a fork read the
/// parent's space out of the task table by value, and a task answered its root
/// the same way.  Both now borrow, which is the honest description — a space is
/// one object a task owns, not a value to be duplicated at each question.
#[cfg(target_os = "none")]
#[derive(Debug)]
pub struct AddressSpace {
    /// The root table's frame.
    root: usize,
    /// The frames the program owns: its image, its stack, the shared frame
    /// behind each page it inherited from a fork, and every page it obtained at
    /// run time.
    ///
    /// Ownership is one *record* per frame this space holds a reference to, and
    /// a frame two spaces share is recorded by both: the pool's co-owner count
    /// is what makes that sound, and `release` is what consults it.  A record
    /// dropped silently is a leak whose symptom is a pool that shrinks with no
    /// line in the log to say why, so `own` refuses past the bound rather than
    /// forgetting.
    ///
    /// It was a fixed array, sized by what an image may weigh.  That bound is
    /// the loader's and not this type's: a `Brk` or an `Mmap` adds pages to a
    /// space that has already loaded, and a program's heap has nothing to do
    /// with its image size.  Growing it is a `Vec`, which is why the struct is
    /// no longer `Copy`.
    frames: alloc::vec::Vec<usize>,
    /// Where the program's data segment ends: the address a `Brk` may grow
    /// upward from, and the value a `Brk` query answers when nothing has grown
    /// yet.  Zero for a space no image was loaded into.
    brk: usize,
    /// Where the next `Mmap` goes, counting **down** from the top of this
    /// program's window.
    ///
    /// Downward because the bottom of the window is taken: the image starts at
    /// the window's base, its stack is one page above the image, and `Brk`
    /// grows up from the image's end.  Growing mappings downward from the top
    /// keeps the two ends apart, and the gap between them is the budget.
    ///
    /// Zero means "no reservation has been made", which is resolved against
    /// the window's end on the first one.
    map_cursor: usize,
    /// This program's window, as the exec path placed it: the lowest address a
    /// mapping may take, and one past the highest.
    ///
    /// Recorded rather than derived, because deriving it needs the image's base
    /// and the image does not keep it — `exec` computes where the image ends
    /// and what window it went into, and this is where those two facts live
    /// afterwards.  `(0, 0)` for a space no image was loaded into, which is the
    /// boot's own machine-code programs; they never reserve.
    window: (usize, usize),
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
            // Depth zero.  Not `with_capacity`: allocating 520 bytes here
            // would be a heap allocation for every space, at the one moment
            // the scheduler may hold its lock.
            frames: alloc::vec::Vec::new(),
            brk: 0,
            map_cursor: 0,
            window: (0, 0),
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
        let permissions = Permissions {
            writable,
            executable: true,
            user: true,
            cache: paging::Cache::Normal,
        };
        // SAFETY: the caller's contract is this one's, unchanged.
        unsafe { self.map_page_with(virtual_address, physical, permissions) }
    }

    /// Map `physical` at `virtual_address` with the caller's permissions.
    ///
    /// `map` is the convenience shape the boot's two-page programs use — code
    /// and stack, both executable, writability the only question.  A loaded
    /// image's segments know better than that: text is read-execute, data is
    /// read-write and *not* executable, and the permissions travel with the
    /// segment rather than with a bool.  `user` is always set — everything an
    /// `AddressSpace` maps is a program's — and a caller passing `user: false`
    /// is refused rather than mapped, because the one mapping that must not
    /// exist is a kernel page a program can reach.
    ///
    /// # Safety
    ///
    /// `virtual_address` must be in the program's range, page-aligned, and not
    /// already mapped; `physical` must be a live frame.
    pub unsafe fn map_page_with(
        &mut self,
        virtual_address: usize,
        physical: usize,
        permissions: Permissions,
    ) -> bool {
        if virtual_address < USER_BASE || !virtual_address.is_multiple_of(GRANULE) {
            return false;
        }
        if !permissions.user {
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
        leaf.set_entry(
            index(Level::Leaf, virtual_address),
            encode(Entry::page(physical, permissions), Level::Leaf),
        );
        arch::flush_translation();
        true
    }

    /// Remove the mapping at `virtual_address`, answering the frame it named.
    ///
    /// `None` when nothing was mapped there, which is not an error: a program
    /// that unmaps a range it partly owns has asked a question with two true
    /// answers, and the one that says "there was nothing" is the honest one.
    ///
    /// ## Why the walk creates nothing
    ///
    /// [`walk_or_create`] allocates the tables a mapping needs.  An unmap needs
    /// the opposite: a table that does not exist is a page that was never
    /// mapped, and allocating one to then find an empty leaf would turn an
    /// unmap of a range nobody used into three frames of permanent leakage.
    /// So this walks the entries that are already there and stops at the first
    /// absent one.
    ///
    /// ## What it does not do
    ///
    /// It does not free the frame, and it does not touch the ownership list.
    /// The two are the caller's, in that order: a frame still recorded and no
    /// longer mapped is what a `Munmap` leaves behind until it releases the
    /// record, and a frame freed while another space still maps it is the
    /// corruption the co-owner counts exist to prevent.
    ///
    /// # Safety
    ///
    /// `self` must not be the installed address space: clearing an entry this
    /// CPU is translating through is a fault on the next instruction.  The
    /// caller also owns the frame that was returned, and owns the decision
    /// about when it may be freed.
    pub unsafe fn unmap_page(&mut self, virtual_address: usize) -> Option<usize> {
        if virtual_address < USER_BASE || !virtual_address.is_multiple_of(GRANULE) {
            return None;
        }
        let mut guard = TABLES.lock();
        let tables = &mut *guard;

        // Entry 0 is the kernel's shared table and entry 1 and above are this
        // space's; the second level is found, never created.
        let root_slot = index(Level::Root, virtual_address);
        let root_word = unsafe { &*(self.root as *const PageTable) }.entry(root_slot);
        if root_word == 0 {
            return None;
        }
        let second = arch::paging::decode(root_word, Level::Root);
        if second.is_leaf {
            // A block mapping is not a page this space allocated.
            return None;
        }
        let _ = tables;

        let mut current = second.address;
        for level in [Level::Second, Level::Third] {
            // SAFETY: `current` is a table this walk reached through an entry
            // that was present, so it is a frame the space owns.
            let table = unsafe { &*(current as *const PageTable) };
            let slot = index(level, virtual_address);
            let word = table.entry(slot);
            if word == 0 {
                return None;
            }
            let entry = arch::paging::decode(word, level);
            if level == Level::Third {
                if !entry.is_leaf {
                    return None;
                }
                // The write the whole function exists for.  `encode` answers
                // zero for a non-present entry on all three machines, which is
                // how "clear this" is spelled without a machine-specific word.
                table.set_entry(
                    slot,
                    encode(
                        Entry {
                            address: 0,
                            permissions: entry.permissions,
                            is_leaf: true,
                            present: false,
                        },
                        level,
                    ),
                );
                arch::flush_translation();
                return Some(entry.address);
            }
            if entry.is_leaf {
                return None;
            }
            current = entry.address;
        }
        None
    }

    /// Map `length` newly allocated pages at a reserved address.
    ///
    /// The whole of `Mmap` after the arguments are validated: reserve the
    /// range, allocate a frame per page, map each, and record it as owned.  A
    /// step that fails undoes the ones before it — a mapping that allocated
    /// nine of ten pages and returned an error would leave nine frames the
    /// program has no name for and the space has forgotten.
    ///
    /// Permissions come from the caller's `PROT_*` set.  `user` is always true,
    /// because everything an `AddressSpace` maps is a program's, and writable
    /// and executable are the two the set names.
    ///
    /// # Safety
    ///
    /// `self` must not be the installed address space, for the reason
    /// [`unmap_page`](Self::unmap_page) gives.
    pub unsafe fn map_anonymous(
        &mut self,
        base: usize,
        length: usize,
        writable: bool,
        executable: bool,
    ) -> bool {
        let pages = length.div_ceil(paging::PAGE_SIZE);
        let permissions = Permissions {
            writable,
            executable,
            user: true,
            cache: paging::Cache::Normal,
        };
        let mut mapped = 0usize;
        while mapped < pages {
            let Some(frame) = crate::address_space::allocate_image_frame() else {
                // Out of frames: undo what this call did and answer no.  The
                // frames themselves are the space's `own`s, so `release` is
                // not what undoes this — each is unmapped and disowned here,
                // one at a time, which is the only thing that knows which
                // pages this call is responsible for.
                // SAFETY: the caller's contract covers the whole function.
                unsafe { self.undo_anonymous(base, mapped) };
                return false;
            };
            if !self.own(frame) {
                // SAFETY: as above.
                unsafe { self.undo_anonymous(base, mapped) };
                return false;
            }
            // SAFETY: the range was reserved by `reserve`, which is what makes
            // it unmapped; the frame is this space's own.
            let ok = unsafe {
                self.map_page_with(base + mapped * paging::PAGE_SIZE, frame, permissions)
            };
            if !ok {
                // SAFETY: as above.
                unsafe { self.undo_anonymous(base, mapped) };
                return false;
            }
            mapped += 1;
        }
        true
    }

    /// Take back the first `pages` pages of a mapping that failed partway.
    ///
    /// # Safety
    ///
    /// The pages must be ones this space mapped and owns, which is the state
    /// `map_anonymous` holds when it calls this.
    unsafe fn undo_anonymous(&mut self, base: usize, pages: usize) {
        for index in 0..pages {
            let address = base + index * paging::PAGE_SIZE;
            // SAFETY: the caller's contract is this function's.
            let frame = unsafe { self.unmap_page(address) };
            if let Some(frame) = frame {
                let _ = self.disown(frame);
            }
        }
    }

    /// Unmap everything in `[base, base + length)` and give its frames back.
    ///
    /// Answers how many pages were taken away, which is zero for a range
    /// nothing was mapped in — an unmapped range is not an error, for the
    /// reason [`unmap_page`](Self::unmap_page) gives.
    ///
    /// The frames go back through the pool's co-owner count, so a page a fork
    /// shares is released from this space and kept for the other, which is the
    /// whole reason `disown` and `unmap_page` are separate.
    ///
    /// # Safety
    ///
    /// `self` must not be the installed address space.
    pub unsafe fn unmap_range(&mut self, base: usize, length: usize) -> usize {
        let pages = length.div_ceil(paging::PAGE_SIZE);
        let mut taken = 0usize;
        for index in 0..pages {
            let address = base + index * paging::PAGE_SIZE;
            // SAFETY: the caller's contract is this function's.
            let frame = unsafe { self.unmap_page(address) };
            let Some(frame) = frame else {
                continue;
            };
            if self.disown(frame) {
                taken += 1;
            }
            let mut guard = TABLES.lock();
            if guard.frames.release_reference(frame) {
                let _ = guard.frames.deallocate(frame as *mut u8, 1);
            }
        }
        taken
    }

    /// Record a frame this space owns, so freeing the space frees its share.
    ///
    /// Answers whether it did: a space at its bound refuses the frame rather
    /// than dropping it, because a frame nobody records is a leak the pool
    /// will report as exhaustion much later.
    pub fn own(&mut self, frame: usize) -> bool {
        if self.frames.len() >= MAX_OWNED_FRAMES {
            return false;
        }
        self.frames.push(frame);
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
        for slot in &mut self.frames {
            if *slot == old_frame {
                *slot = new_frame;
                return true;
            }
        }
        false
    }

    /// Stop recording `frame` as owned by this space, answering whether it was.
    ///
    /// [`unmap_page`](Self::unmap_page) is the other half: it takes the entry
    /// out of the page table and answers the frame, and this takes the frame
    /// out of the ownership list.  Both are needed and neither implies the
    /// other, because a frame can be mapped in more than one space and a frame
    /// can be recorded by a space that has already unmapped it while the copy
    /// is still in flight.
    ///
    /// It does not free the frame.  The pool decides that, and it decides by
    /// [`release_reference`](memory::FrameAllocator::release_reference): a
    /// frame a fork shared goes back only when the last space lets go.
    /// Answering the frame to the caller would invite a `deallocate` here,
    /// which is the double free this method exists to keep out of reach.
    pub fn disown(&mut self, frame: usize) -> bool {
        let Some(position) = self.frames.iter().position(|owned| *owned == frame) else {
            return false;
        };
        self.frames.swap_remove(position);
        true
    }

    /// The frames this space owns, in the order it took them.
    pub fn owned(&self) -> &[usize] {
        &self.frames
    }

    /// Reserve `length` bytes of virtual address space, answering the base.
    ///
    /// The reservation is arithmetic: it moves this space's cursor and does not
    /// touch a page table, so a caller that reserves and then fails to map
    /// leaves a hole rather than a mapping.  The order is the caller's because
    /// it is the one that has to allocate the frames, and a reservation that
    /// allocated them would be a function that both reserves and can fail
    /// halfway.
    ///
    /// **Downward from the top of this program's window**, which is what keeps
    /// a mapping clear of the image and the stack at the bottom.  `hint` is
    /// honoured when it names a page-aligned address inside the window and
    /// below the cursor; anything else is treated as "somewhere", because a
    /// hint is a hint and a caller that wanted a specific address has no way to
    /// demand one in the four numbers this ABI gives it.
    pub fn reserve(&mut self, hint: usize, length: usize) -> Option<usize> {
        if length == 0 {
            return None;
        }
        let length = length.checked_add(paging::PAGE_SIZE - 1)? & !(paging::PAGE_SIZE - 1);
        let (floor, ceiling) = self.window;
        if floor == 0 || ceiling <= floor {
            return None;
        }

        // Where the cursor starts: the top of this program's window, so the
        // first reservation ends where the window does.
        let cursor = if self.map_cursor == 0 {
            ceiling
        } else {
            self.map_cursor
        };

        // A hint below the cursor and inside the window wins, because it is the
        // only thing that lets a program place two mappings adjacently.
        let usable_hint = hint >= floor && hint.is_multiple_of(paging::PAGE_SIZE);
        let start = if usable_hint && hint.checked_add(length)? <= cursor {
            hint
        } else {
            cursor.checked_sub(length)?
        };

        if start < floor {
            // The window is full.  `None` is what the caller turns into the
            // answer the program reads.
            return None;
        }
        self.map_cursor = start;
        Some(start)
    }

    /// Record where this program's window lies, for the reservation above.
    ///
    /// Called by the exec path, which is the only code that knows both numbers:
    /// the window is what `program_base` names and the image's end is what the
    /// loader computed.
    pub fn set_window(&mut self, base: usize, end: usize) {
        self.window = (base, end);
    }

    /// Where this space's `Brk` may grow from, and what a query answers.
    pub const fn brk(&self) -> usize {
        self.brk
    }

    /// Set the break, for the exec path that places a new image.
    pub fn set_brk(&mut self, brk: usize) {
        self.brk = brk;
    }

    /// Give every frame this space holds a reference to its share back, and
    /// the tables its mappings built beneath the root.
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
    /// The **tables** are a second accounting the frames array never carried.
    /// Mapping one page builds a table at each level it needs, and none of
    /// those frames is a page's — they are the walk's scaffolding, allocated
    /// by [`AddressSpace::map`] and [`walk_or_create`], recorded nowhere, and
    /// the first version of this function left every one of them behind:
    /// three frames per space on this kernel's four-level walk, measurable in
    /// the boot's free count, and one `exec`'s worth paid at runtime rather
    /// than only at the boot's end.  They are strictly per space — a fork
    /// shares frames, never tables — so freeing them needs no count.
    ///
    /// # Safety
    ///
    /// `self` must not be the installed address space: freeing the root the
    /// machine is translating through is a fault on the next instruction.
    pub unsafe fn release(self) {
        let mut guard = TABLES.lock();
        let tables = &mut *guard;
        for frame in &self.frames {
            // The protocol, in two lines: release asks whether this was the
            // last owner, and only a `true` returns the frame.  A frame no
            // fork ever shared counts zero co-owners, so its first release is
            // its last, and the ordinary path is unchanged.
            if tables.frames.release_reference(*frame) {
                let _ = tables.frames.deallocate(*frame as *mut u8, 1);
            }
        }
        // SAFETY: the walk frees only tables this space's own `map` calls
        // built, and the root is a frame this space owns; the caller promises
        // none of them is installed.
        unsafe { free_user_walk(tables, self.root) };
        let _ = tables.frames.deallocate(self.root as *mut u8, 1);
    }
}

/// Free every table a space's own mappings built beneath its root.
///
/// The kernel's entry 0 is the shared one, so the walk starts at the user
/// window's entry and takes each table it finds, deepest first.  An entry
/// that decodes as a leaf where a table was expected is skipped rather than
/// freed or followed — a block mapping is not a frame this kernel's walk
/// created, and freeing or descending into one would be a guess about memory
/// this space does not own.
///
/// The data frames behind the leaf tables are *not* freed here: they went
/// back through the co-owner counts above, and a shared frame freed a second
/// time here would be the corruption the counts exist to prevent.
///
/// # Safety
///
/// `root` must be a live root table the caller owns and nothing may be
/// translating through it or through any table beneath it.
#[cfg(target_os = "none")]
unsafe fn free_user_walk(tables: &mut Tables, root: usize) {
    // SAFETY: `root` is a live root table frame the caller owns.
    let root_table = unsafe { &*(root as *const PageTable) };
    for root_index in index(Level::Root, USER_BASE)..paging::ENTRIES_PER_TABLE {
        let word = root_table.entry(root_index);
        if word == 0 {
            continue;
        }
        let second = arch::paging::decode(word, Level::Root);
        if second.is_leaf {
            continue;
        }
        // SAFETY: an entry this kernel wrote, naming a table it allocated.
        let second_table = unsafe { &*(second.address as *const PageTable) };
        for second_index in 0..paging::ENTRIES_PER_TABLE {
            let word = second_table.entry(second_index);
            if word == 0 {
                continue;
            }
            let third = arch::paging::decode(word, Level::Second);
            if third.is_leaf {
                continue;
            }
            // SAFETY: as above.
            let third_table = unsafe { &*(third.address as *const PageTable) };
            for third_index in 0..paging::ENTRIES_PER_TABLE {
                let word = third_table.entry(third_index);
                if word == 0 {
                    continue;
                }
                // The deepest level names the leaf tables, which are the
                // frames this walk is here for; a leaf *entry* at this level
                // would be a 4 KiB page where a table was expected, and it is
                // skipped for the reason the doc gives.
                let leaf = arch::paging::decode(word, Level::Third);
                if leaf.is_leaf {
                    continue;
                }
                let _ = tables.frames.deallocate(leaf.address as *mut u8, 1);
            }
            let _ = tables.frames.deallocate(third.address as *mut u8, 1);
        }
        let _ = tables.frames.deallocate(second.address as *mut u8, 1);
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
/// The virtual address, the frame behind it, and whether the mapping allows
/// writes — everything a fork needs to know about the page it is about to
/// share, and nothing about the page tables themselves, so a caller that only
/// reads this list cannot corrupt a walk by holding a reference into it.
#[cfg(target_os = "none")]
#[derive(Debug, Clone, Copy)]
pub struct MappedPage {
    /// Where the program sees it.
    pub virtual_address: usize,
    /// The frame behind it.
    pub physical: usize,
    /// Whether the parent's mapping allowed writes, which the fork demotes
    /// and the resolver restores.
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
/// The boot's own programs map two pages each, and a loaded image maps
/// several more — segments plus a stack.  The bound rose with the loader, and
/// a program with more pages than this is one whose fork is refused rather
/// than one whose share is silently partial, which is the only other way this
/// could go wrong.
///
/// Derived from the **image** bound and not from [`MAX_OWNED_FRAMES`]: a
/// program the loader admits has to be one a `fork` can share, and those two
/// describe the same set of pages.  The ownership bound describes a different
/// set — everything a space may add at run time as well — and tying them
/// together made this a stack array of 4096 entries, 98 KiB the kernel stack
/// does not have.  Measured: raising `MAX_OWNED_FRAMES` alone took every
/// riscv64 boot down with a store page fault at the bottom of the kernel
/// stack, three frames below `USER_BASE`.
#[cfg(target_os = "none")]
pub const MAX_FORK_PAGES: usize = MAX_IMAGE_FRAMES;
