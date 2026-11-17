//! kernel/src/address_space/mod.rs
//!
//! Paging: the kernel's own table, a program's address space, and the rules the
//! two share.
//!
//! ## The files
//!
//! | File | What it holds |
//! |---|---|
//! | [`table`] | the kernel's tables, the identity map, and the walk that re-maps one |
//! | [`space`] | a program's root, its pages, the frames a fork shares, and the image an exec builds into the window it keeps |
//! | this file | the permission rules, the user window, the install, and the pool's counts |
//!
//! Where this image's sections begin and end is the linker script's answer, and
//! the rules for them are this kernel's policy.  Which addresses are a device's
//! registers is the **machine's** answer, `arch::paging::device_windows`,
//! because an x86_64 finds its devices on a bus and a device-tree machine knows
//! their addresses from the platform, and a kernel that spelled either would be
//! naming a machine.

#[cfg(any(target_os = "none", test))]
use paging::Permissions;

/// How much of the user window one program owns.
///
/// A gigabyte, which is what `process::program_base` spaces programs by.  The
/// number is here rather than there because this is the module that knows what
/// a user address is, and a validator with its own copy would be a second
/// opinion about the same fact.
pub const USER_WINDOW: usize = 0x4000_0000;

/// How many programs the window has room for.
///
/// The boot runs three, a fork adds a child, and the space is four; the number
/// is a bound on the validator, not a policy about how many programs a boot
/// may start.  A program numbered past it would map above this end, and
/// `AddressSpace::map` would have to say so.
pub const USER_WINDOWS: usize = 4;

/// The first address above the user window.
pub const USER_LIMIT: usize = USER_BASE + USER_WINDOW * USER_WINDOWS;

/// Whether `address` is one a program of this kernel could have mapped.
///
/// A pointer from ring 3 is a number, and a number is not an address: the
/// kernel must not dereference one because the program said so.  Three things
/// have to hold together, and this checks all three:
///
/// 1. The range is the user window, `USER_BASE` up to a program's end, so a
///    program cannot hand the kernel a kernel address and have it written to.
/// 2. The range does not wrap.  `start + length` overflows for an address near
///    the top, and a wrapped end would pass a naive `end > start` test.
/// 3. The whole range is inside the window, not merely its start.  A read of
///    one byte at the last valid address is fine; a read of four that crosses
///    the boundary is not.
///
/// What it does **not** check is that the pages are mapped, and it is not the
/// check a call should use.  `user_range` is: it does the arithmetic here and
/// then asks the page tables, which is the difference between "a number this
/// kernel could have mapped" and "a page this program has".  This function
/// remains because the arithmetic is exactly what a host can test, and because
/// one caller, the loader, validates an address before any space exists to
/// walk.
pub fn is_user_range(address: usize, length: usize) -> bool {
    let Some(end) = address.checked_add(length) else {
        return false;
    };
    address >= USER_BASE && end <= USER_LIMIT
}

/// Whether every page `address` through `address + length` touches is one the
/// running task actually has, for the access `write` names.
///
/// This is the check a handler calls before it turns a ring-3 word into a
/// borrow, and it is two questions in one function on purpose:
///
/// 1. the window arithmetic, [`is_user_range`], which refuses a kernel address,
///    a wrapping range and a range that crosses the window's end;
/// 2. a walk of **the running task's own root**, one page at a time, which
///    refuses an address that is inside the window and mapped to nothing.
///
/// The second question is the one that was missing.  `is_user_range` alone let
/// a program pass any number in a gigabyte of address space that happened to be
/// unmapped, and the kernel then dereferenced it; `interrupts::handle` has no
/// kernel-mode arm, so the fault stopped the machine.  A walk costs the page
/// tables and answers the program's mistake with `InvalidArgument`, which is a
/// number the ABI defines and a program can act on.
///
/// A **write** is allowed on a page the table marks writable and on one the
/// pool marks copy-on-write, which is a read-only entry a fork left: the fault
/// that write would take is the recoverable one.  A read needs only a mapped,
/// user-reachable page.
///
/// `false` also answers "no root is installed", which is a call made before any
/// program ran.  The boot's own calls pass real addresses into the boot's own
/// memory and do not come through here.
///
/// A host build has no page tables and no root register, so the walk is the
/// target's; the window arithmetic is not, which is why this function compiles
/// everywhere and answers the window's question on a host.  That keeps the
/// handlers that call it buildable in a `cargo test --workspace`, which is what
/// noticed the difference: a `target_os` gate here made four handlers fail to
/// compile on the host, and they are ordinary code that happens to take a
/// pointer.
pub fn user_range(address: usize, length: usize, write: bool) -> bool {
    if !is_user_range(address, length) {
        // A range outside the window is a program that computed an address
        // wrongly, and the line names it rather than leaving a reader to infer
        // which call refused what.  This is the failure path of a check that is
        // on every buffer-taking syscall, so the line is printed only when the
        // answer is `false`: a boot that never prints it made no illegal call.
        #[cfg(target_os = "none")]
        {
            arch::serial::write_str("protofire: refused a pointer outside the user window at ");
            arch::serial::write_hex(address as u64);
            arch::serial::write_str("\n");
        }
        return false;
    }
    // A zero-length range has no page to walk and is trivially the caller's.
    // It is admitted here rather than by every caller, because a read of zero
    // bytes from an unmapped address is not a memory access at all.
    if length == 0 {
        return true;
    }
    #[cfg(not(target_os = "none"))]
    {
        // A host has no page tables to walk, so the window's answer is the
        // whole of what this build can say.  The tests below exercise the
        // arithmetic; the walk is the target's and is exercised by a boot.
        let _ = write;
        true
    }
    #[cfg(target_os = "none")]
    {
        let Some(root) = arch::installed_root_table() else {
            return false;
        };
        let guard = TABLES.lock();
        if table::range_allowed(&guard, root, address, length, write) {
            return true;
        }
        // The window test passed and the walk refused, which is the case this
        // function was added for: an address a program could have mapped and
        // did not.  The line is printed only on the refusal path, so a boot
        // that made no illegal call prints nothing here, and a boot that made
        // one names the address instead of stopping at a fault in the kernel.
        arch::serial::write_str("protofire: refused a pointer to an unmapped page at ");
        arch::serial::write_hex(address as u64);
        arch::serial::write_str(if write {
            ", for a write\n"
        } else {
            ", for a read\n"
        });
        false
    }
}

/// Visit each page a range touches, answering whether every visit said yes.
///
/// A free function over a predicate rather than a loop in the walk, for the
/// reason [`permissions_at`] is one: a host has no page tables, and the
/// arithmetic that decides *which* pages a range names is the part that can be
/// wrong in a way no walk would catch, a range that walks one page too few at a
/// boundary, or one that loops for ever on a length near `usize::MAX`.
///
/// The last page is the one holding `address + length - 1`, so a range ending
/// exactly on a page boundary does not visit the page after it.
///
/// Compiled for the target and for the tests, and nowhere else: the target's
/// walk is its one production caller, and a host's only reader is the test
/// below.  A host build with no test would have this function and no caller,
/// which is what the lint says, and a `#[cfg(any(target_os = "none",
/// test))]` is the honest description of who uses it.
#[cfg(any(target_os = "none", test))]
pub(crate) fn every_page(
    address: usize,
    length: usize,
    mut visit: impl FnMut(usize) -> bool,
) -> bool {
    let Some(end) = address.checked_add(length) else {
        return false;
    };
    if length == 0 {
        return true;
    }
    let mut page = address & !(paging::PAGE_SIZE - 1);
    let last = (end - 1) & !(paging::PAGE_SIZE - 1);
    loop {
        if !visit(page) {
            return false;
        }
        if page == last {
            return true;
        }
        page += paging::PAGE_SIZE;
    }
}

/// The address of a linker symbol, by name.
///
/// The five names are the linker script's own, and a name that is not one of
/// them is a call this module does not make: the match has no fallthrough, so a
/// typo is a compile error rather than a wrong address.
#[cfg(target_os = "none")]
pub(crate) fn symbol(name: Symbol) -> usize {
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
/// name still marks where its section ends, but a variant is a *reader* of
/// one, and this enum has only the readers there are.
#[cfg(target_os = "none")]
#[derive(Clone, Copy)]
pub(crate) enum Symbol {
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
pub(crate) struct Rule {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) permissions: Permissions,
}

/// The permission an address has, given the rules.
///
/// A free function over a slice rather than one that reads the linker's symbols
/// itself: the rules are the kernel's answer and the ranges are the image's,
/// and separating them is what lets a host test give the function ranges it can
/// see.  A host has no linker script and therefore no `__text_start`, so a
/// function that read one could not be tested at all.
#[cfg(any(target_os = "none", test))]
pub(crate) fn permissions_at(rules: &[Rule], address: usize) -> Permissions {
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
/// **machine's** answer, `arch::paging::device_windows`, because an x86_64
/// finds its devices on a bus and a device-tree machine knows their addresses
/// from the platform, and a kernel that spelled either would be naming a
/// machine.
#[cfg(target_os = "none")]
pub(crate) fn image_rules() -> ([Rule; 2], arch::paging::Windows) {
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
pub(crate) fn permissions_for(
    rules: &[Rule],
    windows: &[(usize, usize)],
    address: usize,
) -> Permissions {
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
    // The lock is taken and dropped inside this call: `build` and the machine's
    // `install` both need to see a complete table, and neither is re-entered.
    let mut guard = TABLES.lock();
    let tables = &mut *guard;

    // Frames for the tables past the spare ones.
    //
    // The pool is a linker-reserved span and the machine's answer clamps it: a
    // machine whose RAM ends inside the span must manage only the frames that
    // are really there, and one that managed the whole span would hand out
    // pages past the end of memory.  `managed_pool_bytes` is that answer, and
    // `None` means the machine cannot say, then the span is all there is.
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
    TABLES.lock().frames.total_frames()
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

/// How many page tables came from the frame pool.
///
/// Zero on a boot whose spares were enough, which is the honest state of this
/// kernel rather than a failure, and the number that says whether the frame
/// allocator is exercised by a boot or only by its tests.
#[cfg(target_os = "none")]
pub fn frames_taken_for_tables() -> usize {
    TABLES.lock().frames_taken
}

/// How many of those frames can still be handed out.
///
/// The recycled holes plus the bump tail.  `free_frames` alone counts only the
/// holes, which is zero on a pool nothing has been freed from and reads as "no
/// memory left", the opposite of the truth on a fresh boot.
#[cfg(target_os = "none")]
pub fn free_frames() -> usize {
    let tables = TABLES.lock();
    tables.frames.free_frames() + tables.frames.available_frames()
}

/// Run `f` over the frame pool, with the page-table lock held.
///
/// The one way a caller outside this module can count a reference on a frame
/// without owning the tables: shared memory adds a reference per attach and
/// drops one per detach, and both are the pool's bookkeeping rather than a
/// mapping.  The lock is the same one every other pool operation takes, so the
/// order a caller has to keep is the order this file already states: page
/// tables first and nothing else inside.
///
/// A caller that maps or unmaps a page inside `f` would be taking the lock
/// twice, which is why the closure receives the allocator and not the tables.
#[cfg(target_os = "none")]
pub(crate) fn with_pool<R>(f: impl FnOnce(&mut memory::FrameAllocator) -> R) -> R {
    let mut tables = TABLES.lock();
    f(&mut tables.frames)
}

/// Give one frame back to the pool, answering whether it went.
///
/// Only for a caller the pool has already told it holds the last reference.
/// The `deallocate` refuses a frame that is free, is not in the pool, or has a
/// co-owner left, so a caller that gets this wrong is refused rather than
/// corrupting the pool, and the `false` is what such a bug looks like.
///
/// # Safety
///
/// The frame must not be mapped by any page table this kernel can still walk:
/// freeing one that is hands the same memory to the next caller while a
/// program reads through an address that names it.
#[cfg(target_os = "none")]
pub(crate) unsafe fn free_frame(frame: usize) -> bool {
    let mut tables = TABLES.lock();
    // The pool's own `deallocate` is not `unsafe`: the safety of a double free
    // is held by the reference count, which refuses a frame that still has an
    // owner.  What makes *this* function `unsafe` is the page-table side, which
    // no count can see.
    tables.frames.deallocate(frame as *mut u8, 1)
}

pub mod space;
pub mod table;

#[cfg(target_os = "none")]
pub(crate) use space::resolve_copy_on_write;
#[cfg(target_os = "none")]
use table::TABLES;
#[cfg(target_os = "none")]
use table::build;
#[cfg(target_os = "none")]
pub use table::map_device;
#[cfg(target_os = "none")]
pub use table::map_region;
#[cfg(target_os = "none")]
pub(crate) use table::permissions_of;

#[cfg(target_os = "none")]
pub use space::AddressSpace;
#[cfg(target_os = "none")]
pub use space::MAX_FORK_PAGES;
#[cfg(target_os = "none")]
pub use space::MAX_IMAGE_FRAMES;
pub use space::MAX_OWNED_FRAMES;
#[cfg(any(target_os = "none", test))]
pub use space::MappedPage;
pub use space::USER_BASE;
#[cfg(target_os = "none")]
pub use space::allocate_image_frame;
#[cfg(test)]
pub(crate) use space::count_writable_executable;
#[cfg(target_os = "none")]
pub use space::fork_from;
#[cfg(target_os = "none")]
pub use space::image_space;
#[cfg(target_os = "none")]
pub use space::mapped_pages;
#[cfg(target_os = "none")]
pub use space::writable_executable_pages;

#[cfg(test)]
mod tests {
    //! The tests for this module.
    //!
    //! The permission rules' tests: what each section is for, that a device
    //! window wins over an image rule, and the user window that refuses what is
    //! not in it.

    use super::Rule;
    use super::permissions_at;
    use super::permissions_for;
    use paging::Cache;
    use paging::Permissions;

    #[cfg(target_os = "none")]
    use paging::PAGE_SIZE;

    /// The rules a host test can see, standing in for an image's linker
    /// script.
    ///
    /// The numbers are made up and the *shape* is what the image has: text
    /// first, then read-only data, then writable data, a `BTreeMap` of ranges
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
    ///, `__text_end` and `__rodata_start` are the same address, and a rule
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
    /// `0x4000_0000`, where RAM begins, is not.
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
    /// device, which is not a state a permission rule can repair, but the
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

    /// A range visits exactly the pages it touches, and no others.
    ///
    /// This is the arithmetic half of [`super::user_range`], and the four cases
    /// below are the four ways it can be off by one:
    ///
    /// - one byte in the middle of a page visits that page only;
    /// - a range ending **on** a boundary does not visit the page after it,
    ///   which is the classic off-by-one and would refuse a legal buffer whose
    ///   length happens to be a page multiple;
    /// - a range starting at an offset and crossing the boundary visits two;
    /// - a zero-length range visits nothing at all, which a loop that computed
    ///   its last page without checking would turn into a wrap to page zero.
    ///
    /// The page numbers are counted as well as checked, because "the right
    /// pages were visited" and "the right number of pages were visited" are
    /// different claims and the second is what a range check needs.
    #[test]
    fn a_range_visits_the_pages_it_touches_and_no_others() {
        use super::every_page;
        use paging::PAGE_SIZE;

        const BASE: usize = 0x80_0000_0000;

        let mut seen = alloc::vec::Vec::new();
        assert!(every_page(BASE + 0x100, 0x10, |page| {
            seen.push(page);
            true
        }));
        assert_eq!(seen, [BASE], "one byte in the middle of a page");

        let mut seen = alloc::vec::Vec::new();
        assert!(every_page(BASE, PAGE_SIZE, |page| {
            seen.push(page);
            true
        }));
        assert_eq!(
            seen,
            [BASE],
            "a range ending on a boundary stops at the page it ends in"
        );

        let mut seen = alloc::vec::Vec::new();
        assert!(every_page(BASE + PAGE_SIZE - 1, 2, |page| {
            seen.push(page);
            true
        }));
        assert_eq!(
            seen,
            [BASE, BASE + PAGE_SIZE],
            "a range crossing a boundary visits both pages"
        );

        let mut visited = 0;
        assert!(every_page(BASE, 0, |_| {
            visited += 1;
            true
        }));
        assert_eq!(visited, 0, "a zero-length range touches nothing");

        // A refusal stops the walk: the predicate is the answer and a range
        // whose third page is bad must not be walked further.
        let mut visited = 0;
        assert!(!every_page(BASE, PAGE_SIZE * 4, |_| {
            visited += 1;
            visited < 3
        }));
        assert_eq!(visited, 3, "the walk stopped at the page that refused");
    }

    /// A range that overflows visits nothing, rather than looping for ever.
    ///
    /// `address + length` overflows near the top of the address space, and an
    /// unchecked `end - 1` there is the largest possible "last page": the loop
    /// would climb from the start to that, wrapping, and never reach it.
    ///
    /// The second assertion is the one that keeps this test honest about what
    /// it covers: `USER_LIMIT - 1 + 8` does **not** overflow, because the user
    /// window ends far below `usize::MAX`, so the walk visits those pages and
    /// refusing them is the window check's job and not this one's.  The two
    /// questions are separate, which is why [`super::user_range`] asks the
    /// window first.
    #[test]
    fn a_wrapping_range_visits_nothing() {
        use super::every_page;
        assert!(!every_page(usize::MAX - 1, 8, |_| true));

        let mut visited = 0;
        assert!(every_page(super::USER_LIMIT - 1, 8, |_| {
            visited += 1;
            true
        }));
        assert_eq!(visited, 2, "no overflow here, so the pages are walked");
        assert!(
            !super::is_user_range(super::USER_LIMIT - 1, 8),
            "and the window is what refuses the range; the walk cannot"
        );
    }

    /// The W^X count is of pages that are **both**, not of one bit or the
    /// other.
    ///
    /// The rule `SECURITY.md` states is a conjunction: a page that is writable
    /// and executable is refused.  A counter that tested either bit alone would
    /// report a program's whole text as a violation (read-execute) or its whole
    /// data and stack (read-write) and be useless, and a counter that tested
    /// `||` would have found the defect everywhere instead of where it was.
    ///
    /// The three pairs below are the three meanings a user page can have, and
    /// the fourth, `false`/`false`, is a read-only page, which is text that has
    /// not been marked executable and is not a violation either.
    #[test]
    fn only_a_page_that_is_both_is_counted() {
        use super::MappedPage;
        use super::count_writable_executable;

        let page = |writable, executable| MappedPage {
            virtual_address: super::USER_BASE,
            physical: 0x1000,
            writable,
            executable,
        };

        assert_eq!(
            count_writable_executable(&[page(true, true)]),
            1,
            "the one pair the rule refuses"
        );
        assert_eq!(
            count_writable_executable(&[page(true, false)]),
            0,
            "a stack or a data segment is not a violation"
        );
        assert_eq!(
            count_writable_executable(&[page(false, true)]),
            0,
            "text is not a violation"
        );
        assert_eq!(
            count_writable_executable(&[page(false, false)]),
            0,
            "a read-only page is not a violation"
        );

        // And the count is a count, not a boolean: two violating pages beside
        // three legal ones answer 2.  A version that stopped at the first would
        // pass the single-page assertions above.
        assert_eq!(
            count_writable_executable(&[
                page(true, true),
                page(true, false),
                page(true, true),
                page(false, true),
                page(false, false),
            ]),
            2
        );
    }

    /// A machine with no device windows behaves exactly as it did before the
    /// question was asked.
    ///
    /// x86_64 answers with an empty slice, it has no fixed peripheral
    /// window, so this is that machine's case, and the assertion is that
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
