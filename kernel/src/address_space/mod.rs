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
/// What it does **not** check is that the pages are mapped.  A valid-looking
/// address into an unmapped page faults when the kernel touches it, and that
/// fault is the program's, the kernel would have to copy the page tables into
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
#[cfg(target_os = "none")]
pub use space::MappedPage;
pub use space::USER_BASE;
#[cfg(target_os = "none")]
pub use space::allocate_image_frame;
#[cfg(target_os = "none")]
pub use space::fork_from;
#[cfg(target_os = "none")]
pub use space::image_space;
#[cfg(target_os = "none")]
pub use space::map_user_page;
#[cfg(target_os = "none")]
pub use space::mapped_pages;

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
