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
//! | [`space`] | a program's root, its pages, and the frame an image lives in |
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
/// The boot runs two and the space is four; the number is a bound on the
/// validator, not a policy about how many programs a boot may start.  A
/// program numbered past it would map above this end, and `AddressSpace::map`
/// would have to say so.
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
mod tests;
