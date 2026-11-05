//! kernel/src/boot_pages.rs
//!
//! The page table, as the boot installs and reports it.
//!
//! ## Why this is separate from `pages`
//!
//! `pages` is the *mechanism*: what a table is, how a walk finds an
//! entry, how a program's space borrows the kernel's.  This module is the
//! boot's *step*: install the table once, report the frames behind it, and
//! exercise the allocator's branch that a healthy boot never reaches.  A reader
//! asking "what does the boot do about paging" reads this; a reader asking "how
//! does a walk work" reads `pages`.

/// Install the kernel's table, and say what happened.
///
/// The assembly's table maps four gigabytes identity with 2 MiB pages, every
/// one writable and cached — the smallest thing that lets Rust run, and wrong
/// for everything after.  This builds a second table with the same translations
/// at a 4 KiB granule, so text is read-execute, read-only data is read, and the
/// kernel's own state is read-write.  Every address the boot already touched
/// translates the same, which is what makes the swap invisible.
///
/// It runs before the heap because the table's backing is a static array rather
/// than allocated frames — a table built from frames would have to be built
/// before the thing that hands them out.
///
/// # Safety
///
/// Called once, from the kernel's entry, with the console up so a failure past
/// this point is visible.  The table it installs covers the code performing the
/// install.
pub unsafe fn install() {
    #[cfg(target_os = "none")]
    {
        arch::serial::write_str("protofire: page table ");
        // SAFETY: the caller's contract is this function's.
        let installed = unsafe { crate::address_space::install() };
        if installed {
            arch::serial::write_str("built and installed, 4 KiB granule\n");
        } else {
            arch::serial::write_str("was already installed\n");
        }

        report_frame_pool();
    }
    #[cfg(not(target_os = "none"))]
    arch::serial::write_str("not installed (a host has no address space to install)\n");
}

/// Report the frames behind the table, and exercise the allocator once.
///
/// Printed here rather than beside the heap because it is the page table's
/// input: a boot that managed a pool larger than RAM would map a device window
/// into memory that is not there, and the line is how that shows.
///
/// The allocator is **exercised** rather than described.  The count of tables
/// taken from frames is zero on a real boot — the spare tables are enough — so
/// the branch that asks the allocator for a table has never run.  A count of
/// zero is honest and is not evidence, and this tree's recurring defect is code
/// that is written, wired and never executed.
#[cfg(target_os = "none")]
fn report_frame_pool() {
    arch::serial::write_str("protofire: frame pool ");
    arch::serial::write_u32(crate::address_space::managed_frames() as u32);
    arch::serial::write_str(" frame(s), ");
    arch::serial::write_u32(crate::address_space::free_frames() as u32);
    arch::serial::write_str(" free, ");
    arch::serial::write_u32(crate::address_space::frames_taken_for_tables() as u32);
    arch::serial::write_str(" in page tables");

    // SAFETY: the pool is initialised and nothing else has allocated from it;
    // the frame is released before the call returns.
    let pool_ok = unsafe { crate::address_space::self_check_frame_pool() };
    arch::serial::write_str(if pool_ok {
        ", pool check ok\n"
    } else {
        ", pool check FAILED\n"
    });
}
