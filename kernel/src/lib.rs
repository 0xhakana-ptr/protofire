//! kernel/src/lib.rs
//!
//! The kernel: the modules that are not a crate of their own, the allocator
//! that makes them allocatable, and the names a caller spells.
//!
//! ## What lives here
//!
//! A subsystem becomes a crate when something else needs to name it without
//! naming the kernel.  `fs`, `memory`, `net`, `ipc` and `power` are crates for
//! that reason — they are asked questions by `syscall`, by drivers, and by each
//! other, and a crate boundary is what makes "who may name whom" a compiler
//! error rather than a convention.
//!
//! What stays in this crate is what only the kernel core organises.  Each
//! subject is a module of its own, and this file is the index:
//!
//! | Module | What it is |
//! |---|---|
//! | [`boot`] | the order a machine comes up in, once |
//! | [`console`] | what the boot says about its handshake, and the allocator's sink |
//! | [`boot_pages`] | the page table, as the boot installs and reports it |
//! | [`address_space`] | paging itself: the identity map, a program's space, the permission rules |
//! | [`cpus`] | the machine's other CPUs, started and counted |
//! | [`heap`] | the heap, brought up and located |
//! | [`volume`] | the storage, the namespace, and the read that proves them |
//! | [`policy`] | the MAC policy, asked both ways through the real handler |
//! | [`tick`] | the timer's line, its slice and its count |
//! | [`programs`] | the programs the boot builds, maps and enters |
//! | [`interrupts`] | what an interrupt frame means to the kernel |

//! | [`scheduler`] | the tasks, their states, and the switch |
//! | [`process`] | what a program's supervisor call does |
//! | [`pipe`] | the pipe's endpoints and the table that holds them |
//! | [`syscall`] | the registry and the handlers a boot serves |
//! | [`devices`] | finding a device on the bus |
//! | [`iso_disc`] | the disc image the boot builds |
//!
//! ## The one thing that has to be here
//!
//! The `#[global_allocator]`.  `libs/allocator` deliberately does not install
//! one: a library that did could not be a dependency of a test binary, and two
//! global allocators is a link error.  But something has to install one before
//! the first `Vec`, and this is the crate that knows it is a kernel.

#![no_std]

// The boot builds a filesystem image in memory and mounts it, and both need a
// heap.  The `#[global_allocator]` below is what provides one, so this line and
// that static arrived together: an `alloc` without an allocator is a link
// error, and an allocator nobody allocates from is a heap with no caller.
extern crate alloc;

pub mod address_space;
pub mod boot;
pub mod boot_pages;
pub mod console;
pub mod cpus;
pub mod devices;
pub mod heap;
pub mod interrupts;
pub mod iso_disc;
pub mod pipe;
pub mod policy;
pub mod process;
pub mod programs;
pub mod scheduler;
pub mod syscall;
pub mod tick;
pub mod volume;

// The heap's global allocator, installed here because this is the crate that
// knows it is a kernel.
//
// SAFETY: `KernelGlobalAllocator` implements `GlobalAlloc` with every method
// taking `&self` and reaching its state only through a lock, so it is safe to
// share as the process-wide allocator.  Its arena is a `static` array and its
// free lists are laid out on the first call.
#[cfg(target_os = "none")]
#[global_allocator]
static GLOBAL_ALLOCATOR: allocator::KernelGlobalAllocator = allocator::KernelGlobalAllocator::new();

/// The stage a boot has reached, as one word, for a log line that cannot yet
/// afford to be wrong.
///
/// This exists so the first thing the kernel does is observable.  A machine
/// that dies before its console is up otherwise leaves nothing behind, and
/// "nothing was printed" is not a diagnosis — it covers a bad image, a bad
/// stack, a bad page table, and a correct kernel that has not been written yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BootStage {
    /// The handshake arrived; nothing has been touched.
    Entered = 0,
    /// The machine's serial port, if it has one, is writing.
    ConsoleUp = 1,
}

/// What the bootloader handed over.
///
/// Defined in `abi` rather than here: the architecture crate parses the
/// handshake and the kernel consumes it, so a type either side has to name
/// belongs where both can reach it.  The re-export keeps the spelling this
/// crate's callers use.
pub use abi::BootInfo;
pub use abi::Loader;

/// The kernel's entry, as every machine's boot assembly calls it.
///
/// Defined in [`boot`], and re-exported at the root because it is the one name
/// `bootloader` is written against: that crate is a protocol and must not have
/// to know how this one arranges its modules.  Everything else the boot does is
/// reachable through [`boot`] and nowhere else.
pub use boot::kernel_main;

/// Stop this CPU.
///
/// Delegated to the architecture crate: the instructions belong there, and this
/// file naming `hlt` would be the exact leak `arch` exists to prevent.  A `->
/// !` function that only stops is `pub` because every later stage — the idle
/// loop, a panic, an unhandled exception — ends here rather than each writing
/// its own stop.
pub fn halt() -> ! {
    arch::halt()
}

#[cfg(test)]
mod tests {
    use super::BootStage;

    /// The stage values are written into a log line, so their discriminants are
    /// part of what a reader sees.  A reordering that changed them would make
    /// every previously captured log a lie without failing to compile.
    #[test]
    fn boot_stages_keep_their_values() {
        assert_eq!(BootStage::Entered as u32, 0);
        assert_eq!(BootStage::ConsoleUp as u32, 1);
    }
}
