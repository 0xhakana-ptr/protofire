//! kernel/src/lib.rs
//!
//! The kernel: the modules that are not a crate of their own, the allocator
//! that makes them allocatable, and the names a caller spells.
//!
//! ## What lives here
//!
//! A subsystem becomes a crate when something else needs to name it without
//! naming the kernel.  `fs`, `memory`, `net`, `ipc` and `power` are crates for
//! that reason, they are asked questions by `syscall`, by drivers, and by each
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
//! | [`per_cpu`] | which CPUs exist, which one is running, and what each has seen |
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
pub mod per_cpu;
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
/// "nothing was printed" is not a diagnosis, it covers a bad image, a bad
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

/// How many console interrupts this boot has taken.
///
/// The count is what makes the claim path a fact about a boot rather than
/// about the code: a source enabled at the controller and never taken leaves
/// it zero.
pub static CONSOLE_INTERRUPTS: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(0);

/// Whether an interrupt number belongs to the console.
#[cfg(target_os = "none")]
pub fn console_owns(vector: usize) -> bool {
    arch::console_source().is_some_and(|source| source == vector)
}

/// Count one console interrupt.
#[cfg(target_os = "none")]
pub fn note_console_interrupt() {
    CONSOLE_INTERRUPTS.fetch_add(1, core::sync::atomic::Ordering::Release);
}

/// Stop this CPU.
///
/// Delegated to the architecture crate: the instructions belong there, and this
/// file naming `hlt` would be the exact leak `arch` exists to prevent.  A `->
/// !` function that only stops is `pub` because every later stage, the idle
/// loop, a panic, an unhandled exception, ends here rather than each writing
/// its own stop.
pub fn halt() -> ! {
    arch::halt()
}

/// Whether the boot is over, as every CPU can see it.
///
/// A `halt` stops **one** CPU, and a machine with two of them does not stop
/// when one does: the boot's last program exits on whichever CPU ran it, and
/// the other was in `wait_for_work` or inside a program at that instant.  A
/// CPU left running after the scheduler is done is a CPU that resumes a task
/// whose pages have been reaped, which showed as an `illegal instruction` at
/// a program address **after** `every program exited`.
///
/// So the boot says it is over once, and every CPU that looks at this flag
/// stops itself.
#[cfg(target_os = "none")]
pub static FINISHED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Record that the boot is over and stop this CPU.
///
/// ## Two different stops, which were one and are now two
///
/// A CPU whose own queue is empty is **idle**: it stops itself, and the
/// machine carries on with the CPUs that still have work.  A CPU that reaches
/// here has decided the machine is finished: every task is gone, and every
/// CPU should stop.
///
/// Conflating them was the defect a first attempt made: a CPU that found
/// nothing to run after its *own* last exit set the flag, the other CPU saw it,
/// and the boot ended with programs that had not run.  So this sets the flag
/// and stops, and [`idle_this_cpu`] does neither.
///
/// The other CPUs see [`FINISHED`] at their next trap or their next look, and
/// stop on their own: nothing can stop a CPU that is mid-instruction, and the
/// only way to stop one is its own `wfi`.
#[cfg(target_os = "none")]
pub fn finish_and_halt() -> ! {
    FINISHED.store(true, core::sync::atomic::Ordering::Release);
    arch::halt()
}

/// Stop this CPU only, leaving the machine running.
///
/// The idle a CPU does when its own queue is empty but the machine still has
/// tasks: another CPU is running one, and this one has nothing to claim.  The
/// halt is this CPU's `wfi`, and nothing is recorded.
///
/// ## Why this exists beside `halt`
///
/// `halt` was the only stop this tree had, and every exit path used it, which
/// was correct with one CPU because that CPU was the machine.  A second CPU
/// makes the difference load-bearing: a CPU that stopped the whole machine
/// because *it* had no work ended the boot early.  This is the same instruction
/// with a different statement attached to it, and the statement is the point.
#[cfg(target_os = "none")]
pub fn idle_this_cpu() -> ! {
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
