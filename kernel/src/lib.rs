//! kernel/src/lib.rs
//!
//! The kernel's core: the subsystems that are not a crate of their own.
//!
//! ## What lives here, and what does not
//!
//! A subsystem becomes a crate when something else needs to name it without
//! naming the kernel.  `fs`, `memory` and `net` are crates for that reason —
//! they are asked questions by `syscall`, by drivers, and by each other, and a
//! crate boundary is what makes "who may name whom" a compiler error rather
//! than a convention.  What stays here is what only the kernel core organises:
//! scheduling, IPC, power, and the boot sequence that puts them in order.
//!
//! ## The boot sequence
//!
//! `kernel_main` is the whole of the ordering decision, and it is a function a
//! host test can call.  The bootloader's contribution is the handshake and the
//! two symbols a `no_std` binary must define; nothing about *what order* lives
//! there.

#![no_std]

// No `extern crate alloc` yet, and the absence is deliberate: declaring it
// commits the final image to a `#[global_allocator]`, and `libs/allocator` is
// still a stub.  A binary that names `alloc` without one fails to link with an
// error about a missing global allocator — which is the correct complaint, but
// it would be answered by writing an allocator to satisfy the compiler rather
// than because something needs to allocate.  The line comes back in the change
// that gives the allocator a real body.

pub mod ipc;
pub mod power;
pub mod scheduler;

/// The stage a boot has reached, as one word, for a log line that cannot yet
/// afford to be wrong.
///
/// This exists so the first thing the kernel does is observable.  A machine
/// that dies before its console is up otherwise leaves nothing behind, and
/// "nothing was printed" is not a diagnosis — it covers a bad image, a bad
/// stack, a bad page table, and a correct kernel that has not been written
/// yet.
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

/// The boot, from the point where a machine is up to the point where it stops.
///
/// This takes a [`BootInfo`] rather than a loader's registers: parsing the
/// handshake is the architecture's business, and the previous tree's entry took
/// x86_64's convention for the whole tree's.  A new machine supplies its own
/// `arch::boot_info()` and nothing here changes.
///
/// The console is what makes this boot observable, so it comes first: every
/// line below is a claim, and a claim nothing can read is not evidence.
pub fn kernel_main() -> ! {
    arch::serial::init();

    // The heap's diagnostics go to the same console, and this is where that is
    // decided.  `allocator` reports through a sink it is handed rather than
    // through a kernel macro, which is what lets its tests run on a host; the
    // price is this line, and a boot that omitted it would lose every
    // allocation-failure message without failing anything.
    //
    // SAFETY: `write_to_console` is a `fn(&str)` that writes the UART and
    // allocates nothing — required, because the allocator may call it from
    // inside a failed allocation.
    unsafe { allocator::diag::set_writer(Some(write_to_console)) };

    let boot = arch::boot_info();

    arch::serial::write_str("protofire 0.1.0: entered via ");
    arch::serial::write_str(boot.loader.as_str());
    arch::serial::write_str(", console up, stage ");
    arch::serial::write_u32(BootStage::ConsoleUp as u32);
    arch::serial::write_str("\n");

    // Initialise the heap and say where it is.
    //
    // This is not a probe left behind: `bounds()` is what makes the allocator
    // lay out its free lists, so a boot that did not call it would hand out
    // memory from a heap with no free list at all.  The line is how that
    // arrangement becomes observable — and how the allocator's diagnostic sink
    // is proven to reach the console, because the sink and this line are the
    // same path.
    let heap = allocator::HeapAllocator::new();
    let (heap_start, heap_end) = heap.bounds();
    arch::serial::write_str("protofire: heap at ");
    arch::serial::write_hex(heap_start as u64);
    arch::serial::write_str("..");
    arch::serial::write_hex(heap_end as u64);
    arch::serial::write_str("\n");

    halt()
}

/// The allocator's diagnostic sink: the console, one string at a time.
///
/// A free function rather than a closure because `set_writer` takes a `fn`, and
/// because this is the one place the allocator's output and the machine's
/// console are joined — naming it makes that join visible in a search.
fn write_to_console(text: &str) {
    arch::serial::write_str(text);
    arch::serial::write_str("\n");
}

/// Stop this CPU.
///
/// Delegated to the architecture crate: the instructions belong there, and
/// this file naming `hlt` would be the exact leak `arch` exists to prevent.
/// A `-> !` function that only stops is `pub` because every later stage — the
/// idle loop, a panic, an unhandled exception — ends here rather than each
/// writing its own stop.
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
