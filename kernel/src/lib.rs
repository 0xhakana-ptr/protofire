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

/// x86_64's boot: the handshake is all this machine gives, and the stage is
/// what the boot does with it.
///
/// Two loaders reach this function, and the number says which.  A multiboot2
/// loader — GRUB — passes [`MULTIBOOT2_BOOTLOADER_MAGIC`] and an information
/// structure.  QEMU's `-kernel` takes the PVH path instead, where there is no
/// magic at all; the boot assembly records that as
/// [`PVH_HANDSHAKE_SENTINEL`], which no multiboot2 magic can be.
///
/// A value that is neither is checked rather than trusted.  A loader that
/// hands over something else has done something other than what either header
/// asked for, and continuing would read whatever happens to be at
/// `multiboot_info` — which on a machine that did not load us there is not
/// memory we own.
#[cfg(target_arch = "x86_64")]
pub fn kernel_main(multiboot_magic: u32, _multiboot_info: u32) -> ! {
    // The console is what makes this boot observable, so it comes first: every
    // line below is a claim, and a claim nothing can read is not evidence.
    arch::serial::init();

    let loader = match multiboot_magic {
        MULTIBOOT2_BOOTLOADER_MAGIC => "multiboot2",
        PVH_HANDSHAKE_SENTINEL => "pvh",
        other => {
            arch::serial::write_str("protofire: unknown boot handshake: magic=");
            arch::serial::write_u32(other);
            arch::serial::write_str("\n");
            halt()
        }
    };

    arch::serial::write_str("protofire 0.1.0: entered via ");
    arch::serial::write_str(loader);
    arch::serial::write_str(", console up, stage ");
    arch::serial::write_u32(BootStage::ConsoleUp as u32);
    arch::serial::write_str("\n");

    halt()
}

/// The magic a multiboot2 loader passes in `%eax`.
#[cfg(target_arch = "x86_64")]
pub const MULTIBOOT2_BOOTLOADER_MAGIC: u32 = 0x36D7_628D;

/// What the boot assembly records when the PVH note brought it up.
///
/// There is no handshake on that path, so the assembly writes a value a
/// multiboot2 loader could never produce; `u32::MAX` is not a magic any loader
/// passes, and treating it as one would be worse than the sentinel.
#[cfg(target_arch = "x86_64")]
pub const PVH_HANDSHAKE_SENTINEL: u32 = 0xFFFF_FFFF;

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
