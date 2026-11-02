//! bootloader/src/main.rs
//!
//! The image's entry point: the assembly hands control here, and this is where
//! the kernel takes over.
//!
//! ## Why this crate exists at all
//!
//! A `no_std` binary needs a `#[panic_handler]` and an entry symbol, and a
//! library can supply neither.  Keeping them here means the `kernel` crate
//! stays a library that host tests can build, while the one artifact that must
//! link on bare metal gets the things only a binary can define.
//!
//! The symbols are deliberately thin.  Everything that is a *decision* — what
//! to initialise, in what order — belongs to `kernel::kernel_main`, where a
//! test can call it.  This file only translates the handshake.

#![no_std]
#![no_main]

use core::panic::PanicInfo;

#[cfg(target_arch = "x86_64")]
core::arch::global_asm!(include_str!("boot-x86_64.S"));

/// The machine's own stop, for the paths that have nowhere left to go.
///
/// Written per architecture rather than taken from `arch`, because a panic can
/// fire before `arch` is reachable and this must not be the call that faults.
#[cfg(target_arch = "x86_64")]
fn halt_forever() -> ! {
    loop {
        // SAFETY: `hlt` in ring 0 stops the CPU until an interrupt arrives.
        // Interrupts stay disabled along every path that reaches here — the
        // boot assembly clears them at `_start` and nothing re-enables them
        // before `kernel_main` returns — so this is a stop the machine does
        // not leave, which is the intent.
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}

#[cfg(target_arch = "aarch64")]
fn halt_forever() -> ! {
    loop {
        // SAFETY: `wfi` waits for an interrupt at the current exception level.
        // Reached only after something has already failed.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
    }
}

#[cfg(target_arch = "riscv64")]
fn halt_forever() -> ! {
    loop {
        // SAFETY: `wfi` waits for an interrupt in S-mode.  See the x86_64 arm
        // for why this path exists.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
    }
}

/// What a panic does.
///
/// There is nowhere to unwind to and no console guaranteed to be up, so the
/// honest answer is to stop.  A console that is up prints through the kernel's
/// own path; a panic before that leaves the machine stopped, which is what a
/// debugger reads.
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    halt_forever()
}

/// x86_64's entry, as `boot-x86_64.S` calls it.
///
/// SAFETY: this is the symbol the assembly jumps to in long mode, with the
/// stack it built and the paging it enabled.  `extern "C"` is the calling
/// convention both sides agree on, and the two arguments are the multiboot2
/// handshake the assembly saved in its `.bss`.
#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub extern "C" fn kernel_main(multiboot_magic: u32, multiboot_info: u32) -> ! {
    kernel::kernel_main(multiboot_magic, multiboot_info)
}
