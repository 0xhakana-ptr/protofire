//! bootloader/src/main.rs
//!
//! The image's entry: what a boot does once a machine can run Rust, and the
//! order it does it in.
//!
//! ## This crate is a protocol; `arch` is the machine
//!
//! The two are different questions and this tree keeps them in different
//! crates.  A *protocol* is "a loader put us here, so now: record what it
//! said, take over the console, start the kernel".  A *machine* is "the state
//! arrived in `%eax`, the stack is at this symbol, an image links at this
//! address".  A new loader changes the first; a new machine changes the second.
//!
//! So this file holds no instruction, no register, no address and no linker
//! script.  It defines one symbol — `protofire_entry` — and the machine's entry
//! assembly calls it.  The call is a link-time reference in one
//! direction: `arch` sits below this crate, so `arch` cannot name
//! `bootloader`, and the assembly names a neutral symbol instead.  That is the
//! same inversion the layering gate exists to prevent, solved at the linker
//! rather than by an upward `use`.
//!
//! ## Why the crate exists at all
//!
//! A `no_std` binary needs a `#[panic_handler]` and it needs to be the artifact
//! that is linked; a library can be neither.  Keeping those here means the
//! `kernel` crate stays a library a host test can build.
//!
//! Everything that is a *decision* — what to initialise, in what order —
//! belongs to `kernel::kernel_main`, where a test can call it.  This file
//! translates an entry convention into that call and does nothing else.
//!
//! ## Host builds
//!
//! `cargo build --workspace` builds this package for the host too, and there
//! the bare-metal half cannot exist: `#[panic_handler]` collides with `std`'s.
//! The body is therefore gated on `target_os = "none"` and the host build is an
//! empty `main`.

#![cfg_attr(target_os = "none", no_std)]
#![cfg_attr(target_os = "none", no_main)]

#[cfg(target_os = "none")]
use core::panic::PanicInfo;

/// The image's entry, as every machine's boot assembly calls it.
///
/// The name is the protocol's and is deliberately neutral: which registers
/// held what, and which loader spoke, are the machine's business and are
/// already recorded by the time this runs.  `arch::boot_info()` reads that
/// record, so this function takes no arguments and there is nothing here for a
/// new machine to translate.
///
/// SAFETY: called from the machine's entry assembly, with a stack that assembly
/// built and in the mode it established.  `extern "C"` is the calling
/// convention both sides agree on; there are no arguments to disagree about.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub extern "C" fn protofire_entry() -> ! {
    kernel::kernel_main()
}

/// What a panic does on bare metal.
///
/// The machine's stop is `arch::halt`, which is where `hlt` and `wfi` are
/// spelled.  This is not an upward reference in disguise: `bootloader` sits
/// above `arch` and may name it, and a panic handler that had to be written
/// three times would be three more places a fourth machine has to be taught.
#[cfg(target_os = "none")]
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    arch::halt()
}

/// The host build, which is a typecheck and nothing else.
#[cfg(not(target_os = "none"))]
fn main() {
    // Intentionally empty.  The image this package produces is for a machine
    // with no operating system; when built for a host there is nothing to run
    // and nothing to link, and saying so is cheaper than a `compile_error!`
    // that would make `cargo build --workspace` refuse a checkout.
}
