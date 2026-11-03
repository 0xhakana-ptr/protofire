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

/// What a panic does on bare metal: say what happened, then stop.
///
/// ## Why it prints
///
/// This handler used to call `arch::halt()` and nothing else, and a boot that
/// panicked left a serial log ending mid-sentence.  Nothing distinguished "the
/// kernel halted on purpose" from "an assertion fired", which is the same
/// failure this tree keeps recording in its rules: a mechanism that runs and
/// says nothing is indistinguishable from one that did not run.
///
/// It cost a session.  A boot stopped after `pci scan found 3 device(s)` with
/// no exception and no further line, and the cause was a panic in the BAR
/// mapping whose message had nowhere to go.
///
/// ## Why printing here is safe
///
/// The console is the machine's and allocates nothing: `serial::write_str`
/// walks a `&str` and writes bytes.  A panic that happened inside the allocator
/// would recurse into this handler only if this handler allocated, and it does
/// not.
///
/// The message is a `&'static str` from `panic_fmt`, which for the
/// `panic!("literal")` and `assert!` forms in this tree is always static — but
/// `PanicInfo::message()` is not statically typed, so it goes through
/// `Display` only for the location and the piece the caller passed.
#[cfg(target_os = "none")]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    arch::serial::write_str("\nprotofire: PANIC: ");
    // The message is written without formatting machinery: `write_fmt` needs a
    // `core::fmt::Write` impl and this is the path that must not fail.
    let mut message = MessageWriter;
    let _ = core::fmt::write(&mut message, format_args!("{info}"));
    arch::serial::write_str("\n");
    arch::halt()
}

/// A `core::fmt::Write` that hands every fragment to the console.
#[cfg(target_os = "none")]
struct MessageWriter;

#[cfg(target_os = "none")]
impl core::fmt::Write for MessageWriter {
    fn write_str(&mut self, text: &str) -> core::fmt::Result {
        arch::serial::write_str(text);
        Ok(())
    }
}

/// The host build, which is a typecheck and nothing else.
#[cfg(not(target_os = "none"))]
fn main() {
    // Intentionally empty.  The image this package produces is for a machine
    // with no operating system; when built for a host there is nothing to run
    // and nothing to link, and saying so is cheaper than a `compile_error!`
    // that would make `cargo build --workspace` refuse a checkout.
}
