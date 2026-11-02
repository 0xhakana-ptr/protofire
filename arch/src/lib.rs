//! arch/src/lib.rs
//!
//! The one crate the rest of the kernel names when it has to ask the machine
//! something.  It holds no implementation of its own: each architecture is a
//! crate beside it, and this file is the route between them.
//!
//! ## Exactly one architecture, and the compiler says so
//!
//! A feature per machine, and a build selects one.  Two selected at once used
//! to compile — the re-exports simply merged, and both machines' symbols
//! answered to the same names — which is the failure this guard exists to make
//! impossible.  It is not a style rule: with two architectures linked into one
//! image, `halt()` is whichever crate won, and nothing in the build says which.
//!
//! Selecting none is refused for the same reason in the other direction: a
//! kernel with no architecture has no `halt`, no page table, and no trap, and
//! the error a caller would get for that is a wall of unresolved names rather
//! than the sentence that explains it.

#![no_std]

#[cfg(any(
    all(feature = "x86_64", feature = "aarch64"),
    all(feature = "x86_64", feature = "riscv64"),
    all(feature = "aarch64", feature = "riscv64"),
))]
compile_error!(
    "exactly one architecture feature must be selected, but this build selected more than one"
);

#[cfg(not(any(feature = "x86_64", feature = "aarch64", feature = "riscv64")))]
compile_error!(
    "no architecture feature selected: pass one of `x86_64`, `aarch64` or `riscv64` (the \
     `virt` crate forwards its own feature to this one)"
);

#[cfg(feature = "x86_64")]
pub use arch_x86_64::*;

#[cfg(feature = "aarch64")]
pub use arch_aarch64::*;

#[cfg(feature = "riscv64")]
pub use arch_riscv64::*;
