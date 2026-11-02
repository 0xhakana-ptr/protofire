//! arch/src/lib.rs
//!
//! The one crate the rest of the kernel names when it has to ask the machine
//! something.  It holds no implementation of its own: each architecture is a
//! crate beside it, and this file is the route between them.
//!
//! ## The target selects the implementation
//!
//! There is no architecture feature, and that is deliberate.  A feature would
//! be a second place the machine is named, and a build could select the one
//! that disagrees with `--target` — `--target aarch64-unknown-none --features
//! x86_64` would compile x86_64's `out`/`in` instructions into an aarch64
//! image, and the only thing that would notice is the assembler, if it did.
//! `arch/Cargo.toml` names each implementation in a `cfg(target_arch)` table
//! instead, which cargo evaluates against the target being built, so the choice
//! is made once and cannot be overridden.
//!
//! Selecting none is not expressible: a build that matches no table gets no
//! `arch_x86_64`, no `arch_aarch64` and no `arch_riscv64`, and the re-exports
//! below then name crates that are not there — an error that says the
//! architecture has no implementation, which is the true statement.
//!
//! ## What this file must not do
//!
//! Spell a `target_arch` gate of its own.  The tables in the manifest are the
//! selection; a `#[cfg(target_arch)]` here would be a second one, and
//! `scripts/check-arch-fanout.sh` counts gates outside `arch/` precisely
//! because they are how a new architecture gets forgotten.  This crate is
//! exempt as a *directory*; the rule it is held to is that the gate lives in
//! the manifest rather than in code.

#![no_std]

#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::*;

#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::*;

#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::*;

// The handshake parser, re-exported by name.
//
// `pub use crate::*` above brings in the implementation crate's root items, and
// `boot_info` is a function in its `boot` module rather than an item at the
// root.  Naming it here is what lets the kernel call `arch::boot_info()`
// without knowing which crate answered — the point of the routing layer.
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::boot::boot_info;

#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::boot::boot_info;

#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::boot::boot_info;
