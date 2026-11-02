// arch/src/lib.rs

#![no_std]

#[cfg(feature = "x86_64")]
pub use arch_x86_64::*;

#[cfg(feature = "aarch64")]
pub use arch_aarch64::*;

#[cfg(feature = "riscv64")]
pub use arch_riscv64::*;