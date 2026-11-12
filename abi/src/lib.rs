//! abi/src/lib.rs
//!
//! The one description of everything the kernel and a program both have to
//! agree on.
//!
//! ## The rule this crate exists to hold
//!
//! `abi` names `core` and nothing else.  Not `alloc`, not `kernel`, not any
//! crate beside it.  A type that lives here is one both sides compile against,
//! so a dependency of this crate is a dependency every program inherits, and a
//! program is not a kernel, which is what makes the rule load-bearing rather
//! than tidy.
//!
//! ## Why there is no mirror
//!
//! The previous tree carried the ABI twice: `src/abi/` for the kernel and the
//! shared crate's copy for the user side, kept identical below the header by a
//! census script with a baseline of recorded differences.  The copy existed
//! because a payload is compiled separately and could not `use` the kernel's
//! crate.  A crate both sides depend on removes the reason: there is one
//! definition, and the script that compared two of them is not needed.
//!
//! The cost is that everything in here must be `no_std` and allocation-free.
//! That is not a hardship for a wire format, a syscall argument is a word,
//! and where it would be, the type does not belong in this crate.

#![no_std]

pub mod boot;
pub mod error;
pub mod exception;
pub mod fs;
pub mod memory;
pub mod number;
pub mod power;
pub mod process;
pub mod syscall;

pub use boot::BootInfo;
pub use boot::DeviceTreeSummary;
pub use boot::Loader;
pub use error::Error;
pub use error::Result;
pub use number::SyscallNumber;
pub use power::CpuFreqDriver;
