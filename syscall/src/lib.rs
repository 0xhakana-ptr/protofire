//! syscall/src/lib.rs
//!
//! The syscall interface: what a number means, what a call carries, and what a
//! handler returns.
//!
//! ## What is here, and what is not
//!
//! The numbering, the [`SyscallContext`] a handler receives, the
//! [`SyscallAction`] it returns, and the argument validators every handler
//! shares.  None of it names a handler, a subsystem or a thread, which is what
//! makes it the interface rather than the implementation.
//!
//! What is not here is the registry: the table from a number to the function
//! that serves it.  Every entry names a subsystem, the filesystem, the
//! network, the scheduler, so the table belongs where those are, and it moves
//! when they do.  It is at `kernel/src/syscall/mod.rs` today, serving `open`,
//! `read` and `close` against the mounted volume.  The split is the same one
//! `fs` makes between `VNode` and a volume.
//!
//! ## The handler type, and why the kernel does not use it
//!
//! [`table::SyscallHandler`] takes the context alone, which is the right shape
//! for a handler with no state.  The kernel's three handlers need the table
//! they were reached through, the descriptor array is in it, so the kernel
//! names its own type that takes the table as well.  This crate's type stays
//! the statement of what a stateless handler is; a later `yield` or `getpid`
//! can be registered through it by wrapping.
//!
//! ## Where the numbering lives
//!
//! Not here.  `SyscallNumber` is a wire format a program is compiled against,
//! which makes it a *contract* rather than an implementation detail of this
//! crate; it lives in `abi::number`, beside the error encoding and the argument
//! count, and this crate re-exports it so a handler author still finds it by
//! name.
//!
//! The split is the same one the whole tree makes between `abi` and everything
//! else: a program that had to depend on this crate to learn what `open` is
//! numbered would be a program depending on the kernel's internals to make its
//! calls.  `abi` is the crate both sides may name, and the numbering is one of
//! the things it is for.

#![no_std]

pub mod table;

pub use table::*;
