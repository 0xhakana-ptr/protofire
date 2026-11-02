//! syscall/src/lib.rs
//!
//! The syscall interface: what a number means, what a call carries, and what a
//! handler returns.
//!
//! ## What is here, and what is not
//!
//! The numbering, the [`SyscallContext`] a handler receives, the
//! [`SyscallAction`] it returns, and the argument validators every handler
//! shares.  None of it names a handler, a subsystem or a thread — which is what
//! makes it the interface rather than the implementation.
//!
//! What is not here is the registry: the table from a number to the function
//! that serves it.  Every entry names a subsystem — the filesystem, the
//! network, the scheduler — so the table belongs where those are, and it moves
//! when they do.  The split is the same one `fs` makes between `VNode` and a
//! volume.
//!
//! ## Why the numbering is a crate
//!
//! `SyscallNumber` is a wire format: a program is compiled against these
//! numbers and the kernel serves them, so a number that changed meaning would
//! reach another handler without anything failing to compile.  Keeping the
//! numbering where the context and the validators live means a change to it is
//! a change to one crate, reviewed against the promise the numbering makes.
//!
//! ## The promise
//!
//! Numbers below [`FROZEN_SYSCALL_COUNT`] are frozen: assigned once, never
//! reused, never renumbered.  The tests below pin every one of them, which is
//! what makes the promise checkable rather than stated.

#![no_std]

pub mod table;

pub use table::*;
