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
//! when they do.  It is at `kernel/src/syscall/mod.rs` today, serving `open`,
//! `read` and `close` against the mounted volume.  The split is the same one
//! `fs` makes between `VNode` and a volume.
//!
//! ## The handler type, and why the kernel does not use it
//!
//! [`table::SyscallHandler`] takes the context alone, which is the right shape
//! for a handler with no state.  The kernel's three handlers need the table
//! they were reached through — the descriptor array is in it — so the kernel
//! names its own type that takes the table as well.  This crate's type stays
//! the statement of what a stateless handler is; a later `yield` or `getpid`
//! can be registered through it by wrapping.
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
//! Numbers up to and including 120 are frozen: assigned once, never reused,
//! never renumbered.  The tests below pin the ones a program is most likely to
//! have hard-coded, which is what makes the promise checkable rather than
//! stated.  Above 120 the numbering is still the wire format but the set may
//! grow, and [`table::PUBLIC_SYSCALL_COUNT`] is the number both sides agree on
//! for a build.

#![no_std]

pub mod table;

pub use table::*;
