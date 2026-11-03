//! irq/src/lib.rs
//!
//! Where an interrupt goes: a number, a handler, and the table that joins them.
//!
//! ## What a handler is
//!
//! A function that takes the number it was called for and answers whether it
//! did anything.  The number is a parameter rather than a closure's capture
//! because a device may share one handler across several vectors — a virtio
//! device with four queues registers four identities and wants to know which
//! one woke it.
//!
//! The answer is a `bool` for the same reason the completion queue's `poll` is:
//! "I handled it" and "not mine" are different, and a dispatcher that could not
//! tell them would have to count every unclaimed interrupt as handled.  On a
//! machine with a shared line, "not mine" is the normal answer for every
//! handler but one.
//!
//! ## Why this is a crate and not a module under `arch`
//!
//! The table is the same on every machine: an array of `Option<Handler>`
//! indexed by identity, plus a lock.  What differs is how a machine *reaches*
//! the table — x86_64 has an IDT and a vector number, aarch64 has an exception
//! vector and reads a controller, riscv64 has `scause` — and that part is
//! `arch`'s.
//!
//! Keeping the table here means a host test can register handlers, dispatch to
//! them, and assert what happened, without an interrupt controller, an IDT or a
//! machine.  The previous tree had the same table and no way to test it: it was
//! reachable only from a boot.
//!
//! ## What is not here
//!
//! The vector table itself, the controller that decides which line is pending,
//! and the return path from an exception.  Each is a machine's, and each
//! arrives with the machine.

#![no_std]

pub mod dispatch;
pub mod frame;

pub use dispatch::Handler;
pub use dispatch::MAX_IDENTITIES;
pub use dispatch::Registry;
pub use dispatch::dispatch_installed;
pub use dispatch::register;
pub use dispatch::unregister;
pub use frame::Frame;
