//! libs/sync/src/lib.rs
//!
//! The leaf synchronisation layer: a spinlock and the RAII wrapper over it.
//!
//! ## What this crate is, and what it is not
//!
//! Neither primitive names a thread, which is what makes them leaves: the heap,
//! the filesystem and every driver can use them, and none of those layers has
//! to be understood to read this one.
//!
//! The primitives that *park a thread* live elsewhere, and deliberately so.
//! Parking is a scheduler act, and a queue that parks has no business in the
//! layer a mutex is built on, the previous tree states the same boundary in
//! its `kernel/sync/mod.rs` and files the wait queues one layer up.
//!
//! ## Why it names `arch`
//!
//! A spinlock that only spins is safe between CPUs and unsafe against itself:
//! an interrupt taken while the lock is held, whose handler takes the same
//! lock, spins forever on a CPU that cannot make progress.  Acquisition
//! therefore closes that window, and closing it needs the machine's interrupt
//! flag, which is `arch`'s to read.  On a host build those functions are
//! no-ops, so the same lock is exercised by the same tests without a kernel.

#![no_std]

pub mod mutex;
pub mod spinlock;

pub use mutex::Mutex;
pub use mutex::MutexGuard;
pub use spinlock::SpinLock;
pub use spinlock::SpinLockGuard;
