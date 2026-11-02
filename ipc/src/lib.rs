//! ipc/src/lib.rs
//!
//! Inter-process communication, starting with the pipe's ring buffer.
//!
//! ## What is here, and what is not
//!
//! The ring: a fixed buffer, two cursors and a count, plus the pipe-size
//! rounding a program's `fcntl(F_SETPIPE_SZ)` depends on.  It has no lock, no
//! wait queue and no `Arc`, which is what lets its arithmetic be tested on a
//! host.
//!
//! What is not here is the pipe itself — the two endpoints that park a reader
//! when the ring is empty and a writer when it is full.  That needs a
//! condition variable, a condition variable needs the scheduler, and a crate
//! that needed the scheduler could not be tested on a host.  The pipe arrives
//! with the wait queue, and this ring is what it will hold.
//!
//! ## Why a crate rather than a module under the kernel
//!
//! The previous tree files its pipe under `kernel::ipc` for a reason its own
//! header states: blocking is the point, and parking a thread is the
//! scheduler's business.  That is right about the *pipe* and wrong about the
//! ring — the ring blocks nothing.  Splitting them is what gives the arithmetic
//! somewhere to be tested.

#![no_std]

extern crate alloc;

pub mod ring;

pub use ring::ByteRing;
pub use ring::DEFAULT_PIPE_CAPACITY;
pub use ring::PIPE_MAX_SIZE;
pub use ring::PIPE_MIN_SIZE;
pub use ring::round_pipe_size;
