//! ipc/src/ring.rs
//!
//! The byte ring a pipe is: a fixed buffer, two cursors, and a count.
//!
//! ## Why this is separate from the pipe
//!
//! A pipe is two things: a ring buffer, and two endpoints that park threads
//! against it.  The second half needs a condition variable, which needs the
//! scheduler, and a crate that needed the scheduler could not be tested on a
//! host, which is where the arithmetic below has to be tested.
//!
//! So the ring is its own type with no lock, no wait queue and no `Arc`.  The
//! previous tree's `PipeRing` was already that; what it did not have was a
//! boundary that said so, and its tests shared a file with twenty others that
//! needed a scheduler.
//!
//! ## What the caller owns
//!
//! Synchronisation.  Every method here takes `&mut self`, so the borrow checker
//! already refuses two writers; what it cannot express is that a reader and a
//! writer must not interleave *partially*, and that is the lock's job, the
//! pipe's, not the ring's.

use alloc::boxed::Box;
use alloc::vec;

use abi::Error;
use abi::Result;

/// Default pipe capacity in bytes (16 KiB = 4 pages).
pub const DEFAULT_PIPE_CAPACITY: usize = 16384;

/// Minimum capacity the resize path accepts (one page).
pub const PIPE_MIN_SIZE: usize = 4096;

/// Maximum capacity the resize path accepts.
///
/// A megabyte is a bound on what one pipe may pin in the heap.  It is a policy
/// this crate picks because a ring that could grow to whatever a program asked
/// for would let one program consume the heap by resizing a pipe it never
/// writes to.  The number is the ring's, not a compatibility target: a caller
/// that asks for more gets this, and reads the granted size back with
/// [`F_GETPIPE_SZ`](abi::fs::F_GETPIPE_SZ) rather than assuming its request was
/// honoured.
pub const PIPE_MAX_SIZE: usize = 1024 * 1024;

/// Round a requested pipe size to the convention a program expects.
///
/// Clamps to `[PIPE_MIN_SIZE, PIPE_MAX_SIZE]` and rounds up to a power-of-two
/// number of pages.  The rounding is not cosmetic: a program that asks for
/// `F_SETPIPE_SZ` and then reads the size back gets what this returned, so a
/// ring that did not round would report a capacity no program asked for.
pub fn round_pipe_size(size: usize) -> usize {
    let clamped = size.clamp(PIPE_MIN_SIZE, PIPE_MAX_SIZE);
    let pages = clamped.div_ceil(PIPE_MIN_SIZE);
    let rounded = pages
        .next_power_of_two()
        .saturating_mul(PIPE_MIN_SIZE)
        .min(PIPE_MAX_SIZE);
    rounded.max(PIPE_MIN_SIZE)
}

/// A fixed-capacity byte ring.
pub struct ByteRing {
    buffer: Box<[u8]>,
    read_position: usize,
    write_position: usize,
    /// Unread bytes currently in the buffer.
    byte_count: usize,
    /// Set when the write end is dropped; a reader that drains the buffer then
    /// sees end-of-file rather than waiting for more.
    pub write_closed: bool,
    /// Set when the read end is dropped; a writer then sees an error rather
    /// than filling a buffer nobody will drain.
    pub read_closed: bool,
}

impl ByteRing {
    /// A ring of `capacity` bytes, empty.
    ///
    /// A capacity of zero is refused in a debug build: every cursor arithmetic
    /// here is modulo the buffer's length, so a zero-length ring is a division
    /// by zero rather than an empty pipe.
    pub fn new(capacity: usize) -> Self {
        debug_assert!(capacity > 0, "a ring of zero bytes cannot be indexed");
        Self {
            buffer: vec![0u8; capacity].into_boxed_slice(),
            read_position: 0,
            write_position: 0,
            byte_count: 0,
            write_closed: false,
            read_closed: false,
        }
    }

    /// The ring's capacity in bytes.
    pub fn capacity(&self) -> usize {
        self.buffer.len()
    }

    /// Whether nothing is buffered.
    pub fn is_empty(&self) -> bool {
        self.byte_count == 0
    }

    /// Whether the buffer is full.
    pub fn is_full(&self) -> bool {
        self.byte_count == self.buffer.len()
    }

    /// How many bytes are waiting to be read.
    pub fn available(&self) -> usize {
        self.byte_count
    }

    /// How many bytes could be written before the ring is full.
    pub fn remaining(&self) -> usize {
        self.buffer.len() - self.byte_count
    }

    /// Read up to `destination.len()` bytes, returning how many were read.
    ///
    /// A short read is not an error: the ring gives what it has, and the caller
    /// decides whether that was enough.
    pub fn read_from(&mut self, destination: &mut [u8]) -> usize {
        let count = core::cmp::min(destination.len(), self.byte_count);
        for byte in destination.iter_mut().take(count) {
            *byte = self.buffer[self.read_position];
            self.read_position = (self.read_position + 1) % self.buffer.len();
        }
        self.byte_count -= count;
        count
    }

    /// Write up to `source.len()` bytes, returning how many were written.
    pub fn write_to(&mut self, source: &[u8]) -> usize {
        let count = core::cmp::min(source.len(), self.remaining());
        for &byte in source.iter().take(count) {
            self.buffer[self.write_position] = byte;
            self.write_position = (self.write_position + 1) % self.buffer.len();
        }
        self.byte_count += count;
        count
    }

    /// Resize to `new_capacity` bytes, preserving buffered data.
    ///
    /// The data is compacted to the front, so both cursors reset and the ring's
    /// next read starts at zero.  Returns [`Error::Busy`] when the new capacity
    /// cannot hold what is already buffered: those bytes were accepted from a
    /// writer that was told they fit, and truncating them would break that
    /// promise silently.  A refusal the caller can report is the only honest
    /// answer.
    pub fn resize(&mut self, new_capacity: usize) -> Result<()> {
        if new_capacity < self.byte_count {
            return Err(Error::Busy);
        }

        let mut pending = vec![0u8; self.byte_count];
        self.read_from(&mut pending);

        self.buffer = vec![0u8; new_capacity].into_boxed_slice();
        self.read_position = 0;
        self.write_position = pending.len();
        self.buffer[..pending.len()].copy_from_slice(&pending);
        self.byte_count = pending.len();
        Ok(())
    }
}

#[cfg(test)]
mod tests;
