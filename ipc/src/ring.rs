//! ipc/src/ring.rs
//!
//! The byte ring a pipe is: a fixed buffer, two cursors, and a count.
//!
//! ## Why this is separate from the pipe
//!
//! A pipe is two things: a ring buffer, and two endpoints that park threads
//! against it.  The second half needs a condition variable, which needs the
//! scheduler — and a crate that needed the scheduler could not be tested on a
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
//! writer must not interleave *partially*, and that is the lock's job — the
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
mod tests {
    use super::ByteRing;
    use super::PIPE_MAX_SIZE;
    use super::PIPE_MIN_SIZE;
    use super::round_pipe_size;
    use abi::Error;

    /// Bytes come back in the order they went in, across the wrap.
    ///
    /// The modulo is the whole of the ring's arithmetic and the one place an
    /// off-by-one is silent: a write that forgot to wrap overwrites the front
    /// of the buffer, and a read that forgot to wrap returns stale bytes.
    #[test]
    fn the_order_survives_the_wrap() {
        let mut ring = ByteRing::new(4);
        assert_eq!(ring.write_to(b"abc"), 3);
        let mut first = [0u8; 2];
        assert_eq!(ring.read_from(&mut first), 2);
        assert_eq!(&first, b"ab");
        // The ring holds one byte (`c`) and has room for three, so all three
        // of `def` fit — and the write cursor starts at 3, so the first byte
        // lands at index 3 and the other two wrap to 0 and 1.  That wrap is
        // the arithmetic this test exists for.
        assert_eq!(ring.write_to(b"def"), 3);
        let mut second = [0u8; 4];
        let read = ring.read_from(&mut second);
        assert_eq!(read, 4);
        assert_eq!(&second[..read], b"cdef");
    }

    /// A full ring accepts nothing and a write reports zero rather than
    /// overwriting.
    #[test]
    fn a_full_ring_refuses_more() {
        let mut ring = ByteRing::new(3);
        assert_eq!(ring.write_to(b"xyz"), 3);
        assert!(ring.is_full());
        assert_eq!(ring.remaining(), 0);
        assert_eq!(ring.write_to(b"more"), 0);
        // And what was there is intact.
        let mut out = [0u8; 3];
        assert_eq!(ring.read_from(&mut out), 3);
        assert_eq!(&out, b"xyz");
    }

    /// A partial write takes what fits and says so.
    #[test]
    fn a_partial_write_takes_what_fits() {
        let mut ring = ByteRing::new(4);
        assert_eq!(ring.write_to(b"abcdef"), 4);
        assert_eq!(ring.available(), 4);
    }

    /// A zero-length read or write is a no-op that reports zero.
    #[test]
    fn zero_length_transfers_do_nothing() {
        let mut ring = ByteRing::new(4);
        assert_eq!(ring.read_from(&mut []), 0);
        assert_eq!(ring.write_to(&[]), 0);
        assert_eq!(ring.write_to(b"a"), 1);
        assert_eq!(ring.read_from(&mut []), 0);
        assert_eq!(ring.available(), 1);
    }

    /// Resizing preserves every buffered byte, in order.
    #[test]
    fn a_resize_preserves_the_data() {
        let mut ring = ByteRing::new(4);
        ring.write_to(b"abcd");
        ring.read_from(&mut [0u8; 1]); // so the cursors are not at zero
        ring.write_to(b"e");
        ring.resize(16).unwrap();
        let mut out = [0u8; 8];
        let read = ring.read_from(&mut out);
        assert_eq!(&out[..read], b"bcde");
        assert_eq!(ring.capacity(), 16);
    }

    /// A resize below what is buffered is refused, and the buffer is unchanged.
    ///
    /// The refusal is the point: truncating would lose bytes a writer was told
    /// had been accepted.
    #[test]
    fn a_resize_below_the_content_is_refused() {
        let mut ring = ByteRing::new(8);
        ring.write_to(b"abcdef");
        assert_eq!(ring.resize(4), Err(Error::Busy));
        assert_eq!(ring.available(), 6);
        let mut out = [0u8; 6];
        assert_eq!(ring.read_from(&mut out), 6);
        assert_eq!(&out, b"abcdef");
    }

    /// A resize to exactly the content is accepted.
    #[test]
    fn a_resize_to_the_content_is_accepted() {
        let mut ring = ByteRing::new(8);
        ring.write_to(b"abcd");
        assert_eq!(ring.resize(4), Ok(()));
        assert_eq!(ring.capacity(), 4);
        assert!(ring.is_full());
    }

    /// The size a program asks for is rounded the way it will read it back.
    #[test]
    fn round_pipe_size_clamps_and_rounds_up() {
        assert_eq!(round_pipe_size(0), PIPE_MIN_SIZE);
        assert_eq!(round_pipe_size(1), PIPE_MIN_SIZE);
        assert_eq!(round_pipe_size(PIPE_MIN_SIZE), PIPE_MIN_SIZE);
        // One byte over a page is two pages.
        assert_eq!(round_pipe_size(PIPE_MIN_SIZE + 1), PIPE_MIN_SIZE * 2);
        assert_eq!(round_pipe_size(usize::MAX), PIPE_MAX_SIZE);
    }

    /// The rounding produces a power-of-two number of pages, which is what a
    /// program's own arithmetic expects.
    #[test]
    fn a_rounded_size_is_a_power_of_two_number_of_pages() {
        for requested in [1, 4097, 9000, 65536, 100_000] {
            let rounded = round_pipe_size(requested);
            assert_eq!(rounded % PIPE_MIN_SIZE, 0);
            let pages = rounded / PIPE_MIN_SIZE;
            assert!(pages.is_power_of_two(), "{pages} is not a power of two");
        }
    }
}
