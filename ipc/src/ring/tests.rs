//! ipc/src/ring/tests.rs
//!
//! The byte ring: a write that wraps, a read that takes what is there, and the
//! full and empty edges.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

use crate::ring::ByteRing;
use crate::ring::PIPE_MAX_SIZE;
use crate::ring::PIPE_MIN_SIZE;
use crate::ring::round_pipe_size;
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
