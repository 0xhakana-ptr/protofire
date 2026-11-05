//! kernel/src/tests.rs
//!
//! The pipe's tests: the ring's arithmetic, the endpoints' counting, and the
//! table that holds them.
//!
//! ## Why these are a file of their own
//!
//! The module is a few hundred lines of endpoint bookkeeping; its tests are
//! larger than the code they check, and a reader following the pipe's contract
//! should be able to read the mechanism without scrolling past every case it
//! has to satisfy.

use super::End;
use super::Kind;
use super::Pipe;
use super::Progress;
use alloc::sync::Arc;

/// An empty pipe with a live writer blocks a reader rather than answering
/// end-of-file.
///
/// This is the distinction the whole design turns on.  A reader that could
/// not tell "nothing yet" from "nothing ever" would either spin on a pipe
/// nobody writes or stop reading one that has more coming.
#[test]
fn an_empty_pipe_with_a_writer_blocks() {
    let reader = End::reader(Arc::new(Pipe::new(16)));
    let pipe = Pipe::new(16);
    let mut buffer = [0u8; 4];

    assert_eq!(reader.try_read(&pipe, &mut buffer), Ok(Progress::Block));
    assert_eq!(pipe.available(), 0);
    assert!(pipe.has_writers(), "the writer is what makes it wait");
}

/// Bytes written are bytes read, in order.
#[test]
fn a_written_byte_comes_back_in_order() {
    let pipe = Pipe::new(16);
    let writer = End::writer(Arc::new(Pipe::new(16)));
    let reader = End::reader(Arc::new(Pipe::new(16)));

    assert_eq!(
        writer.try_write(&pipe, b"abc"),
        Ok(Progress::Done(3)),
        "the writer's own end does not gate the pipe's buffer"
    );
    let mut buffer = [0u8; 4];
    assert_eq!(reader.try_read(&pipe, &mut buffer), Ok(Progress::Done(3)));
    assert_eq!(&buffer[..3], b"abc");
}

/// A drained pipe whose writers are gone answers end-of-file, not a block.
///
/// The difference is what a program's loop tests: `Done(0)` ends it and
/// `Block` waits.  A reader that blocked after the writer closed would wait
/// for a task that has already exited.
#[test]
fn a_drained_pipe_without_writers_ends_the_file() {
    let pipe = Pipe::new(16);
    let reader = End::reader(Arc::new(Pipe::new(16)));
    let mut buffer = [0u8; 4];

    assert_eq!(reader.try_read(&pipe, &mut buffer), Ok(Progress::Block));
    pipe.close_writer();
    assert_eq!(
        reader.try_read(&pipe, &mut buffer),
        Ok(Progress::Done(0)),
        "no writer left, so no bytes are coming"
    );
}

/// A write into a pipe nobody reads reports zero rather than blocking.
#[test]
fn a_write_with_no_reader_reports_zero() {
    let pipe = Pipe::new(16);
    let writer = End::writer(Arc::new(Pipe::new(16)));
    pipe.close_reader();
    assert_eq!(
        writer.try_write(&pipe, b"abc"),
        Ok(Progress::Done(0)),
        "the bytes have nowhere to go and saying otherwise would lie"
    );
}

/// A full pipe blocks a writer instead of dropping bytes.
#[test]
fn a_full_pipe_blocks_the_writer() {
    let pipe = Pipe::new(4);
    let writer = End::writer(Arc::new(Pipe::new(16)));
    assert_eq!(writer.try_write(&pipe, b"abcd"), Ok(Progress::Done(4)));
    assert_eq!(
        writer.try_write(&pipe, b"e"),
        Ok(Progress::Block),
        "there is no room, and dropping the byte would lose it silently"
    );
}

/// Reading from a write end and writing to a read end are refused.
#[test]
fn the_wrong_end_is_an_invalid_argument() {
    let pipe = Arc::new(Pipe::new(16));
    let local = Pipe::new(16);
    let mut buffer = [0u8; 4];

    let writer = End::writer(pipe.clone());
    assert_eq!(
        writer.try_read(&local, &mut buffer),
        Err(abi::Error::InvalidArgument)
    );

    let reader = End::reader(pipe);
    assert_eq!(
        reader.try_write(&local, b"x"),
        Err(abi::Error::InvalidArgument)
    );
    assert_eq!(reader.kind(), Kind::Read);
}
