//! kernel/src/pipe/tests.rs
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

/// An empty pipe whose write handle is live blocks a reader rather than
/// answering end-of-file.
///
/// This is the distinction the whole design turns on.  A reader that could
/// not tell "nothing yet" from "nothing ever" would either spin on a pipe
/// nobody writes or stop reading one that has more coming.
#[test]
fn an_empty_pipe_with_a_writer_blocks() {
    let pipe = Arc::new(Pipe::new(16));
    let reader = End::reader(pipe.clone());
    let _writer = End::writer(pipe.clone());
    let mut buffer = [0u8; 4];

    assert_eq!(reader.try_read(&pipe, &mut buffer), Ok(Progress::Block));
    assert!(pipe.has_writers(), "the writer is what makes it wait");
}

/// Bytes written are bytes read, in order.
#[test]
fn a_written_byte_comes_back_in_order() {
    let pipe = Arc::new(Pipe::new(16));
    let reader = End::reader(pipe.clone());
    let writer = End::writer(pipe.clone());

    assert_eq!(
        writer.try_write(&pipe, b"abc"),
        Ok(Progress::Done(3)),
        "the writer's own end does not gate the pipe's buffer"
    );
    let mut buffer = [0u8; 4];
    assert_eq!(reader.try_read(&pipe, &mut buffer), Ok(Progress::Done(3)));
    assert_eq!(&buffer[..3], b"abc");
}

/// Dropping the last write handle answers a reader's next read with
/// end-of-file, not a block.
///
/// Dropping a handle **is** closing it: that is the whole contract the
/// descriptor table's `Close` leans on.  A reader that blocked after the
/// writer's handle went would wait for a task that can never write again.
#[test]
fn a_dropped_writer_ends_the_file() {
    let pipe = Arc::new(Pipe::new(16));
    let reader = End::reader(pipe.clone());
    let writer = End::writer(pipe.clone());
    let mut buffer = [0u8; 4];

    assert_eq!(reader.try_read(&pipe, &mut buffer), Ok(Progress::Block));
    drop(writer);
    assert_eq!(
        reader.try_read(&pipe, &mut buffer),
        Ok(Progress::Done(0)),
        "no writer left, so no bytes are coming"
    );
}

/// Bytes a writer left behind are read before end-of-file.
///
/// The close takes the *handle* away, not the bytes: a reader that lost what
/// was already written would make every close a data loss.  End-of-file is
/// what a drained pipe answers, and only then.
#[test]
fn bytes_left_by_a_dropped_writer_are_still_there() {
    let pipe = Arc::new(Pipe::new(16));
    let reader = End::reader(pipe.clone());
    let writer = End::writer(pipe.clone());
    let mut buffer = [0u8; 4];

    assert_eq!(writer.try_write(&pipe, b"abc"), Ok(Progress::Done(3)));
    drop(writer);
    assert_eq!(reader.try_read(&pipe, &mut buffer), Ok(Progress::Done(3)));
    assert_eq!(&buffer[..3], b"abc");
    assert_eq!(
        reader.try_read(&pipe, &mut buffer),
        Ok(Progress::Done(0)),
        "drained and no writer left: end-of-file"
    );
}

/// A write into a pipe whose reader handle was dropped reports zero rather
/// than blocking.
#[test]
fn a_write_with_no_reader_reports_zero() {
    let pipe = Arc::new(Pipe::new(16));
    let writer = End::writer(pipe.clone());
    let reader = End::reader(pipe.clone());
    drop(reader);

    assert_eq!(
        writer.try_write(&pipe, b"abc"),
        Ok(Progress::Done(0)),
        "the bytes have nowhere to go and saying otherwise would lie"
    );
}

/// A full pipe blocks a writer instead of dropping bytes.
#[test]
fn a_full_pipe_blocks_the_writer() {
    let pipe = Arc::new(Pipe::new(4));
    let _reader = End::reader(pipe.clone());
    let writer = End::writer(pipe.clone());

    assert_eq!(writer.try_write(&pipe, b"abcd"), Ok(Progress::Done(4)));
    assert_eq!(
        writer.try_write(&pipe, b"e"),
        Ok(Progress::Block),
        "there is no room, and dropping the byte would lose it silently"
    );
}

/// A clone keeps the end open after the original handle is gone.
///
/// The counts are per handle: a temporary clone — which is what every lookup
/// through the descriptor table is — raises the count while it lives and
/// lowers it when it drops, and the pipe stays open underneath.  A drop of one
/// handle closing an end another handle still names would be end-of-file
/// announced by a borrow going out of scope.
#[test]
fn a_clone_keeps_the_end_open() {
    let pipe = Arc::new(Pipe::new(16));
    let reader = End::reader(pipe.clone());
    let writer = End::writer(pipe.clone());
    let second = writer.clone();
    let mut buffer = [0u8; 4];

    drop(writer);
    assert_eq!(
        reader.try_read(&pipe, &mut buffer),
        Ok(Progress::Block),
        "the clone is still a live write handle"
    );
    drop(second);
    assert_eq!(reader.try_read(&pipe, &mut buffer), Ok(Progress::Done(0)));
}

/// Reading from a write end and writing to a read end are refused.
#[test]
fn the_wrong_end_is_an_invalid_argument() {
    let pipe = Arc::new(Pipe::new(16));
    let mut buffer = [0u8; 4];

    let writer = End::writer(pipe.clone());
    assert_eq!(
        writer.try_read(&pipe, &mut buffer),
        Err(abi::Error::InvalidArgument)
    );

    let reader = End::reader(pipe.clone());
    assert_eq!(
        reader.try_write(&pipe, b"x"),
        Err(abi::Error::InvalidArgument)
    );
    assert_eq!(reader.kind(), Kind::Read);
}
