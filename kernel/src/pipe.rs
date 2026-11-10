//! kernel/src/pipe.rs
//!
//! A pipe: one buffer, two ends, and the two things a task does when its end
//! cannot make progress.
//!
//! `ipc::ByteRing` is the arithmetic, a fixed buffer, two cursors, a count,
//! and it is deliberately testable on a host.  What it cannot do is *park* a
//! task: that needs the scheduler, and a crate that needed the scheduler could
//! not be tested without one.  `scripts/layering.txt` says the same thing in
//! one line: the ring is `ipc`'s and the endpoints are the kernel's.
//!
//! So this file holds the endpoints and hands bytes to the ring.  It never
//! learns what a thread is: it asks the scheduler to park and wake, and the
//! scheduler answers.
//!
//! `Sleep` made a task wait for a clock.  A pipe makes it wait for *another
//! task*, which is a different thing in every way that matters: there is no
//! deadline to compare against, the wake comes from a syscall rather than from
//! the timer, and the wait can end in three ways rather than one, bytes
//! arrived, the write end closed, or the wait was interrupted.  The third is
//! not implemented and this file says so where it would be.
//!
//! What is not here is a wait queue with one entry per object.  There is one
//! pipe in the boot that proves this, and one blocked task, so a wake wakes
//! every blocked task, see `scheduler::Scheduler::wake_blocked`, which argues
//! the same point from the other side.  A second blocking object is what will
//! make a queue necessary, and a queue written before there is a second one
//! would be a lookup with one entry.

use alloc::sync::Arc;

use abi::Error;
use abi::Result;
use ipc::ByteRing;

/// One pipe's buffer and the two ends' liveness.
///
/// Shared by both ends, because a reader has to know whether a writer still
/// exists, that is what turns "no bytes yet" into "no bytes ever".
///
/// The two counts are **live handles**, not ends baked in at creation: a
/// handle is made by [`End::reader`], [`End::writer`], or [`End::clone`], and
/// taken back by dropping it.  The invariant that holds everywhere is one
/// count per live handle of that kind, which is what makes the zero real:
/// zero writers is end-of-file, and a pipe that says one writer has one.
/// Counting from one at creation instead — the first version — made a second
/// `End::writer` a handle the counts never saw, and its drop a close of an
/// end that was still held.
pub struct Pipe {
    /// The buffer, behind a lock because both ends reach it through one `Arc`
    /// and neither owns it.  It used to be a cell with the argument that one
    /// CPU serves one call at a time, which stops being true with a second CPU:
    /// a reader on one CPU and a writer on the other would be two mutable
    /// borrows of one ring, moving the same two cursors.
    ///
    /// The lock is per-pipe and held only for one `read_from` or `write_to`, so
    /// two pipes never wait on each other.
    ring: sync::Mutex<ByteRing>,
    /// How many write handles are live.  Zero means a reader will see
    /// end-of-file.
    writers: core::sync::atomic::AtomicUsize,
    /// How many read handles are live.  Zero means a writer's bytes go nowhere.
    readers: core::sync::atomic::AtomicUsize,
}

impl Pipe {
    /// A pipe with a buffer of `capacity` bytes and, as yet, no handles.
    ///
    /// The handles arrive with the [`End`]s, whose constructors count
    /// themselves.
    pub fn new(capacity: usize) -> Pipe {
        Pipe {
            ring: sync::Mutex::new(ByteRing::new(capacity)),
            writers: core::sync::atomic::AtomicUsize::new(0),
            readers: core::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// How many bytes are waiting.
    pub fn available(&self) -> usize {
        self.ring.lock().available()
    }

    /// How much room a writer has.
    pub fn remaining(&self) -> usize {
        self.ring.lock().remaining()
    }

    pub fn has_writers(&self) -> bool {
        self.writers.load(core::sync::atomic::Ordering::Acquire) > 0
    }

    pub fn has_readers(&self) -> bool {
        self.readers.load(core::sync::atomic::Ordering::Acquire) > 0
    }

    /// Take what is buffered into `destination`, answering how many bytes.
    pub fn read_available(&self, destination: &mut [u8]) -> usize {
        self.ring.lock().read_from(destination)
    }

    /// Put as much of `source` as fits, answering how many bytes.
    pub fn write_available(&self, source: &[u8]) -> usize {
        self.ring.lock().write_to(source)
    }

    /// Take one read handle back.
    fn close_reader(&self) {
        // A saturating decrement, and an atomic one: a drop runs on whichever
        // CPU is serving the call that made the handle go, so two CPUs can
        // take the last two handles at once, and a load-then-store would lose
        // one of the two decrements and leave a count that names a handle
        // nothing holds — end-of-file that never arrives, the very bug the
        // saturation here exists to refuse.
        //
        // `checked_sub` answering `None` at zero is the saturation: a handle
        // count that is already zero has nothing to take back, and wrapping
        // past zero would turn a double drop into an end-of-file that never
        // arrives.
        let _ = self.readers.try_update(
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
            |count| count.checked_sub(1),
        );
    }

    /// Record that another handle of this kind exists.
    pub fn add_reader(&self) {
        self.readers
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    }

    /// Record that another handle of this kind exists.
    pub fn add_writer(&self) {
        self.writers
            .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
    }

    /// Take one write handle back.
    fn close_writer(&self) {
        // Atomic and saturating for the same reason `close_reader` is.
        let _ = self.writers.try_update(
            core::sync::atomic::Ordering::AcqRel,
            core::sync::atomic::Ordering::Acquire,
            |count| count.checked_sub(1),
        );
    }
}

/// One end of a pipe, as a task holds it.
///
/// Both ends carry the same [`Pipe`]; what differs is which side of it the task
/// is on.  A task's descriptor table holds these, and a dropped handle is a
/// closed end: [`Drop`] takes the pipe's count of live handles of that kind
/// down by one, and the drop of the last write handle is what makes a reader
/// see end-of-file.  That is the whole of what a `Close` has to do — the
/// descriptor's slot goes and the handle inside it drops — and it is why a
/// temporary clone, which every lookup through the table is, can borrow a
/// handle for the length of a call without closing anything.
pub struct End {
    pipe: Arc<Pipe>,
    kind: Kind,
}

/// Which end of a pipe a handle names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Bytes come out of it.
    Read,
    /// Bytes go into it.
    Write,
}

/// What a read or a write answers when it cannot make progress now.
///
/// Not an `Error`: "nothing to read yet" is not a failure, and a pipe whose
/// empty read answered `WouldBlock` would be a pipe a program had to poll.  The
/// two outcomes are separate so a caller that must not block can tell them
/// apart, and so the blocking path can say what it is doing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Progress {
    /// The operation completed with this many bytes.
    Done(usize),
    /// It could not, and blocking is what a caller does next.
    Block,
}

impl Clone for End {
    /// A second handle onto the same end of the same pipe.
    ///
    /// The pipe's own counts are incremented, because the count is what
    /// end-of-file means: a reader sees it only when every write handle is
    /// gone, and a clone is another handle.  [`Drop`] takes the increment
    /// back, so a handle that lives only for the length of one call nets to
    /// nothing.
    fn clone(&self) -> End {
        match self.kind {
            Kind::Read => self.pipe.add_reader(),
            Kind::Write => self.pipe.add_writer(),
        }
        End {
            pipe: Arc::clone(&self.pipe),
            kind: self.kind,
        }
    }
}

impl Drop for End {
    /// Dropping a handle is closing it.
    ///
    /// One increment per handle — the constructors' and the clone's — and one
    /// decrement here is the whole accounting.  It is what the descriptor
    /// table's `Close` has always promised: the slot goes, the handle inside
    /// it drops, and the drop is what moves the count a reader's end-of-file
    /// is read from.
    fn drop(&mut self) {
        match self.kind {
            Kind::Read => self.pipe.close_reader(),
            Kind::Write => self.pipe.close_writer(),
        }
    }
}

impl End {
    /// One read handle on `pipe`.
    ///
    /// The handle counts itself: the pipe's reader count goes up by one here,
    /// and back down when this `End` drops.
    pub fn reader(pipe: Arc<Pipe>) -> End {
        pipe.add_reader();
        End {
            pipe,
            kind: Kind::Read,
        }
    }

    /// One write handle on `pipe`.
    ///
    /// The handle counts itself: the pipe's writer count goes up by one here,
    /// and back down when this `End` drops — which is the one thing that can
    /// bring a reader's end-of-file about.
    pub fn writer(pipe: Arc<Pipe>) -> End {
        pipe.add_writer();
        End {
            pipe,
            kind: Kind::Write,
        }
    }

    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn pipe(&self) -> &Arc<Pipe> {
        &self.pipe
    }

    /// One attempt at reading, without ever blocking.
    ///
    /// Answers `Done(0)` for end-of-file, every writer is gone and the buffer
    /// is drained, and `Block` when bytes may still arrive.  The distinction
    /// is the whole reason this returns a value rather than an error: a program
    /// that treated both as "nothing" would loop for ever on a closed pipe.
    pub fn try_read(&self, pipe: &Pipe, destination: &mut [u8]) -> Result<Progress> {
        if self.kind != Kind::Read {
            return Err(Error::InvalidArgument);
        }
        if destination.is_empty() {
            return Ok(Progress::Done(0));
        }
        let count = pipe.read_available(destination);
        if count > 0 {
            return Ok(Progress::Done(count));
        }
        if !pipe.has_writers() {
            return Ok(Progress::Done(0));
        }
        Ok(Progress::Block)
    }

    /// One attempt at writing, without ever blocking.
    ///
    /// Answers `Done(0)` when no reader is left, a write to a pipe nobody
    /// reads is not an error a shell needs to report, and returning the count
    /// it would have written would be a lie about where the bytes went.
    pub fn try_write(&self, pipe: &Pipe, source: &[u8]) -> Result<Progress> {
        if self.kind != Kind::Write {
            return Err(Error::InvalidArgument);
        }
        if source.is_empty() {
            return Ok(Progress::Done(0));
        }
        if !pipe.has_readers() {
            return Ok(Progress::Done(0));
        }
        let count = pipe.write_available(source);
        if count > 0 {
            return Ok(Progress::Done(count));
        }
        Ok(Progress::Block)
    }
}

// The pipes this boot has made are descriptors like any other: they live in
// the registry's table, beside the open files, under **one** numbering.  The
// first version had a table here, indexed from zero exactly as the
// registry's was, and the two tables answering the same descriptor number
// with two different things was an ambiguity a caller could not resolve — a
// `Read` of descriptor 0 was a pipe read if a pipe had been made first and a
// file read otherwise, which is not a rule, it is an accident of ordering.
// The table is `syscall`'s now, and this module keeps the pipe half: the
// ring, the ends, and the blocking semantics.
//
// The registry's own lock is what makes `attach` and `lookup` one object
// across CPUs, and it is never held across a blocking operation: a caller
// that is about to block clones the `End` first — the `Arc` inside is what
// keeps the pipe alive while the borrow is out — and releases the lock
// before it does.

/// Register one end of a pipe and answer its descriptor.
///
/// The descriptor is an index into the registry's table, and a descriptor is
/// only meaningful together with the table it indexes, which is why the
/// answer is not a bare number a caller could invent.
///
/// `owner` is the process that will hold it, and its exit releases the end the
/// way a `Close` would.  The boot's own pipe passes the boot's process id, so
/// it outlives every program by design.
pub fn attach(end: End, owner: u32) -> Option<usize> {
    crate::syscall::attach_pipe(end, owner)
}

/// The end a descriptor names, if it names one.
///
/// A clone, because the table owns its entries and a caller that borrowed one
/// would hold the registry's lock across a call that may block.  The `Arc`
/// inside is what makes the clone cheap, and what keeps the pipe alive while
/// the borrow is out.
pub fn lookup(descriptor: usize) -> Option<End> {
    crate::syscall::pipe_end(descriptor)
}

/// The end a descriptor names, if it names one **and `caller` holds it**.
///
/// The ring-3 way in.  A program that names another process's descriptor gets
/// `None`, which is the same answer as a number that names nothing: the error
/// a program sees does not tell it which slots exist.
pub fn lookup_for(descriptor: usize, caller: Option<u32>) -> Option<End> {
    match caller {
        Some(pid) => crate::syscall::pipe_end_for(descriptor, pid),
        // A caller with no pid is the kernel's own, as in the table's own
        // check: the boot serves a call before any program exists.
        None => crate::syscall::pipe_end(descriptor),
    }
}

#[cfg(test)]
mod tests {
    //! The tests for this module.
    //!
    //! The pipe's tests: the ring's arithmetic, the endpoints' counting, and
    //! the table that holds them.
    //!
    //! ## Why these are a file of their own
    //!
    //! The module is a few hundred lines of endpoint bookkeeping; its tests are
    //! larger than the code they check, and a reader following the pipe's
    //! contract should be able to read the mechanism without scrolling past
    //! every case it has to satisfy.

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
    /// The close takes the *handle* away, not the bytes: a reader that lost
    /// what was already written would make every close a data loss.
    /// End-of-file is what a drained pipe answers, and only then.
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
    /// The counts are per handle: a temporary clone — which is what every
    /// lookup through the descriptor table is — raises the count while it lives
    /// and lowers it when it drops, and the pipe stays open underneath.  A drop
    /// of one handle closing an end another handle still names would be
    /// end-of-file announced by a borrow going out of scope.
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
}
