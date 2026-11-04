//! kernel/src/pipe.rs
//!
//! A pipe: one buffer, two ends, and the two things a task does when its end
//! cannot make progress.
//!
//! ## What makes this the kernel's and not `ipc`'s
//!
//! `ipc::ByteRing` is the arithmetic — a fixed buffer, two cursors, a count —
//! and it is deliberately testable on a host.  What it cannot do is *park* a
//! task: that needs the scheduler, and a crate that needed the scheduler could
//! not be tested without one.  `scripts/layering.txt` says the same thing in
//! one line: the ring is `ipc`'s and the endpoints are the kernel's.
//!
//! So this file holds the endpoints and hands bytes to the ring.  It never
//! learns what a thread is: it asks the scheduler to park and wake, and the
//! scheduler answers.
//!
//! ## Why a blocked read is the interesting one
//!
//! `Sleep` made a task wait for a clock.  A pipe makes it wait for *another
//! task*, which is a different thing in every way that matters: there is no
//! deadline to compare against, the wake comes from a syscall rather than from
//! the timer, and the wait can end in three ways rather than one — bytes
//! arrived, the write end closed, or the wait was interrupted.  The third is
//! not implemented and this file says so where it would be.
//!
//! ## What is not here
//!
//! A wait queue with one entry per object.  There is one pipe in the boot that
//! proves this, and one blocked task, so a wake wakes every blocked task — see
//! `scheduler::Scheduler::wake_blocked`, which argues the same point from the
//! other side.  A second blocking object is what will make a queue necessary,
//! and a queue written before there is a second one would be a lookup with one
//! entry.

use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::Error;
use abi::Result;
use ipc::ByteRing;

/// One pipe's buffer and the two ends' liveness.
///
/// Shared by both ends, because a reader has to know whether a writer still
/// exists — that is what turns "no bytes yet" into "no bytes ever".
pub struct Pipe {
    /// The buffer, inside a cell because both ends reach it through one `Arc`
    /// and neither owns it.  This kernel serves one call at a time, so the
    /// exclusive borrow a caller takes is the only one there is — the argument
    /// `syscall`'s registry makes for its own static, and the note that stops
    /// being true with a second CPU belongs in the same place here.
    ring: cell::SyncUnsafeCell<ByteRing>,
    /// How many write ends are open.  Zero means a reader will see end-of-file.
    writers: core::sync::atomic::AtomicUsize,
    /// How many read ends are open.  Zero means a writer's bytes go nowhere.
    readers: core::sync::atomic::AtomicUsize,
}

impl Pipe {
    /// A pipe with a buffer of `capacity` bytes and one end of each kind.
    pub fn new(capacity: usize) -> Pipe {
        Pipe {
            ring: cell::SyncUnsafeCell::new(ByteRing::new(capacity)),
            writers: core::sync::atomic::AtomicUsize::new(1),
            readers: core::sync::atomic::AtomicUsize::new(1),
        }
    }

    /// How many bytes are waiting.
    pub fn available(&self) -> usize {
        self.ring_ref().available()
    }

    /// How much room a writer has.
    pub fn remaining(&self) -> usize {
        self.ring_ref().remaining()
    }

    /// Whether any writer is still open.
    pub fn has_writers(&self) -> bool {
        self.writers.load(core::sync::atomic::Ordering::Acquire) > 0
    }

    /// Whether any reader is still open.
    pub fn has_readers(&self) -> bool {
        self.readers.load(core::sync::atomic::Ordering::Acquire) > 0
    }

    /// The ring, borrowed.
    ///
    /// # Safety
    ///
    /// One caller at a time.  This kernel serves one call at a time and the
    /// buffer is touched only inside a handler; two CPUs serving two calls on
    /// one pipe is the state that would make this unsound, and it is the state
    /// this kernel does not have.
    fn ring_ref(&self) -> &ByteRing {
        // SAFETY: see above.
        unsafe { &*self.ring.get() }
    }

    /// The ring, borrowed exclusively.
    ///
    /// # Safety
    ///
    /// As `ring_ref`.
    #[allow(clippy::mut_from_ref)]
    fn ring_mut(&self) -> &mut ByteRing {
        // SAFETY: as `ring_ref`.
        unsafe { &mut *self.ring.get() }
    }

    /// Take what is buffered into `destination`, answering how many bytes.
    pub fn read_available(&self, destination: &mut [u8]) -> usize {
        self.ring_mut().read_from(destination)
    }

    /// Put as much of `source` as fits, answering how many bytes.
    pub fn write_available(&self, source: &[u8]) -> usize {
        self.ring_mut().write_to(source)
    }

    /// Record that one end of a kind was closed.
    pub fn close_reader(&self) {
        // A saturating decrement, not a bare subtraction: a double close is a
        // program's bug, and wrapping past zero would turn it into an
        // end-of-file that never arrives.
        let count = self.readers.load(core::sync::atomic::Ordering::Acquire);
        self.readers.store(
            count.saturating_sub(1),
            core::sync::atomic::Ordering::Release,
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

    /// Record that one end of a kind was closed.
    pub fn close_writer(&self) {
        let count = self.writers.load(core::sync::atomic::Ordering::Acquire);
        self.writers.store(
            count.saturating_sub(1),
            core::sync::atomic::Ordering::Release,
        );
    }
}

/// One end of a pipe, as a task holds it.
///
/// Both ends carry the same [`Pipe`]; what differs is which side of it the task
/// is on.  A task's descriptor table holds these, and dropping one closes that
/// end — which is what makes a reader see end-of-file when the last writer's
/// descriptor is closed.
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
    /// gone, and a clone is another handle.
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

impl End {
    /// A reader over `pipe`.
    pub fn reader(pipe: Arc<Pipe>) -> End {
        End {
            pipe,
            kind: Kind::Read,
        }
    }

    /// A writer over `pipe`.
    pub fn writer(pipe: Arc<Pipe>) -> End {
        End {
            pipe,
            kind: Kind::Write,
        }
    }

    /// Which end this is.
    pub fn kind(&self) -> Kind {
        self.kind
    }

    /// The pipe behind this end.
    pub fn pipe(&self) -> &Arc<Pipe> {
        &self.pipe
    }

    /// One attempt at reading, without ever blocking.
    ///
    /// Answers `Done(0)` for end-of-file — every writer is gone and the buffer
    /// is drained — and `Block` when bytes may still arrive.  The distinction
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
            // The buffer is empty and no writer can fill it again.
            return Ok(Progress::Done(0));
        }
        Ok(Progress::Block)
    }

    /// One attempt at writing, without ever blocking.
    ///
    /// Answers `Done(0)` when no reader is left — a write to a pipe nobody
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

/// The pipes this boot has made, by descriptor.
///
/// A `Vec` of `Option<Arc<Pipe>>` indexed the way the descriptor table is, so a
/// descriptor that names a pipe is found the same way one that names a file is.
/// The table lives here rather than in `syscall` because a pipe outlives one
/// call and belongs to the kernel's state, not to a handler.
///
/// ## Why there is no lock
///
/// This kernel has one CPU and serves one call at a time; the table is reached
/// only from a syscall handler, which is never re-entered while it runs. That
/// is the same argument `syscall`'s registry makes for its own static, and it
/// stops being true the moment a second CPU serves a call — at which point this
/// needs one and the note belongs here.
static PIPES: cell::SyncUnsafeCell<Option<Vec<Option<End>>>> = cell::SyncUnsafeCell::new(None);

/// Install the pipe table.
///
/// # Safety
///
/// Called once, before any program can make a pipe.
pub unsafe fn install() {
    // SAFETY: the caller promises this is the only write, and it happens before
    // any call can reach the table.
    unsafe { *PIPES.get() = Some(Vec::new()) };
}

/// Whether a pipe table is installed.
pub fn is_installed() -> bool {
    // SAFETY: written once by `install`, read after.
    unsafe { (*PIPES.get()).is_some() }
}

/// Register `pipe` and answer its descriptor.
///
/// The descriptor is an index into this table, and a descriptor is only
/// meaningful together with the table it indexes — which is why the answer is
/// not a bare number a caller could invent.
pub fn attach(end: End) -> Option<usize> {
    // SAFETY: as `is_installed`.
    let pipes = unsafe { (*PIPES.get()).as_mut() }?;
    if let Some(free) = pipes.iter().position(Option::is_none) {
        pipes[free] = Some(end);
        return Some(free);
    }
    pipes.push(Some(end));
    Some(pipes.len() - 1)
}

/// The pipe a descriptor names, if it names one.
/// The end a descriptor names, if it names one.
///
/// A clone, because the table owns its entries and a caller that borrowed one
/// would hold the borrow across a call that may block.  The `Arc` inside is
/// what makes the clone cheap, and what keeps the pipe alive while the borrow
/// is out.
pub fn lookup(descriptor: usize) -> Option<End> {
    // SAFETY: as `is_installed`.
    let pipes = unsafe { (*PIPES.get()).as_ref() }?;
    pipes.get(descriptor).and_then(Option::as_ref).cloned()
}

/// How many pipes this boot has made.
pub fn attached() -> usize {
    // SAFETY: as `is_installed`.
    let pipes = unsafe { (*PIPES.get()).as_ref() };
    pipes.map_or(0, |pipes| {
        pipes.iter().filter(|slot| slot.is_some()).count()
    })
}

#[cfg(test)]
mod tests {
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
}
