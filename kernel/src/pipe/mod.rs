//! kernel/src/pipe/mod.rs
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
    /// How many write ends are open.  Zero means a reader will see end-of-file.
    writers: core::sync::atomic::AtomicUsize,
    /// How many read ends are open.  Zero means a writer's bytes go nowhere.
    readers: core::sync::atomic::AtomicUsize,
}

impl Pipe {
    /// A pipe with a buffer of `capacity` bytes and one end of each kind.
    pub fn new(capacity: usize) -> Pipe {
        Pipe {
            ring: sync::Mutex::new(ByteRing::new(capacity)),
            writers: core::sync::atomic::AtomicUsize::new(1),
            readers: core::sync::atomic::AtomicUsize::new(1),
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
/// end, which is what makes a reader see end-of-file when the last writer's
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
    pub fn reader(pipe: Arc<Pipe>) -> End {
        End {
            pipe,
            kind: Kind::Read,
        }
    }

    pub fn writer(pipe: Arc<Pipe>) -> End {
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
pub fn attach(end: End) -> Option<usize> {
    crate::syscall::attach_pipe(end)
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

#[cfg(test)]
mod tests;
