//! kernel/src/pipe.rs
//!
//! A pipe: one buffer, two ends, and the two things a task does when its end
//! cannot make progress.
//!
//! ## What makes this the kernel's and not `ipc`'s
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
//! ## Why a blocked read is the interesting one
//!
//! `Sleep` made a task wait for a clock.  A pipe makes it wait for *another
//! task*, which is a different thing in every way that matters: there is no
//! deadline to compare against, the wake comes from a syscall rather than from
//! the timer, and the wait can end in three ways rather than one, bytes
//! arrived, the write end closed, or the wait was interrupted.  The third is
//! not implemented and this file says so where it would be.
//!
//! ## What is not here
//!
//! A wait queue with one entry per object.  There is one pipe in the boot that
//! proves this, and one blocked task, so a wake wakes every blocked task, see
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

    /// Whether any writer is still open.
    pub fn has_writers(&self) -> bool {
        self.writers.load(core::sync::atomic::Ordering::Acquire) > 0
    }

    /// Whether any reader is still open.
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
            // The buffer is empty and no writer can fill it again.
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

/// The pipes this boot has made, by descriptor.
///
/// A `Vec` of `Option<Arc<Pipe>>` indexed the way the descriptor table is, so a
/// descriptor that names a pipe is found the same way one that names a file is.
/// The table lives here rather than in `syscall` because a pipe outlives one
/// call and belongs to the kernel's state, not to a handler.
///
/// ## Why there is a lock
///
/// This table was reached only from a syscall handler, and one CPU served one
/// call at a time, so it needed none.  A second CPU serving a call makes
/// `attach` and `lookup` concurrent, and `lookup` clones an `Arc` out of a
/// `Vec` that `attach` may reallocate: a grow between the two is a read of a
/// buffer that has moved.  The lock is what makes the table one object again.
///
/// It is held for the length of one lookup or one attach and never across a
/// blocking operation.  A caller that is about to block clones the `End` first
/// and releases the lock before it does.
static PIPES: sync::Mutex<Option<Vec<Option<End>>>> = sync::Mutex::new(None);

/// Install the pipe table.
///
/// # Safety
///
/// Called once, before any program can make a pipe.
pub unsafe fn install() {
    // SAFETY: the caller promises this is the only write, and it happens before
    // any call can reach the table.
    *PIPES.lock() = Some(Vec::new());
}

/// Whether a pipe table is installed.
pub fn is_installed() -> bool {
    PIPES.lock().is_some()
}

/// Register `pipe` and answer its descriptor.
///
/// The descriptor is an index into this table, and a descriptor is only
/// meaningful together with the table it indexes, which is why the answer is
/// not a bare number a caller could invent.
pub fn attach(end: End) -> Option<usize> {
    let mut guard = PIPES.lock();
    let pipes = guard.as_mut()?;
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
    let guard = PIPES.lock();
    let pipes = guard.as_ref()?;
    pipes.get(descriptor).and_then(Option::as_ref).cloned()
}

/// How many pipes this boot has made.
pub fn attached() -> usize {
    let guard = PIPES.lock();
    guard.as_ref().map_or(0, |pipes| {
        pipes.iter().filter(|slot| slot.is_some()).count()
    })
}

#[cfg(test)]
mod tests;
