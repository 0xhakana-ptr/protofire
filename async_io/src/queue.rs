//! async_io/src/queue.rs
//!
//! The bounded queue a service puts completions in.
//!
//! ## Why bounded
//!
//! A completion is a value a service produces and a caller takes.  If the
//! producer can outrun the consumer forever, the queue is a memory leak with a
//! polite name — and a service that completed four thousand requests during one
//! syscall is exactly the shape that fills one.  So the queue has a capacity,
//! and filling it is an error the producer is told about rather than a silent
//! allocation.
//!
//! This is the same decision an `io_uring` makes with its completion ring: the
//! program sizes it, and a kernel with no room does not grow it.
//!
//! ## Why the queue and not the service owns the bound
//!
//! A service that tracked its own overflow would report it differently from the
//! next one.  Here the accounting is in one place and the tests below use it:
//! what went in, what came out, and what was refused.

use crate::completion::Completion;
use crate::request::RequestId;

/// Why a completion could not be queued.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubmitError {
    /// The queue is full: the caller has not been taking completions.
    Full,
}

/// A bounded FIFO of completions.
///
/// FIFO rather than ordered by request id: a service may finish requests out of
/// order — a short read and a long one both land when they land — and
/// reordering them would be a policy about fairness this crate has no basis
/// for.  The order is the order they finished, which is the one fact the queue
/// actually has.
pub struct CompletionQueue {
    entries: alloc::collections::VecDeque<Completion>,
    capacity: usize,
    /// How many completions were refused because the queue was full.
    ///
    /// Kept rather than only returned: a service that ignored the error still
    /// leaves a trace, and the boot line that reports it is how a workload that
    /// outran its ring becomes visible instead of being a dropped completion.
    refused: u64,
}

impl CompletionQueue {
    /// A queue that holds at most `capacity` completions.
    ///
    /// A capacity of zero is refused by [`Self::try_new`] and by `new` in a
    /// debug build: a queue that can hold nothing accepts nothing, and a caller
    /// that asked for one has almost certainly passed the wrong number.
    pub fn new(capacity: usize) -> Self {
        debug_assert!(capacity > 0, "a completion queue of zero holds nothing");
        Self {
            entries: alloc::collections::VecDeque::with_capacity(capacity),
            capacity,
            refused: 0,
        }
    }

    /// A queue that holds at most `capacity` completions, or `None` for zero.
    pub fn try_new(capacity: usize) -> Option<Self> {
        if capacity == 0 {
            return None;
        }
        Some(Self::new(capacity))
    }

    /// How many completions the queue will hold.
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// How many are waiting.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is waiting.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// How many completions were refused for want of room.
    pub fn refused(&self) -> u64 {
        self.refused
    }

    /// Put a completion in, or report that there was no room.
    pub fn push(&mut self, completion: Completion) -> Result<(), SubmitError> {
        if self.entries.len() >= self.capacity {
            self.refused = self.refused.saturating_add(1);
            return Err(SubmitError::Full);
        }
        self.entries.push_back(completion);
        Ok(())
    }

    /// Take the oldest completion, if any.
    pub fn pop(&mut self) -> Option<Completion> {
        self.entries.pop_front()
    }

    /// Take the completion for one request, leaving the others in order.
    ///
    /// Not the normal path — a caller takes whatever finished first — but a
    /// caller waiting on one particular request needs it, and removing it by
    /// scanning is the only way to keep the remaining order intact.
    pub fn take(&mut self, id: RequestId) -> Option<Completion> {
        let position = self.entries.iter().position(|entry| entry.id == id)?;
        self.entries.remove(position)
    }
}

#[cfg(test)]
mod tests;
