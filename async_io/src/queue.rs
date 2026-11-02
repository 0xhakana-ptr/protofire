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
mod tests {
    use super::CompletionQueue;
    use super::SubmitError;
    use crate::completion::Completion;
    use crate::request::CompletionStatus;
    use crate::request::RequestId;
    use abi::Error;

    #[test]
    fn completions_come_out_in_the_order_they_went_in() {
        let mut queue = CompletionQueue::new(4);
        queue.push(Completion::ok(RequestId::new(1), 10)).unwrap();
        queue.push(Completion::ok(RequestId::new(2), 20)).unwrap();
        assert_eq!(queue.len(), 2);
        assert_eq!(queue.pop().unwrap().id, RequestId::new(1));
        assert_eq!(queue.pop().unwrap().id, RequestId::new(2));
        assert!(queue.pop().is_none());
    }

    /// The queue refuses rather than growing, and counts what it refused.  A
    /// service that ignores the refusal still leaves the count behind, which is
    /// the difference between a dropped completion and a silent one.
    #[test]
    fn a_full_queue_refuses_and_remembers() {
        let mut queue = CompletionQueue::new(2);
        queue.push(Completion::ok(RequestId::new(1), 0)).unwrap();
        queue.push(Completion::ok(RequestId::new(2), 0)).unwrap();
        assert_eq!(
            queue.push(Completion::ok(RequestId::new(3), 0)),
            Err(SubmitError::Full)
        );
        assert_eq!(queue.refused(), 1);
        assert_eq!(queue.len(), 2);
    }

    /// A queue of zero is not constructible through `try_new`, and `new`
    /// asserts in a debug build.  The refusal is the point: a queue that holds
    /// nothing is a capacity someone computed wrong.
    #[test]
    fn a_zero_capacity_queue_is_refused() {
        assert!(CompletionQueue::try_new(0).is_none());
        assert!(CompletionQueue::try_new(1).is_some());
    }

    /// Taking one request's completion leaves the others in order.
    #[test]
    fn taking_one_leaves_the_rest_in_order() {
        let mut queue = CompletionQueue::new(4);
        for id in 1..=3 {
            queue.push(Completion::ok(RequestId::new(id), 0)).unwrap();
        }
        let taken = queue.take(RequestId::new(2)).expect("the middle one");
        assert_eq!(taken.id, RequestId::new(2));
        assert_eq!(queue.pop().unwrap().id, RequestId::new(1));
        assert_eq!(queue.pop().unwrap().id, RequestId::new(3));
    }

    /// A token the queue does not hold is not found rather than removing
    /// something else — the failure a `position` mapped to `unwrap_or(0)` would
    /// produce.
    #[test]
    fn taking_an_unknown_request_finds_nothing() {
        let mut queue = CompletionQueue::new(2);
        queue.push(Completion::ok(RequestId::new(1), 0)).unwrap();
        assert!(queue.take(RequestId::new(99)).is_none());
        assert_eq!(queue.len(), 1);
    }

    /// An error completion keeps its error, and is distinguishable from a
    /// successful one with the same token.
    #[test]
    fn an_error_completion_keeps_its_error() {
        let mut queue = CompletionQueue::new(2);
        queue
            .push(Completion::err(RequestId::new(5), Error::TimedOut))
            .unwrap();
        let done = queue.pop().unwrap();
        assert_eq!(done.status, CompletionStatus::Err(Error::TimedOut));
        assert!(!done.is_ok());
    }
}
