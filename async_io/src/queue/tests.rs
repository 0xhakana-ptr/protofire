//! async_io/src/queue/tests.rs
//!
//! The completion queue: submissions that finish out of order, and the
//! completions a caller takes.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

use crate::completion::Completion;
use crate::queue::CompletionQueue;
use crate::queue::SubmitError;
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
