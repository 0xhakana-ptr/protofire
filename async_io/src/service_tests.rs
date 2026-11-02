//! async_io/src/service_tests.rs
//!
//! A service that is not a driver: a counting one, to show the trait carries
//! the obligations and not only the method names.
//!
//! The point of these tests is the *shape* of the contract.  A trait with three
//! methods and no implementor is a sentence; a service that is written against
//! it, completes every request it accepted, and is checked for that is what
//! makes it a design.  The same three tests are what a disk queue, a socket and
//! a program launcher will each be held to.

use crate::completion::Completion;
use crate::queue::CompletionQueue;
use crate::request::Request;
use crate::request::RequestId;
use crate::service::Service;
use abi::Error;

/// A service that finishes a request after `delay` polls.
///
/// The simplest thing that is genuinely asynchronous: `submit` accepts and
/// returns nothing, each `poll` gets one step closer, and the completion
/// arrives on the poll that reaches zero.  A driver's `delay` is a transfer;
/// the contract is the same.
struct DelayedService {
    /// How many polls each accepted request waits.
    delay: u32,
    /// Requests accepted and not yet completed, with their remaining delay.
    in_flight: alloc::vec::Vec<(RequestId, u32)>,
    /// Where completions go.
    completions: CompletionQueue,
}

impl DelayedService {
    fn new(delay: u32, capacity: usize) -> Self {
        Self {
            delay,
            in_flight: alloc::vec::Vec::new(),
            completions: CompletionQueue::new(capacity),
        }
    }
}

impl Service for DelayedService {
    fn submit(&mut self, request: Request) -> Option<Completion> {
        if self.delay == 0 {
            // The fast path: finished in the call, which the trait allows and a
            // caller that wants an answer now relies on.
            return Some(Completion::ok(request.id, 0));
        }
        self.in_flight.push((request.id, self.delay));
        None
    }

    /// Returns whether a completion is *ready*, which is the trait's word.
    ///
    /// The first version of this returned "did anything change", and the test
    /// below failed on it: a poll that decremented a delay had changed
    /// something and had produced nothing, and the two answers disagree for
    /// exactly one poll per request.  The trait means the second — a driver's
    /// poll is "drain what the device finished", not "advance time" — so the
    /// service says what the trait says.
    fn poll(&mut self) -> bool {
        let mut completed = false;
        let mut still_waiting = alloc::vec::Vec::new();
        for (id, remaining) in core::mem::take(&mut self.in_flight) {
            let next = remaining.saturating_sub(1);
            if next == 0 {
                // The queue refusing here is a real failure a driver would have
                // to report; this test service sizes its queue for itself.
                let _ = self.completions.push(Completion::ok(id, 0));
                completed = true;
            } else {
                still_waiting.push((id, next));
            }
        }
        self.in_flight = still_waiting;
        completed
    }

    fn cancel(&mut self, id: RequestId) -> bool {
        let Some(position) = self.in_flight.iter().position(|(waiter, _)| *waiter == id) else {
            return false;
        };
        self.in_flight.remove(position);
        let _ = self.completions.push(Completion::err(id, Error::Busy));
        true
    }
}

/// A request that is finished in the call never reaches the queue.
#[test]
fn a_zero_delay_service_answers_immediately() {
    let mut service = DelayedService::new(0, 4);
    let done = service
        .submit(Request::pending(RequestId::new(1)))
        .expect("finished in the call");
    assert_eq!(done.id, RequestId::new(1));
    assert!(done.is_ok());
    assert!(!service.poll(), "nothing is in flight");
}

/// A request admitted and completed later arrives through the queue, exactly
/// once, after the number of polls the service promised.
#[test]
fn a_delayed_request_completes_after_its_polls() {
    let mut service = DelayedService::new(2, 4);
    assert!(
        service
            .submit(Request::pending(RequestId::new(7)))
            .is_none()
    );

    assert!(!service.poll(), "the first poll produced no completion");
    assert!(service.completions.is_empty(), "and queued nothing");

    assert!(service.poll(), "the second poll finished it");
    let done = service.completions.pop().expect("the completion arrived");
    assert_eq!(done.id, RequestId::new(7));
    assert!(done.is_ok());
    assert!(service.completions.pop().is_none(), "and only once");
}

/// Cancelling a pending request produces a completion, because a caller with
/// nowhere to put a completion for the request it cancelled would leak the
/// token.
#[test]
fn cancelling_produces_a_completion() {
    let mut service = DelayedService::new(3, 4);
    assert!(
        service
            .submit(Request::pending(RequestId::new(9)))
            .is_none()
    );

    assert!(service.cancel(RequestId::new(9)), "it was still pending");
    let done = service
        .completions
        .pop()
        .expect("the cancellation completed");
    assert_eq!(done.id, RequestId::new(9));
    assert!(!done.is_ok());

    // And cancelling it again says so rather than producing a second
    // completion.
    assert!(!service.cancel(RequestId::new(9)));
    assert!(service.completions.pop().is_none());
}

/// A service answers for every request it accepted: after the polls it
/// promised, the number of completions equals the number of in-flight
/// submissions.
///
/// This is the obligation the trait states in prose and cannot enforce.  It is
/// checkable here because the service's own accounting is visible; a driver's
/// is not, which is why the gate that matters for one is a boot that drains its
/// queue rather than a unit test.
#[test]
fn every_accepted_request_is_completed() {
    let mut service = DelayedService::new(1, 16);
    let submitted = 5u64;
    for id in 0..submitted {
        assert!(
            service
                .submit(Request::pending(RequestId::new(id)))
                .is_none()
        );
    }
    assert!(service.poll());
    let mut completed = 0;
    while service.completions.pop().is_some() {
        completed += 1;
    }
    assert_eq!(completed, submitted as usize);
}
