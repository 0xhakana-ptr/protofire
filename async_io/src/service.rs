//! async_io/src/service.rs
//!
//! What a request goes to.
//!
//! ## The three methods and why each exists
//!
//! [`submit`](Service::submit) accepts a request.  It may finish it in the call
//!, a disk with a cached block does, and the honest way to say so is to
//! return the completion rather than to queue one and make the caller poll for
//! something already known.
//!
//! [`poll`](Service::poll) makes progress and reports whether anything changed.
//! A driver whose completion arrived on an interrupt has already done the work;
//! this is where it hands the results over.  A service with nothing in flight
//! returns `false` and must not spin.
//!
//! [`cancel`](Service::cancel) asks for a request to stop.  It is a request,
//! not a command: a service that has already taken the operation cannot un-take
//! it, and the completion still arrives.
//!
//! ## The obligation
//!
//! A service that accepted a request must eventually complete it.  Nothing
//! enforces that, a trait cannot, and a timeout would be a policy this crate
//! has no business having.  What makes it checkable is that everything a
//! service does goes through
//! [`CompletionQueue`](crate::queue::CompletionQueue): a request that was
//! accepted and never completed leaves the queue's accounting disagreeing with
//! the service's, and the tests here use exactly that.

use crate::completion::Completion;
use crate::request::Request;
use crate::request::RequestId;

/// Something that accepts requests and finishes them later.
///
/// The operation is the implementor's own type; the queue never sees it.  A
/// disk queue's is a block read or write, a program launcher's is a path and an
/// argument vector, and this trait is the same for both because a caller only
/// needs to know that the work will finish.
pub trait Service {
    /// Take a request, returning a completion if it finished in the call.
    ///
    /// `None` means accepted and still pending: the caller will hear about it
    /// through [`poll`](Service::poll).  Returning `Some` is the fast path, and
    /// a service that never uses it is correct but makes every caller wait a
    /// poll for work it could have had immediately.
    fn submit(&mut self, request: Request) -> Option<Completion>;

    /// Make progress, reporting whether any completions are ready.
    ///
    /// Returns `true` when calling again immediately might produce more, the
    /// distinction matters for an interrupt-driven service that drained three
    /// completions and left two, and for a polled one that found nothing and
    /// must not be spun on.
    fn poll(&mut self) -> bool;

    /// Ask for a request to stop.
    ///
    /// Returns `true` if the request was still pending and will now be
    /// completed as cancelled; `false` if it had already finished or is
    /// unknown.  The completion still arrives either way, because a caller that
    /// has nowhere to put a completion for a request it cancelled would be
    /// leaking the token.
    fn cancel(&mut self, id: RequestId) -> bool;
}
