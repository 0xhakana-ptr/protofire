//! async_io/src/request.rs
//!
//! A submitted operation, from the caller's side.
//!
//! ## The token
//!
//! Every request carries a [`RequestId`] the caller chooses.  The queue never
//! interprets it — it is the caller's own handle, which is why the same number
//! can mean "the read at offset 4096" to one service and "job 7" to another.
//! This is the `user_data` field of an `io_uring` entry generalised: a value
//! that survives the round trip and belongs to whoever submitted it.
//!
//! ## The state
//!
//! A request is [`Pending`](RequestState::Pending) until the service finishes
//! it, and the completion says how.  There is deliberately no `Cancelled` state
//! a caller can set: cancellation is a *request* a service may honour, and a
//! flag the caller could flip under a service already reading the request would
//! be a race with no owner.

use abi::Error;

/// The caller's handle for a request.
///
/// Opaque to the queue.  A service that needs more than a number carries it in
/// the operation it accepts, not here: the token is what comes back, and making
/// it larger would make every completion larger for callers that only need an
/// index.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RequestId(pub u64);

impl RequestId {
    /// A token from a caller's own numbering.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The number, for a caller that stores it in its own table.
    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Where a submitted request has got to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestState {
    /// Accepted, and not finished.  The service owes a completion.
    Pending,
    /// Finished.  The completion carries the outcome.
    Done,
}

/// One submitted operation.
///
/// The operation itself is the service's to define: this struct carries what
/// the *queue* needs — the token and the state — and the service keeps the rest
/// in whatever form its own work takes.  A disk queue holds a block address and
/// a buffer pointer; a program launcher holds a path and an argument vector;
/// neither of those belongs in a type the queue names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request {
    /// The caller's handle, returned in the completion.
    pub id: RequestId,
    /// Where the request has got to.
    pub state: RequestState,
}

impl Request {
    /// A request that has just been accepted and is not finished.
    pub const fn pending(id: RequestId) -> Self {
        Self {
            id,
            state: RequestState::Pending,
        }
    }

    /// Whether the service still owes a completion.
    pub const fn is_pending(self) -> bool {
        matches!(self.state, RequestState::Pending)
    }
}

/// Why a completion is what it is.
///
/// The two arms are not "success and failure" in the `Result` sense: a
/// completed read of zero bytes is a success that returned nothing, and a
/// cancelled request is not an error the service made.  A caller that only
/// wants "did it work" folds the second arm with `matches!`, and a caller that
/// wants to tell a short read from a refusal does not have to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionStatus {
    /// The operation finished.  The value is what the service returns on
    /// success — a byte count, a descriptor, zero.
    Ok(usize),
    /// The operation did not finish, and this says why.
    Err(Error),
}

#[cfg(test)]
mod tests {
    use super::CompletionStatus;
    use super::Request;
    use super::RequestId;
    use super::RequestState;
    use abi::Error;

    #[test]
    fn a_new_request_is_pending() {
        let request = Request::pending(RequestId::new(7));
        assert_eq!(request.state, RequestState::Pending);
        assert!(request.is_pending());
        assert_eq!(request.id.get(), 7);
    }

    /// The token survives the round trip unchanged, including the values a
    /// caller is most likely to use as sentinels.
    #[test]
    fn the_token_is_the_callers() {
        for value in [0, 1, u64::MAX / 2, u64::MAX] {
            assert_eq!(RequestId::new(value).get(), value);
        }
    }

    /// A zero-byte success is not a failure, which is the distinction the two
    /// arms exist to keep: `Ok(0)` is a finished read of nothing, and folding
    /// it into an error would make every end-of-file a reported failure.
    #[test]
    fn a_zero_byte_success_is_a_success() {
        assert_eq!(CompletionStatus::Ok(0), CompletionStatus::Ok(0));
        assert_ne!(
            CompletionStatus::Ok(0),
            CompletionStatus::Err(Error::NotFound)
        );
    }
}
