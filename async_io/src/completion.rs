//! async_io/src/completion.rs
//!
//! What a service says when it finishes a request.

use crate::request::CompletionStatus;
use crate::request::RequestId;

/// A finished request, as the caller hears about it.
///
/// Delivered once.  The id is the token the caller chose, so a caller that
/// submitted several requests can match completions to submissions without the
/// queue remembering which was which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Completion {
    /// The token of the request this finishes.
    pub id: RequestId,
    /// What happened.
    pub status: CompletionStatus,
}

impl Completion {
    /// A completion for a request that finished successfully.
    pub const fn ok(id: RequestId, value: usize) -> Self {
        Self {
            id,
            status: CompletionStatus::Ok(value),
        }
    }

    /// A completion for a request that did not finish.
    pub const fn err(id: RequestId, error: abi::Error) -> Self {
        Self {
            id,
            status: CompletionStatus::Err(error),
        }
    }

    /// Whether the request finished successfully.
    pub const fn is_ok(&self) -> bool {
        matches!(self.status, CompletionStatus::Ok(_))
    }
}

#[cfg(test)]
mod tests {
    use super::Completion;
    use crate::request::CompletionStatus;
    use crate::request::RequestId;
    use abi::Error;

    #[test]
    fn a_completion_carries_its_request_and_outcome() {
        let done = Completion::ok(RequestId::new(3), 4096);
        assert_eq!(done.id, RequestId::new(3));
        assert_eq!(done.status, CompletionStatus::Ok(4096));
        assert!(done.is_ok());

        let failed = Completion::err(RequestId::new(4), Error::DeviceError);
        assert_eq!(failed.id, RequestId::new(4));
        assert_eq!(failed.status, CompletionStatus::Err(Error::DeviceError));
        assert!(!failed.is_ok());
    }
}
