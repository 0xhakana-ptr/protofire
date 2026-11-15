//! abi/src/syscall.rs
//!
//! The syscall wire format: how a number becomes a call, and how a result
//! becomes a number.
//!
//! ## Why the encoding lives here
//!
//! A syscall's return value is one machine word, and an error is that word's
//! high end rather than a separate channel: `usize::MAX - code` puts every
//! error above `ERROR_STATUS_FLOOR`, which is above any value a call returns on
//! success.  Both sides of the boundary compute it, so both sides have to agree
//! on the same three constants and the same arithmetic.  Putting them in this
//! crate is what makes that agreement a shared definition instead of two
//! copies and a test.

use crate::error::Error;
use crate::error::Result;

/// How many arguments a syscall takes.
///
/// The number is the ABI's: a program builds its call with this many registers
/// and the kernel reads the same count, so a disagreement is a call that reads
/// past what the caller set.
pub const ARG_COUNT: usize = 6;

/// The lowest status word that means failure rather than success.
///
/// A successful call returns a non-negative value, a count, a descriptor, a
/// zero, and every error encodes near the top of the range.  The floor is
/// therefore the *top* of the success range, not the bottom of the error one:
/// `usize::MAX / 2` is far above any value a call returns and far below any
/// encoded error, so the gap between the two is the margin that keeps a status
/// from a future build (an error code this one does not know) on the failure
/// side.
///
/// Computing it as `usize::MAX - ERROR_CODE_MAX` would put the floor *below*
/// every unknown code: a status naming error 14 then decodes as
/// `Ok(usize::MAX - 14)`, so a failure in a newer program is reported to its
/// caller as a successful return of an enormous count.  Two constants cannot
/// both be "the boundary" when the list of codes can grow.
pub const ERROR_STATUS_FLOOR: usize = usize::MAX / 2;

/// The highest error code this ABI defines.
///
/// Kept in step with [`Error`]'s discriminants by the assertion below rather
/// than by two independent edits.
pub const ERROR_CODE_MAX: usize = 13;

// A variant added to `Error` without moving `ERROR_CODE_MAX` would encode to a
// word below the floor, a failure that reads as success, which is the worst
// direction for this to be wrong in.  This is where that is refused.
const _: () = assert!(ERROR_CODE_MAX == Error::NoSpace as usize);

/// Encode an error as the status word a syscall returns.
pub const fn encode_error(error: Error) -> usize {
    usize::MAX - error as usize
}

/// Encode a result as the status word a syscall returns.
pub fn encode_result(result: Result<usize>) -> usize {
    match result {
        Ok(value) => value,
        Err(error) => encode_error(error),
    }
}

/// Whether a status word means failure.
pub const fn is_error_status(status: usize) -> bool {
    status >= ERROR_STATUS_FLOOR
}

/// Decode a status word into a result.
///
/// A code outside the table is reported as `InternalError`: the caller's build
/// knows a variant this one does not, and there is nothing more specific this
/// side can honestly say.  Keeping it an error, rather than returning `Ok`, ///
/// is the part that matters; the particular variant is a guess either way.
pub fn decode_result(status: usize) -> Result<usize> {
    if !is_error_status(status) {
        return Ok(status);
    }

    let code = usize::MAX - status;
    Err(Error::from_syscall_code(code).unwrap_or(Error::InternalError))
}

#[cfg(test)]
mod tests {
    use super::ERROR_CODE_MAX;
    use super::ERROR_STATUS_FLOOR;
    use super::decode_result;
    use super::encode_error;
    use super::encode_result;
    use super::is_error_status;
    use crate::error::Error;

    #[test]
    fn encoded_ok_status_round_trips() {
        assert_eq!(encode_result(Ok(1234)), 1234);
        assert_eq!(decode_result(1234), Ok(1234));
    }

    #[test]
    fn encoded_error_status_round_trips() {
        for code in 0..=ERROR_CODE_MAX {
            let error = Error::from_syscall_code(code).expect("a code the table names");
            let status = encode_error(error);
            assert!(is_error_status(status), "an error must read as one");
            assert_eq!(decode_result(status), Err(error));
        }
    }

    /// The floor has to be above every value a successful call can return and
    /// below every encoded error.  The first half is what `Ok` relies on; the
    /// second is what makes `is_error_status` a single comparison.
    #[test]
    fn the_floor_separates_success_from_failure() {
        assert!(!is_error_status(0));
        assert!(!is_error_status(ERROR_STATUS_FLOOR - 1));
        assert!(is_error_status(ERROR_STATUS_FLOOR));
        assert!(is_error_status(usize::MAX));
    }

    /// A code from a future build decodes as an error, not as success.  This is
    /// the direction that must not be wrong: reporting a failure as `Ok` gives
    /// the caller a value it will read as data.
    #[test]
    fn an_unknown_code_is_still_an_error() {
        let status = usize::MAX - (ERROR_CODE_MAX + 1);
        assert_eq!(decode_result(status), Err(Error::InternalError));
    }
}
