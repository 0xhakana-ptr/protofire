//! abi/src/error.rs
//!
//! The kernel's error type, which is also a wire format.
//!
//! ## Why this is an ABI type and not a kernel one
//!
//! A syscall returns a number, and an error is that number's high end:
//! `encode_error` computes `usize::MAX - code`, so the discriminant of every
//! variant below *is* the value user space decodes.  A type whose layout is
//! read by another privilege level belongs where the rest of the wire format
//! lives, otherwise the kernel's `Error` and the ABI's code table are two
//! descriptions of one thing, and nothing makes them agree.
//!
//! Splitting them is what puts the kernel's `Error` and the ABI's code table in
//! two places: the enum in one crate root and the constants in a copy the user
//! side compiles, kept in step by an assertion.  One crate both sides depend on
//! is what makes that assertion unnecessary rather than merely cheap.
//!
//! ## Adding a variant
//!
//! Append.  The discriminants are the wire format, so renumbering one changes
//! what an already-built program decodes, the frozen range's promise is that a
//! number keeps its meaning, and this enum is the same promise stated once.

/// Result type used throughout the kernel and by the ABI's own helpers.
pub type Result<T> = core::result::Result<T, Error>;

/// Error codes used by the kernel and user-space programs.
///
/// These are represented as `usize` values for system call return codes: the
/// wire value of variant `n` is `usize::MAX - n`, which is what
/// [`crate::syscall::encode_error`] computes and what every program built
/// against this ABI decodes.
#[repr(usize)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Invalid argument passed to a syscall.
    InvalidArgument = 0,
    /// Resource or file not found.
    NotFound = 1,
    /// Resource or file already exists.
    AlreadyExists = 2,
    /// Insufficient permissions.
    PermissionDenied = 3,
    /// Memory allocation failed.
    OutOfMemory = 4,
    /// Hardware or device error.
    DeviceError = 5,
    /// Resource is busy.
    Busy = 6,
    /// Operation timed out.
    TimedOut = 7,
    /// Operation not supported.
    Unsupported = 8,
    /// Feature not implemented.
    NotImplemented = 9,
    /// Internal kernel error.
    InternalError = 10,
    /// Authentication failed (bad password, and the like).
    InvalidCredential = 11,
    /// TCP/DCCP connection reset by peer, or the network's own reset.
    ConnectionReset = 12,
    /// Device or filesystem has no free space left.
    NoSpace = 13,
}

impl Error {
    /// Convert an error code to a human-readable string.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "invalid argument",
            Self::NotFound => "not found",
            Self::AlreadyExists => "already exists",
            Self::PermissionDenied => "permission denied",
            Self::OutOfMemory => "out of memory",
            Self::DeviceError => "device error",
            Self::Busy => "resource busy",
            Self::TimedOut => "timed out",
            Self::Unsupported => "unsupported",
            Self::NotImplemented => "not implemented",
            Self::InternalError => "internal error",
            Self::InvalidCredential => "invalid credential",
            Self::ConnectionReset => "connection reset",
            Self::NoSpace => "no space left on device",
        }
    }

    /// Convert a raw syscall return code to an `Error`.
    ///
    /// Returns `None` if the code does not name a variant: a status word from
    /// a program built against a longer version of this list is a value this
    /// build cannot name, and inventing one would report the wrong failure.
    pub const fn from_syscall_code(code: usize) -> Option<Self> {
        match code {
            0 => Some(Self::InvalidArgument),
            1 => Some(Self::NotFound),
            2 => Some(Self::AlreadyExists),
            3 => Some(Self::PermissionDenied),
            4 => Some(Self::OutOfMemory),
            5 => Some(Self::DeviceError),
            6 => Some(Self::Busy),
            7 => Some(Self::TimedOut),
            8 => Some(Self::Unsupported),
            9 => Some(Self::NotImplemented),
            10 => Some(Self::InternalError),
            11 => Some(Self::InvalidCredential),
            12 => Some(Self::ConnectionReset),
            13 => Some(Self::NoSpace),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Error;

    /// The discriminants are the wire format, so they are pinned here rather
    /// than left to declaration order.  A variant inserted in the middle would
    /// renumber every one after it, and every already-built program would
    /// decode a different error than the kernel returned, silently, because
    /// both numbers are valid.
    #[test]
    fn every_discriminant_is_pinned() {
        assert_eq!(Error::InvalidArgument as usize, 0);
        assert_eq!(Error::NotFound as usize, 1);
        assert_eq!(Error::AlreadyExists as usize, 2);
        assert_eq!(Error::PermissionDenied as usize, 3);
        assert_eq!(Error::OutOfMemory as usize, 4);
        assert_eq!(Error::DeviceError as usize, 5);
        assert_eq!(Error::Busy as usize, 6);
        assert_eq!(Error::TimedOut as usize, 7);
        assert_eq!(Error::Unsupported as usize, 8);
        assert_eq!(Error::NotImplemented as usize, 9);
        assert_eq!(Error::InternalError as usize, 10);
        assert_eq!(Error::InvalidCredential as usize, 11);
        assert_eq!(Error::ConnectionReset as usize, 12);
        assert_eq!(Error::NoSpace as usize, 13);
    }

    /// `from_syscall_code` and the discriminants have to agree in both
    /// directions: a code that decodes to a variant must be the variant's own
    /// value, or `encode_error` and `decode_result` disagree about the same
    /// failure.
    #[test]
    fn the_code_table_round_trips() {
        for code in 0..=13usize {
            let error = Error::from_syscall_code(code).expect("a code the table names");
            assert_eq!(error as usize, code);
        }
        assert_eq!(Error::from_syscall_code(14), None);
    }

    #[test]
    fn every_variant_has_a_message() {
        for code in 0..=13usize {
            let error = Error::from_syscall_code(code).expect("a code the table names");
            assert!(!error.as_str().is_empty());
        }
    }
}
