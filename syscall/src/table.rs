//! syscall/src/table.rs
//!
//! Syscall number routing table and per-syscall handler dispatch glue.

use abi::Error;
use abi::Result;
use abi::syscall as syscall_abi;

// The numbering is the contract's and lives in `abi`: a program is compiled
// against these numbers, so an implementation crate that owned them would be
// one a program had to depend on to be written.  Re-exported here because this
// is where a handler author looks for it.
pub use abi::number::PUBLIC_SYSCALL_COUNT;
pub use abi::number::SyscallNumber;

// The `PROCESS_SPAWN_KNOWN_FLAGS` and `PROCESS_EXEC_KNOWN_FLAGS` sets live with
// the handlers that validate against them, not here: a set of flags is a fact
// about one operation, and this file is the operations' shared vocabulary.  It
// arrived once already and was removed in the same change, which is the
// boundary saying where it belongs.

pub type SyscallHandler = fn(&mut SyscallContext) -> Result<SyscallDispatch>;

#[derive(Debug, Clone, Copy)]
pub struct SyscallContext {
    pub number: usize,
    pub args: [usize; syscall_abi::ARG_COUNT],
    pub caller_pid: Option<u32>,
    /// The label the caller runs as, for a policy that gates on identity.
    ///
    /// A plain `u32` rather than the security crate's `MacType`, which is an
    /// alias for `u32`, so this *is* that type without this crate naming the
    /// subsystem that defines it.  The rule this file already follows is that
    /// `syscall` holds the operations' shared vocabulary and names no
    /// implementation; a field typed with `security::MacType` would be the one
    /// place it did.
    ///
    /// `None` means "no identity was supplied", which is a caller the kernel
    /// made itself.  A handler that gates on identity decides what that means;
    /// the kernel's `open` treats it as unlabelled, which the policy then
    /// decides about like any other label.
    pub identity: Option<u32>,
}

impl SyscallContext {
    pub const fn new(number: usize, args: [usize; syscall_abi::ARG_COUNT]) -> Self {
        Self {
            number,
            args,
            caller_pid: None,
            identity: None,
        }
    }

    /// The same context with `identity` recorded, for a caller that has one.
    ///
    /// A builder rather than a second constructor: every field but this one has
    /// the same value a `new` gives, and two constructors that differed in one
    /// field would be two places to keep in step.
    pub const fn with_identity(mut self, identity: u32) -> Self {
        self.identity = Some(identity);
        self
    }

    /// The same context with the calling process's id recorded.
    ///
    /// The kernel sets this for a call that came from ring 3, where the pid is
    /// the scheduler's own answer rather than something the program supplies.
    /// A handler uses it to give what the call creates an **owner**, which is
    /// what lets the process's exit release them.
    pub const fn with_caller(mut self, pid: u32) -> Self {
        self.caller_pid = Some(pid);
        self
    }

    /// Return the syscall argument at `index` (0-based).
    ///
    /// # Panics
    ///
    /// Panics if `index >= ARG_COUNT`.  All syscall handlers are expected to
    /// use compile-time-constant indices within bounds; an out-of-bounds
    /// access is a kernel bug and should fail loudly rather than silently
    /// returning 0.
    pub fn arg(&self, index: usize) -> usize {
        self.args[index]
    }
}

/// Refuse a call whose arguments from `start` on are not zero.
///
/// The reserved tail is where a future extension goes, so a call that put
/// something there is a call against a newer ABI than this build serves.
/// Public because every handler uses it, and a handler written without it is a
/// handler that silently accepts an argument it does not read.
pub fn validate_zeroed_args(context: &SyscallContext, start: usize) -> Result<()> {
    let start = start.min(context.args.len());
    if context.args[start..].iter().any(|&arg| arg != 0) {
        return Err(Error::InvalidArgument);
    }

    Ok(())
}

/// Refuse a flag word with a bit outside `known_flags`.
///
/// This is what makes adding a flag safe: the known set grows in the change
/// that defines the flag, and a caller using a flag this build does not know is
/// refused rather than having it ignored.
pub fn validate_known_flags(flags: usize, known_flags: usize) -> Result<()> {
    if flags & !known_flags != 0 {
        return Err(Error::InvalidArgument);
    }

    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallAction {
    None,
    Yield,
    Exit {
        status: usize,
    },
    ReturnFromException {
        frame_pointer: usize,
    },
    ExecProcess,
    /// Restore user context from the saved SignalFrame after async signal.
    SigReturn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyscallDispatch {
    pub value: usize,
    pub action: SyscallAction,
}

impl SyscallDispatch {
    pub const fn complete(value: usize) -> Self {
        Self {
            value,
            action: SyscallAction::None,
        }
    }

    pub const fn yield_now() -> Self {
        Self {
            value: 0,
            action: SyscallAction::Yield,
        }
    }

    pub const fn exit(status: usize) -> Self {
        Self {
            value: status,
            action: SyscallAction::Exit { status },
        }
    }

    pub const fn return_from_exception(frame_pointer: usize) -> Self {
        Self {
            value: 0,
            action: SyscallAction::ReturnFromException { frame_pointer },
        }
    }

    pub const fn exec_process() -> Self {
        Self {
            value: 0,
            action: SyscallAction::ExecProcess,
        }
    }
}

// `Table`, the array of handler slots and the `init` that fills it, lives
// with the handlers, not here.  Its only methods are `new` and `init`, and
// `init` names every subsystem in the tree; the array's element type,
// [`SyscallHandler`], is the interface and stays.  A `Table` in this crate
// would have had a `new` nobody could fill.

#[cfg(test)]
mod tests {
    use super::SyscallContext;
    use super::validate_known_flags;
    use super::validate_zeroed_args;
    use abi::Error;

    /// Trailing arguments that must be zero are accepted when they are.
    #[test]
    fn validate_zeroed_args_accepts_zeroed_trailing_slots() {
        let context = SyscallContext::new(0, [1, 2, 0, 0, 0, 0]);
        assert_eq!(validate_zeroed_args(&context, 2), Ok(()));
        assert_eq!(validate_zeroed_args(&context, 6), Ok(()));
    }

    /// A non-zero slot in the reserved tail is refused rather than ignored.
    ///
    /// The reserved arguments are where a future extension goes.  A call that
    /// put something there is a call against a newer ABI than this kernel
    /// serves, and serving it as if the argument were absent is how a program
    /// silently gets the old behaviour it did not ask for.
    #[test]
    fn validate_zeroed_args_rejects_non_zero_trailing_slots() {
        let context = SyscallContext::new(0, [1, 2, 0, 0, 7, 0]);
        assert_eq!(
            validate_zeroed_args(&context, 2),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            validate_zeroed_args(&context, 4),
            Err(Error::InvalidArgument)
        );
    }

    /// A start past the end is the same as an empty tail.
    ///
    /// A handler that passes a start beyond `ARG_COUNT` has asked to validate
    /// nothing, and refusing it would make the validator's own bound a second
    /// thing a caller has to track.
    #[test]
    fn a_start_past_the_end_validates_nothing() {
        let context = SyscallContext::new(0, [1, 2, 3, 4, 5, 6]);
        assert_eq!(validate_zeroed_args(&context, 99), Ok(()));
    }

    /// Flag validation accepts a subset and refuses a bit it was not told
    /// about.
    ///
    /// This is what makes a new flag safe to add: the validator's `known` set
    /// grows in the change that defines the flag, and a caller using a flag
    /// this build does not know is refused rather than having it ignored.
    #[test]
    fn validate_known_flags_accepts_subsets_and_rejects_unknown_bits() {
        assert_eq!(validate_known_flags(0b0011, 0b0111), Ok(()));
        assert_eq!(validate_known_flags(0, 0b0111), Ok(()));
        assert_eq!(validate_known_flags(0b0111, 0b0111), Ok(()));
        assert_eq!(
            validate_known_flags(0b1000, 0b0111),
            Err(Error::InvalidArgument)
        );
    }
}
