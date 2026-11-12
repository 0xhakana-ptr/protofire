//! kernel/src/service/mod.rs
//!
//! The boot's side of the service table: what it installs, in what order, and
//! the freeze that closes it.
//!
//! **Parked on purpose.**  The clock is the one service, and it is here to show
//! the table working end to end — not as the start of a list that should grow
//! now.  `docs/status.md` says why, and what has to exist before it resumes.
//!
//! ## Why the boot installs and the crate does not
//!
//! `service` knows how to hold a table; only the boot knows which services this
//! kernel has.  Keeping the list here means "what exists" is one file a reader
//! can read, rather than an answer assembled from whatever crates happened to
//! be linked.
//!
//! ## The order, and why the freeze is the last line
//!
//! Every service is installed, then the table is frozen, and only then is
//! anything looked up.  Installing after a freeze is refused by the table, so
//! the sequence is enforced rather than described: a service added later in the
//! boot would fail loudly instead of being invisible.

pub mod clock;

#[cfg(target_os = "none")]
use async_io::Request;
#[cfg(target_os = "none")]
use async_io::RequestId;

/// The name the clock answers to.
///
/// `&'static str`, which is what `service_table::install` requires: a service's
/// name is part of this boot's code and not something built at run time.
pub const CLOCK_NAME: &str = "clock";

/// How many polls a boot gives a service before it calls the request
/// unanswered.
///
/// The clock answers in the call, so this is not spent today; it is the bound a
/// `&mut dyn Service` needs the moment it holds something that waits, and a
/// caller with no bound would hang a boot on a service that never completes.
#[cfg(target_os = "none")]
const POLLS: usize = 8;

/// Install every service this kernel has, then close the table.
///
/// Returns how many are installed, which is what the boot's line reports.
pub fn install_all() -> usize {
    let mut installed = 0usize;
    match clock::install() {
        Ok(()) => installed += 1,
        Err(error) => {
            arch::serial::write_str("protofire: clock service refused: ");
            arch::serial::write_str(match error {
                service_table::InstallError::NameTaken => "the name is taken",
                service_table::InstallError::TableFull => "the table is full",
                service_table::InstallError::Frozen => "the table is frozen",
            });
            arch::serial::write_str("\n");
        }
    }
    service_table::freeze();
    installed
}

/// Ask the clock what the counter reads, through the table.
///
/// This is the self-test: it does not call [`clock::Clock`] directly, because
/// what is being checked is the **table** — that a name resolves, that the
/// handle drives the service through the trait, and that the completion comes
/// back with the caller's token.  A boot that called the service directly would
/// exercise none of it.
///
/// Returns the reading, or `None` when the name does not resolve or the service
/// never completed.
#[cfg(target_os = "none")]
pub fn read_the_clock() -> Option<usize> {
    let token = RequestId::new(1);
    let completion = service_table::request(CLOCK_NAME, Request::pending(token), POLLS)?;
    if completion.id != token || !completion.is_ok() {
        return None;
    }
    match completion.status {
        async_io::CompletionStatus::Ok(value) => Some(value),
        async_io::CompletionStatus::Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    //! What is testable without a machine: the name the boot installs under,
    //! and that the request this module builds is the one a service would
    //! accept.

    use super::CLOCK_NAME;

    /// The name is the one a caller types, and it is not empty.
    #[test]
    fn the_clock_has_a_name_a_caller_can_type() {
        assert_eq!(CLOCK_NAME, "clock");
    }
}
