//! kernel/src/service/clock.rs
//!
//! The first service in the table that reads a machine.
//!
//! ## Why the clock is the first one
//!
//! Every other candidate would have been a byte slice dressed as a device:
//! `async_io`'s own `MemoryBlockService` is exactly that, and registering it
//! would have made the table's first entry a copy of the thing it was built to
//! demonstrate.  A clock is different in the two ways that matter — it answers
//! from hardware rather than from memory, and its answer is different every
//! time it is asked — so a boot that submits to it and gets a number back has
//! shown that a *real* source of values fits behind the trait.
//!
//! It is also the smallest such service: one operation, no state to corrupt, no
//! buffer to validate.  The point of this change is the table, and a service
//! with a bug would have made a red boot ambiguous between two things.
//!
//! ## What the operation is
//!
//! The request's two argument words are unused: "read the counter" takes no
//! parameters, and inventing a parameter so the request looks busy would be a
//! wire format with nothing in it.  The completion's value is the counter's
//! reading, which is `u64` narrowed to `usize` — on every machine this tree
//! builds for those are the same width, and the truncation is named here rather
//! than left as a cast a reader has to trust.

use alloc::boxed::Box;
use alloc::sync::Arc;

use async_io::Completion;
use async_io::Request;
use async_io::RequestId;
use async_io::Service;
use sync::Mutex;

use crate::service::CLOCK_NAME;

/// A service whose operation is "read the machine's counter".
pub struct Clock;

impl Clock {
    /// The service, in the form the table stores.
    ///
    /// `Arc<Mutex<Box<dyn Service + Send>>>` rather than `Arc<Clock>`: the
    /// table holds services of different kinds behind one type, and building
    /// the trait object here means the boot installs exactly what a lookup
    /// returns.
    pub fn shared() -> Arc<Mutex<Box<dyn Service + Send>>> {
        Arc::new(Mutex::new(Box::new(Clock) as Box<dyn Service + Send>))
    }

    /// The counter's reading, as the machine reports it.
    ///
    /// `unsafe` because a machine without its timer running answers a constant,
    /// and the caller's contract is the one `arch::timer_counter` states: read
    /// it after the timer is up.
    #[cfg(target_os = "none")]
    fn read() -> usize {
        // SAFETY: the boot brings the timer up before it installs this service,
        // which is this module's only caller.
        unsafe { arch::timer_counter() as usize }
    }

    /// A host has no counter to read, so it answers a constant.
    ///
    /// Not a fabricated reading: a host build cannot install this service at
    /// all — there is no boot — so the only caller is a test, and a test that
    /// wanted a moving number would be testing the host's clock.
    #[cfg(not(target_os = "none"))]
    fn read() -> usize {
        0
    }
}

impl Service for Clock {
    /// Answer the reading in the call.
    ///
    /// A counter read finishes when it happens, so there is nothing to wait for
    /// and the trait's fast path is the honest one.  A service that queued this
    /// would make every caller poll for a number that was already known.
    fn submit(&mut self, request: Request) -> Option<Completion> {
        Some(Completion::ok(request.id, Clock::read()))
    }

    fn poll(&mut self) -> bool {
        false
    }

    fn cancel(&mut self, _id: RequestId) -> bool {
        false
    }

    fn take_completion(&mut self) -> Option<Completion> {
        None
    }
}

/// Install the clock under [`CLOCK_NAME`] and answer whether it took.
///
/// A refusal is printed by the caller rather than here, so one place in the
/// boot owns the report and this function stays a call.
pub fn install() -> Result<(), service_table::InstallError> {
    service_table::install(CLOCK_NAME, Clock::shared())
}

#[cfg(test)]
mod tests {
    //! A host has no `timer_counter`, so what is testable here is the part that
    //! does not touch the machine: that the service answers in the call and
    //! that the token survives.  Its reading is a boot's evidence.

    use super::Clock;
    use async_io::Request;
    use async_io::RequestId;
    use async_io::Service;

    /// The clock answers in the call, and the caller's token comes back.
    #[test]
    fn the_clock_answers_in_the_call() {
        let mut clock = Clock;
        let id = RequestId::new(11);
        let completion = clock
            .submit(Request::pending(id))
            .expect("a counter read finishes when it happens");
        assert_eq!(completion.id, id);
        assert!(completion.is_ok(), "reading a counter cannot fail");
    }

    /// Nothing is ever left to poll for.
    #[test]
    fn the_clock_has_nothing_pending() {
        let mut clock = Clock;
        assert!(!clock.poll());
        assert!(clock.take_completion().is_none());
        assert!(!clock.cancel(RequestId::new(1)));
    }
}
