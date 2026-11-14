//! kernel/src/service/table/tests.rs
//!
//! The table's tests: installation, lookup, the freeze, and the end-to-end
//! submit-and-take through a name.
//!
//! ## Why each test builds its own table
//!
//! [`Table`] is a value with methods and [`SERVICES`](super::SERVICES) is one
//! instance of it, so a test makes the table it needs and the tests cannot see
//! each other.  The first version of this file had the table reachable only as
//! the global, and one test filling it made six others fail on `TableFull` in
//! whatever order the harness chose, a test suite that was really one test
//! written six times.
//!
//! Exactly one test touches the global, because the global is what a boot uses
//! and something has to prove the free functions reach the same code the tests
//! exercise.

use alloc::boxed::Box;
use alloc::sync::Arc;

use async_io::Completion;
use async_io::CompletionStatus;
use async_io::Request;
use async_io::RequestId;
use async_io::Service;
use sync::Mutex;

use super::InstallError;
use super::MAX_SERVICES;
use super::Shared;
use super::Table;

/// A service that answers every request in the call, with the argument word.
///
/// The simplest thing that satisfies the trait, so a failure in a table test
/// points at the table.  It is `Send` because the table stores
/// `Box<dyn Service + Send>`: a service reachable from more than one CPU has to
/// be movable between them.
struct Echo;

fn echo() -> Shared {
    Arc::new(Mutex::new(Box::new(Echo) as Box<dyn Service + Send>))
}

impl Service for Echo {
    fn submit(&mut self, request: Request) -> Option<Completion> {
        Some(Completion::ok(request.id, request.argument as usize))
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

/// A service that accepts, then completes on its next poll.
///
/// The shape a driver has: the request is taken now and finished when the
/// device says so, so `crate::request`'s polling branch is exercised.
struct AfterOnePoll {
    /// The token to answer with once the poll happens.
    waiting: Option<RequestId>,
    /// The completion, held until it is taken.
    done: Option<Completion>,
}

fn after_one_poll() -> Shared {
    Arc::new(Mutex::new(Box::new(AfterOnePoll {
        waiting: None,
        done: None,
    }) as Box<dyn Service + Send>))
}

impl Service for AfterOnePoll {
    fn submit(&mut self, request: Request) -> Option<Completion> {
        self.waiting = Some(request.id);
        None
    }

    fn poll(&mut self) -> bool {
        if let Some(id) = self.waiting.take() {
            self.done = Some(Completion::ok(id, 1));
            return true;
        }
        false
    }

    fn cancel(&mut self, _id: RequestId) -> bool {
        false
    }

    fn take_completion(&mut self) -> Option<Completion> {
        self.done.take()
    }
}

/// A service that accepts and never completes anything.
struct Never;

fn never() -> Shared {
    Arc::new(Mutex::new(Box::new(Never) as Box<dyn Service + Send>))
}

impl Service for Never {
    fn submit(&mut self, _request: Request) -> Option<Completion> {
        None
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

/// A service is found by the name it was installed under, and a name nothing
/// installed answers with `None`.
#[test]
fn a_service_is_found_by_the_name_it_was_installed_under() {
    let mut table = Table::new();
    table.install("echo", echo()).expect("installed");
    assert!(
        table.lookup("echo").is_some(),
        "the name installed is found"
    );
    assert!(
        table.lookup("nothing-installed-this").is_none(),
        "a name nothing installed answers with nothing"
    );
}

/// A second installation under the same name is refused rather than replacing.
///
/// Replacing would mean a caller that resolved a name earlier holds a service
/// the table no longer answers with, and the two would disagree for as long as
/// the handle lives.  Refusing keeps "the name means one thing" true.
#[test]
fn a_taken_name_is_refused() {
    let mut table = Table::new();
    table.install("taken", echo()).expect("the first installs");
    assert_eq!(table.install("taken", echo()), Err(InstallError::NameTaken));
    assert_eq!(table.installed(), 1, "the refusal added nothing");
}

/// The table fills, and the fill is reported rather than absorbed.
#[test]
fn a_full_table_refuses_rather_than_growing() {
    // Names owned by this test rather than borrowed from a global list: seven
    // of them, so the eighth slot is the last one and the refusal is the one
    // this test is about.
    const NAMES: [&str; MAX_SERVICES] = [
        "slot-0", "slot-1", "slot-2", "slot-3", "slot-4", "slot-5", "slot-6", "slot-7",
    ];
    let mut table = Table::new();
    for (index, name) in NAMES.iter().enumerate() {
        table
            .install(name, echo())
            .unwrap_or_else(|error| panic!("slot {index} refused: {error:?}"));
    }
    assert_eq!(table.installed(), MAX_SERVICES, "every slot is in use");
    assert_eq!(
        table.install("one-too-many", echo()),
        Err(InstallError::TableFull),
        "a full table says so instead of taking one more"
    );
}

/// A handle taken from the table submits to the service and reads its answer.
///
/// The whole model through one name: the call site names no concrete type, the
/// service is reached through the trait, and the completion carries the token
/// the caller chose.
#[test]
fn a_handle_from_the_table_answers_its_callers() {
    let mut table = Table::new();
    table.install("echo-call", echo()).expect("installed");

    let handle = table.lookup("echo-call").expect("the name resolves");
    let mut service = handle.lock();
    let completion = service
        .submit(Request::with_arguments(RequestId::new(77), 4096, 0))
        .expect("this service answers in the call");
    assert_eq!(completion.id, RequestId::new(77), "the caller's token");
    assert_eq!(
        completion.status,
        CompletionStatus::Ok(4096),
        "the argument word came back as the value"
    );
}

/// The end-to-end helper submits, polls a service that waits, and takes the
/// completion, through the global, which is what a boot uses.
///
/// The only test that touches [`super::SERVICES`], and it installs before any
/// freeze: the freeze itself is tested on a value, so the global is never left
/// frozen and no other test can be affected by it.
#[test]
fn the_global_table_answers_through_its_free_functions() {
    super::install("after-one-poll", after_one_poll()).expect("installed");
    let completion = super::request("after-one-poll", Request::pending(RequestId::new(5)), 4)
        .expect("the poll found the completion");
    assert_eq!(completion.id, RequestId::new(5), "the token came back");
    assert_eq!(
        super::installed(),
        1,
        "one service is installed in the global"
    );
    assert!(
        super::request(
            "nobody-installed-this",
            Request::pending(RequestId::new(1)),
            4
        )
        .is_none(),
        "an unknown name is None, not a fabricated completion"
    );
}

/// A service that never completes answers `None` after the polls it was given.
#[test]
fn a_request_gives_up_after_its_polls() {
    let mut table = Table::new();
    table.install("never-answers", never()).expect("installed");
    let handle = table.lookup("never-answers").expect("the name resolves");
    let mut service = handle.lock();
    assert!(
        service
            .submit(Request::pending(RequestId::new(2)))
            .is_none()
    );
    for _ in 0..3 {
        service.poll();
        assert!(
            service.take_completion().is_none(),
            "the service produced nothing to take"
        );
    }
}

/// The freeze stops installation and leaves what is installed answering.
#[test]
fn the_freeze_stops_installation_and_not_use() {
    let mut table = Table::new();
    assert!(!table.is_frozen(), "a new table is open");
    table
        .install("before-freeze", echo())
        .expect("installs while open");

    table.freeze();
    assert!(table.is_frozen());
    assert_eq!(
        table.install("after-freeze", echo()),
        Err(InstallError::Frozen),
        "a frozen table refuses rather than growing"
    );

    table.freeze();
    assert!(table.is_frozen(), "freezing twice is not an error");
    assert!(
        table.lookup("before-freeze").is_some(),
        "a frozen table still answers for what it holds"
    );
    assert_eq!(table.installed(), 1, "the refusal added nothing");
}
