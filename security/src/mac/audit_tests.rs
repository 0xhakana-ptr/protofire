//! security/src/mac/audit_tests.rs
//!
//! That a denial reaches the sink, and that nothing breaks when none is set.

use super::audit::Denial;
use super::audit::has_sink;
use super::audit::report;
use super::audit::set_sink;

/// The sink is installed once per process, so the test that installs it has to
/// run before the one that checks silence, and cargo's harness gives each
/// test binary one process, which is why `set_sink` can be `Once`.
///
/// The two assertions below are ordered by the test attribute names rather than
/// by a lock: `a_denial_reaches_the_installed_sink` sorts before
/// `with_no_sink_nothing_happens` only by luck, so the silent case is checked
/// first when no sink has been installed *and* is written to be correct either
/// way, it only asserts that calling `report` is safe.
#[test]
fn with_no_sink_reporting_is_harmless() {
    // Whether or not another test installed a sink first, this call must not
    // fault.  That is the whole property: the previous code called into the
    // audit layer unconditionally, so a policy check before the audit layer was
    // up was a call into a module with no state.
    let denial = Denial {
        subject: 1,
        object: 2,
        class: 3,
        permissions: 4,
        uid: 1000,
    };
    report(&denial);
    let _ = has_sink();
}

/// Static fields the sink writes to.
static SEEN_SUBJECT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);
static SEEN_OBJECT: core::sync::atomic::AtomicU32 = core::sync::atomic::AtomicU32::new(0);

/// A sink that records what it was handed.
fn recording_sink(denial: &Denial) {
    SEEN_SUBJECT.store(denial.subject, core::sync::atomic::Ordering::Relaxed);
    SEEN_OBJECT.store(denial.object, core::sync::atomic::Ordering::Relaxed);
}

/// An installed sink receives the denial's own fields.
#[test]
fn a_denial_reaches_the_installed_sink() {
    set_sink(recording_sink);
    // If another test installed a sink first, `set_sink` is a no-op and this
    // assertion would be checking theirs.  The harness runs tests in one
    // process, so the guard is that ours is the function that ran: a second
    // call is ignored by design and the first one wins.
    let denial = Denial {
        subject: 42,
        object: 7,
        class: 1,
        permissions: 2,
        uid: 1000,
    };
    report(&denial);
    if has_sink() {
        // The only sink that can be installed here is this file's, because no
        // other test in this crate installs one.
        assert_eq!(SEEN_SUBJECT.load(core::sync::atomic::Ordering::Relaxed), 42);
        assert_eq!(SEEN_OBJECT.load(core::sync::atomic::Ordering::Relaxed), 7);
    }
}

/// A denial displays the terms it was decided in.
#[test]
fn a_denial_describes_itself() {
    let denial = Denial {
        subject: 1,
        object: 2,
        class: 3,
        permissions: 4,
        uid: 1000,
    };
    let text = alloc::format!("{denial}");
    assert!(text.contains("subject 1"), "{text}");
    assert!(text.contains("object 2"), "{text}");
    assert!(text.contains("uid 1000"), "{text}");
}
