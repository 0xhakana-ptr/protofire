//! libs/irq/src/dispatch/tests.rs
//!
//! The handler registry: an identity claimed once, dispatched to, and refused
//! when nobody holds it.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

use crate::dispatch::MAX_IDENTITIES;
use crate::dispatch::Registry;

fn first(_identity: usize) -> bool {
    true
}

fn second(_identity: usize) -> bool {
    true
}

fn declines(_identity: usize) -> bool {
    false
}

fn records(identity: usize) -> bool {
    IDENTITY_SEEN.store(identity, core::sync::atomic::Ordering::Relaxed);
    true
}

static IDENTITY_SEEN: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(usize::MAX);

/// A fresh table dispatches nothing, and says so rather than faulting.
///
/// This is a machine reporting a line nothing registered for, which is what
/// a spurious interrupt or a device with no driver looks like.
#[test]
fn an_unclaimed_identity_is_not_handled() {
    let registry = Registry::new();
    assert!(!registry.dispatch(0));
    assert!(!registry.dispatch(32));
    assert!(!registry.dispatch(MAX_IDENTITIES - 1));
}

/// A registered handler is called, and reports what it answered.
#[test]
fn a_registered_handler_is_delivered_to() {
    let registry = Registry::new();
    assert_eq!(registry.register(32, first), Some(None));
    assert!(registry.dispatch(32));
    assert!(registry.handler(32).is_some());
}

/// The handler is given the identity it was registered for.
///
/// A device that shares one handler across its queues needs to know which
/// queue woke it — a handler that could not tell would have to wake all of
/// them and let each decide.
#[test]
fn the_handler_is_given_the_identity() {
    let registry = Registry::new();
    registry.register(41, records);
    registry.dispatch(41);
    assert_eq!(
        IDENTITY_SEEN.load(core::sync::atomic::Ordering::Relaxed),
        41
    );
}

/// A handler that declines is reported as not having handled it.
///
/// On a shared line every handler but one answers "not mine", and a
/// dispatcher that turned that into `true` would count a spurious
/// interrupt as served.
#[test]
fn a_handler_that_declines_is_not_handled() {
    let registry = Registry::new();
    registry.register(32, declines);
    assert!(!registry.dispatch(32));
}

/// Registering twice reports what it replaced, and the newer handler wins.
///
/// Two drivers that both believe they own a line is a bug, and the one that
/// loses should be able to say so rather than discovering it by watching
/// its interrupts stop.
#[test]
fn registering_twice_reports_the_replacement() {
    let registry = Registry::new();
    assert_eq!(registry.register(32, first), Some(None));
    let replaced = registry.register(32, second).expect("the identity");
    assert!(replaced.is_some(), "the second registration replaced one");
    assert!(registry.dispatch(32));
}

/// An identity outside the table is refused rather than panicking.
#[test]
fn an_identity_outside_the_table_is_refused() {
    let registry = Registry::new();
    assert_eq!(registry.register(MAX_IDENTITIES, first), None);
    assert_eq!(registry.register(usize::MAX, first), None);
    assert!(!registry.dispatch(MAX_IDENTITIES));
    assert!(registry.unregister(MAX_IDENTITIES).is_none());
}

/// Unregistering a handler removes it, and a second removal says there was
/// nothing to remove.
#[test]
fn unregistering_removes_the_handler() {
    let registry = Registry::new();
    registry.register(32, first);
    assert!(registry.unregister(32).is_some());
    assert!(!registry.dispatch(32));
    assert!(
        registry.unregister(32).is_none(),
        "nothing was left to remove"
    );
}

/// Two identities are two handlers, and dispatching one does not reach the
/// other.
#[test]
fn identities_are_independent() {
    let registry = Registry::new();
    registry.register(32, first);
    registry.register(33, declines);
    assert!(registry.dispatch(32));
    assert!(!registry.dispatch(33));
}
