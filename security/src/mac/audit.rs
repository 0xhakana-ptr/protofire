//! security/src/mac/audit.rs
//!
//! Where a MAC denial goes, without this crate knowing what an audit record is.
//!
//! ## The problem this solves
//!
//! `check.rs` used to build an `AuditRecord`, a fixed-size byte layout, an
//! event type, an actor's pid and a timestamp, and hand it to the audit layer.
//! Both of those are the audit layer's to define, and reaching for them from
//! here made the security crate depend on the scheduler (to find the current
//! process) and on the audit module's record ABI (to fill one in).
//!
//! The comment at that call site already said the right thing: *a security
//! decision should not have to know how to find the current process to say that
//! it denied something*.  This module is that sentence as code.
//!
//! ## How
//!
//! A denial is described by its own fields, the two labels, the class, the
//! permissions and the uid, and a sink turns that into whatever record the
//! audit layer wants.  The kernel installs its sink at boot; a test installs a
//! collector, or nothing, and both are correct.

use core::fmt;

/// A refused access, in the terms the decision was made in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Denial {
    /// The label of the subject asking.
    pub subject: u32,
    /// The label of the object asked about.
    pub object: u32,
    /// What kind of object it is: a path, a network endpoint, a process.
    pub class: u32,
    /// Which permissions were asked for, as the policy's bit set.
    pub permissions: u32,
    /// The user the request ran as.
    pub uid: u32,
}

/// The installed sink.
static SINK: spin::Once<Sink> = spin::Once::new();

/// A sink that takes a denial.
pub type Sink = fn(&Denial);

/// Install the sink denials go to.
///
/// The first call wins, and later ones are ignored: a boot installs the audit
/// layer once, and a value that changed underneath a running policy would mean
/// two denials of the same kind being recorded in two places.  A test that
/// needs a different sink is in a process of its own, which is what `cargo
/// test`'s harness gives it.
pub fn set_sink(sink: Sink) {
    let _ = SINK.call_once(|| sink);
}

/// Report a denial through the installed sink, if there is one.
pub fn report(denial: &Denial) {
    if let Some(sink) = SINK.get() {
        (*sink)(denial);
    }
}

/// Whether anything is listening.
///
/// For the tests: a denial with no sink is not an error, and the property worth
/// checking is that nothing happens rather than that a call was made.
pub fn has_sink() -> bool {
    SINK.get().is_some()
}

impl fmt::Display for Denial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "subject {} -> object {} (class {}, perms 0x{:x}, uid {})",
            self.subject, self.object, self.class, self.permissions, self.uid
        )
    }
}
