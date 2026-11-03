//! libs/irq/src/dispatch.rs
//!
//! The handler table and the dispatch over it.
//!
//! ## Why a fixed array and not a map
//!
//! An identity is a small integer a machine printed on a line, and the table is
//! indexed by it.  A map would allocate on the dispatch path, and dispatch runs
//! in an interrupt handler: an allocation there can fail, cannot wait, and may
//! take a lock the interrupted code is holding.
//!
//! The array is [`MAX_IDENTITIES`] entries of one pointer each.  A machine with
//! more identities than that has a number this crate should be told about
//! rather than a table that silently grew.
//!
//! ## Why registering is a function and not a field
//!
//! A handler is installed once at probe time and read many times on the
//! dispatch path.  The read has to be cheap and the write has to be exclusive,
//! so the table is behind a lock and this module is the only thing that touches
//! it.  A caller says "the handler for 32 is this function" and does not learn
//! what protects that.

use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

/// A function an interrupt is delivered to.
///
/// It takes the identity the machine reported and answers whether it recognised
/// it.  A handler that had to trust the machine would report `true` for every
/// line it was called on, which on a shared line means the kernel cannot count
/// the ones nobody wanted.
pub type Handler = fn(usize) -> bool;

/// The most identities this table holds.
///
/// A machine's line count is small: 256 on x86_64's first bus, 256 on a GIC's
/// shared peripheral interrupts, and the identities a device claims are a run
/// inside that.  A table this size covers every machine the tree builds for and
/// is one array rather than a growable structure.
pub const MAX_IDENTITIES: usize = 256;

/// The handler table.
///
/// A `static` rather than a value the kernel owns: dispatch happens in an
/// interrupt, which has no context to be handed one.  That is the same shape
/// the machine's own vector table has, and for the same reason.
pub struct Registry {
    handlers: [AtomicUsize; MAX_IDENTITIES],
}

impl Registry {
    /// An empty table: every identity is unclaimed.
    pub const fn new() -> Registry {
        Registry {
            handlers: [const { AtomicUsize::new(0) }; MAX_IDENTITIES],
        }
    }

    /// The handler for `identity`, if any.
    ///
    /// `Acquire` rather than `Relaxed`: a handler registered before a device is
    /// told to start signalling has to be visible to the dispatch that arrives
    /// after, and on a weakly-ordered machine a `Relaxed` load may see the
    /// stale value.
    pub fn handler(&self, identity: usize) -> Option<Handler> {
        let raw = self.handlers.get(identity)?.load(Ordering::Acquire);
        if raw == 0 {
            return None;
        }
        // SAFETY: every non-zero value in this table was written by
        // `register`, which takes a `Handler` — a bare `fn` pointer, so the
        // transmute is the same type it stored.
        Some(unsafe { core::mem::transmute::<usize, Handler>(raw) })
    }

    /// Install `handler` for `identity`, answering the one it replaced.
    ///
    /// A replacement is reported rather than silent: two drivers that both
    /// believe they own a line is a bug, and the one that loses should be able
    /// to say so.
    pub fn register(&self, identity: usize, handler: Handler) -> Option<Option<Handler>> {
        let slot = self.handlers.get(identity)?;
        let previous = slot.swap(handler as usize, Ordering::Release);
        if previous == 0 {
            Some(None)
        } else {
            // SAFETY: as `handler`.
            Some(Some(unsafe {
                core::mem::transmute::<usize, Handler>(previous)
            }))
        }
    }

    /// Remove the handler for `identity`, answering it.
    pub fn unregister(&self, identity: usize) -> Option<Handler> {
        let slot = self.handlers.get(identity)?;
        let previous = slot.swap(0, Ordering::Release);
        if previous == 0 {
            return None;
        }
        // SAFETY: as `handler`.
        Some(unsafe { core::mem::transmute::<usize, Handler>(previous) })
    }

    /// Deliver `identity` to its handler, answering whether one took it.
    ///
    /// An identity with no handler is **not** an error: a machine may report a
    /// line nothing registered for, which is what a spurious or a shared line
    /// looks like from here.  The answer is `false`, and the caller counts it —
    /// a kernel that treated an unclaimed interrupt as a fault would die on the
    /// first device it has no driver for.
    pub fn dispatch(&self, identity: usize) -> bool {
        match self.handler(identity) {
            Some(handler) => handler(identity),
            None => false,
        }
    }
}

impl Default for Registry {
    fn default() -> Self {
        Self::new()
    }
}

/// The tree's table.
///
/// One per machine, because there is one set of lines.  A `static` because
/// dispatch runs in an interrupt and has no argument to carry it.
static REGISTRY: Registry = Registry::new();

/// Install `handler` for `identity` in the tree's table.
pub fn register(identity: usize, handler: Handler) -> Option<Option<Handler>> {
    REGISTRY.register(identity, handler)
}

/// Remove the handler for `identity` from the tree's table.
pub fn unregister(identity: usize) -> Option<Handler> {
    REGISTRY.unregister(identity)
}

/// Deliver `identity` to its handler, answering whether one took it.
///
/// The entry a machine's dispatch calls.  It is a function rather than the
/// `REGISTRY` being public because the table has one writer — `register` — and
/// a public static would let anything write it.
pub fn dispatch_installed(identity: usize) -> bool {
    REGISTRY.dispatch(identity)
}

#[cfg(test)]
mod tests {
    use super::MAX_IDENTITIES;
    use super::Registry;

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
}
