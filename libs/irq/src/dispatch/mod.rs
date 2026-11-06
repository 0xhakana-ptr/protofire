//! libs/irq/src/dispatch/mod.rs
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
        // `register`, which takes a `Handler`, a bare `fn` pointer, so the
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
    /// looks like from here.  The answer is `false`, and the caller counts it,
    /// /// a kernel that treated an unclaimed interrupt as a fault would die on
    /// the first device it has no driver for.
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
/// `REGISTRY` being public because the table has one writer, `register`, and
/// a public static would let anything write it.
pub fn dispatch_installed(identity: usize) -> bool {
    REGISTRY.dispatch(identity)
}

#[cfg(test)]
mod tests;
