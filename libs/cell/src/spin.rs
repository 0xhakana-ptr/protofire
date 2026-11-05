//! libs/cell/src/spin.rs
//!
//! The smallest lock there is: one atomic bit, and a spin.
//!
//! ## Why not `sync::SpinLock`
//!
//! `sync` names `arch`, because its guard restores the caller's interrupt
//! state, and an architecture crate cannot name `sync` without a cycle.  The
//! console lives in each architecture's `serial` module, so the lock it needs
//! cannot be `sync`'s.
//!
//! What this type has is the half that names nothing: the bit and the spin.
//! The half that names the machine, masking this CPU's interrupts for the
//! length of the critical section, stays with the caller, which is the crate
//! that knows what `sstatus` or `RFLAGS` are.  Both halves are needed and they
//! are needed together; separating them is what keeps this crate a leaf.
//!
//! ## Why the caller must mask interrupts
//!
//! A lock that only spins is safe between CPUs and unsafe against itself: a
//! trap taken while the lock is held, whose handler takes the same lock, spins
//! forever on a CPU that cannot make progress.  Every caller here is a console
//! write, and the trap path prints.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering;

/// One atomic bit, held for the length of a critical section.
pub struct RawSpin {
    locked: AtomicBool,
}

impl RawSpin {
    /// A lock nobody holds.
    pub const fn new() -> RawSpin {
        RawSpin {
            locked: AtomicBool::new(false),
        }
    }

    /// Take the lock, spinning until it is free.
    ///
    /// # Safety
    ///
    /// The caller must have closed the same-CPU window first, interrupts
    /// masked for the length of the section, and must pair this call with
    /// [`release`](Self::release).  Both are why this is `unsafe`: the type
    /// cannot see either, and a caller that skipped the masking has a lock that
    /// deadlocks rather than one that corrupts, which is the better failure but
    /// still a failure.
    pub unsafe fn acquire(&self) {
        while self
            .locked
            .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            while self.locked.load(Ordering::Relaxed) {
                core::hint::spin_loop();
            }
        }
    }

    /// Give the lock back.
    ///
    /// # Safety
    ///
    /// The caller must hold it, once, and must not touch what it guards after.
    pub unsafe fn release(&self) {
        self.locked.store(false, Ordering::Release);
    }
}

impl Default for RawSpin {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::RawSpin;

    /// A lock is taken and given back, and a second acquisition after a release
    /// succeeds.  On a host this is the atomic half only, which is the half
    /// this crate owns.
    #[test]
    fn a_lock_is_exclusive_and_released() {
        let lock = RawSpin::new();
        // SAFETY: single-threaded test, and every acquisition is paired.
        unsafe {
            lock.acquire();
            assert!(lock.locked.load(core::sync::atomic::Ordering::Acquire));
            lock.release();
            assert!(!lock.locked.load(core::sync::atomic::Ordering::Acquire));
            lock.acquire();
            lock.release();
        }
    }
}
