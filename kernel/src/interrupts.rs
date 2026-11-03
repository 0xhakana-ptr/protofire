//! kernel/src/interrupts.rs
//!
//! What the kernel does with an interrupt frame.
//!
//! ## The two halves
//!
//! The machine's half is a table of gates and a stub that saves the registers
//! and calls here — `arch`'s.  This half is the *decision*: which vector means
//! what, and who asked to be told.
//!
//! A vector is delivered to whoever registered for its number.  Nothing is
//! registered yet, so every frame answers "not handled" and the dispatch stops
//! the machine with the vector on the console — which is the honest answer to
//! an interrupt this kernel has no business receiving, and it is what makes a
//! boot past `sti` a proof that the path works.
//!
//! ## Why the vector is the identity
//!
//! On a machine whose controller assigns each line a number, the number *is*
//! the identity a handler registers under.  A translation table between "the
//! number the machine printed" and "the number a driver claimed" would be a
//! second thing to keep in step, and the first driver to get it wrong would be
//! a device whose interrupts nobody receives.
//!
//! So a vector is passed through as it arrived.

/// Handle one interrupt frame, answering whether anything took it.
///
/// Called from the machine's dispatch, on whatever stack the vector found.
/// Nothing here allocates or blocks: an interrupt may arrive while the heap's
/// lock is held, and an allocation from inside one would wait for a lock the
/// interrupted code cannot release.
pub fn handle(frame: irq::Frame) -> bool {
    let vector = frame.vector;

    // The boot's own check: the line it raised, to prove the path.
    if vector == crate::TEST_INTERRUPT {
        crate::TEST_INTERRUPT_RAISED.store(vector, core::sync::atomic::Ordering::Release);
        return true;
    }

    // A device's line: whoever registered for this number is told.
    if irq::dispatch_installed(vector) {
        return true;
    }

    // A fault the kernel raised on itself.  There is no recovery yet — that
    // needs a process to hand the fault to — so the honest answer is "not
    // handled", and the dispatch prints the vector and stops.
    false
}
