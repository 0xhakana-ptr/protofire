//! libs/allocator/src/diag.rs
//!
//! Where the allocator's diagnostics go, without the allocator knowing who is
//! listening.
//!
//! ## The problem this solves
//!
//! A heap that called `println!` directly would be one line in a tree where the
//! heap and the console are the same crate, and impossible in a crate that is
//! supposed to be testable on the host: `println!` is the kernel's macro, it
//! reaches a `_print` that writes a UART, and a host test has neither.
//!
//! The allocator cannot simply drop the messages.  An allocation failure with
//! no explanation is the worst thing a heap can do, the caller gets a null
//! pointer and the log says nothing about which of five overflow checks fired.
//! So the messages stay, and the *sink* is injected.
//!
//! ## How
//!
//! A function pointer in a static, empty by default.  The kernel installs its
//! own writer during boot; a host test installs a collector, or nothing.  The
//! cost is one indirect call on a path that only runs when something has
//! already gone wrong, which is the right place to spend it.

use core::fmt;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

/// The installed writer, as a `fn(&str)`.
///
/// A raw `usize` rather than a typed `AtomicPtr<fn>`: an atomic of a function
/// pointer needs a wrapper type and a transmute to read back, and the value is
/// only ever the address of a `fn` item, which is `'static` by construction.
static WRITER: AtomicUsize = AtomicUsize::new(0);

/// Install the writer the allocator's diagnostics go to.
///
/// Calling it twice replaces the first, which is what a test wants: a test that
/// installs a collector and a later test that installs another must not have to
/// know about each other's ordering.  Passing `None` silences the output.
///
/// # Safety
///
/// The function must be safe to call from any context the allocator runs in,
/// including from an allocation made while a lock is held, which in practice
/// means it must not allocate.  It must also be `'static`: the allocator stores
/// its address and has no way to know when the caller's borrow ends.
pub unsafe fn set_writer(writer: Option<fn(&str)>) {
    let address = match writer {
        Some(writer) => writer as usize,
        None => 0,
    };
    WRITER.store(address, Ordering::Release);
}

/// Write a formatted diagnostic through the installed writer.
///
/// The formatting goes through `core::fmt::Write` on a small stack adapter
/// rather than `alloc::format!`, because the first thing a failing allocator
/// must not do is allocate.
pub fn write(args: fmt::Arguments<'_>) {
    let address = WRITER.load(Ordering::Acquire);
    if address == 0 {
        return;
    }
    // SAFETY: the address was stored by `set_writer`, which requires the value
    // to be a `fn(&str)` that is `'static` and safe from any context the
    // allocator runs in.  `0` was checked above, so this is a live function
    // address rather than a null one.
    let writer: fn(&str) = unsafe { core::mem::transmute::<usize, fn(&str)>(address) };
    let mut adapter = Adapter { writer };
    // `core::fmt::Write::write_fmt` only fails if the adapter does, and this
    // one cannot: its only operation is to hand the string to the writer.
    let _ = fmt::Write::write_fmt(&mut adapter, args);
}

/// Bridges `fmt::Write` to a `fn(&str)`.
struct Adapter {
    writer: fn(&str),
}

impl fmt::Write for Adapter {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        (self.writer)(text);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::set_writer;
    use super::write;
    use core::sync::atomic::AtomicUsize;
    use core::sync::atomic::Ordering;

    /// Where the collector's byte count lands.
    static COLLECTED: AtomicUsize = AtomicUsize::new(0);

    /// A writer that counts what it was handed.
    fn counting_writer(text: &str) {
        COLLECTED.fetch_add(text.len(), Ordering::Relaxed);
    }

    /// An installed writer receives what the allocator writes.
    ///
    /// `set_writer` and `write` are process-global state, so this test and the
    /// one below are written to be independent of each other's order: each
    /// installs its own writer and checks only what it installed.
    #[test]
    fn an_installed_writer_receives_the_message() {
        COLLECTED.store(0, Ordering::Relaxed);
        // SAFETY: `counting_writer` is a `fn(&str)` that does not allocate and
        // is `'static`; that is exactly what the contract asks for.
        unsafe { set_writer(Some(counting_writer)) };
        write(format_args!("[heap] {}", 42));
        // SAFETY: restoring the empty writer, which is the state `set_writer`
        // documents as silence.
        unsafe { set_writer(None) };
        assert_eq!(COLLECTED.load(Ordering::Relaxed), "[heap] 42".len());
    }

    /// With no writer installed, writing is a no-op rather than a fault.
    ///
    /// This is the state a host test that installed nothing is in, and a null
    /// call there would turn every allocation failure into a segfault, which
    /// is a much worse diagnostic than none.
    #[test]
    fn with_no_writer_nothing_happens() {
        // SAFETY: the empty state.
        unsafe { set_writer(None) };
        COLLECTED.store(0, Ordering::Relaxed);
        write(format_args!("nobody is listening"));
        assert_eq!(COLLECTED.load(Ordering::Relaxed), 0);
    }
}
