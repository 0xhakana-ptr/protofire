//! tools/xtask/src/tests.rs
//!
//! The matchers' tests: an absent line, a varying tail, and a prefix that has
//! to be at the start.
//!
//! These are why this tool is Rust.  In a shell the failure path of a gate is
//! the one nobody runs; here it is a function call.

use crate::gate::expect_line;
use crate::gate::expect_line_prefix;

/// The line the boot prints is found when it is there.
#[test]
fn an_exact_line_is_accepted() {
    let log = "first\nprotofire 0.1.0: entered via pvh, console up, stage 1\nlast\n";
    assert_eq!(
        expect_line(log, "protofire 0.1.0: entered via pvh, console up, stage 1"),
        Ok(())
    );
}

/// A log that ends in CRLF still matches: the trailing `\r` is what a
/// terminal sink adds, and it is not part of the claim.
#[test]
fn a_carriage_return_is_ignored() {
    let log = "protofire 0.1.0: entered via pvh, console up, stage 1\r\n";
    assert_eq!(
        expect_line(log, "protofire 0.1.0: entered via pvh, console up, stage 1"),
        Ok(())
    );
}

/// The failure path is the one that has to work: a log without the line is
/// refused.  This is the assertion a boot gate exists for, and it is
/// exercised here without an emulator.
#[test]
fn a_missing_line_is_refused() {
    let log = "first\nsomething else\n";
    assert!(expect_line(log, "protofire 0.1.0: entered via pvh, console up, stage 1").is_err());
}

/// A line that merely contains the expected text is not the expected line.
/// Substring matching is how a gate goes green on a log that printed the
/// failure message this check was looking for.
#[test]
fn a_longer_line_that_contains_it_is_refused() {
    let log = "not a boot: protofire 0.1.0: entered via pvh, console up, stage 1\n";
    assert!(expect_line(log, "protofire 0.1.0: entered via pvh, console up, stage 1").is_err());
}

/// An empty log is a different failure from a wrong one, and the message
/// says so: it is the difference between a boot that died before its
/// console and one that printed the wrong thing.
#[test]
fn an_empty_log_says_the_console_never_came_up() {
    let error = expect_line("", "anything").unwrap_err();
    assert!(error.contains("empty"), "{error}");
}

/// A line whose tail is a value the build chose matches on its prefix.
///
/// The heap's bounds move with the image, so the gate asserts the line's
/// shape rather than its value: a check that named an address would fail
/// for a correct kernel the first time a symbol moved.
#[test]
fn a_prefix_match_accepts_a_varying_tail() {
    let log = "protofire: heap at 0x11d790..0x411d790\n";
    assert_eq!(expect_line_prefix(log, "protofire: heap at "), Ok(()));
}

/// The prefix is required, not merely present somewhere: a log that printed
/// the words in another line is not a boot that reached the heap.
#[test]
fn a_prefix_that_is_absent_is_refused() {
    let log = "protofire 0.1.0: entered via pvh, console up, stage 1\n";
    assert!(expect_line_prefix(log, "protofire: heap at ").is_err());
}

/// An empty log says so, the same way `expect_line` does.
#[test]
fn an_empty_log_says_the_console_never_came_up_for_a_prefix() {
    let error = expect_line_prefix("", "anything").unwrap_err();
    assert!(error.contains("empty"), "{error}");
}

/// The CR stripping is at the end only: a `\r` in the middle of a line is
/// part of that line's content.
#[test]
fn only_the_trailing_carriage_return_is_stripped() {
    let log = "a\rb\r\n";
    assert!(expect_line(log, "a\rb").is_ok());
    assert!(expect_line(log, "ab").is_err());
}
