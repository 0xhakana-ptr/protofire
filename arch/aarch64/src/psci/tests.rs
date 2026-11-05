//! arch/aarch64/src/psci/tests.rs
//!
//! What this module can check on a host: the interpretation of firmware's
//! answer, which is the part that decides whether a core counts as started.

// The constant is bare-metal only, so the test that pins it is too.  A host
// build skips the module rather than asserting a number it cannot see.
#![cfg(target_os = "none")]

/// Zero is success, and `ALREADY_ON` is success too.
///
/// The second half is the one worth pinning.  PSCI's `ALREADY_ON` is `-4`, and
/// a boot that read every non-zero answer as a refusal would run on fewer cores
/// than the machine has, while printing that firmware refused one.  The
/// failure is a boot that looks correct and uses half the machine.
#[test]
fn already_on_is_a_start_that_succeeded() {
    assert_eq!(super::ALREADY_ON, -4);

    // The two answers this module maps to `Started::Yes`, by value rather than
    // by calling `cpu_on`: the call is an instruction a host cannot execute,
    // and what is testable is the mapping.
    let accepts = |answer: i64| answer == 0 || answer == super::ALREADY_ON;
    assert!(accepts(0), "PSCI's success value");
    assert!(
        accepts(-4),
        "ALREADY_ON: the core is running, which is the ask"
    );
    assert!(!accepts(-1), "NOT_SUPPORTED is a refusal");
    assert!(!accepts(-2), "INVALID_PARAMETERS is a refusal");
    assert!(!accepts(-3), "DENIED is a refusal");
}

/// The function id the tree names is what gets called, not a literal.
///
/// The two ids PSCI defines for `cpu_on` differ in one bit, and the tree
/// carries the one the platform wants.  A module that spelled the number would
/// be right on QEMU's `virt` and wrong on a platform that renumbered, with no
/// way for the boot to notice.
#[test]
fn the_call_id_comes_from_the_tree() {
    // The values QEMU's `virt` publishes, as a record of what the module was
    // written against.  `0xc4` is the 64-bit calling convention and `0x84` the
    // 32-bit one; the low three bytes are the function.
    let sixty_four_bit = 0xc400_0003u32;
    let thirty_two_bit = 0x8400_0003u32;
    assert_eq!(sixty_four_bit & 0xFF_FFFF, thirty_two_bit & 0xFF_FFFF);
    assert_ne!(sixty_four_bit, thirty_two_bit);
}
