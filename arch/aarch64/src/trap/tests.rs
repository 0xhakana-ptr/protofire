//! arch/aarch64/src/trap/tests.rs
//!
//! The aarch64 trap path's tests: the frame's size and both its ends, the class
//! a syndrome reports, and the vector arithmetic the table and the module
//! share.

use crate::trap::ExceptionFrame;
use crate::trap::SUPERVISOR_CALL_VECTOR;
use crate::vbar::Group;
use crate::vbar::Kind;
use crate::vbar::entry_offset;

/// A frame is 800 bytes and 16-aligned, so a `q` pair stays aligned.
#[test]
fn the_frame_is_a_multiple_of_sixteen() {
    assert_eq!(core::mem::size_of::<ExceptionFrame>(), 816);
    assert_eq!(core::mem::align_of::<ExceptionFrame>(), 16);
    // The assembly subtracts exactly this from `sp`, and a size that was
    // not a multiple of 16 would let a `q` pair straddle a boundary the
    // `stp` encodes as an offset it cannot express.
    assert_eq!(816 % 16, 0);
}

/// The class is `ESR_EL1`'s top six bits.
///
/// The syndrome this boot actually produced is the test's vector: EC 7 is
/// what a trapped SIMD instruction reports, and it is the value that ended
/// the first aarch64 boot after four lines.  Using it here means the
/// decoder is checked against an event rather than against arithmetic
/// invented for the test.
#[test]
fn the_class_is_the_top_six_bits_of_the_syndrome() {
    let mut frame = empty_frame();
    frame.esr = 0x1fe0_0000;
    assert_eq!(frame.class(), 7);
    assert_eq!(frame.class_name(), Some("fp/simd trapped"));

    frame.esr = 0x15 << 26;
    assert_eq!(frame.class(), 0x15);
    assert!(frame.is_supervisor_call());
    assert_eq!(frame.class_name(), Some("supervisor call"));
}

/// An unrecognised class is reported as such rather than given a name.
#[test]
fn an_unknown_class_has_no_name() {
    let mut frame = empty_frame();
    frame.esr = 0x3F << 26;
    assert_eq!(frame.class_name(), None);
    assert!(!frame.is_supervisor_call());
}

/// The vector a supervisor call from EL1 arrives at is entry 4, and the
/// `vbar` module's arithmetic agrees.
///
/// The two modules each need this number: the assembly writes an index and
/// this module checks it, and `vbar` computes it from the group and kind.
/// Comparing them here is what keeps "entry 4" from becoming three
/// opinions.
#[test]
fn the_supervisor_call_vector_is_the_fourth_entry() {
    assert_eq!(SUPERVISOR_CALL_VECTOR, 4);
    assert_eq!(
        entry_offset(Group::CurrentSpX, Kind::Synchronous) / crate::vbar::ENTRY_STRIDE,
        SUPERVISOR_CALL_VECTOR
    );
    assert_eq!(
        entry_offset(Group::CurrentSpX, Kind::Irq) / crate::vbar::ENTRY_STRIDE,
        5
    );
    // Entry 8 is a synchronous exception from a *lower* EL, which is a
    // different vector: a system call from user mode.
    assert_eq!(
        entry_offset(Group::Lower64, Kind::Synchronous) / crate::vbar::ENTRY_STRIDE,
        8
    );
}

fn empty_frame() -> ExceptionFrame {
    ExceptionFrame {
        registers: [0; 30],
        link_register: 0,
        elr: 0,
        spsr: 0,
        esr: 0,
        far: 0,
        vector: 0,
        simd: [0; 32],
        sp_el0: 0,
    }
}
