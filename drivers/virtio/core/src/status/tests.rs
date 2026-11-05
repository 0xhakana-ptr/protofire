//! drivers/virtio/core/src/status/tests.rs
//!
//! The virtio status handshake: the bits a driver sets, and the order the
//! device requires them in.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

use crate::status::Status;
use crate::status::failed;
use crate::status::next;

/// A fresh device is at zero and the first step is the one the
/// specification names.
#[test]
fn the_first_step_is_acknowledge() {
    assert_eq!(next(0, Status::Acknowledge), Some(1));
    assert_eq!(Status::reached(0), None);
}

/// Every stage follows the one before it, and setting them in order
/// produces the byte the device expects.
#[test]
fn the_stages_accumulate_in_order() {
    let mut byte = 0u8;
    for stage in [
        Status::Acknowledge,
        Status::Driver,
        Status::FeaturesOk,
        Status::DriverOk,
    ] {
        byte = next(byte, stage).expect("the next stage is accepted");
    }
    assert_eq!(byte, 15);
}

/// A stage that skips one is refused, and the refusal is the point.
///
/// This is the failure the module exists to catch: `DRIVER_OK` without
/// `FEATURES_OK` means the driver never negotiated, and QEMU would still
/// answer a queue.  A real device would not.
#[test]
fn a_skipped_stage_is_refused() {
    assert_eq!(next(0, Status::DriverOk), None);
    assert_eq!(next(0, Status::FeaturesOk), None);
    assert_eq!(next(1, Status::FeaturesOk), None);
    assert_eq!(next(3, Status::DriverOk), None);
}

/// Setting a stage twice is refused rather than being a no-op.
#[test]
fn a_repeated_stage_is_refused() {
    assert_eq!(next(1, Status::Acknowledge), None);
    assert_eq!(next(3, Status::Driver), None);
}

/// The device may refuse the feature set, and `FAILED` is how it says so.
#[test]
fn failed_is_readable_at_any_stage() {
    assert!(failed(3 | 128));
    assert!(!failed(3));
    assert!(!failed(15));
}

/// A device that reports stages out of order cannot be reasoned about, and
/// `reached` says so rather than guessing.
#[test]
fn an_out_of_order_byte_is_not_a_stage() {
    assert_eq!(Status::reached(4), None, "FEATURES_OK without ACKNOWLEDGE");
    assert_eq!(Status::reached(6), None, "FEATURES_OK without DRIVER");
    assert_eq!(
        Status::reached(9),
        None,
        "DRIVER_OK without the stages between"
    );
    assert_eq!(Status::reached(7), Some(Status::FeaturesOk));
    assert_eq!(Status::reached(15), Some(Status::DriverOk));
}
