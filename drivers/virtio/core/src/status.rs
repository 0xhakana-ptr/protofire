//! virtio/core/src/status.rs
//!
//! The device status byte, and the order a driver moves it through.
//!
//! ## Why the order is code and not a comment
//!
//! Virtio 1.2 section 2.1: a driver sets `ACKNOWLEDGE`, then `DRIVER`, then
//! reads features, then writes features, then sets `FEATURES_OK`, then sets up
//! its queues, then sets `DRIVER_OK`.  A device that finds `FEATURES_OK` set
//! but sees its required features missing writes `FAILED`; a driver that sets
//! `DRIVER_OK` without `FEATURES_OK` has skipped negotiation entirely.
//!
//! A driver that got the order wrong usually still works on QEMU, which is
//! what makes this worth checking rather than documenting: the failure is a
//! real device refusing to initialise, and it would be found by whoever ran
//! this kernel on hardware rather than by whoever wrote the driver.
//!
//! So [`Status`] is a machine and [`Status::advance`] refuses a step that
//! skipped one.  The bits stay `pub` — a caller has to be able to read
//! `FAILED` off a device — but the transition is this module's.

/// One stage of the device's initialisation, in specification order.
///
/// The numbers are the bit positions in the status byte, which is a wire
/// format: a device compares the byte, so these are not a local enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Status {
    /// The driver has found the device.
    Acknowledge = 1,
    /// The driver knows how to drive it.
    Driver = 2,
    /// The driver has read the feature bits and accepts the set.
    FeaturesOk = 4,
    /// The driver has set up its queues and will start submitting.
    DriverOk = 8,
}

impl Status {
    /// The bit this stage sets.
    pub const fn bit(self) -> u8 {
        self as u8
    }

    /// Read a status byte into the highest stage it has reached.
    ///
    /// `None` when the byte does not have the stages in order — a device that
    /// reports `FEATURES_OK` without `DRIVER` is a device this driver cannot
    /// reason about, and guessing which stage it meant is worse than refusing.
    pub fn reached(byte: u8) -> Option<Status> {
        let stages = [
            Status::Acknowledge,
            Status::Driver,
            Status::FeaturesOk,
            Status::DriverOk,
        ];
        let mut reached = None;
        for stage in stages {
            if byte & stage.bit() != 0 {
                // A stage set without every earlier one is out of order.
                if reached.is_none() && stage != Status::Acknowledge {
                    return None;
                }
                if let Some(previous) = reached
                    && (previous as u8) * 2 != stage as u8
                {
                    return None;
                }
                reached = Some(stage);
            }
        }
        reached
    }
}

/// The stages, in the order a driver must set them.
pub const STAGES: [Status; 4] = [
    Status::Acknowledge,
    Status::Driver,
    Status::FeaturesOk,
    Status::DriverOk,
];

/// The bit a device sets when it cannot proceed.
///
/// Not a stage: it can appear at any point after `Acknowledge`, and it means
/// the device gave up.  A driver reads it after writing a later stage to learn
/// whether the device accepted — `FEATURES_OK` in particular, where the device
/// is entitled to refuse the feature set.
pub const FAILED: u8 = 128;

/// Whether a status byte says the device gave up.
pub const fn failed(byte: u8) -> bool {
    byte & FAILED != 0
}

/// The status byte after `stage`, given the byte before it.
///
/// Refuses to skip: `DriverOk` from `Acknowledge` is a driver that never read
/// the features, and the bit arithmetic would happily produce a byte that
/// looks right.  Returns `None` for a stage that is not one step past
/// `current`.
pub fn next(current: u8, stage: Status) -> Option<u8> {
    let expected = match Status::reached(current) {
        Some(reached) => expected_after(reached),
        None => Some(Status::Acknowledge),
    };
    match expected {
        Some(want) if want == stage => Some(current | stage.bit()),
        _ => None,
    }
}

/// The stage that must follow `stage`, or `None` after the last one.
const fn expected_after(stage: Status) -> Option<Status> {
    match stage {
        Status::Acknowledge => Some(Status::Driver),
        Status::Driver => Some(Status::FeaturesOk),
        Status::FeaturesOk => Some(Status::DriverOk),
        Status::DriverOk => None,
    }
}

#[cfg(test)]
mod tests {
    use super::Status;
    use super::failed;
    use super::next;

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
}
