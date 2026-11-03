//! virtio/core/src/features.rs
//!
//! The feature bits a device offers and a driver accepts.
//!
//! ## Why a type and not a `u64`
//!
//! Negotiation is a set intersection: the device says what it can do, the
//! driver says what it can do, and the device runs with the intersection.  A
//! driver that wrote a `u64` of its own would have to remember to mask it
//! against the device's set; a driver that forgot would set a bit the device
//! never offered, and the device is entitled to misbehave — that is the whole
//! of what "not offered" means.
//!
//! [`Features::negotiate`] is that intersection, and it is a function so the
//! rule is one place rather than a convention each driver re-implements.
//!
//! ## Which bits this crate knows
//!
//! Only the ones the framework must act on: `VIRTIO_F_VERSION_1` (the device
//! speaks the modern interface, which is the only one this tree implements) and
//! `VIRTIO_F_RING_EVENT_IDX` (the interrupt-suppression scheme the queue
//! implements).  A device's own feature bits — a block device's
//! `VIRTIO_BLK_F_FLUSH`, a network card's checksum offloads — belong to the
//! device crate, because the framework has nothing to do with what they mean.

/// Bit 32: the device implements the modern (1.0 and later) interface.
///
/// Section 6.1.  This tree has no legacy transport, so a device without this
/// bit is not one it can drive, and negotiation reports that rather than
/// producing a driver that submits into a queue the device does not understand.
pub const VIRTIO_F_VERSION_1: u64 = 1 << 32;

/// Bit 29: the driver will use the available ring's event index.
///
/// Section 2.7.10.  Off means the queue interrupts after every buffer, which is
/// correct and slower; on means the driver says when it wants to be told.
pub const VIRTIO_F_RING_EVENT_IDX: u64 = 1 << 29;

/// The features this framework itself requires of a device.
pub const FRAMEWORK_REQUIRED: u64 = VIRTIO_F_VERSION_1;

/// The features this framework knows how to use when offered.
pub const FRAMEWORK_KNOWN: u64 = VIRTIO_F_VERSION_1 | VIRTIO_F_RING_EVENT_IDX;

/// The device's offered set and the driver's accepted set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Features {
    device: u64,
    driver: u64,
}

impl Features {
    /// Nothing negotiated: neither side has said anything.
    pub const NONE: Features = Features {
        device: 0,
        driver: 0,
    };

    /// What the device offered, as read from its feature registers.
    pub const fn offered(device: u64) -> Self {
        Self { device, driver: 0 }
    }

    /// What the device offered.
    pub const fn device(self) -> u64 {
        self.device
    }

    /// What the driver has accepted.
    pub const fn driver(self) -> u64 {
        self.driver
    }

    /// Accept `wanted`, keeping only bits the device offered.
    ///
    /// The intersection is the whole rule: a bit the device did not offer is
    /// not accepted, however much the driver wants it, because the device is
    /// entitled to behave as if that bit were clear.
    pub const fn negotiate(mut self, wanted: u64) -> Self {
        self.driver = wanted & self.device;
        self
    }

    /// Whether the accepted set contains every feature this framework needs.
    ///
    /// A device that does not offer `VIRTIO_F_VERSION_1` cannot be driven by
    /// this tree, and this is where that is noticed — before a queue is set
    /// up, rather than at the first submit.
    pub const fn has_required(self) -> bool {
        self.driver & FRAMEWORK_REQUIRED == FRAMEWORK_REQUIRED
    }

    /// A specific bit from the accepted set.
    pub const fn accepts(self, bit: u64) -> bool {
        self.driver & bit != 0
    }
}

#[cfg(test)]
mod tests {
    use super::Features;
    use super::VIRTIO_F_RING_EVENT_IDX;
    use super::VIRTIO_F_VERSION_1;

    /// Acceptance is the intersection, and demanding a bit the device did not
    /// offer does not get it.
    ///
    /// This is the failure the type exists to prevent: a driver that wrote its
    /// wanted set straight into the device's register would have told the
    /// device it may use a feature the device never claimed.
    #[test]
    fn negotiation_is_the_intersection() {
        let device = Features::offered(VIRTIO_F_VERSION_1);
        let accepted = device.negotiate(VIRTIO_F_VERSION_1 | VIRTIO_F_RING_EVENT_IDX);
        assert!(accepted.accepts(VIRTIO_F_VERSION_1));
        assert!(
            !accepted.accepts(VIRTIO_F_RING_EVENT_IDX),
            "a feature the device did not offer is not accepted"
        );
    }

    /// A device offering the modern interface satisfies the framework's
    /// requirement, and one without it does not.
    #[test]
    fn the_modern_interface_is_required() {
        assert!(
            Features::offered(VIRTIO_F_VERSION_1)
                .negotiate(VIRTIO_F_VERSION_1)
                .has_required()
        );
        assert!(!Features::offered(0).negotiate(u64::MAX).has_required());
        assert!(
            !Features::offered(VIRTIO_F_RING_EVENT_IDX)
                .negotiate(u64::MAX)
                .has_required(),
            "the event index alone is not the modern interface"
        );
    }

    /// Negotiating with nothing accepted accepts nothing, and does not panic.
    #[test]
    fn accepting_nothing_is_a_valid_outcome() {
        let accepted = Features::offered(u64::MAX).negotiate(0);
        assert_eq!(accepted.driver(), 0);
        assert!(!accepted.has_required());
    }
}
