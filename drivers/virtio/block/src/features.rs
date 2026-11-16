//! drivers/virtio/block/src/features.rs
//!
//! The block device's own feature bits, and what a driver does with them.
//!
//! ## Why a block device's bits are not the framework's
//!
//! `virtio_core::features` says why it knows only the two bits the framework
//! must act on: a device's own bits describe what the device can do, and the
//! framework has nothing to do with what they mean.  This module is the block
//! device's answer.
//!
//! ## The bit this driver was missing
//!
//! `VIRTIO_BLK_F_FLUSH` (specification section 5.2.3) is the device telling the
//! driver it can answer a `Flush` request.  A device that does not offer it is
//! entitled to ignore the request, and QEMU's does exactly that: the request
//! never completes, so `VirtioBlock::wait` spins to its poll limit and answers
//! `TimedOut`.  The first `Fsync` on a machine without this bit therefore takes
//! seconds and fails, and it looked like a hung kernel rather than a missing
//! feature.
//!
//! Two changes follow from that, and both are here rather than in the flush:
//! the driver **asks** for the bit, and it **remembers** whether it got it, so
//! a flush on a device without it answers `NotImplemented` at once instead of
//! waiting for a completion that is never coming.

/// Bit 9: the device can answer a `Flush` request.
///
/// Specification section 5.2.3.  Without it the driver must not rely on
/// `VIRTIO_BLK_T_FLUSH`, and this tree's `BlockDevice::flush` reports
/// [`abi::Error::NotImplemented`] rather than submitting into a request the
/// device will not service.
pub const VIRTIO_BLK_F_FLUSH: u64 = 1 << 9;

/// The block device's own features this driver asks for.
///
/// Only the flush.  `VIRTIO_BLK_F_SIZE_MAX` and `VIRTIO_BLK_F_SEG_MAX` change
/// what a request may be, and this driver's requests are one sector-aligned
/// buffer at a time, well inside every device's floor, so asking for them
/// would be accepting a contract nothing here reads.  `VIRTIO_BLK_F_RO` and
/// the discard family are the same: a capability this driver does not use.
pub const BLOCK_WANTED: u64 = VIRTIO_BLK_F_FLUSH;

/// What the driver negotiated, after the intersection with what was offered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockFeatures {
    accepted: u64,
}

impl BlockFeatures {
    /// The features a device offered and this driver asked for.
    pub const fn negotiated(offered: u64) -> Self {
        Self {
            accepted: offered & BLOCK_WANTED,
        }
    }

    /// The bits accepted, as the word the transport was given.
    pub const fn accepted(self) -> u64 {
        self.accepted
    }

    /// Whether the device will answer a flush request.
    ///
    /// The one question this module exists to answer: `flush` asks it before it
    /// submits anything.
    pub const fn can_flush(self) -> bool {
        self.accepted & VIRTIO_BLK_F_FLUSH != 0
    }
}

#[cfg(test)]
mod tests {
    use super::BLOCK_WANTED;
    use super::BlockFeatures;
    use super::VIRTIO_BLK_F_FLUSH;

    /// The bit is the specification's.
    #[test]
    fn the_flush_bit_is_nine() {
        assert_eq!(VIRTIO_BLK_F_FLUSH, 1 << 9);
        assert_eq!(BLOCK_WANTED, VIRTIO_BLK_F_FLUSH);
    }

    /// A device that offers the bit gets it accepted and may be flushed.
    #[test]
    fn an_offered_flush_bit_is_accepted() {
        let features = BlockFeatures::negotiated(VIRTIO_BLK_F_FLUSH);
        assert!(features.can_flush());
        assert_eq!(features.accepted(), VIRTIO_BLK_F_FLUSH);
    }

    /// A device that does not offer it is not asked for it.
    ///
    /// The intersection is what makes this true: the driver wants the bit, the
    /// device said nothing about it, and the answer is "no flush" rather than
    /// a bit the device never promised.
    #[test]
    fn a_flush_bit_the_device_did_not_offer_is_not_accepted() {
        let features = BlockFeatures::negotiated(0);
        assert!(!features.can_flush());
        assert_eq!(features.accepted(), 0);
    }

    /// A device that offers bits this driver does not want keeps only the one
    /// it does.
    ///
    /// `VIRTIO_BLK_F_RO` (bit 5) and the discard family are offered by QEMU's
    /// disk and this driver reads neither; accepting them would be claiming a
    /// contract nothing in the crate implements.
    #[test]
    fn only_the_wanted_bit_is_accepted() {
        let offered = VIRTIO_BLK_F_FLUSH | (1 << 5) | (1 << 13);
        let features = BlockFeatures::negotiated(offered);
        assert_eq!(features.accepted(), VIRTIO_BLK_F_FLUSH);
        assert!(features.can_flush());
    }
}
