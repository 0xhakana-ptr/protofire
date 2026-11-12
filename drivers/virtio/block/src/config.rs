//! drivers/virtio/block/src/config.rs
//!
//! The block device's own configuration layout (specification section 5.2.4).
//!
//! ## Why this is here and not in `virtio_core`
//!
//! The device-specific configuration region is the one part of a virtio device
//! the framework cannot interpret: every device puts different fields at
//! different offsets, and `virtio_core` deliberately reads it as opaque dwords.
//! This module is the block device's answer for what those dwords mean.
//!
//! It lived in `virtio_core` until it was moved: a network card's configuration
//! starts with a MAC address at `0x00` and a block device's starts with a
//! capacity there, so a layout in the shared crate would be one device's fields
//! in every other device's compilation.
//!
//! ```text
//! struct virtio_blk_config {
//!     le64 capacity;      // in 512-byte sectors
//!     le32 size_max;
//!     le32 seg_max;
//!     ...
//! };
//! ```

/// `le64 capacity`, in 512-byte sectors.
///
/// The unit is the specification's and it is also the unit a request's `sector`
/// field uses, so a driver that reports capacity in sectors needs no conversion
/// anywhere.  A driver that reported bytes here would be off by 512 in the one
/// comparison that decides whether a write is inside the device.
pub const CAPACITY: u64 = 0x00;

/// `le32 size_max`, the largest request the device accepts, when
/// `VIRTIO_BLK_F_SIZE_MAX` is negotiated.
pub const SIZE_MAX: u64 = 0x04;

/// `le32 seg_max`, the largest number of segments, when
/// `VIRTIO_BLK_F_SEG_MAX` is negotiated.
pub const SEG_MAX: u64 = 0x08;

/// The capacity, read as the two dwords the layout puts at [`CAPACITY`].
///
/// A `le64` in a configuration region that is read a dword at a time is two
/// reads and a shift: low word first, high word at `CAPACITY + 4`.  Doing it in
/// one place is what keeps a second caller from getting the order wrong, and
/// the order is not free — a high-word-first read reports a capacity of zero
/// for every disk under four gigabytes.
pub fn capacity_sectors(read: impl Fn(u64) -> u32) -> u64 {
    let low = read(CAPACITY) as u64;
    let high = read(CAPACITY + 4) as u64;
    low | (high << 32)
}

#[cfg(test)]
mod tests {
    use super::CAPACITY;
    use super::SEG_MAX;
    use super::SIZE_MAX;
    use super::capacity_sectors;

    /// The offsets are the specification's.
    ///
    /// These are wire values: the device puts a `le64` at zero and a driver
    /// that read `0x08` for the capacity would report `seg_max` as a disk size.
    #[test]
    fn the_layout_is_the_specifications() {
        assert_eq!(CAPACITY, 0x00);
        assert_eq!(SIZE_MAX, 0x04);
        assert_eq!(SEG_MAX, 0x08);
    }

    /// The two dwords are read low first and concatenated.
    ///
    /// The direction matters and is not symmetric: reading the high word first
    /// reports zero for any capacity under four gigabytes, which is every disk
    /// this tree boots with.
    #[test]
    fn the_capacity_is_two_dwords_low_first() {
        let low = 0x1122_3344u32;
        let high = 0x5566_7788u32;
        let capacity = capacity_sectors(|offset| {
            if offset == CAPACITY {
                low
            } else if offset == CAPACITY + 4 {
                high
            } else {
                panic!("the capacity is two dwords")
            }
        });
        assert_eq!(capacity, 0x5566_7788_1122_3344);

        // A capacity that fits in the low word stays there rather than being
        // shifted, which is the case a boot with a small disk exercises.  The
        // high word is read too, and it is zero here — a reader that answered
        // the low word for both offsets would report a disk 2^32 times larger.
        assert_eq!(
            capacity_sectors(|offset| if offset == CAPACITY { 0x0800 } else { 0 }),
            0x0800
        );
    }
}
