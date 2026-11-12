//! drivers/virtio/net/src/config.rs
//!
//! The network card's own configuration layout (specification section 5.1.4).
//!
//! ## Why this is here and not in `virtio_core`
//!
//! The device-specific configuration region is the one part of a virtio device
//! the framework cannot interpret: every device puts different fields at
//! different offsets, and `virtio_core` deliberately reads it as opaque dwords.
//! This module is the network card's answer for what those dwords mean.
//!
//! It is also the answer that made the block device's own layout leave the
//! shared crate: a block device's region starts with a capacity and this one
//! starts with an address, so a layout in `virtio_core` would be one device's
//! fields in every other device's compilation.
//!
//! ```text
//! struct virtio_net_config {
//!     u8  mac[6];
//!     le16 status;                // only if VIRTIO_NET_F_STATUS
//!     le16 max_virtqueue_pairs;   // only if VIRTIO_NET_F_MQ
//!     le16 mtu;                   // only if VIRTIO_NET_F_MTU
//! };
//! ```

/// `u8 mac[6]`, the card's address, when `VIRTIO_NET_F_MAC` was negotiated.
///
/// Six bytes, not a number: the specification calls the field an array, so
/// `mac[0]` is the byte at this offset and the first four bytes are one dword
/// read little-endian.  A driver that treated it as a `u64` would reverse it
/// and answer a frame from an address the card does not have.
pub const MAC: u64 = 0x00;

/// `le16 status`, when `VIRTIO_NET_F_STATUS` was negotiated.
///
/// `VIRTIO_NET_S_LINK_UP` is its low bit, and this tree does not negotiate the
/// feature: it names the field so that a reader who adds the feature finds the
/// offset next to the one it follows rather than in a comment elsewhere.
pub const STATUS: u64 = 0x06;

/// `le16 max_virtqueue_pairs`, when `VIRTIO_NET_F_MQ` was negotiated.
pub const MAX_VIRTQUEUE_PAIRS: u64 = 0x08;

/// The card's address, read as the six bytes the layout puts at [`MAC`].
///
/// The region is read a dword at a time, so six bytes are two reads and the
/// high two bytes of the second are the `status` field rather than part of the
/// address.  Doing this in one place is what keeps a second caller from
/// reading five bytes, or from reversing them, and the address is a wire
/// value: a frame's source field carries these bytes in this order.
pub fn mac(read: impl Fn(u64) -> u32) -> [u8; 6] {
    let low = read(MAC);
    let high = read(MAC + 4);
    [
        low as u8,
        (low >> 8) as u8,
        (low >> 16) as u8,
        (low >> 24) as u8,
        high as u8,
        (high >> 8) as u8,
    ]
}

#[cfg(test)]
mod tests {
    use super::MAC;
    use super::MAX_VIRTQUEUE_PAIRS;
    use super::STATUS;
    use super::mac;

    /// The offsets are the specification's, and they follow each other.
    ///
    /// These are wire values: a driver that read the address from `0x02` would
    /// take four bytes of it and two bytes of the link status.
    #[test]
    fn the_layout_is_the_specifications() {
        assert_eq!(MAC, 0x00);
        assert_eq!(STATUS, 0x06);
        assert_eq!(MAX_VIRTQUEUE_PAIRS, 0x08);
        assert_eq!(STATUS - MAC, 6, "the address is six bytes");
        assert_eq!(MAX_VIRTQUEUE_PAIRS - STATUS, 2, "status is a le16");
    }

    /// The six bytes come out in the order the region holds them.
    ///
    /// The failure this pins is silent: a reversed address is still a
    /// well-formed address, so a card that answered frames from it would look
    /// like a card and the bug would be a mail server's logs, months later.
    #[test]
    fn the_address_is_read_low_byte_first() {
        // mac = 02:11:22:33:44:55 as the bytes sit in the region.
        let address = mac(|offset| match offset {
            MAC => u32::from_le_bytes([0x02, 0x11, 0x22, 0x33]),
            _ => u32::from_le_bytes([0x44, 0x55, 0x00, 0x00]),
        });
        assert_eq!(address, [0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    /// The second read is at `MAC + 4`, and its high half is not address.
    ///
    /// A driver that read four bytes at six would take the status word's low
    /// byte for the card's fifth byte; this asserts the reader never asks for
    /// an offset that is not one of the two dwords the address occupies.
    #[test]
    fn the_second_read_stops_at_the_sixth_byte() {
        // `mac` takes an `Fn` because the transport reads by `&self`, so the
        // record is a `Cell` rather than a `&mut Vec`.
        let asked = core::cell::RefCell::new(alloc::vec::Vec::new());
        let address = mac(|offset| {
            asked.borrow_mut().push(offset);
            0xFFFF_FFFF
        });
        assert_eq!(*asked.borrow(), alloc::vec![MAC, MAC + 4]);
        assert_eq!(address, [0xFF; 6], "the status word does not leak in");
    }
}
