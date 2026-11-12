//! drivers/virtio/net/src/features.rs
//!
//! The feature bits a network device offers, and the ones this driver accepts.
//!
//! ## Why these are here and not in `virtio_core`
//!
//! The framework knows the bits every virtio device has: the modern interface
//! and the event index.  Everything else is a device's own vocabulary, and a
//! network card's is large: checksum offloads, segmentation, mergeable receive
//! buffers, a control queue, multiqueue.  A bit in the framework that only one
//! device understands would be a bit every other device's kernel carries.
//!
//! ## What this driver does not negotiate
//!
//! Nothing but the address.  Every offload is a promise about a packet format
//! this driver does not yet build, and negotiating a feature is telling the
//! device the driver will honour it.  `VIRTIO_NET_F_MRG_RXBUF` in particular
//! changes the header's length from ten bytes to twelve, so accepting it
//! without reading it would shift every frame by two bytes.

/// Bit 5: the device supplies the card's address in its configuration.
///
/// Section 5.1.3.  Without it the configuration region has no address field at
/// all, and a driver that read one would read whatever the device put there.
/// This driver requires the bit rather than inventing an address: a made-up
/// address is a claim about a network the driver has not been told about.
pub const VIRTIO_NET_F_MAC: u64 = 1 << 5;

/// The features this driver knows how to use when the device offers them.
///
/// The framework's known set plus the one device bit above.  A driver that
/// passed only its own bit to
/// [`Features::negotiate`](virtio_core::features::Features::negotiate) would
/// clear the modern interface and be refused by its own `has_required` check.
pub const NETWORK_KNOWN: u64 = virtio_core::features::FRAMEWORK_KNOWN | VIRTIO_NET_F_MAC;

#[cfg(test)]
mod tests {
    use virtio_core::features::FRAMEWORK_KNOWN;
    use virtio_core::features::VIRTIO_F_RING_EVENT_IDX;
    use virtio_core::features::VIRTIO_F_VERSION_1;

    use super::NETWORK_KNOWN;
    use super::VIRTIO_NET_F_MAC;

    /// The address bit is the specification's number, not a local choice.
    ///
    /// It is a wire value: the device compares the bit the driver writes back,
    /// so a driver that used another bit would clear a feature it did not mean
    /// to clear and leave this one unnegotiated.
    #[test]
    fn the_mac_bit_is_the_specifications() {
        assert_eq!(VIRTIO_NET_F_MAC, 0x20);
    }

    /// The network's known set contains the framework's, which is what keeps a
    /// network driver from negotiating away the interface it runs on.
    #[test]
    fn the_known_set_contains_the_frameworks() {
        assert_eq!(NETWORK_KNOWN & FRAMEWORK_KNOWN, FRAMEWORK_KNOWN);
        assert_ne!(NETWORK_KNOWN & VIRTIO_F_VERSION_1, 0);
        assert_ne!(NETWORK_KNOWN & VIRTIO_F_RING_EVENT_IDX, 0);
        assert_ne!(NETWORK_KNOWN & VIRTIO_NET_F_MAC, 0);
    }
}
