//! drivers/virtio/net/src/device.rs
//!
//! A virtio network card: the initialisation a device goes through, and the two
//! queues it owns.
//!
//! ## The initialisation order (specification 2.1.1)
//!
//! The same sequence a block device goes through — reset, `ACKNOWLEDGE`,
//! `DRIVER`, features, `FEATURES_OK` read back, queues, `DRIVER_OK` — because
//! it is the protocol's sequence and not any one device's.  What differs is the
//! second queue and the address the device publishes instead of a capacity.
//!
//! ## The two queues, and why they are two
//!
//! Section 5.1.2: a network card has a receive queue at index 0 and a transmit
//! queue at index 1.  A block device puts every request on one queue; a card
//! cannot, because a frame arriving and a frame leaving are different
//! directions of the same ring and the device fills one while the driver fills
//! the other.
//!
//! This is the driver that made the queue index a parameter of every queue
//! operation.  Before that, `set_queue_addresses` and `enable_queue` acted on
//! whichever queue `configure_queue` last selected, which for one queue is
//! indistinguishable from correct and for two is a transmit ring the device
//! reads while the driver writes a receive ring.
//!
//! ## What this does not do yet
//!
//! No frames.  The queues exist, are programmed and are enabled, and the card
//! is `DRIVER_OK`; putting a buffer on one and taking the reply off the other
//! is the next change, and it is a change to this file rather than to the
//! framework.  The boot prints the address the card gave and the two depths, so
//! "the card came up" is a fact about a boot rather than about this comment.

use alloc::sync::Arc;

use spin::Mutex;
use virtio_core::Features;
use virtio_core::Status;
use virtio_core::Transport;
use virtio_core::VirtQueue;

use crate::config;
use crate::features::NETWORK_KNOWN;
use crate::features::VIRTIO_NET_F_MAC;

use abi::Error;
use abi::Result;

/// The queue a card's received frames arrive on (specification 5.1.2).
pub const RECEIVE_QUEUE: u16 = 0;

/// The queue a card's frames leave on.
///
/// `pub` because the boot programs the card's MSI-X vector for **this** queue,
/// exactly as it does for the block device's one, and a queue index the boot
/// guessed at would be a second fact about the driver kept in a second place.
pub const TRANSMIT_QUEUE: u16 = 1;

/// The largest queue this driver asks for.
///
/// A card may offer 256 or more; a receive ring costs a buffer per entry and
/// this driver has no frame path yet, so the depth is a bound rather than a
/// tuning.  256 entries is what the block driver asks for and is a power of
/// two, which [`VirtQueue::new`] requires.
const QUEUE_SIZE_LIMIT: u16 = 256;

/// A virtio network card.
pub struct VirtioNet {
    transport: Arc<dyn Transport>,
    receive: Mutex<VirtQueue>,
    transmit: Mutex<VirtQueue>,
    features: Features,
    /// The address the card published, and the one frames will carry.
    mac: [u8; 6],
}

impl VirtioNet {
    /// Bring up a network card over `transport`.
    ///
    /// Performs the whole initialisation sequence and programs both queues.
    /// A device that does not speak the modern interface, does not offer
    /// `VIRTIO_NET_F_MAC`, or has fewer than two queues is refused rather than
    /// half-driven: each of those is a device whose receive path would be a
    /// ring nothing fills, and a card that came up and never received would
    /// look like a quiet network.
    pub fn new(transport: Arc<dyn Transport>) -> Result<Arc<Self>> {
        // 1. Reset.
        transport.write_status(0);

        // 2-3. Acknowledge, then Driver.
        let mut status = 0u8;
        for stage in [Status::Acknowledge, Status::Driver] {
            status = virtio_core::status::next(status, stage).ok_or(Error::DeviceError)?;
            transport.write_status(status);
        }

        // 4. Features: the framework's bits plus the address, and nothing else.
        let offered = transport.device_features();
        let accepted = Features::offered(offered).negotiate(NETWORK_KNOWN);
        if !accepted.has_required() {
            return Err(Error::Unsupported);
        }
        if !accepted.accepts(VIRTIO_NET_F_MAC) {
            // The address is not optional here.  A card that publishes no
            // address is one whose frames the driver would have to invent a
            // source for, and an invented source is a claim about a network
            // nobody described.
            return Err(Error::Unsupported);
        }
        transport.set_driver_features(accepted.driver());

        // 5. FEATURES_OK, then read it back: this is where a device says no.
        status = virtio_core::status::next(status, Status::FeaturesOk).ok_or(Error::DeviceError)?;
        transport.write_status(status);
        let echoed = transport.read_status();
        if virtio_core::status::failed(echoed) || echoed & Status::FeaturesOk.bit() == 0 {
            return Err(Error::Unsupported);
        }

        // 6. Two queues, each at a size its own answer allows.
        //
        // The count is checked before anything is selected because
        // `queue_select` naming a queue the device does not have is a write
        // whose meaning the device does not define, and enabling such a queue
        // yields a ring the device never reads.
        if transport.queue_count() < TRANSMIT_QUEUE + 1 {
            return Err(Error::Unsupported);
        }
        let receive = Self::bring_up_queue(&*transport, RECEIVE_QUEUE)?;
        let transmit = Self::bring_up_queue(&*transport, TRANSMIT_QUEUE)?;

        status = virtio_core::status::next(status, Status::DriverOk).ok_or(Error::DeviceError)?;
        transport.write_status(status);
        if virtio_core::status::failed(transport.read_status()) {
            return Err(Error::DeviceError);
        }

        // The address is this crate's to read: the framework hands over the
        // configuration region as opaque dwords, and which of them is an
        // address is a network card's business.
        let mac = config::mac(|offset| transport.read_device_config_dword(offset));

        Ok(Arc::new(Self {
            transport,
            receive: Mutex::new(receive),
            transmit: Mutex::new(transmit),
            features: accepted,
            mac,
        }))
    }

    /// Size, address and enable one queue, in the order the specification
    /// requires.
    ///
    /// The three steps are one function because they are one fact: a queue the
    /// device was told about but not enabled is a ring the driver fills and the
    /// device ignores, and an enabled queue whose addresses were never written
    /// is a device reading address zero.
    fn bring_up_queue(transport: &dyn Transport, index: u16) -> Result<VirtQueue> {
        let max = transport.max_queue_size(index);
        if max < 2 {
            // A queue the device offers no depth for is a queue it does not
            // really have, whatever the count said.
            return Err(Error::Unsupported);
        }
        let size = max.min(QUEUE_SIZE_LIMIT);
        transport.configure_queue(index, size);

        let mut queue = VirtQueue::new(size as usize);
        // One value, used twice on purpose: the addresses the device is told
        // and the addresses the queue records have to be the same three, or the
        // driver would submit into a ring the device never reads.
        let addresses = queue.device_addresses();
        transport.set_queue_addresses(index, addresses);
        queue.set_device_addresses(addresses);
        transport.enable_queue(index);
        Ok(queue)
    }

    /// The address the card published.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// The features the card and this driver agreed on.
    pub fn features(&self) -> Features {
        self.features
    }

    /// How many entries the receive ring holds.
    pub fn receive_queue_size(&self) -> u16 {
        self.receive.lock().size() as u16
    }

    /// How many entries the transmit ring holds.
    pub fn transmit_queue_size(&self) -> u16 {
        self.transmit.lock().size() as u16
    }

    /// The card's transport, for a caller that has to ask the device something
    /// the driver has no method for yet.
    ///
    /// The boot's MSI-X wiring is that caller: it names the queue vector and
    /// the table entry, and neither is the driver's state.
    pub fn transport(&self) -> &Arc<dyn Transport> {
        &self.transport
    }
}

#[cfg(test)]
mod tests {
    //! The tests for this module.
    //!
    //! A fake network card behind the transport trait: the initialisation
    //! sequence, the feature negotiation, and the two queues.

    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::AtomicU64;
    use core::sync::atomic::Ordering;

    use spin::Mutex;
    use virtio_core::Transport;
    use virtio_core::features::VIRTIO_F_RING_EVENT_IDX;
    use virtio_core::features::VIRTIO_F_VERSION_1;
    use virtio_core::queue::DeviceAddresses;

    use crate::device::RECEIVE_QUEUE;
    use crate::device::TRANSMIT_QUEUE;
    use crate::device::VirtioNet;
    use crate::features::VIRTIO_NET_F_MAC;

    /// A card that records what the driver asked it to do.
    ///
    /// It is a recorder rather than a fake that services frames because this
    /// change is the bring-up: the question is whether both queues were
    /// programmed, with which addresses, at which sizes.  The frame path
    /// arrives with the fake's `perform`, which is the change that needs it.
    struct RecordingCard {
        status: AtomicU64,
        driver_features: AtomicU64,
        /// The offered features, so a test can leave one out.
        offered: AtomicU64,
        queues: u16,
        /// Each queue's own answer, indexed by queue number.
        sizes: Vec<u16>,
        configured: Mutex<Vec<(u16, u16)>>,
        addresses: Mutex<Vec<(u16, DeviceAddresses)>>,
        enabled: Mutex<Vec<u16>>,
        mac: [u8; 6],
    }

    impl RecordingCard {
        fn new(queues: u16, sizes: Vec<u16>) -> Arc<Self> {
            Arc::new(Self {
                status: AtomicU64::new(0),
                driver_features: AtomicU64::new(0),
                offered: AtomicU64::new(
                    VIRTIO_F_VERSION_1 | VIRTIO_F_RING_EVENT_IDX | VIRTIO_NET_F_MAC,
                ),
                queues,
                sizes,
                configured: Mutex::new(Vec::new()),
                addresses: Mutex::new(Vec::new()),
                enabled: Mutex::new(Vec::new()),
                mac: [0x02, 0x11, 0x22, 0x33, 0x44, 0x55],
            })
        }
    }

    impl Transport for RecordingCard {
        fn device_features(&self) -> u64 {
            self.offered.load(Ordering::Relaxed)
        }

        fn set_driver_features(&self, features: u64) {
            self.driver_features.store(features, Ordering::Relaxed);
        }

        fn read_status(&self) -> u8 {
            self.status.load(Ordering::Relaxed) as u8
        }

        fn write_status(&self, status: u8) {
            self.status.store(status as u64, Ordering::Relaxed);
        }

        fn queue_count(&self) -> u16 {
            self.queues
        }

        fn max_queue_size(&self, index: u16) -> u16 {
            // A card answers whatever its register holds, and a register for a
            // queue the device does not have holds the last value written or
            // the device's default — a *plausible* number, not zero.  That is
            // why the queue count has to be checked before anything is
            // selected: the size answer cannot be trusted to reveal that the
            // queue does not exist.
            self.sizes.get(index as usize).copied().unwrap_or(8)
        }

        fn configure_queue(&self, index: u16, size: u16) {
            self.configured.lock().push((index, size));
        }

        fn set_queue_addresses(&self, index: u16, addresses: DeviceAddresses) {
            self.addresses.lock().push((index, addresses));
        }

        fn enable_queue(&self, index: u16) {
            self.enabled.lock().push(index);
        }

        fn notify_offset(&self, _queue: u16) -> u16 {
            0
        }

        fn notify(&self, _queue: u16) {}

        fn read_device_config_dword(&self, offset: u64) -> u32 {
            // The address lives at 0x00 as six bytes, so the low dword is the
            // first four bytes and the high dword's low half is the last two.
            let bytes = |start: usize| -> [u8; 4] {
                let mut word = [0u8; 4];
                for (index, slot) in word.iter_mut().enumerate() {
                    *slot = self.mac.get(start + index).copied().unwrap_or(0);
                }
                word
            };
            match offset {
                0 => u32::from_le_bytes(bytes(0)),
                _ => u32::from_le_bytes(bytes(4)),
            }
        }
    }

    /// The clause this change exists for: two queues, each programmed with its
    /// own rings.
    ///
    /// This is the test that would have caught the queue-selection defect.  The
    /// driver reads the addresses out of each `VirtQueue` and hands them to the
    /// transport with the queue's index; a transport that ignored the index
    /// would record queue 1's call with queue 0's addresses, and a driver that
    /// reused one address set for both queues fails here.
    #[test]
    fn both_queues_are_programmed_with_their_own_rings() {
        let card = RecordingCard::new(2, alloc::vec![8, 8]);
        let net = VirtioNet::new(card.clone()).expect("bring up");

        let addresses = card.addresses.lock().clone();
        assert_eq!(addresses.len(), 2, "both queues were programmed");
        assert_eq!(addresses[0].0, RECEIVE_QUEUE);
        assert_eq!(addresses[1].0, TRANSMIT_QUEUE);

        let receive = addresses[0].1;
        let transmit = addresses[1].1;
        assert_ne!(
            receive.descriptors, transmit.descriptors,
            "each queue has its own descriptor table"
        );
        assert_ne!(
            receive.available, transmit.available,
            "each queue has its own available ring"
        );
        assert_ne!(
            receive.used, transmit.used,
            "each queue has its own used ring"
        );
        assert_ne!(receive.descriptors, 0, "the address was never built");

        assert_eq!(
            *card.enabled.lock(),
            alloc::vec![RECEIVE_QUEUE, TRANSMIT_QUEUE],
            "both queues were enabled, each by its own index"
        );
        assert_eq!(net.receive_queue_size(), 8);
        assert_eq!(net.transmit_queue_size(), 8);
    }

    /// Each queue is sized from its own answer, not from queue 0's.
    ///
    /// `max_queue_size` took no index before this change, so a two-queue driver
    /// would have asked for queue 0's size twice.  A card whose queues differ
    /// is what makes that visible: here the receive ring offers 4 and the
    /// transmit ring 16.
    #[test]
    fn each_queue_is_sized_from_its_own_answer() {
        let card = RecordingCard::new(2, alloc::vec![4, 16]);
        let net = VirtioNet::new(card.clone()).expect("bring up");

        assert_eq!(
            *card.configured.lock(),
            alloc::vec![(RECEIVE_QUEUE, 4), (TRANSMIT_QUEUE, 16)],
            "each queue was configured with its own size"
        );
        assert_eq!(net.receive_queue_size(), 4);
        assert_eq!(net.transmit_queue_size(), 16);
    }

    /// The address comes out of the configuration region in the card's order.
    #[test]
    fn the_driver_reads_the_address_the_card_gave_it() {
        let card = RecordingCard::new(2, alloc::vec![8, 8]);
        let net = VirtioNet::new(card).expect("bring up");
        assert_eq!(net.mac(), [0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    /// The card is left at `DRIVER_OK`, which is the stage that says it may be
    /// used, and the driver accepted the modern interface and the address bit.
    #[test]
    fn the_device_is_left_ready_with_the_address_feature() {
        let card = RecordingCard::new(2, alloc::vec![8, 8]);
        let net = VirtioNet::new(card.clone()).expect("bring up");
        assert_eq!(
            card.read_status(),
            15,
            "ACKNOWLEDGE|DRIVER|FEATURES_OK|DRIVER_OK"
        );
        let accepted = card.driver_features.load(Ordering::Relaxed);
        assert_ne!(accepted & VIRTIO_F_VERSION_1, 0);
        assert_ne!(accepted & VIRTIO_NET_F_MAC, 0);
        assert!(net.features().accepts(VIRTIO_NET_F_MAC));
    }

    /// A card with one queue is refused rather than driven as if it had two.
    ///
    /// A one-queue card would take the driver's transmit addresses for a queue
    /// it does not have, and the failure on a machine would be a card that
    /// came up and never sent anything.
    ///
    /// The card still **answers** for queue 1, because a register for a queue a
    /// device does not have holds something plausible rather than zero.  The
    /// refusal therefore has to come from the queue count; this test fails if
    /// that check is removed.
    #[test]
    fn a_card_with_one_queue_is_refused() {
        let card = RecordingCard::new(1, alloc::vec![8]);
        assert_eq!(VirtioNet::new(card).err(), Some(abi::Error::Unsupported));
    }

    /// A card that offers a queue no depth for is refused.
    ///
    /// The other half of the same question: a card may report the queue in
    /// `num_queues` and still answer zero for its size, and enabling a queue
    /// with no entries is a ring the device never reads.
    #[test]
    fn a_queue_with_no_depth_is_refused() {
        let card = RecordingCard::new(2, alloc::vec![8, 0]);
        assert_eq!(VirtioNet::new(card).err(), Some(abi::Error::Unsupported));
    }

    /// A card that publishes no address is refused.
    ///
    /// Without `VIRTIO_NET_F_MAC` the configuration region holds no address,
    /// so a driver that read one would read whatever the device put there and
    /// then send frames from it.
    #[test]
    fn a_card_without_an_address_is_refused() {
        let card = RecordingCard::new(2, alloc::vec![8, 8]);
        card.offered.store(
            VIRTIO_F_VERSION_1 | VIRTIO_F_RING_EVENT_IDX,
            Ordering::Relaxed,
        );
        assert_eq!(VirtioNet::new(card).err(), Some(abi::Error::Unsupported));
    }

    /// A card that does not speak the modern interface is refused.
    #[test]
    fn a_legacy_card_is_refused() {
        let card = RecordingCard::new(2, alloc::vec![8, 8]);
        card.offered.store(VIRTIO_NET_F_MAC, Ordering::Relaxed);
        assert_eq!(VirtioNet::new(card).err(), Some(abi::Error::Unsupported));
    }
}
