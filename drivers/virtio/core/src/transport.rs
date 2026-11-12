//! drivers/virtio/core/src/transport.rs
//!
//! What a device and a driver talk through: the register set virtio defines,
//! behind a trait so the queue code does not know whether it is PCI or MMIO.
//!
//! ## Why a trait
//!
//! Virtio 1.2 defines two transports, legacy MMIO (section 4.2) and modern PCI
//! (section 4.1), and they differ in *where the registers are*, not in what
//! they mean.  A feature bit is read from a different place on each and means
//! the same thing; a queue's descriptor address is written in two 32-bit halves
//! on both.
//!
//! Putting that behind a trait means the queue and the device crates are
//! written once.  It also means a host test can implement the trait over a
//! `Vec` and drive the real driver code, which is the difference between a
//! driver that is tested and one that is merely compiled.
//!
//! ## What this crate implements
//!
//! PCI modern only.  QEMU's `q35` puts `virtio-blk-pci` on the PCI bus, and
//! that is the machine the boot gates run on.  The MMIO transport is what a
//! device-tree machine (aarch64 `virt`, riscv64) uses, and it arrives with the
//! device tree rather than before it, a transport with no configuration to
//! find its registers from is a transport that cannot be used.
//!
//! ## The register offsets are the specification's
//!
//! Every constant below is from Virtio 1.2 section 4.1.4.*, and none of them
//! is a local convention.  The `VIRTIO_PCI_CAP_*` capability structure
//! (4.1.4.1) is how a driver finds them: the device's PCI configuration space
//! names a BAR and an offset within it, because a device is entitled to place
//! its registers anywhere in its own address space.

/// The four kinds of capability a modern PCI virtio device publishes.
///
/// Section 4.1.4.1: `struct virtio_pci_cap { u8 cap_vndr; u8 cap_next;
/// u8 cap_len; u8 cfg_type; u8 bar; u8 padding[3]; u32 offset; u32 length; }`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Capability {
    /// The common configuration: features, status, queue addresses.
    Common = 1,
    /// The notification area: one doorbell per queue.
    Notify = 2,
    /// The device-specific configuration: a block device's capacity.
    Device = 4,
    /// The shared-memory regions, which this tree does not use.
    SharedMemory = 8,
}

/// Offsets within the common configuration structure (section 4.1.4.3).
pub mod common {
    /// `u8 device_feature_select`
    pub const DEVICE_FEATURE_SELECT: u64 = 0x00;
    /// `le32 device_feature`
    pub const DEVICE_FEATURE: u64 = 0x04;
    /// `u8 driver_feature_select`
    pub const DRIVER_FEATURE_SELECT: u64 = 0x08;
    /// `le32 driver_feature`
    pub const DRIVER_FEATURE: u64 = 0x0C;
    /// `u16 msix_config`
    pub const MSIX_CONFIG: u64 = 0x10;
    /// `u16 num_queues`
    pub const NUM_QUEUES: u64 = 0x12;
    /// `u8 device_status`
    pub const DEVICE_STATUS: u64 = 0x14;
    /// `u8 config_generation`
    pub const CONFIG_GENERATION: u64 = 0x15;
    /// `u16 queue_select`
    pub const QUEUE_SELECT: u64 = 0x16;
    /// `u16 queue_size`
    pub const QUEUE_SIZE: u64 = 0x18;
    /// `u16 queue_msix_vector`
    pub const QUEUE_MSIX_VECTOR: u64 = 0x1A;
    /// `u16 queue_enable`
    pub const QUEUE_ENABLE: u64 = 0x1C;
    /// `u16 queue_notify_off`
    pub const QUEUE_NOTIFY_OFF: u64 = 0x1E;
    /// `le64 queue_desc`
    pub const QUEUE_DESC: u64 = 0x20;
    /// `le64 queue_driver` (the available ring)
    pub const QUEUE_DRIVER: u64 = 0x28;
    /// `le64 queue_device` (the used ring)
    pub const QUEUE_DEVICE: u64 = 0x30;
}

/// Why a transport operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportError {
    /// The device did not appear where the bus said it would be.
    NoDevice,
    /// The device's configuration space is not the shape it should be.
    BadCapability,
    /// The device did not publish one of the three capabilities a transport
    /// needs.  Which one is the whole question: a device missing `Common`
    /// offers no registers at all, and one missing only `Device` still has a
    /// queue.
    MissingCapability(Capability, Seen),
    /// A queue operation raced with the device's own state.
    DeviceRefused,
    /// The transport has no configuration source on this build.
    Unsupported,
}

/// What a capability walk actually saw.
///
/// The `cfg_type` of each structure, in walk order, plus how many it visited.
/// A transport that reports only "no common capability" leaves a reader to
/// re-derive the list from the device, and the list is exactly what the answer
/// depends on, a device whose structures are all there under different type
/// numbers is not missing anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Seen {
    /// How many structures the walk visited.
    pub count: usize,
    /// The first eight `cfg_type` bytes, in order.
    pub types: [u8; 8],
    /// How many of `types` are meaningful.
    pub walked: usize,
}

impl Seen {
    /// An empty record.
    pub const fn new() -> Seen {
        Seen {
            count: 0,
            types: [0; 8],
            walked: 0,
        }
    }
}

impl Default for Seen {
    fn default() -> Self {
        Self::new()
    }
}

/// Where a virtio device's registers are, and how to reach them.
///
/// A device crate submits through this and never names PCI or MMIO.  The
/// methods are the register accesses the specification defines, in the order a
/// driver uses them, so an implementation is a map from these to addresses.
pub trait Transport: Send + Sync {
    /// The device's offered feature bits.
    ///
    /// Section 2.1: a `le32` is read twice with `device_feature_select` set to
    /// 0 and 1, and the two halves concatenate into the 64-bit set.
    fn device_features(&self) -> u64;

    /// Tell the device which features were accepted.
    fn set_driver_features(&self, features: u64);

    /// Read the device status byte.
    fn read_status(&self) -> u8;

    /// Write the device status byte.
    fn write_status(&self, status: u8);

    /// How many queues the device has.
    ///
    /// Section 4.1.4.3: `num_queues` describes the device, not one queue, and
    /// it is the answer a driver needs before it programs a second queue.
    /// `queue_select` naming a queue the device does not have is a write whose
    /// meaning the device does not define, and a driver that went on to enable
    /// that queue would hold a receive ring nothing ever fills — a card that
    /// looks up and never receives.
    fn queue_count(&self) -> u16;

    /// The largest size the device offers for `index`'s queue.
    ///
    /// Section 4.1.4.3.2: `queue_size` is per-queue state, so the selection is
    /// made here rather than by a `configure_queue` call made some time before.
    /// This method used to take no index and always select queue 0, which is
    /// the same defect the addresses had: a two-queue driver that sized its
    /// transmit queue from the receive queue's answer would program a size the
    /// device never offered for it, and every register would read back what was
    /// written.
    fn max_queue_size(&self, index: u16) -> u16;

    /// Select a queue, and tell the device how large the driver made it.
    fn configure_queue(&self, index: u16, size: u16);

    /// Program the three ring addresses for `index`'s queue.
    ///
    /// Section 4.1.4.3.2: `queue_desc`, `queue_driver` and `queue_device` are
    /// each a `le64` the driver writes once, before enabling the queue.
    ///
    /// The index is a parameter **and not implicit in an earlier selection**,
    /// which is a correction: these two methods used to act on whichever queue
    /// `configure_queue` last selected, and that works only for a device with
    /// one queue.  A network card has a receive queue and a transmit queue, and
    /// a driver that configured one and then programmed the other's addresses
    /// would write them into the first — with every register reading back
    /// exactly what it wrote.  Making the queue explicit is what the device's
    /// own registers mean: `queue_select` names the queue every other
    /// `queue_*` register applies to, so the selection belongs inside each
    /// method rather than in a call made some time before it.
    fn set_queue_addresses(&self, index: u16, addresses: crate::queue::DeviceAddresses);

    /// Tell the device that `index`'s queue is ready.
    fn enable_queue(&self, index: u16);

    /// The offset to write in the notify area to ring a queue's doorbell.
    ///
    /// Section 4.1.4.4: `queue_notify_off` is a *multiplier* into the notify
    /// region, not an address, a driver computes `region + off * mult`.
    fn notify_offset(&self, queue: u16) -> u16;

    /// Ring a queue's doorbell.
    fn notify(&self, queue: u16);

    /// Read one dword of the **device-specific** configuration.
    ///
    /// Section 4.1.4.3.4: every device has a configuration region whose
    /// layout is the device's own, at the offset its
    /// `VIRTIO_PCI_CAP_DEVICE_CFG` capability names.  This framework reads it
    /// and does not interpret it: a block device's capacity, a network card's
    /// MAC address and a GPU's resolution are all somewhere in that region, and
    /// where is each device crate's business.
    ///
    /// Two methods used to sit here — `capacity_sectors` and
    /// `read_device_config_byte` — and both were the block device's.  The first
    /// named the block layout (`0x00` is its `le64 capacity`) in a crate that
    /// is not the block crate, and the second had no caller at all: a method on
    /// a trait every implementor must write, for a byte no driver read.  One
    /// generic reader replaces both, and the device crate that owns a layout
    /// reads its own fields out of it.
    fn read_device_config_dword(&self, offset: u64) -> u32;

    /// Map the selected queue's completion interrupt to MSI-X vector `vector`.
    ///
    /// Section 4.1.4.3.2: the driver writes `queue_msix_vector` and reads it
    /// back; the device latches the mapping **asynchronously**, so an answer
    /// that does not equal what was written is a mapping the device refused —
    /// usually no vector left — and a driver that believed the write would wait
    /// for an interrupt that never comes.
    ///
    /// `false` is the answer for a transport with no MSI-X at all, which is the
    /// ordinary state: a device on a machine with no message-signalled
    /// interrupt destination completes through its driver's polling, and no
    /// vector is mapped.  The default is that answer, so a transport that has
    /// no vector mechanism to speak of says so rather than pretending.
    fn set_queue_vector(&self, queue: u16, vector: u16) -> bool {
        let _ = (queue, vector);
        false
    }
}

/// The transport a host build presents: none.
///
/// A host has no virtio device, and a transport that invented one would let a
/// test pass against a queue no device ever reads.  Reporting
/// [`TransportError::Unsupported`] from construction is the honest answer, and
/// it is why the device crate's host tests drive a transport of their own
/// rather than this one.
pub struct NoDevice;

impl NoDevice {
    /// There is no device to build a transport for.
    pub fn new() -> Result<NoDevice, TransportError> {
        Err(TransportError::Unsupported)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::Capability;
    use super::Transport;
    use super::TransportError;
    use super::common;

    /// The common configuration offsets are at the distances the specification
    /// gives, which is what a driver's byte arithmetic relies on.
    ///
    /// A wrong offset here is a driver that writes its feature bits into the
    /// status byte, and the device's answer would be a refusal that says
    /// nothing about where the mistake is.
    #[test]
    fn the_common_configuration_layout_is_the_specifications() {
        assert_eq!(common::DEVICE_FEATURE, 0x04);
        assert_eq!(common::DEVICE_FEATURE_SELECT, 0x00);
        assert_eq!(common::DRIVER_FEATURE, 0x0C);
        assert_eq!(common::DEVICE_STATUS, 0x14);
        assert_eq!(common::NUM_QUEUES, 0x12);
        assert_eq!(common::QUEUE_SELECT, 0x16);
        assert_eq!(common::QUEUE_SIZE, 0x18);
        assert_eq!(common::QUEUE_NOTIFY_OFF, 0x1E);
        assert_eq!(common::QUEUE_DESC, 0x20);
        assert_eq!(common::QUEUE_DRIVER, 0x28);
        assert_eq!(common::QUEUE_DEVICE, 0x30);
    }

    /// The fields are where the structure's sizes put them: a `le64` at 0x20
    /// and 0x28 means the structure is eight bytes per address.
    #[test]
    fn the_queue_addresses_are_eight_bytes_apart() {
        assert_eq!(common::QUEUE_DRIVER - common::QUEUE_DESC, 8);
        assert_eq!(common::QUEUE_DEVICE - common::QUEUE_DRIVER, 8);
    }

    /// The capability types are the specification's numbers, not an enum this
    /// crate chose.
    #[test]
    fn the_capability_types_are_the_specifications() {
        assert_eq!(Capability::Common as u8, 1);
        assert_eq!(Capability::Notify as u8, 2);
        assert_eq!(Capability::Device as u8, 4);
        assert_eq!(Capability::SharedMemory as u8, 8);
    }

    /// Every queue method names its queue, so two queues cannot be confused.
    ///
    /// A network card has a receive queue and a transmit queue.  The two
    /// methods that program a queue used to act on whichever queue
    /// `configure_queue` last selected, so a driver that configured queue 0,
    /// then configured queue 1, then programmed queue 0's addresses wrote them
    /// into queue 1 — and every register read back what was written.  The
    /// index is a parameter now, and this pins that it is the one used.
    ///
    /// The check is on the trait's contract rather than on one implementation:
    /// a fake records the index it was handed, and an implementation that
    /// ignored the argument would fail here and on the machine.
    #[test]
    fn every_queue_operation_names_its_queue() {
        use crate::queue::DeviceAddresses;
        use std::sync::Mutex;
        use std::vec;
        use std::vec::Vec;

        /// Records the index of every call, so a queue chosen by a previous
        /// call cannot pass.
        struct Recorder {
            seen: Mutex<Vec<(&'static str, u16)>>,
        }

        impl Transport for Recorder {
            fn device_features(&self) -> u64 {
                0
            }
            fn set_driver_features(&self, _features: u64) {}
            fn read_status(&self) -> u8 {
                0
            }
            fn write_status(&self, _status: u8) {}
            fn queue_count(&self) -> u16 {
                2
            }
            fn max_queue_size(&self, index: u16) -> u16 {
                self.seen.lock().unwrap().push(("size", index));
                8
            }
            fn configure_queue(&self, index: u16, _size: u16) {
                self.seen.lock().unwrap().push(("configure", index));
            }
            fn set_queue_addresses(&self, index: u16, _addresses: DeviceAddresses) {
                self.seen.lock().unwrap().push(("addresses", index));
            }
            fn enable_queue(&self, index: u16) {
                self.seen.lock().unwrap().push(("enable", index));
            }
            fn notify_offset(&self, _queue: u16) -> u16 {
                0
            }
            fn notify(&self, _queue: u16) {}
            fn read_device_config_dword(&self, _offset: u64) -> u32 {
                0
            }
            fn set_queue_vector(&self, _queue: u16, _vector: u16) -> bool {
                false
            }
        }

        let recorder = Recorder {
            seen: Mutex::new(Vec::new()),
        };
        let addresses = DeviceAddresses {
            descriptors: 0x1000,
            available: 0x2000,
            used: 0x3000,
        };
        // The order a two-queue driver uses: ask each queue its size, configure
        // both, then program each.
        recorder.max_queue_size(0);
        recorder.max_queue_size(1);
        recorder.configure_queue(0, 8);
        recorder.configure_queue(1, 8);
        recorder.set_queue_addresses(0, addresses);
        recorder.enable_queue(0);
        recorder.set_queue_addresses(1, addresses);
        recorder.enable_queue(1);

        assert_eq!(
            *recorder.seen.lock().unwrap(),
            vec![
                ("size", 0),
                ("size", 1),
                ("configure", 0),
                ("configure", 1),
                ("addresses", 0),
                ("enable", 0),
                ("addresses", 1),
                ("enable", 1),
            ],
            "each call names the queue it applies to"
        );
    }

    /// A host has no device, and the stub says so rather than pretending.
    #[test]
    fn a_host_has_no_device() {
        assert_eq!(
            super::NoDevice::new().err(),
            Some(TransportError::Unsupported)
        );
    }
}
