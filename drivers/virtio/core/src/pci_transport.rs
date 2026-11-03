//! virtio/core/src/pci_transport.rs
//!
//! The PCI modern transport: the four capability structures a virtio device
//! publishes, and the register accesses they name.
//!
//! ## What a virtio PCI device publishes
//!
//! Four capability structures, each naming a BAR and an offset inside it:
//!
//! | capability | what it holds |
//! |---|---|
//! | common (1) | features, status, queue addresses |
//! | notify (2) | one doorbell per queue |
//! | device (4) | the device's own configuration — a block device's capacity |
//! | shared memory (8) | regions, which this tree does not use |
//!
//! The device chooses where in its BAR each one sits, so a driver cannot assume
//! a layout: it walks the capability list and asks.  That is why this is
//! separate from the register offsets — the offsets are the specification's,
//! and the addresses are the device's.
//!
//! ## Why the register file is a trait too
//!
//! A BAR is memory, and reaching it means dereferencing an address the machine
//! assigned.  On a host there is no such memory, so [`RegisterFile`] is the
//! thing a test supplies: a map from offset to value, which lets the whole of
//! this module — capability walk, field packing, the notify multiplier — be
//! tested without a device.

use alloc::sync::Arc;
use core::sync::atomic::Ordering;
use core::sync::atomic::fence;

use pci::ConfigSpace;
use pci::Device;

use crate::queue::DeviceAddresses;
use crate::transport::Capability;
use crate::transport::Transport;
use crate::transport::TransportError;
use crate::transport::block_config;
use crate::transport::common;

/// A mapped region of device memory: the accessor a BAR is used through.
///
/// A real implementation reads and writes the addresses the machine assigned;
/// a test's is a map.  The two operations are what every register access needs,
/// and keeping them here is what lets the transport be tested.
pub trait RegisterFile: Send + Sync {
    /// Read a 32-bit register at `offset`.
    fn read32(&self, offset: u64) -> u32;
    /// Write a 32-bit register at `offset`.
    fn write32(&self, offset: u64, value: u32);
    /// Read a byte.
    fn read8(&self, offset: u64) -> u8;
    /// Write a byte.
    fn write8(&self, offset: u64, value: u8);
    /// Read a 16-bit register.
    fn read16(&self, offset: u64) -> u16;
    /// Write a 16-bit register.
    fn write16(&self, offset: u64, value: u16);
}

/// Where one capability structure sits: a BAR, an offset in it, and a length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapabilityLocation {
    pub capability: Capability,
    pub bar: u8,
    pub offset: u64,
    pub length: u32,
}

/// The location a virtio PCI capability structure describes.
///
/// The structure is four bytes of PCI capability header followed by twelve of
/// virtio's own (section 4.1.4.1):
///
/// ```text
/// u8  cap_vndr, cap_next, cap_len, cfg_type
/// u8  bar, padding[3]
/// le32 offset
/// le32 length
/// ```
///
/// The first twelve bytes are packed into the two dwords the configuration
/// space gives: the capability header's id and next pointer in the first, and
/// `cfg_type`, `bar` and the offset in the second.  `location` reads them from
/// the 32-bit word at the structure's offset plus four.
pub fn decode_capability(
    capability: Capability,
    bar: u8,
    offset: u32,
    length: u32,
) -> CapabilityLocation {
    CapabilityLocation {
        capability,
        bar,
        offset: offset as u64,
        length,
    }
}

/// The virtio PCI transport.
///
/// Holds the two register files it needs — the common configuration and the
/// device-specific one — plus the BAR the notification area is in.  The notify
/// area has no registers of its own: a doorbell is written at
/// `bar_base + queue_notify_off * multiplier`, so what it needs is the base.
pub struct PciTransport {
    common: Arc<dyn RegisterFile>,
    device_config: Arc<dyn RegisterFile>,
    notify_base: Arc<dyn RegisterFile>,
    notify_offset_multiplier: u32,
}

impl PciTransport {
    /// Build a transport for `device`, using `map_bar` to reach its BARs.
    ///
    /// `map_bar` is the machine's: it turns a BAR's address and length into a
    /// [`RegisterFile`], which on a machine means mapping the region and on a
    /// host means refusing.  The transport does not know which.
    ///
    /// The three virtio capabilities are found by walking the device's
    /// capability list; a device missing any of them is not one this transport
    /// can drive, and that is reported rather than half-initialised.
    pub fn new(
        config: Arc<dyn ConfigSpace>,
        device: Device,
        map_bar: &dyn Fn(u8, u64, u64) -> Option<Arc<dyn RegisterFile>>,
    ) -> Result<PciTransport, TransportError> {
        let bars = device.bars(&*config);
        let bar_address = |index: u8| -> Option<(u64, u64)> {
            let bar = bars[index as usize]?;
            Some((bar.address, 0))
        };

        let mut common_location = None;
        let mut notify_location = None;
        let mut device_location = None;

        device.capabilities(&*config, |_id, offset, word| {
            // The structure (section 4.1.4.1) is, in order:
            //
            //   u8 cap_vndr, cap_next, cap_len, cfg_type
            //   u8 bar, padding[3]
            //   le32 offset
            //   le32 length
            //
            // `word` is the dword at the structure's start, so it holds the
            // four bytes of the PCI capability header — `cfg_type` is its high
            // byte.  `bar` is the *next* dword's low byte, not this one's: a
            // driver that read it from `word` would take `cap_len` as the BAR
            // number and read the wrong window.
            let cfg_type = ((word >> 24) & 0xFF) as u8;
            let header_second = config.read_dword(device.address, (offset >> 2) + 1);
            let bar = (header_second & 0xFF) as u8;
            let region_offset = config.read_dword(device.address, (offset >> 2) + 2);
            let region_length = config.read_dword(device.address, (offset >> 2) + 3);

            let capability = match cfg_type {
                x if x == Capability::Common as u8 => Some(Capability::Common),
                x if x == Capability::Notify as u8 => Some(Capability::Notify),
                x if x == Capability::Device as u8 => Some(Capability::Device),
                _ => None,
            };
            if let Some(capability) = capability {
                let location = decode_capability(capability, bar, region_offset, region_length);
                match capability {
                    Capability::Common => common_location = Some(location),
                    Capability::Notify => notify_location = Some(location),
                    Capability::Device => device_location = Some(location),
                    Capability::SharedMemory => {}
                }
            }
            None::<()>
        });

        let common_location = common_location.ok_or(TransportError::BadCapability)?;
        let notify_location = notify_location.ok_or(TransportError::BadCapability)?;
        let device_location = device_location.ok_or(TransportError::BadCapability)?;

        let common = map_capability(map_bar, &bar_address, common_location)?;
        let notify = map_capability(map_bar, &bar_address, notify_location)?;
        let device_config = map_capability(map_bar, &bar_address, device_location)?;

        // The notify multiplier is read from the notification capability's
        // second dword (section 4.1.4.4): a doorbell is at
        // `base + queue_notify_off * multiplier` inside the notify region.
        // The multiplier is the capability's own `length` field, reused: for
        // the notify capability it is "the multiplier to apply to
        // `queue_notify_off`" (section 4.1.4.4.1), not a region length.
        let notify_offset_multiplier = notify_location.length;

        Ok(PciTransport {
            common,
            device_config,
            notify_base: notify,
            notify_offset_multiplier,
        })
    }
}

/// Map a capability's BAR and report the region it describes.
fn map_capability(
    map_bar: &dyn Fn(u8, u64, u64) -> Option<Arc<dyn RegisterFile>>,
    bar_address: &dyn Fn(u8) -> Option<(u64, u64)>,
    location: CapabilityLocation,
) -> Result<Arc<dyn RegisterFile>, TransportError> {
    let (address, _length) = bar_address(location.bar).ok_or(TransportError::BadCapability)?;
    map_bar(
        location.bar,
        address + location.offset,
        location.length as u64,
    )
    .ok_or(TransportError::BadCapability)
}

impl Transport for PciTransport {
    fn device_features(&self) -> u64 {
        // Section 4.1.4.3.1: the 64-bit set is read as two dwords, chosen by
        // `device_feature_select`.  The two halves are written into the
        // select register before each read because the device latches it.
        self.common.write32(common::DEVICE_FEATURE_SELECT, 0);
        let low = self.common.read32(common::DEVICE_FEATURE) as u64;
        self.common.write32(common::DEVICE_FEATURE_SELECT, 1);
        let high = self.common.read32(common::DEVICE_FEATURE) as u64;
        low | (high << 32)
    }

    fn set_driver_features(&self, features: u64) {
        self.common.write32(common::DRIVER_FEATURE_SELECT, 0);
        self.common.write32(common::DRIVER_FEATURE, features as u32);
        self.common.write32(common::DRIVER_FEATURE_SELECT, 1);
        self.common
            .write32(common::DRIVER_FEATURE, (features >> 32) as u32);
    }

    fn read_status(&self) -> u8 {
        self.common.read8(common::DEVICE_STATUS)
    }

    fn write_status(&self, status: u8) {
        self.common.write8(common::DEVICE_STATUS, status);
        // A status write is a request the device acts on, and the write must
        // reach it before the next register read is interpreted.
        fence(Ordering::SeqCst);
    }

    fn max_queue_size(&self) -> u16 {
        // The largest queue is read after selecting queue 0: `queue_size` is
        // per-queue, and a device may offer different sizes.  This driver uses
        // one queue, so the first one's answer is the one that matters.
        self.common.write16(common::QUEUE_SELECT, 0);
        self.common.read16(common::QUEUE_SIZE)
    }

    fn configure_queue(&self, index: u16, size: u16) {
        self.common.write16(common::QUEUE_SELECT, index);
        self.common.write16(common::QUEUE_SIZE, size);
    }

    fn set_queue_addresses(&self, addresses: DeviceAddresses) {
        // The three addresses are `le64` in the common configuration, written
        // as a low dword and a high dword each (section 4.1.4.3.2).
        self.common
            .write32(common::QUEUE_DESC, addresses.descriptors as u32);
        self.common
            .write32(common::QUEUE_DESC + 4, (addresses.descriptors >> 32) as u32);
        self.common
            .write32(common::QUEUE_DRIVER, addresses.available as u32);
        self.common
            .write32(common::QUEUE_DRIVER + 4, (addresses.available >> 32) as u32);
        self.common
            .write32(common::QUEUE_DEVICE, addresses.used as u32);
        self.common
            .write32(common::QUEUE_DEVICE + 4, (addresses.used >> 32) as u32);
    }

    fn enable_queue(&self) {
        // Written last: the device starts reading the rings the moment this is
        // set, so everything the queue needs has to be there first.
        self.common.write16(common::QUEUE_ENABLE, 1);
    }

    fn notify_offset(&self, queue: u16) -> u16 {
        self.common.write16(common::QUEUE_SELECT, queue);
        self.common.read16(common::QUEUE_NOTIFY_OFF)
    }

    fn notify(&self, queue: u16) {
        let offset = self.notify_offset(queue) as u64 * self.notify_offset_multiplier as u64;
        self.notify_base.write16(offset, queue);
    }

    fn capacity_sectors(&self) -> u64 {
        let low = self.device_config.read32(block_config::CAPACITY) as u64;
        let high = self.device_config.read32(block_config::CAPACITY + 4) as u64;
        low | (high << 32)
    }

    fn read_device_config_byte(&self, offset: u64) -> u8 {
        self.device_config.read8(offset)
    }
}

#[cfg(test)]
mod tests {
    use super::decode_capability;
    use crate::transport::Capability;

    /// A capability location is the three fields the structure names, and its
    /// length is the region's, not the structure's.
    #[test]
    fn a_capability_is_its_bar_and_its_offset() {
        let location = decode_capability(Capability::Common, 4, 0x1000, 0x38);
        assert_eq!(location.capability, Capability::Common);
        assert_eq!(location.bar, 4);
        assert_eq!(location.offset, 0x1000);
        assert_eq!(location.length, 0x38);
    }
}
