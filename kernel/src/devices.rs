//! kernel/src/devices.rs
//!
//! Finding the machine's devices, and handing the ones it has to the driver
//! that wants them.
//!
//! ## Why this is the kernel's and not a crate's
//!
//! A scan is a *policy*: which bus, how many of them, which devices are worth
//! keeping, and what happens when the one you wanted is absent.  The bus crate
//! knows how to walk a bus; only the kernel knows that this boot wants a block
//! device and that a machine without one still has to boot.
//!
//! ## The identity map
//!
//! A driver hands the device physical addresses: the virtqueue's rings, and the
//! buffers a request names.  This boot runs on an identity map — the first
//! gigabyte of physical memory is at the same virtual address — so a `Vec`'s
//! address *is* its physical address and the two need no conversion.
//!
//! That is a property of this boot and not of the driver, which is why
//! [`physical_address`] is a function with its argument: when the kernel gets a
//! real address space, this is the one place that has to learn to translate.

use alloc::sync::Arc;

use pci::Device;
use pci::PortConfig;
use virtio_core::PciTransport;
use virtio_core::RegisterFile;

/// The class code a storage controller carries.
///
/// The PCI code is three bytes: class, subclass, interface.  `0x01` is mass
/// storage, and virtio's block device reports `0x01 / 0x00 / 0x00`.
const CLASS_STORAGE: u8 = 0x01;

/// Vendors whose storage devices this boot can drive.
///
/// QEMU's `virtio-blk-pci` reports vendor `0x1AF4` — Red Hat's virtio ID — and
/// device `0x1001` for the legacy interface or `0x1042` for the modern one.
/// Only the modern device is usable here, because the transport this tree
/// implements is the modern one.
const VENDOR_REDHAT: u16 = 0x1AF4;
const DEVICE_VIRTIO_BLOCK_MODERN: u16 = 0x1042;
const DEVICE_VIRTIO_BLOCK_TRANSITIONAL: u16 = 0x1001;

/// A mapped region of device memory.
///
/// The identity map again: a BAR's address is already the address this code
/// can read, so the file is a pointer and a length.  On a machine whose
/// physical memory is not the virtual one, this is the second place that has to
/// learn to map.
struct MappedBar {
    base: usize,
    length: usize,
}

impl RegisterFile for MappedBar {
    fn read32(&self, offset: u64) -> u32 {
        let offset = offset as usize;
        assert!(offset + 4 <= self.length, "read past the mapped BAR");
        // SAFETY: `offset` is inside the region `map_bar` was asked for, and
        // the region is the device's memory as the machine mapped it.  A
        // volatile read is what MMIO needs: the compiler must not fold two
        // reads of a register the device may have changed between them.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }

    fn write32(&self, offset: u64, value: u32) {
        let offset = offset as usize;
        assert!(offset + 4 <= self.length, "write past the mapped BAR");
        // SAFETY: as `read32`.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) }
    }

    fn read8(&self, offset: u64) -> u8 {
        let offset = offset as usize;
        assert!(offset < self.length, "read past the mapped BAR");
        // SAFETY: as `read32`, one byte wide.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u8) }
    }

    fn write8(&self, offset: u64, value: u8) {
        let offset = offset as usize;
        assert!(offset < self.length, "write past the mapped BAR");
        // SAFETY: as `read32`, one byte wide.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u8, value) }
    }

    fn read16(&self, offset: u64) -> u16 {
        let offset = offset as usize;
        assert!(offset + 2 <= self.length, "read past the mapped BAR");
        // SAFETY: as `read32`, two bytes wide and 16-bit aligned by the
        // specification's layout.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u16) }
    }

    fn write16(&self, offset: u64, value: u16) {
        let offset = offset as usize;
        assert!(offset + 2 <= self.length, "write past the mapped BAR");
        // SAFETY: as `read32`, two bytes wide.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u16, value) }
    }
}

/// The PCI bus this boot scans.
///
/// One bus, and that is the machine's statement rather than a limit of the
/// code: QEMU's `q35` puts every device a boot cares about on bus 0, and a
/// second bus is behind a bridge — which [`pci::device::scan`] reports and does
/// not descend into.
const BUS_COUNT: u8 = 1;

/// A block device found on the PCI bus, ready to be mounted.
pub struct FoundBlockDevice {
    pub transport: Arc<virtio_core::PciTransport>,
    pub device: Device,
}

/// Scan the bus for a virtio block device, and bring up its transport.
///
/// Returns `None` when the machine has no such device, which is a normal
/// state: a boot with no disk still has a console and a heap, and a machine
/// that refused to boot because a disk was absent could not be debugged.
pub fn find_virtio_block() -> Option<FoundBlockDevice> {
    let config = PortConfig::new();
    let (scan_result, found) = pci::device::scan(&config, BUS_COUNT, |device| {
        let modern = device.vendor == VENDOR_REDHAT
            && device.device == DEVICE_VIRTIO_BLOCK_MODERN
            && device.class == CLASS_STORAGE;
        let transitional = device.vendor == VENDOR_REDHAT
            && device.device == DEVICE_VIRTIO_BLOCK_TRANSITIONAL
            && device.class == CLASS_STORAGE;
        if modern || transitional {
            Some((device, modern))
        } else {
            None
        }
    });

    // A probe that found nothing is worth reporting: "no virtio-blk" and "the
    // bus answered for nothing" are different states, and only the second means
    // the scan itself is not reaching the machine.
    arch::serial::write_str("protofire: pci scan found ");
    arch::serial::write_u32(scan_result.devices as u32);
    arch::serial::write_str(" device(s) on ");
    arch::serial::write_u32(scan_result.buses as u32);
    arch::serial::write_str(" bus\n");

    let (device, _modern) = found?;
    // A transitional device (0x1001) offers the legacy interface *and* the
    // modern one: the modern capabilities are still in its capability list,
    // and `PciTransport` walks for them.  So it is not refused here — refusing
    // it would mean QEMU's default `virtio-blk-pci` could never be driven.
    // A device with no modern capabilities fails inside `PciTransport::new`,
    // which is where the list is actually read.

    let map_bar = |_bar: u8, address: u64, length: u64| -> Option<Arc<dyn RegisterFile>> {
        let base = physical_address(address);
        // The boot's table maps this window cached, which for a device's
        // registers means a read returns whatever was true when the line was
        // fetched and a store may never arrive.  Re-mapping it uncached is what
        // makes the registers the device's rather than the cache's.
        //
        // SAFETY: the region is a BAR the bus reported, so it is a device's
        // memory and nothing else.
        #[cfg(target_os = "none")]
        unsafe {
            crate::address_space::map_device(base, length as usize);
        }
        Some(Arc::new(MappedBar {
            base,
            length: length as usize,
        }))
    };

    let transport = match PciTransport::new(Arc::new(PortConfig::new()), device, &map_bar) {
        Ok(transport) => transport,
        Err(error) => {
            arch::serial::write_str("protofire: virtio transport failed: ");
            arch::serial::write_str(match error {
                virtio_core::transport::TransportError::NoDevice => "no device",
                virtio_core::transport::TransportError::BadCapability => "bad capability",
                virtio_core::transport::TransportError::DeviceRefused => "device refused",
                virtio_core::transport::TransportError::Unsupported => "unsupported",
            });
            arch::serial::write_str("\n");
            return None;
        }
    };
    Some(FoundBlockDevice {
        transport: Arc::new(transport),
        device,
    })
}

/// The address the device sees, for an address this code can use.
///
/// Identity, and that is this boot's arrangement rather than a fact about
/// memory: the boot assembly maps the first gigabyte at the same virtual
/// address, so a pointer and its physical address are the same number.  When
/// the kernel gets an address space of its own, this is where the translation
/// goes — and it is a function so that becomes one change rather than a search.
pub fn physical_address(virtual_address: u64) -> usize {
    virtual_address as usize
}
