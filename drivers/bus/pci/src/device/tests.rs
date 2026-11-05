//! drivers/bus/pci/src/device/tests.rs
//!
//! The PCI device: its identity read from configuration space, and the
//! functions a multi-function device reports.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

use crate::bar::BarKind;
use crate::config::ConfigSpace;
use crate::device::Device;
use crate::device::DeviceAddress;
use crate::device::REG_BAR0;
use crate::device::REG_CAPABILITY;
use crate::device::REG_CLASS_REVISION;
use crate::device::REG_COMMAND_STATUS;
use crate::device::REG_HEADER;
use crate::device::REG_VENDOR_DEVICE;
use crate::device::STATUS_CAPABILITY_LIST;
use crate::device::scan;
use alloc::collections::BTreeMap;

/// A configuration space a test writes registers into.
///
/// The enumeration is the code under test; this is the machine it runs
/// against, and it is a register file rather than a mock of the code above
/// it.
#[derive(Default)]
struct FakeConfig {
    words: BTreeMap<(u8, u8, u8, u8), u32>,
    /// What a read of an unprogrammed address returns.
    absent: u32,
}

impl FakeConfig {
    fn present() -> Self {
        Self {
            words: BTreeMap::new(),
            absent: 0xFFFF_FFFF,
        }
    }

    fn set(&mut self, address: DeviceAddress, register: u8, value: u32) {
        self.words.insert(
            (address.bus, address.device, address.function, register),
            value,
        );
    }
}

impl ConfigSpace for FakeConfig {
    fn read_dword(&self, address: DeviceAddress, register: u8) -> u32 {
        self.words
            .get(&(address.bus, address.device, address.function, register))
            .copied()
            .unwrap_or(self.absent)
    }

    fn write_dword(&self, _address: DeviceAddress, _register: u8, _value: u32) {}
}

fn virtio_block_at(config: &mut FakeConfig, bus: u8, device: u8) {
    let address = DeviceAddress {
        bus,
        device,
        function: 0,
    };
    // Vendor 0x1AF4 (Red Hat / virtio), device 0x1042 (block).
    config.set(address, REG_VENDOR_DEVICE, 0x1042_1AF4);
    // Class 0x01 (storage), subclass 0x00, interface 0x00.
    config.set(address, REG_CLASS_REVISION, 0x01 << 24);
    // Header type 0, not multi-function, and the capability list bit set.
    config.set(address, REG_HEADER, 0);
    config.set(
        address,
        REG_COMMAND_STATUS,
        (STATUS_CAPABILITY_LIST as u32) << 16,
    );
}

/// A device is found where it is, with the identity it reports.
#[test]
fn a_device_is_probed_from_its_identity() {
    let mut config = FakeConfig::present();
    virtio_block_at(&mut config, 0, 3);

    let found = Device::probe(
        &config,
        DeviceAddress {
            bus: 0,
            device: 3,
            function: 0,
        },
    )
    .expect("a device answers");
    assert_eq!(found.vendor, 0x1AF4);
    assert_eq!(found.device, 0x1042);
    assert_eq!(found.class, 0x01);
    assert!(!found.multi_function);
}

/// An address nothing answers reads as absent, and a scan finds nothing.
///
/// This is the same state a host's port arm produces, so the enumeration
/// has one "nothing there" answer rather than a machine-specific one.
#[test]
fn an_empty_bus_finds_nothing() {
    let config = FakeConfig::present();
    let (scan_result, found) = scan(&config, 1, Some);
    assert_eq!(scan_result.devices, 0);
    assert!(found.is_none());
}

/// A scan finds the one device on the bus and stops there.
#[test]
fn a_scan_finds_the_device_and_stops() {
    let mut config = FakeConfig::present();
    virtio_block_at(&mut config, 0, 5);

    let (scan_result, found) = scan(&config, 1, |device| {
        if device.vendor == 0x1AF4 {
            Some(device)
        } else {
            None
        }
    });
    assert_eq!(scan_result.devices, 1);
    assert_eq!(found.expect("found").address.device, 5);
}

/// Functions past zero are not probed on a single-function device.
///
/// Some chipsets answer for them anyway, and a scan that read every
/// function would report one device eight times.
#[test]
fn a_single_function_device_is_one_device() {
    let mut config = FakeConfig::present();
    virtio_block_at(&mut config, 0, 2);
    // A device that answers on every function, which is the case this
    // guard exists for.
    for function in 1..8u8 {
        let address = DeviceAddress {
            bus: 0,
            device: 2,
            function,
        };
        config.set(address, REG_VENDOR_DEVICE, 0x1042_1AF4);
    }

    let (scan_result, _) = scan(&config, 1, |_| None::<()>);
    assert_eq!(scan_result.devices, 1, "the function guard held");
}

/// A device's BARs are decoded, and a 64-bit one consumes two registers.
#[test]
fn the_bars_are_decoded_and_the_second_half_is_not_a_bar() {
    let mut config = FakeConfig::present();
    virtio_block_at(&mut config, 0, 1);
    let address = DeviceAddress {
        bus: 0,
        device: 1,
        function: 0,
    };
    // BAR0: 32-bit memory at 0xFE00_0000.
    config.set(address, REG_BAR0, 0xFE00_0000);
    // BAR1: 64-bit memory at 0x1_0000_0000 — low half, then high half.
    config.set(address, REG_BAR0 + 1, 0x0000_0004);
    config.set(address, REG_BAR0 + 2, 0x0000_0001);

    let device = Device::probe(&config, address).expect("probe");
    let bars = device.bars(&config);
    assert_eq!(bars[0].expect("bar 0").address, 0xFE00_0000);
    assert_eq!(bars[0].expect("bar 0").kind, BarKind::Memory);
    // BAR1 is the 64-bit one: slot 1 is it, and slot 2 is empty because
    // its upper half took the register.
    let bar1 = bars[1].expect("bar 1");
    assert!(bar1.is_64_bit);
    assert_eq!(bar1.address, 0x1_0000_0000);
    assert_eq!(bars[2], None, "the upper half is not a BAR of its own");
}

/// A capability list is walked, and the visit sees each entry's id.
#[test]
fn the_capability_list_is_walked() {
    let mut config = FakeConfig::present();
    virtio_block_at(&mut config, 0, 1);
    let address = DeviceAddress {
        bus: 0,
        device: 1,
        function: 0,
    };
    // The list starts at 0x40.  Entry 0x40: id 0x09 (vendor-specific),
    // next 0x50.  Entry 0x50: id 0x11, next 0.
    config.set(address, REG_CAPABILITY, 0x40);
    config.set(address, 0x40 >> 2, 0x50_09);
    config.set(address, 0x50 >> 2, 0x00_11);

    let device = Device::probe(&config, address).expect("probe");
    let mut ids = alloc::vec::Vec::new();
    let found = device.capabilities(&config, |id, _offset, _word| {
        ids.push(id);
        None::<()>
    });
    assert_eq!(ids, alloc::vec![0x09, 0x11]);
    assert!(found.is_none());
}
