//! drivers/bus/pci/src/config/tests.rs
//!
//! The configuration space: the header fields, the capability walk, and the
//! registers above the 256-byte head.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

use crate::config::CONFIG_ADDRESS_PORT;
use crate::config::CONFIG_DATA_PORT;
use crate::config::ConfigSpace;
use crate::config::DeviceAddress;
use crate::config::EcamConfig;
use crate::config::NO_DEVICE;
use crate::config::VendorId;

/// The address word has the fields where the specification puts them.
///
/// A driver with a bit off by one reads a neighbouring function's
/// registers, which answers, so the mistake looks like a device with odd
/// values rather than a wrong address.
#[test]
fn the_configuration_address_is_the_specifications() {
    let address = DeviceAddress {
        bus: 0,
        device: 0x1F,
        function: 7,
    };
    assert_eq!(address.port_address(0), 0x8000_FF00);
    assert_eq!(address.port_address(1), 0x8000_FF04);

    let address = DeviceAddress {
        bus: 0x12,
        device: 0x03,
        function: 1,
    };
    assert_eq!(address.port_address(0), 0x8012_1900);
}

/// Bit 31 is set for every address: without it the ports answer for
/// nothing, and a scan would find no device on any bus.
#[test]
fn every_address_enables_the_mechanism() {
    let address = DeviceAddress {
        bus: 0,
        device: 0,
        function: 0,
    };
    assert_eq!(address.port_address(0) >> 31, 1);
}

/// The register field is a dword index, not a byte offset: register 1 is
/// the status/command word, four bytes past the identity.
#[test]
fn the_register_field_is_a_dword_index() {
    let address = DeviceAddress {
        bus: 0,
        device: 0,
        function: 0,
    };
    assert_eq!(address.port_address(1) & 0xFF, 4);
    assert_eq!(address.port_address(0x10) & 0xFF, 0x40);
}

/// The two ports are the ones the specification names.
#[test]
fn the_configuration_ports_are_the_specifications() {
    assert_eq!(CONFIG_ADDRESS_PORT, 0xCF8);
    assert_eq!(CONFIG_DATA_PORT, 0xCFC);
}

/// ECAM's address arithmetic puts each function on its own 4 KiB page.
///
/// Bus 0x12, device 0x03, function 1 is `(0x12 << 20) | (0x03 << 15) |
/// (1 << 12)`, the layout PCIe specifies, and the one a driver that copied
/// the port mechanism's bit positions would get wrong: the port address
/// packs the same fields into a 32-bit word, and ECAM adds them.
#[test]
fn ecam_puts_each_function_on_its_own_page() {
    let address = DeviceAddress {
        bus: 0x12,
        device: 0x03,
        function: 1,
    };
    assert_eq!(
        EcamConfig::offset(address),
        (0x12 << 20) | (0x03 << 15) | (1 << 12)
    );
    assert_eq!(
        EcamConfig::offset(address) % 4096,
        0,
        "a function's space starts on a page"
    );

    // Two functions of one device are one page apart.
    let sibling = DeviceAddress {
        bus: 0x12,
        device: 0x03,
        function: 0,
    };
    assert_eq!(
        EcamConfig::offset(address) - EcamConfig::offset(sibling),
        4096
    );
}

/// A register inside a function's page is the page's offset plus four bytes
/// per dword.
#[test]
fn ecam_registers_are_dword_strides_inside_the_page() {
    let address = DeviceAddress {
        bus: 0,
        device: 1,
        function: 0,
    };
    let base = EcamConfig::offset(address);
    assert_eq!(base, 1 << 15);

    // Register 0 is the identity, register 0x10 is 64 bytes in.  A PCIe
    // function has 4096 bytes, 1024 dwords, so the register field's whole
    // `u8` range is inside one function's page, and the window check is
    // about the *bus* number rather than the register.
    let first = EcamConfig::new(0x1000_0000, 0x1000_0000);
    assert!(first.holds(address, 0));
    assert!(first.holds(address, 0x10));
    assert!(
        first.holds(address, 0xFF),
        "255 dwords is 1020 bytes, inside the page"
    );

    // A window that stops before this device's page.
    let short = EcamConfig::new(0x1000_0000, 0x1000);
    assert!(
        !short.holds(address, 0),
        "device 1 is at 32 KiB, past the window"
    );
}

/// A bus outside the window answers all ones rather than reading past it.
///
/// With the MMU on, a read past the ECAM region is a fault at an address
/// nothing chose, which is a boot that dies in a scan rather than one that
/// reports "no device on that bus".
#[test]
fn a_bus_outside_the_window_answers_nothing() {
    // A one-bus window: 4096 bytes is not even one bus.
    let window = EcamConfig::new(0x1000_0000, 4096);
    let far = DeviceAddress {
        bus: 1,
        device: 0,
        function: 0,
    };
    assert!(!window.holds(far, 0));
    // Reading returns `NO_DEVICE` in both halves, which is what a scan
    // interprets as "nothing there".
    assert_eq!(window.read_dword(far, 0), u32::MAX);
}

/// A vendor of `0xFFFF` is "nothing answered", and that is the value a
/// machine returns for an address it cannot decode.
#[test]
fn no_device_is_all_ones() {
    assert!(
        !VendorId {
            vendor: NO_DEVICE,
            device: 0
        }
        .is_present()
    );
    assert!(
        VendorId {
            vendor: 0x1AF4,
            device: 0x1001
        }
        .is_present()
    );
}
