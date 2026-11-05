//! drivers/bus/pci/src/bar/tests.rs
//!
//! BAR descriptors: the size a BAR asks for, the address assignment, and the
//! alignment it must respect.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

extern crate std;

use crate::bar::Bar;
use crate::bar::BarKind;
use crate::bar::COMMAND_MEMORY_SPACE;
use crate::bar::assign;
use crate::bar::size;
use crate::config::ConfigSpace;
use crate::config::DeviceAddress;

/// A configuration space with one BAR, modelled the way a device behaves.
///
/// Writing all ones returns the size mask, because that is the mechanism a
/// probe is *defined* against — a fake that stored the write would answer
/// `0xFFFF_FFFF` and call every BAR nonexistent.  A fake that only stored
/// values would let a broken probe pass.
struct FakeBar {
    bar: std::sync::Mutex<u32>,
    upper: std::sync::Mutex<u32>,
    command: std::sync::Mutex<u32>,
    /// The size mask this device answers a sizing write with.
    ///
    /// A real device clears the bits below its window size; the fake does
    /// the same, because a fake that merely stored the write would answer
    /// `0xFFFF_FFFF` and call every BAR nonexistent — and a probe bug would
    /// pass.
    mask: u32,
}

const ADDRESS: DeviceAddress = DeviceAddress {
    bus: 0,
    device: 1,
    function: 0,
};

impl ConfigSpace for FakeBar {
    fn read_dword(&self, _address: DeviceAddress, register: u8) -> u32 {
        match register {
            // A register holding all ones is mid-probe: the device answers
            // with the mask it derived from its window size.
            4 if *self.bar.lock().unwrap() == 0xFFFF_FFFF => self.mask,
            4 => *self.bar.lock().unwrap(),
            5 if *self.upper.lock().unwrap() == 0xFFFF_FFFF => self.mask,
            5 => *self.upper.lock().unwrap(),
            crate::device::REG_COMMAND_STATUS => *self.command.lock().unwrap(),
            _ => 0,
        }
    }

    fn write_dword(&self, _address: DeviceAddress, register: u8, value: u32) {
        match register {
            // A sizing write is answered with the mask, not stored.
            4 if value == 0xFFFF_FFFF => {
                *self.bar.lock().unwrap() = value;
            }
            4 => *self.bar.lock().unwrap() = value,
            5 if value == 0xFFFF_FFFF => {}
            5 => *self.upper.lock().unwrap() = value,
            crate::device::REG_COMMAND_STATUS => *self.command.lock().unwrap() = value,
            _ => {}
        }
    }
}

impl FakeBar {
    /// A device whose BAR at register 4 asks for `size` bytes.
    ///
    /// `base` is what the register holds; zero is unaddressed, which is the
    /// state before anything has programmed it.  The type bits come from
    /// `base`, so `0b100` there makes it a 64-bit memory BAR.
    fn new(base: u32, size: u32) -> FakeBar {
        // A size of zero is "no window", and its mask is all ones — which
        // is what a register with no BAR behind it answers, and what
        // `size` reports as `None`.  `saturating_sub` rather than `-` so
        // the test helper does not panic on the input it is given.
        let mask = !size.saturating_sub(1);
        FakeBar {
            bar: std::sync::Mutex::new(base),
            upper: std::sync::Mutex::new(0),
            command: std::sync::Mutex::new(COMMAND_MEMORY_SPACE),
            mask,
        }
    }
}

/// A **failing** fake: one that answers all ones to every write, which is
/// what a device with no BAR there does.
struct NoBar;

impl ConfigSpace for NoBar {
    fn read_dword(&self, _address: DeviceAddress, _register: u8) -> u32 {
        0xFFFF_FFFF
    }
    fn write_dword(&self, _address: DeviceAddress, _register: u8, _value: u32) {}
}

/// A memory BAR's address is the value with the type bits masked, and bit
/// 0 clear says memory.
#[test]
fn a_memory_bar_is_decoded_from_its_low_bits() {
    let bar = Bar::decode(4, 0xFE00_0008);
    assert_eq!(bar.kind, BarKind::Memory);
    assert!(!bar.is_64_bit);
    assert_eq!(bar.address, 0xFE00_0000);
    assert_eq!(bar.register, 4);
}

/// A 64-bit BAR's type bits are 0b10 and it takes two registers: the next
/// register is its upper half, not a BAR.
#[test]
fn a_64_bit_bar_takes_two_registers() {
    let bar = Bar::decode(4, 0xFE00_0004);
    assert_eq!(bar.kind, BarKind::Memory);
    assert!(bar.is_64_bit);
    assert_eq!(bar.register_count(), 2);
}

/// An I/O BAR has bit 0 set and its address is masked two bits, not four:
/// the specification gives it two type bits.
#[test]
fn an_io_bar_has_two_type_bits() {
    let bar = Bar::decode(4, 0x0000_C001);
    assert_eq!(bar.kind, BarKind::Io);
    assert_eq!(bar.address, 0xC000);
    assert!(!bar.is_64_bit);
}

/// A BAR the machine did not assign reads zero, and zero is not a window.
#[test]
fn an_unassigned_bar_is_not_a_window() {
    assert!(!Bar::decode(4, 0).is_assigned());
    assert!(Bar::decode(4, 0x1000_0000).is_assigned());
}

/// A 4 KiB window answers `0xFFFF_F000` and sizes as 4096.
#[test]
fn a_sized_bar_answers_its_mask() {
    let config = FakeBar::new(0, 4096);
    assert_eq!(size(&config, ADDRESS, 4), Some(4096));
}

/// **An unaddressed BAR still has a size.**
///
/// This is the bug the previous version of `size` carried, and it is the
/// state every device-tree machine is in before anything assigns an
/// address: the register reads zero, and a probe that treated zero as "no
/// BAR here" reported no device at all.  QEMU's `virt` brings all of them
/// up that way.
#[test]
fn an_unaddressed_bar_still_sizes() {
    let config = FakeBar::new(0, 4096);
    let found = size(&config, ADDRESS, 4);
    assert_eq!(found, Some(4096), "zero is unaddressed, not absent");
}

/// A register that answers all ones has no BAR, and that is different from
/// one that answers zero.
#[test]
fn a_register_that_answers_all_ones_has_no_bar() {
    assert_eq!(size(&NoBar, ADDRESS, 4), None);
}

/// The probe restores the register it wrote.
///
/// A probe that left all ones behind would leave the device unmapped, and
/// the caller could not tell that from a device that was already broken.
#[test]
fn the_probe_restores_the_register() {
    let config = FakeBar::new(0x1000_0000, 4096);
    let _ = size(&config, ADDRESS, 4);
    assert_eq!(config.read_dword(ADDRESS, 4), 0x1000_0000);
}

/// Memory decoding is off during the probe and back on afterwards.
///
/// While the BAR holds all ones the device would decode a window at an
/// address nothing chose, and a device responding there conflicts with
/// whatever is really at that address.
#[test]
fn decoding_is_off_while_the_bar_holds_all_ones() {
    struct Watching {
        bar: std::sync::Mutex<u32>,
        command: std::sync::Mutex<u32>,
        saw_decoding_off: std::sync::Mutex<bool>,
    }

    /// A 4 KiB window's mask, which this device answers with.
    const MASK: u32 = 0xFFFF_F000;

    impl ConfigSpace for Watching {
        fn read_dword(&self, _address: DeviceAddress, register: u8) -> u32 {
            match register {
                4 if *self.bar.lock().unwrap() == 0xFFFF_FFFF => MASK,
                4 => *self.bar.lock().unwrap(),
                crate::device::REG_COMMAND_STATUS => *self.command.lock().unwrap(),
                _ => 0,
            }
        }

        fn write_dword(&self, _address: DeviceAddress, register: u8, value: u32) {
            match register {
                // Writing all ones is the probe's request; record whether
                // decoding was already off when it arrived.
                4 if value == 0xFFFF_FFFF => {
                    let command = *self.command.lock().unwrap();
                    if command & COMMAND_MEMORY_SPACE == 0 {
                        *self.saw_decoding_off.lock().unwrap() = true;
                    }
                    *self.bar.lock().unwrap() = value;
                }
                4 => *self.bar.lock().unwrap() = value,
                crate::device::REG_COMMAND_STATUS => *self.command.lock().unwrap() = value,
                _ => {}
            }
        }
    }

    let config = Watching {
        bar: std::sync::Mutex::new(0),
        command: std::sync::Mutex::new(COMMAND_MEMORY_SPACE),
        saw_decoding_off: std::sync::Mutex::new(false),
    };
    assert_eq!(size(&config, ADDRESS, 4), Some(4096));
    assert!(
        *config.saw_decoding_off.lock().unwrap(),
        "decoding must be off before the all-ones write, not after"
    );
    assert_ne!(
        config.read_dword(ADDRESS, crate::device::REG_COMMAND_STATUS) & COMMAND_MEMORY_SPACE,
        0,
        "and back on afterwards"
    );
}

/// An address is written to both halves of a 64-bit BAR and read back.
#[test]
fn a_64_bit_bar_takes_an_address_above_four_gigabytes() {
    // 0b100 says a 64-bit memory BAR.
    let config = FakeBar::new(0b100, 1 << 14);
    assert!(assign(&config, ADDRESS, 4, 0x40_1000_0000));
    assert_eq!(config.read_dword(ADDRESS, 4) & 0xFFFF_FFF0, 0x1000_0000);
    assert_eq!(config.read_dword(ADDRESS, 5), 0x40);
}

/// A 32-bit BAR refuses an address it cannot hold, rather than programming
/// the low half of it and leaving the device at the wrong address.
#[test]
fn a_32_bit_bar_refuses_an_address_it_cannot_hold() {
    let config = FakeBar::new(0, 4096);
    assert!(!assign(&config, ADDRESS, 4, 0x1_0000_0000));
    assert_eq!(
        config.read_dword(ADDRESS, 4),
        0,
        "and it did not write a truncated address"
    );
}

/// The command register's two bits are set and the status half is left
/// alone.
#[test]
fn enabling_a_function_sets_memory_and_bus_master() {
    let config = FakeBar::new(0, 4096);
    crate::bar::enable_memory_and_bus_master(&config, ADDRESS);
    let value = config.read_dword(ADDRESS, crate::device::REG_COMMAND_STATUS);
    assert_ne!(value & crate::bar::COMMAND_MEMORY_SPACE, 0);
    assert_ne!(value & crate::bar::COMMAND_BUS_MASTER, 0);
}

/// A prefetchable memory BAR (type bits 0b01) is decoded as memory and as
/// 32-bit, which is what it is.
#[test]
fn a_prefetchable_bar_is_still_32_bit_memory() {
    let bar = Bar::decode(4, 0xFE00_0008 | 0b1000);
    assert_eq!(bar.kind, BarKind::Memory);
    assert!(!bar.is_64_bit);
}
