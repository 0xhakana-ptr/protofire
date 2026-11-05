//! drivers/bus/pci/src/enumerate/tests.rs
//!
//! The PCI enumerator's tests: a bus walked from a device tree of functions,
//! the BAR assignment it decides, and the devices it refuses.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

extern crate std;

use crate::bar::BarKind;
use crate::config::ConfigSpace;
use crate::config::DeviceAddress;
use crate::device::Device;
use crate::enumerate::assign_memory_bars;
use std::collections::BTreeMap;
use std::sync::Mutex;

/// A configuration space holding several functions, each with BARs that
/// answer a sizing write with a mask.
struct Fake {
    /// `(bus, device, function) -> [bar register values; 6]`
    bars: Mutex<BTreeMap<(u8, u8, u8), [u32; 6]>>,
    /// `(bus, device, function) -> each BAR's window size`
    sizes: BTreeMap<(u8, u8, u8), [u32; 6]>,
    /// `(bus, device, function) -> each BAR's hardwired type bits`
    ///
    /// A device's type bits are wires: they are present whatever the
    /// register holds, and they come back in a sizing mask.  A fake that
    /// derived them from the register would lose them the moment an address
    /// was written — and would then report every BAR as 32-bit.
    types: BTreeMap<(u8, u8, u8), [u32; 6]>,
    command: Mutex<BTreeMap<(u8, u8, u8), u32>>,
}

impl Fake {
    fn key(address: DeviceAddress) -> (u8, u8, u8) {
        (address.bus, address.device, address.function)
    }
}

impl ConfigSpace for Fake {
    fn read_dword(&self, address: DeviceAddress, register: u8) -> u32 {
        let key = Self::key(address);
        if register == crate::device::REG_COMMAND_STATUS {
            return *self.command.lock().unwrap().get(&key).unwrap_or(&0);
        }
        if (4..10).contains(&register) {
            let index = (register - 4) as usize;
            let held = self.bars.lock().unwrap()[&key][index];
            // Mid-probe: the device answers with its mask.  A register
            // that is not the low half of a BAR has no window of its own,
            // so it answers all ones — which for a 64-bit BAR's upper half
            // is exactly right, and for an absent register means "nothing
            // here".
            if held == 0xFFFF_FFFF {
                let size = self.sizes.get(&key).map_or(0, |sizes| sizes[index]);
                if size == 0 {
                    return 0xFFFF_FFFF;
                }
                // A real device keeps its hardwired type bits in the mask.
                let types = self.types.get(&key).map_or(0, |types| types[index]);
                return (!size.saturating_sub(1)) | types;
            }
            return held;
        }
        0
    }

    fn write_dword(&self, address: DeviceAddress, register: u8, value: u32) {
        let key = Self::key(address);
        if register == crate::device::REG_COMMAND_STATUS {
            self.command.lock().unwrap().insert(key, value);
            return;
        }
        if (4..10).contains(&register) {
            let index = (register - 4) as usize;
            self.bars.lock().unwrap().get_mut(&key).unwrap()[index] = value;
        }
    }
}

fn device(device_number: u8, vendor: u16) -> Device {
    Device {
        address: DeviceAddress {
            bus: 0,
            device: device_number,
            function: 0,
        },
        vendor,
        device: 0x1001,
        class: 0x01,
        subclass: 0x00,
        interface: 0x00,
        header_type: 0,
        multi_function: false,
    }
}

fn fake_with(bars: [u32; 6], sizes: [u32; 6]) -> Fake {
    let key = (0, 1, 0);
    // The type bits are the value's low four bits, captured before any
    // address is written — which is what a real device's wires do.
    let types = bars.map(|value| value & 0b1111);
    let mut map = BTreeMap::new();
    map.insert(key, bars);
    let mut size_map = BTreeMap::new();
    size_map.insert(key, sizes);
    let mut type_map = BTreeMap::new();
    type_map.insert(key, types);
    let mut command = BTreeMap::new();
    command.insert(key, crate::bar::COMMAND_MEMORY_SPACE);
    Fake {
        bars: Mutex::new(map),
        sizes: size_map,
        types: type_map,
        command: Mutex::new(command),
    }
}

/// A device with one unaddressed memory BAR gets an address in the window,
/// and memory decoding is turned on for it.
#[test]
fn an_unaddressed_bar_is_given_a_window() {
    // BAR0 = 4096 bytes, the rest absent.
    let config = fake_with([0, 0, 0, 0, 0, 0], [4096, 0, 0, 0, 0, 0]);
    let assignment = assign_memory_bars(&config, &[device(1, 0x1AF4)], 0x1000_0000, 0x1_0000);

    assert_eq!(assignment.assigned, 1);
    assert_eq!(assignment.refused, 0);
    assert_eq!(assignment.no_room, 0);

    let placed = config.read_dword(
        DeviceAddress {
            bus: 0,
            device: 1,
            function: 0,
        },
        4,
    );
    assert_eq!(placed, 0x1000_0000);

    let command = config.read_dword(
        DeviceAddress {
            bus: 0,
            device: 1,
            function: 0,
        },
        crate::device::REG_COMMAND_STATUS,
    );
    assert_ne!(command & crate::bar::COMMAND_MEMORY_SPACE, 0);
}

/// Each allocation is aligned to its own size, so two windows cannot
/// overlap.
///
/// A BAR compares the high bits of an address against its own window; a
/// window that was not aligned to its size would claim addresses inside its
/// neighbour.
#[test]
fn windows_do_not_overlap() {
    // BAR0 asks 4096, BAR1 asks 16384.
    let config = fake_with([0, 0, 0, 0, 0, 0], [4096, 16384, 0, 0, 0, 0]);
    let assignment = assign_memory_bars(&config, &[device(1, 0x1AF4)], 0x1000_0000, 0x10_0000);
    assert_eq!(assignment.assigned, 2);

    let first = crate::enumerate::bar_address(
        &config,
        DeviceAddress {
            bus: 0,
            device: 1,
            function: 0,
        },
        4,
    );
    let second = crate::enumerate::bar_address(
        &config,
        DeviceAddress {
            bus: 0,
            device: 1,
            function: 0,
        },
        5,
    );
    assert_eq!(first, 0x1000_0000);
    assert_eq!(second, 0x1000_4000, "16 KiB aligned, after the first");
    assert!(second % 16384 == 0);
    assert!(first + 4096 <= second);
}

/// A BAR with an address already is left alone.
///
/// A machine whose firmware assigned one has a driver that may be using it.
#[test]
fn an_assigned_bar_is_left_alone() {
    let config = fake_with([0x8000_0000, 0, 0, 0, 0, 0], [4096, 0, 0, 0, 0, 0]);
    let assignment = assign_memory_bars(&config, &[device(1, 0x1AF4)], 0x1000_0000, 0x1_0000);
    assert_eq!(assignment.already, 1);
    assert_eq!(assignment.assigned, 0);
    assert_eq!(
        config.read_dword(
            DeviceAddress {
                bus: 0,
                device: 1,
                function: 0
            },
            4
        ),
        0x8000_0000
    );
}

/// An I/O BAR is skipped: a device-tree machine has no port space.
#[test]
fn an_io_bar_is_skipped() {
    // Bit 0 set is an I/O BAR.
    let config = fake_with([0x0000_C001, 0, 0, 0, 0, 0], [256, 0, 0, 0, 0, 0]);
    let assignment = assign_memory_bars(&config, &[device(1, 0x1AF4)], 0x1000_0000, 0x1_0000);
    assert_eq!(assignment.assigned, 0);
    assert_eq!(assignment.no_room, 0, "not a failure, just not memory");
    assert_eq!(
        config.read_dword(
            DeviceAddress {
                bus: 0,
                device: 1,
                function: 0
            },
            4
        ),
        0x0000_C001
    );
}

/// A window too small for the BAR is reported rather than truncated.
#[test]
fn a_window_too_small_is_reported() {
    let config = fake_with([0, 0, 0, 0, 0, 0], [1 << 20, 0, 0, 0, 0, 0]);
    let assignment = assign_memory_bars(&config, &[device(1, 0x1AF4)], 0x1000_0000, 4096);
    assert_eq!(assignment.no_room, 1);
    assert_eq!(assignment.assigned, 0);
}

/// A 64-bit BAR takes an address above four gigabytes, and reads it back
/// from both halves.
#[test]
fn a_64_bit_bar_is_placed_above_four_gigabytes() {
    // Type bits 0b100 say a 64-bit memory BAR.  Register 5 is its upper
    // half, not a BAR of its own — so it has no size and answers all ones
    // to a probe, which is what makes the address 64 bits wide.
    let config = fake_with([0b100, 0, 0, 0, 0, 0], [4096, 0, 0, 0, 0, 0]);
    let assignment = assign_memory_bars(&config, &[device(1, 0x1AF4)], 0x40_0000_0000, 0x1000_0000);
    assert_eq!(assignment.assigned, 1);

    let placed = crate::enumerate::bar_address(
        &config,
        DeviceAddress {
            bus: 0,
            device: 1,
            function: 0,
        },
        4,
    );
    assert_eq!(placed, 0x40_0000_0000);
    assert!(placed > u32::MAX as u64, "the address needed both halves");
}

/// A device that answers no vendor is not probed.
#[test]
fn an_absent_function_is_not_probed() {
    let config = fake_with([0, 0, 0, 0, 0, 0], [4096, 0, 0, 0, 0, 0]);
    let absent = Device {
        address: DeviceAddress {
            bus: 0,
            device: 7,
            function: 0,
        },
        vendor: 0xFFFF,
        device: 0xFFFF,
        class: 0,
        subclass: 0,
        interface: 0,
        header_type: 0,
        multi_function: false,
    };
    let assignment = assign_memory_bars(&config, &[absent], 0x1000_0000, 0x1_0000);
    assert_eq!(assignment.assigned, 0);
    assert_eq!(assignment.already, 0);
    assert_eq!(assignment.refused, 0);
    assert_eq!(
        assignment.used_end, 0x1000_0000,
        "nothing was placed, so the cursor did not move"
    );
}

/// A window start is non-zero and aligned.
#[test]
fn a_window_start_is_aligned() {
    assert!(crate::enumerate::is_window_start(0x1000_0000));
    assert!(!crate::enumerate::is_window_start(0));
    assert!(!crate::enumerate::is_window_start(0x1000_0002));
}

/// The kind test is the same one the allocation uses.
#[test]
fn an_io_bar_is_identified_by_bit_zero() {
    let config = fake_with([0x0000_C001, 0, 0, 0, 0, 0], [256, 0, 0, 0, 0, 0]);
    let bar = crate::bar::Bar::decode(
        4,
        config.read_dword(
            DeviceAddress {
                bus: 0,
                device: 1,
                function: 0,
            },
            4,
        ),
    );
    assert_eq!(bar.kind, BarKind::Io);
}
