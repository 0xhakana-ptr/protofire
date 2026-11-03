//! drivers/bus/pci/src/device.rs
//!
//! One device on the bus: what it says it is, and how to walk its capabilities.
//!
//! ## The capability list
//!
//! A device's configuration space has a linked list of capability structures,
//! each naming a feature it has.  A modern virtio device publishes four: the
//! common configuration, the notification area, the device-specific
//! configuration, and shared memory.  Each structure says which BAR and which
//! offset inside it, because a device places its registers where it likes.
//!
//! Walking it is `capabilities()` here, and the walk is a loop over a `u8`
//! chain that a malformed device could make circular — so it is bounded.
//!
//! ## What enumeration finds
//!
//! A bus has up to 32 devices, each with up to 8 functions.  A function's
//! header type says whether it is a multi-function device: reading functions
//! 1..7 of a single-function device returns the first one's registers again on
//! some chipsets, which a scan that did not check would report as eight
//! identical devices.

use crate::bar::Bar;
use crate::config::ConfigSpace;
use crate::config::DeviceAddress;
use crate::config::NO_DEVICE;

/// The configuration register holding vendor (low half) and device (high).
pub const REG_VENDOR_DEVICE: u8 = 0;
/// The register holding command (low) and status (high).
pub const REG_COMMAND_STATUS: u8 = 1;
/// The register holding the class code and the revision.
pub const REG_CLASS_REVISION: u8 = 2;
/// The register holding the header type, among other things.
pub const REG_HEADER: u8 = 3;
/// The first capability-list register, for a device with `CAP_LIST` set.
pub const REG_CAPABILITY: u8 = 13;
/// The first BAR register.
pub const REG_BAR0: u8 = 4;

/// The status bit that says a capability list exists.
pub const STATUS_CAPABILITY_LIST: u16 = 1 << 4;

/// The longest capability list this crate walks.
///
/// A `u8` chain has at most 256 entries and a device that made it circular
/// would loop forever; the bound is what turns that into a stop.  48 is more
/// than any real device publishes.
const MAX_CAPABILITIES: usize = 48;

/// One device, as the bus sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Device {
    pub address: DeviceAddress,
    pub vendor: u16,
    pub device: u16,
    /// The class code's high byte: 0x01 is storage, 0x02 is network.
    pub class: u8,
    /// The class code's middle byte: 0x06 class 0x01 is an AHCI controller.
    pub subclass: u8,
    /// The class code's low byte.
    pub interface: u8,
    /// The header type's low seven bits; 0 is a normal device, 1 a bridge.
    pub header_type: u8,
    /// Whether the device is multi-function.
    pub multi_function: bool,
}

impl Device {
    /// A function that is not there.
    ///
    /// A caller that keeps a fixed list of functions — the enumeration pass
    /// does, because it runs before anything has an allocator — fills it with
    /// this and then the devices it found.  The vendor is `0xFFFF`, which is
    /// what the bus answers for an address nothing decodes, so a pass that
    /// walked the unfilled tail finds nothing to size rather than probing
    /// address zero.
    pub const ABSENT: Device = Device {
        address: DeviceAddress {
            bus: 0,
            device: 0,
            function: 0,
        },
        vendor: crate::config::NO_DEVICE,
        device: crate::config::NO_DEVICE,
        class: 0,
        subclass: 0,
        interface: 0,
        header_type: 0,
        multi_function: false,
    };

    /// Read a device's identity and class from `config`.
    pub fn probe(config: &dyn ConfigSpace, address: DeviceAddress) -> Option<Device> {
        let identity = config.read_dword(address, REG_VENDOR_DEVICE);
        let vendor = (identity & 0xFFFF) as u16;
        if vendor == NO_DEVICE {
            return None;
        }
        let device = (identity >> 16) as u16;

        let class_revision = config.read_dword(address, REG_CLASS_REVISION);
        let header = config.read_dword(address, REG_HEADER);

        Some(Device {
            address,
            vendor,
            device,
            class: (class_revision >> 24) as u8,
            subclass: (class_revision >> 16) as u8,
            interface: (class_revision >> 8) as u8,
            header_type: ((header >> 16) & 0x7F) as u8,
            multi_function: (header >> 16) & 0x80 != 0,
        })
    }

    /// Whether this is a PCI-to-PCI bridge, which a scan does not follow into.
    ///
    /// A bridge's secondary bus is another bus, and enumerating it needs the
    /// bridge's bus-number registers.  Nothing on this tree's machines is
    /// behind a bridge, so the scan reports a bridge and does not descend —
    /// which is the honest state rather than a half-walk.
    pub fn is_bridge(self) -> bool {
        self.header_type == 1
    }

    /// The device's BARs, decoded.
    ///
    /// A 64-bit BAR consumes two registers, so the walk skips the register its
    /// upper half occupies.  A driver that read the upper half as its own BAR
    /// would find a window at an address made of the wrong bits.
    pub fn bars(self, config: &dyn ConfigSpace) -> [Option<Bar>; 6] {
        let mut bars = [None; 6];
        let mut slot = 0;
        let mut register = REG_BAR0;
        while slot < 6 && register < REG_BAR0 + 6 {
            let (bar, count) = crate::bar::decode(config, self.address, register);
            if bar.is_assigned() {
                bars[slot] = Some(bar);
            }
            // A 64-bit BAR's second register is its upper half, not a BAR.  It
            // takes a slot so the array's indices still match the registers,
            // and that slot stays empty because there is nothing there.
            slot += count as usize;
            register += count;
        }
        bars
    }

    /// The address of the BAR whose **register** is `number`.
    ///
    /// `number` is the PCI capability's `bar` field, which counts BAR
    /// registers: 0 is the register at offset `0x10`, 4 at `0x20`.  That is not
    /// the slot [`Self::bars`] uses — a 64-bit BAR occupies one register pair
    /// and therefore one slot but two register numbers — so a caller that
    /// indexed the slot array with a register number reaches the wrong window.
    ///
    /// ## The defect this exists for
    ///
    /// A virtio capability naming BAR 4 on a device whose BARs are `0`..`3` was
    /// read as slot 4, which holds nothing, and the transport reported "bad
    /// capability" for a device that was offering exactly what it asked for.
    pub fn bar_register(self, config: &dyn ConfigSpace, number: u8) -> Option<Bar> {
        if number >= 6 {
            return None;
        }
        let (bar, _) = crate::bar::decode(config, self.address, REG_BAR0 + number);
        bar.is_assigned().then_some(bar)
    }

    /// Walk the capability list, calling `visit` for each entry.
    ///
    /// `visit` receives the capability's id, the offset of its structure, and
    /// the 32-bit word at that offset — which is where a virtio capability
    /// keeps its type, BAR and offset.  Returning `Some` stops the walk.
    pub fn capabilities<T>(
        self,
        config: &dyn ConfigSpace,
        mut visit: impl FnMut(u8, u8, u32) -> Option<T>,
    ) -> Option<T> {
        let command_status = config.read_dword(self.address, REG_COMMAND_STATUS);
        if (command_status >> 16) as u16 & STATUS_CAPABILITY_LIST == 0 {
            return None;
        }

        let mut pointer = (config.read_dword(self.address, REG_CAPABILITY) & 0xFF) as u8;
        let mut walked = 0;
        while pointer != 0 && walked < MAX_CAPABILITIES {
            // A capability structure's first two bytes are its id and the
            // offset of the next one, and both live in the dword at the
            // structure's own offset.  The offset is a dword index only if it
            // happens to be aligned, so it is read bytewise from the word the
            // aligned read returns.
            let aligned = pointer & !0b11;
            let word = config.read_dword(self.address, aligned >> 2);
            let shift = (pointer & 0b11) as u32 * 8;

            // The two bytes are `id` and `next` at `pointer`, which may start
            // at any of the four byte offsets inside the dword.  Reading them
            // as one `u64` is what makes the `next` byte at `shift = 24`
            // reachable: `word >> (24 + 8)` is a shift of 32 on a `u32`, which
            // is undefined — and this boot panicked with "attempt to shift
            // right with overflow" on exactly that, because a virtio capability
            // structure happened to sit at offset 0x1C.
            //
            // Widening to `u64` puts the next dword's low byte where the shift
            // expects it.  When the structure's two bytes straddle the dword
            // boundary the second byte is then the *next* dword's first, which
            // is what the format means: capability structures are contiguous.
            let wide = u64::from(word)
                | (u64::from(config.read_dword(self.address, (aligned >> 2) + 1)) << 32);
            let id = ((wide >> shift) & 0xFF) as u8;
            let next = ((wide >> (shift + 8)) & 0xFF) as u8;

            if let Some(found) = visit(id, pointer, word) {
                return Some(found);
            }
            pointer = next;
            walked += 1;
        }
        None
    }
}

/// What a scan found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scan {
    /// The buses walked.
    pub buses: u8,
    /// The functions that answered.
    pub devices: usize,
}

/// Walk every bus, device and function, calling `visit` for each that answers.
///
/// `visit` returning `Some` stops the scan and yields that value, which is what
/// a caller looking for one device wants: the first match, not every match.
/// Every function on `bus_count` buses.
///
/// The enumeration pass needs the whole set: a BAR is allocated from one window
/// shared by every device, so a pass that only saw the devices a caller asked
/// about would place two devices on one address.
///
/// `out` is written in place and its length returned, so a caller on a machine
/// with no allocator can size the list itself.  A bus with more functions than
/// the slice holds reports the count it would have written.
pub fn scan_all(config: &dyn ConfigSpace, bus_count: u8, out: &mut [Device]) -> usize {
    let mut found = 0;
    for bus in 0..bus_count {
        for device in 0..32u8 {
            for function in 0..8u8 {
                if function > 0 {
                    let check = DeviceAddress {
                        bus,
                        device,
                        function: 0,
                    };
                    let header = config.read_dword(check, REG_HEADER);
                    if (header >> 16) & 0x80 == 0 {
                        break;
                    }
                }
                let address = DeviceAddress {
                    bus,
                    device,
                    function,
                };
                if let Some(probed) = Device::probe(config, address) {
                    if let Some(slot) = out.get_mut(found) {
                        *slot = probed;
                    }
                    found += 1;
                } else if function == 0 {
                    // Nothing at function 0 means nothing at this slot at all.
                    break;
                }
            }
        }
    }
    found
}

pub fn scan<T>(
    config: &dyn ConfigSpace,
    bus_count: u8,
    mut visit: impl FnMut(Device) -> Option<T>,
) -> (Scan, Option<T>) {
    let mut found = None;
    let mut devices = 0;
    'outer: for bus in 0..bus_count {
        for device in 0..32u8 {
            for function in 0..8u8 {
                // Functions past 0 exist only on a multi-function device.  A
                // single-function device answers for them on some chipsets,
                // which a scan that did not check would report as eight of it.
                if function > 0 {
                    let check = DeviceAddress {
                        bus,
                        device,
                        function: 0,
                    };
                    let header = config.read_dword(check, REG_HEADER);
                    if (header >> 16) & 0x80 == 0 {
                        break;
                    }
                }
                let address = DeviceAddress {
                    bus,
                    device,
                    function,
                };
                let Some(probed) = Device::probe(config, address) else {
                    if function == 0 {
                        break;
                    }
                    continue;
                };
                devices += 1;
                if let Some(value) = visit(probed) {
                    found = Some(value);
                    break 'outer;
                }
            }
        }
    }
    (
        Scan {
            buses: bus_count,
            devices,
        },
        found,
    )
}

#[cfg(test)]
mod tests {
    use super::Device;
    use super::DeviceAddress;
    use super::REG_BAR0;
    use super::REG_CAPABILITY;
    use super::REG_CLASS_REVISION;
    use super::REG_COMMAND_STATUS;
    use super::REG_HEADER;
    use super::REG_VENDOR_DEVICE;
    use super::STATUS_CAPABILITY_LIST;
    use super::scan;
    use crate::bar::BarKind;
    use crate::config::ConfigSpace;
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
}
