//! drivers/bus/pci/src/config.rs
//!
//! Reaching a device's configuration space, and the two ways a machine offers.
//!
//! ## The port mechanism (x86_64)
//!
//! Writing a 32-bit address to port `0xCF8` and reading the 32 bits back from
//! `0xCFC` is one configuration access.  It is an x86_64-only arrangement: the
//! two ports are part of the machine's I/O space, which aarch64 and riscv64 do
//! not have.
//!
//! ## ECAM (aarch64, riscv64, and PCIe generally)
//!
//! A region of memory the firmware describes, where a device's 4096 bytes sit
//! at a computed offset.  This crate has the arithmetic for it but no way to
//! find the region yet: that comes from the device tree, which this tree does
//! not parse.
//!
//! ## Why the trait exists
//!
//! Both mechanisms answer the same three questions — read a dword, write a
//! dword, and say how many bytes there are — and the enumeration above them is
//! identical.  A trait is what lets that enumeration be written once and tested
//! on a host.

/// The I/O port a configuration address is written to.
pub const CONFIG_ADDRESS_PORT: u16 = 0xCF8;
/// The I/O port the selected dword is read from and written to.
pub const CONFIG_DATA_PORT: u16 = 0xCFC;

/// A device's identity, as the first two dwords of its configuration space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VendorId {
    pub vendor: u16,
    pub device: u16,
}

/// `0xFFFF` in the vendor field: no device answered.
///
/// A machine returns all ones from a configuration address nothing decodes,
/// which is also what a host's port arm returns — so a scan on a host finds no
/// devices for the same reason a real bus with nothing there does.
pub const NO_DEVICE: u16 = 0xFFFF;

impl VendorId {
    /// Whether a device answered at this address.
    pub const fn is_present(self) -> bool {
        self.vendor != NO_DEVICE
    }
}

/// Reaching a device's configuration space.
///
/// The three operations a mechanism must provide.  Everything the bus does —
/// enumeration, capability walks, BAR decoding — is written against this and
/// knows nothing about ports or ECAM.
pub trait ConfigSpace: Send + Sync {
    /// Read the 32-bit register at `register` (a dword index, 0..64).
    fn read_dword(&self, address: DeviceAddress, register: u8) -> u32;

    /// Write the 32-bit register at `register`.
    fn write_dword(&self, address: DeviceAddress, register: u8, value: u32);

    /// How many bytes of configuration space the device has.
    ///
    /// 256 for a classic PCI device, 4096 for PCIe.  A capability structure
    /// may name an offset past 256, and a driver that assumed 256 would read
    /// the wrong bytes rather than fail.
    fn space_size(&self, address: DeviceAddress) -> usize {
        let _ = address;
        256
    }
}

/// Where a device is on the bus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceAddress {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
}

impl DeviceAddress {
    /// Build the 32-bit configuration address the port mechanism takes.
    ///
    /// The layout is the specification's; see this crate's header for the bit
    /// positions.  `register` is a dword index, so 0 is the vendor/device word
    /// and 1 is the status/command word.
    pub const fn port_address(self, register: u8) -> u32 {
        // Bit 31 enables the mechanism; without it the ports answer for
        // nothing.
        (1 << 31)
            | ((self.bus as u32) << 16)
            | ((self.device as u32) << 11)
            | ((self.function as u32) << 8)
            | ((register as u32) << 2)
    }
}

/// The `0xCF8`/`0xCFC` mechanism, which is x86_64's.
///
/// The port functions come from `arch`, not from this crate: `in` and `out` are
/// instructions, and the machine that has them owns the reason.  On a machine
/// without a port space the `arch` arm returns all ones, so a scan there finds
/// nothing and falls through to whatever mechanism that machine does have.
pub struct PortConfig;

impl PortConfig {
    /// The mechanism, as a value.
    pub const fn new() -> Self {
        Self
    }
}

impl Default for PortConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigSpace for PortConfig {
    fn read_dword(&self, address: DeviceAddress, register: u8) -> u32 {
        arch::port::outl(CONFIG_ADDRESS_PORT, address.port_address(register));
        arch::port::inl(CONFIG_DATA_PORT)
    }

    fn write_dword(&self, address: DeviceAddress, register: u8, value: u32) {
        arch::port::outl(CONFIG_ADDRESS_PORT, address.port_address(register));
        arch::port::outl(CONFIG_DATA_PORT, value);
    }
}

/// The memory-mapped configuration space PCIe uses: ECAM.
///
/// ## The arithmetic
///
/// A device's 4096 bytes of configuration space sit at
///
/// ```text
/// base + (bus << 20) | (device << 15) | (function << 12)
/// ```
///
/// which is one 4 KiB page per function.  Reading a dword is a volatile load at
/// that address plus `register * 4`; there is no address port and no data port,
/// because the address is in the address.
///
/// ## Why this exists at all
///
/// The port mechanism at `0xCF8`/`0xCFC` is x86_64's, and only x86_64's.  A
/// device-tree machine gets its configuration space as a memory region the tree
/// names, and this is what reads it.  Everything above — enumeration,
/// capability walks, BAR decoding — is written against [`ConfigSpace`] and does
/// not know which mechanism answered.
///
/// ## Why the base is a parameter
///
/// Because it is a device tree's answer, not a constant of the format.  A board
/// puts its ECAM where it likes and the tree says where; a caller that supplied
/// a constant would be naming a machine, which is the split this tree keeps.
pub struct EcamConfig {
    /// Where the machine's ECAM window starts.
    base: usize,
    /// How far the window runs, in bytes.
    length: usize,
}

impl EcamConfig {
    /// An ECAM window at `base`, `length` bytes long.
    ///
    /// The length is the region the device tree declared.  Every read is
    /// checked against it: a bus number beyond the window is a read of whatever
    /// memory follows, and on a machine with the MMU on that is a fault at an
    /// address nothing chose.
    pub const fn new(base: usize, length: usize) -> EcamConfig {
        EcamConfig { base, length }
    }

    /// The offset of a function's configuration space within the window.
    const fn offset(address: DeviceAddress) -> usize {
        ((address.bus as usize) << 20)
            | ((address.device as usize) << 15)
            | ((address.function as usize) << 12)
    }

    /// Whether `address`'s space is inside this window.
    fn holds(&self, address: DeviceAddress, register: u8) -> bool {
        let offset = Self::offset(address).saturating_add((register as usize) * 4);
        offset + 4 <= self.length
    }
}

impl ConfigSpace for EcamConfig {
    fn read_dword(&self, address: DeviceAddress, register: u8) -> u32 {
        if !self.holds(address, register) {
            // The window does not reach this bus.  All ones is what a device
            // that is not there answers, so a scan finds nothing rather than
            // faulting on memory past the window.
            return u32::MAX;
        }
        let at = self.base + Self::offset(address) + (register as usize) * 4;
        // SAFETY: `at` is inside the window the device tree declared, which is
        // the machine's configuration space and nothing else.  A volatile read
        // is what ECAM needs: the device answers the load, and the compiler
        // must not fold two reads of a register it may have changed.
        unsafe { core::ptr::read_volatile(at as *const u32) }
    }

    fn write_dword(&self, address: DeviceAddress, register: u8, value: u32) {
        if !self.holds(address, register) {
            return;
        }
        let at = self.base + Self::offset(address) + (register as usize) * 4;
        // SAFETY: as `read_dword`.
        unsafe { core::ptr::write_volatile(at as *mut u32, value) };
    }

    /// A PCIe function has 4096 bytes, which is the whole page ECAM gives it.
    fn space_size(&self, _address: DeviceAddress) -> usize {
        4096
    }
}

#[cfg(test)]
mod tests {
    use super::CONFIG_ADDRESS_PORT;
    use super::CONFIG_DATA_PORT;
    use super::ConfigSpace;
    use super::DeviceAddress;
    use super::EcamConfig;
    use super::NO_DEVICE;
    use super::VendorId;

    /// The address word has the fields where the specification puts them.
    ///
    /// A driver with a bit off by one reads a neighbouring function's
    /// registers, which answers — so the mistake looks like a device with odd
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
    /// (1 << 12)` — the layout PCIe specifies, and the one a driver that copied
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
        // function has 4096 bytes — 1024 dwords — so the register field's whole
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
    /// nothing chose — which is a boot that dies in a scan rather than one that
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
}
