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
mod tests;
