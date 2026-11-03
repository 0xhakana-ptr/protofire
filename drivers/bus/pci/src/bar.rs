//! drivers/bus/pci/src/bar.rs
//!
//! A Base Address Register: the window a device asks the machine to give it.
//!
//! ## The two kinds
//!
//! Bit 0 says which: set means the register names a range of the machine's
//! **I/O space** (the ports x86_64 has), clear means it names memory.  The two
//! are not interchangeable — a memory BAR written into a port is a device
//! nothing can reach.
//!
//! ## Finding the size
//!
//! A BAR does not state its length.  The mechanism is to write all ones into
//! it, read it back, and count the low zero bits: the device clears the bits it
//! has no use for, so the ones that stay zero are the size.  The register's
//! original value has to be saved and restored, because the write is a request
//! the device takes seriously.
//!
//! That read-modify-write is why [`size`] needs a [`ConfigSpace`] rather
//! than being a field: the answer is not in the value, it is in what the device
//! does when asked.
//!
//! ## 64-bit BARs
//!
//! Three bits of the low dword say what kind it is: 0b000 for a 32-bit memory
//! BAR, 0b010 for a 64-bit one.  A 64-bit BAR takes *two* consecutive
//! registers, and the second one is not a BAR of its own — a driver that read
//! it as one would find a window at an address made of the upper half's bits.

use crate::config::ConfigSpace;
use crate::config::DeviceAddress;

/// Which kind of window a BAR names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarKind {
    /// A range of the machine's memory.
    Memory,
    /// A range of the machine's I/O space.
    Io,
}

/// One BAR, decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bar {
    /// Which register this BAR starts at, as a dword index.
    pub register: u8,
    /// Memory or I/O.
    pub kind: BarKind,
    /// Whether this BAR takes a second register for its upper half.
    pub is_64_bit: bool,
    /// The address the machine assigned.
    pub address: u64,
}

impl Bar {
    /// Decode the BAR at `register` from `value`.
    ///
    /// `value` is the register's contents after the machine has programmed it;
    /// the address is the value with the low four bits masked, because those
    /// are the type, not the address.
    pub const fn decode(register: u8, value: u32) -> Bar {
        if value & 1 != 0 {
            return Bar {
                register,
                kind: BarKind::Io,
                is_64_bit: false,
                // An I/O BAR's address is 32 bits with the low two masked: the
                // specification gives it two type bits, not four.
                address: (value & !0b11) as u64,
            };
        }
        let type_bits = (value >> 1) & 0b11;
        Bar {
            register,
            kind: BarKind::Memory,
            is_64_bit: type_bits == 0b10,
            address: (value & !0b1111) as u64,
        }
    }

    /// Whether the machine assigned this BAR any address at all.
    ///
    /// An unassigned BAR reads zero, and a window at address 0 is not one a
    /// driver can use: address 0 is where a null pointer points.
    pub const fn is_assigned(self) -> bool {
        self.address != 0
    }

    /// The number of registers this BAR occupies.
    pub const fn register_count(self) -> u8 {
        if self.is_64_bit { 2 } else { 1 }
    }
}

/// Decode a memory BAR at `register`, combining a 64-bit BAR's halves.
///
/// Returns the bar and the number of registers it consumed, so a caller walking
/// BARs knows where the next one starts.
pub fn decode(config: &dyn ConfigSpace, address: DeviceAddress, register: u8) -> (Bar, u8) {
    let value = config.read_dword(address, register);
    let mut bar = Bar::decode(register, value);
    if bar.is_64_bit {
        let upper = config.read_dword(address, register + 1);
        bar.address |= (upper as u64) << 32;
    }
    let count = bar.register_count();
    (bar, count)
}

/// The size of the window `register` names, by writing all ones and reading
/// back.
///
/// The register's original value is restored before this returns: the write is
/// a real request, and leaving the BAR holding all ones leaves the device
/// unmapped.
///
/// Returns `None` for a BAR the device says it does not have (all zero) and for
/// a size that is not a power of two, which would be a device answering a
/// question it does not understand.
pub fn size(config: &dyn ConfigSpace, address: DeviceAddress, register: u8) -> Option<u64> {
    let original = config.read_dword(address, register);
    if original == 0 {
        return None;
    }
    let is_64_bit = (original >> 1) & 0b11 == 0b10;
    let original_upper = if is_64_bit {
        Some(config.read_dword(address, register + 1))
    } else {
        None
    };

    config.write_dword(address, register, 0xFFFF_FFFF);
    let low = config.read_dword(address, register);
    let mask_low = low & !0b1111;

    let mut mask = mask_low as u64;
    if is_64_bit {
        config.write_dword(address, register + 1, 0xFFFF_FFFF);
        let high = config.read_dword(address, register + 1);
        mask |= (high as u64) << 32;
        config.write_dword(address, register + 1, original_upper.unwrap_or(0));
    }
    config.write_dword(address, register, original);

    if mask == 0 {
        return None;
    }
    // The size is one more than the mask: a 4 KiB window answers 0xFFFF_F000.
    let size = (!mask).wrapping_add(1);
    if !size.is_power_of_two() {
        return None;
    }
    Some(size)
}

#[cfg(test)]
mod tests {
    use super::Bar;
    use super::BarKind;

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

    /// A prefetchable memory BAR (type bits 0b01) is decoded as memory and as
    /// 32-bit, which is what it is.
    #[test]
    fn a_prefetchable_bar_is_still_32_bit_memory() {
        let bar = Bar::decode(4, 0xFE00_0008 | 0b1000);
        assert_eq!(bar.kind, BarKind::Memory);
        assert!(!bar.is_64_bit);
    }
}
