//! drivers/bus/pci/src/bar/mod.rs
//!
//! A Base Address Register: the window a device asks the machine to give it.
//!
//! ## The two kinds
//!
//! Bit 0 says which: set means the register names a range of the machine's
//! **I/O space** (the ports x86_64 has), clear means it names memory.  The two
//! are not interchangeable, a memory BAR written into a port is a device
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
//! registers, and the second one is not a BAR of its own, a driver that read
//! it as one would find a window at an address made of the upper half's bits.

use crate::config::ConfigSpace;
use crate::config::DeviceAddress;
use crate::device::REG_COMMAND_STATUS;

/// Command register bit 1: the function responds to memory accesses.
pub const COMMAND_MEMORY_SPACE: u32 = 1 << 1;
/// Command register bit 2: the function may master the bus.
pub const COMMAND_BUS_MASTER: u32 = 1 << 2;

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
/// The version of this function that returned early when the register read zero
/// was wrong, and it was wrong in exactly the state a bare-metal boot is in.
/// **An unaddressed BAR reads zero.**  On a machine with firmware, a PC, or a
/// UEFI board, that is unusual; on this tree's device-tree machines it is the
/// normal state before anything assigns an address, so the early return turned
/// "there is a device here asking for a window" into "there is nothing here".
/// The boot then fell back to its in-memory image and said the disk was absent.
///
/// The current value cannot answer whether a BAR exists.  Only the device can,
/// and the way to ask is to write all ones and see what it clears.
///
/// Writing all ones into a live BAR is a request the device acts on: until the
/// restore, it decodes a window at an address nothing chose.  A device that
/// responds to a bus cycle there conflicts with whatever is really at that
/// address.  On a single-master machine with no other traffic this is a window
/// of a few instructions and shipping code has done it for decades; turning the
/// command register's memory bit off for the duration costs one read and one
/// write and removes the conflict.
///
/// ## The restore
///
/// Every path restores the register, including the failure paths.  A probe that
/// left a BAR holding all ones would have left the device unmapped, and the
/// caller would see a device it could not tell from a broken one.
pub fn probe(config: &dyn ConfigSpace, address: DeviceAddress, register: u8) -> Option<BarProbe> {
    let original = config.read_dword(address, register);
    let original_upper = config.read_dword(address, register + 1);

    let command = config.read_dword(address, REG_COMMAND_STATUS) & 0xFFFF;
    let decoding = command & COMMAND_MEMORY_SPACE != 0;
    if decoding {
        let quiet = command & !COMMAND_MEMORY_SPACE;
        let status = config.read_dword(address, REG_COMMAND_STATUS) & 0xFFFF_0000;
        config.write_dword(address, REG_COMMAND_STATUS, status | quiet);
    }

    config.write_dword(address, register, 0xFFFF_FFFF);
    let low = config.read_dword(address, register);

    let restore = |config: &dyn ConfigSpace| {
        config.write_dword(address, register, original);
        config.write_dword(address, register + 1, original_upper);
        if decoding {
            let status = config.read_dword(address, REG_COMMAND_STATUS) & 0xFFFF_0000;
            config.write_dword(address, REG_COMMAND_STATUS, status | command);
        }
    };

    // A register that answers all ones, or that answers zero, has nothing
    // behind it.
    //
    // Both answers mean the same thing and they arrive from different
    // implementations: a function with no BAR there returns the write
    // unchanged (`0xFFFF_FFFF`), and one whose register is hardwired to zero
    // returns zero.  The zero case is the one that is easy to forget, and
    // forgetting it is not a silent omission: with `low == 0` the 64-bit mask
    // below becomes `0xFFFF_FFFF_0000_0000`, whose complement plus one is four
    // gigabytes, a power of two, so the size check passes and the allocator
    // reports "no room" for a BAR that does not exist.
    //
    // The check is on the *low* dword before any widening, because the widening
    // would make an absent register look like a large window.
    if low == 0 || low == 0xFFFF_FFFF {
        restore(config);
        return None;
    }

    // The type bits come from the *mask*, not from the register's current
    // value, and this is the whole reason the probe exists.  An unaddressed BAR
    // reads zero, which is indistinguishable from a memory BAR of unknown type
    //, so a caller that decoded `is_64_bit` from the current value would treat
    // every unassigned 64-bit BAR as 32-bit and place it below four gigabytes,
    // where its window does not fit.
    let kind = if low & 1 != 0 {
        BarKind::Io
    } else {
        BarKind::Memory
    };
    let is_64_bit = kind == BarKind::Memory && (low >> 1) & 0b11 == 0b10;

    let mut mask = (low & if kind == BarKind::Io { !0b11 } else { !0b1111 }) as u64;
    if is_64_bit {
        config.write_dword(address, register + 1, 0xFFFF_FFFF);
        let high = config.read_dword(address, register + 1);
        mask |= (high as u64) << 32;
    } else if kind == BarKind::Memory {
        // A 32-bit BAR has no upper half to hold ones, so its window cannot
        // exceed four gigabytes, and the mask the mechanism produces is
        // **64-bit**, so the top half is all ones.
        //
        // Getting this wrong is invisible above and fatal below: the mask came
        // out as `0x0000_0000_FFFF_F000`, whose complement plus one is
        // `0xFFFF_FFFF_0000_1000`, not a power of two, so every 32-bit BAR
        // sized as absent.
        mask |= 0xFFFF_FFFF_0000_0000;
    }

    restore(config);

    if mask == 0 {
        return None;
    }
    let size = (!mask).wrapping_add(1);
    if !size.is_power_of_two() {
        return None;
    }
    Some(BarProbe {
        size,
        kind,
        is_64_bit,
        address: original as u64 & 0xFFFF_FFF0,
    })
}

/// What a BAR says about itself, asked by writing all ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BarProbe {
    /// The size of the window the BAR asks for, in bytes.
    pub size: u64,
    /// Memory or I/O, from the mask's hardwired bit 0.
    pub kind: BarKind,
    /// Whether this BAR takes two registers, from the mask's type bits.
    pub is_64_bit: bool,
    /// What the register held before the probe.
    pub address: u64,
}

/// The size of the window `register` names.
///
/// [`probe`] answers this and two questions beside it; this is the form a
/// caller that only wants the number uses.
pub fn size(config: &dyn ConfigSpace, address: DeviceAddress, register: u8) -> Option<u64> {
    probe(config, address, register).map(|probe| probe.size)
}

/// Give a memory BAR an address, and verify the device took it.
///
/// Writes both halves of a 64-bit BAR.  A 32-bit BAR's address must fit in
/// thirty-two bits, because the register has no upper half to put the rest in,
/// /// a caller that ignored that would program the low thirty-two bits of an
/// address above four gigabytes and get a device at the wrong address.
///
/// Returns whether the device reads back what was written.  A BAR that does not
/// take an address is a device that would decode somebody else's window if the
/// write were believed, so the answer is checked rather than assumed.
pub fn assign(config: &dyn ConfigSpace, address: DeviceAddress, register: u8, window: u64) -> bool {
    let is_64_bit = {
        let value = config.read_dword(address, register);
        (value >> 1) & 0b11 == 0b10
    };
    if !is_64_bit && window > u32::MAX as u64 {
        return false;
    }

    let low = (window & 0xFFFF_FFF0) as u32;
    config.write_dword(address, register, low);
    if is_64_bit {
        config.write_dword(address, register + 1, (window >> 32) as u32);
    }

    let read_back = {
        let low = config.read_dword(address, register) as u64 & 0xFFFF_FFF0;
        if is_64_bit {
            low | ((config.read_dword(address, register + 1) as u64) << 32)
        } else {
            low
        }
    };
    read_back == window
}

/// Turn on a function's memory decoding and bus-mastering bits.
///
/// Without the first a device's BAR decodes nothing, and without the second it
/// cannot read or write memory on its own, which is what a virtqueue is.  Both
/// are in the command register, which is the low half of
/// [`REG_COMMAND_STATUS`].
pub fn enable_memory_and_bus_master(config: &dyn ConfigSpace, address: DeviceAddress) {
    let current = config.read_dword(address, REG_COMMAND_STATUS);
    let status = current & 0xFFFF_0000;
    let command = (current & 0xFFFF) | COMMAND_MEMORY_SPACE | COMMAND_BUS_MASTER;
    config.write_dword(address, REG_COMMAND_STATUS, status | command);
}

#[cfg(test)]
mod tests;
