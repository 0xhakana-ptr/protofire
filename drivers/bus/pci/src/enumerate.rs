//! drivers/bus/pci/src/enumerate.rs
//!
//! Giving devices the addresses they need: the pass a firmware would run.
//!
//! ## Why this exists
//!
//! A PCI function's BAR is a register asking the machine for a window.  On a
//! machine with firmware — a PC, a UEFI board — something has already answered:
//! the registers hold plausible addresses and a driver only has to read them.
//!
//! A device-tree machine booted directly has no such pass.  Every BAR reads
//! zero, which is indistinguishable from "no device here" unless the probe asks
//! the device rather than reading the register.  That is what
//! [`bar::size`] does, and this module is the other half: allocate from the
//! window the host bridge's `ranges` describes, write it back, and verify the
//! device took it.
//!
//! ## The order
//!
//! Sizing first, for every BAR, then allocation.  A sizing write leaves the
//! register holding all ones for a few instructions, and an address assigned
//! before its neighbours are sized is one that could be collided with.  So the
//! sizes are collected once, and the cursor moves only after every size is
//! known.
//!
//! ## What is left alone
//!
//! A BAR that already has an address.  A machine whose firmware assigned one
//! has a driver that may already be using it, and a second opinion about where
//! a device lives is not this module's to give.

use crate::bar;
use crate::bar::BarKind;
use crate::config::ConfigSpace;
use crate::config::DeviceAddress;
use crate::device::Device;

/// The first BAR register, as a dword index.
const FIRST_BAR: u8 = 4;
/// How many BAR registers a function has.
const BAR_COUNT: u8 = 6;

/// What the pass did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Assignment {
    /// Memory BARs that were given an address.
    pub assigned: usize,
    /// Memory BARs that had one already.
    pub already: usize,
    /// BARs whose address could not be placed in the window.
    pub no_room: usize,
    /// BARs that did not read back what was written.
    pub refused: usize,
    /// Where the next window would start.
    pub used_end: u64,
}

/// Give every unaddressed memory BAR in `devices` a window from
/// `base..base+size`.
///
/// I/O BARs are skipped: a device-tree machine has no port space, so an I/O
/// window is a range nothing can reach.  A function whose BAR does not read
/// back what was written is left as it was — a device that does not take an
/// address would decode somebody else's window if the write were believed.
///
/// Every address this assigns is 4 KiB aligned and sized to a power of two,
/// which is what a BAR requires: the device compares the high bits of an
/// address against its own, and a window that was not aligned would overlap its
/// neighbour by the difference.
pub fn assign_memory_bars(
    config: &dyn ConfigSpace,
    devices: &[Device],
    base: u64,
    size: u64,
) -> Assignment {
    let end = base.saturating_add(size);
    let mut assignment = Assignment {
        used_end: base,
        ..Assignment::default()
    };
    let mut cursor = base;

    for device in devices {
        let address = device.address;
        // A function the bus did not answer for has no BARs to size.  The scan
        // never yields one, and a caller that constructed one by hand is asking
        // about an address nothing decodes.
        if device.vendor == crate::config::NO_DEVICE {
            continue;
        }

        let mut register = FIRST_BAR;
        while register < FIRST_BAR + BAR_COUNT {
            // Every question is answered by the probe: whether a BAR is there
            // at all, whether it is memory or I/O, whether it takes two
            // registers, and how big it is.  Reading any of that from the
            // register's current value is what breaks on an unaddressed BAR,
            // which reads zero.
            let Some(probed) = bar::probe(config, address, register) else {
                register += 1;
                continue;
            };
            let window = probed.size;
            let slots = if probed.is_64_bit { 2 } else { 1 };

            if probed.kind == BarKind::Io {
                register += slots;
                continue;
            }
            if probed.address != 0 {
                assignment.already += 1;
                register += slots;
                continue;
            }
            // A 32-bit BAR cannot hold an address above four gigabytes; the
            // window the bridge describes may be above that, and placing one
            // there would program the low half of it.
            let fits_in_register = probed.is_64_bit || window <= 1 << 32;
            if !fits_in_register {
                assignment.no_room += 1;
                register += slots;
                continue;
            }

            let aligned = match cursor.checked_add(window - 1) {
                Some(value) => value & !(window - 1),
                None => {
                    assignment.no_room += 1;
                    register += slots;
                    continue;
                }
            };
            let fits = aligned
                .checked_add(window)
                .is_some_and(|window_end| window_end <= end);
            if !fits {
                assignment.no_room += 1;
                register += slots;
                continue;
            }

            if bar::assign(config, address, register, aligned) {
                bar::enable_memory_and_bus_master(config, address);
                assignment.assigned += 1;
                cursor = aligned + window;
                assignment.used_end = cursor;
            } else {
                assignment.refused += 1;
            }
            register += slots;
        }
    }

    assignment
}

/// Whether an address is one a device's window may start at.
///
/// Four-byte alignment is what the register's low bits require; the caller's
/// alignment is the size, which is a power of two and therefore stricter.  This
/// exists for the tests to state the rule the allocation follows.
pub const fn is_window_start(address: u64) -> bool {
    address != 0 && address % 4 == 0
}

/// The address a BAR holds, as a full 64-bit value.
///
/// Both halves for a 64-bit BAR, the low half alone otherwise.  A caller that
/// read only the low register would see zero for every device placed above four
/// gigabytes — which is where a device-tree machine's host bridge usually puts
/// its window.
pub fn bar_address(config: &dyn ConfigSpace, address: DeviceAddress, register: u8) -> u64 {
    let low = config.read_dword(address, register) as u64 & 0xFFFF_FFF0;
    // Whether the *next* register is this BAR's upper half is not in the
    // value: once an address is written, the type bits are gone.  The probe is
    // the only thing that knows, and it is also what a caller that wants one
    // number should have used in the first place.
    let is_64_bit = bar::probe(config, address, register).is_some_and(|probe| probe.is_64_bit);
    if is_64_bit {
        low | (u64::from(config.read_dword(address, register + 1)) << 32)
    } else {
        low
    }
}

#[cfg(test)]
mod tests;
