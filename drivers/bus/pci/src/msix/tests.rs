//! drivers/bus/pci/src/msix/tests.rs
//!
//! MSI-X: the table entry a driver names, the function mask, and the register a
//! device writes.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

extern crate std;

use crate::config::ConfigSpace;
use crate::config::DeviceAddress;
use crate::msix::Entry;
use crate::msix::capability;
use crate::msix::enable;
use std::sync::Mutex;

struct Fake {
    registers: Mutex<[u32; 64]>,
}

const ADDRESS: DeviceAddress = DeviceAddress {
    bus: 0,
    device: 2,
    function: 0,
};

impl ConfigSpace for Fake {
    fn read_dword(&self, _address: DeviceAddress, register: u8) -> u32 {
        self.registers.lock().unwrap()[register as usize % 64]
    }

    fn write_dword(&self, _address: DeviceAddress, register: u8, value: u32) {
        self.registers.lock().unwrap()[register as usize % 64] = value;
    }
}

/// A capability at offset 0x98: id 0x11, two entries, table in BAR 1 at
/// 0x1000, PBA in BAR 1 at 0x2000.
fn fake() -> Fake {
    let mut registers = [0_u32; 64];
    registers[0x98 / 4] = 0x11; // id, next 0, control = 0 -> one entry
    registers[0x9C / 4] = (1 & 0x7) | 0x1000; // table: BAR 1, offset 0x1000
    registers[0xA0 / 4] = (1 & 0x7) | 0x2000; // PBA: BAR 1, offset 0x2000
    Fake {
        registers: Mutex::new(registers),
    }
}

/// The capability decodes its two locations, and the BAR index does not eat
/// the offset's low bit.
///
/// The fields overlap: the BAR is bits 0..3 and the offset starts at bit 3.
/// An offset of `0x1000` has bit 3 clear, so both readings agree — but an
/// offset with bit 3 set is one where shifting by four loses it.
#[test]
fn a_capability_names_its_table_and_pba() {
    let config = fake();
    let found = capability(&config, ADDRESS, 0x98).expect("the fake publishes MSI-X");
    assert_eq!(found.offset, 0x98);
    assert_eq!(found.table_bar, 1);
    assert_eq!(found.table_offset, 0x1000);
    assert_eq!(found.pba_bar, 1);
    assert_eq!(found.pba_offset, 0x2000);
}

/// The table size register holds the count **minus one**.
///
/// A register of zero is one entry, which is the value this fake writes.  A
/// driver that read the register directly would believe the function has no
/// entries and never write any.
#[test]
fn the_table_size_is_one_more_than_the_register() {
    let config = fake();
    let found = capability(&config, ADDRESS, 0x98).unwrap();
    assert_eq!(found.table_size(), 1, "a register of zero is one entry");

    let mut registers = config.registers.lock().unwrap();
    // Four entries.
    registers[0x98 / 4] = 0x11 | (3 << 16);
    drop(registers);
    let found = capability(&config, ADDRESS, 0x98).unwrap();
    assert_eq!(found.table_size(), 4);
}

/// A structure whose id is not MSI-X is refused, which is what a capability
/// walk needs to ask about every entry it meets.
#[test]
fn another_capability_is_not_msix() {
    let config = fake();
    assert!(capability(&config, ADDRESS, 0x84).is_none());
}

/// Enabling sets both the feature bit and the "do not use the pin" bit.
///
/// They are different: bit 15 turns MSI-X on and bit 14 says the function
/// must not fall back to INTx.  A driver that set only bit 15 has a device
/// raising both the message and the wire.
#[test]
fn enabling_turns_off_the_pin_as_well() {
    let config = fake();
    let found = capability(&config, ADDRESS, 0x98).unwrap();
    assert!(!found.is_enabled());

    assert!(enable(&config, ADDRESS, &found), "the write was taken");
    let after = capability(&config, ADDRESS, 0x98).unwrap();
    assert!(after.is_enabled());
    assert_ne!(after.control & crate::msix::CONTROL_FUNCTION_MASK, 0);
}

/// An entry round-trips through the sixteen bytes the device reads.
///
/// The byte order is little-endian, and a caller verifying a write compares
/// the entry it wrote against the entry it reads back — so an encoding that
/// did not round-trip would report a correct write as a wrong one.
#[test]
fn an_entry_round_trips() {
    let entry = Entry::new(0x0800_8020, 0x2A);
    let bytes = entry.encode();
    assert_eq!(Entry::decode(&bytes), entry);
    assert_eq!(bytes.len(), crate::msix::ENTRY_SIZE);
}

/// The mask bit is set-means-masked, which is the opposite of every other
/// enable bit in PCI.
///
/// A driver that read it the other way would leave every entry masked and
/// then wait for an interrupt the device is not allowed to send.
#[test]
fn the_mask_bit_is_set_means_masked() {
    let masked = Entry {
        address: 0x1000,
        data: 1,
        vector_control: 1,
    };
    assert!(masked.is_masked());
    assert!(!masked.unmasked().is_masked());
    assert_eq!(
        masked.unmasked().address,
        masked.address,
        "nothing else moved"
    );
}

/// A decoded entry's `decode` agrees with the specification's offsets: the
/// address is eight bytes, then the data, then the control.
#[test]
fn the_entry_layout_is_the_specifications() {
    let mut bytes = [0_u8; 16];
    bytes[0] = 0x20;
    bytes[1] = 0x80;
    bytes[8] = 0x2A;
    bytes[12] = 1;
    let entry = Entry::decode(&bytes);
    assert_eq!(entry.address, 0x8020);
    assert_eq!(entry.data, 0x2A);
    assert!(entry.is_masked());
}
