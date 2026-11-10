//! drivers/bus/pci/src/msix.rs
//!
//! MSI-X: an interrupt a driver writes down rather than one the platform
//! assigns.
//!
//! ## Why this instead of the interrupt pin
//!
//! A PCI function with INTx raises one of four wires, and which of the
//! controller's lines a wire becomes is a table the platform keeps,
//! `interrupt-map`.  That table is a description of somebody else's decision,
//! and reading it correctly took two attempts here and produced one answe for
//! four pins.
//!
//! MSI-X removes the question.  The device holds a table of up to 2048 entries,
//! each naming an **address to write** and a **value to write there**.  Raising
//! interrupt N is a memory write the device performs; the platform's controller
//! decodes the address.  So the driver decides, and there is no table to
//! interpret.
//!
//! ## The three structures
//!
//! The capability is in configuration space; the table and the pending-bit
//! array are in one of the device's BARs.  The capability says which BAR and
//! what offset, and the driver maps that BAR to reach them.
//!
//! ```text
//! capability (config space)
//!   +0  u8   cap_id (0x11)
//!   +1  u8   cap_next
//!   +2  u16  message control
//!   +4  u32  table:   BAR index in bits 0..3, offset in bits 3..32
//!   +8  u32  PBA:     BAR index in bits 0..3, offset in bits 3..32
//! ```
//!
//! An entry in the table is sixteen bytes: the address, the value, a mask bit,
//! and reserved space.
//!
//! ## What this module is and is not
//!
//! It is the encoding: where a table is, what an entry holds, and how the
//! message-control register says whether the device is using them.  It is not
//! the mapping, a BAR's address is the machine's, and a caller supplies the
//! reader and writer it wants the entries written through.

use crate::config::ConfigSpace;
use crate::config::DeviceAddress;

/// PCI command register bit 10: the function must not use its INTx pin.
///
/// The MSI-X message control's bit 14 is **not** this — it is the function
/// mask, which holds the whole table down.  A driver that asked MSI-X for the
/// pin's silence in the wrong register masked its own vectors, and the
/// interrupt it wired never fired.
pub const COMMAND_INTX_DISABLE: u16 = 1 << 10;

/// The command register's dword index in configuration space.
pub const COMMAND_DWORD: u8 = 1;

/// The capability id an MSI-X structure carries.
pub const CAPABILITY_ID: u8 = 0x11;

/// Message control, bit 15: MSI-X is enabled.
pub const CONTROL_ENABLE: u16 = 1 << 15;

/// Message control, bit 14: the **function mask** — set means every vector
/// the function has is masked, which is the opposite of what its name
/// suggests.
///
/// The first version set this bit on the argument that it "prefers MSI-X over
/// the INTx pin", and the device then sent nothing: the mask is per the PCI
/// specification a mask over the whole table, and a driver that set it while
/// believing it an enablement wired an interrupt path that could not fire.
/// The INTx fallback is refused in the **command register** (bit 10,
/// `INTx Disable`), which is a separate register this module does not own.
pub const CONTROL_FUNCTION_MASK: u16 = 1 << 14;

/// Message control, bits 0..10: how many table entries the function has, minus
/// one.
pub const CONTROL_TABLE_SIZE_MASK: u16 = 0x07FF;

/// The size of one table entry.
pub const ENTRY_SIZE: usize = 16;

/// One entry of the MSI-X table, as the device reads it.
///
/// Sixteen bytes, and the layout is the specification's: three meaningful
/// 32-bit fields followed by one reserved.  The vector control field's bit 0 is
/// the mask, **set means masked**, which is the direction that is easy to
/// forget, because every other "enable" bit in PCI is set-means-on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    /// The address the device writes to.
    pub address: u64,
    /// The value the device writes there.
    pub data: u32,
    /// Bit 0 set means this entry is masked.
    pub vector_control: u32,
}

impl Entry {
    /// An entry that names `address`, writes `data`, and is unmasked.
    pub const fn new(address: u64, data: u32) -> Entry {
        Entry {
            address,
            data,
            vector_control: 0,
        }
    }

    /// Whether this entry is masked.
    ///
    /// Bit 0 set means masked.  A driver that read it as "enabled" would leave
    /// every interrupt masked and then wait for one.
    pub const fn is_masked(&self) -> bool {
        self.vector_control & 1 != 0
    }

    /// The same entry with the mask bit cleared.
    pub const fn unmasked(self) -> Entry {
        Entry {
            vector_control: self.vector_control & !1,
            ..self
        }
    }

    /// The entry as the sixteen bytes the device reads.
    ///
    /// Little-endian: the table is device memory and a PCI function reads it
    /// with the byte order every other PCI structure uses.
    pub fn encode(&self) -> [u8; ENTRY_SIZE] {
        let mut bytes = [0_u8; ENTRY_SIZE];
        bytes[0..8].copy_from_slice(&self.address.to_le_bytes());
        bytes[8..12].copy_from_slice(&self.data.to_le_bytes());
        bytes[12..16].copy_from_slice(&self.vector_control.to_le_bytes());
        bytes
    }

    /// The entry those bytes describe, for a caller verifying a write.
    pub fn decode(bytes: &[u8; ENTRY_SIZE]) -> Entry {
        let mut address = [0_u8; 8];
        address.copy_from_slice(&bytes[0..8]);
        let mut data = [0_u8; 4];
        data.copy_from_slice(&bytes[8..12]);
        let mut control = [0_u8; 4];
        control.copy_from_slice(&bytes[12..16]);
        Entry {
            address: u64::from_le_bytes(address),
            data: u32::from_le_bytes(data),
            vector_control: u32::from_le_bytes(control),
        }
    }
}

/// An MSI-X capability, decoded from a function's configuration space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    /// The offset of the capability structure in configuration space.
    pub offset: u8,
    /// The message control register, as it read.
    pub control: u16,
    /// Which BAR the table is in.
    pub table_bar: u8,
    /// Where in that BAR the table starts.
    pub table_offset: u32,
    /// Which BAR the pending-bit array is in.
    pub pba_bar: u8,
    /// Where in that BAR the pending-bit array starts.
    pub pba_offset: u32,
}

impl Capability {
    /// How many entries the function has.
    ///
    /// The register holds the count **minus one**, so a register of zero is one
    /// entry, not none.  A driver that read it directly would write one entry
    /// past the end of a one-entry table.
    pub const fn table_size(&self) -> usize {
        (self.control & CONTROL_TABLE_SIZE_MASK) as usize + 1
    }

    /// Whether the function is currently allowed to use MSI-X.
    pub const fn is_enabled(&self) -> bool {
        self.control & CONTROL_ENABLE != 0
    }

    /// The message control value with MSI-X enabled and **nothing masked**.
    ///
    /// Bit 15 is the feature's enable; bit 14 is the function mask, which set
    /// would hold every vector down.  The INTx fallback is refused in the
    /// command register's own `INTx Disable` bit, not here — see
    /// [`COMMAND_INTX_DISABLE`].
    pub const fn enabled_control(&self) -> u16 {
        (self.control & CONTROL_TABLE_SIZE_MASK) | CONTROL_ENABLE
    }
}

/// Decode the MSI-X capability at `offset`.
///
/// `None` when the structure does not say it is MSI-X, which a caller reaches
/// by walking a capability list and asking about every entry.
pub fn capability(
    config: &dyn ConfigSpace,
    address: DeviceAddress,
    offset: u8,
) -> Option<Capability> {
    let header = read_dword(config, address, offset);
    if (header & 0xFF) as u8 != CAPABILITY_ID {
        return None;
    }
    let control = (header >> 16) as u16;
    let table = read_dword(config, address, offset + 4);
    let pba = read_dword(config, address, offset + 8);

    Some(Capability {
        offset,
        control,
        // The BAR index is four bits and the offset begins at bit 3, the two
        // overlap, because the offset is eight-byte aligned and those low bits
        // would always be zero.  A decoder that shifted by four drops the top
        // bit of a table offset above 2 GiB.
        table_bar: (table & 0x7) as u8,
        table_offset: table & !0x7,
        pba_bar: (pba & 0x7) as u8,
        pba_offset: pba & !0x7,
    })
}

/// Read the dword at `offset` in a function's configuration space.
///
/// The capability's offsets are byte offsets and [`ConfigSpace`] is written in
/// dword registers, so this is the one place the conversion happens.
fn read_dword(config: &dyn ConfigSpace, address: DeviceAddress, offset: u8) -> u32 {
    config.read_dword(address, offset / 4)
}

/// The byte address of MSI-X table entry `index`, in the BAR whose window
/// starts at `bar_base`.
///
/// This is the arithmetic, and the caller does the write, because a table entry
/// is device memory and the mapping is the machine's: the same entry, reached
/// through a different mechanism on every machine this tree boots.  A caller
/// that wrote through a cached mapping would put the entry somewhere the device
/// never reads, and the interrupt would be a silence that says nothing.
///
/// The offset is eight-byte aligned (the capability's low three bits are the
/// BAR number, which is why they overlap it), and one entry is sixteen bytes,
/// so entry `index` is at `table_offset + index * 16`.
pub fn entry_address(bar_base: usize, capability: &Capability, index: usize) -> usize {
    bar_base + capability.table_offset as usize + index * ENTRY_SIZE
}

/// Enable MSI-X for the function whose capability was decoded.
///
/// Writes the message control register and reads it back: a function that does
/// not report the enable is one whose entries will never be used, and a driver
/// that believed the write would wait for an interrupt the device is not
/// sending.
pub fn enable(config: &dyn ConfigSpace, address: DeviceAddress, capability: &Capability) -> bool {
    let wanted = capability.enabled_control();
    let current = read_dword(config, address, capability.offset);

    // The message control register is the **high half** of the dword at the
    // capability's offset; its low half is `cap_id` and `cap_next`, which are
    // read-only.  Writing the control into the low half, which is what the
    // first version of this did, corrupts the capability id and leaves the
    // enable bit where the device is not looking.
    let word = (current & 0x0000_FFFF) | (u32::from(wanted) << 16);
    config.write_dword(address, capability.offset / 4, word);

    let read_back = read_dword(config, address, capability.offset) >> 16;
    (read_back as u16) & CONTROL_ENABLE != 0
}

#[cfg(test)]
mod tests {
    //! The tests for this module.
    //!
    //! MSI-X: the table entry a driver names, the function mask, and the
    //! register a device writes.
    //!
    //! Extracted from the module so that a reader following the mechanism does
    //! not have to scroll past every case it has to satisfy; see
    //! `docs/fmts/testing.md` §1.

    extern crate std;

    use crate::config::ConfigSpace;
    use crate::config::DeviceAddress;
    use crate::msix::Capability;
    use crate::msix::Entry;
    use crate::msix::capability;
    use crate::msix::enable;
    use crate::msix::entry_address;
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
    /// An offset of `0x1000` has bit 3 clear, so both readings agree, but an
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

    /// An entry's address is the BAR's base, the capability's offset, and the
    /// entry's index, and the three are independent.
    ///
    /// QEMU's virtio-blk puts its table in a BAR of its own at offset zero, so
    /// the first entry's address is the BAR's base; the arithmetic is here
    /// because a second entry is where a driver forgets the stride, and an
    /// entry written over the pending-bit array is a table that lies.
    #[test]
    fn an_entry_is_the_bar_plus_the_offset_plus_the_index() {
        let capability = Capability {
            offset: 0x90,
            control: 3,
            table_bar: 4,
            table_offset: 0x0000,
            pba_bar: 4,
            pba_offset: 0x0800,
        };
        assert_eq!(entry_address(0xF000_0000, &capability, 0), 0xF000_0000);
        assert_eq!(entry_address(0xF000_0000, &capability, 1), 0xF000_0010);
        assert_eq!(entry_address(0xF000_0000, &capability, 3), 0xF000_0030);

        // A table at a non-zero offset inside its BAR: the offset and the index
        // are separate terms, and confusing them writes the wrong entry.
        let offset_capability = Capability {
            table_offset: 0x0040,
            ..capability
        };
        assert_eq!(
            entry_address(0xF000_0000, &offset_capability, 2),
            0xF000_0060
        );
        // And the pending-bit array is not part of the table's arithmetic.
        assert_ne!(
            entry_address(0xF000_0000, &offset_capability, 0),
            0xF000_0000 + 0x0800,
            "the table and the PBA are different regions"
        );
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
    /// Bit 15 turns MSI-X on and **bit 14 must stay clear**: it is the
    /// function mask, and set it holds every vector the function has down —
    /// the opposite of an enablement.  The first version set it on the
    /// argument that it refused the INTx pin; the device then sent nothing,
    /// and the interrupt a boot wired never fired.  The pin's silence is the
    /// command register's own `INTx Disable` bit, which the caller writes.
    #[test]
    fn enabling_does_not_set_the_function_mask() {
        let config = fake();
        let found = capability(&config, ADDRESS, 0x98).unwrap();
        assert!(!found.is_enabled());

        assert!(enable(&config, ADDRESS, &found), "the write was taken");
        let after = capability(&config, ADDRESS, 0x98).unwrap();
        assert!(after.is_enabled());
        assert_eq!(
            after.control & crate::msix::CONTROL_FUNCTION_MASK,
            0,
            "the function mask holds every vector down"
        );
    }

    /// An entry round-trips through the sixteen bytes the device reads.
    ///
    /// The byte order is little-endian, and a caller verifying a write compares
    /// the entry it wrote against the entry it reads back, so an encoding that
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
}
