//! drivers/display/vga/src/registers.rs
//!
//! The bochs-display's register block: the indices, the two layouts, and the
//! trait a caller provides so this crate never touches memory.
//!
//! ## Why a trait and not a base address
//!
//! A register is a `u16` at an offset, and reading one is a volatile load at an
//! address the caller mapped.  If this crate took a base address it would have
//! to own the `unsafe` that reads it, which would make the whole register map
//! untestable on a host, the machine would be the only thing that could
//! exercise it, and a mode-set sequence is exactly the kind of arithmetic worth
//! testing where it is cheap.
//!
//! [`RegisterBlock`] is the three operations a device offers: read one, write
//! one, and say which layout it speaks.  The kernel implements it over a mapped
//! BAR; a host test implements it over an array.  Both drive the same
//! sequence.

/// The bochs-display's PCI vendor id.
pub const BOCHS_VENDOR_ID: u16 = 0x1234;

/// The bochs-display's PCI device id.
///
/// QEMU answers this for its `std` VGA, which is the device every machine this
/// tree boots has unless the emulator was told otherwise.  It is the same pair
/// a discrete Bochs display reports, which is why the identifier is the
/// device's name rather than QEMU's.
pub const BOCHS_DEVICE_ID: u16 = 0x1111;

/// `VBE_DISPI_INDEX_ID`: reading it answers the device's interface version.
pub const VBE_DISPI_INDEX_ID: u16 = 0;
/// `VBE_DISPI_INDEX_XRES`: the horizontal resolution, in pixels.
pub const VBE_DISPI_INDEX_XRES: u16 = 1;
/// `VBE_DISPI_INDEX_YRES`: the vertical resolution, in pixels.
pub const VBE_DISPI_INDEX_YRES: u16 = 2;
/// `VBE_DISPI_INDEX_BPP`: bits per pixel.
pub const VBE_DISPI_INDEX_BPP: u16 = 3;
/// `VBE_DISPI_INDEX_ENABLE`: the flags that turn the display on.
pub const VBE_DISPI_INDEX_ENABLE: u16 = 4;

/// `VBE_DISPI_ENABLED`: the mode is active.
pub const VBE_DISPI_ENABLED: u16 = 1 << 0;
/// `VBE_DISPI_LFB_ENABLED`: draw through the linear framebuffer.
///
/// Without it the device keeps answering at its legacy window, and a console
/// writing to BAR0 would be writing where the device is not reading.
pub const VBE_DISPI_LFB_ENABLED: u16 = 1 << 6;
/// `VBE_DISPI_NOCLEARMEM`: do not blank the framebuffer on the switch.
///
/// Set because the console that asks for the mode is about to draw its own
/// blank screen; a device that clears first is one more write of a megabyte
/// that changes nothing.
pub const VBE_DISPI_NOCLEARMEM: u16 = 1 << 7;

/// `VBE_DISPI_ID0`, the first interface version the register answers.
///
/// The check is a **range** rather than equality: QEMU's device answers `ID5`
/// (`0xB0C5`) and a discrete Bochs display may answer less, and every version
/// in between defines the registers this crate writes.  Pinning one value
/// would refuse a device that works.
pub const VBE_DISPI_ID0: u16 = 0xB0C0;
/// The last interface version this crate knows.
pub const VBE_DISPI_ID5: u16 = 0xB0C5;

/// Whether an `ID` register answer is a version this crate can drive.
///
/// The answer is a word, and a device that does not implement the register at
/// all answers zero, an open bus, or the index itself.  All three are outside
/// the range and none of them is a version.
pub const fn is_supported_id(id: u16) -> bool {
    id >= VBE_DISPI_ID0 && id <= VBE_DISPI_ID5
}

/// Which way the device's registers are reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VbeLayout {
    /// A flat window: register `i` is a `u16` at `0x500 + 2*i`.
    ///
    /// QEMU's `std` VGA speaks this, which is why it is the one this tree's
    /// machines use.
    Flat,
    /// The classic index/data pair at `0x0` and `0x4`.
    ///
    /// A discrete bochs-display speaks this.  It is kept because the code that
    /// reads it is four lines and the device it addresses is the same device,
    /// and a driver that refused one layout would be refusing a machine rather
    /// than a version.
    IndexData,
}

impl VbeLayout {
    /// Where register `index` lives in the flat layout.
    pub const fn flat_offset(index: u16) -> usize {
        0x500 + (index as usize) * 2
    }

    /// The offset a write to the index port goes to.
    pub const fn index_port() -> usize {
        0x0
    }

    /// The offset a read or write of the data port goes to.
    pub const fn data_port() -> usize {
        0x4
    }
}

/// The three operations a device's register block offers.
///
/// Implemented by the kernel over a mapped BAR and by a host test over an
/// array.  Every function in this crate takes one of these rather than an
/// address, which is what keeps the sequences testable.
pub trait RegisterBlock {
    /// Which layout this device speaks.
    fn layout(&self) -> VbeLayout;

    /// Read 16-bit register `index`.
    fn read(&mut self, index: u16) -> u16;

    /// Write `value` to 16-bit register `index`.
    fn write(&mut self, index: u16, value: u16);
}

/// Read the interface version and say whether this crate can drive it.
///
/// A device that answers outside the range is not one this crate knows, and
/// the caller's next step is to report it rather than to program a mode: a
/// register block whose `ID` is unrecognised has registers at addresses this
/// crate has no reason to trust.
pub fn probe_id(block: &mut dyn RegisterBlock) -> Option<u16> {
    let id = block.read(VBE_DISPI_INDEX_ID);
    is_supported_id(id).then_some(id)
}

#[cfg(test)]
mod tests {
    //! The register block's tests.

    use super::BOCHS_DEVICE_ID;
    use super::BOCHS_VENDOR_ID;
    use super::RegisterBlock;
    use super::VBE_DISPI_ENABLED;
    use super::VBE_DISPI_ID0;
    use super::VBE_DISPI_ID5;
    use super::VBE_DISPI_INDEX_BPP;
    use super::VBE_DISPI_INDEX_ENABLE;
    use super::VBE_DISPI_INDEX_ID;
    use super::VBE_DISPI_INDEX_XRES;
    use super::VBE_DISPI_INDEX_YRES;
    use super::VBE_DISPI_LFB_ENABLED;
    use super::VBE_DISPI_NOCLEARMEM;
    use super::VbeLayout;
    use super::is_supported_id;
    use super::probe_id;

    /// A register block over an array, which is what makes a sequence testable.
    ///
    /// The registers are addressed by index in both layouts, so one array
    /// serves both: the layout decides how a caller *reaches* them, not what
    /// they are.
    pub(super) struct FakeBlock {
        registers: [u16; 16],
        layout: VbeLayout,
    }

    impl FakeBlock {
        pub(super) fn new(layout: VbeLayout) -> Self {
            Self {
                registers: [0; 16],
                layout,
            }
        }

        /// A block that answers `id` to the `ID` register, the way a device
        /// does.
        pub(super) fn answering(id: u16) -> Self {
            let mut block = Self::new(VbeLayout::Flat);
            block.registers[VBE_DISPI_INDEX_ID as usize] = id;
            block
        }
    }

    impl RegisterBlock for FakeBlock {
        fn layout(&self) -> VbeLayout {
            self.layout
        }

        fn read(&mut self, index: u16) -> u16 {
            self.registers[index as usize]
        }

        fn write(&mut self, index: u16, value: u16) {
            self.registers[index as usize] = value;
        }
    }

    /// The indices are the device's own numbers.
    ///
    /// Written down as literals rather than trusted: a register index that
    /// moved would write one field while reading another, and the symptom would
    /// be a mode that half-applied.
    #[test]
    fn the_register_indices_are_the_devices() {
        assert_eq!(VBE_DISPI_INDEX_ID, 0);
        assert_eq!(VBE_DISPI_INDEX_XRES, 1);
        assert_eq!(VBE_DISPI_INDEX_YRES, 2);
        assert_eq!(VBE_DISPI_INDEX_BPP, 3);
        assert_eq!(VBE_DISPI_INDEX_ENABLE, 4);
    }

    /// The enable flags are the device's own bits, and they are distinct.
    ///
    /// `LFB_ENABLED` without `ENABLED` is a mode that is not on; `ENABLED`
    /// without `LFB_ENABLED` is one drawn through the legacy window.  Both are
    /// states the device has and neither is the one this crate wants, which is
    /// why the bits are asserted separately rather than as a combined constant.
    #[test]
    fn the_enable_flags_are_the_devices_bits() {
        assert_eq!(VBE_DISPI_ENABLED, 1 << 0);
        assert_eq!(VBE_DISPI_LFB_ENABLED, 1 << 6);
        assert_eq!(VBE_DISPI_NOCLEARMEM, 1 << 7);
        assert_eq!(
            VBE_DISPI_ENABLED & VBE_DISPI_LFB_ENABLED,
            0,
            "the two flags do not share a bit"
        );
    }

    /// The identifiers are the ones QEMU answers for its `std` VGA.
    #[test]
    fn the_pci_identifiers_are_the_devices() {
        assert_eq!(BOCHS_VENDOR_ID, 0x1234);
        assert_eq!(BOCHS_DEVICE_ID, 0x1111);
    }

    /// The version range accepts every version and refuses what is not one.
    ///
    /// A device that does not implement the register answers zero or an open
    /// bus, and both are outside the range.  A range rather than equality is
    /// what lets a discrete Bochs display, which may answer an earlier version,
    /// be driven.
    #[test]
    fn only_a_version_in_range_is_supported() {
        assert!(!is_supported_id(0));
        assert!(!is_supported_id(VBE_DISPI_ID0 - 1));
        assert!(is_supported_id(VBE_DISPI_ID0));
        assert!(is_supported_id(VBE_DISPI_ID0 + 2));
        assert!(is_supported_id(VBE_DISPI_ID5));
        assert!(!is_supported_id(VBE_DISPI_ID5 + 1));
        assert!(!is_supported_id(0xFFFF));
    }

    /// The probe answers the version a device reports, and refuses one it
    /// cannot drive.
    #[test]
    fn the_probe_reads_the_version_register() {
        let mut flat = FakeBlock::answering(VBE_DISPI_ID5);
        assert_eq!(probe_id(&mut flat), Some(VBE_DISPI_ID5));

        let mut old = FakeBlock::answering(0);
        assert_eq!(
            probe_id(&mut old),
            None,
            "a register that answered nothing is not a version"
        );
    }

    /// The two layouts compute the offsets the device defines.
    ///
    /// The flat base is the constant a probe maps its BAR against, and the port
    /// pair is the one a discrete device uses.  Both are literals in the
    /// specification, so both are asserted as literals here.
    #[test]
    fn the_layouts_place_the_registers_where_the_device_does() {
        assert_eq!(VbeLayout::flat_offset(0), 0x500);
        assert_eq!(VbeLayout::flat_offset(1), 0x502);
        assert_eq!(VbeLayout::flat_offset(VBE_DISPI_INDEX_ENABLE), 0x508);
        assert_eq!(VbeLayout::index_port(), 0x0);
        assert_eq!(VbeLayout::data_port(), 0x4);
    }

    /// Both layouts reach the same register of the same device.
    ///
    /// The array is addressed by index, so this test is really asserting that
    /// the trait's contract is about *the register*, not about a layout: a
    /// caller that wrote through one layout and read through the other would be
    /// reaching the same field, and that is the property the trait exists to
    /// give.
    #[test]
    fn both_layouts_read_and_write_one_register_set() {
        for layout in [VbeLayout::Flat, VbeLayout::IndexData] {
            let mut block = FakeBlock::new(layout);
            block.write(VBE_DISPI_INDEX_XRES, 1024);
            assert_eq!(block.read(VBE_DISPI_INDEX_XRES), 1024);
            assert_eq!(block.layout(), layout);
        }
    }
}
