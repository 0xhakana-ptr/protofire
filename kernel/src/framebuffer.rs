//! kernel/src/framebuffer.rs
//!
//! Finding the display on the bus, setting its mode, and reporting what it
//! became.
//!
//! ## Why the probe is here and the register map is not
//!
//! `vga` holds the `VBE_DISPI` indices, the two layouts and the mode-set
//! sequence, and it names nothing of this tree: a host test drives the whole
//! sequence against an array.  What it cannot do is reach a device, because
//! that needs a BAR, and a BAR needs the machine's mapping.  So this file is
//! the probe: find the function on the bus, read its two BARs, map them, and
//! hand the mapped registers to `vga`'s sequence.
//!
//! ## What this file does not do yet
//!
//! It does not draw.  Setting a mode is the step whose evidence is a line
//! rather than a picture, and a renderer is a separate body of work with its
//! own record: the device and the console are two things, which is why the
//! previous tree had them as two files and why this one will too.
//!
//! ## The two BARs
//!
//! A bochs-display has the linear framebuffer in BAR0 and the `VBE_DISPI` block
//! in BAR2.  `Console` holds the second, because the first is only useful to
//! something that draws, and the record this file answers carries both.

use alloc::sync::Arc;

use vga::FramebufferInfo;
use vga::Mode;
use vga::RegisterBlock;
use vga::VbeLayout;

/// The register block over a mapped BAR.
///
/// The three operations `vga::RegisterBlock` names, over the region
/// `devices::find_display` mapped.  Both layouts are here rather than one
/// because the caller that found the device is the one that knows which it
/// speaks, and the flat window is what QEMU's `std` VGA answers.
struct MappedRegisters {
    file: Arc<dyn crate::devices::WordAccess>,
    layout: VbeLayout,
}

impl RegisterBlock for MappedRegisters {
    fn layout(&self) -> VbeLayout {
        self.layout
    }

    fn read(&mut self, index: u16) -> u16 {
        let offset = match self.layout {
            VbeLayout::Flat => VbeLayout::flat_offset(index),
            // The index/data pair: a register is reached in two steps, and only
            // the first is a write.
            VbeLayout::IndexData => {
                self.file.write16(VbeLayout::index_port() as u64, index);
                VbeLayout::data_port()
            }
        };
        self.file.read16(offset as u64)
    }

    fn write(&mut self, index: u16, value: u16) {
        match self.layout {
            VbeLayout::Flat => self
                .file
                .write16(VbeLayout::flat_offset(index) as u64, value),
            VbeLayout::IndexData => {
                self.file.write16(VbeLayout::index_port() as u64, index);
                self.file.write16(VbeLayout::data_port() as u64, value);
            }
        }
    }
}

/// Find the display, set the console's mode, and answer the record a renderer
/// would draw with.
///
/// `None` on a machine with no display on the bus, on a device whose `ID`
/// register is not a version `vga` knows, and on a device that ignored the mode
/// it was given.  The three are reported differently by the caller because they
/// are three different states of the machine, and a boot that printed one
/// sentence for all of them would leave the reader unable to tell a machine
/// with no screen from a driver with a bug.
pub fn probe() -> Option<DisplayInfo> {
    let found = crate::devices::find_display()?;

    let mut registers = MappedRegisters {
        file: found.registers.clone(),
        layout: found.layout,
    };

    let id = vga::probe_id(&mut registers)?;
    crate::console::report_display_found(id);

    let mode = Mode::CONSOLE;
    let applied = vga::set_mode(&mut registers, mode)?;
    crate::console::report_display_mode(applied);

    Some(DisplayInfo {
        framebuffer: FramebufferInfo::new(
            found.framebuffer_address,
            found.framebuffer_size,
            applied,
        ),
    })
}

/// What a probe hands to a renderer.
///
/// The framebuffer's record, which is the address and the mode.  A renderer
/// takes this and nothing else: it never reads a device register, so a machine
/// whose display has a different register map only changes this file.
#[derive(Debug, Clone, Copy)]
pub struct DisplayInfo {
    pub framebuffer: FramebufferInfo,
}

#[cfg(test)]
mod tests {
    //! The register block over a fake file.
    //!
    //! The probe itself needs a bus, and a bus is the machine's: what a host
    //! can check is the **translation**, that a `vga` register write lands on
    //! the offset the layout names.  That is the one thing between a sequence
    //! that was tested and a device that was programmed, and it is where a
    //! wrong offset would produce a mode that half applied.

    use super::MappedRegisters;
    use alloc::sync::Arc;
    use vga::RegisterBlock;
    use vga::VBE_DISPI_INDEX_XRES;
    use vga::VbeLayout;

    /// A word-addressable map that records the last offset each write landed
    /// on.
    struct Recording {
        words: spin::Mutex<alloc::vec::Vec<(u64, u16)>>,
    }

    impl crate::devices::WordAccess for Recording {
        fn read16(&self, _offset: u64) -> u16 {
            0
        }

        fn write16(&self, offset: u64, value: u16) {
            self.words.lock().push((offset, value));
        }
    }

    /// The flat layout puts a register where the device does.
    ///
    /// `0x500 + 2*index` is the device's own arithmetic, and an adapter that
    /// got it wrong would write a field the device does not have.  The offset
    /// is asserted as a literal for the reason every MMIO offset is.
    #[test]
    fn a_flat_write_lands_at_the_devices_offset() {
        let file = Arc::new(Recording {
            words: spin::Mutex::new(alloc::vec::Vec::new()),
        });
        let mut registers = MappedRegisters {
            file: file.clone(),
            layout: VbeLayout::Flat,
        };
        registers.write(VBE_DISPI_INDEX_XRES, 1024);

        let words = file.words.lock();
        assert_eq!(words.len(), 1, "one register, one write");
        assert_eq!(words[0].0, 0x502, "XRES is the second register");
        assert_eq!(words[0].1, 1024);
    }

    /// The index/data layout selects a register and then writes it.
    ///
    /// Two writes, in that order: the index first, or the value lands in
    /// whichever register the device was last pointed at.
    #[test]
    fn an_index_data_write_selects_then_writes() {
        let file = Arc::new(Recording {
            words: spin::Mutex::new(alloc::vec::Vec::new()),
        });
        let mut registers = MappedRegisters {
            file: file.clone(),
            layout: VbeLayout::IndexData,
        };
        registers.write(VBE_DISPI_INDEX_XRES, 1024);

        let words = file.words.lock();
        assert_eq!(words.len(), 2, "the index, then the value");
        assert_eq!(words[0], (0x0, VBE_DISPI_INDEX_XRES), "the index port");
        assert_eq!(words[1], (0x4, 1024), "the data port");
    }
}
