//! drivers/display/vga/src/mode.rs
//!
//! Setting a mode, and the record a probe hands to whatever draws.
//!
//! ## The sequence, and why the order is the specification's
//!
//! Switching a bochs-display's mode is four writes and one of them means
//! something only in order:
//!
//! 1. turn the display **off** (clear `VBE_DISPI_ENABLED`);
//! 2. write the resolution and the depth;
//! 3. turn it back on with `LFB_ENABLED` and `NOCLEARMEM`.
//!
//! A device whose resolution changes while it is enabled is reporting a mode
//! it is not driving, and the framebuffer's pitch stops matching the one the
//! console computed from it.  That is the defect this order prevents, and it is
//! why the sequence is here rather than left to each caller.

use crate::registers::RegisterBlock;
use crate::registers::VBE_DISPI_ENABLED;
use crate::registers::VBE_DISPI_INDEX_BPP;
use crate::registers::VBE_DISPI_INDEX_ENABLE;
use crate::registers::VBE_DISPI_INDEX_XRES;
use crate::registers::VBE_DISPI_INDEX_YRES;
use crate::registers::VBE_DISPI_LFB_ENABLED;
use crate::registers::VBE_DISPI_NOCLEARMEM;

/// A mode this crate will set.
///
/// The three fields are the device's own units: pixels and bits.  A mode is
/// refused rather than adjusted when the device cannot take it, because a
/// console that computed its grid from one resolution and got another would
/// draw the wrong number of columns and no error would say so.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mode {
    /// Horizontal resolution, in pixels.
    pub width: u16,
    /// Vertical resolution, in pixels.
    pub height: u16,
    /// Bits per pixel.  This tree uses 32.
    pub bpp: u16,
}

impl Mode {
    /// The mode this tree's console asks for.
    ///
    /// 1024x768 at 32 bits, which is small enough that the framebuffer is four
    /// megabytes and large enough for a character grid of 128 by 48 at an 8x16
    /// cell, which is more than a console a person types into needs.
    pub const CONSOLE: Mode = Mode {
        width: 1024,
        height: 768,
        bpp: 32,
    };

    /// Bytes one scanline occupies.
    ///
    /// There is no padding: the device's linear framebuffer is exactly
    /// `width * bpp / 8` bytes per row, which is the one fact a renderer needs
    /// and the one an off-by-one in it corrupts silently, a row drawn one byte
    /// short shifts every row after it by one.
    pub const fn pitch(self) -> u32 {
        self.width as u32 * (self.bpp as u32 / 8)
    }

    /// Bytes the whole framebuffer occupies.
    pub const fn size(self) -> usize {
        self.pitch() as usize * self.height as usize
    }

    /// Whether the device would accept this mode.
    ///
    /// The bounds are the device's: its maximum resolution is 2560x1600 and its
    /// depth is 4, 8, 15, 16, 24 or 32 bits.  Anything else is a number the
    /// device would write and not honour.
    pub const fn is_supported(self) -> bool {
        let depth_ok = matches!(self.bpp, 4 | 8 | 15 | 16 | 24 | 32);
        depth_ok && self.width > 0 && self.height > 0 && self.width <= 2560 && self.height <= 1600
    }
}

/// What a probe hands to a renderer.
///
/// The mapped framebuffer's address, its size, and the mode that describes
/// what to draw.  A renderer that had to recompute any of these from the device
/// would be a second place the mode is derived, and the two would disagree the
/// day one of them changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FramebufferInfo {
    /// Where the framebuffer is mapped, as the drawing code reaches it.
    pub address: usize,
    /// How many bytes are mapped there.
    pub size: usize,
    /// The mode the device is driving.
    pub mode: Mode,
}

impl FramebufferInfo {
    /// The record for a mapped framebuffer of `size` bytes driving `mode`.
    pub const fn new(address: usize, size: usize, mode: Mode) -> Self {
        Self {
            address,
            size,
            mode,
        }
    }

    /// Where pixel `(x, y)` starts.
    ///
    /// `None` for a pixel outside the mode, which is a caller's mistake rather
    /// than a device's: a renderer that drew at `x = width` would land on the
    /// next row's first pixel and the image would shear by one.
    pub const fn pixel_offset(&self, x: u16, y: u16) -> Option<usize> {
        if x >= self.mode.width || y >= self.mode.height {
            return None;
        }
        Some(y as usize * self.mode.pitch() as usize + x as usize * (self.mode.bpp as usize / 8))
    }
}

/// Program `mode` into the device behind `block`.
///
/// Answers the mode the device is now driving, which is the mode that was
/// asked for: this crate does not adjust a request, so a caller that gets a
/// different answer has a device that lied rather than a driver that
/// negotiated, and the only case where that can happen is a device this crate
/// should have refused at [`crate::registers::probe_id`].
///
/// A mode the device cannot take is refused **before** the display is turned
/// off, so a refusal leaves the machine's screen as it was rather than blank.
pub fn set_mode(block: &mut dyn RegisterBlock, mode: Mode) -> Option<Mode> {
    if !mode.is_supported() {
        return None;
    }

    // Off first: a resolution written while the display is enabled describes a
    // mode the device is not driving.
    block.write(VBE_DISPI_INDEX_ENABLE, 0);
    block.write(VBE_DISPI_INDEX_XRES, mode.width);
    block.write(VBE_DISPI_INDEX_YRES, mode.height);
    block.write(VBE_DISPI_INDEX_BPP, mode.bpp);
    // On, through the linear framebuffer, and without the device's own clear:
    // the console that asked for this mode is about to paint over it anyway.
    block.write(
        VBE_DISPI_INDEX_ENABLE,
        VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED | VBE_DISPI_NOCLEARMEM,
    );

    // Read the resolution back.  A device that ignored a write answers the old
    // mode here, and a caller that trusted its own request would draw a grid
    // that does not match the memory it is writing into.
    let width = block.read(VBE_DISPI_INDEX_XRES);
    let height = block.read(VBE_DISPI_INDEX_YRES);
    let bpp = block.read(VBE_DISPI_INDEX_BPP);
    let applied = Mode { width, height, bpp };
    (applied == mode).then_some(applied)
}

#[cfg(test)]
#[cfg(test)]
mod tests {
    //! The mode-set tests: the sequence's order, what it refuses, and the
    //! record a renderer draws with.
    //!
    //! These are the tests the split exists for.  A mode-set sequence is four
    //! writes whose order is the whole of their meaning, and every one of them
    //! is checked here without a machine: the register block is an array, so
    //! the sequence is observed rather than assumed.

    use super::FramebufferInfo;
    use super::Mode;
    use super::set_mode;
    use crate::registers::RegisterBlock;
    use crate::registers::VBE_DISPI_ENABLED;
    use crate::registers::VBE_DISPI_INDEX_BPP;
    use crate::registers::VBE_DISPI_INDEX_ENABLE;
    use crate::registers::VBE_DISPI_INDEX_XRES;
    use crate::registers::VBE_DISPI_INDEX_YRES;
    use crate::registers::VBE_DISPI_LFB_ENABLED;
    use crate::registers::VBE_DISPI_NOCLEARMEM;
    use crate::registers::VbeLayout;

    /// A register block that records the order the writes arrived in.
    ///
    /// The array alone would show the final state, and the final state is the
    /// same for a sequence that turned the display off first and one that did
    /// not.  The order is the property, so the order is what this records.
    struct RecordingBlock {
        registers: [u16; 16],
        writes: alloc::vec::Vec<(u16, u16)>,
    }

    impl RecordingBlock {
        fn new() -> Self {
            Self {
                registers: [0; 16],
                writes: alloc::vec::Vec::new(),
            }
        }
    }

    impl RegisterBlock for RecordingBlock {
        fn layout(&self) -> VbeLayout {
            VbeLayout::Flat
        }

        fn read(&mut self, index: u16) -> u16 {
            self.registers[index as usize]
        }

        fn write(&mut self, index: u16, value: u16) {
            self.writes.push((index, value));
            self.registers[index as usize] = value;
        }
    }

    /// The console mode is 1024x768 at 32 bits, and its arithmetic follows.
    ///
    /// The pitch is the number a renderer multiplies by, and an off-by-one in
    /// it shears every row after the first.  It is asserted as a literal
    /// because the device's framebuffer has no padding: 1024 pixels at four
    /// bytes is 4096, and a mode whose pitch computed anything else would be a
    /// renderer drawing rows it did not mean.
    #[test]
    fn the_console_mode_has_the_arithmetic_it_says() {
        let mode = Mode::CONSOLE;
        assert_eq!(mode.width, 1024);
        assert_eq!(mode.height, 768);
        assert_eq!(mode.bpp, 32);
        assert_eq!(mode.pitch(), 4096);
        assert_eq!(mode.size(), 4096 * 768);
        assert!(mode.is_supported());
    }

    /// The supported set is the device's: six depths and two bounds.
    #[test]
    fn the_device_accepts_only_the_depths_it_defines() {
        for bpp in [4, 8, 15, 16, 24, 32] {
            assert!(
                Mode {
                    width: 640,
                    height: 480,
                    bpp
                }
                .is_supported(),
                "{bpp} bits is a depth the device defines"
            );
        }
        for bpp in [1, 2, 12, 31, 64] {
            assert!(
                !Mode {
                    width: 640,
                    height: 480,
                    bpp
                }
                .is_supported(),
                "{bpp} bits is not"
            );
        }
        assert!(
            !Mode {
                width: 0,
                height: 480,
                bpp: 32
            }
            .is_supported(),
            "a zero width is not a mode"
        );
        assert!(
            !Mode {
                width: 2561,
                height: 480,
                bpp: 32
            }
            .is_supported(),
            "past the device's maximum width"
        );
        assert!(
            !Mode {
                width: 640,
                height: 1601,
                bpp: 32
            }
            .is_supported(),
            "past the device's maximum height"
        );
    }

    /// The display is turned off before the resolution is written.
    ///
    /// The order is the specification's and the reason is a pitch that stops
    /// matching: a resolution written into an enabled device describes a mode
    /// the device is not driving.  This test reads the recorded sequence rather
    /// than the final state, because the final state is identical either way.
    #[test]
    fn the_sequence_disables_before_it_changes_the_resolution() {
        let mut block = RecordingBlock::new();
        assert_eq!(set_mode(&mut block, Mode::CONSOLE), Some(Mode::CONSOLE));

        let first_enable = block
            .writes
            .iter()
            .position(|(index, _)| *index == VBE_DISPI_INDEX_ENABLE)
            .expect("the sequence writes ENABLE");
        let first_resolution = block
            .writes
            .iter()
            .position(|(index, _)| *index == VBE_DISPI_INDEX_XRES)
            .expect("the sequence writes XRES");
        assert!(
            first_enable < first_resolution,
            "the display is turned off before the mode is written"
        );
        assert_eq!(block.writes[first_enable].1, 0, "and turned off, not on");
    }

    /// The sequence ends with the display on, through the linear framebuffer.
    ///
    /// `ENABLED` without `LFB_ENABLED` is a mode drawn through the legacy
    /// window, and the console writes to BAR0.  A device in that state answers
    /// every write and shows nothing, which is the failure that looks like a
    /// renderer bug.
    #[test]
    fn the_sequence_leaves_the_display_on_through_the_framebuffer() {
        let mut block = RecordingBlock::new();
        assert_eq!(set_mode(&mut block, Mode::CONSOLE), Some(Mode::CONSOLE));

        let enable = block
            .writes
            .iter()
            .rev()
            .find(|(index, _)| *index == VBE_DISPI_INDEX_ENABLE)
            .expect("the sequence writes ENABLE last");
        assert_eq!(
            enable.1,
            VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED | VBE_DISPI_NOCLEARMEM
        );
        assert_eq!(block.read(VBE_DISPI_INDEX_XRES), 1024);
        assert_eq!(block.read(VBE_DISPI_INDEX_YRES), 768);
        assert_eq!(block.read(VBE_DISPI_INDEX_BPP), 32);
    }

    /// A mode the device cannot take is refused before anything is written.
    ///
    /// A refusal that turned the display off first would leave a screen blank
    /// for a mode that never applied, which is worse than the refusal.  The
    /// recorded sequence is what says the refusal came first.
    #[test]
    fn an_unsupported_mode_is_refused_before_the_display_changes() {
        let mut block = RecordingBlock::new();
        let impossible = Mode {
            width: 4096,
            height: 2160,
            bpp: 32,
        };
        assert_eq!(set_mode(&mut block, impossible), None);
        assert!(
            block.writes.is_empty(),
            "a refused mode touches no register"
        );
    }

    /// A device that ignores the writes is not reported as a success.
    ///
    /// The read-back is the whole of this test.  A device that answered its old
    /// resolution would leave a caller drawing a grid that does not match the
    /// memory under it, and trusting the request instead of the device is how
    /// that becomes a corrupted screen rather than a refusal.
    #[test]
    fn a_device_that_ignores_the_mode_is_refused() {
        /// A block that accepts writes and answers a resolution of its own.
        struct Stubborn {
            registers: [u16; 16],
        }

        impl RegisterBlock for Stubborn {
            fn layout(&self) -> VbeLayout {
                VbeLayout::Flat
            }

            fn read(&mut self, index: u16) -> u16 {
                // The resolution always answers the mode the device is stuck
                // in, whatever was written.
                match index {
                    VBE_DISPI_INDEX_XRES => 640,
                    VBE_DISPI_INDEX_YRES => 480,
                    VBE_DISPI_INDEX_BPP => 8,
                    _ => self.registers[index as usize],
                }
            }

            fn write(&mut self, index: u16, value: u16) {
                self.registers[index as usize] = value;
            }
        }

        let mut block = Stubborn { registers: [0; 16] };
        assert_eq!(
            set_mode(&mut block, Mode::CONSOLE),
            None,
            "the device answered a different mode and the sequence says so"
        );
    }

    /// A pixel inside the mode has an offset, and one outside it does not.
    ///
    /// The `None` is the point: an offset for `x == width` is the next row's
    /// first pixel, and a renderer that drew there would shear the image by one
    /// without any error.
    #[test]
    fn a_pixel_offset_is_inside_the_mode_or_it_is_none() {
        let info = FramebufferInfo::new(0x1000, 4096 * 768, Mode::CONSOLE);
        assert_eq!(info.pixel_offset(0, 0), Some(0));
        assert_eq!(info.pixel_offset(1, 0), Some(4));
        assert_eq!(info.pixel_offset(0, 1), Some(4096));
        assert_eq!(info.pixel_offset(1023, 767), Some(4096 * 767 + 1023 * 4));
        assert_eq!(info.pixel_offset(1024, 0), None);
        assert_eq!(info.pixel_offset(0, 768), None);
    }
}
