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
mod tests;
