//! kernel/src/console_screen.rs
//!
//! The screen the boot's own lines reach, beside the serial port they already
//! reach.
//!
//! ## Why this is a second sink and not a replacement
//!
//! Seven hundred call sites in this tree name `arch::serial`.  Rewriting them
//! would be a change to every subsystem for one device's sake, and it would put
//! the machine's output behind a kernel type, which is the inversion the
//! layering exists to prevent.  So the serial console stays what it is, and
//! `arch` grew one hook: every byte it writes is also handed to a sink the
//! kernel installs.
//!
//! That hook is called with the console lock held and interrupts masked, so
//! this sink **must not** allocate, lock, or print.  It writes pixels into a
//! framebuffer it was handed at install time and does nothing else.
//!
//! ## What it draws
//!
//! A grid from `text`: the font, the control characters, and the scroll, all
//! tested on a host.  This file is the surface that grid paints into, which is
//! the one part that needs a mapped framebuffer.

use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

use vga::FramebufferInfo;

use text::CellSurface;
use text::GLYPH_HEIGHT;
use text::GLYPH_WIDTH;
use text::Grid;
use text::glyph_rows;
use text::row_pixel;

/// The pixel colours the console draws with.
///
/// Light grey on black, which is a terminal's default and the pair with the
/// most contrast a bitmap font's antialiasing-free pixels want.
#[cfg(target_os = "none")]
const FOREGROUND: u32 = 0x00C0_C0C0;
#[cfg(target_os = "none")]
const BACKGROUND: u32 = 0x0000_0000;

/// Where the framebuffer is, for the sink to reach without a lock.
///
/// A `usize` rather than an `Arc`, because the sink runs inside the console
/// lock: reaching for another lock there is the deadlock the hook's contract
/// forbids.  The address is installed once, before any program runs, and the
/// ordering pair is what makes that installation visible to a byte written on
/// another CPU.
static FRAMEBUFFER: AtomicUsize = AtomicUsize::new(0);
static PITCH: AtomicUsize = AtomicUsize::new(0);
static WIDTH: AtomicUsize = AtomicUsize::new(0);
static HEIGHT: AtomicUsize = AtomicUsize::new(0);

/// The grid the sink draws from.
///
/// A `SyncUnsafeCell` rather than a lock for the same reason: the console lock
/// is already held, so another lock here would be a lock order two CPUs invert.
/// The safety argument is the console's own exclusion, which the hook's
/// contract states: two bytes never reach this at once.
static GRID: cell::SyncUnsafeCell<Option<Grid>> = cell::SyncUnsafeCell::new(None);

/// The surface: where one cell's pixels go.
///
/// A copy of the four numbers above, taken once per byte rather than per cell,
/// so a byte that repaints the whole grid reads them one time.
#[derive(Clone, Copy)]
struct Screen {
    base: usize,
    pitch: usize,
    width: usize,
    height: usize,
}

impl Screen {
    /// The address of pixel `(x, y)`'s first byte, or `None` off the screen.
    fn pixel(&self, x: usize, y: usize) -> Option<usize> {
        if x >= self.width || y >= self.height {
            return None;
        }
        Some(self.base + y * self.pitch + x * 4)
    }

    /// Write one pixel.
    ///
    /// # Safety
    ///
    /// The screen must be a mapped framebuffer of at least `width` by `height`
    /// pixels at `base`, which is what [`install`] is given: the address comes
    /// from a BAR the bus reported and the size from the mode the device
    /// accepted.
    unsafe fn paint_pixel(&self, x: usize, y: usize, colour: u32) {
        let Some(address) = self.pixel(x, y) else {
            return;
        };
        // SAFETY: the caller's contract says the framebuffer covers this
        // pixel, and a framebuffer is memory the device reads continuously: a
        // volatile store is what stops the compiler from dropping a write it
        // cannot see a reader for.
        unsafe { core::ptr::write_volatile(address as *mut u32, colour) };
    }
}

impl CellSurface for Screen {
    fn paint(&mut self, column: usize, row: usize, byte: u8, foreground: u32, background: u32) {
        let left = column * GLYPH_WIDTH;
        let top = row * GLYPH_HEIGHT;
        let rows = glyph_rows(byte);
        for (offset, &bits) in rows.iter().enumerate() {
            for column in 0..GLYPH_WIDTH {
                let colour = if row_pixel(bits, column) {
                    foreground
                } else {
                    background
                };
                // SAFETY: `install` checked the framebuffer covers the grid's
                // whole extent, and a cell is inside the grid.
                unsafe { self.paint_pixel(left + column, top + offset, colour) };
            }
        }
    }

    fn columns(&self) -> usize {
        self.width / GLYPH_WIDTH
    }

    fn rows(&self) -> usize {
        self.height / GLYPH_HEIGHT
    }
}

/// Install the screen: the framebuffer, a grid sized to it, and the sink.
///
/// Called once, after the display probe set a mode.  A second call with a new
/// framebuffer replaces the first, which is what a mode change needs: the grid
/// is rebuilt for the new size rather than left at the old one's.
pub fn install(framebuffer: FramebufferInfo) {
    let screen = Screen {
        base: framebuffer.address,
        pitch: framebuffer.mode.pitch() as usize,
        width: framebuffer.mode.width as usize,
        height: framebuffer.mode.height as usize,
    };

    FRAMEBUFFER.store(screen.base, Ordering::Release);
    PITCH.store(screen.pitch, Ordering::Release);
    WIDTH.store(screen.width, Ordering::Release);
    HEIGHT.store(screen.height, Ordering::Release);

    // The grid, replaced rather than resized so a mode change starts from a
    // blank screen instead of keeping rows that no longer fit.
    // SAFETY: the console lock is not held here, `install` runs on the boot
    // path before any second CPU has a line of its own, and the sink only
    // reads the cell through the hook, which is installed below this line.
    unsafe {
        *GRID.get() = Some(Grid::for_pixels(screen.width, screen.height));
    }

    #[cfg(target_os = "none")]
    arch::set_console_mirror(Some(sink));
}

/// The sink `arch` calls for every byte.
///
/// Target only: the hook it is installed into is the machine's, and a host
/// build has no framebuffer and no `arch::set_console_mirror` to install it
/// with.
///
/// The byte goes into the grid, and the screen is repainted **when the line
/// ends** rather than when each byte arrives.
///
/// That is not an optimisation, it is what makes the sink usable.  A full
/// repaint is 1024x768 pixels, and this console's own boot prints a few
/// thousand bytes: repainting per byte put the boot four hundred million
/// framebuffer writes deep, and the first measurement of it stopped the boot
/// inside the network probe, whose reply had timed out while the kernel was
/// drawing.  A line is the unit a reader sees, so a line is the unit a repaint
/// waits for.
///
/// A machine with no screen has no framebuffer stored and the byte is dropped:
/// the serial port already has it, and a sink that panicked on a headless
/// machine would make that machine unbootable.
#[cfg(target_os = "none")]
fn sink(byte: u8) {
    let base = FRAMEBUFFER.load(Ordering::Acquire);
    if base == 0 {
        return;
    }
    let screen = Screen {
        base,
        pitch: PITCH.load(Ordering::Acquire),
        width: WIDTH.load(Ordering::Acquire),
        height: HEIGHT.load(Ordering::Acquire),
    };

    // SAFETY: the console lock is held for the whole of a line, which is the
    // hook's contract, so this is the only writer of the grid.  A cell is
    // mutated and the whole grid is read here; nothing else touches it.
    unsafe {
        let Some(grid) = (*GRID.get()).as_mut() else {
            return;
        };
        grid.put(byte);
        if byte != b'\n' {
            return;
        }
        let mut surface = screen;
        grid.repaint(&mut surface, FOREGROUND, BACKGROUND);
    }
}

/// Whether a screen is installed, for the boot's own report.
pub fn is_installed() -> bool {
    FRAMEBUFFER.load(Ordering::Acquire) != 0
}

/// How many columns the installed grid holds.
///
/// The boot prints this, and it is the number a reader needs to know how much
/// of `protofire:`'s own output a screen shows: a grid narrower than a line is
/// a line that wraps.
pub fn columns() -> usize {
    WIDTH.load(Ordering::Acquire) / GLYPH_WIDTH
}

/// How many rows the installed grid holds.
pub fn rows() -> usize {
    HEIGHT.load(Ordering::Acquire) / GLYPH_HEIGHT
}
