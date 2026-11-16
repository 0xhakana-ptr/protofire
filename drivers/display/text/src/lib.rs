//! drivers/display/text/src/lib.rs
//!
//! A character grid over a framebuffer: the font, what a byte does to the
//! screen, and the surface a renderer fills.
//!
//! ## Why this is separate from `vga`
//!
//! `vga` is a device: its registers, its mode sequence, and the record of what
//! it became.  This crate is a renderer: it takes a mode and a surface and
//! draws characters, and it would draw on any framebuffer, which is the
//! question a `virtio_gpu` later asks.  Making the console a mode of the device
//! crate would mean a second display device could not have the same console.
//!
//! It names nothing of this tree either, so the whole of it, the grid's
//! arithmetic, the control characters, and the scrolling, is tested on a host
//! against a recording surface.

#![no_std]

extern crate alloc;

pub mod font;
pub mod grid;

pub use font::GLYPH_HEIGHT;
pub use font::GLYPH_WIDTH;
pub use font::row_pixel;
pub use grid::CellSurface;
pub use grid::Grid;
pub use grid::TAB_WIDTH;
pub use grid::glyph_rows;
