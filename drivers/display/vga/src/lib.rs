//! drivers/display/vga/src/lib.rs
//!
//! The bochs-display: its register block, its mode-set sequence, and the
//! record a probe hands to whatever draws.
//!
//! ## Why this crate names nothing
//!
//! A register map is a description of a device, not an act on one: the
//! `VBE_DISPI_*` indices are numbers the device defines, and the sequence that
//! programs a mode is a list of writes to them.  None of that needs a machine,
//! so all of it compiles and is tested on a host, and the part that does need
//! one, mapping a BAR and reaching it, stays where the machine is.
//!
//! That is the same split `virtio_core` makes one shelf over: the framework and
//! the wire format are portable, and the transport is not.
//!
//! ## What the device is
//!
//! QEMU's `std` VGA is a bochs-display: vendor `0x1234`, device `0x1111`.  It
//! offers two ways to reach the `VBE_DISPI` registers, and they differ in more
//! than convenience:
//!
//! - a **flat** window, where register `i` is a `u16` at `BAR2 + 0x500 + 2*i`;
//! - an **index/data** pair, where a write to `0x0` selects a register and a
//!   read or write of `0x4` is that register.
//!
//! A machine has one or the other, and the probe decides which.  This crate
//! holds both and the caller says which it found.
//!
//! ## What it does not do
//!
//! It does not draw.  The record it answers, [`FramebufferInfo`], is what a
//! console needs to draw with, and the console is a separate body of work: a
//! device and a renderer are two things, and the old tree had them as two
//! files for the same reason.

#![no_std]

// The tests record the order of a sequence, which needs a growable buffer.
extern crate alloc;

pub mod mode;
pub mod registers;

pub use mode::FramebufferInfo;
pub use mode::Mode;
pub use mode::set_mode;
pub use registers::BOCHS_DEVICE_ID;
pub use registers::BOCHS_VENDOR_ID;
pub use registers::RegisterBlock;
pub use registers::VBE_DISPI_ENABLED;
pub use registers::VBE_DISPI_INDEX_BPP;
pub use registers::VBE_DISPI_INDEX_ENABLE;
pub use registers::VBE_DISPI_INDEX_ID;
pub use registers::VBE_DISPI_INDEX_XRES;
pub use registers::VBE_DISPI_INDEX_YRES;
pub use registers::VBE_DISPI_LFB_ENABLED;
pub use registers::VBE_DISPI_NOCLEARMEM;
pub use registers::VbeLayout;
pub use registers::probe_id;
