//! drivers/display/virtio_gpu/src/lib.rs
//!
//! The VirtIO GPU wire format: the control header every command carries, the
//! command and response numbers, the 2D command bodies, the 3D command bodies,
//! and the display-info answer.
//!
//! ## Why the format is a crate of its own
//!
//! A control header is 24 bytes on every machine, and `RESOURCE_CREATE_2D`'s
//! field order is the specification's wherever it is built.  Those are facts
//! about a specification rather than about a machine, so the whole of them
//! compiles and is tested on a host, and the half that needs a device --
//! mapping a BAR, posting the control queue, owning the scanout memory -- stays
//! where the machine is.  The same split `nvme`, `ahci` and `xhci` make.
//!
//! The split is not bookkeeping.  The previous tree's driver carried wire
//! errors that a host test of this crate would have caught before a boot:
//! `CTX_CREATE` written as `0x0201` where the specification's enum makes it
//! `0x0200`, `CTX_DESTROY` as `0x0202` where it is `0x0201`, `SUBMIT_3D` as
//! `0x0208` where it is `0x0207`; `RESOURCE_CREATE_3D` naming `last_level`
//! `levels`, `nr_samples` `num_samples` and `flags` `stride`; and
//! `TRANSFER_HOST_3D` putting its resource id before the box the device reads
//! first.  Each is invisible to a driver that only prints the response it got
//! back, because a device answers a command it cannot parse with an error the
//! driver was already prepared to see.
//!
//! ## The two halves, and which one this boot proves
//!
//! The 2D half is what a framebuffer console needs: create a resource, attach
//! memory to it, point a scanout at it, upload the pixels, flush.  The 3D half
//! is VIRGL over the same control queue, and it needs a host with a rendering
//! capability the emulator only offers when its display backend has OpenGL.
//! This crate holds both -- the wire format does not depend on which one a
//! machine can run -- and the machine's half is where "this boot has no VIRGL"
//! is answered.

#![no_std]

pub mod command;
pub mod display;

pub use command::ATTACH_BACKING_SIZE;
pub use command::CTRL_HEADER_SIZE;
pub use command::CTX_CREATE_SIZE;
pub use command::CTX_DESTROY_SIZE;
pub use command::Command;
pub use command::FORMAT_B8G8R8X8_UNORM;
pub use command::RESOURCE_CREATE_2D_SIZE;
pub use command::RESOURCE_CREATE_3D_SIZE;
pub use command::RESOURCE_FLUSH_SIZE;
pub use command::RESOURCE_UNREF_SIZE;
pub use command::RESPONSE_ERROR_BASE;
pub use command::Response;
pub use command::SET_SCANOUT_SIZE;
pub use command::SUBMIT_3D_SIZE;
pub use command::TRANSFER_TO_HOST_2D_SIZE;
pub use command::TRANSFER_TO_HOST_3D_SIZE;
pub use command::attach_backing;
pub use command::ctrl_header;
pub use command::ctrl_header_fenced;
pub use command::ctx_create;
pub use command::ctx_destroy;
pub use command::resource_create_2d;
pub use command::resource_create_3d;
pub use command::resource_flush;
pub use command::resource_unref;
pub use command::response_is_error;
pub use command::set_scanout;
pub use command::submit_3d;
pub use command::transfer_to_host_2d;
pub use command::transfer_to_host_3d;
pub use display::DisplayInfo;
pub use display::DisplayMode;
pub use display::MAX_SCANOUTS;
pub use display::RESPONSE_DISPLAY_INFO_SIZE;
