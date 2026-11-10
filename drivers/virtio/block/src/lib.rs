//! drivers/virtio/block/src/lib.rs
//!
//! The virtio block device: a request header, a data buffer and a status byte
//! on a virtqueue, answering `BlockDevice` and `QueuedBlockDevice`.
//!
//! ## What a block request is (specification section 5.2.6)
//!
//! Every request is a chain of three descriptors:
//!
//! ```text
//! { type, reserved, sector }   the driver writes  -> the device reads
//! [ data bytes ]               read: the device writes  |  write: it reads
//! { status }                   the device writes
//! ```
//!
//! The status byte is one of `OK`, `IOERR`, `UNSUPP` (5.2.6.1), and it is the
//! only error channel: the used ring reports a length, not a result.  A
//! request whose status is not `OK` failed even though the device completed it.
//!
//! ## Why this crate is separate from `virtio_core`
//!
//! The queue does not know what a buffer means.  This crate is what says "the
//! first buffer is a ten-byte header, the last is a status byte", and that is
//! the only thing a block device has in common with no other virtio device.
//!
//! ## What is here, today
//!
//! The request encoding and the device's state machine, with the transport in
//! `virtio_core`.  The driver is written against `Transport` rather than
//! against PCI, so a host test drives the same code the machine does with a
//! transport that answers from a byte array.

#![no_std]

extern crate alloc;

pub mod device;
pub mod request;

pub use device::REQUEST_QUEUE;
pub use device::VirtioBlock;
pub use request::RequestType;
pub use request::Status as RequestStatus;
