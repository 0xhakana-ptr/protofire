//! drivers/virtio/net/src/lib.rs
//!
//! The virtio network card: two queues — receive and transmit — a header this
//! driver does not yet write, and the address the device publishes.
//!
//! ## Why this crate is separate from `virtio_core`
//!
//! The framework does not know what a buffer means.  This crate is what says
//! "queue 0 is receive and queue 1 is transmit", and that is the only thing a
//! network card has in common with no other virtio device.
//!
//! It is also the second device on the framework, which is the reason the
//! framework's queue operations name a queue.  A block device has one queue and
//! could not tell the difference; a card with a receive ring and a transmit
//! ring is the device that proves the index is the one used.
//!
//! ## What is here, today
//!
//! The bring-up: the status sequence, the feature negotiation, and both queues
//! sized, programmed and enabled.  No frames yet — that is the next change, and
//! it is a change to this crate rather than to the framework.
//!
//! ## The specification
//!
//! Virtio 1.2, section 5.1 (network device).  The queue numbering is 5.1.2, the
//! feature bits are 5.1.3, and the configuration layout is 5.1.4.

#![no_std]

extern crate alloc;

pub mod config;
pub mod device;
pub mod features;

pub use device::RECEIVE_QUEUE;
pub use device::TRANSMIT_QUEUE;
pub use device::VirtioNet;
pub use features::VIRTIO_NET_F_MAC;
