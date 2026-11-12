//! drivers/virtio/net/src/lib.rs
//!
//! The virtio network card: two queues — receive and transmit — the ten-byte
//! header in front of every frame, and the address the device publishes.
//!
//! ## Why this crate is separate from `virtio_core`
//!
//! The framework does not know what a buffer means.  This crate is what says
//! "queue 0 is receive and queue 1 is transmit" and "the first ten bytes are
//! the device's header", and those are the things a network card has in common
//! with no other virtio device.
//!
//! It is also the second device on the framework, which is the reason the
//! framework's queue operations name a queue.  A block device has one queue and
//! could not tell the difference; a card with a receive ring and a transmit
//! ring is the device that proves the index is the one used.
//!
//! ## What is here, today
//!
//! The bring-up, and a frame in each direction: [`VirtioNet::submit_frame`]
//! puts a driver-readable header and a frame on the transmit queue, and
//! [`VirtioNet::post_receive_buffer`] posts a device-writable buffer that
//! [`VirtioNet::receive_frame`] drains.  [`frame::arp_request`] is the frame
//! that proves both, because QEMU's user-mode network answers one without any
//! configuration and the answer is 42 bytes of fields the driver wrote.
//!
//! ## What is not here
//!
//! A network stack.  No IP, no UDP, no DHCP: an ARP exchange is the smallest
//! thing that exercises both queues, and a stack above it is a different
//! project.
//!
//! ## The specification
//!
//! Virtio 1.2, section 5.1 (network device).  The queue numbering is 5.1.2, the
//! feature bits are 5.1.3, and the configuration layout is 5.1.4.  The header
//! is 5.1.6.1 and the two chains are 5.1.6.2.

#![no_std]

extern crate alloc;

pub mod config;
pub mod device;
pub mod features;
pub mod frame;
pub mod header;

pub use device::Health;
pub use device::RECEIVE_BUFFER_LEN;
pub use device::RECEIVE_QUEUE;
pub use device::TRANSMIT_QUEUE;
pub use device::Ticket;
pub use device::VirtioNet;
pub use features::VIRTIO_NET_F_MAC;
pub use frame::Arp;
pub use frame::arp_request;
pub use frame::parse_arp;
