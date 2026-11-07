//! drivers/virtio/core/src/lib.rs
//!
//! The virtio framework: a split virtqueue, the feature bits a device and a
//! driver negotiate, the status a device goes through before it may be used,
//! and the PCI modern transport that carries all three.
//!
//! ## What "framework" means here
//!
//! Virtio is one protocol with several devices behind it.  A block device, a
//! network card and a GPU all: negotiate a feature set, stand up one or more
//! virtqueues, put buffers on a queue, ring a doorbell, and read completions
//! back.  What differs is the *payload*, a request header, a packet, a
//! command stream, and the payload is the device crate's.
//!
//! So this crate holds everything that is true of every virtio device and
//! nothing that is true of one.  It names no device crate, and no device crate
//! should have to reach through another device's code to get to a queue.
//!
//! ## What is testable on a host, and what is not
//!
//! The virtqueue is arithmetic over three rings in memory.  A test can build
//! one over a `Vec`, hand it descriptors, and read back what the "device" did
//! by writing into the rings, no MMIO, no PCI, no emulator.  That is why the
//! queue is in this crate and separate from the transport: the queue's
//! correctness is checkable, and the transport's is a boot.
//!
//! The transport is a set of register accesses at addresses a machine chose.
//! On a host there are none, so its host arm is a stub that reports "no
//! device" rather than pretending.
//!
//! ## The specification
//!
//! Virtio 1.2.  Section references in comments are to that document, and they
//! are the authority for a layout rather than any kernel's source: a field's
//! offset and a flag's meaning are the specification's to state.

#![no_std]

extern crate alloc;

pub mod features;
pub mod pci_transport;
pub mod queue;
pub mod status;
pub mod transport;

pub use features::Features;
pub use pci_transport::PciTransport;
pub use pci_transport::RegisterFile;
pub use queue::VirtQueue;
pub use queue::VirtQueueError;
pub use status::Status;
pub use transport::Capability;
pub use transport::Transport;
