//! drivers/bus/pci/src/lib.rs
//!
//! PCI: finding a device, and reading the addresses a machine gave it.
//!
//! ## What this crate is, and what it is not
//!
//! It is the *bus*: how to enumerate a PCI bus, how to walk a device's
//! capability list, and how to decode a BAR into the address and length of the
//! window it names.  It is not a driver for anything on the bus, the virtio
//! block driver, the network card and whatever comes next are above it.
//!
//! That is the same split `block` makes for disk devices: a bus is a way to
//! reach devices, not one of the devices.
//!
//! ## Why configuration access is a trait
//!
//! PCI gives a device 256 bytes of configuration space (4096 with PCIe) holding
//! its identity, its BARs and its capability list.  How a driver reaches those
//! bytes is the machine's business: x86_64 has the `0xCF8`/`0xCFC` port pair,
//! aarch64 and riscv64 use ECAM, memory-mapped configuration, because they
//! have no port space at all.
//!
//! [`ConfigSpace`] is the three operations both provide.  The enumeration above
//! it is written once against the trait, which means a host test drives the
//! real scanning code against a fake register file rather than against a
//! machine it does not have.
//!
//! ## The layout
//!
//! Address `(bus, device, function, register)` as the specification defines it
//! (PCI 3.0 section 3.2.2.3.2 for the port mechanism):
//!
//! ```text
//! bit 31      enable
//! bits 30..24 reserved
//! bits 23..16 bus
//! bits 15..11 device
//! bits 10..8  function
//! bits 7..2   register (dword index)
//! bits 1..0   zero
//! ```

#![no_std]

// A test builds a fake register file, and a register file is a map.
#[cfg(test)]
extern crate alloc;

pub mod bar;
pub mod config;
pub mod device;
pub mod enumerate;
pub mod msix;

pub use bar::Bar;
pub use bar::BarKind;
pub use config::ConfigSpace;
pub use config::DeviceAddress;
pub use config::EcamConfig;
pub use config::PortConfig;
pub use config::VendorId;
pub use device::Device;
pub use device::Scan;
pub use device::scan_all;
pub use enumerate::Assignment;
pub use enumerate::assign_memory_bars;
pub use msix::Capability as MsixCapability;
pub use msix::Entry as MsixEntry;
