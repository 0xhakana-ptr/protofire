//! drivers/storage/ahci/src/lib.rs
//!
//! The AHCI wire format: BAR5's registers, a port's register block, the three
//! structures a command is built from, and the identify structure a SATA
//! device answers with.
//!
//! ## Why the format is a crate of its own
//!
//! A command header is 32 bytes wherever it is built, and BAR5's register
//! offsets are the same on every machine with a controller.  Those are facts
//! about a specification, not about a machine, so the whole of them compiles
//! and is tested on a host, and the half that needs a device -- finding the
//! function on the bus, mapping BAR5, driving the port's engine -- stays
//! where the machine is.  It is the same split `nvme` and `vga` make, and the
//! reason is the same: a layout that is only reachable by booting is a layout
//! nobody checks.
//!
//! ## What this module is a relocation of
//!
//! The previous tree's AHCI driver was 1,085 lines inside its x86_64
//! architecture crate: register definitions, wire structures, the controller,
//! the bus probe and the block device in one file, behind a module whose very
//! name named a machine.  That is the shape this tree's `check-arch-fanout`
//! refuses -- an architecture crate that names the block layer and the driver
//! registry -- so the work is a **relocation** rather than a port: the
//! specification's half moves here, where a host test can hold it, and the
//! machine's half moves into the kernel's own file.
//!
//! ## What the relocation corrected, beyond the layout
//!
//! Two defects came with the move, and both are assertions in this crate so
//! the next reader cannot reintroduce them:
//!
//! - The command header's `CFL` -- the command FIS's length in dwords -- was
//!   left zero.  A controller is entitled to refuse that and QEMU's does, which
//!   means every command the previous driver submitted was refused before the
//!   device ever saw one.  The length is now the five dwords a Register FIS is.
//! - The port the driver drove was hardcoded to zero with a comment promising
//!   to find the real one later.  Reading `PI` and `PxSSTS.DET` is the
//!   machine's half, and it is the kernel file's job now -- but the reason it
//!   must is stated here, because a hardcoded port is a defect a relocation
//!   that copied the sequence would have carried along.

#![no_std]

// The identify tests build a page-shaped answer, which needs a buffer.
extern crate alloc;

pub mod command;
pub mod identify;
pub mod registers;

pub use command::ATA_FLUSH_CACHE;
pub use command::ATA_IDENTIFY_DEVICE;
pub use command::ATA_READ_DMA_EXT;
pub use command::ATA_WRITE_DMA_EXT;
pub use command::CL_ENTRY_SIZE;
pub use command::CL_SLOTS;
pub use command::CL_TOTAL_SIZE;
pub use command::CT_BASE_SIZE;
pub use command::CT_TOTAL_SIZE;
pub use command::MAX_PRDT;
pub use command::PRDT_ENTRY_SIZE;
pub use command::REGISTER_FIS_BYTES;
pub use command::REGISTER_FIS_DWORDS;
pub use command::RFIS_SIZE;
pub use command::command_header;
pub use command::h2d_fis;
pub use command::prdt_entry;
pub use identify::IDENTIFY_BYTES;
pub use identify::capacity_blocks;
pub use identify::is_ata;
pub use identify::model;
pub use registers::AHCI_REG_BOHC;
pub use registers::AHCI_REG_CAP;
pub use registers::AHCI_REG_GHC;
pub use registers::AHCI_REG_IS;
pub use registers::AHCI_REG_PI;
pub use registers::AHCI_REG_VS;
pub use registers::CMD_CR;
pub use registers::CMD_FR;
pub use registers::CMD_FRE;
pub use registers::CMD_ST;
pub use registers::DET_PRESENT_AND_COMMUNICATING;
pub use registers::GHC_AE;
pub use registers::GHC_HR;
pub use registers::PIS_DHR;
pub use registers::PIS_TFES;
pub use registers::PORT_BASE;
pub use registers::PORT_CI;
pub use registers::PORT_CLB;
pub use registers::PORT_CLBU;
pub use registers::PORT_CMD;
pub use registers::PORT_COUNT;
pub use registers::PORT_FB;
pub use registers::PORT_FBU;
pub use registers::PORT_IE;
pub use registers::PORT_IS;
pub use registers::PORT_SACT;
pub use registers::PORT_SCTL;
pub use registers::PORT_SERR;
pub use registers::PORT_SIG;
pub use registers::PORT_SSTS;
pub use registers::PORT_STRIDE;
pub use registers::PORT_TFD;
pub use registers::SERR_CLEAR_ALL;
pub use registers::SSTS_DET_MASK;
pub use registers::TFD_ERR;
pub use registers::port_register;
