//! drivers/storage/nvme/src/lib.rs
//!
//! The NVMe wire format: BAR0's registers, the two queue entries, and the
//! structures the controller answers with.
//!
//! ## Why the format is a crate of its own
//!
//! A command is 64 bytes wherever it is built, and BAR0's register offsets are
//! the same on every machine with a controller.  Those are facts about a
//! specification, not about a machine, so the whole of them compiles and is
//! tested on a host, and the half that needs a device, mapping a BAR, driving
//! the queues, and claiming a message, stays where the machine is.
//!
//! It is the same split `vga` and `text` make, and the reason is the same: a
//! layout that is only reachable by booting is a layout nobody checks, which is
//! how the previous tree carried an identify structure whose namespace count
//! was read from offset 95 when the specification puts it at 516.
//!
//! ## What the format is, in one paragraph
//!
//! The controller is programmed through BAR0's registers: `CC` turns it on,
//! `CSTS` says whether it is ready, `AQA`/`ASQ`/`ACQ` set up one admin queue
//! pair, and a page of doorbells at `0x1000` says "there is a new command" and
//! "I took a completion".  Commands are 64-byte submission entries in a ring;
//! completions are 16-byte entries in another, each carrying the command id it
//! answers and a phase bit that flips every time the ring wraps.  Two commands
//! are enough to learn what the device is: `Identify Controller` and
//! `Identify Namespace`, and from those a driver knows the namespace's size and
//! its logical block size.

#![no_std]

// The identify tests build a page-shaped answer, which needs a buffer.
extern crate alloc;

pub mod command;
pub mod identify;
pub mod queue;
pub mod registers;

pub use command::CQE_SIZE;
pub use command::DEFAULT_QUEUE_SIZE;
pub use command::NVM_FLUSH;
pub use command::NVM_READ;
pub use command::NVM_WRITE;
pub use command::NvmeCqe;
pub use command::NvmeNamespace;
pub use command::NvmeSqe;
pub use command::SQE_SIZE;
pub use identify::CONTROLLER_NAMESPACE_COUNT_OFFSET;
pub use identify::IDENTIFY_CONTROLLER_SIZE;
pub use identify::IDENTIFY_NAMESPACE_SIZE;
pub use identify::NAMESPACE_FLBAS_OFFSET;
pub use identify::NAMESPACE_LBA_FORMAT_COUNT;
pub use identify::NAMESPACE_LBA_FORMAT_OFFSET;
pub use identify::NAMESPACE_SIZE_OFFSET;
pub use identify::namespace_capacity;
pub use identify::namespace_count;
pub use identify::namespace_geometry;
pub use queue::CompletionQueue;
pub use queue::SubmissionQueue;
pub use queue::queue_size;
pub use registers::ADMIN_CREATE_IOCQ;
pub use registers::ADMIN_CREATE_IOSQ;
pub use registers::ADMIN_DELETE_IOCQ;
pub use registers::ADMIN_DELETE_IOSQ;
pub use registers::ADMIN_IDENTIFY;
pub use registers::CAP_DSTRD_MASK;
pub use registers::CAP_DSTRD_SHIFT;
pub use registers::CAP_MQES_MASK;
pub use registers::CC_EN;
pub use registers::CNS_IDENTIFY_CONTROLLER;
pub use registers::CNS_IDENTIFY_NAMESPACE;
pub use registers::CSTS_RDY;
pub use registers::NVME_DOORBELL_BASE;
pub use registers::NVME_PAGE_SIZE;
pub use registers::NVME_REG_ACQ;
pub use registers::NVME_REG_AQA;
pub use registers::NVME_REG_ASQ;
pub use registers::NVME_REG_CAP;
pub use registers::NVME_REG_CC;
pub use registers::NVME_REG_CSTS;
pub use registers::NVME_REG_VS;
pub use registers::doorbell;
pub use registers::doorbell_stride;
pub use registers::run_prp;
