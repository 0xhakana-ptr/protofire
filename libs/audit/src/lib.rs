//! libs/audit/src/lib.rs
//!
//! The audit record: its fixed layout, its event types, and the ring buffer the
//! kernel keeps them in.
//!
//! ## What is here, and what is not
//!
//! The record and the buffer are data: a 256-byte struct with a documented
//! layout, an enable mask, and a ring of them.  Nothing here opens a file, asks
//! who the current process is, or knows that a boot command line exists.
//!
//! Persistence is not here, and deliberately: opening a log file through the
//! filesystem and the boot argument that asks for one name `fs` and the
//! scheduler, so they move with the filesystem rather than with the record.
//!
//! ## Why the record is `repr(C)`-shaped rather than a Rust struct
//!
//! It is written to a file and read back by a parser that is not this crate,
//! //! the tests and the boot gates both decode the bytes, so its layout is a
//! format, not an implementation detail.  The tests pin the field offsets for
//! that reason: a field inserted in the middle would change every offset after
//! it and the readers would disagree with the writer silently.

#![no_std]

extern crate alloc;

pub mod buffer;
pub mod types;

pub use buffer::AuditBuffer;
pub use types::AuditEventType;
pub use types::AuditRecord;
