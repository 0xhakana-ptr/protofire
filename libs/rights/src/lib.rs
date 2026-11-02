//! libs/rights/src/lib.rs
//!
//! What a handle may do: the rights bit flags every layer names.
//!
//! Two constants, and the reason they are a crate rather than a convention: a
//! device descriptor declares which rights its device supports, the filesystem
//! checks them before answering a read, the audit log opens its own file with
//! one, and the handle table stores them.  A set of flags that four layers need
//! is not a reason for those layers to depend on each other, so they sit at the
//! bottom, below `device`, `fs`, `audit` and `process` alike.
//!
//! This is the smallest crate in the tree and it is not a placeholder: adding a
//! right means every layer that checks one has to learn it, and a single
//! definition is what makes that a compile error where the flags are used
//! rather than a silent disagreement between two copies.
//!
//! The module is separate from `lib.rs` so that the flags keep the path their
//! doc comments and callers already use (`rights::rights::HANDLE_RIGHT_READ`
//! reads as a tautology, so the re-export below is what callers name).

#![no_std]

pub mod rights;

pub use rights::HANDLE_RIGHT_READ;
pub use rights::HANDLE_RIGHT_WRITE;
