//! libs/rights/src/lib.rs
//!
//! What a handle will be allowed to do: the rights bit flags, defined now so
//! that the day handles carry them is one definition away rather than a
//! convention away.
//!
//! Nothing consumes these constants yet, and this header says so plainly:
//! they are a reserved plot, like `sound`'s and `virt`'s, for the mechanism
//! `docs/roadmap.md` Level 10 describes, a filesystem checking a read
//! against the right the opener asked for, a device descriptor declaring what
//! its device supports, the audit log opening its own file with one, and the
//! handle table storing the set.  The reason they are written down anyway is
//! that the flags themselves are the surface: adding a right means every
//! layer that checks one has to learn it, and a single definition is what
//! makes that a compile error where the flags are used rather than a silent
//! disagreement between two copies.
//!
//! The module is separate from `lib.rs` so that the flags keep the path their
//! doc comments use (`rights::rights::HANDLE_RIGHT_READ` reads as a
//! tautology, so the re-export below is what callers will name).

#![no_std]

pub mod rights;

pub use rights::HANDLE_RIGHT_READ;
pub use rights::HANDLE_RIGHT_WRITE;
