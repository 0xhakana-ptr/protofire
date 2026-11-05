//! libs/cell/src/lib.rs
//!
//! A `Sync`-capable `UnsafeCell`, for the statics a kernel needs and Rust does
//! not offer.
//!
//! ## What it is for
//!
//! A bare `UnsafeCell<T>` is `!Sync`, so it cannot be a `static`.  Architecture
//! code wants mutable statics whose access is serialised by something the
//! compiler cannot see, interrupts disabled, the boot CPU alone, an explicit
//! barrier, and this type lets those exist while keeping every access behind
//! an `unsafe` block the caller has to justify.
//!
//! ## Why it is its own crate
//!
//! It is four lines of `core` and a safety argument, and it is needed by the
//! heap, by the architecture crates, and by the shell's state.  Filed under any
//! one of them the others reach across a boundary; here it is a leaf that names
//! nothing, which is what a type this generic should be.
//!
//! The soundness argument is not in this crate and cannot be: whether two
//! accesses race is a fact about the caller's protocol.  What this crate
//! provides is the *permission* to write the `static`, not the proof that it is
//! safe, which is why `get` is `unsafe` and why the type is
//! `#[repr(transparent)]` over the cell it wraps.

#![no_std]

pub mod cell;
pub mod spin;

pub use cell::SyncUnsafeCell;
pub use spin::RawSpin;
