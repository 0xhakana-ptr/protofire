//! crypto/src/lib.rs
//!
//! The cryptographic primitives the kernel uses, as a library with no kernel in
//! it.
//!
//! ## Why this is a crate and not a module
//!
//! Four subsystems needed the same algorithms and none of them owned them: the
//! filesystem hashes streams and checksums clusters, the network derives keys
//! and verifies signatures, the encrypted-zone mount runs PBKDF2 and AES-XTS,
//! and the kernel's own password check salts and hashes.  Filed under any one
//! of them, the other three reach across a boundary that says they may not.
//!
//! The dependencies are the argument: this crate names `core`, `alloc` and
//! `abi` — the error type it returns — and nothing else.  That is what makes it
//! testable on the host, where every one of these algorithms has published test
//! vectors to check against and a boot is not needed to run one.
//!
//! ## What belongs here
//!
//! An algorithm over bytes: a hash, a cipher, a MAC, a key agreement, a
//! signature check.  What does not: anything that reads a device, knows a
//! filesystem, or decides a policy.  A function here takes a slice and returns
//! a value, which is also why the tests can be exhaustive over known-answer
//! vectors rather than over a boot.

#![no_std]

extern crate alloc;

pub mod crypto;

pub use crypto::*;
