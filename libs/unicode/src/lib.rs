//! libs/unicode/src/lib.rs
//!
//! Unicode conversion and normalisation, as a library with no filesystem in it.
//!
//! ## Why this is a crate and not a filesystem module
//!
//! Every algorithm here was filed under `src/fs/unicode/` because the
//! filesystems were the only callers.  That is a statement about today's
//! callers, not about the code: nothing in this crate names a filesystem, a
//! device, a lock, or the kernel, the dependencies are `core` and `alloc` and
//! there are no others.  A pure algorithm's home follows what it is.
//!
//! Filing it by caller has a cost that shows up on a move: a doc test written
//! against the path the code had, `use fs::unicode::…`, keeps compiling because
//! the module it names happens to contain it.  Written against `unicode::…`,
//! the compiler is what checks the name.
//!
//! ## What belongs here
//!
//! A conversion or a comparison between character encodings, and the tables
//! that drive it.  What does not: any policy about which filesystem uses which
//! code page, that is the caller's, and a crate that decided it would be
//! reachable only from the filesystems that agreed.
//!
//! ## The tables
//!
//! `casefold_tables` and `normalize_tables` are generated from the Unicode
//! Character Database and are tracked rather than built: regenerating them is a
//! deliberate act, done by a generator kept outside this crate.  They are
//! ordinary modules here so that this crate has no build script, a crate whose
//! contents change when a generator runs is harder to reason about than one
//! whose source is checked in.

#![no_std]

extern crate alloc;

pub mod casefold;
pub mod casefold_tables;
pub mod gb18030;
pub mod normalize;
pub mod normalize_tables;
pub mod oem;
pub mod utf16;
pub mod validate;

pub use casefold::eq_unicode_insensitive;
pub use oem::OemCodePage;
pub use oem::char_to_oem_byte;
pub use oem::oem_byte_to_char;
pub use oem::utf8_to_oem;
pub use utf16::utf8_to_utf16le;
pub use utf16::utf16le_code_unit_to_char;
pub use utf16::utf16le_to_utf8;
pub use utf16::write_utf16le_chars;
