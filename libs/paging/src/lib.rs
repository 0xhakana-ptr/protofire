//! libs/paging/src/lib.rs
//!
//! Page tables: what one is, what an entry says, and the arithmetic that walks
//! one.
//!
//! ## Why this is a crate of its own
//!
//! Two crates below the machine need the same thing and may not depend on each
//! other: `arch` encodes an entry and installs a table, and `memory` hands out
//! the frames a table is built in.  Keeping the table here means neither
//! reaches across — and `arch` sits at layer 3 while `memory` is at 4, so the
//! edge between them would be upward, which the layering gate refuses.
//!
//! The crate names nothing: not a machine, not a frame allocator, not a lock.
//! A page table is a page of numbers, and the walk over it is arithmetic.
//!
//! ## What is the machine's and what is not
//!
//! | Question | Whose |
//! |---|---|
//! | What bit 0 of an entry means | the machine's, in `arch` |
//! | Which bits of an address select which level | here, and tested |
//! | How large a leaf covers | here, and tested |
//! | The instruction that installs a table | the machine's, in `arch` |
//! | The memory a table occupies | `memory`'s, from its frame pool |
//!
//! The split is why a host test can build a table, map an address and assert
//! what a walk finds: the arithmetic is here and the machine is one function
//! that turns an entry into a word.

#![no_std]

pub mod index;
pub mod table;

pub use index::Cache;
pub use index::ENTRIES_PER_TABLE;
pub use index::Level;
pub use index::PAGE_SIZE;
pub use index::Permissions;
pub use index::index;
pub use index::page_base;
pub use index::span;
pub use table::Entry;
pub use table::EntryEncoding;
pub use table::PageTable;
pub use table::Translation;
