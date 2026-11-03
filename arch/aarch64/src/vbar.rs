//! arch/aarch64/src/vbar.rs
//!
//! The exception vector table, and the register that installs it.
//!
//! ## The layout
//!
//! `VBAR_EL1` names a 2 KiB-aligned table of sixteen entries, 128 bytes each:
//!
//! | offset | when |
//! |---|---|
//! | `0x000` | current EL, stack pointer not shared: synchronous |
//! | `0x080` | current EL, stack pointer not shared: IRQ |
//! | `0x100` | current EL, stack pointer not shared: FIQ |
//! | `0x180` | current EL, stack pointer not shared: SError |
//! | `0x200` | current EL, stack pointer shared: the same four |
//! | `0x400` | lower EL, 64-bit: the same four |
//! | `0x600` | lower EL, 32-bit: the same four |
//!
//! The kernel runs at EL1 with its own stack pointer, so the first four are the
//! ones it takes.  The "shared" group is the same privilege with `SP_EL0`, and
//! the lower-EL groups are what a user program's exception arrives through.
//!
//! ## Why each entry has a lot of room
//!
//! 128 bytes is thirty-two instructions.  The architecture gives each entry
//! that much because a handler is expected to save the context it needs
//! *before* branching anywhere — there is no stack switched for it, and using
//! the interrupted one requires knowing what is safe to clobber.
//!
//! This table's entries jump to one common path after saving the registers a
//! C function may clobber, which is the same shape x86_64's stub table has.

use core::mem::size_of;

/// One entry's stride.  The architecture fixes it at 128 bytes.
pub const ENTRY_STRIDE: usize = 128;

/// The entries: four groups of four.
pub const ENTRIES: usize = 16;

/// The table's size, which is what the alignment has to be a multiple of.
pub const TABLE_SIZE: usize = ENTRIES * ENTRY_STRIDE;

/// Which group an entry belongs to.
///
/// The architecture's own division: where the exception came from, and whether
/// the stack pointer was shared.  A handler that did not know the difference
/// would use the wrong stack for a user program's exception.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Group {
    /// The current exception level, on its own stack pointer.  What a fault
    /// inside the kernel is.
    CurrentOwnStack,
    /// The current exception level, on `SP_EL0`.  What a fault inside the
    /// kernel is when the kernel is using the user's stack.
    CurrentSharedStack,
    /// A 64-bit lower level.  What a system call and a user fault are.
    Lower64,
    /// A 32-bit lower level.  A case this kernel does not support, and the
    /// entry reports it rather than pretending.
    Lower32,
}

/// Which kind of exception an entry is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Synchronous,
    Irq,
    Fiq,
    SError,
}

impl Kind {
    /// The offset of this kind within a group.
    pub const fn offset(self) -> usize {
        match self {
            Kind::Synchronous => 0,
            Kind::Irq => 1,
            Kind::Fiq => 2,
            Kind::SError => 3,
        }
    }
}

impl Group {
    /// The offset of this group within the table.
    pub const fn offset(self) -> usize {
        match self {
            Group::CurrentOwnStack => 0,
            Group::CurrentSharedStack => 4,
            Group::Lower64 => 8,
            Group::Lower32 => 12,
        }
    }
}

/// The byte offset of one entry.
pub const fn entry_offset(group: Group, kind: Kind) -> usize {
    (group.offset() + kind.offset()) * ENTRY_STRIDE
}

/// A table of sixteen entries, aligned as the register requires.
///
/// 2 KiB, because `VBAR_EL1`'s low eleven bits are reserved and a table that
/// did not respect them is one the machine reads from a shifted base.
#[repr(C, align(2048))]
pub struct Table {
    /// The entries themselves.  Each is filled by the assembly's own code, so
    /// this is a byte array rather than sixteen structures: an entry is
    /// instructions, not a value.
    entries: [u8; TABLE_SIZE],
}

impl Table {
    /// An empty table, which is a table nothing has filled and therefore one no
    /// vector should reach.
    pub const fn new() -> Table {
        Table {
            entries: [0; TABLE_SIZE],
        }
    }

    /// The table's address, which is what `VBAR_EL1` takes.
    pub fn address(&self) -> usize {
        self as *const Table as usize
    }
}

impl Default for Table {
    fn default() -> Self {
        Self::new()
    }
}

// The table is one contiguous run of `TABLE_SIZE` bytes and the alignment is
// what the register needs.  A structure whose size disagreed with the stride
// would put an entry's code at the wrong offset, and the machine would branch
// into the middle of it.
const _: () = assert!(size_of::<Table>() == TABLE_SIZE);
const _: () = assert!(TABLE_SIZE == 2048);

#[cfg(test)]
mod tests {
    use super::ENTRY_STRIDE;
    use super::Group;
    use super::Kind;
    use super::TABLE_SIZE;
    use super::Table;
    use super::entry_offset;

    /// The table is 2 KiB and aligned to it, which is what `VBAR_EL1` requires.
    #[test]
    fn the_table_is_aligned_as_the_register_requires() {
        use core::mem::align_of;
        use core::mem::size_of;
        assert_eq!(size_of::<Table>(), TABLE_SIZE);
        assert_eq!(align_of::<Table>(), 2048);
        assert_eq!(TABLE_SIZE, 2048);
    }

    /// The four groups and four kinds give sixteen entries, each 128 bytes
    /// apart.
    ///
    /// The architecture fixes the stride; a table that used any other would put
    /// an entry's code where the machine does not branch.
    #[test]
    fn the_entries_are_128_bytes_apart() {
        assert_eq!(ENTRY_STRIDE, 128);
        assert_eq!(entry_offset(Group::CurrentOwnStack, Kind::Synchronous), 0);
        assert_eq!(entry_offset(Group::CurrentOwnStack, Kind::Irq), 128);
        assert_eq!(entry_offset(Group::CurrentOwnStack, Kind::Fiq), 256);
        assert_eq!(entry_offset(Group::CurrentOwnStack, Kind::SError), 384);
    }

    /// Each group starts where the architecture puts it.
    #[test]
    fn the_groups_are_where_the_architecture_puts_them() {
        assert_eq!(
            entry_offset(Group::CurrentOwnStack, Kind::Synchronous),
            0x000
        );
        assert_eq!(
            entry_offset(Group::CurrentSharedStack, Kind::Synchronous),
            0x200
        );
        assert_eq!(entry_offset(Group::Lower64, Kind::Synchronous), 0x400);
        assert_eq!(entry_offset(Group::Lower32, Kind::Synchronous), 0x600);
    }

    /// A fresh table is all zeros, and its address is what the register takes.
    #[test]
    fn a_fresh_table_is_empty_and_addressable() {
        let table = Table::new();
        assert!(table.entries.iter().all(|byte| *byte == 0));
        assert_eq!(table.address(), &table as *const Table as usize);
    }
}
