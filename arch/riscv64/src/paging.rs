//! arch/riscv64/src/paging.rs
//!
//! riscv64's page-table encoding, and the register that installs a table.
//!
//! ## The encoding
//!
//! A page-table entry is a *physical page number* — the address shifted down by
//! twelve, not kept whole — with ten flag bits above it:
//!
//! ```text
//! bits 0..9     flags: V, R, W, X, U, G, A, D, RSW
//! bits 10..54   the physical page number
//! ```
//!
//! Three differences from x86_64 matter here.  **The address is a page
//! number**, so it is shifted, which is the one place this machine's arithmetic
//! differs from the others.  **A leaf is a combination of permission bits**,
//! not a bit: an entry with V set and R, W or X clear names another table, and
//! one with any of them set is a leaf.  And **A and D are not optional**: a
//! leaf without the accessed bit faults, and without the dirty bit faults on a
//! write, so every leaf this crate encodes sets both — this tree does not
//! implement the fault that sets them.
//!
//! ## The modes
//!
//! Sv39 has three levels and Sv48 four.  Both index nine bits per level, so the
//! walk arithmetic is `paging`'s; what differs is where it starts, which is why
//! `satp` says the mode and this module does not assume one.
//!
//! ## On a host build
//!
//! A host has no `satp`, so `install` is absent.  The encoding is arithmetic
//! and a host test checks it.

use paging::Entry;
use paging::EntryEncoding;
use paging::Level;
use paging::Permissions;

/// Bit 0: the entry is valid.
pub const VALID: u64 = 1 << 0;
/// Bit 1: the page is readable.
pub const READABLE: u64 = 1 << 1;
/// Bit 2: the page is writable.
pub const WRITABLE: u64 = 1 << 2;
/// Bit 3: the page is executable.
pub const EXECUTABLE: u64 = 1 << 3;
/// Bit 4: user mode may access the page.
pub const USER: u64 = 1 << 4;

/// Bits 61..63: the Svpbmt memory-type field, when the extension is present.
///
/// **RISC-V has no cache bit in the base page-table entry.**  Cacheability is a
/// property of the *physical* address, configured in a platform's PMA, and a
/// machine that adds a per-mapping override does it with an extension —
/// `Svpbmt`, whose field says "this page is I/O" (value 2) rather than normal
/// memory.
///
/// This tree's target does not implement `Svpbmt`, so a device mapping here
/// cannot be marked uncached at the page-table level at all.  What the encoder
/// does is refuse to pretend: [`CrossMachine`] below is what a caller gets when
/// it asks for a device mapping on this machine, and it is an error rather than
/// a mapping that silently behaves like memory.
/// Bit 6: the page has been accessed.  A leaf without it faults.
pub const ACCESSED: u64 = 1 << 6;
/// Bit 7: the page has been written.  A leaf without it faults on a write.
pub const DIRTY: u64 = 1 << 7;

/// How far a physical address is shifted down to become a page number: the page
/// offset, twelve bits.
pub const PAGE_NUMBER_SHIFT: u64 = 12;

/// Where the page number starts in an entry: bit 10, above the flag bits.
///
/// This is the shift an encoder applies and a decoder undoes, and it is not the
/// same twelve as the page offset — a writer that put the page number at bit 0
/// would overlay it on the flags and produce an entry the machine reads as a
/// table pointer with a very small page number.
pub const PAGE_NUMBER_START: u64 = 10;

/// The bits a page number occupies: 44 of them, which covers 2^56 bytes.
pub const PAGE_NUMBER_MASK: u64 = (1u64 << 44) - 1;

/// The bits that make an entry a leaf, as the specification defines them: an
/// entry with V set and none of R, W, X is a pointer to the next table.
pub const LEAF_BITS: u64 = READABLE | WRITABLE | EXECUTABLE;

/// Encode an entry as the word the machine reads.
///
/// The address is shifted down to a page number, which is the one place this
/// machine's arithmetic differs from x86_64's and aarch64's: both keep the
/// address whole.
pub fn encode_at(entry: Entry, level: Level) -> u64 {
    if !entry.present {
        return 0;
    }
    let mut word =
        (((entry.address as u64) >> PAGE_NUMBER_SHIFT) & PAGE_NUMBER_MASK) << PAGE_NUMBER_START;
    word |= VALID;

    if !(entry.is_leaf || level == Level::Leaf) {
        // A pointer to the next table: V set, and no permission bits, which is
        // what the specification defines a non-leaf as.
        return word;
    }

    // The permission bits *are* what makes an entry a leaf on this machine, so
    // they are set from the permission and never from a constant: an entry
    // that ORed in `LEAF_BITS` and then added the real permission would give
    // an unexecutable page the execute bit.
    if entry.permissions.executable {
        word |= EXECUTABLE;
    } else {
        // Readable is required on a page that is not executable: an entry with
        // no R, W or X is a table pointer, so a page with none of them would
        // not be a page.  A non-executable leaf is therefore readable.
        word |= READABLE;
    }
    if entry.permissions.writable {
        word |= WRITABLE;
    }
    if entry.permissions.user {
        word |= USER;
    }
    // A and D are set unconditionally: this tree does not implement the faults
    // that would set them.
    word |= ACCESSED | DIRTY;
    word
}

/// Encode an entry with no level context: a table entry.
/// The level is accepted and unused, so that all three machines answer the same
/// signature.  Sv39 decides "leaf or not" from the `R`/`W`/`X` bits in the
/// entry itself, so no level changes this word; aarch64's does.
pub fn encode(entry: Entry, _level: Level) -> u64 {
    encode_at(entry, Level::Third)
}

/// Decode a word the machine wrote, at `level`.
pub fn decode(word: u64, level: Level) -> Entry {
    if word & VALID == 0 {
        return Entry::default();
    }
    let address = (((word >> PAGE_NUMBER_START) & PAGE_NUMBER_MASK) << PAGE_NUMBER_SHIFT) as usize;
    let is_leaf = word & LEAF_BITS != 0 || level == Level::Leaf;
    if !is_leaf {
        return Entry {
            address,
            permissions: Permissions::KERNEL_READ_WRITE,
            is_leaf: false,
            present: true,
        };
    }
    Entry {
        address,
        permissions: Permissions {
            writable: word & WRITABLE != 0,
            executable: word & EXECUTABLE != 0,
            user: word & USER != 0,
            // No bit to read: a mapping that was asked to be uncached decodes
            // as normal, because that is what the machine makes of it.
            cache: paging::Cache::Normal,
        },
        is_leaf: true,
        present: true,
    }
}

/// Why a device mapping cannot be encoded here.
///
/// The base RISC-V page table has no cache attribute.  A machine that carries
/// `Svpbmt` could set bits 61..63 and this module would; one that does not
/// cannot, and a mapping encoded as normal memory is one where a read of a
/// device register returns a cached value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrossMachine;

impl core::fmt::Display for CrossMachine {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(
            "this machine has no per-mapping cache attribute: a device mapping \
             would be encoded as normal memory",
        )
    }
}

/// The encoding, as the trait `paging` names.
pub struct Encoding;

impl EntryEncoding for Encoding {
    /// Sv39's word is the same at every level: a leaf is a combination of its
    /// `R`/`W`/`X` bits, and there is no page-versus-block encoding to choose.
    fn encode(entry: Entry, level: Level) -> u64 {
        encode(entry, level)
    }

    fn decode(word: u64, level: Level) -> Entry {
        decode(word, level)
    }
}

/// The mode Sv39, which is the three-level one.
///
/// `satp` names it in bits 60..63; eight is Sv39 and nine is Sv48.  This tree
/// uses Sv39.
pub const SATP_MODE_SV39: u64 = 8 << 60;

/// The address ranges on this machine that are *not* ordinary memory.
///
/// Empty, and it says nothing about the machine: riscv64 has no entry yet, so
/// there is no platform this crate can name a window for.  When the boot
/// arrives it will be the board's, and a board's window is a fact the device
/// tree states rather than one a constant can hold.
///
/// A `const fn` returning an empty slice rather than an absent function, so the
/// kernel asks one question of three machines and does not need to know which
/// one answered.
pub const fn device_windows() -> &'static [(usize, usize)] {
    &[]
}

/// Read the address of the table the machine is translating through.
#[cfg(target_os = "none")]
pub fn current_root_table() -> usize {
    let value: u64;
    // SAFETY: reading `satp` has no side effect.  The address is bits 0..44 as
    // a page number, which is what the shift undoes.
    unsafe {
        core::arch::asm!("csrr {}, satp", out(reg) value, options(nomem, nostack, preserves_flags))
    };
    (((value >> PAGE_NUMBER_START) & ((1u64 << 44) - 1)) << PAGE_NUMBER_SHIFT) as usize
}

/// Install `table` in `satp`, in Sv39 mode, and answer whether this was a
/// change.
///
/// # Safety
///
/// `table` must be a page-aligned root whose entries name physical memory and
/// whose mappings include the code performing this call.  Writing `satp` makes
/// the hart translate through it on the next memory access, and a `sfence.vma`
/// is what the architecture requires after the write.
#[cfg(target_os = "none")]
pub unsafe fn install(table: usize) -> bool {
    let previous = current_root_table();
    if previous == table {
        return false;
    }
    let root = (((table as u64) >> PAGE_NUMBER_SHIFT) & ((1u64 << 44) - 1)) << PAGE_NUMBER_START;
    // SAFETY: the caller promises the table is complete and aligned.
    unsafe {
        core::arch::asm!(
            "csrw satp, {}",
            "sfence.vma",
            in(reg) SATP_MODE_SV39 | root,
            options(nostack)
        );
    }
    true
}

#[cfg(test)]
mod tests {
    use super::ACCESSED;
    use super::DIRTY;
    use super::USER;
    use super::VALID;
    use super::decode;
    use super::encode;
    use super::encode_at;
    use paging::Entry;
    use paging::Level;
    use paging::Permissions;

    /// The address is a page number, so an entry's word is the address shifted
    /// down.
    ///
    /// This is the difference a copied encoder gets wrong: x86_64 and aarch64
    /// keep the address whole, and a port that did the same here would put the
    /// low twelve bits of the address where the flag bits are.
    #[test]
    fn the_address_is_a_page_number() {
        let entry = Entry::page(0x1234_5000, Permissions::KERNEL_READ_WRITE);
        let word = encode(entry, Level::Leaf);
        // The flags are bits 0..9 and the page number starts at bit 10, so the
        // mask is 0x3FF and not 0xFFF: a page number whose low bits are set
        // spills into bits 8 and 9, and a wider mask would read them as flags.
        assert_eq!(
            word & 0x3FF,
            super::VALID | super::READABLE | super::WRITABLE | super::ACCESSED | super::DIRTY,
            "bits 0..10 are flags; the page number starts above them"
        );
        assert_eq!(
            ((word >> super::PAGE_NUMBER_START) & super::PAGE_NUMBER_MASK)
                << super::PAGE_NUMBER_SHIFT,
            0x1234_5000 & !0xFFF,
            "the page number sits above the flags and is the address shifted down"
        );
        assert_eq!(decode(word, Level::Leaf).address, 0x1234_5000);
    }

    /// A leaf is a combination of permission bits; an entry with V set and none
    /// of R, W, X names another table.
    #[test]
    fn a_leaf_is_a_permission_and_a_table_is_none() {
        let table = Entry::table(0x4000_0000);
        let word = encode_at(table, Level::Third);
        assert_eq!(word & super::LEAF_BITS, 0, "a table has no permission bits");
        assert_eq!(word & VALID, VALID);

        let page = Entry::page(0x4000_0000, Permissions::KERNEL_READ_WRITE);
        let word = encode_at(page, Level::Leaf);
        assert_ne!(word & super::LEAF_BITS, 0, "a page has at least one");

        assert!(!decode(encode_at(table, Level::Third), Level::Third).is_leaf);
        assert!(decode(encode_at(page, Level::Leaf), Level::Leaf).is_leaf);
    }

    /// A and D are set on every leaf, because this tree does not implement the
    /// faults that would set them.
    ///
    /// A leaf without the accessed bit faults on first use, which on a machine
    /// that does not handle the fault is a boot that dies at the first page it
    /// touches.
    #[test]
    fn every_leaf_sets_accessed_and_dirty() {
        let word = encode(
            Entry::page(0x1000, Permissions::KERNEL_READ_WRITE),
            Level::Leaf,
        );
        assert_ne!(word & ACCESSED, 0);
        assert_ne!(word & DIRTY, 0);
        // Even a read-only page sets D: a page that is never written costs
        // nothing for the bit, and a fault on a write is a boot that dies.
        let read_only = encode(
            Entry::page(0x1000, Permissions::KERNEL_READ_EXECUTE),
            Level::Leaf,
        );
        assert_ne!(read_only & DIRTY, 0);
    }

    /// An executable page sets X and no R, which is the specification's
    /// execute-only form.
    ///
    /// The one thing it must not do is leave all three clear: an entry with V
    /// set and none of R, W, X names another table, so a page encoded that way
    /// would be walked as a table pointer.
    #[test]
    fn an_executable_page_sets_x_and_is_still_a_leaf() {
        let execute_only = Entry::page(
            0x1000,
            Permissions {
                writable: false,
                executable: true,
                user: false,
                cache: paging::Cache::Normal,
            },
        );
        let word = encode(execute_only, Level::Leaf);
        assert_ne!(word & super::EXECUTABLE, 0, "execute is set");
        assert_eq!(word & super::READABLE, 0, "read is the permission's answer");
        assert_ne!(word & super::LEAF_BITS, 0, "X alone is enough to be a leaf");
        assert!(decode(word, Level::Leaf).is_leaf);
        assert!(decode(word, Level::Leaf).permissions.executable);
    }

    /// The user bit is bit 4, and a kernel page does not have it.
    #[test]
    fn the_user_bit_says_who_may_reach() {
        let user = Entry::page(
            0x1000,
            Permissions {
                writable: true,
                executable: false,
                user: true,
                cache: paging::Cache::Normal,
            },
        );
        assert_ne!(encode(user, Level::Leaf) & USER, 0);
        assert_eq!(
            encode(
                Entry::page(0x1000, Permissions::KERNEL_READ_WRITE),
                Level::Leaf
            ) & USER,
            0
        );
    }

    /// A device mapping has no cache bit to set on this machine, and the
    /// encoder does not invent one.
    ///
    /// The base RISC-V page table has no cache attribute: cacheability is a
    /// property of the physical address, configured outside the table.  An
    /// encoder that set a bit anyway would be writing into the reserved field,
    /// and the machine would either ignore it or fault.
    #[test]
    fn a_device_mapping_has_nowhere_to_say_so() {
        let device = Entry::page(0xFE00_0000, Permissions::DEVICE);
        let word = encode(device, Level::Leaf);
        assert_eq!(word >> 61, 0, "the Svpbmt field is not used");
        assert_eq!(
            decode(word, Level::Leaf).permissions.cache,
            paging::Cache::Normal,
            "the machine reads it as normal memory, and so does the decoder"
        );
    }

    /// An absent entry is zero.
    #[test]
    fn an_absent_entry_is_zero() {
        assert_eq!(encode(Entry::EMPTY, Level::Leaf), 0);
        assert_eq!(decode(0, Level::Leaf), Entry::default());
    }
}
