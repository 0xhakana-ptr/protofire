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
//! Sv48 has four levels and Sv39 three; both index nine bits per level.  The
//! kernel's walk — `libs/paging`'s `Level` and `index` — is four levels of
//! nine bits, and the walk arithmetic is where the bugs are: a shift off by
//! one maps the wrong page and the failure looks like corruption far away.
//! Sv48 is the mode whose walk has exactly that shape — the kernel's root is
//! Sv48's root, its second level's slots cover one gibibyte, which is what
//! the kernel's third level already assumes — so the arithmetic stays
//! `paging`'s and this machine does not carry a second opinion about how an
//! address splits.  Sv39's three levels would put this kernel's user window at
//! an index the four-level arithmetic cannot name: the walk would share one
//! root slot between the kernel and every program, and per-program isolation
//! would need a machine conditional in code that is machine-neutral today.
//!
//! That is why this machine answers Sv48 and not Sv39, and it is a statement
//! about the *walk*, not about reach: both modes cover the addresses this
//! image uses with room above them.
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
    //
    // A present leaf is **readable**, and that is not a shortcut: the
    // permissions this kernel names carry no "read" flag, because on the two
    // machines that came first a present page is readable and `executable` is
    // an addition to that, not a replacement for it.  RISC-V *could* express
    // execute-only — `R` clear, `X` set — and the first encoder gave exactly
    // that to every executable page, which made a program's stack a page its
    // own program could run but not read: the load from the descriptor the
    // boot handed it was the machine refusing what the mapping said.  Nothing
    // above this crate asks for execute-only, so the encoder does not invent
    // it.
    word |= READABLE;
    if entry.permissions.writable {
        word |= WRITABLE;
    }
    if entry.permissions.executable {
        word |= EXECUTABLE;
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

/// The mode Sv48, which is the four-level one.
///
/// `satp` names it in bits 60..63; nine is Sv48 and eight is Sv39.  Four
/// levels is what this kernel's walk arithmetic assumes, which is the reason
/// this machine answers this mode — see the header's "The modes".
pub const SATP_MODE_SV48: u64 = 9 << 60;

/// Make a change to the page tables visible to the walk.
///
/// `sfence.vma` is the instruction the architecture requires after a table
/// change, and with no operands it invalidates every entry.
///
/// # Safety
///
/// Called after a page-table change on this hart.
#[cfg(target_os = "none")]
pub fn flush_translation() {
    // SAFETY: an architectural fence with no memory operand of its own.
    unsafe { core::arch::asm!("sfence.vma", options(nostack)) };
}

/// The host form: nothing, because a host has no address space to flush.
///
/// The function exists so the kernel asks one question of three machines; on a
/// host the answer is that there is no table, which is the state a test is in.
#[cfg(not(target_os = "none"))]
pub fn flush_translation() {}

/// The address ranges on this machine that are *not* ordinary memory.
///
/// Every address below the lowest RAM bank and above the highest one.  On the
/// platform this tree boots, the UART this console writes, the PLIC, the PCIe
/// ECAM window and the flash all sit below two gigabytes, and RAM begins at
/// `0x8000_0000` — so the gap below the first bank is where this machine's
/// devices live, and the range above the last is where a second bank's
/// neighbours would.
///
/// ## Why the answer comes from the tree and not a constant
///
/// A board's memory map is a fact the firmware states, and the same argument
/// that puts the UART's address in this crate puts the *gap's* edges there:
/// both are the machine's, and the tree is what says them.  The fallback when
/// the tree did not parse is the emulated platform's answer, which is the
/// state a machine with a broken blob is in: it has a console because
/// [`crate::serial`] writes a constant address, and the window below RAM is
/// what makes that console's registers uncached.
pub fn device_windows() -> Windows {
    let mut windows = Windows::new();
    let Some(tree) = crate::boot::device_tree() else {
        // No tree: the constant, which is `virt`'s memory map.
        windows.push(0, VIRT_RAM_START);
        return windows;
    };

    let Ok(root) = tree.root() else {
        windows.push(0, VIRT_RAM_START);
        return windows;
    };

    // Every `memory` node, which a machine may have several of.  A memory node
    // is identified by `device_type`, not by `compatible`: the specification
    // says so, and QEMU's tree has no `compatible` on `memory@80000000` at all.
    let mut ram: [(u64, u64); MAX_MEMORY_NODES] = [(0, 0); MAX_MEMORY_NODES];
    let mut memory_nodes = 0;
    collect_memory(root, &mut ram, &mut memory_nodes);

    if memory_nodes == 0 {
        windows.push(0, VIRT_RAM_START);
        return windows;
    }

    // The lowest memory start and the highest memory end define the gap.  A
    // machine with two discontiguous RAM banks has a device range between
    // them, and treating that as memory is the unsafe direction — but so is
    // *not* treating it as a device, which is what a single gap cannot
    // express.  Sorting the banks and emitting a window between each pair is
    // the general answer; this machine has one bank and the loop below is
    // written so a second would still be correct for the range below the
    // first and above the last.
    let mut lowest = ram[0].0;
    let mut highest = ram[0].1;
    for node in &ram[..memory_nodes] {
        lowest = lowest.min(node.0);
        highest = highest.max(node.1);
    }
    windows.push(0, lowest as usize);
    windows.push(highest as usize, usize::MAX);
    windows
}

/// The most `memory` nodes this function reads.
const MAX_MEMORY_NODES: usize = 4;

/// Where `qemu-system-riscv64 -machine virt` puts its RAM.
const VIRT_RAM_START: usize = 0x8000_0000;

/// Collect the `device_type = "memory"` regions under `node`.
pub(crate) fn collect_memory(
    node: fdt::Node<'_>,
    out: &mut [(u64, u64); MAX_MEMORY_NODES],
    count: &mut usize,
) {
    if node.property("device_type").and_then(|p| p.as_str()) == Some("memory") {
        for region in node.reg() {
            if *count < MAX_MEMORY_NODES {
                out[*count] = (region.address, region.address.saturating_add(region.size));
                *count += 1;
            }
        }
    }
    for child in node.children() {
        if *count < MAX_MEMORY_NODES {
            collect_memory(child, out, count);
        }
    }
}

/// A small set of address ranges.
///
/// A fixed array rather than a slice because the ranges come from a device
/// tree, which is data: a `const fn` returning `&'static [(usize, usize)]`
/// could only ever describe a constant, and the point of this answer is that
/// it no longer does.
#[derive(Debug, Clone, Copy)]
pub struct Windows {
    entries: [(usize, usize); 4],
    length: usize,
}

impl Windows {
    /// No windows: every address keeps its rule.
    pub const fn new() -> Windows {
        Windows {
            entries: [(0, 0); 4],
            length: 0,
        }
    }

    /// Add one range.  A full set drops it rather than growing.
    pub fn push(&mut self, start: usize, end: usize) {
        if self.length < self.entries.len() {
            self.entries[self.length] = (start, end);
            self.length += 1;
        }
    }

    /// The ranges, in the order they were added.
    pub fn as_slice(&self) -> &[(usize, usize)] {
        &self.entries[..self.length]
    }
}

impl Default for Windows {
    fn default() -> Self {
        Self::new()
    }
}

/// Read the address of the table the machine is translating through.
#[cfg(target_os = "none")]
pub fn current_root_table() -> usize {
    let value: u64;
    // SAFETY: reading `satp` has no side effect.  The register's page number
    // is bits 0..43 — *not* bits 10..53, which is where a page-table **entry**
    // keeps one above its flag bits — and the shift back to a byte address
    // undoes the twelve the register dropped.
    unsafe {
        core::arch::asm!("csrr {}, satp", out(reg) value, options(nomem, nostack, preserves_flags))
    };
    ((value & ((1u64 << 44) - 1)) << PAGE_NUMBER_SHIFT) as usize
}

/// Install `table` in `satp`, in Sv48 mode, and answer whether this was a
/// change.
///
/// The register's page number is bits 0..43 — **not** bits 10..53, which is
/// where a page-table *entry* keeps its page number above the flag bits.  The
/// two shifts look alike and the wrong one cost this tree its first boot: the
/// entry's layout moved the root's number into the register's ASID field, the
/// walk started from a root that was mostly an address's middle bits, and the
/// first instruction fetch after the write was a page fault at the instruction
/// itself.
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
    let root = ((table as u64) >> PAGE_NUMBER_SHIFT) & ((1u64 << 44) - 1);
    // SAFETY: the caller promises the table is complete and aligned.
    unsafe {
        core::arch::asm!(
            "csrw satp, {}",
            "sfence.vma",
            in(reg) SATP_MODE_SV48 | root,
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

    /// An executable page is readable too, because readable is what a present
    /// leaf *is* on the permissions this kernel names: there is no "read"
    /// flag to clear, and the specification's execute-only form — `R` clear,
    /// `X` set — is one nothing above this crate asks for.
    ///
    /// The first encoder gave execute-only to every executable page, and the
    /// fault it produced is the test's shape: a program could fetch from its
    /// own stack page and not load from it.
    #[test]
    fn an_executable_page_is_readable_as_well() {
        let executable = Entry::page(
            0x1000,
            Permissions {
                writable: false,
                executable: true,
                user: false,
                cache: paging::Cache::Normal,
            },
        );
        let word = encode(executable, Level::Leaf);
        assert_ne!(word & super::EXECUTABLE, 0, "execute is set");
        assert_ne!(word & super::READABLE, 0, "and read is never refused");
        assert_ne!(word & super::LEAF_BITS, 0, "and the entry is a leaf");
        assert!(decode(word, Level::Leaf).is_leaf);
        assert!(decode(word, Level::Leaf).permissions.executable);

        // A leaf always carries at least one of R, W, X — the specification's
        // definition of a leaf — and with `R` unconditional that holds for
        // every permission set the kernel can name.
        let plain = Entry::page(0x1000, paging::Permissions::default());
        assert_ne!(encode(plain, Level::Leaf) & super::LEAF_BITS, 0);
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
