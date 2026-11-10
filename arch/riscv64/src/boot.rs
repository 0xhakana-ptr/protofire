//! arch/riscv64/src/boot.rs
//!
//! What firmware hands this machine over, and the boot's answer about it.
//!
//! OpenSBI enters the image in S-mode with `a0` holding the hart id and `a1`
//! pointing at a flattened device tree, a device-tree machine's boot protocol
//! passes the tree in a register its own convention names, and there is no
//! handshake to check: the firmware either loaded us or it did not, and a boot
//! that got this far did.
//!
//! The entry assembly hands `a1` to [`riscv64_set_device_tree`], which takes
//! no arguments beyond it: `bootloader` is the protocol and it must not learn
//! which register held what.  So the machine records the pointer before that
//! call, and this module is the reader.  A `static` rather than a parameter
//! for the same reason the trap sink is: the value arrives at an entry
//! convention, and every consumer above is a function with no business
//! carrying a machine's register.
//!
//! `fdt` is the *format* and knows nothing about a machine.  Which register
//! the blob arrived in, how long it is, and whether this machine trusts it are
//! this crate's questions.  Everything above asks [`device_tree`] and gets a
//! parsed tree or nothing.

use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

/// The pointer firmware left in `a1`, as the entry assembly recorded it.
///
/// Zero means "no tree was handed over", which is the state a host build is in
/// and the state a boot that arrived some other way would be in.
static DEVICE_TREE_POINTER: AtomicUsize = AtomicUsize::new(0);

/// Called once, from the entry assembly, before anything reads the tree.
///
/// # Safety
///
/// `pointer` must be the address firmware put in `a1`, and the memory at it
/// must be a flattened device tree that stays mapped for the life of the boot.
/// This function records the number; [`device_tree`] is what reads through it,
/// and it checks the magic before trusting anything.
pub unsafe fn set_device_tree(pointer: usize) {
    DEVICE_TREE_POINTER.store(pointer, Ordering::Release);
}

/// `extern "C"` because `entry.S` calls it and the two files agree only on a
/// symbol.  It forwards to [`set_device_tree`], whose safety contract this
/// shares: what the assembly passes is what firmware left in `a1`.
///
/// # Safety
///
/// As [`set_device_tree`]: called once, from the entry, with the pointer
/// firmware supplied.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn riscv64_set_device_tree(pointer: usize) {
    // SAFETY: the caller's contract is this function's, once, from the entry,
    // with the machine's own register.
    unsafe { set_device_tree(pointer) };
}

/// `None` when the pointer was zero, when the magic is not `0xd00dfeed`, or
/// when the header names blocks past the blob.  A boot that gets `None` has a
/// console and a heap and nothing else, which is a state worth booting into
/// rather than dying in.
///
/// The blob's length is the header's own `totalsize`.  There is no way to ask
/// the firmware how long it is, and the header is the only claim available, so
/// this reads the first bytes, trusts the size in them, and hands the slice to
/// `fdt`, which bounds-checks every access against it.
pub fn device_tree() -> Option<fdt::Fdt<'static>> {
    let pointer = DEVICE_TREE_POINTER.load(Ordering::Acquire);
    if pointer == 0 {
        return None;
    }
    // SAFETY: the caller of `set_device_tree` promises the pointer names a
    // device tree that stays mapped for the life of the boot.  Reading the
    // header first is what makes the slice's length the blob's own claim rather
    // than a guess, and `fdt::Fdt::new` re-checks the magic and every offset
    // against that length.
    unsafe {
        let header = core::slice::from_raw_parts(pointer as *const u8, 40);
        let total = u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
        if total < 40 {
            return None;
        }
        let blob = core::slice::from_raw_parts(pointer as *const u8, total);
        fdt::Fdt::new(blob).ok()
    }
}

/// The rate the timer's counter runs at, as the tree states it.
///
/// RISC-V has no register that reports the `time` counter's rate, the number
/// exists nowhere in the machine but the device tree's `/cpus` node, which is
/// why a machine question is answered from a machine description and not from
/// a constant.  The fallback that answers `None` is honest: a tree that does
/// not say has a timer this kernel cannot convert durations for, and a caller
/// treats `None` as "no timer" rather than as a frequency of zero.
pub fn timebase_frequency() -> Option<u64> {
    let tree = device_tree()?;
    let root = tree.root().ok()?;
    let cpus = root.by_path("/cpus")?;
    let hertz = cpus.property("timebase-frequency")?.as_u32()?;
    (hertz != 0).then_some(hertz as u64)
}

/// `(base, length)` of a `pci-host-ecam-generic` node's `reg`, which is where
/// every function's configuration space is memory-mapped.  `None` when there is
/// no tree, no such node, or a node whose `reg` does not decode.
///
/// This is a machine question and not a driver's: the *format* of the
/// configuration space is `pci`'s, and where this machine put it is the
/// device tree's answer about hardware.
pub fn pcie_ecam_window() -> Option<(usize, usize)> {
    let tree = device_tree()?;
    let node = tree.find_compatible("pci-host-ecam-generic")?;
    let region = node.region()?;
    if region.address == 0 || region.size == 0 {
        return None;
    }
    Some((region.address as usize, region.size as usize))
}

/// The memory window a PCIe host bridge assigns device BARs from.
///
/// `(base, size)` of the first entry in the bridge's `ranges` whose space code
/// says **32-bit non-prefetchable memory** (`0x0200_0000`) or **64-bit memory**
/// (`0x0300_0000`).  That is where a device's BAR can be placed so the CPU can
/// reach it; the I/O window (`0x0100_0000`) is a range of port numbers and a
/// machine with no port space has no use for it.
///
/// On a machine with firmware, a PCI bus comes up already assigned and this
/// function is never needed.  A device-tree machine booted by OpenSBI has no
/// firmware pass that ran on the bridge, so every BAR reads zero and nothing
/// behind one is reachable, the registers, the queues, and the MSI-X table,
/// which lives in a BAR.
///
/// The window is a property of the *machine*, so it comes from the machine's
/// tree.  A `ranges` entry is
/// `(child address, parent address, length)` where the child address's first
/// cell is the space code and the number of cells is the node's own
/// `#address-cells` and the parent's, which for this tree's `virt` machine is
/// three and two.
pub fn pcie_memory_window() -> Option<(u64, u64)> {
    let tree = device_tree()?;
    let node = tree.find_compatible("pci-host-ecam-generic")?;
    let property = node.property("ranges")?;

    // The child side is the bridge's own `#address-cells`; the parent side is
    // the widths the bridge's parent declared, which is what its `ranges` are
    // stated in.
    let (child, _) = node.child_cells();
    let (parent, _) = node.reg_cells();
    let child = child as usize;
    let parent = parent as usize;
    // A `ranges` entry is at least space + address + length, and the bridge
    // this tree drives declares three and two.
    if child < 2 || parent == 0 {
        return None;
    }

    let mut cells = [0_u32; MAX_RANGES_CELLS];
    let mut length = 0;
    for cell in property.as_cells()? {
        if length == MAX_RANGES_CELLS {
            return None;
        }
        cells[length] = cell;
        length += 1;
    }

    let entry = child + 2 * parent;
    let mut at = 0;
    while at + entry <= length {
        let space = cells[at];
        let mut address: u64 = 0;
        for cell in &cells[at + 1..at + child] {
            address = (address << 32) | u64::from(*cell);
        }
        let mut size: u64 = 0;
        for cell in &cells[at + child + parent..at + entry] {
            size = (size << 32) | u64::from(*cell);
        }

        // `0x0200_0000` is 32-bit non-prefetchable memory and `0x0300_0000` is
        // 64-bit memory.  Both are places a BAR may go; the I/O window is a
        // range of port numbers, which a machine with no port space cannot
        // use.
        if (space == 0x0200_0000 || space == 0x0300_0000) && size != 0 {
            return Some((address, size));
        }
        at += entry;
    }
    None
}

/// The most cells a `ranges` property's entries are read through.
///
/// Sixteen entries of two address cells and two size cells is sixty-four; a
/// bridge that described more windows than this has a layout this tree does not
/// read, and the answer is "no window" rather than the first one of a
/// truncated list.
const MAX_RANGES_CELLS: usize = 64;

/// The interrupt controller's window, as the tree describes it.
///
/// `(base, size)`.  A PLIC's `reg` is **one** window: its register groups, ///
/// priorities, pending, enables and the context blocks, are all offsets inside
/// it, which is what this module's `plic` sibling reads.  The first version of
/// this reader asked for two regions, because that is a GIC's shape, and the
/// answer on this machine was `None` for a controller that was right there.
///
/// The compatible strings are the two spellings of the same register layout:
/// `riscv,plic0` is the specification's and `sifive,plic-1.0.0` the original
/// implementor's, and this tree's machine declares both.
pub fn interrupt_controller() -> Option<(usize, usize)> {
    let tree = device_tree()?;
    let node = tree
        .find_compatible("riscv,plic0")
        .or_else(|| tree.find_compatible("sifive,plic-1.0.0"))?;

    let region = node.region()?;
    if region.address == 0 || region.size == 0 {
        return None;
    }
    Some((region.address as usize, region.size as usize))
}

/// This hart's PLIC context number, as the tree's `interrupts-extended` lists
/// it.
///
/// The property is a list of `(phandle, number)` pairs, one per consumer: the
/// `number` is the interrupt the PLIC delivers to that consumer, and the
/// per-hart interrupt controller's are **M-mode 11 and S-mode 9** (`0x0b` and
/// `0x09`).  So a context's index in the PLIC is not the hart id: it is the
/// consumer's position, and S-mode on hart N is context `2N+1` because each
/// hart contributes its M-mode consumer first.
///
/// This reads the tree rather than computing `2N+1`, because the numbering is
/// the platform's and a board with a different arrangement would number them
/// differently.
pub fn plic_context_for_hart(hart: usize) -> Option<usize> {
    let tree = device_tree()?;
    let root = tree.root().ok()?;
    // By compatible, not by path: the window's address is the platform's and
    // a board that moved it would have a tree that says so.
    let node = tree
        .find_compatible("riscv,plic0")
        .or_else(|| tree.find_compatible("sifive,plic-1.0.0"))?;
    let property = node.property("interrupts-extended")?;
    let mut cells = [0u32; MAX_INTERRUPTS_EXTENDED_CELLS];
    let mut cell_count = 0;
    for cell in property.as_cells()? {
        if cell_count == MAX_INTERRUPTS_EXTENDED_CELLS {
            return None;
        }
        cells[cell_count] = cell;
        cell_count += 1;
    }

    // Which phandle belongs to this hart: its `cpu@<hart>` child's
    // `interrupt-controller` node.
    let cpus = root.by_path("/cpus")?;
    let cpu = cpus.children().find(|child| {
        child
            .reg()
            .next()
            .is_some_and(|region| region.address as usize == hart)
    })?;
    let intc = cpu.child("interrupt-controller")?;
    let wanted = intc.property("phandle")?.as_u32()?;

    // The pairs, in order; a pair whose number is 9 is this hart's S-mode
    // consumer, and its index among the pairs is the context number.
    let mut context = 0;
    let mut at = 0;
    while at + 1 < cell_count {
        if cells[at] == wanted && cells[at + 1] == 9 {
            return Some(context);
        }
        context += 1;
        at += 2;
    }
    None
}

/// The most cells [`plic_context_for_hart`] reads.
///
/// Sixteen consumers is thirty-two cells: a machine with more harts than this
/// tree describes (four) has more, and the answer for one past the bound is
/// "no context" rather than the first of a truncated list.
const MAX_INTERRUPTS_EXTENDED_CELLS: usize = 32;

pub fn plic_sources() -> Option<usize> {
    let tree = device_tree()?;
    let node = tree
        .find_compatible("riscv,plic0")
        .or_else(|| tree.find_compatible("sifive,plic-1.0.0"))?;
    Some(node.property("riscv,ndev")?.as_u32()? as usize)
}

/// The AIA's APLIC, when the tree describes one.
///
/// `(base, hart index, sources)`.  The APLIC is a **different controller** from
/// the PLIC, not a newer spelling of it: its enables are per domain, its
/// targets are per source, and its claim is in a per-hart delivery block.  A
/// machine built with `-machine virt,aia=aplic` or `aia=aplic-imsic` names it
/// instead of a PLIC, and a boot that asked only for `riscv,plic0` found no
/// controller at all — `no external interrupt controller`, which is the gap
/// this reader closes.
///
/// ## Which APLIC
///
/// QEMU's AIA machine describes **two**: a machine-mode one at `0xc000000` and
/// a supervisor-mode one at `0xd000000`, and the latter is the one whose
/// `riscv,delegate` names the first as its parent.  This kernel runs at S-mode,
/// so it wants the node the S-mode domain owns.  The tree marks that by placing
/// the *machine* node lower and giving the supervisor node a `riscv,delegate`
/// property holding the other's phandle; the reader below picks the node that
/// is **not** the delegate source, i.e. the one that is not named as
/// `msi-parent` by the other.
///
/// A machine with a single APLIC has no such pair, and the reader takes the
/// only node there is.
///
/// The hart index is the APLIC's own numbering for the harts it delivers to,
/// which is the delivery block's index: the machine's harts are its domain
/// targets, and the boot hart's index among them is what its target words name.
/// On these machines that index is the hart id, because the hart list the
/// tree gives is the machine's order.
pub fn aplic() -> Option<(usize, usize, usize)> {
    let tree = device_tree()?;
    let mut candidates = tree.all_compatible("riscv,aplic");
    let first = candidates.next()?;
    // A pair names the supervisor node by **not** being the other's msi-parent.
    // With one node there is nothing to choose, so it is the answer.
    let second = candidates.next();
    let node = match second {
        Some(second) => {
            let first_is_parent = first
                .property("msi-parent")
                .and_then(|property| property.as_u32())
                .zip(second.property("phandle").and_then(|p| p.as_u32()))
                .is_some_and(|(parent, phandle)| parent == phandle);
            if first_is_parent { second } else { first }
        }
        None => first,
    };

    let region = node.region()?;
    if region.address == 0 || region.size == 0 {
        return None;
    }
    let sources = node.property("riscv,num-sources")?.as_u32()? as usize;
    Some((region.address as usize, hart_index(), sources))
}

/// This hart's index among the machine's harts, as an APLIC target names it.
///
/// The APLIC's delivery blocks are numbered per hart in the machine's order,
/// and the hart the firmware cold-booted is the one this boot runs on.  On the
/// machines this tree boots the tree's hart list is ordered by id, so the index
/// is the hart id; a machine whose list was not ordered that way would need the
/// listing read, which is the change this comment exists to make visible.
#[cfg(target_os = "none")]
fn hart_index() -> usize {
    crate::smp::boot_hart()
}

/// A host build has no hart to index.
#[cfg(not(target_os = "none"))]
fn hart_index() -> usize {
    0
}

/// The AIA's supervisor IMSIC, when the tree describes one.
///
/// `(msi page base, stride, identities)`.  The base is hart index zero's file;
/// every hart's file is `stride` past the previous, and its **first page** is
/// where a device's message is written.
///
/// ## Which node
///
/// QEMU's AIA machine describes **two** IMSIC groups: a machine-mode one and a
/// supervisor-mode one.  They are told apart by `interrupts-extended`: the
/// pairs name each hart's per-hart controller and the cause it delivers on,
/// where **11 (0x0b) is machine mode and 9 (0x09) is supervisor mode**.  This
/// kernel runs at S-mode, so the node whose pairs carry 9 is the one it may
/// use, and the machine-mode one is not merely useless to it: writing through
/// those CSRs is a different privilege level's business.
///
/// ## The stride, and why it is not the `reg` size
///
/// Each node's `reg` is one file — `0x2000`, the MSI page and the register page
/// a device writes to — while consecutive harts' files are further apart than
/// that (`0x4000` on these machines).  The tree states no stride property, so
/// this reads it **from the tree's own geometry when it can**: the second
/// hart's file is at `stride` past the first, and a group's nodes are one per
/// hart.  A group with one hart has nothing to measure and the stride does not
/// matter, because no address is ever built from it.
///
/// A wrong stride here is caught rather than trusted: the boot's self-test
/// writes an identity into **this hart's own** file and claims it back, and a
/// message addressed to the wrong file is one this hart never receives.
pub fn imsic() -> Option<(usize, usize, usize)> {
    let tree = device_tree()?;
    let node = supervisor_imsic()?;
    let region = node.region()?;
    if region.address == 0 {
        return None;
    }
    let identities = node.property("riscv,num-ids")?.as_u32()? as usize;

    // The stride: how far the *next* node's `reg` starts, when the tree
    // describes more than one.  A single-file group answers the window's own
    // size, which is only used to build an address a second hart would need —
    // and a group with one file has no second hart.
    let mut others = tree.all_compatible("riscv,imsics");
    let stride = {
        let mut measured = region.size as usize;
        for candidate in &mut others {
            // By address, because two `Node`s are handles onto one blob rather
            // than values: the node this group is *at* is the one whose `reg`
            // says so.
            let Some(next) = candidate.region() else {
                continue;
            };
            if next.address as usize > region.address as usize {
                measured = next.address as usize - region.address as usize;
                break;
            }
        }
        measured
    };

    Some((region.address as usize, stride, identities))
}

/// The IMSIC node whose `interrupts-extended` names **supervisor** cause 9.
///
/// A machine-mode IMSIC's pairs carry cause 11.  A node with no
/// `interrupts-extended` at all is not one this reader can classify, so it is
/// refused rather than guessed at: reading a machine-mode file's CSRs from
/// S-mode is not a way to find out.
#[cfg(target_os = "none")]
fn supervisor_imsic() -> Option<fdt::Node<'static>> {
    let tree = device_tree()?;
    for node in tree.all_compatible("riscv,imsics") {
        let Some(property) = node.property("interrupts-extended") else {
            continue;
        };
        // The pairs are `(phandle, cause)`, and **any** pair naming 9 is this
        // node's supervisor half: the cause is the same for every hart in one
        // group on these machines.
        let mut cells = property.as_cells()?;
        let mut at = 0;
        while let Some(_phandle) = cells.next() {
            let Some(cause) = cells.next() else { break };
            if cause == 9 {
                return Some(node);
            }
            at += 2;
            let _ = at;
        }
    }
    None
}

/// A host build has no tree to read.
#[cfg(not(target_os = "none"))]
fn supervisor_imsic() -> Option<fdt::Node<'static>> {
    let _ = device_tree()?;
    None
}

/// The GICv2m frame's window: none, because this machine has no GIC.
///
/// A riscv64 machine signals interrupts through its PLIC or, with the AIA, an
/// IMSIC; neither is a GICv2m frame, and `None` is the honest answer rather
/// than a window that would name something the tree does not contain.
pub fn msi_frame() -> Option<usize> {
    None
}

/// Where the tree said the console is, for a boot line.
///
/// Kept beside the window queries because it is the same kind of answer: a fact
/// about this machine that a reader can compare against a machine.
pub fn console_address() -> usize {
    device_tree()
        .and_then(|tree| tree.find_compatible("ns16550a"))
        .and_then(|node| node.region())
        .map_or(0, |region| region.address as usize)
}

/// What the tree said, for a boot line and for a reader comparing a log against
/// a machine.
///
/// `None` when no tree was handed over or the one that was does not parse.  The
/// four numbers are the ones that tell "the tree worked" from "the fallback
/// worked", which are two different machines to debug.
pub fn device_tree_summary() -> Option<abi::DeviceTreeSummary> {
    let tree = device_tree()?;
    let version = tree.version()?;
    let root = tree.root().ok()?;

    // Memory regions, counted the way `paging::device_windows` collects them:
    // by `device_type`, because that is what identifies a memory node.
    let mut memory_regions = 0;
    let mut regions = [(0_u64, 0_u64); 4];
    crate::paging::collect_memory(root, &mut regions, &mut memory_regions);

    let uart = tree
        .find_compatible("ns16550a")
        .and_then(|node| node.region())
        .map_or(0, |region| region.address as usize);

    Some(abi::DeviceTreeSummary {
        version,
        memory_regions: memory_regions as u32,
        uart,
    })
}

/// Which loader brought this image up.
///
/// A device tree, because that is the only convention both firmware paths
/// share.  Whether the tree *parsed* is a separate question, answered by
/// [`device_tree`]: a boot line that said "dtb" for a pointer that is not a tree
/// would be reporting the register rather than the machine.
pub fn boot_info() -> abi::BootInfo {
    abi::BootInfo {
        loader: abi::Loader::DeviceTree,
    }
}

/// The machine's memory, as the device tree describes it.
///
/// The sum of every `device_type = "memory"` region.  This is what a boot hands
/// the frame allocator: the pool is a linker-reserved span and can only manage
/// frames that are really there, so the machine's answer is the ceiling the
/// allocator clamps to.
///
/// `None` when there is no tree.  A caller treats that as "use the pool's own
/// span", which is what a machine with no memory description has.
pub fn managed_pool_bytes() -> Option<usize> {
    let tree = device_tree()?;
    let root = tree.root().ok()?;
    let mut regions = [(0_u64, 0_u64); 4];
    let mut count = 0;
    crate::paging::collect_memory(root, &mut regions, &mut count);
    if count == 0 {
        return None;
    }
    let total: u64 = regions[..count]
        .iter()
        .map(|(start, end)| end.saturating_sub(*start))
        .sum();
    Some(total as usize)
}

/// The most `cpu` nodes this function reads.
const MAX_HART_NODES: usize = 8;

/// The harts the tree says the machine has, in the tree's own order.
///
/// A `cpu` node's `reg` names its hart id, and its `status` says whether
/// firmware means to use it: a node with no status is usable, which is the
/// specification's default, and one marked `disabled` is not this boot's to
/// start.  The boot hart is *not* subtracted here, it is the caller's fact,
/// and subtracting it is the caller's decision.
///
/// `None` when there is no tree: a machine that cannot say what it has starts
/// none of it, which is the answer the tree's absence gets everywhere else.
pub fn hart_list() -> Option<([usize; MAX_HART_NODES], usize)> {
    let tree = device_tree()?;
    let root = tree.root().ok()?;
    let cpus = root.by_path("/cpus")?;

    let mut harts = [0usize; MAX_HART_NODES];
    let mut count = 0;
    for child in cpus.children() {
        if !child.name().starts_with("cpu@") {
            continue;
        }
        if child.property("device_type").and_then(|p| p.as_str()) != Some("cpu") {
            continue;
        }
        if child.property("status").and_then(|p| p.as_str()) == Some("disabled") {
            continue;
        }
        // The hart id is the `reg`'s only cell: `/cpus` declares one address
        // cell and no size, so the register decodes to the id and nothing
        // else.
        let Some(region) = child.reg().next() else {
            continue;
        };
        if count == MAX_HART_NODES {
            break;
        }
        harts[count] = region.address as usize;
        count += 1;
    }
    Some((harts, count))
}
