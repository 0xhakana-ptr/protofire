//! arch/aarch64/src/boot.rs
//!
//! What firmware hands this machine over: a device tree, and the boot's answer
//! about it.
//!
//! A device-tree machine's boot protocol passes a pointer to a flattened device
//! tree in a register its own convention names, `x0` on aarch64, `a1` on
//! riscv64, and there is no handshake to check: the firmware either loaded us
//! or it did not, and a boot that got this far did.
//!
//! ## Where the pointer goes
//!
//! The entry assembly hands `x0` to `protofire_entry`, which takes no
//! arguments: `bootloader` is the protocol and it must not learn which register
//! held what.  So the machine records the pointer before that call, and this
//! module is the reader.
//!
//! A `static` rather than a parameter for the same reason the trap sink is: the
//! value arrives at an entry convention, and every consumer above is a function
//! with no business carrying a machine's register.
//!
//! ## Why the tree is parsed here and not above
//!
//! `fdt` is the *format* and knows nothing about a machine.  Which register the
//! blob arrived in, how long it is, and whether this machine trusts it are this
//! crate's questions.  Everything above asks [`device_tree`] and gets a parsed
//! tree or nothing.

use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

/// The pointer firmware left in `x0`, as the entry assembly recorded it.
///
/// Zero means "no tree was handed over", which is the state a host build is in
/// and the state a boot that arrived some other way would be in.
static DEVICE_TREE_POINTER: AtomicUsize = AtomicUsize::new(0);

/// Record the device tree pointer the assembly passed.
///
/// Called once, from the entry assembly, before anything reads the tree.
///
/// # Safety
///
/// `pointer` must be the address firmware put in `x0`, and the memory at it
/// must be a flattened device tree that stays mapped for the life of the boot.
/// This function records the number; [`device_tree`] is what reads through it,
/// and it checks the magic before trusting anything.
pub unsafe fn set_device_tree(pointer: usize) {
    DEVICE_TREE_POINTER.store(pointer, Ordering::Release);
}

/// The entry the assembly calls, by the name the linker resolves.
///
/// `extern "C"` because `entry.S` calls it and the two files agree only on a
/// symbol.  It forwards to [`set_device_tree`], whose safety contract this
/// shares: what the assembly passes is what firmware left in `x0`.
///
/// # Safety
///
/// As [`set_device_tree`]: called once, from the entry, with the pointer
/// firmware supplied.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aarch64_set_device_tree(pointer: usize) {
    // SAFETY: the caller's contract is this function's, once, from the entry,
    // with the machine's own register.
    unsafe { set_device_tree(pointer) };
}

/// The tree firmware handed over, if it handed one over.
///
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

/// The machine's PCIe configuration window, if the tree describes one.
///
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
/// ## Why this is read rather than assumed
///
/// On a machine with firmware, a PCI bus comes up already assigned and this
/// function is never needed.  A device-tree machine booted directly has no
/// firmware to run that pass, so every BAR reads zero and nothing behind one is
/// reachable, the registers, the queues, and the MSI-X table, which lives in a
/// BAR.
///
/// The window is a property of the *machine*, so it comes from the machine's
/// tree.  A `ranges` entry is
/// `(child address, parent address, length)` where the child address's first
/// cell is the space code and the num ber of cells is the node's own
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

/// The interrupt controller's two windows, as the tree describes them.
///
/// `(distributor, cpu_interface)`.  A GIC's `reg` has two entries, the
/// distributor and the CPU interface, and both are needed: the first decides
/// which lines exist and which CPU they go to, the second is what this core
/// acknowledges and finishes through.
///
/// The compatible string names a GIC version this kernel's [`crate::gic`]
/// implements.  `arm,cortex-a15-gic` is GICv2, and a machine with a GICv3 has a
/// `reg` whose second entry does not exist, its CPU interface is system
/// registers rather than memory.  So this refuses anything it does not
/// recognise rather than reading two windows that are not two.
///
/// `None` when there is no tree, no controller, or one of a version this crate
/// does not drive.
pub fn interrupt_controller() -> Option<(usize, usize)> {
    let tree = device_tree()?;
    let node = tree
        .find_compatible("arm,cortex-a15-gic")
        .or_else(|| tree.find_compatible("arm,gic-400"))?;

    let mut regions = node.reg();
    let distributor = regions.next()?;
    let cpu = regions.next()?;
    if distributor.address == 0 || cpu.address == 0 {
        return None;
    }
    Some((distributor.address as usize, cpu.address as usize))
}

/// The GICv2m frame's window, if the machine has one.
///
/// An MSI-X device raises an interrupt by writing to an address, and the frame
/// is what turns that write into one of the controller's lines.  Without it a
/// machine has no way to deliver a message-signalled interrupt, and a driver
/// falls back to its INTx pin, which is the table this tree could not read.
///
/// The node is a child of the interrupt controller and is identified by
/// `compatible = "arm,gic-v2m-frame"`.  Its `reg` is one window; the two
/// numbers it can raise are in `MSI_TYPER`, which [`crate::gicv2m::Frame`]
/// reads at run time rather than this function guessing.
pub fn msi_frame() -> Option<usize> {
    let tree = device_tree()?;
    let node = tree.find_compatible("arm,gic-v2m-frame")?;
    let region = node.region()?;
    (region.address != 0).then_some(region.address as usize)
}

/// Where the tree said the console is, for a boot line.
///
/// Kept beside the window queries because it is the same kind of answer: a fact
/// about this machine that a reader can compare against a machine.
pub fn console_address() -> usize {
    device_tree()
        .and_then(|tree| tree.find_compatible("arm,pl011"))
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
        .find_compatible("arm,pl011")
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
