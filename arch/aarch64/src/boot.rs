//! arch/aarch64/src/boot.rs
//!
//! What firmware hands this machine over: a device tree, and the boot's answer
//! about it.
//!
//! A device-tree machine's boot protocol passes a pointer to a flattened device
//! tree in a register its own convention names — `x0` on aarch64, `a1` on
//! riscv64 — and there is no handshake to check: the firmware either loaded us
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
    // SAFETY: the caller's contract is this function's — once, from the entry,
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
/// the firmware how long it is, and the header is the only claim available — so
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
