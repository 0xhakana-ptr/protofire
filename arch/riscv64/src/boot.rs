//! arch/riscv64/src/boot.rs
//!
//! What firmware hands this machine over.
//!
//! A device-tree machine's boot protocol passes a pointer to a flattened device
//! tree in a register its own convention names — `x0` on aarch64, `a1` on
//! riscv64 — and there is no handshake to check: the firmware either loaded us
//! or it did not, and a boot that got this far did.
//!
//! The tree itself is not parsed yet.  What this returns is the one thing the
//! kernel's first stage needs: which loader, so the boot line says so.  Parsing
//! the tree is the next change that needs something out of it, and doing it
//! here is what keeps `fdt` out of every crate above.

/// Which loader brought this image up.
///
/// A device tree, because that is the only convention both firmware paths
/// share.  The register the pointer arrived in is not kept: nothing reads the
/// tree yet, and a stored pointer no code dereferences is a value that will be
/// wrong by the time something does.
pub fn boot_info() -> abi::BootInfo {
    abi::BootInfo {
        loader: abi::Loader::DeviceTree,
    }
}

/// What the device tree said: nothing yet.
///
/// This machine's firmware does hand over a tree in `a1`, and nothing records
/// it — the boot entry is not written, so there is no point at which the
/// register is read.  `None` is the honest answer until that entry exists, and
/// the function exists now so the kernel's line does not need a machine
/// condition.
pub fn device_tree_summary() -> Option<abi::DeviceTreeSummary> {
    None
}

/// The machine's PCIe configuration window: none yet.
///
/// A riscv64 board's ECAM comes from the device tree, and this machine's boot
/// entry does not read one.  `None` says so rather than guessing an address.
pub fn pcie_ecam_window() -> Option<(usize, usize)> {
    None
}

/// The window a PCIe host bridge assigns BARs from: none yet.
///
/// A riscv64 board's window comes from the device tree, and this machine's boot
/// entry does not read one.
pub fn pcie_memory_window() -> Option<(u64, u64)> {
    None
}

/// The interrupt controller's two windows: none yet.
///
/// A riscv64 machine's PLIC is one window, and this crate drives none of it —
/// the boot entry does not exist.  `None` is the answer for a machine whose
/// controller this tree cannot reach.
pub fn interrupt_controller() -> Option<(usize, usize)> {
    None
}

/// The GICv2m frame: none yet.
///
/// A riscv64 machine has a PLIC and an IMSIC; neither is a GICv2m frame.
pub fn msi_frame() -> Option<usize> {
    None
}
