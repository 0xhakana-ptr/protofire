//! arch/aarch64/src/boot.rs
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
