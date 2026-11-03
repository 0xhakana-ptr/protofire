//! arch/x86_64/src/boot.rs
//!
//! What x86_64's loaders hand over, and how the kernel hears about it.
//!
//! ## Two loaders, two conventions
//!
//! A multiboot2 loader — GRUB — enters `_start` with a magic in `%eax` and an
//! information structure's address in `%ebx`.  QEMU's `-kernel` reads the PVH
//! ELF note instead and enters with **no handshake at all**: there is nothing
//! in `%eax` to check.
//!
//! The boot assembly saves whatever arrived and marks the PVH path with a value
//! no multiboot2 magic can be, so this module's job is to read that and say
//! which loader it was.  It is the only place the two conventions are known;
//! the kernel names [`abi::Loader`] and nothing else.

/// The magic a multiboot2 loader passes in `%eax`.
pub const MULTIBOOT2_BOOTLOADER_MAGIC: u32 = 0x36D7_628D;

/// What the boot assembly records when the PVH note brought it up.
///
/// `u32::MAX` is not a magic any loader passes, and treating it as one would be
/// worse than a sentinel: the check below would pass for a loader that had done
/// something else entirely.
pub const PVH_HANDSHAKE_SENTINEL: u32 = 0xFFFF_FFFF;

/// The handshake, as the assembly saved it.
///
/// Set by `boot-x86-64.S` before it leaves 32-bit mode, and read exactly once
/// by [`boot_info`].  A `static mut` would be the usual shape; this is a
/// [`SyncUnsafeCell`] because a bare `UnsafeCell` is `!Sync` and the assembly
/// writes through the symbol's address rather than through Rust.
static HANDSHAKE: cell::SyncUnsafeCell<u32> = cell::SyncUnsafeCell::new(0);

/// Where the assembly writes the handshake.
///
/// # Safety
///
/// Called only from the boot assembly, before any Rust code runs, with the
/// value the loader put in `%eax`.
#[unsafe(no_mangle)]
pub fn record_handshake(magic: u32) {
    // SAFETY: the write happens once, before any other Rust code runs and
    // before interrupts are enabled, so no other access can be concurrent.
    unsafe { *HANDSHAKE.get() = magic };
}

/// Which loader brought this image up.
///
/// A value that is neither magic nor the sentinel is not something this machine
/// can explain, and the honest answer is to stop: continuing would read
/// whatever is at the information address, which on a machine that did not load
/// us there is not memory we own.
pub fn boot_info() -> abi::BootInfo {
    // SAFETY: the assembly wrote this once before Rust ran; nothing mutates it
    // afterwards, so reading it here is a read of a value that is already
    // final.
    let magic = unsafe { *HANDSHAKE.get() };
    let loader = match magic {
        MULTIBOOT2_BOOTLOADER_MAGIC => abi::Loader::Multiboot2,
        PVH_HANDSHAKE_SENTINEL => abi::Loader::Pvh,
        other => {
            crate::serial::write_str("protofire: unknown boot handshake: magic=");
            crate::serial::write_u32(other);
            crate::serial::write_str("\n");
            crate::halt()
        }
    };
    abi::BootInfo { loader }
}

/// What the device tree said: nothing, because this machine has none.
///
/// x86_64's loaders hand over a multiboot2 structure or a PVH start info block,
/// not a flattened tree.  The function exists on every machine so the kernel
/// asks one question and prints one line, and an answer of `None` here is the
/// answer rather than a gap.
pub fn device_tree_summary() -> Option<abi::DeviceTreeSummary> {
    None
}

/// The machine's PCIe configuration window: none, because x86_64 does not have
/// one.
///
/// Its configuration space is reached through the `0xCF8`/`0xCFC` ports, which
/// a `PortConfig` drives.  The function exists on every machine so the kernel
/// asks one question and gets an answer rather than a machine condition.
pub fn pcie_ecam_window() -> Option<(usize, usize)> {
    None
}

/// The window a PCIe host bridge assigns BARs from: none.
///
/// x86_64's firmware has already run the assignment pass by the time this
/// kernel starts, so every BAR holds an address and nothing needs to allocate
/// one.  The function exists on every machine so the caller asks one question.
pub fn pcie_memory_window() -> Option<(u64, u64)> {
    None
}

/// The interrupt controller's two windows: this machine has none of that shape.
///
/// x86_64's controller is not two memory windows.  The 8259 is two port ranges
/// and the IOAPIC is a single window addressed through a register pair, so a
/// `(distributor, cpu)` pair is not this machine's model.  `None` says so, and
/// the kernel's controller setup reports that this machine has no such answer
/// rather than inventing one.
pub fn interrupt_controller() -> Option<(usize, usize)> {
    None
}

/// The GICv2m frame: this machine has none.
///
/// The frame is a GICv2 mechanism.  x86_64's message-signalled interrupts go
/// through the APIC's own address range, which this crate does not drive yet.
pub fn msi_frame() -> Option<usize> {
    None
}

/// The machine's memory, as the loader described it.
///
/// `None`, and the reason is a gap rather than a fact about the machine: this
/// crate reads the multiboot2 handshake's magic and nothing else, so the memory
/// map the same structure carries is not parsed.  A caller treats `None` as
/// "use the pool's own span", which on a machine whose RAM is smaller than that
/// span would hand out frames that are not there.
///
/// Parsing the map is the change that fills this in; it is listed in
/// `docs/migration.md`.
pub fn managed_pool_bytes() -> Option<usize> {
    None
}
