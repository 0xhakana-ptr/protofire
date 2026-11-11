//! tools/xtask/src/machine.rs
//!
//! The machines this tool knows: the triple each one builds for, the emulator
//! that runs it, and the arguments that describe its hardware.
//!
//! The gate's expectations are a separate subject and a separate file,
//! [`crate::gate`].  Both are `impl Machine` blocks, which is what shows a
//! reader they describe one type rather than two that agree by arrangement.

use std::path::Path;

/// The machines this tree knows how to build for.
///
/// The target triple is the whole of the selection: `arch` names its
/// implementation in a `cfg(target_arch)` table, so a triple that no crate has
/// an implementation for fails to build rather than picking one silently.
///
/// The accepted spellings are the ones the target triples use, `x86_64`, not
/// `x8664`, because a caller reads them from `rustc --print target-list` and
/// from every other command in this tree.  An alias that disagreed with the
/// thing it names is a papercut the previous tree's `Makefile` had in the other
/// direction (`run-x8664` beside `x86_64-unknown-none`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub(crate) enum Machine {
    #[value(name = "x86_64", alias = "x8664")]
    X8664,
    Aarch64,
    Riscv64,
    /// The AIA variant of `virt`: the same architecture and the same image, a
    /// machine whose tree names an **IMSIC** and an APLIC instead of a PLIC.
    ///
    /// It is a machine rather than an environment variable because that is
    /// what it is: the hardware description is part of what a boot is checked
    /// against, and a gate that could be pointed somewhere else by the
    /// environment is a gate whose evidence depends on the caller.  The image
    /// is `Riscv64`'s — the kernel learns which controller it has from the
    /// device tree, which is the property this machine is here to exercise.
    #[value(name = "riscv64-aia")]
    Riscv64Aia,
}

impl Machine {
    /// The Rust target triple.
    pub(crate) const fn triple(self) -> &'static str {
        match self {
            Self::X8664 => "x86_64-unknown-none",
            Self::Aarch64 => "aarch64-unknown-none",
            Self::Riscv64 | Self::Riscv64Aia => "riscv64gc-unknown-none-elf",
        }
    }

    /// The name this machine is called in a report.
    ///
    /// The triple is not enough once two machines share an architecture: the
    /// AIA machine builds the same image for the same target and differs in
    /// what its tree describes, so a line reporting only the triple would print
    /// the same words for a PLIC boot and an AIA one.
    pub(crate) const fn label(self) -> &'static str {
        match self {
            Self::X8664 => "x86_64",
            Self::Aarch64 => "aarch64",
            Self::Riscv64 => "riscv64",
            Self::Riscv64Aia => "riscv64-aia",
        }
    }

    /// The emulator that boots this machine's image.
    pub(crate) const fn qemu(self) -> &'static str {
        match self {
            Self::X8664 => "qemu-system-x86_64",
            Self::Aarch64 => "qemu-system-aarch64",
            Self::Riscv64 | Self::Riscv64Aia => "qemu-system-riscv64",
        }
    }

    /// The emulator arguments that describe the machine, without the kernel.
    ///
    /// Only x86_64 has one today, because only x86_64 has an image this tree
    /// can boot.  The other two return their arguments as an empty list rather
    /// than a guess: a machine whose boot has not been written is not a machine
    /// whose boot can be asserted, and inventing arguments for it would be a
    /// gate that passes because it never ran anything.
    pub(crate) fn qemu_arguments(self, disk: &Path) -> Vec<String> {
        match self {
            // A disk is part of the machine the gate boots: the boot prefers a
            // real device over its in-memory image, and a machine with no disk
            // would exercise the fallback instead of the driver.  The image is
            // a raw file QEMU creates, because the driver writes to it and a
            // read-only disk would be a different test.
            Self::X8664 => vec![
                "-machine".to_string(),
                "q35".to_string(),
                "-cpu".to_string(),
                "max".to_string(),
                // Two CPUs, so the boot's INIT-SIPI start runs: the boot asks
                // the firmware configuration interface how many exist and
                // starts the rest, and a gate that booted one CPU would never
                // exercise the start.  The same argument aarch64's `-smp 2`
                // and riscv64's make.
                "-smp".to_string(),
                "2".to_string(),
                "-m".to_string(),
                "512M".to_string(),
                "-drive".to_string(),
                format!("file={},format=raw,if=none,id=blk0", disk.display()),
                "-device".to_string(),
                // `disable-legacy=on` asks for the modern interface only.
                //
                // The default is a *transitional* device, which offers both a
                // legacy and a modern interface and, this is the part that
                // costs a boot, a capability list whose virtio structures a
                // modern-only parser does not read the way it expects.  This
                // tree implements the modern transport, so it asks for the
                // device that has only that.  On x86_64 the same flag is
                // unnecessary because `q35`'s default is already modern.
                "virtio-blk-pci,drive=blk0,disable-legacy=on".to_string(),
            ],
            // The device-tree machine, with a disk on its PCIe bus.
            //
            // The disk is what makes the driver path runnable rather than only
            // its fallback.  It needs the BAR assignment pass the boot now
            // runs: QEMU's `virt` has a host bridge and no firmware, so every
            // BAR comes up unaddressed until something allocates one.
            Self::Aarch64 => vec![
                "-machine".to_string(),
                "virt".to_string(),
                "-cpu".to_string(),
                "max".to_string(),
                // Two cores, so the boot's PSCI start runs: the tree lists what
                // the firmware cold-booted and asks the firmware for the rest,
                // and a gate that booted one core would never exercise the
                // call.  The same argument riscv64's `-smp 2` makes.
                "-smp".to_string(),
                "2".to_string(),
                "-m".to_string(),
                "512M".to_string(),
                "-drive".to_string(),
                format!("file={},format=raw,if=none,id=blk0", disk.display()),
                "-device".to_string(),
                // `disable-legacy=on` asks for the modern interface only.
                //
                // The default is a *transitional* device, which offers both a
                // legacy and a modern interface and, this is the part that
                // costs a boot, a capability list whose virtio structures a
                // modern-only parser does not read the way it expects.  This
                // tree implements the modern transport, so it asks for the
                // device that has only that.  On x86_64 the same flag is
                // unnecessary because `q35`'s default is already modern.
                "virtio-blk-pci,drive=blk0,disable-legacy=on".to_string(),
            ],
            // The OpenSBI machine: firmware first, then this image's entry in
            // S-mode.  `-cpu rv64` and not a named extension list, because the
            // generic CPU is what the previous tree booted and what the device
            // tree describes; the disk rides the PCIe bus, which is the same
            // `virtio-blk-pci` the other two machines are given and the same
            // modern-only interface request.  `-smp 2` because the boot starts
            // the machine's second hart, the tree lists what the firmware
            // cold-booted and asks the firmware for the rest, and a gate that
            // booted one hart would never exercise the start.
            Self::Riscv64 | Self::Riscv64Aia => {
                // The two machines differ in **one argument**, and that is the
                // point: the same image, the same firmware, the same disk.  A
                // tree that names an APLIC and an IMSIC makes this kernel find
                // and drive them, and a tree that names a PLIC makes it find
                // that instead — the property under test, and the reason the
                // variant is a machine rather than a knob the environment sets.
                let machine = match self {
                    Self::Riscv64Aia => "virt,aia=aplic-imsic",
                    _ => "virt",
                };
                vec![
                    "-machine".to_string(),
                    machine.to_string(),
                    "-cpu".to_string(),
                    "rv64".to_string(),
                    "-smp".to_string(),
                    "2".to_string(),
                    "-m".to_string(),
                    "512M".to_string(),
                    "-drive".to_string(),
                    format!("file={},format=raw,if=none,id=blk0", disk.display()),
                    "-device".to_string(),
                    // `disable-legacy=on` asks for the modern interface only,
                    // for the same reason the other two machines ask: a
                    // transitional device's capability list is one this tree's
                    // modern parser does not read the way it expects.
                    "virtio-blk-pci,drive=blk0,disable-legacy=on".to_string(),
                ]
            }
        }
    }
}
