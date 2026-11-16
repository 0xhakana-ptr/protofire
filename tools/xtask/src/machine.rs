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
/// thing it names is the papercut a `run-x8664` recipe beside a
/// `x86_64-unknown-none` target produces.
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
    /// is `Riscv64`'s, the kernel learns which controller it has from the
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

    /// Whether this machine is given an NVMe controller.
    ///
    /// One machine, and that is a property of the machine rather than of the
    /// driver: `q35` carries an `nvme` function on its PCIe bus, and the other
    /// two trees describe a bus this controller is not attached to.  The
    /// question is asked here rather than in three places so a machine that
    /// gains a controller answers it once.
    pub(crate) const fn has_nvme(self) -> bool {
        matches!(self, Self::X8664)
    }

    /// Whether this machine is given a SATA disk on its AHCI controller.
    ///
    /// `q35` carries an Intel ICH9 whose six SATA ports are on the PCI bus,
    /// and `ide-hd` on `ide.0` is a disk on the first of them.  The other two
    /// machines' trees carry no SATA controller, so the question is asked
    /// here rather than in three places.
    pub(crate) const fn has_ahci(self) -> bool {
        matches!(self, Self::X8664)
    }

    /// Whether this machine is given an xHCI controller with devices on its
    /// bus.
    ///
    /// `qemu-xhci` is QEMU's own USB 3 controller, and the keyboard and the
    /// storage device are what the two HID/MSC drivers drive.  The other two
    /// machines' trees carry no USB controller, so the question is asked here
    /// rather than in three places.
    pub(crate) const fn has_xhci(self) -> bool {
        matches!(self, Self::X8664)
    }

    /// The emulator that boots this machine's image.
    pub(crate) const fn qemu(self) -> &'static str {
        match self {
            Self::X8664 => "qemu-system-x86_64",
            Self::Aarch64 => "qemu-system-aarch64",
            Self::Riscv64 | Self::Riscv64Aia => "qemu-system-riscv64",
        }
    }

    /// The network card every bootable machine is given.
    ///
    /// `-netdev user` is QEMU's own network, which needs no host privilege, no
    /// tap device and no configuration: it puts the guest on `10.0.2.0/24`,
    /// answers ARP for its gateway at `10.0.2.2`, and drops everything it was
    /// not asked for.  That is exactly enough for the one exchange the driver
    /// does, and it is the reason the gate can assert a reply at all.
    ///
    /// `disable-legacy=on` asks for the modern interface only, for the reason
    /// the disks ask: this tree implements the modern transport, and a
    /// transitional device's capability list is one its parser does not read
    /// the way it expects.
    fn network_arguments() -> Vec<String> {
        vec![
            "-netdev".to_string(),
            // **Not `ipv6=on`.**  Measured: turning it on makes slirp stop
            // answering IPv4 ARP, and the boot's whole network chain, the
            // ARP exchange, the ping, the datagram, goes silent while the
            // boot still exits zero.  The IPv6 exchange this tree proves is
            // a loopback through the receive path's own demux, which needs
            // nothing from the emulated network; a card option that costs
            // four working IPv4 exchanges to enable a path that never uses
            // it is the wrong trade, and the measurement is here so the next
            // reader does not make it again.
            "user,id=net0".to_string(),
            "-device".to_string(),
            "virtio-net-pci,netdev=net0,disable-legacy=on".to_string(),
        ]
    }

    /// The emulator arguments that describe the machine, without the kernel.
    ///
    /// Every machine this tree boots has an arm here, and each one ends with
    /// the same network card: the exchange the driver does is the same on all
    /// three, and only the bus mechanism that reaches the PCI function differs.
    pub(crate) fn qemu_arguments(
        self,
        disk: &Path,
        nvme_disk: &Path,
        sata_disk: &Path,
        usb_disk: &Path,
    ) -> Vec<String> {
        let mut arguments = match self {
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
                // The NVMe controller, on a second disk of its own.
                //
                // A second `-drive` rather than sharing `blk0`: the virtio
                // driver mounts the disk it finds, and a controller that read
                // and wrote the same sectors would be a boot whose two drivers
                // corrupt each other's volume.  This disk is not formatted and
                // nothing mounts it, which is the point -- the NVMe probe is
                // proving the controller, and a mount would be a second claim
                // riding on the first.
                //
                // Only x86_64 gets it: `q35` carries an `nvme` function, and
                // the other two machines' trees describe a PCIe bus this
                // controller is not on.  A required line on them would be a
                // requirement the machine cannot meet.
                "-drive".to_string(),
                format!("file={},format=raw,if=none,id=nvm0", nvme_disk.display()),
                "-device".to_string(),
                "nvme,serial=protofire,drive=nvm0".to_string(),
                // The SATA disk, on the controller's first port.  `ide.0` is
                // how QEMU names the ICH9's first SATA port, and `ide-hd` is
                // the device a driver can identify over it; the controller
                // itself needs no argument, because `q35` creates it.
                "-drive".to_string(),
                format!("file={},format=raw,if=none,id=sata0", sata_disk.display()),
                "-device".to_string(),
                "ide-hd,drive=sata0,bus=ide.0".to_string(),
                // The USB host controller, with a keyboard and a disk on its
                // bus.  `qemu-xhci` creates the controller and its own USB
                // bus; a `-device usb-*` without an explicit bus lands on the
                // first one, which is this controller's.  The keyboard is
                // what a HID report is for; the disk is what the MSC driver's
                // geometry probe is for.
                "-device".to_string(),
                "qemu-xhci".to_string(),
                "-device".to_string(),
                "usb-kbd".to_string(),
                "-device".to_string(),
                "usb-storage,drive=usb0".to_string(),
                "-drive".to_string(),
                format!("file={},format=raw,if=none,id=usb0", usb_disk.display()),
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
            // generic CPU is what the device tree describes; the disk rides the
            // PCIe bus, which is the same `virtio-blk-pci` the other two
            // machines are given and the same modern-only interface request.
            // `-smp 2` because the boot starts the machine's second hart, the
            // tree lists what the firmware
            // cold-booted and asks the firmware for the rest, and a gate that
            // booted one hart would never exercise the start.
            Self::Riscv64 | Self::Riscv64Aia => {
                // The two machines differ in **one argument**, and that is the
                // point: the same image, the same firmware, the same disk.  A
                // tree that names an APLIC and an IMSIC makes this kernel find
                // and drive them, and a tree that names a PLIC makes it find
                // that instead, the property under test, and the reason the
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
        };
        // Every machine that boots gets the card, because the exchange the
        // driver does is the same exchange on all three: the device tree names
        // a different bus mechanism and the PCI function is the same one.
        arguments.extend(Self::network_arguments());
        arguments
    }
}
