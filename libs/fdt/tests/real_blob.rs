//! libs/fdt/tests/real_blob.rs
//!
//! The tree `qemu-system-aarch64 -machine virt` actually hands over.
//!
//! `assets/qemu-virt.dtb` is the output of `qemu-system-aarch64 -machine virt
//! -cpu max -m 512M,dumpdtb=...` — firmware's own bytes, not `dtc`'s rendering
//! of a source file.  The difference matters: a generator and a parser written
//! from the same reading of a specification agree with each other, and a
//! firmware blob is the only input that disagrees when that reading is wrong.
//!
//! This file exists because it caught one.  `all_compatible` kept a fixed stack
//! of thirty-two pending nodes; the `virt` tree has fifty-one children under
//! its root, so the walk found twenty-eight of the thirty-two `virtio,mmio`
//! transports and every test built from a small fixture passed.

use fdt::Fdt;

/// The blob firmware hands over for the machine the boot gates run on.
const QEMU_VIRT: &[u8] = include_bytes!("assets/qemu-virt.dtb");

#[test]
fn the_real_blob_parses() {
    let fdt = Fdt::new(QEMU_VIRT).expect("qemu's own device tree parses");
    let root = fdt.root().unwrap();
    assert_eq!(root.base_name(), "", "the root is unnamed");
    assert_eq!(
        root.child_cells(),
        (2, 2),
        "the root declares 2+2 for children"
    );

    assert_eq!(
        root.property("compatible").and_then(|p| p.as_str()),
        Some("linux,dummy-virt")
    );
}

/// The UART is where the boot needs it, read out of the tree rather than known.
#[test]
fn the_uart_address_comes_out_of_the_tree() {
    let fdt = Fdt::new(QEMU_VIRT).unwrap();
    let uart = fdt
        .find_compatible("arm,pl011")
        .expect("the machine has a PL011");
    assert_eq!(uart.name(), "pl011@9000000");
    let region = uart.region().unwrap();
    assert_eq!(region.address, 0x0900_0000);
    assert_eq!(region.size, 0x1000);
}

/// The PCIe host bridge, whose `reg` is the ECAM window.
///
/// `0x40_1000_0000` is above four gigabytes, so decoding it needs the tree's
/// two-cell address — a one-cell reading would give `0x1000_0000` and map the
/// wrong gigabyte.
#[test]
fn the_pcie_ecam_window_is_above_four_gigabytes() {
    let fdt = Fdt::new(QEMU_VIRT).unwrap();
    let pcie = fdt
        .find_compatible("pci-host-ecam-generic")
        .expect("the machine has a PCIe host bridge");
    let region = pcie.region().unwrap();
    assert_eq!(region.address, 0x40_1000_0000);
    assert_eq!(region.size, 0x1000_0000);
    assert_eq!(pcie.child_cells(), (3, 2), "PCI addresses are three cells");
}

/// RAM is the entry the frame allocator will read.
#[test]
fn memory_is_the_region_the_machine_has() {
    let fdt = Fdt::new(QEMU_VIRT).unwrap();
    let root = fdt.root().unwrap();
    let memory = root.child("memory@40000000").expect("the machine has RAM");
    let region = memory.region().unwrap();
    assert_eq!(region.address, 0x4000_0000);
    assert_eq!(region.size, 0x2000_0000, "512 MiB, as -m 512M says");
}

/// **All thirty-two** virtio-mmio transports are found, in address order.
///
/// This is the assertion that failed against a fixed-depth stack: the root has
/// fifty-one children and the transports are the last thirty-two of them.
#[test]
fn every_virtio_transport_is_visited() {
    let fdt = Fdt::new(QEMU_VIRT).unwrap();
    let addresses: Vec<u64> = fdt
        .all_compatible("virtio,mmio")
        .filter_map(|node| node.region())
        .map(|region| region.address)
        .collect();

    assert_eq!(addresses.len(), 32, "qemu virt declares thirty-two");
    assert_eq!(addresses[0], 0x0A00_0000);
    assert_eq!(addresses[31], 0x0A00_3E00);
    // Each is 0x200 apart, which is the check that the walk did not skip one
    // and renumber the rest.
    for (index, address) in addresses.iter().enumerate() {
        assert_eq!(*address, 0x0A00_0000 + (index as u64) * 0x200);
    }
}
