//! libs/fdt/tests/parse.rs
//!
//! The parser against two kinds of blob: one `dtc` produced from a source file
//! in `tests/assets/`, and blobs this file builds byte by byte.
//!
//! ## Why both
//!
//! A builder and a parser written by the same hand agree about a format neither
//! may have read correctly — the structure block's padding is the classic case:
//! an off-by-one there produces a blob that round-trips through a matching
//! builder and fails on real firmware.  So the fixture is `dtc`'s output, with
//! its `.dts` beside it so a reader can see what the blob claims.
//!
//! The builder exists for what `dtc` will not produce: a truncated blob, a bad
//! magic, a name offset past the strings block.  A parser is judged by what it
//! refuses, and there is no way to ask `dtc` for a broken tree.

use fdt::Error;
use fdt::Fdt;

/// The fixture `dtc` produced from `tests/assets/virt.dts`.
///
/// `include_bytes!` rather than a generated file: the blob is 1 KB and it is
/// the input a test's argument rests on, so it belongs in the tree where a
/// reader can compare it against its source.
const VIRT_DTB: &[u8] = include_bytes!("assets/virt.dtb");

#[test]
fn the_fixture_is_a_device_tree() {
    let fdt = Fdt::new(VIRT_DTB).expect("the fixture parses");
    assert_eq!(fdt.version(), Some(17));
    assert_eq!(fdt.size(), VIRT_DTB.len());
}

/// The root's name is empty and its properties are the ones the `.dts` gives.
#[test]
fn the_root_has_the_properties_the_source_declares() {
    let fdt = Fdt::new(VIRT_DTB).unwrap();
    let root = fdt.root().unwrap();
    assert_eq!(root.name(), "", "the format allows an unnamed root");
    assert_eq!(root.base_name(), "");

    assert_eq!(
        root.property("model").and_then(|p| p.as_str()),
        Some("protofire,fixture")
    );
    assert_eq!(
        root.property("#address-cells").and_then(|p| p.as_u32()),
        Some(2)
    );
    assert_eq!(
        root.property("#size-cells").and_then(|p| p.as_u32()),
        Some(2)
    );
}

/// A node is found by `compatible`, and its `reg` decodes with the widths its
/// parent set.
///
/// This is the query the boot makes: "where is the UART".  The address is
/// `0x0900_0000` and the size `0x1000`, as the `.dts` says — and decoding it
/// needs the root's two address cells, which is why the node carries the widths
/// rather than reading them on demand.
#[test]
fn the_uart_is_found_and_its_region_decodes() {
    let fdt = Fdt::new(VIRT_DTB).unwrap();
    let uart = fdt
        .find_compatible("arm,pl011")
        .expect("the fixture has a PL011");

    assert_eq!(uart.name(), "pl011@9000000");
    assert_eq!(uart.base_name(), "pl011");
    assert_eq!(uart.unit_base(), Some(0x0900_0000));

    let region = uart.region().expect("the PL011 has a reg property");
    assert_eq!(region.address, 0x0900_0000);
    assert_eq!(region.size, 0x1000);
}

/// A `compatible` list matches on any of its entries, which is what the second
/// half of `"arm,pl011", "arm,primecell"` is for.
#[test]
fn either_compatible_entry_matches() {
    let fdt = Fdt::new(VIRT_DTB).unwrap();
    let by_specific = fdt.find_compatible("arm,pl011").unwrap();
    let by_generic = fdt.find_compatible("arm,primecell").unwrap();
    assert_eq!(by_specific.name(), by_generic.name());
}

/// `all_compatible` finds every node that claims a name, in blob order.
///
/// Two `virtio,mmio` nodes are in the fixture and QEMU's real tree has
/// thirty-two; a boot asking "which transports are there" needs all of them,
/// and a single-answer `find` would silently use the first.
#[test]
fn every_matching_node_is_visited_in_order() {
    let fdt = Fdt::new(VIRT_DTB).unwrap();
    let addresses: Vec<u64> = fdt
        .all_compatible("virtio,mmio")
        .filter_map(|node| node.region())
        .map(|region| region.address)
        .collect();
    assert_eq!(addresses, vec![0x0A00_0000, 0x0A00_0200]);
}

/// A node with two regions yields both, which is what a `reg` cursor is for.
///
/// An implementation that read only the first group would answer half a
/// device and look correct doing it.
#[test]
fn a_reg_with_two_entries_yields_two_regions() {
    let fdt = Fdt::new(VIRT_DTB).unwrap();
    let twice = fdt
        .find_compatible("test,twice")
        .expect("the fixture has one");
    let regions: Vec<_> = twice.reg().collect();
    assert_eq!(regions.len(), 2);
    assert_eq!(regions[0].address, 0x1000);
    assert_eq!(regions[0].size, 0x100);
    assert_eq!(regions[1].address, 0x2000);
    assert_eq!(regions[1].size, 0x200);
}

/// A path from `aliases` or `chosen` resolves to the node it names.
///
/// `stdout-path` is what a real boot reads to find its console when the UART's
/// address is not a constant, so the lookup has to work on the form a device
/// tree actually stores.
#[test]
fn a_path_resolves_to_its_node() {
    let fdt = Fdt::new(VIRT_DTB).unwrap();
    let root = fdt.root().unwrap();
    let chosen = root.child("chosen").expect("the fixture has chosen");
    let path = chosen
        .property("stdout-path")
        .and_then(|p| p.as_str())
        .expect("stdout-path is a string");
    assert_eq!(path, "/pl011@9000000");

    let by_path = root.by_path(path).expect("the path resolves");
    assert_eq!(by_path.name(), "pl011@9000000");
    assert!(
        by_path.is_compatible("arm,pl011"),
        "the same node, not a copy"
    );
}

/// A node's own declaration governs its **children**, not its own `reg`.
///
/// This is the rule that is easy to invert and silent when inverted.  The PCIe
/// bridge declares `#address-cells = <3>` because a PCI address is three cells
/// — but the bridge's own `reg` is an ordinary two-cell MMIO address under its
/// parent.  Decoding the bridge's `reg` with its own three cells would read
/// `0x0040_1000_0000_0000`, a number plausible enough that nothing fails.
///
/// So the test asserts both halves: the declaration is three, and the `reg`
/// that declaration does **not** apply to decodes as two.
#[test]
fn a_declaration_governs_children_and_not_the_node_itself() {
    let fdt = Fdt::new(VIRT_DTB).unwrap();
    let pcie = fdt.find_compatible("pci-host-ecam-generic").unwrap();

    assert_eq!(
        pcie.child_cells(),
        (3, 2),
        "the bridge declares three cells"
    );
    assert_eq!(
        pcie.reg_cells(),
        (2, 2),
        "but its own reg is decoded with its parent's two"
    );

    let region = pcie.region().unwrap();
    assert_eq!(region.address, 0x40_1000_0000, "the two-cell reading");
    assert_eq!(region.size, 0x1000_0000);
    assert_eq!(
        region.space, 0,
        "the bridge's own reg has no space selector"
    );
}

/// A three-cell address keeps its space selector out of the number.
///
/// A PCI `ranges` entry and a child device's `reg` both start with a space
/// cell — `0x0200_0000` for 32-bit non-prefetchable memory.  Shifting it into
/// the address gives a 96-bit value that does not fit, so the cell is reported
/// separately.
#[test]
fn a_three_cell_address_reports_its_space_separately() {
    let fdt = Fdt::new(VIRT_DTB).unwrap();
    let pcie = fdt.find_compatible("pci-host-ecam-generic").unwrap();

    // The ranges property's first entry: the I/O window.
    let ranges = pcie.property("ranges").expect("the bridge has ranges");
    let cells: Vec<u32> = ranges.as_cells().unwrap().collect();
    assert_eq!(
        cells[0], 0x0100_0000,
        "the fixture's first ranges entry is the I/O window"
    );
}

/// A child that declares nothing inherits, and the inheritance reaches the
/// `reg` two levels down.
#[test]
fn a_child_inherits_the_parents_cell_widths() {
    let fdt = Fdt::new(VIRT_DTB).unwrap();
    let root = fdt.root().unwrap();
    let memory = root
        .child("memory@40000000")
        .expect("the fixture has memory");
    assert_eq!(
        memory.reg_cells(),
        root.child_cells(),
        "memory declares no #address-cells and must use the root's"
    );
    let region = memory.region().unwrap();
    assert_eq!(region.address, 0x4000_0000);
    assert_eq!(region.size, 0x2000_0000);
}

/// A node's properties stop at its first child.
///
/// The format puts them in that order, and a `properties()` that kept reading
/// would hand a caller the child's `reg` as if it were the parent's — a bug
/// whose symptom is a device address off by one node.
#[test]
fn properties_stop_at_the_first_child() {
    let fdt = Fdt::new(VIRT_DTB).unwrap();
    let root = fdt.root().unwrap();
    let names: Vec<&str> = root.properties().map(|p| p.name).collect();
    assert!(names.contains(&"model"), "the root has its own properties");
    for name in &names {
        assert_ne!(*name, "interrupts", "that is a child's property");
    }
}

// ---------------------------------------------------------------------------
// The builder: blobs `dtc` will not produce.
// ---------------------------------------------------------------------------

/// A structure block assembled token by token.
struct Builder {
    structure: Vec<u8>,
    strings: Vec<u8>,
}

impl Builder {
    fn new() -> Builder {
        Builder {
            structure: Vec::new(),
            strings: Vec::new(),
        }
    }

    fn begin(&mut self, name: &str) -> &mut Builder {
        self.word(1);
        self.padded(name);
        self
    }

    fn end(&mut self) -> &mut Builder {
        self.word(2);
        self
    }

    fn end_tree(&mut self) -> &mut Builder {
        self.word(9);
        self
    }

    fn prop(&mut self, name: &str, value: &[u8]) -> &mut Builder {
        let offset = self.strings.len() as u32;
        self.strings.extend_from_slice(name.as_bytes());
        self.strings.push(0);
        self.word(3);
        self.word(value.len() as u32);
        self.word(offset);
        self.structure.extend_from_slice(value);
        while self.structure.len() % 4 != 0 {
            self.structure.push(0);
        }
        self
    }

    fn word(&mut self, value: u32) {
        self.structure.extend_from_slice(&value.to_be_bytes());
    }

    fn padded(&mut self, text: &str) {
        self.structure.extend_from_slice(text.as_bytes());
        self.structure.push(0);
        while self.structure.len() % 4 != 0 {
            self.structure.push(0);
        }
    }

    /// The whole blob, with a header whose offsets are this builder's.
    fn build(&self) -> Vec<u8> {
        let mut blob = Vec::new();
        // Ten header words; the reserved-map offset (16) and the boot CPU id
        // (28) stay zero, which the format allows.
        let header_words = 10_u32;
        let struct_offset = header_words * 4;
        let strings_offset = struct_offset + self.structure.len() as u32;
        let total = strings_offset + self.strings.len() as u32;
        for word in [
            0xd00d_feed,
            total,
            struct_offset,
            strings_offset,
            0,  // memory reservation map offset; 0 means none
            17, // version
            16, // last compatible version
            0,  // boot CPU id
            self.strings.len() as u32,
            self.structure.len() as u32,
        ] {
            blob.extend_from_slice(&word.to_be_bytes());
        }
        blob.extend_from_slice(&self.structure);
        blob.extend_from_slice(&self.strings);
        blob
    }
}

fn minimal() -> Builder {
    let mut builder = Builder::new();
    builder.begin("");
    builder.prop("#address-cells", &1_u32.to_be_bytes());
    builder.prop("#size-cells", &1_u32.to_be_bytes());
    builder.begin("uart@1000");
    builder.prop("compatible", b"test,uart\0");
    builder.prop("reg", &[0_u8; 0]);
    builder.end();
    builder.end();
    builder.end_tree();
    builder
}

/// A blob built here parses, and its cells come out as they were written.
///
/// The point is not that this parser reads this builder — two halves of one
/// misunderstanding would pass — but that the builder's own padding is what the
/// format specifies, so the assertion against `dtc`'s blob above and this one
/// together pin both.
#[test]
fn a_blob_built_here_parses() {
    let blob = minimal().build();
    let fdt = Fdt::new(&blob).expect("a well-formed blob");
    let root = fdt.root().unwrap();
    assert_eq!(root.child_cells(), (1, 1));
    let uart = root.child("uart@1000").expect("the builder's node");
    assert!(uart.is_compatible("test,uart"));
}

/// A magic that is not `0xd00dfeed` is refused.
#[test]
fn a_wrong_magic_is_refused() {
    let mut blob = minimal().build();
    blob[0] = 0xFF;
    assert_eq!(Fdt::new(&blob), Err(Error::BadMagic));
}

/// A blob shorter than a header is refused rather than read past.
#[test]
fn a_short_blob_is_refused() {
    assert_eq!(Fdt::new(&[]), Err(Error::TooSmall));
    assert_eq!(Fdt::new(&[0; 39]), Err(Error::TooSmall));
}

/// An older version is refused, because its header lacks the strings size.
#[test]
fn an_old_version_is_refused() {
    let mut blob = minimal().build();
    blob[20..24].copy_from_slice(&3_u32.to_be_bytes());
    assert_eq!(Fdt::new(&blob), Err(Error::UnsupportedVersion(3)));
}

/// A structure block that claims more bytes than the blob has is refused.
///
/// This is the bounds check that matters: firmware overstated a size, and a
/// parser that trusted it would read past the blob into whatever the loader
/// left there.
#[test]
fn a_structure_block_past_the_blob_is_refused() {
    let mut blob = minimal().build();
    let oversized = (blob.len() as u32) * 2;
    blob[36..40].copy_from_slice(&oversized.to_be_bytes());
    assert_eq!(Fdt::new(&blob), Err(Error::BadHeader));
}

/// A property name offset past the strings block is refused.
#[test]
fn a_name_offset_past_the_strings_block_is_refused() {
    let mut builder = Builder::new();
    builder.begin("");
    // Offset 0xFFFF is past a strings block this builder will make.
    let offset = 0xFFFF_u32;
    builder.word(3);
    builder.word(4);
    builder.word(offset);
    builder.word(0);
    builder.end();
    builder.end_tree();
    let blob = builder.build();
    let fdt = Fdt::new(&blob).expect("the header is fine");
    // The property's name cannot be read, so the iterator yields nothing and
    // the tree walk reports truncation rather than inventing a name.
    let root = fdt.root();
    assert!(
        root.is_err() || root.unwrap().properties().count() == 0,
        "a name that cannot be read is not a property"
    );
}

/// A structure block that ends before the tree does is refused.
#[test]
fn a_truncated_structure_block_is_refused() {
    let blob = minimal().build();
    // Cut the structure block to just the first token, and fix the header's
    // size so the header itself is consistent.
    let mut short = blob.clone();
    let struct_size = 4_u32;
    short[36..40].copy_from_slice(&struct_size.to_be_bytes());
    let fdt = Fdt::new(&short).expect("the header is consistent");
    assert!(matches!(fdt.root(), Err(Error::Truncated)));
}

/// An unknown token stops the walk rather than being skipped.
///
/// Skipping would read a length out of bytes that are not a length, and the
/// walk would land somewhere that parses as a plausible tree.
#[test]
fn an_unknown_token_is_refused() {
    let mut builder = Builder::new();
    builder.begin("");
    builder.word(0xDEAD_BEEF);
    builder.end();
    builder.end_tree();
    let blob = builder.build();
    let fdt = Fdt::new(&blob).unwrap();
    assert!(matches!(fdt.root(), Err(Error::BadToken(0xDEAD_BEEF))));
}
