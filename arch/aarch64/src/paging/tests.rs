//! arch/aarch64/src/paging/tests.rs
//!
//! The aarch64 descriptors: a 4 KiB page and a 1 GiB block, and the fields each
//! carries.
//!
//! Extracted from the module so a reader following the mechanism does not have
//! to scroll past every case it satisfies; see `docs/fmts/testing.md` §1.

use crate::paging::AF_ACCESSED;
use crate::paging::AP_READ_ONLY;
use crate::paging::AP_USER;
use crate::paging::decode;
use crate::paging::encode;
use crate::paging::encode_at;
use paging::Entry;
use paging::Level;
use paging::Permissions;

/// A table descriptor is an address and a type, and **nothing else**.
///
/// The bits a leaf uses for `AF`, `AP`, the attribute index and `UXN`/`PXN`
/// are the bits the architecture calls Ignored in a table descriptor.  This
/// test is the one that would have caught the first encoder: it set them on
/// every descriptor, and it survived only because the MMU was never turned
/// on, so no descriptor was ever read.
///
/// A byte-for-byte check rather than a mask of the interesting fields,
/// because the point is that no field is interesting: the whole word is the
/// address or period.
#[test]
fn a_table_descriptor_is_an_address_and_a_type() {
    let entry = Entry::table(0x4000_0000);
    let word = encode(entry, Level::Third);
    assert_eq!(
        word, 0x4000_0003,
        "the address and type 0b11, and nothing more"
    );

    assert_eq!(
        word & AF_ACCESSED,
        0,
        "a table descriptor has no access flag"
    );
    assert_eq!(word & AP_READ_ONLY, 0, "no AP[2]");
    assert_eq!(word & AP_USER, 0, "no AP[1]");
    assert_eq!(word & crate::paging::UXN, 0, "no UXN");
    assert_eq!(word & crate::paging::PXN, 0, "no PXN");
    assert_eq!(
        word & (0b111 << crate::paging::ATTR_INDEX_SHIFT),
        0,
        "no attribute index"
    );

    let decoded = decode(word, Level::Third);
    assert_eq!(decoded.address, 0x4000_0000);
    assert!(decoded.present);
    assert!(!decoded.is_leaf);
}

/// A leaf *does* carry those fields, which is what the test above is
/// distinguishing it from.
#[test]
fn a_leaf_carries_the_fields_a_table_does_not() {
    let leaf = Entry::page(0x4000_0000, Permissions::KERNEL_READ_EXECUTE);
    let word = encode_at(leaf, Level::Leaf);
    assert_ne!(word & AF_ACCESSED, 0, "a leaf sets the access flag");
    assert_ne!(word & AP_READ_ONLY, 0, "read-only sets AP[2]");
    assert_eq!(
        word & 0b11,
        crate::paging::TYPE_TABLE_OR_PAGE,
        "the fourth level's leaf is a page"
    );
}

/// `TCR_EL1` says a 39-bit space, a 4 KiB granule, inner shareable, and the
/// physical address size the machine reported.
///
/// The fields are checked by shift because that is where they live, and a
/// field written to the wrong shift is a value the walk reads as something
/// else entirely.
#[test]
fn the_translation_control_says_what_the_table_is() {
    let tcr = crate::paging::tcr_el1(crate::paging::ips_for_parange(0b010));
    assert_eq!(tcr & 0x3F, crate::paging::TCR_T0SZ, "bits 0..6: T0SZ = 16");
    assert_eq!(
        (tcr >> 8) & 0b11,
        crate::paging::TCR_RGN_WRITE_BACK,
        "IRGN0"
    );
    assert_eq!(
        (tcr >> 10) & 0b11,
        crate::paging::TCR_RGN_WRITE_BACK,
        "ORGN0"
    );
    assert_eq!((tcr >> 12) & 0b11, crate::paging::TCR_SH_INNER, "SH0");
    assert_eq!((tcr >> 14) & 0b11, crate::paging::TCR_TG0_4K, "TG0 = 4 KiB");
    assert_eq!(
        (tcr >> 32) & 0b111,
        crate::paging::ips_for_parange(0b010),
        "IPS is the field it maps to"
    );
    assert_eq!(tcr & (1 << 7), 0, "EPD0 clear: walks through TTBR0 are on");
}

/// `PARange` and `IPS` number the same sizes the same way, so the
/// translation is a copy.
///
/// The test this replaced asserted the opposite, it claimed 40 bits was
/// `0b010` as `PARange` and `0b001` as `IPS`, and that a kernel copying one
/// into the other would be wrong.  Copying is exactly right; the test was
/// encoding a belief rather than the architecture, and the boot proved it:
/// `IPS` came out at 36 bits on a 40-bit machine, and an ECAM window at
/// 275 GiB faulted with *address size fault, level 2*.
///
/// So the assertions below are the table a reader can check against the
/// architecture manual, and the `0b010` row is the one the bug was in.
#[test]
fn the_physical_range_uses_the_same_encoding_as_ips() {
    // The encodings are the identity for every size this tree names.
    for encoding in 0b000..=0b110_u64 {
        assert_eq!(
            crate::paging::ips_for_parange(encoding),
            encoding,
            "encoding {encoding:#05b} is its own IPS value"
        );
    }
    // Spelled out, so a change to the loop cannot make the point silently.
    assert_eq!(
        crate::paging::ips_for_parange(0b000),
        0b000,
        "32 bits, 4 GiB"
    );
    assert_eq!(
        crate::paging::ips_for_parange(0b001),
        0b001,
        "36 bits, 64 GiB"
    );
    assert_eq!(
        crate::paging::ips_for_parange(0b010),
        0b010,
        "40 bits, 1 TiB"
    );
    assert_eq!(
        crate::paging::ips_for_parange(0b101),
        0b101,
        "48 bits, 256 TiB"
    );

    // A machine reporting a size this tree does not name gets the most
    // conservative answer: a table naming physical bits the CPU does not
    // have is a fault, and naming fewer is only a smaller space.
    assert_eq!(crate::paging::ips_for_parange(0b111), 0b000);
    assert_eq!(crate::paging::ips_for_parange(0b1111), 0b000);
}

/// `T0SZ` names a virtual address space whose top level is the level the
/// kernel's root table is.
///
/// This is the test that was missing, and the bug it would have caught is
/// the one that stopped the first boot with the MMU on: `T0SZ` was 25,
/// which is 39 bits and three levels, so the machine treated the root as a
/// **level 1** table and never read its entry 0.  The first fetch faulted
/// with `DFSC = translation fault, level 1`.
///
/// The assertion is arithmetic rather than a literal: `64 - T0SZ` has to
/// equal the width the root's index reaches, which is
/// `Level::Root::shift() + 9`.  A `T0SZ` that disagreed with the table's
/// depth is exactly the state that produced the fault.
#[test]
fn the_address_size_matches_the_table_depth() {
    let va_bits = 64 - crate::paging::TCR_T0SZ;
    let root_reaches = (Level::Root.shift() + paging::index::INDEX_BITS) as u64;
    assert_eq!(
        va_bits, root_reaches,
        "T0SZ must describe a space whose top index is the root's"
    );
    // And the numbers that failure is: 48 bits is four levels, 39 is three.
    assert_eq!(va_bits, 48);
    assert_eq!(
        64 - 25,
        39,
        "the value that failed: three levels for a four-level table"
    );
}

/// Read-only is the bit being *set*, which is the opposite of x86_64.
///
/// This is the difference a copied encoder gets wrong: x86_64 clears a
/// writable bit, and aarch64 sets a read-only one, so a port that kept the
/// same arithmetic would give every page the wrong permission.
#[test]
fn read_only_is_a_bit_that_is_set() {
    let writable = Entry::page(0x1000, Permissions::KERNEL_READ_WRITE);
    assert_eq!(
        encode(writable, Level::Leaf) & AP_READ_ONLY,
        0,
        "writable clears the bit"
    );

    let read_only = Entry::page(0x1000, Permissions::KERNEL_READ_EXECUTE);
    assert_ne!(
        encode(read_only, Level::Leaf) & AP_READ_ONLY,
        0,
        "read-only sets it"
    );

    assert!(
        decode(encode(writable, Level::Leaf), Level::Leaf)
            .permissions
            .writable
    );
    assert!(
        !decode(encode(read_only, Level::Leaf), Level::Leaf)
            .permissions
            .writable
    );
}

/// A user page sets `AP[1]` and clears `UXN` when it is executable.
#[test]
fn a_user_mapping_is_marked_user() {
    let user = Entry::page(
        0x1000,
        Permissions {
            writable: true,
            executable: true,
            user: true,
            cache: paging::Cache::Normal,
        },
    );
    let word = encode(user, Level::Leaf);
    assert_ne!(word & AP_USER, 0);
    assert_eq!(
        word & crate::paging::UXN,
        0,
        "an executable user page is not UXN"
    );

    let kernel = Entry::page(0x1000, Permissions::KERNEL_READ_WRITE);
    assert_eq!(encode(kernel, Level::Leaf) & AP_USER, 0);
    assert_ne!(
        encode(kernel, Level::Leaf) & crate::paging::UXN,
        0,
        "a kernel page is unprivileged-execute-never"
    );
}

/// A leaf in a block-capable level is a block; the last level's leaf is a
/// page.
#[test]
fn a_leaf_is_a_block_where_a_block_is_allowed() {
    let entry = Entry::page(0x4000_0000, Permissions::KERNEL_READ_WRITE);
    assert_eq!(
        encode_at(entry, Level::Third) & 0b11,
        crate::paging::TYPE_BLOCK
    );
    assert_eq!(
        encode_at(entry, Level::Second) & 0b11,
        crate::paging::TYPE_BLOCK,
        "a second-level block is a 1 GiB mapping"
    );
    assert_eq!(
        encode_at(entry, Level::Leaf) & 0b11,
        crate::paging::TYPE_TABLE_OR_PAGE,
        "the fourth level's leaf is a 4 KiB page, not a block"
    );
    // A leaf at the root would be a block the root cannot hold, so the
    // encoder writes a page descriptor, the one encoding that is at least
    // not a block.  Nothing builds such a table: the kernel places leaves
    // at `Level::Leaf`.  This records what the function does rather than
    // what a caller should ask for.
    assert_eq!(
        encode_at(entry, Level::Root) & 0b11,
        crate::paging::TYPE_TABLE_OR_PAGE,
        "the root has no block form"
    );
}

/// A device mapping names the device `MAIR` index, and an ordinary one
/// names the normal index.
#[test]
fn a_device_mapping_names_the_device_attribute() {
    let device = Entry::page(0xFE00_0000, Permissions::DEVICE);
    let word = encode(device, Level::Leaf);
    assert_ne!(
        word & crate::paging::ATTR_DEVICE,
        0,
        "the device index is named"
    );
    assert_eq!(
        decode(word, Level::Leaf).permissions.cache,
        paging::Cache::Device
    );

    let ordinary = Entry::page(0x1000, Permissions::KERNEL_READ_WRITE);
    assert_eq!(
        encode(ordinary, Level::Leaf) & (0b111 << crate::paging::ATTR_INDEX_SHIFT),
        0
    );
    assert_eq!(
        decode(encode(ordinary, Level::Leaf), Level::Leaf)
            .permissions
            .cache,
        paging::Cache::Normal
    );
}

/// An absent entry is zero.
#[test]
fn an_absent_entry_is_zero() {
    assert_eq!(encode(Entry::EMPTY, Level::Leaf), 0);
    assert_eq!(decode(0, Level::Leaf), Entry::default());
}
