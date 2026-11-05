//! arch/x86_64/src/paging/tests.rs
//!
//! The x86_64 page-table encoding: present, writable, user and no-execute in
//! the bits the processor reads.
//!
//! Extracted from the module so a reader following the mechanism does not have
//! to scroll past every case it satisfies; see `docs/fmts/testing.md` §1.

use crate::paging::decode;
use crate::paging::encode;
use paging::Cache;
use paging::Entry;
use paging::Level;
use paging::Permissions;

/// A page entry round-trips through the encoding.
#[test]
fn a_page_entry_round_trips() {
    let entry = Entry::page(0x1234_5000, Permissions::KERNEL_READ_WRITE);
    let word = encode(entry, Level::Leaf);
    let decoded = decode(word, Level::Leaf);
    assert_eq!(decoded.address, 0x1234_5000);
    assert!(decoded.present);
    assert!(decoded.is_leaf, "a 4 KiB page is a leaf");
    assert!(decoded.permissions.writable);
    assert!(!decoded.permissions.executable);
    assert!(!decoded.permissions.user);
}

/// The flags land in the bits the machine reads.
#[test]
fn the_flags_are_in_the_machines_bits() {
    let read_write = encode(
        Entry::page(0x1000, Permissions::KERNEL_READ_WRITE),
        Level::Leaf,
    );
    assert_eq!(read_write & 0b111, 0b011, "present and writable");
    assert_ne!(read_write & (1 << 63), 0, "no-execute is bit 63");

    let read_execute = encode(
        Entry::page(0x1000, Permissions::KERNEL_READ_EXECUTE),
        Level::Leaf,
    );
    assert_eq!(read_execute & 0b111, 0b001, "present only");
    assert_eq!(
        read_execute & (1 << 63),
        0,
        "execute is the absence of no-execute"
    );
}

/// A device mapping sets both cache bits, and an ordinary one sets
/// neither.
///
/// The boot's identity map set neither, so every BAR the kernel reached
/// was mapped as cached memory — which works on an emulator and is wrong
/// on hardware.
#[test]
fn a_device_mapping_disables_the_cache() {
    let device = Entry::page(0xFE00_0000, Permissions::DEVICE);
    let word = encode(device, Level::Leaf);
    assert_ne!(
        word & crate::paging::FLAG_PAGE_CACHE_DISABLE,
        0,
        "PCD is set"
    );
    assert_ne!(
        word & crate::paging::FLAG_PAGE_WRITE_THROUGH,
        0,
        "PWT is set"
    );
    assert_eq!(decode(word, Level::Leaf).permissions.cache, Cache::Device);

    let ordinary = Entry::page(0x1000, Permissions::KERNEL_READ_WRITE);
    assert_eq!(
        encode(ordinary, Level::Leaf) & crate::paging::FLAG_UNCACHED,
        0
    );
    assert_eq!(
        decode(encode(ordinary, Level::Leaf), Level::Leaf)
            .permissions
            .cache,
        Cache::Normal
    );
}

/// An absent entry encodes to zero, which is what the machine reads as
/// "nothing here".
#[test]
fn an_absent_entry_is_zero() {
    assert_eq!(encode(Entry::EMPTY, Level::Leaf), 0);
    assert_eq!(decode(0, Level::Leaf), Entry::default());
}

/// The address's low twelve bits are flags, so an address that used them
/// would set a permission nobody asked for.
#[test]
fn the_address_does_not_reach_the_flags() {
    let entry = Entry::page(0xABC0_0000, Permissions::KERNEL_READ_EXECUTE);
    let word = encode(entry, Level::Leaf);
    assert_eq!(word & 0xFFF, 0b001, "only present, no address bits");
}

/// No-execute is bit 63, and a decoded address does not carry it.
///
/// This is the bug the first version had: the address mask was `!0xFFF`,
/// which kept bit 63, so every non-executable mapping decoded to an
/// address above 2^63 — a number no machine has.  The mask is the
/// forty bits a physical address occupies, not everything that is not a
/// flag.
#[test]
fn no_execute_does_not_leak_into_the_address() {
    let entry = Entry::page(0x1234_5000, Permissions::KERNEL_READ_WRITE);
    let word = encode(entry, Level::Leaf);
    assert_ne!(word >> 63, 0, "the entry is non-executable");
    let decoded = decode(word, Level::Leaf);
    assert_eq!(decoded.address, 0x1234_5000);
    assert!(decoded.address < (1usize << 52));
}

/// A user mapping carries the user bit and a kernel one does not.
#[test]
fn the_user_bit_is_what_says_who_may_reach() {
    let user = Entry::page(
        0x1000,
        Permissions {
            writable: true,
            executable: false,
            user: true,
            cache: Cache::Normal,
        },
    );
    assert_ne!(encode(user, Level::Leaf) & 0b100, 0);
    assert_eq!(
        encode(
            Entry::page(0x1000, Permissions::KERNEL_READ_WRITE),
            Level::Leaf
        ) & 0b100,
        0
    );
}
