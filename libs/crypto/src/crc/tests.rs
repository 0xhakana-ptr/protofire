//! libs/crypto/src/crc/tests.rs
//!
//! The CRC: the polynomial, the table it builds, and the residue a correct
//! message leaves.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

// CRC-32 test vectors

#[test]
fn crc32_known_vector() {
    // CRC-32 (IEEE 802.3, polynomial 0xEDB88320) of "123456789" =
    // 0xCBF43926.
    assert_eq!(crate::crc::crc32(b"123456789"), 0xCBF4_3926);
}

/// The table has to be the polynomial's table, computed rather than
/// transcribed.
///
/// It was transcribed once, and one of its 256 entries was a word off
/// (`0x5CB30A04` where the polynomial gives `0x5CB36A04`): every message
/// that never indexed that entry checked out — the known vector above is
/// one of them, which is why the error lived — while a real firmware's
/// GPT (whose 16 KiB entry array indexes entries the demo disks never do)
/// failed its CRC and was refused as "no verified table".  A short message
/// cannot catch a single wrong entry; this can, by construction.
#[test]
fn crc32_table_is_the_polynomials_table() {
    const POLY: u32 = 0xEDB8_8320;
    for (index, &entry) in crate::crc::CRC32_TABLE.iter().enumerate() {
        let mut computed = index as u32;
        for _ in 0..8 {
            computed = if computed & 1 != 0 {
                (computed >> 1) ^ POLY
            } else {
                computed >> 1
            };
        }
        assert_eq!(
            entry, computed,
            "CRC32_TABLE[{index}] is {entry:#010x}, the polynomial gives {computed:#010x}"
        );
    }
}

/// A message long enough to index the whole table, against the same
/// polynomial computed bit by bit: the check above pins the table, this
/// pins what the function does with it.
#[test]
fn crc32_matches_a_bitwise_computation_over_every_index() {
    // Every byte value, repeated so the register walks all 256 states.
    let data: alloc::vec::Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let mut crc: u32 = !0;
    for &byte in &data {
        crc ^= byte as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    assert_eq!(crate::crc::crc32(&data), !crc);
}

#[test]
fn crc32c_known_vector() {
    // CRC-32C (Castagnoli, polynomial 0x82F63B78) of "123456789" =
    // 0xE3069283.
    assert_eq!(crate::crc::crc32c(b"123456789"), 0xE306_9283);
}
