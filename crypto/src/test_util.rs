//! crypto/src/test_util.rs
//!
//! Hex decoding for the test modules that transcribe a published vector.
//!
//! A vector written out as hex is checkable against the RFC it came from by
//! reading the two side by side; the same bytes as a `[0x..]` array are not.
//! Four test modules read one, so the decoder lives here rather than in each.

use alloc::vec::Vec;

/// Decode a 64-character hex string into 32 bytes.
pub fn hex_to_bytes(hex: &str) -> [u8; 32] {
    assert_eq!(hex.len(), 64);
    let mut bytes = [0u8; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        let h = hex.as_bytes()[i * 2];
        let l = hex.as_bytes()[i * 2 + 1];
        *byte = hex_nibble(h) << 4 | hex_nibble(l);
    }
    bytes
}

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        _ => panic!("invalid hex char"),
    }
}

/// Decode a hex string of any even length into bytes.
pub fn hex_to_bytes_vec(hex: &str) -> Vec<u8> {
    assert_eq!(hex.len() % 2, 0, "hex length must be even");
    let bytes = hex.as_bytes();
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in 0..hex.len() / 2 {
        out.push(hex_nibble(bytes[i * 2]) << 4 | hex_nibble(bytes[i * 2 + 1]));
    }
    out
}
