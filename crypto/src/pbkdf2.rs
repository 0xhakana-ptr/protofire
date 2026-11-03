//! crypto/src/pbkdf2.rs
//!
//! PBKDF2-HMAC-SHA256 (RFC 8018 section 5.2).

use crate::hmac::hmac_sha256;
use alloc::vec::Vec;

/// Derive a key from a passphrase using PBKDF2-HMAC-SHA256.
///
/// Returns `dklen` bytes of derived key material.
///
/// Used by the LUKS2 disk-encryption driver to turn a passphrase into a
/// keyslot key (the KDF in the LUKS2 header's keyslot configuration).
pub fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, dklen: usize) -> Vec<u8> {
    assert!(iterations > 0, "PBKDF2 iteration count must be positive");

    const H_LEN: usize = 32; // HMAC-SHA256 output length
    let num_blocks = dklen.div_ceil(H_LEN);

    let mut result = Vec::with_capacity(dklen);

    for block in 1..=num_blocks {
        // U_1 = PRF(password, salt || INT_32_BE(i))
        let mut u = Vec::with_capacity(salt.len() + 4);
        u.extend_from_slice(salt);
        u.extend_from_slice(&(block as u32).to_be_bytes());
        let mut u_last = hmac_sha256(password, &u);

        // T_i = U_1 XOR U_2 XOR ... XOR U_c
        let mut block_out = u_last;
        for _ in 1..iterations {
            u.clear();
            u.extend_from_slice(&u_last);
            u_last = hmac_sha256(password, &u);
            for (a, b) in block_out.iter_mut().zip(u_last.iter()) {
                *a ^= b;
            }
        }

        result.extend_from_slice(&block_out);
    }

    result.truncate(dklen);
    result
}
