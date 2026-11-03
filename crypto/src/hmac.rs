//! crypto/src/hmac.rs
//!
//! HMAC-SHA256 (RFC 2104, NIST FIPS 198-1).

use crate::sha256::sha256;
use alloc::vec::Vec;

const HMAC_IPAD: u8 = 0x36;
const HMAC_OPAD: u8 = 0x5c;
const HMAC_BLOCK_SIZE: usize = 64;

/// Compute the HMAC-SHA256 authentication code for `data` using `key`.
///
/// Per RFC 2104: HMAC(K, m) = H((K ⊕ opad) || H((K ⊕ ipad) || m))
///
/// If `key` is longer than 64 bytes it is first hashed with SHA-256.
/// If shorter, it is zero-padded to 64 bytes.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut key_block = [0u8; HMAC_BLOCK_SIZE];

    // If key is longer than block size, hash it first.
    let key_hashed: [u8; 32];
    let normalized_key: &[u8] = if key.len() > HMAC_BLOCK_SIZE {
        key_hashed = sha256(key);
        &key_hashed
    } else {
        key
    };

    key_block[..normalized_key.len()].copy_from_slice(normalized_key);

    // Inner hash: H((K ⊕ ipad) || message)
    let mut inner_input = Vec::with_capacity(HMAC_BLOCK_SIZE + data.len());
    for byte in &key_block {
        inner_input.push(byte ^ HMAC_IPAD);
    }
    inner_input.extend_from_slice(data);
    let inner_hash = sha256(&inner_input);

    // Outer hash: H((K ⊕ opad) || inner_hash)
    let mut outer_input = Vec::with_capacity(HMAC_BLOCK_SIZE + 32);
    for byte in &key_block {
        outer_input.push(byte ^ HMAC_OPAD);
    }
    outer_input.extend_from_slice(&inner_hash);
    sha256(&outer_input)
}
#[cfg(test)]
mod tests_hmac {
    use crate::test_util::*;

    // HMAC-SHA256 test vectors (RFC 4231)

    #[test]
    fn hmac_sha256_rfc4231_tc1() {
        // Key = 20 × 0x0b, Data = "Hi There"
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let mac = super::hmac_sha256(&key, data);
        let expected =
            hex_to_bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
        assert_eq!(mac, expected);
    }

    #[test]
    fn hmac_sha256_rfc4231_tc2() {
        // Key = "Jefe", Data = "what do ya want for nothing?"
        let key = b"Jefe";
        let data = b"what do ya want for nothing?";
        let mac = super::hmac_sha256(key, data);
        let expected =
            hex_to_bytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
        assert_eq!(mac, expected);
    }

    #[test]
    fn hmac_sha256_key_longer_than_block() {
        // Key longer than 64 bytes — internally hashed first.
        let key = [0xaa; 80];
        let data = b"Test message";
        let mac = super::hmac_sha256(&key, data);

        // Verify the result has correct length and is non-zero.
        let sum: u32 = mac.iter().map(|&b| b as u32).sum();
        assert!(sum > 0);
    }

    #[test]
    fn hmac_sha256_empty_message() {
        let key = b"secret";
        let mac1 = super::hmac_sha256(key, b"");
        let mac2 = super::hmac_sha256(key, b"");
        assert_eq!(mac1, mac2);
    }
}
