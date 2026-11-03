//! libs/crypto/src/gcm.rs
//!
//! AES-128-GCM (NIST SP 800-38D): CTR mode with GHASH authentication.

use crate::aes::aes128_encrypt_block;
use abi::Error;
use abi::Result;
use alloc::vec::Vec;

/// GF(2^128) multiplication used for GHASH.
/// Multiplies two 128-bit values in GF(2^128) with the irreducible polynomial
/// x^128 + x^7 + x^2 + x + 1.
fn gf128_mul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut z = [0u8; 16];
    let mut v = *y;

    for &xi_byte in x.iter() {
        let mut xi = xi_byte;
        for _bit in 0..8 {
            if xi & 0x80 != 0 {
                // z ^= v
                for j in 0..16 {
                    z[j] ^= v[j];
                }
            }
            // Check if the low bit of v[15] is set (v * x mod polynomial)
            let lsb = v[15] & 1;
            // v >>= 1 (big-endian shift right)
            for j in (1..16).rev() {
                v[j] = (v[j] >> 1) | (v[j - 1] << 7);
            }
            v[0] >>= 1;
            // If the bit shifted out was 1, XOR with the polynomial.
            if lsb != 0 {
                v[0] ^= 0xe1; // x^7 + x^2 + x + 1 in upper byte
            }
            xi <<= 1;
        }
    }
    z
}

/// Increment a 128-bit counter (big-endian, increment the last 4 bytes).
fn gcm_ctr_inc(counter: &mut [u8; 16]) {
    for i in (12..16).rev() {
        counter[i] = counter[i].wrapping_add(1);
        if counter[i] != 0 {
            break;
        }
    }
}

/// GHASH of a single data string under key `h` (NIST SP 800-38D).
///
/// Every 16-byte block (final block zero-padded if short) is XORed into the
/// running tag and multiplied by `h` in GF(2^128).
fn ghash(h: &[u8; 16], data: &[u8]) -> [u8; 16] {
    let mut y = [0u8; 16];
    for chunk in data.chunks(16) {
        for i in 0..16 {
            if i < chunk.len() {
                y[i] ^= chunk[i];
            }
        }
        y = gf128_mul(&y, h);
    }
    y
}

/// Compute the GHASH authentication tag contribution for (aad, ciphertext).
fn gcm_ghash(h: &[u8; 16], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let mut data = Vec::new();
    data.extend_from_slice(aad);
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    data.resize(data.len() + aad_pad, 0);
    data.extend_from_slice(ciphertext);
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
    data.resize(data.len() + ct_pad, 0);

    // Final block: len(AAD) || len(C) as 64-bit big-endian each.
    let mut len_block = [0u8; 16];
    let aad_bits = (aad.len() as u64).wrapping_mul(8);
    let ct_bits = (ciphertext.len() as u64).wrapping_mul(8);
    len_block[..8].copy_from_slice(&aad_bits.to_be_bytes());
    len_block[8..].copy_from_slice(&ct_bits.to_be_bytes());
    data.extend_from_slice(&len_block);

    ghash(h, &data)
}

/// Encrypt `plaintext` with AES-128-GCM.
///
/// Returns `(ciphertext, 16_byte_tag)`.
/// `key` is 16 bytes, `nonce` is 12 bytes (96-bit IV), `aad` is optional
/// additional authenticated data.
pub fn aes128_gcm_encrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    // Hash subkey H = AES_K(0^128).
    let mut zero = [0u8; 16];
    aes128_encrypt_block(key, &mut zero);
    let h = zero;

    // Initial counter J0 = nonce || 0^31 || 1.
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 0x01;

    // Encrypt plaintext in CTR mode, starting from J0+1.
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    let mut counter = j0;
    gcm_ctr_inc(&mut counter); // J0 + 1

    for chunk in plaintext.chunks(16) {
        let mut ctr_blk = counter;
        aes128_encrypt_block(key, &mut ctr_blk);
        let keystream = ctr_blk;
        for (i, p) in chunk.iter().enumerate() {
            ciphertext.push(p ^ keystream[i]);
        }
        gcm_ctr_inc(&mut counter);
    }

    // Authentication tag.
    let ghash = gcm_ghash(&h, aad, &ciphertext);
    let mut j0_blk = j0;
    aes128_encrypt_block(key, &mut j0_blk);
    let s = j0_blk;
    let mut tag = [0u8; 16];
    for i in 0..16 {
        tag[i] = ghash[i] ^ s[i];
    }

    (ciphertext, tag)
}

/// Decrypt and verify `ciphertext` with AES-128-GCM.
///
/// Returns `Ok(plaintext)` if the tag verifies, or `Err` on authentication
/// failure.
pub fn aes128_gcm_decrypt(
    key: &[u8; 16],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>> {
    // Hash subkey H = AES_K(0^128).
    let mut zero = [0u8; 16];
    aes128_encrypt_block(key, &mut zero);
    let h = zero;

    // Verify tag before decrypting.
    let computed_ghash = gcm_ghash(&h, aad, ciphertext);
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(nonce);
    j0[15] = 0x01;
    let mut j0_blk = j0;
    aes128_encrypt_block(key, &mut j0_blk);
    let s = j0_blk;

    let mut computed_tag = [0u8; 16];
    let mut diff: u8 = 0;
    for i in 0..16 {
        computed_tag[i] = computed_ghash[i] ^ s[i];
        diff |= computed_tag[i] ^ tag[i];
    }
    if diff != 0 {
        return Err(Error::InvalidCredential);
    }

    // Decrypt in CTR mode.
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let mut counter = j0;
    gcm_ctr_inc(&mut counter); // J0 + 1

    for chunk in ciphertext.chunks(16) {
        let mut ctr_blk = counter;
        aes128_encrypt_block(key, &mut ctr_blk);
        let keystream = ctr_blk;
        for (i, c) in chunk.iter().enumerate() {
            plaintext.push(c ^ keystream[i]);
        }
        gcm_ctr_inc(&mut counter);
    }

    Ok(plaintext)
}
#[cfg(test)]
mod tests_gcm {

    // AES-128-GCM test vectors

    #[test]
    fn aes128_gcm_encrypt_decrypt_round_trip() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let nonce: [u8; 12] = [
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
        ];
        let aad = b"authenticated";
        let plaintext = b"Hello, AES-128-GCM!";

        let (ciphertext, tag) = super::aes128_gcm_encrypt(&key, &nonce, aad, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len());

        let decrypted = super::aes128_gcm_decrypt(&key, &nonce, aad, &ciphertext, &tag)
            .expect("decryption should succeed");
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn aes128_gcm_tag_verification_fails_with_wrong_key() {
        let key1: [u8; 16] = [0x00; 16];
        let key2: [u8; 16] = [0x01; 16];
        let nonce: [u8; 12] = [0x00; 12];
        let plaintext = b"sensitive";

        let (ciphertext, tag) = super::aes128_gcm_encrypt(&key1, &nonce, b"", plaintext);
        let result = super::aes128_gcm_decrypt(&key2, &nonce, b"", &ciphertext, &tag);
        assert!(result.is_err());
    }

    #[test]
    fn aes128_gcm_empty_plaintext() {
        let key: [u8; 16] = [0x42; 16];
        let nonce: [u8; 12] = [0x00; 12];
        let (ciphertext, tag) = super::aes128_gcm_encrypt(&key, &nonce, b"", b"");
        assert_eq!(ciphertext.len(), 0);
        assert_eq!(tag.len(), 16);
        // Should be able to decrypt empty ciphertext.
        let decrypted = super::aes128_gcm_decrypt(&key, &nonce, b"", &ciphertext, &tag)
            .expect("empty decryption");
        assert!(decrypted.is_empty());
    }

    #[test]
    fn aes128_gcm_known_vector() {
        // NIST GCM spec test case 3 (AES-128).
        let key: [u8; 16] = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30,
            0x83, 0x08,
        ];
        let nonce: [u8; 12] = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88,
        ];
        let aad = [
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad,
            0xbe, 0xef, 0xab, 0xad, 0xda, 0xd2,
        ];
        let plaintext = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5, 0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5,
            0x26, 0x9a, 0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda, 0x2e, 0x4c, 0x30, 0x3d,
            0x8a, 0x31, 0x8a, 0x72, 0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53, 0x2f, 0xcf,
            0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25, 0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39, 0x1a, 0xaf, 0xd2, 0x55,
        ];
        let expected_ct = [
            0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24, 0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0,
            0xd4, 0x9c, 0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0, 0x35, 0xc1, 0x7e, 0x23,
            0x29, 0xac, 0xa1, 0x2e, 0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c, 0x7d, 0x8f,
            0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05, 0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
            0x3d, 0x58, 0xe0, 0x91, 0x47, 0x3f, 0x59, 0x85,
        ];
        let expected_tag = [
            0xda, 0x80, 0xce, 0x83, 0x0c, 0xfd, 0xa0, 0x2d, 0xa2, 0xa2, 0x18, 0xa1, 0x74, 0x4f,
            0x4c, 0x76,
        ];
        let (ciphertext, tag) = super::aes128_gcm_encrypt(&key, &nonce, &aad, &plaintext);
        assert_eq!(ciphertext, expected_ct);
        assert_eq!(tag, expected_tag);

        // Decryption must round-trip and reject a corrupted tag.
        let decrypted =
            super::aes128_gcm_decrypt(&key, &nonce, &aad, &ciphertext, &tag).expect("GCM decrypt");
        assert_eq!(decrypted, plaintext);
        let mut bad_tag = tag;
        bad_tag[0] ^= 0x01;
        assert!(super::aes128_gcm_decrypt(&key, &nonce, &aad, &ciphertext, &bad_tag).is_err());
    }
}
