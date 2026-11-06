//! libs/crypto/src/gcm/mod.rs
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
mod tests;
