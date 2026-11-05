//! libs/crypto/src/aead.rs
//!
//! ChaCha20-Poly1305 AEAD (RFC 8439).

use crate::chacha20::chacha20_block;
use crate::chacha20::chacha20_keystream;
use crate::poly1305::poly1305_mac;
use abi::Error;
use abi::Result;
use alloc::vec::Vec;

/// Encrypt `plaintext` with ChaCha20-Poly1305 AEAD.
///
/// Returns `(ciphertext, 16_byte_tag)` where ciphertext has the same length
/// as plaintext.  `key` is 32 bytes, `nonce` is 12 bytes, `aad` is
/// additional authenticated data (may be empty).
pub fn chacha20_poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> (Vec<u8>, [u8; 16]) {
    // Generate Poly1305 one-time key from ChaCha20 with counter=0.
    let mut poly_key = [0u8; 32];
    chacha20_keystream(key, nonce, 0, &mut poly_key);

    // Encrypt plaintext with ChaCha20 starting at counter=1.
    let mut ciphertext = plaintext.to_vec();
    chacha20_encrypt_inner(key, nonce, 1, &mut ciphertext);

    // Build Poly1305 input: aad || pad(aad) || ciphertext || pad(ciphertext) ||
    // len(aad) || len(ciphertext)
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(aad);
    // Pad AAD to 16-byte boundary with zeros.
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    mac_input.resize(mac_input.len() + aad_pad, 0);
    mac_input.extend_from_slice(&ciphertext);
    // Pad ciphertext to 16-byte boundary with zeros.
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
    mac_input.resize(mac_input.len() + ct_pad, 0);
    // Append lengths as 64-bit little-endian.
    mac_input.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_input.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());

    let tag = poly1305_mac(&poly_key, &mac_input);
    (ciphertext, tag)
}

/// Decrypt and verify `ciphertext` with ChaCha20-Poly1305 AEAD.
///
/// Returns `Ok(plaintext)` if the tag verifies, or `Err` if authentication
/// fails.
pub fn chacha20_poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
    tag: &[u8; 16],
) -> Result<Vec<u8>> {
    // Generate Poly1305 one-time key.
    let mut poly_key = [0u8; 32];
    chacha20_keystream(key, nonce, 0, &mut poly_key);

    // Build Poly1305 input.
    let mut mac_input = Vec::new();
    mac_input.extend_from_slice(aad);
    let aad_pad = (16 - (aad.len() % 16)) % 16;
    mac_input.resize(mac_input.len() + aad_pad, 0);
    mac_input.extend_from_slice(ciphertext);
    let ct_pad = (16 - (ciphertext.len() % 16)) % 16;
    mac_input.resize(mac_input.len() + ct_pad, 0);
    mac_input.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    mac_input.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());

    let computed_tag = poly1305_mac(&poly_key, &mac_input);

    // Constant-time tag comparison.
    let mut diff: u8 = 0;
    for i in 0..16 {
        diff |= computed_tag[i] ^ tag[i];
    }
    if diff != 0 {
        return Err(Error::InvalidCredential);
    }

    // Decrypt.
    let mut plaintext = ciphertext.to_vec();
    chacha20_encrypt_inner(key, nonce, 1, &mut plaintext);
    Ok(plaintext)
}

/// Internal: encrypt/decrypt with ChaCha20 starting at a given counter.
/// XORs keystream with `data` in-place.
fn chacha20_encrypt_inner(key: &[u8; 32], nonce: &[u8; 12], start_counter: u32, data: &mut [u8]) {
    let mut counter = start_counter;
    for chunk in data.chunks_mut(64) {
        let keystream = chacha20_block(key, counter, nonce);
        for (byte, ks) in chunk.iter_mut().zip(keystream.iter()) {
            *byte ^= ks;
        }
        counter = counter.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests;
