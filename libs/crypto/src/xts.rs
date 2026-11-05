//! libs/crypto/src/xts.rs
//!
//! AES-XTS (IEEE 1619), the mode a full-disk encryption header uses.
//!
//! The 128-bit tweak is formed from the sector id and encrypted with the
//! tweak key; each 16-byte data block is XORed with the running tweak,
//! encrypted with the data key, and XORed with the tweak again.  Between
//! blocks the tweak is multiplied by `x` in GF(2^128) (reduction polynomial
//! 0x87, little-endian byte order).

use crate::aes::aes256_decrypt_block;
use crate::aes::aes256_encrypt_block;

// the sector id and encrypted with the tweak key; each 16-byte data block is
// XORed with the running tweak, encrypted with the data key, and XORed with
// the tweak again.  Between blocks the tweak is multiplied by `x` in
// GF(2^128) (reduction polynomial 0x87, little-endian byte order).

/// Multiply a 128-bit tweak by `x` in GF(2^128) (the XTS "alpha" step).
///
/// IEEE 1619 stores an element as 16 bytes with the *low* byte first: the
/// tweak a sector starts from is the tweak key's encryption of the sector
/// number as a little-endian integer, and the bytes that come out are then
/// read that way.  Multiplying by `x` is therefore a 1-bit left shift that
/// carries **into the higher byte**, with the bit shifted out of the last byte
/// folded back into the first with the polynomial's 0x87.
///
/// This was written the other way round, carry out of `t[0]`, 0x87 into
/// `t[15]`, which is the big-endian reading, and the comment above said
/// "big-endian" to match.  It is wrong, and a LUKS2 keyslot area is where it
/// shows: a decrypted area came out right for its first block and garbage
/// after, because the first block is the only one whose tweak is used as
/// computed, every later one needs this step.  Measured against the tree's
/// own fixture, the correct direction and the old one agree on the leading
/// 16 bytes and nothing after them.  With the carry reversed the whole unit
/// matches OpenSSL's XTS.
fn xts_mul_alpha(tweak: &[u8; 16]) -> [u8; 16] {
    let mut t = *tweak;
    let carry = t[15] >> 7;
    let mut i = 15;
    while i > 0 {
        t[i] = (t[i] << 1) | (t[i - 1] >> 7);
        i -= 1;
    }
    t[0] <<= 1;
    if carry == 1 {
        t[0] ^= 0x87;
    }
    t
}

/// XOR each byte of `a` into `out`.
fn xor_bytes_into(out: &mut [u8], a: &[u8]) {
    for (o, x) in out.iter_mut().zip(a.iter()) {
        *o ^= x;
    }
}

/// Encrypt `data` in-place with AES-256-XTS (IEEE 1619).
///
/// `key` is 64 bytes: `key[..32]` is the data key and `key[32..]` is the
/// tweak key (both AES-256).  `sector_id` selects the initial tweak, encoded
/// little-endian in the first 8 bytes of the 16-byte tweak.  `data.len()`
/// must be a multiple of 16.
pub fn aes_xts_encrypt(key: &[u8; 64], sector_id: u64, data: &mut [u8]) {
    let tweak_key: &[u8; 32] = key[32..].try_into().expect("xts tweak key 32 bytes");

    // Initial tweak from the sector id (little-endian) in the low half.
    let mut tweak = [0u8; 16];
    tweak[..8].copy_from_slice(&sector_id.to_le_bytes());
    aes256_encrypt_block(tweak_key, &mut tweak);

    for chunk in data.chunks_mut(16) {
        let c: &mut [u8; 16] = chunk.try_into().expect("16-byte chunk");
        for (i, b) in c.iter_mut().enumerate() {
            *b ^= tweak[i];
        }
        aes256_encrypt_block(&key[..32].try_into().expect("xts data key 32 bytes"), c);
        for (i, b) in c.iter_mut().enumerate() {
            *b ^= tweak[i];
        }
        tweak = xts_mul_alpha(&tweak);
    }
}

/// Decrypt `data` in-place with AES-256-XTS (IEEE 1619).
pub fn aes_xts_decrypt(key: &[u8; 64], sector_id: u64, data: &mut [u8]) {
    let tweak_key: &[u8; 32] = key[32..].try_into().expect("xts tweak key 32 bytes");

    let mut tweak = [0u8; 16];
    tweak[..8].copy_from_slice(&sector_id.to_le_bytes());
    aes256_encrypt_block(tweak_key, &mut tweak);

    for chunk in data.chunks_mut(16) {
        // Decrypt in place needs the original ciphertext for the second XOR,
        // so buffer the first XOR (tweak ^ ciphertext) in a temp block.
        let c: &mut [u8; 16] = chunk.try_into().expect("16-byte chunk");
        let mut buf = *c;
        xor_bytes_into(&mut buf, &tweak);
        aes256_decrypt_block(
            &key[..32].try_into().expect("xts data key 32 bytes"),
            &mut buf,
        );
        xor_bytes_into(&mut buf, &tweak);
        c.copy_from_slice(&buf);
        tweak = xts_mul_alpha(&tweak);
    }
}

#[cfg(test)]
mod tests;
