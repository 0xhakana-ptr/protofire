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
/// This was written the other way round — carry out of `t[0]`, 0x87 into
/// `t[15]`, which is the big-endian reading — and the comment above said
/// "big-endian" to match.  It is wrong, and a LUKS2 keyslot area is where it
/// shows: a decrypted area came out right for its first block and garbage
/// after, because the first block is the only one whose tweak is used as
/// computed — every later one needs this step.  Measured against the tree's
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
mod tests_xts {

    // AES-XTS test vectors (IEEE 1619)

    #[test]
    fn aes_xts_encrypt_decrypt_round_trip() {
        let key = [0x37u8; 64];
        let mut data = alloc::vec![0u8; 512];
        #[allow(clippy::needless_range_loop)]
        for i in 0..512 {
            data[i] = (i & 0xFF) as u8;
        }
        let mut enc = data.clone();
        super::aes_xts_encrypt(&key, 12345, &mut enc);
        let mut dec = enc.clone();
        super::aes_xts_decrypt(&key, 12345, &mut dec);
        assert_eq!(dec, data, "XTS round-trip should recover plaintext");
    }

    #[test]
    fn aes_xts_encrypt_decrypt_different_sectors_differ() {
        let key = [0x11u8; 64];
        let data = alloc::vec![0xABu8; 64];
        let mut enc1 = data.clone();
        let mut enc2 = data.clone();
        super::aes_xts_encrypt(&key, 0, &mut enc1);
        super::aes_xts_encrypt(&key, 1, &mut enc2);
        assert_ne!(enc1, enc2, "adjacent sectors must encrypt differently");
    }

    #[test]
    fn aes_xts_known_vector() {
        // NIST XTS-AES-256 test vector (IEEE 1619 / CAVS):
        // key = 2718281828459045235360287471352662497757247093699959574966967627
        //        3141592653589793238462643383279502884197169399375105820974944592
        // tweak = ff000000000000000000000000000000  (sector_id = 255, LE)
        // data = 000102030405060708090a0b0c0d0e0f
        // ct   = 1c3b3a102f770386e4836c99e370cf9b
        let key: [u8; 64] = [
            0x27, 0x18, 0x28, 0x18, 0x28, 0x45, 0x90, 0x45, 0x23, 0x53, 0x60, 0x28, 0x74, 0x71,
            0x35, 0x26, 0x62, 0x49, 0x77, 0x57, 0x24, 0x70, 0x93, 0x69, 0x99, 0x59, 0x57, 0x49,
            0x66, 0x96, 0x76, 0x27, 0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97, 0x93, 0x23, 0x84,
            0x62, 0x64, 0x33, 0x83, 0x27, 0x95, 0x02, 0x88, 0x41, 0x97, 0x16, 0x93, 0x99, 0x37,
            0x51, 0x05, 0x82, 0x09, 0x74, 0x94, 0x45, 0x92,
        ];
        let mut data: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let expected: [u8; 16] = [
            0x1c, 0x3b, 0x3a, 0x10, 0x2f, 0x77, 0x03, 0x86, 0xe4, 0x83, 0x6c, 0x99, 0xe3, 0x70,
            0xcf, 0x9b,
        ];
        // sector_id 255 (0xff) encodes little-endian as ff 00 00 00 00 00 00
        // 00, matching the NIST tweak ff000000000000000000000000000000.
        super::aes_xts_encrypt(&key, 255, &mut data);
        assert_eq!(data, expected);

        super::aes_xts_decrypt(&key, 255, &mut data);
        assert_eq!(
            data,
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f
            ]
        );
    }

    /// The alpha step across four blocks, not one.
    ///
    /// The single-block NIST vector above cannot see `xts_mul_alpha`: one
    /// block never advances the tweak, so a multiplication that shifts the
    /// bytes the wrong way passes it.  This one is four blocks of the same key
    /// and the same sector, generated with OpenSSL through Python's
    /// `cryptography`, and its first block is the single-block answer — which
    /// is what makes it the same test extended rather than a second opinion.
    ///
    /// Measured, this is what the wrong direction costs: the first block
    /// decrypts correctly and everything after it is garbage — 16 bytes agree
    /// and the rest does not — which reads as "the cipher works" until
    /// something spans a block.  A LUKS2 keyslot area spans 500 of them.
    #[test]
    fn aes_xts_known_vector_across_blocks() {
        let key: [u8; 64] = [
            0x27, 0x18, 0x28, 0x18, 0x28, 0x45, 0x90, 0x45, 0x23, 0x53, 0x60, 0x28, 0x74, 0x71,
            0x35, 0x26, 0x62, 0x49, 0x77, 0x57, 0x24, 0x70, 0x93, 0x69, 0x99, 0x59, 0x57, 0x49,
            0x66, 0x96, 0x76, 0x27, 0x31, 0x41, 0x59, 0x26, 0x53, 0x58, 0x97, 0x93, 0x23, 0x84,
            0x62, 0x64, 0x33, 0x83, 0x27, 0x95, 0x02, 0x88, 0x41, 0x97, 0x16, 0x93, 0x99, 0x37,
            0x51, 0x05, 0x82, 0x09, 0x74, 0x94, 0x45, 0x92,
        ];
        let mut data = [0u8; 64];
        for (i, byte) in data.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let expected: [u8; 64] = [
            0x1c, 0x3b, 0x3a, 0x10, 0x2f, 0x77, 0x03, 0x86, 0xe4, 0x83, 0x6c, 0x99, 0xe3, 0x70,
            0xcf, 0x9b, 0xea, 0x00, 0x80, 0x3f, 0x5e, 0x48, 0x23, 0x57, 0xa4, 0xae, 0x12, 0xd4,
            0x14, 0xa3, 0xe6, 0x3b, 0x5d, 0x31, 0xe2, 0x76, 0xf8, 0xfe, 0x4a, 0x8d, 0x66, 0xb3,
            0x17, 0xf9, 0xac, 0x68, 0x3f, 0x44, 0x68, 0x0a, 0x86, 0xac, 0x35, 0xad, 0xfc, 0x33,
            0x45, 0xbe, 0xfe, 0xcb, 0x4b, 0xb1, 0x88, 0xfd,
        ];
        super::aes_xts_encrypt(&key, 255, &mut data);
        assert_eq!(data, expected);
        super::aes_xts_decrypt(&key, 255, &mut data);
        assert_eq!(data[0], 0, "decrypt must recover the plaintext");
    }
}
