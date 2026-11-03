//! crypto/src/aes.rs
//!
//! AES-128 and AES-256 block ciphers (NIST FIPS 197).
//!
//! The block functions are `pub(crate)` rather than public: a mode of
//! operation is what a caller wants, and an exposed raw block cipher is an
//! invitation to build one without a mode.  `gcm` and `xts` are the two
//! modes this tree uses, and they live beside this file.

/// AES-128 S-box (SubBytes substitution table).
const AES_SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// AES Round Constants (Rcon[i] = x^{i-1} in GF(2^8)).
const AES_RCON: [u8; 11] = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
];

/// Expand a 16-byte AES-128 key into 11 round keys (176 bytes).
fn aes128_key_expand(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut rk = [[0u8; 16]; 11];
    rk[0].copy_from_slice(key);

    for i in 1..11 {
        let mut temp = rk[i - 1][12..16].to_vec();
        // RotWord: circular left shift.
        temp.rotate_left(1);
        // SubWord: apply S-box to each byte.
        for b in &mut temp {
            *b = AES_SBOX[*b as usize];
        }
        // XOR with Rcon.
        temp[0] ^= AES_RCON[i];

        // XOR with previous round key word.
        for j in 0..4 {
            rk[i][j] = rk[i - 1][j] ^ temp[j];
        }
        for j in 4..8 {
            rk[i][j] = rk[i - 1][j] ^ rk[i][j - 4];
        }
        for j in 8..12 {
            rk[i][j] = rk[i - 1][j] ^ rk[i][j - 4];
        }
        for j in 12..16 {
            rk[i][j] = rk[i - 1][j] ^ rk[i][j - 4];
        }
    }
    rk
}

/// AddRoundKey: XOR state with round key.
#[inline(always)]
fn aes_add_round_key(state: &mut [u8; 16], rk: &[u8; 16]) {
    for i in 0..16 {
        state[i] ^= rk[i];
    }
}

/// SubBytes: apply S-box substitution to each byte.
#[inline(always)]
fn aes_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = AES_SBOX[*b as usize];
    }
}

/// ShiftRows: rotate rows left by 0, 1, 2, 3 bytes.
#[inline(always)]
fn aes_shift_rows(state: &mut [u8; 16]) {
    // Row 1: shift bytes [1,5,9,13] left by 1
    // Row 2: shift bytes [2,6,10,14] left by 2
    // Row 3: shift bytes [3,7,11,15] left by 3
    // State layout (column-major): 0 4  8 12
    //                               1 5  9 13
    //                               2 6 10 14
    //                               3 7 11 15
    let mut tmp = [0u8; 16];
    tmp.copy_from_slice(state);
    // Row 0: unchanged.
    state[1] = tmp[5];
    state[5] = tmp[9];
    state[9] = tmp[13];
    state[13] = tmp[1];
    state[2] = tmp[10];
    state[6] = tmp[14];
    state[10] = tmp[2];
    state[14] = tmp[6];
    state[3] = tmp[15];
    state[7] = tmp[3];
    state[11] = tmp[7];
    state[15] = tmp[11];
}

/// GF(2^8) multiplication by 2 (used in MixColumns).
#[inline(always)]
fn aes_xtime(x: u8) -> u8 {
    let hi = (x & 0x80) != 0;
    let r = x << 1;
    if hi { r ^ 0x1b } else { r }
}

/// MixColumns: mix each column using GF(2^8) arithmetic.
#[inline(always)]
fn aes_mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let base = col * 4;
        let s0 = state[base];
        let s1 = state[base + 1];
        let s2 = state[base + 2];
        let s3 = state[base + 3];
        state[base] = aes_xtime(s0) ^ aes_xtime(s1) ^ s1 ^ s2 ^ s3;
        state[base + 1] = s0 ^ aes_xtime(s1) ^ aes_xtime(s2) ^ s2 ^ s3;
        state[base + 2] = s0 ^ s1 ^ aes_xtime(s2) ^ aes_xtime(s3) ^ s3;
        state[base + 3] = aes_xtime(s0) ^ s0 ^ s1 ^ s2 ^ aes_xtime(s3);
    }
}

/// Expand a 32-byte AES-256 key into 15 round keys (240 bytes).
fn aes256_key_expand(key: &[u8; 32]) -> [[u8; 16]; 15] {
    let mut rk = [[0u8; 16]; 15];
    rk[0].copy_from_slice(&key[..16]);
    rk[1].copy_from_slice(&key[16..]);

    for i in 2..15 {
        let mut temp = rk[i - 1][12..16].to_vec();
        if i % 2 == 0 {
            // RotWord + SubWord + Rcon.
            temp.rotate_left(1);
            for b in &mut temp {
                *b = AES_SBOX[*b as usize];
            }
            temp[0] ^= AES_RCON[i / 2];
        } else {
            // SubWord only (i % 8 == 4).
            for b in &mut temp {
                *b = AES_SBOX[*b as usize];
            }
        }
        // w[i] = w[i-8] ^ temp.
        for j in 0..4 {
            rk[i][j] = rk[i - 2][j] ^ temp[j];
        }
        for j in 4..16 {
            rk[i][j] = rk[i - 2][j] ^ rk[i][j - 4];
        }
    }
    rk
}

/// Encrypt a single 16-byte block with AES-128, in place.
pub(crate) fn aes128_encrypt_block(key: &[u8; 16], block: &mut [u8; 16]) {
    let rk = aes128_key_expand(key);
    aes_add_round_key(block, &rk[0]);

    for rk_round in &rk[1..10] {
        aes_sub_bytes(block);
        aes_shift_rows(block);
        aes_mix_columns(block);
        aes_add_round_key(block, rk_round);
    }

    // Final round: no MixColumns.
    aes_sub_bytes(block);
    aes_shift_rows(block);
    aes_add_round_key(block, &rk[10]);
}

/// Encrypt a single 16-byte block with AES-256, in place.
pub(crate) fn aes256_encrypt_block(key: &[u8; 32], block: &mut [u8; 16]) {
    let rk = aes256_key_expand(key);
    aes_add_round_key(block, &rk[0]);

    for rk_round in &rk[1..14] {
        aes_sub_bytes(block);
        aes_shift_rows(block);
        aes_mix_columns(block);
        aes_add_round_key(block, rk_round);
    }

    aes_sub_bytes(block);
    aes_shift_rows(block);
    aes_add_round_key(block, &rk[14]);
}

/// AES inverse S-box (used by decryption).
const AES_INV_SBOX: [u8; 256] = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d,
];

/// Inverse ShiftRows: rotate rows right by 0, 1, 2, 3 bytes.
#[inline(always)]
fn aes_inv_shift_rows(state: &mut [u8; 16]) {
    let mut tmp = [0u8; 16];
    tmp.copy_from_slice(state);
    // Row 1: shift right by 1.
    state[1] = tmp[13];
    state[5] = tmp[1];
    state[9] = tmp[5];
    state[13] = tmp[9];
    // Row 2: shift right by 2.
    state[2] = tmp[10];
    state[6] = tmp[14];
    state[10] = tmp[2];
    state[14] = tmp[6];
    // Row 3: shift right by 3.
    state[3] = tmp[7];
    state[7] = tmp[11];
    state[11] = tmp[15];
    state[15] = tmp[3];
}

/// Inverse SubBytes: apply the inverse S-box to each byte.
#[inline(always)]
fn aes_inv_sub_bytes(state: &mut [u8; 16]) {
    for b in state.iter_mut() {
        *b = AES_INV_SBOX[*b as usize];
    }
}

/// GF(2^8) multiplication used by InvMixColumns.
#[inline(always)]
fn aes_gmul(x: u8, y: u8) -> u8 {
    let mut p = 0u8;
    let mut a = x;
    let mut b = y;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let hi = a & 0x80 != 0;
        a <<= 1;
        if hi {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    p
}

/// Inverse MixColumns: multiply each column by the inverse matrix.
#[inline(always)]
fn aes_inv_mix_columns(state: &mut [u8; 16]) {
    for col in 0..4 {
        let base = col * 4;
        let s0 = state[base];
        let s1 = state[base + 1];
        let s2 = state[base + 2];
        let s3 = state[base + 3];
        state[base] =
            aes_gmul(0x0e, s0) ^ aes_gmul(0x0b, s1) ^ aes_gmul(0x0d, s2) ^ aes_gmul(0x09, s3);
        state[base + 1] =
            aes_gmul(0x09, s0) ^ aes_gmul(0x0e, s1) ^ aes_gmul(0x0b, s2) ^ aes_gmul(0x0d, s3);
        state[base + 2] =
            aes_gmul(0x0d, s0) ^ aes_gmul(0x09, s1) ^ aes_gmul(0x0e, s2) ^ aes_gmul(0x0b, s3);
        state[base + 3] =
            aes_gmul(0x0b, s0) ^ aes_gmul(0x0d, s1) ^ aes_gmul(0x09, s2) ^ aes_gmul(0x0e, s3);
    }
}

/// Decrypt a single 16-byte block with AES-128, in place.
///
/// GCM and CTR decrypt with the *encrypt* primitive, so nothing in the tree
/// calls this outside its own test: the XTS entry points here are AES-256 and
/// take 64-byte keys.  Kept because a block-mode cipher that can only go one
/// way is an invitation to write the inverse somewhere worse.
#[allow(dead_code)]
pub(crate) fn aes128_decrypt_block(key: &[u8; 16], block: &mut [u8; 16]) {
    let rk = aes128_key_expand(key);
    aes_add_round_key(block, &rk[10]);
    for rk_round in (1..10).rev() {
        aes_inv_shift_rows(block);
        aes_inv_sub_bytes(block);
        aes_add_round_key(block, &rk[rk_round]);
        aes_inv_mix_columns(block);
    }
    aes_inv_shift_rows(block);
    aes_inv_sub_bytes(block);
    aes_add_round_key(block, &rk[0]);
}

/// Decrypt a single 16-byte block with AES-256, in place.
pub(crate) fn aes256_decrypt_block(key: &[u8; 32], block: &mut [u8; 16]) {
    let rk = aes256_key_expand(key);
    aes_add_round_key(block, &rk[14]);
    for rk_round in (1..14).rev() {
        aes_inv_shift_rows(block);
        aes_inv_sub_bytes(block);
        aes_add_round_key(block, &rk[rk_round]);
        aes_inv_mix_columns(block);
    }
    aes_inv_shift_rows(block);
    aes_inv_sub_bytes(block);
    aes_add_round_key(block, &rk[0]);
}
#[cfg(test)]
mod tests_aes {
    use super::*;

    // AES-128 test vectors (NIST FIPS 197 Appendix B)

    #[test]
    fn aes128_encrypt_block_known_vector() {
        let key: [u8; 16] = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        let plaintext: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];
        let expected: [u8; 16] = [
            0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb, 0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a,
            0x0b, 0x32,
        ];
        let mut result = plaintext;
        super::aes128_encrypt_block(&key, &mut result);
        assert_eq!(result, expected);
    }

    #[test]
    fn aes128_decrypt_matches_encrypt_known_vector() {
        let key: [u8; 16] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f,
        ];
        let plaintext: [u8; 16] = [
            0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37,
            0x07, 0x34,
        ];
        let expected_ct: [u8; 16] = [
            0x89, 0xed, 0x5e, 0x6a, 0x05, 0xca, 0x76, 0x33, 0x81, 0x35, 0x08, 0x5f, 0xe2, 0x1c,
            0x40, 0xbd,
        ];
        let mut block = plaintext;
        super::aes128_encrypt_block(&key, &mut block);
        assert_eq!(block, expected_ct);

        super::aes128_decrypt_block(&key, &mut block);
        assert_eq!(block, plaintext);
    }

    #[test]
    fn aes256_encrypt_decrypt_known_vector() {
        // FIPS 197 Appendix C.3 AES-256: key 0x000102..0f1011..1f,
        // plaintext 0x00112233445566778899aabbccddeeff
        // ciphertext 0x8ea2b7ca516745bfeafc49904b496089.
        let key: [u8; 32] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let mut block: [u8; 16] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
            0xee, 0xff,
        ];
        let expected: [u8; 16] = [
            0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49,
            0x60, 0x89,
        ];
        super::aes256_encrypt_block(&key, &mut block);
        assert_eq!(block, expected);

        super::aes256_decrypt_block(&key, &mut block);
        assert_eq!(
            block,
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff
            ]
        );
    }

    #[test]
    fn inv_sbox_is_inverse_of_sbox() {
        #[allow(clippy::needless_range_loop)]
        for i in 0..256usize {
            let out = AES_SBOX[i];
            assert_eq!(AES_INV_SBOX[out as usize], i as u8);
        }
    }
}
