//! crypto/src/sha256.rs
//!
//! FIPS 180-4 SHA-256, and its digest as lowercase hex.

use alloc::string::String;
use alloc::vec::Vec;

/// Initial hash values (FIPS 180-4 Section 5.3.3).
const H_INIT: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// Round constants (FIPS 180-4 Section 4.2.2).
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

// FIPS 180-4 Section 4.1.2 — logical functions.
#[inline(always)]
fn ch(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

#[inline(always)]
fn maj(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

#[inline(always)]
fn cap_sigma0(x: u32) -> u32 {
    x.rotate_right(2) ^ x.rotate_right(13) ^ x.rotate_right(22)
}

#[inline(always)]
fn cap_sigma1(x: u32) -> u32 {
    x.rotate_right(6) ^ x.rotate_right(11) ^ x.rotate_right(25)
}

#[inline(always)]
fn sigma0(x: u32) -> u32 {
    x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3)
}

#[inline(always)]
fn sigma1(x: u32) -> u32 {
    x.rotate_right(17) ^ x.rotate_right(19) ^ (x >> 10)
}

/// Process one 512-bit message block (FIPS 180-4 Section 6.2.2).
fn compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];

    // Prepare message schedule W[0..15].
    for (t, chunk) in block.as_chunks::<4>().0.iter().take(16).enumerate() {
        w[t] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }

    // Extend to W[16..63].
    for t in 16..64 {
        w[t] = sigma1(w[t - 2])
            .wrapping_add(w[t - 7])
            .wrapping_add(sigma0(w[t - 15]))
            .wrapping_add(w[t - 16]);
    }

    // Initialize working variables.
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];

    // Compression rounds.
    for t in 0..64 {
        let t1 = h
            .wrapping_add(cap_sigma1(e))
            .wrapping_add(ch(e, f, g))
            .wrapping_add(K[t])
            .wrapping_add(w[t]);
        let t2 = cap_sigma0(a).wrapping_add(maj(a, b, c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }

    // Update state.
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

/// Compute the SHA-256 hash of `data` and return the 32-byte digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut state = H_INIT;
    let bit_len: u64 = (data.len() as u64).wrapping_mul(8);
    let mut remaining = data;

    // Process full 512-bit (64-byte) blocks.
    while remaining.len() >= 64 {
        let block: &[u8; 64] = remaining[..64].try_into().unwrap();
        compress(&mut state, block);
        remaining = &remaining[64..];
    }

    // Padding.
    let pad_len = if remaining.len() < 56 {
        64 - remaining.len()
    } else {
        128 - remaining.len()
    };

    let mut padded = Vec::with_capacity(remaining.len() + pad_len);
    padded.extend_from_slice(remaining);
    padded.push(0x80u8); // append '1' bit followed by zeros

    // Zero-pad to 8 bytes before the end of the block(s).
    let total_padded = if remaining.len() < 56 { 64 } else { 128 };
    while padded.len() < total_padded - 8 {
        padded.push(0u8);
    }

    // Append 64-bit big-endian message length.
    padded.extend_from_slice(&bit_len.to_be_bytes());

    // Process the final block(s).
    for block in padded.as_chunks::<64>().0 {
        compress(&mut state, block);
    }

    // Produce final digest as a flat byte array.
    let mut digest = [0u8; 32];
    for (i, word) in state.iter().enumerate() {
        let bytes = word.to_be_bytes();
        digest[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }
    digest
}

/// Return the SHA-256 digest of `data` as a 64-character lowercase hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let digest = sha256(data);
    let mut out = String::with_capacity(64);
    for byte in &digest {
        out.push(HEX_CHARS[(byte >> 4) as usize]);
        out.push(HEX_CHARS[(byte & 0x0f) as usize]);
    }
    out
}

const HEX_CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];
#[cfg(test)]
mod tests_sha256 {
    use super::*;

    #[test]
    fn sha256_hex_output() {
        let hex = sha256_hex(b"abc");
        assert_eq!(
            hex,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(hex.len(), 64);
    }
}
