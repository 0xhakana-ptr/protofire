//! libs/crypto/src/poly1305.rs
//!
//! Poly1305 one-time authenticator (RFC 8439 section 2.5).

/// Clamp the first 16 bytes of `r` per Poly1305 specification.
fn poly1305_clamp(key: &[u8; 32]) -> ([u8; 16], [u8; 16]) {
    let mut r = [0u8; 16];
    let mut s = [0u8; 16];
    r.copy_from_slice(&key[..16]);
    s.copy_from_slice(&key[16..]);
    // Clamp r.
    r[3] &= 15;
    r[7] &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4] &= 252;
    r[8] &= 252;
    r[12] &= 252;
    (r, s)
}

/// Poly1305 one-time authenticator (RFC 8439).
///
/// `key` must be exactly 32 bytes.  Returns a 16-byte authentication tag.
pub fn poly1305_mac(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let (r_bytes, s_bytes) = poly1305_clamp(key);

    let r = [
        u64::from_le_bytes([
            r_bytes[0], r_bytes[1], r_bytes[2], r_bytes[3], r_bytes[4], r_bytes[5], r_bytes[6],
            r_bytes[7],
        ]),
        u64::from_le_bytes([
            r_bytes[8],
            r_bytes[9],
            r_bytes[10],
            r_bytes[11],
            r_bytes[12],
            r_bytes[13],
            r_bytes[14],
            r_bytes[15],
        ]),
    ];

    // Accumulator as three 64-bit limbs: acc = a0 + a1*2^64 + a2*2^128.
    let mut a0: u64 = 0;
    let mut a1: u64 = 0;
    let mut a2: u64 = 0;

    // Process 16-byte blocks.
    // For full blocks, the appended 0x01 byte is at position 16 (= bit 128
    // = 2^128), which adds 1 to the a2 limb.
    let (chunks, remainder) = data.as_chunks::<16>();
    for chunk in chunks {
        let mut block = [0u8; 17];
        block[..16].copy_from_slice(chunk);
        block[16] = 0x01;
        let n0 = u64::from_le_bytes([
            block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7],
        ]);
        let n1 = u64::from_le_bytes([
            block[8], block[9], block[10], block[11], block[12], block[13], block[14], block[15],
        ]);

        // Add n0 + n1*2^64 + 2^128 to the accumulator.
        let t0 = a0 as u128 + n0 as u128;
        let t1 = a1 as u128 + n1 as u128 + (t0 >> 64);
        a0 = t0 as u64;
        a1 = t1 as u64;
        // carry from t1 + 1 for the 0x01 byte at bit 128.
        a2 = a2.wrapping_add((t1 >> 64) as u64).wrapping_add(1);

        poly1305_mul_mod(&mut a0, &mut a1, &mut a2, r);
    }

    // Final partial block.
    // The 0x01 byte is appended at `len`, so it already contributes to n0/n1
    // directly (its position is < 128 bits). No extra +1 to a2.
    if !remainder.is_empty() {
        let mut block = [0u8; 17];
        let len = remainder.len();
        block[..len].copy_from_slice(remainder);
        block[len] = 0x01;
        let n0 = u64::from_le_bytes([
            block[0], block[1], block[2], block[3], block[4], block[5], block[6], block[7],
        ]);
        let n1 = u64::from_le_bytes([
            block[8], block[9], block[10], block[11], block[12], block[13], block[14], block[15],
        ]);

        let t0 = a0 as u128 + n0 as u128;
        let t1 = a1 as u128 + n1 as u128 + (t0 >> 64);
        a0 = t0 as u64;
        a1 = t1 as u64;
        // No +1 for 0x01, already encoded in n0/n1 via LE interpretation.
        a2 = a2.wrapping_add((t1 >> 64) as u64);

        poly1305_mul_mod(&mut a0, &mut a1, &mut a2, r);
    }

    // Add s modulo 2^128.
    // a2 * 2^128 ≡ 0 (mod 2^128), so only a0 and a1 contribute.
    // Use u128 arithmetic for the additions to capture carries correctly.
    let s0 = u64::from_le_bytes([
        s_bytes[0], s_bytes[1], s_bytes[2], s_bytes[3], s_bytes[4], s_bytes[5], s_bytes[6],
        s_bytes[7],
    ]);
    let s1 = u64::from_le_bytes([
        s_bytes[8],
        s_bytes[9],
        s_bytes[10],
        s_bytes[11],
        s_bytes[12],
        s_bytes[13],
        s_bytes[14],
        s_bytes[15],
    ]);

    let t0 = a0 as u128 + s0 as u128;
    let carry0 = t0 >> 64;
    a0 = t0 as u64;
    let t1 = a1 as u128 + s1 as u128 + carry0;
    a1 = t1 as u64;
    // t1 may have a carry into a2 but it vanishes mod 2^128.

    // Output as 16-byte little-endian.
    let mut tag = [0u8; 16];
    tag[..8].copy_from_slice(&a0.to_le_bytes());
    tag[8..].copy_from_slice(&a1.to_le_bytes());
    tag
}

/// Multiply (a0,a1,a2) by r modulo 2^130 - 5.
///
/// Uses 128-bit arithmetic for intermediate products then reduces modulo
/// 2^130-5 using the identities 2^192 ≡ 5·2^62 and 2^128 ≡ 5·2^-2 (handled
/// via splitting: c2 = 4·c2_hi + c2_lo → c2·2^128 ≡ c2_hi·5 + c2_lo·2^128).
#[inline]
fn poly1305_mul_mod(a0: &mut u64, a1: &mut u64, a2: &mut u64, r: [u64; 2]) {
    let x0 = *a0 as u128;
    let x1 = *a1 as u128;
    let x2 = *a2 as u128;
    let r0 = r[0] as u128;
    let r1 = r[1] as u128;

    // Full product: P = h0 + h1·2^64 + h2·2^128 + h3·2^192
    let h0 = x0 * r0;
    let h1 = x0 * r1 + x1 * r0;
    let h2 = x1 * r1 + x2 * r0;
    let h3 = x2 * r1;

    // Step 1: carry propagation → get canonical 4-word representation.
    let c0 = h0 & 0xFFFF_FFFF_FFFF_FFFF;
    let c1 = (h1 + (h0 >> 64)) & 0xFFFF_FFFF_FFFF_FFFF;
    let s1 = h1 + (h0 >> 64);
    let c2 = (h2 + (s1 >> 64)) & 0xFFFF_FFFF_FFFF_FFFF;
    let s2 = h2 + (s1 >> 64);
    let c3 = h3 + (s2 >> 64);
    // P = c0 + c1·2^64 + c2·2^128 + c3·2^192

    // Step 2: reduce c3·2^192 using 2^192 = 2^130·2^62 ≡ 5·2^62.
    let c3s = c3 * 5;
    let mut r0_acc = c0 + ((c3s & 0x3) << 62);
    let mut r1_acc = c1 + ((c3s >> 2) & 0xFFFF_FFFF_FFFF_FFFF);

    // Step 3: reduce c2·2^128.
    // Write c2 = 4·c2_hi + c2_lo, then c2·2^128 = c2_hi·2^130 + c2_lo·2^128
    // ≡ c2_hi·5 + c2_lo·2^128.
    let c2_lo = c2 & 0x3;
    let c2_hi = c2 >> 2;
    r0_acc += c2_hi * 5;
    // c2_lo goes into the high limb.
    let mut r2_acc = c2_lo;

    // Step 4: propagate carries from r0 to r1, r1 to r2.
    let carry0 = r0_acc >> 64;
    r0_acc &= 0xFFFF_FFFF_FFFF_FFFF;
    r1_acc += carry0;
    let carry1 = r1_acc >> 64;
    r1_acc &= 0xFFFF_FFFF_FFFF_FFFF;
    r2_acc += carry1;

    *a0 = r0_acc as u64;
    *a1 = r1_acc as u64;
    *a2 = r2_acc as u64;
}

#[cfg(test)]
mod tests;
