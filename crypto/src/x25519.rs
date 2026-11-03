//! crypto/src/x25519.rs
//!
//! X25519 Diffie-Hellman (RFC 7748).
//!
//! Montgomery form: y^2 = x^3 + 486662 x^2 + x over GF(2^255 - 19), base
//! point u-coordinate 9.  Field elements are five 51-bit limbs,
//! little-endian.

use crate::sha256::sha256;

/// Mask for 51-bit limbs: (1 << 51) - 1.
const MASK_51: u64 = (1u64 << 51) - 1; // 0x0007_FFFF_FFFF_FFFF

/// 2^255 - 19 as 5 51-bit limbs.
/// (2^255 - 1) - 18  decomposes as [MASK_51-18, MASK_51, MASK_51, MASK_51,
/// MASK_51].
const FE25519_PRIME: [u64; 5] = [MASK_51 - 18, MASK_51, MASK_51, MASK_51, MASK_51];

/// A field element in GF(2^255 - 19), stored as 5 51-bit limbs (little-endian).
type Fe25519 = [u64; 5];

/// Carry from the i-th limb to the next, reducing each limb.
///
/// After the forward sweep, limb 4 may still have bits ≥ 2^51.
/// Those bits represent multiples of 2^255, and since 2^255 ≡ 19 (mod p),
/// we fold them back to limb 0 and re-propagate.  The loop repeats until
/// limb 4 is fully reduced (never more than two iterations in practice).
#[inline]
fn fe25519_carry(x: &mut Fe25519) {
    loop {
        // Forward sweep: carry limbs 0→1→2→3→4.
        for i in 0..4 {
            let carry = x[i] >> 51;
            x[i] &= MASK_51;
            x[i + 1] = x[i + 1].wrapping_add(carry);
        }
        // Fold the carry out of limb 4 back to limb 0.
        let wrap = x[4] >> 51;
        if wrap == 0 {
            break;
        }
        x[4] &= MASK_51;
        x[0] = x[0].wrapping_add(wrap.wrapping_mul(19));
        // Loop again to propagate any new carry from limb 0.
    }
}

/// Fully reduce a field element to canonical form (< p).
fn fe25519_reduce(x: &mut Fe25519) {
    fe25519_carry(x);
    // After carry, the value is < 2^255 + tiny.  Subtract p if >= p.
    let (below, borrow) = fe25519_sub_internal(x, &FE25519_PRIME);
    if !borrow {
        // x >= p, so x - p < p. Use the reduced value.
        *x = below;
    }
    // Otherwise x < p already.
}

/// Internal: compute a - b with borrow propagation.  Returns (result,
/// borrow_out).
fn fe25519_sub_internal(a: &Fe25519, b: &Fe25519) -> (Fe25519, bool) {
    let mut out = [0u64; 5];
    let mut borrow: u64 = 0;
    for i in 0..5 {
        let (sub, br1) = a[i].overflowing_sub(b[i]);
        let (sub, br2) = sub.overflowing_sub(borrow);
        out[i] = sub;
        borrow = (br1 || br2) as u64;
    }
    (out, borrow != 0)
}

/// Field addition: a + b (mod p).
fn fe25519_add(a: &Fe25519, b: &Fe25519) -> Fe25519 {
    let mut out = [0u64; 5];
    for i in 0..5 {
        out[i] = a[i].wrapping_add(b[i]);
    }
    fe25519_reduce(&mut out);
    out
}

/// Field subtraction: a - b (mod p).
///
/// Subtracts at 51-bit limb boundaries (the native representation),
/// avoiding the u64 wrapping mismatch that occurs with the generic
/// `fe25519_sub_internal`.
fn fe25519_sub(a: &Fe25519, b: &Fe25519) -> Fe25519 {
    // Subtract at 51-bit boundaries.  Each limb is in [0, 2^51), so
    // the difference without wrapping is in (-2^51, 2^51).  We borrow
    // 2^51 from the next limb whenever the result goes negative.
    let mut result = [0u64; 5];
    let mut borrow: i64 = 0;
    for i in 0..5 {
        let diff = (a[i] as i128) - (b[i] as i128) - (borrow as i128);
        if diff < 0 {
            result[i] = (diff + (1i128 << 51)) as u64;
            borrow = 1;
        } else {
            result[i] = diff as u64;
            borrow = 0;
        }
    }

    if borrow > 0 {
        // a < b.  Compute b - a (positive, in canonical 51-bit form),
        // then return p - (b - a).  This avoids the double-wrapping
        // that occurs when naively adding p to the wrapped diff.
        let mut b_minus_a = [0u64; 5];
        let mut b_borrow: i64 = 0;
        for i in 0..5 {
            let diff = (b[i] as i128) - (a[i] as i128) - (b_borrow as i128);
            if diff < 0 {
                b_minus_a[i] = (diff + (1i128 << 51)) as u64;
                b_borrow = 1;
            } else {
                b_minus_a[i] = diff as u64;
                b_borrow = 0;
            }
        }
        debug_assert_eq!(b_borrow, 0, "b > a guarantee");

        // p - (b - a): guaranteed non-negative since b-a < p (both a,b < p).
        let mut p_borrow: i64 = 0;
        for i in 0..5 {
            let diff = (FE25519_PRIME[i] as i128) - (b_minus_a[i] as i128) - (p_borrow as i128);
            if diff < 0 {
                result[i] = (diff + (1i128 << 51)) as u64;
                p_borrow = 1;
            } else {
                result[i] = diff as u64;
                p_borrow = 0;
            }
        }
        debug_assert_eq!(p_borrow, 0, "p > b-a guarantee");
    }
    // else a >= b: result limbs are already in [0, 2^51).  No carry needed.

    result
}

/// Field multiplication: a * b (mod p).
///
/// Each a[i], b[j] is at most 51 bits.  Every partial product a[i]·b[j] is
/// folded directly into the correct 51-bit limb of the accumulator using the
/// identity 2^255 ≡ 19 (mod p).  This avoids a separate 9-entry product array
/// and the attendant carry-splitting complexity.
fn fe25519_mul(a: &Fe25519, b: &Fe25519) -> Fe25519 {
    let mut acc = [0u128; 5];

    for (i, &ai) in a.iter().enumerate() {
        for (j, &bj) in b.iter().enumerate() {
            let prod = (ai as u128) * (bj as u128);
            let pos = i + j;
            if pos < 5 {
                acc[pos] = acc[pos].wrapping_add(prod);
            } else {
                // 2^(pos·51) = 2^(255 + (pos-5)·51) ≡ 19 · 2^((pos-5)·51)
                acc[pos - 5] = acc[pos - 5].wrapping_add(prod.wrapping_mul(19));
            }
        }
    }

    // Carry chain: bring each limb below 2^51.
    for _pass in 0..2 {
        for i in 0..4 {
            acc[i + 1] = acc[i + 1].wrapping_add(acc[i] >> 51);
            acc[i] &= MASK_51 as u128;
        }
        // Fold the carry out of limb 4 back to limb 0 (2^255 ≡ 19).
        let wrap = acc[4] >> 51;
        acc[4] &= MASK_51 as u128;
        acc[0] = acc[0].wrapping_add(wrap.wrapping_mul(19));
    }

    // One final carry sweep guarantees each limb fits in u64.
    for i in 0..4 {
        acc[i + 1] = acc[i + 1].wrapping_add(acc[i] >> 51);
        acc[i] &= MASK_51 as u128;
    }
    // acc[4] may still have a tiny wrap — fold it once more.
    let wrap = acc[4] >> 51;
    acc[4] &= MASK_51 as u128;
    acc[0] = acc[0].wrapping_add(wrap.wrapping_mul(19));

    let mut result: Fe25519 = [
        acc[0] as u64,
        acc[1] as u64,
        acc[2] as u64,
        acc[3] as u64,
        acc[4] as u64,
    ];
    fe25519_reduce(&mut result);
    result
}

/// Field squaring: a^2 (mod p).  Marginally faster than general multiply.
fn fe25519_square(a: &Fe25519) -> Fe25519 {
    fe25519_mul(a, a)
}

/// Modular inverse using Fermat's little theorem: a^(p-2) mod p.
fn fe25519_inv(a: &Fe25519) -> Fe25519 {
    // p - 2 = 2^255 - 19 - 2 = 2^255 - 21
    // We compute a^(p-2) by repeated squaring.
    let sq = |x: &Fe25519| fe25519_square(x);
    let mul = |x: &Fe25519, y: &Fe25519| fe25519_mul(x, y);

    // Chain: 2^255 - 21.  Use addition-chain / square-and-multiply.
    // Start with a^1.
    let mut result = *a;

    // Raise to 2^255 - 21 via square-and-multiply.
    // 2^255 - 21 =
    // 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeb
    // 252 bits set to 1, except the lowest few bits.
    // Strategy: set result = a, then square 255 times, multiplying by a at
    // the positions where the exponent bit is 1.
    //
    // But (p-2) has most bits set, so it's more efficient to square 255 times
    // and multiply where needed.  Since most bits are 1, we do a squaring
    // followed by a multiply at each step.

    // Simpler approach: use 255 iterations of square-then-conditional-multiply.
    // Exponent in binary:
    // 2^255 - 21 = 2^255 - 16 - 4 - 1 = 2^255 - 0b10101
    // = 0x7FF...FEB
    // = all 1s from bit 254 down to bit 0, except bits 0, 2, 4 are 0.

    // Use a shorter chain: compute a^(2^255 - 21) as:
    //   a^(2^255 - 21) = a^(2^255 - 1) * a^(-20)
    // This is a bit complicated.  Let's just do the straightforward
    // square-and-multiply.

    // Exponent p-2 = 2^255 - 21.  Bits 2 and 4 are 0; bits 0,1,3,5..254 are 1.
    // (21 = 16+4+1, so subtracting from 2^255 clears bits 2,4; bit 0 = 1 since
    // result is odd.) Start with result = a (MSB bit 254 already consumed).
    let mut i: i32 = 253;
    while i >= 0 {
        result = sq(&result);
        // Bit i is 1 unless i == 2 or i == 4.
        if i != 2 && i != 4 {
            result = mul(&result, a);
        }
        i -= 1;
    }

    result
}

/// Conditional swap of two field elements if `swap` is true (constant-time).
fn fe25519_cswap(a: &mut Fe25519, b: &mut Fe25519, swap: bool) {
    let mask = if swap { !0u64 } else { 0u64 };
    for i in 0..5 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
}

/// Montgomery ladder step for X25519.
/// Computes (x2, z2, x3, z3) ← ladder_step(x1, x2, z2, x3, z3).
fn x25519_ladder_step(
    x1: &Fe25519,
    x2: &mut Fe25519,
    z2: &mut Fe25519,
    x3: &mut Fe25519,
    z3: &mut Fe25519,
) {
    let a = fe25519_add(x2, z2); // A  = x2 + z2
    let aa = fe25519_square(&a); // AA = A^2
    let b = fe25519_sub(x2, z2); // B  = x2 - z2
    let bb = fe25519_square(&b); // BB = B^2
    let e = fe25519_sub(&aa, &bb); // E  = AA - BB
    let c = fe25519_add(x3, z3); // C  = x3 + z3
    let d = fe25519_sub(x3, z3); // D  = x3 - z3
    let da = fe25519_mul(&d, &a); // DA = D * A
    let cb = fe25519_mul(&c, &b); // CB = C * B
    *x3 = fe25519_square(&fe25519_add(&da, &cb)); // x3 = (DA + CB)^2
    let tmp = fe25519_sub(&da, &cb); // (DA - CB)
    *z3 = fe25519_mul(x1, &fe25519_square(&tmp)); // z3 = x1 * (DA - CB)^2
    *x2 = fe25519_mul(&aa, &bb); // x2 = AA * BB
    // a24 = 121665 = (486662-2)/4
    let a24: Fe25519 = [121665, 0, 0, 0, 0];
    *z2 = fe25519_mul(&e, &fe25519_add(&aa, &fe25519_mul(&a24, &e)));
    // z2 = E * (AA + a24 * E)
}

/// X25519 scalar multiplication: compute `scalar * u_coord`.
///
/// Returns the u-coordinate of the result point.
/// `scalar` is 32 bytes (clamped internally).
/// `u_coord` is the u-coordinate of the input point (32 bytes, little-endian).
pub fn x25519(scalar: &[u8; 32], u_coord: &[u8; 32]) -> [u8; 32] {
    // Clamp scalar: clear bits 0, 1, 2; set bit 254; clear bit 255.
    let mut clamped = *scalar;
    clamped[0] &= 248;
    clamped[31] &= 127;
    clamped[31] |= 64;

    // Decode u-coordinate.
    let u = fe25519_from_bytes(u_coord);

    // Montgomery ladder.
    let x1 = u;
    let mut x2 = FE25519_ONE;
    let mut z2 = FE25519_ZERO;
    let mut x3 = u;
    let mut z3 = FE25519_ONE;

    let mut swap: bool = false;

    for i in (0..255).rev() {
        let bit = (clamped[i >> 3] >> (i & 7)) & 1;
        let do_swap = (bit == 1) ^ swap;
        fe25519_cswap(&mut x2, &mut x3, do_swap);
        fe25519_cswap(&mut z2, &mut z3, do_swap);
        swap = bit == 1;

        x25519_ladder_step(&x1, &mut x2, &mut z2, &mut x3, &mut z3);
    }
    fe25519_cswap(&mut x2, &mut x3, swap);
    fe25519_cswap(&mut z2, &mut z3, swap);

    // Result u-coordinate = x2 * z2^(-1).
    let z2_inv = fe25519_inv(&z2);
    let result_pt = fe25519_mul(&x2, &z2_inv);
    fe25519_to_bytes(&result_pt)
}

const FE25519_ZERO: Fe25519 = [0, 0, 0, 0, 0];
const FE25519_ONE: Fe25519 = [1, 0, 0, 0, 0];

/// Decode a 32-byte little-endian integer into a field element.
///
/// Reads the 32 LE bytes as a 255-bit integer (top bit cleared) and
/// decomposes it into 5 limbs of 51 bits each using u128 arithmetic.
fn fe25519_from_bytes(bytes: &[u8; 32]) -> Fe25519 {
    let lo = u128::from_le_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
        bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]);
    let hi_raw = u128::from_le_bytes([
        bytes[16], bytes[17], bytes[18], bytes[19], bytes[20], bytes[21], bytes[22], bytes[23],
        bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
    ]);
    let hi = hi_raw & 0x7FFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFFu128;

    let mut out = [0u64; 5];

    // total = lo + hi * 2^128.  Extract 51-bit limbs by repeatedly
    // shifting down.  u128 wrapping on `hi << 77` naturally discards
    // the bits that go past bit 127; `hi >> 51` captures them.
    out[0] = (lo & (MASK_51 as u128)) as u64;

    let v1 = (lo >> 51) | (hi.wrapping_shl(77));
    let hi1 = hi >> 51;
    out[1] = (v1 & (MASK_51 as u128)) as u64;

    let v2 = (v1 >> 51) | (hi1.wrapping_shl(77));
    let hi2 = hi1 >> 51;
    out[2] = (v2 & (MASK_51 as u128)) as u64;

    let v3 = (v2 >> 51) | (hi2.wrapping_shl(77));
    let hi3 = hi2 >> 51;
    out[3] = (v3 & (MASK_51 as u128)) as u64;

    let v4 = (v3 >> 51) | (hi3.wrapping_shl(77));
    out[4] = (v4 & (MASK_51 as u128)) as u64;

    out
}

/// Encode a field element into 32 bytes little-endian.
///
/// Reverses the decomposition performed by `fe25519_from_bytes`.
fn fe25519_to_bytes(fe: &Fe25519) -> [u8; 32] {
    let t = *fe;

    // Reconstruct total = limb[0] + limb[1]*2^51 + limb[2]*2^102
    //                         + limb[3]*2^153 + limb[4]*2^204
    // Then pack into lo (bits 0-127) and hi (bits 128-255).

    let total_lo = (t[0] as u128) | ((t[1] as u128) << 51) | ((t[2] as u128) << 102);
    // In u128, (t[2] << 102) wraps, keeping only the low 26 bits.
    // The upper 25 bits of limb[2] go into hi.

    let total_hi = (t[2] as u128 >> 26) // upper 25 bits of limb[2]
        | ((t[3] as u128) << 25)         // limb[3]
        | ((t[4] as u128) << (25 + 51)); // limb[4]

    let lo = total_lo; // u128 wrapping already cleared overflow bits
    let hi = total_hi & 0x7FFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFFu128;

    let mut out = [0u8; 32];
    out[..16].copy_from_slice(&lo.to_le_bytes());
    out[16..].copy_from_slice(&hi.to_le_bytes());
    out
}

/// Generate an X25519 key pair.
///
/// Returns `(private_key, public_key)` where each is 32 bytes.
/// `private_key` is the 32-byte secret scalar.
/// `public_key` is the result of `x25519(private_key, base_point)`.
pub fn x25519_keygen() -> ([u8; 32], [u8; 32]) {
    // No RNG dependency in this bare-metal kernel.  Derive a deterministic
    // private key from a constant salt via SHA-256 and clamp it per RFC 7748.
    // NOTE: this is NOT cryptographically random — acceptable only for the
    // recovery prototype; production must use a true entropy source.
    let mut private = sha256(b"protofire-x25519-keygen");
    // Clamp per RFC 7748 §5.
    private[0] &= 248;
    private[31] &= 127;
    private[31] |= 64;
    let public = x25519(&private, &X25519_BASE_POINT_BYTES);
    (private, public)
}

/// The X25519 base point (u-coordinate = 9) as bytes.
const X25519_BASE_POINT_BYTES: [u8; 32] = {
    let mut b = [0u8; 32];
    b[0] = 9;
    b
};
#[cfg(test)]
mod tests_x25519 {

    // X25519 test vectors (RFC 7748 §5.2)

    // Field arithmetic sanity tests

    #[test]
    fn fe25519_add_sub_identity() {
        use super::fe25519_add;
        use super::fe25519_from_bytes;
        use super::fe25519_sub;
        use super::fe25519_to_bytes;

        let a_bytes = [0x42u8; 32];
        let b_bytes = [0x13u8; 32];
        let a = fe25519_from_bytes(&a_bytes);
        let b = fe25519_from_bytes(&b_bytes);
        let sum = fe25519_add(&a, &b);
        let diff = fe25519_sub(&sum, &b);
        let a_back = fe25519_to_bytes(&diff);
        // a_back should equal a mod p.
        // Since a is small (< p), it should be exact.
        assert_eq!(a_back, a_bytes, "add-sub identity failed");
    }

    #[test]
    fn fe25519_mul_identity() {
        use super::fe25519_from_bytes;
        use super::fe25519_mul;
        use super::fe25519_to_bytes;

        let one: super::Fe25519 = [1, 0, 0, 0, 0];
        let a_bytes = [0x2a; 32];
        let a = fe25519_from_bytes(&a_bytes);
        let result = fe25519_mul(&a, &one);
        let result_bytes = fe25519_to_bytes(&result);
        assert_eq!(result_bytes, a_bytes, "mul-by-one identity failed");
    }

    #[test]
    fn fe25519_encode_decode_roundtrip() {
        use super::fe25519_from_bytes;
        use super::fe25519_to_bytes;

        // Random-looking bytes.
        let bytes: [u8; 32] = [
            0x9a, 0xd6, 0x3b, 0x88, 0xf7, 0x2c, 0x15, 0x4e, 0x3d, 0x92, 0xa1, 0xbf, 0x60, 0x7d,
            0x41, 0x33, 0x8c, 0xde, 0xab, 0x54, 0x19, 0x72, 0xef, 0xc6, 0x0a, 0xbb, 0x33, 0x99,
            0x4d, 0x28, 0x1e, 0x7f,
        ];
        let fe = fe25519_from_bytes(&bytes);
        let recovered = fe25519_to_bytes(&fe);
        assert_eq!(recovered, bytes, "encode-decode roundtrip failed");
    }

    #[test]
    fn x25519_rfc7748_first_iteration() {
        // After 1 iteration: scalar = 1, u = 9 → output.
        let scalar: [u8; 32] = [
            0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d, 0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46,
            0x5e, 0xdd, 0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18, 0x50, 0x6a, 0x22, 0x44,
            0xba, 0x44, 0x9a, 0xc4,
        ];
        let u_coord: [u8; 32] = [
            0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb, 0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1,
            0x5f, 0x7c, 0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b, 0x10, 0xa9, 0x03, 0xa6,
            0xd0, 0xab, 0x1c, 0x4c,
        ];
        let expected: [u8; 32] = [
            0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90, 0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d,
            0x08, 0x4f, 0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7, 0x54, 0xb4, 0x07, 0x55,
            0x77, 0xa2, 0x85, 0x52,
        ];
        let result = super::x25519(&scalar, &u_coord);
        assert_eq!(result, expected);
    }

    #[test]
    fn x25519_rfc7748_second_iteration() {
        // After 2 iterations: uses the output of iteration 1 as new u.
        let scalar: [u8; 32] = [
            0x4b, 0x66, 0xe9, 0xd4, 0xd1, 0xb4, 0x67, 0x3c, 0x5a, 0xd2, 0x26, 0x91, 0x95, 0x7d,
            0x6a, 0xf5, 0xc1, 0x1b, 0x64, 0x21, 0xe0, 0xea, 0x01, 0xd4, 0x2c, 0xa4, 0x16, 0x9e,
            0x79, 0x18, 0xba, 0x0d,
        ];
        let u_coord: [u8; 32] = [
            0xe5, 0x21, 0x0f, 0x12, 0x78, 0x68, 0x11, 0xd3, 0xf4, 0xb7, 0x95, 0x9d, 0x05, 0x38,
            0xae, 0x2c, 0x31, 0xdb, 0xe7, 0x10, 0x6f, 0xc0, 0x3c, 0x3e, 0xfc, 0x4c, 0xd5, 0x49,
            0xc7, 0x15, 0xa4, 0x93,
        ];
        let expected: [u8; 32] = [
            0x95, 0xcb, 0xde, 0x94, 0x76, 0xe8, 0x90, 0x7d, 0x7a, 0xad, 0xe4, 0x5c, 0xb4, 0xb8,
            0x73, 0xf8, 0x8b, 0x59, 0x5a, 0x68, 0x79, 0x9f, 0xa1, 0x52, 0xe6, 0xf8, 0xf7, 0x64,
            0x7a, 0xac, 0x79, 0x57,
        ];
        let result = super::x25519(&scalar, &u_coord);
        assert_eq!(result, expected);
    }

    #[test]
    fn x25519_basepoint_multiply() {
        // Scalar multiply with the base point (u=9).
        // Arbitrary scalar, just verify it produces consistent output.
        let scalar: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let u_coord: [u8; 32] = [
            0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let result1 = super::x25519(&scalar, &u_coord);
        let result2 = super::x25519(&scalar, &u_coord);
        assert_eq!(result1, result2, "X25519 should be deterministic");

        // Result should be non-zero for non-zero scalar.
        let sum: u64 = result1.iter().map(|&b| b as u64).sum();
        assert!(sum > 0, "X25519 result should be non-zero");
    }

    #[test]
    fn x25519_keygen_produces_valid_keys() {
        let (private, public) = super::x25519_keygen();
        assert_eq!(private.len(), 32);
        assert_eq!(public.len(), 32);
        // Public key should be non-zero for a random private key.
        let sum: u64 = public.iter().map(|&b| b as u64).sum();
        assert!(sum > 0);
    }
}

#[cfg(test)]
mod field_debug_tests {
    use super::*;

    #[test]
    fn fe25519_mul_reference() {
        // a = 123456789012345678901234567890, b = 987654321012345
        let a: Fe25519 = [1091739049724626, 54825827883118, 0, 0, 0];
        let b: Fe25519 = [987654321012345, 0, 0, 0, 0];
        let got = fe25519_mul(&a, &b);
        let want: Fe25519 = [79892000831810, 1259430764839786, 24046971441578, 0, 0];
        assert_eq!(got, want, "mul mismatch: got {got:?}");
    }

    #[test]
    fn fe25519_square_reference() {
        let a: Fe25519 = [1091739049724626, 54825827883118, 0, 0, 0];
        let got = fe25519_square(&a);
        let want: Fe25519 = [
            1715883656418372,
            1665434582479255,
            2159184764567970,
            1334875056299,
            0,
        ];
        assert_eq!(got, want, "sq mismatch: got {got:?}");
    }

    #[test]
    fn fe25519_sub_reference() {
        let a: Fe25519 = [1091739049724626, 54825827883118, 0, 0, 0];
        let b: Fe25519 = [987654321012345, 0, 0, 0, 0];
        let got = fe25519_sub(&a, &b);
        let want: Fe25519 = [104084728712281, 54825827883118, 0, 0, 0];
        assert_eq!(got, want, "sub mismatch: got {got:?}");
    }

    #[test]
    fn fe25519_add_reference() {
        let a: Fe25519 = [1091739049724626, 54825827883118, 0, 0, 0];
        let b: Fe25519 = [987654321012345, 0, 0, 0, 0];
        let got = fe25519_add(&a, &b);
        let want: Fe25519 = [2079393370736971, 54825827883118, 0, 0, 0];
        assert_eq!(got, want, "add mismatch: got {got:?}");
    }

    #[test]
    fn fe25519_inv_reference() {
        let a: Fe25519 = [1091739049724626, 54825827883118, 0, 0, 0];
        let got = fe25519_inv(&a);
        let want: Fe25519 = [
            981237069453266,
            194231194608803,
            290761331866964,
            216053795122436,
            2154218031290001,
        ];
        assert_eq!(got, want, "inv mismatch: got {got:?}");
    }
}

#[cfg(test)]
mod x25519_correctness_tests {
    // RFC 7748 §6.1 fixed scalar DH vector (validated against Python
    // reference).
    #[test]
    fn x25519_rfc7748_canonical_vector() {
        let scalar: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2,
            0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5,
            0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let u: [u8; 32] = [
            0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];
        let expected: [u8; 32] = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e,
            0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e,
            0xaa, 0x9b, 0x4e, 0x6a,
        ];
        let result = super::x25519(&scalar, &u);
        assert_eq!(
            result, expected,
            "canonical X25519 vector mismatch: got {result:02x?}"
        );
    }
}
