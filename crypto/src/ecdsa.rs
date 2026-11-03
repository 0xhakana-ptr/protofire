//! crypto/src/ecdsa.rs
//!
//! ECDSA over P-256 (secp256r1) signature verification
//! (NIST FIPS 186-5 / SEC 2).
//!
//! Field arithmetic modulo the P-256 prime, point operations on the curve
//! y^2 = x^3 + ax + b, and the verification formula
//! u1 = e*s^-1 mod n, u2 = r*s^-1 mod n, R = u1*G + u2*Q, check R.x == r (mod
//! n).

use alloc::vec::Vec;

/// P-256 prime: 2^256 - 2^224 + 2^192 + 2^96 - 1.
const P256_PRIME: [u64; 4] = [
    0xFFFF_FFFF_FFFF_FFFF,
    0x0000_0000_FFFF_FFFF,
    0x0000_0000_0000_0000,
    0xFFFF_FFFF_0000_0001,
];

/// P-256 curve coefficient a = -3 mod p.
const P256_A: [u64; 4] = [
    0xFFFF_FFFF_FFFF_FFFC,
    0x0000_0000_FFFF_FFFF,
    0x0000_0000_0000_0000,
    0xFFFF_FFFF_0000_0001,
];

/// P-256 curve coefficient b.
/// 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B (LE).
#[allow(dead_code)]
const P256_B: [u64; 4] = [
    0x3BCE_3C3E_27D2_604B,
    0x651D_06B0_CC53_B0F6,
    0xB3EB_BD55_7698_86BC,
    0x5AC6_35D8_AA3A_93E7,
];

/// P-256 generator G affine x.
/// 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296 (LE).
const P256_GX: [u64; 4] = [
    0xF4A1_3945_D898_C296,
    0x7703_7D81_2DEB_33A0,
    0xF8BC_E6E5_63A4_40F2,
    0x6B17_D1F2_E12C_4247,
];

/// P-256 generator G affine y.
/// 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5 (LE).
const P256_GY: [u64; 4] = [
    0xCBB6_4068_37BF_51F5,
    0x2BCE_3357_6B31_5ECE,
    0x8EE7_EB4A_7C0F_9E16,
    0x4FE3_42E2_FE1A_7F9B,
];

/// P-256 curve order n.
/// 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 (LE).
const P256_ORDER: [u64; 4] = [
    0xF3B9_CAC2_FC63_2551,
    0xBCE6_FAAD_A717_9E84,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_0000_0000,
];

/// c = 2^256 - P256_PRIME, so 2^256 ≡ c (mod p).
/// c = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF00000000000000000000000000000001 (LE).
const P256_C: [u64; 4] = [
    0x0000_0000_0000_0001,
    0xFFFF_FFFF_0000_0000,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFE,
];

/// c_n = 2^256 - P256_ORDER, so 2^256 ≡ c_n (mod n).
/// c_n = 0xFFFFFFFF00000000000000004319055258E8617B0C46353D039CDAAF (LE).
const P256_ORDER_C: [u64; 4] = [
    0x0C46_353D_039C_DAAF,
    0x4319_0552_58E8_617B,
    0x0000_0000_0000_0000,
    0x0000_0000_FFFF_FFFF,
];

// 256-bit field element

/// A 256-bit field element stored as four 64-bit limbs (little-endian).
#[derive(Clone, Copy)]
struct Fe256([u64; 4]);

impl Fe256 {
    const ZERO: Self = Fe256([0; 4]);
    const ONE: Self = Fe256([1, 0, 0, 0]);

    fn from_limbs(limbs: [u64; 4]) -> Self {
        Fe256(limbs)
    }

    /// Create from a big-endian byte slice, reducing mod p if needed.
    fn from_bytes_be(bytes: &[u8; 32]) -> Self {
        let mut limbs = [0u64; 4];
        for (i, chunk) in bytes.chunks(8).enumerate() {
            let mut val = 0u64;
            for &b in chunk {
                val = (val << 8) | (b as u64);
            }
            limbs[3 - i] = val;
        }
        Fe256(limbs)
    }

    fn is_zero(&self) -> bool {
        self.0[0] == 0 && self.0[1] == 0 && self.0[2] == 0 && self.0[3] == 0
    }

    /// Compare against a 4-limb constant.
    fn cmp_limbs(&self, other: &[u64; 4]) -> core::cmp::Ordering {
        for i in (0..4).rev() {
            match self.0[i].cmp(&other[i]) {
                core::cmp::Ordering::Equal => {}
                ord => return ord,
            }
        }
        core::cmp::Ordering::Equal
    }

    /// Modular addition: (self + rhs) mod p.
    fn add(&self, rhs: &Fe256) -> Fe256 {
        let mut carry = 0u64;
        let mut r = [0u64; 4];
        for ((&a, &b), r_item) in self.0.iter().zip(rhs.0.iter()).zip(r.iter_mut()) {
            let (s, c1) = a.overflowing_add(b);
            let (s2, c2) = s.overflowing_add(carry);
            *r_item = s2;
            carry = (c1 as u64) + (c2 as u64);
        }
        // Conditional subtraction of p if carry or r >= p.
        if carry > 0 || Fe256(r).cmp_limbs(&P256_PRIME) >= core::cmp::Ordering::Equal {
            let mut borrow = 0u64;
            for (r_item, &p_limb) in r.iter_mut().zip(P256_PRIME.iter()) {
                let (s1, b1) = r_item.overflowing_sub(p_limb);
                let (s2, b2) = s1.overflowing_sub(borrow);
                *r_item = s2;
                borrow = (b1 as u64) + (b2 as u64);
            }
        }
        Fe256(r)
    }

    /// Modular subtraction: (self - rhs) mod p.
    fn sub(&self, rhs: &Fe256) -> Fe256 {
        let mut borrow = 0u64;
        let mut r = [0u64; 4];
        for ((&a, &b), r_item) in self.0.iter().zip(rhs.0.iter()).zip(r.iter_mut()) {
            let (s1, b1) = a.overflowing_sub(b);
            let (s2, b2) = s1.overflowing_sub(borrow);
            *r_item = s2;
            borrow = (b1 as u64) + (b2 as u64);
        }
        if borrow > 0 {
            let mut carry = 0u64;
            for (r_item, &p_limb) in r.iter_mut().zip(P256_PRIME.iter()) {
                let (s, c) = r_item.overflowing_add(p_limb);
                let (s2, c2) = s.overflowing_add(carry);
                *r_item = s2;
                carry = (c as u64) + (c2 as u64);
            }
        }
        Fe256(r)
    }

    /// Modular multiplication using Barrett reduction.
    fn mul(&self, rhs: &Fe256) -> Fe256 {
        let mut prod = [0u64; 8];
        // The index arithmetic is the algorithm: `prod[i + j]` accumulates the
        // schoolbook product's columns, and an `enumerate()` iterator would
        // have to be re-indexed through a running offset to say the same thing
        // — which is what the lint suggests and what this comment refuses.  The
        // lint is right that both indices walk the array; it is wrong that the
        // walk is what the loop is about.
        #[allow(clippy::needless_range_loop)]
        for i in 0..4 {
            let mut carry = 0u64;
            for j in 0..4 {
                let idx = i + j;
                let (lo, hi) = mul_wide(self.0[i], rhs.0[j]);
                let (s1, c1) = prod[idx].overflowing_add(lo);
                let (s2, c2) = s1.overflowing_add(carry);
                prod[idx] = s2;
                carry = hi + (c1 as u64) + (c2 as u64);
            }
            // Propagate the carry out of this row fully.
            let mut idx = i + 4;
            while carry > 0 && idx < 8 {
                let (s, c) = prod[idx].overflowing_add(carry);
                prod[idx] = s;
                carry = c as u64;
                idx += 1;
            }
        }
        barrett_reduce(&prod)
    }

    /// Modular square: self² mod p.
    fn square(&self) -> Fe256 {
        self.mul(self)
    }

    /// Modular inverse via Fermat's little theorem: self^(p-2) mod p.
    fn invert(&self) -> Fe256 {
        // p - 2: subtract 2 from the lowest limb (index 0).
        let mut r = Fe256::ONE;
        let base = *self;
        let mut exp = P256_PRIME;
        exp[0] -= 2;
        for limb_idx in (0..4).rev() {
            let mut limb = exp[limb_idx];
            for _ in 0..64 {
                // Square the running result, then multiply by base on set bits.
                r = r.square();
                if limb & 0x8000_0000_0000_0000 != 0 {
                    r = r.mul(&base);
                }
                limb <<= 1;
            }
        }
        r
    }
}

/// Multiply two u64 values, returning (low, high).
#[inline]
fn mul_wide(a: u64, b: u64) -> (u64, u64) {
    let p = (a as u128) * (b as u128);
    (p as u64, (p >> 64) as u64)
}

/// Reduce a 512-bit value (8 little-endian limbs) modulo a 256-bit modulus.
///
/// Uses the Solinas-style folding identity `2^256 = c (mod m)`, where
/// `c = 2^256 - m` (for m = P-256's prime p and curve order n, `c < 2^224`):
/// for `x = x_hi·2^256 + x_lo`, `x = x_lo + x_hi·c (mod m)`.
///
/// Repeatedly folding the high limbs shrinks x to below 2^256, after which
/// at most two conditional subtractions of m finish the reduction.  For both
/// P-256 moduli, x_hi·c < 2^481, so the intermediate never exceeds 8 limbs
/// (verified against an independent big-integer reference).
fn reduce_512_mod(s: &[u64; 8], c: &[u64; 4], modulus: &[u64; 4]) -> Fe256 {
    let mut v = [0u64; 8];
    v.copy_from_slice(s);

    // Fold the high half into the low half until only the low 4 limbs matter.
    for _ in 0..16 {
        if v[4] == 0 && v[5] == 0 && v[6] == 0 && v[7] == 0 {
            break;
        }
        let hi = [v[4], v[5], v[6], v[7]];
        let lo = [v[0], v[1], v[2], v[3]];
        let prod = mul_256_by_256(&hi, c); // hi·c, at most 8 limbs
        let mut out = [0u64; 8];
        let mut carry = 0u64;
        for i in 0..4 {
            let (s1, c1) = lo[i].overflowing_add(prod[i]);
            let (s2, c2) = s1.overflowing_add(carry);
            out[i] = s2;
            carry = (c1 as u64) + (c2 as u64);
        }
        for i in 4..8 {
            let (s1, c1) = prod[i].overflowing_add(carry);
            out[i] = s1;
            carry = c1 as u64;
        }
        // lo + hi·c < 2^256 + 2^481 < 2^512 for both P-256 moduli.
        debug_assert!(carry == 0);
        v = out;
    }

    // Final conditional subtraction (v < 2^256 < 2·m, so ≤ 1 subtraction in
    // practice; loop twice for safety).
    let mut r = [v[0], v[1], v[2], v[3]];
    for _ in 0..3 {
        if Fe256(r).cmp_limbs(modulus) >= core::cmp::Ordering::Equal {
            let mut borrow = 0u64;
            for i in 0..4 {
                let (s1, b1) = r[i].overflowing_sub(modulus[i]);
                let (s2, b2) = s1.overflowing_sub(borrow);
                r[i] = s2;
                borrow = (b1 as u64) + (b2 as u64);
            }
        } else {
            break;
        }
    }
    Fe256(r)
}

/// Fast reduction modulo P-256 prime: x mod p.
fn barrett_reduce(s: &[u64; 8]) -> Fe256 {
    reduce_512_mod(s, &P256_C, &P256_PRIME)
}

// Curve points

/// Affine point on the P-256 curve, or the point at infinity.
#[derive(Clone, Copy)]
struct P256Point {
    x: Fe256,
    y: Fe256,
    is_infinity: bool,
}

impl P256Point {
    const INFINITY: Self = P256Point {
        x: Fe256::ZERO,
        y: Fe256::ZERO,
        is_infinity: true,
    };

    fn is_infinity(&self) -> bool {
        self.is_infinity
    }

    /// Point addition: self + other.
    fn add(&self, other: &P256Point) -> P256Point {
        if self.is_infinity() {
            return *other;
        }
        if other.is_infinity() {
            return *self;
        }
        // Check for same x.
        if self.x.cmp_limbs(&other.x.0) == core::cmp::Ordering::Equal {
            if self.y.cmp_limbs(&other.y.0) == core::cmp::Ordering::Equal {
                if self.y.is_zero() {
                    return P256Point::INFINITY;
                }
                return self.double();
            }
            return P256Point::INFINITY; // P + (-P) = O
        }
        // λ = (y₂ - y₁) / (x₂ - x₁)
        let dx = other.x.sub(&self.x);
        let dy = other.y.sub(&self.y);
        let lambda = dy.mul(&dx.invert());
        let lambda2 = lambda.square();
        let x3 = lambda2.sub(&self.x).sub(&other.x);
        let y3 = lambda.mul(&self.x.sub(&x3)).sub(&self.y);
        P256Point {
            x: x3,
            y: y3,
            is_infinity: false,
        }
    }

    /// Point doubling: 2 * self.
    fn double(&self) -> P256Point {
        if self.is_infinity() || self.y.is_zero() {
            return P256Point::INFINITY;
        }
        // λ = (3x² + a) / (2y)
        let x2 = self.x.square();
        let three_x2 = x2.add(&x2).add(&x2);
        let a_fe = Fe256::from_limbs(P256_A);
        let numerator = three_x2.add(&a_fe);
        let denominator = self.y.add(&self.y);
        let lambda = numerator.mul(&denominator.invert());
        let x3 = lambda.square().sub(&self.x).sub(&self.x);
        let y3 = lambda.mul(&self.x.sub(&x3)).sub(&self.y);
        P256Point {
            x: x3,
            y: y3,
            is_infinity: false,
        }
    }

    /// Scalar multiplication: k * self, using double-and-add (MSB-first).
    fn mul_scalar(&self, k: &[u64; 4]) -> P256Point {
        let mut result = P256Point::INFINITY;
        let addend = *self;
        for limb_idx in (0..4).rev() {
            let mut limb = k[limb_idx];
            for _ in 0..64 {
                // Double the running result, then add `self` on set bits.
                result = result.double();
                if limb & 0x8000_0000_0000_0000 != 0 {
                    result = result.add(&addend);
                }
                limb <<= 1;
            }
        }
        result
    }
}

fn p256_generator() -> P256Point {
    P256Point {
        x: Fe256::from_limbs(P256_GX),
        y: Fe256::from_limbs(P256_GY),
        is_infinity: false,
    }
}

// ECDSA verification

/// Parse a big-endian integer from bytes into an Fe256 (reduced mod n).
fn parse_ecdsa_int(bytes: &[u8]) -> Option<Fe256> {
    if bytes.is_empty() {
        return None;
    }
    // Strip leading zeros.
    let mut start = 0;
    while start < bytes.len() && bytes[start] == 0 {
        start += 1;
    }
    let trimmed = &bytes[start..];
    if trimmed.len() > 33 || (trimmed.len() == 33 && trimmed[0] > 0) {
        return None;
    }
    let mut arr = [0u8; 32];
    let copy_start = 32usize.saturating_sub(trimmed.len());
    let copy_len = trimmed.len().min(32);
    arr[copy_start..copy_start + copy_len].copy_from_slice(&trimmed[..copy_len]);
    Some(Fe256::from_bytes_be(&arr))
}

/// Modular inverse and multiplication modulo the curve order n.
impl Fe256 {
    fn invert_mod_n(&self) -> Fe256 {
        let mut r = Fe256::ONE;
        let base = *self;
        let mut exp = P256_ORDER;
        exp[0] -= 2;
        for limb_idx in (0..4).rev() {
            let mut limb = exp[limb_idx];
            for _ in 0..64 {
                // Square the running result, then multiply by base on set bits.
                r = r.mul_mod_n(&r);
                if limb & 0x8000_0000_0000_0000 != 0 {
                    r = r.mul_mod_n(&base);
                }
                limb <<= 1;
            }
        }
        r
    }

    fn mul_mod_n(&self, rhs: &Fe256) -> Fe256 {
        let mut prod = [0u64; 8];
        // The index arithmetic is the algorithm: `prod[i + j]` accumulates the
        // schoolbook product's columns, and an `enumerate()` iterator would
        // have to be re-indexed through a running offset to say the same thing
        // — which is what the lint suggests and what this comment refuses.  The
        // lint is right that both indices walk the array; it is wrong that the
        // walk is what the loop is about.
        #[allow(clippy::needless_range_loop)]
        for i in 0..4 {
            let mut carry = 0u64;
            for j in 0..4 {
                let idx = i + j;
                let (lo, hi) = mul_wide(self.0[i], rhs.0[j]);
                let (s1, c1) = prod[idx].overflowing_add(lo);
                let (s2, c2) = s1.overflowing_add(carry);
                prod[idx] = s2;
                carry = hi + (c1 as u64) + (c2 as u64);
            }
            // Propagate the carry out of this row fully.
            let mut idx = i + 4;
            while carry > 0 && idx < 8 {
                let (s, c) = prod[idx].overflowing_add(carry);
                prod[idx] = s;
                carry = c as u64;
                idx += 1;
            }
        }
        reduce_mod_n(&prod)
    }
}

/// Fast reduction modulo the curve order n.
/// n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551.
fn reduce_mod_n(x: &[u64; 8]) -> Fe256 {
    reduce_512_mod(x, &P256_ORDER_C, &P256_ORDER)
}

/// Multiply two 256-bit values (4 limbs each), returning 8 limbs.
fn mul_256_by_256(a: &[u64; 4], b: &[u64; 4]) -> [u64; 8] {
    let mut prod = [0u64; 8];
    for (i, &av) in a.iter().enumerate() {
        let mut carry = 0u64;
        for (j, &bv) in b.iter().enumerate() {
            let idx = i + j;
            let (lo, hi) = mul_wide(av, bv);
            let (s1, c1) = prod[idx].overflowing_add(lo);
            let (s2, c2) = s1.overflowing_add(carry);
            prod[idx] = s2;
            carry = hi + (c1 as u64) + (c2 as u64);
        }
        // Propagate the carry out of this row fully (it may overflow limb
        // i+4 and need to continue into i+5, i+6, ...).
        let mut idx = i + 4;
        while carry > 0 && idx < 8 {
            let (s, c) = prod[idx].overflowing_add(carry);
            prod[idx] = s;
            carry = c as u64;
            idx += 1;
        }
    }
    prod
}

/// ECDSA P-256 signature verification.
///
/// Verifies that `(r, s)` is a valid signature over `message_hash` (32-byte
/// SHA-256 digest) using the given uncompressed public key (65 bytes:
/// 0x04 || x || y).
///
/// Returns `true` if the signature is valid per NIST FIPS 186-5.
pub fn ecdsa_p256_verify(public_key: &[u8], message_hash: &[u8; 32], r: &[u8], s: &[u8]) -> bool {
    if public_key.len() != 65 || public_key[0] != 0x04 {
        return false;
    }
    let mut px = [0u8; 32];
    let mut py = [0u8; 32];
    px.copy_from_slice(&public_key[1..33]);
    py.copy_from_slice(&public_key[33..65]);
    let qx = Fe256::from_bytes_be(&px);
    let qy = Fe256::from_bytes_be(&py);

    let (rn, sn) = match (parse_ecdsa_int(r), parse_ecdsa_int(s)) {
        (Some(rv), Some(sv)) => (rv, sv),
        _ => return false,
    };
    if rn.is_zero() || sn.is_zero() {
        return false;
    }
    if rn.cmp_limbs(&P256_ORDER) >= core::cmp::Ordering::Equal
        || sn.cmp_limbs(&P256_ORDER) >= core::cmp::Ordering::Equal
    {
        return false;
    }

    let e = {
        let mut e_bytes = [0u8; 32];
        e_bytes.copy_from_slice(message_hash);
        Fe256::from_bytes_be(&e_bytes)
    };

    let w = sn.invert_mod_n();
    let u1 = e.mul_mod_n(&w);
    let u2 = rn.mul_mod_n(&w);

    let g = p256_generator();
    let q = P256Point {
        x: qx,
        y: qy,
        is_infinity: false,
    };
    let point = g.mul_scalar(&u1.0).add(&q.mul_scalar(&u2.0));

    if point.is_infinity() {
        return false;
    }

    // Verify R.x ≡ r (mod n).
    point.x.reduce_mod_n().cmp_limbs(&rn.0) == core::cmp::Ordering::Equal
}

impl Fe256 {
    /// Reduce self modulo the curve order n.
    fn reduce_mod_n(&self) -> Fe256 {
        reduce_mod_n(&{
            let mut v = [0u64; 8];
            v[..4].copy_from_slice(&self.0);
            v
        })
    }
}

/// Parse a DER-encoded ECDSA signature: SEQUENCE { INTEGER r, INTEGER s }.
///
/// Returns `Some((r_bytes, s_bytes))` on success, stripping leading zero
/// sign bytes from each integer.
pub fn parse_ecdsa_der_signature(der: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    if der.len() < 8 || der[0] != 0x30 {
        return None;
    }
    let seq_len = der[1] as usize;
    if der.len() < 2 + seq_len {
        return None;
    }
    let content = &der[2..2 + seq_len];

    if content.is_empty() || content[0] != 0x02 {
        return None;
    }
    let r_len = content[1] as usize;
    if content.len() < 2 + r_len {
        return None;
    }
    let r_raw = &content[2..2 + r_len];
    let r = if r_raw.len() > 32 && r_raw[0] == 0 {
        &r_raw[1..]
    } else {
        r_raw
    };

    let after_r = &content[2 + r_len..];
    if after_r.is_empty() || after_r[0] != 0x02 {
        return None;
    }
    let s_len = after_r[1] as usize;
    if after_r.len() < 2 + s_len {
        return None;
    }
    let s_raw = &after_r[2..2 + s_len];
    let s = if s_raw.len() > 32 && s_raw[0] == 0 {
        &s_raw[1..]
    } else {
        s_raw
    };

    Some((r.to_vec(), s.to_vec()))
}

#[cfg(test)]
mod ecdsa_tests {
    use super::*;

    #[test]
    fn fe_add_sub_identity() {
        let a = Fe256::from_bytes_be(&[0xAB; 32]);
        let b = Fe256::from_bytes_be(&[0x12; 32]);
        let sum = a.add(&b);
        let diff = sum.sub(&b);
        assert_eq!(diff.0, a.0);
    }

    #[test]
    fn fe_mul_identity() {
        let mut v = [0u8; 32];
        v[31] = 42;
        let a = Fe256::from_bytes_be(&v);
        let inv = a.invert();
        let prod = a.mul(&inv);
        assert!(prod.0[0] == 1 && prod.0[1] == 0 && prod.0[2] == 0 && prod.0[3] == 0);
    }

    #[test]
    fn fe_mul_commutative() {
        let mut va = [0u8; 32];
        va[31] = 123;
        let mut vb = [0u8; 32];
        vb[31] = 200;
        let a = Fe256::from_bytes_be(&va);
        let b = Fe256::from_bytes_be(&vb);
        assert_eq!(a.mul(&b).0, b.mul(&a).0);
    }

    #[test]
    fn point_double_and_add() {
        let g = p256_generator();
        let g2 = g.double();
        let g2b = g.add(&g);
        assert_eq!(g2.x.0, g2b.x.0);
        assert_eq!(g2.y.0, g2b.y.0);
    }

    #[test]
    fn point_on_curve() {
        let g = p256_generator();
        let mut v = [0u8; 32];
        v[31] = 100;
        let k = Fe256::from_bytes_be(&v);
        let p = g.mul_scalar(&k.0);
        let x3 = p.x.square().mul(&p.x);
        let ax = p.x.mul(&Fe256::from_limbs(P256_A));
        let b = Fe256::from_limbs(P256_B);
        let rhs = x3.add(&ax).add(&b);
        let lhs = p.y.square();
        assert_eq!(lhs.0, rhs.0);
    }

    #[test]
    fn point_mul_order_is_infinity() {
        let g = p256_generator();
        let p = g.mul_scalar(&P256_ORDER);
        assert!(p.is_infinity());
    }

    #[test]
    fn parse_der_signature_works() {
        let der = [
            0x30, 0x0A, 0x02, 0x03, 0x01, 0x00, 0x01, 0x02, 0x03, 0x00, 0xFF, 0xFE,
        ];
        let (r, s) = parse_ecdsa_der_signature(&der).expect("parse DER signature");
        assert!(!r.is_empty());
        assert!(!s.is_empty());
    }

    #[test]
    fn ecdsa_verify_zero_signature_fails() {
        let pubkey = [
            0x04, 0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63,
            0xA4, 0x40, 0xF2, 0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39,
            0x45, 0xD8, 0x98, 0xC2, 0x96, 0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E,
            0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16, 0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E,
            0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5,
        ];
        let hash = [0u8; 32];
        let r = [0u8; 32];
        let s = [0u8; 32];
        assert!(!ecdsa_p256_verify(&pubkey, &hash, &r, &s));
    }

    #[test]
    fn ecdsa_p256_verify_known_vector() {
        // Generated with Python `cryptography` (fixed private key d =
        // 0x9B4F49110F2B5C9C9B2A4A0B7D62D3A9C0A5E7F2B8D4E6A1C3F5B7D9A2C4E6F8),
        // signing "ECDSA P-256 test message for protofire crypto".
        let public_key: [u8; 65] = [
            0x04, 0x12, 0xbe, 0x33, 0x72, 0x61, 0x56, 0x8a, 0x6f, 0x7a, 0x2e, 0xca, 0xea, 0x09,
            0x68, 0x50, 0x1c, 0x96, 0x73, 0xae, 0x0d, 0xa1, 0x72, 0xcb, 0xbc, 0x29, 0x45, 0x28,
            0xd3, 0xeb, 0x6a, 0xbf, 0x20, 0x85, 0x13, 0x32, 0xf5, 0x9c, 0x0f, 0x01, 0x76, 0xe6,
            0x5e, 0x1e, 0xcf, 0x83, 0xaa, 0xf9, 0x9c, 0x8d, 0x09, 0x2b, 0x85, 0xc4, 0x44, 0x13,
            0x0c, 0xd4, 0x74, 0x50, 0xad, 0xe6, 0x7a, 0x00, 0x23,
        ];
        let message_hash: [u8; 32] = [
            0xec, 0x3c, 0x1d, 0xc8, 0x6c, 0x6c, 0x13, 0xb6, 0xe9, 0xe7, 0x9d, 0x43, 0xc2, 0xf2,
            0x0f, 0xfc, 0xa9, 0x0b, 0xc7, 0xab, 0x15, 0x53, 0x98, 0xe6, 0x9c, 0xc3, 0x3b, 0x5a,
            0x97, 0x7d, 0xb6, 0x34,
        ];
        let r: [u8; 32] = [
            0x43, 0x20, 0xc0, 0xa4, 0x9a, 0x9a, 0xa4, 0x11, 0xf3, 0x37, 0x03, 0x3f, 0x45, 0xd0,
            0x93, 0xaa, 0x57, 0x6c, 0x57, 0xcc, 0x78, 0x3d, 0x6e, 0x6a, 0x5f, 0x3d, 0xf6, 0x6c,
            0x7a, 0x6b, 0xd8, 0x9e,
        ];
        let s: [u8; 32] = [
            0x45, 0x94, 0x53, 0x7f, 0x16, 0x69, 0xc9, 0xab, 0x59, 0xab, 0x40, 0xd2, 0xaa, 0xd9,
            0x8a, 0x7f, 0xa3, 0xcd, 0x75, 0x90, 0x72, 0xfe, 0xfe, 0x6b, 0x21, 0x25, 0xeb, 0xd7,
            0x3b, 0x89, 0x5b, 0x26,
        ];
        assert!(ecdsa_p256_verify(&public_key, &message_hash, &r, &s));

        // A flipped bit in the message hash must invalidate the signature.
        let mut bad_hash = message_hash;
        bad_hash[0] ^= 0x01;
        assert!(!ecdsa_p256_verify(&public_key, &bad_hash, &r, &s));
    }

    #[test]
    fn ecdsa_verify_rejects_bad_public_key() {
        let hash = [1u8; 32];
        let r = [2u8; 32];
        let s = [3u8; 32];
        assert!(!ecdsa_p256_verify(&[0x04, 0x00], &hash, &r, &s));
        let mut bad_pk = [0u8; 65];
        bad_pk[0] = 0x03;
        assert!(!ecdsa_p256_verify(&bad_pk, &hash, &r, &s));
    }
}
