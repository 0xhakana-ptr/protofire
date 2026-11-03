//! libs/crypto/src/rsa.rs
//!
//! RSA signature verification (RFC 8017).
//!
//! Stack-allocated limb arrays, for verification against 2048-bit and
//! 4096-bit keys.  Montgomery multiplication does the modular arithmetic,
//! so there is no division on the path.
//!
//! Verification only: the private half of RSA needs constant-time
//! arithmetic this tree has not written, and an exempted zone is verified
//! rather than signed.

use crate::constant_time::constant_time_eq;
use crate::sha256::sha256;
use alloc::vec::Vec;

/// Maximum RSA modulus size: 4096 bits = 64 × u64 limbs = 512 bytes.
const RSA_MAX_LIMBS: usize = 64;
const RSA_MAX_BYTES: usize = RSA_MAX_LIMBS * 8;

/// Convert big-endian bytes to u64 limbs (little-endian).  Returns the number
/// of non-zero limbs (counting from the most-significant side).
fn rsa_bytes_to_limbs(bytes: &[u8], limbs: &mut [u64; RSA_MAX_LIMBS]) -> usize {
    assert!(bytes.len() <= RSA_MAX_LIMBS * 8);
    limbs.fill(0);
    for (i, &b) in bytes.iter().enumerate() {
        let pos = bytes.len() - 1 - i;
        limbs[pos / 8] |= (b as u64) << ((pos % 8) * 8);
    }
    let mut n = bytes.len().div_ceil(8);
    while n > 1 && limbs[n - 1] == 0 {
        n -= 1;
    }
    n
}

/// Convert u64 limbs to big-endian bytes of length `out_len`.
fn rsa_limbs_to_bytes(limbs: &[u64; RSA_MAX_LIMBS], num_limbs: usize, out: &mut [u8]) {
    let n = out.len();
    out.fill(0);
    #[allow(clippy::needless_range_loop)]
    for li in 0..num_limbs {
        let limb = limbs[li];
        for bi in 0..8 {
            let bp = li * 8 + bi;
            if bp < n {
                out[n - 1 - bp] = (limb >> (bi * 8)) as u8;
            }
        }
    }
}

/// Bit-length of a limb array.
fn rsa_limbs_bitlen(limbs: &[u64; RSA_MAX_LIMBS], num_limbs: usize) -> usize {
    for i in (0..num_limbs).rev() {
        if limbs[i] != 0 {
            return i * 64 + 64 - (limbs[i].leading_zeros() as usize);
        }
    }
    0
}

// Montgomery multiplication

/// Compute the modular inverse of an odd `a` modulo 2^64 via Newton iteration.
fn rsa_modinv_u64(a: u64) -> u64 {
    // x_{n+1} = x_n * (2 - a * x_n)  mod 2^(2^(n+1))
    let mut x = a; // correct mod 2^3 for odd a
    x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x))); // mod 2^6
    x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x))); // mod 2^12
    x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x))); // mod 2^24
    x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x))); // mod 2^48
    x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x))); // mod 2^96 (full 2^64)
    x
}

/// Montgomery multiplication: `result = a * b * R^(-1) mod n` where
/// R = 2^(num_limbs * 64).  Uses CIOS (Coarsely Integrated Operand Scanning).
///
/// `nprime0` = -n[0]^(-1) mod 2^64 (precomputed).
///
/// Inputs a, b must be < n and in Montgomery form (scaled by R).
/// `result`, `a`, `b`, `n` all have `num_limbs` limbs.
fn rsa_mont_mul(
    result: &mut [u64; RSA_MAX_LIMBS],
    a: &[u64; RSA_MAX_LIMBS],
    b: &[u64; RSA_MAX_LIMBS],
    n: &[u64; RSA_MAX_LIMBS],
    num_limbs: usize,
    nprime0: u64,
) {
    // Temporary t of length num_limbs + 2.
    let mut t = [0u64; RSA_MAX_LIMBS + 2];
    let t_len = num_limbs + 2;

    #[allow(clippy::needless_range_loop)]
    for i in 0..num_limbs {
        // t += a[i] * b
        let mut carry: u64 = 0;
        for j in 0..num_limbs {
            let prod = (a[i] as u128) * (b[j] as u128) + (t[j] as u128) + (carry as u128);
            t[j] = prod as u64;
            carry = (prod >> 64) as u64;
        }
        // Propagate carry through remaining t entries
        let mut pos = num_limbs;
        while carry != 0 && pos < t_len {
            let sum = (t[pos] as u128) + (carry as u128);
            t[pos] = sum as u64;
            carry = (sum >> 64) as u64;
            pos += 1;
        }

        // m = t[0] * nprime0 mod 2^64
        let m = t[0].wrapping_mul(nprime0);

        // t += m * n
        carry = 0;
        for j in 0..num_limbs {
            let prod = (m as u128) * (n[j] as u128) + (t[j] as u128) + (carry as u128);
            t[j] = prod as u64;
            carry = (prod >> 64) as u64;
        }
        pos = num_limbs;
        while carry != 0 && pos < t_len {
            let sum = (t[pos] as u128) + (carry as u128);
            t[pos] = sum as u64;
            carry = (sum >> 64) as u64;
            pos += 1;
        }

        // t >>= 64 (right-shift by one limb)
        for j in 0..t_len - 1 {
            t[j] = t[j + 1];
        }
        t[t_len - 1] = 0;
    }

    // Final reduction.  `t` may carry a nonzero guard limb at `t[num_limbs]`
    // even when the truncated `t[0..num_limbs]` is below `n`: `t < 2n` while
    // `n < R < 2n` for a full-size modulus, so the true value can be
    // `t[0..num_limbs] + R`.  Compare the FULL `t` (guard limbs included)
    // against `n` and subtract once; `t < 2n` guarantees the borrow clears
    // the guard limbs, leaving a result below `n`.
    let mut ge = true;
    for i in (0..=num_limbs + 1).rev() {
        let nv = if i < num_limbs { n[i] } else { 0 };
        if t[i] > nv {
            break;
        }
        if t[i] < nv {
            ge = false;
            break;
        }
    }
    if ge {
        let mut borrow: u64 = 0;
        for i in 0..=num_limbs + 1 {
            let nv = if i < num_limbs { n[i] } else { 0 };
            let (s1, b1) = t[i].overflowing_sub(nv);
            let (s2, b2) = s1.overflowing_sub(borrow);
            t[i] = s2;
            borrow = (b1 as u64) + (b2 as u64);
        }
    }
    result[..num_limbs].copy_from_slice(&t[..num_limbs]);
}

/// Convert `a` into Montgomery form: `a_mont = a * R mod n`.
fn rsa_to_mont(
    a: &[u64; RSA_MAX_LIMBS],
    n: &[u64; RSA_MAX_LIMBS],
    num_limbs: usize,
    nprime0: u64,
) -> [u64; RSA_MAX_LIMBS] {
    // R^2 mod n, precomputed.
    let mut r_sq = [0u64; RSA_MAX_LIMBS];
    r_sq[0] = 1; // R = 2^(64*num_limbs) ≡ 1 limb
    // Compute R^2 mod n via repeated Montgomery squaring.
    // R = 2^(64*num_limbs).  We want R^2 mod n.
    // In Montgomery form, an integer x is represented as x*R mod n.
    // To convert a to Montgomery form, compute a * R mod n.
    // We compute this as MontMul(a, R^2 mod n, n, nprime0).
    //
    // First compute R mod n: start with 1, shift left by 64*num_limbs bits mod
    // n.
    let mut r_mod_n = [0u64; RSA_MAX_LIMBS];
    r_mod_n[0] = 1;
    for _ in 0..num_limbs {
        // Multiply R by 2^64 mod n: shift left 64, subtract n as needed.
        // This is: for 64 times: r_mod_n *= 2; if r_mod_n >= n: r_mod_n -= n
        for _bit in 0..64 {
            // r_mod_n <<= 1
            let mut carry: u64 = 0;
            #[allow(clippy::needless_range_loop)]
            for i in 0..num_limbs {
                let next_carry = r_mod_n[i] >> 63;
                r_mod_n[i] = (r_mod_n[i] << 1) | carry;
                carry = next_carry;
            }
            // If r_mod_n >= n, subtract n.
            let mut ge = true;
            for i in (0..num_limbs).rev() {
                if r_mod_n[i] > n[i] {
                    break;
                }
                if r_mod_n[i] < n[i] {
                    ge = false;
                    break;
                }
            }
            if ge || carry > 0 {
                let mut borrow: u64 = 0;
                for i in 0..num_limbs {
                    let (s1, b1) = r_mod_n[i].overflowing_sub(n[i]);
                    let (s2, b2) = s1.overflowing_sub(borrow);
                    r_mod_n[i] = s2;
                    borrow = (b1 as u64) + (b2 as u64);
                }
            }
        }
    }

    // Now r_mod_n = R mod n.  Compute R^2 mod n = MontMul(R mod n, R mod n).
    // But wait, R and R_mod_n aren't in Montgomery form.  MontMul expects
    // inputs in Montgomery form.  So we can't use it directly.
    //
    // To compute a * R mod n (Montgomery form of a), we use:
    //   MontMul(a, R^2 mod n) = a * R^2 * R^(-1) mod n = a * R mod n.
    //
    // We still need R^2 mod n.  Let's compute it:
    //   R^2 mod n = (R mod n) * (R mod n) mod n
    //
    // Compute (R mod n)^2 via schoolbook multiply then modular reduction.
    let mut r2_prod = [0u64; 2 * RSA_MAX_LIMBS];
    r2_prod[..2 * num_limbs].fill(0);
    for i in 0..num_limbs {
        let av = r_mod_n[i];
        if av == 0 {
            continue;
        }
        let mut carry: u64 = 0;
        #[allow(clippy::needless_range_loop)]
        for j in 0..num_limbs {
            let idx = i + j;
            let prod =
                (av as u128) * (r_mod_n[j] as u128) + (r2_prod[idx] as u128) + (carry as u128);
            r2_prod[idx] = prod as u64;
            carry = (prod >> 64) as u64;
        }
        let mut pos = i + num_limbs;
        while carry != 0 {
            let sum = (r2_prod[pos] as u128) + (carry as u128);
            r2_prod[pos] = sum as u64;
            carry = (sum >> 64) as u64;
            pos += 1;
        }
    }
    // Reduce r2_prod mod n using shift-subtract: copy r2_prod into a working
    // buffer and repeatedly subtract n << shift.
    let mut work = [0u64; 2 * RSA_MAX_LIMBS];
    work.copy_from_slice(&r2_prod);
    let n_bits = rsa_limbs_bitlen(n, num_limbs);
    'reduce: loop {
        let w_bits = {
            let mut bits = 0;
            for i in (0..2 * num_limbs).rev() {
                if work[i] != 0 {
                    bits = i * 64 + 64 - (work[i].leading_zeros() as usize);
                    break;
                }
            }
            bits
        };
        if w_bits < n_bits {
            break;
        }
        // Candidate shift: subtracting n << (w_bits - n_bits) can overshoot
        // (n << shift has the same bit length as work but may be larger), so
        // if sub > work, drop shift by one (always safe because
        // n << (shift - 1) < 2^(w_bits - 1) <= work).
        let mut shift = w_bits - n_bits;
        let mut sub = [0u64; 2 * RSA_MAX_LIMBS];
        loop {
            sub.fill(0);
            let limb_shift = shift / 64;
            let bit_shift = shift % 64;
            #[allow(clippy::needless_range_loop)]
            for i in 0..num_limbs {
                let idx = i + limb_shift;
                sub[idx] |= n[i] << bit_shift;
                if bit_shift > 0 && idx + 1 < 2 * RSA_MAX_LIMBS {
                    sub[idx + 1] |= n[i] >> (64 - bit_shift);
                }
            }
            // Check work >= sub.
            let mut ge = true;
            for i in (0..2 * num_limbs).rev() {
                if work[i] > sub[i] {
                    break;
                }
                if work[i] < sub[i] {
                    ge = false;
                    break;
                }
            }
            if ge {
                // work -= sub
                let mut borrow: u64 = 0;
                for i in 0..2 * num_limbs {
                    let (s1, b1) = work[i].overflowing_sub(sub[i]);
                    let (s2, b2) = s1.overflowing_sub(borrow);
                    work[i] = s2;
                    borrow = (b1 as u64) + (b2 as u64);
                }
                break;
            }
            // sub > work: either we already had shift == 0 (work < n, done) or
            // we drop shift by one and retry.
            if shift == 0 {
                break 'reduce;
            }
            shift -= 1;
        }
    }
    // Copy reduced result to r_sq.
    r_sq[..num_limbs].copy_from_slice(&work[..num_limbs]);

    // Now compute a * R mod n = MontMul(a, R^2 mod n).
    let mut result = [0u64; RSA_MAX_LIMBS];
    rsa_mont_mul(&mut result, a, &r_sq, n, num_limbs, nprime0);
    result
}

/// Modular exponentiation via Montgomery ladder: `result = base^exp mod n`.
/// `exp_bits` is the bit-length of the exponent.
fn rsa_mod_pow(
    result: &mut [u64; RSA_MAX_LIMBS],
    base: &[u64; RSA_MAX_LIMBS],
    exp: &[u64; RSA_MAX_LIMBS],
    exp_bits: usize,
    n: &[u64; RSA_MAX_LIMBS],
    num_limbs: usize,
    nprime0: u64,
) {
    // Convert base to Montgomery form.
    let base_mont = rsa_to_mont(base, n, num_limbs, nprime0);

    // R mod n in Montgomery form: MontMul(R mod n, R^2 mod n) — but actually
    // 1 in Montgomery form is just R mod n.
    // Since Montgomery form of x is x*R mod n, the value 1 is represented as R
    // mod n. Let's compute R mod n.
    let mut one_mont = [0u64; RSA_MAX_LIMBS];
    one_mont[0] = 1;
    // Shift left by 64*num_limbs mod n (same as r_mod_n in rsa_to_mont).
    for _ in 0..num_limbs {
        for _bit in 0..64 {
            let mut carry: u64 = 0;
            #[allow(clippy::needless_range_loop)]
            for i in 0..num_limbs {
                let next_carry = one_mont[i] >> 63;
                one_mont[i] = (one_mont[i] << 1) | carry;
                carry = next_carry;
            }
            let mut ge = true;
            for i in (0..num_limbs).rev() {
                if one_mont[i] > n[i] {
                    break;
                }
                if one_mont[i] < n[i] {
                    ge = false;
                    break;
                }
            }
            if ge || carry > 0 {
                let mut borrow: u64 = 0;
                for i in 0..num_limbs {
                    let (s1, b1) = one_mont[i].overflowing_sub(n[i]);
                    let (s2, b2) = s1.overflowing_sub(borrow);
                    one_mont[i] = s2;
                    borrow = (b1 as u64) + (b2 as u64);
                }
            }
        }
    }

    // Start with result = 1 (in Montgomery form).
    result[..num_limbs].copy_from_slice(&one_mont[..num_limbs]);
    result[num_limbs..].fill(0);

    let mut base_copy = [0u64; RSA_MAX_LIMBS];
    base_copy[..num_limbs].copy_from_slice(&base_mont[..num_limbs]);

    // Left-to-right square-and-multiply.
    for bit in (0..exp_bits).rev() {
        // Square: result = MontMul(result, result).
        let mut sq = [0u64; RSA_MAX_LIMBS];
        rsa_mont_mul(&mut sq, result, result, n, num_limbs, nprime0);
        result[..num_limbs].copy_from_slice(&sq[..num_limbs]);

        // Check if exponent bit is set.
        let exp_limb = bit / 64;
        let exp_bit = bit % 64;
        if exp_limb < RSA_MAX_LIMBS && (exp[exp_limb] >> exp_bit) & 1 != 0 {
            let mut mul_res = [0u64; RSA_MAX_LIMBS];
            rsa_mont_mul(&mut mul_res, result, &base_copy, n, num_limbs, nprime0);
            result[..num_limbs].copy_from_slice(&mul_res[..num_limbs]);
        }
    }

    // Convert back from Montgomery form: result * 1 * R^(-1) mod n.
    let mut one = [0u64; RSA_MAX_LIMBS];
    one[0] = 1;
    let mut unmont = [0u64; RSA_MAX_LIMBS];
    rsa_mont_mul(&mut unmont, result, &one, n, num_limbs, nprime0);
    result[..num_limbs].copy_from_slice(&unmont[..num_limbs]);
}

// MGF1

/// MGF1 based on SHA-256 (RFC 8017 Appendix B.2.1).
/// Fills `output` with mask bytes generated from `seed`.
fn mgf1_sha256(seed: &[u8], output: &mut [u8]) {
    let n_blocks = output.len().div_ceil(32);
    let mut counter_bytes = [0u8; 4];
    let mut hasher_input = Vec::with_capacity(seed.len() + 4);
    hasher_input.extend_from_slice(seed);
    hasher_input.extend_from_slice(&counter_bytes);

    for counter in 0u32..(n_blocks as u32) {
        let offset = counter as usize * 32;
        let remaining = output.len() - offset;
        let take = remaining.min(32);

        // Update counter bytes.
        counter_bytes.copy_from_slice(&counter.to_be_bytes());
        let input_len = hasher_input.len();
        hasher_input[input_len - 4..].copy_from_slice(&counter_bytes);

        let hash = sha256(&hasher_input);
        output[offset..offset + take].copy_from_slice(&hash[..take]);
    }
}

// RSA-PSS Verification (RFC 8017 §8.1.2, §9.1.2)

/// Raw RSA public-key operation: compute `m = s^e mod n` and return the
/// `k`-byte big-endian encoded message `EM` alongside the modulus length `k`.
///
/// Returns `None` when the inputs are invalid: modulus larger than
/// [`RSA_MAX_LIMBS`] limbs, a signature whose length differs from the modulus,
/// or a signature value `s >= n`.
fn rsa_public_key_op(
    n_bytes: &[u8],
    e_bytes: &[u8],
    signature: &[u8],
) -> Option<([u8; RSA_MAX_BYTES], usize)> {
    let k = n_bytes.len(); // modulus length in bytes
    if k > RSA_MAX_LIMBS * 8 {
        return None;
    }
    if signature.len() != k {
        return None;
    }

    let num_limbs = k.div_ceil(8);

    // Parse modulus n.
    let mut n = [0u64; RSA_MAX_LIMBS];
    rsa_bytes_to_limbs(n_bytes, &mut n);

    // Parse signature s.
    let mut s = [0u64; RSA_MAX_LIMBS];
    rsa_bytes_to_limbs(signature, &mut s);

    // If s >= n, invalid.
    let mut s_ge_n = true;
    for i in (0..num_limbs).rev() {
        if s[i] > n[i] {
            break;
        }
        if s[i] < n[i] {
            s_ge_n = false;
            break;
        }
    }
    if s_ge_n {
        return None;
    }

    // Parse exponent e.
    let mut e_limbs = [0u64; RSA_MAX_LIMBS];
    let e_num = rsa_bytes_to_limbs(e_bytes, &mut e_limbs);
    let e_bits = rsa_limbs_bitlen(&e_limbs, e_num);

    // Precompute Montgomery constant nprime0 = -n[0]^(-1) mod 2^64.
    // If inv * n[0] ≡ 1 (mod 2^64), then (-inv) * n[0] ≡ -1 (mod 2^64).
    let inv = rsa_modinv_u64(n[0]);
    let nprime0_correct = 0u64.wrapping_sub(inv);

    // Compute m = s^e mod n.
    let mut m_limbs = [0u64; RSA_MAX_LIMBS];
    rsa_mod_pow(
        &mut m_limbs,
        &s,
        &e_limbs,
        e_bits,
        &n,
        num_limbs,
        nprime0_correct,
    );

    // Convert m to EM bytes (k bytes, big-endian).
    let mut em = [0u8; RSA_MAX_BYTES];
    rsa_limbs_to_bytes(&m_limbs, num_limbs, &mut em[..k]);
    Some((em, k))
}

/// Return the bit length of the RSA modulus `n_bytes`.
fn rsa_mod_bits(n_bytes: &[u8]) -> usize {
    let mut n = [0u64; RSA_MAX_LIMBS];
    let num = rsa_bytes_to_limbs(n_bytes, &mut n);
    rsa_limbs_bitlen(&n, num)
}

/// Verify an RSA-PSS signature.
///
/// TLS 1.3 parameters: Hash=SHA-256, MGF=MGF1(SHA-256), salt_len=32.
///
/// `n` = RSA modulus (big-endian bytes, 256/512 bytes for 2048/4096-bit keys).
/// `e` = public exponent (big-endian bytes, typically `[1, 0, 1]` = 65537).
/// `message` = 32-byte hash to verify (the TLS transcript hash).
/// `signature` = the raw signature bytes (big-endian, same length as `n`).
#[must_use]
pub fn rsa_pss_verify(
    n_bytes: &[u8],
    e_bytes: &[u8],
    message: &[u8; 32],
    signature: &[u8],
) -> bool {
    let (em, k) = match rsa_public_key_op(n_bytes, e_bytes, signature) {
        Some(v) => v,
        None => return false,
    };

    // EMSA-PSS-VERIFY (RFC 8017 §9.1.2).
    // 1. mHash = Hash(M) -- `message` is already the 32-byte transcript hash.
    let m_hash = *message;

    // 2. Check EM rightmost byte == 0xBC.
    if em[k - 1] != 0xBC {
        return false;
    }

    // 3. Split EM: maskedDB = EM[0..k-hLen-1], H = EM[k-hLen-1..k-1] hLen = 32
    //    (SHA-256).
    let h_len: usize = 32;
    if k < h_len + 1 {
        return false;
    }
    let db_len = k - h_len - 1;
    let masked_db = &em[..db_len];
    let h_val = &em[db_len..db_len + h_len];

    // 4. dbMask = MGF1(H, db_len).
    let mut db_mask = [0u8; RSA_MAX_BYTES];
    let db_mask_slice = &mut db_mask[..db_len];
    mgf1_sha256(h_val, db_mask_slice);

    // 5. DB = maskedDB XOR dbMask.
    let mut db = [0u8; RSA_MAX_BYTES];
    for i in 0..db_len {
        db[i] = masked_db[i] ^ db_mask[i];
    }

    // 6. Set leftmost 8*kLen - 2*hLen - 16 bits of DB to 0. kLen = k (bytes).
    //    8k - 2*256 - 16 = 8k
    //    - 528 bits. That's (8k - 528) bits = (k - 66) bytes.  Wait, let me
    //      recalculate. emBits = 8
    //    * k - (8 * k - bitlen(n)) rounded down to a multiple of 8? No.
    //      Actually, RFC 8017 §9.1.1
    //    says: emBits = modBits - 1 where modBits = bitlen(n). The leftmost
    // 8*emLen
    // - emBits bits    of the leftmost octet of DB shall be 0.
    //
    //    modBits = bitlen(n)
    //    emBits = modBits - 1
    //    emLen = k
    //    Bits to zero = 8 * emLen - emBits = 8k - (modBits - 1)
    let mod_bits = rsa_mod_bits(n_bytes);
    let em_bits = mod_bits - 1;
    let zero_bits = 8 * k - em_bits;

    // Zero the most significant bits of DB.
    if zero_bits > 0 {
        let full_bytes = zero_bits / 8;
        #[allow(clippy::needless_range_loop)]
        for i in 0..full_bytes.min(db_len) {
            if db[i] != 0 {
                return false;
            }
        }
        let rem_bits = zero_bits % 8;
        if rem_bits > 0 && full_bytes < db_len {
            let mask = 0xFFu8 >> rem_bits;
            db[full_bytes] &= mask;
        }
    }

    // RFC 8017 §9.1.2, steps 9-15 (EMSA-PSS-VERIFY):
    //   9. Set the leftmost 8*emLen - emBits bits of the leftmost byte of DB to
    //      0.
    //   10. The emLen - hLen - sLen - 2 leftmost bytes of DB must be 0x00.
    //   11. The byte at position emLen - hLen - sLen - 2 of DB must be 0x01.
    //   12. Let salt be the last sLen bytes of DB.
    //   13. Let M' = 0x00...00 || Hash(M) || salt  (8 bytes of 0x00)
    //   14. Let H' = Hash(M').
    //   15. Output "valid" iff H == H'.
    let s_len: usize = 32; // saltLen for TLS 1.3 RSA-PSS

    // Step 9: Set leftmost bits to 0 (same as the masking done above).
    let zero_bits_step9 = 8 * k - em_bits;
    if zero_bits_step9 > 0 {
        let full_bytes = zero_bits_step9 / 8;
        #[allow(clippy::needless_range_loop)]
        for byte_idx in 0..full_bytes.min(db_len) {
            if db[byte_idx] != 0 {
                return false;
            }
        }
        let rem_bits = zero_bits_step9 % 8;
        if rem_bits > 0 && full_bytes < db_len {
            db[full_bytes] &= 0xFFu8 >> rem_bits;
        }
    }

    // Step 10: The leftmost emLen - hLen - sLen - 2 bytes of DB must be 0x00.
    if db_len < s_len + 2 {
        return false;
    }
    let ps_len = db_len - s_len - 1; // length of PS in bytes
    #[allow(clippy::needless_range_loop)]
    for byte_idx in 0..ps_len {
        // Wait, step 10 says "emLen - hLen - sLen - 2 leftmost bytes".
        // db_len = k - h_len - 1.
        // ps_bytes = db_len - s_len - 1 = k - h_len - 1 - s_len - 1 = k - h_len
        // - s_len
        // - 2. That matches step 10.
        if db[byte_idx] != 0 {
            return false;
        }
    }

    // Step 11: The byte at position emLen - hLen - sLen - 2 must be 0x01.
    // That's db[ps_len] = 0x01.
    if db[ps_len] != 0x01 {
        return false;
    }

    // Step 12: salt = last sLen bytes of DB.
    let salt = &db[db_len - s_len..db_len];

    // Step 13-14: H' = SHA-256(0x00 * 8 || mHash || salt).
    let mut m_prime = [0u8; 8 + 32 + RSA_MAX_BYTES]; // 8 + 32 + 512 max
    let m_prime_len = 8 + 32 + s_len;
    // First 8 bytes are 0x00 (already initialized to 0).
    m_prime[8..8 + 32].copy_from_slice(&m_hash);
    m_prime[8 + 32..8 + 32 + s_len].copy_from_slice(salt);
    let h_prime = sha256(&m_prime[..m_prime_len]);

    // Step 15: H == H'.
    constant_time_eq(&h_prime, &h_val.try_into().unwrap_or([0u8; 32]))
}

// RSASSA-PKCS1-v1_5 Verification (RFC 8017 §8.2, §9.2)

/// DER prefix of the SHA-256 `DigestInfo` value (RFC 8017 §9.2):
///
/// ```text
/// DigestInfo ::= SEQUENCE {
///     digestAlgorithm AlgorithmIdentifier,   -- sha256WithRSAEncryption
///     digest OCTET STRING }                  -- 32-byte SHA-256 digest
/// ```
///
/// This is the fixed 19-byte header that precedes the digest inside an
/// EMSA-PKCS1-v1_5 encoded message.
const DIGEST_INFO_PREFIX_SHA256: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
    0x00, 0x04, 0x20,
];

/// Verify an RSASSA-PKCS1-v1_5 signature (RFC 8017 §8.2) over `message` using
/// SHA-256 as the message digest.
///
/// This is the signature scheme mandated by X.509 for `sha256WithRSAEncryption`
/// certificate chain signatures, as opposed to the RSA-PSS scheme used for the
/// TLS 1.3 CertificateVerify handshake message.
#[must_use]
pub fn rsa_pkcs1v15_verify(
    n_bytes: &[u8],
    e_bytes: &[u8],
    message: &[u8],
    signature: &[u8],
) -> bool {
    let (em, k) = match rsa_public_key_op(n_bytes, e_bytes, signature) {
        Some(v) => v,
        None => return false,
    };

    let hash = sha256(message);

    // EMSA-PKCS1-v1_5-ENCODE (RFC 8017 §9.2):
    //   EM = 0x00 || 0x01 || PS || 0x00 || DigestInfo || Digest
    // where PS is at least 8 bytes of 0xFF, and EM is exactly k bytes (the
    // modulus length).  A well-formed signature uses every remaining byte for
    // PS, so the layout is fully determined once `k` is known.
    let digest_info_len = DIGEST_INFO_PREFIX_SHA256.len() + hash.len();
    if k < digest_info_len + 11 {
        return false;
    }
    if em[0] != 0x00 || em[1] != 0x01 {
        return false;
    }
    let mut idx = 2;
    while idx < k && em[idx] == 0xFF {
        idx += 1;
    }
    if idx < 2 + 8 {
        // PS must be at least 8 bytes long.
        return false;
    }
    if idx >= k || em[idx] != 0x00 {
        return false;
    }
    let di_start = idx + 1;
    if di_start + digest_info_len != k {
        return false;
    }
    if em[di_start..di_start + DIGEST_INFO_PREFIX_SHA256.len()] != DIGEST_INFO_PREFIX_SHA256 {
        return false;
    }
    constant_time_eq(
        &hash,
        // Bound the slice at `k`: `em` is `[u8; RSA_MAX_BYTES]` with only the
        // first `k` bytes populated, so an open-ended range would compare the
        // digest against trailing zero padding and always fail.
        &em[di_start + DIGEST_INFO_PREFIX_SHA256.len()..k],
    )
}

#[cfg(test)]
mod tests_rsa {
    use crate::test_util::*;

    #[test]
    fn rsa_pss_verify_known_vector() {
        // Generated with Python `cryptography` (RSA-2048, PSS-MGF1-SHA256,
        // salt length 32) over "RSA-PSS test message for protofire crypto".
        let n: [u8; 256] = [
            0xa1, 0x33, 0x63, 0xd6, 0x9c, 0x6e, 0xeb, 0x78, 0x1f, 0xc0, 0x58, 0xbc, 0x90, 0x0e,
            0x3c, 0x15, 0x3f, 0xeb, 0xe6, 0x7f, 0xc2, 0x2e, 0xe1, 0x85, 0xd6, 0x2d, 0x15, 0x7e,
            0xbb, 0x3f, 0x82, 0x50, 0xc6, 0x93, 0x82, 0x0f, 0x57, 0x67, 0x82, 0xf4, 0x7c, 0x8a,
            0x03, 0x39, 0x1f, 0x77, 0x64, 0x05, 0x20, 0x7a, 0x11, 0x62, 0xf8, 0x93, 0x47, 0x37,
            0x25, 0x42, 0xc4, 0x2e, 0x8c, 0xe4, 0x98, 0xbd, 0x17, 0x8b, 0xfa, 0x66, 0x18, 0x03,
            0x3b, 0xc4, 0xe9, 0x00, 0xb1, 0xbc, 0x5c, 0x5b, 0x4c, 0x0d, 0x9a, 0x64, 0xe1, 0x60,
            0xeb, 0x83, 0xd0, 0x85, 0x43, 0xcd, 0x34, 0xee, 0x18, 0xa5, 0xc4, 0x68, 0x61, 0x1e,
            0x34, 0x09, 0xa0, 0xac, 0x75, 0xd6, 0x84, 0x83, 0x62, 0xfe, 0xb9, 0x17, 0x75, 0x2e,
            0xdf, 0xa7, 0x9e, 0xd9, 0x76, 0xe8, 0x16, 0x80, 0xd4, 0xc8, 0xfd, 0x83, 0x8c, 0x99,
            0xbe, 0x7c, 0x27, 0x0e, 0x66, 0x53, 0x67, 0x1c, 0x32, 0x09, 0x59, 0x1d, 0x17, 0xed,
            0xbc, 0x7c, 0x9d, 0xbb, 0x15, 0x60, 0x25, 0xc1, 0x6c, 0xeb, 0x48, 0x8b, 0xb1, 0xfc,
            0xc9, 0x42, 0xf6, 0x93, 0xf7, 0xa8, 0x59, 0x29, 0xf8, 0x3f, 0x8b, 0x24, 0x57, 0x15,
            0x85, 0x65, 0x75, 0x86, 0x11, 0xe7, 0x9c, 0xca, 0xd7, 0x74, 0x89, 0xef, 0x48, 0xe1,
            0xc2, 0x4b, 0x67, 0xb8, 0xd9, 0xd7, 0x53, 0x17, 0x1a, 0x50, 0xd3, 0xc4, 0x1b, 0xed,
            0x65, 0x4e, 0x55, 0xbf, 0xa0, 0x08, 0x07, 0x4c, 0xcc, 0xfb, 0x84, 0xc0, 0x76, 0xd6,
            0xce, 0xdd, 0xd8, 0xaa, 0x2b, 0xfd, 0xc4, 0x76, 0x79, 0x08, 0x40, 0x68, 0xa5, 0xcd,
            0xab, 0x27, 0xf0, 0x02, 0xeb, 0x1e, 0xd7, 0xd5, 0xd3, 0xc4, 0x0f, 0xe1, 0x1f, 0xe1,
            0xec, 0x41, 0xe3, 0x31, 0x7d, 0xb7, 0x80, 0x2a, 0x3a, 0x17, 0x63, 0x41, 0x73, 0x98,
            0xfb, 0x25, 0xcb, 0x33,
        ];
        let e: [u8; 3] = [0x01, 0x00, 0x01];
        let message: [u8; 32] = [
            0xf2, 0x85, 0x35, 0xea, 0x7d, 0xe4, 0xbf, 0x16, 0xc4, 0x3d, 0x69, 0x85, 0x0e, 0x2b,
            0x5c, 0xee, 0x53, 0x33, 0xe2, 0x18, 0x05, 0xe8, 0x55, 0xa1, 0xc1, 0x4c, 0x44, 0x8a,
            0x4e, 0x25, 0xc0, 0x9d,
        ];
        let signature: [u8; 256] = [
            0x66, 0x69, 0x4e, 0xbd, 0xf4, 0x46, 0x6c, 0xb4, 0x1d, 0x5a, 0xd1, 0x78, 0xdd, 0x09,
            0xcd, 0xef, 0xfa, 0x38, 0xe0, 0xce, 0xec, 0xa5, 0xe1, 0x0a, 0x05, 0x3c, 0xa5, 0xdf,
            0xb4, 0x50, 0x62, 0x4f, 0x79, 0x79, 0x7f, 0x89, 0xed, 0x2a, 0x40, 0xbe, 0xd5, 0x59,
            0x4f, 0x11, 0x33, 0xb3, 0xa0, 0xf8, 0x45, 0x5e, 0x10, 0x1b, 0x7a, 0xeb, 0x6b, 0x82,
            0x2b, 0x0e, 0x79, 0x7d, 0xba, 0x85, 0xff, 0x97, 0x9b, 0x1d, 0xa1, 0x77, 0xcd, 0x30,
            0x71, 0x45, 0x3c, 0xea, 0x00, 0xfc, 0xbb, 0x78, 0x1c, 0x86, 0x69, 0xd6, 0x33, 0x46,
            0xfb, 0x1c, 0x36, 0x4b, 0x85, 0xf5, 0xd4, 0x1c, 0x90, 0xc9, 0x02, 0xa0, 0x6b, 0x07,
            0x09, 0x4c, 0xa2, 0x9a, 0x81, 0xb1, 0xe5, 0x01, 0x4c, 0xf6, 0x6a, 0xf3, 0xf4, 0x33,
            0x89, 0x15, 0xaf, 0x34, 0x18, 0xd0, 0xfa, 0x37, 0xa9, 0x7a, 0x08, 0xa5, 0xd6, 0x04,
            0x42, 0x20, 0xb9, 0x10, 0x4f, 0x13, 0x70, 0x53, 0xfd, 0x3c, 0x8a, 0x54, 0x6a, 0x38,
            0xa7, 0x96, 0x11, 0x94, 0x17, 0x02, 0x17, 0xe4, 0x50, 0xda, 0x8e, 0xfe, 0x3f, 0xd6,
            0x27, 0xa8, 0x99, 0xad, 0xd5, 0xe6, 0xb2, 0xd7, 0x84, 0xfa, 0xa5, 0x78, 0xda, 0x40,
            0x7c, 0x6b, 0xd2, 0x03, 0x0f, 0x39, 0x45, 0xe8, 0x53, 0xb2, 0x6c, 0x79, 0xb0, 0x1f,
            0xa3, 0x62, 0x82, 0xfd, 0xba, 0xe9, 0x4e, 0x51, 0x69, 0x49, 0x9b, 0x5b, 0xca, 0x81,
            0x96, 0x5e, 0x64, 0x52, 0xfc, 0xcf, 0xdd, 0xc1, 0x00, 0x58, 0x72, 0xa7, 0x11, 0xb4,
            0x28, 0x9b, 0xb7, 0x09, 0x01, 0xf9, 0x73, 0xb7, 0x2e, 0x64, 0x02, 0x9d, 0x2f, 0xa0,
            0x0b, 0x02, 0xc1, 0x71, 0xb9, 0x7c, 0x5e, 0xcc, 0xe1, 0x6a, 0xf7, 0x71, 0x0e, 0x6c,
            0xe0, 0x5a, 0xda, 0x4e, 0xcc, 0x78, 0x9f, 0xe2, 0xda, 0x4f, 0x94, 0xf2, 0x15, 0xb3,
            0xac, 0x92, 0x4d, 0x63,
        ];
        assert!(super::rsa_pss_verify(&n, &e, &message, &signature));

        // Flipping a bit in the message hash must invalidate the signature.
        let mut bad_hash = message;
        bad_hash[0] ^= 0x01;
        assert!(!super::rsa_pss_verify(&n, &e, &bad_hash, &signature));

        // Flipping a bit in the signature must also invalidate it.
        let mut bad_sig = signature;
        bad_sig[0] ^= 0x01;
        assert!(!super::rsa_pss_verify(&n, &e, &message, &bad_sig));
    }

    #[test]
    fn rsa_pkcs1v15_verify_known_vector() {
        // X.509 `sha256WithRSAEncryption` (RSASSA-PKCS1-v1_5) signature over
        // the demo leaf certificate's TBS, produced by openssl with the demo
        // root CA key (both fixtures live in the TLS certificate tests).  This
        // regression vector pins two past bugs: the Montgomery-multiplication
        // final reduction (a nonzero guard limb could be truncated, yielding
        // the wrong `s^e mod n`), and the digest comparison slicing past `k`
        // into the zeroed tail of the `em` scratch array.
        let message = hex_to_bytes_vec(concat!(
            "3082022ba003020102021458de22c0610386d5ea9be01a3bb4940590202630300d06092a864886f70d01010b05003021",
            "311f301d06035504030c1650726f746f666972652044656d6f20526f6f74204341301e170d3236303832373131353135",
            "325a170d3336303832343131353135325a3021311f301d06035504030c1664656d6f2e70726f746f666972652e657861",
            "6d706c6530820122300d06092a864886f70d01010105000382010f003082010a0282010100e81886fa632cb0666b310e",
            "bc402ecc2f84d93f268278d1ea35b6c658bde9fa7823a55541df3ce2fead33daa1e9a75b06d812ffe6eb7b98847936ef",
            "6412f2c67860e2a94422e1ce5faa6fb821e82613952715c15210a18d00a19cfccf321d4b59236685e5126a4a9f8680c9",
            "83c8d61edf4dcbb367ff3b7a93198e949c1df377d859248179c1f025fabd0189b4baf1f437b797b02dd8128d6d7d28ae",
            "9ec5f425e5b585627792809a2b28f8c812d7c985fb10ebd32fe5e1ed369032d4478a8ade9d08c30d089bdbcb8c0fe66e",
            "5fe4994b30994c2f7a469e14bdda004226c98a9d19720063049a33257d0bcbce8c723eaf0fe17e37621f820909f8241b",
            "be394bf0fb0203010001a3733071300c0603551d130101ff0402300030210603551d11041a3018821664656d6f2e7072",
            "6f746f666972652e6578616d706c65301d0603551d0e04160414ca9acd6530d985b767d2e501e50f9fc526950dbd301f",
            "0603551d23041830168014ab25b50f8ba632d6d40f47cc532f2e6adc01f240",
        ));
        assert_eq!(message.len(), 559);
        let n: [u8; 256] = [
            0xab, 0xbd, 0x9c, 0x4c, 0x21, 0x23, 0xef, 0xd4, 0x0f, 0xa0, 0xd8, 0xfa, 0x24, 0xb1,
            0x08, 0x8a, 0x60, 0x56, 0x55, 0xa1, 0xf9, 0x77, 0x8f, 0x36, 0xc7, 0x12, 0x9d, 0x13,
            0x38, 0x6c, 0x10, 0x8e, 0x7a, 0xfd, 0x34, 0x34, 0x73, 0xed, 0x21, 0x0b, 0x0b, 0x50,
            0x65, 0x85, 0xd9, 0x05, 0x3a, 0x42, 0x62, 0x59, 0x53, 0x92, 0xe9, 0x0a, 0x87, 0xe2,
            0xea, 0xc5, 0x7b, 0x5c, 0x1b, 0x1f, 0xae, 0xf3, 0x31, 0x5e, 0x7b, 0x47, 0xaf, 0x32,
            0x74, 0xee, 0xf2, 0x18, 0xe6, 0x16, 0x13, 0xd0, 0x66, 0xb8, 0x43, 0x44, 0x51, 0x0d,
            0x94, 0x9c, 0xfc, 0x99, 0xc0, 0x0d, 0xa2, 0xa3, 0x58, 0xe3, 0xfa, 0x86, 0xc8, 0xf4,
            0xd1, 0x54, 0x72, 0x64, 0xbf, 0xa6, 0x81, 0x69, 0x9c, 0x0d, 0x92, 0x4c, 0xbd, 0xf8,
            0x6c, 0x39, 0x41, 0x20, 0xaa, 0x52, 0x95, 0xa3, 0x03, 0x0a, 0xc4, 0xf5, 0xe5, 0x24,
            0x90, 0x90, 0x7a, 0x7b, 0xa2, 0x72, 0xf0, 0x3c, 0xee, 0x23, 0xba, 0x56, 0xd4, 0x3a,
            0x0f, 0xef, 0xcd, 0xc2, 0x20, 0x5b, 0xc8, 0x8e, 0x86, 0x55, 0x7f, 0xb1, 0x08, 0xb6,
            0xc8, 0x49, 0x43, 0xbd, 0x40, 0x8c, 0x35, 0x81, 0x45, 0x22, 0x84, 0xcf, 0x64, 0x42,
            0x09, 0x56, 0x7d, 0xeb, 0x91, 0xe2, 0x95, 0xa3, 0x05, 0x59, 0x39, 0xde, 0xdb, 0xba,
            0xfd, 0x2a, 0x2e, 0xaa, 0x70, 0x1d, 0x2a, 0x03, 0x0c, 0xef, 0x1a, 0xf8, 0xc9, 0xf8,
            0x72, 0xcf, 0x76, 0x54, 0xd6, 0xc3, 0xe6, 0xee, 0x19, 0x8e, 0x72, 0xac, 0xf9, 0x3f,
            0x3e, 0x95, 0x57, 0x9e, 0xc9, 0x8f, 0x88, 0x73, 0xcf, 0x60, 0x68, 0xc3, 0x9d, 0xf1,
            0x40, 0x62, 0x49, 0xfe, 0xe9, 0xf8, 0x68, 0x6a, 0xd1, 0x0f, 0x3a, 0x23, 0xa5, 0x64,
            0x1b, 0xe6, 0x3d, 0xfe, 0x24, 0xaf, 0xc6, 0x54, 0x49, 0x49, 0xed, 0x62, 0x6a, 0x46,
            0x07, 0x99, 0x2e, 0xa1,
        ];
        let e: [u8; 3] = [0x01, 0x00, 0x01];
        let signature: [u8; 256] = [
            0x25, 0xfd, 0x7d, 0x1b, 0xcc, 0xb4, 0x38, 0x4a, 0x54, 0x7c, 0x1f, 0xf2, 0xc5, 0xa6,
            0xd6, 0x0a, 0xb0, 0xba, 0xfb, 0x65, 0x38, 0x0b, 0xa3, 0x16, 0x20, 0x32, 0xb1, 0x91,
            0xfa, 0x0f, 0x1a, 0x53, 0xa2, 0x26, 0xb9, 0x5b, 0x30, 0x2f, 0x2e, 0xa2, 0x2f, 0x1c,
            0x88, 0x27, 0x93, 0x5b, 0x16, 0xb7, 0xa5, 0x02, 0x97, 0xe5, 0xa7, 0xb0, 0xed, 0x31,
            0x91, 0x5a, 0x8e, 0x8f, 0xcd, 0xb1, 0xa9, 0x48, 0xb8, 0x28, 0x2f, 0xdc, 0x95, 0x53,
            0x39, 0xc4, 0x0a, 0x28, 0x90, 0xbd, 0xa6, 0x45, 0xd7, 0xb9, 0x0f, 0x52, 0x9f, 0x55,
            0x89, 0xb0, 0x7d, 0xef, 0x1a, 0x3f, 0xc7, 0x7d, 0x27, 0x75, 0x1e, 0xd7, 0xf6, 0x88,
            0x29, 0xb6, 0x2c, 0xdf, 0x2e, 0x33, 0xd2, 0x41, 0xa7, 0x62, 0x79, 0x07, 0x45, 0x83,
            0xa3, 0xdc, 0x51, 0x6b, 0x39, 0x0a, 0x8d, 0x20, 0x85, 0xb6, 0x7c, 0x5b, 0x68, 0x00,
            0xe5, 0x45, 0xf2, 0xa8, 0xde, 0x5e, 0xe0, 0x33, 0xdb, 0x89, 0x77, 0x9a, 0xb3, 0x3b,
            0x7b, 0x7c, 0x5d, 0x67, 0x51, 0xa8, 0x64, 0x05, 0xbf, 0xce, 0x2c, 0x61, 0x8c, 0xb4,
            0xd1, 0x99, 0x82, 0x93, 0x8d, 0x12, 0x24, 0xaa, 0x28, 0x40, 0x90, 0xe0, 0x81, 0x44,
            0x91, 0xec, 0x37, 0xb7, 0x96, 0x11, 0x00, 0x74, 0x1e, 0xb2, 0x5a, 0xae, 0x2a, 0x47,
            0x9e, 0xbe, 0x04, 0x7f, 0x2c, 0x4b, 0xdd, 0xaf, 0xcf, 0x74, 0xb2, 0x31, 0x74, 0x64,
            0xcc, 0xf3, 0x55, 0x85, 0x4a, 0x82, 0x29, 0xfe, 0x56, 0x58, 0x6f, 0xc9, 0x6a, 0x91,
            0xb3, 0x5f, 0x35, 0xfd, 0x6b, 0xa2, 0x65, 0x44, 0xe3, 0x76, 0x3f, 0x53, 0x40, 0x0d,
            0x68, 0x2e, 0xe2, 0x9a, 0x38, 0xef, 0x2a, 0x5b, 0x93, 0x99, 0x3f, 0x97, 0xeb, 0x50,
            0xe9, 0x5b, 0xcb, 0x71, 0x1c, 0x71, 0x61, 0xb2, 0x74, 0xdd, 0x7c, 0x19, 0x4b, 0x80,
            0x06, 0xc6, 0xdb, 0x12,
        ];
        assert!(super::rsa_pkcs1v15_verify(&n, &e, &message, &signature));

        // Flipping a bit in the signature must invalidate it.
        let mut bad_sig = signature;
        bad_sig[0] ^= 0x01;
        assert!(!super::rsa_pkcs1v15_verify(&n, &e, &message, &bad_sig));

        // Flipping a bit in the message must also invalidate it.
        let mut bad_msg = message;
        bad_msg[0] ^= 0x01;
        assert!(!super::rsa_pkcs1v15_verify(&n, &e, &bad_msg, &signature));
    }
}
