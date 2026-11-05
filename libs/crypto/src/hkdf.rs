//! libs/crypto/src/hkdf.rs
//!
//! HKDF-SHA256 (RFC 5869): extract, then expand.

use crate::hmac::hmac_sha256;
use alloc::vec::Vec;

/// HKDF extract step: `HKDF-Extract(salt, IKM) -> PRK`.
///
/// Returns a 32-byte pseudorandom key.  If `salt` is empty, a string of
/// 32 zero bytes is used as the HMAC key per RFC 5869 §2.2.
pub fn hkdf_sha256_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let effective_salt: &[u8] = if salt.is_empty() { &[0u8; 32] } else { salt };
    hmac_sha256(effective_salt, ikm)
}

/// HKDF expand step: `HKDF-Expand(PRK, info, L) -> OKM`.
///
/// Returns a `Vec<u8>` of exactly `output_len` bytes.  The output length
/// MUST NOT exceed `255 * 32 = 8160` bytes per RFC 5869 §2.3.
pub fn hkdf_sha256_expand(prk: &[u8; 32], info: &[u8], output_len: usize) -> Vec<u8> {
    assert!(
        output_len <= 255 * 32,
        "HKDF-Expand output length exceeds maximum"
    );

    let n = output_len.div_ceil(32);
    let mut okm = Vec::with_capacity(output_len);
    let mut t_prev: &[u8] = &[];

    for i in 0..n {
        let mut input = Vec::with_capacity(t_prev.len() + info.len() + 1);
        input.extend_from_slice(t_prev);
        input.extend_from_slice(info);
        input.push(i as u8 + 1);
        let t = hmac_sha256(prk, &input);
        okm.extend_from_slice(&t);
        // t_prev points into okm, safe because Vec never moves elements
        // after they are written, and we only append.
        let start = i * 32;
        t_prev = &okm[start..start + 32];
    }

    okm.truncate(output_len);
    okm
}
#[cfg(test)]
mod tests_hkdf {
    use crate::sha256::sha256;
    use crate::test_util::*;

    // HKDF-SHA256 test vectors (RFC 5869 Appendix A.1)

    #[test]
    fn hkdf_sha256_extract_rfc5869() {
        // Extract with salt.
        let ikm = [0x0bu8; 22];
        let salt: [u8; 13] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let prk = super::hkdf_sha256_extract(&salt, &ikm);
        let expected =
            hex_to_bytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        assert_eq!(prk, expected);
    }

    #[test]
    fn hkdf_sha256_expand_rfc5869() {
        // Expand from known PRK.
        let prk = hex_to_bytes("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5");
        let info: &[u8] = &[0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];
        let okm = super::hkdf_sha256_expand(&prk, info, 42);
        assert_eq!(okm.len(), 42);
        let expected_first_32 =
            hex_to_bytes("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf");
        assert_eq!(&okm[..32], &expected_first_32);
        // Remaining bytes.
        assert_eq!(
            &okm[32..],
            &[0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65]
        );
    }

    #[test]
    fn hkdf_sha256_extract_empty_salt() {
        // Empty salt → uses 32 zero bytes.
        let ikm = b"test input keying material";
        let prk = super::hkdf_sha256_extract(&[], ikm);
        let sum: u32 = prk.iter().map(|&b| b as u32).sum();
        assert!(sum > 0);
    }

    #[test]
    fn hkdf_sha256_round_trip() {
        // Extract + expand with no info.
        let ikm = sha256(b"master secret");
        let salt = sha256(b"random salt value");
        let prk = super::hkdf_sha256_extract(&salt, &ikm);
        let okm = super::hkdf_sha256_expand(&prk, b"", 64);
        assert_eq!(okm.len(), 64);
        // Output should differ from input.
        assert_ne!(&okm[..32], &ikm[..]);
    }
}
