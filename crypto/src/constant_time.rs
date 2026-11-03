//! crypto/src/constant_time.rs
//!
//! Comparison whose running time does not depend on where two byte
//! strings first differ.

/// Compare two 32-byte arrays in constant time to prevent timing side-channels.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    for i in 0..a.len() {
        acc |= a[i] ^ b[i];
    }
    acc == 0
}
#[cfg(test)]
mod tests_constant_time {
    use super::*;
    use crate::sha256::sha256;

    #[test]
    fn constant_time_eq_match() {
        let a = sha256(b"password");
        let b = sha256(b"password");
        assert!(constant_time_eq(&a, &b));
    }

    #[test]
    fn constant_time_eq_mismatch() {
        let a = sha256(b"password");
        let b = sha256(b"wrong");
        assert!(!constant_time_eq(&a, &b));
    }
}
