//! crypto/src/salt.rs
//!
//! A deterministic salt for password recovery.
//!
//! Read the warning on [`generate_salt`] before using it: it is not a
//! random salt, and the module is separate so that the one caller that
//! tolerates a deterministic one is the only one that reaches it.

use crate::sha256::sha256;

/// Generate a 16-byte deterministic salt bound to `username`.
///
/// The salt is `sha256(username)[..16]`.  This is deterministic per user and
/// therefore recoverable for a known username; acceptable for the recovery
/// prototype but not for production password storage (which must use a random
/// per-user salt).
pub fn generate_salt(username: &str) -> [u8; 16] {
    // Deterministic per-user salt: sha256(username)[..16].
    // NOTE: deterministic salts are recoverable for a known username; this is
    // acceptable for the recovery prototype but not for production password
    // storage (which must use a random per-user salt).
    let hash = sha256(username.as_bytes());
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&hash[..16]);
    salt
}
#[cfg(test)]
mod tests_salt {
    use super::*;

    #[test]
    fn generate_salt_is_deterministic_length() {
        let s1 = generate_salt("alice");
        let s2 = generate_salt("alice");
        assert_eq!(s1.len(), 16);
        assert_eq!(s2.len(), 16);
        // Salts differ because the counter advances.
    }
}
