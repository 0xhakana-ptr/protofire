//! libs/crypto/src/aead/tests.rs
//!
//! The AEAD contract: a tag verified, associated data, and a tampered
//! ciphertext refused.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

use crate::sha256::sha256;

// ChaCha20-Poly1305 AEAD test vectors (RFC 8439 §2.8.2)

#[test]
fn chacha20_poly1305_rfc8439_aead_vector() {
    // RFC 8439 §2.8.2: known ciphertext + tag for a fixed
    // key/nonce/AAD/plaintext.
    let key: [u8; 32] = [
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e,
        0x8f, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d,
        0x9e, 0x9f,
    ];
    let nonce: [u8; 12] = [
        0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    ];
    let aad = [
        0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
    ];
    let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let expected_ct_and_tag: [u8; 130] = [
        0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef, 0x7e,
        0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7, 0x36, 0xee,
        0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa, 0xfb, 0x69, 0xda,
        0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29, 0x05, 0xd6, 0xa5, 0xb6,
        0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77, 0x8b, 0x8c, 0x98, 0x03, 0xae,
        0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4, 0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85,
        0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4, 0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5,
        0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b, 0x61, 0x16, 0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09,
        0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
    ];
    let (ciphertext, tag) = crate::aead::chacha20_poly1305_encrypt(&key, &nonce, &aad, plaintext);
    let mut combined = ciphertext.clone();
    combined.extend_from_slice(&tag);
    assert_eq!(
        combined,
        expected_ct_and_tag.to_vec(),
        "RFC 8439 §2.8.2 ciphertext+tag"
    );

    // Decrypt must recover the plaintext and reject a tampered tag.
    let decrypted = crate::aead::chacha20_poly1305_decrypt(&key, &nonce, &aad, &ciphertext, &tag)
        .expect("RFC 8439 AEAD decrypt");
    assert_eq!(decrypted, plaintext);
    let mut bad_tag = tag;
    bad_tag[15] ^= 0x80;
    assert!(
        crate::aead::chacha20_poly1305_decrypt(&key, &nonce, &aad, &ciphertext, &bad_tag).is_err()
    );
}

#[test]
fn chacha20_poly1305_encrypt_decrypt_round_trip() {
    let key = sha256(b"test-aead-key-32-bytes-long!!");
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sha256(b"test-nonce-12")[..12]);
    let aad = b"additional authenticated data";
    let plaintext = b"Hello, ChaCha20-Poly1305!";

    let (ciphertext, tag) = crate::aead::chacha20_poly1305_encrypt(&key, &nonce, aad, plaintext);
    assert_eq!(ciphertext.len(), plaintext.len());

    let decrypted = crate::aead::chacha20_poly1305_decrypt(&key, &nonce, aad, &ciphertext, &tag)
        .expect("decryption should succeed");
    assert_eq!(decrypted, plaintext);
}

#[test]
fn chacha20_poly1305_tag_verification_fails_with_wrong_key() {
    let key1 = sha256(b"key-1-32-bytes-long!!!!!!!!!");
    let key2 = sha256(b"key-2-32-bytes-long!!!!!!!!!");
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sha256(b"nonce-12-bytes!")[..12]);
    let plaintext = b"sensitive data";

    let (ciphertext, tag) = crate::aead::chacha20_poly1305_encrypt(&key1, &nonce, b"", plaintext);

    let result = crate::aead::chacha20_poly1305_decrypt(&key2, &nonce, b"", &ciphertext, &tag);
    assert!(result.is_err());
}

#[test]
fn chacha20_poly1305_tag_verification_fails_with_wrong_ciphertext() {
    let key = sha256(b"aead-key-32-bytes-long!!!!!!");
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&sha256(b"12-byte-nonce")[..12]);
    let plaintext = b"tamper-resistant data";

    let (mut ciphertext, tag) =
        crate::aead::chacha20_poly1305_encrypt(&key, &nonce, b"", plaintext);
    // Flip a bit in the ciphertext.
    if !ciphertext.is_empty() {
        ciphertext[0] ^= 0x01;
    }

    let result = crate::aead::chacha20_poly1305_decrypt(&key, &nonce, b"", &ciphertext, &tag);
    assert!(result.is_err());
}
