//! libs/crypto/src/lib.rs
//!
//! The cryptographic primitives the kernel uses, as a library with no kernel in
//! it.
//!
//! ## Why this is a crate and not a module
//!
//! Four subsystems needed the same algorithms and none of them owned them: the
//! filesystem hashes streams and checksums clusters, the network derives keys
//! and verifies signatures, the encrypted-zone mount runs PBKDF2 and AES-XTS,
//! and the kernel's own password check salts and hashes.  Filed under any one
//! of them, the other three reach across a boundary that says they may not.
//!
//! The dependencies are the argument: this crate names `core`, `alloc` and
//! `abi`, the error type it returns, and nothing else.  That is what makes it
//! testable on the host, where every one of these algorithms has published test
//! vectors to check against and a boot is not needed to run one.
//!
//! ## What belongs here
//!
//! An algorithm over bytes: a hash, a cipher, a MAC, a key agreement, a
//! signature check.  What does not: anything that reads a device, knows a
//! filesystem, or decides a policy.  A function here takes a slice and returns
//! a value, which is also why the tests can be exhaustive over known-answer
//! vectors rather than over a boot.
//!
//! ## One module per algorithm
//!
//! Each algorithm is a file, and a file is one algorithm's worth of arithmetic
//! plus its vectors.  The split is not decoration: primitives are added and
//! removed one at a time, a machine that needs no signature verification
//! should be able to say so by removing a module, and a single 4,600-line file
//! makes "what does this crate contain" a search rather than a listing.
//!
//! The modules that build on another say so by importing it: `hmac` names
//! `sha256`, `hkdf` names `hmac`, `pbkdf2` names `hmac`, and the two modes of
//! operation name the block cipher they wrap.  Nothing is re-exported through
//! an intermediate module, so the graph a reader sees in the `use` lines is the
//! graph that exists.

#![no_std]

extern crate alloc;

pub mod aead;
pub mod aes;
pub mod chacha20;
pub mod constant_time;
pub mod crc;
pub mod ecdsa;
pub mod gcm;
pub mod hkdf;
pub mod hmac;
pub mod pbkdf2;
pub mod poly1305;
pub mod rsa;
pub mod salt;
pub mod sha256;
pub mod x25519;
pub mod xts;

#[cfg(test)]
mod test_util;

pub use aead::chacha20_poly1305_decrypt;
pub use aead::chacha20_poly1305_encrypt;
pub use chacha20::chacha20_encrypt;
pub use chacha20::chacha20_keystream;
pub use constant_time::constant_time_eq;
pub use crc::crc32;
pub use crc::crc32c;
pub use ecdsa::ecdsa_p256_verify;
pub use ecdsa::parse_ecdsa_der_signature;
pub use gcm::aes128_gcm_decrypt;
pub use gcm::aes128_gcm_encrypt;
pub use hkdf::hkdf_sha256_expand;
pub use hkdf::hkdf_sha256_extract;
pub use hmac::hmac_sha256;
pub use pbkdf2::pbkdf2_hmac_sha256;
pub use poly1305::poly1305_mac;
pub use rsa::rsa_pkcs1v15_verify;
pub use rsa::rsa_pss_verify;
pub use salt::generate_salt;
pub use sha256::sha256;
pub use sha256::sha256_hex;
pub use x25519::x25519;
pub use x25519::x25519_keygen;
pub use xts::aes_xts_decrypt;
pub use xts::aes_xts_encrypt;
