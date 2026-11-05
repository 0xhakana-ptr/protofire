//! libs/crypto/src/poly1305/tests.rs
//!
//! Poly1305: the limb arithmetic, the final reduction, and the tag it produces.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

// Poly1305 test vectors (RFC 8439 §2.5.2)

#[test]
fn poly1305_rfc8439_test_vector() {
    // Key from RFC 8439 §2.5.2.
    let key: [u8; 32] = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06,
        0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49,
        0xf5, 0x1b,
    ];
    let message = b"Cryptographic Forum Research Group";
    let tag = crate::poly1305::poly1305_mac(&key, message);
    let expected: [u8; 16] = [
        0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01, 0x27,
        0xa9,
    ];
    assert_eq!(tag, expected);
}

#[test]
fn poly1305_empty_message() {
    let key: [u8; 32] = [0x00; 32];
    let tag = crate::poly1305::poly1305_mac(&key, b"");
    // With an all-zero key and empty message, the tag should still
    // be computed (s value is 0, r is clamped from 0).
    let sum: u32 = tag.iter().map(|&b| b as u32).sum();
    assert_eq!(sum, 0); // r clamped to 0 → accumulator = 0, s = 0 → tag = 0
}

/// Trace through the RFC 8439 test vector step by step, comparing with
/// Python reference intermediate values.
#[test]
fn poly1305_debug_trace_rfc8439() {
    let key: [u8; 32] = [
        0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5, 0x06,
        0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf, 0x41, 0x49,
        0xf5, 0x1b,
    ];

    let (r_bytes, s_bytes) = crate::poly1305::poly1305_clamp(&key);
    let r0 = u64::from_le_bytes(r_bytes[..8].try_into().unwrap());
    let r1 = u64::from_le_bytes(r_bytes[8..].try_into().unwrap());
    let s0 = u64::from_le_bytes(s_bytes[..8].try_into().unwrap());
    let s1 = u64::from_le_bytes(s_bytes[8..].try_into().unwrap());

    // Check clamped r matches Python reference values.
    assert_eq!(r0, 0x036d555408bed685, "r0 mismatch");
    assert_eq!(r1, 0x0806d5400e52447c, "r1 mismatch");
    assert_eq!(s0, 0xfdb20dfb8a800301, "s0 mismatch");
    assert_eq!(s1, 0x1bf54941aff6bf4a, "s1 mismatch");

    let msg = b"Cryptographic Forum Research Group";

    let mut a0: u64 = 0;
    let mut a1: u64 = 0;
    let mut a2: u64 = 0;

    // Block 0: bytes 0..16
    {
        let mut block = [0u8; 17];
        block[..16].copy_from_slice(&msg[..16]);
        block[16] = 0x01;
        let n0 = u64::from_le_bytes(block[..8].try_into().unwrap());
        let n1 = u64::from_le_bytes(block[8..16].try_into().unwrap());
        assert_eq!(n0, 0x72676f7470797243, "blk0 n0");
        assert_eq!(n1, 0x06f46206369687061, "blk0 n1");

        let t0 = a0 as u128 + n0 as u128;
        let t1 = a1 as u128 + n1 as u128 + (t0 >> 64);
        a0 = t0 as u64;
        a1 = t1 as u64;
        a2 = a2.wrapping_add((t1 >> 64) as u64);

        // The 0x01 appended to each 16-byte block is what makes the
        // accumulator a 130-bit number rather than a 128-bit one, and its
        // contribution lands in `a2`: the block is
        // `n0 + n1·2^64 + 2^128`, so adding it to `a` adds one to the
        // third limb as well as folding in the carry from `n0 + n1`.
        assert_eq!(a0, 0x72676f7470797243, "blk0 after add a0");
        assert_eq!(a1, 0x06f46206369687061, "blk0 after add a1");
        // The accumulator after the first block is the block's value as a
        // 129-bit number: `0x1_6f4620_63696870_6172676f_7470797243`.  Split
        // into three limbs it is exactly what the assertions above read,
        // and the leading one is the appended byte's contribution.
        //
        // The two halves of the first chunk are `"Cryptogr"` and
        // `"aphic Fo"` read little-endian, which is why `n1` looks like
        // `0x06f462...` rather than the bytes in order.
        //
        // Actually, the LE interpretation means:
        // n0 = 0x72676f7470797243 (from bytes 0-7 reversed)
        // n1 = 0x6f46206369687061 (from bytes 8-15, but check the
        // endianness!)
        //
        // `u64::from_le_bytes` takes the bytes little-endian, so
        // n1 = u64::from_le_bytes([97, 112, 104, 105, 99, 32, 70, 111])
        //      = 111*2^56 + 70*2^48 + 32*2^40 + 99*2^32 + 105*2^24 +
        // 104*2^16 + 112*2^8
        // + 97      = 0x6f46206369687061
        //
        // The 2^128 term the appended byte carries, in the third limb.
        a2 = a2.wrapping_add(1);

        assert_eq!(a0, 0x72676f7470797243, "blk0 after add a0");
        assert_eq!(a1, 0x06f46206369687061, "blk0 after add a1");
        assert_eq!(
            a2, 0x1,
            "blk0 after add a2, need +1 for 0x01 byte at bit 128"
        );

        crate::poly1305::poly1305_mul_mod(&mut a0, &mut a1, &mut a2, [r0, r1]);
        assert_eq!(a0, 0x47ddeb88e69c83fc, "blk0 after mul a0");
        assert_eq!(a1, 0xc88c77849d64ae91, "blk0 after mul a1");
        assert_eq!(a2, 0x2, "blk0 after mul a2");
    }

    // Block 1: bytes 16..32
    {
        let mut block = [0u8; 17];
        block[..16].copy_from_slice(&msg[16..32]);
        block[16] = 0x01;
        let n0 = u64::from_le_bytes(block[..8].try_into().unwrap());
        let n1 = u64::from_le_bytes(block[8..16].try_into().unwrap());

        let t0 = a0 as u128 + n0 as u128;
        let t1 = a1 as u128 + n1 as u128 + (t0 >> 64);
        a0 = t0 as u64;
        a1 = t1 as u64;
        a2 = a2.wrapping_add((t1 >> 64) as u64);
        a2 = a2.wrapping_add(1); // FIX: 0x01 byte → +1 to a2

        assert_eq!(a0, 0xad5150db0709f96e, "blk1 after add a0");
        assert_eq!(a1, 0x37febea505c820f2, "blk1 after add a1");
        assert_eq!(a2, 0x4, "blk1 after add a2");

        crate::poly1305::poly1305_mul_mod(&mut a0, &mut a1, &mut a2, [r0, r1]);
        assert_eq!(a0, 0xcccfb4ea344b30de, "blk1 after mul a0");
        assert_eq!(a1, 0xd8adaf23b0337fa7, "blk1 after mul a1");
        assert_eq!(a2, 0x2, "blk1 after mul a2");
    }

    // Block 2 (partial): bytes 32..34
    {
        let remainder = &msg[32..];
        let mut block = [0u8; 17];
        block[..remainder.len()].copy_from_slice(remainder);
        block[remainder.len()] = 0x01;
        let n0 = u64::from_le_bytes(block[..8].try_into().unwrap());
        let n1 = u64::from_le_bytes(block[8..16].try_into().unwrap());
        // remainder = "up" = [117, 112]. block = [117, 112, 0x01, 0, 0, 0,
        // 0, 0] (9 meaningful bytes) n0 = LE of first 8 bytes = [117, 112,
        // 1, 0, 0, 0, 0, 0] = 117 + 112*256 + 1*65536 = 117 + 28672 + 65536
        // = 94325 = 0x17075
        assert_eq!(n0, 0x0000000000017075, "blk2 n0");

        // For partial block, the 0x01 byte is at len=2, so it's already in
        // n0. No +1 to a2 needed.
        let t0 = a0 as u128 + n0 as u128;
        let t1 = a1 as u128 + n1 as u128 + (t0 >> 64);
        a0 = t0 as u64;
        a1 = t1 as u64;
        a2 = a2.wrapping_add((t1 >> 64) as u64);

        assert_eq!(a0, 0xcccfb4ea344ca153, "blk2 after add a0");
        assert_eq!(a1, 0xd8adaf23b0337fa7, "blk2 after add a1");
        assert_eq!(a2, 0x2, "blk2 after add a2");

        crate::poly1305::poly1305_mul_mod(&mut a0, &mut a1, &mut a2, [r0, r1]);
        assert_eq!(a0, 0xc8844335369d03a7, "blk2 after mul a0");
        assert_eq!(a1, 0x8d31b7caff946c77, "blk2 after mul a1");
        assert_eq!(a2, 0x2, "blk2 after mul a2");
    }

    // Final: add s modulo 2^128 (no reduce needed).
    let t0 = a0 as u128 + s0 as u128;
    let carry0 = t0 >> 64;
    a0 = t0 as u64;
    let t1 = a1 as u128 + s1 as u128 + carry0;
    a1 = t1 as u64;

    let mut tag = [0u8; 16];
    tag[..8].copy_from_slice(&a0.to_le_bytes());
    tag[8..].copy_from_slice(&a1.to_le_bytes());
    assert_eq!(
        tag,
        [
            0xa8, 0x06, 0x1d, 0xc1, 0x30, 0x51, 0x36, 0xc6, 0xc2, 0x2b, 0x8b, 0xaf, 0x0c, 0x01,
            0x27, 0xa9
        ],
        "final tag mismatch, got {tag:02x?}"
    );
}
