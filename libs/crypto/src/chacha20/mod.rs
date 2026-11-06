//! libs/crypto/src/chacha20/mod.rs
//!
//! ChaCha20 (RFC 8439): 256-bit key, 96-bit nonce, 32-bit counter.

/// ChaCha20 quarter round: operates on four 32-bit state words in-place.
#[inline(always)]
fn chacha20_quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(16);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(12);

    state[a] = state[a].wrapping_add(state[b]);
    state[d] ^= state[a];
    state[d] = state[d].rotate_left(8);

    state[c] = state[c].wrapping_add(state[d]);
    state[b] ^= state[c];
    state[b] = state[b].rotate_left(7);
}

/// ChaCha20 block function: process the 4x4 state matrix with 20 rounds
/// (10 double rounds) and return the result added to the input.
pub(crate) fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    // Initial state: "expand 32-byte k" constant (4 words) + key (8 words) +
    // block counter (1 word) + nonce (3 words).
    let mut state: [u32; 16] = [
        0x61707865, // "expa"
        0x3320646e, // "nd 3"
        0x79622d32, // "2-by"
        0x6b206574, // "te k"
        // Key words (8 × 32-bit little-endian).
        u32::from_le_bytes([key[0], key[1], key[2], key[3]]),
        u32::from_le_bytes([key[4], key[5], key[6], key[7]]),
        u32::from_le_bytes([key[8], key[9], key[10], key[11]]),
        u32::from_le_bytes([key[12], key[13], key[14], key[15]]),
        u32::from_le_bytes([key[16], key[17], key[18], key[19]]),
        u32::from_le_bytes([key[20], key[21], key[22], key[23]]),
        u32::from_le_bytes([key[24], key[25], key[26], key[27]]),
        u32::from_le_bytes([key[28], key[29], key[30], key[31]]),
        counter, // Block counter.
        // Nonce words (3 × 32-bit little-endian).
        u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]),
        u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]),
        u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]),
    ];

    let initial = state;

    // 10 double rounds = 20 rounds total.
    for _ in 0..10 {
        // Column rounds.
        chacha20_quarter_round(&mut state, 0, 4, 8, 12);
        chacha20_quarter_round(&mut state, 1, 5, 9, 13);
        chacha20_quarter_round(&mut state, 2, 6, 10, 14);
        chacha20_quarter_round(&mut state, 3, 7, 11, 15);
        // Diagonal rounds.
        chacha20_quarter_round(&mut state, 0, 5, 10, 15);
        chacha20_quarter_round(&mut state, 1, 6, 11, 12);
        chacha20_quarter_round(&mut state, 2, 7, 8, 13);
        chacha20_quarter_round(&mut state, 3, 4, 9, 14);
    }

    // Add the original state to produce the 64-byte keystream block.
    for i in 0..16 {
        state[i] = state[i].wrapping_add(initial[i]);
    }

    // Serialise to little-endian bytes.
    let mut block = [0u8; 64];
    for (i, word) in state.iter().enumerate() {
        let bytes = word.to_le_bytes();
        block[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }

    block
}

/// Encrypt or decrypt `data` in-place using ChaCha20.
///
/// ChaCha20 is a stream cipher: encryption and decryption are the same
/// XOR operation with the keystream.
pub fn chacha20_encrypt(key: &[u8; 32], nonce: &[u8; 12], data: &mut [u8]) {
    let mut counter: u32 = 0;

    for chunk in data.chunks_mut(64) {
        let keystream = chacha20_block(key, counter, nonce);
        for (byte, ks) in chunk.iter_mut().zip(keystream.iter()) {
            *byte ^= ks;
        }
        counter = counter.wrapping_add(1);
    }
}

/// Generate ChaCha20 keystream bytes without XOR'ing into plaintext.
/// Useful for generating random bytes from a CSPRNG seeded with ChaCha20.
pub fn chacha20_keystream(key: &[u8; 32], nonce: &[u8; 12], counter: u32, out: &mut [u8]) {
    let mut ctr = counter;
    for chunk in out.chunks_mut(64) {
        let keystream = chacha20_block(key, ctr, nonce);
        let len = chunk.len();
        chunk.copy_from_slice(&keystream[..len]);
        ctr = ctr.wrapping_add(1);
    }
}

#[cfg(test)]
mod tests;
