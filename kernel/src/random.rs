//! kernel/src/random.rs
//!
//! The bytes a program gets when it asks the kernel for randomness.
//!
//! ## What this is, and what it is not
//!
//! A ChaCha20 keystream, keyed once at boot from material this machine can
//! produce and re-keyed after a bounded number of blocks.  That is a generator
//! whose **output** does not repeat inside a boot and does not repeat across
//! boots, and whose next bytes cannot be guessed from the previous ones.
//!
//! It is **not** a substitute for hardware entropy, and this paragraph is the
//! place that says so rather than a caveat in a commit message.  The tree has
//! no `RDRAND`, `RNDR` or `RDSEED` probe, so the seed is timing: the counter
//! readings this boot happened to observe.  A program that can read the same
//! counter — and any program can, through `GetTimeOfDay` — knows the *kind* of
//! material the seed was made from.  It cannot know the exact readings, because
//! the seed is taken across boot steps a program never runs, but "cannot
//! practically" is a weaker claim than "cannot at all".
//!
//! So the honest statement of what [`fill`] gives a caller: bytes that differ
//! on every call and across boots, fit for a nonce, a salt, a jitter value, or
//! a program's own shuffle.  Not fit for a long-lived key an attacker is
//! motivated to recover, until this tree has a entropy source that is not the
//! clock.  `docs/status.md` records that gap next to the level that landed.
//!
//! ## Why the state is a ratchet
//!
//! The key is not constant for a boot.  After [`RESEED_BLOCKS`] blocks the
//! generator hashes its own key and nonce into the next key, so the material
//! behind any one output is bounded: recovering the seed from an early output
//! does not yield the bytes handed out later.  A ratchet is the cheapest honest
//! thing to do with a weak seed, because it stops the weakness from being one
//! that applies to the whole boot.

use crypto::chacha20::chacha20_keystream;
use crypto::sha256::sha256;
use sync::Mutex;

/// How many blocks the generator produces before it re-keys.
///
/// A block is 64 bytes, so this is 64 KiB between ratchets — small enough that
/// a program reading megabytes still crosses it, large enough that the hash is
/// not on a path a program calls per byte.
pub const RESEED_BLOCKS: u32 = 1024;

/// The generator's state: a key, a nonce, and where in the stream it is.
///
/// `counter` is the ChaCha20 block counter and is what makes successive fills
/// different; `since_reseed` counts blocks toward the ratchet and is a separate
/// number because the two mean different things — a wrapped counter is a stream
/// restart, a spent budget is a re-key.
pub struct Keystream {
    key: [u8; 32],
    nonce: [u8; 12],
    counter: u32,
    since_reseed: u32,
}

impl Keystream {
    /// A generator over `seed`, with a nonce derived from it.
    ///
    /// The nonce is the first twelve bytes of `sha256(seed)` — not the seed's
    /// own first twelve, because a ChaCha20 key and nonce that share bytes are
    /// two values an attacker gets for the price of one, and the hash costs one
    /// pass over 32 bytes at boot.
    pub fn new(seed: [u8; 32]) -> Self {
        let digest = sha256(&seed);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&digest[..12]);
        Self {
            key: seed,
            nonce,
            counter: 0,
            since_reseed: 0,
        }
    }

    /// Fill `buffer` with the next bytes of the stream.
    ///
    /// A zero-length buffer writes nothing and advances nothing: a caller that
    /// asked for no bytes is not a caller who consumed any.
    pub fn fill(&mut self, buffer: &mut [u8]) {
        if buffer.is_empty() {
            return;
        }
        chacha20_keystream(&self.key, &self.nonce, self.counter, buffer);
        let blocks = buffer.len().div_ceil(64) as u32;
        self.counter = self.counter.wrapping_add(blocks);
        self.since_reseed += blocks;
        if self.since_reseed >= RESEED_BLOCKS {
            self.ratchet();
        }
    }

    /// Replace the key with a hash of the whole state.
    ///
    /// Every field goes in, which is what makes this a ratchet rather than a
    /// derivation of the old key alone: the nonce and the counters are state an
    /// observer would have to reproduce to follow the generator past a re-key.
    fn ratchet(&mut self) {
        let mut material = [0u8; 32 + 12 + 4 + 4];
        material[..32].copy_from_slice(&self.key);
        material[32..44].copy_from_slice(&self.nonce);
        material[44..48].copy_from_slice(&self.counter.to_le_bytes());
        material[48..52].copy_from_slice(&self.since_reseed.to_le_bytes());
        self.key = sha256(&material);
        self.nonce.copy_from_slice(&sha256(&self.key)[..12]);
        self.counter = 0;
        self.since_reseed = 0;
    }
}

/// The boot's generator, installed once.
///
/// `None` until the boot seeds it.  A program that asks for random bytes on a
/// boot that never seeded is told the call is unsupported, which is true: this
/// kernel has no generator, not a generator that answered nothing.
static GENERATOR: Mutex<Option<Keystream>> = Mutex::new(None);

/// Seed the generator from this boot's own timing.
///
/// Six counter readings, taken with a spin between them, hashed into a key.
/// The spin is not decoration: two reads of a counter back to back differ by a
/// handful of ticks on a machine whose granularity is coarser than the two
/// instructions between them, and a seed made of six nearly equal numbers is
/// nearly one number.
///
/// Answers the first eight bytes of the key it installed, so the boot's line
/// can name its generator without printing the key.
///
/// # Safety
///
/// Called once, from the boot, after the timer is up and before any program
/// runs.
#[cfg(target_os = "none")]
pub unsafe fn seed() -> Option<u64> {
    let mut material = [0u8; 6 * 8];
    // SAFETY: the caller's contract is this function's; the counter is read
    // after the boot brought the timer up.
    let first = unsafe { arch::timer_counter() };
    for slot in 0..6 {
        // SAFETY: read-only.
        let reading = unsafe { arch::timer_counter() };
        material[slot * 8..slot * 8 + 8].copy_from_slice(&reading.to_le_bytes());
        let mut spin = 0u64;
        while spin < 1_000 {
            spin += 1;
        }
    }
    // The first reading goes in too, at the front, so the seed covers the span
    // the six were taken over and not only their values.
    let seed = sha256(&material);
    let mut with_origin = [0u8; 40];
    with_origin[..32].copy_from_slice(&seed);
    with_origin[32..].copy_from_slice(&first.to_le_bytes());
    let key = sha256(&with_origin);
    let mut generator = GENERATOR.lock();
    *generator = Some(Keystream::new(key));
    Some(u64::from_le_bytes(key[..8].try_into().ok()?))
}

/// Fill `buffer` with the next bytes of this boot's stream.
///
/// `OutOfMemory` when the boot never seeded, which is the state a host build is
/// in and the state a machine whose timer never reported a rate is in.  Named
/// as an allocation failure because a caller has no other word for "the thing
/// you asked for does not exist on this machine"; the syscall layer turns it
/// into `Unsupported` for a program, which says it better.
pub fn fill(buffer: &mut [u8]) -> abi::Result<()> {
    let mut generator = GENERATOR.lock();
    let generator = generator.as_mut().ok_or(abi::Error::Unsupported)?;
    generator.fill(buffer);
    Ok(())
}

/// The generator's kind and where it is, for a boot line and for `AbiInfo`.
///
/// Answers how many blocks this generator has produced since its last re-key.
/// A caller that reports it is reporting that the generator exists and has
/// moved, which is the part a boot can check without printing a key.
pub fn progress() -> Option<u32> {
    let generator = GENERATOR.lock();
    generator.as_ref().map(|generator| generator.since_reseed)
}

#[cfg(test)]
mod tests {
    use super::Keystream;
    use super::RESEED_BLOCKS;

    /// A seed the generator can be built from on a host, where there is no
    /// counter.  Fixed rather than random: a test whose input moves is a test
    /// whose failure cannot be reproduced.
    fn seed() -> [u8; 32] {
        let mut seed = [0u8; 32];
        for (index, byte) in seed.iter_mut().enumerate() {
            *byte = index as u8;
        }
        seed
    }

    /// Successive fills are different bytes.
    ///
    /// The whole point of the generator.  A stream that restarted at every call
    /// would pass a test that only checked the length.
    #[test]
    fn successive_fills_differ() {
        let mut generator = Keystream::new(seed());
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        generator.fill(&mut first);
        generator.fill(&mut second);
        assert_ne!(first, second);
        assert_ne!(first, [0u8; 32], "the stream is not zeros");
    }

    /// The same seed produces the same stream.
    ///
    /// Determinism is not a security property here — it is what makes the
    /// ratchet testable: two generators built from one seed must agree before
    /// their state can be shown to diverge after a re-key.
    #[test]
    fn the_same_seed_produces_the_same_stream() {
        let mut one = Keystream::new(seed());
        let mut two = Keystream::new(seed());
        let mut first = [0u8; 64];
        let mut second = [0u8; 64];
        one.fill(&mut first);
        two.fill(&mut second);
        assert_eq!(first, second);
    }

    /// A fill that is not a multiple of the block size still produces the bytes
    /// asked for, and the next call continues rather than repeating.
    ///
    /// The off-by-one case: a fill of 65 bytes consumes **two** blocks, because
    /// the second chunk is one byte and the cipher still produces a whole
    /// block for it.  A counter advanced by one block instead of by two would
    /// hand out block 1 a second time, so the next call's first byte has to be
    /// the stream's 129th and not its 65th.
    #[test]
    fn a_partial_block_does_not_repeat_the_next_call() {
        let mut generator = Keystream::new(seed());
        let mut first = [0u8; 65];
        let mut second = [0u8; 64];
        generator.fill(&mut first);
        generator.fill(&mut second);
        let mut reference = [0u8; 192];
        let mut fresh = Keystream::new(seed());
        fresh.fill(&mut reference);
        assert_eq!(
            &second[..1],
            &reference[128..129],
            "the next call starts at block 2, after 65 bytes consumed two blocks"
        );
        assert_ne!(
            &second[..1],
            &reference[64..65],
            "and not at block 1, which is what advancing by one block would give"
        );
    }

    /// An empty fill advances nothing.
    ///
    /// A caller that asked for no bytes consumed none of the stream, so the
    /// next fill is the same as if the empty one had not happened.
    #[test]
    fn an_empty_fill_advances_nothing() {
        let mut with = Keystream::new(seed());
        let mut without = Keystream::new(seed());
        with.fill(&mut []);
        let mut first = [0u8; 32];
        let mut second = [0u8; 32];
        with.fill(&mut first);
        without.fill(&mut second);
        assert_eq!(first, second);
    }

    /// The generator re-keys after its block budget, and the next bytes are not
    /// the ones the un-re-keyed stream would have produced.
    ///
    /// This is the ratchet, and it is checked at the boundary rather than by
    /// calling it: a generator handed exactly [`RESEED_BLOCKS`] blocks of
    /// output must have re-keyed, and a generator handed one block fewer must
    /// not have.
    #[test]
    fn the_stream_ratchets_at_its_budget() {
        let full = RESEED_BLOCKS as usize * 64;
        let mut spent = Keystream::new(seed());
        let mut buffer = alloc::vec![0u8; full];
        spent.fill(&mut buffer);
        assert_eq!(
            spent.since_reseed, 0,
            "the budget was spent, so it re-keyed"
        );

        let mut short = Keystream::new(seed());
        let mut buffer = alloc::vec![0u8; full - 64];
        short.fill(&mut buffer);
        assert_eq!(
            short.since_reseed,
            RESEED_BLOCKS - 1,
            "one block short of the budget, so it did not re-key"
        );

        // And the re-key changed the key, which is what makes it a ratchet: the
        // same generator's next bytes differ from a fresh one's.
        let mut after = [0u8; 32];
        let mut fresh = Keystream::new(seed());
        let mut expected = [0u8; 32];
        spent.fill(&mut after);
        fresh.fill(&mut expected);
        assert_ne!(after, expected);
    }
}
