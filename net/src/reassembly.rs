//! net/src/reassembly.rs
//!
//! Putting a packet back together: the pieces of a fragmented datagram, held
//! until the last one arrives, bounded in every direction a peer controls.
//!
//! ## Why a stack has to do this
//!
//! A path can shrink below the sender's packet size, and the sender's answer
//! is to split a packet into pieces an 8-byte-aligned offset can address.  A
//! stack that reads a piece as a whole answers with a truncated segment that
//! looks complete — which is the wrong answer this crate's parsers already
//! refuse one layer down.  Refusing is honest and it is not usable: a peer's
//! first large datagram would be undelivered forever.
//!
//! ## What a peer controls, and what bounds it
//!
//! Everything a fragment carries is the sender's choice: how many pieces, how
//! large each is, and how long the whole thing claims to be.  So every bound
//! here exists because a peer would otherwise choose it:
//!
//! | a peer could choose | so this does |
//! |---|---|
//! | unbounded memory | a fixed block budget per entry, and a fixed number of entries |
//! | an offset past the end | refuse a piece that would run past the budget |
//! | overlapping pieces with conflicting bytes | refuse the whole datagram ([RFC 5722]) |
//! | never sending the last piece | expire the entry on the caller's clock |
//! | a duplicate that re-writes covered bytes | treat the second copy as a duplicate, not new data |
//!
//! [RFC 5722]: https://www.rfc-editor.org/rfc/rfc5722
//!
//! ## Why no lock and no `static`
//!
//! A cache is a value a caller owns.  Which clock it expires against, how it
//! is shared, and whether it is rebuilt every boot are the caller's decisions
//! — and a host test can hold one without any of them.
//!
//! ## The clock is the caller's
//!
//! Nothing here reads a timer.  Every method that needs the time is given it,
//! because a timer in this crate would be a crate that could not be tested
//! without one.  The unit is the caller's too: the kernel passes its own
//! ticks.

use alloc::vec::Vec;

use crate::address::Address;

/// How many bytes one reassembled payload may be.
///
/// An IPv4 datagram's total length field is sixteen bits, and its payload is
/// that less a header of at least twenty: sixty-five thousand five hundred
/// and fifteen minus twenty is the ceiling a legal sender could produce.  A
/// claimed length past it is a peer choosing a number, not a wire fact.
pub const MAX_PAYLOAD: usize = 65_535 - 20;

/// How many entries the cache holds before it refuses a new one.
///
/// Sixteen, because a fragment a peer sends is memory this stack spends on
/// that peer's word, and a peer with sixteen half-assembled datagrams is
/// already past what one conversation needs.  A refused entry is a datagram
/// dropped, which is what an unfragmented path would have done anyway.
pub const MAX_ENTRIES: usize = 16;

/// How long an entry may wait for its last piece, in the caller's units.
///
/// The value is the RFC's own floor for IPv4 reassembly — a minute is too long
/// for a stack that boots in seconds, so this is [RFC 1122]'s "at least
/// thirty seconds" against a hundred-hertz clock: three thousand ticks.
///
/// [RFC 1122]: https://www.rfc-editor.org/rfc/rfc1122
pub const TIMEOUT_TICKS: u64 = 3_000;

/// What one fragment says about the packet it is a piece of.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Piece<'a> {
    /// The bytes this piece carries.
    pub data: &'a [u8],
    /// Where they start in the payload being reassembled.
    pub offset: usize,
    /// Whether more pieces follow.  The piece that says `false` is the one
    /// that fixes the payload's total length.
    pub more: bool,
}

/// The identity every piece of one datagram shares.
///
/// Keyed on the sender, the receiver, the identification and the protocol,
/// which is the set the two families agree on: IPv4's fragment header carries
/// the identification and the protocol in the IP header, and IPv6's carries
/// the identification in the fragment header while its next-header field names
/// the transport.  The family is part of the key because the two
/// identifications are not comparable numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key {
    /// Which family the pieces are.
    pub family: u8,
    /// Who sent them.
    pub source: Address,
    /// Who they are for.
    pub destination: Address,
    /// The number the sender chose for this datagram.
    pub identification: u32,
    /// The transport the whole packet carries, as the fragment header names
    /// it.
    pub next_header: u8,
}

/// One fragment, as the cache holds it.
///
/// Bytes rather than a range: pieces may arrive in any order, and a piece
/// that arrives before the last one is the only record of what it covered.
#[derive(Debug)]
struct Held {
    offset: usize,
    data: Vec<u8>,
}

/// One datagram being reassembled.
#[derive(Debug)]
struct Entry {
    /// When this entry was opened, on the caller's clock.
    created_at: u64,
    /// The pieces that arrived.
    held: Vec<Held>,
    /// How many bytes have been covered, and which: a byte map rather than a
    /// bitmap of eight-byte blocks, because a legal sender's pieces are
    /// eight-byte aligned but a *wrong* one's are not, and a map answers
    /// "covered" for both.
    covered: Vec<bool>,
    /// The bytes themselves, so a piece that lies entirely inside what is
    /// already held can be compared rather than assumed.  That comparison is
    /// the whole of [RFC 5722]'s rule: a second copy of the same bytes is a
    /// retransmission, and a second copy that *differs* is how a sender
    /// smuggles bytes past whatever read the first one.
    ///
    /// [RFC 5722]: https://www.rfc-editor.org/rfc/rfc5722
    bytes: Vec<u8>,
    /// The payload's total length, once a piece has said it is the last.
    total: Option<usize>,
    /// How many bytes of `covered` are true, which is what makes completion a
    /// comparison rather than another scan.
    covered_count: usize,
}

impl Entry {
    fn new(now: u64) -> Self {
        Self {
            created_at: now,
            held: Vec::new(),
            covered: Vec::new(),
            bytes: Vec::new(),
            total: None,
            covered_count: 0,
        }
    }

    /// Whether `[offset, offset + length)` is already entirely covered, and
    /// holds exactly `data`.
    ///
    /// Both halves matter: coverage alone cannot tell a retransmission from
    /// the overlap [RFC 5722] refuses, because the attack is a piece that is
    /// entirely inside what is held and says something different.
    ///
    /// [RFC 5722]: https://www.rfc-editor.org/rfc/rfc5722
    fn holds_same(&self, offset: usize, data: &[u8]) -> bool {
        let length = data.len();
        if !self.covers(offset, length) {
            return false;
        }
        length == 0 || self.bytes[offset..offset + length] == *data
    }

    /// Whether `[offset, offset + length)` is already entirely covered.
    fn covers(&self, offset: usize, length: usize) -> bool {
        if length == 0 {
            return true;
        }
        let end = offset + length;
        if end > self.covered.len() {
            return false;
        }
        self.covered[offset..end].iter().all(|covered| *covered)
    }

    /// Whether `[offset, offset + length)` overlaps anything covered.
    fn overlaps(&self, offset: usize, length: usize) -> bool {
        if length == 0 {
            return false;
        }
        let end = (offset + length).min(self.covered.len());
        if offset >= end {
            return false;
        }
        self.covered[offset..end].iter().any(|covered| *covered)
    }

    /// Record `[offset, offset + length)` as covered, growing the map and the
    /// bytes with it.
    fn mark(&mut self, offset: usize, data: &[u8]) {
        let length = data.len();
        let end = offset + length;
        if self.covered.len() < end {
            self.covered.resize(end, false);
            self.bytes.resize(end, 0);
        }
        self.bytes[offset..end].copy_from_slice(data);
        for slot in &mut self.covered[offset..end] {
            if !*slot {
                *slot = true;
                self.covered_count += 1;
            }
        }
    }
}

/// What one received fragment did.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Nothing yet: the piece is held, and the datagram is not complete.
    Collected,
    /// The datagram is complete, and this is its payload.
    Complete(Vec<u8>),
    /// The piece was refused, and the datagram it belonged to is gone.
    ///
    /// Every refusal drops the whole entry rather than the one piece: a
    /// sender whose pieces disagree has produced a datagram this stack cannot
    /// reconstruct, and keeping the pieces it likes would be assembling bytes
    /// no sender sent.
    Refused(Refusal),
}

/// Why a piece was refused.
///
/// Named rather than counted, because each is a different lie a peer can tell
/// and the caller's line says which.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A piece whose bytes run past the budget a payload may have.
    TooLarge,
    /// A piece that covers bytes another piece already covered.
    ///
    /// [RFC 5722] requires this: overlapping fragments let a sender smuggle
    /// bytes past whatever read the first copy.
    ///
    /// [RFC 5722]: https://www.rfc-editor.org/rfc/rfc5722
    Overlap,
    /// A second last piece that disagrees with the first about the length.
    ConflictingLength,
    /// The cache holds `MAX_ENTRIES` datagrams already, and this is one more.
    CacheFull,
}

/// The fragments a machine is holding, and the clock it expires them on.
#[derive(Debug)]
pub struct Cache {
    entries: Vec<(Key, Entry)>,
}

impl Cache {
    /// An empty cache.
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// How many datagrams are being reassembled.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether nothing is being reassembled.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drop every entry that has waited past [`TIMEOUT_TICKS`].
    ///
    /// Called by the caller's own clock, which is why the tick is an argument:
    /// a cache that expired itself would need a timer, and a timer here would
    /// be a crate that could not be tested without one.
    pub fn expire(&mut self, now: u64) {
        self.entries
            .retain(|(_, entry)| now.wrapping_sub(entry.created_at) < TIMEOUT_TICKS);
    }

    /// Whether a datagram is being held under this key.
    pub fn holds(&self, key: &Key) -> bool {
        self.entries.iter().any(|(held, _)| held == key)
    }

    /// Forget a datagram, which a caller does when it gives up on one.
    pub fn forget(&mut self, key: &Key) {
        self.entries.retain(|(held, _)| held != key);
    }

    /// Take one fragment, answering what it did.
    ///
    /// A piece that arrives before the last one grows the entry's budget as it
    /// goes: the payload's total is unknown until a piece says it is last, so
    /// an entry can only be refused for size once a total is known or once a
    /// piece's own end reaches past [`MAX_PAYLOAD`].
    pub fn accept(&mut self, key: Key, piece: Piece<'_>, now: u64) -> Outcome {
        self.expire(now);

        let end = piece.offset.saturating_add(piece.data.len());
        if end > MAX_PAYLOAD {
            self.forget(&key);
            return Outcome::Refused(Refusal::TooLarge);
        }

        let index = match self.entries.iter().position(|(held, _)| *held == key) {
            Some(index) => index,
            None => {
                // A new datagram: refused when the cache is full, rather than
                // evicting a datagram another peer is mid-send on.  An evicted
                // entry is one this stack was already spending memory on and
                // would have timed out; refusing the *newest* is the choice
                // that keeps a completed exchange's pieces together.
                if self.entries.len() >= MAX_ENTRIES {
                    return Outcome::Refused(Refusal::CacheFull);
                }
                self.entries.push((key, Entry::new(now)));
                self.entries.len() - 1
            }
        };

        let entry = &mut self.entries[index].1;

        // The last piece fixes the total, and a second last piece that
        // disagrees is a sender whose two halves describe different packets.
        if !piece.more {
            match entry.total {
                Some(total) if total != end => {
                    self.entries.remove(index);
                    return Outcome::Refused(Refusal::ConflictingLength);
                }
                _ => entry.total = Some(end),
            }
        }
        if entry.total.is_some_and(|total| end > total) {
            self.entries.remove(index);
            return Outcome::Refused(Refusal::TooLarge);
        }

        // A piece whose bytes are already held *and agree* is a
        // retransmission, which changes nothing.  A piece that covers some
        // covered bytes and disagrees — or that runs into them at all — is
        // the overlap [RFC 5722] refuses: a retransmitted fragment is legal,
        // a redrawn one is the attack.
        //
        // [RFC 5722]: https://www.rfc-editor.org/rfc/rfc5722
        if entry.holds_same(piece.offset, piece.data) {
            return self.complete_or_collected(index);
        }
        if entry.overlaps(piece.offset, piece.data.len()) {
            self.entries.remove(index);
            return Outcome::Refused(Refusal::Overlap);
        }

        entry.held.push(Held {
            offset: piece.offset,
            data: Vec::from(piece.data),
        });
        entry.mark(piece.offset, piece.data);
        self.complete_or_collected(index)
    }

    /// Answer whether the entry at `index` is complete, removing it if it is.
    fn complete_or_collected(&mut self, index: usize) -> Outcome {
        let entry = &self.entries[index].1;
        let Some(total) = entry.total else {
            return Outcome::Collected;
        };
        if entry.covered_count < total {
            return Outcome::Collected;
        }
        let (_, entry) = self.entries.remove(index);
        let mut payload = alloc::vec![0_u8; total];
        for held in &entry.held {
            let end = (held.offset + held.data.len()).min(total);
            if held.offset < end {
                payload[held.offset..end].copy_from_slice(&held.data[..end - held.offset]);
            }
        }
        Outcome::Complete(payload)
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::Cache;
    use super::Key;
    use super::MAX_ENTRIES;
    use super::MAX_PAYLOAD;
    use super::Outcome;
    use super::Piece;
    use super::Refusal;
    use super::TIMEOUT_TICKS;
    use crate::address::Address;
    use alloc::vec::Vec;

    const SOURCE: Address = Address::V4([10, 0, 2, 2]);
    const DESTINATION: Address = Address::V4([10, 0, 2, 15]);

    fn key(identification: u32) -> Key {
        Key {
            family: 4,
            source: SOURCE,
            destination: DESTINATION,
            identification,
            next_header: 17,
        }
    }

    /// A piece at an offset.
    fn piece(data: &'static [u8], offset: usize, more: bool) -> Piece<'static> {
        Piece { data, offset, more }
    }

    /// Pieces in any order reassemble into the payload the sender split.  The
    /// piece that says "no more" fixes the total, and the entry completes the
    /// moment every byte before that total is covered — which for the last
    /// piece first means the moment the first piece joins it.
    #[test]
    fn pieces_in_any_order_reassemble() {
        let mut cache = Cache::new();
        let key = key(1);

        // The tail first: it says where the payload ends, and on its own it
        // covers bytes 8..12 of a twelve-byte payload, so nothing completes.
        assert_eq!(
            cache.accept(key, piece(b"ijkl", 8, false), 0),
            Outcome::Collected
        );
        assert_eq!(cache.len(), 1);

        // The head joins it, and the two together are the whole payload.
        assert_eq!(
            cache.accept(key, piece(b"01234567", 0, true), 0),
            Outcome::Complete(Vec::from(&b"01234567ijkl"[..]))
        );
        assert!(cache.is_empty(), "a completed datagram is not kept");
    }

    /// Two pieces that both claim to be the last, and disagree about where
    /// the payload ends, are a sender describing two different packets: the
    /// second one takes the datagram with it.
    #[test]
    fn a_second_last_piece_that_disagrees_refuses_the_datagram() {
        let mut cache = Cache::new();
        let key = key(11);
        assert_eq!(
            cache.accept(key, piece(b"abcdefgh", 8, false), 0),
            Outcome::Collected
        );
        // A different end for the same datagram.
        assert_eq!(
            cache.accept(key, piece(b"ijkl", 16, false), 0),
            Outcome::Refused(Refusal::ConflictingLength)
        );
        assert!(cache.is_empty(), "and the entry went with it");
    }

    /// A piece whose bytes are already held *exactly* is a retransmission and
    /// changes nothing — including when it is the piece that completes the
    /// datagram.
    #[test]
    fn an_exact_duplicate_is_a_retransmission() {
        let mut cache = Cache::new();
        let key = key(12);
        cache.accept(key, piece(b"abcdefgh", 0, true), 0);
        // The same piece again: nothing new, and nothing completes without
        // the last one.
        assert_eq!(
            cache.accept(key, piece(b"abcdefgh", 0, true), 0),
            Outcome::Collected
        );
        assert_eq!(cache.len(), 1, "the duplicate did not disturb it");
        // The last piece completes it as it would have without the duplicate.
        assert_eq!(
            cache.accept(key, piece(b"ijkl", 8, false), 0),
            Outcome::Complete(Vec::from(&b"abcdefghijkl"[..]))
        );
    }

    /// The simple case, in the order the network usually delivers: first
    /// piece, middle pieces, last piece.
    #[test]
    fn a_last_piece_completes_the_payload() {
        let mut cache = Cache::new();
        let key = key(2);
        assert_eq!(
            cache.accept(key, piece(b"abcdefgh", 0, true), 0),
            Outcome::Collected
        );
        assert_eq!(
            cache.accept(key, piece(b"ijklmnop", 8, true), 0),
            Outcome::Collected
        );
        assert_eq!(cache.len(), 1, "still holding it");
        let outcome = cache.accept(key, piece(b"qrst", 16, false), 0);
        assert_eq!(
            outcome,
            Outcome::Complete(Vec::from(&b"abcdefghijklmnopqrst"[..]))
        );
        assert!(cache.is_empty(), "a completed datagram is not kept");
    }

    /// The last piece may arrive first: the total is fixed then, and the
    /// earlier pieces fill in behind it.
    #[test]
    fn the_last_piece_may_arrive_first() {
        let mut cache = Cache::new();
        let key = key(3);
        assert_eq!(
            cache.accept(key, piece(b"ijkl", 8, false), 0),
            Outcome::Collected
        );
        assert_eq!(
            cache.accept(key, piece(b"abcdefgh", 0, true), 0),
            Outcome::Complete(Vec::from(&b"abcdefghijkl"[..]))
        );
    }

    /// A retransmitted piece is legal and changes nothing; a piece that
    /// covers *some* already-covered bytes is the overlap [RFC 5722] refuses,
    /// and the whole datagram goes with it.
    ///
    /// [RFC 5722]: https://www.rfc-editor.org/rfc/rfc5722
    #[test]
    fn an_overlap_is_refused() {
        let mut cache = Cache::new();
        let key = key(4);
        cache.accept(key, piece(b"abcdefgh", 0, true), 0);
        // A piece that starts inside the covered range and runs past it: the
        // bytes it covers twice are the attack RFC 5722 names.
        assert_eq!(
            cache.accept(key, piece(b"xyz", 4, true), 0),
            Outcome::Refused(Refusal::Overlap)
        );
        assert!(cache.is_empty(), "and the datagram went with it");
    }

    /// A piece whose end reaches past the payload budget is refused before
    /// anything is held, because it is a peer choosing a number.
    #[test]
    fn a_piece_past_the_budget_is_refused() {
        let mut cache = Cache::new();
        let key = key(5);
        let huge = alloc::vec![0_u8; 16];
        // An offset whose end is past the ceiling: the data itself is small.
        let outcome = cache.accept(
            key,
            Piece {
                data: &huge,
                offset: MAX_PAYLOAD - 8,
                more: true,
            },
            0,
        );
        assert_eq!(outcome, Outcome::Refused(Refusal::TooLarge));
        assert!(cache.is_empty());
    }

    /// The cache has a bound, and a seventeenth datagram is refused rather
    /// than evicting one another peer is mid-send on.
    #[test]
    fn a_full_cache_refuses_a_new_datagram() {
        let mut cache = Cache::new();
        for index in 0..MAX_ENTRIES {
            assert_eq!(
                cache.accept(key(index as u32), piece(b"abcdefgh", 0, true), 0),
                Outcome::Collected
            );
        }
        assert_eq!(cache.len(), MAX_ENTRIES);
        assert_eq!(
            cache.accept(key(999), piece(b"abcdefgh", 0, false), 0),
            Outcome::Refused(Refusal::CacheFull)
        );
        assert_eq!(cache.len(), MAX_ENTRIES, "nothing was evicted for it");
    }

    /// An entry that waits too long is dropped, and a piece arriving after
    /// that starts a new datagram rather than completing a partial one.
    #[test]
    fn an_entry_that_waits_too_long_expires() {
        let mut cache = Cache::new();
        let key = key(6);
        cache.accept(key, piece(b"abcdefgh", 0, true), 0);
        assert!(cache.holds(&key));

        cache.expire(TIMEOUT_TICKS);
        assert!(!cache.holds(&key), "the clock took it");
        assert!(cache.is_empty());

        // The late piece opens a new entry, and the datagram it belonged to
        // is gone — which is the RFC's "silently discarded".
        assert_eq!(
            cache.accept(key, piece(b"ijkl", 8, false), TIMEOUT_TICKS),
            Outcome::Collected
        );
        assert!(cache.holds(&key));
    }

    /// Two families' datagrams are two keys even when every number in them
    /// agrees, which is what stops a shared identification from mixing them.
    #[test]
    fn the_family_is_part_of_the_key() {
        let mut cache = Cache::new();
        let four = Key {
            family: 4,
            ..key(7)
        };
        let six = Key {
            family: 6,
            ..key(7)
        };
        assert_ne!(four, six);
        cache.accept(four, piece(b"abcdefgh", 0, true), 0);
        cache.accept(six, piece(b"ijklmnop", 0, true), 0);
        assert_eq!(cache.len(), 2, "two datagrams, not one confused one");
    }

    /// The offset is the wire's, so a datagram whose first piece starts at
    /// zero and whose pieces are contiguous completes only when every byte
    /// between them is covered.
    #[test]
    fn a_gap_keeps_the_datagram_incomplete() {
        let mut cache = Cache::new();
        let key = key(8);
        cache.accept(key, piece(b"abcdefgh", 0, true), 0);
        // The middle is missing; the last piece fixes a total of 20.
        assert_eq!(
            cache.accept(key, piece(b"qrst", 16, false), 0),
            Outcome::Collected
        );
        assert_eq!(cache.len(), 1, "a hole is not a completion");
        // The missing middle arrives.
        let outcome = cache.accept(key, piece(b"ijklmnop", 8, true), 0);
        assert_eq!(
            outcome,
            Outcome::Complete(Vec::from(&b"abcdefghijklmnopqrst"[..]))
        );
    }
}
