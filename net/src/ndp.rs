//! net/src/ndp.rs
//!
//! The neighbour cache and the addresses a host configures for itself.
//!
//! ## Why IPv6 needs a cache and IPv4's ARP table is the same thing
//!
//! IPv6 has no broadcast, so it has no ARP request that everyone hears.  A
//! neighbour solicitation goes to one solicited-node group and the answer is
//! a neighbour advertisement; what a stack remembers between questions is a
//! **cache**, and it is the same idea as ARP's table with one difference that
//! matters: an entry has a **state**, because "I asked and heard nothing" and
//! "this node answered" are two facts, and a sender waiting on the second
//! must not be handed the address from the first.
//!
//! ## The states, and what each means to a sender
//!
//! - **Incomplete**, a solicitation went out and no advertisement came back. A
//!   sender asking for this address must wait or drop, never send: the MAC is
//!   unknown and guessing one is how a packet goes nowhere.
//! - **Reachable**, the node answered, and the answer is fresh.  A sender may
//!   use the MAC.
//! - **Stale**, the entry is old.  A sender may still use the MAC, and the
//!   traffic itself is what refreshes it; a stale entry that answers nothing is
//!   evicted rather than kept.
//!
//! ## Address configuration
//!
//! Two ways, and this module does both because a link-local address needs
//! neither a router nor a server:
//!
//! - **Link-local**, from the MAC by EUI-64.  Every IPv6 interface has one
//!   before it has said anything to anyone, and it is what a neighbour
//!   solicitation can be sent *from* while the interface waits for a router.
//! - **Stateless from a router advertisement's prefix** (`autonomous`), by
//!   appending the same interface identifier to the prefix the router named.
//!   That is SLAAC, and it is what makes an address the whole link can reach
//!   rather than only the nodes beside it.
//!
//! ## Duplicate address detection
//!
//! An address is not usable until the node has asked whether anyone else has
//! it: a solicitation from `::` about the candidate, and an advertisement
//! answering it means the address is taken and must be given up.  Silence for
//! [`DAD_QUIET_TICKS`] is the acceptance, and [`Candidate::settle`] is that
//! transition.  It is a state machine rather than an answer because silence
//! has no message: it is a deadline.

use alloc::vec::Vec;

use crate::ipv6::Addr;

/// How long an entry stays reachable before it is stale, in ticks.
///
/// RFC 4861's default is thirty seconds; a boot's whole life is shorter than
/// that, so what this number really says is "a reachable entry does not go
/// stale within one boot", the states are still implemented because the
/// correctness of handing a sender a MAC depends on them, not on the timer
/// being reached here.
pub const REACHABLE_TICKS: u64 = 30_000;

/// How long a duplicate-address check waits for an answer before accepting.
///
/// One second is RFC 4861's `RETRANS_TIMER`, and it is a deadline rather than
/// a count because silence is the answer.
pub const DAD_QUIET_TICKS: u64 = 1_000;

/// How long an incomplete entry is kept before it is dropped.
///
/// A node that never answers must not leave an entry that makes every later
/// send to it wait: the entry expires and the next send asks again.
pub const INCOMPLETE_TICKS: u64 = 3_000;

/// How many entries the cache holds.
///
/// A link with more neighbours than this has more neighbours than a boot
/// talks to, and an unbounded cache is a table a hostile link fills.
pub const CACHE_LIMIT: usize = 32;

/// What the cache knows about one neighbour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Asked, and nothing answered yet.  A sender must not use this.
    Incomplete,
    /// Answered recently; the address is good.
    Reachable,
    /// Answered, but the entry has aged.  The address is still good, a
    /// sender may use it, and traffic is what refreshes it.
    Stale,
}

/// One entry: an address, the MAC it resolved to, and how sure the cache is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Entry {
    pub address: Addr,
    /// The MAC, meaningless while [`State::Incomplete`].
    pub link_layer: [u8; 6],
    pub state: State,
    /// When the entry last changed state, for the timers above.
    pub since: u64,
}

/// The neighbour cache.
///
/// A `Vec` rather than a map: a link this cache serves holds tens of
/// neighbours, and a linear walk over thirty-two six-byte keys is faster than
/// hashing one, the same argument the tree's ARP cache makes, and the reason
/// both are bounded.
#[derive(Debug, Default)]
pub struct Cache {
    entries: Vec<Entry>,
}

impl Cache {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// How many entries the cache holds.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// What the cache knows about `address`, or `None` when it knows nothing.
    pub fn state(&self, address: Addr) -> Option<State> {
        self.entries
            .iter()
            .find(|entry| entry.address == address)
            .map(|entry| entry.state)
    }

    /// The MAC for `address`, if the cache has one a sender may use.
    ///
    /// `Incomplete` answers `None`: there is no MAC yet, and the caller's job
    /// is to wait for the advertisement it already asked for.
    pub fn lookup(&self, address: Addr) -> Option<[u8; 6]> {
        self.entries
            .iter()
            .find(|entry| entry.address == address)
            .filter(|entry| entry.state != State::Incomplete)
            .map(|entry| entry.link_layer)
    }

    /// Record that a solicitation went out for `address` and nothing has
    /// answered.
    ///
    /// A second call for the same address refreshes the deadline rather than
    /// adding a second entry: the question is identical, and two entries for
    /// one address would be two answers to one wait.
    pub fn ask(&mut self, address: Addr, now: u64) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.address == address)
        {
            if entry.state == State::Incomplete {
                entry.since = now;
                return;
            }
            // An entry that was reachable and is being questioned again keeps
            // its MAC: the question may be a probe, and dropping a working
            // address on asking would break a link that was fine.
            return;
        }
        if self.entries.len() >= CACHE_LIMIT {
            self.evict_oldest();
        }
        self.entries.push(Entry {
            address,
            link_layer: [0; 6],
            state: State::Incomplete,
            since: now,
        });
    }

    /// Record a neighbour advertisement's answer.
    ///
    /// An advertisement is authoritative: it names the MAC, and the entry
    /// becomes reachable whether or not a solicitation went out, which is
    /// what makes an unsolicited advertisement (a node that moved) reach the
    /// cache.
    pub fn learn(&mut self, address: Addr, link_layer: [u8; 6], now: u64) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.address == address)
        {
            entry.link_layer = link_layer;
            entry.state = State::Reachable;
            entry.since = now;
            return;
        }
        if self.entries.len() >= CACHE_LIMIT {
            self.evict_oldest();
        }
        self.entries.push(Entry {
            address,
            link_layer,
            state: State::Reachable,
            since: now,
        });
    }

    /// Note that a stale entry's address answered something, which makes it
    /// reachable again without a new question.
    pub fn refresh(&mut self, address: Addr, now: u64) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.address == address)
            && entry.state == State::Stale
        {
            entry.state = State::Reachable;
            entry.since = now;
        }
    }

    /// Advance the cache to `now`: reachable entries past
    /// [`REACHABLE_TICKS`] become stale, and incomplete ones past
    /// [`INCOMPLETE_TICKS`] are dropped.
    ///
    /// Both edges are the timers that make the states mean something: a
    /// reachable entry that never goes stale is an entry that never asks
    /// again, and an incomplete one that never expires is a send that waits
    /// forever on a node that is not there.
    pub fn advance(&mut self, now: u64) {
        self.entries.retain(|entry| {
            !(entry.state == State::Incomplete
                && now.saturating_sub(entry.since) > INCOMPLETE_TICKS)
        });
        for entry in &mut self.entries {
            if entry.state == State::Reachable && now.saturating_sub(entry.since) > REACHABLE_TICKS
            {
                entry.state = State::Stale;
                entry.since = now;
            }
        }
    }

    /// Drop the entry that has been in its state longest.
    fn evict_oldest(&mut self) {
        if let Some(oldest) = self
            .entries
            .iter()
            .enumerate()
            .min_by_key(|(_, entry)| entry.since)
            .map(|(index, _)| index)
        {
            self.entries.remove(oldest);
        }
    }
}

/// A candidate address, and how far its duplicate-address check has got.
///
/// An address is not usable until the check settles, which is why this is a
/// type and not a bool: the difference between "not yet" and "no" is the
/// difference between waiting and giving up, and neither is the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Candidate {
    /// The solicitation went out and the deadline has not passed.
    Checking { since: u64 },
    /// Silence for the whole interval: the address is this node's.
    Accepted,
    /// An advertisement answered: another node holds it.
    Taken,
}

impl Candidate {
    /// The candidate a check starts with.
    pub fn new(now: u64) -> Self {
        Self::Checking { since: now }
    }

    /// Whether the address may be used.
    pub fn is_usable(self) -> bool {
        matches!(self, Self::Accepted)
    }

    /// Advance the check to `now`: a deadline that has passed is acceptance.
    ///
    /// A check that is already settled does not move, because the two
    /// settled states are the answers and a deadline cannot change one.
    pub fn settle(&mut self, now: u64) {
        if let Self::Checking { since } = *self
            && now.saturating_sub(since) >= DAD_QUIET_TICKS
        {
            *self = Self::Accepted;
        }
    }

    /// Record that an advertisement answered for the candidate's address.
    pub fn contest(&mut self) {
        *self = Self::Taken;
    }
}

/// The interface identifier a MAC address makes: the modified EUI-64.
///
/// Exposed because address configuration needs the identifier alone, a
/// link-local address is `fe80::` plus it, and a stateless address is a
/// router's prefix plus it, and computing it twice is how the two spellings
/// of one interface drift apart.
pub fn interface_identifier(mac: [u8; 6]) -> [u8; 8] {
    [
        mac[0] ^ 0x02,
        mac[1],
        mac[2],
        0xFF,
        0xFE,
        mac[3],
        mac[4],
        mac[5],
    ]
}

/// The address a router's prefix and this node's identifier make.
///
/// `prefix_len` is the advertisement's prefix length in bits, and this driver
/// supports the one length a link's addresses are configured with: 64.  A
/// prefix of another length would need the identifier truncated or shifted,
/// and a stack that guessed is a stack with an address nobody else computes
/// the same way, so an unsupported length answers `None` rather than an
/// address that is almost right.
pub fn address_from_prefix(prefix: Addr, prefix_len: u8, mac: [u8; 6]) -> Option<Addr> {
    if prefix_len != 64 {
        return None;
    }
    let identifier = interface_identifier(mac);
    let mut address = prefix;
    address[8..16].copy_from_slice(&identifier);
    Some(address)
}

/// Whether two addresses are on one link, given a prefix length in bits.
///
/// The comparison is the prefix's, byte by byte and then bit by bit for the
/// length that is not a whole number of bytes, which is what makes a `/64`
/// and a `/120` both answer correctly rather than only the lengths that are
/// multiples of eight.
pub fn same_prefix(left: Addr, right: Addr, prefix_len: u8) -> bool {
    let whole = (prefix_len / 8) as usize;
    if left[..whole] != right[..whole] {
        return false;
    }
    let bits = prefix_len % 8;
    if bits == 0 {
        return true;
    }
    // The mask for a partial byte: the top `bits` bits.
    let mask = 0xFF_u8 << (8 - bits);
    (left[whole] & mask) == (right[whole] & mask)
}

#[cfg(test)]
mod tests {
    //! The tests for this module.
    //!
    //! The neighbour cache's three states and the timers that move between
    //! them, the duplicate-address check that makes an address usable, and
    //! the two address computations a host does without asking anyone.

    use super::CACHE_LIMIT;
    use super::Cache;
    use super::Candidate;
    use super::DAD_QUIET_TICKS;
    use super::INCOMPLETE_TICKS;
    use super::REACHABLE_TICKS;
    use super::State;
    use super::address_from_prefix;
    use super::interface_identifier;
    use super::same_prefix;
    use crate::ipv6;
    use crate::ipv6::Addr;

    fn address(last: u8) -> Addr {
        let mut value = [0_u8; 16];
        value[0] = 0xFE;
        value[1] = 0x80;
        value[15] = last;
        value
    }

    /// A question and no answer leaves an entry a sender must not use.
    #[test]
    fn an_asked_address_is_incomplete_and_unusable() {
        let mut cache = Cache::new();
        let target = address(2);
        cache.ask(target, 0);

        assert_eq!(cache.state(target), Some(State::Incomplete));
        assert_eq!(cache.lookup(target), None, "no MAC yet");
    }

    /// An advertisement answers with the MAC, and the entry becomes
    /// reachable.
    #[test]
    fn an_advertisement_makes_an_entry_reachable() {
        let mut cache = Cache::new();
        let target = address(2);
        let mac = [0x52, 0x54, 0, 0x12, 0x34, 0x57];
        cache.ask(target, 0);
        cache.learn(target, mac, 10);

        assert_eq!(cache.state(target), Some(State::Reachable));
        assert_eq!(cache.lookup(target), Some(mac));
    }

    /// An unsolicited advertisement, a node that moved, reaches the cache
    /// without a question, which is what makes a link recover from a change.
    #[test]
    fn an_unsolicited_advertisement_is_learned() {
        let mut cache = Cache::new();
        let target = address(2);
        let mac = [1, 2, 3, 4, 5, 6];
        cache.learn(target, mac, 0);
        assert_eq!(cache.lookup(target), Some(mac));
    }

    /// A reachable entry past its timer goes stale, and a stale one is still
    /// usable, the address is good, the freshness is not.
    #[test]
    fn an_aged_entry_goes_stale_and_stays_usable() {
        let mut cache = Cache::new();
        let target = address(2);
        let mac = [1, 2, 3, 4, 5, 6];
        cache.learn(target, mac, 0);

        cache.advance(REACHABLE_TICKS + 1);
        assert_eq!(cache.state(target), Some(State::Stale));
        assert_eq!(cache.lookup(target), Some(mac), "a stale MAC is a MAC");

        // Traffic refreshes it without a new question.
        cache.refresh(target, REACHABLE_TICKS + 2);
        assert_eq!(cache.state(target), Some(State::Reachable));
    }

    /// An incomplete entry past its timer is dropped, so a node that never
    /// answered does not make every later send wait.
    #[test]
    fn an_unanswered_question_expires() {
        let mut cache = Cache::new();
        let target = address(2);
        cache.ask(target, 0);
        cache.advance(INCOMPLETE_TICKS + 1);
        assert_eq!(cache.state(target), None, "the entry is gone");
        assert!(cache.is_empty());
    }

    /// Asking twice for one address leaves one entry, not two.
    #[test]
    fn asking_twice_leaves_one_entry() {
        let mut cache = Cache::new();
        let target = address(2);
        cache.ask(target, 0);
        cache.ask(target, 100);
        assert_eq!(cache.len(), 1);
    }

    /// Asking about an address that is already reachable does not throw the
    /// working MAC away.
    #[test]
    fn asking_about_a_working_address_keeps_its_mac() {
        let mut cache = Cache::new();
        let target = address(2);
        let mac = [1, 2, 3, 4, 5, 6];
        cache.learn(target, mac, 0);
        cache.ask(target, 10);
        assert_eq!(cache.state(target), Some(State::Reachable));
        assert_eq!(cache.lookup(target), Some(mac));
    }

    /// The cache is bounded, so a link that floods it cannot make it grow
    /// without end.
    #[test]
    fn the_cache_is_bounded() {
        let mut cache = Cache::new();
        for index in 0..CACHE_LIMIT + 10 {
            let mut target = [0_u8; 16];
            target[0] = 0xFE;
            target[15] = index as u8;
            cache.learn(target, [1, 2, 3, 4, 5, index as u8], index as u64);
        }
        assert_eq!(cache.len(), CACHE_LIMIT);
    }

    /// A duplicate-address check accepts on silence and refuses on an answer.
    #[test]
    fn the_duplicate_check_accepts_silence_and_refuses_a_contest() {
        let mut candidate = Candidate::new(0);
        assert!(!candidate.is_usable(), "not yet");
        candidate.settle(DAD_QUIET_TICKS - 1);
        assert!(!candidate.is_usable(), "the deadline has not passed");
        candidate.settle(DAD_QUIET_TICKS);
        assert!(candidate.is_usable(), "silence is acceptance");

        let mut contested = Candidate::new(0);
        contested.contest();
        contested.settle(DAD_QUIET_TICKS + 5);
        assert_eq!(contested, Candidate::Taken);
        assert!(!contested.is_usable(), "another node holds it");

        // A settled state does not move again.
        let mut accepted = Candidate::new(0);
        accepted.settle(DAD_QUIET_TICKS);
        accepted.settle(DAD_QUIET_TICKS * 10);
        assert_eq!(accepted, Candidate::Accepted);
    }

    /// The interface identifier is the modified EUI-64: the MAC's bytes with
    /// `FF:FE` in the middle and the universal/local bit inverted.
    #[test]
    fn the_interface_identifier_is_the_modified_eui_64() {
        assert_eq!(
            interface_identifier([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]),
            [0x50, 0x54, 0x00, 0xFF, 0xFE, 0x12, 0x34, 0x56]
        );
        // The link-local address is fe80:: plus the identifier, which is the
        // same computation ipv6.rs does for its own address.
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        assert_eq!(
            &ipv6::link_local_from_mac(mac)[8..],
            &interface_identifier(mac),
            "one interface identifier, two spellings"
        );
    }

    /// A `/64` prefix and this node's identifier make the address SLAAC
    /// configures, and a prefix length this driver does not support answers
    /// nothing rather than an address that is almost right.
    #[test]
    fn a_prefix_and_the_identifier_make_an_address() {
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let mut prefix = [0_u8; 16];
        prefix[0] = 0x20;
        prefix[1] = 0x01;
        prefix[2] = 0x0D;
        prefix[3] = 0xB8;

        let address = address_from_prefix(prefix, 64, mac).expect("a /64");
        assert_eq!(&address[..8], &prefix[..8]);
        assert_eq!(&address[8..], &interface_identifier(mac));

        assert_eq!(address_from_prefix(prefix, 48, mac), None);
        assert_eq!(address_from_prefix(prefix, 120, mac), None);
    }

    /// Two addresses are on one link when their prefixes agree, byte by byte
    /// and then bit by bit, so a length that is not a multiple of eight
    /// still answers correctly.
    #[test]
    fn the_prefix_comparison_handles_partial_bytes() {
        let mut left = [0_u8; 16];
        left[0] = 0x20;
        left[1] = 0x01;
        left[2] = 0x0D;
        left[3] = 0xB8;
        let mut right = left;
        right[15] = 1;
        assert!(same_prefix(left, right, 64));

        // Byte 4 is where the partial byte starts.  left's is 0x10
        // 0001_0000, so its top two bits are 00 and its top bit is 0.
        left[4] = 0x10;

        // A /34 compares two bits of byte 4: 0011_0000 shares them.
        let mut same_two = left;
        same_two[4] = 0x30;
        assert!(same_prefix(left, same_two, 34));

        // 0100_0000 differs in the second of those two bits.
        let mut differs_second = left;
        differs_second[4] = 0x40;
        assert!(!same_prefix(left, differs_second, 34));

        // At /33 only the first bit counts, so 0100_0000 is on the same
        // prefix after all, and 1000_0000 is not.
        assert!(same_prefix(left, differs_second, 33));
        let mut differs_first = left;
        differs_first[4] = 0x80;
        assert!(!same_prefix(left, differs_first, 33));
    }
}
