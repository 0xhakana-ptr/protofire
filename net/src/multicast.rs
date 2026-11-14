//! net/src/multicast.rs
//!
//! Multicast routing's two tables: the virtual interfaces a forwarding decision
//! names, and the cache that maps one arriving `(source, group)` to the
//! interfaces it leaves by.
//!
//! ## Why virtual interfaces at all
//!
//! A router's forwarding decision is "this packet arrived on an interface and
//! leaves by those ones", and the interfaces are the unit of that decision.  On
//! a machine with one card the physical interface is one of them, but it is not
//! a useful unit on its own: a repeater on one link has to distinguish the
//! interface a packet arrived on from the interface it leaves by even when both
//! are the same card, or its cache cannot express "do not send it back out the
//! way it came".
//!
//! So the table is of **virtual** interfaces, and each one names what it does
//! with a frame: [`Vif::Local`] is this host's own delivery, [`Vif::Link`] is a
//! frame sent out of the card.  The distinction is the one Linux's `MRT_*`
//! ioctl surface makes with its VIF flags, and it is what makes the local
//! interface VIF 0 a thing a cache entry can name instead of a special case at
//! every lookup.
//!
//! ## What is deliberately not here
//!
//! **No membership protocol.**  IGMP and MLD are how a host learns which groups
//! the link wants, and they are their own state machines with their own
//! timers: a cache entry here is installed by a program, and this module
//! neither asks a link for a group nor ages an entry out on a membership
//! report.  The calls that install an entry are the ABI's `Mrt*` four, which is
//! a manager's interface and not a protocol's.
//!
//! **No reverse-path check.**  A router that forwards multicast asks whether
//! the packet arrived on the interface the route to its **source** names, and
//! this module does not: the check needs a unicast routing table with more than
//! one interface, which is the metric [`crate::route`] already records as
//! absent.  What is here is the cache's own rule, that a packet for an entry
//! arrives on that entry's interface, and the difference is stated rather than
//! papered over.
//!
//! **No rate limit.**  A VIF's rate is a field the ABI carries and this module
//! stores.  It is not enforced, because enforcing it needs a clock the decision
//! does not have and a token bucket whose drop would be silent; a field that a
//! caller can read back and that changes nothing is the exact shape the packet
//! filter's `enabled` flag taught this tree to refuse.  The field is carried
//! because the ABI's record has it and a program reading its own VIF back
//! should learn what it set, and [`Interface::rate_limit`]'s doc says outright
//! that nothing reads it.

use alloc::vec::Vec;

use abi::Error;
use abi::Result;

/// The interface a host's own delivery is, which every machine has.
///
/// Zero because the ABI's records name it that way: a forwarding-cache entry's
/// `in_vif` is a word a program writes, and a value that meant "local" only by
/// convention would be a program's guess.
pub const VIF_LOCAL: u32 = 0;

/// How many virtual interfaces a machine may have.
///
/// The same order as the cache's bound and the previous tree's, and bounded
/// because the entries arrive from a program: a caller that added VIFs in a
/// loop would otherwise make the kernel hold whatever it sent.
pub const VIF_LIMIT: usize = 64;

/// How many forwarding-cache entries a machine may hold.
pub const CACHE_LIMIT: usize = 256;

/// How many outgoing interfaces one cache entry may name.
///
/// The ABI's record carries four, which is the bound a program's own record
/// expresses: an entry that leaves by more than four interfaces is an entry the
/// record cannot describe, and refusing it is better than truncating it into
/// one that forwards to the wrong set.
pub const OUT_LIMIT: usize = 4;

/// What a virtual interface does with a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Vif {
    /// This host's own delivery: a frame for the interface is handed to the
    /// transports rather than sent anywhere.
    Local,
    /// The link: a frame for the interface is sent out of the card.
    ///
    /// One card, so one `Link` interface is all this machine can have, and the
    /// table refuses a second: a second one would be a second name for the same
    /// card with no difference in what it does, and a cache entry naming it
    /// would forward exactly as the first does while looking like a second
    /// path.
    Link,
}

/// One virtual interface: what it does, and the thresholds a caller stated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interface {
    /// What this interface does with a frame.
    pub vif: Vif,
    /// The smallest time-to-live a packet needs to leave by this interface.
    ///
    /// Read, and the one threshold this module enforces: a packet whose
    /// remaining hops are below it is not forwarded here.  That is the rule
    /// that keeps a forwarded copy from crossing a link it could not have
    /// reached, and it costs one comparison at the decision.
    pub threshold: u8,
    /// The rate a caller asked for, in packets per second, zero for none.
    ///
    /// **Stored and not enforced.**  A rate needs a clock and a bucket, and a
    /// drop from either is a drop the sender never learns of; the field is here
    /// because the ABI's record carries it and a reader should get back what it
    /// set.  A field that claimed to act would be worse than one that says it
    /// does not.
    pub rate_limit: u32,
}

/// The virtual interfaces, by index.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Interfaces {
    entries: Vec<(u32, Interface)>,
    /// The next index an automatically numbered interface is given.
    next: u32,
}

impl Interfaces {
    /// An empty table, which is a machine that forwards no multicast.
    ///
    /// The local interface is **not** installed here: it arrives with the
    /// caller's first `init`, which is what makes "is this machine routing
    /// multicast" a fact the table can answer.  A table that started with VIF 0
    /// would answer yes to a question no call had asked.
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
            next: VIF_LOCAL + 1,
        }
    }

    /// Install the local interface, answering whether it was already there.
    ///
    /// Idempotent, because `init` is: a program that enabled routing twice is a
    /// program whose second call should not be an error, and a table that
    /// refused would make a restart a failure.
    pub fn install_local(&mut self) -> bool {
        if self.entries.iter().any(|(index, _)| *index == VIF_LOCAL) {
            return false;
        }
        self.entries.push((
            VIF_LOCAL,
            Interface {
                vif: Vif::Local,
                threshold: 0,
                rate_limit: 0,
            },
        ));
        true
    }

    /// Add an interface from the words a caller stated, answering its index.
    ///
    /// `requested` is zero for "number it for me".  That reading is this
    /// module's decision, and it is stated because the ABI's own comment is
    /// ambiguous: `MRT_VIF_FLAG_LOCAL`'s record says a `vif_index` of zero is
    /// the local interface **or** a request for automatic numbering, and one
    /// value cannot be both.  Automatic numbering wins here, because the local
    /// interface is not a caller's to create: [`Interfaces::install_local`] is
    /// what installs it, `init` is what calls that, and a cache entry naming
    /// `VIF_LOCAL` before either ran is an entry naming an interface the table
    /// says does not exist.
    ///
    /// A requested index already in the table is `AlreadyExists` rather than a
    /// replacement: a second statement about one interface is a caller that
    /// meant to change it, and a table that silently replaced would make an add
    /// and a change the same call with different intents.
    pub fn add(
        &mut self,
        requested: u32,
        vif: Vif,
        threshold: u32,
        rate_limit: u32,
    ) -> Result<u32> {
        if self.entries.len() >= VIF_LIMIT {
            return Err(Error::Busy);
        }
        let index = if requested == 0 { self.next } else { requested };
        // Number zero is the local interface's, so a request for it is refused
        // before anything else is asked about the entry: a caller naming zero
        // is naming the host's own delivery, and which kind of interface it
        // asked to put there does not change that the number is taken.
        if index == VIF_LOCAL {
            return Err(Error::InvalidArgument);
        }
        // A second link interface is a second name for one card, which is a
        // distinction with no behaviour behind it.
        if vif == Vif::Link && self.entries.iter().any(|(_, entry)| entry.vif == Vif::Link) {
            return Err(Error::AlreadyExists);
        }
        if self.entries.iter().any(|(held, _)| *held == index) {
            return Err(Error::AlreadyExists);
        }
        if threshold > u8::MAX as u32 {
            return Err(Error::InvalidArgument);
        }
        self.entries.push((
            index,
            Interface {
                vif,
                threshold: threshold as u8,
                rate_limit,
            },
        ));
        if index >= self.next {
            self.next = index + 1;
        }
        Ok(index)
    }

    /// Remove an interface, answering whether one was there.
    ///
    /// The local interface cannot be removed: it is not a forwarder a caller
    /// installed, and a table without it would be one whose `VIF_LOCAL` names
    /// nothing while every cache entry may still name it.
    pub fn remove(&mut self, index: u32) -> Result<()> {
        if index == VIF_LOCAL {
            return Err(Error::InvalidArgument);
        }
        let before = self.entries.len();
        self.entries.retain(|(held, _)| *held != index);
        if self.entries.len() == before {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    /// One interface, if it is there.
    pub fn get(&self, index: u32) -> Option<&Interface> {
        self.entries
            .iter()
            .find(|(held, _)| *held == index)
            .map(|(_, entry)| entry)
    }

    /// Every interface with its index, for a boot's own report.
    pub fn entries(&self) -> &[(u32, Interface)] {
        &self.entries
    }

    /// How many interfaces are held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether none is.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Whether a link interface is installed, which is what makes forwarding
    /// possible at all.
    pub fn has_link(&self) -> bool {
        self.entries.iter().any(|(_, entry)| entry.vif == Vif::Link)
    }
}

/// One forwarding-cache entry: one `(source, group)` and where it goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The source the entry is for, which is also the check that keeps a
    /// stranger's traffic out of a group's distribution: a packet whose source
    /// is not the entry's is not the stream the entry describes.
    pub source: [u8; 4],
    /// The group it is going to.
    pub group: [u8; 4],
    /// The interface it must arrive on, or [`VIF_LOCAL`] for this host's own
    /// traffic.
    pub incoming: u32,
    /// Where it goes: up to [`OUT_LIMIT`] interfaces and the hop count each
    /// needs.
    outgoing: Vec<(u32, u8)>,
    /// Packets this entry forwarded.
    pub packets: u64,
    /// Bytes it forwarded.
    pub bytes: u64,
}

impl Entry {
    /// The interfaces this entry forwards to.
    pub fn outgoing(&self) -> &[(u32, u8)] {
        &self.outgoing
    }

    /// Whether a packet arriving on `interface` is the one this entry
    /// describes.
    ///
    /// The source is part of the question, not only the group: two senders to
    /// one group are two streams, and an entry that matched on the group alone
    /// would forward both under one sender's name.
    pub fn accepts(&self, source: [u8; 4], group: [u8; 4], interface: u32) -> bool {
        self.source == source && self.group == group && self.incoming == interface
    }
}

/// The forwarding cache.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cache {
    entries: Vec<Entry>,
}

impl Cache {
    /// An empty cache: nothing is forwarded.
    pub const fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Install an entry, replacing one for the same `(source, group)`.
    ///
    /// Replacing rather than refusing, unlike an interface: a forwarding entry
    /// is a route, and a route's second statement is a manager changing its
    /// mind about where a stream goes.  Answers whether it replaced one.
    ///
    /// Refused: an outgoing set larger than [`OUT_LIMIT`], a set that names no
    /// interface, and a set that repeats one, which would forward two copies
    /// down one link.
    pub fn add(
        &mut self,
        source: [u8; 4],
        group: [u8; 4],
        incoming: u32,
        outgoing: &[(u32, u32)],
    ) -> Result<bool> {
        if outgoing.is_empty() || outgoing.len() > OUT_LIMIT {
            return Err(Error::InvalidArgument);
        }
        let mut set = Vec::with_capacity(outgoing.len());
        for (index, (interface, threshold)) in outgoing.iter().enumerate() {
            if *threshold > u8::MAX as u32 {
                return Err(Error::InvalidArgument);
            }
            // A repeated interface is two copies of one packet down one link,
            // which the second copy's sender would read as two packets.
            if outgoing[..index]
                .iter()
                .any(|(earlier, _)| earlier == interface)
            {
                return Err(Error::InvalidArgument);
            }
            set.push((*interface, *threshold as u8));
        }
        let replaced = if let Some(existing) = self
            .entries
            .iter_mut()
            .find(|entry| entry.source == source && entry.group == group)
        {
            existing.incoming = incoming;
            existing.outgoing = set;
            true
        } else {
            if self.entries.len() >= CACHE_LIMIT {
                return Err(Error::Busy);
            }
            self.entries.push(Entry {
                source,
                group,
                incoming,
                outgoing: set,
                packets: 0,
                bytes: 0,
            });
            false
        };
        Ok(replaced)
    }

    /// Remove an entry, answering whether one was there.
    pub fn remove(&mut self, source: [u8; 4], group: [u8; 4]) -> bool {
        let before = self.entries.len();
        self.entries
            .retain(|entry| !(entry.source == source && entry.group == group));
        self.entries.len() != before
    }

    /// The entry a packet belongs to, if one does.
    ///
    /// Read-only, because the decision that follows is made by the caller with
    /// the interface table in hand: the cache says where a stream goes, and
    /// whether any of those interfaces exist and what each does is the other
    /// table's answer.
    pub fn entry(&self, source: [u8; 4], group: [u8; 4], incoming: u32) -> Option<&Entry> {
        self.entries
            .iter()
            .find(|entry| entry.accepts(source, group, incoming))
    }

    /// Count one forwarded packet against an entry.
    ///
    /// A count of the packets that **did** go, added after the decision rather
    /// than before it: an entry that counted what it considered would report
    /// traffic a full table or a TTL of one kept off the wire.
    pub fn note_forwarded(&mut self, source: [u8; 4], group: [u8; 4], bytes: usize) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.source == source && entry.group == group)
        {
            entry.packets = entry.packets.saturating_add(1);
            entry.bytes = entry.bytes.saturating_add(bytes as u64);
        }
    }

    /// Every entry, for a boot's own report.
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// How many entries are held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether none is.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Drop everything, which is what disabling routing does.
    ///
    /// The previous tree kept the cache across a disable and said so, quoting
    /// Linux.  That is not the rule here: an entry a manager installed while
    /// routing was on is an entry it wanted forwarding for, and a machine that
    /// stopped forwarding should not start again on the next `init` with a
    /// cache nobody re-checked.  The interfaces go the same way, so a later
    /// `init` installs the local interface and nothing else.
    pub fn clear(&mut self) {
        self.entries.clear();
    }
}

/// Where one packet goes: the interfaces that forward it, with their
/// thresholds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Forwarding {
    /// The interfaces this packet leaves by, with the hop count each needs.
    ///
    /// A copy whose threshold the packet does not meet has already been
    /// removed, so this is the set to send and not the set the entry named.
    pub outgoing: Vec<(u32, u8)>,
    /// The interfaces whose threshold the packet failed, and which therefore
    /// did **not** get a copy.
    ///
    /// Reported rather than silently dropped, because a sender whose packets
    /// reach one link and not another has no other way to learn that: the
    /// packet leaves, and only this machine knew it was supposed to go twice.
    pub limited: Vec<u32>,
}

/// The forwarding decision for one arriving packet.
///
/// The two tables decide together, and this is the one place they are read in
/// the same call: the cache says which interfaces a stream goes to, the
/// interface table says what each one does and what hop count it needs, and the
/// packet's own time-to-live decides whether it reaches each.  Split across two
/// callers, the two reads would be two chances to ask the wrong table first.
///
/// `None` is "not this machine's to forward": no entry names the stream, or the
/// stream's interfaces are all gone.  A packet whose remaining hops are zero is
/// **not** `None` and is not forwarded either: [`Forward]]` reports it as
/// limited, because "a loop took it" and "no entry did" are different silences
/// and a boot's line should tell them apart.
pub fn decide(
    cache: &Cache,
    interfaces: &Interfaces,
    source: [u8; 4],
    group: [u8; 4],
    incoming: u32,
    time_to_live: u8,
) -> Option<Forwarding> {
    let entry = cache.entry(source, group, incoming)?;
    let mut outgoing = Vec::new();
    let mut limited = Vec::new();
    for (index, threshold) in entry.outgoing() {
        let Some(interface) = interfaces.get(*index) else {
            // An interface the entry names and the table does not have is an
            // entry whose destination was removed after it was installed.  It
            // contributes nothing, and it is not a limit: a threshold is a hop
            // count and this is a missing interface.
            continue;
        };
        if time_to_live <= interface.threshold || time_to_live <= *threshold {
            limited.push(*index);
            continue;
        }
        outgoing.push((*index, *threshold));
    }
    if outgoing.is_empty() && limited.is_empty() {
        return None;
    }
    Some(Forwarding { outgoing, limited })
}

#[cfg(test)]
mod tests {
    use super::Cache;
    use super::Entry;
    use super::Interfaces;
    use super::OUT_LIMIT;
    use super::VIF_LOCAL;
    use super::Vif;
    use super::decide;
    use abi::Error;

    const SOURCE: [u8; 4] = [10, 0, 2, 2];
    const GROUP: [u8; 4] = [239, 1, 2, 3];

    /// A table with the local interface and one link.
    fn tables() -> (Interfaces, u32) {
        let mut interfaces = Interfaces::new();
        interfaces.install_local();
        let link = interfaces
            .add(0, Vif::Link, 1, 0)
            .expect("a link interface");
        (interfaces, link)
    }

    /// An empty cache forwards nothing, and an empty interface table has no
    /// local interface to name.
    ///
    /// The pair is the state a machine that never called `init` is in: a
    /// forwarding decision has to answer nothing rather than invent an
    /// interface, and `VIF_LOCAL` has to name nothing until the call that
    /// installs it ran.
    #[test]
    fn nothing_is_forwarded_until_something_is_installed() {
        let cache = Cache::new();
        let interfaces = Interfaces::new();
        assert!(interfaces.is_empty());
        assert!(
            interfaces.get(VIF_LOCAL).is_none(),
            "no local interface yet"
        );
        assert_eq!(
            decide(&cache, &interfaces, SOURCE, GROUP, VIF_LOCAL, 64),
            None
        );

        let (interfaces, _) = tables();
        assert_eq!(
            decide(&cache, &interfaces, SOURCE, GROUP, VIF_LOCAL, 64),
            None,
            "interfaces and no entry is still nothing"
        );
    }

    /// Installing the local interface is idempotent, and it is the only
    /// interface `init` gives a machine.
    #[test]
    fn the_local_interface_is_installed_once() {
        let mut interfaces = Interfaces::new();
        assert!(interfaces.install_local(), "the first install");
        assert!(!interfaces.install_local(), "the second changes nothing");
        assert_eq!(interfaces.len(), 1);
        assert_eq!(
            interfaces.get(VIF_LOCAL).map(|entry| entry.vif),
            Some(Vif::Local)
        );
        assert!(!interfaces.has_link(), "and nothing forwards yet");
    }

    /// Removing the local interface is refused: it is not a caller's to
    /// remove, and every cache entry may still name it.
    #[test]
    fn the_local_interface_cannot_be_removed() {
        let mut interfaces = Interfaces::new();
        interfaces.install_local();
        assert_eq!(interfaces.remove(VIF_LOCAL), Err(Error::InvalidArgument));
        assert_eq!(interfaces.remove(9), Err(Error::NotFound));
        assert_eq!(interfaces.len(), 1);
    }

    /// One link interface and no second: a second would be a second name for
    /// one card with no behaviour between them.
    #[test]
    fn a_second_link_interface_is_refused() {
        let (mut interfaces, _) = tables();
        // Zero is automatic numbering, not the local interface: the ABI's own
        // comment reads both ways and this module chose one.  So this is a
        // request for a second link, which is refused.
        assert_eq!(
            interfaces.add(0, Vif::Link, 1, 0),
            Err(Error::AlreadyExists)
        );
        // A requested index is honoured, and what is already there is refused.
        assert_eq!(
            interfaces.add(1, Vif::Local, 0, 0),
            Err(Error::AlreadyExists),
            "index one is the link"
        );
        // A local interface at a free index is not the same thing as
        // `VIF_LOCAL`, and is not what `init` makes; the table allows it
        // because a caller may install one, but `VIF_LOCAL` still names the
        // host's own delivery.
        assert!(interfaces.add(7, Vif::Local, 0, 0).is_ok());
    }

    /// A VIF's threshold and rate are stored as stated, and a threshold past
    /// eight bits is refused rather than truncated.
    #[test]
    fn an_interface_keeps_what_it_was_given() {
        let mut interfaces = Interfaces::new();
        let index = interfaces.add(0, Vif::Link, 200, 1000).expect("a link");
        let entry = interfaces.get(index).expect("the interface");
        assert_eq!(entry.threshold, 200);
        assert_eq!(entry.rate_limit, 1000);
        assert_eq!(
            interfaces.add(5, Vif::Local, 256, 0),
            Err(Error::InvalidArgument),
            "a threshold is a hop count and does not fit in nine bits"
        );
    }

    /// An entry forwards where it says, and the packet's own source and
    /// arriving interface are part of what it matches.
    ///
    /// The three refusals are the property: a packet for the group from
    /// another sender, a packet from the right sender for another group, and a
    /// packet from the right sender that arrived on another interface.  An
    /// entry that matched on the group alone would forward a stranger's stream
    /// as though it were the configured one.
    #[test]
    fn an_entry_matches_its_own_stream() {
        let (interfaces, link) = tables();
        let mut cache = Cache::new();
        assert!(
            !cache
                .add(SOURCE, GROUP, VIF_LOCAL, &[(link, 1)])
                .expect("an entry")
        );

        let forwarding =
            decide(&cache, &interfaces, SOURCE, GROUP, VIF_LOCAL, 64).expect("a forwarding");
        assert_eq!(forwarding.outgoing, alloc::vec![(link, 1)]);
        assert!(forwarding.limited.is_empty());

        assert_eq!(
            decide(&cache, &interfaces, [10, 0, 2, 9], GROUP, VIF_LOCAL, 64),
            None,
            "another sender"
        );
        assert_eq!(
            decide(&cache, &interfaces, SOURCE, [239, 1, 2, 4], VIF_LOCAL, 64),
            None,
            "another group"
        );
        assert_eq!(
            decide(&cache, &interfaces, SOURCE, GROUP, link, 64),
            None,
            "another interface"
        );
    }

    /// A packet whose remaining hops do not reach an interface's threshold is
    /// limited, not forwarded, and is reported as limited.
    ///
    /// Both thresholds are checked: the one the entry names for this outgoing
    /// interface and the one the interface itself states.  The higher of the
    /// two is what the packet must beat, which is why the test states them
    /// apart.
    #[test]
    fn a_packet_below_a_threshold_is_limited() {
        let mut interfaces = Interfaces::new();
        interfaces.install_local();
        let link = interfaces.add(0, Vif::Link, 8, 0).expect("a link");
        let mut cache = Cache::new();
        cache
            .add(SOURCE, GROUP, VIF_LOCAL, &[(link, 2)])
            .expect("an entry");

        // Above both thresholds: forwarded.
        let forwarding =
            decide(&cache, &interfaces, SOURCE, GROUP, VIF_LOCAL, 9).expect("a forwarding");
        assert_eq!(forwarding.outgoing, alloc::vec![(link, 2)]);
        assert!(forwarding.limited.is_empty());

        // At the interface's own threshold: limited, because `<=` is the
        // comparison a hop count makes.
        let forwarding =
            decide(&cache, &interfaces, SOURCE, GROUP, VIF_LOCAL, 8).expect("a forwarding");
        assert!(forwarding.outgoing.is_empty());
        assert_eq!(forwarding.limited, alloc::vec![link]);

        // At the entry's threshold, which is below the interface's: limited.
        let forwarding =
            decide(&cache, &interfaces, SOURCE, GROUP, VIF_LOCAL, 2).expect("a forwarding");
        assert_eq!(forwarding.limited, alloc::vec![link]);

        // Zero remaining hops: limited and never forwarded, which is the rule
        // that ends a routing loop.
        let forwarding =
            decide(&cache, &interfaces, SOURCE, GROUP, VIF_LOCAL, 0).expect("a forwarding");
        assert!(forwarding.outgoing.is_empty());
        assert_eq!(forwarding.limited, alloc::vec![link]);
    }

    /// An entry naming an interface the table no longer has contributes
    /// nothing, and is not a limit.
    ///
    /// The difference matters to a boot's line: a removed interface is a
    /// configuration that changed, and a threshold is a packet that could not
    /// cross.  An implementation that counted both as limited would report a
    /// loop where there was an edit.
    #[test]
    fn a_removed_interface_contributes_nothing() {
        let (mut interfaces, link) = tables();
        let mut cache = Cache::new();
        cache
            .add(SOURCE, GROUP, VIF_LOCAL, &[(link, 1)])
            .expect("an entry");
        interfaces.remove(link).expect("removed");

        assert_eq!(
            decide(&cache, &interfaces, SOURCE, GROUP, VIF_LOCAL, 64),
            None,
            "no interface to send by and none limited"
        );
    }

    /// A second entry for one `(source, group)` replaces the first, and says
    /// so.
    #[test]
    fn a_second_entry_for_one_stream_replaces_it() {
        let (interfaces, link) = tables();
        let mut cache = Cache::new();
        assert!(
            !cache
                .add(SOURCE, GROUP, VIF_LOCAL, &[(link, 1)])
                .expect("first")
        );
        assert!(
            cache
                .add(SOURCE, GROUP, VIF_LOCAL, &[(link, 9)])
                .expect("second")
        );
        assert_eq!(cache.len(), 1, "one entry, not two");
        let forwarding =
            decide(&cache, &interfaces, SOURCE, GROUP, VIF_LOCAL, 10).expect("a forwarding");
        assert_eq!(
            forwarding.outgoing,
            alloc::vec![(link, 9)],
            "the new threshold"
        );
    }

    /// An outgoing set that is empty, too large, or repeats an interface is
    /// refused, and nothing is installed.
    #[test]
    fn an_outgoing_set_that_cannot_be_sent_is_refused() {
        let (_, link) = tables();
        let mut cache = Cache::new();
        assert_eq!(
            cache.add(SOURCE, GROUP, VIF_LOCAL, &[]),
            Err(Error::InvalidArgument),
            "an entry that forwards nowhere"
        );
        assert_eq!(
            cache.add(SOURCE, GROUP, VIF_LOCAL, &[(link, 1); OUT_LIMIT + 1]),
            Err(Error::InvalidArgument),
            "more interfaces than the record describes"
        );
        assert_eq!(
            cache.add(SOURCE, GROUP, VIF_LOCAL, &[(link, 1), (link, 2)]),
            Err(Error::InvalidArgument),
            "two copies down one link"
        );
        assert!(cache.is_empty(), "and nothing was installed");
    }

    /// Only the packets that went are counted.
    ///
    /// A count added by the caller after the decision, so an entry reports the
    /// traffic it forwarded and not the traffic it considered: a boot's line
    /// that said "forwarded 3" while a threshold kept two of them off the wire
    /// would be a line about the configuration rather than about the wire.
    #[test]
    fn only_the_forwarded_packets_are_counted() {
        let mut cache = Cache::new();
        cache
            .add(SOURCE, GROUP, VIF_LOCAL, &[(1, 1)])
            .expect("an entry");
        let entry = cache.entry(SOURCE, GROUP, VIF_LOCAL).expect("the entry");
        assert_eq!((entry.packets, entry.bytes), (0, 0));

        cache.note_forwarded(SOURCE, GROUP, 100);
        cache.note_forwarded(SOURCE, GROUP, 50);
        let entry = cache.entry(SOURCE, GROUP, VIF_LOCAL).expect("the entry");
        assert_eq!((entry.packets, entry.bytes), (2, 150));

        // An entry that is not there absorbs the count silently, which is the
        // caller's race and not a panic: a stream removed between the decision
        // and the count is a stream that stopped.
        cache.note_forwarded([1, 1, 1, 1], GROUP, 100);
    }

    /// Removing an entry says whether one was there, and clearing drops all of
    /// them.
    #[test]
    fn an_entry_can_be_removed_and_the_cache_cleared() {
        let mut cache = Cache::new();
        cache
            .add(SOURCE, GROUP, VIF_LOCAL, &[(1, 1)])
            .expect("an entry");
        assert!(cache.remove(SOURCE, GROUP));
        assert!(
            !cache.remove(SOURCE, GROUP),
            "the second says nothing was there"
        );
        assert!(cache.is_empty());

        cache
            .add(SOURCE, GROUP, VIF_LOCAL, &[(1, 1)])
            .expect("an entry");
        cache.clear();
        assert!(cache.is_empty());
    }

    /// An entry exposes its own words, so a caller reading a cache reports what
    /// it installed.
    #[test]
    fn an_entry_reports_what_it_holds() {
        let mut cache = Cache::new();
        cache
            .add(SOURCE, GROUP, VIF_LOCAL, &[(3, 4), (5, 6)])
            .expect("an entry");
        let entry: &Entry = cache.entry(SOURCE, GROUP, VIF_LOCAL).expect("the entry");
        assert_eq!(entry.source, SOURCE);
        assert_eq!(entry.group, GROUP);
        assert_eq!(entry.incoming, VIF_LOCAL);
        assert_eq!(entry.outgoing(), [(3_u32, 4_u8), (5_u32, 6_u8)]);
    }
}
