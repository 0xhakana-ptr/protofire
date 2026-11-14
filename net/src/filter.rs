//! net/src/filter.rs
//!
//! The packet filter: an ordered list of rules, the first one a packet matches
//! deciding its fate, and a table of flows that a stateful rule keeps so the
//! answer a connection's return traffic gets is the answer its first packet
//! already got.
//!
//! ## Why a rule list and not a policy
//!
//! A filter is a **decision about one packet**, asked at the two points a
//! packet crosses this machine: the demux, before any transport reads the
//! bytes, and the send path, before the frame reaches the card.  The decision
//! is a walk down an ordered list, and the first rule that matches is the
//! answer.  That is not an implementation detail of this module, it is what
//! makes a rule set readable: a deny written above an allow means the deny
//! wins, and a program that reordered its rules would get a different filter.
//!
//! ## What is deliberately not here
//!
//! **Nothing is enabled or disabled.**  The previous tree's filter had an
//! `enabled` flag and four calls that managed rules, and not one of those four
//! turned it on: every packet took the `if !self.enabled { allow }` early
//! return, so the rules a program installed were consulted by nothing.  That is
//! the defect this module's shape prevents.  There is no flag here to leave
//! off: a filter with no rules is a filter whose default action decides
//! everything, the boot installs a filter that allows, and the presence of a
//! rule is what makes the filter do something.  What a call can change is the
//! rules and the default action, and those are the two things that decide.
//!
//! **It is not a connection tracker's state machine.**  A flow here is a key
//! and a last-seen time.  This module does not read TCP's flags, and it says so
//! rather than reading them badly: an entry lives until its protocol's timeout
//! or until it is swept, and a rule that wanted to end a flow when a peer
//! closed it would need the transport's state, which is [`crate::tcp`]'s and
//! not this module's.
//!
//! **It sees no fragment but the first.**  A packet's ports are in its
//! transport header, and a later fragment does not carry one.  A rule that
//! names a port is therefore matched against the first piece of a datagram and
//! the pieces after it are decided by the default action, which is the
//! behaviour the alternative cannot improve: guessing a port from bytes that
//! are not a header is how a filter is made to pass what it was written to
//! stop.
//!
//! ## Where the clock comes from
//!
//! From the caller, as an argument to [`Filter::permits`] and
//! [`Filter::sweep`].  A filter that read a clock would be a module that could
//! not be tested on the host, and this tree's whole network layer is host
//! tests over values: [`crate::reassembly`] takes its clock the same way.

use alloc::vec::Vec;

use abi::Error;
use abi::Result;
use abi::network;

use crate::address::Address;

/// How many rules one filter holds.
///
/// A bound rather than no bound, because the rules arrive from a program: a
/// caller that added rules in a loop would otherwise make the kernel hold
/// whatever it sent.  It is the previous tree's number, which is the number a
/// boot's own configuration has been written against.
pub const RULE_LIMIT: usize = 256;

/// How many flows the tracking table holds.
///
/// Reached, the table stops growing and a new flow is not tracked, which means
/// the packets of that flow are decided by the rule walk on every packet
/// rather than by the entry.  That is the degradation a full table should
/// have: a filter that fell over would be one a stranger could switch off by
/// opening connections.
pub const FLOW_LIMIT: usize = 4096;

/// How long a tracked flow survives without a packet, in microseconds.
///
/// Three numbers, because three kinds of flow end differently.  A TCP
/// connection can idle for hours and still be open, and the entry only stops
/// the rule walk for as long as the connection could exist.  A UDP flow is a
/// pair of datagrams and nothing else, so its entry outlives the conversation
/// by enough to carry a reply.  Anything else is not tracked at all and these
/// two are the whole table.
pub const TCP_FLOW_MICROS: u64 = 86_400_000_000;
/// See [`TCP_FLOW_MICROS`].
pub const UDP_FLOW_MICROS: u64 = 300_000_000;

/// How often [`Filter::sweep`] walks the table, in microseconds.
///
/// A sweep is a walk of up to [`FLOW_LIMIT`] entries, and doing it on every
/// packet would make the filter's cost the table's size.  A packet that
/// arrives in between still finds its entry's own age checked on the lookup
/// that matters, so a stale entry delays a sweep and never the answer.
pub const SWEEP_MICROS: u64 = 30_000_000;

/// What a rule does to a packet that matches it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Let it through.
    Allow,
    /// Drop it, and tell the sender nothing.
    ///
    /// Silence is the whole of what a filter does to a dropped packet, and it
    /// is not an omission: a reset or an unreachable message would tell the
    /// sender that a filter exists, and a port scan's value is in learning
    /// which answers come back.  A stack that answered would be a stack that
    /// reports its own policy to whoever asked.
    Deny,
}

impl Action {
    /// The action a wire value names, or the error for one this build does not.
    ///
    /// Two values and no default: a rule whose action is neither allow nor
    /// deny is a caller's mistake, and reading it as allow would install a
    /// permissive rule where a program meant to write a restrictive one.
    pub fn from_wire(value: u32) -> Result<Self> {
        match value {
            network::FILTER_ACTION_ALLOW => Ok(Self::Allow),
            network::FILTER_ACTION_DENY => Ok(Self::Deny),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// The wire value this action is.
    pub fn to_wire(self) -> u32 {
        match self {
            Self::Allow => network::FILTER_ACTION_ALLOW,
            Self::Deny => network::FILTER_ACTION_DENY,
        }
    }
}

/// Which way a packet is crossing this machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Arriving: the demux is about to read it.
    Inbound,
    /// Leaving: the send path is about to hand it to the card.
    Outbound,
}

impl Direction {
    /// The rule-direction mask that matches this direction.
    ///
    /// A rule states which directions it applies to, and the two values a
    /// caller uses are `FILTER_DIRECTION_BOTH` and the one for this direction:
    /// the mask is not a set of bits, it is one of three words, so the test is
    /// equality with the rule's own word or with both.
    fn matches(self, rule: u32) -> bool {
        rule == network::FILTER_DIRECTION_BOTH
            || rule
                == match self {
                    Self::Inbound => network::FILTER_DIRECTION_INBOUND,
                    Self::Outbound => network::FILTER_DIRECTION_OUTBOUND,
                }
    }
}

/// One rule: what it matches, and what it does with a packet that matches.
///
/// A rule is a value copied out of [`network::FilterRuleDef`] and validated
/// there: every field is a number a program chose, so the constructor is the
/// one place that refuses a rule nothing could match, and the walk below never
/// has to ask whether a prefix is longer than an address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    /// The id this rule was given when it was installed.
    ///
    /// Stored on the rule and not derived from its position, because a removal
    /// shifts every position after it: an id that was a position would name the
    /// **next** rule the moment the one before it went, and a program that
    /// removed two rules by the ids it was given would delete the wrong two.
    id: u32,
    /// What the rule does with a packet it matches.
    action: Action,
    /// The protocol number to match, or zero for any.
    protocol: u32,
    /// The source prefix: its address and how many of its bits are the
    /// network's.
    source: Address,
    source_length: u8,
    /// The destination prefix, the same way.
    destination: Address,
    destination_length: u8,
    /// The source port range, in the shape the ABI states: a zero start is any
    /// port, and a zero end is the start as a single port.
    source_port_start: u32,
    source_port_end: u32,
    /// The destination port range, the same way.
    destination_port_start: u32,
    destination_port_end: u32,
    /// Which directions the rule applies to.
    direction: u32,
    /// Whether a packet that matches leaves a flow the return traffic finds.
    stateful: bool,
}

impl Rule {
    /// A rule from the record a program passed, or the error for one no
    /// packet could match.
    ///
    /// Every refusal here is a value that would make the rule's meaning depend
    /// on a machine's word order or an address's family, and a rule whose
    /// meaning is not what its author wrote is worse than a rule that was
    /// refused: the first is a filter that passes something silently.
    pub fn from_record(record: &network::FilterRuleDef) -> Result<Self> {
        if record.reserved != 0 {
            return Err(Error::InvalidArgument);
        }
        let action = Action::from_wire(record.action)?;
        // The four words that name a range are ports, and a port is sixteen
        // bits: a rule naming 70000 is a rule that matches nothing and says it
        // matches 70000, which a program would find by the rule never firing.
        for port in [
            record.source_port_start,
            record.source_port_end,
            record.destination_port_start,
            record.destination_port_end,
        ] {
            if port > u16::MAX as u32 {
                return Err(Error::InvalidArgument);
            }
        }
        // A range whose end is below its start matches nothing, and the ABI's
        // own reading (a zero end is the start) does not cover it: this is a
        // caller that wrote a range backwards.
        if record.source_port_end != 0 && record.source_port_end < record.source_port_start {
            return Err(Error::InvalidArgument);
        }
        if record.destination_port_end != 0
            && record.destination_port_end < record.destination_port_start
        {
            return Err(Error::InvalidArgument);
        }
        // The direction word is one of three, and anything else is a rule
        // that would apply to no packet if it were compared and to every one
        // if it were not.
        if record.direction != network::FILTER_DIRECTION_BOTH
            && record.direction != network::FILTER_DIRECTION_INBOUND
            && record.direction != network::FILTER_DIRECTION_OUTBOUND
        {
            return Err(Error::InvalidArgument);
        }
        // The stateful word is a flag, and a flag outside its two values is a
        // caller that meant something this build does not do.
        if record.stateful != 0 && record.stateful != 1 {
            return Err(Error::InvalidArgument);
        }

        // The family decides how the two address fields are read, and a rule
        // that names no family has not said which address space its prefix
        // bits live in: it matches both only if it constrains neither.
        let (source, source_length, destination, destination_length) = match record.family {
            network::FILTER_FAMILY_IPV4 => {
                if record.source_prefix > 32 || record.destination_prefix > 32 {
                    return Err(Error::InvalidArgument);
                }
                // The twelve bytes after the address must be zero, which is
                // what makes a record written by a caller that meant IPv4 the
                // same record whatever it left there: a nonzero tail is a
                // caller that wrote an IPv6 address and said it was IPv4.
                if record.source_address[4..].iter().any(|byte| *byte != 0)
                    || record.destination_address[4..]
                        .iter()
                        .any(|byte| *byte != 0)
                {
                    return Err(Error::InvalidArgument);
                }
                let mut source = [0_u8; 4];
                source.copy_from_slice(&record.source_address[..4]);
                let mut destination = [0_u8; 4];
                destination.copy_from_slice(&record.destination_address[..4]);
                (
                    Address::V4(source),
                    record.source_prefix as u8,
                    Address::V4(destination),
                    record.destination_prefix as u8,
                )
            }
            network::FILTER_FAMILY_IPV6 => {
                if record.source_prefix > 128 || record.destination_prefix > 128 {
                    return Err(Error::InvalidArgument);
                }
                (
                    Address::V6(record.source_address),
                    record.source_prefix as u8,
                    Address::V6(record.destination_address),
                    record.destination_prefix as u8,
                )
            }
            network::FILTER_FAMILY_ANY => {
                // A prefix in a rule that names no family is a caller that
                // meant "10.0.0.0/8" and forgot which field said so.  Reading
                // its four bytes as the start of an IPv4 address and matching
                // only IPv4 would be a rule the author did not write.
                if record.source_prefix != 0 || record.destination_prefix != 0 {
                    return Err(Error::InvalidArgument);
                }
                (Address::V4([0; 4]), 0, Address::V4([0; 4]), 0)
            }
            _ => return Err(Error::InvalidArgument),
        };

        Ok(Self {
            id: 0,
            action,
            protocol: record.protocol,
            source,
            source_length,
            destination,
            destination_length,
            source_port_start: record.source_port_start,
            source_port_end: record.source_port_end,
            destination_port_start: record.destination_port_start,
            destination_port_end: record.destination_port_end,
            direction: record.direction,
            stateful: record.stateful == 1,
        })
    }

    /// The id this rule was given when it was installed.
    ///
    /// Zero before it is added, because a rule that has not been installed has
    /// not been given one: a caller reading the id of a rule it built and never
    /// added learns that rather than a number that names another rule.
    pub fn id(&self) -> u32 {
        self.id
    }

    /// What the rule does with a packet it matches.
    pub fn action(&self) -> Action {
        self.action
    }

    /// Whether the rule asks for a flow to be remembered.
    pub fn is_stateful(&self) -> bool {
        self.stateful
    }

    /// Whether this rule applies to `packet`.
    ///
    /// The order of the tests is the order of how cheaply each one excludes a
    /// packet, and it is also the order that keeps a rule from reading a
    /// transport header it has not earned: the ports are compared only after
    /// the rule has said it is about a protocol whose header carries them.
    fn matches(&self, direction: Direction, packet: &Packet) -> bool {
        if !direction.matches(self.direction) {
            return false;
        }
        // Zero is the protocol wildcard, which is the ABI's
        // `FILTER_PROTOCOL_ANY` and also every protocol number nothing uses.
        if !protocol_matches(self.protocol, packet.protocol) {
            return false;
        }
        if !covers(self.source, packet.source, self.source_length)
            || !covers(
                self.destination,
                packet.destination,
                self.destination_length,
            )
        {
            return false;
        }

        // A port rule on a packet with no ports.  `matches` is called with
        // the ports this module could read, and a rule that names a port range
        // against a packet whose header was too short to carry one is a
        // **refusal to match**, not a match: a rule written for TCP must not
        // pass an ICMP message because the bytes it would have read as ports
        // were absent.
        let names_ports = self.source_port_start != 0 || self.destination_port_start != 0;
        if !names_ports {
            return true;
        }
        let Some((source_port, destination_port)) = packet.ports else {
            return false;
        };
        port_matches(source_port, self.source_port_start, self.source_port_end)
            && port_matches(
                destination_port,
                self.destination_port_start,
                self.destination_port_end,
            )
    }
}

/// The protocol word that matches any protocol, and the numbers the three
/// protocols this stack parses are.
///
/// The three numbers are **not** restated here: they are the IP header's own
/// protocol numbers, [`crate::ipv4::PROTOCOL_TCP`] and its siblings, and the
/// ABI's `FILTER_PROTOCOL_*` constants name the same values.  A caller writes
/// the number its own headers already have, which is what makes a rule about
/// "TCP" and a packet whose header says 6 agree without an enumeration in
/// between.
const PROTOCOL_ANY: u32 = 0;

/// Whether `protocol` is the rule's protocol or the rule's wildcard.
fn protocol_matches(rule: u32, packet: u8) -> bool {
    rule == PROTOCOL_ANY || rule == u32::from(packet)
}

/// Whether the first `length` bits of `prefix` and `address` are equal.
///
/// The comparison is [`crate::route`]'s, reached through the function that
/// module made `pub(crate)`: a filter and a route table asking whether an
/// address is inside a prefix are asking one question, and two spellings of it
/// would be two places for a `/20` to mean different things.
fn covers(prefix: Address, address: Address, length: u8) -> bool {
    match (prefix, address) {
        (Address::V4(prefix), Address::V4(address)) => {
            crate::route::prefix_bits(&prefix, &address, length as usize)
        }
        (Address::V6(prefix), Address::V6(address)) => {
            crate::route::prefix_bits(&prefix, &address, length as usize)
        }
        // A rule of one family does not match a packet of the other.  The two
        // are different lengths and different meanings, and a comparison
        // across them would be a rule with no subject.
        _ => false,
    }
}

/// Whether `port` is inside a range written the ABI's way.
///
/// A zero start is any port, which is what makes an unset field mean "do not
/// constrain"; a zero end is the start as one port, which is what makes a
/// single-port rule writable without repeating the number.
fn port_matches(port: u16, start: u32, end: u32) -> bool {
    if start == 0 {
        return true;
    }
    let port = u32::from(port);
    let end = if end == 0 { start } else { end };
    port >= start && port <= end
}

/// The parts of one packet a rule is allowed to see.
///
/// A value rather than a reference to the frame, because a rule must not read
/// a byte it did not earn: the ports are `None` when the packet's own header
/// did not carry them, and that is a different fact from a port of zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Packet {
    /// Where it claims to come from.
    pub source: Address,
    /// Where it claims to go.
    pub destination: Address,
    /// The IP header's protocol number.
    pub protocol: u8,
    /// The transport's two ports, when its header carried them.
    pub ports: Option<(u16, u16)>,
}

impl Packet {
    /// An IPv4 packet, with its ports read from the transport header when the
    /// protocol is one that has them.
    ///
    /// TCP and UDP both put the source port first and the destination port
    /// second, so one reader serves both.  A header shorter than four bytes is
    /// [`None`] rather than zeros: a UDP header that short would be refused by
    /// its own parser, and the filter is asked before the parser runs.
    pub fn v4(source: [u8; 4], destination: [u8; 4], protocol: u8, payload: &[u8]) -> Self {
        let ports = transport_ports(protocol, payload);
        Self {
            source: Address::V4(source),
            destination: Address::V4(destination),
            protocol,
            ports,
        }
    }

    /// An IPv6 packet, the same way.
    pub fn v6(source: [u8; 16], destination: [u8; 16], protocol: u8, payload: &[u8]) -> Self {
        let ports = transport_ports(protocol, payload);
        Self {
            source: Address::V6(source),
            destination: Address::V6(destination),
            protocol,
            ports,
        }
    }
}

/// The two ports a transport header starts with, for the protocols that have
/// them.
///
/// ICMP is deliberately not here even though its header has two sixteen-bit
/// words in the same place: those are a type and a code, and a rule written
/// for ports read against them would be matching a number that is not a port.
fn transport_ports(protocol: u8, payload: &[u8]) -> Option<(u16, u16)> {
    if protocol != crate::ipv4::PROTOCOL_TCP && protocol != crate::ipv4::PROTOCOL_UDP {
        return None;
    }
    if payload.len() < 4 {
        return None;
    }
    Some((
        u16::from_be_bytes([payload[0], payload[1]]),
        u16::from_be_bytes([payload[2], payload[3]]),
    ))
}

/// A tracked flow: the key that identifies it, and when it was last seen.
///
/// The key is **canonical**, which is what makes one entry answer both
/// directions: the two endpoints are ordered, so a reply's `(peer, local)`
/// and its request's `(local, peer)` are the same key.  Without that, every
/// flow would need two entries and the table would be twice its bound for no
/// gain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Flow {
    /// The lower endpoint's address, then the higher.
    first: Address,
    second: Address,
    /// The port that belongs to `first`, then the one that belongs to
    /// `second`.
    first_port: u16,
    second_port: u16,
    /// The IP header's protocol number.
    protocol: u8,
    /// When a packet of this flow was last seen.
    last_seen: u64,
}

impl Flow {
    /// The key one packet makes, with its two ends ordered.
    fn key(packet: &Packet, now: u64) -> Option<Self> {
        let (source_port, destination_port) = packet.ports?;
        let (first, second, first_port, second_port) =
            if (packet.source, source_port) <= (packet.destination, destination_port) {
                (
                    packet.source,
                    packet.destination,
                    source_port,
                    destination_port,
                )
            } else {
                (
                    packet.destination,
                    packet.source,
                    destination_port,
                    source_port,
                )
            };
        Some(Self {
            first,
            second,
            first_port,
            second_port,
            protocol: packet.protocol,
            last_seen: now,
        })
    }

    /// Whether this is the same flow as `other`, ignoring when it was seen.
    fn same_as(&self, other: &Self) -> bool {
        self.first == other.first
            && self.second == other.second
            && self.first_port == other.first_port
            && self.second_port == other.second_port
            && self.protocol == other.protocol
    }

    /// How long an unseen flow of this protocol survives.
    fn lifetime(&self) -> u64 {
        match self.protocol {
            crate::ipv4::PROTOCOL_TCP => TCP_FLOW_MICROS,
            _ => UDP_FLOW_MICROS,
        }
    }
}

/// What a filter decided, and what it counted.
///
/// The counts are the caller's, not the filter's: [`Filter::permits`] takes a
/// `&self` and answers a value, so two callers on two CPUs do not contend and
/// no counter is a lock.  The caller adds it up, which is the arrangement
/// [`crate::tcp_table`] uses for its counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Verdict {
    /// Whether the packet may cross.
    pub allowed: bool,
    /// Whether a rule decided it, as opposed to the default action.
    ///
    /// A caller reading a filter's log wants the difference: a rule that never
    /// fires and a default action that always does are the same packet and two
    /// different configurations.
    pub by_rule: bool,
    /// The index of the rule that decided it, when one did.
    pub rule: Option<usize>,
}

/// The rules a machine holds, the flows they have remembered, and the action
/// for a packet no rule matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Filter {
    rules: Vec<Rule>,
    flows: Vec<Flow>,
    default_action: Action,
    /// When the last sweep ran, so a sweep is not a walk per packet.
    swept_at: u64,
    /// The next id a rule is given, never reused.
    ///
    /// Monotonic rather than the rule's index, because a program removes rules
    /// and an index that shifted would make a rule's id name a different rule
    /// after a removal.  A filter that renumbered would be one whose remove can
    /// delete the wrong rule.
    next_id: u32,
    /// Packets that crossed since the boot.
    ///
    /// Plain fields and not atomics: the filter is a value the kernel holds
    /// behind its own lock, so the lock a caller already took is the one that
    /// makes these safe, and an atomic under a lock is arithmetic the lock
    /// already did.
    allowed: u64,
    /// Packets that were dropped since the boot.
    dropped: u64,
}

impl Filter {
    /// A filter that allows everything: no rules, and the default allowing.
    ///
    /// The state a machine starts in, and the state a program has to leave
    /// deliberately.  A filter that started closed would break the boot's own
    /// exchanges, and a boot whose network stopped working because a subsystem
    /// arrived would be one whose arrival nobody could test.
    pub const fn new() -> Self {
        Self {
            rules: Vec::new(),
            flows: Vec::new(),
            default_action: Action::Allow,
            swept_at: 0,
            next_id: 1,
            allowed: 0,
            dropped: 0,
        }
    }

    /// The action a packet no rule matches gets.
    pub fn default_action(&self) -> Action {
        self.default_action
    }

    /// Set the action a packet no rule matches gets.
    ///
    /// The one call that changes the filter's posture without adding a rule,
    /// and it is the pair to a boot that installed rules and wants a closed
    /// default: the order a program does those two in decides whether there is
    /// a moment the machine is open, which is why the default moves here and
    /// not implicitly with the first rule.
    pub fn set_default_action(&mut self, action: Action) {
        self.default_action = action;
    }

    /// Add a rule, answering the id it was given.
    ///
    /// Appended, and not inserted by specificity: the walk is ordered and the
    /// order is the caller's, so a rule that arrives last is consulted last.
    /// That is the property a program relies on when it writes a deny before a
    /// broader allow.
    pub fn add(&mut self, mut rule: Rule) -> Result<u32> {
        if self.rules.len() >= RULE_LIMIT {
            return Err(Error::Busy);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        rule.id = id;
        self.rules.push(rule);
        Ok(id)
    }

    /// Remove a rule by id, answering whether one was there.
    ///
    /// By the id the rule was given and not by its position: a position moves
    /// when a rule before it is removed, and a remove that walked positions
    /// would delete whichever rule had moved into the slot.
    pub fn remove(&mut self, id: u32) -> bool {
        let before = self.rules.len();
        self.rules.retain(|rule| rule.id != id);
        self.rules.len() != before
    }

    /// How many rules are held.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Whether no rule is held.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// How many flows are tracked.
    pub fn flows(&self) -> usize {
        self.flows.len()
    }

    /// The rules, in the order they decide.
    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Decide one packet, remembering the flow a stateful rule asked for.
    ///
    /// `now` is the caller's clock in microseconds.  The order is the whole of
    /// the rule:
    ///
    /// 1. A flow that is already tracked allows the packet without consulting
    ///    the rules.  That is what makes a stateful rule a stateful rule: the
    ///    return traffic never matches the rule that started it, because that
    ///    rule was written for one direction and the return packet is the
    ///    other.
    /// 2. The rules are walked in order and the first match decides.
    /// 3. No match is the default action.
    pub fn permits(&mut self, direction: Direction, packet: &Packet, now: u64) -> Verdict {
        // A tracked flow answers first, and its last-seen moves: a connection
        // that is being used is a connection whose entry must not expire.
        let verdict = self.decide(direction, packet, now);
        if verdict.allowed {
            self.allowed = self.allowed.saturating_add(1);
        } else {
            self.dropped = self.dropped.saturating_add(1);
        }
        verdict
    }

    /// The decision itself, with no counting.
    ///
    /// Split from [`Filter::permits`] so the counters are updated in one place:
    /// a walk that returned early from five spots would be five places to
    /// forget a count, and the count is what `FilterGetStats` reports.
    fn decide(&mut self, direction: Direction, packet: &Packet, now: u64) -> Verdict {
        if let Some(key) = Flow::key(packet, now)
            && let Some(flow) = self.flows.iter_mut().find(|flow| flow.same_as(&key))
        {
            flow.last_seen = now;
            return Verdict {
                allowed: true,
                by_rule: true,
                rule: None,
            };
        }

        for (index, rule) in self.rules.iter().enumerate() {
            if !rule.matches(direction, packet) {
                continue;
            }
            match rule.action {
                Action::Allow => {
                    if rule.stateful {
                        self.remember(packet, now);
                    }
                    return Verdict {
                        allowed: true,
                        by_rule: true,
                        rule: Some(index),
                    };
                }
                Action::Deny => {
                    return Verdict {
                        allowed: false,
                        by_rule: true,
                        rule: Some(index),
                    };
                }
            }
        }

        Verdict {
            allowed: self.default_action == Action::Allow,
            by_rule: false,
            rule: None,
        }
    }

    /// How many packets the filter allowed and dropped since the boot.
    pub fn counts(&self) -> (u64, u64) {
        (self.allowed, self.dropped)
    }

    /// Remember the flow a packet belongs to, if the table has room.
    ///
    /// A full table does not evict: an evicted flow is a return packet that
    /// the rule walk then has to re-decide, and a rule written for one
    /// direction would deny it.  Not remembering is the failure that keeps the
    /// filter's answers right at the cost of its speed, which is the direction
    /// a full table should fail in.
    fn remember(&mut self, packet: &Packet, now: u64) {
        let Some(key) = Flow::key(packet, now) else {
            return;
        };
        if self.flows.iter().any(|flow| flow.same_as(&key)) {
            return;
        }
        if self.flows.len() >= FLOW_LIMIT {
            return;
        }
        self.flows.push(key);
    }

    /// Drop every flow that has gone unseen past its protocol's lifetime.
    ///
    /// Called with the caller's clock, and rate-limited by [`SWEEP_MICROS`]:
    /// the walk is over up to [`FLOW_LIMIT`] entries, which is not a per-packet
    /// cost.  A clock that went backwards (a caller with a different epoch) is
    /// handled by the wrapping subtraction, the same way
    /// [`crate::reassembly::Cache::expire`] handles it.
    pub fn sweep(&mut self, now: u64) {
        if now.wrapping_sub(self.swept_at) < SWEEP_MICROS && self.swept_at != 0 {
            return;
        }
        self.swept_at = now;
        self.flows
            .retain(|flow| now.wrapping_sub(flow.last_seen) < flow.lifetime());
    }

    /// Forget every flow, and keep the rules.
    ///
    /// What a call that changes the policy does: a flow remembered under the
    /// old rules would otherwise outlive them and allow traffic the new set
    /// was written to stop.
    pub fn forget_flows(&mut self) {
        self.flows.clear();
    }
}

impl Default for Filter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::Action;
    use super::Direction;
    use super::FLOW_LIMIT;
    use super::Filter;
    use super::Packet;
    use super::RULE_LIMIT;
    use super::Rule;
    use abi::Error;
    use abi::network;

    /// A record with everything wildcarded, so a test changes only the field
    /// it is about.
    fn any_rule() -> network::FilterRuleDef {
        network::FilterRuleDef {
            action: network::FILTER_ACTION_ALLOW,
            protocol: super::PROTOCOL_ANY,
            family: network::FILTER_FAMILY_ANY,
            direction: network::FILTER_DIRECTION_BOTH,
            stateful: 0,
            source_prefix: 0,
            destination_prefix: 0,
            source_port_start: 0,
            source_port_end: 0,
            destination_port_start: 0,
            destination_port_end: 0,
            reserved: 0,
            source_address: [0; network::FILTER_ADDRESS_BYTES],
            destination_address: [0; network::FILTER_ADDRESS_BYTES],
        }
    }

    /// The same record, naming IPv4, so a test that writes prefixes has a
    /// family that makes them mean something.
    fn ipv4_rule() -> network::FilterRuleDef {
        let mut record = any_rule();
        record.family = network::FILTER_FAMILY_IPV4;
        record
    }

    fn packet(protocol: u8, ports: Option<(u16, u16)>) -> Packet {
        Packet {
            source: crate::address::Address::V4([10, 0, 2, 2]),
            destination: crate::address::Address::V4([10, 0, 2, 15]),
            protocol,
            ports,
        }
    }

    /// An empty filter allows everything, which is the state a boot has to
    /// start in.
    ///
    /// The property is not decoration: the boot's own ARP, DHCP and echo
    /// exchanges run before any program can install a rule, and a filter that
    /// started closed would make every one of them fail at the point this
    /// module arrived.
    #[test]
    fn an_empty_filter_allows_everything() {
        let mut filter = Filter::new();
        let verdict = filter.permits(
            Direction::Inbound,
            &packet(crate::ipv4::PROTOCOL_TCP, Some((1234, 80))),
            0,
        );
        assert!(verdict.allowed);
        assert!(!verdict.by_rule, "the default action decided it");
        assert_eq!(verdict.rule, None);
    }

    /// A deny rule drops the packet the default action would have allowed.
    ///
    /// This is the test the previous tree could not have passed: its filter had
    /// an `enabled` flag that started `false` and no call that set it, so the
    /// rule walk never ran.  The absence of that flag is what this asserts, by
    /// asserting the rule's effect with nothing else turned on.
    #[test]
    fn a_deny_rule_drops_what_the_default_allows() {
        let mut filter = Filter::new();
        let mut record = any_rule();
        record.action = network::FILTER_ACTION_DENY;
        record.protocol = u32::from(crate::ipv4::PROTOCOL_TCP);
        record.destination_port_start = 23;
        let id = filter
            .add(Rule::from_record(&record).expect("a rule"))
            .unwrap();
        assert_eq!(id, 1);

        // The port the rule names is refused.
        let verdict = filter.permits(
            Direction::Inbound,
            &packet(crate::ipv4::PROTOCOL_TCP, Some((1234, 23))),
            0,
        );
        assert!(!verdict.allowed, "the rule decided, and it denies");
        assert_eq!(verdict.rule, Some(0));

        // Everything else still gets the default action.
        assert!(
            filter
                .permits(
                    Direction::Inbound,
                    &packet(crate::ipv4::PROTOCOL_TCP, Some((1234, 80))),
                    0
                )
                .allowed
        );
        // And the same port on another protocol, because the rule names TCP.
        assert!(
            filter
                .permits(
                    Direction::Inbound,
                    &packet(crate::ipv4::PROTOCOL_UDP, Some((1234, 23))),
                    0
                )
                .allowed
        );
    }

    /// The first matching rule decides, whatever the rules after it say.
    ///
    /// The property a readable rule set depends on: a deny written above a
    /// broader allow is a deny, and a filter that took the last match or the
    /// most specific one would make the order meaningless.
    #[test]
    fn the_first_match_decides_in_the_order_the_rules_arrived() {
        let mut filter = Filter::new();

        let mut deny = any_rule();
        deny.action = network::FILTER_ACTION_DENY;
        deny.protocol = u32::from(crate::ipv4::PROTOCOL_TCP);
        filter
            .add(Rule::from_record(&deny).expect("a rule"))
            .unwrap();

        // A broader allow, added second, and consulted second.
        filter
            .add(Rule::from_record(&any_rule()).expect("a rule"))
            .unwrap();

        let verdict = filter.permits(
            Direction::Inbound,
            &packet(crate::ipv4::PROTOCOL_TCP, Some((1, 2))),
            0,
        );
        assert!(!verdict.allowed, "the first rule is the deny");
        assert_eq!(verdict.rule, Some(0));

        // A UDP packet matches only the second rule.
        let verdict = filter.permits(
            Direction::Inbound,
            &packet(crate::ipv4::PROTOCOL_UDP, Some((1, 2))),
            0,
        );
        assert!(verdict.allowed);
        assert_eq!(verdict.rule, Some(1));
    }

    /// An allow before a deny is an allow: the walk stops at the first match.
    ///
    /// The case the two-rule test cannot reach.  With one deny and one allow,
    /// "the first match" and "any deny wins" give the same answer, so a walk
    /// that scanned for a deny would pass a test written only that way.  Here
    /// the allow is first and names the traffic; a filter that let the later
    /// deny win would refuse a packet the first rule allowed.
    #[test]
    fn an_allow_before_a_deny_is_an_allow() {
        let mut filter = Filter::new();

        let mut allow = ipv4_rule();
        allow.action = network::FILTER_ACTION_ALLOW;
        allow.protocol = u32::from(crate::ipv4::PROTOCOL_TCP);
        allow.destination_port_start = 80;
        filter
            .add(Rule::from_record(&allow).expect("a rule"))
            .unwrap();

        let mut deny = ipv4_rule();
        deny.action = network::FILTER_ACTION_DENY;
        deny.protocol = u32::from(crate::ipv4::PROTOCOL_TCP);
        filter
            .add(Rule::from_record(&deny).expect("a rule"))
            .unwrap();

        let verdict = filter.permits(
            Direction::Inbound,
            &packet(crate::ipv4::PROTOCOL_TCP, Some((1234, 80))),
            0,
        );
        assert!(
            verdict.allowed,
            "the first rule allowed it and the walk stopped"
        );
        assert_eq!(verdict.rule, Some(0));
    }

    /// An IPv6 rule matches by its own bits, and its prefix may be longer
    /// than an IPv4 address.
    ///
    /// The family is what makes a rule's address bytes mean something: read as
    /// IPv4 they are four bytes and a tail nothing explained, and a `/64` in an
    /// IPv6 rule would be refused as a prefix longer than the address it names.
    /// Both halves are asserted because a reader that took the family but kept
    /// IPv4's bound would get the second one wrong.
    #[test]
    fn an_ipv6_rule_matches_its_own_prefix() {
        let mut filter = Filter::new();
        let mut record = any_rule();
        record.family = network::FILTER_FAMILY_IPV6;
        record.action = network::FILTER_ACTION_DENY;
        record.destination_prefix = 64;
        record.destination_address = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        filter
            .add(Rule::from_record(&record).expect("an ipv6 rule"))
            .unwrap();

        // Inside the /64: refused.
        let inside = Packet {
            source: crate::address::Address::V6([
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x54, 0, 0xff, 0xfe, 0x12, 0x34, 0x56,
            ]),
            destination: crate::address::Address::V6([
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ]),
            protocol: crate::ipv4::PROTOCOL_TCP,
            ports: Some((1, 2)),
        };
        assert!(!filter.permits(Direction::Inbound, &inside, 0).allowed);

        // One bit past it: allowed.
        let outside = Packet {
            destination: crate::address::Address::V6([
                0x20, 0x01, 0x0d, 0xb9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ]),
            ..inside
        };
        assert!(filter.permits(Direction::Inbound, &outside, 0).allowed);

        // And the family is part of the match: an IPv4 packet is not covered by
        // an IPv6 rule, even when the first four bytes would agree.
        let v4 = packet(crate::ipv4::PROTOCOL_TCP, Some((1, 2)));
        assert!(filter.permits(Direction::Inbound, &v4, 0).allowed);

        // A prefix longer than an IPv6 address is refused, which is the same
        // refusal IPv4 makes for a /33.
        let mut long = record;
        long.destination_prefix = 129;
        assert_eq!(Rule::from_record(&long), Err(Error::InvalidArgument));
    }

    /// The counters say what the decisions said, in both directions.
    ///
    /// The number `FilterGetStats` reports, asserted against the verdicts
    /// themselves rather than against a literal: a counter that was incremented
    /// in the wrong branch would still sum to the packets offered, so the test
    /// checks each side separately.
    #[test]
    fn the_counters_follow_the_decisions() {
        let mut filter = Filter::new();
        let mut deny = ipv4_rule();
        deny.action = network::FILTER_ACTION_DENY;
        deny.protocol = u32::from(crate::ipv4::PROTOCOL_TCP);
        deny.destination_port_start = 23;
        filter
            .add(Rule::from_record(&deny).expect("a rule"))
            .unwrap();

        let allowed = packet(crate::ipv4::PROTOCOL_TCP, Some((1, 80)));
        let dropped = packet(crate::ipv4::PROTOCOL_TCP, Some((1, 23)));
        assert_eq!(filter.counts(), (0, 0), "nothing has crossed yet");

        assert!(filter.permits(Direction::Inbound, &allowed, 0).allowed);
        assert_eq!(filter.counts(), (1, 0));

        assert!(!filter.permits(Direction::Inbound, &dropped, 0).allowed);
        assert_eq!(filter.counts(), (1, 1));

        // The default action counts too: a packet no rule matches is a packet
        // the filter decided, not one it never saw.
        filter.set_default_action(Action::Deny);
        let unmatched = packet(crate::ipv4::PROTOCOL_UDP, Some((1, 2)));
        assert!(!filter.permits(Direction::Inbound, &unmatched, 0).allowed);
        assert_eq!(filter.counts(), (1, 2));

        // And a packet a tracked flow allows counts as allowed.
        filter.set_default_action(Action::Allow);
        let mut stateful = ipv4_rule();
        stateful.stateful = 1;
        filter
            .add(Rule::from_record(&stateful).expect("a rule"))
            .unwrap();
        filter.permits(Direction::Outbound, &packet_toward(443), 0);
        let before = filter.counts().0;
        assert!(
            filter
                .permits(Direction::Inbound, &packet_from(443), 1)
                .allowed
        );
        assert_eq!(filter.counts().0, before + 1, "the flow's packet counted");
    }

    /// A rule naming a port does not match a packet whose header carried none.
    ///
    /// The defect this prevents: a rule written for TCP passing an ICMP
    /// message because the bytes after its header happened to be read as
    /// ports.  `None` and a port of zero are different facts and the rule
    /// treats them so.
    #[test]
    fn a_port_rule_does_not_match_a_packet_with_no_ports() {
        let mut filter = Filter::new();
        let mut record = any_rule();
        record.action = network::FILTER_ACTION_DENY;
        record.destination_port_start = 80;
        filter
            .add(Rule::from_record(&record).expect("a rule"))
            .unwrap();

        // ICMP has no ports, and the rule must not match it.
        let verdict = filter.permits(
            Direction::Inbound,
            &packet(crate::ipv4::PROTOCOL_ICMP, None),
            0,
        );
        assert!(verdict.allowed, "no port to match, so no match");
        assert!(!verdict.by_rule);
    }

    /// A direction's rule applies to that direction and not the other.
    #[test]
    fn a_direction_is_part_of_what_a_rule_matches() {
        let mut filter = Filter::new();
        let mut record = any_rule();
        record.action = network::FILTER_ACTION_DENY;
        record.direction = network::FILTER_DIRECTION_INBOUND;
        filter
            .add(Rule::from_record(&record).expect("a rule"))
            .unwrap();
        let packet = packet(crate::ipv4::PROTOCOL_TCP, Some((1, 2)));

        assert!(!filter.permits(Direction::Inbound, &packet, 0).allowed);
        assert!(
            filter.permits(Direction::Outbound, &packet, 0).allowed,
            "the rule names the inbound direction only"
        );

        // A rule that names both applies to both.
        let mut both = Filter::new();
        let mut record = any_rule();
        record.action = network::FILTER_ACTION_DENY;
        both.add(Rule::from_record(&record).expect("a rule"))
            .unwrap();
        assert!(!both.permits(Direction::Inbound, &packet, 0).allowed);
        assert!(!both.permits(Direction::Outbound, &packet, 0).allowed);
    }

    /// A prefix rule matches its leading bits and nothing past them.
    ///
    /// The rule and [`crate::route`] share the comparison, and this asserts the
    /// filter uses it rather than comparing whole addresses: a `/24` that
    /// matched one address would be a rule that never fires for the host it was
    /// written about.
    #[test]
    fn a_prefix_rule_matches_every_address_under_it() {
        let mut filter = Filter::new();
        let mut record = ipv4_rule();
        record.action = network::FILTER_ACTION_DENY;
        record.source_address = [10, 1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        record.source_prefix = 24;
        filter
            .add(Rule::from_record(&record).expect("a rule"))
            .unwrap();

        for host in [1_u8, 2, 200, 254] {
            let mut probe = packet(crate::ipv4::PROTOCOL_TCP, Some((1, 2)));
            probe.source = crate::address::Address::V4([10, 1, 2, host]);
            assert!(
                !filter.permits(Direction::Inbound, &probe, 0).allowed,
                "10.1.2.{host} is inside the /24"
            );
        }

        let mut outside = packet(crate::ipv4::PROTOCOL_TCP, Some((1, 2)));
        outside.source = crate::address::Address::V4([10, 1, 3, 1]);
        assert!(
            filter.permits(Direction::Inbound, &outside, 0).allowed,
            "and the next subnet is not"
        );
    }

    /// A stateful rule's return traffic is allowed without matching the rule,
    /// and a stateless rule's is not.
    ///
    /// The two halves are one test because the difference between them is the
    /// whole point of the flag: an implementation that tracked every allowed
    /// flow would pass the first assertion and be wrong about the second.
    #[test]
    fn a_stateful_rule_remembers_the_flow_and_a_stateless_one_does_not() {
        // The rule allows outbound traffic to one destination port.  The
        // reply comes **inbound** from that port, so it does not match.
        let mut record = any_rule();
        record.direction = network::FILTER_DIRECTION_OUTBOUND;
        record.destination_port_start = 443;
        record.destination_port_end = 443;

        let outbound = packet_toward(443);
        let inbound = packet_from(443);

        // Stateless: the reply falls to the default action.
        let mut stateless = Filter::new();
        stateless.set_default_action(Action::Deny);
        stateless
            .add(Rule::from_record(&record).expect("a rule"))
            .unwrap();
        assert!(
            stateless.permits(Direction::Outbound, &outbound, 0).allowed,
            "the request matches the rule"
        );
        assert!(
            !stateless.permits(Direction::Inbound, &inbound, 1).allowed,
            "and the reply has no flow to find"
        );
        assert_eq!(stateless.flows(), 0, "nothing was remembered");

        // Stateful: the request remembers the flow and the reply finds it.
        let mut stateful = Filter::new();
        stateful.set_default_action(Action::Deny);
        record.stateful = 1;
        stateful
            .add(Rule::from_record(&record).expect("a rule"))
            .unwrap();
        assert!(stateful.permits(Direction::Outbound, &outbound, 0).allowed);
        assert_eq!(stateful.flows(), 1, "the first packet remembered it");
        assert!(
            stateful.permits(Direction::Inbound, &inbound, 1).allowed,
            "the reply finds the flow and needs no rule"
        );
    }

    /// The two directions of one flow are one entry.
    ///
    /// The canonical key: a reply's endpoints are the request's swapped, and a
    /// table that keyed them as written would need two entries per flow and
    /// answer the reply with the rule walk, which is the bug stateful filtering
    /// exists to avoid.
    #[test]
    fn the_two_directions_of_one_flow_share_an_entry() {
        let mut filter = Filter::new();
        let mut record = any_rule();
        record.stateful = 1;
        filter
            .add(Rule::from_record(&record).expect("a rule"))
            .unwrap();

        filter.permits(Direction::Outbound, &packet_toward(443), 0);
        filter.permits(Direction::Inbound, &packet_from(443), 1);
        assert_eq!(filter.flows(), 1, "one entry, not two");
    }

    /// A flow expires after its protocol's lifetime and not before.
    ///
    /// The lifetime is the caller's clock, so the test states the times
    /// directly: UDP's entry survives inside its window and is gone past it,
    /// and a sweep is what removes it.
    #[test]
    fn a_flow_expires_when_its_time_passes() {
        let mut filter = Filter::new();
        let mut record = any_rule();
        record.stateful = 1;
        record.protocol = u32::from(crate::ipv4::PROTOCOL_UDP);
        filter
            .add(Rule::from_record(&record).expect("a rule"))
            .unwrap();
        assert_eq!(filter.flows(), 0);
        filter.permits(
            Direction::Outbound,
            &packet_toward_as(crate::ipv4::PROTOCOL_UDP, 53),
            0,
        );
        assert_eq!(filter.flows(), 1);

        // Inside the window the sweep keeps it.
        filter.sweep(super::UDP_FLOW_MICROS - 1);
        assert_eq!(filter.flows(), 1, "still inside its lifetime");

        // Past it, the sweep drops it.
        filter.sweep(super::UDP_FLOW_MICROS + super::SWEEP_MICROS);
        assert_eq!(filter.flows(), 0, "past its lifetime");
    }

    /// A sweep that ran a moment ago does not run again.
    ///
    /// The rate limit, and the reason it exists: a walk of up to
    /// [`FLOW_LIMIT`] entries on every packet would make the filter's cost the
    /// table's size.  The second call is asserted by its **effect**, an expired
    /// flow still present, which is what a run-again sweep would have removed.
    #[test]
    fn a_sweep_is_rate_limited() {
        let mut filter = Filter::new();
        let mut record = any_rule();
        record.stateful = 1;
        record.protocol = u32::from(crate::ipv4::PROTOCOL_UDP);
        filter
            .add(Rule::from_record(&record).expect("a rule"))
            .unwrap();
        filter.permits(
            Direction::Outbound,
            &packet_toward_as(crate::ipv4::PROTOCOL_UDP, 53),
            0,
        );

        // The first sweep runs just before the flow's lifetime ends, and keeps
        // it: a sweep at the lifetime itself would remove it, which is the next
        // case and not this one.
        let before = super::UDP_FLOW_MICROS - 10;
        filter.sweep(before);
        assert_eq!(filter.flows(), 1);

        // The second is asked for **after** the flow has expired and **inside**
        // the sweep interval, so a sweep that ran would remove it and a sweep
        // that was skipped leaves it.  Both conditions meet because the
        // interval is far shorter than the flow's lifetime.
        let expired_but_too_soon = super::UDP_FLOW_MICROS + 10;
        assert!(
            expired_but_too_soon - before < super::SWEEP_MICROS,
            "the test needs this sweep to be inside the interval"
        );
        filter.sweep(expired_but_too_soon);
        assert_eq!(
            filter.flows(),
            1,
            "the sweep was skipped, not the flow kept"
        );

        // Past the interval the sweep runs, and the flow goes.
        filter.sweep(before + super::SWEEP_MICROS);
        assert_eq!(filter.flows(), 0);
    }

    /// A removed rule stops deciding, and a rule after it keeps its own id.
    ///
    /// The id arithmetic: ids are assigned from a monotonic counter and a
    /// removal does not renumber, so removing the first rule and then the
    /// second by the id it was given must remove the rule that was second.
    #[test]
    fn removing_a_rule_does_not_renumber_the_others() {
        let mut filter = Filter::new();
        let mut deny = any_rule();
        deny.action = network::FILTER_ACTION_DENY;
        deny.protocol = u32::from(crate::ipv4::PROTOCOL_TCP);
        let first = filter
            .add(Rule::from_record(&deny).expect("a rule"))
            .unwrap();
        let second = filter
            .add(Rule::from_record(&deny).expect("a rule"))
            .unwrap();
        assert_eq!((first, second), (1, 2));

        assert!(filter.remove(first));
        assert_eq!(filter.len(), 1);
        let tcp = packet(crate::ipv4::PROTOCOL_TCP, Some((1, 2)));
        assert!(
            !filter.permits(Direction::Inbound, &tcp, 0).allowed,
            "one deny left"
        );

        // The second rule is still the one id 2 names.
        assert!(filter.remove(second));
        assert!(filter.is_empty());
        assert!(
            filter.permits(Direction::Inbound, &tcp, 0).allowed,
            "no rule is left to deny it"
        );
        assert!(!filter.remove(second), "and removing it twice says so");
    }

    /// A record no packet could match is refused, and nothing is installed.
    ///
    /// Each refusal is a value whose meaning would depend on something the
    /// rule does not state: an action that is neither allow nor deny, a prefix
    /// longer than an address, a port past sixteen bits, a range written
    /// backwards, a direction word nothing defines.
    #[test]
    fn a_rule_no_packet_could_match_is_refused() {
        let mut filter = Filter::new();

        let mut bad_action = any_rule();
        bad_action.action = 7;
        assert_eq!(
            Rule::from_record(&bad_action).map(|rule| filter.add(rule)),
            Err(Error::InvalidArgument)
        );

        let mut long_prefix = ipv4_rule();
        long_prefix.source_prefix = 33;
        assert_eq!(Rule::from_record(&long_prefix), Err(Error::InvalidArgument));

        let mut long_port = any_rule();
        long_port.destination_port_start = 70_000;
        assert_eq!(Rule::from_record(&long_port), Err(Error::InvalidArgument));

        let mut backwards = any_rule();
        backwards.destination_port_start = 100;
        backwards.destination_port_end = 50;
        assert_eq!(Rule::from_record(&backwards), Err(Error::InvalidArgument));

        let mut direction = any_rule();
        direction.direction = 9;
        assert_eq!(Rule::from_record(&direction), Err(Error::InvalidArgument));

        let mut flag = any_rule();
        flag.reserved = 1;
        assert_eq!(Rule::from_record(&flag), Err(Error::InvalidArgument));

        assert!(filter.is_empty(), "nothing was installed by a refusal");
    }

    /// A range rule matches inside the range and not outside it.
    ///
    /// The ABI's two readings: a zero end is the start as one port, and a
    /// nonzero end is the range's own end.  Both are asserted because a reader
    /// that treated zero as "port zero" would refuse every single-port rule.
    #[test]
    fn a_port_range_matches_inside_it() {
        let mut filter = Filter::new();
        let mut record = any_rule();
        record.action = network::FILTER_ACTION_DENY;
        record.destination_port_start = 1000;
        record.destination_port_end = 2000;
        filter
            .add(Rule::from_record(&record).expect("a rule"))
            .unwrap();
        for (port, refused) in [
            (999, false),
            (1000, true),
            (1500, true),
            (2000, true),
            (2001, false),
        ] {
            let verdict = filter.permits(
                Direction::Inbound,
                &packet(crate::ipv4::PROTOCOL_TCP, Some((40000, port))),
                0,
            );
            assert_eq!(!verdict.allowed, refused, "port {port}");
        }

        // A zero end is the start as one port.
        let mut single = Filter::new();
        let mut record = any_rule();
        record.action = network::FILTER_ACTION_DENY;
        record.destination_port_start = 22;
        single
            .add(Rule::from_record(&record).expect("a rule"))
            .unwrap();
        assert!(
            !single
                .permits(
                    Direction::Inbound,
                    &packet(crate::ipv4::PROTOCOL_TCP, Some((1, 22))),
                    0
                )
                .allowed
        );
        assert!(
            single
                .permits(
                    Direction::Inbound,
                    &packet(crate::ipv4::PROTOCOL_TCP, Some((1, 23))),
                    0
                )
                .allowed
        );
    }

    /// The rule and flow bounds refuse rather than grow.
    ///
    /// Both are numbers a program chooses how often to reach, so both are the
    /// kernel holding what a program sent.  The flow bound is asserted by its
    /// **effect on the answer** and not only its count: a full table must still
    /// decide packets correctly.
    #[test]
    fn the_two_bounds_refuse_rather_than_grow() {
        let mut filters = Filter::new();
        for _ in 0..RULE_LIMIT {
            filters
                .add(Rule::from_record(&any_rule()).expect("a rule"))
                .expect("room");
        }
        assert_eq!(filters.len(), RULE_LIMIT);
        assert_eq!(
            filters.add(Rule::from_record(&any_rule()).expect("a rule")),
            Err(Error::Busy)
        );

        // The flow table: filled with `FLOW_LIMIT` distinct flows, and one more
        // is not tracked.  The packet that would have started it is still
        // decided by the rules, which is what the full table costs.
        let mut filter = Filter::new();
        let mut record = any_rule();
        record.stateful = 1;
        filter
            .add(Rule::from_record(&record).expect("a rule"))
            .unwrap();
        for index in 0..FLOW_LIMIT {
            let mut probe = packet(crate::ipv4::PROTOCOL_TCP, Some((index as u16, 80)));
            probe.source = crate::address::Address::V4([10, 0, 2, 2]);
            assert!(filter.permits(Direction::Outbound, &probe, 0).allowed);
        }
        assert_eq!(filter.flows(), FLOW_LIMIT);
        let mut extra = packet(crate::ipv4::PROTOCOL_TCP, Some((1, 81)));
        extra.source = crate::address::Address::V4([192, 0, 2, 1]);
        assert!(
            filter.permits(Direction::Outbound, &extra, 0).allowed,
            "the rule still decides"
        );
        assert_eq!(filter.flows(), FLOW_LIMIT, "and nothing grew");
    }

    /// The default action is a setting, and forgetting flows does not touch
    /// the rules.
    #[test]
    fn the_default_and_the_flows_are_separate_settings() {
        let mut filter = Filter::new();
        let mut record = any_rule();
        record.stateful = 1;
        filter
            .add(Rule::from_record(&record).expect("a rule"))
            .unwrap();
        filter.set_default_action(Action::Deny);
        assert_eq!(filter.default_action(), Action::Deny);

        filter.permits(Direction::Outbound, &packet_toward(80), 0);
        assert_eq!(filter.flows(), 1);
        filter.forget_flows();
        assert_eq!(filter.flows(), 0, "the flows went");
        assert_eq!(filter.len(), 1, "and the rules did not");
    }

    /// A packet toward a port and the packet answering it, as values.
    ///
    /// TCP, because that is what most of the tests are about; the ones that
    /// need another protocol call [`packet_toward_as`].
    fn packet_toward(port: u16) -> Packet {
        packet_toward_as(crate::ipv4::PROTOCOL_TCP, port)
    }

    /// The answer to [`packet_toward`]: the two ends swapped.
    fn packet_from(port: u16) -> Packet {
        packet_from_as(crate::ipv4::PROTOCOL_TCP, port)
    }

    /// A packet of `protocol` toward a port, and the packet answering it.
    fn packet_toward_as(protocol: u8, port: u16) -> Packet {
        Packet {
            source: crate::address::Address::V4([10, 0, 2, 15]),
            destination: crate::address::Address::V4([10, 0, 2, 2]),
            protocol,
            ports: Some((40_000, port)),
        }
    }

    /// See [`packet_toward_as`].
    fn packet_from_as(protocol: u8, port: u16) -> Packet {
        Packet {
            source: crate::address::Address::V4([10, 0, 2, 2]),
            destination: crate::address::Address::V4([10, 0, 2, 15]),
            protocol,
            ports: Some((port, 40_000)),
        }
    }
}
