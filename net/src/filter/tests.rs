//! net/src/filter/tests.rs
//!
//! The module's tests.
//!
//! A sibling file because the tests outgrew the module: a reader looking for
//! the mechanism should not scroll past them to find the end of it.

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
/// This is the test an `enabled` flag would have made unable to fail: with
/// that flag in the condition and nothing setting it, the rule walk never
/// runs and this packet is allowed.  Asserting the rule's effect with
/// nothing else turned on is what holds the absence of the flag.
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
