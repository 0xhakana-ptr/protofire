//! net/src/route.rs
//!
//! Which next hop a destination goes to: the prefixes a machine knows, the
//! gateway each one names, and the rule that the longest match wins.
//!
//! ## Why a table and not a gateway
//!
//! This stack had one IPv4 gateway and one IPv6 default router, and both were
//! fields on the interface.  That is a table with one entry, and it is enough
//! for a machine on one link with one way out.  It stops being enough the
//! moment a machine has two: a host that reaches a second subnet through a
//! second router, a link with a router that routes only part of the address
//! space, or a boot whose DHCP server hands out a route that is not the
//! default one.
//!
//! What replaces them is the same arithmetic at every size: a route is a
//! **prefix**, a length and a next hop, a destination goes to the route whose
//! prefix is the longest match, and no match is no route.
//!
//! ## What this module deliberately is not
//!
//! It is not a routing **protocol**.  Nothing here learns anything: a route
//! arrives from a configuration (DHCP's router option, a router advertisement)
//! or from a program, and this module holds it and answers lookups.  The
//! protocols that exchange routes are their own stacks, and the numbers they
//! would use are above the frozen range.
//!
//! It is not a metric.  Two routes to one prefix is a second route replacing
//! the first, not two candidates with a cost between them: this machine has one
//! interface and one address per family, and a metric chooses between routes
//! that a single interface cannot have.  The day there are two interfaces,
//! this module gains one field and the lookup gains one comparison, and both
//! are stated here rather than guessed at now.
//!
//! ## The two families, in one table
//!
//! A route carries an [`Address`], which carries its family, so one table
//! holds both.  A lookup asks with an address of either family and matches only
//! routes of that family: the two address spaces overlap in no bit, and a table
//! that compared a sixteen-byte address against a four-byte prefix would be
//! comparing two different things with one rule.

use alloc::vec::Vec;

use crate::address::Address;

/// One route: a prefix, how many of its bits are the network's, and a next hop.
///
/// A next hop that is **absent** means the destination is on the link: the
/// frame goes to the destination's own hardware address, and the neighbour
/// protocol is asked about the destination rather than about a router.  That is
/// what a directly connected subnet is, and it is the case a table of gateways
/// could not express at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// The destination network, with the bits past the prefix zeroed.
    pub prefix: Address,
    /// How many leading bits of `prefix` are the network's.
    pub length: u8,
    /// The next hop, when the destination is not on the link.
    pub gateway: Option<Address>,
}

impl Route {
    /// Whether `destination` is inside this route's prefix.
    ///
    /// The comparison is on the **leading bits only**, which is what a prefix
    /// is: a route to `10.0.0.0/8` owns every address whose first eight bits
    /// are `10`, and comparing all thirty-two would make it own exactly one
    /// address and describe nothing.
    ///
    /// A route of length zero owns everything of its family, which is a default
    /// route and not a mistake: `/0` is how "everything else" is written.
    pub fn covers(&self, destination: Address) -> bool {
        match (self.prefix, destination) {
            (Address::V4(prefix), Address::V4(destination)) => {
                prefix_bits(&prefix, &destination, self.length as usize)
            }
            (Address::V6(prefix), Address::V6(destination)) => {
                prefix_bits(&prefix, &destination, self.length as usize)
            }
            // A route of one family does not cover an address of the other.
            // The two are different lengths and different meanings, and a
            // comparison across them would be a rule with no subject.
            _ => false,
        }
    }

    /// The next hop for a destination this route covers.
    ///
    /// `None` is "on the link": the caller sends to the destination itself.
    /// A route with no gateway is a connected subnet, and that is a value and
    /// not an error.
    pub fn next_hop(&self, destination: Address) -> Option<Address> {
        if !self.covers(destination) {
            return None;
        }
        self.gateway
    }
}

/// Whether the first `length` bits of `prefix` and `destination` are equal.
///
/// The last byte is `length % 8` bits, and a mask of those bits must be the
/// `length`-th bit position's; a whole-byte comparison would make a `/20` own
/// its last four bits too, which is a route that claims more than it states.
pub(crate) fn prefix_bits(prefix: &[u8], destination: &[u8], length: usize) -> bool {
    if length > prefix.len() * 8 {
        return false;
    }
    let whole = length / 8;
    if prefix[..whole] != destination[..whole] {
        return false;
    }
    let rest = length % 8;
    if rest == 0 {
        return true;
    }
    // The mask keeps the high `rest` bits of the byte and clears the rest, so
    // the two bytes agree exactly on the bits the prefix names.
    let mask = 0xFF_u8 << (8 - rest);
    prefix[whole] & mask == destination[whole] & mask
}

/// The routes one machine holds, and the lookup over them.
///
/// A value, with no lock: the kernel holds it behind its own, the way it holds
/// [`crate::tcp_table::Table`].  Ordered by nothing in particular, because the
/// lookup is a longest-match and not a walk in a fixed order: a table that
/// relied on its order would be a table a second route could break.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Table {
    routes: Vec<Route>,
}

impl Table {
    /// An empty table: a machine with no route reaches nothing.
    pub const fn new() -> Self {
        Self { routes: Vec::new() }
    }

    /// Add a route, replacing one to the same prefix if there is one.
    ///
    /// Answers whether it replaced something, which is what a boot's line can
    /// report: a second statement about one prefix is a configuration changing
    /// its mind, and saying so is cheaper than a reader guessing.
    ///
    /// The same prefix **and** the same gateway length is the same route: a
    /// table that kept both would have one lookup answer two ways, which is
    /// the ambiguity a longest-match cannot resolve because the two match
    /// equally.
    ///
    /// The prefix's bits past `length` are **not** cleared here.  A caller that
    /// passed `10.1.2.3/8` meant `10.0.0.0/8`, and the comparison does not
    /// care, because it looks only at the first eight bits.  A table that
    /// rewrote its input would be a table whose entries no longer matched what
    /// its caller asked about.
    pub fn add(&mut self, route: Route) -> bool {
        if let Some(existing) = self
            .routes
            .iter_mut()
            .find(|candidate| candidate.prefix == route.prefix && candidate.length == route.length)
        {
            *existing = route;
            return true;
        }
        self.routes.push(route);
        false
    }

    /// Remove the route to a prefix, answering whether one was there.
    pub fn remove(&mut self, prefix: Address, length: u8) -> bool {
        let before = self.routes.len();
        self.routes
            .retain(|route| !(route.prefix == prefix && route.length == length));
        self.routes.len() != before
    }

    /// The next hop for `destination`, or `None` when no route covers it.
    ///
    /// The longest match wins, which is the whole of the lookup: a route to
    /// `10.0.0.0/8` and one to `10.1.0.0/16` both cover `10.1.2.3`, and the
    /// more specific one is the one that knows about that subnet.  A default
    /// route is length zero, so it loses to every other match by construction
    /// and needs no special case.
    ///
    /// The answer distinguishes three things a caller must not confuse: `Some`
    /// with a gateway is "send it there", `Some` with no gateway is "it is on
    /// this link, ask the neighbour about the destination itself", and `None`
    /// is "no route", which is a destination this machine cannot reach.
    pub fn next_hop(&self, destination: Address) -> Option<Option<Address>> {
        self.routes
            .iter()
            .filter(|route| route.covers(destination))
            .max_by_key(|route| route.length)
            .map(|route| route.gateway)
    }

    /// The route a destination resolves to, for a caller that wants the entry
    /// and not only its next hop.
    pub fn route_for(&self, destination: Address) -> Option<&Route> {
        self.routes
            .iter()
            .filter(|route| route.covers(destination))
            .max_by_key(|route| route.length)
    }

    /// Every route, in the order they were added, for a boot's own report.
    pub fn routes(&self) -> &[Route] {
        &self.routes
    }

    /// How many routes are held.
    pub fn len(&self) -> usize {
        self.routes.len()
    }

    /// Whether nothing is held.
    pub fn is_empty(&self) -> bool {
        self.routes.is_empty()
    }
}

/// A default route: everything of this family goes to `gateway`.
///
/// `/0`, which [`Route::covers`] makes own every address of its family and
/// [`Table::next_hop`] makes lose to every more specific route.  It is a
/// function rather than a struct literal because the two fields that matter are
/// the length and the gateway, and a caller that wrote the prefix as the
/// gateway's own address would have a route that looks like a host route and
/// behaves like a default.
pub fn default_via(gateway: Address) -> Route {
    Route {
        prefix: match gateway {
            Address::V4(_) => Address::V4([0; 4]),
            Address::V6(_) => Address::V6([0; 16]),
        },
        length: 0,
        gateway: Some(gateway),
    }
}

/// A directly connected network: everything in `prefix`/`length` is on the
/// link.
///
/// No gateway, because there is none to name: the frame goes to the
/// destination's own hardware address.
pub fn connected(prefix: Address, length: u8) -> Route {
    Route {
        prefix,
        length,
        gateway: None,
    }
}

#[cfg(test)]
mod tests {
    use super::Route;
    use super::Table;
    use super::connected;
    use super::default_via;
    use crate::address::Address;

    const GATEWAY: Address = Address::V4([10, 0, 2, 2]);
    const OTHER_GATEWAY: Address = Address::V4([10, 0, 3, 1]);

    /// The four cases of a prefix comparison, in one place.
    ///
    /// A whole-byte mask would get the fourth wrong, and a comparison over the
    /// whole address would get the second and third wrong: the first three are
    /// inside a `/20`, the fourth is one bit past it.
    #[test]
    fn a_prefix_covers_its_leading_bits_and_nothing_else() {
        let route = connected(Address::V4([10, 1, 0, 0]), 20);

        // `10.1.0.0/20` is ten, then one, then the high four bits of zero:
        // the third byte runs 0x00..0x0F.  A mask over a whole byte would take
        // 0x10 as well, which is a route claiming a subnet it did not name.
        assert!(route.covers(Address::V4([10, 1, 0x00, 0])));
        assert!(route.covers(Address::V4([10, 1, 0x0F, 255])));
        assert!(!route.covers(Address::V4([10, 1, 0x10, 0])));
        assert!(!route.covers(Address::V4([10, 1, 0x20, 0])));
        assert!(!route.covers(Address::V4([10, 2, 0, 0])));

        // And a /20 that does not start on a byte boundary either.
        let mid = connected(Address::V4([172, 16, 0x30, 0]), 20);
        assert!(mid.covers(Address::V4([172, 16, 0x31, 0])), "0x30..0x3F");
        assert!(mid.covers(Address::V4([172, 16, 0x3F, 255])));
        assert!(!mid.covers(Address::V4([172, 16, 0x40, 0])));
    }

    /// A route of one family does not cover an address of the other.
    #[test]
    fn the_two_families_do_not_cover_each_other() {
        let v4 = connected(Address::V4([0, 0, 0, 0]), 0);
        let v6 = Address::V6(crate::ipv6::link_local_from_mac([
            0x52, 0x54, 0, 0x12, 0x34, 0x56,
        ]));
        assert!(!v4.covers(v6), "a /0 of IPv4 owns no IPv6 address");
        assert!(v4.covers(Address::V4([192, 0, 2, 1])), "but every IPv4 one");
    }

    /// A default route covers everything of its family and loses to anything
    /// more specific.
    ///
    /// The property that makes `/0` a default rather than a special case.
    #[test]
    fn a_default_route_is_the_shortest_match() {
        let mut table = Table::new();
        assert_eq!(table.next_hop(Address::V4([8, 8, 8, 8])), None, "no route");

        table.add(default_via(GATEWAY));
        assert_eq!(
            table.next_hop(Address::V4([8, 8, 8, 8])),
            Some(Some(GATEWAY))
        );

        table.add(connected(Address::V4([10, 1, 0, 0]), 16));
        assert_eq!(
            table.next_hop(Address::V4([10, 1, 2, 3])),
            Some(None),
            "the /16 is on the link, and the default does not apply"
        );
        assert_eq!(
            table.next_hop(Address::V4([8, 8, 8, 8])),
            Some(Some(GATEWAY)),
            "and the default still holds for everything else"
        );
    }

    /// The longest match wins, and it is the length that decides and not the
    /// order they were added in.
    #[test]
    fn the_longest_match_wins_whatever_the_order() {
        for reversed in [false, true] {
            let mut table = Table::new();
            let broad = Route {
                prefix: Address::V4([10, 0, 0, 0]),
                length: 8,
                gateway: Some(GATEWAY),
            };
            let narrow = Route {
                prefix: Address::V4([10, 1, 0, 0]),
                length: 16,
                gateway: Some(OTHER_GATEWAY),
            };
            if reversed {
                table.add(narrow);
                table.add(broad);
            } else {
                table.add(broad);
                table.add(narrow);
            }
            assert_eq!(
                table.next_hop(Address::V4([10, 1, 2, 3])),
                Some(Some(OTHER_GATEWAY)),
                "the /16 knows about that subnet"
            );
            assert_eq!(
                table.next_hop(Address::V4([10, 2, 2, 3])),
                Some(Some(GATEWAY)),
                "and the /8 covers the rest"
            );
        }
    }

    /// A second route to one prefix replaces the first and says so.
    ///
    /// The ambiguity a longest match cannot resolve: two routes that match
    /// equally, and a lookup that answered one of them by list order would be
    /// answering by accident.
    #[test]
    fn a_second_route_to_one_prefix_replaces_it() {
        let mut table = Table::new();
        assert!(!table.add(default_via(GATEWAY)), "the first");
        assert!(table.add(default_via(OTHER_GATEWAY)), "the second replaces");
        assert_eq!(table.len(), 1, "and there is still one");
        assert_eq!(
            table.next_hop(Address::V4([8, 8, 8, 8])),
            Some(Some(OTHER_GATEWAY))
        );

        // Two routes that differ in length are two routes.
        assert!(!table.add(connected(Address::V4([10, 0, 0, 0]), 8)));
        assert_eq!(table.len(), 2);
    }

    /// A route can be removed, and removing one that is not there says so.
    #[test]
    fn a_route_can_be_removed() {
        let mut table = Table::new();
        table.add(default_via(GATEWAY));
        assert!(table.remove(Address::V4([0; 4]), 0));
        assert!(table.is_empty());
        assert!(!table.remove(Address::V4([0; 4]), 0), "nothing to remove");
    }

    /// A default route's prefix is the zero address and not its gateway's.
    ///
    /// The mistake this prevents: a caller writing the gateway into the prefix
    /// field gets a route that looks like a host route and behaves like a
    /// default, which is two descriptions of one entry that disagree.
    #[test]
    fn a_default_route_has_no_prefix_of_its_own() {
        let route = default_via(GATEWAY);
        assert_eq!(route.length, 0);
        assert_eq!(route.prefix, Address::V4([0; 4]));
        assert_ne!(route.prefix, GATEWAY);
        assert_eq!(route.gateway, Some(GATEWAY));
        assert!(route.covers(Address::V4([1, 2, 3, 4])));
    }

    /// An IPv6 route matches by its own bits, and a `/64` is a whole half.
    #[test]
    fn an_ipv6_route_matches_its_prefix() {
        // Two link-local addresses share their first sixty-four bits: the
        // `fe80::` prefix is the same for both, and what differs is the
        // interface identifier, which a `/64` does not name.  So a `/64` route
        // covers **both**, and a `/128` covers one.
        let link = crate::ipv6::link_local_from_mac([0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        let other = crate::ipv6::link_local_from_mac([0x52, 0x55, 0, 0x12, 0x34, 0x57]);
        let route = connected(Address::V6(link), 64);
        assert!(route.covers(Address::V6(link)), "its own address");
        assert!(
            route.covers(Address::V6(other)),
            "and one whose prefix it shares, which is what a /64 means"
        );

        let host = connected(Address::V6(link), 128);
        assert!(host.covers(Address::V6(link)));
        assert!(
            !host.covers(Address::V6(other)),
            "a /128 is one address and not the prefix"
        );

        // A route with a zero length covers both, being that family's default.
        let everything = connected(Address::V6([0_u8; 16]), 0);
        assert!(everything.covers(Address::V6(link)));
        assert!(everything.covers(Address::V6(other)));
    }

    /// A length past its family's width covers nothing.
    ///
    /// A `/33` on IPv4 is a route whose prefix is longer than an address, which
    /// is a caller's error and not a route: matching it against anything would
    /// read past the address's end.
    #[test]
    fn a_length_past_the_address_covers_nothing() {
        let route = connected(Address::V4([10, 0, 0, 0]), 33);
        assert!(!route.covers(Address::V4([10, 0, 0, 0])));
        let route6 = connected(Address::V6([0_u8; 16]), 129);
        assert!(!route6.covers(Address::V4([10, 0, 0, 0])));
    }
}
