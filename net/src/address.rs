//! net/src/address.rs
//!
//! One address, of either family, and the family it is.
//!
//! ## Why a type and not two
//!
//! A transport and a socket table hold an address they did not build: the
//! peer of a stream, the sender of a datagram.  Before this module those were
//! `[u8; 4]` everywhere, which meant the tables could only ever describe an
//! IPv4 machine, the one place the stack was not dual-stack was its state,
//! not its parsers.
//!
//! [`Address`] is that state's type.  It carries the family with the bytes, so
//! a table keyed on it cannot confuse `10.0.2.2` with a sixteen-byte address
//! whose first four bytes happen to match, and a caller that has to put one on
//! a wire asks the family rather than assuming it.
//!
//! ## What it deliberately is not
//!
//! An address is not a scope, a prefix or a route.  Which address is this
//! machine's, and whether one is reachable from another, are questions about a
//! boot's interface, the kernel's.  This is the bytes and the length, which
//! is all a state machine and a socket key need.

use crate::ipv6;

/// Which family an [`Address`] is.
///
/// A separate type rather than a `bool`, because the two families differ in
/// far more than a length: a pseudo-header, a frame's ethertype, whether a
/// destination is a group, and how an address prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Family {
    /// Four bytes: IPv4.
    V4,
    /// Sixteen bytes: IPv6.
    V6,
}

impl Family {
    /// How many bytes an address of this family is.
    pub const fn length(self) -> usize {
        match self {
            Self::V4 => 4,
            Self::V6 => 16,
        }
    }

    /// The ethertype a frame carrying this family's packet names.
    pub const fn ethertype(self) -> u16 {
        match self {
            Self::V4 => crate::ethernet::ETHERTYPE_IPV4,
            Self::V6 => crate::ethernet::ETHERTYPE_IPV6,
        }
    }
}

/// An address, with the family that says how to read its bytes.
///
/// [`Address::V6`] is boxed in nothing and allocated by nothing: sixteen bytes
/// inline is what an address is, and a table of thirty of them is under six
/// hundred bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Address {
    /// An IPv4 address, as the wire carries it.
    V4([u8; 4]),
    /// An IPv6 address, as the wire carries it.
    V6([u8; 16]),
}

impl Address {
    /// The family of this address.
    pub const fn family(self) -> Family {
        match self {
            Self::V4(_) => Family::V4,
            Self::V6(_) => Family::V6,
        }
    }

    /// The four bytes, when this is an IPv4 address.
    pub const fn as_v4(self) -> Option<[u8; 4]> {
        match self {
            Self::V4(bytes) => Some(bytes),
            Self::V6(_) => None,
        }
    }

    /// The sixteen bytes, when this is an IPv6 address.
    pub const fn as_v6(self) -> Option<[u8; 16]> {
        match self {
            Self::V4(_) => None,
            Self::V6(bytes) => Some(bytes),
        }
    }

    /// Whether this address names a group rather than one node.
    ///
    /// IPv4's multicast range is `224.0.0.0/4`; IPv6's is `ff00::/8`.  A
    /// caller that has a table entry for a group has a bug rather than a
    /// neighbour, which is why the predicate is here and not at each caller.
    pub fn is_multicast(self) -> bool {
        match self {
            Self::V4(bytes) => bytes[0] & 0xF0 == 0xE0,
            Self::V6(bytes) => ipv6::is_multicast(bytes),
        }
    }

    /// The same address, as the sixteen bytes an IPv6 writer needs.
    ///
    /// `None` for an IPv4 address: the families do not convert, and a
    /// function that made an IPv4 address look like an IPv6 one would be
    /// inventing a mapping the wire does not have.
    pub const fn to_v6(self) -> Option<[u8; 16]> {
        self.as_v6()
    }
}

impl From<[u8; 4]> for Address {
    fn from(bytes: [u8; 4]) -> Self {
        Self::V4(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::Address;
    use super::Family;

    const V4: [u8; 4] = [10, 0, 2, 15];
    const V6: [u8; 16] = [
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x54, 0, 0xff, 0xfe, 0x12, 0x34, 0x56,
    ];

    /// The family travels with the bytes, which is the whole reason the type
    /// exists: two addresses whose first four bytes agree are still different
    /// addresses.
    #[test]
    fn the_family_travels_with_the_bytes() {
        let four = Address::V4(V4);
        let sixteen = Address::V6(V6);
        assert_eq!(four.family(), Family::V4);
        assert_eq!(sixteen.family(), Family::V6);
        assert_ne!(
            four, sixteen,
            "the same leading bytes are not the same address"
        );
        assert_eq!(four.as_v4(), Some(V4));
        assert_eq!(four.as_v6(), None);
        assert_eq!(sixteen.as_v6(), Some(V6));
        assert_eq!(sixteen.as_v4(), None);
    }

    /// A family knows how long its address is and which ethertype carries it,
    /// because those are the two things a caller that has to write a frame
    /// asks and must not guess.
    #[test]
    fn a_family_knows_its_length_and_ethertype() {
        assert_eq!(Family::V4.length(), 4);
        assert_eq!(Family::V6.length(), 16);
        assert_eq!(Family::V4.ethertype(), crate::ethernet::ETHERTYPE_IPV4);
        assert_eq!(Family::V6.ethertype(), crate::ethernet::ETHERTYPE_IPV6);
    }

    /// Multicast is a range in each family, and a table that holds a group
    /// entry is holding a bug.
    #[test]
    fn multicast_is_a_range_in_each_family() {
        assert!(Address::V4([224, 0, 0, 1]).is_multicast());
        assert!(Address::V4([239, 255, 255, 255]).is_multicast());
        assert!(!Address::V4([223, 255, 255, 255]).is_multicast());
        assert!(!Address::V4([240, 0, 0, 1]).is_multicast());

        assert!(Address::V6([0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]).is_multicast());
        assert!(!Address::V6(V6).is_multicast());
    }

    /// The families do not convert: an IPv4 address has no sixteen-byte form,
    /// and a function that made one would be inventing a mapping.
    #[test]
    fn the_families_do_not_convert() {
        assert_eq!(Address::V4(V4).to_v6(), None);
        assert_eq!(Address::V6(V6).to_v6(), Some(V6));
        assert_eq!(Address::from(V4), Address::V4(V4));
    }

    /// A table keyed on an address orders and hashes it, which is what makes
    /// one usable as a map key without a second representation.
    #[test]
    fn an_address_is_a_key() {
        use alloc::collections::BTreeSet;
        let mut set = BTreeSet::new();
        set.insert(Address::V4(V4));
        set.insert(Address::V6(V6));
        set.insert(Address::V4(V4));
        assert_eq!(set.len(), 2, "the repeat was the same key");
    }
}
