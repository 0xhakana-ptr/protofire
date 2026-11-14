//! net/src/internet/arp.rs
//!
//! Address Resolution Protocol: who holds this address, and what does it answer
//! with.
//!
//! ## The layout
//!
//! ```text
//! Ethernet  dst[6] src[6] ethertype=0x0806       14 bytes
//! ARP       htype[2] ptype[2] hlen[1] plen[1]
//!           oper[2] sha[6] spa[4] tha[6] tpa[4]  28 bytes
//! ```
//!
//! ## Why ARP is the first protocol here
//!
//! It is the smallest exchange that needs nothing configured: an ARP request is
//! 42 bytes, needs no address assignment, and QEMU's user-mode network answers
//! one for its gateway without being asked to.  So a boot that sends one and
//! reads the answer has exercised the transmit chain, the device's send path,
//! the receive chain and the device's receive path, four things a bring-up
//! cannot reach.
//!
//! ## The cache, and why it does not expire
//!
//! A question the wire answered once should not be asked again, which is what
//! [`Cache`] is for: a fixed table from a protocol address to the hardware
//! address that holds it.  It has no timer, deliberately, an entry that
//! outlives its truth is a wrong delivery, but the conversations this stack
//! carries are minutes long against a cache that lives for a boot, and an
//! expiry the boot never reaches is a timer nobody checks.  A stack that runs
//! for days is the change that adds one, and it adds it here.

use crate::ethernet::BROADCAST;
use crate::ethernet::ETHERTYPE_ARP;
use crate::ethernet::ETHERTYPE_IPV4;
use crate::ethernet::get_u16;
use crate::ethernet::put_u16;
use crate::ethernet::write_header;
use netdev::ETHERNET_HEADER_LEN;

/// The ARP message's length, for an Ethernet and IPv4 pair.
pub const ARP_LEN: usize = 28;

/// The length of a complete ARP frame for Ethernet over IPv4.
pub const ARP_FRAME_LEN: usize = ETHERNET_HEADER_LEN + ARP_LEN;

/// `oper` value 1: a request.
pub const OPER_REQUEST: u16 = 1;

/// `oper` value 2: a reply.
pub const OPER_REPLY: u16 = 2;

/// `htype` value 1: Ethernet hardware.
const HTYPE_ETHERNET: u16 = 1;

/// An ARP message, as this stack reads one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arp {
    /// `oper`: 1 for a request, 2 for a reply.
    pub operation: u16,
    /// `sha`: the sender's hardware address.
    pub sender_hardware: [u8; 6],
    /// `spa`: the sender's protocol address, four bytes as the wire carries it.
    pub sender_protocol: [u8; 4],
    /// `tha`: the target's hardware address.
    pub target_hardware: [u8; 6],
    /// `tpa`: the target's protocol address.
    pub target_protocol: [u8; 4],
}

/// Build an ARP request asking who holds `target_protocol`.
///
/// `source` is this card's address, which the device published; the request is
/// a broadcast because the answer is what the caller does not have.  The
/// sender's hardware field carries `source` so the reply is addressed back to
/// it.
pub fn request(
    source: [u8; 6],
    sender_protocol: [u8; 4],
    target_protocol: [u8; 4],
) -> [u8; ARP_FRAME_LEN] {
    let mut frame = [0_u8; ARP_FRAME_LEN];

    // Ethernet: to everyone, from this card, and it is an ARP.
    write_header(&mut frame, BROADCAST, source, ETHERTYPE_ARP);

    let arp = ETHERNET_HEADER_LEN;
    // htype = Ethernet, ptype = IPv4, hlen = 6, plen = 4.
    put_u16(&mut frame, arp, HTYPE_ETHERNET);
    put_u16(&mut frame, arp + 2, ETHERTYPE_IPV4);
    frame[arp + 4] = 6;
    frame[arp + 5] = 4;
    put_u16(&mut frame, arp + 6, OPER_REQUEST);
    frame[arp + 8..arp + 14].copy_from_slice(&source);
    frame[arp + 14..arp + 18].copy_from_slice(&sender_protocol);
    // The target's hardware address is unknown, which is the question.
    frame[arp + 18..arp + 24].copy_from_slice(&[0; 6]);
    frame[arp + 24..arp + 28].copy_from_slice(&target_protocol);

    frame
}

/// Read the ARP message at the start of an Ethernet frame.
///
/// `None` for anything that is not an Ethernet ARP frame this stack can
/// interpret: a frame shorter than the message, a different ethertype, or an
/// ARP whose own field sizes say it is not Ethernet over IPv4.  Each of those
/// would otherwise be read from offsets that mean something else, and the
/// fields after the mistake would look plausible.
pub fn parse(frame: &[u8]) -> Option<Arp> {
    if frame.len() < ARP_FRAME_LEN {
        return None;
    }
    if get_u16(frame, 12) != ETHERTYPE_ARP {
        return None;
    }
    let arp = ETHERNET_HEADER_LEN;
    if get_u16(frame, arp) != HTYPE_ETHERNET {
        return None;
    }
    if get_u16(frame, arp + 2) != ETHERTYPE_IPV4 {
        return None;
    }
    if frame[arp + 4] != 6 || frame[arp + 5] != 4 {
        return None;
    }

    let mut sender_hardware = [0_u8; 6];
    sender_hardware.copy_from_slice(&frame[arp + 8..arp + 14]);
    let mut sender_protocol = [0_u8; 4];
    sender_protocol.copy_from_slice(&frame[arp + 14..arp + 18]);
    let mut target_hardware = [0_u8; 6];
    target_hardware.copy_from_slice(&frame[arp + 18..arp + 24]);
    let mut target_protocol = [0_u8; 4];
    target_protocol.copy_from_slice(&frame[arp + 24..arp + 28]);

    Some(Arp {
        operation: get_u16(frame, arp + 6),
        sender_hardware,
        sender_protocol,
        target_hardware,
        target_protocol,
    })
}

/// How many answers the cache remembers.
///
/// Eight covers the peers one boot talks to, a gateway, a name server, the
/// hosts a program dials, with room to spare, and a fixed table is one array
/// rather than a growable structure: the cache is checked on every send, and
/// one a caller could grow is one a caller could grow without bound.
pub const CACHE_CAPACITY: usize = 8;

/// One answer the wire gave: who holds a protocol address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Entry {
    protocol: [u8; 4],
    hardware: [u8; 6],
}

/// The answers the wire has given, so the wire is not asked again.
///
/// A pure table: it holds what `learn` was told and answers what it holds.
/// The lock is the caller's, because a cache behind a stack is one field of a
/// state the boot already serialises, and a second lock would be a second
/// order to get wrong.
pub struct Cache {
    entries: [Option<Entry>; CACHE_CAPACITY],
    /// Where the next answer lands when the table is full: the oldest entry's
    /// slot, one past the last that was replaced.
    cursor: usize,
}

impl Cache {
    /// An empty cache: every question goes to the wire.
    pub fn new() -> Self {
        Self {
            entries: [const { None }; CACHE_CAPACITY],
            cursor: 0,
        }
    }

    /// The hardware address that holds `protocol`, if the wire answered for
    /// it before.
    pub fn hardware_for(&self, protocol: [u8; 4]) -> Option<[u8; 6]> {
        self.entries
            .iter()
            .flatten()
            .find(|entry| entry.protocol == protocol)
            .map(|entry| entry.hardware)
    }

    /// Record an answer the wire gave, replacing what it said before.
    ///
    /// A repeated answer for an address already held updates that entry in
    /// place, a sender that changed its hardware address is a fact the cache
    /// should follow, not a second entry for one address.  A full table
    /// replaces the slot the cursor names and moves past it, which is the
    /// oldest entry's slot by construction: every entry between the cursor
    /// and the newest was written later than the one under it.
    pub fn learn(&mut self, protocol: [u8; 4], hardware: [u8; 6]) {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .flatten()
            .find(|entry| entry.protocol == protocol)
        {
            entry.hardware = hardware;
            return;
        }
        let slot = self
            .entries
            .get_mut(self.cursor)
            .expect("the cursor stays inside the table");
        *slot = Some(Entry { protocol, hardware });
        self.cursor = (self.cursor + 1) % CACHE_CAPACITY;
    }

    /// How many answers the cache holds.
    pub fn len(&self) -> usize {
        self.entries.iter().flatten().count()
    }

    /// Whether the cache holds nothing.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for Cache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::ARP_FRAME_LEN;
    use super::ARP_LEN;
    use super::Cache;
    use super::OPER_REPLY;
    use super::OPER_REQUEST;
    use super::parse;
    use super::request;
    use crate::ethernet::BROADCAST;
    use netdev::ETHERNET_HEADER_LEN;

    const CARD: [u8; 6] = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
    const US: [u8; 4] = [10, 0, 2, 15];
    const GATEWAY: [u8; 4] = [10, 0, 2, 2];
    const GATEWAY_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];

    /// The request is the bytes an ARP for the gateway is, at every offset a
    /// reader would check.
    ///
    /// The frame is compared whole rather than field by field because that is
    /// what the wire carries: a writer that used the host's byte order produces
    /// a frame that is wrong in a way a per-field read back through the same
    /// wrong order would agree with.
    #[test]
    fn the_request_is_the_frame_the_wire_carries() {
        let request = request(CARD, US, GATEWAY);
        assert_eq!(request.len(), 42, "the smallest ARP frame");
        assert_eq!(
            request,
            [
                // dst: everyone.
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // src
                0x02, 0x11, 0x22, 0x33, 0x44, 0x55, // ethertype: ARP, big-endian.
                0x08, 0x06, // htype = 1, big-endian.
                0x00, 0x01, // ptype = IPv4, big-endian.
                0x08, 0x00, // hlen = 6, plen = 4.
                0x06, 0x04, // oper = 1 (request), big-endian.
                0x00, 0x01, // sha
                0x02, 0x11, 0x22, 0x33, 0x44, 0x55, // spa = 10.0.2.15, in wire order.
                0x0A, 0x00, 0x02, 0x0F, // tha: unknown
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // tpa = 10.0.2.2
                0x0A, 0x00, 0x02, 0x02,
            ]
        );
    }

    /// The offsets the structure puts each field at are the ones used.
    #[test]
    fn the_offsets_are_the_structures() {
        assert_eq!(ETHERNET_HEADER_LEN, 14);
        assert_eq!(ARP_LEN, 28);
        assert_eq!(ARP_FRAME_LEN, 42);
        assert_eq!(BROADCAST, [0xFF; 6]);
    }

    /// The request parses back as the message it is.
    #[test]
    fn a_request_parses_back() {
        let parsed = parse(&request(CARD, US, GATEWAY)).expect("an ARP frame");
        assert_eq!(parsed.operation, OPER_REQUEST);
        assert_eq!(parsed.sender_hardware, CARD);
        assert_eq!(parsed.sender_protocol, US);
        assert_eq!(parsed.target_hardware, [0; 6], "the question is the target");
        assert_eq!(parsed.target_protocol, GATEWAY);
    }

    /// A reply's fields land where the structure says.
    ///
    /// Written here as a device would, rather than by this module's own
    /// builder, so the parser is checked against the layout rather than against
    /// itself.
    #[test]
    fn a_reply_parses() {
        let mut frame = request(CARD, US, GATEWAY);
        // Turn it into the answer: from the gateway, to the card, oper 2.
        frame[0..6].copy_from_slice(&CARD);
        frame[6..12].copy_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        frame[20..22].copy_from_slice(&OPER_REPLY.to_be_bytes());
        frame[22..28].copy_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        frame[28..32].copy_from_slice(&GATEWAY);
        frame[32..38].copy_from_slice(&CARD);
        frame[38..42].copy_from_slice(&US);

        let parsed = parse(&frame).expect("an ARP frame");
        assert_eq!(parsed.operation, OPER_REPLY);
        assert_eq!(
            parsed.sender_hardware,
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
            "the gateway's address is what the request asked for"
        );
        assert_eq!(parsed.sender_protocol, GATEWAY);
        assert_eq!(parsed.target_hardware, CARD);
        assert_eq!(parsed.target_protocol, US);
    }

    /// A frame this stack cannot interpret is refused rather than read at the
    /// wrong offsets.
    #[test]
    fn a_frame_that_is_not_ethernet_over_ipv4_arp_is_refused() {
        let request = request(CARD, US, GATEWAY);

        assert!(parse(&request[..ARP_FRAME_LEN - 1]).is_none(), "short");

        let mut wrong_type = request;
        wrong_type[12..14].copy_from_slice(&0x0800u16.to_be_bytes());
        assert!(parse(&wrong_type).is_none(), "not an ARP");

        let mut wrong_hardware = request;
        wrong_hardware[18] = 8;
        assert!(parse(&wrong_hardware).is_none(), "not an Ethernet address");

        let mut wrong_protocol = request;
        wrong_protocol[19] = 16;
        assert!(parse(&wrong_protocol).is_none(), "not an IPv4 address");

        let mut wrong_htype = request;
        wrong_htype[14..16].copy_from_slice(&6u16.to_be_bytes());
        assert!(parse(&wrong_htype).is_none(), "not Ethernet hardware");

        let mut wrong_ptype = request;
        wrong_ptype[16..18].copy_from_slice(&0x86DDu16.to_be_bytes());
        assert!(parse(&wrong_ptype).is_none(), "not an IPv4 protocol");
    }

    /// A buffer longer than the frame parses from its start, which is what a
    /// receive buffer holds: the frame, then whatever else the buffer had.
    #[test]
    fn a_longer_buffer_parses_from_the_start() {
        let mut buffer = [0xAA_u8; 128];
        buffer[..ARP_FRAME_LEN].copy_from_slice(&request(CARD, US, GATEWAY));
        let parsed = parse(&buffer).expect("the frame is at the start");
        assert_eq!(parsed.sender_protocol, US);
    }

    /// An empty cache answers nothing, which is what sends the first
    /// question to the wire.
    #[test]
    fn an_empty_cache_answers_nothing() {
        let cache = Cache::new();
        assert!(cache.is_empty());
        assert_eq!(cache.hardware_for(GATEWAY), None);
    }

    /// An answer the wire gave is what the cache holds, and the second ask
    /// never needs the wire.
    #[test]
    fn an_answered_question_is_not_asked_again() {
        let mut cache = Cache::new();
        assert_eq!(cache.hardware_for(GATEWAY), None, "the first ask misses");
        cache.learn(GATEWAY, GATEWAY_MAC);
        assert_eq!(cache.len(), 1);
        assert_eq!(
            cache.hardware_for(GATEWAY),
            Some(GATEWAY_MAC),
            "the second ask answers from the table"
        );
    }

    /// A new answer for an address already held replaces it, and leaves one
    /// entry, not two.
    #[test]
    fn a_repeated_answer_replaces_its_entry() {
        let mut cache = Cache::new();
        cache.learn(GATEWAY, [0x11; 6]);
        cache.learn(GATEWAY, GATEWAY_MAC);
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.hardware_for(GATEWAY), Some(GATEWAY_MAC));
    }

    /// A full cache forgets its oldest answer, and keeps the rest.
    ///
    /// The table is fixed because it is checked on every send; the eviction
    /// is the whole cost of that.  The cursor replaces in insertion order,
    /// so the entry that has been there longest is the one that goes.
    #[test]
    fn a_full_cache_forgots_its_oldest_answer() {
        let mut cache = Cache::new();
        for index in 0..CACHE_CAPACITY_TEST as u32 {
            cache.learn([10, 0, 2, index as u8], [index as u8; 6]);
        }
        assert_eq!(cache.len(), CACHE_CAPACITY_TEST);

        // One more: the first address goes, the second stays.
        cache.learn([10, 0, 2, 200], [0xEE; 6]);
        assert_eq!(cache.len(), CACHE_CAPACITY_TEST, "the table does not grow");
        assert_eq!(cache.hardware_for([10, 0, 2, 0]), None, "the oldest went");
        assert_eq!(cache.hardware_for([10, 0, 2, 1]), Some([1_u8; 6]));
        assert_eq!(cache.hardware_for([10, 0, 2, 200]), Some([0xEE; 6]));
    }

    /// The cache's capacity, spelled as a constant the tests compile against.
    const CACHE_CAPACITY_TEST: usize = super::CACHE_CAPACITY;
}
