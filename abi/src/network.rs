//! abi/src/network.rs
//!
//! The wire shape of what a program may ask the kernel about the network:
//! whether a card is up, and the addresses it answers for.
//!
//! ## What is deliberately not here
//!
//! Socket records, port sets, the address families a fuller stack would
//! name.  They arrive with the calls they answer, in the changes that serve
//! those calls, a record the kernel does not fill is a promise about a
//! machine state nothing observes, and this crate does not make those.

use core::mem::offset_of;
use core::mem::size_of;

/// The state word a `NetworkStatusRecord` carries for a card the kernel
/// drives.
pub const NETWORK_STATUS_UP: usize = 1;

/// How many bytes of addresses the record carries: the card's hardware
/// address in six, its protocol address in four, and the gateway's in four
/// packed in that order, as the wire carries them.
pub const NETWORK_ADDRESSES_BYTES: usize = 14;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// What the network answers, as `NetworkStatus` fills it.
///
/// One interface, one address, one gateway, which is this build's whole
/// routing table, and the record says so rather than pretending a program
/// asked about a network.  The state word exists because "is a card up" is
/// the question this call exists for; a machine with no card answers the
/// call with `NotFound` rather than a record that says `DOWN`, because a
/// record implies addresses and a machine with no card has none.
pub struct NetworkStatusRecord {
    /// Whether the card is up: [`NETWORK_STATUS_UP`].
    pub state: usize,
    /// The three addresses, packed: hardware, protocol, gateway.
    pub addresses: [u8; NETWORK_ADDRESSES_BYTES],
}

impl NetworkStatusRecord {
    /// The record for an interface the kernel drives.
    pub fn new(state: usize, hardware: [u8; 6], protocol: [u8; 4], gateway: [u8; 4]) -> Self {
        let mut addresses = [0_u8; NETWORK_ADDRESSES_BYTES];
        addresses[0..6].copy_from_slice(&hardware);
        addresses[6..10].copy_from_slice(&protocol);
        addresses[10..14].copy_from_slice(&gateway);
        Self { state, addresses }
    }
}

pub const NETWORK_STATUS_SIZE: usize = size_of::<NetworkStatusRecord>();

/// Where a datagram came from, as `RecvFromUdp` answers it: a word of
/// address and a word of port.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpSenderRecord {
    /// The sender's protocol address, packed by [`pack_address`].
    pub address: usize,
    /// The sender's port, as the datagram's header carried it.
    pub port: usize,
}

/// What `Ipv6Status` answers: the interface's link-local address, whether a
/// router configured a global one, and the two counters a boot's own
/// exchanges leave.
///
/// The addresses are sixteen bytes each and the record is `repr(C)`, so a
/// program reads them at the offsets this crate names rather than assuming
/// an alignment.  `has_global` is a word rather than a byte because every
/// field here is a word: a record a program reads by pointer wants its
/// fields where the compiler puts them, and a mixed-width struct is a layout
/// two languages can disagree about.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6StatusRecord {
    /// Whether the interface has an IPv6 side at all: 1 when it does.
    ///
    /// A card the kernel drives always does, the link-local address is the
    /// MAC's by EUI-64 and needs nothing from the wire, but the field is
    /// here so a program can tell "no card" from "a card with no address",
    /// which are different answers.
    pub state: usize,
    /// Whether a router configured a global address: 1 when one has.
    pub has_global: usize,
    /// How many neighbours the cache holds, reachable and stale together.
    ///
    /// Incomplete entries are not counted: a question with no answer is not
    /// a neighbour, and a program that read the count as "nodes I can send
    /// to" would be wrong by exactly the entries that cannot be sent to.
    pub neighbours: usize,
    /// The link-local address, sixteen bytes.
    pub link_local: [u8; 16],
    /// The global address, meaningful only when `has_global` is 1.
    pub global: [u8; 16],
}

impl Ipv6StatusRecord {
    /// The record for an interface with a link-local address and no router.
    pub fn new(link_local: [u8; 16], global: Option<[u8; 16]>, neighbours: usize) -> Self {
        Self {
            state: 1,
            has_global: usize::from(global.is_some()),
            neighbours,
            link_local,
            global: global.unwrap_or([0_u8; 16]),
        }
    }
}

pub const IPV6_STATUS_SIZE: usize = size_of::<Ipv6StatusRecord>();
pub const IPV6_STATUS_LINK_LOCAL_OFFSET: usize = offset_of!(Ipv6StatusRecord, link_local);
pub const IPV6_STATUS_GLOBAL_OFFSET: usize = offset_of!(Ipv6StatusRecord, global);
pub const IPV6_STATUS_NEIGHBOURS_OFFSET: usize = offset_of!(Ipv6StatusRecord, neighbours);

pub const UDP_SENDER_RECORD_SIZE: usize = size_of::<UdpSenderRecord>();
pub const UDP_SENDER_ADDRESS_OFFSET: usize = offset_of!(UdpSenderRecord, address);
pub const UDP_SENDER_PORT_OFFSET: usize = offset_of!(UdpSenderRecord, port);

/// Pack an IPv4 address into a word, the first byte in the highest byte of
/// the low word: `10.0.2.2` is `0x0A000202`.
///
/// Both directions live here because the address crosses the boundary as a
/// word, `SendToUdp` carries its destination in one, `RecvFromUdp` answers
/// its sender with one, and a caller that packed it in the host's order
/// would send to `0x0202000A` and call the silence the wire's.
pub const fn pack_address(address: [u8; 4]) -> usize {
    ((address[0] as usize) << 24)
        | ((address[1] as usize) << 16)
        | ((address[2] as usize) << 8)
        | address[3] as usize
}

/// The word [`pack_address`] made, back as the four bytes the wire carries.
pub const fn unpack_address(word: usize) -> [u8; 4] {
    [
        (word >> 24) as u8,
        (word >> 16) as u8,
        (word >> 8) as u8,
        word as u8,
    ]
}

/// The flag that makes a datagram call carry a sixteen-byte address.
///
/// ## Why a flag and not a second number
///
/// `SendToUdp` and `RecvFromUdp` are below 120, so their semantics and their
/// layout are frozen.  A flag is what the frozen rule permits: a caller that
/// passes zero behaves exactly as it did before this constant existed, and a
/// caller that passes the bit opts into the wider shape.  The alternative, a
/// `SendToUdp6` beside each call, would have spent numbers from the
/// experimental range to say something the flags word already had room for,
/// and left two spellings of one operation to keep in step.
///
/// ## What each call means when the bit is set
///
/// - **`SendToUdp`**, `a1` is a **pointer** to sixteen bytes of IPv6 address in
///   the caller's memory, not a packed IPv4 word.  When it is a pointer the
///   call reads the address before it builds anything, so a refused address is
///   refused before a frame exists.
/// - **`RecvFromUdp`**, the sender record is [`UDP_SENDER6_RECORD_SIZE`] bytes
///   and its address field is a pointer-free sixteen bytes at
///   [`UDP_SENDER6_ADDRESS_OFFSET`].  `a4` must be at least that size, which
///   the call checks: a caller that set the bit and passed a two-word record
///   would be asking the kernel to write past the end of it.
///
/// Both bits are the same bit, named twice because the two calls are two calls:
/// a program that sets it on one and not the other is a program whose sends and
/// receives disagree about their family, and the kernel refuses nothing for
/// that, a socket can carry both, and which one a datagram is comes from the
/// address it names.
pub const NETWORK_FLAG_IPV6: usize = 1 << 0;

/// The flags `SendToUdp` knows.
pub const SEND_TO_UDP_KNOWN_FLAGS: usize = NETWORK_FLAG_IPV6;

/// The flags `RecvFromUdp` knows.
pub const RECV_FROM_UDP_KNOWN_FLAGS: usize = NETWORK_FLAG_IPV6;

/// The flags `ConnectTcp` knows.
///
/// `ConnectTcp`'s address is `a0`, and with this bit set it is a **pointer** to
/// sixteen bytes rather than a packed word, the same reading `SendToUdp`
/// gives its `a1`.  `AcceptTcp` needs no flag: an accepted stream's family is
/// the client's, which the connection already knows.
pub const CONNECT_TCP_KNOWN_FLAGS: usize = NETWORK_FLAG_IPV6;

/// Where a datagram came from when its address is sixteen bytes: the address,
/// then the port, each a word, and the address is the sixteen bytes at the
/// offset rather than a packed one.
///
/// `repr(C)` with two pointer-width fields, so a sixteen-byte address does not
/// fit in one word on any machine this tree builds for.  The record is what a
/// caller that set [`NETWORK_FLAG_IPV6`] on `RecvFromUdp` passes, and its size
/// is what `a4` must be at least.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpSender6Record {
    /// The sender's address: sixteen bytes, at
    /// [`UDP_SENDER6_ADDRESS_OFFSET`].
    pub address: [u8; 16],
    /// The sender's port, as the datagram's header carried it.
    pub port: usize,
}

pub const UDP_SENDER6_RECORD_SIZE: usize = size_of::<UdpSender6Record>();
pub const UDP_SENDER6_ADDRESS_OFFSET: usize = offset_of!(UdpSender6Record, address);
pub const UDP_SENDER6_PORT_OFFSET: usize = offset_of!(UdpSender6Record, port);

/// A socket's address, as `GetSockName` and `GetPeerName` write it.
///
/// The layout every program already knows: a family, a port in network order,
/// four address bytes, and eight of padding.  It is sixteen bytes, which is
/// what those calls answer as their return value, and the padding is not
/// slack: a program that read this record as the `sockaddr_in` its own libc
/// defines compares it byte for byte.
///
/// The family is [`SOCKADDR_IN_FAMILY`] for IPv4.  An IPv6 address does not
/// fit and is not what these calls answer, which is why the record names the
/// family it is rather than carrying a union.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockAddrIn {
    /// [`SOCKADDR_IN_FAMILY`].
    pub family: u16,
    /// The port in network byte order, which is what `sockaddr_in` carries.
    pub port: [u8; 2],
    /// The address.
    pub address: [u8; 4],
    /// Eight bytes a program compares against zero.
    pub padding: [u8; 8],
}

/// The family word a `sockaddr_in` carries for IPv4.
///
/// Two, in the host's own byte order: the field is the one part of the record
/// that is not network order, which is the detail a hand-written record gets
/// wrong and a program's `connect` then refuses.
pub const SOCKADDR_IN_FAMILY: u16 = 2;

pub const SOCKADDR_IN_SIZE: usize = size_of::<SockAddrIn>();
pub const SOCKADDR_IN_FAMILY_OFFSET: usize = offset_of!(SockAddrIn, family);
pub const SOCKADDR_IN_PORT_OFFSET: usize = offset_of!(SockAddrIn, port);
pub const SOCKADDR_IN_ADDRESS_OFFSET: usize = offset_of!(SockAddrIn, address);

/// The longest host name this ABI moves in one call.
///
/// `GetHostName`, `SetHostName` and `ResolveHostname` all take or write a name
/// in one buffer, and this is its bound: the longest label a DNS name may
/// carry is sixty-three bytes and the longest name is two hundred and
/// fifty-three, so a buffer larger than that is a caller describing something
/// that is not a name.
pub const HOST_NAME_MAX: usize = 255;

/// The level `SetSockOpt` and `GetSockOpt` name for an option about a socket
/// rather than about the protocol running over it.
///
/// A level is neither an error code nor a syscall number, so it is not frozen
/// the way the syscall range is: it is a number in a field, and the set this
/// build serves is stated here rather than assumed.  `IPPROTO_TCP` is the
/// other level, and is the protocol's own number, where a program did not have
/// to guess.
pub const SOL_SOCKET: u32 = 1;

/// The level a TCP option names: the same number the IP header's protocol
/// field carries, because that is what every caller means by it.
pub const IPPROTO_TCP: u32 = 6;

/// The longest option value these calls move, in bytes.
///
/// Every option this build serves is a word, and a buffer wider than a word
/// holding fewer bytes than it claims is the caller's; the bound is on the
/// buffer rather than on a particular option, because a caller that named the
/// wrong option should be refused for the option and not for its width.
pub const SOCK_OPT_MAX: usize = 8;

/// `SO_RCVBUF`: how many bytes this socket's receive side advertises room for.
///
/// The value is a word, and the effect is the number every segment the socket's
/// stream sends advertises as its window: a program that names a smaller buffer
/// asks the peer to send less, which is the only honest meaning a receive
/// buffer has on a stack that does not grow its inbox.
pub const SO_RCVBUF: u32 = 5;

/// `SO_SNDBUF`: how many unacknowledged bytes this socket may have in flight.
///
/// The value is a word, and the effect is the congestion window: this stack's
/// window is the bytes a write may put on the wire before an acknowledgement,
/// so a program that names a smaller one asks for a slower start.
pub const SO_SNDBUF: u32 = 6;

/// `TCP_NODELAY`: whether a small write may wait for more bytes.
///
/// [`TCP_NODELAY_DISABLED`] is a write held until a segment's worth has
/// accumulated, which is Nagle's rule: a small segment is sent only when there
/// is nothing in flight, so a stream of small writes becomes one segment per
/// round trip rather than one per write.  The value is a byte, and setting a
/// non-zero one sends every write as soon as it is made.
pub const TCP_NODELAY: u32 = 1;

/// `TCP_NODELAY`'s default here: Nagle's rule **on**, so a small write is held
/// until the stream has nothing in flight.
///
/// The default is stated rather than left to whatever zero means, because a
/// program that reads the option back before setting it should learn the rule
/// this stack is actually running, and the alternative, a default of "send at
/// once", is a different protocol behaviour that would also be defensible.
pub const TCP_NODELAY_DISABLED: u8 = 0;

/// What a filter rule does with a packet it matches.
///
/// [`FILTER_ACTION_DENY`] is a **silent** drop: no reset and no unreachable
/// message.  A filter that answered would report its own existence to whoever
/// asked, and which answers come back is most of what a port scan learns.
pub const FILTER_ACTION_ALLOW: u32 = 0;

/// See [`FILTER_ACTION_ALLOW`].
pub const FILTER_ACTION_DENY: u32 = 1;

/// The direction a rule applies to.
///
/// A rule that names one direction matches packets crossing that way and no
/// others.  [`FILTER_DIRECTION_BOTH`] is a value and not a bit mask: the three
/// words are exclusive, and a fourth is refused.
pub const FILTER_DIRECTION_BOTH: u32 = 0;

/// See [`FILTER_DIRECTION_BOTH`].
pub const FILTER_DIRECTION_INBOUND: u32 = 1;

/// See [`FILTER_DIRECTION_BOTH`].
pub const FILTER_DIRECTION_OUTBOUND: u32 = 2;

/// The protocol word that matches any IP protocol number.
///
/// Zero, because no protocol is numbered zero: the value a rule leaves in its
/// protocol field by writing nothing is the value that matches everything,
/// which is the one zero in this record that is not a mistake.
pub const FILTER_PROTOCOL_ANY: u32 = 0;

/// The address family a rule's two prefixes are in.
///
/// The numbers are the IP version's own, which is the number a program already
/// has when it says which family it means.  [`FILTER_FAMILY_ANY`] matches both
/// and requires both prefix lengths to be zero, because a rule that names no
/// family has not said which address space its prefix bits are in.
pub const FILTER_FAMILY_ANY: u32 = 0;

/// See [`FILTER_FAMILY_ANY`].
pub const FILTER_FAMILY_IPV4: u32 = 4;

/// See [`FILTER_FAMILY_ANY`].
pub const FILTER_FAMILY_IPV6: u32 = 6;

/// How many bytes each of a rule's two address fields holds.
///
/// Sixteen, so one record describes a rule in either family: a rule is a
/// **policy**, and a filter that could only express IPv4 rules would be one
/// whose IPv6 traffic took the default action while its author believed the
/// rules covered it.
pub const FILTER_ADDRESS_BYTES: usize = 16;

/// One filter rule, as `FilterAddRule` takes it.
///
/// Twelve words and two sixteen-byte addresses, `repr(C)` with only word-wide
/// fields before the addresses so the layout is the same on every machine this
/// tree builds for.  The addresses are read as the family says: four bytes of
/// an IPv4 address and twelve of zero, or all sixteen of an IPv6 one.
///
/// Every field is a number the caller chose, and the kernel refuses a record
/// whose fields do not describe something a packet could match: a prefix longer
/// than its family's address, a port past sixteen bits, a range written
/// backwards, a direction word nothing defines.  A rule that reached the walk
/// with one of those would decide packets by a comparison its author did not
/// write.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterRuleDef {
    /// [`FILTER_ACTION_ALLOW`] or [`FILTER_ACTION_DENY`].
    pub action: u32,
    /// The IP protocol number, or [`FILTER_PROTOCOL_ANY`].
    pub protocol: u32,
    /// [`FILTER_FAMILY_ANY`], [`FILTER_FAMILY_IPV4`] or [`FILTER_FAMILY_IPV6`].
    pub family: u32,
    /// [`FILTER_DIRECTION_BOTH`], [`FILTER_DIRECTION_INBOUND`] or
    /// [`FILTER_DIRECTION_OUTBOUND`].
    pub direction: u32,
    /// Whether a packet this rule allows leaves a flow its return traffic
    /// finds: zero is stateless, one is stateful.
    pub stateful: u32,
    /// How many leading bits of `source_address` are the network's.
    pub source_prefix: u32,
    /// How many leading bits of `destination_address` are the network's.
    pub destination_prefix: u32,
    /// The source port range's first port, zero for any.
    pub source_port_start: u32,
    /// The source port range's last port, zero for `source_port_start` alone.
    pub source_port_end: u32,
    /// The destination port range's first port, zero for any.
    pub destination_port_start: u32,
    /// The destination port range's last port, zero for the start alone.
    pub destination_port_end: u32,
    /// Reserved, and must be zero.
    ///
    /// A word the record keeps so a later field can arrive without moving the
    /// addresses: the two sixteen-byte fields are the part of this record a
    /// program is most likely to have written by hand, and a field inserted
    /// before them would be a silent misread rather than a failed compile.
    pub reserved: u32,
    /// The source prefix's address, of the family the record names.
    pub source_address: [u8; FILTER_ADDRESS_BYTES],
    /// The destination prefix's address, the same way.
    pub destination_address: [u8; FILTER_ADDRESS_BYTES],
}

pub const FILTER_RULE_DEF_SIZE: usize = size_of::<FilterRuleDef>();

/// Where the source address begins inside a [`FilterRuleDef`].
pub const FILTER_RULE_SOURCE_ADDRESS_OFFSET: usize = offset_of!(FilterRuleDef, source_address);

/// Where the destination address begins inside a [`FilterRuleDef`].
pub const FILTER_RULE_DESTINATION_ADDRESS_OFFSET: usize =
    offset_of!(FilterRuleDef, destination_address);

/// What `FilterGetStats` answers.
///
/// Four words and two counters, in that order: the shape a program reads as a
/// struct.  `packets_allowed` and `packets_dropped` are sixty-four-bit because
/// a filter that has been running for a day has counted more packets than a
/// thirty-two-bit word holds, and a counter that wrapped would report a busy
/// machine as an idle one.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterStats {
    /// The default action: [`FILTER_ACTION_ALLOW`] or
    /// [`FILTER_ACTION_DENY`].
    pub default_action: u32,
    /// How many rules are installed.
    pub rules: u32,
    /// How many flows the tracking table holds.
    pub flows: u32,
    /// Reserved, and must be zero.
    pub reserved: u32,
    /// Packets the filter allowed since the boot.
    pub packets_allowed: u64,
    /// Packets the filter dropped since the boot.
    pub packets_dropped: u64,
}

pub const FILTER_STATS_SIZE: usize = size_of::<FilterStats>();

/// Where the allowed-packet counter begins inside a [`FilterStats`].
///
/// The counters are sixty-four-bit and the four words before them are not, so
/// this offset is also where the record's alignment changes: a program reading
/// the record at the offsets this crate names cannot assume a word stride past
/// it.
pub const FILTER_STATS_ALLOWED_OFFSET: usize = offset_of!(FilterStats, packets_allowed);

/// What a security policy does with a packet.
pub const IPSEC_ACTION_BYPASS: u32 = 0;

/// See [`IPSEC_ACTION_BYPASS`].
pub const IPSEC_ACTION_DISCARD: u32 = 1;

/// See [`IPSEC_ACTION_BYPASS`].
pub const IPSEC_ACTION_PROTECT: u32 = 2;

/// Which packets a security policy is about.
pub const IPSEC_DIR_INBOUND: u32 = 1;

/// See [`IPSEC_DIR_INBOUND`].
pub const IPSEC_DIR_OUTBOUND: u32 = 2;

/// See [`IPSEC_DIR_INBOUND`].
pub const IPSEC_DIR_BOTH: u32 = 3;

/// ESP: the protocol number [RFC 4303] gives it.
///
/// [RFC 4303]: https://www.rfc-editor.org/rfc/rfc4303
pub const IPSEC_PROTO_ESP: u32 = 50;

/// AH: the protocol number [RFC 4302] gives it.
///
/// Named because a caller may set it, and refused when it does: this build
/// serves ESP and no AH, and a refusal at the call is better than an ESP
/// packet a peer's AH policy will drop.
///
/// [RFC 4302]: https://www.rfc-editor.org/rfc/rfc4302
pub const IPSEC_PROTO_AH: u32 = 51;

/// Transport mode: the ESP header goes between the IP header and the payload.
pub const IPSEC_MODE_TRANSPORT: u32 = 0;

/// Tunnel mode: the whole packet is encapsulated.
///
/// Named and refused: it needs a second IP header around the ESP one, which
/// this stack's senders do not compose.
pub const IPSEC_MODE_TUNNEL: u32 = 1;

/// AES-128-GCM, [RFC 4106].
///
/// [RFC 4106]: https://www.rfc-editor.org/rfc/rfc4106
pub const IPSEC_AEAD_AES128_GCM: u32 = 1;

/// ChaCha20-Poly1305, [RFC 7634].
///
/// [RFC 7634]: https://www.rfc-editor.org/rfc/rfc7634
pub const IPSEC_AEAD_CHACHA20_POLY1305: u32 = 2;

/// One security policy, as `IpsecAddSp` takes it.
///
/// Twelve words, the previous tree's shape.  The selector is the five-tuple: a
/// protocol, two prefixes with their lengths, and two ports, each of which a
/// zero leaves unconstrained.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpsecSpDef {
    /// Reserved, and must be zero.
    pub flags: u32,
    /// [`IPSEC_ACTION_BYPASS`], [`IPSEC_ACTION_DISCARD`] or
    /// [`IPSEC_ACTION_PROTECT`].
    pub action: u32,
    /// [`IPSEC_DIR_INBOUND`], [`IPSEC_DIR_OUTBOUND`] or [`IPSEC_DIR_BOTH`].
    pub direction: u32,
    /// The IP protocol number, or zero for any.
    pub protocol: u32,
    /// The source prefix's address.
    pub src_addr: [u8; 4],
    /// How many leading bits of it are the network's.
    pub src_prefix: u32,
    /// The destination prefix's address.
    pub dst_addr: [u8; 4],
    /// How many leading bits of it are the network's.
    pub dst_prefix: u32,
    /// The source port, or zero for any.
    pub src_port: u32,
    /// The destination port, or zero for any.
    pub dst_port: u32,
    /// The association a `PROTECT` policy applies, which must exist when the
    /// policy is installed.
    pub sa_id: u32,
    /// Reserved, and must be zero.
    pub reserved: u32,
}

pub const IPSEC_SP_DEF_SIZE: usize = size_of::<IpsecSpDef>();

/// One security association, as `IpsecAddSa` takes it.
///
/// The keys are inlined so the record is one flat read; only
/// `enc_key_len`/`auth_key_len` bytes of each are meaningful.  The salt is
/// twelve bytes in the record and four are used: [RFC 4106] and [RFC 7634]
/// both derive a twelve-byte nonce from four bytes of salt and the sequence
/// number, and the record leaves room for a construction that needed more.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpsecSaDef {
    /// Reserved, and must be zero.
    pub flags: u32,
    /// The Security Parameters Index, which names this association on the
    /// wire.
    pub spi: u32,
    /// [`IPSEC_MODE_TRANSPORT`] is served; [`IPSEC_MODE_TUNNEL`] is refused.
    pub mode: u32,
    /// [`IPSEC_PROTO_ESP`] is served; [`IPSEC_PROTO_AH`] is refused.
    pub proto: u32,
    /// [`IPSEC_AEAD_AES128_GCM`] or [`IPSEC_AEAD_CHACHA20_POLY1305`].
    pub aead_algo: u32,
    /// Reserved: AH is the only protocol that uses it and this build refuses
    /// AH.
    pub auth_algo: u32,
    /// How many of `enc_key` are the key: sixteen for AES-128, thirty-two for
    /// ChaCha20.
    pub enc_key_len: u32,
    /// How many of `auth_key` are meaningful, which for every algorithm this
    /// build serves is none.
    pub auth_key_len: u32,
    /// The encryption key.
    pub enc_key: [u8; 32],
    /// The authentication key, which no served algorithm uses.
    pub auth_key: [u8; 32],
    /// The salt the nonce's first four bytes come from.
    pub salt: [u8; 12],
    /// Reserved: the selector belongs to the policy, and this is the
    /// association's own address, which transport mode does not add to a
    /// packet.
    pub src_addr: [u8; 4],
    /// See [`IpsecSaDef::src_addr`].
    pub dst_addr: [u8; 4],
    /// Reserved: tunnel mode's outer addresses, and tunnel mode is refused.
    pub tunnel_src: [u8; 4],
    /// See [`IpsecSaDef::tunnel_src`].
    pub tunnel_dst: [u8; 4],
    /// Reserved: a lifetime needs a clock and a byte count that this build
    /// does not enforce, and an expired association is one a program removes.
    pub lifetime_bytes: u64,
    /// See [`IpsecSaDef::lifetime_bytes`].
    pub lifetime_ticks: u64,
}

pub const IPSEC_SA_DEF_SIZE: usize = size_of::<IpsecSaDef>();

/// What `IpsecGetStats` answers.
///
/// Four counters and the two table sizes.  The counters are sixty-four-bit
/// because a machine that has been running for a day has encrypted more
/// packets than a word holds, and `integrity_failures` and `replay_drops` are
/// separate because they are two different failures: a tag that did not verify
/// is a packet that was not the peer's, and a refused sequence is a packet
/// that was and arrived twice.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct IpsecStats {
    /// How many policies are installed.
    pub policies: u32,
    /// How many associations are installed.
    pub associations: u32,
    /// Reserved, and must be zero.
    pub reserved0: u32,
    /// Reserved, and must be zero.
    pub reserved1: u32,
    /// Packets ESP encapsulated.
    pub esp_encrypted: u64,
    /// Packets ESP decapsulated.
    pub esp_decrypted: u64,
    /// Payloads whose tag did not verify.
    pub integrity_failures: u64,
    /// Sequences the replay window refused.
    pub replay_drops: u64,
}

pub const IPSEC_STATS_SIZE: usize = size_of::<IpsecStats>();

/// A virtual interface's flag: this one is the host's own delivery.
///
/// The number the previous tree published, kept because it is a value a
/// program's own record carries.
pub const MRT_VIF_FLAG_LOCAL: u32 = 1;

/// A virtual interface's flag: this one sends out of the card.
pub const MRT_VIF_FLAG_LINK: u32 = 2;

/// One virtual interface, as `MrtAddVif` takes it.
///
/// Six words, the previous tree's shape.  `vif_index` of zero asks for
/// automatic numbering: the field is documented on `MrtAddVif` and the reading
/// is stated there, because the record's own comment and the flag word could be
/// read as saying zero means the local interface, and one value cannot be both.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MrtVifDef {
    /// [`MRT_VIF_FLAG_LOCAL`] or [`MRT_VIF_FLAG_LINK`].
    pub flags: u32,
    /// The index to use, or zero to be given one.
    pub vif_index: u32,
    /// The smallest time-to-live a packet needs to leave by this interface.
    pub threshold: u32,
    /// The rate a caller asks for, in packets per second, zero for none.
    ///
    /// Stored and read back, and **nothing enforces it**: a rate needs a clock
    /// and a bucket, and a drop from either is silent.  The field is here
    /// because a program reading its own interface back should learn what it
    /// set, and pretending otherwise would be a promise nothing keeps.
    pub rate_limit: u32,
    /// Reserved, and must be zero.
    pub reserved0: u32,
    /// Reserved, and must be zero.
    pub reserved1: u32,
}

pub const MRT_VIF_DEF_SIZE: usize = size_of::<MrtVifDef>();

/// One outgoing interface of a forwarding-cache entry.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MrtOutVif {
    /// The interface to send by.
    pub vif: u32,
    /// The smallest time-to-live a packet needs to leave by it.
    pub ttl: u32,
}

/// A multicast forwarding-cache entry, as `MrtAddMfc` takes it.
///
/// `(source, group)`, the interface it must arrive on, and up to four outgoing
/// interfaces.  All four are carried in the record and `num_out_vifs` says how
/// many are meaningful, which is the shape the previous tree published: a
/// caller that set two and left the rest zero is a caller whose record this
/// reads the first two of.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MrtMfcDef {
    /// The sender the entry is for.
    pub source: [u8; 4],
    /// The group it is going to.
    pub group: [u8; 4],
    /// The interface it must arrive on.
    pub in_vif: u32,
    /// How many of `out_vifs` are meaningful.
    pub num_out_vifs: u32,
    /// Where it goes.
    pub out_vifs: [MrtOutVif; 4],
}

pub const MRT_MFC_DEF_SIZE: usize = size_of::<MrtMfcDef>();

#[cfg(test)]
mod tests {
    use super::NETWORK_ADDRESSES_BYTES;
    use super::NETWORK_STATUS_SIZE;
    use super::NETWORK_STATUS_UP;
    use super::NetworkStatusRecord;
    use super::UDP_SENDER_RECORD_SIZE;
    use super::UdpSenderRecord;
    use super::pack_address;
    use super::unpack_address;

    /// The record's layout is the wire's: a word of state, then the fourteen
    /// address bytes in the order the boot's own exchange names them.
    #[test]
    fn the_record_carries_a_word_and_three_addresses() {
        assert_eq!(NETWORK_STATUS_SIZE, 24, "a word, then the addresses");
        assert_eq!(NETWORK_ADDRESSES_BYTES, 14, "six, then four, then four");

        let record = NetworkStatusRecord::new(
            NETWORK_STATUS_UP,
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
            [10, 0, 2, 15],
            [10, 0, 2, 2],
        );
        assert_eq!(record.addresses[0..6], [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        assert_eq!(record.addresses[6..10], [10, 0, 2, 15]);
        assert_eq!(record.addresses[10..14], [10, 0, 2, 2]);
    }

    /// The sender record is two words, and the address packing round-trips
    /// through the word both sides of the boundary carry.
    #[test]
    fn the_sender_record_is_two_words_and_the_address_packs() {
        assert_eq!(UDP_SENDER_RECORD_SIZE, 16);
        let record = UdpSenderRecord {
            address: pack_address([10, 0, 2, 2]),
            port: 8612,
        };
        assert_eq!(record.address, 0x0A00_0202, "the first byte is the highest");
        assert_eq!(unpack_address(record.address), [10, 0, 2, 2]);
        assert_eq!(unpack_address(pack_address([255, 255, 255, 255])), [255; 4]);
    }
    /// The IPv6 record's layout is the wire's: three words then two
    /// sixteen-byte addresses, and the offsets this crate names are where
    /// the compiler put them.
    #[test]
    fn the_ipv6_record_carries_three_words_and_two_addresses() {
        assert_eq!(super::IPV6_STATUS_SIZE, 24 + 32);
        assert_eq!(super::IPV6_STATUS_LINK_LOCAL_OFFSET, 24);
        assert_eq!(super::IPV6_STATUS_GLOBAL_OFFSET, 40);

        let link_local = [
            0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x54, 0, 0xFF, 0xFE, 0x12, 0x34, 0x56,
        ];
        let global = [
            0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0x50, 0x54, 0, 0xFF, 0xFE, 0x12, 0x34, 0x56,
        ];
        let record = super::Ipv6StatusRecord::new(link_local, Some(global), 2);
        assert_eq!(record.state, 1);
        assert_eq!(record.has_global, 1);
        assert_eq!(record.neighbours, 2);
        assert_eq!(record.link_local, link_local);
        assert_eq!(record.global, global);

        // No router: the flag says zero and the address field is zeroes
        // rather than an address a program might read as real.
        let record = super::Ipv6StatusRecord::new(link_local, None, 0);
        assert_eq!(record.has_global, 0);
        assert_eq!(record.global, [0_u8; 16]);
    }

    /// The IPv6 flag is one bit, the two sender records differ by a word, and
    /// the wider record's address is sixteen bytes at the offset this crate
    /// names, the shape a caller with the flag set passes.
    #[test]
    fn the_ipv6_flag_and_the_wider_sender_record() {
        assert_eq!(super::NETWORK_FLAG_IPV6, 1);
        assert_eq!(super::SEND_TO_UDP_KNOWN_FLAGS, super::NETWORK_FLAG_IPV6);
        assert_eq!(super::RECV_FROM_UDP_KNOWN_FLAGS, super::NETWORK_FLAG_IPV6);
        assert_eq!(super::CONNECT_TCP_KNOWN_FLAGS, super::NETWORK_FLAG_IPV6);

        // The frozen record is still two words and still the size it was:
        // this change is additive and the assertion is what says so.
        assert_eq!(super::UDP_SENDER_RECORD_SIZE, 16);
        // The wider one is an address and a word.
        assert_eq!(
            super::UDP_SENDER6_RECORD_SIZE,
            16 + core::mem::size_of::<usize>()
        );
        assert_eq!(super::UDP_SENDER6_ADDRESS_OFFSET, 0);
        // The port follows the address, aligned up to the word it lives in.
        assert_eq!(
            super::UDP_SENDER6_PORT_OFFSET,
            16usize.next_multiple_of(core::mem::align_of::<usize>())
        );

        let record = super::UdpSender6Record {
            address: [
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x54, 0, 0xff, 0xfe, 0x12, 0x34, 0x56,
            ],
            port: 8612,
        };
        assert_eq!(record.address[0], 0xfe);
        assert_eq!(record.port, 8612);
    }

    /// The filter records are word-wide fields with the two addresses last, so
    /// the layout is the same on every machine this tree builds for.
    ///
    /// The addresses are sixteen bytes each rather than four, which is the one
    /// field a caller is most likely to write by hand: a record whose
    /// addresses were four bytes and whose family could name IPv6 would be a
    /// rule that could only express half of what it claimed.
    #[test]
    fn the_filter_records_are_word_fields_and_two_addresses() {
        // Twelve words: action through the reserved word.
        assert_eq!(
            super::FILTER_RULE_DEF_SIZE,
            12 * core::mem::size_of::<u32>() + 2 * super::FILTER_ADDRESS_BYTES
        );
        assert_eq!(super::FILTER_ADDRESS_BYTES, 16);
        assert_eq!(
            super::FILTER_RULE_SOURCE_ADDRESS_OFFSET,
            12 * core::mem::size_of::<u32>(),
            "the addresses begin after the twelve words"
        );
        assert_eq!(
            super::FILTER_RULE_DESTINATION_ADDRESS_OFFSET,
            super::FILTER_RULE_SOURCE_ADDRESS_OFFSET + super::FILTER_ADDRESS_BYTES
        );

        // The statistics record: four words then two counters.
        assert_eq!(
            super::FILTER_STATS_SIZE,
            4 * core::mem::size_of::<u32>() + 2 * core::mem::size_of::<u64>()
        );
        assert_eq!(
            super::FILTER_STATS_ALLOWED_OFFSET,
            4 * core::mem::size_of::<u32>()
        );

        // The numbers a program passes are pinned for the same reason the
        // option numbers are: they are a field's value, and a value that moved
        // silently would be a rule with a different meaning.
        assert_eq!(super::FILTER_ACTION_ALLOW, 0);
        assert_eq!(super::FILTER_ACTION_DENY, 1);
        assert_eq!(super::FILTER_DIRECTION_BOTH, 0);
        assert_eq!(super::FILTER_DIRECTION_INBOUND, 1);
        assert_eq!(super::FILTER_DIRECTION_OUTBOUND, 2);
        assert_eq!(super::FILTER_PROTOCOL_ANY, 0);
        assert_eq!(super::FILTER_FAMILY_ANY, 0);
        assert_eq!(super::FILTER_FAMILY_IPV4, 4);
        assert_eq!(super::FILTER_FAMILY_IPV6, 6);
    }

    /// The multicast records are the previous tree's shapes, and their sizes
    /// are pinned because a program's own record is written against them.
    #[test]
    fn the_multicast_records_keep_their_shape() {
        assert_eq!(
            super::MRT_VIF_DEF_SIZE,
            6 * core::mem::size_of::<u32>(),
            "six words"
        );
        assert_eq!(
            super::MRT_MFC_DEF_SIZE,
            2 * 4 + 2 * core::mem::size_of::<u32>() + 4 * 2 * core::mem::size_of::<u32>(),
            "two addresses, two words, four outgoing interfaces"
        );
        assert_eq!(super::MRT_VIF_FLAG_LOCAL, 1);
        assert_eq!(super::MRT_VIF_FLAG_LINK, 2);
    }

    /// The three option numbers are pinned, and the two levels with them.
    ///
    /// They are not in the frozen syscall range and nothing renumbers them at
    /// a boot, so they are pinned here for the same reason the error
    /// discriminants are: a number a program passes in a field is a wire
    /// value, and a value that moves silently is a call that sets a different
    /// option than the caller wrote.
    ///
    /// `SOL_SOCKET` is 1 and `IPPROTO_TCP` is 6 because those are what every
    /// program means by them, and the option numbers are the standard ones so
    /// that a program written against another stack's headers sets the option
    /// it names.  `SO_RCVBUF` is 5 and `SO_SNDBUF` is 6 for that reason, and
    /// `SO_REUSEADDR` and `TCP_NODELAY` are both 1 in their own scopes, which
    /// is why the level is part of the key and not a decoration.
    #[test]
    fn the_option_numbers_and_levels_are_pinned() {
        assert_eq!(super::SOL_SOCKET, 1);
        assert_eq!(super::IPPROTO_TCP, 6);
        assert_eq!(super::SO_RCVBUF, 5);
        assert_eq!(super::SO_SNDBUF, 6);
        assert_eq!(super::TCP_NODELAY, 1);
        assert_eq!(super::TCP_NODELAY_DISABLED, 0);

        // The two levels do not collide, which is the property a table keyed
        // on the level alone would need and a table keyed on the pair gets:
        // `TCP_NODELAY` is 1, and a future socket-level option numbered 1
        // would be the same number twice.
        assert_ne!(super::SOL_SOCKET, super::IPPROTO_TCP);
        assert_eq!(
            super::SOCK_OPT_MAX,
            core::mem::size_of::<usize>(),
            "every option this build serves is one word"
        );
    }
}
