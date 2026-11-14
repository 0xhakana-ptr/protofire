//! net/src/dhcp.rs
//!
//! DHCP: how a machine that has been told nothing learns what it is.
//!
//! ## The layout
//!
//! ```text
//! BOOTP header    op[1] htype[1] hlen[1] hops[1]
//!                 xid[4] secs[2] flags[2]
//!                 ciaddr[4] yiaddr[4] siaddr[4] giaddr[4]
//!                 chaddr[16] sname[64] file[128]        236 bytes
//! magic cookie    [0x63, 0x82, 0x53, 0x63]
//! options         code[1] length[1] value[…], then 0xFF
//! ```
//!
//! ## Why this is not a client
//!
//! A client needs a socket bound to port 68 before it has an address, a
//! broadcast frame with a source address of zero, and a clock for the retry
//! and the lease timers.  All three are the caller's.  What is here is the
//! whole of the protocol's arithmetic: the two messages a client sends, the
//! options a reply carries, and the machine that says when a lease is due for
//! renewal.
//!
//! That is what lets every case be a host test: an offer with no router, a
//! reply with a bad cookie, a lease whose T1 has passed, a message that claims
//! more options than it holds.  A boot sees one server's one answer.
//!
//! ## The four messages
//!
//! A client broadcasts **DISCOVER**, a server answers **OFFER** with an
//! address, the client broadcasts **REQUEST** naming the offer it accepted,
//! and the server answers **ACK**.  The REQUEST is a broadcast even when the
//! server is known, because the client has no address to unicast from yet: it
//! is the ACK that makes the address usable.
//!
//! ## What is not here
//!
//! The retransmission schedule, which needs a clock; DHCPv6, which is a
//! different protocol with a different message set; and prefix delegation.

use abi::Error;
use abi::Result;

use crate::address::Address;

/// The BOOTP header's length, before the magic cookie.
pub const HEADER_LEN: usize = 236;

/// The four bytes that say the options field follows.  Without it a BOOTP
/// reply is BOOTP, which this stack does not speak.
pub const MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];

/// Where the options begin.
pub const OPTIONS_AT: usize = HEADER_LEN + 4;

/// The server's port, which every client message is addressed to.
pub const SERVER_PORT: u16 = 67;

/// The client's port, which a reply comes back to.
pub const CLIENT_PORT: u16 = 68;

/// A client's request for an address.
pub const MESSAGE_DISCOVER: u8 = 1;

/// A server's offer of one.
pub const MESSAGE_OFFER: u8 = 2;

/// A client's request for a specific offer.
pub const MESSAGE_REQUEST: u8 = 3;

/// A server's confirmation.
pub const MESSAGE_ACK: u8 = 5;

/// A server's refusal of a request.
pub const MESSAGE_NAK: u8 = 6;

/// The option that carries the message type, which every message must have.
pub const OPTION_MESSAGE_TYPE: u8 = 53;

/// The option that carries the subnet mask.
pub const OPTION_SUBNET_MASK: u8 = 1;

/// The option that carries a router's address.
pub const OPTION_ROUTER: u8 = 3;

/// The option that carries a name server's address.
pub const OPTION_DNS: u8 = 6;

/// The option that names the address the client wants.
pub const OPTION_REQUESTED_ADDRESS: u8 = 50;

/// The option that carries the lease's length in seconds.
pub const OPTION_LEASE_TIME: u8 = 51;

/// The option that names the server, which a REQUEST echoes so the server it
/// chose answers rather than every server that hears the broadcast.
pub const OPTION_SERVER_IDENTIFIER: u8 = 54;

/// The option that lists the options the client wants back.
pub const OPTION_PARAMETER_REQUEST: u8 = 55;

/// The option that says when renewal is due.
pub const OPTION_RENEWAL_TIME: u8 = 58;

/// The option that says when rebinding is due.
pub const OPTION_REBINDING_TIME: u8 = 59;

/// The option that ends the options field.  Everything after it is padding.
pub const OPTION_END: u8 = 255;

/// The option that pads, which a walker skips.
pub const OPTION_PAD: u8 = 0;

/// What the client asks for when the server does not say.
///
/// Twenty-four hours, which is what [RFC 2131] suggests a server default to
/// and what a client that was told nothing should assume rather than
/// assuming forever.
///
/// [RFC 2131]: https://www.rfc-editor.org/rfc/rfc2131
pub const DEFAULT_LEASE_SECONDS: u32 = 24 * 60 * 60;

/// The one field a client chooses: the transaction it is answering.
///
/// Two lookups on one port are told apart by nothing else, so a client draws it
/// from its own generator rather than reusing a constant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transaction {
    /// The number this exchange names itself by.
    pub id: u32,
    /// The hardware address the reply must come back for.
    pub hardware: [u8; 6],
}

/// A reply's options, read out of the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply {
    /// The message type: [`MESSAGE_OFFER`], [`MESSAGE_ACK`] or [`MESSAGE_NAK`].
    pub kind: u8,
    /// The address the server is giving out, which is meaningless in a NAK.
    pub address: [u8; 4],
    /// The server's own address, which a REQUEST echoes.
    pub server: Option<[u8; 4]>,
    /// The router, which is this build's whole default route.
    pub router: Option<[u8; 4]>,
    /// A name server.
    pub dns: Option<[u8; 4]>,
    /// The mask, which says what is on this link.
    pub subnet_mask: Option<[u8; 4]>,
    /// The lease's length in seconds, or [`DEFAULT_LEASE_SECONDS`] when the
    /// server said nothing.
    pub lease_seconds: u32,
    /// When renewal is due, defaulting to half the lease.
    pub renewal_seconds: u32,
    /// When rebinding is due, defaulting to seven eighths of it.
    pub rebinding_seconds: u32,
}

/// A lease as the boot applies it.
///
/// Separate from [`Reply`] because a lease is what a machine *is* and a reply
/// is what one server said: a lease outlives the exchange, and a renewal
/// replaces only its clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Lease {
    /// The address this machine answers for.
    pub address: [u8; 4],
    /// The router it sends everything off-link to.
    pub router: Option<[u8; 4]>,
    /// The name server it asks.
    pub dns: Option<[u8; 4]>,
    /// The mask.
    pub subnet_mask: Option<[u8; 4]>,
    /// The server that granted it, which a renewal asks.
    pub server: Option<[u8; 4]>,
    /// When it was granted, on the caller's clock.
    pub granted_at: u64,
    /// How long it lasts, in the caller's units.
    pub lifetime: u64,
    /// When renewal is due, in the caller's units.
    pub renew_at: u64,
    /// When rebinding is due, in the caller's units.
    pub rebind_at: u64,
}

/// What a lease's clocks say to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Duty {
    /// Nothing: the lease is still fresh.
    Bound,
    /// Renew it with the server that granted it.
    Renew,
    /// Ask any server: the grant's own server has stopped answering.
    Rebind,
    /// It has run out.  The address is no longer this machine's.
    Expired,
}

impl Lease {
    /// What the clocks say at `now`.
    ///
    /// The three thresholds are the exchange's own: renewal at half the lease
    /// and rebinding at seven eighths are [RFC 2131]'s, and a client that
    /// waited for expiry would hand out an address it no longer holds.
    ///
    /// [RFC 2131]: https://www.rfc-editor.org/rfc/rfc2131
    pub fn duty(&self, now: u64) -> Duty {
        if now >= self.expires_at() {
            Duty::Expired
        } else if now >= self.rebind_at {
            Duty::Rebind
        } else if now >= self.renew_at {
            Duty::Renew
        } else {
            Duty::Bound
        }
    }

    /// When it runs out.
    pub fn expires_at(&self) -> u64 {
        self.granted_at.saturating_add(self.lifetime)
    }
}

/// Turn a reply into the lease a boot applies, on the caller's clock.
///
/// `scale` converts the server's seconds into the caller's units, because a
/// clock's tick is the clock's: a hundred-hertz timer passes one hundred, an
/// ARM generic timer passes its own rate, and this crate knows neither.
///
/// [`Error::InvalidArgument`] for a NAK: a refusal is not a lease, and a
/// caller that applied one would be configuring a machine the server said no
/// to.
pub fn lease_from(reply: &Reply, granted_at: u64, ticks_per_second: u64) -> Result<Lease> {
    if reply.kind != MESSAGE_ACK && reply.kind != MESSAGE_OFFER {
        return Err(Error::InvalidArgument);
    }
    let scale = |seconds: u32| u64::from(seconds).saturating_mul(ticks_per_second);
    Ok(Lease {
        address: reply.address,
        router: reply.router,
        dns: reply.dns,
        subnet_mask: reply.subnet_mask,
        server: reply.server,
        granted_at,
        lifetime: scale(reply.lease_seconds),
        renew_at: granted_at.saturating_add(scale(reply.renewal_seconds)),
        rebind_at: granted_at.saturating_add(scale(reply.rebinding_seconds)),
    })
}

/// The options a client asks to be told about.
///
/// A server sends every option it thinks a client wants, but asking is what
/// tells it that this client knows what to do with a mask and a name server.
pub const PARAMETER_REQUEST: [u8; 4] = [
    OPTION_SUBNET_MASK,
    OPTION_ROUTER,
    OPTION_DNS,
    OPTION_LEASE_TIME,
];

/// How many bytes a client's message is: the header, the cookie, and room for
/// the options this crate writes.
pub const fn message_len() -> usize {
    // The longest message this crate builds: DISCOVER carries the type, the
    // parameter request and the end.
    OPTIONS_AT + 3 + 2 + PARAMETER_REQUEST.len() + 1
}

/// Write a DISCOVER: the client has no address and wants one.
///
/// `into` is the datagram and is returned as a slice of its written length.
/// The message names the client's hardware address, which is what a server
/// keys its offer on, and asks for the options a boot needs.
///
/// `None` when `into` is too small.
pub fn write_discover(into: &mut [u8], transaction: Transaction) -> Option<Region<'_>> {
    write_message(into, transaction, MESSAGE_DISCOVER, None, None)
}

/// Write a REQUEST: the client accepts the address a server offered.
///
/// The server identifier is echoed because a broadcast REQUEST reaches every
/// server on the link, and each one that did not make the offer must ignore
/// it.  `requested` names the address the client was offered; `server` names
/// who offered it, or `None` when the offer carried no identifier, which is
/// the shape a single-server link produces.
///
/// `None` when `into` is too small.
pub fn write_request(
    into: &mut [u8],
    transaction: Transaction,
    requested: [u8; 4],
    server: Option<[u8; 4]>,
) -> Option<Region<'_>> {
    write_message(into, transaction, MESSAGE_REQUEST, Some(requested), server)
}

/// A datagram's bytes and the length actually written.
///
/// The buffer is the caller's and is almost always longer than the message, so
/// a writer answers what it wrote rather than making the caller guess.
pub struct Region<'a> {
    bytes: &'a [u8],
}

impl Region<'_> {
    /// The bytes to send.
    pub fn as_slice(&self) -> &[u8] {
        self.bytes
    }

    /// The message's length.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the message is empty, which it never is: a caller that had a
    /// zero-length DHCP message would have built one with no header.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Write one client message.
fn write_message(
    into: &mut [u8],
    transaction: Transaction,
    kind: u8,
    requested: Option<[u8; 4]>,
    server: Option<[u8; 4]>,
) -> Option<Region<'_>> {
    let needed =
        OPTIONS_AT + 3 + if requested.is_some() { 6 } else { 0 } + 2 + PARAMETER_REQUEST.len() + 1;
    if into.len() < needed {
        return None;
    }
    into[..OPTIONS_AT].fill(0);
    into[0] = 1; // BOOTREQUEST
    into[1] = 1; // Ethernet
    into[2] = 6; // a hardware address is six bytes
    into[3] = 0; // hops
    into[4..8].copy_from_slice(&transaction.id.to_be_bytes());
    // Zero seconds elapsed and no broadcast flag: this stack is not asking
    // for a broadcast reply, because it has no way to receive one before it
    // has an address and the server broadcasts anyway.
    into[10..12].copy_from_slice(&0u16.to_be_bytes());
    into[28..34].copy_from_slice(&transaction.hardware);
    into[HEADER_LEN..OPTIONS_AT].copy_from_slice(&MAGIC_COOKIE);

    let mut at = OPTIONS_AT;
    into[at] = OPTION_MESSAGE_TYPE;
    into[at + 1] = 1;
    into[at + 2] = kind;
    at += 3;

    if let Some(requested) = requested {
        into[at] = OPTION_REQUESTED_ADDRESS;
        into[at + 1] = 4;
        into[at + 2..at + 6].copy_from_slice(&requested);
        at += 6;
    }
    if let Some(server) = server {
        into[at] = OPTION_SERVER_IDENTIFIER;
        into[at + 1] = 4;
        into[at + 2..at + 6].copy_from_slice(&server);
        at += 6;
    }

    into[at] = OPTION_PARAMETER_REQUEST;
    into[at + 1] = PARAMETER_REQUEST.len() as u8;
    into[at + 2..at + 2 + PARAMETER_REQUEST.len()].copy_from_slice(&PARAMETER_REQUEST);
    at += 2 + PARAMETER_REQUEST.len();

    into[at] = OPTION_END;
    at += 1;

    Some(Region { bytes: &into[..at] })
}

/// Read a server's reply, or `None` when the bytes are not one this client
/// asked for.
///
/// Three things are checked before an option is read: the message is a reply,
/// its transaction id is the one this exchange named, and its hardware
/// address is this client's.  The last two are what keep a reply meant for
/// another machine, or for another exchange on this one, from configuring it.
pub fn parse_reply(message: &[u8], transaction: Transaction) -> Option<Reply> {
    if message.len() < OPTIONS_AT {
        return None;
    }
    if message[0] != 2 {
        return None; // not a BOOTREPLY
    }
    if message[4..8] != transaction.id.to_be_bytes() {
        return None;
    }
    if message[28..34] != transaction.hardware {
        return None;
    }
    if message[HEADER_LEN..OPTIONS_AT] != MAGIC_COOKIE {
        return None;
    }

    let mut kind = None;
    let mut server = None;
    let mut router = None;
    let mut dns = None;
    let mut subnet_mask = None;
    let mut lease_seconds = DEFAULT_LEASE_SECONDS;
    let mut renewal_seconds = None;
    let mut rebinding_seconds = None;

    walk_options(&message[OPTIONS_AT..], &mut |code, value| match code {
        OPTION_MESSAGE_TYPE => {
            if !value.is_empty() {
                kind = Some(value[0]);
            }
        }
        OPTION_SERVER_IDENTIFIER => server = read_address(value),
        OPTION_ROUTER => router = read_address(value),
        OPTION_DNS => dns = read_address(value),
        OPTION_SUBNET_MASK => subnet_mask = read_address(value),
        OPTION_LEASE_TIME => {
            if let Some(seconds) = read_u32(value) {
                lease_seconds = seconds;
            }
        }
        OPTION_RENEWAL_TIME => renewal_seconds = read_u32(value),
        OPTION_REBINDING_TIME => rebinding_seconds = read_u32(value),
        _ => {}
    });

    let kind = kind?;
    if kind != MESSAGE_OFFER && kind != MESSAGE_ACK && kind != MESSAGE_NAK {
        return None;
    }
    // The three clocks a client did not hear about are the RFC's fractions of
    // the one it did: half and seven eighths.
    let renewal_seconds = renewal_seconds.unwrap_or(lease_seconds / 2);
    let rebinding_seconds = rebinding_seconds.unwrap_or(lease_seconds / 8 * 7);
    Some(Reply {
        kind,
        address: [message[16], message[17], message[18], message[19]],
        server,
        router,
        dns,
        subnet_mask,
        lease_seconds,
        renewal_seconds,
        rebinding_seconds,
    })
}

/// Walk the options field, handing each (code, value) to `visit`.
///
/// A pad is skipped and the end marker stops the walk.  A code whose length
/// byte is missing, or whose length runs past the field, is a message that
/// claims more than it holds: the walk stops rather than reading the next
/// option's bytes as this one's value.
fn walk_options(options: &[u8], visit: &mut impl FnMut(u8, &[u8])) {
    let mut at = 0;
    while at < options.len() {
        match options[at] {
            OPTION_PAD => {
                at += 1;
                continue;
            }
            OPTION_END => return,
            code => {
                let Some(&length) = options.get(at + 1) else {
                    return;
                };
                let length = length as usize;
                let start = at + 2;
                let Some(end) = start.checked_add(length) else {
                    return;
                };
                if end > options.len() {
                    return;
                }
                visit(code, &options[start..end]);
                at = end;
            }
        }
    }
}

/// An IPv4 address from the first four bytes of an option's value.
fn read_address(value: &[u8]) -> Option<[u8; 4]> {
    value
        .get(..4)
        .map(|bytes| [bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// A big-endian word from the first four bytes of an option's value.
fn read_u32(value: &[u8]) -> Option<u32> {
    value
        .get(..4)
        .map(|bytes| u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// The address a lease names, as the type the rest of the stack keys on.
pub fn lease_address(lease: &Lease) -> Address {
    Address::V4(lease.address)
}

#[cfg(test)]
mod tests {
    use super::DEFAULT_LEASE_SECONDS;
    use super::Duty;
    use super::MAGIC_COOKIE;
    use super::MESSAGE_ACK;
    use super::MESSAGE_DISCOVER;
    use super::MESSAGE_OFFER;
    use super::OPTIONS_AT;
    use super::Reply;
    use super::Transaction;
    use super::lease_from;
    use super::parse_reply;
    use super::write_discover;
    use super::write_request;
    use alloc::vec;
    use alloc::vec::Vec;
    const HARDWARE: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

    fn transaction() -> Transaction {
        Transaction {
            id: 0xDEAD_BEEF,
            hardware: HARDWARE,
        }
    }

    /// A DISCOVER is a BOOTREQUEST naming this machine's hardware address,
    /// carrying the magic cookie and asking for the options a boot needs.
    #[test]
    fn a_discover_names_the_client_and_asks_for_what_it_needs() {
        let mut buffer = [0_u8; 400];
        let region = write_discover(&mut buffer, transaction()).expect("a discover");
        let bytes = region.as_slice();

        assert_eq!(bytes[0], 1, "BOOTREQUEST");
        assert_eq!(bytes[1], 1, "Ethernet");
        assert_eq!(bytes[2], 6, "a six-byte hardware address");
        assert_eq!(&bytes[4..8], &0xDEAD_BEEFu32.to_be_bytes());
        assert_eq!(&bytes[28..34], &HARDWARE);
        assert_eq!(&bytes[236..240], &MAGIC_COOKIE);

        // The message type is the first option, and its value is DISCOVER.
        assert_eq!(bytes[OPTIONS_AT], super::OPTION_MESSAGE_TYPE);
        assert_eq!(bytes[OPTIONS_AT + 1], 1);
        assert_eq!(bytes[OPTIONS_AT + 2], MESSAGE_DISCOVER);

        // It ends with the end marker, and nothing past it is part of the
        // message.
        assert_eq!(bytes[bytes.len() - 1], super::OPTION_END);
    }

    /// A REQUEST echoes the offered address and the server that offered it,
    /// which is what tells every other server on the link to ignore it.
    #[test]
    fn a_request_echoes_the_offer() {
        let mut buffer = [0_u8; 400];
        let region = write_request(
            &mut buffer,
            transaction(),
            [10, 0, 2, 15],
            Some([10, 0, 2, 2]),
        )
        .expect("a request");
        let bytes = region.as_slice();
        assert_eq!(bytes[OPTIONS_AT + 2], super::MESSAGE_REQUEST);

        // Both options are somewhere in the field, and their values are the
        // ones the caller named.
        let mut requested = None;
        let mut server = None;
        super::walk_options(&bytes[OPTIONS_AT..], &mut |code, value| match code {
            super::OPTION_REQUESTED_ADDRESS => requested = super::read_address(value),
            super::OPTION_SERVER_IDENTIFIER => server = super::read_address(value),
            _ => {}
        });
        assert_eq!(requested, Some([10, 0, 2, 15]));
        assert_eq!(server, Some([10, 0, 2, 2]));
    }

    /// A reply is read only when its transaction and hardware address are this
    /// exchange's: a datagram meant for another machine must not configure
    /// this one.
    #[test]
    fn a_reply_for_another_exchange_is_refused() {
        let reply = ack();
        assert!(parse_reply(&reply, transaction()).is_some());

        let mut other_id = transaction();
        other_id.id = 1;
        assert!(parse_reply(&reply, other_id).is_none(), "another exchange");

        let mut other_hardware = transaction();
        other_hardware.hardware = [0xFF; 6];
        assert!(
            parse_reply(&reply, other_hardware).is_none(),
            "another machine"
        );

        // A message without the magic cookie is BOOTP, which this stack does
        // not speak.
        let mut no_cookie = reply.clone();
        no_cookie[236] = 0;
        assert!(parse_reply(&no_cookie, transaction()).is_none());
    }

    /// An ACK carries the address, the router, the mask, the name server and
    /// the lease; the clocks it did not name are the RFC's fractions of the
    /// one it did.
    #[test]
    fn an_ack_carries_the_lease_the_server_granted() {
        let reply = parse_reply(&ack(), transaction()).expect("an ack");
        assert_eq!(reply.kind, MESSAGE_ACK);
        assert_eq!(reply.address, [10, 0, 2, 15]);
        assert_eq!(reply.router, Some([10, 0, 2, 2]));
        assert_eq!(reply.dns, Some([10, 0, 2, 3]));
        assert_eq!(reply.subnet_mask, Some([255, 255, 255, 0]));
        assert_eq!(reply.lease_seconds, 3600);
        assert_eq!(reply.renewal_seconds, 1800, "half, because none was named");
        assert_eq!(
            reply.rebinding_seconds, 3150,
            "seven eighths, because none was named"
        );
    }

    /// A reply that names the clocks uses them, and one that names no lease
    /// gets the RFC's default rather than zero.
    #[test]
    fn the_clocks_a_server_names_are_the_ones_used() {
        let mut message = ack();
        // Replace the lease option's value in place: 3600 becomes 600.
        let at = find_option(&message, super::OPTION_LEASE_TIME).expect("the lease option");
        message[at + 2..at + 6].copy_from_slice(&600u32.to_be_bytes());
        let reply = parse_reply(&message, transaction()).expect("an ack");
        assert_eq!(reply.lease_seconds, 600);
        assert_eq!(reply.renewal_seconds, 300);
        assert_eq!(reply.rebinding_seconds, 525);

        // An ACK with no lease option at all.
        let bare = ack_without(super::OPTION_LEASE_TIME);
        let reply = parse_reply(&bare, transaction()).expect("an ack");
        assert_eq!(reply.lease_seconds, DEFAULT_LEASE_SECONDS);
    }

    /// A lease's clock walks through its three thresholds and then expires.
    #[test]
    fn a_leases_clock_walks_through_its_thresholds() {
        let reply = parse_reply(&ack(), transaction()).expect("an ack");
        let lease = lease_from(&reply, 1_000, 1).expect("a lease");
        assert_eq!(lease.address, [10, 0, 2, 15]);
        assert_eq!(lease.expires_at(), 1_000 + 3_600);

        assert_eq!(lease.duty(1_000), Duty::Bound);
        assert_eq!(lease.duty(2_799), Duty::Bound);
        assert_eq!(lease.duty(2_800), Duty::Renew, "half the lease has passed");
        assert_eq!(lease.duty(4_149), Duty::Renew);
        assert_eq!(lease.duty(4_150), Duty::Rebind, "seven eighths");
        assert_eq!(lease.duty(4_599), Duty::Rebind);
        assert_eq!(lease.duty(4_600), Duty::Expired);
    }

    /// A NAK is not a lease: a caller that applied one would configure a
    /// machine the server said no to.
    #[test]
    fn a_nak_is_not_a_lease() {
        let mut message = ack();
        let at = find_option(&message, super::OPTION_MESSAGE_TYPE).expect("the type");
        message[at + 2] = super::MESSAGE_NAK;
        let reply = parse_reply(&message, transaction()).expect("a reply");
        assert_eq!(reply.kind, super::MESSAGE_NAK);
        assert!(lease_from(&reply, 0, 100).is_err());
    }

    /// A reply whose options claim more bytes than the message holds stops the
    /// walk rather than reading the next option as this one's value.
    #[test]
    fn an_option_that_runs_past_the_message_stops_the_walk() {
        let mut message = ack();
        let at = find_option(&message, super::OPTION_LEASE_TIME).expect("the option");
        message[at + 1] = 200; // a length the message does not have
        let reply = parse_reply(&message, transaction()).expect("a reply");
        // The options after the truncated one were not read, so the clocks are
        // the defaults and the lease is the RFC's.
        assert_eq!(reply.lease_seconds, DEFAULT_LEASE_SECONDS);
    }

    /// An ACK for the transaction above, with the options a QEMU user-mode
    /// network sends.
    fn ack() -> Vec<u8> {
        reply_with(
            MESSAGE_ACK,
            &[
                (super::OPTION_SUBNET_MASK, vec![255, 255, 255, 0]),
                (super::OPTION_ROUTER, vec![10, 0, 2, 2]),
                (super::OPTION_DNS, vec![10, 0, 2, 3]),
                (super::OPTION_LEASE_TIME, 3600u32.to_be_bytes().to_vec()),
                (super::OPTION_SERVER_IDENTIFIER, vec![10, 0, 2, 2]),
            ],
        )
    }

    /// The same ACK minus one option.
    fn ack_without(omit: u8) -> Vec<u8> {
        reply_with(
            MESSAGE_ACK,
            &[
                (super::OPTION_SUBNET_MASK, vec![255, 255, 255, 0]),
                (super::OPTION_ROUTER, vec![10, 0, 2, 2]),
                (super::OPTION_DNS, vec![10, 0, 2, 3]),
                (super::OPTION_LEASE_TIME, 3600u32.to_be_bytes().to_vec()),
                (super::OPTION_SERVER_IDENTIFIER, vec![10, 0, 2, 2]),
            ]
            .into_iter()
            .filter(|(code, _)| *code != omit)
            .collect::<Vec<_>>(),
        )
    }

    /// A reply message with `kind` and `options`, built the way a server
    /// builds one.
    fn reply_with(kind: u8, options: &[(u8, Vec<u8>)]) -> Vec<u8> {
        let mut message = vec![0_u8; OPTIONS_AT];
        message[0] = 2; // BOOTREPLY
        message[1] = 1;
        message[2] = 6;
        message[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        message[16..20].copy_from_slice(&[10, 0, 2, 15]);
        message[28..34].copy_from_slice(&HARDWARE);
        message[236..240].copy_from_slice(&MAGIC_COOKIE);
        message.push(super::OPTION_MESSAGE_TYPE);
        message.push(1);
        message.push(kind);
        for (code, value) in options {
            message.push(*code);
            message.push(value.len() as u8);
            message.extend_from_slice(value);
        }
        message.push(super::OPTION_END);
        message
    }

    /// Where an option's code byte is, for a test that wants to edit it.
    fn find_option(message: &[u8], code: u8) -> Option<usize> {
        let mut found = None;
        let mut at = OPTIONS_AT;
        while at < message.len() {
            match message[at] {
                0 => at += 1,
                255 => break,
                current => {
                    let length = message[at + 1] as usize;
                    if current == code {
                        found = Some(at);
                        break;
                    }
                    at += 2 + length;
                }
            }
        }
        found
    }

    /// The offer a server sends is read exactly as an ack is, which is what
    /// lets a client confirm one with the other.
    #[test]
    fn an_offer_is_read_like_an_ack() {
        let reply = reply_with(
            MESSAGE_OFFER,
            &[
                (super::OPTION_ROUTER, vec![10, 0, 2, 2]),
                (super::OPTION_SERVER_IDENTIFIER, vec![10, 0, 2, 2]),
            ],
        );
        let parsed = parse_reply(&reply, transaction()).expect("an offer");
        assert_eq!(parsed.kind, MESSAGE_OFFER);
        assert_eq!(parsed.address, [10, 0, 2, 15]);
        assert_eq!(parsed.router, Some([10, 0, 2, 2]));
        assert_eq!(parsed.dns, None, "the offer named no name server");
        assert_eq!(parsed.subnet_mask, None);
        // A lease can be built from an offer, which is what a client applies
        // when a server skips the ACK.
        assert!(lease_from(&parsed, 0, 100).is_ok());
    }

    /// A message with no message type at all is not a reply this client can
    /// act on.
    #[test]
    fn a_reply_with_no_message_type_is_refused() {
        let message = reply_with(MESSAGE_ACK, &[]);
        let mut without_type = Vec::new();
        without_type.extend_from_slice(&message[..OPTIONS_AT]);
        without_type.push(super::OPTION_END);
        assert!(parse_reply(&without_type, transaction()).is_none());
    }

    /// The `Reply` type is a value a caller can hold and compare, which is what
    /// a test needs and what a lease is built from.
    #[test]
    fn a_reply_outlives_its_message() {
        let reply: Reply = parse_reply(&ack(), transaction()).expect("an ack");
        let copy = reply;
        assert_eq!(copy, reply);
    }
}
