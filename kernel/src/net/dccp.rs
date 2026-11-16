//! kernel/src/net/dccp.rs
//!
//! DCCP: the eight calls, the segments they send, and the checksum.
//!
//! One section of `kernel/src/net/mod.rs`.  The sections call each other in
//! both directions: the demux reaches every protocol's delivery and a protocol
//! reaches the interface, so each names what it needs through `super::`.  What
//! the split buys is that a reader looking for one protocol opens one file.

use abi::Error;
use abi::Result;

use super::core::DCCP;
use super::core::INTERFACE;
use super::core::dccp_first_sequence;
use super::core::hardware_for_v4;
use super::core::is_loopback_v4;
use super::filter::submit_filtered;

/// Bind a DCCP port for listening, answering the listener's id.
pub fn dccp_listen(port: u16, service_code: Option<u32>) -> Result<usize> {
    DCCP.lock().listen(port, service_code)
}

/// Whether a Request is waiting at `port`.
pub fn dccp_has_pending(port: u16) -> bool {
    DCCP.lock().has_pending(port)
}

/// Take the next Request waiting at `port`, answering the connection's id.
pub fn dccp_accept(port: u16) -> Result<Option<usize>> {
    DCCP.lock().accept(port)
}

/// Open a DCCP connection to `peer`, answering its id.
///
/// **The connection is opened and its Request sent.**  `Unsupported` when the
/// destination is not this machine, which is the same rule `connect_tcp`
/// follows and for the same reason: a Request that waits on the wire is a wait
/// this build does not make a call do, and a loopback is where a peer is
/// reachable without one.
pub fn dccp_connect(
    local_port: u16,
    peer: net::address::Address,
    peer_port: u16,
    service_code: u32,
) -> Result<usize> {
    let first = dccp_first_sequence();
    let id = DCCP
        .lock()
        .connect(local_port, peer, peer_port, service_code, first)?;
    // The Request goes out now, through the demux for a loopback and through
    // the card for a peer: a connection whose Request was never sent is a
    // client waiting for a Response that nothing prompted.
    let sent = dccp_send_segment(id, net::dccp::PacketType::Request, None, &[]);
    if sent.is_err() {
        // A Request that could not leave is a connection nothing will answer,
        // so it is closed rather than left in the table.
        if let Some(connection) = DCCP.lock().connection_mut(id) {
            let _ = connection.receive(&reset_for(connection), &[]);
        }
        DCCP.lock().prune();
        return sent.map(|_| id);
    }
    Ok(id)
}

/// Send one DCCP datagram on a connection, answering the sequence it used.
pub fn dccp_send(id: usize, bytes: &[u8]) -> Result<u64> {
    let sequence = {
        let mut table = DCCP.lock();
        let connection = table.connection_mut(id).ok_or(Error::InvalidArgument)?;
        connection.send(bytes)?
    };
    dccp_send_segment(id, net::dccp::PacketType::Data, Some(sequence), bytes)?;
    Ok(sequence)
}

/// Read one datagram from a connection, or `None` when the caller should wait.
pub fn dccp_read(id: usize, into: &mut [u8]) -> Result<Option<usize>> {
    DCCP.lock()
        .connection_mut(id)
        .ok_or(Error::InvalidArgument)?
        .read(into)
}

/// The peer and port a connection is to.
pub fn dccp_peer(id: usize) -> Option<(net::address::Address, u16)> {
    DCCP.lock()
        .connection(id)
        .map(|connection| connection.peer())
}

/// The local port a connection is on.
pub fn dccp_local_port(id: usize) -> Option<u16> {
    DCCP.lock()
        .connection(id)
        .map(|connection| connection.local_port())
}

/// Close a connection: send a Close and forget it.
///
/// The `Close` is what tells the peer, and it goes before the entry is dropped:
/// a connection removed first would have nothing left to send it from.
pub fn dccp_close(id: usize) -> Result<()> {
    let exists = DCCP.lock().connection(id).is_some();
    if !exists {
        return Err(Error::InvalidArgument);
    }
    let _ = dccp_send_segment(id, net::dccp::PacketType::Close, None, &[]);
    if let Some(connection) = DCCP.lock().connection_mut(id) {
        // The state the send left it in is the peer's to confirm, and this
        // machine has said all it will say: `TimeWait` is the state a close
        // leaves behind so a duplicate of the last packet is answered.
        connection.receive(&close_for(connection), &[]);
    }
    DCCP.lock().prune();
    Ok(())
}

/// A `Close` segment for this connection's state machine.
fn close_for(connection: &net::dccp::Connection) -> net::dccp::Segment {
    net::dccp::Segment {
        source_port: 0,
        destination_port: 0,
        kind: net::dccp::PacketType::Close,
        sequence: connection.next_sequence(),
        acknowledgement: None,
        service_code: None,
        reset_code: None,
        options: &[],
        payload_at: 0,
        payload_len: 0,
    }
}

/// A `Reset` segment, for the state machines that are told a connection failed.
fn reset_for(_connection: &net::dccp::Connection) -> net::dccp::Segment {
    net::dccp::Segment {
        source_port: 0,
        destination_port: 0,
        kind: net::dccp::PacketType::Reset,
        sequence: 0,
        acknowledgement: None,
        service_code: None,
        reset_code: None,
        options: &[],
        payload_at: 0,
        payload_len: 0,
    }
}

/// Build and send one DCCP segment for a connection.
///
/// The sequence number comes from the connection, and the acknowledgement is
/// the peer's greatest received number, which is what an Ack is: this side
/// saying "I have everything up to here".
fn dccp_send_segment(
    id: usize,
    kind: net::dccp::PacketType,
    _sequence: Option<u64>,
    payload: &[u8],
) -> Result<()> {
    let (peer, peer_port, local_port, sequence, service_code) = {
        let table = DCCP.lock();
        let connection = table.connection(id).ok_or(Error::InvalidArgument)?;
        (
            connection.peer().0,
            connection.peer().1,
            connection.local_port(),
            connection.next_sequence(),
            connection.service_code(),
        )
    };

    let mut segment = alloc::vec![0; net::dccp::HEADER_LEN + 8 + 4 + payload.len() + 8];
    let length = net::dccp::write_segment(
        &mut segment,
        local_port,
        peer_port,
        &net::dccp::HeaderFields {
            kind,
            sequence,
            acknowledgement: Some(0),
            service_code: Some(service_code),
            options: &[],
        },
        payload,
    ) as usize;
    segment.truncate(length);

    match peer {
        net::address::Address::V4(destination) => {
            // The address is read and the lock released **before** anything
            // that may take it again: `deliver_dccp` sends its own reply, and
            // that reply reads the interface too.  A guard alive across the
            // call is a self-deadlock on a lock that is not reentrant, which is
            // exactly what the first version of this did.
            let local = {
                let interface = INTERFACE.lock();
                let Some(interface) = interface.as_ref() else {
                    return Err(Error::NotFound);
                };
                interface.protocol
            };
            // The checksum covers the pseudo-header, which is what makes a
            // DCCP packet's sum different from a bare sum over its bytes.
            let sum = dccp_checksum(&segment, local, destination);
            segment[6..8].copy_from_slice(&sum.to_be_bytes());

            if is_loopback_v4(destination) {
                // Through the demux, the same path a frame takes, which is what
                // makes the loopback exercise the state machine rather than
                // bypass it.
                return deliver_dccp(&segment, net::address::Address::V4(local), destination);
            }

            let interface = INTERFACE.lock();
            let Some(interface) = interface.as_ref() else {
                return Err(Error::NotFound);
            };
            let hardware = interface.hardware;
            let gateway_hardware = hardware_for_v4(interface, destination)?;
            let packet_len = netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + segment.len();
            let mut frame = alloc::vec![0; packet_len];
            net::ethernet::write_header(
                &mut frame,
                gateway_hardware,
                hardware,
                net::ethernet::ETHERTYPE_IPV4,
            );
            net::ipv4::write_header(
                &mut frame[netdev::ETHERNET_HEADER_LEN..],
                local,
                destination,
                net::dccp::PROTOCOL,
                segment.len(),
            );
            frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..].copy_from_slice(&segment);
            submit_filtered(
                interface.card.as_ref(),
                &frame,
                &net::filter::Packet::v4(
                    local,
                    destination,
                    net::dccp::PROTOCOL,
                    &frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..],
                ),
            )
        }
        net::address::Address::V6(_) => Err(Error::Unsupported),
    }
}

/// The DCCP checksum over the pseudo-header and the segment.
///
/// Protocol thirty-three in the pseudo-header, which is the number that makes
/// this a DCCP sum rather than a sum over the segment's own bytes: a peer
/// verifying it with UDP's number computes a different answer, and the packet
/// is refused.
fn dccp_checksum(segment: &[u8], source: [u8; 4], destination: [u8; 4]) -> u16 {
    let mut sum: u32 = 0;
    for byte in source.iter().chain(destination.iter()) {
        sum += u32::from(*byte);
    }
    // The pseudo-header's protocol and length, then the segment itself with its
    // checksum field already zero.
    sum += u32::from(net::dccp::PROTOCOL);
    sum += segment.len() as u32;
    let (words, remainder) = segment.as_chunks::<2>();
    for word in words {
        sum += u32::from(u16::from_be_bytes(*word));
    }
    if let Some(last) = remainder.first() {
        sum += u32::from(*last) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    let sum = !(sum as u16);
    // A computed zero is transmitted as all ones, which is the rule every
    // internet checksum follows: a zero in the field means "no checksum".
    if sum == 0 { 0xFFFF } else { sum }
}

/// Hand one arriving DCCP segment to the table, and act on what it answers.
///
/// The reply is the state machine's, and sending it here is what makes the
/// receive path complete: a `Data` that arrived is owed an `Ack`, a `Request`
/// for a listening port is owed a `Response`, and a segment for no port is owed
/// a `Reset`.  A stack that collected the reply and dropped it would have a
/// state machine whose answers never reached the peer.
pub(crate) fn deliver_dccp(
    segment_bytes: &[u8],
    source: net::address::Address,
    destination: [u8; 4],
) -> Result<()> {
    let segment = net::dccp::parse(segment_bytes)?;
    let data = &segment_bytes[segment.payload_at..segment.payload_at + segment.payload_len];
    let first = dccp_first_sequence();
    let reply = {
        let mut table = DCCP.lock();
        let reply = table.receive(&segment, data, source, first);
        // A Request that became a pending connection is what a parked accept is
        // waiting for, so this is where that wait ends.
        table.prune();
        reply
    };
    let _ = destination;
    // A segment that arrived is what a parked reader or acceptor was waiting
    // for: the wake is here, after the table's lock is down, for the reason
    // every other wake in this file is here and not inside a handler.
    let woken = crate::scheduler::wake_blocked();
    #[cfg(target_os = "none")]
    if woken > 0 {
        // SAFETY: the boot's own IPI path, installed before any program ran.
        unsafe { arch::send_ipi_to_others() };
    }
    #[cfg(not(target_os = "none"))]
    let _ = woken;
    match reply {
        net::dccp::Reply::None => Ok(()),
        net::dccp::Reply::Send(kind) => dccp_reply(&segment, source, kind),
        net::dccp::Reply::Reset(code) => dccp_reply_reset(&segment, source, code),
    }
}

/// Send a segment of `kind` answering one that arrived.
///
/// The ports are the arriving segment's, swapped: a reply goes back the way the
/// packet came, and the sequence number is a fresh one because this side's
/// numbers are its own.
fn dccp_reply(
    arrived: &net::dccp::Segment,
    peer: net::address::Address,
    kind: net::dccp::PacketType,
) -> Result<()> {
    let local = {
        let interface = INTERFACE.lock();
        let Some(interface) = interface.as_ref() else {
            return Err(Error::NotFound);
        };
        interface.protocol
    };
    let mut segment = alloc::vec![0; net::dccp::HEADER_LEN + 8 + 4 + 8];
    let length = net::dccp::write_segment(
        &mut segment,
        arrived.destination_port,
        arrived.source_port,
        &net::dccp::HeaderFields {
            kind,
            sequence: arrived.sequence.wrapping_add(1) & net::dccp::SEQUENCE_MASK,
            acknowledgement: Some(arrived.sequence),
            service_code: arrived.service_code,
            options: &[],
        },
        &[],
    ) as usize;
    segment.truncate(length);
    let sum = dccp_checksum(&segment, local, peer.as_v4().unwrap_or(local));
    segment[6..8].copy_from_slice(&sum.to_be_bytes());
    send_dccp_bytes(&segment, peer, local)
}

/// Send a Reset answering one that arrived.
fn dccp_reply_reset(
    arrived: &net::dccp::Segment,
    peer: net::address::Address,
    _code: u8,
) -> Result<()> {
    let local = {
        let interface = INTERFACE.lock();
        let Some(interface) = interface.as_ref() else {
            return Err(Error::NotFound);
        };
        interface.protocol
    };
    let mut segment = alloc::vec![0; net::dccp::HEADER_LEN + 8 + 4 + 8];
    let length = net::dccp::write_segment(
        &mut segment,
        arrived.destination_port,
        arrived.source_port,
        &net::dccp::HeaderFields {
            kind: net::dccp::PacketType::Reset,
            sequence: arrived.sequence.wrapping_add(1) & net::dccp::SEQUENCE_MASK,
            acknowledgement: Some(arrived.sequence),
            service_code: None,
            options: &[],
        },
        &[],
    ) as usize;
    segment.truncate(length);
    let sum = dccp_checksum(&segment, local, peer.as_v4().unwrap_or(local));
    segment[6..8].copy_from_slice(&sum.to_be_bytes());
    send_dccp_bytes(&segment, peer, local)
}

/// Put one built DCCP segment on the wire, or through the demux for a
/// loopback.
fn send_dccp_bytes(segment: &[u8], peer: net::address::Address, local: [u8; 4]) -> Result<()> {
    match peer {
        net::address::Address::V4(destination) => {
            // A reply is **never** handed back to the demux, and that is the
            // rule this function exists to keep: `deliver_dccp` sends its own
            // answer through here, so a loopback that re-entered it would
            // answer the answer, forever.  A segment this machine composes for
            // a peer on this machine leaves by the card like any other, and the
            // stack's own loopback is only for a **program's** send, which
            // enters the demux once.
            let _ = is_loopback_v4(destination);
            let interface = INTERFACE.lock();
            let Some(interface) = interface.as_ref() else {
                return Err(Error::NotFound);
            };
            let hardware = interface.hardware;
            let gateway_hardware = hardware_for_v4(interface, destination)?;
            let packet_len = netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + segment.len();
            let mut frame = alloc::vec![0; packet_len];
            net::ethernet::write_header(
                &mut frame,
                gateway_hardware,
                hardware,
                net::ethernet::ETHERTYPE_IPV4,
            );
            net::ipv4::write_header(
                &mut frame[netdev::ETHERNET_HEADER_LEN..],
                local,
                destination,
                net::dccp::PROTOCOL,
                segment.len(),
            );
            frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..].copy_from_slice(segment);
            interface.card.submit_frame(&frame)
        }
        net::address::Address::V6(_) => Err(Error::Unsupported),
    }
}
