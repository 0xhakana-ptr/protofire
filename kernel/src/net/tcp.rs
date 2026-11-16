//! kernel/src/net/tcp.rs
//!
//! The streams: the calls, the segments, the retransmissions, and the demux
//! on both address families.
//!
//! One section of `kernel/src/net/mod.rs`.  The sections call each other in
//! both directions: the demux reaches every protocol's delivery and a protocol
//! reaches the interface, so each names what it needs through `super::`.  What
//! the split buys is that a reader looking for one protocol opens one file.

use alloc::vec::Vec;

use abi::Error;
use abi::Result;

use super::core::INTERFACE;
use super::core::TCP;
use super::core::hardware_for_v4;
use super::core::is_loopback;
use super::demux6::peer_hardware;
use super::filter::submit_filtered;

/// Open a listening port, answering the listener's id.
///
/// `AlreadyExists` when the port is taken, for the reason a bound datagram
/// port is: two listeners on one port would make one SYN two streams.
pub fn tcp_listen(port: u16) -> Result<usize> {
    TCP.lock().listen(port)
}

/// Whether a listener has a connection waiting to be accepted.
pub fn tcp_has_pending(listener: usize) -> bool {
    TCP.lock().has_pending(listener)
}

/// Take the connection a listener has been holding, answering its id.
///
/// `NotFound` for an id that names no listener, and `Ok(None)` when the
/// listener holds nothing, which is the caller's signal to park, the same
/// shape a datagram receive is.
pub fn tcp_accept(listener: usize) -> Result<Option<usize>> {
    TCP.lock().accept(listener)
}

/// Open a stream to `destination`'s port, answering the connection's id.
///
/// The handshake runs here, synchronously: the SYN goes out, the listener's
/// answer comes back through the demux, the client's acknowledgement goes
/// back, and by the time this returns both ends hold an open stream.  A
/// connect to another machine would have to wait for its answer on the
/// wire, which is a wait this build does not make a call do, the answer
/// for a destination that is not this machine is `Unsupported`, and the
/// exchange that proves the layer runs where the proof is, on loopback.
pub fn tcp_connect(destination: net::address::Address, destination_port: u16) -> Result<usize> {
    // A connect whose peer is not this machine would have to wait for its
    // answer on the wire, which is a wait this build does not make a call do.
    if !is_loopback(destination) {
        return Err(Error::Unsupported);
    }
    if !INTERFACE.lock().as_ref().is_some() {
        return Err(Error::NotFound);
    }

    let (id, noteworthy) = {
        let mut table = TCP.lock();
        let (id, outgoing) = table.connect((destination, destination_port));
        let queued = outgoing.into_iter().map(|segment| (id, segment)).collect();
        let noteworthy = tcp_exchange(&mut table, queued)?;
        (id, noteworthy)
    };
    // The handshake a connect starts is what a parked accept was waiting
    // for, and the wake is here because the table's lock is down.
    note_stream_wake(noteworthy);
    Ok(id)
}

/// Write bytes onto a stream, answering how many were carried.
///
/// The count is the whole write: a stream carries what it is given in one
/// segment, and a partial write on a stream this size would be a caller
/// re-writing bytes the first write already took.
pub fn tcp_write(id: usize, bytes: &[u8]) -> Result<usize> {
    let (count, noteworthy) = {
        let mut table = TCP.lock();
        let Some(connection) = table.connection_mut(id) else {
            return Err(Error::InvalidArgument);
        };
        let (count, outgoing) = connection.send_data(bytes);
        let queued = outgoing.into_iter().map(|segment| (id, segment)).collect();
        let noteworthy = tcp_exchange(&mut table, queued)?;
        (count, noteworthy)
    };
    // The bytes a stream carried are what a parked reader was waiting for.
    note_stream_wake(noteworthy);
    Ok(count)
}

/// Where a stream's two ends are: this machine's own port and the peer.
///
/// One call rather than two because the two are a single fact about one
/// connection and a caller asking for both would otherwise take the lock twice.
pub fn stream_ends(id: usize) -> Option<(u16, (net::address::Address, u16))> {
    let table = TCP.lock();
    let connection = table.connection(id)?;
    Some((connection.local_port(), connection.remote()))
}

/// Set one option on a stream, answering what the connection answered.
///
/// The table's lock is taken once and released before the caller returns: a
/// setter does not send, so nothing here re-enters the demux, and the option's
/// effect is on the next segment the connection builds rather than on one in
/// flight.
pub fn set_stream_option(id: usize, level: u32, name: u32, value: &[u8]) -> Result<()> {
    let mut table = TCP.lock();
    let connection = table.connection_mut(id).ok_or(Error::NotFound)?;
    connection.set_option(level, name, value)
}

/// Read one option from a stream, answering the bytes written.
pub fn stream_option(id: usize, level: u32, name: u32, into: &mut [u8]) -> Result<usize> {
    let table = TCP.lock();
    let connection = table.connection(id).ok_or(Error::NotFound)?;
    connection.get_option(level, name, into)
}

/// Whether a stream has bytes its reader has not taken.
pub fn tcp_has_data(id: usize) -> bool {
    TCP.lock().has_data(id)
}

/// Read bytes off a stream, answering how many.
///
/// `None` is "nothing arrived, ask again", the answer a caller parks on,
/// the same shape a datagram receive is.  A stream whose connection is gone
/// reached its close, and answers zero: end of file, which is what a reader
/// whose writer finished reads.  A read that never answered zero would be a
/// reader parked on a writer that said it was done.
pub fn tcp_read(id: usize, into: &mut [u8]) -> Result<Option<usize>> {
    let mut table = TCP.lock();
    let Some(connection) = table.connection_mut(id) else {
        return Ok(Some(0));
    };
    if connection.inbox_len() == 0 {
        // An empty inbox is "ask again" only while a peer could still fill
        // it.  A stream whose close is over cannot, so its empty read is
        // end-of-file: `TimeWait` is the state that made this distinction
        // necessary, because the entry is still in the table and a reader
        // parked on it would otherwise wait for a writer that has finished.
        return Ok(match connection.state() {
            net::tcp::State::TimeWait | net::tcp::State::Closed => Some(0),
            _ => None,
        });
    }
    Ok(Some(connection.take(into)))
}

/// Close a stream: the FIN, the peer's, and the acknowledgements that cross
/// between them.
///
/// A close of an id that names nothing is `Ok`, because the close already
/// happened, the orderly one this call ran, or the abrupt one a process's
/// exit ran when it released its descriptors.
pub fn tcp_close(id: usize) -> Result<()> {
    let noteworthy = {
        let mut table = TCP.lock();
        let Some(connection) = table.connection_mut(id) else {
            return Ok(());
        };
        let outgoing = connection.close();
        let queued = outgoing.into_iter().map(|segment| (id, segment)).collect();
        let noteworthy = tcp_exchange(&mut table, queued)?;
        table.prune();
        noteworthy
    };
    // The finish a close sends is what a parked reader's end of file is.
    note_stream_wake(noteworthy);
    Ok(())
}

/// Wake what a stream event parked, from a context that holds no lock.
///
/// The count is printed when it is not zero, because the wake is the fact
/// the parked caller's retry answers, and the IPI, for the reason every
/// wake here carries one: the woken task may be held by another CPU parked
/// in a wait whose own clock may never move.
pub(crate) fn note_stream_wake(noteworthy: bool) {
    if !noteworthy {
        return;
    }
    let woken = crate::scheduler::wake_blocked();
    if woken > 0 {
        #[cfg(target_os = "none")]
        {
            arch::serial::write_str("protofire: a stream event woke ");
            arch::serial::write_u32(woken as u32);
            arch::serial::write_str(" blocked task(s)\n");
            // SAFETY: the boot's own IPI path, installed before any program
            // ran.
            unsafe { arch::send_ipi_to_others() };
        }
        #[cfg(not(target_os = "none"))]
        let _ = woken;
    }
}

/// Carry one connection's outgoing segments to their peers, and everything
/// the peers answer back, until the wire is quiet.
///
/// This is the loopback the protocol crate's tests run on, in the kernel:
/// a segment for this machine is delivered to the peer's own state machine
/// inside the same locked region, whose replies queue behind it, and the
/// loop runs until nothing is left.  A segment for another machine goes out
/// through the card in an IPv4 packet, which is the whole of the
/// difference between the two wires, the state machine never learns which
/// one carried its bytes.
pub(crate) fn tcp_exchange(
    table: &mut net::tcp_table::Table,
    queue: Vec<(usize, net::tcp::Outgoing)>,
) -> Result<bool> {
    // Whether anything happened that a parked caller was waiting for: a
    // connection a SYN opened, bytes that landed in a stream's inbox, a
    // finish that ends a read.  The answer comes back to the caller, which
    // wakes **after** this function returns, the table's lock is its
    // caller's, and the scheduler's is never taken inside it.
    let mut noteworthy = false;
    let mut queue = queue;
    while let Some((sender_id, outgoing)) = queue.pop() {
        // The sender's own facts, read before anything is delivered: where
        // the segment goes, and what port it names itself from.
        let Some((address, destination_port)) = table.remote_of(sender_id) else {
            // The sender's close finished while its last segment was in
            // flight; the segment has nowhere to name itself from, and a
            // wire that carried it would be a wire answering a closed
            // stream.
            continue;
        };
        let Some(sender_port) = table.local_port_of(sender_id) else {
            continue;
        };

        if is_loopback(address) {
            let interface = INTERFACE.lock();
            let Some(interface) = interface.as_ref() else {
                return Err(Error::NotFound);
            };
            // The address this machine's own end of a loopback exchange is
            // known by: the protocol address for IPv4, the link-local one for
            // IPv6, which is the address a solicitation is answered from.
            let local = match address {
                net::address::Address::V4(_) => net::address::Address::V4(interface.protocol),
                net::address::Address::V6(_) => net::address::Address::V6(interface.ipv6),
            };
            // A SYN for a listening port opens a connection right here: the
            // listener answers inside the same exchange, whose SYN with ACK
            // queues behind this one, and the connection waits in the
            // listener's pending list for the accept that takes it.
            if outgoing.flags & net::tcp::FLAG_SYN != 0
                && outgoing.flags & net::tcp::FLAG_ACK == 0
                && table
                    .connection_for(destination_port, local, sender_port)
                    .is_none()
            {
                let Some((id, replies)) = table.accept_syn(
                    &net::tcp::Segment::new(
                        sender_port,
                        destination_port,
                        outgoing.sequence,
                        outgoing.acknowledgement,
                        outgoing.flags,
                        outgoing.window,
                        outgoing.payload.len(),
                    ),
                    (local, sender_port),
                ) else {
                    // A SYN for a port nothing listens on: dropped, the way
                    // a datagram for an unbound port is.
                    continue;
                };
                noteworthy = true;
                queue.extend(replies.into_iter().map(|reply| (id, reply)));
                continue;
            }
            let Some(peer_id) = table.connection_for(destination_port, local, sender_port) else {
                // A segment for a stream this table does not hold: the peer
                // is gone, and a wire that carried the segment would be a
                // wire talking to nobody.  Dropped, the way a segment to a
                // closed port is.
                continue;
            };
            // The window the segment advertises, read from the segment rather
            // than restated: it is what the sender's own buffers had room for
            // at the moment it was built.  A segment the loopback carries
            // states no receive buffer, so `Segment::new`'s "nothing said" is
            // right for it: the option is a handshake's and the connection
            // learned this side's MSS when the SYN that opened it arrived.
            let segment = net::tcp::Segment::new(
                sender_port,
                destination_port,
                outgoing.sequence,
                outgoing.acknowledgement,
                outgoing.flags,
                outgoing.window,
                outgoing.payload.len(),
            );
            let connection = table
                .connection_mut(peer_id)
                .expect("the id came from this table");
            let (answer, replies) = connection.receive(&segment, &outgoing.payload);
            answer?;
            noteworthy |= matches!(
                answer,
                Ok(net::tcp::Event::Data(_)) | Ok(net::tcp::Event::PeerFinished)
            );
            queue.extend(replies.into_iter().map(|reply| (peer_id, reply)));
        } else {
            tcp_send_on_wire(table, sender_port, address, destination_port, &outgoing)?;
        }
    }
    Ok(noteworthy)
}

/// Put one segment in an IPv4 packet and give it to the card.
fn tcp_send_on_wire(
    table: &mut net::tcp_table::Table,
    sender_port: u16,
    address: net::address::Address,
    destination_port: u16,
    outgoing: &net::tcp::Outgoing,
) -> Result<()> {
    let _ = table;
    let interface = INTERFACE.lock();
    let Some(interface) = interface.as_ref() else {
        return Err(Error::NotFound);
    };
    let (our_hardware, our_protocol) = (interface.hardware, interface.protocol);
    // A SYN carries the MSS option and every other segment does not, so the
    // header's length is the segment's and not a constant: a frame sized by
    // `HEADER_LEN` for a SYN is four bytes short, and the writer's option
    // would run past it.
    let header = if outgoing.flags & net::tcp::FLAG_SYN != 0 {
        net::tcp::SYN_HEADER_LEN
    } else {
        net::tcp::HEADER_LEN
    };
    let tcp_len = header + outgoing.payload.len();
    match address {
        net::address::Address::V4(destination) => {
            // The gateway's hardware address is this build's whole routing
            // decision for IPv4: one interface, one gateway.
            let gateway_hardware = hardware_for_v4(interface, destination)?;
            let packet_len = netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + tcp_len;
            let mut frame = alloc::vec![0; packet_len];
            net::ethernet::write_header(
                &mut frame,
                gateway_hardware,
                our_hardware,
                net::ethernet::ETHERTYPE_IPV4,
            );
            net::ipv4::write_header(
                &mut frame[netdev::ETHERNET_HEADER_LEN..],
                our_protocol,
                destination,
                net::ipv4::PROTOCOL_TCP,
                tcp_len,
            );
            net::tcp::write_segment(
                &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..],
                our_protocol,
                destination,
                sender_port,
                destination_port,
                outgoing.sequence,
                outgoing.acknowledgement,
                outgoing.flags,
                outgoing.window,
                &outgoing.payload,
            );
            submit_filtered(
                interface.card.as_ref(),
                &frame,
                &net::filter::Packet::v4(
                    our_protocol,
                    destination,
                    net::ipv4::PROTOCOL_TCP,
                    &frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..],
                ),
            )
        }
        net::address::Address::V6(destination) => {
            // No router address to route by yet: an IPv6 packet for another
            // machine goes to the neighbour cache's answer for its own
            // address, which is the neighbour discovery this stack has.
            let destination_hardware = peer_hardware(destination);
            let local = interface.ipv6;
            let packet_len = netdev::ETHERNET_HEADER_LEN + net::ipv6::HEADER_LEN + tcp_len;
            let mut frame = alloc::vec![0; packet_len];
            net::ethernet::write_header(
                &mut frame,
                destination_hardware,
                our_hardware,
                net::ethernet::ETHERTYPE_IPV6,
            );
            net::ipv6::write_header(
                &mut frame[netdev::ETHERNET_HEADER_LEN..],
                local,
                destination,
                net::ipv6::NEXT_TCP,
                tcp_len,
            );
            net::tcp::write_segment6(
                &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv6::HEADER_LEN..],
                local,
                destination,
                sender_port,
                destination_port,
                outgoing.sequence,
                outgoing.acknowledgement,
                outgoing.flags,
                outgoing.window,
                &outgoing.payload,
            );
            submit_filtered(
                interface.card.as_ref(),
                &frame,
                &net::filter::Packet::v6(
                    local,
                    destination,
                    net::ipv6::NEXT_TCP,
                    &frame[netdev::ETHERNET_HEADER_LEN + net::ipv6::HEADER_LEN..],
                ),
            )
        }
    }
}

/// What the pump does with a TCP segment: route it to the connection it
/// names, or open one for it on a listener.
///
/// The SYN's connection is created here, with the listener's answer sent
/// before the accept ever runs, which is why a client's connect completes
/// against a listener nothing has accepted from yet, and why the data
/// before an accept is in the connection's own inbox when the accept
/// returns it.
pub(crate) fn demux_tcp(packet: net::ipv4::Packet, payload: &[u8]) -> bool {
    let Some(segment) = net::tcp::parse(payload, packet.header.source, packet.header.destination)
    else {
        return false;
    };
    let mut table = TCP.lock();
    table.prune();

    // A SYN for a listening port opens a connection.
    if net::tcp_table::Table::is_opening(&segment) {
        let Some((id, outgoing)) = table.accept_syn(
            &segment,
            (
                net::address::Address::V4(packet.header.source),
                segment.source_port,
            ),
        ) else {
            return false;
        };
        let queued = outgoing.into_iter().map(|segment| (id, segment)).collect();
        let _ = tcp_exchange(&mut table, queued);
        // A connection opened is what a parked accept was waiting for.
        return true;
    }

    let Some(id) = table.connection_for(
        segment.destination_port,
        net::address::Address::V4(packet.header.source),
        segment.source_port,
    ) else {
        return false;
    };
    let noteworthy = table.has_data(id) || segment.flags & net::tcp::FLAG_FIN != 0;
    let connection = table
        .connection_mut(id)
        .expect("the id came from this table");
    // The segment's **data**, not the packet: `receive`'s second argument is
    // the peer's bytes, and handing it the whole packet put the segment's own
    // header at the front of the stream.  The offset is the parser's, and it is
    // why `Segment` carries one: a segment with options has its data past them,
    // and only the data offset knows where.  Both demux paths had this defect,
    // which no loopback exchange could show: the loopback hands a connection
    // the payload it built, never a frame.
    let data = &payload[segment.payload_at..segment.payload_at + segment.payload_len];
    let (answer, replies) = connection.receive(&segment, data);
    let _ = answer;
    if !replies.is_empty() {
        let queued = replies.into_iter().map(|segment| (id, segment)).collect();
        let _ = tcp_exchange(&mut table, queued);
    }
    // Anything the peer has waiting is what a parked reader was waiting
    // for, but the wake takes the scheduler's lock, and this function
    // holds the table's, so the answer is returned and the wake happens
    // where the lock is no longer held.
    noteworthy
}

/// Route one IPv6 segment, and wake what a parked reader was waiting for.
///
/// The wake is here rather than inside [`demux_tcp6`] because that function
/// holds the connection table's lock, and the scheduler's is never taken while
/// it is held: the routing answers whether anything a parked caller cares
/// about happened, the table's lock drops when that function returns, and this
/// one wakes after it.
pub(crate) fn route_stream6(packet: &net::ipv6::Packet, payload: &[u8]) {
    if !demux_tcp6(packet, payload) {
        return;
    }
    let woken = crate::scheduler::wake_blocked();
    #[cfg(target_os = "none")]
    if woken > 0 {
        // SAFETY: the boot's own IPI path, installed before any program ran.
        unsafe { arch::send_ipi_to_others() };
    }
    #[cfg(not(target_os = "none"))]
    let _ = woken;
}

/// What the pump does with a TCP segment that arrived over IPv6.
///
/// The same routing the IPv4 demux does, against the same table: a connection
/// is keyed by the port it answers on and the peer it answers for, and the
/// family is part of the peer because [`net::address::Address`] carries it.
/// A SYN for a listening port opens a connection; anything else joins one, and
/// a segment for a stream this table does not hold is dropped.
fn demux_tcp6(packet: &net::ipv6::Packet, payload: &[u8]) -> bool {
    let Some(segment) = net::tcp::parse6(payload, packet.header.source, packet.header.destination)
    else {
        return false;
    };
    let peer = net::address::Address::V6(packet.header.source);
    let mut table = TCP.lock();
    table.prune();

    if net::tcp_table::Table::is_opening(&segment) {
        let Some((id, outgoing)) = table.accept_syn(&segment, (peer, segment.source_port)) else {
            return false;
        };
        let queued = outgoing.into_iter().map(|segment| (id, segment)).collect();
        let _ = tcp_exchange(&mut table, queued);
        return true;
    }

    let Some(id) = table.connection_for(segment.destination_port, peer, segment.source_port) else {
        return false;
    };
    let noteworthy = table.has_data(id) || segment.flags & net::tcp::FLAG_FIN != 0;
    let connection = table
        .connection_mut(id)
        .expect("the id came from this table");
    // The same defect the IPv4 path had, and the same fix: the connection is
    // handed the segment's data, whose start only the data offset knows.
    let data = &payload[segment.payload_at..segment.payload_at + segment.payload_len];
    let (answer, replies) = connection.receive(&segment, data);
    let _ = answer;
    if !replies.is_empty() {
        let queued = replies.into_iter().map(|segment| (id, segment)).collect();
        let _ = tcp_exchange(&mut table, queued);
    }
    noteworthy
}
