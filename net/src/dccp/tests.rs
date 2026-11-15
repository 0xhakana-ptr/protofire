//! net/src/dccp/tests.rs
//!
//! The module's tests.
//!
//! A sibling file because the tests outgrew the module: a reader looking for
//! the mechanism should not scroll past them to find the end of it.

use super::Connection;
use super::HeaderFields;
use super::INBOX_LIMIT;
use super::MAX_DATAGRAM;
use super::PacketType;
use super::Reply;
use super::SEQUENCE_MASK;
use super::State;
use super::after;
use super::before;
use super::parse;
use super::write_segment;
use crate::address::Address;
use abi::Error;

const PEER: Address = Address::V4([10, 0, 2, 2]);
const SERVICE: u32 = 0x0000_0001;

/// A connection already open, for the tests that start after the
/// handshake.
///
/// Built by walking the handshake rather than by a constructor that skips
/// it: a test that could make an `Open` connection any other way would pass
/// on a state machine whose handshake does not work.
fn open_for_tests() -> Connection {
    let mut connection = Connection::connecting(5000, PEER, 5001, SERVICE, 100);
    let response = segment(PacketType::Response, 1);
    let _ = connection.receive(&response, &[]);
    connection
}

fn segment(kind: PacketType, sequence: u64) -> super::Segment {
    super::Segment {
        source_port: 5000,
        destination_port: 5001,
        kind,
        sequence,
        acknowledgement: None,
        service_code: None,
        reset_code: None,
        options: &[],
        payload_at: 0,
        payload_len: 0,
    }
}

/// A segment written by this module is read back by it, for every type.
///
/// The round trip is the point: a writer that put a field at one offset and
/// a reader that took it from another would build packets only this stack
/// could read, and the test would pass if both were wrong the same way, so
/// the two are also checked against the offsets [RFC 4340] names.
#[test]
fn a_segment_round_trips_for_every_type() {
    let kinds = [
        PacketType::Request,
        PacketType::Response,
        PacketType::Data,
        PacketType::Ack,
        PacketType::DataAck,
        PacketType::CloseReq,
        PacketType::Close,
        PacketType::Reset,
        PacketType::Sync,
        PacketType::SyncAck,
    ];
    for kind in kinds {
        let mut wire = [0_u8; 64];
        let payload = b"data";
        let length = write_segment(
            &mut wire,
            5000,
            5001,
            &HeaderFields {
                kind,
                sequence: 0x0000_1234_5678_9ABC,
                acknowledgement: Some(0x0000_0000_0000_0042),
                service_code: Some(SERVICE),
                options: &[],
            },
            payload,
        ) as usize;
        let parsed = parse(&wire[..length]).expect("a segment");
        assert_eq!(parsed.kind, kind, "type {kind:?}");
        assert_eq!(parsed.source_port, 5000);
        assert_eq!(parsed.destination_port, 5001);
        assert_eq!(parsed.sequence, 0x0000_1234_5678_9ABC & SEQUENCE_MASK);
        if kind.carries_acknowledgement() {
            assert_eq!(parsed.acknowledgement, Some(0x42), "type {kind:?}");
        }
        if kind.carries_service_code() {
            assert_eq!(parsed.service_code, Some(SERVICE));
        }
        assert_eq!(
            &wire[parsed.payload_at..parsed.payload_at + payload.len()],
            payload
        );
    }
}

/// The two X bits are both written and both checked.
///
/// Byte eight's bit 4 and byte nine's bit 7 carry one value, and a reader
/// that took one and ignored the other would misread a short-form packet:
/// the sequence number would come from the wrong six bytes, and the
/// resulting number would be a quiet wrong answer rather than an error.
#[test]
fn the_redundant_x_bit_must_agree() {
    let mut wire = [0_u8; 32];
    let length = write_segment(
        &mut wire,
        1,
        2,
        &HeaderFields {
            kind: PacketType::Data,
            sequence: 7,
            acknowledgement: None,
            service_code: None,
            options: &[],
        },
        b"x",
    ) as usize;
    assert!(parse(&wire[..length]).is_ok());
    // Disagree one way, then the other.
    wire[9] = 0;
    assert_eq!(parse(&wire[..length]), Err(Error::InvalidArgument));
    wire[9] = 0x80;
    wire[8] &= !0x10;
    assert_eq!(parse(&wire[..length]), Err(Error::InvalidArgument));
}

/// The short header is accepted, and its sequence number comes from its own
/// three bytes.
///
/// The form this writer never emits and every peer may: twenty-four bits in
/// bytes nine to eleven, with the X bit clear in both places.
#[test]
fn the_short_header_is_read() {
    let mut wire = [0_u8; 16];
    wire[0..2].copy_from_slice(&7_u16.to_be_bytes());
    wire[2..4].copy_from_slice(&9_u16.to_be_bytes());
    wire[4] = 3;
    wire[8] = PacketType::Data.to_wire();
    wire[9] = 0x01;
    wire[10] = 0x02;
    wire[11] = 0x03;
    let parsed = parse(&wire).expect("a short segment");
    assert_eq!(parsed.sequence, 0x01_0203);
    assert_eq!(parsed.kind, PacketType::Data);
    assert_eq!(parsed.payload_len, 4, "the payload starts at word three");
}

/// The reserved packet types are refused rather than read as something.
#[test]
fn the_reserved_types_are_refused() {
    for reserved in 10..=15_u8 {
        let mut wire = [0_u8; 16];
        wire[4] = 4;
        wire[8] = 0x10 | reserved;
        wire[9] = 0x80;
        assert_eq!(parse(&wire), Err(Error::InvalidArgument), "type {reserved}");
    }
}

/// A data offset pointing inside the header is refused.
///
/// The packet claims its payload starts before its own type-specific part
/// ended, which is two fields describing one byte range.
#[test]
fn a_data_offset_inside_the_header_is_refused() {
    let mut wire = [0_u8; 32];
    let length = write_segment(
        &mut wire,
        1,
        2,
        &HeaderFields {
            kind: PacketType::Request,
            sequence: 5,
            acknowledgement: None,
            service_code: Some(SERVICE),
            options: &[],
        },
        b"x",
    ) as usize;
    assert!(parse(&wire[..length]).is_ok());
    // Word three is past the generic header and inside the service code.
    wire[4] = 3;
    assert_eq!(parse(&wire[..length]), Err(Error::InvalidArgument));
}

/// The sequence comparison wraps, and a plain `>` does not.
///
/// The case a comparison without the mask gets wrong: a number one past the
/// wrap is **after** one just before it, and `1 > MASK` is false.
#[test]
fn the_sequence_comparison_wraps() {
    assert!(after(5, 4));
    assert!(!after(4, 5));
    assert!(!after(4, 4), "a number is not after itself");

    let near = SEQUENCE_MASK - 2;
    let wrapped = 1_u64;
    assert!(
        after(wrapped, near),
        "one past the wrap is after one before it"
    );
    assert!(before(near, wrapped));
    // And the naive comparison disagrees, which is the defect.
    assert!(wrapped < near, "the two orders differ at the wrap");
}

/// A client's handshake opens the connection, and a client may not send
/// before it does.
///
/// The three states: `RequestSent` after the first send, `Open` after the
/// Response, and `send` refused in between.
#[test]
fn a_client_opens_with_a_request_and_a_response() {
    let mut connection = Connection::connecting(5000, PEER, 5001, SERVICE, 100);
    assert_eq!(connection.state(), State::RequestSent);
    assert!(!connection.is_open());
    assert_eq!(connection.send(b"early"), Err(Error::InvalidArgument));

    // The Response arrives and is answered with an Ack.
    let mut response = segment(PacketType::Response, 200);
    response.service_code = Some(SERVICE);
    assert_eq!(
        connection.receive(&response, &[]),
        Reply::Send(PacketType::Ack)
    );
    assert_eq!(connection.state(), State::Open);
    assert!(connection.is_open());
    assert_eq!(connection.send(b"data").map(|_| ()), Ok(()));
}

/// A server answers a Request with a Response, and the client's Ack opens
/// it.
#[test]
fn a_server_opens_when_the_ack_arrives() {
    let mut connection = Connection::accepted(5001, PEER, 5000, SERVICE, 300, 100);
    assert_eq!(connection.state(), State::ResponseSent);
    assert!(!connection.is_open());

    let mut ack = segment(PacketType::Ack, 101);
    ack.acknowledgement = Some(101);
    assert_eq!(connection.receive(&ack, &[]), Reply::None);
    assert_eq!(connection.state(), State::Open);
}

/// A datagram inside the window is taken, and the inbox answers what
/// arrived.
#[test]
fn a_datagram_arrives_and_can_be_read() {
    let mut connection = open_for_tests();
    let mut data = segment(PacketType::Data, 10);
    data.acknowledgement = None;
    assert_eq!(
        connection.receive(&data, b"payload"),
        Reply::Send(PacketType::Ack)
    );
    assert_eq!(connection.inbox_len(), 1);

    let mut buffer = [0_u8; 32];
    assert_eq!(connection.read(&mut buffer), Ok(Some(7)));
    assert_eq!(&buffer[..7], b"payload");
    assert_eq!(connection.read(&mut buffer), Ok(None), "empty and open");
}

/// A datagram longer than the reader's buffer is refused and kept.
#[test]
fn a_small_buffer_is_refused_and_the_datagram_kept() {
    let mut connection = open_for_tests();
    connection.receive(&segment(PacketType::Data, 10), b"a datagram");
    let mut small = [0_u8; 4];
    assert_eq!(connection.read(&mut small), Err(Error::InvalidArgument));
    assert_eq!(connection.inbox_len(), 1, "and it is still there");
    let mut large = [0_u8; 32];
    assert_eq!(connection.read(&mut large), Ok(Some(10)));
}

/// A finished connection with an empty inbox answers end of file.
///
/// The distinction a reader's loop turns on: `None` is a wait, `Some(0)` is
/// the end.  A connection that answered `None` after finishing would make a
/// reader wait on a writer that is gone.
#[test]
fn a_finished_connection_answers_end_of_file() {
    let mut connection = open_for_tests();
    connection.receive(&segment(PacketType::Close, 11), &[]);
    assert!(connection.is_finished());
    let mut buffer = [0_u8; 8];
    assert_eq!(connection.read(&mut buffer), Ok(Some(0)));
}

/// A sequence outside the window is answered with a Reset.
///
/// Both edges: behind the window's low edge is too old, and past its high
/// one is further ahead than the buffer allows.
#[test]
fn a_sequence_outside_the_window_is_reset() {
    let mut connection = open_for_tests();
    // The window is [0, WINDOW] to start with.
    let too_far = super::WINDOW + 10;
    assert_eq!(
        connection.receive(&segment(PacketType::Data, too_far), b"x"),
        Reply::Reset(super::RESET_CODE_SEQUENCE_WINDOW)
    );
    assert_eq!(connection.state(), State::Closed);
}

/// A duplicate datagram is refused by the window, which is how DCCP drops a
/// repeat without a reader seeing it twice.
#[test]
fn a_duplicate_datagram_is_not_delivered_twice() {
    let mut connection = open_for_tests();
    assert_eq!(
        connection.receive(&segment(PacketType::Data, 10), b"once"),
        Reply::Send(PacketType::Ack)
    );
    // The same sequence again: the low edge moved past it.
    assert_eq!(
        connection.receive(&segment(PacketType::Data, 10), b"again"),
        Reply::Reset(super::RESET_CODE_SEQUENCE_WINDOW)
    );
    assert_eq!(connection.inbox_len(), 1);
}

/// A full inbox drops the newest rather than growing.
#[test]
fn a_full_inbox_drops_the_newest() {
    let mut connection = open_for_tests();
    for index in 0..INBOX_LIMIT {
        assert_eq!(
            connection.receive(&segment(PacketType::Data, 10 + index as u64), b"x"),
            Reply::Send(PacketType::Ack)
        );
    }
    assert_eq!(connection.inbox_len(), INBOX_LIMIT);
    connection.receive(&segment(PacketType::Data, 10 + INBOX_LIMIT as u64), b"y");
    assert_eq!(
        connection.inbox_len(),
        INBOX_LIMIT,
        "the count did not grow"
    );
    // The kept ones are the first ones.
    let mut buffer = [0_u8; 8];
    assert_eq!(connection.read(&mut buffer), Ok(Some(1)));
    assert_eq!(&buffer[..1], b"x");
}

/// A datagram larger than the bound is refused at the send.
#[test]
fn an_oversized_datagram_is_refused() {
    let mut connection = open_for_tests();
    let large = alloc::vec![0_u8; MAX_DATAGRAM + 1];
    assert_eq!(connection.send(&large), Err(Error::InvalidArgument));
    assert_eq!(
        connection
            .send(&alloc::vec![0_u8; MAX_DATAGRAM])
            .map(|_| ()),
        Ok(())
    );
}

/// A Request on an open connection is answered again rather than treated
/// as new.
#[test]
fn a_duplicate_request_is_answered_again() {
    let mut connection = open_for_tests();
    assert_eq!(
        connection.receive(&segment(PacketType::Request, 12), &[]),
        Reply::Send(PacketType::Response)
    );
    assert_eq!(
        connection.state(),
        State::Open,
        "and the state did not move"
    );
}

/// A CloseReq asks for a Close, and a Close finishes the connection.
#[test]
fn the_close_sequence() {
    let mut connection = open_for_tests();
    assert_eq!(
        connection.receive(&segment(PacketType::CloseReq, 10), &[]),
        Reply::Send(PacketType::Close)
    );
    assert_eq!(connection.state(), State::CloseReq);
    assert!(!connection.is_open(), "data no longer crosses");

    let mut second = open_for_tests();
    assert_eq!(
        second.receive(&segment(PacketType::Close, 10), &[]),
        Reply::None
    );
    assert_eq!(second.state(), State::TimeWait);
    assert!(second.is_finished());
}

/// A Reset closes whatever state the connection was in, and it is not
/// subject to the window.
///
/// The one packet whose sequence number does not matter: it is what a peer
/// sends when the two sides disagree, so requiring the window to agree
/// first would refuse exactly the packet that resolves the disagreement.
#[test]
fn a_reset_closes_from_any_state() {
    let mut connection = open_for_tests();
    assert_eq!(
        connection.receive(&segment(PacketType::Reset, 999_999), &[]),
        Reply::None
    );
    assert_eq!(connection.state(), State::Closed);
}

/// A port has one listener, and releasing it frees the port.
#[test]
fn a_listening_port_has_one_owner() {
    use super::Table;
    let mut table = Table::new();
    assert_eq!(table.listen(5000, None).map(|_| ()), Ok(()));
    assert_eq!(table.listen(5000, None), Err(Error::AlreadyExists));
    assert!(table.is_listening(5000));
    assert!(!table.is_listening(5001));
    assert!(table.unlisten(5000));
    assert!(!table.unlisten(5000), "the second says nothing was there");
    assert_eq!(
        table.listen(5000, None).map(|_| ()),
        Ok(()),
        "and it is free"
    );
}

/// A Request for a listening port makes a pending connection, and the
/// accept takes it.
#[test]
fn a_request_waits_at_a_listener_until_it_is_accepted() {
    use super::Table;
    let mut table = Table::new();
    table.listen(5000, Some(SERVICE)).expect("a listener");
    assert!(!table.has_pending(5000));

    let mut request = segment(PacketType::Request, 100);
    request.service_code = Some(SERVICE);
    request.destination_port = 5000;
    request.source_port = 4000;
    assert_eq!(
        table.receive(&request, &[], PEER, 900),
        Reply::Send(PacketType::Response)
    );
    assert!(table.has_pending(5000));
    assert_eq!(
        table.counts(),
        (0, 1),
        "a pending connection is not one yet"
    );

    let id = table.accept(5000).expect("an accept").expect("a Request");
    assert_eq!(table.counts(), (1, 1));
    let connection = table.connection(id).expect("the connection");
    assert_eq!(connection.state(), State::ResponseSent);
    assert_eq!(connection.peer(), (PEER, 4000));
    assert_eq!(connection.service_code(), SERVICE);
    assert!(!table.has_pending(5000), "and the queue is empty");
    assert_eq!(
        table.accept(5000).expect("an accept"),
        None,
        "nothing else is waiting"
    );
}

/// A listener naming a service code refuses a Request for another one.
#[test]
fn a_listener_refuses_another_service_code() {
    use super::Table;
    let mut table = Table::new();
    table.listen(5000, Some(SERVICE)).expect("a listener");
    let mut request = segment(PacketType::Request, 100);
    request.service_code = Some(SERVICE + 1);
    request.destination_port = 5000;
    request.source_port = 4000;
    assert_eq!(
        table.receive(&request, &[], PEER, 900),
        Reply::Reset(super::RESET_CODE_CONNECTION_REFUSED)
    );
    assert!(!table.has_pending(5000));
}

/// A packet for a port nothing answers on is answered with a Reset.
#[test]
fn a_packet_for_no_port_is_reset() {
    use super::Table;
    let mut table = Table::new();
    assert_eq!(
        table.receive(&segment(PacketType::Data, 1), b"x", PEER, 900),
        Reply::Reset(super::RESET_CODE_CONNECTION_REFUSED)
    );
}

/// A connection's own segments find it, and another peer's do not.
#[test]
fn a_connection_is_found_by_its_four_tuple() {
    use super::Table;
    let mut table = Table::new();
    let id = table
        .connect(5000, PEER, 5001, SERVICE, 100)
        .expect("a connection");
    assert!(table.find(5000, PEER, 5001).is_some());
    assert!(table.find(5000, PEER, 5002).is_none(), "another peer port");
    assert!(
        table.find(5000, Address::V4([10, 0, 2, 9]), 5001).is_none(),
        "another peer"
    );
    assert_eq!(table.connection(id).map(|c| c.local_port()), Some(5000));
}

/// A full backlog refuses the Request that would have grown it.
#[test]
fn a_full_backlog_refuses() {
    use super::Table;
    let mut table = Table::new();
    table.listen(5000, None).expect("a listener");
    for index in 0..super::BACKLOG {
        let mut request = segment(PacketType::Request, 100 + index as u64);
        request.service_code = Some(SERVICE);
        request.destination_port = 5000;
        request.source_port = 4000 + index as u16;
        assert_eq!(
            table.receive(&request, &[], PEER, 900),
            Reply::Send(PacketType::Response)
        );
    }
    let mut one_too_many = segment(PacketType::Request, 999);
    one_too_many.service_code = Some(SERVICE);
    one_too_many.destination_port = 5000;
    one_too_many.source_port = 4500;
    assert_eq!(
        table.receive(&one_too_many, &[], PEER, 900),
        Reply::Reset(super::RESET_CODE_CONNECTION_REFUSED)
    );
}

/// An id names the same connection after an earlier one is pruned.
///
/// The property a stored id has and a position does not: the first
/// connection is finished and pruned, and the second keeps the id it was
/// given rather than sliding into the first one's place.
#[test]
fn an_id_survives_a_prune() {
    use super::Table;
    let mut table = Table::new();
    let first = table
        .connect(5000, PEER, 5001, SERVICE, 100)
        .expect("a connection");
    let second = table
        .connect(5001, PEER, 5002, SERVICE, 200)
        .expect("a connection");
    assert_ne!(first, second);

    table
        .connection_mut(first)
        .expect("the first")
        .receive(&segment(PacketType::Reset, 1), &[]);
    table.prune();
    assert_eq!(table.counts().0, 1);
    let held = table.connection(second).expect("the second is still here");
    assert_eq!(held.id(), second, "and it is the one id two names");
    assert!(table.connection(first).is_none(), "and id one is gone");
}

/// Pruning drops closed connections and keeps everything else.
#[test]
fn pruning_drops_only_closed_connections() {
    use super::Table;
    let mut table = Table::new();
    let open = table
        .connect(5000, PEER, 5001, SERVICE, 100)
        .expect("a connection");
    let second = table
        .connect(5001, PEER, 5002, SERVICE, 200)
        .expect("a connection");
    {
        let connection = table.connection_mut(second).expect("the connection");
        connection.receive(&segment(PacketType::Reset, 1), &[]);
        assert_eq!(connection.state(), State::Closed);
    }
    table.prune();
    assert_eq!(table.counts().0, 1);
    assert!(
        table.connection(open).is_some(),
        "the open one is still here"
    );
}

/// A `DataAck` completes a server's handshake: the client's Ack and its
/// first datagram are one packet.
///
/// The transition this test exists for: a server in `ResponseSent` that
/// refused a `DataAck` would refuse the first thing the client ever sends,
/// because the client's handshake and its data are one segment.
#[test]
fn a_data_ack_opens_a_server_that_sent_its_response() {
    let mut connection = Connection::accepted(5001, PEER, 5000, SERVICE, 300, 100);
    assert_eq!(connection.state(), State::ResponseSent);

    // The client's first packet is a DataAck: it acknowledges the Response
    // and carries the first datagram.
    let mut first = segment(PacketType::DataAck, 101);
    first.acknowledgement = Some(300);
    assert_eq!(
        connection.receive(&first, b"first"),
        Reply::Send(PacketType::Ack)
    );
    assert_eq!(connection.state(), State::Open);
    assert_eq!(connection.inbox_len(), 1, "and the datagram arrived");
}

/// The connection's own words are what it was built with.
#[test]
fn a_connection_reports_its_own_stream() {
    let connection = Connection::connecting(5000, PEER, 5001, SERVICE, 100);
    assert_eq!(connection.local_port(), 5000);
    assert_eq!(connection.peer(), (PEER, 5001));
    assert_eq!(connection.service_code(), SERVICE);
    assert_eq!(connection.next_sequence(), 101, "one past the first");
}
