//! net/src/transport/tcp/tests.rs
//!
//! The module's tests.
//!
//! A sibling file because the tests outgrew the module: a reader looking for
//! the mechanism should not scroll past them to find the end of it.

use super::Connection;
use super::Event;
use super::FLAG_ACK;
use super::FLAG_FIN;
use super::FLAG_PSH;
use super::FLAG_SYN;
use super::HEADER_LEN;
use super::Outgoing;
use super::Segment;
use super::State;
use super::parse;
use super::write_segment;
use crate::address::Address;

const US: [u8; 4] = [10, 0, 2, 15];
const OUR_PORT: u16 = 50000;
const THEIR_PORT: u16 = 9000;

/// The loopback the tests run on: each side's outgoing segments queue
/// here, and [`drain`] hands every one to the peer's own state machine
/// until the wire is quiet.  This is what the kernel's demux does for a
/// segment this machine sends to itself, which is why the handshake
/// here finishes in one drain, and why the kernel's own loopback
/// behaves the same way.
fn drain(
    client_out: &mut alloc::vec::Vec<Outgoing>,
    server_out: &mut alloc::vec::Vec<Outgoing>,
    client: &mut Connection,
    server: &mut Connection,
) {
    loop {
        if client_out.is_empty() && server_out.is_empty() {
            return;
        }
        while let Some(item) = client_out.pop() {
            let (answer, replies) =
                server.receive(&segment(OUR_PORT, THEIR_PORT, &item), &item.payload);
            let _ = answer;
            server_out.extend(replies);
        }
        while let Some(item) = server_out.pop() {
            let (answer, replies) =
                client.receive(&segment(THEIR_PORT, OUR_PORT, &item), &item.payload);
            let _ = answer;
            client_out.extend(replies);
        }
    }
}

/// An outgoing segment as the peer reads it: the header's fields with
/// the ports set from the direction it travels.
fn segment(source_port: u16, destination_port: u16, outgoing: &Outgoing) -> Segment {
    Segment::new(
        source_port,
        destination_port,
        outgoing.sequence,
        outgoing.acknowledgement,
        outgoing.flags,
        super::WINDOW,
        outgoing.payload.len(),
    )
}

/// The handshake's first three moves, run once and returned in the open
/// state.
fn handshake() -> (Connection, Connection) {
    let (mut client, mut client_out) =
        Connection::connect(OUR_PORT, (Address::V4(US), THEIR_PORT), 1000);
    assert_eq!(client.state(), State::SynSent);
    assert_eq!(client_out.len(), 1, "the SYN");
    assert_eq!(client_out[0].flags, FLAG_SYN);

    // The SYN reaches a listener, which builds the server's end and
    // answers with its own SYN with ACK.
    let syn = client_out.pop().expect("the SYN");
    let (mut server, mut server_out) =
        Connection::accept_syn(THEIR_PORT, (Address::V4(US), OUR_PORT), 5000, syn.sequence);
    assert_eq!(server.state(), State::SynReceived);

    drain(&mut client_out, &mut server_out, &mut client, &mut server);
    assert_eq!(client.state(), State::Established);
    assert_eq!(server.state(), State::Established);
    (client, server)
}

/// The handshake, over the loopback: a connect whose SYN the listener
/// answers, the answer the client answers back, and both ends in the
/// open state by the time the drain is quiet.
#[test]
fn a_handshake_finishes_on_the_loopback() {
    let _ = handshake();
}

/// A stream that carries data both ways, and the acknowledgements the
/// carries pull behind them.
#[test]
fn a_stream_carries_data_both_ways() {
    let (mut client, mut server) = handshake();
    let mut client_out = alloc::vec::Vec::new();
    let mut server_out = alloc::vec::Vec::new();

    // The client sends; the server's inbox takes it, and the ACK is the
    // only thing that crosses the wire for it.
    let (sent, outgoing) = client.send_data(b"protofire");
    assert_eq!(sent, 9);
    assert_eq!(outgoing.len(), 1, "one segment");
    assert_eq!(outgoing[0].flags, FLAG_ACK | FLAG_PSH);
    client_out.extend(outgoing);
    drain(&mut client_out, &mut server_out, &mut client, &mut server);
    assert_eq!(server.inbox_len(), 9);

    let mut buffer = [0_u8; 16];
    assert_eq!(server.take(&mut buffer), 9);
    assert_eq!(&buffer[..9], b"protofire");

    // The server answers; the client's inbox takes that.
    let (sent, outgoing) = server.send_data(b"back");
    assert_eq!(sent, 4);
    server_out.extend(outgoing);
    drain(&mut client_out, &mut server_out, &mut client, &mut server);
    assert_eq!(client.inbox_len(), 4);
    let mut buffer = [0_u8; 16];
    assert_eq!(client.take(&mut buffer), 4);
    assert_eq!(&buffer[..4], b"back");
}

/// The orderly close: one side finishes, the peer answers with its own,
/// and both ends are closed by the time the wire is quiet.
#[test]
fn an_orderly_close_ends_both_ends() {
    let (mut client, mut server) = handshake();
    let mut client_out = alloc::vec::Vec::new();
    let mut server_out = alloc::vec::Vec::new();

    client_out.extend(client.close());
    assert_eq!(client.state(), State::FinWait);
    assert_eq!(client_out[0].flags, FLAG_ACK | FLAG_FIN, "the FIN");
    drain(&mut client_out, &mut server_out, &mut client, &mut server);
    assert_eq!(server.state(), State::CloseWait, "the peer's finish landed");

    server_out.extend(server.close());
    assert_eq!(server.state(), State::LastAck);
    drain(&mut client_out, &mut server_out, &mut client, &mut server);
    // Both ends are done, and both **hold the four-tuple**: the close is
    // over and the entry stays so a retransmitted finish is answered
    // rather than reset.  `TimeWait` is the state that says both of those
    // things at once, and it is why this is not `Closed`.
    assert_eq!(
        client.state(),
        State::TimeWait,
        "the last exchange closed it"
    );
    assert_eq!(server.state(), State::TimeWait, "and the other end with it");

    // The hold ends on the caller's clock, and not before: a stream that
    // left `TimeWait` the moment it entered would be the `Closed` this
    // replaced.
    client.advance(super::TIME_WAIT_MICROS - 1);
    assert!(!client.time_wait_elapsed(), "the hold has not run out");
    client.advance(super::TIME_WAIT_MICROS);
    assert!(client.time_wait_elapsed(), "and then it has");
}

/// A stream whose peer has not finished waits in `FinWait2`, not `Closed`.
///
/// The defect this pins: this side's FIN acknowledged used to move the
/// stream straight to `Closed`, so a peer that had not said its own finish
/// yet found no connection when it did, and this stack answered a segment
/// for a port nothing owns with a reset, which is a close the peer never
/// asked for.  `FinWait2` is the state that is done sending and still
/// listening.
#[test]
fn an_acknowledged_fin_waits_in_fin_wait2_for_the_peers() {
    let (mut client, mut server) = handshake();
    let mut client_out = alloc::vec::Vec::new();
    let mut server_out = alloc::vec::Vec::new();

    client_out.extend(client.close());
    assert_eq!(client.state(), State::FinWait);
    drain(&mut client_out, &mut server_out, &mut client, &mut server);
    assert_eq!(
        client.state(),
        State::FinWait2,
        "the peer acknowledged the finish and has not sent its own"
    );
    assert_eq!(server.state(), State::CloseWait, "and the peer read it");

    // Data still flows the other way: a half-closed stream reads.
    let (sent, outgoing) = server.send_data(b"still here");
    assert_eq!(sent, 10);
    server_out.extend(outgoing);
    drain(&mut client_out, &mut server_out, &mut client, &mut server);
    assert_eq!(client.inbox_len(), 10, "and the reader got it");

    // The peer's finish is what ends the hold's beginning.
    server_out.extend(server.close());
    drain(&mut client_out, &mut server_out, &mut client, &mut server);
    assert_eq!(client.state(), State::TimeWait, "both finished");
}

/// A finish that crosses this side's lands in `Closing`, and the peer's
/// acknowledgement of this side's is what ends it.
///
/// The other half of the close, and the state this stack did not have: the
/// peer's finish can arrive before this side's own has been acknowledged,
/// and the stream is then done in both directions with one
/// acknowledgement still owed.  `Closing` is that, and the acknowledgement
/// it is waiting for is what moves it to `TimeWait`.
#[test]
fn a_crossing_finish_lands_in_closing() {
    let (mut client, mut server) = handshake();
    // Both sides say finish before either has heard the other's, which is
    // what a crossing is.
    let client_fin = client.close();
    let server_fin = server.close();
    assert_eq!(client.state(), State::FinWait);
    assert_eq!(server.state(), State::FinWait);

    // The server's finish reaches the client with **no acknowledgement**
    // in it: a FIN that also acknowledged this side's would move the
    // stream to `FinWait2` first, and `FinWait2` is the state where this
    // side's finish is already acknowledged.  The crossing is a FIN that
    // says nothing about it.
    for outgoing in server_fin {
        let crossing = super::Segment::new(
            server.local_port(),
            client.local_port(),
            outgoing.sequence,
            outgoing.acknowledgement,
            FLAG_FIN,
            super::WINDOW,
            0,
        );
        let (_, _) = client.receive(&crossing, b"");
        assert_eq!(client.state(), State::Closing, "the crossing");
    }

    // The client's acknowledgement of the server's finish, and the
    // server's of the client's, finish both.
    for outgoing in client_fin {
        let segment = segment(client.local_port(), server.local_port(), &outgoing);
        let (_, _) = server.receive(&segment, &outgoing.payload);
    }
    let _ = client.receive(
        &super::Segment::new(
            server.local_port(),
            client.local_port(),
            client.expected_position().wrapping_sub(1),
            client.send_position(),
            FLAG_ACK,
            super::WINDOW,
            0,
        ),
        b"",
    );
    assert_eq!(client.state(), State::TimeWait, "both acknowledged");
}

/// A retransmitted finish lands on `TimeWait` and is answered again.
///
/// The reason the hold exists.  A peer whose acknowledgement of its own
/// FIN was lost sends the FIN again, and the second one reaches a
/// four-tuple this side has already closed.  `TimeWait` answers it with
/// the same acknowledgement; a stream that had gone to `Closed` would have
/// been pruned, and the segment would reach nothing, which this stack
/// answers with a reset.
#[test]
fn a_retransmitted_finish_is_answered_in_time_wait() {
    let (mut client, mut server) = handshake();
    let mut client_out = alloc::vec::Vec::new();
    let mut server_out = alloc::vec::Vec::new();

    client_out.extend(client.close());
    drain(&mut client_out, &mut server_out, &mut client, &mut server);
    server_out.extend(server.close());
    drain(&mut client_out, &mut server_out, &mut client, &mut server);
    assert_eq!(client.state(), State::TimeWait);

    // The peer's finish again, exactly as it was sent the first time.
    let repeated = super::Segment::new(
        server.local_port(),
        client.local_port(),
        client.expected_position().wrapping_sub(1),
        client.send_position(),
        FLAG_ACK | FLAG_FIN,
        super::WINDOW,
        0,
    );
    let (event, replies) = client.receive(&repeated, b"");
    assert_eq!(event, Ok(Event::None), "nothing new happened");
    assert_eq!(replies.len(), 1, "and the acknowledgement went again");
    assert_eq!(
        replies[0].flags, FLAG_ACK,
        "which is the same bare acknowledgement"
    );
    assert_eq!(
        replies[0].acknowledgement,
        client.expected_position(),
        "naming the position it named before"
    );
    assert_eq!(client.state(), State::TimeWait, "and the hold continues");
}

/// A write after a close answers zero, because the send side is
/// finished and a stream carries nothing after its FIN.
#[test]
fn a_write_after_a_close_carries_nothing() {
    let (mut client, mut server) = handshake();
    let mut client_out = alloc::vec::Vec::new();
    let mut server_out = alloc::vec::Vec::new();

    client_out.extend(client.close());
    drain(&mut client_out, &mut server_out, &mut client, &mut server);

    let (sent, outgoing) = client.send_data(b"late");
    assert_eq!(sent, 0, "the stream is half-closed at the sender");
    assert!(outgoing.is_empty(), "and nothing went on the wire");
}

/// A segment ahead of the expected position is held, and the moment the
/// gap fills it reaches the inbox in sequence order.
///
/// This used to be a drop test, and what it asserted was the defect: a
/// wire may reorder, and a stack that dropped every early segment asked
/// the peer to send it again and again until the gap filled, which is a
/// stream whose speed is the round trip's.
#[test]
fn a_segment_ahead_of_the_gap_is_held_until_it_fills() {
    let (_client, mut server) = handshake();
    let base = server.acknowledgement;

    // Four bytes past the hole.
    let second = Segment::new(
        OUR_PORT,
        THEIR_PORT,
        base + 4,
        5001,
        FLAG_ACK | FLAG_PSH,
        super::WINDOW,
        4,
    );
    let (answer, replies) = server.receive(&second, b"wxyz");
    assert_eq!(answer, Ok(Event::None), "nothing reached a reader yet");
    assert_eq!(replies.len(), 1, "the duplicate ACK that names the hole");
    assert_eq!(
        replies[0].acknowledgement, base,
        "the position the peer should fill, not the one it sent past"
    );
    assert_eq!(server.inbox_len(), 0);
    assert_eq!(server.out_of_order(), 1, "the segment is held");

    // The hole fills, and both runs land in order.
    let first = Segment::new(
        OUR_PORT,
        THEIR_PORT,
        base,
        5001,
        FLAG_ACK | FLAG_PSH,
        super::WINDOW,
        4,
    );
    let (answer, _) = server.receive(&first, b"abcd");
    assert_eq!(answer, Ok(Event::Data(8)), "both runs reached the inbox");
    assert_eq!(server.out_of_order(), 0, "the held segment was taken");
    assert_eq!(server.inbox_len(), 8);

    let mut buffer = [0_u8; 8];
    assert_eq!(server.take(&mut buffer), 8);
    assert_eq!(&buffer, b"abcdwxyz", "sequence order, not arrival order");
}

/// The far end of a hole may arrive first, and the walk keeps going: a
/// cache filled backwards becomes a whole stream the moment the first
/// hole closes.
#[test]
fn several_held_segments_all_land_when_the_gap_closes() {
    let (_client, mut server) = handshake();
    let base = server.acknowledgement;

    for (offset, data) in [(12u32, &b"mnop"[..]), (8, b"ijkl"), (4, b"efgh")] {
        let segment = Segment::new(
            OUR_PORT,
            THEIR_PORT,
            base + offset,
            5001,
            FLAG_ACK | FLAG_PSH,
            super::WINDOW,
            4,
        );
        let (answer, _) = server.receive(&segment, data);
        assert_eq!(answer, Ok(Event::None));
    }
    assert_eq!(server.out_of_order(), 3);

    let first = Segment::new(
        OUR_PORT,
        THEIR_PORT,
        base,
        5001,
        FLAG_ACK | FLAG_PSH,
        super::WINDOW,
        4,
    );
    let (answer, _) = server.receive(&first, b"abcd");
    assert_eq!(answer, Ok(Event::Data(16)), "every held byte arrived");
    assert_eq!(server.out_of_order(), 0);

    let mut buffer = [0_u8; 16];
    assert_eq!(server.take(&mut buffer), 16);
    assert_eq!(&buffer, b"abcdefghijklmnop");
}

/// A segment that starts before the expected position and runs past it is
/// trimmed to the bytes that are new.
///
/// This is what a peer's retransmission after a partial loss looks like,
/// and a stack that dropped the whole segment would lose the new half.
#[test]
fn a_straddling_segment_contributes_only_its_new_half() {
    let (_client, mut server) = handshake();
    let base = server.acknowledgement;

    let whole = Segment::new(
        OUR_PORT,
        THEIR_PORT,
        base,
        5001,
        FLAG_ACK | FLAG_PSH,
        super::WINDOW,
        4,
    );
    let (answer, _) = server.receive(&whole, b"abcd");
    assert_eq!(answer, Ok(Event::Data(4)));

    // A segment that begins at the position this side has already passed
    // and runs past it: four bytes that are already in the inbox and four
    // that are not.  Only the new four count, which is what a peer's
    // retransmission after a partial loss looks like: a stack that
    // dropped the whole segment would lose the new half.
    let straddling = Segment::new(
        OUR_PORT,
        THEIR_PORT,
        base,
        5001,
        FLAG_ACK | FLAG_PSH,
        super::WINDOW,
        8,
    );
    let (answer, _) = server.receive(&straddling, b"abcdefgh");
    assert_eq!(answer, Ok(Event::Data(4)), "only the new half");
    assert_eq!(server.inbox_len(), 8);

    let mut buffer = [0_u8; 8];
    assert_eq!(server.take(&mut buffer), 8);
    assert_eq!(&buffer, b"abcdefgh");
}

/// A duplicate of what the inbox already holds adds nothing.
#[test]
fn a_repeated_segment_adds_nothing() {
    let (_client, mut server) = handshake();
    let base = server.acknowledgement;
    let segment = Segment::new(
        OUR_PORT,
        THEIR_PORT,
        base,
        5001,
        FLAG_ACK | FLAG_PSH,
        super::WINDOW,
        8,
    );
    let (answer, _) = server.receive(&segment, b"abcdefgh");
    assert_eq!(answer, Ok(Event::Data(8)));

    let (answer, _) = server.receive(&segment, b"abcdefgh");
    assert_eq!(answer, Ok(Event::None), "a duplicate is not data");
    assert_eq!(server.inbox_len(), 8, "and does not double the inbox");
}

/// A short run just past the gap is held, not trimmed into the gap.
///
/// This is the defect the boot's probe found after the tests were green:
/// the hold test compared the *gap* against the segment's length, so a
/// run nine bytes past the gap and ten bytes long read as "one byte new,
/// nine already seen" and was delivered as the wrong bytes.  The test's
/// numbers are the probe's, which is why it is here with them.
#[test]
fn a_short_run_just_past_the_gap_is_held_not_trimmed() {
    let (_client, mut server) = handshake();
    let base = server.acknowledgement;

    // Nine bytes past the gap, ten bytes long: its start is past the
    // position this side expects, so it is a run to hold.
    let second = Segment::new(
        OUR_PORT,
        THEIR_PORT,
        base + 9,
        5001,
        FLAG_ACK | FLAG_PSH,
        super::WINDOW,
        10,
    );
    let (answer, _) = server.receive(&second, b"secondhalf");
    assert_eq!(answer, Ok(Event::None), "held, not delivered");
    assert_eq!(server.out_of_order(), 1, "the run is held");
    assert_eq!(server.inbox_len(), 0, "and nothing reached the inbox");

    // The first nine bytes, and the whole run lands in order.
    let first = Segment::new(
        OUR_PORT,
        THEIR_PORT,
        base,
        5001,
        FLAG_ACK | FLAG_PSH,
        super::WINDOW,
        9,
    );
    let (answer, _) = server.receive(&first, b"firsthalf");
    assert_eq!(answer, Ok(Event::Data(19)), "both runs");
    let mut buffer = [0_u8; 19];
    assert_eq!(server.take(&mut buffer), 19);
    assert_eq!(&buffer, b"firsthalfsecondhalf");
}

/// The window a segment advertises is the room this side has left, and
/// bytes past it are dropped.
///
/// This is the difference between a window that is carried and one that is
/// enforced.  Before this change the field was a constant: this stack told
/// every peer it had eight kilobytes of room however full its inbox was, so
/// a peer that filled it was entitled to send more, and what stopped it was
/// the connection's own memory growing without bound.
#[test]
fn the_window_shrinks_as_the_peer_fills_it() {
    let (mut client, mut server) = handshake();
    // The handshake's answers are built before any data, so the first one
    // advertises the whole buffer.
    let base = server.acknowledgement;
    assert_eq!(
        server.advertised_window(),
        super::WINDOW,
        "an empty connection has all of it"
    );

    // Half the buffer arrives, and the next segment says so.
    let half = (super::WINDOW as usize) / 2;
    let full = Segment::new(
        OUR_PORT,
        THEIR_PORT,
        base,
        5001,
        FLAG_ACK | FLAG_PSH,
        super::WINDOW,
        half,
    );
    let (answer, replies) = server.receive(&full, &alloc::vec![0x41_u8; half]);
    assert_eq!(answer, Ok(Event::Data(half)));
    assert_eq!(
        server.advertised_window(),
        super::WINDOW - half as u16,
        "the acknowledgement says what is left"
    );
    assert_eq!(
        replies[0].window,
        super::WINDOW - half as u16,
        "and the segment carrying it says the same"
    );

    // A reader takes everything, and the window reopens: a window that
    // only ever shrank would close the stream for good.
    let mut buffer = alloc::vec![0_u8; half];
    assert_eq!(server.take(&mut buffer), half);
    assert_eq!(server.advertised_window(), super::WINDOW, "reopened");
    let _ = &mut client;
}

/// Bytes past the advertised window are dropped rather than grown into.
///
/// The peer chooses how much of this machine's memory to spend only up to
/// the window; past it, the answer is "no", and the sender learns by
/// retransmitting rather than by this stack's allocation growing.
#[test]
fn bytes_past_the_window_are_dropped() {
    let (_client, mut server) = handshake();
    let base = server.acknowledgement;

    // One segment fills the whole window.
    let window = super::WINDOW as usize;
    let filling = Segment::new(
        OUR_PORT,
        THEIR_PORT,
        base,
        5001,
        FLAG_ACK | FLAG_PSH,
        super::WINDOW,
        window,
    );
    let (answer, _) = server.receive(&filling, &alloc::vec![0x42_u8; window]);
    assert_eq!(answer, Ok(Event::Data(window)));
    assert_eq!(server.advertised_window(), 0, "nothing left");
    assert_eq!(server.held(), window);

    // One more byte arrives, and there is nowhere for it.
    let extra = Segment::new(
        OUR_PORT,
        THEIR_PORT,
        base + window as u32,
        5001,
        FLAG_ACK | FLAG_PSH,
        super::WINDOW,
        1,
    );
    let (answer, _) = server.receive(&extra, b"x");
    assert_eq!(answer, Ok(Event::None), "past the window");
    assert_eq!(server.held(), window, "the buffer did not grow");
}

/// A run held ahead of a gap is bounded by the same window the inbox is.
///
/// A peer that opens a hole and then sends past the window would otherwise
/// hold two buffers' worth of this machine's memory: the inbox is full and
/// the out-of-order cache is a second place the same bytes live.
#[test]
fn a_held_run_is_bounded_by_the_window() {
    let (_client, mut server) = handshake();
    let base = server.acknowledgement;

    // A run more than the whole window, entirely ahead of the gap.
    let too_much = super::WINDOW as usize + 1;
    let segment = Segment::new(
        OUR_PORT,
        THEIR_PORT,
        base + 4,
        5001,
        FLAG_ACK | FLAG_PSH,
        super::WINDOW,
        too_much,
    );
    let (answer, _) = server.receive(&segment, &alloc::vec![0x43_u8; too_much]);
    assert_eq!(answer, Ok(Event::None));
    assert_eq!(
        server.out_of_order(),
        0,
        "a run larger than the window is not held"
    );
    assert_eq!(server.held(), 0);
}

/// A full out-of-order cache keeps what it has and drops the newest, so a
/// peer that opens more holes than this stack holds cannot grow it.
#[test]
fn a_full_out_of_order_cache_drops_the_newest() {
    let (_client, mut server) = handshake();
    let base = server.acknowledgement;

    // Every held segment starts a hole of its own: one byte, two apart.
    for index in 0..super::MAX_OUT_OF_ORDER {
        let segment = Segment::new(
            OUR_PORT,
            THEIR_PORT,
            base + 2 + (index as u32 * 2),
            5001,
            FLAG_ACK | FLAG_PSH,
            super::WINDOW,
            1,
        );
        let (answer, _) = server.receive(&segment, b"x");
        assert_eq!(answer, Ok(Event::None));
    }
    assert_eq!(server.out_of_order(), super::MAX_OUT_OF_ORDER);

    let overflow = Segment::new(
        OUR_PORT,
        THEIR_PORT,
        base + 2 + (super::MAX_OUT_OF_ORDER as u32 * 2),
        5001,
        FLAG_ACK | FLAG_PSH,
        super::WINDOW,
        1,
    );
    let (_, _) = server.receive(&overflow, b"y");
    assert_eq!(
        server.out_of_order(),
        super::MAX_OUT_OF_ORDER,
        "the cache did not grow"
    );
    assert_eq!(server.inbox_len(), 0);
}

/// A data segment is acknowledged empty: carrying the data back would
/// be the wire echoing to itself, and the echo the test before this
/// one's bug ran found was the inbox doubling.
#[test]
fn an_acknowledgement_is_empty() {
    let (mut client, mut server) = handshake();

    let (_, outgoing) = client.send_data(b"protofire");
    let (answer, replies) =
        server.receive(&segment(OUR_PORT, THEIR_PORT, &outgoing[0]), b"protofire");
    assert_eq!(answer, Ok(Event::Data(9)));
    assert_eq!(replies.len(), 1, "the ACK");
    assert!(replies[0].payload.is_empty(), "and it carries no data");
}

/// A segment this stack wrote, read back as the wire carries it, with
/// the corruption checks the checksum is there for.
#[test]
fn a_segment_round_trips() {
    let mut buffer = [0_u8; HEADER_LEN + 5];
    write_segment(
        &mut buffer,
        US,
        US,
        OUR_PORT,
        THEIR_PORT,
        100,
        200,
        FLAG_ACK | FLAG_PSH,
        super::WINDOW,
        b"hello",
    );

    let segment = parse(&buffer, US, US).expect("a segment");
    assert_eq!(segment.source_port, OUR_PORT);
    assert_eq!(segment.destination_port, THEIR_PORT);
    assert_eq!(segment.sequence, 100);
    assert_eq!(segment.acknowledgement, 200);
    assert_eq!(segment.flags, FLAG_ACK | FLAG_PSH);
    assert_eq!(segment.payload_len, 5);
    assert_eq!(segment.window, super::WINDOW);

    buffer[HEADER_LEN] = !buffer[HEADER_LEN];
    assert!(parse(&buffer, US, US).is_none(), "corrupt data");
    buffer[HEADER_LEN] = 0x68;
    buffer[4] = !buffer[4];
    assert!(parse(&buffer, US, US).is_none(), "corrupt header");
}

/// The header's length is what the data offset field says it is.
#[test]
fn the_header_is_twenty_bytes_with_no_options() {
    assert_eq!(HEADER_LEN, 20);
    let mut buffer = [0_u8; HEADER_LEN];
    write_segment(
        &mut buffer,
        US,
        US,
        OUR_PORT,
        THEIR_PORT,
        1,
        2,
        FLAG_ACK,
        super::WINDOW,
        &[],
    );
    assert_eq!(buffer[12] >> 4, 5, "five words of header");
}

/// A SYN carries the MSS option, and the data offset says so.
///
/// The option is a handshake's, and without it a peer has to assume
/// [RFC 1122]'s 536-byte default: this stack would send segments the peer
/// cannot receive and learn that from a loss rather than from the SYN.
///
/// [RFC 1122]: https://www.rfc-editor.org/rfc/rfc1122
#[test]
fn a_syn_states_the_largest_segment_this_side_takes() {
    let mut buffer = [0_u8; super::SYN_HEADER_LEN];
    write_segment(
        &mut buffer,
        US,
        US,
        OUR_PORT,
        THEIR_PORT,
        1,
        0,
        FLAG_SYN,
        super::WINDOW,
        &[],
    );
    assert_eq!(
        buffer[12] >> 4,
        6,
        "six words of header: five, and the option's one"
    );
    let options = &buffer[HEADER_LEN..super::SYN_HEADER_LEN];
    assert_eq!(options[0], super::OPTION_MSS, "kind");
    assert_eq!(options[1], 4, "length");
    assert_eq!(
        u16::from_be_bytes([options[2], options[3]]),
        super::MSS_DEFAULT as u16,
        "the value the peer may send"
    );

    // And the parser reads it back as the segment's own statement.
    let parsed = parse(&buffer, US, US).expect("a segment");
    assert_eq!(parsed.mss, Some(super::MSS_DEFAULT as u16));
    assert_eq!(parsed.payload_at, super::SYN_HEADER_LEN);
    assert_eq!(parsed.payload_len, 0, "a SYN with options carries no data");
}

/// A segment with options is read with its data starting past them.
///
/// The defect this pins: the IPv4 parser used to take the whole packet
/// less [`HEADER_LEN`] for the payload, so a segment carrying an option
/// had the option counted as the peer's data.  The segment here is a SYN
/// with the option **and five bytes of data**, which is what makes the two
/// readings differ: a segment with no data gives the same answer either
/// way, and the earlier version of this test asserted only that and so
/// could not tell them apart.
#[test]
fn a_segment_with_options_puts_its_data_after_them() {
    let mut buffer = [0_u8; super::SYN_HEADER_LEN + 5];
    write_segment(
        &mut buffer,
        US,
        US,
        OUR_PORT,
        THEIR_PORT,
        1,
        0,
        FLAG_SYN,
        super::WINDOW,
        b"hello",
    );
    assert_eq!(buffer[12] >> 4, 6, "the writer emitted six words");
    assert_eq!(buffer[20], super::OPTION_MSS, "and the option is there");
    let parsed = parse(&buffer, US, US).expect("a segment");
    assert_eq!(
        parsed.payload_at, 24,
        "the data starts past the twenty-four-byte header"
    );
    assert_eq!(
        parsed.payload_len, 5,
        "and is the five bytes that followed it, not nine: this is the \
         assertion that distinguishes the data offset from a constant \
         header length, because the writer's own data is what it counts"
    );
    assert_eq!(
        &buffer[parsed.payload_at..parsed.payload_at + parsed.payload_len],
        b"hello"
    );
}

/// A peer's MSS is a limit on what this side sends, and it only shrinks.
///
/// The handshake's SYN is where a peer states its receive buffer's largest
/// segment, and a sender that ignored it would build segments past what
/// the peer said it takes.  The value goes through the same `limit_segment`
/// a path report uses, so a later statement cannot grow it back: a limit
/// that could rise would repeat the loss that taught it.
#[test]
fn a_peers_stated_segment_size_limits_what_this_side_sends() {
    let (mut client, _server) = established_on_the_loopback();
    client.limit_segment(super::MSS_DEFAULT);
    assert_eq!(client.segment_limit(), super::MSS_DEFAULT);

    let stated = super::Segment {
        source_port: THEIR_PORT,
        destination_port: OUR_PORT,
        sequence: client.expected_position(),
        acknowledgement: client.send_position(),
        flags: FLAG_ACK,
        window: super::WINDOW,
        payload_len: 0,
        payload_at: HEADER_LEN,
        mss: Some(536),
    };
    let _ = client.receive(&stated, b"");
    assert_eq!(
        client.segment_limit(),
        536,
        "the peer's number is the limit"
    );

    // A larger statement afterwards does not grow it back.
    let larger = super::Segment {
        mss: Some(super::MSS_DEFAULT as u16),
        ..stated
    };
    let _ = client.receive(&larger, b"");
    assert_eq!(client.segment_limit(), 536, "it only ever shrinks");
}

/// A segment that states no MSS leaves the limit alone.
///
/// A data segment carries no option, and reading its silence as "the
/// default" would shrink a stream every time a plain acknowledgement
/// arrived: the limit is a statement, and a segment that makes none says
/// nothing about it.
#[test]
fn a_segment_without_the_option_leaves_the_limit_alone() {
    let (mut client, _server) = established_on_the_loopback();
    client.limit_segment(536);
    let silent = super::Segment::new(
        THEIR_PORT,
        OUR_PORT,
        client.expected_position(),
        client.send_position(),
        FLAG_ACK,
        super::WINDOW,
        0,
    );
    assert_eq!(silent.mss, None);
    let _ = client.receive(&silent, b"");
    assert_eq!(client.segment_limit(), 536, "unchanged");
}

/// An option list is walked, not searched for the MSS kind's byte.
///
/// A value byte of an earlier option may be `2`, and a reader that scanned
/// for that byte would report a segment size out of a number that means
/// something else.  The first list here is a no-op and an option whose
/// value happens to be two: no MSS may be found in it.
#[test]
fn an_option_list_is_walked_and_not_searched() {
    let options = [1_u8, 3, 3, 2, 0];
    assert_eq!(
        super::mss_option(&options),
        None,
        "the 2 is a value, not a kind"
    );

    // And a real MSS after a no-op is found.
    let with_mss = [1_u8, super::OPTION_MSS, 4, 0x05, 0xB4];
    assert_eq!(super::mss_option(&with_mss), Some(1460));
}
/// A segment written for IPv6 verifies over IPv6's pseudo-header, and a
/// segment written for IPv4 does not: the two sums cover forty bytes and
/// twelve.
#[test]
fn the_two_pseudo_headers_are_not_interchangeable() {
    let source4 = [10, 0, 2, 15];
    let destination4 = [10, 0, 2, 2];
    // A SYN carries the MSS option, so its header is four bytes longer
    // than a bare one: a buffer the size of `HEADER_LEN` is a buffer the
    // writer overruns, which is what this test found when the option
    // arrived.
    let mut v4 = [0_u8; super::SYN_HEADER_LEN];
    super::write_segment(
        &mut v4,
        source4,
        destination4,
        1234,
        5678,
        1,
        0,
        super::FLAG_SYN,
        super::WINDOW,
        b"",
    );
    assert!(super::parse(&v4, source4, destination4).is_some());

    let source6 = crate::ipv6::link_local_from_mac([0x52, 0x54, 0, 0x12, 0x34, 0x56]);
    let destination6 = crate::ipv6::link_local_from_mac([0x52, 0x55, 0, 0x12, 0x34, 0x57]);
    let mut v6 = [0_u8; super::SYN_HEADER_LEN];
    super::write_segment6(
        &mut v6,
        source6,
        destination6,
        1234,
        5678,
        1,
        0,
        super::FLAG_SYN,
        super::WINDOW,
        b"",
    );
    assert!(super::parse6(&v6, source6, destination6).is_some());

    // The IPv6 segment read as IPv4, or the other way round, does not
    // verify, which is the whole reason these are two functions.
    assert!(
        super::parse(&v4, [0; 4], [0; 4]).is_none(),
        "an IPv4 segment does not verify against other addresses"
    );
    let mut v4_as_v6 = [0_u8; super::SYN_HEADER_LEN];
    v4_as_v6.copy_from_slice(&v4);
    assert!(
        super::parse6(&v4_as_v6, source6, destination6).is_none(),
        "an IPv4 checksum is not an IPv6 one"
    );
}

/// A segment with data verifies too, and its payload length is the bytes
/// past the header.
#[test]
fn a_segment_with_data_round_trips_over_ipv6() {
    let source = crate::ipv6::link_local_from_mac([0x52, 0x54, 0, 0x12, 0x34, 0x56]);
    let destination = crate::ipv6::link_local_from_mac([0x52, 0x55, 0, 0x12, 0x34, 0x57]);
    let mut segment = [0_u8; super::HEADER_LEN + 9];
    super::write_segment6(
        &mut segment,
        source,
        destination,
        1234,
        5678,
        0x1122_3344,
        0x5566_7788,
        super::FLAG_ACK,
        super::WINDOW,
        b"pyrofire!",
    );
    let parsed = super::parse6(&segment, source, destination).expect("a segment");
    assert_eq!(parsed.source_port, 1234);
    assert_eq!(parsed.destination_port, 5678);
    assert_eq!(parsed.sequence, 0x1122_3344);
    assert_eq!(parsed.acknowledgement, 0x5566_7788);
    assert_eq!(parsed.flags, super::FLAG_ACK);
    assert_eq!(parsed.payload_len, 9);
}

/// An opened stream: the handshake run, both ends established, and both
/// told what time it is.
fn established_on_the_loopback() -> (Connection, Connection) {
    let (mut client, mut server) = handshake();
    // The handshake's own segments are acknowledged by the drain, so the
    // queue starts empty and the test's own send is the first entry.
    client.advance(0);
    server.advance(0);
    (client, server)
}

/// A write larger than one segment becomes a run of segments, each no
/// larger than the path's payload.
///
/// This is the defect a stream this stack could not have carried: every
/// write went out as **one** segment, so a write larger than a frame built
/// a frame the card could not carry.  The assertion is the segment sizes
/// and the byte count, because a stack that split the write but lost a
/// byte would satisfy neither.
#[test]
fn a_large_write_becomes_a_run_of_segments() {
    let (mut client, _server) = established_on_the_loopback();
    let mut bytes = alloc::vec![0_u8; 5000];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = (index % 251) as u8;
    }

    let (carried, outgoing) = client.send_data(&bytes);
    assert_eq!(carried, 5000, "the whole write was carried");
    assert!(outgoing.len() > 1, "and in more than one segment");
    assert_eq!(
        client.segment_limit(),
        super::MSS_DEFAULT,
        "the default path payload"
    );

    let mut total = 0;
    for segment in &outgoing {
        assert!(
            segment.payload.len() <= super::MSS_DEFAULT,
            "a segment of {} bytes is larger than the path carries",
            segment.payload.len()
        );
        assert!(!segment.payload.is_empty(), "no empty segments");
        total += segment.payload.len();
    }
    assert_eq!(total, 5000, "and every byte once");

    // Concatenated back together, the segments are the write.
    let rebuilt: alloc::vec::Vec<u8> = outgoing
        .iter()
        .flat_map(|segment| segment.payload.iter().copied())
        .collect();
    assert_eq!(rebuilt, bytes, "the bytes, in order");
}

/// A path that says it carries less makes the next write use less.
#[test]
fn a_smaller_path_shrinks_every_later_segment() {
    let (mut client, _server) = established_on_the_loopback();
    assert_eq!(client.segment_limit(), super::MSS_DEFAULT);

    client.limit_segment(512);
    assert_eq!(client.segment_limit(), 512, "the path's own payload");

    let (carried, outgoing) = client.send_data(&alloc::vec![0xAB_u8; 1500]);
    assert_eq!(carried, 1500);
    for segment in &outgoing {
        assert!(
            segment.payload.len() <= 512,
            "a segment of {} bytes after the path shrank",
            segment.payload.len()
        );
    }

    // A later report that claims more does not grow it back: a path that
    // was found small does not become large because a later measurement
    // says so, and growing would repeat the loss that taught it.
    client.limit_segment(9000);
    assert_eq!(client.segment_limit(), 512, "it only ever shrinks");

    // And a report below the floor is the floor, because a stream of
    // handfuls is a header per handful.
    client.limit_segment(1);
    assert_eq!(client.segment_limit(), super::MIN_MSS);
}

/// Nagle's rule holds a small write while anything is in flight.
///
/// The rule is [RFC 1122] section 4.2.3.4's: a small segment is sent only
/// when there is nothing unacknowledged, so a program writing a byte at a
/// time costs one segment per round trip rather than one per byte.  The
/// test is the **second** write: the first goes out because the stream is
/// idle, and a stack without the rule would send the second as well.
///
/// [RFC 1122]: https://www.rfc-editor.org/rfc/rfc1122
#[test]
fn a_small_write_is_held_while_anything_is_in_flight() {
    let (mut client, _server) = established_on_the_loopback();
    assert!(!client.options().no_delay(), "the rule is on by default");

    let (first, _) = client.send_data(b"a");
    assert_eq!(first, 1, "the stream was idle, so the first byte goes");
    assert_eq!(client.unacknowledged(), 1, "and is now in flight");

    let (second, outgoing) = client.send_data(b"b");
    assert_eq!(second, 0, "the second is held");
    assert!(outgoing.is_empty(), "and nothing was built");
    assert_eq!(client.unacknowledged(), 1, "the queue did not grow");
}

/// `TCP_NODELAY` makes the same write go.
///
/// The pair of assertions is what makes this a test of the **option** and
/// not of the rule: the same two writes, the same stream state, and the
/// only difference is the flag.
#[test]
fn tcp_nodelay_makes_a_small_write_go() {
    let (mut client, _server) = established_on_the_loopback();
    client
        .set_option(abi::network::IPPROTO_TCP, abi::network::TCP_NODELAY, &[1])
        .expect("no delay is an option this stack serves");
    assert!(client.options().no_delay());

    assert_eq!(client.send_data(b"a").0, 1);
    assert_eq!(client.unacknowledged(), 1);
    let (second, outgoing) = client.send_data(b"b");
    assert_eq!(second, 1, "the option is what let it through");
    assert_eq!(outgoing.len(), 1);
}

/// A write at least a segment long is not held, whatever the rule says.
///
/// Nagle's rule is about small writes: a full segment is data the path is
/// waiting for, and holding it would make every large transfer wait for an
/// acknowledgement it does not need.  The test writes exactly one segment
/// with one already in flight.
#[test]
fn a_full_segment_is_not_held() {
    let (mut client, _server) = established_on_the_loopback();
    assert_eq!(client.send_data(b"a").0, 1, "something in flight");

    let full = alloc::vec![0x5A_u8; client.segment_limit()];
    let (carried, outgoing) = client.send_data(&full);
    assert_eq!(carried, full.len(), "a whole segment goes");
    assert_eq!(outgoing.len(), 1);
}

/// A write past what may be in flight is partly carried, and the count
/// says how much.
///
/// The count is what a caller writes again from, so a write that answered
/// the whole length and queued part of it would lose the rest silently.
/// The bound that stops it is the **smallest** of the three a sender
/// respects, and on a fresh loopback stream that is the peer's advertised
/// window: the congestion window starts at ten segments (14600 bytes) and
/// the peer advertises [`super::WINDOW`] (8192), which is the tighter of
/// the two.  Asserting the exact number is what says which bound worked;
/// asserting only "less than the write" would pass with the queue's bound,
/// the congestion window's, or the peer's, and this test has been all three
/// as the stack grew.
#[test]
fn a_write_stops_where_the_window_is_full() {
    let (mut client, _server) = established_on_the_loopback();
    client.advance(0);
    assert_eq!(client.unacknowledged(), 0);
    assert_eq!(client.in_flight(), 0);
    let bound = client.send_budget();
    assert_eq!(
        bound,
        super::WINDOW as usize,
        "the peer's window is the tighter bound on a fresh stream"
    );
    assert_eq!(bound, client.peer_window());

    // Enough segments to fill the window and then some.
    let bytes = alloc::vec![0x5A_u8; bound + super::MSS_DEFAULT * 4];
    let (carried, outgoing) = client.send_data(&bytes);
    assert_eq!(carried, bound, "exactly the budget, not a segment past it");
    assert_eq!(client.in_flight(), bound);
    assert!(outgoing.len() > 1, "and more than one segment");
    assert!(carried < bytes.len(), "the rest is the caller's to write");

    // The next write carries nothing until an acknowledgement opens room.
    let (again, none) = client.send_data(b"more");
    assert_eq!(again, 0, "the window is full");
    assert!(none.is_empty());
}

/// A budget that is not a whole number of segments carries a short last
/// segment rather than overshooting.
///
/// The defect this pins: the send loop tested `carried < budget` and then
/// appended a whole MSS, so a budget of 8192 against segments of 1460 put
/// 8760 bytes in flight, 568 past what the window allows.  No test saw it
/// while the congestion window was the only bound, because that one is ten
/// whole segments; the peer's window is an arbitrary number and made it
/// reachable on the first write.
#[test]
fn a_budget_that_is_not_whole_segments_carries_a_short_last_segment() {
    let (mut client, _server) = established_on_the_loopback();
    // A peer that states a window one byte past two segments.
    let narrow = 2 * super::MSS_DEFAULT + 1;
    let ack = super::Segment::new(
        THEIR_PORT,
        OUR_PORT,
        client.expected_position(),
        client.send_position(),
        FLAG_ACK,
        narrow as u16,
        0,
    );
    let (_, replies) = client.receive(&ack, b"");
    assert!(replies.is_empty(), "a bare acknowledgement answers nothing");
    assert_eq!(client.peer_window(), narrow);

    let bytes = alloc::vec![0x33_u8; narrow * 2];
    let (carried, outgoing) = client.send_data(&bytes);
    assert_eq!(carried, narrow, "the budget, to the byte");
    assert_eq!(
        client.in_flight(),
        narrow,
        "in flight is what the peer said it would take"
    );
    assert_eq!(
        outgoing.last().map(|segment| segment.payload.len()),
        Some(1),
        "the last segment carries the odd byte and not a whole MSS"
    );
    assert!(
        outgoing
            .iter()
            .map(|segment| segment.payload.len())
            .sum::<usize>()
            == narrow,
        "the segments add up to the budget exactly"
    );
}

/// The peer's window is a bound on sending, separate from this side's.
///
/// The field was parsed into every [`Segment`] and read by nothing: a
/// sender compared the congestion window and the queue's size and treated
/// the peer's statement as information it had already accounted for.  A
/// peer that shrank its window to zero said "send nothing" and was sent to
/// anyway.  This test is the one that would fail with the field ignored,
/// because a zero window and a full congestion window are different facts
/// that produce the same count only if one of them is not read.
#[test]
fn a_zero_peer_window_stops_the_sender() {
    let (mut client, _server) = established_on_the_loopback();
    let ack = super::Segment::new(
        THEIR_PORT,
        OUR_PORT,
        client.expected_position(),
        client.send_position(),
        FLAG_ACK,
        0,
        0,
    );
    let _ = client.receive(&ack, b"");
    assert_eq!(client.peer_window(), 0, "the peer said its buffer is full");
    assert!(
        client.congestion_window() > 0,
        "and the path said nothing, so the two bounds disagree"
    );

    let (carried, outgoing) = client.send_data(b"blocked");
    assert_eq!(carried, 0, "a zero window carries nothing");
    assert!(outgoing.is_empty());

    // The peer reopens, and the same write now goes.
    let reopen = super::Segment::new(
        THEIR_PORT,
        OUR_PORT,
        client.expected_position(),
        client.send_position(),
        FLAG_ACK,
        super::WINDOW,
        0,
    );
    let _ = client.receive(&reopen, b"");
    let (carried, outgoing) = client.send_data(b"blocked");
    assert_eq!(carried, 7, "the reopen is what let it through");
    assert_eq!(outgoing.len(), 1);
}

/// A stream starts with ten segments of window, whatever the handshake
/// A receive buffer a program set is the window its peer sees, and the
/// room it enforces.
///
/// The option is only real if both halves move together: a connection that
/// advertised the smaller window and enforced the old room would accept
/// more than it said it would, and one that enforced the smaller room and
/// advertised the old one would drop bytes a peer was told to send.  The
/// test asserts both numbers, which is what distinguishes an option that
/// works from a field that is stored and read by one path.
#[test]
fn a_receive_buffer_option_moves_the_window_and_the_room() {
    let (mut client, _server) = established_on_the_loopback();
    assert_eq!(
        client.advertised_window(),
        super::WINDOW,
        "the default before anything is set"
    );

    let narrowed = 1000_usize;
    client
        .set_option(
            abi::network::SOL_SOCKET,
            abi::network::SO_RCVBUF,
            &narrowed.to_le_bytes(),
        )
        .expect("a receive buffer");
    assert_eq!(
        client.advertised_window(),
        narrowed as u16,
        "the peer sees it"
    );

    // The peer sends exactly the advertised number and it fits; one byte
    // more does not.  The second segment starts past the gap the first
    // filled, so it is refused by the window and not by the sequence.
    let base = client.expected_position();
    let filling = super::Segment::new(
        THEIR_PORT,
        OUR_PORT,
        base,
        client.send_position(),
        FLAG_ACK | FLAG_PSH,
        super::WINDOW,
        narrowed,
    );
    let (_, replies) = client.receive(&filling, &alloc::vec![0x41_u8; narrowed]);
    assert!(!replies.is_empty(), "the segment is acknowledged");
    assert_eq!(client.held(), narrowed, "all of it is held");
    assert_eq!(client.advertised_window(), 0, "and the window is closed");

    // A byte past the window, at the position the peer would send it.
    let extra = super::Segment::new(
        THEIR_PORT,
        OUR_PORT,
        base + narrowed as u32,
        client.send_position(),
        FLAG_ACK | FLAG_PSH,
        super::WINDOW,
        1,
    );
    let _ = client.receive(&extra, b"x");
    assert_eq!(
        client.held(),
        narrowed,
        "the byte past the window was refused, and by the option's number"
    );
}

/// A send buffer a program set caps the congestion window.
///
/// `SO_SNDBUF` is the ceiling this side may have in flight, and slow
/// start's growth stops at it.  The test sets a buffer smaller than the
/// window slow start had already reached: the ceiling has to apply to what
/// is already open, not only to what a fresh connection would start with,
/// because an acknowledgement that grew the window is history and the next
/// write has to respect the number the program set after it.
#[test]
fn a_send_buffer_option_caps_the_congestion_window() {
    let (mut client, _server) = established_on_the_loopback();
    assert_eq!(client.congestion_window(), super::INITIAL_CWND);
    let ceiling = 3 * super::MSS_DEFAULT;
    assert!(
        ceiling < super::INITIAL_CWND,
        "the test needs a tighter cap"
    );

    client
        .set_option(
            abi::network::SOL_SOCKET,
            abi::network::SO_SNDBUF,
            &ceiling.to_le_bytes(),
        )
        .expect("a send buffer");
    assert_eq!(
        client.congestion_window(),
        ceiling,
        "the window already open is capped, not only a fresh one"
    );
    // And the budget follows it, which is what a write reads.
    assert_eq!(client.send_budget(), ceiling);

    // Reading it back answers the number that was set.
    let mut buffer = [0_u8; 8];
    let written = client
        .get_option(
            abi::network::SOL_SOCKET,
            abi::network::SO_SNDBUF,
            &mut buffer,
        )
        .expect("a send buffer");
    assert_eq!(written, core::mem::size_of::<usize>());
    assert_eq!(
        usize::from_le_bytes(buffer[..written].try_into().unwrap()),
        ceiling
    );
}

/// A stream's option calls refuse a number nothing in this stack serves.
///
/// The refusal reaches through the connection, so a program's `SetSockOpt`
/// on a stream is refused by the same `match` a datagram socket's is, and
/// the stream's own state is unchanged by the attempt.
#[test]
fn a_stream_refuses_an_option_it_does_not_serve() {
    let (mut client, _server) = established_on_the_loopback();
    let before = client.options();
    assert_eq!(
        client.set_option(abi::network::SOL_SOCKET, 1, &[1]),
        Err(abi::Error::InvalidArgument)
    );
    assert_eq!(client.options(), before, "a refusal changes nothing");
    let mut buffer = [0_u8; 8];
    assert_eq!(
        client.get_option(abi::network::IPPROTO_TCP, 9, &mut buffer),
        Err(abi::Error::InvalidArgument)
    );
}

/// occupied, and its first acknowledgements double it.
///
/// Slow start's rule is that an acknowledged byte adds a byte of window, so
/// a round trip of acknowledgements doubles what may be in flight.  The
/// initial number is [RFC 6928]'s ten segments exactly: the first version
/// of this counted the handshake's SYN as a byte, which left the window at
/// ten segments and one, a number no rule produces.
///
/// [RFC 6928]: https://www.rfc-editor.org/rfc/rfc6928
#[test]
fn a_stream_starts_with_ten_segments_and_doubles_on_acknowledgement() {
    let (mut client, mut server) = established_on_the_loopback();
    assert_eq!(
        client.congestion_window(),
        super::INITIAL_CWND,
        "ten segments, and not ten segments plus the SYN"
    );
    assert_eq!(super::INITIAL_CWND, 10 * super::MSS_DEFAULT);

    // One segment's worth of acknowledgements, and the window grows by
    // exactly that much.
    let before = client.congestion_window();
    let (_, outgoing) = client.send_data(&alloc::vec![0x11_u8; super::MSS_DEFAULT]);
    let mut client_out = outgoing;
    let mut server_out = alloc::vec::Vec::new();
    drain(&mut client_out, &mut server_out, &mut client, &mut server);
    assert_eq!(
        client.congestion_window(),
        before + super::MSS_DEFAULT,
        "one acknowledged segment opens the window by one"
    );

    // And once ssthresh is reached the growth is one segment per round
    // trip rather than one per acknowledgement.  The threshold is pushed
    // down to the current window so the next acknowledgement takes the
    // avoidance branch.
    client.ssthresh = client.congestion_window();
    let before = client.congestion_window();
    let (_, outgoing) = client.send_data(&alloc::vec![0x22_u8; super::MSS_DEFAULT]);
    let mut client_out = outgoing;
    drain(&mut client_out, &mut server_out, &mut client, &mut server);
    let grown = client.congestion_window() - before;
    assert!(
        grown < super::MSS_DEFAULT,
        "congestion avoidance grew by {grown}, which is a full segment per              acknowledgement rather than per round trip"
    );
    assert!(grown > 0, "and it still grew");
}

/// A timeout collapses the window to one segment and lowers the threshold.
#[test]
fn a_timeout_collapses_the_congestion_window() {
    let (mut client, _server) = established_on_the_loopback();
    client.advance(0);
    let before = client.congestion_window();
    let (_, outgoing) = client.send_data(&alloc::vec![0x33_u8; 4 * super::MSS_DEFAULT]);
    assert!(outgoing.len() >= 4);

    // Nothing answers, and the timer fires.
    client.advance(super::RTO_INITIAL_MICROS);
    assert!(matches!(
        client.retransmit(),
        super::Retransmission::Again(_)
    ));

    assert_eq!(
        client.congestion_window(),
        client.segment_limit(),
        "one segment: the path just said it dropped something"
    );
    assert!(
        client.slow_start_threshold() <= before / 2,
        "and the threshold halved from {}",
        before
    );
    assert!(
        client.slow_start_threshold() >= 2 * client.segment_limit(),
        "but never below two segments"
    );
}

/// Three duplicate acknowledgements send the segment at the gap at once,
/// without waiting for its timer.
///
/// This is fast retransmit, and it is the half of congestion control a
/// timer cannot do: the peer is saying it received something past a gap, so
/// the sender knows which segment was lost before a second has passed.
#[test]
fn three_duplicate_acknowledgements_retransmit_at_once() {
    let (mut client, _server) = established_on_the_loopback();
    client.advance(0);
    let (_, outgoing) = client.send_data(&alloc::vec![0x44_u8; 3 * super::MSS_DEFAULT]);
    assert_eq!(outgoing.len(), 3);
    let first = outgoing[0].clone();
    let window_before = client.congestion_window();

    // The peer's position, which is what a duplicate acknowledgement
    // repeats: it has the first segment missing and the rest held.
    let position = client.expected_position();
    let duplicate = Segment::new(
        THEIR_PORT,
        OUR_PORT,
        position,
        first.sequence,
        FLAG_ACK,
        super::WINDOW,
        0,
    );

    // The first two say nothing new.
    for expected in 1..super::DUPLICATE_ACKS {
        let (_event, replies) = client.receive(&duplicate, &[]);
        assert!(replies.is_empty(), "duplicate {expected} is not yet a loss");
    }
    // The third is.
    let (_event, replies) = client.receive(&duplicate, &[]);
    assert_eq!(replies.len(), 1, "the segment at the gap, sent again");
    assert_eq!(
        replies[0].sequence, first.sequence,
        "the same position it first carried"
    );
    assert_eq!(replies[0].payload, first.payload, "and the same bytes");
    assert!(
        client.congestion_window() < window_before,
        "fast recovery halved the window"
    );
}

/// A reordered pair is not a loss: two duplicate acknowledgements leave
/// the window alone.
///
/// This is the reason the threshold is three rather than one.  A wire that
/// swaps two segments produces two duplicates and no loss, and a sender
/// that halved its window for each would shrink for a path that carried
/// everything.
#[test]
fn two_duplicate_acknowledgements_are_not_a_loss() {
    let (mut client, _server) = established_on_the_loopback();
    client.advance(0);
    let (_, outgoing) = client.send_data(&alloc::vec![0x55_u8; 2 * super::MSS_DEFAULT]);
    let first = outgoing[0].clone();
    let window_before = client.congestion_window();

    let duplicate = Segment::new(
        THEIR_PORT,
        OUR_PORT,
        client.expected_position(),
        first.sequence,
        FLAG_ACK,
        super::WINDOW,
        0,
    );
    for _ in 0..2 {
        let (_event, replies) = client.receive(&duplicate, &[]);
        assert!(replies.is_empty());
    }
    assert_eq!(
        client.congestion_window(),
        window_before,
        "two duplicates are a reordering, not a loss"
    );
}

/// A sent segment is kept until the peer acknowledges it.
///
/// This is the defect the change this test arrived with was written for:
/// nothing kept a sent segment, so nothing could send it again, and the
/// first loss on a real wire hung the stream for the rest of the boot.
#[test]
fn a_sent_segment_is_kept_until_its_acknowledgement() {
    let (mut client, mut server) = established_on_the_loopback();
    let mut client_out = alloc::vec::Vec::new();
    let mut server_out = alloc::vec::Vec::new();

    assert_eq!(client.unacknowledged(), 0, "the handshake was acknowledged");
    let (sent, outgoing) = client.send_data(b"protofire");
    assert_eq!(sent, 9);
    assert_eq!(client.unacknowledged(), 1, "the data is held");
    client_out.extend(outgoing);

    // The peer gets it and answers, and the answer retires the entry.
    drain(&mut client_out, &mut server_out, &mut client, &mut server);
    assert_eq!(client.unacknowledged(), 0, "the acknowledgement retired it");

    // Nothing is due on a queue with nothing in it.
    client.advance(super::RTO_INITIAL_MICROS * 10);
    assert_eq!(client.retransmit(), super::Retransmission::Idle);
}

/// A segment nobody acknowledged is sent again when its timeout passes,
/// with the same bytes and the same sequence.
#[test]
fn an_unacknowledged_segment_is_sent_again_after_its_timeout() {
    let (mut client, _server) = established_on_the_loopback();
    client.advance(0);
    let (_, outgoing) = client.send_data(b"lost");
    let original = outgoing[0].clone();
    assert_eq!(client.unacknowledged(), 1);

    // The interval is the estimate's, which the handshake measured, and
    // reading it here is what keeps this a test of the **timeout** rather
    // than of the estimator: a stream that never measured anything waits
    // the initial second, and one that has waits what it measured.
    let timeout = client.rto();

    // Before the timeout, nothing is due.
    client.advance(timeout - 1);
    assert_eq!(client.retransmit(), super::Retransmission::Idle);

    // At it, the same segment is handed back.
    client.advance(timeout);
    match client.retransmit() {
        super::Retransmission::Again(sent) => {
            assert_eq!(sent.len(), 1, "one segment again");
            assert_eq!(sent[0].sequence, original.sequence, "the same position");
            assert_eq!(sent[0].payload, original.payload, "the same bytes");
            assert_eq!(sent[0].flags, original.flags);
        }
        other => panic!("expected a retransmission, got {other:?}"),
    }
    assert_eq!(client.unacknowledged(), 1, "still waiting for the one ACK");
}

/// The first measurement is the estimate, and the second averages into it.
///
/// [RFC 6298]'s two cases, and the numbers are the section's own: the first
/// sample **is** the estimate and its variance is half of it, and each
/// later sample moves the estimate an eighth of the way toward itself and
/// the variance a quarter.  A stack that skipped the first case and
/// averaged against a zero estimate would spend several round trips
/// recovering from a path that was right the whole time.
///
/// The estimator's arithmetic is driven directly, because what is under
/// test is the formula and not what a loopback happens to measure: a
/// loopback's round trip is zero and every sample after it is zero too,
/// which would pass for any formula that returned zero.
///
/// [RFC 6298]: https://www.rfc-editor.org/rfc/rfc6298
#[test]
fn the_estimate_starts_at_the_first_sample_and_moves_slowly() {
    let (mut client, _server) = established_on_the_loopback();

    // A hundred milliseconds, which is the first sample.
    client.srtt = None;
    client.rttvar = 0;
    client.measure(100_000);
    assert_eq!(
        client.smoothed_round_trip(),
        Some(100_000),
        "the first sample is the estimate"
    );
    assert_eq!(
        client.round_trip_variance(),
        50_000,
        "and its variance is half of it"
    );
    assert_eq!(
        client.rto(),
        100_000 + 4 * 50_000,
        "so the timeout is the estimate plus four deviations"
    );

    // A second sample, ten milliseconds later.
    client.measure(110_000);
    assert_eq!(
        client.smoothed_round_trip(),
        Some((100_000 * 7 + 110_000) / 8),
        "seven eighths of the old estimate and one eighth of the sample"
    );
    assert_eq!(
        client.round_trip_variance(),
        (50_000 * 3 + 10_000) / 4,
        "three quarters of the old variance and a quarter of the distance"
    );
}

/// A retransmitted segment's acknowledgement measures nothing.
///
/// [RFC 6298] section 3's Karn rule.  The acknowledgement names a
/// position, and after a retransmission two copies have that position, so
/// the round trip it appears to measure may be a measurement of the
/// timeout rather than of the path.  A stream that took it would think its
/// path had become a second slow.
///
/// [RFC 6298]: https://www.rfc-editor.org/rfc/rfc6298
#[test]
fn a_retransmitted_segment_contributes_no_sample() {
    let (mut client, _server) = established_on_the_loopback();
    let before = client.smoothed_round_trip();
    let before_rto = client.rto();

    client.advance(0);
    client.send_data(b"lost");
    // The timeout fires and the segment goes again.
    client.advance(client.rto());
    assert!(matches!(
        client.retransmit(),
        super::Retransmission::Again(_)
    ));

    // The acknowledgement arrives a long time after the *original* was
    // sent, which would measure a huge round trip if it were taken.
    client.advance(client.rto() + 5_000_000);
    let (_, _) = client.receive(
        &super::Segment::new(
            THEIR_PORT,
            OUR_PORT,
            client.expected_position(),
            client.send_position(),
            FLAG_ACK,
            super::WINDOW,
            0,
        ),
        b"",
    );
    assert_eq!(
        client.smoothed_round_trip(),
        before,
        "the retransmitted segment's acknowledgement is not a sample"
    );
    assert!(
        client.rto() >= before_rto,
        "and the timeout did not shrink on the strength of it"
    );
}

/// A measured round trip below a millisecond is the clock's floor.
///
/// [RFC 6298] section 2.4: a smaller measurement is a measurement of the
/// clock rather than of the path, and a timeout that short would
/// retransmit every segment before its acknowledgement could arrive.  A
/// loopback measures zero, which is the case this exists for.
///
/// [RFC 6298]: https://www.rfc-editor.org/rfc/rfc6298
#[test]
fn a_round_trip_below_a_millisecond_is_floored() {
    let (mut client, _server) = handshake();
    client.advance(0);
    // The handshake measured zero: a loopback has no time to divide.
    assert_eq!(client.smoothed_round_trip(), Some(0));
    assert_eq!(
        client.rto(),
        super::RTO_FLOOR_MICROS,
        "and the timeout is the floor, not zero"
    );
}

/// The timeout doubles with each attempt, which is [RFC 6298]'s backoff.
///
/// The test measures the intervals rather than reading the field: a
/// backoff that was written but never applied is the defect this is for,
/// and the interval between two retransmissions is what a peer sees.
///
/// [RFC 6298]: https://www.rfc-editor.org/rfc/rfc6298
#[test]
fn the_timeout_doubles_with_each_attempt() {
    let (mut client, _server) = established_on_the_loopback();
    client.advance(0);
    client.send_data(b"backoff");

    // The interval the first attempt waits is the estimate's, which the
    // handshake's acknowledgement measured: a loopback round trip is as
    // short as the clock can see, so this is `RTO_FLOOR_MICROS` and not the
    // initial second.  Reading it from the connection rather than
    // assuming it is what makes the test about the **backoff** and not
    // about the estimate: a stream that has measured nothing waits the
    // initial second, and one that has waits what it measured.
    let first = client.rto();
    assert_eq!(
        client.smoothed_round_trip(),
        Some(0),
        "the handshake measured a round trip the clock could not divide"
    );

    client.advance(first);
    assert!(matches!(
        client.retransmit(),
        super::Retransmission::Again(_)
    ));

    let doubled = first * 2;
    client.advance(first + doubled - 1);
    assert_eq!(client.retransmit(), super::Retransmission::Idle);
    client.advance(first + doubled);
    assert!(matches!(
        client.retransmit(),
        super::Retransmission::Again(_)
    ));
}

/// An acknowledgement of *any* segment resets the backoff, because
/// progress is what the timeout is measuring toward.
#[test]
fn an_acknowledgement_resets_the_backoff() {
    let (mut client, mut server) = established_on_the_loopback();
    let mut client_out = alloc::vec::Vec::new();
    let mut server_out = alloc::vec::Vec::new();
    client.advance(0);
    let (_, outgoing) = client.send_data(b"first");
    client_out.extend(outgoing);

    // Two lost attempts, so the next wait would be four times the initial.
    client.advance(super::RTO_INITIAL_MICROS);
    assert!(matches!(
        client.retransmit(),
        super::Retransmission::Again(_)
    ));
    client.advance(super::RTO_INITIAL_MICROS * 3);
    assert!(matches!(
        client.retransmit(),
        super::Retransmission::Again(_)
    ));

    // The answer lands after all, and the schedule starts over.
    drain(&mut client_out, &mut server_out, &mut client, &mut server);
    assert_eq!(client.unacknowledged(), 0);

    client.advance(super::RTO_INITIAL_MICROS * 3 + 10);
    let (_, outgoing) = client.send_data(b"second");
    client_out.extend(outgoing);
    // The initial timeout, not four times it, is what the new segment
    // waits: an entry recorded at the later time is due at the later time
    // plus the *initial* timeout.
    client.advance(super::RTO_INITIAL_MICROS * 3 + 10 + super::RTO_INITIAL_MICROS);
    assert!(
        matches!(client.retransmit(), super::Retransmission::Again(_)),
        "the backoff started over"
    );
}

/// A full unacknowledged queue refuses a write rather than growing.
///
/// `TCP_NODELAY` is turned **on** for the fill: the writes are one byte
/// each, and Nagle's rule holds a small write while anything is in flight,
/// so without the option the first byte would go and the second would be
/// held and the test would be measuring the rule rather than the queue's
/// bound.  Which of the two is holding a byte is exactly what the option
/// decides, and this test is about the other one.
#[test]
fn a_full_unacknowledged_queue_refuses_a_write() {
    let (mut client, _server) = established_on_the_loopback();
    client.advance(0);
    client
        .set_option(abi::network::IPPROTO_TCP, abi::network::TCP_NODELAY, &[1])
        .expect("no delay is an option this stack serves");
    for length in 0..super::MAX_UNACKNOWLEDGED {
        let (sent, _) = client.send_data(b"x");
        assert_eq!(sent, 1, "write {length} fit");
    }
    assert_eq!(
        client.unacknowledged(),
        super::MAX_UNACKNOWLEDGED,
        "the queue is full"
    );
    let (sent, outgoing) = client.send_data(b"one too many");
    assert_eq!(sent, 0, "a full queue carried nothing");
    assert!(outgoing.is_empty(), "nothing went out");

    // The peer's acknowledgement frees room, and the same write succeeds.
    let acknowledgement = client.sequence;
    let (_event, _replies) = client.receive(
        &super::Segment::new(
            THEIR_PORT,
            OUR_PORT,
            client.acknowledgement,
            acknowledgement,
            FLAG_ACK,
            super::WINDOW,
            0,
        ),
        &[],
    );
    assert_eq!(client.unacknowledged(), 0, "one acknowledgement freed it");
    let (sent, _) = client.send_data(b"now it fits");
    assert_eq!(sent, 11, "the write the full queue refused");
}

/// A stream that is never answered is abandoned, and a caller learns it
/// rather than waiting forever.
#[test]
fn a_stream_nobody_answers_is_abandoned() {
    let (mut client, _server) = established_on_the_loopback();
    client.advance(0);
    client.send_data(b"into the void");

    // Walk the whole schedule, asking after each interval.
    let mut now = 0u64;
    let mut attempts = 0;
    let mut timeout = super::RTO_INITIAL_MICROS;
    while attempts < super::MAX_ATTEMPTS {
        now += timeout;
        client.advance(now);
        match client.retransmit() {
            super::Retransmission::Again(_) => attempts += 1,
            other => panic!("attempt {attempts}: expected a retransmission, got {other:?}"),
        }
        timeout = (timeout * 2).min(super::RTO_MAX_MICROS);
    }

    // One more interval, and the next attempt is the one past the limit.
    now += timeout;
    client.advance(now);
    assert_eq!(client.retransmit(), super::Retransmission::Abandoned);
    assert_eq!(
        client.state(),
        State::Closed,
        "a stream nobody answers is not a stream a caller waits on"
    );
    assert_eq!(client.unacknowledged(), 0, "the queue is released");
}

/// A pure acknowledgement is not queued: it carries no bytes, and the
/// peer recovers a lost one by retransmitting what it acknowledged.
#[test]
fn a_pure_acknowledgement_is_not_kept() {
    let (mut client, mut server) = established_on_the_loopback();
    let mut client_out = alloc::vec::Vec::new();
    let mut server_out = alloc::vec::Vec::new();

    // The server acknowledges the client's data, and that ACK is not the
    // server's to remember.
    let (_, outgoing) = client.send_data(b"x");
    client_out.extend(outgoing);
    let before = server.unacknowledged();
    drain(&mut client_out, &mut server_out, &mut client, &mut server);
    assert_eq!(
        server.unacknowledged(),
        before,
        "an acknowledgement is not retransmitted"
    );
}

/// An acknowledgement of a byte this side never sent retires nothing.
///
/// The defect this is for is the one [RFC 793] section 3.9 names: a
/// segment carrying an acknowledgement past `SND.NXT` is a segment whose
/// number means nothing, and acting on it would drop data the peer never
/// received.  The stream would then be silent rather than slow, which is
/// the harder failure to find.
///
/// [RFC 793]: https://www.rfc-editor.org/rfc/rfc793
#[test]
fn an_acknowledgement_past_what_was_sent_retires_nothing() {
    let (mut client, _server) = established_on_the_loopback();
    client.advance(0);
    let (_, outgoing) = client.send_data(b"protofire");
    assert_eq!(client.unacknowledged(), 1);

    // One byte past the last one this side sent: refused.
    let past = outgoing[0].sequence + outgoing[0].payload.len() as u32 + 1;
    let (_event, _replies) = client.receive(
        &super::Segment::new(
            THEIR_PORT,
            OUR_PORT,
            client.acknowledgement,
            past,
            FLAG_ACK,
            super::WINDOW,
            0,
        ),
        &[],
    );
    assert_eq!(
        client.unacknowledged(),
        1,
        "an acknowledgement past the send position retires nothing"
    );

    // Below the oldest unacknowledged byte: also refused.
    let (_event, _replies) = client.receive(
        &super::Segment::new(
            THEIR_PORT,
            OUR_PORT,
            client.acknowledgement,
            outgoing[0].sequence - 1,
            FLAG_ACK,
            super::WINDOW,
            0,
        ),
        &[],
    );
    assert_eq!(
        client.unacknowledged(),
        1,
        "an acknowledgement below the oldest sent byte retires nothing"
    );

    // And the exact last byte does retire it, which is the control that
    // shows the two refusals above were the range and not a queue that
    // never retires anything.
    let (_event, _replies) = client.receive(
        &super::Segment::new(
            THEIR_PORT,
            OUR_PORT,
            client.acknowledgement,
            past - 1,
            FLAG_ACK,
            super::WINDOW,
            0,
        ),
        &[],
    );
    assert_eq!(client.unacknowledged(), 0, "the last byte retires it");
}
