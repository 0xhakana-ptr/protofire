//! kernel/src/net/mod.rs
//!
//! The kernel's network half: the interface the boot brought up, the answers
//! the network calls give, and the sockets a program holds.
//!
//! ## Where `net` ends and this file begins
//!
//! The `net` crate computes what a frame means: it parses a header, builds a
//! request, checks a sum, and every one of its functions is a pure call over a
//! byte slice.  The state it does hold, [`net::tcp_table::Table`], the streams
//! a machine owns, and [`net::udp_socket::Queue`], what arrived for one bound
//! port, it holds as **values** its caller owns, with no lock and no
//! `static`, which is what lets that arithmetic be a host test as well.  So
//! does the writing of a reply frame: [`net::reply`] composes one from
//! addresses, and this file decides **whose** addresses and when.
//!
//! This file holds everything `net` deliberately does not: **which** address
//! this machine answers for, **which** neighbours the wire has answered about,
//! **which** ports a program has bound, **who** holds the table's lock, and
//! **when** a waiting task wakes.  Those are facts about a boot rather than
//! about a protocol, and each one is a `static` behind a `Mutex` for that
//! reason.
//!
//! The line is what makes a second card a second `Interface` rather than a
//! second stack: `net` never learns which card carried a frame, and this file
//! never reads a field of one.  It is also what keeps this module's size from
//! following the protocol count: a protocol added to `net` adds nothing here,
//! and the one thing that had grown here, the connection table, moved out.
//!
//! ## Why this is a module and not a field of the boot
//!
//! The probes in `devices.rs` prove the wire; this module holds what the
//! probes found, so a call made after the boot has finished answers from
//! state rather than from constants a caller would have to guess.  The
//! interface is installed once, when the card comes up, and every network
//! call reads through it, which is what makes `NetworkStatus` a fact about
//! this boot's machine rather than about the QEMU defaults a reader could
//! have looked up.
//!
//! ## The sockets, and the one table that knows their ports
//!
//! A datagram socket is a bound port and a queue of what arrived for it.  It
//! lives behind an `Arc` a descriptor holds, and the port table beside this
//! file's interface holds a `Weak`, so a socket's port is routable for
//! exactly as long as some descriptor holds the socket, and a process that
//! exits releases its descriptors the way it releases its files and pipes,
//! with the port going with the last of them.  The demux prunes the dead
//! entries on the way past rather than keeping a second count.
//!
//! ## Loopback, and why a datagram to this machine never touches the card
//!
//! A datagram addressed to this interface's own address is delivered through
//! the demux directly: the port table answers, the queue takes it, the
//! waiter wakes.  Sending it to the card would ask the wire to hand this
//! machine its own frame back, which no card promises to do, and the
//! exchanges a program makes with itself are the ones this build can prove
//! on every machine it boots.  A datagram for anyone else goes out through
//! the gateway, whose hardware address the ARP cache holds.

// The sections, each a file.  `core` is what a boot installs and what a call
// reads; every other section is a protocol or a layer on top of it.
mod core;
mod dccp;
mod demux4;
mod demux6;
mod dhcp;
mod filter;
mod ipsec;
mod multicast;
mod tcp;

// The probes, in a file of their own: they drive the stack through a recording
// card and are the boot's evidence, not part of what a call reaches.
#[cfg(target_os = "none")]
mod probes;

// Everything this module published before the split, re-exported so a caller
// keeps spelling `crate::net::xxx`.  A hand-written list would have to be
// updated by every section added; the globs cannot drift.
pub use core::*;
pub use dccp::*;
#[cfg(target_os = "none")]
pub use dhcp::*;
pub use filter::*;
pub use ipsec::*;
pub use multicast::*;
#[cfg(target_os = "none")]
pub use probes::*;
pub use tcp::*;

#[cfg(test)]
mod tests {
    use super::QUEUE_LIMIT;
    use super::core::Interface;
    use super::core::bind_udp;
    use super::core::deliver_udp;
    use super::core::install;
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use netdev::LinkDevice;
    use sync::Mutex;

    /// The interface, port table, neighbour cache and stream table are process
    /// globals.  Rust's test harness runs tests in parallel by default, so two
    /// tests that install or bind through the same singleton can otherwise
    /// observe one another's state.  This lock gives the network tests one
    /// deterministic world at a time without changing the production lock.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    fn exclusive() -> sync::MutexGuard<'static, ()> {
        TEST_LOCK.lock()
    }

    /// A card that records what it was asked to send, and hands back the
    /// frames a test queues for it, the same shape a driver has, without a
    /// machine behind it.
    struct FakeCard {
        sent: Mutex<Vec<Vec<u8>>>,
        incoming: Mutex<Vec<Vec<u8>>>,
    }

    impl FakeCard {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                sent: Mutex::new(Vec::new()),
                incoming: Mutex::new(Vec::new()),
            })
        }

        /// Queue a frame the card has "received", for the pump to drain.
        fn receive(&self, frame: &[u8]) {
            self.incoming.lock().push(Vec::from(frame));
        }
    }

    impl LinkDevice for FakeCard {
        fn hardware_address(&self) -> [u8; 6] {
            [0x02; 6]
        }

        fn submit_frame(&self, frame: &[u8]) -> abi::Result<()> {
            self.sent.lock().push(Vec::from(frame));
            Ok(())
        }

        fn receive_frame(&self, into: &mut [u8]) -> abi::Result<Option<usize>> {
            let mut incoming = self.incoming.lock();
            let Some(frame) = incoming.first() else {
                return Ok(None);
            };
            if frame.len() > into.len() {
                return Err(abi::Error::InvalidArgument);
            }
            let length = frame.len();
            into[..length].copy_from_slice(frame);
            incoming.remove(0);
            Ok(Some(length))
        }

        fn maximum_frame_len(&self) -> usize {
            1514
        }
    }

    /// Each test binds its own ports, because the port table is one boot's
    /// state and the tests run beside each other.
    /// The two protocol addresses these tests speak between.
    const OUR_PROTOCOL: [u8; 4] = [10, 9, 9, 15];
    const PEER_PROTOCOL: [u8; 4] = [10, 9, 9, 2];

    const PORT_A: u16 = 40001;
    const PORT_B: u16 = 40002;
    const PORT_C: u16 = 40003;
    const PORT_D: u16 = 40004;
    const PORT_E: u16 = 40005;
    const PORT_F: u16 = 40006;

    /// A bound port answers, and binding it again is the wire's refusal.
    #[test]
    fn a_bound_port_has_one_owner() {
        let _guard = exclusive();
        let socket = bind_udp(PORT_A).expect("a bind");
        assert_eq!(socket.port(), PORT_A);
        assert!(
            matches!(bind_udp(PORT_A), Err(abi::Error::AlreadyExists)),
            "the second bind on one port is the wire's refusal"
        );
    }

    /// A datagram delivered to a bound port is what the socket's next
    /// receive answers, with the source the delivery was given.
    #[test]
    fn a_delivered_datagram_is_what_the_receive_answers() {
        let _guard = exclusive();
        let socket = bind_udp(PORT_B).expect("a bind");
        let _ = deliver_udp(
            net::address::Address::V4([10, 0, 2, 2]),
            PORT_B,
            net::address::Address::V4([10, 0, 2, 9]),
            77,
            b"protofire",
        )
        .expect("a delivery");

        let mut buffer = [0_u8; 16];
        let (source, source_port, count) = socket
            .try_recv(&mut buffer)
            .expect("a receive")
            .expect("a datagram");
        assert_eq!(source, net::address::Address::V4([10, 0, 2, 9]));
        assert_eq!(source_port, 77);
        assert_eq!(count, 9);
        assert_eq!(&buffer[..count], b"protofire");
    }

    /// A datagram for a port nothing owns is dropped, because UDP promised
    /// nothing; the receive that follows answers nothing.
    #[test]
    fn a_datagram_for_an_unbound_port_is_dropped() {
        let _guard = exclusive();
        let woken = deliver_udp(
            net::address::Address::V4([10, 0, 2, 15]),
            PORT_E,
            net::address::Address::V4([10, 0, 2, 9]),
            77,
            b"nobody",
        )
        .expect("a delivery");
        assert_eq!(
            woken,
            super::core::Delivery::Unbound,
            "and no socket owned the port"
        );
        let socket = bind_udp(PORT_E).expect("a bind after the drop");
        let mut buffer = [0_u8; 16];
        assert_eq!(socket.try_recv(&mut buffer), Ok(None), "nothing arrived");
    }

    /// A receive with nothing in the queue answers none, and one whose
    /// datagram does not fit is refused with the datagram kept.
    #[test]
    fn a_receive_refuses_a_datagram_that_does_not_fit_and_keeps_it() {
        let _guard = exclusive();
        let socket = bind_udp(PORT_C).expect("a bind");
        let mut buffer = [0_u8; 16];
        assert_eq!(socket.try_recv(&mut buffer), Ok(None), "nothing yet");

        deliver_udp(
            net::address::Address::V4([10, 0, 2, 2]),
            PORT_C,
            net::address::Address::V4([10, 0, 2, 9]),
            77,
            b"way too long for this buffer",
        )
        .expect("a delivery");
        let mut small = [0_u8; 4];
        assert_eq!(
            socket.try_recv(&mut small).unwrap_err(),
            abi::Error::InvalidArgument,
            "the buffer, not the datagram, is the problem"
        );
        // The datagram is still there, and a buffer that fits takes it.
        let mut whole = [0_u8; 32];
        let (source, _, count) = socket
            .try_recv(&mut whole)
            .expect("a receive")
            .expect("the datagram was kept");
        assert_eq!(count, 28);
        assert_eq!(source, net::address::Address::V4([10, 0, 2, 9]));
    }

    /// A full queue refuses the next datagram with `Busy`, which is what a
    /// sender can act on.
    #[test]
    fn a_full_queue_refuses_with_busy() {
        let _guard = exclusive();
        let _socket = bind_udp(PORT_D).expect("a bind");
        for index in 0..QUEUE_LIMIT {
            deliver_udp(
                net::address::Address::V4([10, 0, 2, 2]),
                PORT_D,
                net::address::Address::V4([10, 0, 2, 9]),
                77,
                &[index as u8; 4],
            )
            .expect("a delivery");
        }
        assert_eq!(
            deliver_udp(
                net::address::Address::V4([10, 0, 2, 2]),
                PORT_D,
                net::address::Address::V4([10, 0, 2, 9]),
                77,
                b"one more",
            )
            .unwrap_err(),
            abi::Error::Busy
        );
    }

    /// The interface's whole day, as one test, because the interface is one
    /// static and the tests run beside each other: a datagram to this
    /// machine goes through the demux and never touches the card, one for
    /// another machine leaves through the gateway, a frame the card
    /// received is a datagram in a socket's queue after the pump, a stream
    /// opens, carries and closes on loopback, and a closed stream reads as
    /// end of file.
    #[test]
    fn the_interface_runs_the_whole_of_the_stack() {
        let _guard = exclusive();
        let card = FakeCard::new();
        let hardware = [0x02, 0x11, 0x22, 0x33, 0x44, 0x55];
        let protocol = [10, 9, 9, 15];
        let gateway = [10, 9, 9, 2];
        install(Interface::new(card.clone(), hardware, protocol, gateway));
        super::core::arp_learn(gateway, [0x52; 6]);

        // Loopback, as a datagram: to this machine's own address.
        let socket = bind_udp(PORT_F).expect("a bind");
        super::core::send_datagram(net::address::Address::V4(protocol), PORT_F, 50000, b"self")
            .expect("a loopback send");
        assert!(
            card.sent.lock().is_empty(),
            "a datagram to this machine does not touch the card"
        );
        let mut buffer = [0_u8; 8];
        let (source, _, count) = socket
            .try_recv(&mut buffer)
            .expect("a receive")
            .expect("the loopback datagram");
        assert_eq!(
            source,
            net::address::Address::V4(protocol),
            "the sender is this machine"
        );
        assert_eq!(&buffer[..count], b"self");

        // The wire, as a datagram: the frame names the gateway's hardware
        // address and the destination's protocol address, which is the
        // whole of this build's routing.
        super::core::send_datagram(
            net::address::Address::V4([10, 9, 9, 7]),
            9004,
            50000,
            b"out",
        )
        .expect("a send");
        {
            let sent = card.sent.lock();
            assert_eq!(sent.len(), 1);
            let frame = &sent[0];
            assert_eq!(&frame[0..6], &[0x52; 6], "to the gateway's address");
            assert_eq!(
                netdev::ethertype(frame),
                Some(net::ethernet::ETHERTYPE_IPV4)
            );
            let packet = net::ipv4::parse(&frame[netdev::ETHERNET_HEADER_LEN..]).expect("a packet");
            assert_eq!(packet.header.destination, [10, 9, 9, 7]);
            assert_eq!(packet.header.source, protocol);
        }

        // The pump: a real frame in the card's ring, a datagram in a
        // socket's queue after it, built by the same writers the send path
        // uses, so the pump is tested against the wire's own bytes.
        let datagram_socket = bind_udp(40008).expect("a bind");
        let udp_len = net::udp::datagram_len(5);
        let packet_len = netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + udp_len;
        let mut frame = alloc::vec![0; packet_len];
        net::ethernet::write_header(
            &mut frame,
            [0x02; 6],
            [0x02; 6],
            net::ethernet::ETHERTYPE_IPV4,
        );
        net::ipv4::write_header(
            &mut frame[netdev::ETHERNET_HEADER_LEN..],
            [10, 9, 9, 9],
            protocol,
            net::ipv4::PROTOCOL_UDP,
            udp_len,
        );
        net::udp::write_datagram(
            &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..],
            [10, 9, 9, 9],
            protocol,
            77,
            40008,
            b"hello",
        );
        card.receive(&frame);
        assert_eq!(
            super::core::pump(),
            1,
            "the pump took the frame the card held"
        );
        let mut buffer = [0_u8; 8];
        let (source, source_port, count) = datagram_socket
            .try_recv(&mut buffer)
            .expect("a receive")
            .expect("the datagram the frame carried");
        assert_eq!(source, net::address::Address::V4([10, 9, 9, 9]));
        assert_eq!(source_port, 77);
        assert_eq!(&buffer[..count], b"hello");

        // The stream: the boot's own probe, as a host test.  The same
        // calls, the same demux, and a card that records nothing, because a
        // loopback stream touches none of it.
        let listener = super::tcp::tcp_listen(9002).expect("a listen");
        let client =
            super::tcp::tcp_connect(net::address::Address::V4(protocol), 9002).expect("a connect");
        assert_eq!(
            card.sent.lock().len(),
            1,
            "the handshake never touched the card: the wire datagram's frame is still the only one"
        );
        assert!(
            super::tcp::tcp_has_pending(listener),
            "the SYN opened a stream"
        );
        let accepted = super::tcp::tcp_accept(listener)
            .expect("an accept")
            .expect("a pending stream");

        let sent = super::tcp::tcp_write(client, b"protofire").expect("a write");
        assert_eq!(sent, 9);
        assert!(super::tcp::tcp_has_data(accepted), "the stream carried it");
        let mut stream_buffer = [0_u8; 32];
        let echoed = super::tcp::tcp_read(accepted, &mut stream_buffer)
            .expect("a read")
            .expect("the bytes");
        assert_eq!(echoed, 9);
        assert_eq!(&stream_buffer[..9], b"protofire");

        let back = super::tcp::tcp_write(accepted, &stream_buffer[..echoed]).expect("a write");
        assert_eq!(back, 9);
        let received = super::tcp::tcp_read(client, &mut stream_buffer)
            .expect("a read")
            .expect("the echo");
        assert_eq!(received, 9);
        assert_eq!(&stream_buffer[..9], b"protofire");

        // The orderly close, and the end of file it leaves behind.
        super::tcp::tcp_close(client).expect("a close");
        super::tcp::tcp_close(accepted).expect("a close");
        {
            let table = super::core::TCP.lock();
            // Both ends finished, and both **hold** the four-tuple: the close
            // is over and the entry stays in `TimeWait` so a retransmitted
            // finish is answered rather than reset.  The read below is the
            // part that matters to a program, and it is end-of-file either
            // way: a stream whose inbox is drained and whose peer finished
            // reads zero.
            assert_eq!(
                table.connection(client).map(|c| c.state()),
                Some(net::tcp::State::TimeWait),
                "the client's end finished and its four-tuple is held"
            );
            assert_eq!(
                table.connection(accepted).map(|c| c.state()),
                Some(net::tcp::State::TimeWait),
                "and the accepted end with it"
            );
        }
        assert_eq!(
            super::tcp::tcp_read(client, &mut stream_buffer),
            Ok(Some(0)),
            "a stream whose close is over reads as end of file, and not as \
             `None`: the entry is held in `TimeWait`, so a reader that treated \
             an empty inbox as `ask again` would wait for a writer that has \
             finished"
        );
        // The stream never touched the card, and the wire datagram's frame
        // is still the only thing the card carries.
        assert_eq!(card.sent.lock().len(), 1, "loopback is not the wire");
    }

    /// A datagram for a port nothing owns is answered with a report that
    /// quotes the datagram, and the sender can read its own ports back out of
    /// the quote.
    ///
    /// This is the assertion a boot cannot make: the boot sees no report,
    /// because a report only goes to a sender that sent something.  What the
    /// test can do is build the report the kernel would send and check the
    /// bytes a sender acts on, its own source port and destination port, at
    /// the offsets its own header layout puts them.
    #[test]
    fn a_port_unreachable_report_quotes_the_datagram_it_answers() {
        // A datagram from a peer to a port on this machine, with a UDP header
        // whose ports the test can read back.
        const SOURCE_PORT: u16 = 9300;
        const DESTINATION_PORT: u16 = 9400;
        const PAYLOAD: &[u8] = b"nobody";
        let udp_len = net::udp::datagram_len(PAYLOAD.len());
        let mut datagram = alloc::vec![0_u8; udp_len];
        net::udp::write_datagram(
            &mut datagram,
            PEER_PROTOCOL,
            OUR_PROTOCOL,
            SOURCE_PORT,
            DESTINATION_PORT,
            PAYLOAD,
        );

        // The header carries a type of service and a time-to-live this stack
        // never sends, so a quote rebuilt from the fields `parse` keeps would
        // differ from the bytes: the assertions below tell a quote from a
        // rebuild.
        let mut header = [0_u8; net::ipv4::HEADER_LEN];
        header[0] = 0x45;
        header[1] = 0xB8;
        header[2..4].copy_from_slice(&((net::ipv4::HEADER_LEN + udp_len) as u16).to_be_bytes());
        header[8] = 3;
        header[9] = net::ipv4::PROTOCOL_UDP;
        header[12..16].copy_from_slice(&PEER_PROTOCOL);
        header[16..20].copy_from_slice(&OUR_PROTOCOL);
        let sum = net::ipv4::checksum(&header);
        header[10..12].copy_from_slice(&sum.to_be_bytes());
        // `parse` cross-checks the total length against the bytes it was
        // given, so the header has to arrive with the payload it claims.
        let mut wire = alloc::vec![0_u8; net::ipv4::HEADER_LEN + udp_len];
        wire[..net::ipv4::HEADER_LEN].copy_from_slice(&header);
        wire[net::ipv4::HEADER_LEN..].copy_from_slice(&datagram);
        let packet = net::ipv4::parse(&wire).expect("the packet a peer wrote");
        let original_header = packet.header_bytes(&wire).expect("its own header");

        let frame = super::demux4::port_unreachable_frame(
            original_header,
            &packet,
            &datagram,
            OUR_PROTOCOL,
            [0x02; 6],
            [0x54; 6],
        );

        // The frame is addressed to the sender, from this machine.
        assert_eq!(&frame[0..6], &[0x54; 6], "to the sender's own address");
        assert_eq!(&frame[6..12], &[0x02; 6]);
        let answer = net::ipv4::parse(&frame[netdev::ETHERNET_HEADER_LEN..])
            .expect("the report's own header");
        assert_eq!(answer.header.protocol, net::ipv4::PROTOCOL_ICMP);
        assert_eq!(answer.header.source, OUR_PROTOCOL, "from this machine");
        assert_eq!(answer.header.destination, PEER_PROTOCOL, "to the sender");

        // The message is a port-unreachable, verifies, and quotes the
        // datagram's ports where the sender looks for them: eight fixed
        // bytes, then the quoted twenty-byte header, then the UDP header.
        let message = &frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..];
        let error = net::icmp::parse_error(message).expect("an error message");
        assert_eq!(error.kind, net::icmp::DESTINATION_UNREACHABLE);
        assert_eq!(error.code, net::icmp::PORT_UNREACHABLE);
        let quote = &message[error.quoted_at..error.quoted_at + error.quoted_len];
        assert_eq!(quote[0] >> 4, 4, "the quoted packet is IPv4");
        // The quote is the sender's own bytes, not a header rebuilt from the
        // fields this stack reads: the ttl and the type of service are the
        // ones the test wrote and this stack never sends.
        assert_eq!(
            &quote[..20],
            &header[..],
            "the sender's header, byte for byte"
        );
        assert_eq!(quote[8], 3, "the ttl the sender chose");
        assert_eq!(quote[1], 0xB8, "the type of service the sender chose");
        assert_eq!(quote[9], net::ipv4::PROTOCOL_UDP);
        assert_eq!(
            &quote[12..16],
            &PEER_PROTOCOL,
            "the sender's address came back"
        );
        assert_eq!(
            &quote[20..22],
            &SOURCE_PORT.to_be_bytes(),
            "its source port, where its own UDP header puts it"
        );
        assert_eq!(
            &quote[22..24],
            &DESTINATION_PORT.to_be_bytes(),
            "and the port nothing owned"
        );
    }

    /// A frame the card received is a datagram in a socket's queue after the
    /// pump, which is the receive path's own shape.
    #[test]
    fn a_frame_the_card_received_is_a_datagram_after_the_pump() {
        let _guard = exclusive();
        let card = FakeCard::new();
        let protocol = [10, 9, 9, 15];
        install(Interface::new(
            card.clone(),
            [0x02; 6],
            protocol,
            [10, 9, 9, 2],
        ));

        let socket = bind_udp(40007).expect("a bind");
        // A real frame: Ethernet to this machine, IPv4 to its address, and
        // the datagram in the payload, built by the same writers the send
        // path uses, so the pump is tested against the wire's own bytes.
        let udp_len = net::udp::datagram_len(5);
        let packet_len = netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + udp_len;
        let mut frame = alloc::vec![0; packet_len];
        net::ethernet::write_header(
            &mut frame,
            [0x02; 6],
            [0x02; 6],
            net::ethernet::ETHERTYPE_IPV4,
        );
        net::ipv4::write_header(
            &mut frame[netdev::ETHERNET_HEADER_LEN..],
            [10, 9, 9, 9],
            protocol,
            net::ipv4::PROTOCOL_UDP,
            udp_len,
        );
        net::udp::write_datagram(
            &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..],
            [10, 9, 9, 9],
            protocol,
            77,
            40007,
            b"hello",
        );
        card.receive(&frame);

        let taken = super::core::pump();
        assert_eq!(taken, 1, "the pump took the frame the card held");

        let mut buffer = [0_u8; 8];
        let (source, source_port, count) = socket
            .try_recv(&mut buffer)
            .expect("a receive")
            .expect("the datagram the frame carried");
        assert_eq!(source, net::address::Address::V4([10, 9, 9, 9]));
        assert_eq!(source_port, 77);
        assert_eq!(&buffer[..count], b"hello");
    }

    /// The clock the fragment cache is given is a duration, and the cache's
    /// constant is the same duration.
    ///
    /// This is the join no test could see before: the cache's own tests
    /// measure against a clock they supply, so a caller that handed it raw
    /// ticks satisfied every one of them while the window it actually offered
    /// was a hundred times shorter than the constant describing it.
    #[test]
    fn the_tick_is_a_duration_and_the_timeout_is_measured_in_one() {
        // The machine's slice and this file's copy are the same number.  On a
        // host only one of them compiles, so the comparison is made where the
        // machine's exists; what this test can always check is that the cache
        // holds a duration and that the conversion is a duration too.
        #[cfg(target_os = "none")]
        assert_eq!(
            super::crate::tick::TIME_SLICE_US,
            super::core::MICROS_PER_TICK,
            "the boot's slice and the conversion's copy are one number"
        );

        assert_eq!(
            super::core::micros_of_ticks(1),
            super::core::MICROS_PER_TICK,
            "one timer interrupt is one slice"
        );

        // The reassembly timeout, converted back to seconds, is RFC 1122's
        // thirty.  A factor of a hundred wrong either way fails here: too
        // small and the window is 0.3 s, too large and it is fifty minutes.
        let timeout_seconds = net::reassembly::TIMEOUT_MICROS / 1_000_000;
        assert_eq!(
            timeout_seconds, 30,
            "RFC 1122's floor for reassembly is thirty seconds"
        );

        // And the count of interrupts that thirty seconds is, which is what a
        // caller passing ticks instead of a duration would have got wrong.
        let ticks_in_the_window = net::reassembly::TIMEOUT_MICROS / super::core::MICROS_PER_TICK;
        assert_eq!(
            super::core::micros_of_ticks(ticks_in_the_window),
            net::reassembly::TIMEOUT_MICROS,
            "the window, measured in ticks and converted back, is itself"
        );
        assert_eq!(
            ticks_in_the_window, 300_000,
            "ten kilohertz for thirty seconds"
        );
    }

    /// A DHCP lease's seconds are converted into the clock its duty is
    /// measured by, and the two agree.
    ///
    /// This is the second place the same class of defect lived: `lease_from`
    /// takes the caller's unit, and the caller passed `1` while its clock
    /// counted microseconds, so an hour's lease was read as expired
    /// eighty-six milliseconds after it was granted.  The test goes through
    /// `lease_from` for exactly that reason: a test that built a `Lease` by
    /// hand would pass whatever scale the caller used, which is what the
    /// first version of this test did.
    #[test]
    fn a_lease_is_measured_in_the_clock_its_duty_reads() {
        let reply = net::dhcp::Reply {
            kind: net::dhcp::MESSAGE_ACK,
            address: [10, 0, 2, 15],
            server: Some([10, 0, 2, 2]),
            router: Some([10, 0, 2, 2]),
            dns: Some([10, 0, 2, 3]),
            subnet_mask: Some([255, 255, 255, 0]),
            lease_seconds: 3_600,
            renewal_seconds: 1_800,
            rebinding_seconds: 3_150,
        };

        // The conversion this kernel makes: a second is `MICROS_PER_SECOND`
        // of its clock.
        let lease = net::dhcp::lease_from(&reply, 0, super::core::MICROS_PER_SECOND)
            .expect("an ACK is a lease");
        assert_eq!(
            lease.lifetime,
            3_600 * super::core::MICROS_PER_SECOND,
            "an hour, in this kernel's unit"
        );
        assert_eq!(lease.duty(0), net::dhcp::Duty::Bound, "fresh at the grant");
        assert_eq!(
            lease.duty(lease.lifetime / 2),
            net::dhcp::Duty::Renew,
            "renewal at half the lease"
        );
        assert_eq!(
            lease.duty(lease.lifetime / 8 * 7),
            net::dhcp::Duty::Rebind,
            "rebinding at seven eighths"
        );
        assert_eq!(
            lease.duty(lease.lifetime),
            net::dhcp::Duty::Expired,
            "and the address is gone at the end"
        );

        // The scale the caller used before this fix, for contrast: the same
        // reply becomes a lease whose thirty-six hundred seconds are read as
        // thirty-six hundred *microseconds*, so a boot three and a half
        // milliseconds old is already past it.
        let wrong = net::dhcp::lease_from(&reply, 0, 1).expect("an ACK is a lease");
        assert_eq!(wrong.lifetime, 3_600, "an hour read as 3600 units");
        assert_eq!(
            wrong.duty(3_600),
            net::dhcp::Duty::Expired,
            "expired 3.6 milliseconds into a boot"
        );
        assert!(
            super::core::micros_of_ticks(36) == 3_600,
            "which is thirty-six timer interrupts, not an hour"
        );
    }

    /// A report about this machine's own packet names the stream by this
    /// machine's port first and the peer's second.
    ///
    /// The port order is the whole test.  The quoted packet is one this
    /// machine sent, so its source port is ours; a reader that handed the
    /// table the pair the other way round found the peer's own end of a
    /// loopback exchange and shrank the wrong stream, which is the defect the
    /// boot's probe found after this test's subject was already written.
    #[test]
    fn a_report_names_our_port_first_and_the_peers_second() {
        const OURS: u16 = 49152;
        const THEIRS: u16 = 9000;
        let us = [10, 0, 2, 15];

        // The report: the bytes a router sends about a segment this machine
        // sent to a peer, which is why the original's source is this machine's
        // address and its destination is the peer's.
        let mut quoted_header = [0_u8; 20];
        net::ipv4::write_header(
            &mut quoted_header,
            us,
            [10, 0, 2, 2],
            net::ipv4::PROTOCOL_TCP,
            net::icmp::QUOTED_PAYLOAD,
        );
        let mut quoted_payload = [0_u8; 8];
        quoted_payload[0..2].copy_from_slice(&THEIRS.to_be_bytes());
        quoted_payload[2..4].copy_from_slice(&OURS.to_be_bytes());

        let mut message = [0_u8; 64];
        net::icmp::write_unreachable_with_mtu(
            &mut message,
            net::icmp::FRAGMENTATION_NEEDED,
            1_400,
            &quoted_header,
            &quoted_payload,
        );
        let length = net::icmp::error_len(quoted_header.len(), quoted_payload.len());
        let error = net::icmp::parse_error(&message[..length]).expect("an error");

        let report =
            super::demux4::quoted_report(us, &error, &message[..length]).expect("a report");
        assert_eq!(
            report.local_port, THEIRS,
            "the port the quoted packet named first is ours"
        );
        assert_eq!(
            report.remote.1, OURS,
            "and the second is the peer it went to"
        );
        assert_eq!(report.remote.0, net::address::Address::V4([10, 0, 2, 2]));
    }

    /// A report about a packet that was not this machine's is refused.
    ///
    /// The quoted packet is one whose destination is somebody else, so no
    /// stream of ours could be the subject: acting on it would let a stranger
    /// shrink or end a connection by guessing a port.
    #[test]
    fn a_report_about_someone_elses_packet_is_refused() {
        let us = [10, 0, 2, 15];
        let mut quoted_header = [0_u8; 20];
        net::ipv4::write_header(
            &mut quoted_header,
            [10, 0, 2, 9],
            [10, 0, 2, 2],
            net::ipv4::PROTOCOL_TCP,
            net::icmp::QUOTED_PAYLOAD,
        );
        let mut quoted_payload = [0_u8; 8];
        quoted_payload[0..2].copy_from_slice(&9000u16.to_be_bytes());
        quoted_payload[2..4].copy_from_slice(&49152u16.to_be_bytes());

        let mut message = [0_u8; 64];
        net::icmp::write_unreachable_with_mtu(
            &mut message,
            net::icmp::FRAGMENTATION_NEEDED,
            1_400,
            &quoted_header,
            &quoted_payload,
        );
        let length = net::icmp::error_len(quoted_header.len(), quoted_payload.len());
        let error = net::icmp::parse_error(&message[..length]).expect("an error");

        assert_eq!(
            super::demux4::quoted_report(us, &error, &message[..length]),
            None,
            "the quoted packet was not addressed to this machine"
        );
    }

    /// The payload a path's MTU leaves is the MTU less both headers, and a
    /// wrongly small one is not a wrapped number.
    #[test]
    fn a_paths_mtu_leaves_room_for_the_headers() {
        assert_eq!(
            super::demux4::payload_for(1_500),
            1_500 - net::ipv4::HEADER_LEN - net::tcp::HEADER_LEN
        );
        // A path that claims less than the headers is a peer's mistake, and
        // the subtraction must not wrap into four gigabytes.
        assert_eq!(super::demux4::payload_for(10), 0);
        assert_eq!(super::demux4::payload_for(0), 0);
    }
}
