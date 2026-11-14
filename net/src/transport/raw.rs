//! net/src/transport/raw.rs
//!
//! A socket that names an IP protocol number instead of a port: what arrives
//! with that number in the IP header is queued for its reader, and what is
//! written leaves as that protocol's payload.
//!
//! ## What a raw socket is, and what it is not
//!
//! It sits where a datagram socket does, one layer down.  A UDP socket is keyed
//! on a port and receives what the transport layer demultiplexed for it; a raw
//! socket is keyed on the protocol number in the IP header and receives what
//! the internet layer carried, so an implementation of a protocol this stack
//! does not have (ICMP's diagnostics, a routing protocol, a transport being
//! written) can run in a program.  That is the whole reason the call exists,
//! and it is also why it is a privileged interface on every system that has
//! one: nothing checks what the bytes say.
//!
//! ## What it deliberately does not do
//!
//! It does not **compose** an IP header.  A raw send names a destination and a
//! payload, and the header is written by the same function that writes every
//! other IPv4 header this stack sends, because a program that wrote its own
//! header would also write its own source address and its own length, and
//! fields the stack is responsible for would become a program's.  What the
//! program chooses is the **protocol number** and the payload; what the stack
//! chooses is everything the header says about this machine.
//!
//! It does not receive bytes that are not this machine's.  The demux hands a
//! raw socket the packets addressed to this machine and nothing else, which is
//! what the IP layer already decided; a raw socket is a reader of the internet
//! layer's output, not a promiscuous capture, and a promiscuous mode is a
//! different mechanism with a different argument in front of it.
//!
//! ## The bound on the queue
//!
//! [`QUEUE_LIMIT`] packets, and a full queue drops the newest.  A raw socket
//! receives whatever arrives with its number, which is traffic a program did
//! not ask for and cannot slow down: without a bound, a program that stopped
//! reading would make the kernel hold whatever the wire sent.  The drop is not
//! reported to the sender, because on a raw socket there is no sender to
//! report it to.

use alloc::vec::Vec;

use abi::Error;
use abi::Result;

use crate::address::Address;

/// How many packets one raw socket holds before it drops the newest.
///
/// The same order as a datagram queue's bound, and a larger number because
/// what arrives with a protocol number is not one conversation's traffic: a
/// program watching ICMP sees every ICMP message this machine receives, so its
/// queue is a stream rather than a request's answer.
pub const QUEUE_LIMIT: usize = 32;

/// One received packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    /// Where it came from, as the IP header named.
    pub source: Address,
    /// What it carried: everything after the IP header.
    pub payload: Vec<u8>,
}

/// One protocol's queue.
///
/// The arithmetic is a queue's: push, take, and the bound, with the one rule
/// that makes a short buffer an error rather than a truncation.  A caller that
/// asked for sixteen bytes and was handed the first sixteen of a hundred has
/// been given a packet that is not what arrived, and the only honest answers
/// are the whole thing or a refusal that keeps it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Socket {
    /// The protocol number this socket is bound to.
    protocol: u8,
    /// The packets waiting, oldest first.
    queue: Vec<Packet>,
}

impl Socket {
    /// A socket bound to `protocol`.
    pub fn new(protocol: u8) -> Self {
        Self {
            protocol,
            queue: Vec::new(),
        }
    }

    /// The protocol number this socket answers for.
    pub fn protocol(&self) -> u8 {
        self.protocol
    }

    /// How many packets are waiting.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Whether nothing is waiting.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Queue one packet, or drop it because the queue is full.
    ///
    /// Answers whether it was kept, which is what the demux needs to know: a
    /// dropped packet is a packet no raw socket will ever read, and a caller
    /// that printed a delivery count would otherwise overstate what happened.
    pub fn deliver(&mut self, source: Address, payload: &[u8]) -> bool {
        if self.queue.len() >= QUEUE_LIMIT {
            return false;
        }
        self.queue.push(Packet {
            source,
            payload: Vec::from(payload),
        });
        true
    }

    /// Take the oldest packet into `into`, answering what was written.
    ///
    /// `Ok(None)` is an empty queue, which is a caller's signal to park rather
    /// than an error: a raw socket is a stream of what the wire sends, and
    /// nothing yet is its ordinary state.
    ///
    /// A packet longer than `into` is [`Error::InvalidArgument`] with the
    /// packet **kept**, the same rule a datagram receive keeps: the caller
    /// learns from the error that its buffer was small and asks again with a
    /// larger one, and a take that discarded the rest would make the loss
    /// permanent and silent.
    pub fn take(&mut self, into: &mut [u8]) -> Result<Option<(Address, usize)>> {
        let Some(packet) = self.queue.first() else {
            return Ok(None);
        };
        if packet.payload.len() > into.len() {
            return Err(Error::InvalidArgument);
        }
        let count = packet.payload.len();
        let source = packet.source;
        into[..count].copy_from_slice(&packet.payload);
        self.queue.remove(0);
        Ok(Some((source, count)))
    }

    /// Drop everything waiting.
    pub fn clear(&mut self) {
        self.queue.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::QUEUE_LIMIT;
    use super::Socket;
    use crate::address::Address;
    use abi::Error;

    const PEER: Address = Address::V4([10, 0, 2, 2]);

    /// A packet delivered comes back whole, with where it came from.
    #[test]
    fn a_packet_comes_back_with_its_source() {
        let mut socket = Socket::new(1);
        assert!(socket.deliver(PEER, b"icmp"));
        let mut buffer = [0_u8; 16];
        let (source, count) = socket
            .take(&mut buffer)
            .expect("a queue")
            .expect("a packet");
        assert_eq!(source, PEER);
        assert_eq!(count, 4);
        assert_eq!(&buffer[..count], b"icmp");
        assert!(socket.is_empty(), "and it was taken, not copied");
    }

    /// An empty queue answers `Ok(None)`, not an error.
    ///
    /// The distinction is what a program's loop turns on: nothing yet is a
    /// park, and an error is a reason to stop.  A raw socket whose empty read
    /// answered an error would make every server a poll.
    #[test]
    fn an_empty_queue_answers_nothing() {
        let mut socket = Socket::new(1);
        let mut buffer = [0_u8; 16];
        assert_eq!(socket.take(&mut buffer), Ok(None));
    }

    /// A buffer too small is refused and the packet is kept.
    ///
    /// A truncated packet is not the packet that arrived, and a take that
    /// dropped the rest would make the loss permanent: the caller learns from
    /// the refusal to ask again with a larger buffer.
    #[test]
    fn a_small_buffer_is_refused_and_the_packet_kept() {
        let mut socket = Socket::new(1);
        assert!(socket.deliver(PEER, b"a packet longer than four bytes"));
        let mut small = [0_u8; 4];
        assert_eq!(
            socket.take(&mut small),
            Err(Error::InvalidArgument),
            "four bytes is not the packet"
        );
        assert_eq!(socket.len(), 1, "and it is still there");
        let mut large = [0_u8; 64];
        let (_, count) = socket.take(&mut large).expect("a queue").expect("a packet");
        assert_eq!(count, 31);
        assert!(socket.is_empty());
    }

    /// Packets keep their order.
    #[test]
    fn packets_keep_their_order() {
        let mut socket = Socket::new(17);
        for index in 0..4_u8 {
            assert!(socket.deliver(PEER, &[index]));
        }
        let mut buffer = [0_u8; 8];
        for index in 0..4_u8 {
            let (_, count) = socket
                .take(&mut buffer)
                .expect("a queue")
                .expect("a packet");
            assert_eq!(count, 1);
            assert_eq!(buffer[0], index);
        }
    }

    /// A full queue drops the newest and says so.
    ///
    /// The bound is what stops a program that stopped reading from making the
    /// kernel hold whatever the wire sends.  The answer is what lets the demux
    /// report a real count rather than one that overstates it.
    #[test]
    fn a_full_queue_drops_the_newest() {
        let mut socket = Socket::new(1);
        for _ in 0..QUEUE_LIMIT {
            assert!(socket.deliver(PEER, b"x"), "room");
        }
        assert!(!socket.deliver(PEER, b"one too many"), "and no room");
        assert_eq!(socket.len(), QUEUE_LIMIT, "the count did not grow");

        // The oldest are still the ones that were kept, so the drop was the
        // newest and not a silent eviction of what had already arrived.
        let mut buffer = [0_u8; 8];
        for _ in 0..QUEUE_LIMIT {
            let (_, count) = socket
                .take(&mut buffer)
                .expect("a queue")
                .expect("a packet");
            assert_eq!(&buffer[..count], b"x");
        }
    }

    /// A clear empties the queue, which is what a close does with what was
    /// never read.
    #[test]
    fn a_clear_empties_the_queue() {
        let mut socket = Socket::new(1);
        assert!(socket.deliver(PEER, b"x"));
        assert!(socket.deliver(PEER, b"y"));
        socket.clear();
        assert!(socket.is_empty());
    }

    /// Two protocols are two sockets, and a packet for one does not reach the
    /// other.
    ///
    /// The property the demux depends on: it matches the protocol number and
    /// delivers only to the sockets that named it.
    #[test]
    fn two_protocols_are_two_sockets() {
        let mut icmp = Socket::new(1);
        let tcp = Socket::new(6);
        assert!(icmp.deliver(PEER, b"echo"));
        assert!(tcp.is_empty(), "a different protocol's packet");
        assert_eq!(icmp.protocol(), 1);
        assert_eq!(tcp.protocol(), 6);
    }
}
