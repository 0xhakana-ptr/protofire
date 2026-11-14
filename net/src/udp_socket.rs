//! net/src/udp_socket.rs
//!
//! A datagram socket's queue: the datagrams that arrived for one bound port,
//! in the order they arrived, bounded.
//!
//! ## Why the queue is here and not in the kernel
//!
//! A socket's queue is three rules and a buffer.  The rules are the wire's:
//! datagrams keep the order they arrived in, a full queue refuses the next
//! one with `Busy` rather than dropping the oldest, and a receive whose buffer
//! is too small is refused with the datagram **kept**, a caller learns its
//! buffer is wrong and asks again, and a take that discarded the bytes would
//! make that loss permanent and silent.
//!
//! None of that needs a scheduler, a card or a lock.  So it is a value here,
//! and the kernel holds one behind a `Mutex` because two callers reach it
//! the demux that delivers and the task that receives, which is the kernel's
//! decision about its own concurrency and not this module's.
//!
//! What stays in the kernel: the `Arc` that is the socket's life, the `Weak`
//! in the port table that makes a closed socket's port free again, and the
//! scheduler wake a delivery makes.  A queue cannot own any of those, because
//! a queue is not a socket, it is what a socket holds.

use alloc::vec::Vec;

use abi::Error;
use abi::Result;

use crate::address::Address;

/// How many datagrams one socket may hold before it refuses more.
///
/// Sixteen, and the number is a policy rather than a limit of the wire: a
/// socket that queued everything would let one sender spend a receiver's
/// memory, and a socket that queued one would make a burst a loss.  Sixteen
/// covers a burst and bounds what one port costs.
pub const QUEUE_LIMIT: usize = 16;

/// One datagram that arrived, and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Datagram {
    /// The sender's address, as the packet's header carried it.
    pub source: Address,
    /// The sender's port, as the datagram's header carried it.
    pub source_port: u16,
    /// The bytes, copied: the frame they arrived in is the card's ring's and
    /// is reused by the next receive.
    pub bytes: Vec<u8>,
}

/// What one receive answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Taken {
    /// Where the datagram came from.
    pub source: Address,
    /// The port it came from.
    pub source_port: u16,
    /// How many bytes were written into the caller's buffer.
    pub count: usize,
}

/// One bound port's queue of what arrived for it.
#[derive(Debug, Default)]
pub struct Queue {
    datagrams: Vec<Datagram>,
}

impl Queue {
    /// An empty queue.
    pub const fn new() -> Self {
        Self {
            datagrams: Vec::new(),
        }
    }

    /// How many datagrams are waiting.
    pub fn len(&self) -> usize {
        self.datagrams.len()
    }

    /// Whether nothing is waiting, which is what a receive parks on.
    pub fn is_empty(&self) -> bool {
        self.datagrams.is_empty()
    }

    /// Put one datagram at the back, or refuse when the queue is full.
    ///
    /// [`Error::Busy`] rather than a dropped datagram: the sender can act on
    /// a refusal, and a queue that silently discarded its oldest would lose a
    /// datagram the receiver was about to take.
    pub fn push(&mut self, source: Address, source_port: u16, bytes: &[u8]) -> Result<()> {
        if self.datagrams.len() >= QUEUE_LIMIT {
            return Err(Error::Busy);
        }
        self.datagrams.push(Datagram {
            source,
            source_port,
            bytes: Vec::from(bytes),
        });
        Ok(())
    }

    /// Take the oldest datagram, answering where it came from and how much of
    /// it fit.
    ///
    /// `Ok(None)` is "nothing arrived, ask again", the answer a caller parks
    /// on, and not an error.  A datagram longer than `into` is refused with
    /// [`Error::InvalidArgument`] and **kept**: a caller whose buffer is small
    /// learns that from the error and asks again with a larger one, and a take
    /// that discarded the bytes would make the loss permanent.
    pub fn take(&mut self, into: &mut [u8]) -> Result<Option<Taken>> {
        let Some(oldest) = self.datagrams.first() else {
            return Ok(None);
        };
        if oldest.bytes.len() > into.len() {
            return Err(Error::InvalidArgument);
        }
        let taken = self.datagrams.remove(0);
        into[..taken.bytes.len()].copy_from_slice(&taken.bytes);
        Ok(Some(Taken {
            source: taken.source,
            source_port: taken.source_port,
            count: taken.bytes.len(),
        }))
    }

    /// Drop everything queued, which is what a socket's last descriptor does
    /// with what arrived after it closed.
    pub fn clear(&mut self) {
        self.datagrams.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::QUEUE_LIMIT;
    use super::Queue;
    use abi::Error;

    use crate::address::Address;

    /// The peer a test's datagrams come from.
    fn peer() -> Address {
        Address::V4([10, 0, 2, 2])
    }

    /// An empty queue answers nothing rather than an error, which is the
    /// difference a parking receive depends on.
    #[test]
    fn an_empty_queue_answers_nothing() {
        let mut queue = Queue::new();
        assert!(queue.is_empty());
        assert_eq!(queue.len(), 0);
        let mut buffer = [0_u8; 8];
        assert_eq!(queue.take(&mut buffer), Ok(None));
    }

    /// Datagrams keep the order they arrived in: a queue that reordered them
    /// would make every protocol above a datagram look broken.
    #[test]
    fn datagrams_keep_their_order() {
        let mut queue = Queue::new();
        queue.push(peer(), 77, b"first").expect("the first");
        queue.push(peer(), 78, b"second").expect("the second");
        assert_eq!(queue.len(), 2);

        let mut buffer = [0_u8; 16];
        let taken = queue.take(&mut buffer).expect("a take").expect("one");
        assert_eq!(&buffer[..taken.count], b"first");
        assert_eq!(taken.source_port, 77, "and its own port");

        let taken = queue.take(&mut buffer).expect("a take").expect("one");
        assert_eq!(&buffer[..taken.count], b"second");
        assert_eq!(taken.source_port, 78);
        assert!(queue.is_empty());
    }

    /// A buffer too small is refused with the datagram kept, which is what
    /// makes a caller's retry with a larger buffer answer instead of nothing.
    #[test]
    fn a_small_buffer_is_refused_and_the_datagram_kept() {
        let mut queue = Queue::new();
        queue.push(peer(), 77, b"way too long").expect("a push");

        let mut small = [0_u8; 4];
        assert_eq!(queue.take(&mut small), Err(Error::InvalidArgument));
        assert_eq!(queue.len(), 1, "the datagram is still there");

        let mut whole = [0_u8; 32];
        let taken = queue.take(&mut whole).expect("a take").expect("one");
        assert_eq!(&whole[..taken.count], b"way too long");
        assert_eq!(taken.source, peer());
    }

    /// The queue has a bound, and the refusal is `Busy` rather than a dropped
    /// datagram: a sender can act on a refusal.
    #[test]
    fn a_full_queue_refuses_with_busy() {
        let mut queue = Queue::new();
        for index in 0..QUEUE_LIMIT {
            queue
                .push(peer(), 77, &[index as u8])
                .expect("a delivery inside the bound");
        }
        assert_eq!(queue.len(), QUEUE_LIMIT);
        assert_eq!(queue.push(peer(), 77, b"one more"), Err(Error::Busy));
        assert_eq!(queue.len(), QUEUE_LIMIT, "and nothing was dropped for it");

        // What is held is the first QUEUE_LIMIT, in order, and the refused
        // one is the one that is absent.
        let mut buffer = [0_u8; 8];
        for index in 0..QUEUE_LIMIT {
            let taken = queue.take(&mut buffer).expect("a take").expect("one");
            assert_eq!(buffer[0], index as u8);
            assert_eq!(taken.count, 1);
        }
        assert!(queue.is_empty());
    }

    /// A clear empties the queue, which is what a close does with what
    /// arrived too late for anyone to read.
    #[test]
    fn a_clear_empties_the_queue() {
        let mut queue = Queue::new();
        queue.push(peer(), 77, b"a").expect("a push");
        queue.push(peer(), 77, b"b").expect("a push");
        queue.clear();
        assert!(queue.is_empty());
        let mut buffer = [0_u8; 8];
        assert_eq!(queue.take(&mut buffer), Ok(None));
    }
}
