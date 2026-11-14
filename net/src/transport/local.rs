//! net/src/transport/local.rs
//!
//! A rendezvous between two processes on one machine: a name a listener binds,
//! the queue of connections waiting at it, and the rule that the name is held
//! by one binder and taken back when its last descriptor goes.
//!
//! ## What this is, and what it is not
//!
//! This is **not** a protocol: no bytes here are on a wire, and nothing in this
//! module parses or composes a frame.  What it is is the naming and the queue,
//! the two things a local-domain socket has that a pipe does not: a pipe is
//! anonymous and can only be handed to a child, and a local socket is a name a
//! process that was never its parent can find.
//!
//! The bytes cross through a pipe, and that is the kernel's half.  A `Table`
//! here hands back the **ids** of the two ends of one connection; the kernel
//! keeps the pipes behind them, because a pipe parks a reader and parking is
//! the scheduler's act.  This crate's `option` module is the same split: what
//! is arithmetic is here and testable on a host, and what needs a scheduler is
//! the kernel's.
//!
//! ## Why the name is a value and not a path
//!
//! A local socket's name is a byte string a program chooses and a listener
//! owns.  It is not a filesystem path: nothing resolves it through a
//! namespace, nothing stat()s it, and a name a filesystem already holds is a
//! name a local socket may still use.  The previous tree stored them in a
//! `BTreeMap` keyed on the path string and called them paths, which is why its
//! `bind` had to be careful about `/tmp`; this module keys on the bytes and the
//! ABI names them bytes.
//!
//! The bound on a name is [`NAME_LIMIT`], and it is the ABI's: a name is copied
//! from the caller's memory into kernel memory, so its length is a number a
//! program chose, and a name of a hundred kilobytes is a program asking the
//! kernel to hold a hundred kilobytes.
//!
//! ## The queue, and what a full one means
//!
//! [`Table::connect`] answers [`Error::Busy`] at [`BACKLOG`] waiting
//! connections, which is the same refusal a full datagram queue gives: the
//! listener has not accepted, and this side will not grow its memory to hold
//! what the listener never asked for.  A program that retries is a program
//! that learns.

use alloc::string::String;
use alloc::vec::Vec;

use abi::Error;
use abi::Result;

/// The longest name a listener may bind, in bytes.
///
/// The ABI's bound, restated here because this module refuses a name before the
/// handler does: a name is copied into a [`String`], and a name whose length is
/// the caller's number is a length this crate bounds.  Two hundred and
/// fifty-five bytes is far past any name a program in this tree uses and far
/// below any length worth arguing about.
pub const NAME_LIMIT: usize = 255;

/// How many connections may wait at one listener.
///
/// The same sixteen a pipe's queue and a stream's unacknowledged queue use,
/// for the same reason: the number bounds memory a peer's actions can spend.
/// A connect past it is [`Error::Busy`], and the caller's retry is what turns
/// that into a wait.
pub const BACKLOG: usize = 16;

/// The id of one end of a local connection.
///
/// An id and not a pipe, because the pipe lives in the kernel.  The ids of one
/// connection's two ends are handed back together by [`Table::accept`] and
/// [`Table::connect`], and what the kernel does with them is make one pipe and
/// keep its two ends under these numbers.
pub type EndId = usize;

/// One connection waiting to be accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pending {
    /// The client's end, which the connecting process writes and reads.
    pub client: EndId,
    /// The server's end, which the accepting process reads and writes.
    pub server: EndId,
}

/// A listener: a name and the connections waiting at it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Listener {
    /// The bytes a program bound.  Owned, because a name outlives the call
    /// that created it and the caller's buffer does not.
    name: String,
    /// The connections a `connect` has made and an `accept` has not taken.
    pending: Vec<Pending>,
}

/// The local sockets one machine holds.
///
/// A value, with no lock: the kernel holds it behind its own, the way it holds
/// [`crate::tcp_table::Table`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    listeners: Vec<Listener>,
    /// The next end id to hand out.
    ///
    /// A counter, and never reused: a program that kept a descriptor for an
    /// end whose connection closed has a number no new connection can answer,
    /// which is the distinction between "the end I have" and "an end that
    /// happens to be the same number".
    next_end: EndId,
    /// How many local sockets have been bound and not released, for the boot's
    /// own report.
    bound: usize,
}

impl Table {
    /// An empty table.
    pub const fn new() -> Self {
        Self {
            listeners: Vec::new(),
            next_end: 1,
            bound: 0,
        }
    }

    /// Bind `name`, answering nothing: a listener is named, not numbered, and
    /// the descriptor a program holds is the kernel's.
    ///
    /// An empty name is [`Error::InvalidArgument`] and a name longer than
    /// [`NAME_LIMIT`] is the same, because a name is the one thing a program
    /// chooses that the kernel stores by the caller's length.
    ///
    /// A name another listener holds is [`Error::AlreadyExists`].  Two
    /// listeners on one name would make one `connect` two servers' answer, the
    /// same rule a bound port has and for the same reason.
    pub fn bind(&mut self, name: &[u8]) -> Result<()> {
        if name.is_empty() || name.len() > NAME_LIMIT {
            return Err(Error::InvalidArgument);
        }
        let name = core::str::from_utf8(name).map_err(|_| Error::InvalidArgument)?;
        if self.listeners.iter().any(|entry| entry.name == name) {
            return Err(Error::AlreadyExists);
        }
        self.listeners.push(Listener {
            name: String::from(name),
            pending: Vec::new(),
        });
        self.bound += 1;
        Ok(())
    }

    /// Open a connection to the listener named `name`, answering the two ends.
    ///
    /// The client's end is the caller's to keep; the server's goes in the
    /// listener's queue for [`Table::accept`] to hand to whichever process is
    /// waiting there.  `NotFound` when nothing listens on the name, which is
    /// the error a program's own retry loop is about: a server that has not
    /// bound yet is a fact the client can see.
    ///
    /// The two ends are made here rather than by the kernel for the reason this
    /// module exists: the pairing is arithmetic, and a kernel that made the
    /// pair would be a kernel deciding which end a connection's bytes come out
    /// of.  What the kernel does is attach a pipe's two ends under these ids.
    pub fn connect(&mut self, name: &[u8]) -> Result<(EndId, EndId)> {
        if name.is_empty() || name.len() > NAME_LIMIT {
            return Err(Error::InvalidArgument);
        }
        let name = core::str::from_utf8(name).map_err(|_| Error::InvalidArgument)?;
        // The listener is found by index and its queue touched through that
        // index: a borrow of the found entry would be a borrow of `self` while
        // `take_end` needs it mutably, which is the pattern the stream table
        // already uses for the same reason.
        let index = self
            .listeners
            .iter()
            .position(|entry| entry.name == name)
            .ok_or(Error::NotFound)?;
        if self.listeners[index].pending.len() >= BACKLOG {
            return Err(Error::Busy);
        }
        let client = self.take_end();
        let server = self.take_end();
        self.listeners[index]
            .pending
            .push(Pending { client, server });
        Ok((client, server))
    }

    /// Take the oldest connection waiting at `name`, answering its two ends.
    ///
    /// `Ok(None)` when the listener holds nothing, which is a caller's signal
    /// to park rather than an error: a socket that has not been connected to
    /// yet is the ordinary state of a server that has bound and is waiting.
    /// The two answers are deliberately different, because `NotFound` is a name
    /// that does not exist and this is a name that exists with nothing behind
    /// it.
    pub fn accept(&mut self, name: &[u8]) -> Result<Option<Pending>> {
        if name.is_empty() || name.len() > NAME_LIMIT {
            return Err(Error::InvalidArgument);
        }
        let name = core::str::from_utf8(name).map_err(|_| Error::InvalidArgument)?;
        let index = self
            .listeners
            .iter()
            .position(|entry| entry.name == name)
            .ok_or(Error::NotFound)?;
        if self.listeners[index].pending.is_empty() {
            return Ok(None);
        }
        Ok(Some(self.listeners[index].pending.remove(0)))
    }

    /// Release a name, answering whether anything held it.
    ///
    /// What a process's exit does with the names its descriptors bound.  The
    /// connections already made stay made: a name is a rendezvous, and the
    /// conversation it started does not end because the name did, which is the
    /// same reason closing a listening port does not reset the streams it
    /// opened.
    pub fn release(&mut self, name: &[u8]) -> bool {
        let Ok(name) = core::str::from_utf8(name) else {
            return false;
        };
        let before = self.listeners.len();
        self.listeners.retain(|entry| entry.name != name);
        let released = self.listeners.len() != before;
        if released {
            self.bound = self.bound.saturating_sub(1);
        }
        released
    }

    /// Whether anything listens on `name`.
    pub fn is_bound(&self, name: &[u8]) -> bool {
        core::str::from_utf8(name)
            .is_ok_and(|name| self.listeners.iter().any(|entry| entry.name == name))
    }

    /// How many names are bound, for a boot's own report.
    pub fn bound(&self) -> usize {
        self.bound
    }

    /// How many connections are waiting at `name`, for a boot's own report.
    pub fn waiting(&self, name: &[u8]) -> usize {
        core::str::from_utf8(name)
            .ok()
            .and_then(|name| {
                self.listeners
                    .iter()
                    .find(|entry| entry.name == name)
                    .map(|entry| entry.pending.len())
            })
            .unwrap_or(0)
    }

    /// The next end id.
    fn take_end(&mut self) -> EndId {
        let id = self.next_end;
        self.next_end = self.next_end.wrapping_add(1);
        id
    }
}

impl Default for Table {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::BACKLOG;
    use super::NAME_LIMIT;
    use super::Table;

    /// A bound name is a name something listens on, and nothing else is.
    #[test]
    fn a_bound_name_is_the_one_that_was_bound() {
        let mut table = Table::new();
        assert!(!table.is_bound(b"pyro.sock"));
        table.bind(b"pyro.sock").expect("a name");
        assert!(table.is_bound(b"pyro.sock"));
        assert!(!table.is_bound(b"pyro.other"));
        assert_eq!(table.bound(), 1);
    }

    /// Two listeners cannot share one name, and the refusal is `AlreadyExists`.
    ///
    /// The rule a bound port has: two servers on one name would make one
    /// connect two servers' answer, and the client could not tell which it
    /// reached.
    #[test]
    fn a_second_bind_of_one_name_is_refused() {
        let mut table = Table::new();
        table.bind(b"pyro.sock").expect("the first");
        assert_eq!(table.bind(b"pyro.sock"), Err(abi::Error::AlreadyExists));
        assert_eq!(table.bound(), 1, "the refusal added nothing");
    }

    /// An empty name and one past the limit are refused.
    ///
    /// The name is the caller's length, which is why the bound is here: a name
    /// is copied into kernel memory, and a length a program chose is a length
    /// the kernel bounds.
    #[test]
    fn a_name_of_no_bytes_or_too_many_is_refused() {
        let mut table = Table::new();
        assert_eq!(table.bind(b""), Err(abi::Error::InvalidArgument));
        let too_long = [b'x'; NAME_LIMIT + 1];
        assert_eq!(table.bind(&too_long), Err(abi::Error::InvalidArgument));
        let longest = [b'x'; NAME_LIMIT];
        assert_eq!(table.bind(&longest), Ok(()), "the limit itself is allowed");
        // And a name that is not UTF-8 at all, which no program's text is.
        assert_eq!(table.bind(&[0xFF, 0xFE]), Err(abi::Error::InvalidArgument));
    }

    /// A connect to a name nothing bound is `NotFound`, which is different from
    /// a listener with nothing waiting.
    ///
    /// The two answers are why `connect` returns an error where `accept`
    /// returns `Ok(None)`: a server that has not bound yet is a fact the client
    /// can act on by retrying, and a server that has bound and not been
    /// connected to is a fact the server's accept waits on.
    #[test]
    fn a_connect_before_a_bind_is_not_a_connect_to_nothing_waiting() {
        let mut table = Table::new();
        assert_eq!(table.connect(b"pyro.sock"), Err(abi::Error::NotFound));
        table.bind(b"pyro.sock").expect("a name");
        assert_eq!(table.accept(b"pyro.sock"), Ok(None));
        assert_eq!(table.accept(b"pyro.other"), Err(abi::Error::NotFound));
    }

    /// A connection made is a connection waiting, and accept takes it once.
    ///
    /// The two ends are distinct and are the pair the connect answered, which
    /// is the property the kernel's pipe attachment depends on: a table that
    /// answered the same id twice would attach one pipe end under two numbers.
    #[test]
    fn a_connection_waits_and_is_accepted_once() {
        let mut table = Table::new();
        table.bind(b"pyro.sock").expect("a name");
        let (client, server) = table.connect(b"pyro.sock").expect("a connection");
        assert_ne!(client, server, "the two ends are two numbers");
        assert_eq!(table.waiting(b"pyro.sock"), 1);

        let pending = table
            .accept(b"pyro.sock")
            .expect("a listener")
            .expect("a connection");
        assert_eq!(pending.client, client, "the same pair, not a new one");
        assert_eq!(pending.server, server);
        assert_eq!(table.waiting(b"pyro.sock"), 0, "and taken, not copied");
        assert_eq!(table.accept(b"pyro.sock"), Ok(None));
    }

    /// Connections wait in the order they were made.
    ///
    /// Accept is a queue and not a set: a server that accepted the newest
    /// connection first would answer two clients in an order neither chose,
    /// and a test that only checked "one connection came out" would not
    /// notice.
    #[test]
    fn connections_are_accepted_in_the_order_they_were_made() {
        let mut table = Table::new();
        table.bind(b"pyro.sock").expect("a name");
        let first = table.connect(b"pyro.sock").expect("the first");
        let second = table.connect(b"pyro.sock").expect("the second");
        let third = table.connect(b"pyro.sock").expect("the third");

        assert_eq!(table.accept(b"pyro.sock").unwrap().unwrap().client, first.0);
        assert_eq!(
            table.accept(b"pyro.sock").unwrap().unwrap().client,
            second.0
        );
        assert_eq!(table.accept(b"pyro.sock").unwrap().unwrap().client, third.0);
    }

    /// A full backlog is `Busy` and the connection is not made.
    ///
    /// The bound exists so a server that stopped accepting cannot be made to
    /// hold connections by a client that keeps connecting.  The refusal is
    /// `Busy` and not `NotFound`: the name exists, it is holding all it will
    /// hold.
    #[test]
    fn a_full_backlog_refuses_and_does_not_queue() {
        let mut table = Table::new();
        table.bind(b"pyro.sock").expect("a name");
        for _ in 0..BACKLOG {
            table.connect(b"pyro.sock").expect("room");
        }
        assert_eq!(table.connect(b"pyro.sock"), Err(abi::Error::Busy));
        assert_eq!(table.waiting(b"pyro.sock"), BACKLOG, "nothing was added");

        // And accepting one makes room for exactly one more, not two.
        table.accept(b"pyro.sock").expect("a listener");
        table.connect(b"pyro.sock").expect("one place was freed");
        assert_eq!(
            table.connect(b"pyro.sock"),
            Err(abi::Error::Busy),
            "and only one"
        );
    }

    /// A released name is free, and releasing it twice is not a second release.
    ///
    /// What a process exit does.  The second release answering `false` is what
    /// stops a boot's count falling twice for one name.
    #[test]
    fn a_released_name_is_free_again() {
        let mut table = Table::new();
        table.bind(b"pyro.sock").expect("a name");
        assert!(table.release(b"pyro.sock"));
        assert!(!table.is_bound(b"pyro.sock"));
        assert_eq!(table.bound(), 0);
        assert!(
            !table.release(b"pyro.sock"),
            "the second release is nothing"
        );
        assert_eq!(table.bound(), 0, "and the count did not fall past zero");
        table.bind(b"pyro.sock").expect("the name is free again");
    }

    /// Two names are two listeners, and a connect reaches the one it named.
    ///
    /// The property a table keyed on the name gives and a single slot would
    /// not: two servers on one machine, each with its own queue.
    #[test]
    fn two_names_are_two_listeners() {
        let mut table = Table::new();
        table.bind(b"alpha").expect("alpha");
        table.bind(b"beta").expect("beta");
        let to_alpha = table.connect(b"alpha").expect("alpha");
        assert_eq!(table.waiting(b"alpha"), 1);
        assert_eq!(table.waiting(b"beta"), 0, "the other queue is untouched");
        assert_eq!(table.accept(b"beta"), Ok(None));
        assert_eq!(table.accept(b"alpha").unwrap().unwrap().client, to_alpha.0);
    }
}
