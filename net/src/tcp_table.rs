//! net/src/tcp_table.rs
//!
//! The streams a machine holds: an id per end, the listeners that open them,
//! and the four fields a segment is matched on.
//!
//! ## Why this is here and not in the kernel
//!
//! [`Connection`] is one end of a stream and it is pure: give it a segment,
//! get back an event and the segments to send.  What it cannot answer is
//! *which* of the streams a machine holds a segment belongs to, because that
//! is a question about a table rather than about a connection.
//!
//! That table is still protocol state — the four fields a segment is keyed on,
//! the port a listener reserves, the queue a completed handshake waits in, and
//! the two counters that hand out ids and initial sequence numbers — and none
//! of it needs a card, a scheduler or a lock.  So it lives beside the state
//! machine, and the kernel keeps the half that does: whether an address is
//! this machine, which hardware address a frame goes to, and when a parked
//! task wakes.
//!
//! The split is what makes this table testable on a host.  The exchange that
//! runs it — deliver this segment to the peer's own state machine, take what
//! it answers, repeat — is the kernel's, because the peer may be a machine
//! across a wire rather than the same one; but every lookup, every id and
//! every move of the counters is here.
//!
//! ## No lock, and why
//!
//! Nothing here takes one.  A `Table` is a value a caller owns, and how it is
//! shared — one lock, one per CPU, one per connection — is the caller's
//! decision about its own concurrency.  The kernel holds it behind a single
//! `Mutex` for the reason its own header gives: a loopback exchange is
//! re-entrant and a per-connection lock would deadlock on the first
//! full-duplex one.

use alloc::vec::Vec;

use abi::Error;
use abi::Result;

use crate::tcp::Connection;
use crate::tcp::FLAG_ACK;
use crate::tcp::FLAG_SYN;
use crate::tcp::Outgoing;
use crate::tcp::Segment;
use crate::tcp::State;

/// The first ephemeral port a client's end is given.
///
/// The range the wire's own convention reserves for clients.  A counter
/// rather than a search, because the connections a boot makes are a handful
/// and the range is thirty thousand wide.
pub const EPHEMERAL_FIRST: u16 = 49152;

/// The first initial sequence number a stream is given.
///
/// A counter rather than a constant: two connections whose handshakes used
/// the same numbers would be two streams one segment could confuse for the
/// other.  It is not a secret and this stack does not pretend the wire is one
/// that needs it to be.
pub const SEQUENCE_FIRST: u32 = 1000;

/// One end of a stream, keyed by the id a descriptor carries.
struct Entry {
    id: usize,
    connection: Connection,
}

/// One listening port, with the connections its SYNs opened.
struct Listener {
    id: usize,
    port: u16,
    pending: Vec<usize>,
}

/// Every stream this machine holds, and the counters that name them.
///
/// The counters live here rather than in two `static`s because they are the
/// table's own: an id names an entry of *this* table, and a sequence number
/// belongs to a handshake this table started.  Two tables would be two
/// machines, and nothing outside a test makes two.
pub struct Table {
    listeners: Vec<Listener>,
    connections: Vec<Entry>,
    next_id: usize,
    next_sequence: u32,
    next_ephemeral: u16,
}

impl Table {
    /// An empty table.
    pub const fn new() -> Self {
        Self {
            listeners: Vec::new(),
            connections: Vec::new(),
            next_id: 1,
            next_sequence: SEQUENCE_FIRST,
            next_ephemeral: EPHEMERAL_FIRST,
        }
    }

    /// Take the next id, which is nobody else's.
    fn take_id(&mut self) -> usize {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// The next initial sequence number, and the counter's move past it.
    fn take_sequence(&mut self) -> u32 {
        let sequence = self.next_sequence;
        self.next_sequence = self.next_sequence.wrapping_add(1);
        sequence
    }

    /// The next ephemeral port, and the counter's move past it.
    fn take_ephemeral(&mut self) -> u16 {
        let port = self.next_ephemeral;
        self.next_ephemeral = self.next_ephemeral.wrapping_add(1);
        port
    }

    /// Open a listening port, answering the listener's id.
    ///
    /// [`Error::AlreadyExists`] when the port is taken, for the reason a bound
    /// datagram port is: two listeners on one port would make one SYN two
    /// streams.
    pub fn listen(&mut self, port: u16) -> Result<usize> {
        if self.listeners.iter().any(|entry| entry.port == port) {
            return Err(Error::AlreadyExists);
        }
        let id = self.take_id();
        self.listeners.push(Listener {
            id,
            port,
            pending: Vec::new(),
        });
        Ok(id)
    }

    /// The listener a port names, if one is listening on it.
    pub fn listener_for_port(&self, port: u16) -> Option<usize> {
        self.listeners
            .iter()
            .find(|entry| entry.port == port)
            .map(|entry| entry.id)
    }

    /// Whether a listener has a connection waiting to be accepted.
    pub fn has_pending(&self, listener: usize) -> bool {
        self.listeners
            .iter()
            .find(|entry| entry.id == listener)
            .is_some_and(|entry| !entry.pending.is_empty())
    }

    /// Take the connection a listener has been holding, answering its id.
    ///
    /// [`Error::NotFound`] for an id that names no listener, and `Ok(None)`
    /// when the listener holds nothing — which is the caller's signal to
    /// park, the same shape a datagram receive is.
    pub fn accept(&mut self, listener: usize) -> Result<Option<usize>> {
        let Some(entry) = self.listeners.iter_mut().find(|entry| entry.id == listener) else {
            return Err(Error::NotFound);
        };
        Ok(entry.pending.pop())
    }

    /// The id of the connection a segment answers, by its own four fields:
    /// the port it names and the peer it names them for.
    pub fn connection_for(
        &self,
        destination_port: u16,
        source: [u8; 4],
        source_port: u16,
    ) -> Option<usize> {
        self.connections
            .iter()
            .find(|entry| {
                entry.connection.local_port() == destination_port
                    && entry.connection.remote() == (source, source_port)
            })
            .map(|entry| entry.id)
    }

    /// Open a client's end to `remote`, answering its id and the SYN to send.
    ///
    /// The port and the sequence number are taken here rather than passed in,
    /// because they are the table's to give: two callers that named their own
    /// could name the same one.
    pub fn connect(&mut self, remote: ([u8; 4], u16)) -> (usize, Vec<Outgoing>) {
        let local_port = self.take_ephemeral();
        let sequence = self.take_sequence();
        let (connection, outgoing) = Connection::connect(local_port, remote, sequence);
        let id = self.take_id();
        self.connections.push(Entry { id, connection });
        (id, outgoing)
    }

    /// Open a server's end for a SYN that arrived on a listening port,
    /// answering its id and the SYN with ACK to send.
    ///
    /// `None` when nothing listens on the segment's destination port: a SYN
    /// for a port nothing owns is dropped, the way a datagram for an unbound
    /// port is.  Otherwise the connection joins the listener's pending queue,
    /// which is what a parked `accept` wakes for.
    ///
    /// The reply is returned rather than sent: this table has no wire, and a
    /// caller that dropped the SYN with ACK would leave a client retrying a
    /// handshake nothing answered.
    pub fn accept_syn(
        &mut self,
        segment: &Segment,
        remote: ([u8; 4], u16),
    ) -> Option<(usize, Vec<Outgoing>)> {
        // The listener is found first and held by index: the counters and
        // the connection list are this table's too, and a borrow of one
        // field across a call that takes `&mut self` is two borrows of the
        // same table.
        let listener = self
            .listeners
            .iter()
            .position(|entry| entry.port == segment.destination_port)?;
        let sequence = self.take_sequence();
        let (connection, outgoing) =
            Connection::accept_syn(segment.destination_port, remote, sequence, segment.sequence);
        let id = self.take_id();
        self.connections.push(Entry { id, connection });
        self.listeners[listener].pending.push(id);
        Some((id, outgoing))
    }

    /// One end, by the id a descriptor carries.
    pub fn connection(&self, id: usize) -> Option<&Connection> {
        self.connections
            .iter()
            .find(|entry| entry.id == id)
            .map(|entry| &entry.connection)
    }

    /// One end, for a caller that has a move to make on it.
    pub fn connection_mut(&mut self, id: usize) -> Option<&mut Connection> {
        self.connections
            .iter_mut()
            .find(|entry| entry.id == id)
            .map(|entry| &mut entry.connection)
    }

    /// The peer a stream runs to, if the id names one.
    ///
    /// A caller about to put a segment on a wire asks this rather than
    /// reaching into the connection: the wire needs the address and the port,
    /// and nothing else about the end.
    pub fn remote_of(&self, id: usize) -> Option<([u8; 4], u16)> {
        self.connection(id).map(Connection::remote)
    }

    /// The port a stream answers on, if the id names one.
    pub fn local_port_of(&self, id: usize) -> Option<u16> {
        self.connection(id).map(Connection::local_port)
    }

    /// Whether a stream has bytes its reader has not taken.
    pub fn has_data(&self, id: usize) -> bool {
        self.connection(id)
            .is_some_and(|connection| connection.inbox_len() > 0)
    }

    /// Whether the id names nothing, which an orderly close leaves behind.
    ///
    /// A read of an id that is gone answers end of file rather than an error:
    /// the stream reached its close, and a reader parked on its writer is a
    /// reader whose writer said it was done.
    pub fn is_gone(&self, id: usize) -> bool {
        self.connection(id).is_none()
    }

    /// Drop every connection whose close finished: its id is nobody's, and
    /// the descriptors that named it are closed or closing.
    pub fn prune(&mut self) {
        self.connections
            .retain(|entry| entry.connection.state() != State::Closed);
    }

    /// How many ends the table holds, after a prune or before one.
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Whether the table holds no ends at all.
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
    }

    /// How many ports are listening.
    pub fn listeners(&self) -> usize {
        self.listeners.len()
    }

    /// Whether a segment opens a connection rather than joining one.
    ///
    /// A SYN with no ACK is a handshake's first move; anything else is either
    /// an answer or the stream itself.  The test is the flag word's, which is
    /// why it is here and not repeated at each caller.
    pub fn is_opening(segment: &Segment) -> bool {
        segment.flags & FLAG_SYN != 0 && segment.flags & FLAG_ACK == 0
    }
}

impl Default for Table {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::Table;
    use crate::tcp::FLAG_ACK;
    use crate::tcp::FLAG_FIN;
    use crate::tcp::FLAG_SYN;
    use crate::tcp::Outgoing;
    use crate::tcp::Segment;
    use abi::Error;

    const LOCAL: [u8; 4] = [10, 0, 2, 15];
    const PEER: [u8; 4] = [10, 0, 2, 2];

    /// A segment with the fields a test cares about, and nothing else.
    fn segment(flags: u8, sequence: u32, source_port: u16, destination_port: u16) -> Segment {
        Segment {
            source_port,
            destination_port,
            sequence,
            acknowledgement: 0,
            flags,
            window: crate::tcp::WINDOW,
            payload_len: 0,
        }
    }

    /// A table with a listener on `port` and a client connected to it, which
    /// is the state every other test starts from.
    fn connected(port: u16) -> (Table, usize, usize) {
        let mut table = Table::new();
        let listener = table.listen(port).expect("a listener");
        let (client, _) = table.connect((LOCAL, port));
        (table, listener, client)
    }

    /// A port has one owner, and the refusal is the ABI's own word.
    #[test]
    fn a_port_has_one_listener() {
        let mut table = Table::new();
        let first = table.listen(7000).expect("the first listener");
        assert_eq!(table.listen(7000), Err(Error::AlreadyExists));
        assert_eq!(table.listener_for_port(7000), Some(first));
        assert_eq!(table.listeners(), 1);
        // A second port is a second listener with its own id.
        let second = table.listen(7001).expect("a second listener");
        assert_ne!(first, second);
        assert_eq!(table.listeners(), 2);
    }

    /// The two counters start where the wire's convention says and move one
    /// step per use, so two streams never share a number.
    #[test]
    fn the_counters_hand_out_distinct_numbers() {
        let mut table = Table::new();
        let (first, outgoing) = table.connect((LOCAL, 80));
        let first_port = table.local_port_of(first).expect("the first stream's port");
        assert_eq!(first_port, super::EPHEMERAL_FIRST);
        // The SYN carries the sequence the connection was built with.
        assert_eq!(outgoing.len(), 1);
        assert_eq!(outgoing[0].sequence, super::SEQUENCE_FIRST);

        let (second, outgoing) = table.connect((LOCAL, 80));
        let second_port = table
            .local_port_of(second)
            .expect("the second stream's port");
        assert_ne!(first_port, second_port, "two streams, two ports");
        assert_ne!(
            outgoing[0].sequence,
            super::SEQUENCE_FIRST,
            "two handshakes, two sequence numbers"
        );
        assert_ne!(first, second, "two streams, two ids");
    }

    /// The table answers a segment by its four fields, and a segment for a
    /// port or a peer this table does not hold answers nothing.
    #[test]
    fn a_segment_is_matched_by_its_four_fields() {
        let (table, _, client) = connected(7000);
        let port = table.local_port_of(client).expect("the stream's port");
        assert_eq!(
            table.connection_for(port, LOCAL, 7000),
            Some(client),
            "the port and the peer name the one stream"
        );
        assert_eq!(
            table.connection_for(port, PEER, 7000),
            None,
            "a different peer on the same port is not this stream"
        );
        assert_eq!(
            table.connection_for(port.wrapping_add(1), LOCAL, 7000),
            None,
            "a different port is not this stream"
        );
    }

    /// A SYN on a listening port opens a connection the listener can be
    /// asked for; a SYN on a port nothing listens on opens nothing.
    #[test]
    fn a_syn_opens_a_connection_only_on_a_listening_port() {
        let mut table = Table::new();
        let listener = table.listen(7000).expect("a listener");
        assert!(!table.has_pending(listener), "nothing has arrived yet");
        assert_eq!(table.accept(listener), Ok(None), "so nothing is accepted");

        let opening = segment(FLAG_SYN, 4000, 5555, 7000);
        let (accepted, answer) = table
            .accept_syn(&opening, (PEER, 5555))
            .expect("the listener opens it");
        assert_eq!(answer.len(), 1, "the SYN with ACK");
        assert_eq!(answer[0].flags, FLAG_SYN | FLAG_ACK);
        assert!(table.has_pending(listener), "it waits for the accept");
        assert_eq!(
            table.accept(listener),
            Ok(Some(accepted)),
            "and the accept takes it"
        );
        assert_eq!(table.len(), 1);

        let elsewhere = segment(FLAG_SYN, 4000, 5555, 7001);
        assert_eq!(
            table.accept_syn(&elsewhere, (PEER, 5555)),
            None,
            "a SYN for a port nothing owns opens nothing"
        );
        assert_eq!(table.len(), 1, "and adds no connection");
    }

    /// Only a SYN with no ACK opens a connection; an answer does not.
    #[test]
    fn only_a_syn_without_an_ack_is_an_opening() {
        assert!(Table::is_opening(&segment(FLAG_SYN, 0, 1, 2)));
        assert!(!Table::is_opening(&segment(FLAG_SYN | FLAG_ACK, 0, 1, 2)));
        assert!(!Table::is_opening(&segment(FLAG_ACK, 0, 1, 2)));
        assert!(!Table::is_opening(&segment(FLAG_FIN, 0, 1, 2)));
    }

    /// An accept of an id that names no listener is the ABI's `NotFound`,
    /// which is a different answer from a listener with nothing waiting.
    #[test]
    fn an_accept_names_a_listener() {
        let (mut table, listener, _) = connected(7000);
        assert_eq!(table.accept(listener), Ok(None));
        assert_eq!(table.accept(9999), Err(Error::NotFound));
    }

    /// The segments to an end's peer, as that peer reads them: the ports set
    /// from the direction the segment travels.
    fn to_peer(table: &mut Table, from: usize, outgoing: Outgoing) {
        let Some((_address, peer_port)) = table.remote_of(from) else {
            return;
        };
        let Some(own_port) = table.local_port_of(from) else {
            return;
        };
        let segment = Segment {
            source_port: own_port,
            destination_port: peer_port,
            sequence: outgoing.sequence,
            acknowledgement: outgoing.acknowledgement,
            flags: outgoing.flags,
            window: crate::tcp::WINDOW,
            payload_len: outgoing.payload.len(),
        };
        // The peer is the end whose own port is the segment's destination
        // and whose remote is this end: this machine is `LOCAL`, so the
        // segment's source address is, and the source port is this end's.
        let Some(peer) = table.connection_for(peer_port, LOCAL, own_port) else {
            return;
        };
        let (_, replies) = table
            .connection_mut(peer)
            .expect("the peer the table just named")
            .receive(&segment, &outgoing.payload);
        for reply in replies {
            to_peer(table, peer, reply);
        }
    }

    /// The prune drops what closed and keeps what has not, which is what
    /// makes `is_gone` the answer an orderly close leaves.
    #[test]
    fn the_prune_drops_only_what_closed() {
        let (mut table, listener, client) = connected(7000);
        let client_port = table.local_port_of(client).expect("the client's port");
        let opening = segment(FLAG_SYN, super::SEQUENCE_FIRST, client_port, 7000);
        let (accepted, handshake) = table
            .accept_syn(&opening, (LOCAL, client_port))
            .expect("a listener");
        assert!(table.has_pending(listener));

        // The handshake's answer and the acknowledgement it pulls, routed the
        // way the wire would route them.
        for outgoing in handshake.clone() {
            to_peer(&mut table, accepted, outgoing);
        }

        // One side's finish alone leaves the connection in the table: a half
        // close is not a closed connection.
        let finish = table.connection_mut(client).expect("the client").close();
        assert!(!table.is_gone(client), "a half close is not gone");
        table.prune();
        assert!(table.connection(client).is_some(), "so the prune keeps it");

        // The client's finish reaches the peer, which is now finished
        // reading; the peer's own close is the stream's other half.
        for outgoing in finish {
            to_peer(&mut table, client, outgoing);
        }
        let finish = table
            .connection_mut(accepted)
            .expect("the accepted end")
            .close();
        for outgoing in finish {
            to_peer(&mut table, accepted, outgoing);
        }
        table.prune();
        assert!(table.is_gone(client), "the client's close finished");
        assert!(table.is_gone(accepted), "and the accepted end's");
        assert!(table.is_empty());
    }
}
