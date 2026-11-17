//! kernel/src/local.rs
//!
//! The machine's local-domain sockets: the names a process binds, the pipes
//! behind each connection, and the halves a descriptor holds.
//!
//! ## The split with `net`
//!
//! [`net::local::Table`] is the naming and the queue: which names are bound,
//! which connections wait at them, and what a full backlog answers.  It is
//! arithmetic over values and it is a host test.  What it cannot do is make a
//! pipe, because a pipe parks a reader and parking is the scheduler's act.
//!
//! So this file keeps the half that needs the kernel: two pipes per
//! connection and the four ends they are seen through.  The ids the table
//! hands back name entries in `CONNECTIONS`, and a descriptor holds the two
//! ends of one of them.
//!
//! ## Why two pipes and not one
//!
//! A connection is **two directions** and a pipe is one.  One pipe per
//! connection, the client handed its write end and the server its read end, is
//! a local socket a client cannot read an answer from, which is half of what a
//! socket is for.  Two pipes cost one more buffer per connection and make the
//! connection a connection.
//!
//! The four ends are counted by the pipes themselves, so a client that exits
//! drops its two handles, and a server reading sees end-of-file on the pipe
//! whose only writer went, which is the contract a pipe already keeps and the
//! reason none of that is restated here.
//!
//! ## What a name holds
//!
//! A name is bound by a process and released when the last descriptor that
//! bound it goes, which is a process exit's release in `syscall::table`.  The
//! connections already made outlive the name: a name is a rendezvous and the
//! conversation it started is not the name's.

use alloc::sync::Arc;
use alloc::vec::Vec;

use abi::Error;
use abi::Result;

use crate::pipe;

/// One connection waiting to be accepted: the two pipes behind it.
///
/// The client's side and the server's side share two pipes: one carries what
/// the client writes to the server, and one carries the answer back.  Held
/// here until an accept makes the server's halves, which is why they are the
/// pipes and not the ends: the ends are counted handles, and a `Connection`
/// holding a third handle on each pipe would keep the pipe open after both
/// processes' descriptors went.
struct Connection {
    /// The server's two halves, made when the connection was.
    ///
    /// Made at **connect** and not at accept, because a pipe's counts are its
    /// handles: a pipe with no reader handle answers a write with zero, which
    /// is the rule that stops bytes going nowhere, and a connection whose
    /// reader was not made until an accept would drop everything the client
    /// wrote before the server got round to accepting.  Both ends of a pipe
    /// exist when the pipe does, and this is the same rule.
    server: Halves,
}

/// The two halves of one end, as a descriptor holds them.
///
/// Cloned out of the connection when a descriptor is made, so the descriptor's
/// own drop is what closes the end: a clone of a pipe `End` is another handle
/// on the same pipe, and the pipe's counts see it.
#[derive(Clone)]
pub struct Halves {
    /// The end a read takes bytes from.
    pub reader: pipe::End,
    /// The end a write puts bytes into.
    pub writer: pipe::End,
}

/// The bound names and the connections waiting at them, one value.
///
/// A single lock, for the reason the stream table has one: a connect and an
/// accept are one exchange and both reach the same table, and two locks would
/// be two orders to get wrong.
struct Registry {
    names: net::local::Table,
    /// Connections made and not accepted, keyed by the id the table gave the
    /// server's end.  An accepted connection leaves this and its halves go to
    /// a descriptor.  The client's halves are not kept here: `connect` answers
    /// them and its descriptor takes them at once, so a table entry would be a
    /// second owner of two ends nobody would read.
    waiting: Vec<(usize, Connection)>,
}

static REGISTRY: sync::Mutex<Option<Registry>> = sync::Mutex::new(None);

/// Run `body` with the registry, installing an empty one the first time.
///
/// `sync::Mutex`'s `new` is const and `Option` is `None` here, so the table is
/// built on the first call rather than by the boot: a machine whose programs
/// never open a local socket pays for none of it.
fn with_registry<T>(body: impl FnOnce(&mut Registry) -> T) -> T {
    let mut guard = REGISTRY.lock();
    let registry = guard.get_or_insert_with(|| Registry {
        names: net::local::Table::new(),
        waiting: Vec::new(),
    });
    body(registry)
}

/// Bind `name`, answering nothing: the name is the program's, not a number.
///
/// The refusal is the table's: `AlreadyExists` for a name another listener
/// holds, `InvalidArgument` for a name no program should have chosen.
pub fn bind(name: &[u8]) -> Result<()> {
    with_registry(|registry| registry.names.bind(name))
}

/// Connect to `name`, answering the two halves of the client's end.
///
/// The server's end goes in the table's queue and this file's `waiting` list,
/// where an accept takes it.  A name nothing bound is `NotFound`, which is the
/// error a client's own retry loop is about.
pub fn connect(name: &[u8]) -> Result<Halves> {
    with_registry(|registry| {
        let (_client, server_id) = registry.names.connect(name)?;
        let client_writes = Arc::new(pipe::Pipe::new(crate::local::PIPE_CAPACITY));
        let server_writes = Arc::new(pipe::Pipe::new(crate::local::PIPE_CAPACITY));
        // The client's two halves and the server's, all four made here: two
        // handles per pipe, one for each side, which is what makes the counts
        // mean "a process holds this end" from the moment the connection
        // exists.
        let halves = Halves {
            reader: pipe::End::reader(Arc::clone(&server_writes)),
            writer: pipe::End::writer(Arc::clone(&client_writes)),
        };
        let server = Halves {
            reader: pipe::End::reader(Arc::clone(&client_writes)),
            writer: pipe::End::writer(Arc::clone(&server_writes)),
        };
        let connection = Connection { server };
        registry.waiting.push((server_id, connection));
        Ok(halves)
    })
}

/// Take the oldest connection waiting at `name`, answering the server's two
/// halves.
///
/// `Ok(None)` is a listener with nothing waiting, the caller's signal to park:
/// a server that has bound and is waiting is the ordinary state, and an error
/// would make it indistinguishable from a name that does not exist.
pub fn accept(name: &[u8]) -> Result<Option<Halves>> {
    with_registry(|registry| {
        let Some(pending) = registry.names.accept(name)? else {
            return Ok(None);
        };
        let Some(index) = registry
            .waiting
            .iter()
            .position(|(id, _)| *id == pending.server)
        else {
            // The table handed back an id this file never made, which would be
            // the two halves of the state disagreeing.  Answering `Ok(None)`
            // here would park a server on a connection that cannot exist.
            return Err(Error::InternalError);
        };
        let (_, connection) = registry.waiting.remove(index);
        Ok(Some(connection.server))
    })
}

/// How many connections are waiting at a name.
///
/// The non-destructive half of [`accept`]: `Poll` asks whether an accept would
/// take something, and a check that removed the connection it found would be
/// the accept, not the question about it.
pub fn waiting(name: &[u8]) -> usize {
    with_registry(|registry| registry.names.waiting(name))
}

/// Release a name, answering whether anything held it.
///
/// What a process's exit does with the names its descriptors bound, and the
/// connections already made are untouched: a rendezvous that has done its job
/// may go.
pub fn release(name: &[u8]) -> bool {
    with_registry(|registry| registry.names.release(name))
}

/// Whether anything listens on `name`.
pub fn is_bound(name: &[u8]) -> bool {
    with_registry(|registry| registry.names.is_bound(name))
}

/// How many names are bound, for a boot's own report.
pub fn bound() -> usize {
    with_registry(|registry| registry.names.bound())
}

/// The buffer one direction of a local connection holds, in bytes.
///
/// The boot's pipe's capacity, because a local connection is a pair of pipes
/// and a second number would be a second thing to explain.  A program that
/// fills it is a program whose peer has not read, which is the same answer a
/// pipe gives.
pub const PIPE_CAPACITY: usize = ipc::DEFAULT_PIPE_CAPACITY;

/// Prove that a name is a rendezvous two halves of one process can meet at.
///
/// The exchange is the whole of it: this boot binds a name, connects to it,
/// accepts, and moves bytes both ways through the two pipes.  What a
/// ring-3 program proves is the same exchange between **two** processes, and
/// that is the line the gate requires; this one runs before any program exists
/// and is what makes a failure attributable to the mechanism rather than to
/// the program.
///
/// The bytes are a constant both directions and unequal, so a stack that
/// wired one pipe to both ends would echo the wrong way and be visible in the
/// count.
#[cfg(target_os = "none")]
pub fn probe() -> bool {
    const NAME: &[u8] = b"protofire.local.probe";
    const FORWARD: &[u8] = b"local";
    const BACKWARD: &[u8] = b"answer";

    if bind(NAME).is_err() {
        return false;
    }
    let client = match connect(NAME) {
        Ok(halves) => halves,
        Err(_) => return false,
    };
    let server = match accept(NAME) {
        Ok(Some(halves)) => halves,
        _ => return false,
    };

    // The client writes, the server reads.  The count is the length, and the
    // bytes are compared, because a pipe that carried the wrong direction's
    // bytes would still answer a count.
    let written = match client.writer.try_write(client.writer.pipe(), FORWARD) {
        Ok(pipe::Progress::Done(count)) => count,
        _ => return false,
    };
    let mut buffer = [0_u8; 16];
    let forward = match server.reader.try_read(server.reader.pipe(), &mut buffer) {
        Ok(pipe::Progress::Done(count)) => count,
        _ => return false,
    };
    let forward_ok = forward == FORWARD.len() && &buffer[..forward] == FORWARD;

    // And back, which is the half one pipe could not carry.
    let backwards = match server.writer.try_write(server.writer.pipe(), BACKWARD) {
        Ok(pipe::Progress::Done(count)) => count,
        _ => return false,
    };
    let mut reply = [0_u8; 16];
    let backward = match client.reader.try_read(client.reader.pipe(), &mut reply) {
        Ok(pipe::Progress::Done(count)) => count,
        _ => return false,
    };
    let backward_ok = backward == BACKWARD.len() && &reply[..backward] == BACKWARD;

    let released = release(NAME);
    let correct = written == FORWARD.len()
        && forward_ok
        && backwards == BACKWARD.len()
        && backward_ok
        && released;
    arch::serial::write_str("protofire: local socket ");
    arch::serial::write_u32(forward as u32);
    arch::serial::write_str(" byte(s) forward, ");
    arch::serial::write_u32(backward as u32);
    arch::serial::write_str(if correct {
        " back, both ways through one name\n"
    } else {
        " back, MISMATCH\n"
    });
    correct
}
