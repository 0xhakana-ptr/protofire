//! kernel/src/syscall/table/mod.rs
//!
//! The registry: a number in, a handler out, and the one descriptor table
//! the handlers and the pipes both work through.
//!
//! Every number the ABI defines has a slot.  A number this kernel does not
//! serve answers [`Error::NotImplemented`] rather than being absent: an absent
//! slot would have to be a panic or a silent zero, and both report a lie.
//! "This kernel does not serve that number" is a fact the caller can act on.
//!
//! A supervisor call arrives from a trap with no context to be handed anything,
//! so the table it needs has to be reachable without one.  The static is
//! written once by the boot, before any call can arrive, and read by every call
//! after.

use alloc::sync::Arc;
use alloc::vec::Vec;

use crate::pipe;
use security::mac;

use abi::Error;
use abi::Result;
use abi::fs as fs_abi;
use fs::ExtentKind;
use fs::MountTable;
use fs::VNode;
use syscall::SyscallContext;
use syscall::SyscallDispatch;
use syscall::SyscallNumber;

/// The highest number the table has room for.
pub(crate) const MAX_SYSCALLS: usize = syscall::PUBLIC_SYSCALL_COUNT as usize;

/// The most descriptors one boot's table holds.
///
/// A fixed number rather than a growable vector: the table is indexed by a
/// number a caller supplies, and one that could grow with the caller's requests
/// is one a caller can grow without bound.
pub const MAX_DESCRIPTORS: usize = 64;

/// The longest path a handler accepts.
///
/// A path is compared against a table of names, and a length no filesystem
/// accepts is a length the comparison never needs.  The bound is checked rather
/// than trusted because the path's size is the one argument a caller chooses.
pub const PATH_MAX: usize = 4096;

/// The offset value that means "where the descriptor is now".
///
/// A value no real offset uses, rather than a second syscall: a caller that has
/// been reading asks for the next bytes, and one that wants a position names
/// it.  `pread` and `read` are one handler because the difference is one
/// argument.
pub const READ_OFFSET_CURRENT: usize = usize::MAX;

/// The arguments of one call, after the address-shaped ones have been borrowed.
///
/// The registry's handlers take this rather than a bare [`SyscallContext`], and
/// the borrow is how the module keeps [`SyscallContext`]'s "an argument is a
/// word" rule while never turning a word into a pointer itself.
pub struct Arguments<'a> {
    pub context: &'a mut SyscallContext,
    /// The path `open` was given, when this is an `open`.
    pub path: Option<&'a str>,
    /// The second path of a call that names two, `rename`'s destination.
    ///
    /// A separate slot rather than a pair packed into [`Self::path`], because
    /// a call with one path and a call with two differ in more than arity:
    /// the reserved arguments sit in different slots, and a handler that
    /// reached into a list for its second path would be one that could not
    /// say from its signature whether it had one.
    pub second_path: Option<&'a str>,
    /// The buffer `read` was given, when this is a `read`.
    pub buffer: Option<&'a mut [u8]>,
}

impl<'a> Arguments<'a> {
    /// The arguments of a call that names no address.
    pub fn plain(context: &'a mut SyscallContext) -> Self {
        Self {
            context,
            path: None,
            second_path: None,
            buffer: None,
        }
    }
}

/// A handler that also needs the table it was reached through.
pub type KernelHandler = fn(&mut SyscallTable, &mut Arguments<'_>) -> Result<Dispatch>;

/// What a handler answered.
pub type Dispatch = SyscallDispatch;

/// What a slot in the registry does.
#[derive(Clone, Copy)]
pub enum Handler {
    /// A function that serves this number.
    Served(KernelHandler),
    /// A number the ABI defines and this build does not serve.
    Unimplemented,
}

/// What a descriptor number names.
///
/// One table, one numbering: a pipe end and an open file are both "a thing a
/// descriptor holds", and two tables numbering from zero would make a file's
/// descriptor 0 and a pipe's descriptor 0 the same word meaning two things
/// which is exactly the ambiguity a caller cannot be asked to resolve.  A
/// descriptor is a descriptor, and this is the one table that numbers them.
pub(crate) enum Descriptor {
    /// An open node and the rights it was opened with.
    File {
        node: Arc<dyn VNode>,
        readable: bool,
        /// Whether the open asked to write.
        ///
        /// Recorded per descriptor, like `readable`: the right is the open's,
        /// not the node's, a node the filesystem would accept bytes for is
        /// still not writable *through a descriptor* that opened it for
        /// reading, which is the reading least privilege needs.
        writable: bool,
        /// The offset the next `read` starts at.
        ///
        /// Per descriptor rather than per node: two descriptors on one file are
        /// two positions, which is what a program that seeks one of them
        /// expects.
        offset: u64,
        /// The path the open resolved to, normalized.
        ///
        /// The `*At` calls' anchor: a relative path resolves against the
        /// directory the descriptor was opened from, and that directory is
        /// where the open happened, not a name the node carries, a node
        /// knows its own last component and nothing of the namespace above
        /// it, which is the namespace a relative path is relative *to*.
        path: alloc::string::String,
        /// The process that opened it, so its exit can release it.
        owner: u32,
    },
    /// One end of a pipe.  Dropping it closes that end, which is what turns a
    /// reader's "no bytes yet" into end-of-file when the last writer goes.
    Pipe {
        end: pipe::End,
        /// The process that holds it, so its exit can close it.
        owner: u32,
    },
    /// A bound datagram socket.  The socket lives behind an `Arc`, so a fork's
    /// copy shares the one bound port and queue the way two descriptors on
    /// one file share the node, and the port stops being routable when the
    /// last descriptor goes, which is what the port table's `Weak` reads.
    UdpSocket {
        socket: Arc<crate::net::UdpSocket>,
        /// The process that holds it, so its exit can close it.
        owner: u32,
    },
    /// A listening port, the thing an accept is called on.  The id is the
    /// kernel's own table's, which is why a fork's copy accepts from the
    /// same listener: the id is not the holder's, it is the port's.
    TcpListener {
        listener: usize,
        /// The process that holds it, so its exit can release it.
        owner: u32,
    },
    /// One end of a stream, readable and writable through the same `Read`
    /// and `Write` a file and a pipe are.  The id names the connection in
    /// the kernel's table; a stream whose close finished answers a read
    /// with end of file, which is what makes a reader's loop end.
    TcpStream {
        stream: usize,
        /// The process that holds it, so its exit can release it.
        owner: u32,
    },
    /// One end of a local-domain connection: the two pipe halves a program
    /// reads and writes through.
    ///
    /// Two halves and not one pipe, because a connection is two directions.
    /// The halves are the pipes' own counted handles, so the descriptor's drop
    /// is what closes the end, and a peer's read sees end-of-file when the
    /// last descriptor naming the other side goes, which is a contract this
    /// variant inherits rather than restates.
    Local {
        halves: crate::local::Halves,
        /// The process that holds it, so its exit can release it.
        owner: u32,
    },
    /// A DCCP port a connection is to be made from.
    ///
    /// The bound end of a connection, which is what `DccpBind` answers: a
    /// connection has two ports, and the call that names only the peer's would
    /// leave this machine with nothing to answer on.
    DccpBound {
        port: u16,
        /// The process that holds it, so its exit can release it.
        owner: u32,
    },
    /// A DCCP listening port, the thing an accept is called on.
    DccpListener {
        port: u16,
        /// The listener's id in the kernel's own table.
        listener: usize,
        /// The process that holds it, so its exit can release it.
        owner: u32,
    },
    /// One end of a DCCP connection: the id names it in the kernel's table.
    DccpConnection {
        connection: usize,
        /// The process that holds it, so its exit can close it.
        owner: u32,
    },
    /// A raw socket: one IP protocol number's packets, queued for its reader.
    ///
    /// Shares the `Arc` with the table in `crate::net`, so a fork's copy reads
    /// the same queue the way two descriptors on one datagram socket share a
    /// port.  The socket stops being routable when the last descriptor goes,
    /// which is what the table's `Weak` reads.
    Raw {
        socket: Arc<crate::net::RawSocket>,
        /// The process that holds it, so its exit can release it.
        owner: u32,
    },
    /// A bound name, the thing an accept is called on.
    ///
    /// A listener holds no pipe: the connection's pipes are made by the
    /// connect that arrives, and a listener's own two ends would be handles on
    /// a pipe nothing carries bytes through.  The name is held because its
    /// owner's exit is what releases it, and a name whose listener died
    /// without that release could not be bound again until the boot ended.
    LocalListener {
        name: alloc::string::String,
        /// The process that holds it, so its exit can release the name.
        owner: u32,
    },
}

/// A descriptor copied into another process, with that process as its owner.
///
/// `fork`'s inheritance, written by hand rather than derived because the two
/// variants copy in two different ways, and one of them is not a plain copy.
/// A file descriptor is a node and an offset, both of which copy freely.  A
/// pipe **end** raises the pipe's count as it copies, which is what makes the
/// count mean "live handles" rather than "the two the pipe was made with": a
/// parent and a child holding the same write end are two handles, and
/// end-of-file arrives only after both have gone.
///
/// The clone is of the **handle**, not of the descriptor number: the child gets
/// its own slot, and closing one process's end leaves the other's alone.
impl Descriptor {
    fn for_owner(&self, owner: u32) -> Descriptor {
        match self {
            Descriptor::File {
                node,
                readable,
                writable,
                offset,
                path,
                ..
            } => Descriptor::File {
                node: Arc::clone(node),
                readable: *readable,
                writable: *writable,
                // The offset is copied, not shared.  A shared file position
                // would move both processes' next read, which is what one open
                // file description means; this tree reads through explicit
                // offsets and no boot program shares a file across a fork, so
                // nothing observes the difference yet.
                offset: *offset,
                // The anchor moves with the handle: the child resolving a
                // relative path against the descriptor it inherited anchors
                // where the parent's open did.
                path: path.clone(),
                owner,
            },
            Descriptor::Pipe { end, .. } => Descriptor::Pipe {
                end: end.clone(),
                owner,
            },
            Descriptor::UdpSocket { socket, .. } => Descriptor::UdpSocket {
                socket: Arc::clone(socket),
                owner,
            },
            // A listener's and a stream's ids are the table's, not the
            // holder's: a copy names the same port or the same stream, which
            // is what makes two processes' halves of one exchange meet.
            Descriptor::TcpListener { listener, .. } => Descriptor::TcpListener {
                listener: *listener,
                owner,
            },
            Descriptor::TcpStream { stream, .. } => Descriptor::TcpStream {
                stream: *stream,
                owner,
            },
            // A local end copies as two **halves**, and each half's clone is a
            // new handle on its pipe, which is what makes a forked child's
            // copy keep the connection open until both processes are done.
            Descriptor::Local { halves, .. } => Descriptor::Local {
                halves: halves.clone(),
                owner,
            },
            Descriptor::Raw { socket, .. } => Descriptor::Raw {
                socket: Arc::clone(socket),
                owner,
            },
            // A DCCP handle is a number the kernel's table owns, so the copy is
            // the number: two descriptors naming one connection is what a fork
            // means, and the connection answers both.
            Descriptor::DccpBound { port, .. } => Descriptor::DccpBound { port: *port, owner },
            Descriptor::DccpListener { port, listener, .. } => Descriptor::DccpListener {
                port: *port,
                listener: *listener,
                owner,
            },
            Descriptor::DccpConnection { connection, .. } => Descriptor::DccpConnection {
                connection: *connection,
                owner,
            },
            Descriptor::LocalListener { name, .. } => Descriptor::LocalListener {
                name: name.clone(),
                owner,
            },
        }
    }
}

/// The registry, and the descriptor table the handlers use.
pub struct SyscallTable {
    slots: [Handler; MAX_SYSCALLS],
    descriptors: [Option<Descriptor>; MAX_DESCRIPTORS],
    namespace: Option<Arc<MountTable>>,
}

impl SyscallTable {
    /// An empty table: every number answers [`Handler::Unimplemented`].
    pub fn new() -> Self {
        Self {
            slots: [Handler::Unimplemented; MAX_SYSCALLS],
            descriptors: [const { None }; MAX_DESCRIPTORS],
            namespace: None,
        }
    }

    /// Install the namespace `open` resolves paths against.
    ///
    /// A namespace rather than a volume: a path names a mount, the mount names
    /// a filesystem, and the handler never learns which one it reached.  A
    /// table that held a single volume would have made `/tmp/x` a path the
    /// filesystem was asked about directly, which is the arrangement this
    /// replaced.
    pub fn set_namespace(&mut self, namespace: Arc<MountTable>) {
        self.namespace = Some(namespace);
    }

    pub fn register(&mut self, number: SyscallNumber, handler: KernelHandler) {
        self.slots[number as usize] = Handler::Served(handler);
    }

    /// Serve a call.
    ///
    /// A number past the table's end is refused rather than indexed: the table
    /// is sized from the ABI count, so this cannot happen for a variant that
    /// exists, but a caller's number is a word off a wire, and indexing with
    /// it would be the one place this module trusted it.
    pub fn dispatch(&mut self, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
        let Some(slot) = self.slots.get(arguments.context.number).copied() else {
            return Err(Error::InvalidArgument);
        };

        match slot {
            Handler::Served(handler) => handler(self, arguments),
            Handler::Unimplemented => Err(Error::NotImplemented),
        }
    }

    /// The process that holds a descriptor, if one does.
    pub(crate) fn owner_of(&self, descriptor: usize) -> Option<u32> {
        match self.descriptors.get(descriptor)? {
            Some(Descriptor::File { owner, .. })
            | Some(Descriptor::Pipe { owner, .. })
            | Some(Descriptor::UdpSocket { owner, .. })
            | Some(Descriptor::TcpListener { owner, .. })
            | Some(Descriptor::TcpStream { owner, .. })
            | Some(Descriptor::Local { owner, .. })
            | Some(Descriptor::LocalListener { owner, .. })
            | Some(Descriptor::Raw { owner, .. })
            | Some(Descriptor::DccpBound { owner, .. })
            | Some(Descriptor::DccpListener { owner, .. })
            | Some(Descriptor::DccpConnection { owner, .. }) => Some(*owner),
            None => None,
        }
    }

    /// Whether `caller` may use `descriptor`, or the error to answer with.
    ///
    /// A descriptor belongs to the process that opened it, so another process
    /// naming it is naming something that is not its own.  The answer is
    /// `InvalidArgument` rather than `PermissionDenied`: the number is not a
    /// **descriptor** to this caller at all, and the difference matters, a
    /// caller told "denied" learns that the slot exists and can probe for
    /// which numbers are in use.
    ///
    /// A caller with no pid is the kernel's own, which is allowed: the boot
    /// reads a file through the table before any program exists.
    fn check_owner(&self, descriptor: usize, caller: Option<u32>) -> Result<()> {
        let Some(caller) = caller else {
            return Ok(());
        };
        match self.owner_of(descriptor) {
            Some(owner) if owner == caller => Ok(()),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Close a descriptor, returning its slot to the table.
    ///
    /// Refused for a descriptor another process opened: a `Close` a program did
    /// not own would end a reader's wait in a process it never touched, which
    /// is the same cross-process reach a bad pointer would give it.
    pub fn close_for(&mut self, descriptor: usize, caller: Option<u32>) -> Result<()> {
        self.check_owner(descriptor, caller)?;
        let slot = self
            .descriptors
            .get_mut(descriptor)
            .ok_or(Error::InvalidArgument)?;
        slot.take().map(|_| ()).ok_or(Error::InvalidArgument)
    }

    /// Close a descriptor with no ownership check.
    ///
    /// The kernel's own release paths, which already know whose slot they are
    /// taking: `release_owned` walks by owner and the pipe's error path closes
    /// a descriptor it just made.
    pub fn close(&mut self, descriptor: usize) -> Result<()> {
        self.close_for(descriptor, None)
    }

    /// The number of descriptors in use, for a boot line that reports it.
    pub fn open_descriptors(&self) -> usize {
        self.descriptors
            .iter()
            .filter(|slot| slot.is_some())
            .count()
    }

    /// How many numbers this table serves.
    ///
    /// The rest answer [`Handler::Unimplemented`], which is a fact a caller can
    /// act on, so the count is what a boot line reports and what a test
    /// compares against.
    pub fn served(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| matches!(slot, Handler::Served(_)))
            .count()
    }

    pub(crate) fn namespace(&self) -> Option<&Arc<MountTable>> {
        self.namespace.as_ref()
    }

    /// The path a `*At` call's argument names, given the descriptor it is
    /// relative to.
    ///
    /// Three readings, in the order they are decided: an absolute path is
    /// anchored at the root and the descriptor is bypassed, a caller that
    /// named `/x` from where it was meant `/x`; the `AT_FDCWD` sentinel asks
    /// for the caller's own base, and this tree has no per-process current
    /// directory yet, so the base is `/`, the one base every process shares;
    /// anything else resolves against the directory the descriptor was
    /// opened from, which is what makes the descriptor the anchor.
    ///
    /// A descriptor that names no file of this caller's, a pipe end, or a
    /// file that is not a directory is refused before the path is looked
    /// at: a non-directory is not a place a relative path can be relative
    /// from, and the answer is the same one for every reason it cannot be.
    pub(crate) fn resolve_at(
        &self,
        dirfd: usize,
        path: &str,
        caller: Option<u32>,
    ) -> Result<alloc::string::String> {
        if dirfd == fs_abi::AT_FDCWD {
            return fs::path::normalize_path(path, "/");
        }
        self.check_owner(dirfd, caller)?;
        let descriptor = self
            .descriptors
            .get(dirfd)
            .ok_or(Error::InvalidArgument)?
            .as_ref()
            .ok_or(Error::InvalidArgument)?;
        let Descriptor::File {
            node, path: base, ..
        } = descriptor
        else {
            return Err(Error::InvalidArgument);
        };
        if node.kind() != fs::types::NodeKind::Directory {
            return Err(Error::InvalidArgument);
        }
        fs::path::normalize_path(path, base)
    }

    /// The path a descriptor was opened at.
    ///
    /// The descriptor's own anchor, which is what the calls that name a
    /// descriptor **instead of** a path need: `StatFd` and `ReadDirFd` ask
    /// about the file the descriptor holds, and the only thing this table must
    /// say to answer them is which name that descriptor resolved to.
    ///
    /// A descriptor that names no file of this caller's, or a pipe end, socket
    /// or stream, is refused: none of those has a path in the namespace, so
    /// none of them is something a stat or a listing could describe.  The
    /// refusal is the same word for every reason, which is the reading
    /// [`Self::resolve_at`] keeps and for the same reason.
    ///
    /// Answers an owned copy rather than a borrow because the call that asked
    /// is about to need the table mutably, and the path is a `String` the
    /// descriptor already owns.
    pub(crate) fn path_of(
        &self,
        descriptor: usize,
        caller: Option<u32>,
    ) -> Result<alloc::string::String> {
        self.check_owner(descriptor, caller)?;
        let descriptor = self
            .descriptors
            .get(descriptor)
            .ok_or(Error::InvalidArgument)?
            .as_ref()
            .ok_or(Error::InvalidArgument)?;
        match descriptor {
            Descriptor::File { path, .. } => Ok(path.clone()),
            _ => Err(Error::InvalidArgument),
        }
    }

    /// Put one descriptor in a free slot and answer its index.
    pub(crate) fn insert(&mut self, descriptor: Descriptor) -> Result<usize> {
        for (index, slot) in self.descriptors.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(descriptor);
                return Ok(index);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Register one end of a pipe and answer its descriptor.
    ///
    /// The same table, the same first-free-slot rule, one numbering: a pipe
    /// end a caller holds by descriptor 3 and a file a caller holds by
    /// descriptor 3 cannot both exist, which is the whole property two tables
    /// could not give.
    pub(crate) fn insert_pipe(&mut self, end: pipe::End, owner: u32) -> Result<usize> {
        self.insert(Descriptor::Pipe { end, owner })
    }

    /// Register a bound datagram socket and answer its descriptor.
    ///
    /// The same table, the same first-free-slot rule, one numbering: a
    /// socket a caller holds by descriptor 3 and a file a caller holds by
    /// descriptor 3 cannot both exist, which is the property that makes a
    /// descriptor a descriptor.
    pub(crate) fn insert_udp_socket(
        &mut self,
        socket: Arc<crate::net::UdpSocket>,
        owner: u32,
    ) -> Result<usize> {
        self.insert(Descriptor::UdpSocket { socket, owner })
    }

    /// Register a listening port and answer its descriptor.
    ///
    /// The same table, the same first-free-slot rule: a listener a caller
    /// holds by descriptor 3 and a file a caller holds by descriptor 3
    /// cannot both exist.
    pub(crate) fn insert_tcp_listener(&mut self, listener: usize, owner: u32) -> Result<usize> {
        self.insert(Descriptor::TcpListener { listener, owner })
    }

    /// Register one end of a stream and answer its descriptor.
    pub(crate) fn insert_tcp_stream(&mut self, stream: usize, owner: u32) -> Result<usize> {
        self.insert(Descriptor::TcpStream { stream, owner })
    }

    /// Register one end of a local connection and answer its descriptor.
    pub(crate) fn insert_local(
        &mut self,
        halves: crate::local::Halves,
        owner: u32,
    ) -> Result<usize> {
        self.insert(Descriptor::Local { halves, owner })
    }

    /// Register a raw socket and answer its descriptor.
    pub(crate) fn insert_raw(
        &mut self,
        socket: Arc<crate::net::RawSocket>,
        owner: u32,
    ) -> Result<usize> {
        self.insert(Descriptor::Raw { socket, owner })
    }

    /// Insert a bound DCCP port, answering its descriptor.
    pub(crate) fn insert_dccp_bound(&mut self, port: u16, owner: u32) -> Result<usize> {
        self.insert(Descriptor::DccpBound { port, owner })
    }

    /// Insert a DCCP listening port, answering its descriptor.
    pub(crate) fn insert_dccp_listener(
        &mut self,
        port: u16,
        listener: usize,
        owner: u32,
    ) -> Result<usize> {
        self.insert(Descriptor::DccpListener {
            port,
            listener,
            owner,
        })
    }

    /// Insert one end of a DCCP connection, answering its descriptor.
    pub(crate) fn insert_dccp_connection(
        &mut self,
        connection: usize,
        owner: u32,
    ) -> Result<usize> {
        self.insert(Descriptor::DccpConnection { connection, owner })
    }

    /// The port a bound DCCP descriptor names.
    pub(crate) fn dccp_bound_port(&self, descriptor: usize, caller: Option<u32>) -> Option<u16> {
        self.check_owner(descriptor, caller).ok()?;
        match self.descriptors.get(descriptor)? {
            Some(Descriptor::DccpBound { port, .. }) => Some(*port),
            _ => None,
        }
    }

    /// The port a DCCP listener descriptor names.
    pub(crate) fn dccp_listener_port(&self, descriptor: usize, caller: Option<u32>) -> Option<u16> {
        self.check_owner(descriptor, caller).ok()?;
        match self.descriptors.get(descriptor)? {
            Some(Descriptor::DccpListener { port, .. }) => Some(*port),
            _ => None,
        }
    }

    /// The connection id a DCCP connection descriptor names.
    pub(crate) fn dccp_connection(&self, descriptor: usize, caller: Option<u32>) -> Option<usize> {
        self.check_owner(descriptor, caller).ok()?;
        match self.descriptors.get(descriptor)? {
            Some(Descriptor::DccpConnection { connection, .. }) => Some(*connection),
            _ => None,
        }
    }

    /// The raw socket a descriptor names, cloned, if it names one and the
    /// caller owns it.
    pub(crate) fn raw_socket(
        &self,
        descriptor: usize,
        caller: Option<u32>,
    ) -> Option<Arc<crate::net::RawSocket>> {
        self.check_owner(descriptor, caller).ok()?;
        match self.descriptors.get(descriptor)? {
            Some(Descriptor::Raw { socket, .. }) => Some(Arc::clone(socket)),
            _ => None,
        }
    }

    /// Register a bound name and answer the descriptor an accept is called on.
    pub(crate) fn insert_local_listener(
        &mut self,
        name: alloc::string::String,
        owner: u32,
    ) -> Result<usize> {
        self.insert(Descriptor::LocalListener { name, owner })
    }

    /// The halves of the local end a descriptor names, cloned.
    ///
    /// A clone, for the same reason [`Self::pipe_end`] is one: a borrow held
    /// across a read or a write would hold the registry's lock for a call that
    /// may park.  Each cloned half raises its pipe's handle count, so the pipe
    /// stays alive while the caller works and its own drop takes the count
    /// back.
    pub(crate) fn local_halves(
        &self,
        descriptor: usize,
        caller: Option<u32>,
    ) -> Option<crate::local::Halves> {
        self.check_owner(descriptor, caller).ok()?;
        match self.descriptors.get(descriptor)? {
            Some(Descriptor::Local { halves, .. }) => Some(halves.clone()),
            _ => None,
        }
    }

    /// The name a listener's descriptor carries, for the accept called on it
    /// and for the release its exit performs.
    pub(crate) fn local_name(
        &self,
        descriptor: usize,
        caller: Option<u32>,
    ) -> Option<alloc::string::String> {
        self.check_owner(descriptor, caller).ok()?;
        match self.descriptors.get(descriptor)? {
            Some(Descriptor::LocalListener { name, .. }) => Some(name.clone()),
            _ => None,
        }
    }

    /// Every name the process `owner` holds a listener for, for its exit's
    /// release.
    pub(crate) fn local_names_of(&self, owner: u32) -> alloc::vec::Vec<alloc::string::String> {
        self.descriptors
            .iter()
            .filter_map(|slot| match slot {
                Some(Descriptor::LocalListener { name, owner: held }) if *held == owner => {
                    Some(name.clone())
                }
                _ => None,
            })
            .collect()
    }

    /// The pipe end a descriptor names, cloned, if it names one.
    ///
    /// A clone, because the table owns its entries and a caller that borrowed
    /// one would hold the registry's lock across a call that may block.  The
    /// `Arc` inside is what makes the clone cheap and what keeps the pipe
    /// alive while the caller works.
    pub(crate) fn pipe_end(&self, descriptor: usize, caller: Option<u32>) -> Option<pipe::End> {
        self.check_owner(descriptor, caller).ok()?;
        match self.descriptors.get(descriptor)? {
            Some(Descriptor::Pipe { end, .. }) => Some(end.clone()),
            _ => None,
        }
    }

    /// The datagram socket a descriptor names, cloned, if it names one and
    /// the caller owns it.
    ///
    /// A clone, for the same reason [`Self::pipe_end`] is: the table owns its
    /// entries, and a caller that borrowed one would hold the registry's
    /// lock across a call that may block.  The `Arc` inside is what makes the
    /// clone cheap and what keeps the socket's port routable while the
    /// caller works.
    pub(crate) fn udp_socket(
        &self,
        descriptor: usize,
        caller: Option<u32>,
    ) -> Option<Arc<crate::net::UdpSocket>> {
        self.check_owner(descriptor, caller).ok()?;
        match self.descriptors.get(descriptor)? {
            Some(Descriptor::UdpSocket { socket, .. }) => Some(Arc::clone(socket)),
            _ => None,
        }
    }

    /// The listener a descriptor names, if it names one and the caller owns
    /// it.
    pub(crate) fn tcp_listener(&self, descriptor: usize, caller: Option<u32>) -> Option<usize> {
        self.check_owner(descriptor, caller).ok()?;
        match self.descriptors.get(descriptor)? {
            Some(Descriptor::TcpListener { listener, .. }) => Some(*listener),
            _ => None,
        }
    }

    /// The stream a descriptor names, if it names one and the caller owns
    /// it.
    pub(crate) fn tcp_stream(&self, descriptor: usize, caller: Option<u32>) -> Option<usize> {
        self.check_owner(descriptor, caller).ok()?;
        match self.descriptors.get(descriptor)? {
            Some(Descriptor::TcpStream { stream, .. }) => Some(*stream),
            _ => None,
        }
    }

    /// Copy every descriptor `parent` holds to `child`, answering how many.
    ///
    /// `fork`'s inheritance: a child starts with its parent's open
    /// descriptors, owned by the child, so closing or reading them is the
    /// child's own business and the parent's slots are untouched.  A pipe's
    /// count rises with each end copied, because the child holds a handle the
    /// pipe must wait for.
    ///
    /// Answers the count so the boot can report it; `0` for a parent with
    /// nothing open.
    pub(crate) fn inherit(&mut self, parent: u32, child: u32) -> usize {
        // Collected first: `insert` borrows the array mutably while the
        // sources are read from it.
        let mut inherited = alloc::vec::Vec::new();
        for slot in &self.descriptors {
            if let Some(descriptor) = slot
                && let Descriptor::File { owner, .. }
                | Descriptor::Pipe { owner, .. }
                | Descriptor::UdpSocket { owner, .. }
                | Descriptor::TcpListener { owner, .. }
                | Descriptor::TcpStream { owner, .. }
                | Descriptor::Local { owner, .. }
                | Descriptor::LocalListener { owner, .. }
                | Descriptor::Raw { owner, .. }
                | Descriptor::DccpBound { owner, .. }
                | Descriptor::DccpListener { owner, .. }
                | Descriptor::DccpConnection { owner, .. } = descriptor
                && *owner == parent
            {
                inherited.push(descriptor.for_owner(child));
            }
        }
        let mut copied = 0;
        for descriptor in inherited {
            if self.insert(descriptor).is_ok() {
                copied += 1;
            } else {
                // The table is full.  What was copied stays and the count says
                // how much: a `fork` that half-succeeded is a state a program
                // can observe, and it is better reported than hidden.
                break;
            }
        }
        copied
    }

    /// Release everything `owner` still holds, answering how many were closed.
    ///
    /// The exit path's release.  A process that exits without closing what it
    /// opened would otherwise leave its ends in the table for ever: a pipe's
    /// write end would keep a reader waiting for a writer that had ceased to
    /// exist, and the slot would be unreachable, a descriptor number a program
    /// could name only after it had gone.
    ///
    /// Dropping a `Descriptor` is the whole close: a pipe `End`'s drop moves
    /// the pipe's count, which is what turns a reader's "no bytes yet" into
    /// end-of-file.  So this is the same release a `Close` makes, done for
    /// every slot the process owned.
    ///
    /// Answers the count rather than nothing so the caller can report it: a
    /// boot line saying how many a process's exit released is what makes the
    /// release observable rather than assumed.
    pub(crate) fn release_owned(&mut self, owner: u32) -> usize {
        // Every name this process was listening on, taken before the slots go:
        // the name is `crate::local`'s state and not the table's, and a
        // listener's descriptor dropped without it would hold a name nothing
        // could bind again.  Collected first because the release reads the
        // slot while the loop below takes it.
        let names = self.local_names_of(owner);
        let mut released = 0;
        for slot in &mut self.descriptors {
            let owned = match slot {
                Some(Descriptor::File { owner: held, .. })
                | Some(Descriptor::Pipe { owner: held, .. })
                | Some(Descriptor::UdpSocket { owner: held, .. })
                | Some(Descriptor::TcpListener { owner: held, .. })
                | Some(Descriptor::TcpStream { owner: held, .. })
                | Some(Descriptor::Local { owner: held, .. })
                | Some(Descriptor::LocalListener { owner: held, .. })
                | Some(Descriptor::Raw { owner: held, .. })
                | Some(Descriptor::DccpBound { owner: held, .. })
                | Some(Descriptor::DccpListener { owner: held, .. })
                | Some(Descriptor::DccpConnection { owner: held, .. }) => *held == owner,
                None => false,
            };
            if owned {
                slot.take();
                released += 1;
            }
        }
        for name in names {
            crate::local::release(name.as_bytes());
        }
        released
    }

    /// Read from a descriptor, at `offset` or at its own position.
    pub(crate) fn read_at(
        &mut self,
        descriptor_index: usize,
        offset_arg: usize,
        buffer: &mut [u8],
        caller: Option<u32>,
    ) -> Result<usize> {
        self.check_owner(descriptor_index, caller)?;
        let descriptor = self
            .descriptors
            .get_mut(descriptor_index)
            .ok_or(Error::InvalidArgument)?
            .as_mut()
            .ok_or(Error::InvalidArgument)?;

        // A pipe is read through the pipe path, whose blocking semantics are
        // the pipe's: a read that may park the caller is not this handler's
        // shape.  A descriptor that names a pipe end answers "wrong kind"
        // rather than pretending to be a file.
        let Descriptor::File {
            node,
            readable,
            offset,
            ..
        } = descriptor
        else {
            return Err(Error::InvalidArgument);
        };

        if !*readable {
            return Err(Error::PermissionDenied);
        }

        let at_current = offset_arg == READ_OFFSET_CURRENT;
        let start = if at_current {
            *offset
        } else {
            offset_arg as u64
        };

        let count = node.read(start, buffer)?;
        // An explicit offset is a peek, not a step: the descriptor's own
        // position moves only when the caller asked to read from it.  A
        // position that moved on every probe would make "read a header, then
        // continue from where I was" impossible to express.
        if at_current {
            *offset = start + count as u64;
        }
        Ok(count)
    }

    /// Write to a descriptor, at its own position.
    ///
    /// The mirror of [`Self::read_at`] without the explicit-offset form: a
    /// write starts where the descriptor is and moves it by the bytes
    /// accepted, which is what makes "append by writing again" one call.  The
    /// checks run in the order a write that cannot be attempted should fail
    /// in, owner, then kind, then the right, so a refusal answers before
    /// the node sees a byte.
    ///
    /// A zero-length write to a descriptor the caller may write is a success
    /// of zero rather than an error: nothing was asked for, so nothing failed.
    pub(crate) fn write_at(
        &mut self,
        descriptor_index: usize,
        buffer: &[u8],
        caller: Option<u32>,
    ) -> Result<usize> {
        self.check_owner(descriptor_index, caller)?;
        let descriptor = self
            .descriptors
            .get_mut(descriptor_index)
            .ok_or(Error::InvalidArgument)?
            .as_mut()
            .ok_or(Error::InvalidArgument)?;

        // A pipe end is written through the pipe path, whose blocking
        // semantics are the pipe's; the ring-3 branch that serves it answers
        // before the registry is reached.  A write that arrives here naming
        // one is a write to the wrong kind of thing, and "wrong kind" is the
        // answer, not a silent fall-through to the node.
        let Descriptor::File {
            node,
            writable,
            offset,
            ..
        } = descriptor
        else {
            return Err(Error::InvalidArgument);
        };

        if !*writable {
            return Err(Error::PermissionDenied);
        }

        if buffer.is_empty() {
            return Ok(0);
        }

        let count = node.write(*offset, buffer)?;
        *offset += count as u64;
        Ok(count)
    }

    /// Shorten or extend the file a descriptor names.
    ///
    /// The checks are [`Self::write_at`]'s, in the same order and for the same
    /// reason: a truncate is a mutation of the file's bytes, so it takes the
    /// same right, and a descriptor opened for reading answers
    /// `PermissionDenied` rather than letting the node's own `set_len` decide.
    ///
    /// The descriptor's offset does **not** move.  A truncate is not a seek:
    /// POSIX leaves the position where it was, and moving it would make "write
    /// a header, truncate the tail, append" a sequence whose third call
    /// overwrites the header.  A position past the new end is legal and reads
    /// as end of file, which is a fact a caller can observe and act on.
    ///
    /// A node that refuses is the node's answer: `tmpfs` and PyroFS both
    /// implement this, the synthetic volumes refuse with the same
    /// `PermissionDenied` their `write` answers, and a directory refuses
    /// because a directory has no length to set.
    pub(crate) fn set_len_at(
        &mut self,
        descriptor_index: usize,
        length: u64,
        caller: Option<u32>,
    ) -> Result<()> {
        self.check_owner(descriptor_index, caller)?;
        let descriptor = self
            .descriptors
            .get_mut(descriptor_index)
            .ok_or(Error::InvalidArgument)?
            .as_mut()
            .ok_or(Error::InvalidArgument)?;

        let Descriptor::File { node, writable, .. } = descriptor else {
            return Err(Error::InvalidArgument);
        };

        if !*writable {
            return Err(Error::PermissionDenied);
        }

        node.set_len(length)
    }

    /// Move a descriptor's position, and answer where it now is.
    ///
    /// Five readings of the offset, and the two families differ in more than
    /// their arithmetic:
    ///
    /// `SEEK_SET`, `SEEK_CUR` and `SEEK_END` are a **distance** from a base,
    /// so the offset is signed and a result below zero is refused rather than
    /// wrapped.  The arithmetic goes through `i128` so that neither a base
    /// near `u64::MAX` nor an offset near `i64::MIN` can overflow the sum; an
    /// offset that does not fit is `InvalidArgument`, which is a word the
    /// caller can act on.
    ///
    /// A position **past the end of the file** is legal and stays.  POSIX
    /// permits it, and this tree's writes already read a position past the end
    /// as end of file; refusing it here would be a rule the read path does not
    /// keep, and a caller seeking to `size + n` to reserve is a caller the
    /// write path serves.
    ///
    /// `SEEK_DATA` and `SEEK_HOLE` are not distances: their offset is
    /// absolute, the answer is the node's, and the position **moves to the
    /// answer**, which is what makes them a seek rather than a query.  An
    /// offset past the end is refused, and a node with nothing to report
    /// answers `NotFound` and leaves the position alone, the way a refused
    /// seek does.  A node that cannot say where its holes are refuses with
    /// `NotImplemented`, which is a different claim from "there are none".
    ///
    /// The right is the reader's: a seek moves where the next read starts and
    /// says nothing about the bytes, so a descriptor opened read-only may seek.
    /// A pipe end and a socket are refused, because neither has a position.
    pub(crate) fn seek_at(
        &mut self,
        descriptor_index: usize,
        offset: i64,
        whence: usize,
        caller: Option<u32>,
    ) -> Result<u64> {
        self.check_owner(descriptor_index, caller)?;
        let descriptor = self
            .descriptors
            .get_mut(descriptor_index)
            .ok_or(Error::InvalidArgument)?
            .as_mut()
            .ok_or(Error::InvalidArgument)?;

        let Descriptor::File {
            node,
            offset: position,
            ..
        } = descriptor
        else {
            return Err(Error::InvalidArgument);
        };

        // The two extent questions first, because their offset is absolute and
        // they answer the node's number rather than a sum.
        let extent = match whence {
            fs_abi::SEEK_DATA => Some(ExtentKind::Data),
            fs_abi::SEEK_HOLE => Some(ExtentKind::Hole),
            _ => None,
        };
        if let Some(kind) = extent {
            let start = u64::try_from(offset).map_err(|_| Error::InvalidArgument)?;
            if start > node.size() as u64 {
                return Err(Error::InvalidArgument);
            }
            let at = node.next_extent(start, kind)?.ok_or(Error::NotFound)?;
            *position = at;
            return Ok(at);
        }

        let base = match whence {
            fs_abi::SEEK_SET => 0_i128,
            fs_abi::SEEK_CUR => *position as i128,
            fs_abi::SEEK_END => node.size() as i128,
            _ => return Err(Error::InvalidArgument),
        };
        let next = base
            .checked_add(offset as i128)
            .ok_or(Error::InvalidArgument)?;
        // One conversion refuses both ends: a sum below zero and a sum above
        // `u64::MAX` are both outside the range a position can hold, so the
        // refusal is `try_from`'s rather than a comparison beside it.  A
        // `next < 0` check before this was written, and no test could tell it
        // was there: deleting it changed nothing, which is what a redundant
        // refusal looks like from the outside.
        let next = u64::try_from(next).map_err(|_| Error::InvalidArgument)?;
        *position = next;
        Ok(next)
    }
}

impl Default for SyscallTable {
    fn default() -> Self {
        Self::new()
    }
}

/// The registry, once the boot has installed one.
///
/// The table was a local in `kernel_main`: the boot built it, served three
/// calls through it, and dropped it.  That is enough to prove the handlers work
/// and not enough to be a kernel, a table that exists only inside one function
/// is a table nothing else can ever reach, and "the syscall interface" would be
/// a claim about a variable.
///
/// A `SyncUnsafeCell` for the same reason the machine's trap sink uses one:
/// there is one table per boot, it is written once, and every later reader is a
/// call that arrived without a context to be handed one.
static REGISTRY: sync::Mutex<Option<SyscallTable>> = sync::Mutex::new(None);

/// Install the registry the boot built.
///
/// Called once.  A second call replaces the table, which is harmless and is not
/// reported: the table is rebuilt from the same boot code, so a second install
/// is a second boot in one address space, which this kernel does not have.
///
/// # Safety
///
/// Called once, after the namespace is set and the handlers are registered.
/// Nothing may serve a call concurrently with this write.
pub unsafe fn install(table: SyscallTable) {
    // SAFETY: the caller promises this is the only write and that no call is in
    // flight.  The write is a whole-table store under the lock, so a reader
    // either sees the old table or the new one and never a half-built one.
    *REGISTRY.lock() = Some(table);
}

/// Serve one call through the installed registry.
///
/// `None` when the boot has not installed one, which is the state before the
/// filesystem is mounted.
///
/// This is the path a trap will use when there is a process to take one from.
/// It exists now so the registry is reachable from outside the function that
/// built it, the thing that was missing, and so the boot can serve a call
/// through the same entry point a later trap will.
pub fn serve(arguments: &mut Arguments<'_>) -> Option<Result<Dispatch>> {
    // The borrow is exclusive for the length of the call, which is what the
    // table's methods require, and the lock is what makes it exclusive across
    // CPUs rather than across one CPU's calls.
    REGISTRY
        .lock()
        .as_mut()
        .map(|table| table.dispatch(arguments))
}

/// Register one end of a stream with the installed registry, answering its
/// descriptor.
///
/// The accept path's way in: the stream the listener handed out becomes a
/// descriptor of the process that accepted it.  `None` when no registry is
/// installed, which is the state before the boot has mounted its namespace.
pub fn attach_local(halves: crate::local::Halves, owner: u32) -> Option<usize> {
    REGISTRY.lock().as_mut()?.insert_local(halves, owner).ok()
}

/// Register one end of a stream and answer its descriptor.
pub fn attach_tcp_stream(stream: usize, owner: u32) -> Option<usize> {
    REGISTRY
        .lock()
        .as_mut()?
        .insert_tcp_stream(stream, owner)
        .ok()
}

/// Register one end of a pipe with the installed registry, answering its
/// descriptor.
///
/// The pipe facade's way in.  `None` when no registry is installed, which is
/// the state before the boot has mounted its namespace.
pub fn attach_pipe(end: pipe::End, owner: u32) -> Option<usize> {
    REGISTRY.lock().as_mut()?.insert_pipe(end, owner).ok()
}

/// Copy every descriptor `parent` holds to `child`, answering how many.
///
/// `None` when no registry is installed, which is the state before the boot
/// mounts its namespace and before any program exists.
pub fn inherit(parent: u32, child: u32) -> Option<usize> {
    REGISTRY
        .lock()
        .as_mut()
        .map(|table| table.inherit(parent, child))
}

/// Release everything `owner` holds in the installed registry, answering how
/// many descriptors went back.
///
/// The exit path's release, and the same one a `Close` makes per call: the
/// slot goes and the descriptor's `Drop` runs, which for a pipe end is the
/// close a blocked reader has been waiting for.  `None` when no registry is
/// installed, which is the state before the boot mounts its namespace.
pub fn release_owned(owner: u32) -> Option<usize> {
    REGISTRY
        .lock()
        .as_mut()
        .map(|table| table.release_owned(owner))
}

/// The DCCP listening port a descriptor names, if it names one and the
/// registry is up.
///
/// The trap path's way in for the accept's re-check: the re-check runs under
/// the scheduler's lock, so it reads a value here rather than a handler, and
/// the value is the port a retry would ask the kernel's table again.
pub fn dccp_listener_port_for(descriptor: usize, caller: Option<u32>) -> Option<u16> {
    REGISTRY
        .lock()
        .as_ref()?
        .dccp_listener_port(descriptor, caller)
}

/// Accept the next DCCP Request at `port`, answering the descriptor it became.
///
/// The accept's whole, for the trap path's re-check and its first ask: the
/// listener is found by port, the connection it answers is pushed into the
/// kernel's table, and the descriptor the caller gets is the one the registry
/// makes.  A port with nothing waiting is `usize::MAX`, which is the park's
/// signal.
pub fn accept_dccp(port: u16, owner: u32) -> abi::Result<usize> {
    let mut registry = REGISTRY.lock();
    let table = registry.as_mut().ok_or(abi::Error::NotFound)?;
    match crate::net::dccp_accept(port)? {
        Some(id) => table.insert_dccp_connection(id, owner),
        None => Ok(usize::MAX),
    }
}

/// The pipe end a descriptor names, if it names one and the registry is up.
pub fn pipe_end(descriptor: usize) -> Option<pipe::End> {
    REGISTRY.lock().as_ref()?.pipe_end(descriptor, None)
}

/// The pipe end a descriptor names, for a caller that must own it.
///
/// The ring-3 way in: a program naming another process's descriptor gets
/// `None`, the same answer as a number that names nothing, so the error a
/// program sees does not tell it which slots exist.
pub fn pipe_end_for(descriptor: usize, caller: u32) -> Option<pipe::End> {
    REGISTRY.lock().as_ref()?.pipe_end(descriptor, Some(caller))
}

pub fn raw_socket_for(
    descriptor: usize,
    caller: Option<u32>,
) -> Option<Arc<crate::net::RawSocket>> {
    REGISTRY.lock().as_ref()?.raw_socket(descriptor, caller)
}

/// The two halves of the local end a descriptor names, for a caller that must
/// own it.
///
/// The ring-3 way in, the same shape [`pipe_end_for`] is.  A local end's read
/// and write are the two halves', and the caller gets both because a
/// connection is two directions: a lookup that answered one would be a socket
/// a program could only use half of.
pub fn local_halves_for(descriptor: usize, caller: Option<u32>) -> Option<crate::local::Halves> {
    REGISTRY.lock().as_ref()?.local_halves(descriptor, caller)
}

/// The name a listener's descriptor names, for the accept called on it.
pub fn local_name_for(descriptor: usize, caller: Option<u32>) -> Option<alloc::string::String> {
    REGISTRY.lock().as_ref()?.local_name(descriptor, caller)
}

/// The datagram socket a descriptor names, for a caller that must own it.
///
/// The ring-3 way in, the same shape [`pipe_end_for`] is: a program naming
/// another process's descriptor gets `None`, the same answer as a number
/// that names nothing.
pub fn udp_socket_for(
    descriptor: usize,
    caller: Option<u32>,
) -> Option<Arc<crate::net::UdpSocket>> {
    REGISTRY.lock().as_ref()?.udp_socket(descriptor, caller)
}

/// The listener a descriptor names, for a caller that must own it.
pub fn tcp_listener_for(descriptor: usize, caller: Option<u32>) -> Option<usize> {
    REGISTRY.lock().as_ref()?.tcp_listener(descriptor, caller)
}

/// The stream a descriptor names, for a caller that must own it.
pub fn tcp_stream_for(descriptor: usize, caller: Option<u32>) -> Option<usize> {
    REGISTRY.lock().as_ref()?.tcp_stream(descriptor, caller)
}

pub fn has_registry() -> bool {
    REGISTRY.lock().is_some()
}

/// Read a whole file from the installed registry's namespace, answering its
/// bytes.
///
/// The exec path's way in: the program names a file it wants to **become**,
/// and the bytes come back for the loader to map.  The MAC policy is asked
/// first, with the boot's own identity, exactly as `open` asks it, an exec
/// is a read of the file plus a jump, and the read half does not get to skip
/// the policy the open half is policed by.
///
/// `max_bytes` is the bound: a file a caller cannot load is one the caller
/// refuses before it allocates, and the error is the caller's to name.
pub fn read_file(path: &str, identity: u32, max_bytes: usize) -> Result<Vec<u8>> {
    let mut guard = REGISTRY.lock();
    let table = guard.as_mut().ok_or(Error::NotFound)?;
    let namespace = table.namespace().ok_or(Error::NotFound)?;

    // The same order the open handler uses: who is asking, before what they
    // asked for is resolved.
    mac::check_file(identity, path, mac::MAC_CLASS_FILE, mac::MAC_PERM_READ, 0)?;

    let node = namespace.lookup(path)?;
    let mut bytes: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 512];
    let mut offset = 0u64;
    loop {
        let count = node.read(offset, &mut chunk)?;
        if count == 0 {
            return Ok(bytes);
        }
        if bytes.len() + count > max_bytes {
            return Err(Error::OutOfMemory);
        }
        bytes.extend_from_slice(&chunk[..count]);
        offset += count as u64;
    }
}

/// How many descriptors the installed table holds open.
pub fn open_descriptors() -> usize {
    REGISTRY
        .lock()
        .as_ref()
        .map_or(0, SyscallTable::open_descriptors)
}

/// How many numbers the installed table serves.
///
/// A served number is one with a handler rather than
/// [`Handler::Unimplemented`], and the count is what makes "the table is
/// installed" a claim with a number beside it.
pub fn served_numbers() -> usize {
    REGISTRY.lock().as_ref().map_or(0, SyscallTable::served)
}
#[cfg(test)]
mod tests;
