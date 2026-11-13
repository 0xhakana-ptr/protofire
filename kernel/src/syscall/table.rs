//! kernel/src/syscall/table.rs
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
    /// The second path of a call that names two — `rename`'s destination.
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
/// descriptor 0 and a pipe's descriptor 0 the same word meaning two things —
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
        /// not the node's — a node the filesystem would accept bytes for is
        /// still not writable *through a descriptor* that opened it for
        /// reading, which is the reading least privilege needs.
        writable: bool,
        /// The offset the next `read` starts at.
        ///
        /// Per descriptor rather than per node: two descriptors on one file are
        /// two positions, which is what a program that seeks one of them
        /// expects.
        offset: u64,
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
}

/// A descriptor copied into another process, with that process as its owner.
///
/// `fork`'s inheritance, written by hand rather than derived because the two
/// variants copy in two different ways — and one of them is not a plain copy.
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
                owner,
            },
            Descriptor::Pipe { end, .. } => Descriptor::Pipe {
                end: end.clone(),
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
            Some(Descriptor::File { owner, .. }) | Some(Descriptor::Pipe { owner, .. }) => {
                Some(*owner)
            }
            None => None,
        }
    }

    /// Whether `caller` may use `descriptor`, or the error to answer with.
    ///
    /// A descriptor belongs to the process that opened it, so another process
    /// naming it is naming something that is not its own.  The answer is
    /// `InvalidArgument` rather than `PermissionDenied`: the number is not a
    /// **descriptor** to this caller at all, and the difference matters — a
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
                && let Descriptor::File { owner, .. } | Descriptor::Pipe { owner, .. } = descriptor
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
    /// exist, and the slot would be unreachable — a descriptor number a program
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
        let mut released = 0;
        for slot in &mut self.descriptors {
            let owned = match slot {
                Some(Descriptor::File { owner: held, .. })
                | Some(Descriptor::Pipe { owner: held, .. }) => *held == owner,
                None => false,
            };
            if owned {
                slot.take();
                released += 1;
            }
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
    /// in — owner, then kind, then the right — so a refusal answers before
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
        // answer — not a silent fall-through to the node.
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

pub fn has_registry() -> bool {
    REGISTRY.lock().is_some()
}

/// Read a whole file from the installed registry's namespace, answering its
/// bytes.
///
/// The exec path's way in: the program names a file it wants to **become**,
/// and the bytes come back for the loader to map.  The MAC policy is asked
/// first, with the boot's own identity, exactly as `open` asks it — an exec
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
mod tests {
    //! The tests for this module.
    //!
    //! The syscall registry's tests: the table's dispatch, the descriptor
    //! slots, the validators, and the MAC calls answering through the table
    //! rather than beside it.

    use alloc::sync::Arc;

    use super::super::*;
    use super::MAX_SYSCALLS;
    use abi::Error;
    use abi::Result;
    use abi::fs as fs_abi;
    use fs::MountTable;
    use fs::StaticFileSystem;
    use fs::TmpFsVolume;
    use fs::types::NodeKind;
    use syscall::SyscallContext;
    use syscall::SyscallNumber;

    /// A volume with one file in it, and a table serving the three handlers.
    fn mounted() -> SyscallTable {
        let volume = StaticFileSystem::with_entries(
            "test",
            &[
                ("/", NodeKind::Directory, b""),
                ("/greeting.txt", NodeKind::File, b"hello from a syscall"),
                ("/docs", NodeKind::Directory, b""),
            ],
        );
        let mut table = SyscallTable::new();
        let mut namespace = MountTable::new();
        namespace
            .mount("/", "pyrofs", "boot", Arc::new(volume))
            .expect("mount");
        table.set_namespace(Arc::new(namespace));
        table.register(SyscallNumber::Open, open);
        table.register(SyscallNumber::Read, read);
        table.register(SyscallNumber::Write, write);
        table.register(SyscallNumber::Stat, stat);
        table.register(SyscallNumber::ReadDir, read_dir);
        table.register(SyscallNumber::Close, close);
        table
    }

    /// A table on the tmpfs, the one backend whose nodes accept bytes.
    ///
    /// The static volume above is a synthetic view, and its nodes refuse a
    /// write by construction; the write tests need the filesystem the boot
    /// itself mounts for scratch space, whose `create_file` creates and whose
    /// nodes hold what was written.  A host has no clock installed, so the
    /// timestamps it stamps are zero, which is a timestamp that says "unknown"
    /// and is not part of what these tests read.
    fn writable() -> SyscallTable {
        let volume = TmpFsVolume::new("test-tmpfs", 64 * 1024);
        let mut table = SyscallTable::new();
        let mut namespace = MountTable::new();
        namespace
            .mount("/", "tmpfs", "memory", Arc::new(volume))
            .expect("mount");
        table.set_namespace(Arc::new(namespace));
        table.register(SyscallNumber::Open, open);
        table.register(SyscallNumber::Read, read);
        table.register(SyscallNumber::Write, write);
        table.register(SyscallNumber::Stat, stat);
        table.register(SyscallNumber::CreateDir, create_dir);
        table.register(SyscallNumber::RemovePath, remove_path);
        table.register(SyscallNumber::Rename, rename);
        table.register(SyscallNumber::ReadDir, read_dir);
        table.register(SyscallNumber::Close, close);
        table
    }

    /// Open a path through the registry, as the boot does.
    fn open_path(table: &mut SyscallTable, path: &str, flags: usize) -> Result<usize> {
        let mut context = SyscallContext::new(SyscallNumber::Open as usize, [0, flags, 0, 0, 0, 0]);
        let mut arguments = Arguments {
            context: &mut context,
            path: Some(path),
            second_path: None,
            buffer: None,
        };
        let dispatch = table.dispatch(&mut arguments)?;
        Ok(dispatch.value)
    }

    /// Read through the registry.
    fn read_into(
        table: &mut SyscallTable,
        descriptor: usize,
        offset: usize,
        buffer: &mut [u8],
    ) -> Result<usize> {
        let mut context = SyscallContext::new(
            SyscallNumber::Read as usize,
            [descriptor, offset, 0, 0, 0, 0],
        );
        let mut arguments = Arguments {
            context: &mut context,
            path: None,
            second_path: None,
            buffer: Some(buffer),
        };
        let dispatch = table.dispatch(&mut arguments)?;
        Ok(dispatch.value)
    }

    /// The whole path: open, read, close, and the bytes that came back.
    ///
    /// This is the test the wiring exists for.  Every part of the interface is
    /// on it, the number reaches the table, the context carries the arguments,
    /// the validators run, the filesystem answers, and the value comes back as
    /// a dispatch, and a break in any of them makes the comparison fail.
    #[test]
    fn a_file_is_opened_read_and_closed_through_the_table() {
        let mut table = mounted();
        let descriptor = open_path(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ)
            .expect("open through the registry");

        let mut buffer = [0u8; 20];
        let count = read_into(&mut table, descriptor, READ_OFFSET_CURRENT, &mut buffer)
            .expect("read through the registry");
        assert_eq!(count, 20);
        assert_eq!(&buffer, b"hello from a syscall");

        assert_eq!(table.close(descriptor), Ok(()));
        assert_eq!(table.open_descriptors(), 0);
    }

    /// A second read at the descriptor's own offset continues where the first
    /// stopped, and produces no bytes at end of file.
    ///
    /// The offset is the descriptor's state, not the caller's: a program that
    /// reads twice without seeking expects the second call to continue, and a
    /// handler that restarted at zero would loop forever on a short buffer.
    #[test]
    fn the_descriptor_remembers_its_offset() {
        let mut table = mounted();
        let descriptor =
            open_path(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ).expect("open");

        let mut first = [0u8; 6];
        assert_eq!(
            read_into(&mut table, descriptor, READ_OFFSET_CURRENT, &mut first),
            Ok(6)
        );
        assert_eq!(&first, b"hello ");

        let mut second = [0u8; 20];
        assert_eq!(
            read_into(&mut table, descriptor, READ_OFFSET_CURRENT, &mut second),
            Ok(14)
        );
        assert_eq!(&second[..14], b"from a syscall");

        // Past the end the answer is zero, not an error: a short read at end of
        // file is how a caller learns it is done.
        let mut past_end = [0u8; 4];
        assert_eq!(
            read_into(&mut table, descriptor, READ_OFFSET_CURRENT, &mut past_end),
            Ok(0)
        );
    }

    /// An explicit offset overrides the descriptor's own, and does not move it.
    ///
    /// A caller reading a header at a known position and then continuing from
    /// where it was is the case; the descriptor keeping its position is what
    /// makes it expressible.
    #[test]
    fn an_explicit_offset_does_not_disturb_the_position() {
        let mut table = mounted();
        let descriptor =
            open_path(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ).expect("open");

        let mut probe = [0u8; 5];
        assert_eq!(read_into(&mut table, descriptor, 6, &mut probe), Ok(5));
        assert_eq!(&probe, b"from ");

        let mut from_start = [0u8; 5];
        assert_eq!(
            read_into(&mut table, descriptor, READ_OFFSET_CURRENT, &mut from_start),
            Ok(5)
        );
        assert_eq!(&from_start, b"hello");
    }

    /// Write through the registry, the way `read_into` reads.
    fn write_as(
        table: &mut SyscallTable,
        descriptor: usize,
        bytes: &[u8],
        pid: Option<u32>,
    ) -> Result<usize> {
        let mut context = SyscallContext::new(
            SyscallNumber::Write as usize,
            [descriptor, 0, bytes.len(), 0, 0, 0],
        );
        if let Some(pid) = pid {
            context = context.with_caller(pid);
        }
        // A copy, because the argument takes a mutable borrow and the test's
        // sources are literals; the handler reads what the borrow names
        // either way.
        let mut copy = bytes.to_vec();
        let mut arguments = Arguments {
            context: &mut context,
            path: None,
            second_path: None,
            buffer: Some(&mut copy),
        };
        let dispatch = table.dispatch(&mut arguments)?;
        Ok(dispatch.value)
    }

    /// The loop the write closes: a program creates a file, writes it, and
    /// reads its own bytes back through the same descriptor.
    ///
    /// This is the whole of what `Write` exists for, and every link is on
    /// this path — the create flag reaching the filesystem, the descriptor
    /// recording the right, the write starting at the position and moving it,
    /// and the read continuing where the write stopped.  A break in any of
    /// them fails the comparison.
    #[test]
    fn a_file_is_written_and_read_back_through_the_table() {
        let mut table = writable();
        let flags = fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
        let descriptor = open_path(&mut table, "/note.txt", flags).expect("create and open");

        assert_eq!(
            write_as(&mut table, descriptor, b"written ", None),
            Ok(8),
            "the first write answers the bytes it accepted"
        );
        assert_eq!(
            write_as(&mut table, descriptor, b"by a syscall", None),
            Ok(12),
            "the second write continues where the first stopped"
        );

        // The position moved with each write, so a read from the descriptor's
        // own position starts past what was written — which is how a caller
        // knows the bytes are behind it rather than ahead of it.
        let mut buffer = [0u8; 4];
        assert_eq!(
            read_into(&mut table, descriptor, READ_OFFSET_CURRENT, &mut buffer),
            Ok(0),
            "the position sits at end of file after two writes"
        );

        // And a fresh open reads the whole thing from the start: the bytes
        // are the file's now, not the descriptor's.
        let reader = open_path(&mut table, "/note.txt", fs_abi::OPEN_FLAG_READ).expect("reopen");
        let mut whole = [0u8; 20];
        assert_eq!(
            read_into(&mut table, reader, READ_OFFSET_CURRENT, &mut whole),
            Ok(20)
        );
        assert_eq!(&whole, b"written by a syscall");
    }

    /// A descriptor opened read-only refuses a write, and stays readable.
    ///
    /// The right is the open's, recorded per descriptor: a node the
    /// filesystem would accept bytes for is still not writable through a
    /// descriptor that did not ask.  The answer is `PermissionDenied` —
    /// the descriptor exists and the caller owns it; what it may not do is
    /// write.
    #[test]
    fn a_descriptor_opened_read_only_refuses_a_write() {
        let mut table = writable();
        let creator = open_path(
            &mut table,
            "/note.txt",
            fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE,
        )
        .expect("create");
        assert_eq!(table.close(creator), Ok(()));

        let reader = open_path(&mut table, "/note.txt", fs_abi::OPEN_FLAG_READ).expect("open");
        assert_eq!(
            write_as(&mut table, reader, b"no", None),
            Err(Error::PermissionDenied)
        );

        let mut buffer = [0u8; 4];
        assert_eq!(
            read_into(&mut table, reader, READ_OFFSET_CURRENT, &mut buffer),
            Ok(0),
            "the refusal left the descriptor readable, at an empty file"
        );
    }

    /// A write of another process's descriptor is refused, and writes nothing.
    ///
    /// The same reach a read refuses, one operation over: a write that went
    /// through would put one process's bytes in another's file.
    #[test]
    fn one_process_cannot_write_another_process_descriptor() {
        let mut table = writable();
        let theirs = open_as(
            &mut table,
            "/note.txt",
            fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE,
            8,
        )
        .expect("open");

        assert_eq!(
            write_as(&mut table, theirs, b"intrusion", Some(7)),
            Err(Error::InvalidArgument)
        );
        assert_eq!(
            write_as(&mut table, theirs, b"mine", Some(8)),
            Ok(4),
            "the owner writes"
        );
    }

    /// A pipe end is not a file to write into.
    ///
    /// The pipe's write path is the ring-3 branch that never reaches the
    /// registry; a write that arrives here naming one is naming the wrong
    /// kind of thing, and the answer is that, not a silent fall-through to a
    /// node the descriptor does not have.
    #[test]
    fn a_pipe_end_is_not_a_file_to_write() {
        use crate::pipe;
        use crate::pipe::End;

        let pipe = Arc::new(pipe::Pipe::new(16));
        let mut table = SyscallTable::new();
        table.register(SyscallNumber::Write, write);
        let end = table
            .insert_pipe(End::writer(pipe.clone()), 7)
            .expect("insert");

        assert_eq!(
            write_as(&mut table, end, b"bytes", None),
            Err(Error::InvalidArgument)
        );
    }

    /// Opening with the create flag a path the volume already has opens that
    /// path, and opening one it does not have on a read-only volume refuses
    /// with the volume's own answer.
    ///
    /// The two halves pin the branch: a create of an existing file is the
    /// open that was asked for, and a create the filesystem cannot grant is
    /// `PermissionDenied` — the volume's refusal, not the lookup's miss,
    /// because reporting `NotFound` for a path the caller asked to create
    /// would tell it the wrong thing about why.
    #[test]
    fn a_create_refusal_is_the_volumes_answer_and_a_create_of_an_existing_path_opens_it() {
        let mut table = mounted();
        assert_eq!(
            open_path(&mut table, "/new.txt", fs_abi::OPEN_FLAG_CREATE),
            Err(Error::PermissionDenied),
            "the static volume creates nothing"
        );

        let existing = open_path(
            &mut table,
            "/greeting.txt",
            fs_abi::OPEN_FLAG_READ | fs_abi::OPEN_FLAG_CREATE,
        )
        .expect("a create of an existing path is an open");
        let mut buffer = [0u8; 5];
        assert_eq!(
            read_into(&mut table, existing, READ_OFFSET_CURRENT, &mut buffer),
            Ok(5)
        );
        assert_eq!(&buffer, b"hello");
    }

    /// A number this build does not serve answers `NotImplemented`, and a
    /// number past the table's end is refused rather than indexed.
    ///
    /// The two answers differ on purpose: "the ABI defines this and this build
    /// does not have it" is something a program can act on, and "this is not a
    /// syscall number" is a caller's bug.
    #[test]
    fn an_unserved_number_answers_rather_than_panics() {
        let mut table = SyscallTable::new();
        let mut context = SyscallContext::new(SyscallNumber::GetPid as usize, [0, 0, 0, 0, 0, 0]);
        let mut arguments = Arguments::plain(&mut context);
        assert_eq!(table.dispatch(&mut arguments), Err(Error::NotImplemented));

        let mut context = SyscallContext::new(MAX_SYSCALLS + 5, [0, 0, 0, 0, 0, 0]);
        let mut arguments = Arguments::plain(&mut context);
        assert_eq!(table.dispatch(&mut arguments), Err(Error::InvalidArgument));
    }

    /// An unknown flag is refused, and so is a non-zero reserved argument.
    ///
    /// Both are checked before the path is looked up, so a call that is wrong
    /// in its arguments does not reach the filesystem at all.
    #[test]
    fn open_refuses_an_unknown_flag_and_a_reserved_argument() {
        let mut table = mounted();

        let mut context =
            SyscallContext::new(SyscallNumber::Open as usize, [0, 0b1000, 0, 0, 0, 0]);
        let mut arguments = Arguments {
            context: &mut context,
            path: Some("/greeting.txt"),
            second_path: None,
            buffer: None,
        };
        assert_eq!(table.dispatch(&mut arguments), Err(Error::InvalidArgument));

        let mut context = SyscallContext::new(SyscallNumber::Open as usize, [0, 0, 0, 0, 7, 0]);
        let mut arguments = Arguments {
            context: &mut context,
            path: Some("/greeting.txt"),
            second_path: None,
            buffer: None,
        };
        assert_eq!(table.dispatch(&mut arguments), Err(Error::InvalidArgument));
    }

    /// A path the volume does not have answers `NotFound`.
    #[test]
    fn a_missing_path_answers_not_found() {
        let mut table = mounted();
        assert_eq!(
            open_path(&mut table, "/no-such-file", fs_abi::OPEN_FLAG_READ),
            Err(Error::NotFound)
        );
    }

    /// A read from a descriptor that was closed, or never opened, is refused.
    ///
    /// The slot a closed descriptor had may already belong to another file, and
    /// reading through a stale number would be reading someone else's data.
    #[test]
    fn a_closed_descriptor_cannot_be_read() {
        let mut table = mounted();
        let descriptor =
            open_path(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ).expect("open");
        assert_eq!(table.close(descriptor), Ok(()));

        let mut buffer = [0u8; 4];
        assert_eq!(
            read_into(&mut table, descriptor, READ_OFFSET_CURRENT, &mut buffer),
            Err(Error::InvalidArgument)
        );
        // Closing it a second time is the same refusal.
        assert_eq!(table.close(descriptor), Err(Error::InvalidArgument));
    }

    /// Opening past the table's capacity answers `OutOfMemory` rather than
    /// reusing a slot that belongs to an open file.
    #[test]
    fn the_descriptor_table_is_bounded() {
        let mut table = mounted();
        for _ in 0..MAX_DESCRIPTORS {
            open_path(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ).expect("open");
        }
        assert_eq!(
            open_path(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ),
            Err(Error::OutOfMemory)
        );
        assert_eq!(table.open_descriptors(), MAX_DESCRIPTORS);
    }

    /// An exiting process releases what it opened, and only that.
    ///
    /// A descriptor belongs to the process that opened it: its exit is the
    /// release a `Close` would have made, and a process that exits without
    /// closing leaves nothing behind.  Two owners are opened here because the
    /// second half of the claim is the one a single-owner test cannot make — a
    /// release keyed on the wrong field, or on "any", would pass the first half
    /// and silently take another process's descriptors with it.
    #[test]
    fn an_exiting_process_releases_only_its_own_descriptors() {
        let mut table = mounted();

        let mine = open_as(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ, 7).expect("open");
        let theirs = open_as(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ, 8).expect("open");
        let also_mine =
            open_as(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ, 7).expect("open");
        assert_eq!(table.open_descriptors(), 3);

        assert_eq!(
            table.release_owned(7),
            2,
            "both of that process's went back"
        );
        assert_eq!(table.open_descriptors(), 1, "and only that process's");
        assert_eq!(
            table.release_owned(8),
            1,
            "the other process still held its own"
        );
        assert_eq!(table.open_descriptors(), 0);

        // The released slots are free again, and a release that already
        // happened answers zero rather than counting something twice.
        assert_eq!(table.release_owned(7), 0);
        for descriptor in [mine, also_mine, theirs] {
            assert_eq!(table.close(descriptor), Err(Error::InvalidArgument));
        }
    }

    /// Opening a path as a given process, for the ownership tests.
    fn open_as(table: &mut SyscallTable, path: &str, flags: usize, pid: u32) -> Result<usize> {
        let mut context = SyscallContext::new(SyscallNumber::Open as usize, [0, flags, 0, 0, 0, 0])
            .with_caller(pid);
        let mut arguments = Arguments {
            context: &mut context,
            path: Some(path),
            second_path: None,
            buffer: None,
        };
        Ok(table.dispatch(&mut arguments)?.value)
    }

    /// A process cannot use a descriptor another process opened.
    ///
    /// The whole point of an owner on a descriptor.  A number is a number, so a
    /// process that guessed one would otherwise read another's file or close
    /// its pipe end — a reach into a process it never touched, which is exactly
    /// the power a bad pointer would give it.  The refusal is `InvalidArgument`
    /// and not `PermissionDenied`: a caller told "denied" learns the slot is in
    /// use and can probe for which numbers are.
    #[test]
    fn one_process_cannot_close_another_process_descriptor() {
        let mut table = mounted();
        let mine = open_as(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ, 7).expect("open");
        let theirs = open_as(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ, 8).expect("open");

        assert_eq!(
            table.close_for(theirs, Some(7)),
            Err(Error::InvalidArgument),
            "another process's descriptor is not this process's to close"
        );
        assert_eq!(table.open_descriptors(), 2, "and the refusal left it open");

        assert_eq!(table.close_for(theirs, Some(8)), Ok(()), "its own is");
        assert_eq!(table.close_for(mine, Some(7)), Ok(()));
        assert_eq!(table.open_descriptors(), 0);
    }

    /// A read of another process's descriptor is refused, and leaves it
    /// readable.
    ///
    /// The same reach as the close above, one operation over: a read that went
    /// through would hand one process another's bytes.
    #[test]
    fn one_process_cannot_read_another_process_descriptor() {
        let mut table = mounted();
        let theirs = open_as(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ, 8).expect("open");
        let mut buffer = [0u8; 8];

        assert_eq!(
            table.read_at(theirs, READ_OFFSET_CURRENT, &mut buffer, Some(7)),
            Err(Error::InvalidArgument)
        );
        assert_eq!(buffer, [0u8; 8], "and nothing was read into it");

        let count = table
            .read_at(theirs, READ_OFFSET_CURRENT, &mut buffer, Some(8))
            .expect("the owner reads it");
        assert_eq!(&buffer[..count], b"hello fr");
    }

    /// The kernel's own callers have no pid and are not refused.
    ///
    /// The boot reads a file through the table before any program exists, and a
    /// check keyed only on "the caller matches the owner" would refuse it:
    /// there is no caller.  `None` is that caller, and it is allowed.
    #[test]
    fn a_caller_with_no_pid_is_allowed() {
        let mut table = mounted();
        let descriptor =
            open_as(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ, 7).expect("open");
        let mut buffer = [0u8; 4];

        assert_eq!(
            table
                .read_at(descriptor, READ_OFFSET_CURRENT, &mut buffer, None)
                .expect("the kernel reads"),
            4
        );
        assert_eq!(table.close_for(descriptor, None), Ok(()));
    }

    /// A fork's child starts with its parent's descriptors, as its own.
    ///
    /// The inheritance `fork` promises.  A child that got nothing would find
    /// every inherited number refused, because the table checks the owner; a
    /// child that got the **same slots** rather than copies would close its
    /// parent's file.
    #[test]
    fn a_child_inherits_its_parents_descriptors_as_its_own() {
        let mut table = mounted();
        let parent = open_as(&mut table, "/greeting.txt", fs_abi::OPEN_FLAG_READ, 7).expect("open");

        assert_eq!(table.inherit(7, 8), 1, "one descriptor copied");
        assert_eq!(table.open_descriptors(), 2, "the child's slot is its own");

        let child = (0..MAX_DESCRIPTORS)
            .find(|index| *index != parent && table.owner_of(*index) == Some(8))
            .expect("the child has one");
        let mut buffer = [0u8; 4];
        assert_eq!(
            table
                .read_at(child, READ_OFFSET_CURRENT, &mut buffer, Some(8))
                .expect("the child reads its own"),
            4
        );
        assert_eq!(
            table.read_at(child, READ_OFFSET_CURRENT, &mut buffer, Some(7)),
            Err(Error::InvalidArgument),
            "and the parent cannot use the child's"
        );
    }

    /// A pipe end copied by a fork keeps the pipe alive until **both** are
    /// gone.
    ///
    /// The count is what end-of-file is read from, so an inheritance that
    /// copied the number without raising it would make a parent's close end the
    /// reader's file while the child still held a writer.
    #[test]
    fn a_copied_pipe_end_keeps_the_pipe_open() {
        use crate::pipe;
        use crate::pipe::End;

        let pipe = Arc::new(pipe::Pipe::new(16));
        let mut table = SyscallTable::new();
        // The parent holds a write end directly, in the table.
        let parent_end = table
            .insert_pipe(End::writer(pipe.clone()), 7)
            .expect("insert");
        assert!(pipe.has_writers());

        assert_eq!(table.inherit(7, 8), 1, "the child copied it");
        assert_eq!(table.close_for(parent_end, Some(7)), Ok(()));
        assert!(
            pipe.has_writers(),
            "the child still holds a write end, so the pipe is not closed"
        );
    }

    /// Stat through the registry, and read the record the way a caller does.
    fn stat_path(table: &mut SyscallTable, path: &str) -> Result<(usize, usize)> {
        let mut context = SyscallContext::new(SyscallNumber::Stat as usize, [0, 0, 16, 0, 0, 0]);
        let mut record = [0u8; 16];
        let mut arguments = Arguments {
            context: &mut context,
            path: Some(path),
            second_path: None,
            buffer: Some(&mut record),
        };
        table.dispatch(&mut arguments)?;
        let kind = usize::from_le_bytes(record[..8].try_into().expect("kind bytes"));
        let size = usize::from_le_bytes(record[8..].try_into().expect("size bytes"));
        Ok((kind, size))
    }

    /// A stat of a file answers the kind and the size the volume holds.
    ///
    /// The record is the wire format, so the parse is the caller's own: kind
    /// in the first word, size in the second, little-endian, the layout the
    /// ABI pins.  A handler that answered a different layout would still
    /// answer zero, and the caller's next read would start at a size that
    /// was never the file's.
    #[test]
    fn a_stat_reports_the_kind_and_size_the_volume_holds() {
        let mut table = mounted();
        assert_eq!(
            stat_path(&mut table, "/greeting.txt"),
            Ok((fs_abi::FILE_KIND_FILE, 20))
        );
        assert_eq!(
            stat_path(&mut table, "/docs"),
            Ok((fs_abi::FILE_KIND_DIRECTORY, 0)),
            "a directory is stat'd as one, at size zero"
        );
    }

    /// A stat of a path the namespace does not have answers `NotFound`.
    #[test]
    fn a_stat_of_a_missing_path_answers_not_found() {
        let mut table = mounted();
        assert_eq!(stat_path(&mut table, "/no-such-file"), Err(Error::NotFound));
    }

    /// A record shorter than the stat is refused, not partly written.
    ///
    /// A caller handed eight bytes would otherwise read a size field that
    /// holds the kind's bytes — a number that looks like a size, which is
    /// the kind of wrong answer that survives a program's own checking.
    #[test]
    fn a_record_shorter_than_the_stat_is_refused() {
        let mut table = mounted();
        let mut context = SyscallContext::new(SyscallNumber::Stat as usize, [0, 0, 8, 0, 0, 0]);
        let mut short = [0u8; 8];
        let mut arguments = Arguments {
            context: &mut context,
            path: Some("/greeting.txt"),
            second_path: None,
            buffer: Some(&mut short),
        };
        assert_eq!(table.dispatch(&mut arguments), Err(Error::InvalidArgument));
        assert_eq!(short, [0u8; 8], "and nothing was written into it");
    }

    /// A stat of a file the table's own writes grew answers the grown size.
    ///
    /// The static volume's sizes are fixed at build time, so this is the one
    /// test that can catch a stat reading a cached or declared size where
    /// the file's current one belongs.
    #[test]
    fn a_stat_after_a_write_answers_the_written_size() {
        let mut table = writable();
        let flags = fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
        let descriptor = open_path(&mut table, "/note.txt", flags).expect("create");
        assert_eq!(
            write_as(&mut table, descriptor, b"twelve byte", None),
            Ok(11)
        );
        assert_eq!(table.close(descriptor), Ok(()));

        assert_eq!(
            stat_path(&mut table, "/note.txt"),
            Ok((fs_abi::FILE_KIND_FILE, 11))
        );
    }

    /// A stat whose reserved arguments are not zero is refused.
    #[test]
    fn a_stat_with_reserved_arguments_set_is_refused() {
        let mut table = mounted();
        let mut context = SyscallContext::new(SyscallNumber::Stat as usize, [0, 0, 16, 1, 0, 0]);
        let mut record = [0u8; 16];
        let mut arguments = Arguments {
            context: &mut context,
            path: Some("/greeting.txt"),
            second_path: None,
            buffer: Some(&mut record),
        };
        assert_eq!(table.dispatch(&mut arguments), Err(Error::InvalidArgument));
    }

    /// Create a directory through the registry.
    fn make_dir(table: &mut SyscallTable, path: &str) -> Result<usize> {
        let mut context = SyscallContext::new(SyscallNumber::CreateDir as usize, [0; 6]);
        let mut arguments = Arguments {
            context: &mut context,
            path: Some(path),
            second_path: None,
            buffer: None,
        };
        Ok(table.dispatch(&mut arguments)?.value)
    }

    /// Remove a path through the registry.
    fn remove(table: &mut SyscallTable, path: &str) -> Result<usize> {
        let mut context = SyscallContext::new(SyscallNumber::RemovePath as usize, [0; 6]);
        let mut arguments = Arguments {
            context: &mut context,
            path: Some(path),
            second_path: None,
            buffer: None,
        };
        Ok(table.dispatch(&mut arguments)?.value)
    }

    /// Rename through the registry.
    fn rename_to(table: &mut SyscallTable, old_path: &str, new_path: &str) -> Result<usize> {
        let mut context = SyscallContext::new(SyscallNumber::Rename as usize, [0; 6]);
        let mut arguments = Arguments {
            context: &mut context,
            path: Some(old_path),
            second_path: Some(new_path),
            buffer: None,
        };
        Ok(table.dispatch(&mut arguments)?.value)
    }

    /// A made directory is there, and is a directory.
    ///
    /// The claim is checked with `stat`, not with a second create: a create
    /// that answered zero without making anything would fail the stat, and
    /// a create that made something of the wrong kind would fail the kind.
    #[test]
    fn a_made_directory_is_there_and_is_a_directory() {
        let mut table = writable();
        assert_eq!(make_dir(&mut table, "/notes"), Ok(0));
        assert_eq!(
            stat_path(&mut table, "/notes"),
            Ok((fs_abi::FILE_KIND_DIRECTORY, 0))
        );
        // A second create of the same name is the filesystem's refusal, not
        // a silent success that would have replaced it.
        assert_eq!(make_dir(&mut table, "/notes"), Err(Error::AlreadyExists));
    }

    /// A file is made inside a made directory, and removed by name.
    ///
    /// This is the path mutations composing: the directory exists because a
    /// create made it, the file exists because an open-with-create made it
    /// under that directory, and the remove takes exactly the file and
    /// leaves the directory.
    #[test]
    fn a_file_in_a_made_directory_is_removed_and_the_directory_stays() {
        let mut table = writable();
        assert_eq!(make_dir(&mut table, "/notes"), Ok(0));
        let flags = fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
        let descriptor = open_path(&mut table, "/notes/todo.txt", flags).expect("create");
        assert_eq!(write_as(&mut table, descriptor, b"buy milk", None), Ok(8));
        assert_eq!(table.close(descriptor), Ok(()));

        assert_eq!(remove(&mut table, "/notes/todo.txt"), Ok(0));
        assert_eq!(
            stat_path(&mut table, "/notes/todo.txt"),
            Err(Error::NotFound)
        );
        assert_eq!(
            stat_path(&mut table, "/notes"),
            Ok((fs_abi::FILE_KIND_DIRECTORY, 0)),
            "the removal took the file and left the directory"
        );
        assert_eq!(remove(&mut table, "/notes/todo.txt"), Err(Error::NotFound));
    }

    /// A rename moves the file, its bytes and nothing else.
    ///
    /// Both names are checked, because the failure modes differ: a rename
    /// that lost the bytes would leave an empty file at the new name, and
    /// one that copied rather than moved would leave the old name behind.
    #[test]
    fn a_rename_moves_the_file_and_its_bytes() {
        let mut table = writable();
        let flags = fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
        let descriptor = open_path(&mut table, "/draft.txt", flags).expect("create");
        assert_eq!(write_as(&mut table, descriptor, b"final v2", None), Ok(8));
        assert_eq!(table.close(descriptor), Ok(()));

        assert_eq!(rename_to(&mut table, "/draft.txt", "/sent.txt"), Ok(0));
        assert_eq!(stat_path(&mut table, "/draft.txt"), Err(Error::NotFound));
        assert_eq!(
            stat_path(&mut table, "/sent.txt"),
            Ok((fs_abi::FILE_KIND_FILE, 8))
        );
        let reader = open_path(&mut table, "/sent.txt", fs_abi::OPEN_FLAG_READ).expect("open");
        let mut buffer = [0u8; 8];
        assert_eq!(
            read_into(&mut table, reader, READ_OFFSET_CURRENT, &mut buffer),
            Ok(8)
        );
        assert_eq!(&buffer, b"final v2");
    }

    /// A rename whose two names resolve to different filesystems is
    /// refused, and moves nothing.
    ///
    /// No filesystem sees both names, so the only ways to serve the call
    /// are a copy and a delete — whose crash between the halves is the one
    /// outcome a rename exists to make impossible — or a refusal.  The
    /// refusal is what this tree answers.
    #[test]
    fn a_rename_across_filesystems_is_refused() {
        let volume = TmpFsVolume::new("test-tmpfs", 64 * 1024);
        let mut table = SyscallTable::new();
        let mut namespace = MountTable::new();
        namespace
            .mount(
                "/",
                "pyrofs",
                "boot",
                Arc::new(StaticFileSystem::with_entries(
                    "pyrofs",
                    &[("/greeting.txt", NodeKind::File, b"hello")],
                )),
            )
            .expect("mount");
        namespace
            .mount("/tmp", "tmpfs", "memory", Arc::new(volume))
            .expect("mount");
        table.set_namespace(Arc::new(namespace));
        table.register(SyscallNumber::Rename, rename);

        assert_eq!(
            rename_to(&mut table, "/greeting.txt", "/tmp/greeting.txt"),
            Err(Error::Unsupported)
        );
    }

    /// A rename without a second path is refused before the filesystem is
    /// reached.
    #[test]
    fn a_rename_without_a_second_path_is_refused() {
        let mut table = writable();
        let mut context = SyscallContext::new(SyscallNumber::Rename as usize, [0; 6]);
        let mut arguments = Arguments {
            context: &mut context,
            path: Some("/draft.txt"),
            second_path: None,
            buffer: None,
        };
        assert_eq!(table.dispatch(&mut arguments), Err(Error::InvalidArgument));
    }

    /// List one entry through the registry, parsed the way a caller parses
    /// it: four header words and the name bytes the header points at.
    fn list_entry(
        table: &mut SyscallTable,
        path: &str,
        index: usize,
        buffer: &mut [u8],
    ) -> Result<(usize, usize, usize, usize, alloc::string::String)> {
        let mut context =
            SyscallContext::new(SyscallNumber::ReadDir as usize, [0, index, 0, 0, 0, 0]);
        let mut arguments = Arguments {
            context: &mut context,
            path: Some(path),
            second_path: None,
            buffer: Some(buffer),
        };
        let written = table.dispatch(&mut arguments)?.value;
        let word =
            |at: usize| usize::from_le_bytes(buffer[at..at + 8].try_into().expect("header word"));
        let kind = word(0);
        let size = word(8);
        let name_offset = word(16);
        let name_len = word(24);
        // The answer is the bytes the call wrote — header and name together —
        // which is the number a caller sizes its next buffer from.
        assert_eq!(
            written,
            fs_abi::DIRECTORY_ENTRY_RECORD_SIZE + name_len,
            "the answer is the bytes written"
        );
        let name =
            alloc::string::String::from_utf8_lossy(&buffer[name_offset..name_offset + name_len])
                .into_owned();
        Ok((kind, size, name_offset, name_len, name))
    }

    /// A directory lists its entries by index, and the record carries the
    /// name the header points at.
    ///
    /// The static volume's two root entries are in name order, so the
    /// indexes are known; the entries past the end are the loop's end, and
    /// answering `NotFound` there is what lets a caller's loop be `while
    /// let` rather than a count it had to know in advance.
    #[test]
    fn a_directory_lists_its_entries_in_order_and_stops() {
        let mut table = mounted();
        let mut buffer = [0u8; 64];

        let (kind, size, offset, len, name) =
            list_entry(&mut table, "/", 0, &mut buffer).expect("first entry");
        assert_eq!(kind, fs_abi::FILE_KIND_DIRECTORY);
        assert_eq!(size, 0);
        assert_eq!(offset, fs_abi::DIRECTORY_ENTRY_RECORD_SIZE);
        assert_eq!(len, name.len());
        assert_eq!(name, "docs");

        let (kind, _, _, _, name) = list_entry(&mut table, "/", 1, &mut buffer).expect("second");
        assert_eq!(kind, fs_abi::FILE_KIND_FILE);
        assert_eq!(name, "greeting.txt");

        assert_eq!(
            list_entry(&mut table, "/", 2, &mut buffer),
            Err(Error::NotFound),
            "past the end is the loop's end"
        );
    }

    /// A directory the table's own creates have grown lists what it holds.
    ///
    /// The static volume's listing is fixed at build time, so this is the
    /// test that catches a listing that answered from a snapshot rather
    /// than from the namespace.
    #[test]
    fn a_directory_lists_what_the_table_itself_put_in_it() {
        let mut table = writable();
        assert_eq!(make_dir(&mut table, "/notes"), Ok(0));
        let flags = fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE;
        let descriptor = open_path(&mut table, "/notes/todo.txt", flags).expect("create");
        assert_eq!(table.close(descriptor), Ok(()));

        let mut buffer = [0u8; 64];
        let (kind, size, _, len, name) =
            list_entry(&mut table, "/notes", 0, &mut buffer).expect("the entry");
        assert_eq!(kind, fs_abi::FILE_KIND_FILE);
        assert_eq!(size, 0, "created empty, listed empty");
        assert_eq!(len, 8);
        assert_eq!(name, "todo.txt");

        assert_eq!(
            list_entry(&mut table, "/notes", 1, &mut buffer),
            Err(Error::NotFound)
        );
    }

    /// A listing of a file is refused: a file has no entries to list.
    #[test]
    fn a_listing_of_a_file_is_refused() {
        let mut table = mounted();
        let mut buffer = [0u8; 64];
        assert_eq!(
            list_entry(&mut table, "/greeting.txt", 0, &mut buffer),
            Err(Error::InvalidArgument)
        );
    }

    /// A buffer without room for the header, or for the whole name, is
    /// refused rather than partly written.
    ///
    /// The record declares the name's length, so a truncated name would be
    /// a record that lies about itself; refusing names the number the
    /// caller has to grow instead.
    #[test]
    fn a_buffer_without_room_for_the_record_is_refused() {
        let mut table = mounted();
        let mut header_only = [0u8; fs_abi::DIRECTORY_ENTRY_RECORD_SIZE];
        assert_eq!(
            list_entry(&mut table, "/", 0, &mut header_only),
            Err(Error::InvalidArgument),
            "the header fits and the name does not"
        );

        let mut short = [0u8; 8];
        let mut context = SyscallContext::new(SyscallNumber::ReadDir as usize, [0, 0, 0, 0, 0, 0]);
        let mut arguments = Arguments {
            context: &mut context,
            path: Some("/"),
            second_path: None,
            buffer: Some(&mut short),
        };
        assert_eq!(
            table.dispatch(&mut arguments),
            Err(Error::InvalidArgument),
            "not even the header fits"
        );
    }

    /// Call a number through the registry with six argument words and no
    /// borrow.
    ///
    /// The memory calls take no pointer, so this is the whole of their wire
    /// shape: a number, six words, and an answer.
    fn call(table: &mut SyscallTable, number: SyscallNumber, args: [usize; 6]) -> Result<usize> {
        let mut context = SyscallContext::new(number as usize, args);
        let mut arguments = Arguments::plain(&mut context);
        let dispatch = table.dispatch(&mut arguments)?;
        Ok(dispatch.value)
    }

    /// The memory calls validate their arguments, and a host can check that
    /// without a page table.
    ///
    /// Each of these is refused **before** the mapping is attempted, which is
    /// what makes them testable on a host and what makes them cheap on a
    /// machine: a call that reached the allocator with a bad length would have
    /// spent frames before discovering the caller was wrong.
    #[test]
    fn the_memory_calls_refuse_bad_arguments() {
        let mut table = SyscallTable::new();
        table.register(SyscallNumber::Mmap, mmap);
        table.register(SyscallNumber::Munmap, munmap);
        table.register(SyscallNumber::Brk, brk);

        // A zero-length mapping names nothing.
        assert_eq!(
            call(&mut table, SyscallNumber::Mmap, [0, 0, 1, 0x20, 0, 0]),
            Err(Error::InvalidArgument)
        );
        // A protection bit outside the set this build knows.
        assert_eq!(
            call(
                &mut table,
                SyscallNumber::Mmap,
                [0, 4096, 1 << 7, 0x20, 0, 0]
            ),
            Err(Error::InvalidArgument)
        );
        // Anonymous is required: without it the call asks for a mapping this
        // kernel cannot back.
        assert_eq!(
            call(&mut table, SyscallNumber::Mmap, [0, 4096, 1, 0x02, 0, 0]),
            Err(Error::InvalidArgument)
        );
        // Write and execute together, which the loader already refuses for
        // images and which turns a bug into an exploit.
        assert_eq!(
            call(
                &mut table,
                SyscallNumber::Mmap,
                [0, 4096, 3 | 4, 0x22, 0, 0]
            ),
            Err(Error::InvalidArgument)
        );
        // A reserved argument that is not zero.
        assert_eq!(
            call(&mut table, SyscallNumber::Mmap, [0, 4096, 1, 0x20, 7, 0]),
            Err(Error::InvalidArgument)
        );
        // A zero-length unmap names no range.
        assert_eq!(
            call(
                &mut table,
                SyscallNumber::Munmap,
                [0x80_0000_0000, 0, 0, 0, 0, 0]
            ),
            Err(Error::InvalidArgument)
        );
        // An unmap below the user window would name the kernel's own pages.
        assert_eq!(
            call(
                &mut table,
                SyscallNumber::Munmap,
                [0x1000, 4096, 0, 0, 0, 0]
            ),
            Err(Error::InvalidArgument)
        );
        // A brk with a reserved argument that is not zero.
        assert_eq!(
            call(&mut table, SyscallNumber::Brk, [0, 3, 0, 0, 0, 0]),
            Err(Error::InvalidArgument)
        );
    }

    /// A memory call whose arguments are well-formed gets past validation.
    ///
    /// On a host there is no page table, so the answer is `NotImplemented` —
    /// and that is the assertion: the call was **accepted by the validator**
    /// and refused by the machine it could not reach, which is a different
    /// outcome from `InvalidArgument` and is what a host can honestly check.
    #[test]
    fn a_well_formed_mapping_passes_validation() {
        let mut table = SyscallTable::new();
        table.register(SyscallNumber::Mmap, mmap);
        table.register(SyscallNumber::Brk, brk);
        assert_eq!(
            call(&mut table, SyscallNumber::Mmap, [0, 4096, 1, 0x22, 0, 0]),
            Err(Error::NotImplemented),
            "validated, then refused by a host that has no page table"
        );
        assert_eq!(
            call(&mut table, SyscallNumber::Brk, [0, 0, 0, 0, 0, 0]),
            Err(Error::NotImplemented)
        );
    }
}
