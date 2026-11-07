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

use crate::pipe;

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
    /// The buffer `read` was given, when this is a `read`.
    pub buffer: Option<&'a mut [u8]>,
}

impl<'a> Arguments<'a> {
    /// The arguments of a call that names no address.
    pub fn plain(context: &'a mut SyscallContext) -> Self {
        Self {
            context,
            path: None,
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
        /// The offset the next `read` starts at.
        ///
        /// Per descriptor rather than per node: two descriptors on one file are
        /// two positions, which is what a program that seeks one of them
        /// expects.
        offset: u64,
    },
    /// One end of a pipe.  Dropping it closes that end, which is what turns a
    /// reader's "no bytes yet" into end-of-file when the last writer goes.
    Pipe(pipe::End),
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

    /// Close a descriptor, returning its slot to the table.
    pub fn close(&mut self, descriptor: usize) -> Result<()> {
        let slot = self
            .descriptors
            .get_mut(descriptor)
            .ok_or(Error::InvalidArgument)?;
        slot.take().map(|_| ()).ok_or(Error::InvalidArgument)
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
    pub(crate) fn insert_pipe(&mut self, end: pipe::End) -> Result<usize> {
        self.insert(Descriptor::Pipe(end))
    }

    /// The pipe end a descriptor names, cloned, if it names one.
    ///
    /// A clone, because the table owns its entries and a caller that borrowed
    /// one would hold the registry's lock across a call that may block.  The
    /// `Arc` inside is what makes the clone cheap and what keeps the pipe
    /// alive while the caller works.
    pub(crate) fn pipe_end(&self, descriptor: usize) -> Option<pipe::End> {
        match self.descriptors.get(descriptor)? {
            Some(Descriptor::Pipe(end)) => Some(end.clone()),
            _ => None,
        }
    }

    /// Read from a descriptor, at `offset` or at its own position.
    pub(crate) fn read_at(
        &mut self,
        descriptor_index: usize,
        offset_arg: usize,
        buffer: &mut [u8],
    ) -> Result<usize> {
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
pub fn attach_pipe(end: pipe::End) -> Option<usize> {
    REGISTRY.lock().as_mut()?.insert_pipe(end).ok()
}

/// The pipe end a descriptor names, if it names one and the registry is up.
pub fn pipe_end(descriptor: usize) -> Option<pipe::End> {
    REGISTRY.lock().as_ref()?.pipe_end(descriptor)
}

pub fn has_registry() -> bool {
    REGISTRY.lock().is_some()
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
