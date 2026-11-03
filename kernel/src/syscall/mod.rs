//! kernel/src/syscall/mod.rs
//!
//! The syscall registry: the table from a number to the function that serves
//! it, and the three handlers this boot can answer.
//!
//! ## Why the table is here and not in the `syscall` crate
//!
//! Every slot names a subsystem — the filesystem, the network, the scheduler —
//! and the `syscall` crate must not know that any of them exist.  A table there
//! would have to import them, which is the edge `scripts/check-layering.sh`
//! refuses.  The crate keeps the numbering, the context and the validators;
//! where the handlers live is the kernel's business, because the kernel is the
//! only crate that may name them all.
//!
//! ## What is served today
//!
//! Three handlers — `open`, `read` and `close` — backed by the one mounted
//! volume.  That is the smallest set that makes the registry real: a program
//! cannot read without opening, opening without closing leaks the slot, and the
//! three together exercise every part of the interface — a number, an argument
//! vector, the validators, a dispatch value, and an error that comes back as a
//! status word.
//!
//! Every other number answers [`Error::NotImplemented`] rather than being
//! absent.  An absent slot would have to be a panic or a silent zero, and both
//! report a lie: this kernel does not serve that number, which is a fact the
//! caller can act on.
//!
//! ## Arguments, and what a pointer means here
//!
//! [`SyscallContext`] carries six words, and a word may be an address.  This
//! boot has no user address space, so the only caller is the kernel itself and
//! the two address-shaped arguments arrive as borrows — [`Arguments::path`]
//! and [`Arguments::buffer`] — rather than as integers a handler would have to
//! turn back into pointers.
//!
//! That is deliberate.  A handler that does `from_raw_parts` on
//! `context.arg(1)` carries a promise it cannot show — the comment would say
//! "the caller promises this is valid", and nothing would check it.  Taking a
//! `&mut [u8]` moves the promise to the one place that can keep it: the code
//! that built the borrow.  When a program can call these, the entry path copies
//! its buffer into kernel memory and calls the same handler with the same
//! borrow, so the handler does not change and this module never gains an
//! `unsafe`.
//!
//! ## Descriptors
//!
//! A descriptor is an index into a fixed table of open nodes.  The table is per
//! boot because there is one address space and no process yet; when the
//! scheduler arrives it moves into the process, and this module keeps only the
//! number-to-handler mapping, which is the part that is genuinely the kernel's.

use alloc::sync::Arc;

use abi::Error;
use abi::Result;
use abi::fs as fs_abi;
use fs::MountTable;
use fs::VNode;
use security::mac;
use syscall::SyscallContext;
use syscall::SyscallDispatch;
use syscall::SyscallNumber;
use syscall::validate_known_flags;
use syscall::validate_zeroed_args;

/// The highest number the table has room for.
///
/// Sized from the ABI's own count rather than a number chosen here, so a
/// syscall added to the enum cannot be served by a table with no room for it:
/// the array length and the enum move together or the build fails.
const MAX_SYSCALLS: usize = syscall::PUBLIC_SYSCALL_COUNT as usize;

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

/// One open node and the rights it was opened with.
struct Descriptor {
    node: Arc<dyn VNode>,
    readable: bool,
    /// The offset the next `read` starts at.
    ///
    /// Per descriptor rather than per node: two descriptors on one file are two
    /// positions, which is what a program that seeks one of them expects.
    offset: u64,
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

    /// Register a handler for `number`.
    pub fn register(&mut self, number: SyscallNumber, handler: KernelHandler) {
        self.slots[number as usize] = Handler::Served(handler);
    }

    /// Serve a call.
    ///
    /// A number past the table's end is refused rather than indexed: the table
    /// is sized from the ABI count, so this cannot happen for a variant that
    /// exists — but a caller's number is a word off a wire, and indexing with
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
    /// act on — so the count is what a boot line reports and what a test
    /// compares against.
    pub fn served(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| matches!(slot, Handler::Served(_)))
            .count()
    }

    /// The namespace, if a boot installed one.
    fn namespace(&self) -> Option<&Arc<MountTable>> {
        self.namespace.as_ref()
    }

    /// Put one descriptor in a free slot and answer its index.
    fn insert(&mut self, descriptor: Descriptor) -> Result<usize> {
        for (index, slot) in self.descriptors.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(descriptor);
                return Ok(index);
            }
        }
        Err(Error::OutOfMemory)
    }

    /// Read from a descriptor, at `offset` or at its own position.
    fn read_at(
        &mut self,
        descriptor_index: usize,
        offset: usize,
        buffer: &mut [u8],
    ) -> Result<usize> {
        let descriptor = self
            .descriptors
            .get_mut(descriptor_index)
            .ok_or(Error::InvalidArgument)?
            .as_mut()
            .ok_or(Error::InvalidArgument)?;

        if !descriptor.readable {
            return Err(Error::PermissionDenied);
        }

        let at_current = offset == READ_OFFSET_CURRENT;
        let start = if at_current {
            descriptor.offset
        } else {
            offset as u64
        };

        let count = descriptor.node.read(start, buffer)?;
        // An explicit offset is a peek, not a step: the descriptor's own
        // position moves only when the caller asked to read from it.  A
        // position that moved on every probe would make "read a header, then
        // continue from where I was" impossible to express.
        if at_current {
            descriptor.offset = start + count as u64;
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
/// ## Why a static
///
/// The table was a local in `kernel_main`: the boot built it, served three
/// calls through it, and dropped it.  That is enough to prove the handlers work
/// and not enough to be a kernel — a table that exists only inside one function
/// is a table nothing else can ever reach, and "the syscall interface" would be
/// a claim about a variable.
///
/// A `SyncUnsafeCell` for the same reason the machine's trap sink uses one:
/// there is one table per boot, it is written once, and every later reader is a
/// call that arrived without a context to be handed one.
static REGISTRY: cell::SyncUnsafeCell<Option<SyscallTable>> = cell::SyncUnsafeCell::new(None);

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
    // flight.  The write is a whole-table store, so a reader either sees the
    // old table or the new one and never a half-built one.
    unsafe { *REGISTRY.get() = Some(table) };
}

/// Serve one call through the installed registry.
///
/// `None` when the boot has not installed one, which is the state before the
/// filesystem is mounted.
///
/// This is the path a trap will use when there is a process to take one from.
/// It exists now so the registry is reachable from outside the function that
/// built it — the thing that was missing — and so the boot can serve a call
/// through the same entry point a later trap will.
pub fn serve(arguments: &mut Arguments<'_>) -> Option<Result<Dispatch>> {
    // SAFETY: the table is written once, before any call can arrive, and this
    // read happens after that write.  The borrow it takes is exclusive for the
    // length of the call, which is what the table's methods require.
    let table = unsafe { (*REGISTRY.get()).as_mut() };
    table.map(|table| table.dispatch(arguments))
}

/// Whether a boot installed a registry.
pub fn has_registry() -> bool {
    // SAFETY: as `serve`.
    unsafe { (*REGISTRY.get()).is_some() }
}

/// How many descriptors the installed table holds open.
pub fn open_descriptors() -> usize {
    // SAFETY: as `serve`.
    let table = unsafe { (*REGISTRY.get()).as_ref() };
    table.map_or(0, SyscallTable::open_descriptors)
}

/// How many numbers the installed table serves.
///
/// A served number is one with a handler rather than
/// [`Handler::Unimplemented`], and the count is what makes "the table is
/// installed" a claim with a number beside it.
pub fn served_numbers() -> usize {
    // SAFETY: as `serve`.
    let table = unsafe { (*REGISTRY.get()).as_ref() };
    table.map_or(0, SyscallTable::served)
}

/// Open a path and return its descriptor.
///
/// Arguments: the path, the flags, then two reserved slots that must be zero.
///
/// [`OPEN_FLAG_NONE`](fs_abi::OPEN_FLAG_NONE) is read-only: a caller that named
/// no access mode asked for the least it could get, and least privilege is the
/// reading that cannot surprise it with a write it did not name.
pub fn open(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let path = arguments.path.ok_or(Error::InvalidArgument)?;
    let flags = arguments.context.arg(1);
    validate_known_flags(flags, fs_abi::OPEN_KNOWN_FLAGS)?;
    validate_zeroed_args(arguments.context, 2)?;

    // Who is asking, before what they asked for is resolved.
    //
    // The check comes first because a policy decision that ran after the lookup
    // would have already told the caller whether the path exists: a denial and
    // a "not found" are different answers, and the one that leaks less is the
    // one that does not distinguish them.
    //
    // The action decides the permission.  A descriptor opened for writing is a
    // request to write, and asking the policy about a read would grant a write
    // on the strength of a read rule.
    let subject = arguments
        .context
        .identity
        .unwrap_or(mac::MAC_TYPE_UNLABELED);
    let permission = if flags & (fs_abi::OPEN_FLAG_WRITE | fs_abi::OPEN_FLAG_CREATE) != 0 {
        mac::MAC_PERM_WRITE
    } else {
        mac::MAC_PERM_READ
    };
    mac::check_file(subject, path, mac::MAC_CLASS_FILE, permission, 0)?;

    // Through the namespace: the table resolves the path to a mount and a path
    // relative to it, and the filesystem answers for that.  `open` names no
    // filesystem, which is what lets a second one be mounted without this
    // handler changing.
    let node = table.namespace().ok_or(Error::NotFound)?.lookup(path)?;

    let descriptor = table.insert(Descriptor {
        node,
        readable: flags & fs_abi::OPEN_FLAG_READ != 0 || flags == fs_abi::OPEN_FLAG_NONE,
        offset: 0,
    })?;

    Ok(Dispatch::complete(descriptor))
}

/// Read from a descriptor into the buffer the caller supplied.
///
/// Arguments: the descriptor, the offset, then four reserved slots that must be
/// zero.  The offset is the descriptor's own when the caller passes
/// [`READ_OFFSET_CURRENT`].
///
/// Returns the number of bytes read, which is short at end of file and zero
/// past it — the reading that lets a caller tell "no more data" from "the call
/// failed", which a status word alone cannot say.
pub fn read(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let descriptor_index = arguments.context.arg(0);
    let offset = arguments.context.arg(1);
    validate_zeroed_args(arguments.context, 2)?;

    let buffer = arguments
        .buffer
        .as_deref_mut()
        .ok_or(Error::InvalidArgument)?;
    if buffer.is_empty() {
        return Ok(Dispatch::complete(0));
    }

    let count = table.read_at(descriptor_index, offset, buffer)?;
    Ok(Dispatch::complete(count))
}

/// Close a descriptor.
///
/// Arguments: the descriptor, then five reserved slots that must be zero.
///
/// Closing twice is an error rather than a no-op: a descriptor number a caller
/// reused after closing is a number the kernel may have handed to something
/// else, and a silent success would let a program close another's file.
pub fn close(table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let descriptor = arguments.context.arg(0);
    validate_zeroed_args(arguments.context, 1)?;
    table.close(descriptor)?;
    Ok(Dispatch::complete(0))
}

/// Report the MAC policy's state.
///
/// Arguments: five reserved slots that must be zero.  Answers
/// `enabled | default_deny << 1 | rule_count << 8 | label_count << 32`.
///
/// A packed word rather than a struct because a syscall returns one `usize`,
/// and a program that wanted four fields would otherwise need a second call per
/// field.  The layout is stated here and in no other place, which is what lets
/// it be a number.
pub fn mac_get_status(
    _table: &mut SyscallTable,
    arguments: &mut Arguments<'_>,
) -> Result<Dispatch> {
    validate_zeroed_args(arguments.context, 0)?;
    let state = mac::policy_state().lock();
    let mut value = 0usize;
    if state.policy.enabled {
        value |= 1;
    }
    if state.policy.default_deny {
        value |= 1 << 1;
    }
    value |= state.policy.rule_count().min(0xFF) << 8;
    value |= state.label_count().min(0xFFFF) << 32;
    Ok(Dispatch::complete(value))
}

/// Turn enforcement on or off.
///
/// Arguments: `0` disables, `1` enables, then four reserved slots that must be
/// zero.  Answers the previous state.
///
/// Disabling is permitted and is not a security hole in this kernel: the policy
/// is off at boot, so a program that can call this already runs as something
/// the kernel trusts.  When there is a process layer, this becomes a call the
/// policy itself gates — which is why the handler does not check `identity`
/// today rather than because it forgot.
pub fn mac_set_mode(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let enable = arguments.context.arg(0);
    if enable > 1 {
        return Err(Error::InvalidArgument);
    }
    validate_zeroed_args(arguments.context, 1)?;
    let mut state = mac::policy_state().lock();
    let previous = state.policy.enabled;
    state.policy.enabled = enable == 1;
    Ok(Dispatch::complete(usize::from(previous)))
}

/// Add one allow rule.
///
/// Arguments: `subject, object, class, permissions, replace`, then one reserved
/// slot that must be zero.  Answers the number of rules after the addition.
///
/// The five values are the rule's own fields in the order
/// [`mac::MacRule`] declares them, so a caller that read the type knows the
/// argument order without reading this function.  An unknown class or type is
/// refused rather than stored: a rule matching nothing is a rule that silently
/// does nothing, and a policy is the wrong place for a silent no-op.
pub fn mac_add_rule(_table: &mut SyscallTable, arguments: &mut Arguments<'_>) -> Result<Dispatch> {
    let subject = arguments.context.arg(0) as mac::MacType;
    let object = arguments.context.arg(1) as mac::MacType;
    let class = arguments.context.arg(2) as mac::MacClass;
    let perms = arguments.context.arg(3) as mac::MacPermission;
    let replace = arguments.context.arg(4);
    if replace > 1 {
        return Err(Error::InvalidArgument);
    }
    validate_zeroed_args(arguments.context, 5)?;

    if !mac::is_known_type(subject) || !mac::is_known_type(object) {
        return Err(Error::InvalidArgument);
    }
    if !mac::is_known_class(class) {
        return Err(Error::InvalidArgument);
    }

    let rule = mac::MacRule {
        subject,
        object,
        class,
        perms,
    };
    let mut state = mac::policy_state().lock();
    state.policy.add_rule(rule, replace == 1);
    Ok(Dispatch::complete(state.policy.rule_count()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use fs::StaticFileSystem;
    use fs::types::NodeKind;

    /// A volume with one file in it, and a table serving the three handlers.
    fn mounted() -> SyscallTable {
        let volume = StaticFileSystem::with_entries(
            "test",
            &[("/greeting.txt", NodeKind::File, b"hello from a syscall")],
        );
        let mut table = SyscallTable::new();
        let mut namespace = MountTable::new();
        namespace
            .mount("/", "pyrofs", "boot", Arc::new(volume))
            .expect("mount");
        table.set_namespace(Arc::new(namespace));
        table.register(SyscallNumber::Open, open);
        table.register(SyscallNumber::Read, read);
        table.register(SyscallNumber::Close, close);
        table
    }

    /// Open a path through the registry, as the boot does.
    fn open_path(table: &mut SyscallTable, path: &str, flags: usize) -> Result<usize> {
        let mut context = SyscallContext::new(SyscallNumber::Open as usize, [0, flags, 0, 0, 0, 0]);
        let mut arguments = Arguments {
            context: &mut context,
            path: Some(path),
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
            buffer: Some(buffer),
        };
        let dispatch = table.dispatch(&mut arguments)?;
        Ok(dispatch.value)
    }

    /// The whole path: open, read, close, and the bytes that came back.
    ///
    /// This is the test the wiring exists for.  Every part of the interface is
    /// on it — the number reaches the table, the context carries the arguments,
    /// the validators run, the filesystem answers, and the value comes back as
    /// a dispatch — and a break in any of them makes the comparison fail.
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
            buffer: None,
        };
        assert_eq!(table.dispatch(&mut arguments), Err(Error::InvalidArgument));

        let mut context = SyscallContext::new(SyscallNumber::Open as usize, [0, 0, 0, 0, 7, 0]);
        let mut arguments = Arguments {
            context: &mut context,
            path: Some("/greeting.txt"),
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
}
