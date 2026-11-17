//! abi/src/memory.rs
//!
//! The wire values a program passes to the memory calls: what it wants a
//! mapping to be, and how it wants it established.
//!
//! ## Why these are here and not in a driver
//!
//! They travel in argument slots.  A program compiled against a different
//! number asks for a protection it did not get, and the kernel would have no
//! way to tell, so the numbers are the ABI's and a test pins them.
//!
//! Their values are the ones this tree's older ABI already gave them, which is
//! what makes a program written against either one mean the same thing.

// Protection bits, as `Mmap`'s third argument takes them.
//
// A set, not an enumeration: a caller that wants a page both readable and
// writable passes `PROT_READ | PROT_WRITE`.

/// The page may be read.  Every mapping this kernel makes is readable, so this
/// bit is accepted and recorded rather than required, a `Mmap` asking for
/// `PROT_WRITE` alone still gets a page it can read, because this kernel has no
/// way to make a page unreadable.
pub const PROT_READ: usize = 1 << 0;

/// The page may be written.
pub const PROT_WRITE: usize = 1 << 1;

/// The page may be executed.
///
/// Refused together with [`PROT_WRITE`], which is the write-xor-execute rule
/// the loader already enforces for images: a page a program can change and then
/// run is the one mapping that turns a bug into an exploit.
pub const PROT_EXEC: usize = 1 << 2;

/// The protection bits this build understands.
pub const PROT_KNOWN: usize = PROT_READ | PROT_WRITE | PROT_EXEC;

// Mapping flags, as `Mmap`'s fourth argument takes them.

/// The mapping is not backed by a file.
///
/// Required: this kernel has no file-backed mapping, and a caller that did not
/// ask for anonymous memory is asking for something it will not get.
pub const MAP_ANONYMOUS: usize = 0x20;

/// Changes are private to the calling process.
///
/// Required alongside [`MAP_ANONYMOUS`] because anonymous memory has no other
/// sensible reading, there is no other process to share it with until this
/// kernel has shared memory, which it does not.
pub const MAP_PRIVATE: usize = 0x02;

/// The flags this build understands.
pub const MAP_KNOWN_FLAGS: usize = MAP_ANONYMOUS | MAP_PRIVATE;

/// The largest mapping one call may ask for.
///
/// 64 MiB, which is the whole frame pool on the smallest machine this tree
/// boots.  A single call asking for more than the pool holds is one the kernel
/// can refuse before it starts allocating, and a caller learns that from the
/// argument rather than from a partial mapping.
pub const MAP_MAX_BYTES: usize = 64 * 1024 * 1024;

// Shared memory, as `ShmGet`, `ShmAt`, `ShmDt` and `ShmCtl` take it.
//
// The four numbers are frozen in the syscall range and were served by nothing
// before this.  `docs/rfcs/0001-name-a-memory-region-two-processes-both-map.md`
// is the decision behind the values below; this is only the wire.
//
// The constants keep Unix's values rather than inventing fresh ones, for the
// reason `PROT_READ` does: a program and a person both already know what
// `IPC_CREAT` means, and a new number would make a reader look it up.

/// A named region may be made by this call, or an existing one answered.
///
/// Without it a `ShmGet` naming a key that has no region answers `NotFound`,
/// so a mistyped key is a refusal rather than a second region nobody wanted.
pub const IPC_CREAT: usize = 0o1000;

/// A region is destroyed when its last attach is dropped.
///
/// `ShmCtl`'s command.  The region is **marked** and stays until the last
/// detach, because a program still has it mapped; freeing now would take
/// memory out from under that program.
pub const IPC_RMID: usize = 0;

/// A region's length and attach count are written into the caller's record.
///
/// `ShmCtl`'s command.  It answers the one question a program with a region
/// needs and cannot answer itself: is anything else attached.
pub const IPC_STAT: usize = 2;

/// The `ShmGet` flag bits this build understands.
pub const SHM_GET_KNOWN_FLAGS: usize = IPC_CREAT;

/// The `ShmAt` flag bits this build understands.
///
/// The protection bits: an attach asks whether the region is writable, and
/// nothing else.  There is no partial attach to flag, because the frozen ABI
/// gives `ShmAt` no length argument.
pub const SHM_AT_KNOWN_FLAGS: usize = PROT_READ | PROT_WRITE | PROT_EXEC;

/// The `ShmGet` key that always makes a new region.
///
/// Unix's `IPC_PRIVATE`: a region nobody else can find by name, so the caller
/// must pass the answer to whoever should map it.  Zero, so a program that
/// passes an uninitialised word gets a private region rather than somebody
/// else's.
pub const IPC_PRIVATE: i32 = 0;

/// What `ShmCtl`'s `IPC_STAT` writes into the caller's record: a region's
/// length in bytes and how many mappings it has.
///
/// Two words, in the order below.  A field nothing reads is a field a reader
/// has to check, so this is the pair and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ShmStat {
    /// The region's length, which every attach maps whole.
    pub bytes: usize,
    /// How many attaches exist right now, this caller's included.
    pub attaches: usize,
}

/// The size of the record [`ShmStat`] describes.
pub const SHM_STAT_SIZE: usize = core::mem::size_of::<ShmStat>();

/// Where the two fields sit, for a program walking bytes it did not write.
pub const SHM_STAT_BYTES_OFFSET: usize = core::mem::offset_of!(ShmStat, bytes);
pub const SHM_STAT_ATTACHES_OFFSET: usize = core::mem::offset_of!(ShmStat, attaches);

#[cfg(test)]
mod tests {
    use super::MAP_ANONYMOUS;
    use super::MAP_KNOWN_FLAGS;
    use super::MAP_MAX_BYTES;
    use super::MAP_PRIVATE;
    use super::PROT_EXEC;
    use super::PROT_KNOWN;
    use super::PROT_READ;
    use super::PROT_WRITE;

    /// The bit values are the wire format, so they do not move.
    ///
    /// These are the numbers a program's own headers carry.  A change here is a
    /// program compiled against one kernel running on another, which is the
    /// class of bug the frozen range exists to make impossible.
    #[test]
    fn the_protection_bits_are_the_wire_values() {
        assert_eq!(PROT_READ, 1);
        assert_eq!(PROT_WRITE, 2);
        assert_eq!(PROT_EXEC, 4);
        assert_eq!(MAP_PRIVATE, 0x02);
        assert_eq!(MAP_ANONYMOUS, 0x20);
    }

    /// The known sets are exactly the bits above, which is what a handler
    /// validates against.
    #[test]
    fn the_known_sets_are_the_bits_above() {
        assert_eq!(PROT_KNOWN, PROT_READ | PROT_WRITE | PROT_EXEC);
        assert_eq!(MAP_KNOWN_FLAGS, MAP_ANONYMOUS | MAP_PRIVATE);
    }

    /// The size bound is the smallest machine's whole pool, not an arbitrary
    /// number.
    #[test]
    fn the_largest_mapping_fits_the_smallest_pool() {
        assert_eq!(MAP_MAX_BYTES, 64 * 1024 * 1024);
        assert!(
            MAP_MAX_BYTES.is_multiple_of(4096),
            "the bound is page-aligned"
        );
    }

    /// The shared-memory values are the wire format, and they are Unix's.
    ///
    /// `IPC_CREAT` is `0o1000` because a program that passes Unix's flag to
    /// this kernel must mean "make one if it is not there", and a fresh number
    /// would make that program wrong without telling anyone.  `IPC_RMID` is
    /// zero, which is also `MAP_SHARED`'s value on other systems and is why the
    /// two flag words are validated separately.
    #[test]
    fn the_shared_memory_values_are_unix() {
        use super::IPC_CREAT;
        use super::IPC_PRIVATE;
        use super::IPC_RMID;
        use super::IPC_STAT;

        assert_eq!(IPC_CREAT, 0o1000);
        assert_eq!(IPC_RMID, 0);
        assert_eq!(IPC_STAT, 2);
        assert_eq!(IPC_PRIVATE, 0);
        assert_ne!(
            IPC_CREAT, IPC_RMID,
            "a command and a creation flag must not share a value"
        );
    }

    /// The attach's flag word is the protection word, and nothing else.
    ///
    /// `ShmAt` has one flag argument in the frozen numbering, and an attach
    /// needs to say whether it wants a writable mapping; so the bits it takes
    /// are the protection bits and the known set is exactly theirs.  A bit
    /// added to `PROT_*` without being added here would be refused as unknown,
    /// which fails closed.
    #[test]
    fn an_attach_takes_the_protection_bits() {
        use super::SHM_AT_KNOWN_FLAGS;

        assert_eq!(SHM_AT_KNOWN_FLAGS, PROT_KNOWN);
    }

    /// The `ShmStat` record is two words and its offsets name them.
    ///
    /// A program parses this record out of a buffer it did not write, so the
    /// offsets are what it has: a struct whose fields moved would make every
    /// reader wrong at once, and the assertion is the one that notices.
    #[test]
    fn the_stat_record_is_two_words_in_order() {
        use super::SHM_STAT_ATTACHES_OFFSET;
        use super::SHM_STAT_BYTES_OFFSET;
        use super::SHM_STAT_SIZE;

        assert_eq!(SHM_STAT_SIZE, 2 * core::mem::size_of::<usize>());
        assert_eq!(SHM_STAT_BYTES_OFFSET, 0);
        assert_eq!(
            SHM_STAT_ATTACHES_OFFSET,
            core::mem::size_of::<usize>(),
            "the attach count follows the length"
        );
    }
}
