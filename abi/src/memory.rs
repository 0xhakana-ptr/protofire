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
}
