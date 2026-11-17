//! kernel/src/shm.rs
//!
//! Shared memory: a table from a key to a run of frames that more than one
//! process maps.
//!
//! ## What this is not
//!
//! Not a fork.  A fork makes two spaces map one frame and **demotes** it
//! read-only with a copy-on-write mark, so the first write on either side gives
//! that process a private copy.  That is the right answer for a fork and the
//! wrong one here: a region whose first write silently unshares is not shared
//! memory.  A region is mapped writable, is never marked copy-on-write, and
//! stays shared for as long as two processes have it mapped.
//!
//! ## What it is
//!
//! A region is a run of frames owned by this table and by no address space.
//! Each attach adds one reference per frame and records each frame in the
//! attaching space's ownership list; each detach unmaps, drops one reference,
//! and frees a frame only when the pool says that detach was the last owner.
//! The protocol is `memory::FrameAllocator`'s and is the same one `fork` uses,
//! which is why this file is small: the mechanism existed and the name did not.
//!
//! ## The decision this implements
//!
//! `docs/rfcs/0001-name-a-memory-region-two-processes-both-map.md`.  The parts
//! worth restating here, because they are the ones a reader of this file will
//! ask about:
//!
//! - a key is an authority and there is no other: two processes that choose one
//!   number share memory, and nothing asks who made it;
//! - `IPC_RMID` marks a region and the last detach frees it, because freeing a
//!   region a program still has mapped takes memory out from under that
//!   program;
//! - every attach maps the whole region, because the frozen ABI gives `ShmAt`
//!   no length to map a part of it.
//!
//! ## Why the table is a free function and not a field
//!
//! The handlers run with the registry's lock held, and this table's lock is
//! taken inside that one: the order is registry then region and never the
//! other way, and nothing in this file reaches back into the registry.  A field
//! a handler could reach into would be a second owner of the same rule.

use alloc::sync::Arc;
use alloc::vec::Vec;

/// One shared region.
///
/// The frames are the pool's, and this record is the only thing that names
/// them between attaches: the region is not owned by an address space, so no
/// space's `release` will ever free it, which is what makes a region outlive
/// the process that made it.
///
/// The frames live in the record and not in a table beside it.  A second table
/// keyed by the same identifier would be a second record of one fact, and the
/// first thing to drift would be whichever the two writers forgot; a region
/// that answered its length while its frames said something else is a detach
/// that frees the wrong pages.
#[derive(Debug)]
pub struct Region {
    /// The name `ShmGet` answers for a named region, or the synthetic negative
    /// identifier of a private one.
    ///
    /// Private regions are keyed by their identifier and not by
    /// `IPC_PRIVATE`, because two private regions are two regions: a key of
    /// zero would make the second `ShmGet` of zero answer the first.
    key: i32,
    /// How many attaches exist right now, this caller's included.
    attaches: usize,
    /// How many attaches are being built and are not counted yet.
    ///
    /// A region can be marked for destruction while an attach is between
    /// "looked up" and "mapped".  The attach count is zero in that window, so a
    /// mark that looked only at it could remove the region and free frames the
    /// attach is about to map.  The pending count closes that window: a marked
    /// region is removable only when both counts are zero.
    pending: usize,
    /// Whether `IPC_RMID` said to free the region when the last one goes.
    marked: bool,
    /// The region's length in bytes, which every attach maps whole.
    bytes: usize,
    /// The frames behind it, one per page of `bytes`.
    ///
    /// Empty in a host test, which has no pool.  The length is the truth for
    /// every question a host asks; the frames are the target's.
    frames: Vec<usize>,
}

impl Region {
    /// The region's length in bytes.
    pub fn bytes(&self) -> usize {
        self.bytes
    }

    /// How many mappings of it exist.
    pub fn attaches(&self) -> usize {
        self.attaches
    }

    /// How many attaches are in flight.
    pub fn pending(&self) -> usize {
        self.pending
    }

    /// Whether `IPC_RMID` has been asked for.
    pub fn marked(&self) -> bool {
        self.marked
    }

    /// The pages one attach maps.
    pub fn pages(&self) -> usize {
        self.bytes.div_ceil(paging::PAGE_SIZE)
    }

    /// The frames behind it.  Empty except on a machine.
    pub fn frames(&self) -> &[usize] {
        &self.frames
    }

    fn new(key: i32, bytes: usize) -> Region {
        Region {
            key,
            attaches: 0,
            pending: 0,
            marked: false,
            bytes,
            frames: Vec::new(),
        }
    }

    #[cfg(target_os = "none")]
    fn with_frames(key: i32, bytes: usize, frames: Vec<usize>) -> Region {
        Region {
            key,
            attaches: 0,
            pending: 0,
            marked: false,
            bytes,
            frames,
        }
    }

    /// Begin an attach that has not reached the region's count yet.
    pub fn begin_attach(&mut self) -> bool {
        if self.marked {
            return false;
        }
        self.pending += 1;
        true
    }

    /// Finish a pending attach: the mapping now counts as a real attachment.
    pub fn finish_attach(&mut self) {
        debug_assert!(self.pending > 0);
        self.pending -= 1;
        self.attaches += 1;
    }

    /// Abort a pending attach without changing the attach count.
    pub fn abort_attach(&mut self) {
        debug_assert!(self.pending > 0);
        self.pending -= 1;
    }

    /// Count one attachment inherited by a fork.
    ///
    /// A marked region is still valid for an existing mapping, so inheritance
    /// is allowed; it is a new attach to a region that cannot be removed while
    /// the parent's attachment exists.
    pub fn inherit_attach(&mut self) {
        self.attaches += 1;
    }

    /// Drop one attachment, answering whether no mapping or attach remains.
    pub fn detach_one(&mut self) -> bool {
        if self.attaches == 0 {
            return false;
        }
        self.attaches -= 1;
        self.attaches == 0 && self.pending == 0
    }

    /// Whether the region can be removed from the table.
    pub fn vacant(&self) -> bool {
        self.attaches == 0 && self.pending == 0
    }
}

/// The regions this boot has made.
///
/// A `Vec` because the region namespace is dynamic: a boot may create any
/// number of keys, and the table has no useful fixed ceiling.  The lock is
/// held for the length of the table operation, and the allocation's lock order
/// is stated at `get_or_create`.
#[cfg(target_os = "none")]
static REGIONS: sync::Mutex<Vec<Arc<sync::Mutex<Region>>>> = sync::Mutex::new(Vec::new());

/// The next identifier a private region will take.
///
/// Negative and counting down, so a private identifier can never be mistaken
/// for a named key a program chose, and zero is the one value neither can be:
/// `ShmAt` of zero is refused as an identifier rather than taken to mean the
/// first region.
#[cfg(target_os = "none")]
static NEXT_PRIVATE: core::sync::atomic::AtomicI32 = core::sync::atomic::AtomicI32::new(-1);

/// What a lookup found.
pub enum Lookup {
    /// The region, and its index in the table.
    Found(Arc<sync::Mutex<Region>>, usize),
    /// Nothing has that name.
    Missing,
}

/// Find the region `key` names, or say there is none.
///
/// A free function over a slice so a host test can exercise the rule that a key
/// naming one region answers that region and a key naming none answers nothing,
/// which is the half of this file that is not about frames.
pub fn find(
    regions: &[Arc<sync::Mutex<Region>>],
    key: i32,
) -> Option<(Arc<sync::Mutex<Region>>, usize)> {
    regions
        .iter()
        .enumerate()
        .find(|(_, region)| region.lock().key == key)
        .map(|(index, region)| (region.clone(), index))
}

/// Which identifier a `ShmGet` answers, given the table and the request.
///
/// The decision, in one function so a host can test it without a frame: a key
/// that names a region answers that region's key, a key the caller asked to
/// create is answered as itself, and a key the caller did not ask to create
/// answers nothing.  `IPC_PRIVATE` always takes a new identifier, which is why
/// the caller supplies it rather than this computing it.
pub fn identifier_for(
    regions: &[Arc<sync::Mutex<Region>>],
    key: i32,
    private: i32,
    create: bool,
) -> Result<i32, abi::Error> {
    if key == abi::memory::IPC_PRIVATE {
        return Ok(private);
    }
    if key < abi::memory::IPC_PRIVATE {
        return Err(abi::Error::InvalidArgument);
    }
    if find(regions, key).is_some() {
        return Ok(key);
    }
    if create {
        return Ok(key);
    }
    Err(abi::Error::NotFound)
}

/// Make a region, answering it with no attaches.
///
/// Separate from the table so a host test can build one and look at it: the
/// rule under test is that a fresh region is unmarked and unattached, which is
/// what makes the first attach the one that decides its length.
pub fn make(key: i32, bytes: usize) -> Region {
    Region::new(key, bytes)
}

#[cfg(target_os = "none")]
pub mod target;

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::sync::Arc;
    use alloc::vec::Vec;

    use super::Region;
    use super::find;
    use super::identifier_for;
    use super::make;

    fn table(entries: &[(i32, usize)]) -> Vec<Arc<sync::Mutex<Region>>> {
        entries
            .iter()
            .map(|(key, bytes)| Arc::new(sync::Mutex::new(make(*key, *bytes))))
            .collect()
    }

    /// A key names one region, and asking for it twice answers the same one.
    ///
    /// This is what makes a key a name and not a reference count: the second
    /// `ShmGet` of a key is a lookup, and two regions behind one key would be
    /// two processes that both thought they were sharing.
    #[test]
    fn one_key_names_one_region() {
        let regions = table(&[(0x1234, 4096)]);
        let (first, index) = find(&regions, 0x1234).expect("the key names it");
        assert_eq!(index, 0);
        let (second, again) = find(&regions, 0x1234).expect("and again");
        assert_eq!(again, 0, "the same slot, not a second copy");
        assert_eq!(
            Arc::as_ptr(&first),
            Arc::as_ptr(&second),
            "the same region, which is the fact the caller relies on"
        );
        assert!(find(&regions, 0x4321).is_none(), "a key nothing made");
    }

    /// `IPC_PRIVATE` always takes a new identifier.
    ///
    /// A private region has no name to find, so two of them are two regions and
    /// the identifier a caller is given is the only way back to it.  Counting
    /// down from `-1` is what keeps one of those from ever colliding with a key
    /// a program chose, since a key is a positive name in practice and the
    /// negative half is this side's.
    #[test]
    fn ipc_private_always_takes_the_identifier_it_was_given() {
        let regions = table(&[]);
        assert_eq!(
            identifier_for(&regions, abi::memory::IPC_PRIVATE, -1, false),
            Ok(-1),
            "a private region is answered the identifier it computed"
        );
        assert_eq!(
            identifier_for(&regions, abi::memory::IPC_PRIVATE, -2, true),
            Ok(-2),
            "and creation does not change that"
        );
    }

    /// A named key is refused unless the caller asked to create it.
    ///
    /// This is the rule that makes a mistyped key a refusal rather than a
    /// second region nobody wanted, and it is the whole of what `IPC_CREAT`
    /// buys.
    #[test]
    fn a_missing_key_needs_ipc_creat() {
        let regions = table(&[]);
        assert_eq!(
            identifier_for(&regions, 0x1234, -1, false),
            Err(abi::Error::NotFound),
            "no region and no permission to make one"
        );
        assert_eq!(
            identifier_for(&regions, 0x1234, -1, true),
            Ok(0x1234),
            "with the flag, the key is the identifier"
        );
    }

    /// A key that already names a region is answered without the flag.
    ///
    /// The other half of the rule above: `IPC_CREAT` is about making one, not
    /// about finding one, so a caller that omits it and names a region it knows
    /// exists gets that region.
    #[test]
    fn an_existing_key_is_answered_without_ipc_creat() {
        let regions = table(&[(0x1234, 4096)]);
        assert_eq!(
            identifier_for(&regions, 0x1234, -1, false),
            Ok(0x1234),
            "it is there, so finding it needs no permission to make one"
        );
    }

    /// The negative identifier range belongs to `IPC_PRIVATE`.
    ///
    /// Allowing a named key there lets a caller collide with the counter that
    /// hands private identifiers out, which would make two regions answer one
    /// name.
    #[test]
    fn a_named_key_cannot_enter_the_private_range() {
        let regions = table(&[]);
        assert_eq!(
            identifier_for(&regions, -1, -7, true),
            Err(abi::Error::InvalidArgument)
        );
        assert_eq!(
            identifier_for(&regions, abi::memory::IPC_PRIVATE, -7, false),
            Ok(-7)
        );
    }

    /// A fresh region is unattached, unmarked, and knows its own length.
    ///
    /// The three facts an attach depends on: an unmarked region is one no
    /// `IPC_RMID` has asked to destroy, and an unattached one is one whose last
    /// detach has not happened yet.
    #[test]
    fn a_fresh_region_is_whole() {
        let region = make(0x10, 8192);
        assert_eq!(region.bytes(), 8192);
        assert_eq!(region.attaches(), 0);
        assert_eq!(region.pending(), 0);
        assert!(!region.marked());
        assert_eq!(region.pages(), 2, "one page per 4096 bytes");
        assert!(
            region.frames().is_empty(),
            "a host has no pool, so a region made here names no frame"
        );
    }

    /// The page count rounds up, because a region is a whole number of pages.
    ///
    /// A one-byte region still costs a page and still maps one; a count that
    /// rounded down would map nothing and hand back an address with no memory
    /// behind it.
    #[test]
    fn a_region_rounds_its_pages_up() {
        assert_eq!(make(1, 1).pages(), 1);
        assert_eq!(make(1, 4096).pages(), 1);
        assert_eq!(make(1, 4097).pages(), 2);
        assert_eq!(make(1, 0).pages(), 0, "and zero is no pages at all");
    }

    /// A pending attach keeps a marked region alive until it finishes.
    ///
    /// This is the race `IPC_RMID` has with `ShmAt`: the attach has found the
    /// region but has not incremented `attaches` yet.  A region that was
    /// removed in that window would hand the attach freed frames to map.
    #[test]
    fn a_pending_attach_keeps_a_marked_region_from_being_vacant() {
        let mut region = make(7, 4096);
        assert!(region.begin_attach());
        region.marked = true;
        assert!(
            !region.vacant(),
            "the in-flight attach still owns the region"
        );

        region.finish_attach();
        assert_eq!(region.attaches(), 1);
        assert_eq!(region.pending(), 0);
        assert!(!region.vacant());

        assert!(region.detach_one(), "the final attach makes it vacant");
        assert!(region.vacant());
    }

    /// An aborted attach releases its reservation without inventing a mapping.
    #[test]
    fn an_aborted_pending_attach_leaves_no_attachment() {
        let mut region = make(8, 4096);
        assert!(region.begin_attach());
        region.abort_attach();
        assert_eq!(region.pending(), 0);
        assert_eq!(region.attaches(), 0);
        assert!(region.vacant());
    }

    /// A marked region refuses a new attach but still accepts inheritance.
    ///
    /// The parent already holds a mapping, so its fork is not what `IPC_RMID`
    /// was asked to exclude.  A brand-new `ShmAt` is.
    #[test]
    fn a_marked_region_refuses_new_attaches_but_accepts_inheritance() {
        let mut region = make(9, 4096);
        region.attaches = 1;
        region.marked = true;
        assert!(!region.begin_attach());
        assert_eq!(region.attaches(), 1);

        region.inherit_attach();
        assert_eq!(region.attaches(), 2);
        assert!(!region.detach_one());
        assert!(region.detach_one());
        assert!(region.vacant());
    }
}
