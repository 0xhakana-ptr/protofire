//! kernel/src/shm/target.rs
//!
//! The half of shared memory that needs frames and page tables.
//!
//! [`super`] holds the region record and the key rule, which a host can test.
//! This file is everything that must not run on a host: taking frames from the
//! pool, mapping them into a running space, and giving them back.  The split is
//! the same one `address_space::space` makes, and for the same reason: a host
//! has no frames and no tables, so a file that did both could not be tested at
//! all.

use alloc::sync::Arc;
use alloc::vec::Vec;

use super::REGIONS;
use super::Region;
use super::find;

/// Count one more owner of each frame, answering whether all of them took.
///
/// Every frame is counted before any is mapped, so a refusal happens with
/// nothing to undo: `add_reference` is the one operation here that can fail
/// without having done anything, and doing all of them first is what makes the
/// failure path a loop of releases rather than a loop of unmaps.
#[cfg(target_os = "none")]
fn reference_all(frames: &[usize]) -> bool {
    if !crate::address_space::with_pool(|pool| {
        frames.iter().all(|frame| pool.add_reference(*frame))
    }) {
        return false;
    }
    // A failure partway through has already counted the frames before it, so
    // the undo is one release per frame counted.  The pool's own answer for
    // "was this the last" cannot be true here: this call is what added the
    // counts it is taking back.
    true
}

/// Drop one reference to each frame, freeing the ones this release was last
/// for.
///
/// Answers how many frames went back to the pool, which is the number a caller
/// prints when it wants to say what a detach cost.
#[cfg(target_os = "none")]
fn release_all(frames: &[usize]) -> usize {
    let freed = crate::address_space::with_pool(|pool| {
        let mut freed = Vec::new();
        for frame in frames {
            if pool.release_reference(*frame) {
                freed.push(*frame);
            }
        }
        freed
    });
    let mut count = 0;
    for frame in freed {
        // SAFETY: the pool said this was the last reference to the frame, and
        // the caller released it only after taking the mapping away.
        if unsafe { crate::address_space::free_frame(frame) } {
            count += 1;
        }
    }
    count
}

/// Take `pages` frames from the pool, counting one reference each.
#[cfg(target_os = "none")]
fn take_frames(pages: usize) -> Option<Vec<usize>> {
    let mut frames = Vec::new();
    while frames.len() < pages {
        let Some(frame) = crate::address_space::allocate_image_frame() else {
            release_all(&frames);
            return None;
        };
        frames.push(frame);
    }
    Some(frames)
}

/// Make a region of `bytes`, taking the frames it needs.
///
/// The length is rounded up to a page by [`Region::pages`], and a request of
/// zero pages is refused before anything is taken: a name with nothing behind
/// it is not a region.
#[cfg(target_os = "none")]
pub(crate) fn create(key: i32, bytes: usize) -> Option<Arc<sync::Mutex<Region>>> {
    let pages = bytes.div_ceil(paging::PAGE_SIZE);
    if pages == 0 {
        return None;
    }
    let frames = take_frames(pages)?;
    let region = Arc::new(sync::Mutex::new(Region::with_frames(key, bytes, frames)));
    REGIONS.lock().push(region.clone());
    Some(region)
}

/// Find a region by the identifier a caller passed.
#[cfg(target_os = "none")]
pub(crate) fn lookup(identifier: i32) -> Option<Arc<sync::Mutex<Region>>> {
    let regions = REGIONS.lock();
    find(&regions, identifier).map(|(region, _)| region)
}

/// Map a region's frames into the running process, answering the base.
///
/// The one place this design differs from a fork: **no page is demoted and none
/// is marked copy-on-write.**  The frame is shared and it stays writable, which
/// is the whole of what shared memory promises.
///
/// Every failure undoes what it did.  The order is deliberate: the references
/// are counted first, the space records the frames second, and the mappings are
/// written last, so the two ways a failure can arrive (a count refused, a
/// record full) happen before any page table has been touched and cost one loop
/// each. A mapping that fails after some pages are written unmaps those.
#[cfg(target_os = "none")]
pub(crate) fn attach(identifier: i32, writable: bool, executable: bool) -> Option<usize> {
    let region = lookup(identifier)?;
    let (frames, bytes) = {
        let region = region.lock();
        (region.frames().to_vec(), region.bytes())
    };
    if frames.is_empty() {
        return None;
    }
    if !reference_all(&frames) {
        return None;
    }
    let base = crate::scheduler::attach_shared(
        crate::per_cpu::current_slot(),
        identifier,
        &frames,
        bytes,
        writable,
        executable,
    );
    if base.is_none() {
        // The attach did not happen, so the references this call added are the
        // only trace of it.  Taking them back cannot free a frame: this call
        // is what counted them, so some other owner is still there.
        let _ = release_all(&frames);
    }
    base
}

/// Drop one attach of the region mapped at `address`.
///
/// Answers whether the address named an attach.  The mapping is taken away
/// first and the references dropped second, which is the order the pool's
/// protocol requires: a frame freed while a page table still names it is a
/// frame another process may write through an address nothing owns.
#[cfg(target_os = "none")]
pub(crate) fn detach(address: usize) -> bool {
    let Some((identifier, frames)) =
        crate::scheduler::detach_shared(crate::per_cpu::current_slot(), address)
    else {
        return false;
    };
    let _ = release_all(&frames);
    // The count moves only for a region still in the table: a region whose last
    // attach just went is being destroyed, not counted down.
    let (marked, last) = match lookup(identifier) {
        Some(region) => {
            let mut region = region.lock();
            if region.attaches > 0 {
                region.attaches -= 1;
            }
            (region.marked(), region.attaches() == 0)
        }
        None => return true,
    };
    if last && marked {
        // The last attach of a region `IPC_RMID` marked.  The region leaves the
        // table here and its frames go back to the pool; they are taken out of
        // the record first, because releasing a frame takes the page-table lock
        // and the region table's lock must not be held across that.
        if let Some(frames) = take_destroyed(identifier) {
            let _ = release_all(&frames);
        }
    }
    true
}

/// Note one more attach of a region, answering how many there now are.
#[cfg(target_os = "none")]
pub(crate) fn noted_attach(identifier: i32) -> Option<usize> {
    let region = lookup(identifier)?;
    let mut region = region.lock();
    region.attaches += 1;
    Some(region.attaches)
}

/// Mark a region destroyed, answering whether it was found.
///
/// A region with attaches is marked and stays; the detach that takes the last
/// one frees it.  A region with **none** is freed here, because there is no
/// later detach to free it.  Which path runs is decided by the count and not
/// by the caller, and both free exactly once.
#[cfg(target_os = "none")]
pub(crate) fn mark(identifier: i32) -> bool {
    let Some(region) = lookup(identifier) else {
        return false;
    };
    let unattached = {
        let mut region = region.lock();
        region.marked = true;
        region.attaches == 0
    };
    // A region with no attaches goes **here**, because there is no later
    // detach to free it.  A mark that waited for one would be a region nobody
    // could find and a frame nobody would free: found by the boot's own frame
    // census, which read one frame short after this call was the only one.
    if unattached && let Some(frames) = take_destroyed(identifier) {
        let _ = release_all(&frames);
    }
    true
}

/// A region's length and attach count, for `IPC_STAT`.
#[cfg(target_os = "none")]
pub(crate) fn stat(identifier: i32) -> Option<(usize, usize)> {
    let region = lookup(identifier)?;
    let region = region.lock();
    Some((region.bytes(), region.attaches()))
}

/// The frames of a region whose last attach has gone, and its removal.
///
/// Called by the detach that took the last mapping away, when the region was
/// marked.  Answers the frames so the caller can release them, which is the one
/// thing that cannot be done while this file's table lock is held: releasing a
/// frame takes the page-table lock, and the order every other path keeps is
/// table first and pool second, never inside the region table.
#[cfg(target_os = "none")]
pub(crate) fn take_destroyed(identifier: i32) -> Option<Vec<usize>> {
    let mut regions = REGIONS.lock();
    let position = regions
        .iter()
        .position(|region| region.lock().key == identifier)?;
    let (attaches, marked) = {
        let region = regions[position].lock();
        (region.attaches(), region.marked())
    };
    if attaches != 0 || !marked {
        return None;
    }
    let region = regions.swap_remove(position);
    drop(regions);
    let frames = region.lock().frames().to_vec();
    Some(frames)
}

/// The next private identifier, counting down from `-1`.
#[cfg(target_os = "none")]
pub(crate) fn next_private() -> i32 {
    super::NEXT_PRIVATE.fetch_sub(1, core::sync::atomic::Ordering::Relaxed)
}
