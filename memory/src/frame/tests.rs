//! memory/src/frame/tests.rs
//!
//! The frame allocator: a bump tail, the free-list fusing a freed pair, and the
//! high-water mark a rewind restores.
//!
//! Extracted from the module so a reader following the mechanism does not have
//! to scroll past every case it satisfies; see `docs/fmts/testing.md` §1.

use crate::frame::FRAME_SIZE;
use crate::frame::FrameAllocator;
use crate::frame::physical_pool_size;
use alloc::vec::Vec;

/// The free list survives fragmentation far past any fixed bound.
///
/// This is the test that decided the representation.  A sorted array of
/// ranges dropped `alloc` and lost frames: seventy interleaved single-frame
/// holes do not fit in eight nodes, and `deallocate` answered `false` and
/// dropped the frame.  A bitmap has one bit per frame, so the number of
/// holes is the pool's size and not a constant somebody picked.
///
/// The `is_some` on every allocation is the assertion that matters: a
/// figure that merely counted free frames right would pass while the
/// allocator had forgotten where they were.
#[test]
fn fragmentation_is_bounded_by_the_pool_and_not_by_a_constant() {
    let mut allocator = FrameAllocator::new();
    allocator.init(FRAME_SIZE * 256);

    let mut frames = Vec::new();
    for _ in 0..200 {
        frames.push(allocator.allocate(1).expect("allocate frame"));
    }

    // Every other frame, which is the worst case: no two holes are adjacent
    // and none of them coalesce.
    for index in (0..frames.len()).step_by(2) {
        assert!(
            allocator.deallocate(frames[index], 1),
            "a deallocation that answers false loses the frame"
        );
    }
    assert_eq!(allocator.free_range_count(), 100);

    for _ in 0..100 {
        assert!(allocator.allocate(1).is_some(), "every hole is reusable");
    }
    assert_eq!(allocator.free_frames(), 0);
}

#[test]
fn allocator_reuses_a_freed_frame_range() {
    let mut allocator = FrameAllocator::new();
    allocator.init(FRAME_SIZE * 16);

    let first = allocator.allocate(1).expect("allocate first frame") as usize;
    let second = allocator.allocate(1).expect("allocate second frame") as usize;

    assert!(allocator.deallocate(first as *mut u8, 1));
    let recycled = allocator.allocate(1).expect("reuse freed frame") as usize;

    assert_eq!(recycled, first);
    assert_ne!(recycled, second);
}

#[test]
fn allocator_coalesces_adjacent_freed_ranges() {
    let mut allocator = FrameAllocator::new();
    allocator.init(FRAME_SIZE * 16);

    let head = allocator.allocate(3).expect("allocate head") as usize;
    let tail = allocator.allocate(3).expect("allocate tail") as usize;

    assert_eq!(tail, head + 3 * FRAME_SIZE);
    assert!(allocator.deallocate(head as *mut u8, 3));
    assert!(allocator.deallocate(tail as *mut u8, 3));

    let merged = allocator.allocate(6).expect("allocate merged range") as usize;
    assert_eq!(merged, head);
}

#[test]
fn allocator_rejects_invalid_or_overlapping_deallocations() {
    let mut allocator = FrameAllocator::new();
    allocator.init(FRAME_SIZE * 8);

    let first = allocator.allocate(2).expect("allocate test range");
    assert!(!allocator.deallocate(core::ptr::null_mut(), 1));
    assert!(!allocator.deallocate((first as usize + 1) as *mut u8, 1));
    assert!(!allocator.deallocate(first, 0));
    assert!(!allocator.deallocate((first as usize + 4 * FRAME_SIZE) as *mut u8, 1));

    assert!(allocator.deallocate(first, 2));
    assert!(!allocator.deallocate(first, 1));
}

#[test]
fn allocator_rewinds_high_water_mark_after_tail_free() {
    let mut allocator = FrameAllocator::new();
    allocator.init(FRAME_SIZE * 8);

    let _head = allocator.allocate(2).expect("allocate head range") as usize;
    let tail = allocator.allocate(2).expect("allocate tail range") as usize;

    assert!(allocator.deallocate(tail as *mut u8, 2));
    let rewound = allocator.allocate(4).expect("allocate after tail rewind") as usize;

    assert_eq!(rewound, tail);
}

#[test]
fn allocator_zeroes_recycled_frames_before_reuse() {
    let mut allocator = FrameAllocator::new();
    allocator.init(FRAME_SIZE * 8);

    let frame = allocator.allocate(1).expect("allocate test frame");
    // SAFETY: a frame this allocator just handed out, one `FRAME_SIZE`
    // long; the test fills it to prove the reuse path zeroes it.
    unsafe {
        core::ptr::write_bytes(frame, 0xA5, FRAME_SIZE);
    }

    assert!(allocator.deallocate(frame, 1));
    let recycled = allocator.allocate(1).expect("reallocate test frame");
    assert_eq!(recycled as usize, frame as usize);

    // SAFETY: as the fill above: the frame is the one the allocator
    // returned and the slice covers exactly it.
    let bytes = unsafe { core::slice::from_raw_parts(recycled as *const u8, FRAME_SIZE) };
    assert!(bytes.iter().all(|byte| *byte == 0));
}

#[test]
fn allocator_tracks_more_than_legacy_free_range_capacity() {
    let mut allocator = FrameAllocator::new();
    allocator.init(FRAME_SIZE * 256);

    let mut frames = Vec::new();
    for _ in 0..140 {
        frames.push(allocator.allocate(1).expect("allocate frame"));
    }

    for index in (0..frames.len()).step_by(2) {
        assert!(allocator.deallocate(frames[index], 1));
    }

    for _ in 0..70 {
        assert!(allocator.allocate(1).is_some());
    }
}

#[test]
fn allocator_init_clamps_capacity_to_backing_pool_size() {
    let mut allocator = FrameAllocator::new();
    allocator.init(physical_pool_size() + FRAME_SIZE * 8);

    let max_frames = physical_pool_size() / FRAME_SIZE;
    for _ in 0..max_frames {
        assert!(allocator.allocate(1).is_some());
    }
    assert!(allocator.allocate(1).is_none());
}

// compaction / defragmentation

/// Helper: build a fragmented pool with `total` single frames, then free
/// every even-indexed frame so the free ranges interleave with live
/// frames.
fn fragmented_pool(total: usize) -> (FrameAllocator, Vec<*mut u8>) {
    let mut allocator = FrameAllocator::new();
    allocator.init(FRAME_SIZE * total);
    let mut frames = Vec::new();
    for _ in 0..total {
        frames.push(allocator.allocate(1).expect("allocate frame"));
    }
    for &frame in frames.iter().step_by(2) {
        assert!(allocator.deallocate(frame, 1));
    }
    (allocator, frames)
}

#[test]
fn compact_consolidates_fragmented_free_ranges_into_one_block() {
    let (mut allocator, frames) = fragmented_pool(10);

    // Before: 5 interleaved single-frame holes.
    assert_eq!(allocator.free_range_count(), 5);
    assert_eq!(allocator.largest_free_contiguous_frames(), 1);

    // The bitmap is the caller's, because the allocator must work before
    // the heap and one bit per frame cannot live in its own struct.
    let moved = allocator.compact(|_, _| true);
    assert_eq!(moved, 5); // the 5 live frames moved into the 5 holes

    // After: a single contiguous 5-frame free block at the tail.
    assert_eq!(allocator.free_range_count(), 1);
    assert_eq!(allocator.largest_free_contiguous_frames(), 5);

    // The freed tail now satisfies a 5-frame allocation.
    assert!(allocator.allocate(5).is_some());
    // Keep `frames` alive for the duration of the test (borrow semantics).
    let _ = &frames;
}

#[test]
fn compact_moves_contents_and_reports_address_pairs() {
    let (mut allocator, _frames) = fragmented_pool(6);
    // Fragmented: live at {1,3,5}, holes at {0,2,4}.
    let mut moves: Vec<(usize, usize)> = Vec::new();
    let moved = allocator.compact(|old_addr, new_addr| {
        moves.push((old_addr, new_addr));
        true
    });
    assert_eq!(moved, 3); // frames 1, 3, 5 move down into holes 0, 1, 2
    // Every move relocates a frame strictly downward.
    assert!(moves.iter().all(|(old, new)| old > new));
    assert_eq!(allocator.largest_free_contiguous_frames(), 3);
}

#[test]
fn compact_preserves_content_of_moved_frames() {
    // Use a high sub-range of the shared backing pool (64 MiB in) so
    // parallel frame tests allocating from the front of the pool cannot
    // clobber the patterns written here.
    const BASE_FRAME: usize = 1 << 14;
    let mut allocator = FrameAllocator::new();
    allocator.set_node_range(0, BASE_FRAME, BASE_FRAME + 16);
    let mut frames = Vec::new();
    for _ in 0..16 {
        frames.push(allocator.allocate(1).expect("allocate frame"));
    }
    for &frame in frames.iter().step_by(2) {
        assert!(allocator.deallocate(frame, 1));
    }

    // Write a distinctive pattern into every frame so we can verify the
    // live frames' contents survive the move.  Frames 1, 3, .., 15 are
    // live (evens were freed); each holds value (index + 1).
    let base = allocator.base;
    for (i, &_frame) in frames.iter().enumerate() {
        // SAFETY: `base` is the pool's start and `i` indexes frames this
        // allocator handed out, so the range is inside the pool.
        unsafe {
            core::ptr::write_bytes(
                (base + i * FRAME_SIZE) as *mut u8,
                (i + 1) as u8,
                FRAME_SIZE,
            );
        }
    }
    let moved = allocator.compact(|_, _| true);
    assert_eq!(moved, 8);

    // After compaction the live frames occupy slots 0..8, contents must
    // match the original frames 1, 3, .., 15 (values 2, 4, .., 16).
    let expected: Vec<u8> = (0..8).map(|k| ((k * 2) + 2) as u8).collect();
    for (slot, &value) in expected.iter().enumerate() {
        let frame_base = base + slot * FRAME_SIZE;
        // SAFETY: as above, for a frame the compaction left in place; the
        // slice covers one whole frame.
        let bytes = unsafe { core::slice::from_raw_parts(frame_base as *const u8, FRAME_SIZE) };
        assert!(
            bytes.iter().all(|&b| b == value),
            "compacted frame {slot} should hold original value {value}"
        );
    }
}

#[test]
fn compact_stops_at_immovable_frame() {
    let (mut allocator, _frames) = fragmented_pool(6);
    // Refuse the very first move: nothing should be relocated and the
    // free ranges must stay untouched.
    let moved = allocator.compact(|_, _| false);
    assert_eq!(moved, 0);
    assert_eq!(allocator.free_range_count(), 3);
}

#[test]
fn compact_is_idempotent_on_already_compacted_pool() {
    let mut allocator = FrameAllocator::new();
    allocator.init(FRAME_SIZE * 8);
    let head = allocator.allocate(2).expect("allocate head");
    let tail = allocator.allocate(3).expect("allocate tail");
    assert!(allocator.deallocate(tail, 3));

    // Freeing the exact tail rewinds the high-water mark, so the whole
    // remaining pool is one contiguous free block above `next_frame`.
    assert_eq!(allocator.free_range_count(), 0);
    let moved = allocator.compact(|_, _| true);
    assert_eq!(moved, 0);
    assert_eq!(allocator.largest_free_contiguous_frames(), 6);
    // head/tail handles keep their allocations valid for this test scope.
    let _ = (head, tail);
}
