//! memory/src/slot_pool/tests.rs
//!
//! The slot pool: allocation under pressure, the free list, and the exhaustion
//! that refuses rather than wraps.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

use crate::slot_pool::SlotPool;

/// A fresh pool hands out every region once, then refuses.
#[test]
fn a_pool_hands_out_each_region_once() {
    let pool: SlotPool<4> = SlotPool::new();
    let mut seen = [false; 4];
    for _ in 0..4 {
        let index = pool.claim().expect("a free region");
        assert!(!seen[index], "region {index} was handed out twice");
        seen[index] = true;
        assert!(pool.is_taken(index));
        assert_eq!(pool.holders(index), 1);
    }
    assert!(pool.claim().is_none(), "an empty pool must refuse");
}

/// A region with two holders survives the first one's release.
///
/// This is the fork case, and the defect it exists for: releasing on the
/// first drop hands a live process's pages to the next claim.
#[test]
fn a_shared_region_survives_until_the_last_holder_drops() {
    let pool: SlotPool<4> = SlotPool::new();
    let index = pool.claim().expect("a free region");
    pool.retain(index);
    assert_eq!(pool.holders(index), 2);

    pool.release(index);
    assert!(
        pool.is_taken(index),
        "the region was released while a second holder still mapped it"
    );
    assert_eq!(pool.holders(index), 1);

    pool.release(index);
    assert!(!pool.is_taken(index), "the last drop must free the region");
    assert_eq!(pool.holders(index), 0);
}

/// A claimed region is handed out again only after every holder dropped.
#[test]
fn a_shared_region_is_not_reused_while_it_is_still_held() {
    let pool: SlotPool<2> = SlotPool::new();
    let first = pool.claim().expect("a free region");
    let second = pool.claim().expect("a free region");
    pool.retain(first);

    // The pool is full, and one of the two is shared, so nothing is free.
    assert!(pool.claim().is_none());

    pool.release(first);
    assert!(pool.claim().is_none(), "one holder is still mapping it");

    pool.release(first);
    assert!(
        pool.claim().is_some(),
        "the region must come back once both holders dropped"
    );

    pool.release(second);
}

/// A reused region starts its count from one, not from the old one.
///
/// The claim `store`s rather than adding, because the bitmap already says
/// no other holder exists; an add would carry a previous generation's
/// count into this one and the region would never be freed.
#[test]
fn a_reused_region_starts_its_count_over() {
    let pool: SlotPool<1> = SlotPool::new();
    let index = pool.claim().expect("a free region");
    pool.retain(index);
    pool.retain(index);
    assert_eq!(pool.holders(index), 3);

    pool.release(index);
    pool.release(index);
    pool.release(index);
    assert_eq!(pool.holders(index), 0);

    let again = pool.claim().expect("the region must be free again");
    assert_eq!(again, index);
    assert_eq!(pool.holders(again), 1, "the count restarts at one");
}

/// An index outside the pool is ignored rather than panicking.
#[test]
fn an_index_past_the_end_is_ignored() {
    let pool: SlotPool<2> = SlotPool::new();
    pool.retain(9);
    pool.release(9);
    assert!(!pool.is_taken(9));
    assert_eq!(pool.holders(9), 0);
}
