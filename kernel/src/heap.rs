//! kernel/src/heap.rs
//!
//! The heap: bringing it up, saying where it is, and checking it once the boot
//! has carved it.
//!
//! ## Why the boot has to say where it is
//!
//! The line is not decoration and it is not a probe left behind.  `bounds()` is
//! what makes the allocator lay out its free lists, so a boot that did not call
//! it would hand out memory from a heap with no free list at all, the line is
//! how that arrangement becomes observable.  And the allocator's diagnostic
//! sink and this line are the same path, so reaching the line is what proves
//! the sink reaches the console.
//!
//! ## Why the boot checks the heap again later, and why that line exists
//!
//! A check that reads an allocator nothing allocates from passes forever.  This
//! tree shipped exactly that: `verify_kernel_heap` reached a second
//! `KernelGlobalAllocator`, the free lists were a field of it, and the kernel's
//! `#[global_allocator]` was a third view, so the check compared the arena
//! against a record that still said "one free block" and reported a used block
//! as damage.  The state is a `static` now, so a handle cannot hold a copy of
//! it, and the number on this line is how a reader sees that with one boot: a
//! check reading a second instance would print the whole arena free after the
//! mount had carved a great deal of it.
//!
//! The line is debug-only because the check is.  `verify_heap_integrity` is a
//! no-op without debug assertions, and a boot that printed "checked" from a
//! build that never looked would be the same class of claim this gate exists to
//! refuse.

/// Initialise the heap and report its bounds.
pub fn bring_up() {
    let heap = allocator::HeapAllocator::new();
    let (heap_start, heap_end) = heap.bounds();
    arch::serial::write_str("protofire: heap at ");
    arch::serial::write_hex(heap_start as u64);
    arch::serial::write_str("..");
    arch::serial::write_hex(heap_end as u64);
    arch::serial::write_str("\n");
}

/// Walk the heap after the mount, and say whether the walk saw a carved heap.
///
/// The mount is where the kernel first allocates in volume: images, devices,
/// namespace entries and the copies the filesystem makes of them.  A checker
/// reading a stale second view of the arena would survive every earlier point
/// in the boot, because before the mount both views say the same thing.  Here
/// they cannot, so here is where the check has to run.
///
/// The line states the **verdict** and not the byte count.  A count moves with
/// the allocation sequence, so a gate that required it whole would break on any
/// change to an unrelated allocation, which is a gate reporting a refactor as a
/// defect.  The verdict is the claim that does not move: a handle reading a
/// second view would report the arena untouched.
///
/// The two outcomes start with different words on purpose.  The gate requires
/// the prefix `... after mount, carved `, and the failure branch does not begin
/// with it, so a boot that regressed cannot satisfy the requirement with the
/// sentence that reports the regression.
///
/// Panics on the first defect, through the allocator's own invariant, which is
/// what makes the line's absence a failure rather than a missing observation.
#[cfg(debug_assertions)]
pub fn check_after_mount() {
    allocator::verify_kernel_heap();
    let heap = allocator::HeapAllocator::new();
    let (heap_start, heap_end) = heap.bounds();
    let remaining = heap.remaining();
    let carved = (heap_end - heap_start).saturating_sub(remaining);
    if carved == 0 {
        // Two allocators over one arena produce exactly this: the checker's
        // view was never asked for memory, so it still describes the whole
        // range as free.  Failing here names the defect at its own line rather
        // than leaving a later allocation to trip over it.
        arch::serial::write_str(
            "protofire: heap check after mount saw an UNTOUCHED heap, so it is reading a second view\n",
        );
        panic!("check_after_mount: the heap a check reads is not the heap that allocates");
    }
    arch::serial::write_str("protofire: heap checked after mount, carved ");
    arch::serial::write_hex(carved as u64);
    arch::serial::write_str(" byte(s), and the free lists agree\n");
}
