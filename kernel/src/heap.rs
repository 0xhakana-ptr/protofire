//! kernel/src/heap.rs
//!
//! The heap: bringing it up and saying where it is.
//!
//! ## Why the boot has to say where it is
//!
//! The line is not decoration and it is not a probe left behind.  `bounds()` is
//! what makes the allocator lay out its free lists, so a boot that did not call
//! it would hand out memory from a heap with no free list at all — the line is
//! how that arrangement becomes observable.  And the allocator's diagnostic
//! sink and this line are the same path, so reaching the line is what proves
//! the sink reaches the console.

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
