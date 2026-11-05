//! kernel/src/console.rs
//!
//! What the boot says about the machine it arrived on, and the one sink the
//! allocator reports through.
//!
//! ## Why the allocator's sink lives here
//!
//! `allocator::diag::set_writer` takes a `fn(&str)`, and the function has to
//! write the console and allocate nothing, it is called from inside a failed
//! allocation.  That is a fact about the console, not about the allocator, and
//! keeping it beside the lines that report the handshake means a reader looking
//! for "what does this boot print at startup" finds one file.

/// Write one line of allocator diagnostics to the console.
///
/// A free function rather than a closure because `set_writer` takes a `fn`, and
/// because this is the one place the allocator's output and the machine's
/// console are joined, naming it makes that join visible in a search.
pub fn write_to_console(text: &str) {
    arch::serial::write_str(text);
    arch::serial::write_str("\n");
}

/// Report what the machine's handshake actually contained.
///
/// A device-tree machine puts a pointer in a register and the pointer may name
/// anything: firmware that handed over something unauthoritative, a loader that
/// cleared the register, a blob whose header disagrees with its bytes.  So the
/// answer is a line rather than an assumption, and it is the line that says
/// whether the console's address, the memory map and the boot's device windows
/// came from a tree or from a fallback.
pub fn report_handshake() {
    arch::serial::write_str("protofire: device tree ");
    match arch::device_tree_summary() {
        Some(summary) => {
            arch::serial::write_str("v");
            arch::serial::write_u32(summary.version);
            arch::serial::write_str(", ");
            arch::serial::write_u32(summary.memory_regions);
            arch::serial::write_str(" memory region(s), uart at ");
            arch::serial::write_hex(summary.uart as u64);
        }
        None => arch::serial::write_str("not handed over (using this machine's constants)"),
    }
    arch::serial::write_str("\n");
}
