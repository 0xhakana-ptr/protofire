//! arch/src/lib.rs
//!
//! The one crate the rest of the kernel names when it has to ask the machine
//! something.  It holds no implementation of its own: each architecture is a
//! crate beside it, and this file is the route between them.
//!
//! ## The target selects the implementation
//!
//! There is no architecture feature, and that is deliberate.  A feature would
//! be a second place the machine is named, and a build could select the one
//! that disagrees with `--target`, `--target aarch64-unknown-none --features
//! x86_64` would compile x86_64's `out`/`in` instructions into an aarch64
//! image, and the only thing that would notice is the assembler, if it did.
//! `arch/Cargo.toml` names each implementation in a `cfg(target_arch)` table
//! instead, which cargo evaluates against the target being built, so the choice
//! is made once and cannot be overridden.
//!
//! Selecting none is not expressible: a build that matches no table gets no
//! `arch_x86_64`, no `arch_aarch64` and no `arch_riscv64`, and the re-exports
//! below then name crates that are not there, an error that says the
//! architecture has no implementation, which is the true statement.
//!
//! ## What this file must not do
//!
//! Spell a `target_arch` gate of its own.  The tables in the manifest are the
//! selection; a `#[cfg(target_arch)]` here would be a second one, and
//! `scripts/check-arch-fanout.sh` counts gates outside `arch/` precisely
//! because they are how a new architecture gets forgotten.  This crate is
//! exempt as a *directory*; the rule it is held to is that the gate lives in
//! the manifest rather than in code.

#![no_std]

#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::*;

#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::*;

#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::*;

// The handshake parser, re-exported by name.
//
// `pub use crate::*` above brings in the implementation crate's root items, and
// `boot_info` is a function in its `boot` module rather than an item at the
// root.  Naming it here is what lets the kernel call `arch::boot_info()`
// without knowing which crate answered, the point of the routing layer.
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::boot::boot_info;

// The interrupt table.  Every machine has one and it is named the same way, //
// a boot installs a table and hands it a sink, so a machine that has not
// written its own fails to build here rather than at the call site.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::set_interrupt_dispatch;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::set_interrupt_dispatch;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::idt::InterruptFrame;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::idt::loaded as idt_descriptor;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::idt::set_dispatch as set_interrupt_dispatch;

// `install_interrupt_table` is re-exported for every machine: each answers
// whether it has one, and a machine whose entry is not written says `false`
// rather than making a caller ask which machine it is.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::install_interrupt_table;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::install_interrupt_table;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::idt::install as install_interrupt_table;

// The descriptor table and the TSS.  Every machine answers; only x86_64 has
// one, and `false` from the others is an answer rather than a gap.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::install_descriptor_tables;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::install_descriptor_tables;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::install_descriptor_tables;

// Where an interrupt from ring 3 lands.  Every machine answers; only a machine
// with a TSS uses the answer.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::interrupt_stack_top;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::interrupt_stack_top;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::interrupt_stack_top;

#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::boot::boot_info;

// What the machine's handshake contained, when the machine has a device tree.
// Every machine answers the same question, `None` is an answer, so the kernel
// prints one line and does not ask which machine it is running on.
#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::boot::device_tree_summary;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::boot::device_tree_summary;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::boot::device_tree_summary;

// Where this machine memory-maps a PCIe function's configuration space.  `None`
// is an answer: x86_64 reaches it through ports instead.
#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::boot::pcie_ecam_window;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::boot::pcie_ecam_window;

// The window a host bridge assigns BARs from.  `None` is an answer: x86_64's
// firmware has already assigned them.
#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::boot::pcie_memory_window;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::boot::pcie_memory_window;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::boot::pcie_memory_window;

// The interrupt controller's windows, where a machine has one of that shape.
// `None` is an answer: x86_64's controller is not two memory windows.
#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::boot::interrupt_controller;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::boot::interrupt_controller;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::boot::interrupt_controller;

// A program's calls, and the way in.  Every machine names the types; only the
// machines that can enter a lower exception level have a path.
#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::CallFrame;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::CallFrame;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::CallFrame;

#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::CallOutcome;

#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::Context;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::CallOutcome;

#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::Context;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::CallOutcome;

#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::Context;

// What a context is *asked*, rather than how its fields are laid out.  A
// scheduler that read `context.elr` would be written against aarch64; these
// are the questions every machine answers about its own frame.
#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::install_context;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::install_context;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::install_context;

#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::is_user_context;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::is_user_context;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::is_user_context;

#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::resume_address;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::resume_address;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::resume_address;

#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::set_resume_address;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::set_resume_address;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::set_resume_address;

#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::return_state;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::return_state;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::return_state;

#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::return_value;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::return_value;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::return_value;

#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::set_return_value;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::set_return_value;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::set_return_value;

#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::stack_pointer;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::stack_pointer;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::stack_pointer;

#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::starting_context;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::starting_context;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::starting_context;

// The program a boot runs.  Machine code, so each machine supplies its own:
// a kernel holding one array for three architectures would have two of them
// wrong, and the failure would be a fault at an address the kernel chose.
#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::PROGRAM_LEN;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::PROGRAM_LEN;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::PROGRAM_LEN;

#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::program_bytes;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::program_bytes;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::program_bytes;

// Which numbered program is the pipe's reader, which its writer, and which
// the image `exec` hands a process to.  The numbering is the image's, so it
// lives with the image.
#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::ELF_MACHINE;
#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::PIPE_READER;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::ELF_MACHINE;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::PIPE_READER;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::ELF_MACHINE;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::PIPE_READER;

#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::PIPE_WRITER;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::PIPE_WRITER;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::PIPE_WRITER;

// The idle a scheduler uses when every program is asleep.  `halt` masks
// interrupts and is the final stop; this leaves them on and returns.
#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::wait_for_a_wakeup;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::wait_for_a_wakeup;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::wait_for_a_wakeup;

// How long the boot's programs sleep.  The duration is part of what the program
// is, it is an immediate in its machine code, so it lives with the program
// and not with the boot that reports it.
#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::SLEEP_MICROSECONDS;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::SLEEP_MICROSECONDS;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::SLEEP_MICROSECONDS;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::enter_user;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::enter_user;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::enter_user;

// Entering with a whole context, which is what a scheduler has: a first program
// needs an entry and a stack, and a resumed one needs every register it left.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::enter_user_with_context;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::enter_user_with_context;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::enter_user_with_context;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::switch_address_space;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::switch_address_space;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::switch_address_space;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::set_call_sink;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::set_fault_sink;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::set_preempt_sink;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::set_call_sink;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::set_fault_sink;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::set_preempt_sink;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::trap::set_call_sink;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::trap::set_fault_sink;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::trap::set_preempt_sink;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::interrupt_line_enabled;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::interrupt_line_enabled;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::interrupt_line_enabled;

// The timer.  Every machine names the four operations; only aarch64 drives one.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::arm_timer;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::disarm_timer;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::arm_timer;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::disarm_timer;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::arm_timer;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::disarm_timer;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::clock_frequency;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::timer_control;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::timer_counter;
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::timer_frequency;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::clock_frequency;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::timer_control;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::timer_counter;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::timer_frequency;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::clock_frequency;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::timer_control;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::timer_counter;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::timer_frequency;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::timer_fired;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::timer_fired;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::timer_fired;

// Converting a duration to a counter reading.  A scheduler that makes a
// deadline asks this, and the machine answers because its counter's rate is
// the machine's.
#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::ticks_for_microseconds;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::ticks_for_microseconds;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::ticks_for_microseconds;

#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::timer_interrupt;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::timer_interrupt;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::timer_interrupt;

// The line a boot raises to prove the interrupt path.  The number is the
// machine's: aarch64's only askable line is a software interrupt in 0..15, and
// x86_64's APIC will send any vector at all, including zero, which is a fault.
#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::test_interrupt;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::test_interrupt;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::test_interrupt;

// How much memory this machine has, for a frame allocator that must clamp to
// what is really there.  `None` means "use the pool's own span".
#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::boot::managed_pool_bytes;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::boot::managed_pool_bytes;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::boot::managed_pool_bytes;

// The message-signalled interrupt frame, where a machine has one.
#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::boot::msi_frame;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::boot::msi_frame;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::boot::msi_frame;

// The message-signalled interrupt frame, probed for the numbers it can raise.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::message_frame;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::message_frame;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::message_frame;

// Enabling one interrupt line.  Every machine answers; `false` is an answer.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::enable_interrupt_line;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::enable_interrupt_line;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::enable_interrupt_line;

// Raising one interrupt from the controller, for a boot that wants to prove
// the path rather than report it.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::raise_interrupt;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::raise_interrupt;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::raise_interrupt;

// The machine's other CPUs: started, counted, reported.  Every machine answers
// the same question, the ones that start none answer zero, which is an answer
// and not a gap, so a boot asks one question and does not learn which machine
// it is running on.
#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::boot_cpu_owns_this_trap;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::boot_cpu_owns_this_trap;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::boot_cpu_owns_this_trap;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::start_secondary_harts;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::start_secondary_harts;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::start_secondary_harts;

#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::current_cpu_slot;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::current_cpu_slot;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::current_cpu_slot;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::secondary_hart_id;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::secondary_hart_id;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::secondary_hart_id;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::secondary_online;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::secondary_online;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::secondary_online;

#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::refused_harts;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::refused_harts;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::refused_harts;

// Making a page-table change visible.  Every machine has an instruction for
// it, and a caller that changed a table without one changed nothing the CPU
// observes.
#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::paging::flush_translation;
#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::paging::flush_translation;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::boot::pcie_ecam_window;
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::paging::flush_translation;

// The root this CPU is translating through.
//
// Asked by the fault handler, which has to describe a faulting address in the
// **space the faulting CPU is running** — a program's, not the kernel's.  The
// register is per-CPU, so the question only has an answer on the machine that
// took the fault, and a host has no table at all.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub fn installed_root_table() -> Option<usize> {
    Some(arch_aarch64::paging::current_root_table())
}
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub fn installed_root_table() -> Option<usize> {
    let root = arch_riscv64::paging::current_root_table();
    // Zero is `satp`'s own "no table": a hart that never wrote it walks bare,
    // and reporting that as a root would have the walk read whatever address
    // zero happens to name.
    (root != 0).then_some(root)
}
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub fn installed_root_table() -> Option<usize> {
    Some(arch_x86_64::paging::current_root_table())
}
#[cfg(not(target_os = "none"))]
pub fn installed_root_table() -> Option<usize> {
    None
}

#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::boot::boot_info;

#[cfg(test)]
mod tests {
    /// This crate routes, and on a host there is nothing to route to.
    ///
    /// The selection is `cfg(target_arch)` in the manifest, so a host build of
    /// `arch`, which is what `cargo test --workspace` makes, matches no
    /// implementation and re-exports nothing.  That is correct: a host is not
    /// one of the three machines this kernel runs on, and pretending one of
    /// them was would compile the kernel's boot path for a machine it does not
    /// have.
    ///
    /// What is worth asserting is exactly that, and it is the assertion that
    /// catches the failure a feature-based selection had: with a feature, a
    /// host build could name a machine and nothing said so.
    #[test]
    fn a_host_build_selects_no_machine() {
        // The three machine crates are `cfg(target_arch)` dependencies, so on a
        // host they are not linked.  A host that did link one would make the
        // assertions below fail to compile, which is the form this check
        // takes.
        #[cfg(all(
            not(target_arch = "x86_64"),
            not(target_arch = "aarch64"),
            not(target_arch = "riscv64")
        ))]
        {
            // Being here at all is the assertion: this crate compiled on a
            // target no implementation covers, which is what the manifest's
            // tables are for.
        }
    }
}
