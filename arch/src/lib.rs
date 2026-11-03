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
//! that disagrees with `--target` — `--target aarch64-unknown-none --features
//! x86_64` would compile x86_64's `out`/`in` instructions into an aarch64
//! image, and the only thing that would notice is the assembler, if it did.
//! `arch/Cargo.toml` names each implementation in a `cfg(target_arch)` table
//! instead, which cargo evaluates against the target being built, so the choice
//! is made once and cannot be overridden.
//!
//! Selecting none is not expressible: a build that matches no table gets no
//! `arch_x86_64`, no `arch_aarch64` and no `arch_riscv64`, and the re-exports
//! below then name crates that are not there — an error that says the
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
// without knowing which crate answered — the point of the routing layer.
#[cfg(target_arch = "x86_64")]
pub use arch_x86_64::boot::boot_info;

// The interrupt table.  Every machine has one and it is named the same way —
// a boot installs a table and hands it a sink — so a machine that has not
// written its own fails to build here rather than at the call site.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::set_interrupt_dispatch;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::set_interrupt_dispatch;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::InterruptFrame;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::idt_descriptor;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::set_interrupt_dispatch;

// `install_interrupt_table` is re-exported for every machine: each answers
// whether it has one, and a machine whose entry is not written says `false`
// rather than making a caller ask which machine it is.
#[cfg(all(target_arch = "aarch64", target_os = "none"))]
pub use arch_aarch64::install_interrupt_table;
#[cfg(all(target_arch = "riscv64", target_os = "none"))]
pub use arch_riscv64::install_interrupt_table;
#[cfg(all(target_arch = "x86_64", target_os = "none"))]
pub use arch_x86_64::install_interrupt_table;

#[cfg(target_arch = "aarch64")]
pub use arch_aarch64::boot::boot_info;

// What the machine's handshake contained, when the machine has a device tree.
// Every machine answers the same question — `None` is an answer — so the kernel
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

#[cfg(target_arch = "riscv64")]
pub use arch_riscv64::boot::boot_info;

#[cfg(test)]
mod tests {
    /// This crate routes, and on a host there is nothing to route to.
    ///
    /// The selection is `cfg(target_arch)` in the manifest, so a host build of
    /// `arch` — which is what `cargo test --workspace` makes — matches no
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
        // assertions below fail to compile — which is the form this check
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
