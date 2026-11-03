//! arch/x86_64/src/lib.rs
//!
//! The x86_64 machine: what the kernel asks it, and nothing else.
//!
//! Everything here is a fact about this architecture — a port, an instruction,
//! a register — and none of it may be spelled outside this crate.  The test is
//! mechanical: a `#[cfg(target_arch = ...)]` anywhere else in the tree is a
//! question this crate should answer instead.

#![no_std]

// The host arm of the console records bytes instead of writing a port.
#[cfg(not(target_os = "none"))]
extern crate alloc;

pub mod boot;
pub mod idt;
pub mod interrupts;
pub mod paging;
pub mod pic;

// The entry encoding, re-exported by name: `kernel::address_space` builds a
// mapping and asks the machine how to write it down, and asking through `arch`
// is what keeps the answer a machine's business.
pub use paging::install;

// The interrupt table, by name: the kernel installs one and hands it a sink,
// and both are this crate's decisions about the machine.  Bare-metal only: a
// host has no IDT to load and no vector to take, and the types are gated the
// same way for the same reason.
#[cfg(target_os = "none")]
pub use idt::InterruptFrame;
#[cfg(target_os = "none")]
pub use idt::install as install_interrupt_table;
#[cfg(target_os = "none")]
pub use idt::loaded as idt_descriptor;
#[cfg(target_os = "none")]
pub use idt::set_dispatch as set_interrupt_dispatch;

pub mod port;
pub mod serial;

// The machine's entry, assembled from `src/boot-x86-64.S`.
//
// It is here rather than in `bootloader` because everything in it is a fact
// about this architecture: the multiboot2 header's checksum, the PVH note's
// type, the identity map's page-table layout, the GDT's descriptor bits.  A
// machine that entered differently writes its own file and `bootloader` does
// not change.
//
// `bootloader` supplies the symbol it calls.  The direction is a link-time
// reference rather than a crate dependency, because `arch` sits below
// `bootloader` and an upward `use` is the edge this tree's layering forbids.
#[cfg(target_os = "none")]
core::arch::global_asm!(include_str!("boot-x86-64.S"));

/// Stop this CPU until an interrupt arrives.
///
/// Interrupts are disabled first, so this does not return unless something
/// enables them; every caller in the kernel treats it as a final stop.
pub fn halt() -> ! {
    loop {
        // SAFETY: `cli` clears the interrupt flag and `hlt` stops the core
        // until an interrupt is pending.  With the flag clear there is none to
        // take, so the pair cannot leave this loop.
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}

/// Enable one of the machine's interrupt lines.
///
/// False: this machine has no controller this crate drives yet.  The function
/// exists on every machine so a driver asks one question, and `false` is an
/// answer a caller reports rather than a gap it works around.
///
/// # Safety
///
/// As the aarch64 arm: after [`install_interrupt_table`], once per line.
#[cfg(target_os = "none")]
pub unsafe fn enable_interrupt_line(number: usize) -> bool {
    let _ = number;
    false
}

/// Raise one interrupt from the controller: this machine has none to raise.
///
/// False, as [`enable_interrupt_line`] is — the machine has no controller this
/// crate drives, so there is nothing to ask.
///
/// # Safety
///
/// As the aarch64 arm.
#[cfg(target_os = "none")]
pub unsafe fn raise_interrupt(number: usize) -> bool {
    let _ = number;
    false
}

/// The machine's message-signalled interrupt frame: none this crate drives.
///
/// # Safety
///
/// As the aarch64 arm.
#[cfg(target_os = "none")]
pub unsafe fn message_frame() -> Option<()> {
    None
}

/// What a supervisor call's handler answers.
///
/// Shared shape with the aarch64 crate so the kernel names one type: a machine
/// without an entry still has to answer what a call would mean, and
/// `unreachable` in `enter_user` is what makes the answer untested rather than
/// wrong.
#[derive(Debug, Clone, Copy)]
pub struct CallFrame {
    /// The number the program put in its syscall register.
    pub number: usize,
    /// The six arguments.
    pub arguments: [usize; 6],
    /// Where the program resumes.
    pub resume: usize,
}

/// What a call's handler answers.
#[derive(Debug, Clone, Copy)]
pub enum CallOutcome {
    /// Resume the program with this value.
    Return(usize),
    /// The program has ended.  The handler has already chosen what runs next.
    Exit,
}

/// The function a supervisor call is handed to.
#[cfg(target_os = "none")]
pub type CallSink = fn(CallFrame, &mut Context) -> CallOutcome;

/// Install the function that serves a program's supervisor call: no-op here.
///
/// # Safety
///
/// As the aarch64 arm: once, before any program can run.
#[cfg(target_os = "none")]
pub unsafe fn set_call_sink(sink: CallSink) {
    let _ = sink;
}

/// Enter ring 3: this machine has no path yet.
///
/// The pieces exist — ring 3 needs a TSS with an RSP0, a user-accessible GDT
/// segment, and a gate with DPL 3, and `idt.rs` installs every gate at DPL 0
/// because nothing has ever entered ring 3 on this machine.  Declaring this
/// `unreachable` rather than stopping the machine is the honest thing: a caller
/// that reached it would be a caller whose boot assumed a capability this crate
/// does not have.
///
/// # Safety
///
/// As the aarch64 arm.
#[cfg(target_os = "none")]
pub unsafe fn enter_user(_entry: usize, _stack_top: usize) -> ! {
    unreachable!("ring 3 is not implemented on x86_64 yet")
}

/// Translate through a different root table: this machine has no such path yet.
///
/// x86_64's equivalent is a `cr3` write, which this crate does have for
/// installation and does not yet have for switching; riscv64's is `satp`.  Both
/// need a per-process root to switch to, which is what the kernel builds for
/// the machine that has one.
///
/// # Safety
///
/// As the aarch64 arm.
#[cfg(target_os = "none")]
pub unsafe fn switch_address_space(_root: usize) -> bool {
    false
}

/// A program's saved context.
///
/// The machine's own trap frame, which this crate does not have: a task switch
/// copies one of these into the frame the trap path restores, and this machine
/// has no such path yet.  The type exists so the scheduler names one thing on
/// every machine.
///
/// It is the aarch64 frame's shape because that is the one written; a real
/// frame here would be the registers an interrupt from ring 3 pushed.
#[derive(Debug, Clone, Copy, Default)]
pub struct Context {
    /// The general registers.
    pub registers: [u64; 30],
    /// The link register.
    pub link_register: u64,
    /// Where to resume.
    pub elr: u64,
    /// The state to resume in.
    pub spsr: u64,
    /// The syndrome.
    pub esr: u64,
    /// The fault address.
    pub far: u64,
    /// The vector.
    pub vector: u64,
    /// The SIMD registers.
    pub simd: [u128; 32],
}
