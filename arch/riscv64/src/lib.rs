//! arch/riscv64/src/lib.rs
//!
//! The riscv64 machine, as far as the kernel can ask it anything today.
//!
//! This crate is a sibling of `arch/x86_64` and `arch/aarch64` and shares no
//! code with either: what they share is the *names* the kernel calls, which is
//! the whole interface.

#![no_std]

// The host arm of the console records bytes instead of writing a port.
#[cfg(not(target_os = "none"))]
extern crate alloc;

// No crate-level `cfg(target_arch)` gate, and its absence is the point.
//
// The first version of this file had one, so that `cargo build --workspace` —
// which builds every member for the host — would not try to assemble `wfi` into
// an x86 binary.  What that also did was make the whole crate empty on a host,
// including the tests: `cargo test -p arch_aarch64` reported zero, and every
// assertion in `interrupts.rs` was dead code that had never been compiled.
//
// A gate that silences a build by removing the code is the wrong tool.  Each
// module keeps its own `cfg(target_os)` arms — a host has no `DAIF` and no
// `wfi`, so those arms are no-ops that a test can still run — and the crate
// stays compilable everywhere it is named.

pub mod boot;
pub mod interrupts;
pub mod paging;
pub mod port;
pub mod serial;
pub mod stvec;

/// Stop this CPU until an interrupt arrives.
///
/// `wfi` in S-mode waits for an interrupt.  The loop is what makes the function
/// `-> !`: a stop that returned would fall into whatever follows, and there is
/// nothing after a stop.
#[cfg(target_os = "none")]
pub fn halt() -> ! {
    loop {
        // SAFETY: `wfi` is the wait-for-interrupt hint.  `sstatus.SIE` is clear
        // on every path that reaches here, so no interrupt is taken and the
        // loop does not exit.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
    }
}

/// The host build's stop: end the process, because a host has no hart to idle.
#[cfg(not(target_os = "none"))]
pub fn halt() -> ! {
    panic!("halt() called on a host: this is the kernel's stop, not a test's")
}

/// Install the trap vector.
///
/// Returns whether one was installed.  This machine has the vector's shape —
/// `stvec::Cause` splits a `scause` into its flag and code, and that is tested
/// — and not yet the entry: the boot assembly does not branch into a Rust trap
/// handler, so a `stvec` naming an unfilled vector would be a register pointing
/// at nothing.
///
/// So it answers `false`, and the boot says so.
/// # Safety
///
/// A machine with an entry would make a register name an address here; this
/// one has none, and the promise is kept by doing nothing.  The signature is
/// unsafe on every machine so that the caller reads one contract.
#[cfg(target_os = "none")]
pub unsafe fn install_interrupt_table() -> bool {
    false
}

/// Install the sink a trap frame goes to.
///
/// A machine with no trap entry has nothing to hand a frame to, so this records
/// nothing and says nothing: the sink is installed by a machine that can call
/// one, and [`install_interrupt_table`] is what reports whether that is this
/// one.
///
/// # Safety
///
/// The caller promises to call this once, before any vector can be raised.  A
/// machine that cannot raise one keeps that promise trivially.
#[cfg(target_os = "none")]
pub unsafe fn set_interrupt_dispatch(sink: fn(irq::Frame) -> bool) {
    let _ = sink;
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

/// Enter U-mode: this machine has no boot and no path.
///
/// U-mode needs a `sstatus.SPP` clear, an `sepc`, and a trap entry at `stvec`;
/// this crate has the last of the three and neither of the others, because
/// nothing has entered it.
///
/// # Safety
///
/// As the aarch64 arm.
#[cfg(target_os = "none")]
pub unsafe fn enter_user(_entry: usize, _stack_top: usize) -> ! {
    unreachable!("U-mode is not implemented on riscv64 yet")
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

/// The timer's frequency: this machine's timer is not driven yet.
///
/// x86_64's is the local APIC's, programmed through the APIC's timer divide and
/// initial-count registers; riscv64's is `time`/`stimecmp`.  Neither is wired,
/// so `None` is the honest answer — and a caller treats it as "no timer" rather
/// than as a frequency of zero.
///
/// # Safety
///
/// As the aarch64 arm.
#[cfg(target_os = "none")]
pub unsafe fn timer_frequency() -> Option<u64> {
    None
}

/// Arm the timer: this machine's timer is not driven yet.
///
/// # Safety
///
/// As the aarch64 arm.
#[cfg(target_os = "none")]
pub unsafe fn arm_timer(_frequency: u64, _milliseconds: u64) -> u64 {
    0
}

/// Whether the timer has fired: it has not, because it is not armed.
///
/// # Safety
///
/// As the aarch64 arm.
#[cfg(target_os = "none")]
pub unsafe fn timer_fired() -> bool {
    false
}

/// The timer's interrupt number: this machine's is not wired.
pub const fn timer_interrupt() -> usize {
    0
}

/// The timer's counter: this machine's timer is not driven yet.
///
/// # Safety
///
/// As the aarch64 arm.
#[cfg(target_os = "none")]
pub unsafe fn timer_counter() -> u64 {
    0
}

/// The timer's control register: this machine's timer is not driven yet.
///
/// # Safety
///
/// As the aarch64 arm.
#[cfg(target_os = "none")]
pub unsafe fn timer_control() -> u64 {
    0
}

/// Whether an interrupt line is enabled: this machine's controller is not
/// driven.
///
/// # Safety
///
/// As the aarch64 arm.
#[cfg(target_os = "none")]
pub unsafe fn interrupt_line_enabled(_number: usize) -> bool {
    false
}

/// The function called at an interrupt, for a scheduler that preempts: none.
///
/// # Safety
///
/// As the aarch64 arm.
#[cfg(target_os = "none")]
pub unsafe fn set_preempt_sink(sink: fn(&mut Context)) {
    let _ = sink;
}
