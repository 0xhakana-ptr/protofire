//! arch/aarch64/src/trap/call.rs
//!
//! What a supervisor call's handler is given and answers, and the two sink
//! types the kernel installs.
//!
//! An interrupt's frame carries a vector and an address; a syscall's carries
//! six arguments and answers with a word.  Folding the two into one type would
//! give every IRQ handler six fields it does not have and every syscall handler
//! an address it did not ask for, which is the union-of-conventions the
//! `irq::Frame` header already refuses.

#[cfg(target_os = "none")]
use super::frame::ExceptionFrame;

/// What a supervisor call's handler answers.
///
/// An interrupt's frame carries a vector and an address; a syscall's carries
/// six arguments and answers with a word.  Folding the two into one type would
/// give every IRQ handler six fields it does not have and every syscall handler
/// an address it did not ask for, which is the union-of-conventions this
/// tree's `irq::Frame` header already refuses.
///
/// The two are separate types and separate sinks.  A kernel installs both.
#[derive(Debug, Clone, Copy)]
pub struct CallFrame {
    /// The number the program put in `x8`.
    pub number: usize,
    /// The six arguments from `x0..x5`.
    pub arguments: [usize; 6],
    /// The instruction after the `svc`, which is where to resume.
    pub resume: usize,
}

/// What a call's handler answers.
#[derive(Debug, Clone, Copy)]
pub enum CallOutcome {
    /// Resume *this* program with this value in `x0`.
    Return(usize),
    /// The program has ended.  The handler has already chosen what runs next
    /// and has put that program's context where the trap path will find it.
    ///
    /// A scheduler that answers "resume *this* context" would be answering
    /// about a dead one.  So the handler does the switch itself, writing the
    /// next context into the frame and, if the next program lives somewhere
    /// else, changing `TTBR0_EL1`, and answers only that this program is done.
    /// The trap path then returns through the same epilogue as a normal call,
    /// which is what keeps one restore path rather than two.
    Exit,
}

/// The function called at an interrupt, for a scheduler that preempts.
///
/// Separate from the IRQ sink because the two answer different questions.  The
/// sink says whether the line was claimed; this decides whether the CPU moves
/// to another task, and it is called only for a claimed line, an interrupt
/// nobody handled is not a reason to switch programs.
#[cfg(target_os = "none")]
pub type PreemptSink = fn(&mut ExceptionFrame);

#[cfg(target_os = "none")]
static PREEMPT_SINK: cell::SyncUnsafeCell<Option<PreemptSink>> = cell::SyncUnsafeCell::new(None);

/// Install the function called after a handled interrupt.
///
/// # Safety
///
/// Called once, before any line is unmasked.
/// The sink for a fault in a program the kernel did not answer: the frame,
/// the vector, and the address the fault named.  Injected like the call and
/// preempt sinks — the machine knows where a fault happened, and only the
/// kernel knows what a process is.
#[cfg(target_os = "none")]
pub type FaultSink = fn(&mut ExceptionFrame, usize, usize);

#[cfg(target_os = "none")]
static FAULT_SINK: cell::SyncUnsafeCell<Option<FaultSink>> = cell::SyncUnsafeCell::new(None);

/// Install the function a fatal program fault is reported through.
///
/// # Safety
///
/// Called once, before EL0 is entered.
#[cfg(target_os = "none")]
pub unsafe fn set_fault_sink(sink: FaultSink) {
    // SAFETY: the caller promises this is the only write and that it happens
    // before ring 3 is entered.
    unsafe { *FAULT_SINK.get() = Some(sink) };
}

#[cfg(target_os = "none")]
pub(super) fn fault_sink() -> Option<FaultSink> {
    // SAFETY: written once before EL0 is entered, read after.
    unsafe { *FAULT_SINK.get() }
}

/// Install the function called after a handled interrupt.
///
/// # Safety
///
/// Called once, before any line is unmasked.
#[cfg(target_os = "none")]
pub unsafe fn set_preempt_sink(sink: PreemptSink) {
    // SAFETY: the caller promises this is the only write and that it happens
    // before an interrupt can arrive.
    unsafe { *PREEMPT_SINK.get() = Some(sink) };
}

#[cfg(target_os = "none")]
pub(super) fn preempt_sink() -> Option<PreemptSink> {
    // SAFETY: written once before any line is unmasked, read here after.
    unsafe { *PREEMPT_SINK.get() }
}

/// The function a supervisor call is handed to.
///
/// It takes the frame itself, not a copy of the few fields a call names,
/// because an `Exit` has to replace the whole context with another program's,
/// /// every register, the `ELR` and the `SPSR`.  A sink that received only the
/// number and the arguments could answer a call and could not switch tasks.
#[cfg(target_os = "none")]
pub type CallSink = fn(CallFrame, &mut ExceptionFrame) -> CallOutcome;

#[cfg(target_os = "none")]
pub(super) static CALL_SINK: cell::SyncUnsafeCell<Option<CallSink>> =
    cell::SyncUnsafeCell::new(None);

/// Install the function that serves a program's supervisor call.
///
/// # Safety
///
/// Called once, before any program can run.
#[cfg(target_os = "none")]
pub unsafe fn set_call_sink(sink: CallSink) {
    // SAFETY: the caller promises this is the only write and that it happens
    // before EL0 is entered.
    unsafe { *CALL_SINK.get() = Some(sink) };
}
