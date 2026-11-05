//! arch/x86_64/src/trap.rs
//!
//! What a vector arrives as, and the one path that answers it.
//!
//! ## The frame
//!
//! `idt_stub.S`'s `common_stub` builds a [`Context`] on the kernel stack and
//! hands it to `x86_64_interrupt_dispatch`.  The two files agree on every
//! offset because `context.rs` asserts them against `offset_of!`, a fact no
//! compiler checks, since a `repr(C)` structure and a run of `push`es are two
//! descriptions of one layout.
//!
//! ## Two kinds of vector, one entry point
//!
//! A device's interrupt and a program's system call arrive through the same
//! stubs; what differs is the vector number and what the handler does with the
//! frame.  The system call vector is a gate at `DPL` 3 so that `int $0x80`
//! from ring 3 reaches it, and its handler is the call sink, a program asking
//! the kernel to do something.  Everything else is a fault or a device's line.
//!
//! ## Why the sinks are statics
//!
//! An interrupt has no context to hand a function, which is the same reason
//! aarch64's sink is a static.  The kernel installs them; until it does, an
//! interrupt is unhandled and stops the machine with its vector on the
//! console.

use crate::context::Context;
use crate::context::install_context;

/// The vector a program's system call arrives on.
///
/// `0x80` because the tree's older arm used it and a program is compiled
/// against the number; the vector's identity is the interface, so it is named
/// once here and the boot's gate is installed from it rather than from a
/// literal.
pub const SYSCALL_VECTOR: usize = 0x80;

/// The `DPL` a gate needs for ring 3 to raise it.
///
/// A gate at `DPL` 0 refuses `int $0x80` from ring 3 with a general protection
/// fault, which is the state every gate was in before this module existed.
pub const USER_DPL: u8 = 3;

/// What a supervisor call's handler answers.
///
/// The same shape aarch64's answers with, so the kernel names one type: a
/// program's call either resumes it with a value or ends it.
#[derive(Debug, Clone, Copy)]
pub struct CallFrame {
    /// The number the program put in `rax`.
    pub number: usize,
    /// The six arguments, from `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`.
    pub arguments: [usize; 6],
    /// The instruction after the `int`, which is where to resume.
    pub resume: usize,
}

/// What a call's handler answers.
#[derive(Debug, Clone, Copy)]
pub enum CallOutcome {
    /// Resume the program with this value in `rax`.
    Return(usize),
    /// The program has ended.  The handler has already chosen what runs next
    /// and has put that program's context in the frame.
    Exit,
}

/// The function a supervisor call is handed to.
#[cfg(target_os = "none")]
pub type CallSink = fn(CallFrame, &mut Context) -> CallOutcome;

/// The function called at an interrupt, for a scheduler that preempts.
#[cfg(target_os = "none")]
pub type PreemptSink = fn(&mut Context);

// The sinks, and the one the kernel installed for faults.
#[cfg(target_os = "none")]
static CALL_SINK: cell::SyncUnsafeCell<Option<CallSink>> = cell::SyncUnsafeCell::new(None);
#[cfg(target_os = "none")]
static PREEMPT_SINK: cell::SyncUnsafeCell<Option<PreemptSink>> = cell::SyncUnsafeCell::new(None);

/// Install the function that serves a program's supervisor call.
///
/// # Safety
///
/// Called once, before any program can run.
#[cfg(target_os = "none")]
pub unsafe fn set_call_sink(sink: CallSink) {
    // SAFETY: the caller promises this is the only write and that it happens
    // before ring 3 is entered.
    unsafe { *CALL_SINK.get() = Some(sink) };
}

/// Install the function called after a handled interrupt.
///
/// # Safety
///
/// Called once, before any line can be unmasked.
#[cfg(target_os = "none")]
pub unsafe fn set_preempt_sink(sink: PreemptSink) {
    // SAFETY: as `set_call_sink`.
    unsafe { *PREEMPT_SINK.get() = Some(sink) };
}

#[cfg(target_os = "none")]
fn call_sink() -> Option<CallSink> {
    // SAFETY: written once before ring 3 is entered, read after.
    unsafe { *CALL_SINK.get() }
}

#[cfg(target_os = "none")]
fn preempt_sink() -> Option<PreemptSink> {
    // SAFETY: as `call_sink`.
    unsafe { *PREEMPT_SINK.get() }
}

/// Read `cr2`, which is where a page fault left the address it named.
///
/// Re-exported from `idt` rather than written again: the register is read in
/// one place, and two copies of the instruction would be two places to keep in
/// step about which register holds it.
#[cfg(target_os = "none")]
pub(crate) use crate::idt::fault_address;

/// The number a program put in the call register.
///
/// `rax`, which is both the architecture's return-value register and the
/// convention this tree's programs are built against.
pub fn syscall_number(frame: &Context) -> usize {
    frame.registers[crate::context::RAX] as usize
}

/// The six arguments, in the order the architecture passes them.
///
/// `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`, the System V argument order, with
/// `rcx` in the fourth slot because `syscall`/`sysret` already spend `rcx` and
/// programming against one ordering for both entry paths is worth more than
/// matching the `syscall` instruction's own quirk.
///
/// Public because it is the ABI's answer, not this file's: a test asserts it
/// and a second copy anywhere else would be a second ordering.
pub fn syscall_arguments(frame: &Context) -> [usize; 6] {
    use crate::context::R8;
    use crate::context::R9;
    use crate::context::RCX;
    use crate::context::RDI;
    use crate::context::RDX;
    use crate::context::RSI;

    [
        frame.registers[RDI] as usize,
        frame.registers[RSI] as usize,
        frame.registers[RDX] as usize,
        frame.registers[RCX] as usize,
        frame.registers[R8] as usize,
        frame.registers[R9] as usize,
    ]
}

/// Serve a program's supervisor call and resume it.
///
/// ## Why the frame is written rather than copied back
///
/// `common_stub` reloads every register from the frame before `iretq`, so a
/// value written into the frame's `rax` *is* the value the program finds on
/// return.  The instruction pointer needs no change: the processor pushed the
/// address after the `int`, which is where the program continues.
#[cfg(target_os = "none")]
fn serve_user_call(frame: &mut Context) {
    let call = CallFrame {
        number: syscall_number(frame),
        arguments: syscall_arguments(frame),
        resume: frame.instruction_pointer as usize,
    };

    // SAFETY: the sink is installed before ring 3 is entered and this runs
    // after.
    let outcome = match call_sink() {
        Some(sink) => sink(call, frame),
        None => {
            crate::serial::write_str("protofire: supervisor call with no handler\n");
            crate::halt()
        }
    };

    match outcome {
        CallOutcome::Return(value) => crate::context::set_return_value(frame, value),
        // The handler has already written what resumes into this frame.
        CallOutcome::Exit => {}
    }
}

/// What the call's handler answers, and the sinks.
///
/// `pub(crate)` statics below are this module's own; the controller is not, and
/// it is recorded here rather than in `apic` because it is what the handler
/// needs, and a handler that had to probe would probe on every tick.
#[cfg(target_os = "none")]
static TIMER: cell::SyncUnsafeCell<Option<crate::apic::Apic>> = cell::SyncUnsafeCell::new(None);

/// Record the local APIC the boot enabled, so a handler can end its interrupt.
///
/// # Safety
///
/// Called once, after [`crate::apic::Apic::enable`], before the timer is armed.
#[cfg(target_os = "none")]
pub unsafe fn set_timer_controller(apic: crate::apic::Apic) {
    // SAFETY: the caller promises this is the only write and that it happens
    // before any timer interrupt can arrive.
    unsafe { *TIMER.get() = Some(apic) };
}

/// The controller the boot recorded, if any.
///
/// # Safety
///
/// Called after [`set_timer_controller`].
#[cfg(target_os = "none")]
pub unsafe fn timer_controller() -> Option<crate::apic::Apic> {
    // SAFETY: written once before the timer is armed, read after.
    unsafe { *TIMER.get() }
}

/// Acknowledge the interrupt that just ran.
///
/// The local APIC holds a line in service until this is written.  A handler
/// that returned without it takes exactly one interrupt and then appears to
/// hang, the same failure aarch64's `EOIR` exists to prevent.
#[cfg(target_os = "none")]
fn end_of_interrupt() {
    // SAFETY: the controller was recorded before the timer was armed, and this
    // runs in the handler for the vector it raised.
    if let Some(apic) = unsafe { *TIMER.get() } {
        // SAFETY: as above.
        unsafe { apic.end_of_interrupt() };
    }
}

/// Whether an end-of-interrupt has to be written for this vector.
///
/// Only the local APIC holds a line in service, and it holds one for every
/// vector it delivers, so the rule is "the controller delivered it" rather than
/// "it is the timer's".  A vector the processor raised as a fault has no line
/// in service, and writing EOI for one would clear whichever line *is* being
/// serviced, which is why the boundary is the processor's 32 exceptions and
/// not "everything".
pub fn needs_end_of_interrupt(vector: usize) -> bool {
    vector >= 32
}

/// Hand a non-call vector to the kernel's sink, and give the scheduler a turn.
///
/// ## Why this is one function
///
/// An interrupt is three things in order: the kernel claims it or not, the
/// scheduler may switch away from the program it interrupted, and an
/// unclaimed one is reported.  Keeping them in one place is what makes the
/// order visible, the switch happens only after the line was claimed, because
/// an interrupt nobody handled is not a reason to move the CPU to another
/// program.
#[cfg(target_os = "none")]
fn finish_interrupt(frame: &mut Context) {
    let shared = irq::Frame::fault(frame.vector as usize, unsafe { fault_address() });

    // SAFETY: the sink is installed once before any vector can be raised.
    let sink = unsafe { *DISPATCH.get() };
    let handled = match sink {
        Some(sink) => sink(shared),
        None => false,
    };

    // The local APIC's line is ended *before* the scheduler runs, for the
    // reason aarch64's `EOIR` comes before its preemption hook: a switch made
    // with the line still in service leaves it active in a task that may not
    // run again for a while, and the next tick is then never delivered.
    if needs_end_of_interrupt(frame.vector as usize) {
        end_of_interrupt();
    }

    if handled && let Some(preempt) = preempt_sink() {
        // The frame is the machine's, not a call's: this interrupt stopped
        // whatever the program was doing, so its saved state is the whole
        // context and the scheduler can install another program's over it.
        preempt(frame);
    }

    if !handled {
        // Not fatal: a device with no driver raises its line whether or not
        // anything wants it, and a kernel that stopped here could not boot on a
        // machine with one device more than it knows.
        crate::serial::write_str("protofire: unhandled interrupt ");
        crate::serial::write_u32(frame.vector as u32);
        crate::serial::write_str(" at ");
        crate::serial::write_hex(unsafe { fault_address() } as u64);
        crate::serial::write_str(" rip ");
        crate::serial::write_hex(frame.instruction_pointer);
        crate::serial::write_str("\n");
    }
}

// The kernel's sink for vectors that are not a program's call.  `idt.rs` owns
// it, because a table of gates and the sink a frame goes to are the same
// decision; this module reads it through that module's accessor.
#[cfg(target_os = "none")]
use crate::idt::DISPATCH;

/// The dispatch the assembly calls.
///
/// # Safety
///
/// `extern "C"` because `idt_stub.S` calls it, with a pointer to the frame that
/// file built on the kernel stack.  The pointer must name a live [`Context`],
/// which is the stub's contract, and it does not unwind: an exception has no
/// context to unwind into.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x86_64_interrupt_dispatch(frame: *mut Context) {
    // SAFETY: the stub passes the address of the frame it built, and nothing
    // else holds it.
    let frame = unsafe { &mut *frame };

    // A system call from a program is a *request*, not a fault: it is served
    // and the program resumed.  The check is the vector and the ring the frame
    // came from, because the kernel's own `int $0x80`, which the boot uses as
    // a self-test, must not be mistaken for a program's call.
    if frame.vector as usize == SYSCALL_VECTOR && frame.is_user() {
        return serve_user_call(frame);
    }

    if frame.vector as usize == SYSCALL_VECTOR && !frame.is_user() {
        // The kernel raised the call itself.  That is what `install` does to
        // prove the gate is live, and the answer is to resume: a self-test that
        // stopped the machine would be a test nothing reported on.
        crate::context::set_return_value(frame, SYSCALL_SELF_TEST_ANSWER);
        return;
    }

    finish_interrupt(frame);
}

/// What the kernel's own `int $0x80` is answered with.
///
/// A value no syscall returns, so the self-test can tell "the gate delivered my
/// call" from "the answer was whatever `rax` already held", the same reason
/// the boot's interrupt probe uses a sentinel instead of zero.
pub const SYSCALL_SELF_TEST_ANSWER: usize = 0x5EF7_EFE7;

/// Install a context over the frame the trap path will restore.
///
/// A copy, on every build and through one function: the frames are the same
/// type, so there is nothing a bare-metal arm would do differently, and a host
/// arm that did nothing would be a function whose only caller could not test
/// it.
pub fn install_trap_context(frame: &mut Context, context: &Context) {
    install_context(frame, context);
}

#[cfg(test)]
mod tests {
    use super::SYSCALL_VECTOR;
    use super::USER_DPL;
    use super::syscall_arguments;
    use crate::context::Context;
    use crate::context::R8;
    use crate::context::R9;
    use crate::context::RAX;
    use crate::context::RCX;
    use crate::context::RDI;
    use crate::context::RDX;
    use crate::context::RSI;

    /// The system call vector is the one a program's `int` names.
    #[test]
    fn the_syscall_vector_is_the_one_programs_are_built_against() {
        assert_eq!(SYSCALL_VECTOR, 0x80);
        // And its gate is at DPL 3: a gate at DPL 0 refuses ring 3 with a
        // protection fault, which is silent about why.
        assert_eq!(USER_DPL, 3);
    }

    /// The number and the arguments come from the registers the ABI names.
    ///
    /// The first argument is `rdi` and not `rsi`, the ordering is the
    /// architecture's, and a program is compiled against it.
    #[test]
    fn the_arguments_come_from_the_architectures_registers() {
        let mut frame = Context::user(0, 0);
        frame.registers[RAX] = 6; // Write
        frame.registers[RDI] = 1;
        frame.registers[RSI] = 2;
        frame.registers[RDX] = 3;
        frame.registers[RCX] = 4;
        frame.registers[R8] = 5;
        frame.registers[R9] = 6;

        assert_eq!(super::syscall_number(&frame), 6);
        assert_eq!(syscall_arguments(&frame), [1, 2, 3, 4, 5, 6]);
    }

    /// A call from ring 3 is a user call, and the same vector from ring 0 is
    /// not.
    ///
    /// The distinction is what keeps the boot's own self-test from being served
    /// as a program's request: `cs` 0x08 is the kernel's segment.
    #[test]
    fn only_a_call_from_ring_three_is_a_programs_call() {
        let user = Context::user(0x1000, 0x2000);
        assert!(user.is_user());

        let mut kernel = Context::user(0x1000, 0x2000);
        kernel.code_segment = 0x08;
        assert!(!kernel.is_user());
    }
}
