//! arch/aarch64/src/trap/context.rs
//!
//! The frame as a scheduler sees it: where a program resumes, what it returns,
//! and whether it was a program at all.
//!
//! These are plain accessors over [`ExceptionFrame`], and they are here rather
//! than in `frame.rs` because they answer a different question.  That file says
//! what the machine saved; this one says what a saved word *means* to a
//! scheduler, which is a reading of the frame and not a part of it.

use crate::SPSR_EL0T;

use super::frame::ExceptionFrame;

/// What a program's context looks like to a scheduler.
///
/// The whole 800-byte frame the assembly built, so a task switch is a copy of
/// one of these into the frame the trap path already has on the stack.
pub type Context = ExceptionFrame;

/// The context a program begins with.
///
/// Every register zero except the two that decide where it runs: `ELR_EL1`
/// names the entry and `SPSR_EL1` names EL0t.  A program that started with a
/// kernel value in a register would be one whose first instruction ran on it.
///
/// `SP_EL0` is not in the frame, the assembly does not save it, because a trap
/// never changes it, so the stack pointer travels in `x0` and the install path
/// writes it to the register before the `eret`.
pub fn starting_context(entry: usize, stack_top: usize) -> Context {
    ExceptionFrame {
        registers: [0; 30],
        link_register: 0,
        elr: entry as u64,
        spsr: SPSR_EL0T,
        esr: 0,
        far: 0,
        vector: 0,
        simd: [0; 32],
        // The stack pointer belongs here and not in `x0`: `x0` is a program's
        // first argument and it overwrites it immediately, so a context that
        // carried the stack there lost it the moment the program ran.  The
        // pipe reader's `ldr x0, [sp]` is what made that visible.
        sp_el0: stack_top as u64,
    }
}

/// Where a context resumes: the instruction the `eret` will return to.
pub fn resume_address(context: &Context) -> usize {
    context.elr as usize
}

/// Point a context at another address, for a caller building one by hand.
pub fn set_resume_address(context: &mut Context, address: usize) {
    context.elr = address as u64;
}

/// The stack pointer a context runs on.
///
/// `SP_EL0`, which the assembly saves and restores like any other register.
/// It used to travel in `x0`, and that was wrong for a reason the pipe reader
/// found: `x0` is a program's first argument and it overwrites it on its first
/// instruction, so the next switch installed a context whose "stack" was
/// whatever the program had put there.
pub fn stack_pointer(context: &Context) -> usize {
    context.sp_el0 as usize
}

/// The word a program reads a call's answer from.
pub fn return_value(context: &Context) -> usize {
    context.registers[0] as usize
}

/// Put a call's answer where a program reads it.
pub fn set_return_value(context: &mut Context, value: usize) {
    context.registers[0] = value as u64;
}

/// Whether a context is a program's rather than the kernel's.
///
/// `SPSR_EL1`'s `M` field names the exception level an `eret` returns to, and
/// `0b0000` is EL0t, the only state a program runs in.
pub fn is_user_context(context: &Context) -> bool {
    context.spsr & 0b1111 == 0
}

/// The state the trap path will restore, for a boot line that reports it.
pub fn return_state(context: &Context) -> u64 {
    context.spsr
}

/// Write `context` over the frame the trap path will restore.
///
/// That is the whole of a task switch: the epilogue restores every register,
/// `ELR_EL1` and `SPSR_EL1` from this frame, so replacing it replaces what the
/// machine does next, including the exception level it returns to.
#[cfg(target_os = "none")]
pub fn install_context(frame: &mut ExceptionFrame, context: &Context) {
    *frame = *context;
}
