//! arch/aarch64/src/trap.rs
//!
//! What an exception arrives as, and the one path that answers it.
//!
//! ## The frame
//!
//! `entry.S`'s `exception_entry` builds [`ExceptionFrame`] on the kernel stack
//! before calling `aarch64_exception_dispatch`, and the two files agree on
//! every offset because the offsets are written down in both.  That is a fact
//! no compiler checks — a `repr(C)` struct and a run of `stp`s are two
//! descriptions of one layout — so the offsets are asserted here against
//! `offset_of!` instead of being trusted.
//!
//! The SIMD half of the frame is not caution.  `CPACR_EL1.FPEN` is open, so the
//! compiler emits NEON for a `memcpy`; a handler that saved only `x0`..`x30`
//! would return to code whose vector operands it had destroyed.  This tree
//! learned that the hard way: the first aarch64 boot printed four lines and
//! stopped, and `ESR_EL1.EC` = 7 at a NEON word was why.
//!
//! ## The sixteen entries become sixteen numbers
//!
//! The architecture's table is four groups of four, and `entry.S` moves the
//! entry's index into `x16` before branching to the common path.  So the vector
//! this module reports is `(group * 4) + kind` — which is exactly what
//! [`crate::vbar::entry_offset`] divides by 128, and a test checks the two
//! agree rather than leaving the arithmetic in two places to drift.
//!
//! ## Why the sink is a static
//!
//! An exception has no context to hand a function, which is the same reason the
//! x86_64 dispatch reads its sink from a static.  The kernel installs one with
//! `set_sink`; until then every exception is unhandled, and an unhandled one
//! stops the machine with its number and syndrome on the console.

// The self-test's two words.  Only the bare-metal build has a trap path to
// write them from, so a host build would find these unused — and an import a
// host build never names is what the host check exists to notice.
#[cfg(target_os = "none")]
use core::sync::atomic::AtomicBool;
#[cfg(target_os = "none")]
use core::sync::atomic::AtomicUsize;
#[cfg(target_os = "none")]
use core::sync::atomic::Ordering;

use crate::SPSR_EL0T;
use crate::vbar::ENTRIES;
use crate::vbar::ENTRY_STRIDE;

/// The saved context of an interrupted instruction.
///
/// Laid out by `entry.S`, offset for offset, and asserted against
/// `offset_of!` below.  The fields are public because they are what the machine
/// saved and a handler reads them; nothing here has an invariant a setter would
/// protect.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExceptionFrame {
    /// `x0`..`x29`, in the order the assembly stores them.
    pub registers: [u64; 30],
    /// `x30`, the link register at the time of the exception.
    pub link_register: u64,
    /// `ELR_EL1`: the instruction that was interrupted.
    pub elr: u64,
    /// `SPSR_EL1`: the state to return to — the EL, the masks, the flags.
    pub spsr: u64,
    /// `ESR_EL1`: what the exception was.
    pub esr: u64,
    /// `FAR_EL1`: the address a faulting access named.
    pub far: u64,
    /// The entry's index, 0..16.
    pub vector: u64,
    /// `q0`..`q31`.  Saved because the compiler uses them for `memcpy`.
    pub simd: [u128; 32],
    /// The interrupted `SP_EL0`, at the end so every `q` pair keeps its offset.
    ///
    /// A system register, and the hardware does not push it — so without this
    /// field a task switch carries every register but the stack pointer, and a
    /// program that uses its stack resumes with the previous task's.  The pipe
    /// reader is what found it: it took a data abort at an address inside
    /// another program's memory.
    pub sp_el0: u64,
}

/// An `irq::Frame` needs a vector and nothing else from a machine that has no
/// process to hand a fault to, but the syndrome is what makes a log line
/// diagnosable, so `class_name` names it.
impl ExceptionFrame {
    /// The exception class — `ESR_EL1.EC`, bits 31..26.
    ///
    /// The class is what says *why*: an undefined instruction, a data abort, a
    /// system-register trap, or a supervisor call.  A log that printed only the
    /// vector would say which slot fired and not what arrived in it.
    pub fn class(&self) -> u32 {
        ((self.esr >> 26) & 0x3F) as u32
    }

    /// A short name for this exception class.
    ///
    /// Only the classes this machine has actually produced, plus the one a
    /// supervisor call uses.  An unnamed class reports `None` rather than
    /// inventing a name for it.
    pub fn class_name(&self) -> Option<&'static str> {
        match self.class() {
            0x00 => Some("unknown"),
            0x07 => Some("fp/simd trapped"),
            0x0E => Some("illegal execution state"),
            0x15 => Some("supervisor call"),
            0x18 => Some("trapped msr/mrs"),
            0x20 | 0x21 => Some("instruction abort"),
            0x24 | 0x25 => Some("data abort"),
            0x26 => Some("stack-pointer alignment fault"),
            0x2C => Some("fp/simd access trapped"),
            _ => None,
        }
    }

    /// Whether this exception is a supervisor call, which returns.
    pub fn is_supervisor_call(&self) -> bool {
        self.class() == 0x15
    }

    /// Whether this exception is a supervisor call from a program.
    ///
    /// The vector is entry 8 — `Lower64`'s synchronous kind — and the class is
    /// `0x15`.  Both, because either alone is a different thing: entry 8 with
    /// another class is a program's fault, and an `svc` at EL1 is the kernel
    /// calling itself, which `install_table` does as its self-test.
    pub fn is_user_supervisor_call(&self) -> bool {
        self.vector == USER_SUPERVISOR_CALL_VECTOR && self.is_supervisor_call()
    }

    /// The syscall number a program put in `x8`.
    ///
    /// The register is the ABI's choice, and it is the one every caller sets
    /// before `svc`.  Reading it here rather than from `x0` keeps the number
    /// and the first argument from sharing a register.
    pub fn syscall_number(&self) -> usize {
        self.registers[8] as usize
    }

    /// The six arguments a program put in `x0..x5`.
    pub fn syscall_arguments(&self) -> [usize; 6] {
        let mut arguments = [0usize; 6];
        for (index, slot) in arguments.iter_mut().enumerate() {
            *slot = self.registers[index] as usize;
        }
        arguments
    }

    /// Put a syscall's result in `x0`, which is where a caller reads it.
    pub fn set_return(&mut self, value: usize) {
        self.registers[0] = value as u64;
    }

    /// Whether this exception arrived on one of the four IRQ entries.
    ///
    /// The vector is `(group * 4) + kind`, and every group's `Irq` kind has the
    /// index 1.  So the question is `vector % 4 == 1` — the same arithmetic for
    /// an IRQ taken from the kernel and one taken from a user program, which is
    /// what makes one check enough.
    pub fn is_irq(&self) -> bool {
        self.vector % 4 == IRQ_KIND
    }
}

// The offsets `entry.S` writes, checked against this structure's.  A mismatch
// is a frame the assembly filled in one place and Rust reads in another, and
// the symptom would be a handler acting on `x0` when it meant `x7`.
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, registers) == 0);
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, link_register) == 240);
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, elr) == 248);
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, spsr) == 256);
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, esr) == 264);
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, far) == 272);
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, vector) == 280);
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, sp_el0) == 800);
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, simd) == 288);
const _: () = assert!(core::mem::size_of::<ExceptionFrame>() == 816);
const _: () = assert!(core::mem::align_of::<ExceptionFrame>() == 16);

/// What the kernel installs: one function, answering whether it took the frame.
#[cfg(target_os = "none")]
pub type Sink = fn(irq::Frame) -> bool;

#[cfg(target_os = "none")]
static SINK: cell::SyncUnsafeCell<Option<Sink>> = cell::SyncUnsafeCell::new(None);

/// Install the function that handles an exception frame.
///
/// Called once by the kernel, after its console is up and before any vector can
/// be raised.  A frame that arrived with no sink is answered by stopping, which
/// is the only answer a machine can give to an exception nobody registered for.
///
/// # Safety
///
/// Called once, before any vector can be raised.  The function must not
/// allocate, block, or enable interrupts: it runs on the kernel stack the
/// exception found, with the interrupted code's SIMD state in the frame rather
/// than in the registers.
#[cfg(target_os = "none")]
pub unsafe fn set_sink(sink: Sink) {
    // SAFETY: the caller promises this is the only call, and the write is what
    // makes a frame reachable rather than unhandled.
    unsafe { *SINK.get() = Some(sink) };
}

/// The installed sink, if any.
#[cfg(target_os = "none")]
fn sink() -> Option<Sink> {
    // SAFETY: written once by `set_sink` before any vector can be raised, and
    // read here after that.
    unsafe { *SINK.get() }
}

// The vector table's address, as the assembly defined it.
#[cfg(target_os = "none")]
unsafe extern "C" {
    /// The 2 KiB table `exception_vectors:` labels.
    static exception_vectors: u8;
}

/// The address the machine should branch to for an exception.
#[cfg(target_os = "none")]
fn table_address() -> usize {
    // `addr_of!` takes the address without creating a reference; there is a run
    // of instructions there, not a value.
    core::ptr::addr_of!(exception_vectors) as usize
}

/// Read `VBAR_EL1`, which is where the machine looks for an exception.
#[cfg(target_os = "none")]
fn installed_table() -> usize {
    let value: u64;
    // SAFETY: reading `VBAR_EL1` at EL1 has no side effect; the low eleven bits
    // are reserved and the address is what remains.
    unsafe {
        core::arch::asm!(
            "mrs {}, vbar_el1",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        )
    };
    (value as usize) & !0x7FF
}

/// What a self-test raised and what came back.
///
/// Two atomics rather than a mutex: the trap path runs with interrupts masked
/// and cannot take a lock the interrupted code might hold, and there is exactly
/// one writer and one reader, in that order.
#[cfg(target_os = "none")]
static TEST_RAISED: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "none")]
static TEST_RETURNED: AtomicBool = AtomicBool::new(false);

/// The sink the self-test installs: record the frame and claim it.
///
/// It returns `true`, which is what makes the exception return: the common path
/// ends in `eret` either way, but a sink that answered `false` would have the
/// dispatch stop the machine, and a self-test that halted the boot would be a
/// test the boot never reported on.
#[cfg(target_os = "none")]
fn recording_sink(frame: irq::Frame) -> bool {
    TEST_RAISED.store(frame.vector, Ordering::Release);
    TEST_RETURNED.store(true, Ordering::Release);
    true
}

/// Install the table, then prove the path works by taking one exception.
///
/// Returns whether the machine will now deliver an exception through this
/// module.  Two things make that true, and the second is why the answer is a
/// claim rather than a hope:
///
/// 1. `VBAR_EL1` names `exception_vectors`, read back rather than assumed — a
///    register written and never re-read is a value a later change can break
///    silently.
/// 2. A supervisor call raised from EL1 arrives at entry 4, reaches this
///    module, and returns to the instruction after it.  That exercises the
///    assembly's save/restore, the vector numbering, the sink indirection and
///    the `eret` together; the frame's own offsets are what the return path
///    restored, so a frame laid out wrong would return into garbage rather than
///    here.
///
/// The sink the kernel installed is swapped out for the duration and put back
/// afterwards, so the probe adds no branch to the steady-state path.
///
/// # Safety
///
/// Called once, after [`set_sink`] and before the kernel enables interrupts.
/// It writes `VBAR_EL1` and executes one `svc`, which the machine takes as an
/// exception; that is safe at EL1 with the kernel's stack valid, and not safe
/// anywhere else.
#[cfg(target_os = "none")]
pub unsafe fn install_table() -> bool {
    let table = table_address();

    // SAFETY: written below and read back here; the register's reserved bits
    // are cleared by `installed_table`.
    unsafe {
        core::arch::asm!(
            "msr vbar_el1, {}",
            "isb",
            in(reg) table as u64,
            options(nostack)
        );
    }
    if installed_table() != table {
        return false;
    }

    let previous = sink();
    // SAFETY: this runs before any vector can arrive, and the sink is put back
    // before this function returns.  A vector that arrived between the two
    // stores would be answered by the recording sink, which claims it.
    unsafe { *SINK.get() = Some(recording_sink) };

    TEST_RAISED.store(usize::MAX, Ordering::Release);
    TEST_RETURNED.store(false, Ordering::Release);
    // SAFETY: `svc #0` from EL1 is taken as a synchronous exception at entry 4
    // and returns to the following instruction.  `esr_el1` must be told the
    // immediate is ours; the machine does that, not this code.
    unsafe {
        core::arch::asm!("svc #0", options(nostack));
    }

    let returned = TEST_RETURNED.load(Ordering::Acquire);
    let raised = TEST_RAISED.load(Ordering::Acquire);

    // SAFETY: putting back what was there.  The kernel's sink was installed
    // before this call by contract.
    unsafe { *SINK.get() = previous };

    returned && raised == SUPERVISOR_CALL_VECTOR
}

/// The index of `Kind::Irq` within a group.
const IRQ_KIND: u64 = 1;

/// The vector a program's supervisor call arrives on.
///
/// `Lower64` (offset 8) and `Synchronous` (offset 0) is entry 8, which is a
/// different entry from the kernel's own `svc` at entry 4 — the one
/// `install_table` uses as its self-test.  The two being one number apart in
/// nobody's arithmetic is why this is named.
pub const USER_SUPERVISOR_CALL_VECTOR: u64 = 8;

/// The controller, once the boot has found and enabled one.
#[cfg(target_os = "none")]
static GIC: cell::SyncUnsafeCell<Option<crate::gic::Gic>> = cell::SyncUnsafeCell::new(None);

/// Record the controller the boot enabled, so an IRQ can be acknowledged.
///
/// # Safety
///
/// Called once, after [`crate::gic::Gic::enable`], before any line is
/// unmasked.  The two windows must stay mapped for the life of the boot.
#[cfg(target_os = "none")]
pub unsafe fn set_controller(gic: crate::gic::Gic) {
    // SAFETY: the caller promises this is the only write, and it happens before
    // any interrupt can arrive.
    unsafe { *GIC.get() = Some(gic) };
}

/// What a supervisor call's handler answers.
///
/// ## Why this is not `irq::Frame`
///
/// An interrupt's frame carries a vector and an address; a syscall's carries
/// six arguments and answers with a word.  Folding the two into one type would
/// give every IRQ handler six fields it does not have and every syscall handler
/// an address it did not ask for — which is the union-of-conventions this
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
    /// ## Why this carries no value
    ///
    /// A scheduler that answers "resume *this* context" would be answering
    /// about a dead one.  So the handler does the switch itself — writing the
    /// next context into the frame and, if the next program lives somewhere
    /// else, changing `TTBR0_EL1` — and answers only that this program is done.
    /// The trap path then returns through the same epilogue as a normal call,
    /// which is what keeps one restore path rather than two.
    Exit,
}

/// The function called at an interrupt, for a scheduler that preempts.
///
/// Separate from the IRQ sink because the two answer different questions.  The
/// sink says whether the line was claimed; this decides whether the CPU moves
/// to another task, and it is called only for a claimed line — an interrupt
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
#[cfg(target_os = "none")]
pub unsafe fn set_preempt_sink(sink: PreemptSink) {
    // SAFETY: the caller promises this is the only write and that it happens
    // before an interrupt can arrive.
    unsafe { *PREEMPT_SINK.get() = Some(sink) };
}

#[cfg(target_os = "none")]
fn preempt_sink() -> Option<PreemptSink> {
    // SAFETY: written once before any line is unmasked, read here after.
    unsafe { *PREEMPT_SINK.get() }
}

/// The function a supervisor call is handed to.
///
/// It takes the frame itself, not a copy of the few fields a call names,
/// because an `Exit` has to replace the whole context with another program's —
/// every register, the `ELR` and the `SPSR`.  A sink that received only the
/// number and the arguments could answer a call and could not switch tasks.
#[cfg(target_os = "none")]
pub type CallSink = fn(CallFrame, &mut ExceptionFrame) -> CallOutcome;

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
/// `SP_EL0` is not in the frame — the assembly does not save it, because a trap
/// never changes it — so the stack pointer travels in `x0` and the install path
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
/// `0b0000` is EL0t — the only state a program runs in.
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
/// machine does next — including the exception level it returns to.
#[cfg(target_os = "none")]
pub fn install_context(frame: &mut ExceptionFrame, context: &Context) {
    *frame = *context;
}

#[cfg(target_os = "none")]
static CALL_SINK: cell::SyncUnsafeCell<Option<CallSink>> = cell::SyncUnsafeCell::new(None);

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

/// Serve a program's supervisor call and resume it.
///
/// ## Why the frame is written rather than copied back
///
/// `entry.S` restores `x0..x30` from the frame before `eret`, so a value
/// written into the frame's `x0` *is* the value the program finds on return.
/// Copying it somewhere else afterwards would need a second restore path, which
/// is the one thing the assembly's common epilogue exists to avoid.
///
/// `ELR_EL1` needs no change: it already holds the instruction after the `svc`,
/// which is where the program continues.
#[cfg(target_os = "none")]
fn serve_user_call(frame: &mut ExceptionFrame) {
    let call = CallFrame {
        number: frame.syscall_number(),
        arguments: frame.syscall_arguments(),
        resume: frame.elr as usize,
    };

    // SAFETY: the sink is installed before EL0 is entered and this runs after.
    let sink = unsafe { *CALL_SINK.get() };
    let outcome = match sink {
        Some(sink) => sink(call, frame),
        None => {
            // No sink: nothing can answer, and there is no context to resume.
            crate::serial::write_str("protofire: supervisor call with no handler\n");
            crate::halt()
        }
    };

    match outcome {
        CallOutcome::Return(value) => frame.set_return(value),
        // The handler has already written what resumes into this frame, and the
        // epilogue below restores it and `eret`s.  Nothing to do here, which is
        // the point: one restore path, whichever program it belongs to.
        CallOutcome::Exit => {}
    }
}

/// Acknowledge the interrupt, hand it to the sink, and finish it.
///
/// ## Why the order is acknowledge, handle, finish
///
/// The controller holds the line *active* between the acknowledge and the
/// finish.  An interrupt at that priority is not delivered again until it is
/// finished, and a handler that returned without one would leave the machine
/// taking exactly one interrupt and then appearing to hang — which is the
/// failure mode a span of code that looks correct produces.
///
/// ## Why an unhandled interrupt finishes anyway
///
/// A device the boot has no driver for still raises its line, and a kernel that
/// stopped the machine for it could never be debugged on a machine that had one
/// more device.  The line is finished and the arrival is reported; a sink that
/// wants to treat it as fatal can answer `false` and stop.
#[cfg(target_os = "none")]
fn finish_irq(frame: &mut ExceptionFrame) {
    // SAFETY: the static is written once before any line is unmasked.
    let controller = unsafe { *GIC.get() };
    let Some(controller) = controller else {
        crate::serial::write_str("protofire: irq with no controller at vector ");
        crate::serial::write_u32(frame.vector as u32);
        crate::serial::write_str("\n");
        crate::halt()
    };

    // SAFETY: the windows were mapped uncached by the boot that installed this
    // controller, and this runs in an exception handler where nothing else is
    // touching them.
    let interrupt = unsafe { controller.acknowledge() };
    let Some(interrupt) = interrupt else {
        // A spurious reading: there was nothing to acknowledge.  Finishing it
        // would name an interrupt that never existed, so this returns and the
        // assembly's `eret` resumes the interrupted code.
        return;
    };

    let handled = match sink() {
        Some(sink) => sink(irq::Frame::device(interrupt as usize)),
        None => false,
    };

    // SAFETY: `interrupt` is the number `acknowledge` returned.
    unsafe { controller.finish(interrupt) };

    // A preemption point, after the interrupt is finished.
    //
    // The timer's handler has just said "handled"; whether the CPU now goes to
    // another program is the scheduler's decision and not the controller's, so
    // it is a separate call the kernel installs.  It runs *after* the `EOIR`
    // because a switch that happened before would leave the line active in a
    // task that may not run again for a while.
    //
    // The frame is the machine's, not the call's: this exception interrupted
    // whatever the program was doing, so its saved state is the whole context
    // and the scheduler can install another program's over it.
    if handled && let Some(preempt) = preempt_sink() {
        preempt(frame);
    }

    if !handled {
        crate::serial::write_str("protofire: unhandled interrupt ");
        crate::serial::write_u32(interrupt);
        crate::serial::write_str("\n");
        // Not fatal: a device with no driver raises its line whether or not
        // anything wants it, and a kernel that stopped here could not boot on a
        // machine with one device more than it knows.
    }
}

/// The entry a supervisor call from EL1 arrives at.
///
/// Group `CurrentSpX` (offset 4) and kind `Synchronous` (offset 0), so entry
/// 4 — *not* 0 and *not* 8.  Entry 0 is the same kind with `SP_EL0` selected,
/// and entry 8 is a supervisor call from a lower EL, which is what a user
/// program's system call will take.  Three numbers that differ by one bit of
/// `PSTATE.SP` or one exception level is why this constant is named rather than
/// written as a literal wherever it is needed.
pub const SUPERVISOR_CALL_VECTOR: usize = 4;

/// The dispatch the assembly calls.
///
/// # Safety
///
/// `extern "C"` because `entry.S` calls it, with a pointer to the frame that
/// file built on the kernel stack.  The pointer must name a live
/// [`ExceptionFrame`], which is the assembly's contract — and it does not
/// unwind: an exception has no context to unwind into.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aarch64_exception_dispatch(frame: *mut ExceptionFrame) {
    // SAFETY: `entry.S` passes `sp` after building the frame at that address,
    // and nothing else holds it.
    let frame = unsafe { &mut *frame };

    // An IRQ is not a fault: the vector says which kind arrived, and the two
    // need different handling.  A fault's frame carries the address it named;
    // an IRQ's carries the interrupt number the controller hands out, and the
    // controller has to be told when the handler is done.
    if frame.is_irq() {
        return finish_irq(frame);
    }

    // A supervisor call from EL0 is the one exception that is a *request*: a
    // program asking the kernel to do something.  It is served and the program
    // resumed, which is what makes this the first path in the tree where
    // something outside the kernel can reach the registry.
    if frame.is_user_supervisor_call() {
        return serve_user_call(frame);
    }

    let shared = irq::Frame::fault(frame.vector as usize, frame.far as usize);
    let handled = match sink() {
        Some(sink) => sink(shared),
        None => false,
    };

    if !handled {
        // A supervisor call is the one exception that is not a fault: the
        // kernel raises it deliberately.  Without a process layer there is
        // nothing to serve it, so it is reported as unhandled rather than
        // mistaken for one.
        crate::serial::write_str("protofire: unhandled exception ");
        crate::serial::write_u32(frame.vector as u32);
        crate::serial::write_str(" (ec ");
        crate::serial::write_u32(frame.class());
        crate::serial::write_str(", ");
        crate::serial::write_str(frame.class_name().unwrap_or("unrecognised class"));
        crate::serial::write_str(") at ");
        crate::serial::write_hex(frame.elr);
        if frame.far != 0 {
            crate::serial::write_str(", address ");
            crate::serial::write_hex(frame.far);
        }
        crate::serial::write_str("\n");
        crate::halt()
    }
}

// The two numbers this module and the table have to agree about: an entry's
// index is its offset divided by the stride, and sixteen of them is the table.
const _: () = assert!(ENTRIES == 16);
const _: () = assert!(ENTRY_STRIDE * ENTRIES == 2048);
const _: () = assert!(SUPERVISOR_CALL_VECTOR == 4);

#[cfg(test)]
mod tests {
    use super::ExceptionFrame;
    use super::SUPERVISOR_CALL_VECTOR;
    use crate::vbar::Group;
    use crate::vbar::Kind;
    use crate::vbar::entry_offset;

    /// A frame is 800 bytes and 16-aligned, so a `q` pair stays aligned.
    #[test]
    fn the_frame_is_a_multiple_of_sixteen() {
        assert_eq!(core::mem::size_of::<ExceptionFrame>(), 816);
        assert_eq!(core::mem::align_of::<ExceptionFrame>(), 16);
        // The assembly subtracts exactly this from `sp`, and a size that was
        // not a multiple of 16 would let a `q` pair straddle a boundary the
        // `stp` encodes as an offset it cannot express.
        assert_eq!(816 % 16, 0);
    }

    /// The class is `ESR_EL1`'s top six bits.
    ///
    /// The syndrome this boot actually produced is the test's vector: EC 7 is
    /// what a trapped SIMD instruction reports, and it is the value that ended
    /// the first aarch64 boot after four lines.  Using it here means the
    /// decoder is checked against an event rather than against arithmetic
    /// invented for the test.
    #[test]
    fn the_class_is_the_top_six_bits_of_the_syndrome() {
        let mut frame = empty_frame();
        frame.esr = 0x1fe0_0000;
        assert_eq!(frame.class(), 7);
        assert_eq!(frame.class_name(), Some("fp/simd trapped"));

        frame.esr = 0x15 << 26;
        assert_eq!(frame.class(), 0x15);
        assert!(frame.is_supervisor_call());
        assert_eq!(frame.class_name(), Some("supervisor call"));
    }

    /// An unrecognised class is reported as such rather than given a name.
    #[test]
    fn an_unknown_class_has_no_name() {
        let mut frame = empty_frame();
        frame.esr = 0x3F << 26;
        assert_eq!(frame.class_name(), None);
        assert!(!frame.is_supervisor_call());
    }

    /// The vector a supervisor call from EL1 arrives at is entry 4, and the
    /// `vbar` module's arithmetic agrees.
    ///
    /// The two modules each need this number: the assembly writes an index and
    /// this module checks it, and `vbar` computes it from the group and kind.
    /// Comparing them here is what keeps "entry 4" from becoming three
    /// opinions.
    #[test]
    fn the_supervisor_call_vector_is_the_fourth_entry() {
        assert_eq!(SUPERVISOR_CALL_VECTOR, 4);
        assert_eq!(
            entry_offset(Group::CurrentSpX, Kind::Synchronous) / crate::vbar::ENTRY_STRIDE,
            SUPERVISOR_CALL_VECTOR
        );
        assert_eq!(
            entry_offset(Group::CurrentSpX, Kind::Irq) / crate::vbar::ENTRY_STRIDE,
            5
        );
        // Entry 8 is a synchronous exception from a *lower* EL, which is a
        // different vector: a system call from user mode.
        assert_eq!(
            entry_offset(Group::Lower64, Kind::Synchronous) / crate::vbar::ENTRY_STRIDE,
            8
        );
    }

    fn empty_frame() -> ExceptionFrame {
        ExceptionFrame {
            registers: [0; 30],
            link_register: 0,
            elr: 0,
            spsr: 0,
            esr: 0,
            far: 0,
            vector: 0,
            simd: [0; 32],
            sp_el0: 0,
        }
    }
}
