//! arch/riscv64/src/trap.rs
//!
//! What a trap arrives as, and the one path that answers it.
//!
//! ## The frame
//!
//! `entry.S`'s `trap_entry` builds [`ExceptionFrame`] on the kernel stack
//! before calling `riscv64_trap_dispatch`, and the two files agree on every
//! offset because the offsets are written down in both.  That is a fact no
//! compiler checks — a `repr(C)` struct and a run of `sd`s are two
//! descriptions of one layout — so the offsets are asserted here against
//! `offset_of!` instead of being trusted.
//!
//! ## The machine does not save the FPU, and neither does this frame
//!
//! `sstatus.FS` is left off from the entry onward, so a float instruction
//! faults rather than silently corrupting state — the same answer x86_64's
//! frame gives for SSE.  aarch64's frame saves its vector registers because
//! that machine's compiler provably emits them for `memcpy`; this one's does
//! not, and a frame that saved registers nothing in this tree uses would be
//! two hundred bytes of ceremony per trap.
//!
//! ## One entry, one cause
//!
//! `stvec` names a single address, and the cause read there is the whole of
//! what arrived: bit 63 says interrupt against exception, and the code says
//! which.  There is no vector table to index and no group to decode — what
//! x86_64's 256 gates and aarch64's sixteen entries pre-decide, this machine
//! asks.
//!
//! ## Why the sinks are statics
//!
//! A trap has no context to hand a function, which is the same reason the
//! other two machines read their sinks from statics.  The kernel installs them
//! with `set_interrupt_dispatch` and `set_call_sink`; until then every trap is
//! unhandled, and an unhandled one stops the machine with its cause on the
//! console.

use crate::stvec::Cause;

/// `sstatus` bit 5: interrupts are enabled on return from `sret`.
///
/// A program is entered with it set, so the first trap back sets `SPIE` to
/// what `SIE` was and the handler runs masked — the same shape x86_64's
/// interrupt gate gives.
pub const SSTATUS_SPIE: u64 = 1 << 5;
/// `sstatus` bit 8: the privilege `sret` returns to.  Set is S-mode, clear is
/// U-mode, and a program's frame always has it clear.
pub const SSTATUS_SPP: u64 = 1 << 8;
/// `sstatus` bit 18: the supervisor may reach a page whose `U` bit is set.
///
/// RISC-V is the reverse of x86_64 here — the kernel may **not** touch user
/// pages unless this bit says so, where x86_64 may unless `SMAP` was switched
/// on.  The entry sets it once, and it is part of a program's initial state so
/// the first `sret` does not clear it out from under the pipe handlers.
pub const SSTATUS_SUM: u64 = 1 << 18;

/// The state a program is entered in: interrupts enabled on the first trap
/// back, and the supervisor's own user-page permission carried across the
/// `sret`.
pub const USER_SSTATUS: u64 = SSTATUS_SPIE | SSTATUS_SUM;

/// The supervisor software interrupt: the one line this machine raises
/// itself, by setting `sip`'s own bit.
pub const SOFTWARE_INTERRUPT: usize = 1;
/// The supervisor timer interrupt, which the firmware's deadline produces.
pub const TIMER_INTERRUPT: usize = 5;
/// An environment call from U-mode: a program asking the kernel for something.
pub const USER_ECALL: usize = 8;

/// The saved context of an interrupted instruction.
///
/// Laid out by `entry.S`, offset for offset, and asserted against
/// `offset_of!` below.  The fields are public because they are what the
/// machine saved and a handler reads them; nothing here has an invariant a
/// setter would protect.
///
/// `registers[i]` is `x[i]`, with `x0` stored as the zero it always reads —
/// the frame is one shape for all thirty-two, and an index that skipped `x0`
/// would make every register's slot two opinions about where it lives.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExceptionFrame {
    /// `x0`..`x31`, in the order the assembly stores them.
    pub registers: [u64; 32],
    /// `sepc`: the instruction that was interrupted.
    ///
    /// For a program's `ecall` this names the **call itself** — the machine
    /// does not advance past it the way aarch64's `ELR` moves past an `svc`.
    /// The advance is this module's job, and forgetting it is a program that
    /// re-executes every call forever.
    pub sepc: u64,
    /// `sstatus`: the state to return to — the privilege, the masks, the
    /// float state.
    pub sstatus: u64,
    /// `scause`: what the trap was, flag and code together.
    pub scause: u64,
    /// `stval`: the address a faulting access named, or zero for a call.
    pub stval: u64,
}

/// What a supervisor call's handler answers.
///
/// Shared shape with the other machines so the kernel names one type: the
/// frame carries six arguments and answers with a word, and a call is the one
/// exception that is a request rather than something that happened to the
/// machine.
#[derive(Debug, Clone, Copy)]
pub struct CallFrame {
    /// The number the program put in `a7`.
    pub number: usize,
    /// The six arguments from `a0`..`a5`.
    pub arguments: [usize; 6],
    /// The instruction after the `ecall`, which is where the program resumes —
    /// the dispatcher advanced `sepc` before the handler saw this frame, so a
    /// handler that parks it parks a resume past the call.
    pub resume: usize,
}

/// What a call's handler answers.
#[derive(Debug, Clone, Copy)]
pub enum CallOutcome {
    /// Resume *this* program with this value in `a0`.
    Return(usize),
    /// The program has ended.  The handler has already chosen what runs next
    /// and has put that program's context where the trap path will find it.
    ///
    /// ## Why this carries no value
    ///
    /// A scheduler that answers "resume *this* context" would be answering
    /// about a dead one.  So the handler does the switch itself — writing the
    /// next context into the frame and, if the next program lives somewhere
    /// else, writing `satp` — and answers only that this program is done.  The
    /// trap path then returns through the same epilogue as a normal call,
    /// which is what keeps one restore path rather than two.
    Exit,
}

// The offsets `entry.S` writes, checked against this structure's.  A mismatch
// is a frame the assembly filled in one place and Rust reads in another, and
// the symptom would be a handler acting on `a0` when it meant `a7`.
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, registers) == 0);
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, sepc) == 256);
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, sstatus) == 264);
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, scause) == 272);
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, stval) == 280);
const _: () = assert!(core::mem::size_of::<ExceptionFrame>() == 288);
const _: () = assert!(core::mem::align_of::<ExceptionFrame>() == 8);

// The register indices the call ABI names, so the frame's array is read
// through names rather than through numbers a reader decodes every time.
/// `a0`: the first argument, and the register a call's answer goes back in.
const REGISTER_A0: usize = 10;
/// `a1`: the second argument, which `Write` prints as the program's number.
const REGISTER_A1: usize = 11;
/// `a7`: the register the call's number travels in — this machine's choice,
/// where aarch64 uses `x8` and x86_64 the gate's own vector.
const REGISTER_A7: usize = 17;

impl ExceptionFrame {
    /// The syscall number a program put in `a7`.
    ///
    /// The register is the ABI's choice, and it is the one every caller sets
    /// before `ecall`.  Reading it here rather than from `a0` keeps the number
    /// and the first argument from sharing a register.
    pub fn syscall_number(&self) -> usize {
        self.registers[REGISTER_A7] as usize
    }

    /// The six arguments a program put in `a0`..`a5`.
    pub fn syscall_arguments(&self) -> [usize; 6] {
        let mut arguments = [0usize; 6];
        for (index, slot) in arguments.iter_mut().enumerate() {
            *slot = self.registers[REGISTER_A0 + index] as usize;
        }
        arguments
    }

    /// Put a syscall's result in `a0`, which is where a caller reads it.
    pub fn set_return(&mut self, value: usize) {
        self.registers[REGISTER_A0] = value as u64;
    }

    /// The cause of this trap, as `scause` splits.
    pub fn cause(&self) -> Cause {
        Cause::of(self.scause as usize)
    }
}

/// What the kernel installs: one function, answering whether it took the frame.
#[cfg(target_os = "none")]
pub type Sink = fn(irq::Frame) -> bool;

#[cfg(target_os = "none")]
static SINK: cell::SyncUnsafeCell<Option<Sink>> = cell::SyncUnsafeCell::new(None);

/// Install the function that handles an interrupt or fault frame.
///
/// Called once by the kernel, after its console is up and before any vector
/// can be raised.  A frame that arrived with no sink is answered by stopping,
/// which is the only answer a machine can give to a trap nobody registered
/// for.
///
/// # Safety
///
/// Called once, before any vector can be raised.  The function must not
/// allocate, block, or enable interrupts: it runs on the kernel stack the
/// trap found.
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

/// The function called at an interrupt, for a scheduler that preempts.
///
/// Separate from the sink because the two answer different questions.  The
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
/// every register, `sepc` and `sstatus`.  A sink that received only the number
/// and the arguments could answer a call and could not switch tasks.
#[cfg(target_os = "none")]
pub type CallSink = fn(CallFrame, &mut ExceptionFrame) -> CallOutcome;

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
    // before U-mode is entered.
    unsafe { *CALL_SINK.get() = Some(sink) };
}

// The entry the trap vector names, as the assembly defined it.  A `//` and
// not a `///`: a doc comment on an extern block decorates nothing.
#[cfg(target_os = "none")]
unsafe extern "C" {
    static trap_entry: u8;
}

/// The address the machine should trap to.
#[cfg(target_os = "none")]
fn trap_entry_address() -> usize {
    // `addr_of!` takes the address without creating a reference; there is a
    // run of instructions there, not a value.
    core::ptr::addr_of!(trap_entry) as usize
}

/// What `stvec` holds, as the machine reports it.
#[cfg(target_os = "none")]
fn installed_table() -> usize {
    let value: u64;
    // SAFETY: reading `stvec` at S-mode has no side effect; the low two bits
    // are the mode and the address is what remains.
    unsafe {
        core::arch::asm!(
            "csrr {}, stvec",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        )
    };
    (value as usize) & !0x3
}

/// Install the trap vector, and answer whether the machine took the write.
///
/// There is no self-test `ecall` here, and the absence is not an omission: an
/// `ecall` from S-mode is the **firmware's** door — the same instruction that
/// arms the timer — and OpenSBI owns it.  A supervisor call raised as a probe
/// would be a request to another program's handler, not a trap into this one.
/// The proof the path works comes from the line this machine can raise
/// itself, the software interrupt, which the boot raises the moment this
/// returns; the trap's cause and the handler's record are what the boot's
/// interrupt line asserts.
///
/// # Safety
///
/// Called once, after [`set_sink`] and before the kernel enables interrupts.
#[cfg(target_os = "none")]
pub unsafe fn install_table() -> bool {
    let entry = trap_entry_address();
    // SAFETY: the address is this file's own assembly, 4-aligned as `stvec`'s
    // direct mode requires.  Writing it is what makes a trap land somewhere
    // rather than nowhere.
    unsafe {
        core::arch::asm!("csrw stvec, {}", in(reg) entry as u64, options(nostack));
    }
    installed_table() == entry
}

/// Clear the software interrupt's own pending bit.
///
/// The source of the one interrupt this machine raises itself is a bit in
/// `sip`, and a bit that stays set takes the same interrupt again the moment
/// interrupts are enabled.  The controller-less acknowledge is the clear.
///
/// # Safety
///
/// Called from the trap path, for an interrupt whose code is the software
/// line.
#[cfg(target_os = "none")]
pub unsafe fn clear_software_pending() {
    // SAFETY: clearing the pending bit of the line that was just taken.  The
    // interrupt is in service; leaving it pending would re-enter forever.
    unsafe {
        core::arch::asm!(
            "csrc sip, {}",
            in(reg) (1u64 << SOFTWARE_INTERRUPT),
            options(nomem, nostack)
        )
    };
}

/// Serve a program's supervisor call and resume it.
///
/// ## Why the frame is written rather than copied back
///
/// `entry.S` restores `x1`..`x31` and the system registers from the frame
/// before `sret`, so a value written into the frame's `a0` *is* the value the
/// program finds on return.  Copying it somewhere else afterwards would need a
/// second restore path, which is the one thing the assembly's common epilogue
/// exists to avoid.
///
/// ## Why `sepc` is advanced before the handler runs, not after it answers
///
/// The machine names the `ecall` itself, not the instruction after it — the
/// opposite of aarch64, whose `ELR` the hardware has already moved past the
/// `svc` before any handler exists.  And a handler may **park the frame**: a
/// sleep saves it with a deadline, a blocked read saves it for a writer.  What
/// a wake later resumes is whatever the frame held when it was parked — so the
/// advance has to be inside the frame *before* the handler sees it.  Placed
/// after the answer, it repairs only the call that returned immediately: the
/// sleeper resumed at the call it had just made, slept again, and did so
/// forever, which is what the first boot's log did in a two-millisecond
/// rhythm.
#[cfg(target_os = "none")]
fn serve_user_call(frame: &mut ExceptionFrame) {
    // The one instruction the machine did not advance: the `ecall` is four
    // bytes, and everything from here on — the handler's saved frames, the
    // answer's resume — names the instruction after it.
    frame.sepc = frame.sepc.wrapping_add(4);

    let call = CallFrame {
        number: frame.syscall_number(),
        arguments: frame.syscall_arguments(),
        resume: frame.sepc as usize,
    };

    // SAFETY: the sink is installed before U-mode is entered and this runs
    // after.
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
        // The handler has already written what resumes into this frame, and
        // the epilogue below restores it and `sret`s.  Nothing to do here,
        // which is the point: one restore path, whichever program it belongs
        // to.
        CallOutcome::Exit => {}
    }
}

/// The dispatch the assembly calls.
///
/// # Safety
///
/// `extern "C"` because `entry.S` calls it, with a pointer to the frame that
/// file built on the kernel stack.  The pointer must name a live
/// [`ExceptionFrame`], which is the assembly's contract — and it does not
/// unwind: a trap has no context to unwind into.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn riscv64_trap_dispatch(frame: *mut ExceptionFrame) {
    // SAFETY: `entry.S` passes `sp` after building the frame at that address,
    // and nothing else holds it.
    let frame = unsafe { &mut *frame };
    let cause = frame.cause();

    if cause.interrupt {
        // The software line silences its own source before the handler sees
        // it: the bit that raised it stays set until something clears it, and
        // a return to a still-set source is the same interrupt again.
        if cause.code == SOFTWARE_INTERRUPT {
            // SAFETY: this is the software line's own acknowledge.
            unsafe { clear_software_pending() };
        }

        // The code is the identity: a controller on this machine assigns no
        // numbers of its own, so the cause *is* what a driver registers under.
        let shared = irq::Frame::device(cause.code);
        let handled = match sink() {
            Some(sink) => sink(shared),
            None => false,
        };

        // The preemption point, after the source is silenced: whether the CPU
        // now goes to another program is the scheduler's decision, and the
        // frame is the machine's — this interrupt interrupted whatever the
        // program was doing, so its saved state is the whole context.
        if handled && let Some(preempt) = preempt_sink() {
            preempt(frame);
        }

        if !handled {
            crate::serial::write_str("protofire: unhandled interrupt ");
            crate::serial::write_u32(cause.code as u32);
            crate::serial::write_str("\n");
            // Not fatal: a machine this boot does not know may raise its line
            // whether or not anything wants it, and a kernel that stopped
            // here could not boot on a machine with one device more than it
            // knows.
        }
        return;
    }

    // A supervisor call from a program is the one exception that is a
    // *request*: served and resumed, which is what makes this the first path
    // in the tree where something outside the kernel can reach the registry.
    if cause.code == USER_ECALL {
        return serve_user_call(frame);
    }

    // Everything else is a fault, and the address it named is the half that
    // makes a log line diagnosable.
    let shared = irq::Frame::fault(cause.code, frame.stval as usize);
    let handled = match sink() {
        Some(sink) => sink(shared),
        None => false,
    };

    if !handled {
        crate::serial::write_str("protofire: unhandled exception ");
        crate::serial::write_u32(cause.code as u32);
        crate::serial::write_str(" (");
        crate::serial::write_str(cause.name());
        crate::serial::write_str(") at ");
        crate::serial::write_hex(frame.sepc);
        if frame.stval != 0 {
            crate::serial::write_str(", address ");
            crate::serial::write_hex(frame.stval);
        }
        crate::serial::write_str("\n");
        crate::halt()
    }
}

/// What a program's context looks like to a scheduler.
///
/// The whole 288-byte frame the assembly built, so a task switch is a copy of
/// one of these into the frame the trap path already has on the stack.
pub type Context = ExceptionFrame;

/// The context a program begins with.
///
/// Every register zero except the two that decide where it runs: `sepc` names
/// the entry and `x2` the stack it runs on.  A program that started with a
/// kernel value in a register would be one whose first instruction ran on it.
pub fn starting_context(entry: usize, stack_top: usize) -> Context {
    // The stack pointer belongs in `x2` and nowhere else: on this machine `x2`
    // *is* the stack pointer, and a context that carried it anywhere else
    // would be one the trap path restored onto the wrong stack.
    let mut registers = [0; 32];
    registers[STACK_POINTER_REGISTER] = stack_top as u64;
    ExceptionFrame {
        registers,
        sepc: entry as u64,
        sstatus: USER_SSTATUS,
        scause: 0,
        stval: 0,
    }
}

/// `x2`, which is both the ABI's stack pointer and the register the trap path
/// restores last — the frame's `sp` slot is the one the assembly's return path
/// treats specially.
const STACK_POINTER_REGISTER: usize = 2;

/// Where a context resumes: the instruction the `sret` will return to.
pub fn resume_address(context: &Context) -> usize {
    context.sepc as usize
}

/// Point a context at another address, for a caller building one by hand.
pub fn set_resume_address(context: &mut Context, address: usize) {
    context.sepc = address as u64;
}

/// The stack pointer a context runs on.
pub fn stack_pointer(context: &Context) -> usize {
    context.registers[STACK_POINTER_REGISTER] as usize
}

/// The word a program reads a call's answer from.
pub fn return_value(context: &Context) -> usize {
    context.registers[REGISTER_A0] as usize
}

/// Put a call's answer where a program reads it.
pub fn set_return_value(context: &mut Context, value: usize) {
    context.registers[REGISTER_A0] = value as u64;
}

/// Whether a context is a program's rather than the kernel's.
///
/// `sstatus`'s `SPP` bit names the privilege an `sret` returns to, and clear
/// is U-mode — the only state a program runs in.  Set is S-mode, which is
/// what the boot's own traps carry.
pub fn is_user_context(context: &Context) -> bool {
    context.sstatus & SSTATUS_SPP == 0
}

/// The state the trap path will restore, for a boot line that reports it.
pub fn return_state(context: &Context) -> u64 {
    context.sstatus
}

/// Write `context` over the frame the trap path will restore.
///
/// That is the whole of a task switch: the epilogue restores every register,
/// `sepc` and `sstatus` from this frame, so replacing it replaces what the
/// machine does next — including the privilege it returns to.
#[cfg(target_os = "none")]
pub fn install_context(frame: &mut ExceptionFrame, context: &Context) {
    *frame = *context;
}

// The program a boot runs, as this machine's machine code.
//
// A program is machine code, so the array lives with the machine that
// executes it: `ecall` is the call, `a7` carries the number and `a1` holds
// this program's own number because `Write` prints its second argument.  The
// kernel names `arch::program_bytes` and gets whichever machine answered.

/// How long a program's image is, in bytes.
///
/// The longest of the three images: the announcing program, the pipe writer
/// and the pipe reader.  A program is copied into a whole page, so this
/// matters only to the copy.
pub const PROGRAM_LEN: usize = 24 * 4;

/// The number of the program that reads the pipe.
pub const PIPE_READER: u16 = 3;

/// The number of the program that writes to it.
pub const PIPE_WRITER: u16 = 2;

/// How long the program sleeps, in microseconds.
///
/// Two thousand, and that is the encoding's answer rather than a preference:
/// the sleep travels in an `addi` immediate, whose twelve signed bits reach
/// two thousand and forty-seven — the aarch64 program's twenty thousand needs
/// the sixteen bits a `movz` has, which this machine's instruction does not.
/// Two milliseconds is twenty time slices at this boot's hundred, which is
/// what the duration is for: a wake observably later than the request, where
/// a sleep the timer could not distinguish from "did not sleep" would be a
/// call that ran and proved nothing.
pub const SLEEP_MICROSECONDS: u64 = 2_000;

/// `addi rd, rs, imm`, as the word the machine reads.
///
/// The workhorse of a hand-written program: every immediate the ABI needs — a
/// call number in `a7`, a duration in `a0`, this program's own number in `a1`
/// — is one of these.  A helper rather than thirty literals, because an
/// immediate encoded wrong by hand is an instruction the machine reads as
/// something else and the failure is a plausible-looking wrong answer.
const fn addi(rd: u32, rs: u32, immediate: i32) -> u32 {
    // `imm[11:0] | rs1 | funct3 | rd | opcode`, the I-type layout.
    ((immediate as u32) & 0xFFF) << 20 | rs << 15 | rd << 7 | 0x13
}

/// `bne rs, x0, offset`, as the word the machine reads.
///
/// The busy loop's only branch: one register counted down against zero, back
/// to the instruction `offset` bytes before.  Encoded here for the same reason
/// `addi` is — a branch offset in the wrong field loops to an address the
/// program did not mean, and the failure is a fault far from the word that
/// caused it.
const fn bne_against_zero(rs: u32, offset: i32) -> u32 {
    let immediate = (offset as u32) & 0x1FFF;
    // `imm[12|10:5] | rs2=0 | rs1 | funct3 | imm[4:1|11] | opcode`, the
    // B-type layout: the immediate is split around the registers it does not
    // touch.
    (immediate & 0x1000) << 19
        | ((immediate >> 5) & 0x3F) << 25
        | rs << 20
        | 1 << 12
        | (immediate & 0x1E) << 7
        | (immediate & 0x800) >> 4
        | 0x63
}

/// The busy loop: outer 64, inner 256, one decrement each.
///
/// Without it a program finishes in microseconds, no tick arrives, and a boot
/// that never preempted is indistinguishable from one that could not.  The
/// loop is nested because one register's twelve-bit immediate is a small
/// count, and the counts are the aarch64 program's — the same work per
/// iteration, so the same number of them spans a slice under the same
/// emulator.
const BUSY_LOOP: [u32; 6] = [
    addi(13, 0, 64),           // li a3, #64      (outer)
    addi(12, 0, 256),          // li a2, #256     (inner)
    addi(12, 12, -1),          // addi a2, a2, -1
    bne_against_zero(12, -4),  // bne a2, x0, back to the decrement
    addi(13, 13, -1),          // addi a3, a3, -1
    bne_against_zero(13, -16), // bne a3, x0, back to the inner reload
];

/// One program's words: its number, a busy loop, and four calls.
///
/// Built rather than stored so the number is a parameter: a table of two
/// constants would be two things to keep in step with the encoding.
///
/// ## Why the order is loop, Write, Sleep, Write, Exit
///
/// The first `Write` says which program ran.  `Sleep` then takes it out of the
/// rotation for [`SLEEP_MICROSECONDS`], during which the *other* program runs —
/// so a log that shows two "says hello" lines before the second program's is a
/// log where sleeping worked.  The second `Write` after the sleep is what makes
/// the wake visible: a program that never woke prints one line, not two.
const fn program_words(number: u16) -> [u32; 18] {
    [
        BUSY_LOOP[0],
        BUSY_LOOP[1],
        BUSY_LOOP[2],
        BUSY_LOOP[3],
        BUSY_LOOP[4],
        BUSY_LOOP[5],
        addi(REGISTER_A1 as u32, 0, number as i32), // li a1, #number
        addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Write as i32),
        0x0000_0073,                                            // ecall
        addi(REGISTER_A0 as u32, 0, SLEEP_MICROSECONDS as i32), // li a0, #the sleep
        addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Sleep as i32),
        0x0000_0073, // ecall
        addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Write as i32),
        0x0000_0073, // ecall
        addi(REGISTER_A0 as u32, 0, 0),
        addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Exit as i32),
        0x0000_0073, // ecall
        0x0000_006F, // j .
    ]
}

/// The writer: announce, sleep, announce again, then put bytes in the pipe.
///
/// The reader must reach its `Read` first and block, or a write into a pipe
/// nobody has read yet is an ordinary copy.  The reader's loop is shorter and
/// it makes no earlier call; this sleep then makes the order a fact rather
/// than a hope.
///
/// `x2` — the stack pointer — points at the write end's descriptor, and the
/// four bytes it sends are the word above it.
const PIPE_WRITER_PROGRAM: [u32; 24] = [
    BUSY_LOOP[0],
    BUSY_LOOP[1],
    BUSY_LOOP[2],
    BUSY_LOOP[3],
    BUSY_LOOP[4],
    BUSY_LOOP[5],
    addi(REGISTER_A1 as u32, 0, 2), // li a1, #2   (this program's number)
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Write as i32),
    0x0000_0073, // ecall
    addi(REGISTER_A0 as u32, 0, SLEEP_MICROSECONDS as i32),
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Sleep as i32),
    0x0000_0073,                    // ecall
    addi(REGISTER_A1 as u32, 0, 2), // li a1, #2   (Write, after the wake)
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Write as i32),
    0x0000_0073,                        // ecall
    0x0001_3503,                        // ld a0, 0(sp)  (the write end)
    addi(REGISTER_A1 as u32, 2, 8),     // addi a1, sp, #8 (the bytes)
    addi(REGISTER_A0 as u32 + 2, 0, 4), // li a2, #4
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Write as i32),
    0x0000_0073, // ecall
    addi(REGISTER_A0 as u32, 0, 0),
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Exit as i32),
    0x0000_0073, // ecall
    0x0000_006F, // j .
];

/// The reader: wait on a descriptor the boot left on its stack.
///
/// `x2` points at the read end's descriptor and the four-byte buffer is the
/// word above it.  The read blocks — the pipe is empty and its writer is
/// alive — and the writer's syscall is the only thing that ends the wait.
const PIPE_READER_PROGRAM: [u32; 21] = [
    BUSY_LOOP[0],
    BUSY_LOOP[1],
    BUSY_LOOP[2],
    BUSY_LOOP[3],
    BUSY_LOOP[4],
    BUSY_LOOP[5],
    addi(REGISTER_A1 as u32, 0, 3), // li a1, #3     (announce)
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Write as i32),
    0x0000_0073,                        // ecall
    0x0001_3503,                        // ld a0, 0(sp)  (the read end)
    addi(REGISTER_A1 as u32, 2, 8),     // addi a1, sp, #8 (the buffer)
    addi(REGISTER_A0 as u32 + 2, 0, 4), // li a2, #4
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Read as i32),
    0x0000_0073, // ecall
    // The length is cleared before the second announcement: `a2` still holds
    // the read's four, and a write with a length to a pipe descriptor is a
    // pipe write, so the announcement would go into the pipe and print
    // nothing.
    addi(REGISTER_A0 as u32 + 2, 0, 0), // li a2, #0     (announce has no length)
    addi(REGISTER_A1 as u32, 0, 3),     // li a1, #3     (Write, after the wait)
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Write as i32),
    0x0000_0073, // ecall
    addi(REGISTER_A0 as u32, 0, 0),
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Exit as i32),
    0x0000_0073, // ecall
];

/// A program's bytes, for a caller that writes them into a frame.
pub fn program_bytes(number: u16) -> [u8; PROGRAM_LEN] {
    let mut bytes = [0u8; PROGRAM_LEN];
    let mut words = [0u32; PROGRAM_LEN / 4];
    if number == PIPE_WRITER {
        words[..PIPE_WRITER_PROGRAM.len()].copy_from_slice(&PIPE_WRITER_PROGRAM);
    } else if number == PIPE_READER {
        words[..PIPE_READER_PROGRAM.len()].copy_from_slice(&PIPE_READER_PROGRAM);
    } else {
        let announcing = program_words(number);
        words[..announcing.len()].copy_from_slice(&announcing);
    }
    for (index, word) in words.iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    use super::addi;
    use super::bne_against_zero;
    use super::program_bytes;
    use super::program_words;

    /// The immediate an `addi` encodes, decoded back the way the machine
    /// sign-extends it: twelve bits, so a word whose top immediate bit is set
    /// decodes negative, and a decode that stopped at sixteen would call
    /// forty thousand nine hundred and fifty-one the same as minus one.
    fn addi_immediate(word: u32) -> i32 {
        (word as i32) >> 20
    }

    /// The offset a branch word encodes, decoded back the way the machine
    /// reads it: the immediate is split around the register fields, and the
    /// test is what keeps the encoder and the decoder from agreeing on a
    /// reading neither of them got from the layout.
    fn branch_offset(word: u32) -> i32 {
        let immediate = ((word >> 31) & 1) << 12
            | ((word >> 25) & 0x3F) << 5
            | ((word >> 8) & 0xF) << 1
            | ((word >> 7) & 1) << 11;
        // Sign-extend from thirteen bits.
        ((immediate << 19) as i32) >> 19
    }

    /// The program's bytes are the words in little-endian order.
    #[test]
    fn the_program_is_little_endian() {
        let bytes = program_bytes(1);
        assert_eq!(bytes.len(), super::PROGRAM_LEN);
        assert_eq!(&bytes[0..4], &0x0400_0693u32.to_le_bytes());
    }

    /// The immediate an `addi` encodes is the one it decodes to, across the
    /// sign the twelve-bit field carries: a negative decrement must come back
    /// negative, or the busy loop counts up and never ends.
    #[test]
    fn an_addi_immediate_survives_the_round_trip() {
        assert_eq!(addi_immediate(addi(12, 12, -1)), -1);
        assert_eq!(addi_immediate(addi(13, 0, 64)), 64);
        assert_eq!(addi_immediate(addi(17, 0, 6)), 6);
        // The sign is where the decode bites: the field is twelve bits, and
        // an immediate whose eleventh bit is set is negative, not a large
        // positive number the program never asked for.
        assert_eq!(addi_immediate(addi(10, 0, -480)), -480);
        // The register fields, too: an immediate in the wrong field would
        // still decode as *an* addi, just not this one.
        assert_eq!((addi(12, 12, -1) >> 15) & 0x1F, 12, "rs1");
        assert_eq!((addi(12, 12, -1) >> 7) & 0x1F, 12, "rd");
    }

    /// The busy loop branches back to itself, decoded from the encoding: the
    /// inner branch reaches the decrement four bytes up, and the outer one
    /// reaches the inner reload sixteen bytes up.
    #[test]
    fn the_busy_loop_branches_back_to_itself() {
        let words = program_words(1);
        assert_eq!(words[0], addi(13, 0, 64), "li a3, #64");
        assert_eq!(words[1], addi(12, 0, 256), "li a2, #256");

        let inner = branch_offset(words[3]);
        assert_eq!(inner, -4, "the inner branch loops on the decrement");
        assert_eq!(branch_offset(words[5]), -16, "the outer reloads");
    }

    /// Every syscall number the program uses is the ABI's own.
    ///
    /// Four calls: `Write`, `Sleep`, `Write`, `Exit`.  A program compiled
    /// against a number this build does not serve would print its first line
    /// and then fail silently, which is the one failure a sleep program could
    /// have and still look healthy.
    #[test]
    fn the_program_calls_write_sleep_write_and_exit() {
        let words = program_words(1);
        assert_eq!(
            addi_immediate(words[7]) as usize,
            abi::SyscallNumber::Write as usize,
            "the first call is Write"
        );
        assert_eq!(
            addi_immediate(words[10]) as usize,
            abi::SyscallNumber::Sleep as usize,
            "then Sleep"
        );
        assert_eq!(
            addi_immediate(words[12]) as usize,
            abi::SyscallNumber::Write as usize,
            "then Write again, after the wake"
        );
        assert_eq!(
            addi_immediate(words[15]) as usize,
            abi::SyscallNumber::Exit as usize,
            "and Exit"
        );

        // The sleep's duration is the immediate in `li a0`.
        assert_eq!(addi_immediate(words[9]) as u64, super::SLEEP_MICROSECONDS);
        // And the program's own number is the immediate in `li a1`.
        assert_eq!(addi_immediate(words[6]) as usize, 1);
    }

    /// The number is the only word that differs.
    #[test]
    fn the_number_is_the_only_word_that_differs() {
        let one = program_words(1);
        let two = program_words(2);
        let differing: alloc::vec::Vec<usize> = (0..one.len())
            .filter(|index| one[*index] != two[*index])
            .collect();
        assert_eq!(differing, alloc::vec![6], "only `li a1` differs");
        assert_eq!(addi_immediate(one[6]) as usize, 1);
        assert_eq!(addi_immediate(two[6]) as usize, 2);
    }

    /// The writer's fourth call names the pipe: the descriptor is loaded from
    /// the stack the boot handed it, the buffer is the word above it, and the
    /// length is the four the payload needs.
    #[test]
    fn the_writer_reads_its_descriptor_from_the_stack() {
        let words = super::PIPE_WRITER_PROGRAM;
        // `ld a0, 0(sp)` — the load's width field is 3 and the register is the
        // stack pointer's.
        assert_eq!(words[15], 0x0001_3503);
        assert_eq!(addi_immediate(words[16]), 8, "the buffer is at sp + 8");
        assert_eq!(addi_immediate(words[17]), 4, "the payload is four bytes");
        assert_eq!(
            addi_immediate(words[18]) as usize,
            abi::SyscallNumber::Write as usize,
            "and the call is a Write"
        );
    }

    /// The reader clears the length before its second announcement: a write
    /// that still carried the read's four would be a pipe write, and the
    /// announcement would vanish into the pipe.
    #[test]
    fn the_reader_clears_the_length_before_it_announces_again() {
        let words = super::PIPE_READER_PROGRAM;
        assert_eq!(addi_immediate(words[11]), 4, "the read asked for four");
        assert_eq!(
            addi_immediate(words[12]) as usize,
            abi::SyscallNumber::Read as usize,
        );
        assert_eq!(
            addi_immediate(words[14]),
            0,
            "and the announce's length is zero"
        );
        assert_eq!(
            addi_immediate(words[16]) as usize,
            abi::SyscallNumber::Write as usize,
        );
    }

    /// The branch helper agrees with the encoder it tests, on a positive
    /// offset too — a helper and its subject written from one reading of the
    /// layout would agree on the one value they were both written for.
    #[test]
    fn the_branch_decoder_decodes_what_the_encoder_encoded() {
        assert_eq!(branch_offset(bne_against_zero(12, -4)), -4);
        assert_eq!(branch_offset(bne_against_zero(13, -16)), -16);
        assert_eq!(branch_offset(bne_against_zero(12, 8)), 8);
    }
}
