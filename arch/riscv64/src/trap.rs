//! arch/riscv64/src/trap.rs
//!
//! What a trap arrives as, and the one path that answers it.
//!
//! ## The frame
//!
//! `entry.S`'s `trap_entry` builds [`ExceptionFrame`] on the kernel stack
//! before calling `riscv64_trap_dispatch`, and the two files agree on every
//! offset because the offsets are written down in both.  That is a fact no
//! compiler checks, a `repr(C)` struct and a run of `sd`s are two
//! descriptions of one layout, so the offsets are asserted here against
//! `offset_of!` instead of being trusted.
//!
//! ## The machine does not save the FPU, and neither does this frame
//!
//! `sstatus.FS` is left off from the entry onward, so a float instruction
//! faults rather than silently corrupting state, the same answer x86_64's
//! frame gives for SSE.  aarch64's frame saves its vector registers because
//! that machine's compiler provably emits them for `memcpy`; this one's does
//! not, and a frame that saved registers nothing in this tree uses would be
//! two hundred bytes of ceremony per trap.
//!
//! ## One entry, one cause
//!
//! `stvec` names a single address, and the cause read there is the whole of
//! what arrived: bit 63 says interrupt against exception, and the code says
//! which.  There is no vector table to index and no group to decode, what
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
/// what `SIE` was and the handler runs masked, the same shape x86_64's
/// interrupt gate gives.
pub const SSTATUS_SPIE: u64 = 1 << 5;
/// `sstatus` bit 8: the privilege `sret` returns to.  Set is S-mode, clear is
/// U-mode, and a program's frame always has it clear.
pub const SSTATUS_SPP: u64 = 1 << 8;
/// `sstatus` bit 18: the supervisor may reach a page whose `U` bit is set.
///
/// RISC-V is the reverse of x86_64 here, the kernel may **not** touch user
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
/// The supervisor external interrupt, which a PLIC source reaches a hart as.
pub const EXTERNAL_INTERRUPT: usize = 9;

/// The saved context of an interrupted instruction.
///
/// Laid out by `entry.S`, offset for offset, and asserted against
/// `offset_of!` below.  The fields are public because they are what the
/// machine saved and a handler reads them; nothing here has an invariant a
/// setter would protect.
///
/// `registers[i]` is `x[i]`, with `x0` stored as the zero it always reads, ///
/// the frame is one shape for all thirty-two, and an index that skipped `x0`
/// would make every register's slot two opinions about where it lives.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExceptionFrame {
    /// `x0`..`x31`, in the order the assembly stores them.
    pub registers: [u64; 32],
    /// `sepc`: the instruction that was interrupted.
    ///
    /// For a program's `ecall` this names the **call itself**, the machine
    /// does not advance past it the way aarch64's `ELR` moves past an `svc`.
    /// The advance is this module's job, and forgetting it is a program that
    /// re-executes every call forever.
    pub sepc: u64,
    /// `sstatus`: the state to return to, the privilege, the masks, the
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
    /// The instruction after the `ecall`, which is where the program resumes,
    /// /// the dispatcher advanced `sepc` before the handler saw this frame, so
    /// a handler that parks it parks a resume past the call.
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
    /// about a dead one.  So the handler does the switch itself, writing the
    /// next context into the frame and, if the next program lives somewhere
    /// else, writing `satp`, and answers only that this program is done.  The
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
pub(crate) const REGISTER_A0: usize = 10;
/// `a1`: the second argument, which `Write` prints as the program's number.
pub(crate) const REGISTER_A1: usize = 11;
/// `a7`: the register the call's number travels in, this machine's choice,
/// where aarch64 uses `x8` and x86_64 the gate's own vector.
pub(crate) const REGISTER_A7: usize = 17;

/// `a6`, which no call in this tree writes, used by a program to keep a value
/// across a call that would overwrite `a0`.
pub(crate) const REGISTER_A6: usize = 16;

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
/// because an `Exit` has to replace the whole context with another program's,
/// /// every register, `sepc` and `sstatus`.  A sink that received only the
/// number and the arguments could answer a call and could not switch tasks.
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
/// `ecall` from S-mode is the **firmware's** door, the same instruction that
/// arms the timer, and OpenSBI owns it.  A supervisor call raised as a probe
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
/// The machine names the `ecall` itself, not the instruction after it, the
/// opposite of aarch64, whose `ELR` the hardware has already moved past the
/// `svc` before any handler exists.  And a handler may **park the frame**: a
/// sleep saves it with a deadline, a blocked read saves it for a writer.  What
/// a wake later resumes is whatever the frame held when it was parked, so the
/// advance has to be inside the frame *before* the handler sees it.  Placed
/// after the answer, it repairs only the call that returned immediately: the
/// sleeper resumed at the call it had just made, slept again, and did so
/// forever, which is what the first boot's log did in a two-millisecond
/// rhythm.
#[cfg(target_os = "none")]
fn serve_user_call(frame: &mut ExceptionFrame) {
    // The one instruction the machine did not advance: the `ecall` is four
    // bytes, and everything from here on, the handler's saved frames, the
    // answer's resume, names the instruction after it.
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

/// Claim an external interrupt, hand it over, and finish it.
///
/// ## Why claim, handle, complete
///
/// The PLIC's `claim` answers the highest-priority pending source and clears
/// its pending bit; `complete` with the same number is what lets the source be
/// delivered again.  A handler that returned after only the claim would leave a
/// device able to raise one interrupt and then silence for the rest of the boot
///, the same failure a GIC without its `EOIR` produces, and just as invisible
/// until the device's second event is the one that mattered.
///
/// A claim of nothing is not a failure: an interrupt can be withdrawn between
/// the line arriving and the claim being read, and the honest answer is to
/// return and let the machine continue.
#[cfg(target_os = "none")]
fn finish_external(frame: &mut ExceptionFrame) {
    // SAFETY: the controller is written once by the boot before any line is
    // enabled.
    let Some(controller) = (unsafe { *CONTROLLER.get() }) else {
        crate::serial::write_str("protofire: external interrupt with no controller\n");
        crate::halt()
    };

    // SAFETY: the window is the tree's `reg` and this runs in the trap path,
    // where nothing else touches it.
    let Some(number) = (unsafe { controller.claim() }) else {
        return;
    };

    // The console's UART is the one source this tree drives, and it is
    // acknowledged at the *device* before the controller is told the source is
    // finished.  The order is the point: a 16550 keeps its line raised until
    // something reads `IIR`, so a source completed at the PLIC but not at the
    // device arrives again the moment interrupts are unmasked, which is a storm
    // rather than a handler.
    let is_console = crate::console_source().is_some_and(|source| source == number);
    let acknowledged = if is_console {
        // SAFETY: `number` is the console's own source.
        unsafe { crate::acknowledge_console() }
    } else {
        false
    };

    let handled = match sink() {
        Some(sink) => sink(irq::Frame::device(number)),
        None => false,
    };

    // SAFETY: `number` is what `claim` answered.
    unsafe { controller.complete(number) };

    // And silenced, so the one interrupt this boot asked for is the one it got.
    // A transmitter interrupt fires whenever the holding register is empty, so
    // an enabled device turns every printed byte into a trap inside the print
    // that reports it.
    if is_console && acknowledged {
        // SAFETY: `number` is the console's source and the device has been
        // acknowledged.
        unsafe { crate::silence_console() };
    }

    // The preemption point, after the source is finished: a switch made before
    // the completion would leave the line claimed in a task that may not run
    // again for a while.
    if handled && let Some(preempt) = preempt_sink() {
        preempt(frame);
    }

    if !handled {
        crate::serial::write_str("protofire: unhandled external interrupt ");
        crate::serial::write_u32(number as u32);
        crate::serial::write_str("\n");
    }
}

/// Record the controller the boot enabled, so an external interrupt can be
/// claimed.
///
/// # Safety
///
/// Called once, after [`crate::plic::Plic::enable`], before any source is
/// enabled.  The window must stay mapped for the life of the boot.
#[cfg(target_os = "none")]
pub unsafe fn set_controller(plic: crate::plic::Plic) {
    // SAFETY: the caller promises this is the only write, and it happens before
    // any source can be enabled.
    unsafe { *CONTROLLER.get() = Some(plic) };
}

/// The controller the boot installed, if it installed one.
///
/// What a boot line reads to report the controller it is actually using: a
/// line built from the device tree would print the same words on a boot whose
/// driver was never installed.
#[cfg(target_os = "none")]
pub fn controller() -> Option<crate::plic::Plic> {
    // SAFETY: written once by the boot before any source is enabled, read
    // after.
    unsafe { *CONTROLLER.get() }
}

/// The controller, once the boot has found and enabled one.
#[cfg(target_os = "none")]
static CONTROLLER: cell::SyncUnsafeCell<Option<crate::plic::Plic>> =
    cell::SyncUnsafeCell::new(None);

/// The dispatch the assembly calls.
///
/// # Safety
///
/// `extern "C"` because `entry.S` calls it, with a pointer to the frame that
/// file built on the kernel stack.  The pointer must name a live
/// [`ExceptionFrame`], which is the assembly's contract, and it does not
/// unwind: a trap has no context to unwind into.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn riscv64_trap_dispatch(frame: *mut ExceptionFrame) {
    // SAFETY: `entry.S` passes `sp` after building the frame at that address,
    // and nothing else holds it.
    let frame = unsafe { &mut *frame };
    let cause = frame.cause();

    // A CPU that is not the boot CPU answers its own interrupt and nothing
    // else.
    //
    // The kernel's sink is the boot CPU's: it wakes sleepers and hands frames
    // to a scheduler that is one structure with no lock.  A second CPU that
    // called it would write state the boot CPU owns, and the first thing the
    // log showed was a fault inside the device tree, because the other CPU had
    // walked into the console sink's path.  What a second CPU does with a trap
    // is count it, silence any source it raised, and return; its clock is
    // re-armed by the kernel's handler only through the path it is allowed to
    // take, which is the count.
    if !crate::boot_cpu_owns_this_trap() {
        if cause.interrupt && cause.code == SOFTWARE_INTERRUPT {
            // SAFETY: the software line's own acknowledge.
            unsafe { clear_software_pending() };
        }
        return;
    }

    if cause.interrupt {
        // An external source is claimed from the controller, handed to the
        // sink by its number, and finished.  Without the claim the trap has no
        // identity, the PLIC answers one on request and a handler needs it, //
        // and without the finish the source is never delivered a second time.
        if cause.code == EXTERNAL_INTERRUPT {
            return finish_external(frame);
        }

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
        // frame is the machine's, this interrupt interrupted whatever the
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
/// restores last, the frame's `sp` slot is the one the assembly's return path
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
/// is U-mode, the only state a program runs in.  Set is S-mode, which is
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
/// machine does next, including the privilege it returns to.
#[cfg(target_os = "none")]
pub fn install_context(frame: &mut ExceptionFrame, context: &Context) {
    *frame = *context;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The program's bytes are the words in little-endian order.
    #[test]
    fn the_program_is_little_endian() {
        let bytes = crate::program::program_bytes(1);
        assert_eq!(bytes.len(), crate::program::PROGRAM_LEN);
        assert_eq!(&bytes[0..4], &0x0400_0693u32.to_le_bytes());
    }

    /// The frame's offsets are the assembly's, checked at compile time by the
    /// `const` assertions above; what a test can add is that the size is a
    /// multiple of the alignment the hardware restores under.
    #[test]
    fn the_frame_is_aligned() {
        assert_eq!(core::mem::size_of::<ExceptionFrame>() % 8, 0);
        assert_eq!(core::mem::align_of::<ExceptionFrame>(), 8);
    }

    /// The registers a call reads are the ABI's, not this module's choice.
    #[test]
    fn the_call_registers_are_the_abis() {
        let mut frame = crate::trap::starting_context(0, 0);
        frame.registers[17] = abi::SyscallNumber::Write as u64;
        frame.registers[10] = 7;
        assert_eq!(frame.syscall_number(), abi::SyscallNumber::Write as usize);
        assert_eq!(frame.syscall_arguments()[0], 7, "a0 is the first argument");
    }
}
