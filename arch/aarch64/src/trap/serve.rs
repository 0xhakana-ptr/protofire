//! arch/aarch64/src/trap/serve.rs
//!
//! The two things a frame can turn out to be: a supervisor call to serve, or an
//! interrupt to finish.
//!
//! A call is a request and is answered; an interrupt is a notification and is
//! acknowledged.  They part company here rather than in `dispatch`, because
//! what they do with the frame has nothing in common beyond the frame itself.

#[cfg(target_os = "none")]
use super::call::CALL_SINK;
#[cfg(target_os = "none")]
use super::call::CallFrame;
#[cfg(target_os = "none")]
use super::call::CallOutcome;
#[cfg(target_os = "none")]
use super::call::preempt_sink;
#[cfg(target_os = "none")]
use super::dispatch::GIC;
#[cfg(target_os = "none")]
use super::dispatch::sink;
#[cfg(target_os = "none")]
use super::frame::ExceptionFrame;

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
/// The controller holds the line *active* between the acknowledge and the
/// finish.  An interrupt at that priority is not delivered again until it is
/// finished, and a handler that returned without one would leave the machine
/// taking exactly one interrupt and then appearing to hang, which is the
/// failure mode a span of code that looks correct produces.
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
/// 4, *not* 0 and *not* 8.  Entry 0 is the same kind with `SP_EL0` selected,
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
/// [`ExceptionFrame`], which is the assembly's contract, and it does not
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

    let shared = irq::Frame::fault(
        frame.vector as usize,
        frame.far as usize,
        frame.fault_was_write(),
    );
    let handled = match sink() {
        Some(sink) => sink(shared),
        None => false,
    };

    if !handled {
        // An exception from EL0 that the kernel did not answer kills the
        // **program**, not the machine: the diagnostic is already on the
        // console, and the death is the scheduler's, the task goes
        // `Finished` with the kernel's fault status and the frame this tail
        // leaves behind is whatever runs next.  `SPSR_EL1` is what says the
        // fault was the program's and not the kernel's; a kernel that cannot
        // trust its own translations has nothing left to schedule for, and
        // its faults keep the halt below.
        if crate::is_user_context(frame)
            && let Some(sink) = super::call::fault_sink()
        {
            sink(frame, frame.vector as usize, frame.far as usize);
            return;
        }
        // A supervisor call is the one exception that is not a fault: the
        // kernel raises it deliberately.  An `svc` from EL0 is a program's
        // call and is served above; one from EL1 is the kernel's own, and
        // nothing in the kernel serves one, so it is reported as unhandled
        // rather than mistaken for a program's.
        crate::serial::write_str("protofire: unhandled exception ");
        crate::serial::write_u32(frame.vector as u32);
        crate::serial::write_str(" on cpu ");
        crate::serial::write_u32(crate::current_cpu_slot() as u32);
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
