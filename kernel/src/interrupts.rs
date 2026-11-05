//! kernel/src/interrupts.rs
//!
//! What the kernel does with an interrupt frame.
//!
//! ## The two halves
//!
//! The machine's half is a table of gates and a stub that saves the registers
//! and calls here — `arch`'s.  This half is the *decision*: which vector means
//! what, and who asked to be told.
//!
//! A vector is delivered to whoever registered for its number.  Nothing is
//! registered yet, so every frame answers "not handled" and the dispatch stops
//! the machine with the vector on the console — which is the honest answer to
//! an interrupt this kernel has no business receiving, and it is what makes a
//! boot past `sti` a proof that the path works.
//!
//! ## Why the vector is the identity
//!
//! On a machine whose controller assigns each line a number, the number *is*
//! the identity a handler registers under.  A translation table between "the
//! number the machine printed" and "the number a driver claimed" would be a
//! second thing to keep in step, and the first driver to get it wrong would be
//! a device whose interrupts nobody receives.
//!
//! So a vector is passed through as it arrived.

/// Install the interrupt table, the sink, the machine's other CPUs, and prove
/// the path with one interrupt the machine raises itself.
///
/// ## Why the order matters
///
/// The sink is installed first, so a vector that arrived between the table
/// being loaded and the handler existing would be one the dispatch could not
/// answer. Then the table, then the flag.  And the proof comes last, because it
/// is the only thing that separates "the table is installed" from "an interrupt
/// arrives through it".
///
/// # Safety
///
/// Called once, with the console up and before any program can run.
#[cfg(target_os = "none")]
pub unsafe fn install() {
    // The descriptor table and the task state segment, before the interrupt
    // table.  On a machine that needs a TSS, the `RSP0` it names is the stack
    // every interrupt from ring 3 lands on, and a table installed without one
    // would take its first ring-3 interrupt as a triple fault.
    //
    // A machine with no such table answers `false`, and that is not a failure:
    // aarch64's vector table needs no descriptor and its answer says so.
    //
    // SAFETY: the caller's contract is this function's.  The stack it names as
    // `RSP0` is the kernel's, which is live.
    let descriptors = unsafe { arch::install_descriptor_tables(arch::interrupt_stack_top()) };
    if descriptors {
        arch::serial::write_str("protofire: descriptor tables installed, TSS loaded\n");
    }

    // SAFETY: called once, with the console up.  The sink answers "not handled"
    // for everything, so a vector that arrives stops the machine with its
    // number on the console rather than jumping into nothing.
    unsafe { arch::set_interrupt_dispatch(handle) };
    // SAFETY: called once, after the sink exists and before any vector can be
    // raised.
    let installed = unsafe { arch::install_interrupt_table() };
    arch::serial::write_str("protofire: interrupt table ");
    if installed {
        arch::serial::write_str("installed");
    } else {
        arch::serial::write_str("not installed (this machine has no entry yet)");
    }

    // And enabled, if there is a table behind the flag.
    //
    // The 8259 is masked first, and that is not tidiness.  Its reset vector
    // bases are 8 and 0x70; vector 8 is the double fault.  A machine whose
    // timer still reaches the 8259 takes its first tick as a double fault
    // through a gate this kernel wrote for a fault it will never raise — which
    // is exactly what happened the first time this line existed.  q35 has an
    // IOAPIC, so the legacy controller is masked rather than remapped: two
    // controllers able to raise one line is a worse state than one controller
    // silent.
    //
    // SAFETY: the table is installed and the sink is set, so a vector that
    // arrives is one the dispatch can answer.
    if installed {
        // The legacy controller is silenced before the flag, not after and not
        // as part of building the table: its pending lines are latched until
        // the mask is written, so the order is mask then enable.
        arch::interrupts::silence_legacy_controller();
        arch::interrupts::enable();
        arch::serial::write_str(", interrupts on\n");

        // Then prove the path, rather than reporting it.
        raise_test_interrupt();
    } else {
        arch::serial::write_str("\n");
    }
}

/// Handle one interrupt frame, answering whether anything took it.
///
/// Called from the machine's dispatch, on whatever stack the vector found.
/// Nothing here allocates or blocks: an interrupt may arrive while the heap's
/// lock is held, and an allocation from inside one would wait for a lock the
/// interrupted code cannot release.
pub fn handle(frame: irq::Frame) -> bool {
    let vector = frame.vector;

    // The timer: count it, and re-arm.
    //
    // Re-arming here rather than in the preemption path is deliberate: a
    // `CNTP_TVAL_EL0` countdown fires once and stops, so a handler that only
    // counted would get one tick and then silence for the rest of the boot.
    #[cfg(target_os = "none")]
    if vector == arch::timer_interrupt() {
        let slot = crate::per_cpu::current_slot();
        crate::per_cpu::count_tick(slot);
        crate::tick::TIMER_TICKS.fetch_add(1, core::sync::atomic::Ordering::Release);
        // The boot's self-check reads this, and so does nothing else: it is the
        // record that *this* vector reached a handler, which is the one claim
        // the boot makes before any program runs.
        TEST_INTERRUPT_RAISED.store(vector, core::sync::atomic::Ordering::Release);

        // Re-arm this CPU's own timer, whoever this CPU is.  A countdown fires
        // once, so a hart that did not re-arm its own would get one tick and
        // then silence for the rest of the boot.
        //
        // SAFETY: the line is enabled on this CPU, so this is a timer that can
        // fire again.
        if let Some(frequency) = unsafe { arch::timer_frequency() } {
            // SAFETY: as above.
            unsafe { arch::arm_timer(frequency, crate::tick::TIME_SLICE_US) };
        }

        // The scheduling half belongs to the boot CPU alone.
        //
        // The scheduler is one structure with no lock: wake_expired and the
        // preemption hook both write it.  A second CPU that ran them would be a
        // second writer, and the failure — a task resumed with another CPU's
        // context — is the sort this tree refuses to leave in.  So another CPU
        // counts its tick and re-arms its clock, and the boot CPU does the
        // deciding until the scheduler grows a per-CPU half.
        if !crate::per_cpu::on_boot_cpu() {
            return true;
        }

        // Wake whatever slept past its deadline, *before* the preemption hook
        // asks who can run: a task that has finished sleeping is runnable now,
        // and a pass that ran first would find nothing and stop the machine
        // with work left.
        let woken = crate::scheduler::wake_expired();
        if woken > 0 {
            arch::serial::write_str("protofire: a program woke, ");
            arch::serial::write_u32(woken as u32);
            arch::serial::write_str(" of them\n");
        }
        return true;
    }

    // A machine whose self-check uses a vector of its own records it here.
    // x86_64's uses the timer's, so it never reaches this; aarch64's uses a
    // software interrupt, which is not a timer and not a fault.
    #[cfg(target_os = "none")]
    if vector == test_interrupt() && vector != arch::timer_interrupt() {
        let slot = crate::per_cpu::current_slot();
        crate::per_cpu::count_ipi(slot);
        TEST_INTERRUPT_RAISED.store(vector, core::sync::atomic::Ordering::Release);
        return true;
    }

    // A device's line: whoever registered for this number is told.
    if irq::dispatch_installed(vector) {
        return true;
    }

    // A fault the kernel raised on itself.  There is no recovery yet — that
    // needs a process to hand the fault to — so the honest answer is "not
    // handled", and the dispatch prints the vector and stops.
    false
}

/// The sentinel [`TEST_INTERRUPT_RAISED`] holds before an interrupt arrives.
///
/// `usize::MAX` is not an interrupt number any controller reports, so it is
/// distinguishable from every real one — including zero, which some machines'
/// self-tests raise.
const NO_INTERRUPT: usize = usize::MAX;

/// The interrupt the test raised, if any.
///
/// A static because the sink is a plain `fn` and has no context to be handed
/// one — the same shape the trap sink itself has.  It lives here because the
/// sink is the only reader and the writer is one function in this module.
pub static TEST_INTERRUPT_RAISED: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(NO_INTERRUPT);

/// The line the boot raises to prove the interrupt path.
///
/// The machine's own, and on x86_64 it is the **timer's** vector rather than a
/// spare one.  A spare vector proved the gate but cost the timer: the local
/// APIC records every vector it delivers as in-service, and ending an interrupt
/// for a vector the kernel's sink does not claim leaves the controller's state
/// ordered differently from what a real tick produces.  The boot then reported
/// a delivered test interrupt and never took a tick.
#[cfg(target_os = "none")]
fn test_interrupt() -> usize {
    arch::test_interrupt()
}

/// Raise one interrupt from the controller and require that it arrived.
///
/// Prints what happened either way.  A line that was published and never
/// delivered is the failure this reports, and a boot log that said "interrupts
/// on" without it has said nothing about whether the machine can take one.
#[cfg(target_os = "none")]
fn raise_test_interrupt() {
    use core::sync::atomic::Ordering;

    // A value no interrupt can have, so "nothing arrived" is distinguishable
    // from "interrupt 0 arrived".
    //
    // This is the defect that made the first version of this probe useless: the
    // line raised is interrupt *zero* on some machines, the counter's initial
    // value was zero, and so a boot that raised nothing printed exactly what a
    // boot that raised something printed.  A test that cannot fail is worse
    // than no test.
    TEST_INTERRUPT_RAISED.store(NO_INTERRUPT, Ordering::Release);
    let line = test_interrupt();

    // SAFETY: the controller is enabled and the sink is installed by the time
    // this runs.  An SGI needs no enable — its bit is always set — and a
    // self-directed APIC interrupt needs none either, so this asks the
    // controller to raise it and nothing else.
    let raised = unsafe { arch::raise_interrupt(line) };

    if !raised {
        arch::serial::write_str(
            "protofire: interrupt path not exercised (this machine has no controller to raise one)",
        );
        arch::serial::write_str("\n");
        return;
    }

    let delivered = TEST_INTERRUPT_RAISED.load(Ordering::Acquire);
    if delivered == line {
        arch::serial::write_str("protofire: interrupt delivered to its handler\n");
    } else {
        arch::serial::write_str("protofire: interrupt raised but not delivered");
        if delivered != NO_INTERRUPT {
            arch::serial::write_str(" (handler saw ");
            arch::serial::write_u32(delivered as u32);
            arch::serial::write_str(")");
        }
        arch::serial::write_str("\n");
    }
}
