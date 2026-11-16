//! kernel/src/interrupts.rs
//!
//! What the kernel does with an interrupt frame.
//!
//! ## The two halves
//!
//! The machine's half is a table of gates and a stub that saves the registers
//! and calls here, `arch`'s.  This half is the *decision*: which vector means
//! what, and who asked to be told.
//!
//! A vector is delivered to whoever registered for its number: the timer's,
//! the wake between CPUs, the console's line, and, for a fault, one
//! recoverable shape, the write a copy-on-write fork demoted.  A vector no
//! one claims is reported rather than acted on, an unclaimed *interrupt*
//! continuing and an unresolved *fault* stopping the machine, which is the
//! honest answer to a line this kernel has no business receiving, and it is
//! what makes a boot past `sti` a proof that the path works.
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

    // SAFETY: called once, with the console up.  The sink claims every vector
    // this kernel knows and refuses the rest, so an unclaimed one is a printed
    // line with its number on the console rather than a jump into nothing.
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

    // The 8259 is masked first, and that is not tidiness.  Its reset vector
    // bases are 8 and 0x70; vector 8 is the double fault.  A machine whose
    // timer still reaches the 8259 takes its first tick as a double fault
    // through a gate this kernel wrote for a fault it will never raise, which
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

        // The scheduling half is the boot CPU's, and it is a policy now rather
        // than a safety requirement.
        //
        // It was both until the scheduler grew a lock: the comment here used to
        // say the structure had no lock, so a second writer would resume a task
        // with another CPU's context.  `scheduler::SCHEDULER` is a
        // `sync::Mutex` now, and `wake_expired` takes it like every other entry
        // point, so any CPU could call it and be correct.
        //
        // What keeps the gate is that it would be *wasteful* and *noisy*, not
        // wrong: every CPU takes its own timer, so every CPU would walk the
        // same task list to find the same expired sleepers, and the boot's `a
        // program woke` line is printed by whichever CPU found them first.  One
        // CPU waking them once is the shape the report describes.
        //
        // Removing this gate is part of making the scheduler shard per CPU, and
        // that change has to decide what the wake line means when several CPUs
        // can each wake a different task.
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
            // The woken task may be held by another CPU, whose own clock may
            // not move; the IPI is what makes it re-check.
            unsafe { arch::send_ipi_to_others() };
        }

        // The USB controller's event ring, when the machine has one.  Until a
        // device-message wiring exists for it this tick is the ring's only
        // reader, so a keyboard report waits for the tick that drains it -- the
        // same wait every polling driver here asks of its device, and the same
        // fallback the controller's interrupt path names for itself.
        crate::xhci::poll();

        return true;
    }

    // A wake from another CPU, and the machine's own self-test interrupt,
    // which on every machine here is the same line an inter-processor
    // interrupt arrives on: aarch64's software interrupt, riscv64's software
    // cause, x86_64's IPI vector.  Counting it is what separates "the CPU
    // took an interrupt" from "the CPU is running this kernel", which is the
    // evidence the boot's own IPI proof reads.
    #[cfg(target_os = "none")]
    if vector == arch::ipi_interrupt() {
        // The sending side's contract, discharged before the count: a CPU that
        // recorded the interrupt and had not flushed would be an
        // acknowledgement of a change it cannot see.  `acknowledge` flushes
        // first and then stores, so the count below and the epoch word agree.
        crate::shootdown::acknowledge();
        let slot = crate::per_cpu::current_slot();
        crate::per_cpu::count_ipi(slot);
        TEST_INTERRUPT_RAISED.store(vector, core::sync::atomic::Ordering::Release);
        return true;
    }

    // The console's transmitter: the one device line this boot claims.
    //
    // The device itself was acknowledged in the trap path, because reading a
    // 16550's `IIR` is what the device counts as an acknowledge; what is left
    // here is to say the line was taken and to count it.  A boot that did not
    // claim it printed the same number forever.
    #[cfg(target_os = "none")]
    if crate::console_owns(vector) {
        crate::note_console_interrupt();
        return true;
    }

    // A device's line: whoever registered for this number is told.
    if irq::dispatch_installed(vector) {
        return true;
    }

    // A fault.  One shape of it is recoverable, and it is tried first: a write
    // to a page a fork demoted is the copy-on-write event, and resolving it
    // resumes the very instruction that faulted, so the program never knows.
    // Everything else stops the machine, but it stops it with the three facts
    // that make the stop diagnosable, and only after asking the page table
    // whether the address was mapped at all.
    //
    // Before this, every fault printed the same line: the vector and an
    // address.  A program that wrote its own code page and a program that
    // jumped into unmapped memory read identically, and the difference is the
    // whole of what a fault handler exists to tell apart.
    #[cfg(target_os = "none")]
    if let Some(write) = frame.write {
        if write && resolve_write_fault(frame.fault_address) {
            return true;
        }
        describe_fault(frame, write);
    }
    false
}

/// The write fault's one recoverable shape, tried before the machine stops.
///
/// The fault arrived with no task named, and the task it belongs to is the one
/// this CPU marked as running, which is the same condition a host and the
/// boot's own code fail, and both are answered `false`, straight to the
/// diagnostic.  The lock order is the scheduler's and then the pool's, taken
/// inside [`crate::scheduler::with_current_space`], the only order this kernel
/// ever takes the two.
#[cfg(target_os = "none")]
fn resolve_write_fault(fault_address: usize) -> bool {
    let cpu = crate::per_cpu::current_slot();
    crate::scheduler::with_current_space(cpu, |space| {
        crate::address_space::resolve_copy_on_write(space, fault_address)
    })
    .unwrap_or(false)
}

/// Say what a fault was, in the terms a reader can act on.
///
/// Three facts, and the third is the one this function exists for:
///
/// 1. the address the access named;
/// 2. whether the access was a read or a write;
/// 3. what the page table says about that address, **not mapped**, mapped with
///    the permissions it has, or mapped as a block this kernel's walk does not
///    describe at 4 KiB.
///
/// A fault with no mapping and a fault on a mapped, read-only page are the same
/// crash and different bugs, and a log that said only the address left the
/// reader to work it out from the address alone.
///
/// It allocates nothing and takes no lock: it runs inside an interrupt, where
/// the heap may be held by the code it interrupted.  The table walk it does
/// take reads one root table, which is the one the faulting CPU is running.
#[cfg(target_os = "none")]
fn describe_fault(frame: irq::Frame, write: bool) {
    arch::serial::write_str("protofire: fault at ");
    arch::serial::write_hex(frame.fault_address as u64);
    arch::serial::write_str(", ");
    arch::serial::write_str(if write { "write" } else { "read" });
    arch::serial::write_str(", ");

    // The root the faulting CPU is running, not the kernel's: a program's
    // space is the one the address is in, and asking the kernel's would report
    // every user address as unmapped.
    match arch::installed_root_table() {
        Some(root) => match crate::address_space::permissions_of(root, frame.fault_address) {
            Some(Some(permissions)) => {
                arch::serial::write_str("mapped ");
                arch::serial::write_str(permissions_name(permissions));
                if write && !permissions.writable {
                    arch::serial::write_str(", not writable");
                }
            }
            Some(None) => arch::serial::write_str("mapped as a block, not at 4 KiB"),
            None => arch::serial::write_str("not mapped"),
        },
        None => arch::serial::write_str("no table installed on this cpu"),
    }
    arch::serial::write_str("\n");
}

/// A permission set as the three words a fault line can carry.
#[cfg(target_os = "none")]
fn permissions_name(permissions: paging::Permissions) -> &'static str {
    match (
        permissions.writable,
        permissions.executable,
        permissions.user,
    ) {
        (true, true, true) => "read-write-execute, user",
        (true, false, true) => "read-write, user",
        (false, true, true) => "read-execute, user",
        (false, false, true) => "read, user",
        (true, true, false) => "read-write-execute, supervisor",
        (true, false, false) => "read-write, supervisor",
        (false, true, false) => "read-execute, supervisor",
        (false, false, false) => "read, supervisor",
    }
}

/// The sentinel [`TEST_INTERRUPT_RAISED`] holds before an interrupt arrives.
///
/// `usize::MAX` is not an interrupt number any controller reports, so it is
/// distinguishable from every real one, including zero, which some machines'
/// self-tests raise.
const NO_INTERRUPT: usize = usize::MAX;

/// The interrupt the test raised, if any.
///
/// A static because the sink is a plain `fn` and has no context to be handed
/// one, the same shape the trap sink itself has.  It lives here because the
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
    // this runs.  An SGI needs no enable, its bit is always set, and a
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
