//! kernel/src/scheduler/mod.rs
//!
//! A boot's programs, taking turns — and the fork and exec that change what a
//! task is.
//!
//! A task here is a saved `Context`, the whole trap frame, and the address
//! space it runs in.  There is no kernel stack per task, because a task never
//! has one of its own to be suspended on: a program runs at ring 3, so the
//! only time it is inside the kernel is inside a trap, and the trap path's
//! frame *is* its saved state.
//!
//! ## The three files
//!
//! | File | What it holds |
//! |---|---|
//! | [`task`] | what a task is: its context, its space, its state |
//! | [`core`] | the tasks, the current one, and the switch |
//! | this file | the installed scheduler and the questions a trap asks it |
//!
//! The split is by subject: a reader asking "what is a task" reads `task`, one
//! asking "how does a switch work" reads `scheduler`, and one asking "who is
//! runnable" reads the free functions here, which are what the trap path, the
//! timer's handler and the idle loop call.
//!
//! A real scheduler decides by priority, by how long a task has run, and by
//! what it is waiting for.  Those are decisions about *when* to switch.  This
//! kernel switches at two moments: a program made a call, and the timer fired.
//! Both are the machine's, not the policy's, so the policy is "the next one",
//! and saying so is more useful than a weight table that decides nothing.

//! It was one structure reached through a `SyncUnsafeCell` with no lock, which
//! was sound only because one CPU ever wrote it.  A second CPU taking a timer
//! tick reaches `preempt`, and a second CPU serving a call reaches `advance`:
//! two `&mut Scheduler` over one `Vec<Task>` is undefined behaviour, and the
//! symptom, a task resumed with another CPU's context, is a fault far from its
//! cause.
//!
//! So every entry below takes one lock.  It is a **global** lock and not one
//! queue per CPU, and the choice is deliberate.  A task is already free to be
//! placed anywhere — nothing pins it, the `running` array is the only binding,
//! and leaving it is what every switch does — so what a sharded scheduler adds
//! is a *decision* about contention, and this kernel has no load to produce the
//! cost the lock is paying.
//!
//! What a per-CPU queue does **not** need here is a TLB shootdown, and the
//! earlier version of this paragraph said it did.  Every machine's
//! `switch_address_space` is a whole-TLB flush, so the CPU that leaves a task
//! has already discarded its translations, and a task taken elsewhere costs one
//! flush.  The broadcast is for the **shared** kernel tables, and it is
//! [`crate::shootdown`]'s.
//!
//! The lock masks interrupts while it is held, which is what keeps a tick from
//! arriving on this CPU mid-update and taking the lock again.  Callers that
//! take several of these entry points in sequence are holding nothing between
//! them, so the nesting that would deadlock does not exist.

pub mod core;
pub mod task;

pub use core::Claim;
pub use core::Scheduler;
pub use core::wait::PidWait;
pub use task::Task;
pub use task::starting_context;

use arch::CallFrame;

#[cfg(target_os = "none")]
use crate::address_space::AddressSpace;

/// The scheduler the boot installed, behind the lock every CPU takes.
///
/// A `static` for the same reason the syscall registry is one: a supervisor
/// call arrives from a trap with no context to be handed anything, so the table
/// it needs has to be reachable without one.
static SCHEDULER: sync::Mutex<Option<Scheduler>> = sync::Mutex::new(None);

/// Run `f` with the installed scheduler, holding the lock.
///
/// One place that spells the lock, so no entry point can forget it and no
/// caller can hold it across another.  The closure receives the `Option`
/// rather than the scheduler because "nothing installed" is a state every
/// entry point answers differently.
fn with_scheduler<R>(f: impl FnOnce(&mut Option<Scheduler>) -> R) -> R {
    let mut guard = SCHEDULER.lock();
    f(&mut guard)
}

/// The CPU this call is running on, which is the one a switch belongs to.
///
/// Read before the lock is taken, from the machine's own register, so it cannot
/// change while the lock is held and cannot be confused with another CPU's.
fn this_cpu() -> usize {
    crate::per_cpu::current_slot()
}

/// Install the scheduler the boot built.
///
/// # Safety
///
/// Called once, before any program runs.
pub unsafe fn install(scheduler: Scheduler) {
    // SAFETY: the caller promises this is the only write and that it happens
    // before EL0 is entered.  The lock is what makes the write visible to a
    // second CPU that installs a trap later.
    *SCHEDULER.lock() = Some(scheduler);
}

/// The status a process dies with when a fault no resolver answered.
///
/// A program's own `Exit` carries the status the program chose; a death by
/// fault carries one the kernel chose, and the two must never be mistakable.
/// 139 is the shape the wider world gives a process killed by its own bad
/// memory access — 128 plus the signal number — and this kernel's meaning is
/// written here rather than borrowed from there: the program died of a fault,
/// not of an exit, and the boot line that reports the death names the fault
/// beside it.
pub const FAULT_STATUS: usize = 139;

/// Kill the running process: its task becomes `Finished` with
/// [`FAULT_STATUS`], and whatever runs next is installed into the frame.
///
/// Called from the machines' fault tails, with the fault's vector and the
/// address it named, after the diagnostic has printed — the line above the
/// death says what the access was; this line says who paid for it.  A fault
/// in **kernel** code never reaches here: the machines' tails ask
/// `is_user_context` first, and a fault the kernel takes is still the machine
/// stopping, because a kernel that cannot trust its own translations has
/// nothing left to schedule for.
///
/// The task's space is **not** released here.  The CPU taking the fault has
/// the task's root installed, and the exclusion the exits rely on — every
/// task finished, every other CPU told — does not hold; the space goes back
/// with the rest at the machine's end, the same deferral an exit takes.
pub fn die_from_fault(frame: &mut arch::Context, vector: usize, address: usize) {
    // A program that installed a handler takes the fault itself: the handler
    // is entered with the fault's vector, address and direction in the three
    // argument registers, and `ReturnFromException` is how it comes back.  The
    // frame is replaced with one that resumes at the handler, so the trap
    // path's own restore returns **into the program's handler** rather than
    // into the instruction that faulted.
    if hand_the_fault_to_the_program(frame, vector, address) {
        return;
    }
    arch::serial::write_str("protofire: process ");
    arch::serial::write_u32(current_pid().unwrap_or(0));
    arch::serial::write_str(" died from a fault at ");
    arch::serial::write_hex(address as u64);
    arch::serial::write_str(" (vector ");
    arch::serial::write_u32(vector as u32);
    arch::serial::write_str("), status ");
    arch::serial::write_u32(FAULT_STATUS as u32);
    arch::serial::write_str(", rip ");
    arch::serial::write_hex(arch::resume_address(frame) as u64);
    arch::serial::write_str(", rsp ");
    arch::serial::write_hex(arch::stack_pointer(frame) as u64);
    arch::serial::write_str("\n");
    advance_with_status(frame, true, FAULT_STATUS);
}

/// Record the fault handler a program installed, or clear it.
///
/// `InstallExceptionHandler(address)` names a virtual address in the caller's
/// own space; `0` withdraws a handler.  The address is not validated against
/// the program's mappings here: it is the program's own pointer, and an
/// unmapped one faults when the handler is entered, which is the program's
/// mistake and reaches the same fault path it came from — with the handler
/// withdrawn, so the second fault kills it instead of looping.
///
/// Answers whether a running task was found, which a call from ring 3 always
/// has.
pub fn install_exception_handler(address: usize) -> bool {
    let cpu = this_cpu();
    with_scheduler(|scheduler| {
        let Some(scheduler) = scheduler.as_mut() else {
            return false;
        };
        let Some(index) = scheduler.running.get(cpu).copied().flatten() else {
            return false;
        };
        let Some(task) = scheduler.tasks.get_mut(index) else {
            return false;
        };
        task.handler = (address != 0).then_some(address);
        true
    })
}

/// Answer from a handler the program installed, resuming where it faulted.
///
/// `ReturnFromException`'s carrier.  The fault's frame was replaced when the
/// handler was entered, so the position the program faulted at is no longer in
/// the context the scheduler holds — it was overwritten by the handler's own
/// call.  What this restores is therefore not the faulting instruction but the
/// handler's caller: the handler returns to the instruction **after** its own
/// `svc`, with the value the program gives as the call's answer.
///
/// Returns the answer for the trap path to put in the return register.
pub fn return_from_exception(resume: usize, answer: usize, frame: &mut arch::Context) {
    // The handler names where to continue.  The kernel does not have an
    // opinion: a fixed-width machine could add its instruction's size, and
    // x86_64 could not, so the caller supplies the address and this is the one
    // rule that works on all three.
    arch::set_resume_address(frame, resume);
    arch::set_return_value(frame, answer);
}

/// Hand a fault to the program that took it, if it installed a handler.
///
/// Answers whether it did.  The handler is entered as a function call the
/// program never made: its three argument registers carry the vector, the
/// faulting address, and the direction (`1` for a write), and the frame is
/// rewritten so the trap path's epilogue returns to the handler instead of the
/// instruction that faulted.
///
/// The registers the faulting code had are **not** preserved across this: a
/// handler that wanted them would need them passed, and three words is what
/// the ABI's argument registers hold.  What survives is everything the handler
/// itself touches, which is the contract `ReturnFromException` completes.
///
/// The handler runs on the program's own stack — `sp` is untouched — so a
/// guard page's fault reaches it with the stack exactly as the program left it,
/// and a handler that recurses into its own fault runs out of stack the way
/// any runaway does.
#[cfg(target_os = "none")]
fn hand_the_fault_to_the_program(frame: &mut arch::Context, vector: usize, address: usize) -> bool {
    let Some(handler) = with_scheduler(|scheduler| {
        let scheduler = scheduler.as_ref()?;
        let cpu = this_cpu();
        let index = scheduler.running.get(cpu).copied().flatten()?;
        scheduler.tasks.get(index)?.handler
    }) else {
        return false;
    };

    arch::serial::write_str("protofire: process ");
    arch::serial::write_u32(current_pid().unwrap_or(0));
    arch::serial::write_str(" handled its own fault at ");
    arch::serial::write_hex(address as u64);
    arch::serial::write_str(" (vector ");
    arch::serial::write_u32(vector as u32);
    arch::serial::write_str(")\n");

    // The handler is entered as a function call with four arguments in the
    // ABI's argument registers:
    //
    // 0. the exception vector,
    // 1. the faulting address,
    // 2. the direction (`1` for a write),
    // 3. the address of the instruction that faulted.
    //
    // The fourth is why the kernel does not compute a resume itself.
    //
    // It travels in the **fifth** argument register, not the fourth: on
    // x86_64 the fourth is `rcx`, and `int 0x80` saves its return address
    // there, so a value put in it arrives at the handler as whatever the
    // instruction left.  Measured: the handler resumed at `0x1`, a supervisor
    // read, because `rcx` had been overwritten.  `r8` is the first argument
    // register the call instruction does not touch.  A
    // machine whose instructions are a fixed width can add four; **x86_64's
    // are not**, so an instruction length is not a constant the kernel can
    // name.  The program knows its own instructions, so the resume is the
    // handler's answer: `ReturnFromException(resume, value)` names where to
    // continue and what the call answers.
    let faulting_instruction = arch::resume_address(frame);
    arch::set_return_value(frame, vector);
    arch::set_argument(frame, 1, address);
    arch::set_argument(frame, 2, 0);
    arch::set_argument(frame, 4, faulting_instruction);
    arch::set_resume_address(frame, handler);
    true
}

/// A host has no trap path to hand a fault to.
#[cfg(not(target_os = "none"))]
fn hand_the_fault_to_the_program(
    _frame: &mut arch::Context,
    _vector: usize,
    _address: usize,
) -> bool {
    false
}

/// Install the next task's context without saving the frame it was given,
/// waiting through the wakes other CPUs take.
///
/// For the idle path: the boot waiting for a wakeup holds a kernel frame, and
/// saving it into a task would replace that task's saved program state with a
/// kernel address.  See `Scheduler::schedule_from`.
///
/// ## Why the wait is here and not in the caller
///
/// A caller reaches this having just seen "something is selectable" — the end
/// of an idle wait, a write that woke a reader — and that check and this
/// switch are **two lock acquisitions, not one**.  In the window between them
/// another CPU can take the very task the check saw, and the switch then
/// finds nothing: the slot is cleared and `Exit` comes back meaning "the
/// frame was not replaced".  A caller that resumed its frame on that answer
/// would run a program whose task another CPU holds or whose state is still
/// asleep — a process with no entry in the `running` array, which is the one
/// invariant the exclusion set is.  The boot showed the shape: an announce
/// printed by a process the scheduler had no record of, twice from one resume
/// address.  So the loser of the race waits here, for the wake that names
/// work, and retries — the frame is installed exactly once, and only while
/// this CPU owns it.
///
/// Answers what `advance` answers: `Return` once a task's context is in the
/// frame, `Exit` only when the machine has no work left to wait for.
pub fn switch_without_saving(frame: &mut arch::Context) -> arch::CallOutcome {
    let mut idle_turns = 0u32;
    loop {
        let outcome = with_scheduler(|scheduler| match scheduler {
            Some(scheduler) => scheduler.schedule_on(this_cpu(), frame, false, false, None),
            None => arch::CallOutcome::Exit,
        });
        match outcome {
            // Work exists somewhere — a task sleeping, blocked, or runnable —
            // so the emptiness was the race, and the wake that ends it is the
            // timer's line or another CPU's IPI.
            //
            // **Unless the boot is over**, which is the same guard
            // `advance_with_status` carries: this loop has no other branch that
            // reaches `park`, and a CPU that never says it has stopped is what
            // the reaping side waits on.  The wait between turns is a bounded
            // spin now, so the guard is reachable.
            arch::CallOutcome::Exit if has_runnable() && !crate::programs::boot_has_ended() => {
                idle_turns += 1;
                if idle_turns.is_multiple_of(IDLE_PINGS_BEFORE_A_PING) {
                    wake_the_other_cpus();
                }
                arch::wait_for_a_wakeup();
            }
            // **Nothing is left.**  This used to hand `Exit` back and rely on
            // the caller's trap path to notice, and it did not: the epilogue
            // restored a frame that belonged to a program which had already
            // finished, and the machine sat there with every task `Finished`,
            // no CPU running, and no report line.  The end of the machine is
            // this function's to say, because this is where the last absence
            // becomes known.
            arch::CallOutcome::Exit => crate::programs::report_and_finish(),
            other => return other,
        }
    }
}

/// Save the current task, install the next one's context, and answer.
///
/// `None` runs when the boot never installed a scheduler, which is the state a
/// host build is in.
pub fn advance_with_status(
    frame: &mut arch::Context,
    exiting: bool,
    status: usize,
) -> arch::CallOutcome {
    let cpu = this_cpu();
    if schedule_on_this_cpu(cpu, frame, exiting, status) {
        return arch::CallOutcome::Exit;
    }

    // Nothing was installed, so the frame is still the *finished* program's:
    // returning `Exit` would tell the trap path to `sret` to the instruction
    // after its last one, past the end of its image, which on this machine is a
    // zero word and the fault is `illegal instruction` at offset 21 words.
    //
    // So this CPU waits here instead.  Two ways out, and they are different
    // questions:
    //
    // - **Another CPU still has work.**  This one waits for the interrupt that
    //   changes that, and tries again.  It must not stop the machine: the other
    //   CPU is inside a program, and a boot that stopped here would end with
    //   programs that had not run.
    // - **Nothing anywhere is runnable.**  The machine is finished, and every
    //   CPU should stop.  That is the only case that ends a boot.
    //
    // ## The ping, and the hang it answers
    //
    // Two CPUs can reach this loop having seen each other's work and each gone
    // to `wfi` for the interrupt that would announce it: the one that would
    // have woken them is the one they each expected, and neither sends it.  The
    // machine then has every task finished, `has_runnable` false, and no CPU
    // running — a deadlock that looks exactly like a slow boot, and that
    // reproduced on two boots in thirty with the report waiting on a CPU asleep
    // in `wfi`.
    //
    // So the loop counts its own idle turns and, after enough of them to know
    // the wait is not going to be ended by someone else, sends the inter-CPU
    // line itself.  The ping cost is one interrupt per turn of an idle CPU
    // while nothing is runnable, which is bounded by how long the machine takes
    // to finish rather than by any deadline.
    let mut idle_turns = 0u32;
    loop {
        if !has_runnable() {
            // The machine is finished: report what ran, then stop every CPU.
            crate::programs::report_and_finish()
        }
        // **And the boot may have been declared over by another CPU.**
        //
        // This is the branch whose absence kept a started core from ever
        // recording that it had stopped.  `boot_is_finished` — the one place a
        // CPU says "I will not touch a user space again" — is called only from
        // the started core's `wait_for_work`, and a core that has entered a
        // program never returns there.  So a core waiting *here* had no
        // instruction that could satisfy the reaping side, and the boot ended
        // `ended without confirmation from 1 cpu(s)` after a hundred million
        // turns of a wait that could not end.
        //
        // The check could not simply be added earlier: the wait between the two
        // turns was a `wfi`, and on this machine a started core's second `wfi`
        // never returned — its timer was expired and its line enabled and the
        // distributor never had the interrupt pending.  `wait_for_a_wakeup`
        // waits on the **event** now, which the inter-CPU wake sets with a
        // `sev` beside its SGI, so the park ends on a call this kernel makes
        // rather than on an interrupt the controller may not deliver.  Measured
        // on that change: 22 unconfirmed boots in 40 with the interrupt wait,
        // none in 100 with the event wait, and none in 40 more with the bounded
        // spin behind it removed — the event is what ends it.
        //
        // `boot_has_ended` and not `boot_is_finished`: this CPU is still here,
        // deciding.  The record is made in `report_and_finish`, where the
        // decision is taken and the halt follows.
        if crate::programs::boot_has_ended() {
            crate::programs::report_and_finish()
        }
        arch::wait_for_a_wakeup();
        idle_turns += 1;
        if idle_turns.is_multiple_of(IDLE_PINGS_BEFORE_A_PING) {
            wake_the_other_cpus();
        }
        if schedule_on_this_cpu(cpu, frame, false, 0) {
            return arch::CallOutcome::Exit;
        }
    }
}

/// How many idle turns a CPU takes before it wakes the others itself.
///
/// Large enough that an ordinary wait — a sleep's deadline, a pipe's write —
/// never reaches it: those are woken by a timer that is running anyway, and a
/// ping on every turn would turn an idle machine into a broadcast storm.  Small
/// enough that the two-CPU deadlock above is broken within a boot's patience.
const IDLE_PINGS_BEFORE_A_PING: u32 = 64;

/// Send the inter-CPU line, or nothing on a machine that has none.
///
/// The kernel's own name for the arch call, so the idle loops do not have to
/// carry a `cfg` for a fact about the machine: a host build has no CPUs to
/// wake and no `send_ipi_to_others` to call.
fn wake_the_other_cpus() {
    #[cfg(target_os = "none")]
    {
        // SAFETY: the boot's own inter-CPU line, installed before any program
        // ran.
        unsafe { arch::send_ipi_to_others() };
    }
}

/// Install the next task for `cpu`, answering whether one was installed.
///
/// One spelling of the switch, because the two callers differ only in whether
/// they save the frame: an exiting program's frame is its own last one, and a
/// CPU waiting between tasks holds a kernel frame that no task owns.
fn schedule_on_this_cpu(
    cpu: usize,
    frame: &mut arch::Context,
    exiting: bool,
    status: usize,
) -> bool {
    with_scheduler(|scheduler| match scheduler {
        Some(scheduler) => {
            if exiting {
                scheduler.schedule_with_status(cpu, frame, true, true, Some(status));
            } else {
                // The frame belongs to no task here: this CPU is between
                // programs, so there is nothing to save into.
                scheduler.schedule_with_status(cpu, frame, false, false, None);
            }
            scheduler.holds_a_task(cpu)
        }
        None => false,
    })
}

pub fn advance(frame: &mut arch::Context, exiting: bool) -> arch::CallOutcome {
    with_scheduler(|scheduler| match scheduler {
        Some(scheduler) => scheduler.schedule(this_cpu(), frame, exiting),
        None => arch::CallOutcome::Exit,
    })
}

/// Release every finished task's address space, answering how many went back.
///
/// Called once, when the machine is finished: every task is `Finished` and
/// every other CPU has been told to stop.  That is the only moment the whole
/// task set is quiescent; `Scheduler::reap_finished` has the measurement that
/// made releasing at each exit wrong.
///
/// A task whose space is already gone is skipped, so a second call answers
/// zero rather than freeing a frame twice.
#[cfg(target_os = "none")]
pub fn reap_address_spaces() -> usize {
    with_scheduler(|scheduler| match scheduler {
        Some(scheduler) => scheduler.reap_finished(),
        None => 0,
    })
}

/// A host build has no address space to release.
#[cfg(not(target_os = "none"))]
pub fn reap_address_spaces() -> usize {
    0
}

/// How many switches, exits and signal deliveries the installed scheduler
/// has seen.
///
/// `(switches, exited, delivered)`, or zeros when nothing ran.
pub fn statistics() -> (usize, usize, usize) {
    with_scheduler(|scheduler| {
        scheduler.as_ref().map_or((0, 0, 0), |scheduler| {
            (
                scheduler.switches(),
                scheduler.exited(),
                scheduler.delivered_signals,
            )
        })
    })
}

/// How many tasks were taken onto a CPU other than the one they last ran on,
/// and the most recent one as `(pid, from, to)`.
///
/// The count is the placement rule's own record.  A task is not pinned to a
/// CPU: the only binding is the scheduler's `running` array, so any task that
/// left its CPU may be selected by another, and this says whether one was.  It
/// is a **measurement**, not a policy: this kernel has no load balancer, and a
/// zero here means no task was ever placed twice, not that placement is
/// refused.
pub fn migrations() -> (usize, Option<(u32, usize, usize)>) {
    with_scheduler(|scheduler| match scheduler {
        Some(scheduler) => {
            let (count, last) = scheduler.migrations();
            let named =
                last.and_then(|(task, from, to)| scheduler.pid_at(task).map(|pid| (pid, from, to)));
            (count, named)
        }
        None => (0, None),
    })
}

/// The root the first task runs through.
///
/// Read out of the static because the boot installs the scheduler and then
/// enters a program: the value it built is gone by then, and the entry into EL0
/// has to translate through the first task's root rather than the kernel's.
#[cfg(target_os = "none")]
pub fn first_root() -> Option<usize> {
    let cpu = this_cpu();
    with_scheduler(|scheduler| {
        scheduler
            .as_ref()
            .and_then(|scheduler| scheduler.current_root(cpu))
    })
}

/// Whether a scheduler is installed and still has work.
pub fn has_runnable() -> bool {
    with_scheduler(|scheduler| scheduler.as_ref().is_some_and(Scheduler::has_runnable))
}

/// Preempt: put the next task's context in `frame` and switch to its space.
///
/// `advance` answers a call: the frame it is given belongs to a task that asked
/// for something, and the caller does something with the answer.  This is
/// called from an interrupt, where the frame belongs to whatever the program
/// was doing, so there is no call, no answer, and nothing to report to anyone.
/// The only thing that matters is that the frame the epilogue restores is the
/// next task's.
///
/// A timer that fires in a system with one runnable task is a timer, not a
/// switch.  Counting it would make the boot's switch total depend on how long
/// the program ran, and the number would stop describing the scheduler.
pub fn preempt(frame: &mut arch::Context) {
    // Only from a program.
    //
    // A timer fires at EL1 as well as at EL0, the kernel's own boot code takes
    // ticks, and its saved context is a kernel one.  Installing a program's
    // context over it would resume a ring-3 program from inside a kernel stack
    // that nothing will ever unwind, and the boot stops mid-line: the first run
    // of this printed `program 1 mappe` and nothing more.
    //
    // A kernel frame's saved state does not name a program's ring, and the
    // machine answers the question rather than this file decoding it:
    // `SPSR_EL1` and `cs` say "which ring and which exception level" in two
    // different encodings, and neither belongs here.
    if !arch::is_user_context(frame) {
        return;
    }

    let cpu = this_cpu();
    with_scheduler(|scheduler| {
        let Some(scheduler) = scheduler else {
            return;
        };
        // No switch is not no work: a signal the running program armed for
        // is one it does not read on a wait, and the tick that finds no one
        // to switch to is still the one moment the running task's frame can
        // be redirected — it is saved, owned by this CPU, and about to be
        // resumed.  A timer in a system with one runnable task stays a
        // timer — the switch count does not move — and the delivery moves,
        // because it is the signal's arrival, not a scheduling decision.
        if !scheduler.has_other_runnable(cpu) {
            if let Some(index) = scheduler.running.get(cpu).copied().flatten() {
                scheduler.deliver_pending(index, frame);
            }
            return;
        }
        let _ = scheduler.schedule(cpu, frame, false);
    });
}

/// Put the running program to sleep for `microseconds`.
///
/// Answers the counter reading it will wake at, so a boot line can report the
/// deadline rather than the duration, the two differ by however long the
/// program has been running.
///
/// `None` when no scheduler is installed, which is the state a host build is
/// in.
pub fn sleep_for_microseconds(microseconds: u64, frame: &arch::Context) -> Option<u64> {
    #[cfg(target_os = "none")]
    {
        // The **clock's** rate, not the timer's: `timer_counter` is what
        // `until` is compared against, and on a machine whose two clocks run at
        // different rates a duration converted with the timer's would be a
        // deadline that is right by accident.
        // SAFETY: read-only.
        let frequency = unsafe { arch::clock_frequency() }?;
        // SAFETY: read-only.
        let now = unsafe { arch::timer_counter() };
        let until = now.saturating_add(arch::ticks_for_microseconds(frequency, microseconds));
        let cpu = this_cpu();
        with_scheduler(|scheduler| {
            scheduler.as_mut()?.sleep_until(cpu, until, frame);
            Some(until)
        })
    }
    #[cfg(not(target_os = "none"))]
    {
        // A host has no timer, so a program that asked to sleep is told the
        // call is not served rather than told it slept.
        let _ = (microseconds, frame);
        None
    }
}

/// Wake every sleeping task whose deadline has passed, answering how many.
///
/// Called from the timer's interrupt.  A host build has no scheduler and
/// answers zero, which is the correct number of tasks a host woke.
pub fn wake_expired() -> usize {
    #[cfg(target_os = "none")]
    {
        // SAFETY: read-only.
        let now = unsafe { arch::timer_counter() };
        with_scheduler(|scheduler| {
            scheduler
                .as_mut()
                .map_or(0, |scheduler| scheduler.wake_expired(now))
        })
    }
    #[cfg(not(target_os = "none"))]
    {
        0
    }
}

/// Whether a task other than the running one can be selected right now.
///
/// The question a sleep handler asks before it hands the frame over: with
/// another task runnable the switch is a normal one, and with none the boot
/// waits instead.
pub fn has_other_runnable() -> bool {
    let cpu = this_cpu();
    with_scheduler(|scheduler| {
        scheduler
            .as_ref()
            .is_some_and(|scheduler| scheduler.has_other_runnable(cpu))
    })
}

/// Whether a task other than the running one could still finish.
///
/// The question `WaitProcess` asks before parking.  Deliberately not
/// [`has_other_runnable`]: a task that is asleep or blocked is precisely what
/// a wait is waiting for, and answering `NotFound` because the child was
/// asleep would turn a wait into an error.
pub fn has_other_unfinished() -> bool {
    let cpu = this_cpu();
    with_scheduler(|scheduler| {
        scheduler
            .as_ref()
            .is_some_and(|scheduler| scheduler.has_other_unfinished(cpu))
    })
}

/// Whether any installed task could be selected right now.
pub fn has_selectable() -> bool {
    let cpu = this_cpu();
    with_scheduler(|scheduler| {
        scheduler
            .as_ref()
            .is_some_and(|scheduler| scheduler.has_selectable(cpu))
    })
}

/// Park the running task until another task wakes it.
///
/// `None` when no scheduler is installed, which is the state a host build is in
/// and the state a boot is in before it installs one.
pub fn block(frame: &arch::Context) -> bool {
    let cpu = this_cpu();
    with_scheduler(|scheduler| match scheduler {
        Some(scheduler) => {
            scheduler.block(cpu, frame);
            true
        }
        None => false,
    })
}

/// Park the running task unless `recheck` answers its wait's question now.
///
/// `recheck` asks the waiting caller's own question again — `try_read` for a
/// pipe's reader — **under the same lock** [`wake_blocked`] takes, which is
/// what makes the park and the wake a two-order story instead of a race: the
/// fact arrived before the re-check and the answer comes back for the caller
/// to hand the program, or the task is parked before the wake looks and the
/// wake ends it.  A park that ran its check outside this lock would be a task
/// that can park after the wake it was waiting for has already fired, and
/// nothing would ever wake it.
///
/// `Some(answer)` is that answer, and the caller responds to the program at
/// once; `None` is a parked task, and the caller's next step is the wait it
/// was already shaped for.
pub fn block_unless<T>(frame: &arch::Context, recheck: impl FnOnce() -> Option<T>) -> Option<T> {
    let cpu = this_cpu();
    let mut answer: Option<T> = None;
    with_scheduler(|scheduler| {
        answer = recheck();
        if answer.is_none()
            && let Some(scheduler) = scheduler
        {
            scheduler.block(cpu, frame);
        }
    });
    answer
}

/// Park the running task until the process `pid` exits, unless it has.
///
/// `None` when no scheduler is installed — the state before the boot installs
/// one and the state a host test that never installs one is in.  Otherwise the
/// answer is the scheduler's [`PidWait`], which names all three outcomes so a
/// caller cannot fold "no such process" into "not yet".
pub fn block_unless_pid(frame: &arch::Context, pid: u32) -> Option<PidWait> {
    let cpu = this_cpu();
    with_scheduler(|scheduler| {
        scheduler
            .as_mut()
            .map(|scheduler| scheduler.block_unless_pid(cpu, frame, pid))
    })
}

/// Wake every blocked task, answering how many.
///
/// Called when something a blocked task was waiting for changed, a pipe's
/// writer putting bytes in, its write end closing, or a process exiting.
pub fn wake_blocked() -> usize {
    with_scheduler(|scheduler| scheduler.as_mut().map_or(0, Scheduler::wake_blocked))
}

/// How many tasks were placed back on the CPU they last ran on, and the most
/// recent as `(pid, cpu)`.
///
/// The placement rule's own record, reported beside the migration count: the
/// two partition the placements, and a boot whose home count is zero left
/// nothing where it was.  The pid is the scheduler's answer, so a line names a
/// process a reader can find elsewhere in the log.
pub fn placings_home() -> (usize, Option<(u32, usize)>) {
    with_scheduler(|scheduler| match scheduler {
        Some(scheduler) => {
            let (count, last) = scheduler.placings_home();
            let named = last.and_then(|(task, cpu)| scheduler.pid_at(task).map(|pid| (pid, cpu)));
            (count, named)
        }
        None => (0, None),
    })
}

/// Park the running task until a process exits, unless one already has.
///
/// `WaitProcess`'s own park.  The exit statuses are read **under the same
/// lock** the exit's wake takes — the discipline [`block_unless`] argues —
/// so the exit and the park have exactly two orders: the process died first
/// and its status comes back for the caller, or the task is parked before
/// the exit's wake looks and the wake ends it.
///
/// `Some(status)` answers the call; `None` is a parked task, and the
/// caller's next step is the wait it was already shaped for.
pub fn block_unless_exit(frame: &arch::Context) -> Option<usize> {
    let cpu = this_cpu();
    let mut answer: Option<usize> = None;
    with_scheduler(|scheduler| {
        if let Some(scheduler) = scheduler {
            answer = scheduler.block_unless_exit(cpu, frame);
        }
    });
    answer
}

/// How many installed tasks are blocked, for a boot line that reports it.
pub fn blocked() -> usize {
    with_scheduler(|scheduler| scheduler.as_ref().map_or(0, Scheduler::blocked))
}

/// Whether any installed task is asleep rather than runnable or finished.
///
/// The question a sleep handler asks: with the running task asleep and no other
/// runnable, the boot has to wait for a tick instead of stopping, and this is
/// what says the wait has a reason.
pub fn has_sleeping() -> bool {
    with_scheduler(|scheduler| scheduler.as_ref().is_some_and(Scheduler::has_sleeping))
}

/// How many installed tasks are asleep, for a boot line that reports it.
pub fn sleeping() -> usize {
    with_scheduler(|scheduler| scheduler.as_ref().map_or(0, Scheduler::sleeping))
}

/// Take a task for `cpu`, answering which one.
///
/// The one operation that marks a task taken.  A started CPU calls this when it
/// is woken, and gets `NothingToRun` until the boot has built a task it may
/// run.
///
/// Answers a [`Claim`] rather than an `Option` so "this CPU already holds a
/// task" is a value the caller has to name: that case used to be answered by
/// silently releasing the old task, and a loop written against the old type
/// exhausted memory before anyone saw what it was doing.
pub fn claim(cpu: usize) -> Claim {
    with_scheduler(|scheduler| match scheduler {
        Some(scheduler) => scheduler.claim(cpu),
        // No scheduler at all is the same answer as an empty one, and it is the
        // honest one: there is nothing to take.
        None => Claim::NothingToRun,
    })
}

/// A task's root table and saved frame, for a CPU about to enter it.
///
/// The two together are what an entry into a program needs, and neither is
/// useful alone: the frame says where to start, the root says which mapping
/// that address is in.  `None` for a task that has no space of its own, which
/// no program the boot builds has.
#[cfg(target_os = "none")]
pub fn start_of(task: usize) -> Option<(usize, arch::Context)> {
    with_scheduler(|scheduler| {
        let scheduler = scheduler.as_ref()?;
        let root = scheduler.tasks.get(task)?.root()?;
        Some((root, *scheduler.tasks.get(task)?.context()))
    })
}

/// The process id a task index names.
pub fn pid_of(task: usize) -> Option<u32> {
    with_scheduler(|scheduler| scheduler.as_ref()?.tasks.get(task).map(Task::pid))
}

/// Run `f` with the address space of the task `cpu` is running.
///
/// The write-fault resolver's way in: a fault arrives with no task named, and
/// the task it belongs to is the one this CPU marked as running — a program
/// faults while it runs, and the kernel's own code that touches a program's
/// pages does so while serving that program's call.  `None` when no scheduler
/// is installed or the CPU holds no task, which is the host's permanent state
/// and the boot's before it enters ring 3.
///
/// The closure runs under the scheduler's lock, and the resolver takes the
/// pool's inside it — the same order a fork holds the two, which is the only
/// order any code here takes them, and therefore the only order that cannot
/// deadlock against the rest.
#[cfg(target_os = "none")]
pub(crate) fn with_current_space<R>(
    cpu: usize,
    f: impl FnOnce(&mut AddressSpace) -> R,
) -> Option<R> {
    with_scheduler(|scheduler| {
        let scheduler = scheduler.as_mut()?;
        let task = scheduler.running.get(cpu).copied().flatten()?;
        let space = scheduler.tasks.get_mut(task)?.space.as_mut()?;
        Some(f(space))
    })
}

/// Map anonymous pages into the running process's space, answering the base.
///
/// `Mmap`'s work, and the reason it lives here rather than in the handler: the
/// space belongs to a task, the task belongs to the scheduler, and reaching it
/// takes the scheduler's lock.  The handler validates and formats; this is the
/// one place that knows which space "the caller's" means.
///
/// Answers `None` when there is no running task with a space, or when the
/// window has no room, or when the frames ran out — three different refusals
/// the handler cannot tell apart, and does not need to: all three are
/// `InvalidArgument` or `OutOfMemory`, and the program learns only that the
/// mapping did not happen.
#[cfg(target_os = "none")]
pub(crate) fn map_current(
    cpu: usize,
    hint: usize,
    length: usize,
    writable: bool,
    executable: bool,
) -> Option<usize> {
    with_scheduler(|scheduler| {
        let scheduler = scheduler.as_mut()?;
        let task = scheduler.running.get(cpu).copied().flatten()?;
        let space = scheduler.tasks.get_mut(task)?.space.as_mut()?;
        let base = space.reserve(hint, length)?;
        // SAFETY: the space is the running task's, so it is the installed one —
        // and `map_anonymous` requires the opposite.  That is why this cannot
        // be called from a trap that is already translating through it.
        //
        // The mapping is into the *current* space, which the CPU is using: the
        // new pages are outside every address the program is executing or
        // reading at this instant, so the entries it changes are ones no
        // instruction is mid-way through.  A stale TLB entry for them cannot
        // exist, because nothing had mapped them.
        unsafe { space.map_anonymous(base, length, writable, executable) }.then_some(base)
    })
}

/// Unmap a range from the running process's space, answering the page count.
///
/// `Munmap`'s work.  The safety note on [`map_current`] applies unchanged, with
/// one addition: unmapping a range the program is **currently executing from**
/// or reading through would fault the very instruction that asked, which is a
/// program's own mistake and one the machine reports as a fault rather than the
/// kernel refusing.
#[cfg(target_os = "none")]
pub(crate) fn unmap_current(cpu: usize, base: usize, length: usize) -> Option<usize> {
    with_scheduler(|scheduler| {
        let scheduler = scheduler.as_mut()?;
        let task = scheduler.running.get(cpu).copied().flatten()?;
        let space = scheduler.tasks.get_mut(task)?.space.as_mut()?;
        // SAFETY: as `map_current`.
        Some(unsafe { space.unmap_range(base, length) })
    })
}

/// Read or set the running process's break.
///
/// `Some(current)` for a query, and the new break for a set that the space
/// accepted.  The **space** decides what is acceptable: it knows the window,
/// the stack above the image, and how many frames it already owns.
#[cfg(target_os = "none")]
pub(crate) fn brk_current(cpu: usize, requested: usize) -> Option<usize> {
    with_scheduler(|scheduler| {
        let scheduler = scheduler.as_mut()?;
        let task = scheduler.running.get(cpu).copied().flatten()?;
        let space = scheduler.tasks.get_mut(task)?.space.as_mut()?;
        // SAFETY: as `map_current` — the space is the running task's and the
        // pages a break adds are above every address it is using.
        unsafe { space.set_break(requested) }
    })
}

/// Give back the pages the running process's space holds and no table names.
///
/// `ReclaimPages`'s work, and the only set this kernel can identify without
/// scanning every program's tables: a frame the space still records but whose
/// entry was cleared — by a `Munmap` that failed partway, or by a mapping the
/// space undid — is a frame nothing can reach and the space still owns.
///
/// `target` bounds the walk, zero meaning "all of them".  Answers how many
/// frames went back to the pool.
#[cfg(target_os = "none")]
pub(crate) fn reclaim_current(cpu: usize, target: usize) -> Option<usize> {
    with_scheduler(|scheduler| {
        let scheduler = scheduler.as_mut()?;
        let task = scheduler.running.get(cpu).copied().flatten()?;
        let space = scheduler.tasks.get_mut(task)?.space.as_mut()?;
        // SAFETY: as `map_current` — the space belongs to the running task.
        Some(unsafe { space.reclaim_unmapped(target) })
    })
}

/// Fork the running process: share its pages with a new task and hand the
/// context down.
///
/// The child inherits its parent's pages — the same frames, writable ones
/// demoted read-only for the copy-on-write fault that copies them if either
/// side writes — its parent's context (so it resumes at the instruction after
/// the `fork`), and a pid of its own.  What it does **not** inherit is the
/// parent's return value: the fork returns the child's pid to the parent and
/// zero to the child, which is the one difference the two processes running
/// the same instruction see.
///
/// A forked child resumes exactly where its parent asked, with the parent's
/// registers, including the stack pointer, which points into the page the two
/// now share.  A context built from scratch instead starts a task at the
/// beginning of a program of its own; that is a different call, `exec`, which
/// the kernel serves separately.
///
/// Answers the child's pid, or `None` when the share could not be made.
#[cfg(target_os = "none")]
pub fn fork_current(frame: &arch::Context) -> Option<u32> {
    let cpu = this_cpu();
    with_scheduler(|scheduler| {
        let scheduler = scheduler.as_mut()?;
        scheduler.fork_current(cpu, frame).map(|pid| pid as u32)
    })
}

/// A host has no address space to copy, so a fork is a call the machine
/// cannot serve, reported as such rather than as a pid nobody can use.
#[cfg(not(target_os = "none"))]
pub fn fork_current(_frame: &arch::Context) -> Option<u32> {
    None
}

/// Replace the running process's image with the file at `path`, and answer
/// its pid.
///
/// `None` when the machine cannot serve it: no scheduler, no task running,
/// the file missing or malformed, or a pool too empty to build the new space.
/// The caller answers an error rather than inventing a pid, and the process
/// keeps running the program it was running.
#[cfg(target_os = "none")]
pub fn exec_current(frame: &mut arch::Context, path: &str) -> Option<u32> {
    let cpu = this_cpu();
    with_scheduler(|scheduler| scheduler.as_mut()?.exec_current(cpu, frame, path))
}

/// A host has no file to become and no window to become it in.
#[cfg(not(target_os = "none"))]
pub fn exec_current(_frame: &mut arch::Context, _path: &str) -> Option<u32> {
    None
}

/// Start a new process running the program at `path`, and answer its pid.
///
/// The caller is the parent, which is what makes the child a process the
/// caller can wait for: [`WaitProcessOf`] names a pid, and a supervisor that
/// started the child is the caller that knows which pid to name.
#[cfg(target_os = "none")]
pub fn spawn_process(path: &str) -> Option<u32> {
    let caller = current_pid()?;
    with_scheduler(|scheduler| scheduler.as_mut()?.spawn_from_file(path, caller))
}

/// A host has no scheduler to grow and no filesystem to read the program
/// from.
#[cfg(not(target_os = "none"))]
pub fn spawn_process(_path: &str) -> Option<u32> {
    None
}

/// Queue a signal for `pid`, from the running process, and wake what waits.
///
/// A process signalling itself crosses no boundary and is not refused; the
/// answer is `NotFound` for a pid no task carries and `Busy` for a target
/// whose ring is full.
#[cfg(target_os = "none")]
pub fn send_signal(
    sender_pid: u32,
    pid: u32,
    signal: usize,
    payload: usize,
) -> Result<(), abi::Error> {
    let mut answer = Err(abi::Error::NotImplemented);
    with_scheduler(|scheduler| {
        if let Some(scheduler) = scheduler.as_mut() {
            answer = scheduler.send_signal_to(sender_pid, pid, signal, payload);
        }
    });
    answer
}

/// A host has no processes to signal.
#[cfg(not(target_os = "none"))]
pub fn send_signal(
    _sender_pid: u32,
    _pid: u32,
    _signal: usize,
    _payload: usize,
) -> Result<(), abi::Error> {
    Err(abi::Error::NotImplemented)
}

/// Take the running process's oldest pending signal, or park it until one
/// arrives.
///
/// The record is `(signal, sender_pid, payload)`; `None` is a parked task,
/// whose wake resumes the call for a retry.
#[cfg(target_os = "none")]
pub fn wait_signal(frame: &arch::Context) -> Option<(usize, u32, usize)> {
    let cpu = this_cpu();
    with_scheduler(|scheduler| scheduler.as_mut()?.wait_signal_current(cpu, frame))
}

/// A host has no signals to wait for.
#[cfg(not(target_os = "none"))]
pub fn wait_signal(_frame: &arch::Context) -> Option<(usize, u32, usize)> {
    None
}

/// Set the running process's signal mask, answering what it was.
#[cfg(target_os = "none")]
pub fn set_signal_mask(mask: u32) -> u32 {
    let cpu = this_cpu();
    with_scheduler(|scheduler| {
        scheduler
            .as_mut()
            .map_or(0, |s| s.set_signal_mask_current(cpu, mask))
    })
}

/// A host has no mask to set.
#[cfg(not(target_os = "none"))]
pub fn set_signal_mask(_mask: u32) -> u32 {
    0
}

/// Run the calling process's ring under `mask` and answer an unblocked
/// signal with the previous mask put back.
#[cfg(target_os = "none")]
pub fn sigsuspend(frame: &arch::Context, mask: u32) -> Option<(usize, u32, usize)> {
    let cpu = this_cpu();
    with_scheduler(|scheduler| scheduler.as_mut()?.sigsuspend_current(cpu, frame, mask))
}

/// A host has nothing to suspend.
#[cfg(not(target_os = "none"))]
pub fn sigsuspend(_frame: &arch::Context, _mask: u32) -> Option<(usize, u32, usize)> {
    None
}

/// Install (action `1`) or withdraw (action `0`) a program's handler for one
/// signal, answering whether the action was taken.
#[cfg(target_os = "none")]
pub fn set_signal_handler(signal: usize, action: usize, handler: usize) -> bool {
    let cpu = this_cpu();
    let mut answer = false;
    with_scheduler(|scheduler| {
        if let Some(scheduler) = scheduler.as_mut() {
            answer = scheduler.set_signal_handler_current(cpu, signal, action, handler);
        }
    });
    answer
}

/// A host has no programs to arm.
#[cfg(not(target_os = "none"))]
pub fn set_signal_handler(_signal: usize, _action: usize, _handler: usize) -> bool {
    false
}

/// The delivered-signal handler's exit: the displaced registers go back into
/// the frame, the interrupted flow resumes at `resume`, and nothing comes
/// back to the handler.
#[cfg(target_os = "none")]
pub fn signal_return(frame: &mut arch::Context, resume: usize) -> bool {
    let _ = resume;
    let cpu = this_cpu();
    with_scheduler(|scheduler| {
        let Some(scheduler) = scheduler.as_mut() else {
            return false;
        };
        let Some(index) = scheduler.running.get(cpu).copied().flatten() else {
            return false;
        };
        let Some(saved) = scheduler
            .tasks
            .get_mut(index)
            .and_then(|task| task.delivery_saved.take())
        else {
            return false;
        };
        // The whole context comes home — the registers, and the resume the
        // delivery stashed with them, which is the interrupted instruction
        // itself.  The handler's `resume` argument is the same address and
        // is not needed: the context is the truth the kernel kept.
        *frame = saved;
        true
    })
}

/// A host has no delivered signal to return from.
#[cfg(not(target_os = "none"))]
pub fn signal_return(_frame: &mut arch::Context, _resume: usize) -> bool {
    false
}

/// The process id of the running task, if a scheduler is installed.
pub fn current_pid() -> Option<u32> {
    let cpu = this_cpu();
    with_scheduler(|scheduler| scheduler.as_ref()?.current_pid(cpu))
}

/// A non-boot CPU the running task has run on, or `usize::MAX`.
///
/// The question a program's exit asks when the boot reports that programs ran
/// in parallel.  The CPU it exits on is not that question: a task taken back by
/// the boot CPU before its last instruction is still a task that ran beside it,
/// and a report built from the exit's own CPU called those boots "0 non-boot
/// CPUs" — four in fifteen, on a boot whose own `task migrations` line named
/// the move.
pub fn current_ran_off_boot_cpu() -> usize {
    let cpu = this_cpu();
    with_scheduler(|scheduler| {
        scheduler.as_ref().map_or(usize::MAX, |scheduler| {
            scheduler.current_ran_off_boot_cpu(cpu)
        })
    })
}

/// The parent of the running task, if a scheduler is installed.
pub fn current_parent() -> Option<u32> {
    let cpu = this_cpu();
    with_scheduler(|scheduler| scheduler.as_ref()?.current_parent(cpu))
}

/// The status of the first process that has exited, if any has.
///
/// A wait in this boot has one process tree, so "the first exit" is the only
/// answer it can give; a caller that needs a particular child needs a wait
/// that names a pid, which is a later change.
pub fn first_exit_status() -> Option<usize> {
    with_scheduler(|scheduler| {
        scheduler
            .as_ref()?
            .first_exited()
            .and_then(|task| task.status())
    })
}

/// Every process that has exited, with its id and status.
///
/// Reported as a list rather than looked up by a guessed id: the boot's tasks
/// are the processes it built, and asking for pids 1..3 would answer nothing on
/// a boot that numbered them differently.
pub fn exit_statuses() -> alloc::vec::Vec<(u32, usize)> {
    with_scheduler(|scheduler| match scheduler.as_ref() {
        Some(scheduler) => scheduler.exited_with_status(),
        None => alloc::vec::Vec::new(),
    })
}

/// The status a process exited with, if it has exited.
pub fn exit_status(pid: u32) -> Option<Option<usize>> {
    with_scheduler(|scheduler| scheduler.as_ref()?.exit_status(pid))
}

/// Whether a task other than the running one can be selected.
///
/// What a wait asks before it parks: with nothing else runnable no exit can
/// arrive, and blocking would be a hang rather than a wait.
pub fn has_runnable_except_current() -> bool {
    let cpu = this_cpu();
    with_scheduler(|scheduler| {
        scheduler
            .as_ref()
            .is_some_and(|scheduler| scheduler.has_other_runnable(cpu))
    })
}

pub fn is_exit(call: &CallFrame) -> bool {
    call.number == syscall::SyscallNumber::Exit as usize
}

/// Wait here until a sleeping program's deadline passes.
///
/// This replaces a `halt` loop.  When every program is asleep the scheduler
/// has nothing to resume, and the trap path's return would land on a program
/// that is not runnable.  The choices are to stop the machine or to wait for
/// the tick that wakes one; stopping is the boot ending with work left.
///
/// The timer keeps firing, and its handler calls [`wake_expired`], which is
/// what turns a deadline into a runnable task.  The loop below takes the
/// interrupt, the handler wakes a task, and `arch::wait_for_a_wakeup` returns
/// once one is runnable.  The scheduler is then asked for a context and the
/// trap path resumes it.
///
/// A supervisor call arrives through an **interrupt gate**, which clears the
/// interrupt flag on entry, so the kernel runs with interrupts masked for the
/// whole of a served call, and a wait that did not unmask them waits for a tick
/// that can never be delivered.  x86_64's `sti` is that unmask and aarch64 has
/// no such flag to clear.  `arch::wait_for_a_wakeup` is the whole of the
/// machine half: it unmasks where there is something to unmask and stops the
/// core until something says the world changed.  The boot hung once with
/// `every program is asleep, waiting` and no tick, because the kernel had tried
/// to spell `sti` itself.
///
/// On aarch64 that "something" is an **event**, not an interrupt: the timer's
/// PPI was measured not to reach a started core's idle, so a wait on an
/// interrupt there parks a core for ever — 22 boots of 40 ended without
/// confirmation.  [`arch::wait_for_a_wakeup`] waits on `wfe` and the kernel's
/// inter-CPU wake issues a `sev` beside its SGI, which measured 0 of 100.
///
/// A spin bound was here, at a million waits, on the argument that a machine
/// whose timer does not tick should say so rather than hang.  It fired on a
/// healthy aarch64 boot: a `wfi` returns on every tick whether or not that
/// tick ended the wait, so the counter measured the boot's speed and not a
/// fault.  What ends the loop is `wake_expired` turning a deadline into a
/// runnable task, and a machine that never does that is a machine that hangs,
/// with a log that already said "every program is asleep, waiting".
///
/// ## The boot can end while this loops
///
/// The task being waited for can be the last one that is not finished, and the
/// CPU that could have woken it can already be gone.  A debugger attached to a
/// stalled boot caught exactly that: one CPU halted, the other here, waiting
/// for a sleep that belonged to a machine which had already said it was over.
///
/// So the loop asks whether the boot is over and hands the ending to
/// [`crate::programs::report_and_finish`] rather than stopping here.  That call
/// knows whether this CPU is the reporting one or a loser that should stop, and
/// it is what releases the spaces every CPU has finished with; stopping here
/// instead would leave the report to a CPU that had already halted, which is
/// the same deadlock wearing a different hat.
pub fn idle_until_woken() {
    while has_sleeping() && !has_selectable() {
        if crate::programs::boot_is_finished() {
            crate::programs::report_and_finish()
        }
        arch::wait_for_a_wakeup();
    }
}

#[cfg(test)]
mod tests {
    //! The tests for this module.
    //!
    //! The scheduler's tests: the rotation, the three states that are not
    //! "runnable", the deadline that wakes a sleeper, and the position a woken
    //! task keeps.

    extern crate alloc;

    use alloc::vec;
    use alloc::vec::Vec;

    use super::Claim;
    use super::PidWait;
    use super::Scheduler;
    use super::Task;
    use super::starting_context;

    /// The starting context names the entry and EL0, and nothing else.
    ///
    /// A task that began with a register holding a kernel value would be one
    /// whose first instruction ran on it, and the failure would look like a
    /// fault in the program rather than in the kernel that set it up.
    #[test]
    fn a_task_starts_at_its_entry_and_nothing_else() {
        let context = starting_context(0x80_0000_1000, 0x80_0000_2000);
        // Read through the machine's accessors, not by naming fields: on a host
        // no implementation is linked, so this test runs only where a machine
        // answered, and the answer is what the kernel actually asks for.
        assert_eq!(arch::resume_address(&context), 0x80_0000_1000);
        assert_eq!(arch::stack_pointer(&context), 0x80_0000_2000);
        assert!(
            arch::is_user_context(&context),
            "a program's, not the kernel's"
        );
    }

    /// Round-robin visits each runnable task once before repeating.
    ///
    /// The test reads the entry each install lands on rather than a cursor,
    /// because the cursor is not the claim: the order the tasks run in is.
    #[test]
    fn tasks_take_turns_in_order() {
        let mut scheduler = Scheduler::new();
        for index in 0..3 {
            let name: &'static str = ["a", "b", "c"][index];
            let mut task = Task::without_space(name);
            arch::set_resume_address(task.context_mut(), index);
            scheduler.add(task);
        }

        // The boot claims its first task; a test that did not would be driving
        // a scheduler in a state no boot reaches.
        assert_eq!(scheduler.claim(0), Claim::Took(0));
        let mut frame = starting_context(0, 0);
        let mut order = Vec::new();
        for _ in 0..6 {
            scheduler.schedule(0, &mut frame, false);
            order.push(arch::resume_address(&frame));
        }
        // The first schedule saves task 0 and installs task 1, so the entries
        // visited are 1, 2, 0, 1, 2, 0.
        assert_eq!(order, vec![1, 2, 0, 1, 2, 0]);
    }

    /// A finished task is never selected again.
    #[test]
    fn an_exited_task_is_skipped() {
        let mut scheduler = Scheduler::new();
        for index in 0..3 {
            let name: &'static str = ["a", "b", "c"][index];
            let mut task = Task::without_space(name);
            arch::set_resume_address(task.context_mut(), index);
            scheduler.add(task);
        }

        // The boot claims the task it is about to enter, so task 0 is CPU 0's.
        assert_eq!(scheduler.claim(0), Claim::Took(0));
        let mut frame = starting_context(0, 0);
        // Task 0 exits.
        scheduler.schedule(0, &mut frame, true);
        assert_eq!(scheduler.exited(), 1);

        let mut order = Vec::new();
        for _ in 0..4 {
            scheduler.schedule(0, &mut frame, false);
            order.push(arch::resume_address(&frame));
        }
        assert!(
            !order.contains(&0),
            "task 0 exited and came back: {order:?}"
        );
        // The exit's own `schedule` already installed task 1, so the loop's
        // first observation is the task after it.
        assert_eq!(order, vec![2, 1, 2, 1]);
    }

    /// With every task finished there is nothing to run.
    #[test]
    fn a_scheduler_with_nothing_runnable_answers_exit() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("only"));
        assert_eq!(scheduler.claim(0), Claim::Took(0));
        let mut frame = starting_context(0, 0);
        scheduler.schedule(0, &mut frame, true);
        assert_eq!(scheduler.exited(), 1);
        assert!(!scheduler.has_runnable());
        assert!(scheduler.current(0).is_none());
    }

    /// A sleeping task is not selectable, and waking one makes it so.
    ///
    /// Two different questions, deliberately: `has_runnable` answers "does the
    /// boot still owe work", which a sleeper makes true, and `has_selectable`
    /// answers "can the CPU move now", which it does not.  The idle loop asked
    /// the first and never waited, the boot printed one program's line and
    /// stopped with the other asleep.
    #[test]
    fn a_sleeping_task_is_owed_but_not_selectable() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("a"));
        scheduler.add(Task::without_space("b"));

        assert_eq!(
            scheduler.claim(0),
            Claim::Took(0),
            "the boot claims what it enters"
        );
        let mut frame = starting_context(0, 0);
        scheduler.sleep_until(0, 100, &frame);
        assert_eq!(scheduler.sleeping(), 1);
        assert!(scheduler.has_sleeping(), "the boot still owes it a run");
        assert!(scheduler.has_runnable(), "which is what this answers");
        assert!(scheduler.has_selectable(0), "and b can still run");

        // Now b sleeps too: nothing is selectable, though two tasks are owed.
        scheduler.schedule(0, &mut frame, false);
        scheduler.sleep_until(0, 100, &frame);
        assert_eq!(scheduler.sleeping(), 2);
        assert!(!scheduler.has_selectable(0), "neither can run");
        assert!(scheduler.has_runnable(), "and both are still owed");
    }

    /// A woken task is selectable again, and one whose deadline has not passed
    /// is not.
    #[test]
    fn a_deadline_wakes_only_when_it_has_passed() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("only"));
        assert_eq!(scheduler.claim(0), Claim::Took(0));
        let frame = starting_context(0, 0);
        scheduler.sleep_until(0, 1000, &frame);

        assert_eq!(scheduler.wake_expired(999), 0, "not yet");
        assert_eq!(scheduler.sleeping(), 1);

        assert_eq!(scheduler.wake_expired(1000), 1, "at the deadline");
        assert_eq!(scheduler.sleeping(), 0);
        assert!(scheduler.has_selectable(0));
    }

    /// A task that sleeps resumes where it asked to.
    ///
    /// The frame is saved by `sleep_until` itself.  Leaving it to the next
    /// scheduling call worked only while a call always happened; with every
    /// task asleep the boot idles instead, and the task then resumed at
    /// whatever position its context last held, which was the `Sleep` call,
    /// so it printed its line and slept again forever.
    #[test]
    fn a_sleeper_keeps_the_position_it_slept_at() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("a"));
        scheduler.add(Task::without_space("b"));

        // A frame that is unmistakably not a fresh one: it is the *reference*
        // the comparison below is against, so nothing has to read a field.
        assert_eq!(scheduler.claim(0), Claim::Took(0));
        let frame = starting_context(0x80_0000_1234, 0x80_0000_2000);
        let slept_at = frame;

        scheduler.sleep_until(0, 50, &frame);

        // The frame the task holds is the one the sleep was called from, byte
        // for byte.  `Context` is `Copy` and `PartialEq`-free, so the check is
        // the two addresses plus a comparison of the whole value as bytes,
        // which is what "the position survived" means and nothing narrower.
        let saved = *scheduler.tasks[0].context();
        assert_eq!(
            core::mem::size_of_val(&saved),
            core::mem::size_of_val(&slept_at)
        );
        assert!(
            saved == slept_at,
            "the sleeping task kept the frame it asked from"
        );
    }

    /// A task that made a call is resumed with that call's answer in `x0`.
    ///
    /// The value lives in the installed context, which is the frame the
    /// epilogue restores, so this is the same mechanism as the task switch,
    /// and a scheduler that copied contexts but lost `x0` would resume the
    /// program with the wrong answer.
    #[test]
    fn a_resumed_task_finds_the_answer_in_x0() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("a"));
        let mut task = Task::without_space("b");
        arch::set_return_value(task.context_mut(), 42);
        scheduler.add(task);

        assert_eq!(scheduler.claim(0), Claim::Took(0));
        let mut frame = starting_context(0, 0);
        let outcome = scheduler.schedule(0, &mut frame, false);
        match outcome {
            arch::CallOutcome::Return(value) => assert_eq!(value, 42),
            arch::CallOutcome::Exit => panic!("nothing exited"),
        }
        assert_eq!(
            arch::return_value(&frame),
            42,
            "and it is in the restored frame"
        );
    }

    /// Two CPUs asking at once do not take the same task.
    ///
    /// This is what the per-CPU `running` array exists for.  A single `current`
    /// index answered both CPUs with the same task, and both installed its
    /// context: one task, two CPUs, and a program that ran its own instructions
    /// on two stacks at once.
    #[test]
    fn a_claim_does_not_hand_the_same_task_to_two_cpus() {
        // The host builds with one CPU slot, so the decisive block below — an
        // idle CPU refused a task another holds — is exercised here only as far
        // as this host's `MAX_CPUS` reaches; the two-CPU shape itself is the
        // machines' boot gate, which runs the same scheduler on a second CPU
        // and requires `program ended on cpu 1` for it.
        let mut scheduler = Scheduler::new();
        for index in 0..3 {
            let name: &'static str = ["a", "b", "c"][index];
            let mut task = Task::without_space(name);
            arch::set_resume_address(task.context_mut(), index);
            scheduler.add(task);
        }

        // As many CPUs as this build describes, which is one on a host and more
        // on a machine that starts a second CPU.  A test that named four slots
        // would be a test that only compiles where the machine had them.
        let cpus = crate::per_cpu::MAX_CPUS.min(3);

        // Each CPU takes one task, and no two are the same.
        //
        // It was a `while let Some(x) = scheduler.claim(0)` loop, and it never
        // ended: `claim` on a CPU that already holds a task releases that task
        // and takes another, so the released one is claimable again on the next
        // call and the call after that takes it back.  The `Vec` grew until the
        // kernel's OOM killer ended the run, which read as "the build is too
        // large for this machine" through three separate attempts before the
        // loop was found.
        //
        // So: one claim per CPU, in a loop bounded by the number of CPUs, and
        // every claim is checked rather than fed to another claim.
        let mut taken = Vec::new();
        for cpu in 0..cpus {
            let Claim::Took(claimed) = scheduler.claim(cpu) else {
                panic!("cpu {cpu} was refused a task with tasks still free");
            };
            assert!(
                !taken.contains(&claimed),
                "two CPUs took one task: {claimed} twice"
            );
            taken.push(claimed);
        }

        // A CPU that holds nothing never receives a task another CPU holds.
        //
        // On a host `MAX_CPUS` is one, so there is no idle CPU to ask and this
        // block does not run; on a machine that starts a second CPU it does,
        // and it is the assertion the whole two-CPU design rests on.
        if cpus < crate::per_cpu::MAX_CPUS
            && let Claim::Took(claimed) = scheduler.claim(cpus)
        {
            assert!(
                !taken.contains(&claimed),
                "an idle CPU was handed {claimed}, which another CPU holds"
            );
        }
    }

    /// A CPU that already holds a task is refused, not silently given another.
    ///
    /// This is the property the old `Option` return could not express.  It used
    /// to answer `Some` for this case by releasing the task the CPU held and
    /// taking a new one, so a loop that claimed until it saw `None` never
    /// ended: its `Vec` grew until the OOM killer stopped the run, three times,
    /// and the failure read as a build too large for the machine.
    ///
    /// The type is the fix: `Claim` has no `is_some`, so that loop cannot be
    /// written without naming the case, and a caller that names it has to
    /// decide what happens to the task it was holding.
    #[test]
    fn a_cpu_that_already_holds_a_task_is_refused() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("a"));
        scheduler.add(Task::without_space("b"));

        assert_eq!(scheduler.claim(0), Claim::Took(0));
        assert_eq!(
            scheduler.claim(0),
            Claim::AlreadyRunning,
            "a second claim by the same CPU is a mistake, and it says so"
        );
        // And the refusal changed nothing: task 0 is still this CPU's, and task
        // 1 is still free for a CPU that has nothing.
        assert_eq!(
            scheduler.current_pid(0),
            Some(0),
            "the refused claim released the task it was holding"
        );
        assert_eq!(scheduler.claim(1), Claim::Took(1));
    }

    /// A task a CPU finishes does not come back to another CPU.
    #[test]
    fn a_finished_task_is_not_handed_to_another_cpu() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("a"));
        scheduler.add(Task::without_space("b"));

        // CPU 0 is running task 0, which the first `add` recorded.
        assert_eq!(scheduler.claim(0), Claim::Took(0));
        let mut frame = starting_context(0, 0);
        scheduler.schedule(0, &mut frame, true);
        assert_eq!(scheduler.exited(), 1);
        assert_ne!(
            scheduler.claim(0),
            Claim::Took(0),
            "the finished task came back"
        );
    }

    /// A task another CPU is running is not offered, and one it finished is.
    #[test]
    fn one_cpu_running_a_task_hides_it_from_the_other() {
        let mut scheduler = Scheduler::new();
        for index in 0..3 {
            let name: &'static str = ["a", "b", "c"][index];
            let mut task = Task::without_space(name);
            arch::set_resume_address(task.context_mut(), index);
            scheduler.add(task);
        }

        // The boot claims the task it enters, which is task 0 for CPU 0 here.
        assert_eq!(scheduler.claim(0), Claim::Took(0), "cpu 0 takes task 0");
        // Tasks 1 and 2 are free, so both CPUs have somewhere to go.  What must
        // not happen is CPU 1 being offered the task CPU 0 is running.
        assert!(scheduler.has_selectable(0), "tasks 1 and 2 are free");
        let Claim::Took(theirs) = scheduler.claim(1) else {
            panic!("cpu 1 was refused a task with two free");
        };
        assert_ne!(theirs, 0, "cpu 1 was offered the task cpu 0 is running");
    }

    /// A task placed on a CPU for the first time has not migrated.
    ///
    /// The count exists to say a task **moved**, and a first placement is where
    /// a task starts.  Counting it would make every boot report one migration
    /// it did not make, and the number would stop describing placement.
    #[test]
    fn a_first_placement_is_not_a_migration() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("one"));
        scheduler.assign(0, 0);
        let (count, last) = scheduler.migrations();
        assert_eq!(count, 0, "the first CPU to run a task is not a move");
        assert_eq!(last, None);
    }

    /// Taking a task onto a different CPU is a migration, and it is named.
    ///
    /// This is the mechanism the boot reports, and a host is the only place its
    /// arithmetic can be exercised without depending on which CPU reaches the
    /// queue first: on a real boot two runs in twenty move no task at all,
    /// which is why the gate cannot require a move and this test is what pins
    /// the rule.
    #[test]
    fn taking_a_task_elsewhere_is_a_migration_and_names_both_cpus() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("one"));
        scheduler.assign(0, 0);
        scheduler.assign(1, 0);
        let (count, last) = scheduler.migrations();
        assert_eq!(count, 1);
        assert_eq!(
            last,
            Some((0, 0, 1)),
            "the task, the CPU it left, the CPU it reached"
        );
    }

    /// Re-selecting the task a CPU already holds is not a migration.
    ///
    /// A preemption with one runnable task comes back to the same task, and a
    /// count that included it would grow with the timer rather than with
    /// placement.
    #[test]
    fn the_same_cpu_taking_it_back_is_not_a_migration() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("one"));
        scheduler.assign(0, 0);
        scheduler.assign(0, 0);
        assert_eq!(scheduler.migrations().0, 0);
    }

    /// A park whose question answered itself does not park.
    ///
    /// `block_unless` is the fix for the gap between "the wait is real" and
    /// "the task is in the blocked set": a wake that fires inside that gap
    /// wakes nothing, and the task parks after the fact it was waiting for has
    /// already happened.  The interleaving itself is a machine's; what a host
    /// pins is the decision — an answer comes back and the task stays runnable,
    /// `None` parks.
    #[test]
    fn a_park_whose_question_answered_itself_does_not_park() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("a"));
        scheduler.add(Task::without_space("b"));
        assert_eq!(scheduler.claim(0), Claim::Took(0));
        let frame = starting_context(0, 0);

        let answer = scheduler.block_unless(0, &frame, || Some(7));
        assert_eq!(answer, Some(7), "the answer comes back for the caller");
        assert_eq!(scheduler.blocked(), 0, "nothing parked");
        assert!(scheduler.has_selectable(0), "the task is still runnable");
    }

    /// A park saves the call's own address, so the wake retries the call.
    ///
    /// A trap resumes at the instruction after the call.  That is right for an
    /// answered call and wrong for a parked one: the wake would continue past a
    /// call whose handler never answered, and the program would read whatever
    /// its answer register held from the call before.  The rewind is part of
    /// what parking means, and it has to happen **after** the frame is copied
    /// into the task — the first attempt rewound the caller's own copy and left
    /// the saved one pointing past the call, which is why the wait parked and
    /// never came back.
    #[test]
    fn a_park_saves_the_address_of_the_call_it_did_not_answer() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("only"));
        assert_eq!(scheduler.claim(0), Claim::Took(0));

        // A frame whose resume is the instruction after a call: this is what a
        // trap hands a handler.
        let after_the_call = 0x80_0000_2004;
        let frame = starting_context(after_the_call, 0x80_0000_2000);
        scheduler.block(0, &frame);

        assert_eq!(scheduler.blocked(), 1);
        let saved = *scheduler.tasks[0].context();
        assert_ne!(
            arch::resume_address(&saved),
            after_the_call,
            "the saved position is the call, not the instruction after it"
        );
        assert!(
            arch::resume_address(&saved) < after_the_call,
            "and it moved back, not forward: {:x}",
            arch::resume_address(&saved)
        );
    }

    /// A park whose question is still open parks, and a wake ends it.
    ///
    /// This is the other order, and the one the wake must find: the task is in
    /// the blocked set with the frame it parked from, and `wake_blocked` is
    /// what makes it selectable again.  One task, so selectable means *this*
    /// task and not merely some other one.
    #[test]
    fn a_park_whose_question_is_still_open_parks_and_a_wake_ends_it() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("a"));
        assert_eq!(scheduler.claim(0), Claim::Took(0));
        let frame = starting_context(0x80_0000_1234, 0x80_0000_2000);

        assert_eq!(scheduler.block_unless(0, &frame, || None::<usize>), None);
        assert_eq!(scheduler.blocked(), 1);
        assert!(!scheduler.has_selectable(0), "a is parked");
        assert_eq!(scheduler.wake_blocked(), 1);
        assert!(scheduler.has_selectable(0), "and the wake ended it");
        // The saved frame is the one it parked from, except that its resume
        // points at the call the park did not answer.  Everything else
        // survives: a park that lost a register would resume the call with the
        // wrong arguments.
        let saved = *scheduler.tasks[0].context();
        assert_eq!(
            arch::stack_pointer(&saved),
            arch::stack_pointer(&frame),
            "the park kept the task's stack"
        );
        assert_eq!(
            arch::return_value(&saved),
            arch::return_value(&frame),
            "and its arguments"
        );
    }

    /// A wait whose exit already happened answers it without parking.
    ///
    /// The re-check exists for the deciding moment: a child that died while the
    /// call was deciding to wait answers the call at once, and a park that ran
    /// anyway would wait for an exit that will never come again.
    #[test]
    fn a_wait_whose_exit_already_happened_answers_it_without_parking() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("a"));
        scheduler.add(Task::without_space("b"));
        assert_eq!(scheduler.claim(0), Claim::Took(0));
        let mut frame = starting_context(0, 0);

        // a exits with 7; b is what this cpu runs next.
        scheduler.schedule_on(0, &mut frame, true, true, Some(7));
        let _ = scheduler.claim(0);
        let waited_at = starting_context(0x80_0000_1234, 0x80_0000_2000);

        let answer = scheduler.block_unless_exit(0, &waited_at);
        assert_eq!(answer, Some(7), "the first exit's status is the answer");
        assert_eq!(scheduler.blocked(), 0, "nothing parked");
        assert!(scheduler.has_selectable(0), "the waiter is still runnable");
    }

    /// A sleeping task counts as a reason to wait; a finished one does not.
    ///
    /// This is the difference between the two questions.  `has_other_runnable`
    /// answers "would a switch be a switch", and a sleeping child answers no —
    /// so a wait that asked it answered `NotFound` to a parent whose child had
    /// only gone to sleep, turning a wait into an error.  The wait's question
    /// is "could another task still finish", and a sleeper could.
    #[test]
    fn a_sleeping_task_is_a_reason_to_wait() {
        // The shape a wait actually has: this CPU runs the parent, and the only
        // other task — a child — is asleep.  Both predicates look at that
        // child, and they must disagree about it.
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("parent"));
        scheduler.add(Task::without_space("child"));
        assert_eq!(scheduler.claim(0), Claim::Took(0));

        // The child asleep, reached directly: a host has one CPU slot, so there
        // is no second CPU to have put it to sleep through `sleep_until`.
        scheduler.tasks[1].state = super::task::State::Sleeping { until: 1000 };
        assert_eq!(scheduler.sleeping(), 1);

        assert!(
            !scheduler.has_other_runnable(0),
            "a switch now would be a timer tick, not a switch"
        );
        assert!(
            scheduler.has_other_unfinished(0),
            "but the sleeper will wake and exit, which is what a wait waits for"
        );
    }

    /// A signal sent to a process queues, and the oldest comes out first.
    ///
    /// The ring is FIFO on purpose: a sender that sent two signals and a
    /// receiver that answers them in the order they were sent is the reading
    /// a caller can reason about, and a ring that answered the newest first
    /// would make two signals race.
    #[test]
    fn a_signal_queues_and_the_oldest_comes_out_first() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("target"));
        scheduler.tasks[0].identify(1, 7);
        // The receiver is the running task: a wait takes the ring of the
        // task this CPU runs, which is what `wait_signal_current` reads.
        assert_eq!(scheduler.claim(0), Claim::Took(0));

        scheduler
            .send_signal_to(7, 1, 10, 0xfeed)
            .expect("send to a real pid");
        scheduler
            .send_signal_to(7, 1, 12, 0xbeef)
            .expect("a second signal queues beside the first");

        let taken = scheduler.wait_signal_current(0, &starting_context(0, 0));
        assert_eq!(taken, Some((10, 7, 0xfeed)), "the oldest first");
        let taken = scheduler.wait_signal_current(0, &starting_context(0, 0));
        assert_eq!(taken, Some((12, 7, 0xbeef)));
        assert_eq!(
            scheduler.wait_signal_current(0, &starting_context(0, 0)),
            None
        );
    }

    /// A signal to a pid no task carries is `NotFound`, and a full ring is
    /// `Busy` — the two refusals a sender can act on.
    #[test]
    fn a_signal_to_no_one_is_not_found_and_a_full_ring_is_busy() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("target"));
        scheduler.tasks[0].identify(1, 7);
        assert_eq!(scheduler.claim(0), Claim::Took(0));

        assert_eq!(
            scheduler.send_signal_to(7, 99, 10, 0),
            Err(abi::Error::NotFound),
            "no task carries that pid"
        );

        for _ in 0..super::task::TASK_SIGNAL_QUEUE {
            scheduler.send_signal_to(7, 1, 10, 0).expect("room");
        }
        assert_eq!(
            scheduler.send_signal_to(7, 1, 10, 0),
            Err(abi::Error::Busy),
            "the target is not consuming"
        );
        // And taking one makes room: the refusal is about the ring, not the
        // target.
        assert!(
            scheduler
                .wait_signal_current(0, &starting_context(0, 0))
                .is_some()
        );
        scheduler.send_signal_to(7, 1, 10, 0).expect("room again");
    }

    /// A masked signal stays queued, and the wait skips it: the refusal is
    /// "not yet", not "no".
    ///
    /// The property is what makes a mask usable — a caller that blocks a
    /// signal must be able to hold the bit without losing what arrives
    /// under it, and the day the bit clears the ring answers.  The queue
    /// filling while blocked is the sender's `Busy`, which the ring test
    /// above pins; this one is the skip.
    #[test]
    fn a_masked_signal_stays_queued_and_a_clear_bit_answers_it() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("target"));
        scheduler.tasks[0].identify(1, 7);
        assert_eq!(scheduler.claim(0), Claim::Took(0));

        scheduler
            .send_signal_to(7, 1, 10, 0x41)
            .expect("the send succeeds whatever the mask says");
        scheduler.set_signal_mask_current(0, 1 << 10);

        assert_eq!(
            scheduler.wait_signal_current(0, &starting_context(0, 0)),
            None,
            "the wait skips what the mask blocks"
        );
        scheduler.set_signal_mask_current(0, 0);
        assert_eq!(
            scheduler.wait_signal_current(0, &starting_context(0, 0)),
            Some((10, 7, 0x41)),
            "the day the bit clears, the ring answers"
        );
    }

    /// A suspend answers an unblocked signal and puts the caller's own mask
    /// back — the mask the suspend found, not the one it was told to run
    /// under.
    ///
    /// The restore is the call's whole point: a caller that ends a suspend
    /// with the suspend's own mask would have its blocking silently widened
    /// by the act of waiting.
    #[test]
    fn a_suspend_answers_and_puts_the_caller_s_mask_back() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("target"));
        scheduler.tasks[0].identify(1, 7);
        assert_eq!(scheduler.claim(0), Claim::Took(0));
        scheduler.set_signal_mask_current(0, 1 << 10);

        scheduler.send_signal_to(7, 1, 10, 0x42).expect("send");

        // Everything unblocked: the masked signal answers, and the mask the
        // caller had — bit 10 — goes back.
        let answer = scheduler.sigsuspend_current(0, &starting_context(0, 0), 0);
        assert_eq!(answer, Some((10, 7, 0x42)));
        assert_eq!(
            scheduler.tasks[0].signal_mask,
            1 << 10,
            "the mask went back"
        );

        // And the ring is empty: the signal was taken, not copied.
        assert!(scheduler.tasks[0].take_signal().is_none());
    }

    /// A signal sent to a task that is not running still queues, and the
    /// task that owns the ring is the one whose take answers.
    ///
    /// The send is addressed to a **pid**, and two tasks in the scheduler
    /// have separate rings: a signal for one must never surface in the
    /// other's wait.
    #[test]
    fn a_signal_surfaces_in_the_target_s_wait_and_no_one_else_s() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("first"));
        scheduler.add(Task::without_space("second"));
        scheduler.tasks[0].identify(1, 9);
        scheduler.tasks[1].identify(2, 9);

        scheduler.send_signal_to(9, 2, 15, 0x77).expect("send");

        // The first task's wait — the cpu slot that is not running anything
        // in this test — takes nothing: the ring belongs to pid 2.
        let mut answer = None;
        if let Some(task) = scheduler.tasks.get_mut(0) {
            answer = task.take_signal();
        }
        assert!(answer.is_none(), "the signal is not the first task's");
        assert!(
            scheduler.tasks[1].take_signal().is_some(),
            "it is the second's"
        );
    }

    /// A task that finished is not a reason to wait, and the waiter is.
    ///
    /// The other half: once the only other task is `Finished`, no exit can
    /// arrive, and a wait that parked would be a hang.  The waiter itself is
    /// excluded — it is unfinished by definition and cannot answer its own
    /// wait.
    #[test]
    fn a_finished_task_is_not_a_reason_to_wait() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("parent"));
        assert_eq!(scheduler.claim(0), Claim::Took(0));

        assert!(
            !scheduler.has_other_unfinished(0),
            "the only task is the one asking"
        );

        scheduler.add(Task::without_space("child"));
        assert!(scheduler.has_other_unfinished(0), "a live child counts");

        // The parent exits; the child is the only unfinished task left, and a
        // CPU running it would not be waiting on itself.
        let mut frame = starting_context(0, 0);
        scheduler.schedule(0, &mut frame, true);
        assert_eq!(scheduler.exited(), 1);
    }

    /// A pid-keyed wait answers about that process and no other.
    ///
    /// This is what `WaitProcess` could not do: it answered about whichever
    /// process finished first.  Two children are marked finished with different
    /// statuses here, and the wait names one of them, so a lookup keyed on "the
    /// first exit" would answer the other's number.  The statuses are written
    /// directly because a host has one CPU slot — it cannot run two tasks to
    /// their exits in turn, and the property under test is the lookup.
    #[test]
    fn a_pid_keyed_wait_answers_about_the_process_it_names() {
        let mut scheduler = Scheduler::new();
        for (name, pid) in [("parent", 10u32), ("first", 11), ("second", 12)] {
            let mut task = Task::without_space(name);
            task.identify(pid, 10);
            scheduler.add(task);
        }
        scheduler.tasks[1].status = Some(11);
        scheduler.tasks[2].status = Some(22);

        let assert_at = starting_context(0x80_0000_1234, 0x80_0000_2000);
        assert_eq!(
            scheduler.block_unless_pid(0, &assert_at, 12),
            PidWait::Ended(22),
            "the process the caller named"
        );
        assert_eq!(
            scheduler.block_unless_pid(0, &assert_at, 11),
            PidWait::Ended(11),
            "and the other one, on its own pid"
        );
    }

    /// A pid no task has says so, and does not park.
    ///
    /// The three-way answer's point: a caller that mistyped a pid must be told,
    /// not left waiting for a process that will never exist.  Folding this into
    /// "not yet" is a wait that hangs for ever on an argument.
    #[test]
    fn a_pid_keyed_wait_refuses_a_process_that_does_not_exist() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("only"));
        assert_eq!(scheduler.claim(0), Claim::Took(0));
        let frame = starting_context(0x80_0000_1234, 0x80_0000_2000);

        assert_eq!(
            scheduler.block_unless_pid(0, &frame, 9999),
            PidWait::NoSuchProcess
        );
        assert_eq!(
            scheduler.blocked(),
            0,
            "nothing parked for a pid that is not"
        );
    }

    /// A pid that exists and has not ended parks.
    #[test]
    fn a_pid_keyed_wait_parks_until_the_process_ends() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("parent"));
        let mut child = Task::without_space("child");
        child.identify(42, 0);
        scheduler.add(child);
        assert_eq!(scheduler.claim(0), Claim::Took(0));
        let frame = starting_context(0x80_0000_1234, 0x80_0000_2000);

        assert_eq!(scheduler.block_unless_pid(0, &frame, 42), PidWait::NotYet);
        assert_eq!(scheduler.blocked(), 1, "the child has not ended");
    }

    /// A wait whose exit has not happened parks./// A wait whose exit has not
    /// happened parks.
    #[test]
    fn a_wait_with_no_exit_parks() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("a"));
        scheduler.add(Task::without_space("b"));
        assert_eq!(scheduler.claim(0), Claim::Took(0));
        let frame = starting_context(0, 0);

        assert_eq!(scheduler.block_unless_exit(0, &frame), None);
        assert_eq!(scheduler.blocked(), 1);
    }

    /// A process finishing wakes what waited on it.
    ///
    /// The wake in the exit's own recording is what makes the wait endable: a
    /// waiter parked before the child's exit would otherwise stay parked beside
    /// the very fact it was waiting for.  A host can hold one running task, so
    /// the parked waiter here is not the cpu's current one — the state is the
    /// field the park itself writes, reached directly, and the exit is the only
    /// writer that undoes it.
    #[test]
    fn a_process_finishing_wakes_what_waited_on_it() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("a"));
        scheduler.add(Task::without_space("b"));
        assert_eq!(scheduler.claim(0), Claim::Took(0));
        let mut frame = starting_context(0, 0);

        // A preemption puts b on the cpu and leaves a runnable beside it.
        scheduler.schedule(0, &mut frame, false);

        // The waiter parks — on a machine this is `block_unless_exit` parking
        // the task that called the wait, on the cpu that serves it; a host with
        // one cpu slot reaches the same state through the field.
        scheduler.tasks[0].state = super::task::State::Blocked;
        assert_eq!(scheduler.blocked(), 1);

        // The cpu's own task exits: the status is recorded and the wake fires
        // in the same critical section.
        scheduler.schedule(0, &mut frame, true);
        assert_eq!(scheduler.blocked(), 0, "the exit woke the waiter");
        assert!(scheduler.has_selectable(0), "and it is selectable again");
    }
}
