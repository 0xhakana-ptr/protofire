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
        // distributor never had the interrupt pending.  `wait_for_a_wakeup` is
        // a bounded spin now for that reason, which is what makes this branch
        // reachable at all.
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

/// How many switches and exits the installed scheduler has seen.
///
/// `(switches, exited)`, or `(0, 0)` when nothing ran.
pub fn statistics() -> (usize, usize) {
    with_scheduler(|scheduler| {
        scheduler.as_ref().map_or((0, 0), |scheduler| {
            (scheduler.switches(), scheduler.exited())
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
        if !scheduler.has_other_runnable(cpu) {
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

/// Wake every blocked task, answering how many.
///
/// Called when something a blocked task was waiting for changed, a pipe's
/// writer putting bytes in, its write end closing, or a process exiting.
pub fn wake_blocked() -> usize {
    with_scheduler(|scheduler| scheduler.as_mut().map_or(0, Scheduler::wake_blocked))
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
/// core until an interrupt arrives.  The boot hung once with `every program is
/// asleep, waiting` and no tick, because the kernel had tried to spell `sti`
/// itself.
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
mod tests;
