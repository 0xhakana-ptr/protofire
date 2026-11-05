//! kernel/src/scheduler/mod.rs
//!
//! Two programs, taking turns.
//!
//! ## What a task is here
//!
//! A saved `Context`, the whole trap frame, and the address space it runs
//! in.  There is no kernel stack per task, because a task never has one of its
//! own to be suspended on: a program runs at ring 3, so the only time it is
//! inside the kernel is inside a trap, and the trap path's frame *is* its saved
//! state.
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
//! ## Why round-robin and nothing else
//!
//! A real scheduler decides by priority, by how long a task has run, and by
//! what it is waiting for.  Those are decisions about *when* to switch.  This
//! kernel switches at two moments: a program made a call, and the timer fired.
//! Both are the machine's, not the policy's, so the policy is "the next one",
//! and saying so is more useful than a weight table that decides nothing.

//! ## Why the scheduler is behind a lock
//!
//! It was one structure reached through a `SyncUnsafeCell` with no lock, which
//! was sound only because one CPU ever wrote it.  A second CPU taking a timer
//! tick reaches `preempt`, and a second CPU serving a call reaches `advance`:
//! two `&mut Scheduler` over one `Vec<Task>` is undefined behaviour, and the
//! symptom, a task resumed with another CPU's context, is a fault far from its
//! cause.
//!
//! So every entry below takes one lock.  It is a **global** lock and not one
//! queue per CPU, and the choice is deliberate: a per-CPU queue needs task
//! migration, migration needs TLB shootdown on a machine whose flush is local,
//! and a load balancer to decide where a task goes.  A global queue needs none
//! of those and pays for it in contention, which this kernel has no load to
//! produce.  The change that adds per-CPU queues is the change that also adds
//! the three things they require.
//!
//! The lock masks interrupts while it is held, which is what keeps a tick from
//! arriving on this CPU mid-update and taking the lock again.  Callers that
//! take several of these entry points in sequence are holding nothing between
//! them, so the nesting that would deadlock does not exist.

pub mod core;
pub mod task;

pub use core::Scheduler;
pub use task::Task;
pub use task::starting_context;

use arch::CallFrame;

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

/// Install the next task's context without saving the frame it was given.
///
/// For the idle path: the boot waiting for a wakeup holds a kernel frame, and
/// saving it into a task would replace that task's saved program state with a
/// kernel address.  See `Scheduler::schedule_from`.
///
/// Answers what `advance` answers, and for the same reason: `Exit` means the
/// frame was not replaced and the caller decides what to do about it.
pub fn switch_without_saving(frame: &mut arch::Context) -> arch::CallOutcome {
    with_scheduler(|scheduler| match scheduler {
        Some(scheduler) => scheduler.schedule_on(this_cpu(), frame, false, false, None),
        None => arch::CallOutcome::Exit,
    })
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
    with_scheduler(|scheduler| match scheduler {
        Some(scheduler) => {
            scheduler.schedule_with_status(this_cpu(), frame, exiting, true, Some(status))
        }
        None => arch::CallOutcome::Exit,
    })
}

pub fn advance(frame: &mut arch::Context, exiting: bool) -> arch::CallOutcome {
    with_scheduler(|scheduler| match scheduler {
        Some(scheduler) => scheduler.schedule(this_cpu(), frame, exiting),
        None => arch::CallOutcome::Exit,
    })
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
/// ## Why this is different from `advance`
///
/// `advance` answers a call: the frame it is given belongs to a task that asked
/// for something, and the caller does something with the answer.  This is
/// called from an interrupt, where the frame belongs to whatever the program
/// was doing, so there is no call, no answer, and nothing to report to anyone.
/// The only thing that matters is that the frame the epilogue restores is the
/// next task's.
///
/// ## Why it does not count a switch when nothing else can run
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

/// Wake every blocked task, answering how many.
///
/// Called when something a blocked task was waiting for changed, a pipe's
/// writer putting bytes in, or its write end closing.
pub fn wake_blocked() -> usize {
    with_scheduler(|scheduler| scheduler.as_mut().map_or(0, Scheduler::wake_blocked))
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

/// Whether a call means the program has finished.
/// Fork the running process: copy its space and context into a new task.
///
/// ## What the child inherits, and what it does not
///
/// Its parent's pages (copied, so a write in one does not reach the other), its
/// parent's context (so it resumes at the instruction after the `fork`), and a
/// pid of its own.  What it does **not** inherit is the parent's return value:
/// the fork returns the child's pid to the parent and zero to the child, which
/// is the one difference the two copies of the same instruction see.
///
/// ## Why the context is copied rather than built
///
/// A forked child resumes exactly where its parent asked, with the parent's
/// registers, including the stack pointer, which points into the copy.  A
/// context built from scratch would start the child at the beginning of its
/// program, which is `exec`, not `fork`.
///
/// Answers the child's pid, or `None` when the copy could not be made.
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

/// The process id of the running task, if a scheduler is installed.
pub fn current_pid() -> Option<u32> {
    let cpu = this_cpu();
    with_scheduler(|scheduler| scheduler.as_ref()?.current_pid(cpu))
}

/// The parent of the running task, if a scheduler is installed.
pub fn current_parent() -> Option<u32> {
    let cpu = this_cpu();
    with_scheduler(|scheduler| scheduler.as_ref()?.current_parent(cpu))
}

/// The status of the first process that has exited, if any has.
///
/// A wait in this boot has one process tree, so "the first exit" is the only
/// answer it can give; a caller that needs a particular child needs a parent
/// that exists, which is a later change.
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
/// ## What this replaces
///
/// A `halt` loop.  When every program is asleep the scheduler has nothing to
/// resume, and the trap path's return would land on a program that is not
/// runnable.  The choices are to stop the machine or to wait for the tick that
/// wakes one; stopping is the boot ending with work left.
///
/// ## How the wake happens
///
/// The timer keeps firing, and its handler calls [`wake_expired`], which is
/// what turns a deadline into a runnable task.  The loop below takes the
/// interrupt, the handler wakes a task, and `arch::wait_for_a_wakeup` returns
/// once one is runnable.  The scheduler is then asked for a context and the
/// trap path resumes it.
///
/// ## Why the machine does the waiting
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
/// ## Why there is no spin bound
///
/// One was here, at a million waits, on the argument that a machine whose timer
/// does not tick should say so rather than hang.  It fired on a healthy aarch64
/// boot: a `wfi` returns on every tick whether or not that tick ended the wait,
/// so the counter measured the boot's speed and not a fault.  What ends the
/// loop is `wake_expired` turning a deadline into a runnable task, and a
/// machine that never does that is a machine that hangs, with a log that
/// already said "every program is asleep, waiting".
pub fn idle_until_woken() {
    while has_sleeping() && !has_selectable() {
        arch::wait_for_a_wakeup();
    }
}

#[cfg(test)]
mod tests;
