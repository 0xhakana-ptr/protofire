//! kernel/src/scheduler/mod.rs
//!
//! Two programs, taking turns.
//!
//! ## What a task is here
//!
//! A saved `Context` — the whole trap frame — and the address space it runs
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
//! runnable" reads the free functions here — which are what the trap path, the
//! timer's handler and the idle loop call.
//!
//! ## Why round-robin and nothing else
//!
//! A real scheduler decides by priority, by how long a task has run, and by
//! what it is waiting for.  Those are decisions about *when* to switch.  This
//! kernel switches at two moments: a program made a call, and the timer fired.
//! Both are the machine's, not the policy's, so the policy is "the next one",
//! and saying so is more useful than a weight table that decides nothing.

pub mod core;
pub mod task;

pub use core::Scheduler;
pub use task::Task;
pub use task::starting_context;

use arch::CallFrame;

/// The scheduler the boot installed.
///
/// A `static` for the same reason the syscall registry is one: a supervisor
/// call arrives from a trap with no context to be handed anything, so the table
/// it needs has to be reachable without one.
static SCHEDULER: cell::SyncUnsafeCell<Option<Scheduler>> = cell::SyncUnsafeCell::new(None);

/// Install the scheduler the boot built.
///
/// # Safety
///
/// Called once, before any program runs.
pub unsafe fn install(scheduler: Scheduler) {
    // SAFETY: the caller promises this is the only write and that it happens
    // before EL0 is entered.
    unsafe { *SCHEDULER.get() = Some(scheduler) };
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
    // SAFETY: the scheduler is written once before any program runs.
    let scheduler = unsafe { (&mut *SCHEDULER.get()).as_mut() };
    match scheduler {
        Some(scheduler) => scheduler.schedule_from(frame, false, false),
        None => arch::CallOutcome::Exit,
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
    // SAFETY: the scheduler is written once before any program runs.
    let scheduler: &mut Option<Scheduler> = unsafe { &mut *SCHEDULER.get() };
    match scheduler {
        Some(scheduler) => scheduler.schedule_with_status(frame, exiting, true, Some(status)),
        None => arch::CallOutcome::Exit,
    }
}

pub fn advance(frame: &mut arch::Context, exiting: bool) -> arch::CallOutcome {
    // SAFETY: the scheduler is written once before any program runs, and this
    // read happens after that.
    let scheduler = unsafe { (*SCHEDULER.get()).as_mut() };
    match scheduler {
        Some(scheduler) => scheduler.schedule(frame, exiting),
        None => arch::CallOutcome::Exit,
    }
}

/// How many switches and exits the installed scheduler has seen.
///
/// `(switches, exited)`, or `(0, 0)` when nothing ran.
pub fn statistics() -> (usize, usize) {
    // SAFETY: as `advance`.
    let scheduler = unsafe { (*SCHEDULER.get()).as_ref() };
    scheduler.map_or((0, 0), |scheduler| {
        (scheduler.switches(), scheduler.exited())
    })
}

/// The root the first task runs through.
///
/// Read out of the static because the boot installs the scheduler and then
/// enters a program: the value it built is gone by then, and the entry into EL0
/// has to translate through the first task's root rather than the kernel's.
#[cfg(target_os = "none")]
pub fn first_root() -> Option<usize> {
    // SAFETY: as `advance`.
    let scheduler = unsafe { (*SCHEDULER.get()).as_ref() };
    scheduler.and_then(|scheduler| scheduler.current_root())
}

/// Whether a scheduler is installed and still has work.
pub fn has_runnable() -> bool {
    // SAFETY: as `advance`.
    let scheduler = unsafe { (*SCHEDULER.get()).as_ref() };
    scheduler.is_some_and(Scheduler::has_runnable)
}

/// Preempt: put the next task's context in `frame` and switch to its space.
///
/// ## Why this is different from `advance`
///
/// `advance` answers a call: the frame it is given belongs to a task that asked
/// for something, and the caller does something with the answer.  This is
/// called from an interrupt, where the frame belongs to whatever the program
/// was doing — so there is no call, no answer, and nothing to report to anyone.
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
    // A timer fires at EL1 as well as at EL0 — the kernel's own boot code takes
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

    // SAFETY: the scheduler is written once before any program runs.
    let scheduler = unsafe { (*SCHEDULER.get()).as_mut() };
    let Some(scheduler) = scheduler else {
        return;
    };
    if !scheduler.has_other_runnable() {
        return;
    }
    let _ = scheduler.schedule(frame, false);
}

/// Put the running program to sleep for `microseconds`.
///
/// Answers the counter reading it will wake at, so a boot line can report the
/// deadline rather than the duration — the two differ by however long the
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
        // SAFETY: the scheduler is written once before any program runs, and
        // `as_mut` on the raw pointer is what a single writer holding the only
        // reference is allowed to do.
        let scheduler: &mut Option<Scheduler> = unsafe { &mut *SCHEDULER.get() };
        scheduler.as_mut()?.sleep_until(until, frame);
        Some(until)
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
        // SAFETY: as `sleep_for_microseconds`.
        let scheduler: &mut Option<Scheduler> = unsafe { &mut *SCHEDULER.get() };
        scheduler
            .as_mut()
            .map_or(0, |scheduler| scheduler.wake_expired(now))
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
    // SAFETY: the scheduler is written once before any program runs.
    let scheduler = unsafe { (*SCHEDULER.get()).as_ref() };
    scheduler.is_some_and(Scheduler::has_other_runnable)
}

/// Whether any installed task could be selected right now.
pub fn has_selectable() -> bool {
    // SAFETY: the scheduler is written once before any program runs.
    let scheduler = unsafe { (*SCHEDULER.get()).as_ref() };
    scheduler.is_some_and(Scheduler::has_selectable)
}

/// Park the running task until another task wakes it.
///
/// `None` when no scheduler is installed, which is the state a host build is in
/// and the state a boot is in before it installs one.
pub fn block(frame: &arch::Context) -> bool {
    // SAFETY: the scheduler is written once before any program runs.
    let scheduler = unsafe { (&mut *SCHEDULER.get()).as_mut() };
    match scheduler {
        Some(scheduler) => {
            scheduler.block(frame);
            true
        }
        None => false,
    }
}

/// Wake every blocked task, answering how many.
///
/// Called when something a blocked task was waiting for changed — a pipe's
/// writer putting bytes in, or its write end closing.
pub fn wake_blocked() -> usize {
    // SAFETY: as `block`.
    let scheduler = unsafe { (&mut *SCHEDULER.get()).as_mut() };
    scheduler.map_or(0, Scheduler::wake_blocked)
}

/// How many installed tasks are blocked, for a boot line that reports it.
pub fn blocked() -> usize {
    // SAFETY: as `block`.
    let scheduler = unsafe { (*SCHEDULER.get()).as_ref() };
    scheduler.map_or(0, Scheduler::blocked)
}

/// Whether any installed task is asleep rather than runnable or finished.
///
/// The question a sleep handler asks: with the running task asleep and no other
/// runnable, the boot has to wait for a tick instead of stopping, and this is
/// what says the wait has a reason.
pub fn has_sleeping() -> bool {
    // SAFETY: the scheduler is written once before any program runs.
    let scheduler = unsafe { (*SCHEDULER.get()).as_ref() };
    scheduler.is_some_and(Scheduler::has_sleeping)
}

/// How many installed tasks are asleep, for a boot line that reports it.
pub fn sleeping() -> usize {
    // SAFETY: as `has_sleeping`.
    let scheduler = unsafe { (*SCHEDULER.get()).as_ref() };
    scheduler.map_or(0, Scheduler::sleeping)
}

/// Whether a call means the program has finished.
/// The process id of the running task, if a scheduler is installed.
pub fn current_pid() -> Option<u32> {
    // SAFETY: the scheduler is written once before any program runs.
    let scheduler = unsafe { (*SCHEDULER.get()).as_ref() };
    scheduler?.current_pid()
}

/// The parent of the running task, if a scheduler is installed.
pub fn current_parent() -> Option<u32> {
    // SAFETY: as `current_pid`.
    let scheduler = unsafe { (*SCHEDULER.get()).as_ref() };
    scheduler?.current_parent()
}

/// The status of the first process that has exited, if any has.
///
/// A wait in this boot has one process tree, so "the first exit" is the only
/// answer it can give; a caller that needs a particular child needs a parent
/// that exists, which is a later change.
pub fn first_exit_status() -> Option<usize> {
    // SAFETY: as `current_pid`.
    let scheduler = unsafe { (*SCHEDULER.get()).as_ref() }?;
    scheduler.first_exited().and_then(|task| task.status())
}

/// Every process that has exited, with its id and status.
///
/// Reported as a list rather than looked up by a guessed id: the boot's tasks
/// are the processes it built, and asking for pids 1..3 would answer nothing on
/// a boot that numbered them differently.
pub fn exit_statuses() -> alloc::vec::Vec<(u32, usize)> {
    // SAFETY: as `current_pid`.
    let Some(scheduler) = (unsafe { (*SCHEDULER.get()).as_ref() }) else {
        return alloc::vec::Vec::new();
    };
    scheduler.exited_with_status()
}

/// The status a process exited with, if it has exited.
pub fn exit_status(pid: u32) -> Option<Option<usize>> {
    // SAFETY: as `current_pid`.
    let scheduler = unsafe { (*SCHEDULER.get()).as_ref() }?;
    scheduler.exit_status(pid)
}

/// Whether a task other than the running one can be selected.
///
/// What a wait asks before it parks: with nothing else runnable no exit can
/// arrive, and blocking would be a hang rather than a wait.
pub fn has_runnable_except_current() -> bool {
    // SAFETY: as `current_pid`.
    let scheduler = unsafe { (*SCHEDULER.get()).as_ref() };
    scheduler.is_some_and(Scheduler::has_other_runnable)
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
/// The timer keeps firing, and its handler calls [`wake_expired`] — which is
/// what turns a deadline into a runnable task.  The loop below takes the
/// interrupt, the handler wakes a task, and `arch::wait_for_a_wakeup` returns
/// once one is runnable.  The scheduler is then asked for a context and the
/// trap path resumes it.
///
/// ## Why the machine does the waiting
///
/// A supervisor call arrives through an **interrupt gate**, which clears the
/// interrupt flag on entry — so the kernel runs with interrupts masked for the
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
/// machine that never does that is a machine that hangs — with a log that
/// already said "every program is asleep, waiting".
pub fn idle_until_woken() {
    while has_sleeping() && !has_selectable() {
        arch::wait_for_a_wakeup();
    }
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;
    use alloc::vec::Vec;

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
        // answered — and the answer is what the kernel actually asks for.
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

        let mut frame = starting_context(0, 0);
        let mut order = Vec::new();
        for _ in 0..6 {
            scheduler.schedule(&mut frame, false);
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

        let mut frame = starting_context(0, 0);
        // Task 0 exits.
        scheduler.schedule(&mut frame, true);
        assert_eq!(scheduler.exited(), 1);

        let mut order = Vec::new();
        for _ in 0..4 {
            scheduler.schedule(&mut frame, false);
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
        let mut frame = starting_context(0, 0);
        scheduler.schedule(&mut frame, true);
        assert_eq!(scheduler.exited(), 1);
        assert!(!scheduler.has_runnable());
        assert!(scheduler.current().is_none());
    }

    /// A sleeping task is not selectable, and waking one makes it so.
    ///
    /// Two different questions, deliberately: `has_runnable` answers "does the
    /// boot still owe work", which a sleeper makes true, and `has_selectable`
    /// answers "can the CPU move now", which it does not.  The idle loop asked
    /// the first and never waited — the boot printed one program's line and
    /// stopped with the other asleep.
    #[test]
    fn a_sleeping_task_is_owed_but_not_selectable() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("a"));
        scheduler.add(Task::without_space("b"));

        let mut frame = starting_context(0, 0);
        scheduler.sleep_until(100, &frame);
        assert_eq!(scheduler.sleeping(), 1);
        assert!(scheduler.has_sleeping(), "the boot still owes it a run");
        assert!(scheduler.has_runnable(), "which is what this answers");
        assert!(scheduler.has_selectable(), "and b can still run");

        // Now b sleeps too: nothing is selectable, though two tasks are owed.
        scheduler.schedule(&mut frame, false);
        scheduler.sleep_until(100, &frame);
        assert_eq!(scheduler.sleeping(), 2);
        assert!(!scheduler.has_selectable(), "neither can run");
        assert!(scheduler.has_runnable(), "and both are still owed");
    }

    /// A woken task is selectable again, and one whose deadline has not passed
    /// is not.
    #[test]
    fn a_deadline_wakes_only_when_it_has_passed() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("only"));
        let frame = starting_context(0, 0);
        scheduler.sleep_until(1000, &frame);

        assert_eq!(scheduler.wake_expired(999), 0, "not yet");
        assert_eq!(scheduler.sleeping(), 1);

        assert_eq!(scheduler.wake_expired(1000), 1, "at the deadline");
        assert_eq!(scheduler.sleeping(), 0);
        assert!(scheduler.has_selectable());
    }

    /// A task that sleeps resumes where it asked to.
    ///
    /// The frame is saved by `sleep_until` itself.  Leaving it to the next
    /// scheduling call worked only while a call always happened; with every
    /// task asleep the boot idles instead, and the task then resumed at
    /// whatever position its context last held — which was the `Sleep` call,
    /// so it printed its line and slept again forever.
    #[test]
    fn a_sleeper_keeps_the_position_it_slept_at() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("a"));
        scheduler.add(Task::without_space("b"));

        // A frame that is unmistakably not a fresh one: it is the *reference*
        // the comparison below is against, so nothing has to read a field.
        let frame = starting_context(0x80_0000_1234, 0x80_0000_2000);
        let slept_at = frame;

        scheduler.sleep_until(50, &frame);

        // The frame the task holds is the one the sleep was called from, byte
        // for byte.  `Context` is `Copy` and `PartialEq`-free, so the check is
        // the two addresses plus a comparison of the whole value as bytes —
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
    /// epilogue restores — so this is the same mechanism as the task switch,
    /// and a scheduler that copied contexts but lost `x0` would resume the
    /// program with the wrong answer.
    #[test]
    fn a_resumed_task_finds_the_answer_in_x0() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("a"));
        let mut task = Task::without_space("b");
        arch::set_return_value(task.context_mut(), 42);
        scheduler.add(task);

        let mut frame = starting_context(0, 0);
        let outcome = scheduler.schedule(&mut frame, false);
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
}
