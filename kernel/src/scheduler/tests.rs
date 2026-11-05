//! kernel/src/scheduler/tests.rs
//!
//! The scheduler's tests: the rotation, the three states that are not
//! "runnable", the deadline that wakes a sleeper, and the position a woken task
//! keeps.

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;

use super::Claim;
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

    // The boot claims its first task; a test that did not would be driving a
    // scheduler in a state no boot reaches.
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
    // the two addresses plus a comparison of the whole value as bytes, // which
    // is what "the position survived" means and nothing narrower.
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
/// context: one task, two CPUs, and a program that ran its own instructions on
/// two stacks at once.
#[test]
fn a_claim_does_not_hand_the_same_task_to_two_cpus() {
    let mut scheduler = Scheduler::new();
    for index in 0..3 {
        let name: &'static str = ["a", "b", "c"][index];
        let mut task = Task::without_space(name);
        arch::set_resume_address(task.context_mut(), index);
        scheduler.add(task);
    }

    // As many CPUs as this build describes, which is one on a host and more on
    // a machine that starts a second CPU.  A test that named four slots would
    // be a test that only compiles where the machine had them.
    let cpus = crate::per_cpu::MAX_CPUS.min(3);

    // Each CPU takes one task, and no two are the same.
    //
    // ## Why this is a bounded loop
    //
    // It was a `while let Some(x) = scheduler.claim(0)` loop, and it never
    // ended: `claim` on a CPU that already holds a task releases that task and
    // takes another, so the released one is claimable again on the next call
    // and the call after that takes it back.  The `Vec` grew until the kernel's
    // OOM killer ended the run, which read as "the build is too large for this
    // machine" through three separate attempts before the loop was found.
    //
    // So: one claim per CPU, in a loop bounded by the number of CPUs, and every
    // claim is checked rather than fed to another claim.
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
    // block does not run; on a machine that starts a second CPU it does, and it
    // is the assertion the whole two-CPU design rests on.
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
/// This is the property the old `Option` return could not express.  It used to
/// answer `Some` for this case by releasing the task the CPU held and taking a
/// new one, so a loop that claimed until it saw `None` never ended — its `Vec`
/// grew until the OOM killer stopped the run, three times, and the failure read
/// as a build too large for the machine.
///
/// The type is the fix: `Claim` has no `is_some`, so that loop cannot be
/// written without naming the case, and a caller that names it has to decide
/// what happens to the task it was holding.
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
    // And the refusal changed nothing: task 0 is still this CPU's, and task 1
    // is still free for a CPU that has nothing.
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
