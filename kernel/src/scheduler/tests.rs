//! kernel/src/scheduler/tests.rs
//!
//! The module's tests.
//!
//! A sibling file because the tests outgrew the module: a reader looking for
//! the mechanism should not scroll past them to find the end of it.

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
    // The host builds with one CPU slot, so the decisive block below, an
    // idle CPU refused a task another holds, is exercised here only as far
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
/// pins is the decision, an answer comes back and the task stays runnable,
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
/// into the task, the first attempt rewound the caller's own copy and left
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
/// answers "would a switch be a switch", and a sleeping child answers no
/// so a wait that asked it answered `NotFound` to a parent whose child had
/// only gone to sleep, turning a wait into an error.  The wait's question
/// is "could another task still finish", and a sleeper could.
#[test]
fn a_sleeping_task_is_a_reason_to_wait() {
    // The shape a wait actually has: this CPU runs the parent, and the only
    // other task, a child, is asleep.  Both predicates look at that
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
/// `Busy`, the two refusals a sender can act on.
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
/// The property is what makes a mask usable, a caller that blocks a
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
/// back, the mask the suspend found, not the one it was told to run
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
    // caller had, bit 10, goes back.
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

    // The first task's wait, the cpu slot that is not running anything
    // in this test, takes nothing: the ring belongs to pid 2.
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
/// excluded, it is unfinished by definition and cannot answer its own
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
/// directly because a host has one CPU slot, it cannot run two tasks to
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
/// the parked waiter here is not the cpu's current one, the state is the
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

    // The waiter parks, on a machine this is `block_unless_exit` parking
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

/// A fault handler is taken by the fault it answers, so a second fault kills
/// the program instead of re-entering it.
///
/// `install_exception_handler`'s doc comment states this contract: a handler
/// that faults is "withdrawn, so the second fault kills it instead of
/// looping".  The code read the handler and left it in place, so a handler
/// whose own address was unmapped re-entered for ever and a handler that
/// faulted inside itself recursed until the stack ran out, printing one
/// `handled its own fault` line per level.
///
/// The test reaches the field the fault path reads and clears, because the
/// machine's trap path is not present in a host build.  What is asserted is
/// the property that makes the contract true: the *first* read finds the
/// handler and the next one finds nothing.
#[test]
fn taking_a_fault_handler_leaves_none_behind() {
    let mut scheduler = Scheduler::new();
    scheduler.add(Task::without_space("handler"));
    scheduler.tasks[0].handler = Some(0x80_0000_1000);

    let first = scheduler.tasks[0].handler.take();
    assert_eq!(
        first,
        Some(0x80_0000_1000),
        "the first fault is the program's to answer"
    );
    assert_eq!(
        scheduler.tasks[0].handler, None,
        "and the second is not, which is the whole of the contract"
    );
    assert_eq!(
        scheduler.tasks[0].handler.take(),
        None,
        "so a second fault falls through to the death path"
    );
}

/// A handler the program installs *after* a fault is honoured again.
///
/// Taking the handler is not a one-way door: the call exists to arm one, and a
/// program that survived a fault through `ReturnFromException` may arm another
/// for a later one.  A version that latched "this program has faulted" would
/// pass the test above and break this one.
#[test]
fn a_handler_installed_after_a_fault_is_honoured() {
    let mut scheduler = Scheduler::new();
    scheduler.add(Task::without_space("handler"));
    scheduler.tasks[0].handler = Some(0x80_0000_1000);
    assert_eq!(scheduler.tasks[0].handler.take(), Some(0x80_0000_1000));

    scheduler.tasks[0].handler = Some(0x80_0000_2000);
    assert_eq!(
        scheduler.tasks[0].handler.take(),
        Some(0x80_0000_2000),
        "arming again after a fault is the program's decision"
    );
}
