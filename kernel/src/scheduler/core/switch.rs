//! kernel/src/scheduler/core/switch.rs
//!
//! Moving a CPU from the task it holds to the next one.
//!
//! A switch is: save the frame into the task this CPU was running, pick the
//! next task, copy its context over the frame, and write its root if it
//! differs. The frame is the trap path's, and the epilogue that restores it is
//! the assembly a switch is made of — there is none here, which is the point.
//!
//! Which CPU is the argument everywhere in this file.  A switch belongs to one
//! CPU: it saves into the task **that** CPU held and marks the next one as
//! **that** CPU's.  A file with one `current` would move the whole machine's
//! idea of what is running, which is the state this scheduler had before it
//! could run on two.

use arch::CallOutcome;
use arch::Context;

use super::Claim;
use super::Scheduler;
use crate::scheduler::task::State;
#[cfg(target_os = "none")]
use crate::scheduler::task::Task;

impl Scheduler {
    /// The next task a CPU that has just come up may run.
    ///
    /// `None` when nothing is runnable, which is the state a started CPU finds
    /// before the boot has built any task.  The task is marked as running on
    /// `cpu` here, so two CPUs claiming at once cannot take the same one.
    ///
    /// ## It replaces whatever the CPU was holding, silently
    ///
    /// There is no check for "this CPU already has a task".  The assignment is
    /// unconditional, so a CPU that held task A and calls this gets task B and
    /// A becomes claimable by anyone, including by this CPU on its next call,
    /// which would then take A back.  A loop that claimed until it got `None`
    /// never ends.
    ///
    /// Every caller is written for the other shape: the boot claims once, and a
    /// CPU claims only after giving its task up, through a switch or an exit.
    /// A caller that has to check first asks
    /// [`holds_a_task`](Self::holds_a_task).
    ///
    /// The hazard is worth this paragraph because the failure is silent:
    /// nothing about a repeated claim looks wrong until two CPUs are running
    /// one task.
    pub fn claim(&mut self, cpu: usize) -> Claim {
        // A CPU that already holds a task is refused, and the refusal is a
        // value rather than an overwrite.
        //
        // This is the whole of the fix for what the paragraph above describes.
        // Returning `None` here instead would be indistinguishable from "no
        // task is runnable", so a caller could not tell a mistake from an
        // empty machine, and the mistake is the one that produced an
        // `illegal instruction` on riscv64 and three out-of-memory kills here.
        if self.holds_a_task(cpu) {
            return Claim::AlreadyRunning;
        }
        let Some(next) = self.next_runnable(cpu) else {
            return Claim::NothingToRun;
        };
        self.assign(cpu, next);
        self.switches += 1;
        Claim::Took(next)
    }

    /// Install the next task's context over `frame`.
    ///
    /// Answers what the caller should do with the trap path: `Exit` when
    /// `exiting` is set, `Return` with whatever the resumed task's `x0` holds
    /// otherwise.  Either way `frame` now describes the program that runs next,
    /// so the caller's epilogue resumes the right one.
    ///
    /// The frame is saved even when the task exits: a finished task has
    /// nothing to resume, and saving its frame anyway costs one copy and
    /// removes a branch.  The code that decides *whether* to save is the code
    /// that could get it wrong.  What is not done is selecting it
    /// again, which the `finished` flag prevents.
    pub fn schedule(&mut self, cpu: usize, frame: &mut Context, exiting: bool) -> CallOutcome {
        self.schedule_from(cpu, frame, exiting, true)
    }

    /// Select the next task and install it, optionally saving `frame` first.
    ///
    /// The flag exists because a frame is not always the leaving task's.
    /// `schedule`'s frame always belongs to the task that is leaving: the
    /// trap frame that task was suspended in.  A caller whose frame is a
    /// *kernel* frame has no such claim: the boot's idle loop runs on the
    /// kernel stack, and writing that frame into the sleeping task would put a
    /// kernel address where a program's `ELR` was.  The symptom is an
    /// instruction abort from ring 3 at an address inside the kernel, one boot
    /// in three, and the first version of the sleep path did exactly that.
    ///
    /// So the two callers say which they are.  A trap saves; an idle does not.
    pub(crate) fn schedule_from(
        &mut self,
        cpu: usize,
        frame: &mut Context,
        exiting: bool,
        save: bool,
    ) -> CallOutcome {
        self.schedule_with_status(cpu, frame, exiting, save, None)
    }

    /// The same, for the CPU that is asking.
    ///
    /// Every switch belongs to a CPU: which task it was running is where the
    /// frame is saved, and which task it will run is what the other CPUs must
    /// not select.
    pub(crate) fn schedule_on(
        &mut self,
        cpu: usize,
        frame: &mut Context,
        exiting: bool,
        save: bool,
        status: Option<usize>,
    ) -> CallOutcome {
        // Where this CPU's task was, kept exactly.
        //
        // `exiting` is the *caller's* claim about what happened, and a sleeping
        // task is neither running nor finished, it was put to sleep before
        // this call, so its state is already `Sleeping` and this must not
        // overwrite it with `Finished`.  That is why the flag only ever sets
        // `Finished` and never the other way.
        let leaving = self.running.get(cpu).copied().flatten();
        if save
            && let Some(index) = leaving
            && let Some(task) = self.tasks.get_mut(index)
        {
            task.context = *frame;
            if exiting {
                task.state = State::Finished;
                // What the program answered `Exit` with.  The status
                // travels as `Exit`'s first argument (`edi` on x86_64,
                // `a0`/`x0` on the others), which is **not** always the
                // register a call's answer comes back in, x86_64's `rax`
                // holds `GetPid`'s answer, and `edi` holds the status.  So
                // the scheduler is told the status rather than reading a
                // register: a machine-specific guess here would be wrong on
                // exactly the machine whose convention differs.
                task.status = status;
                self.exited += 1;
                // A waiter's question just answered itself: a process
                // finished, and the wait parks on exactly that.  Wake what a
                // pipe's write wakes — every blocked task — and let the
                // woken caller retry its own check, which is what makes a
                // spurious wake cost a retry instead of a hang.  A wake that
                // never fires leaves the waiter parked beside the exit it
                // was waiting for.
                self.wake_blocked();
                // **The exit is an event, and the wait parked on it may be on
                // another CPU.**  A blocked task's state change is a memory
                // write, and `wfe` does not return for one: the parked core is
                // woken by `sev`, which is what `send_ipi_to_others` issues
                // beside its SGI.  Without this a parent parked in
                // `WaitProcessOf` stays parked beside a child that has already
                // exited — the boot's log stops at `a program waits for
                // process N`, and the machine sits there.
                //
                // Unconditional, not "when a task was woken": the wake that
                // matters may have been consumed by a `block_unless_pid`
                // re-check that ran before this exit was recorded, in which
                // case nothing was blocked at this instant and the waiter is
                // about to park.  Sending on every exit costs one interrupt per
                // program that ends, and a program that ends is not a hot path.
                #[cfg(target_os = "none")]
                // SAFETY: the boot's own inter-CPU line, installed before any
                // program ran.
                unsafe {
                    arch::send_ipi_to_others()
                };
            }
        }

        let Some(next) = self.next_runnable(cpu) else {
            // Nothing to install.  With every task finished the caller stops
            // the machine; with some asleep the caller waits for the tick that
            // wakes one.  The scheduler does not distinguish the two, that
            // decision belongs to whoever knows whether a timer is armed, so
            // it answers `Exit` and its context says which case it is.
            //
            // **This CPU owns nothing now.**  Clearing the slot is not
            // bookkeeping: a CPU that kept pointing at a task it had parked
            // would make `is_running_elsewhere` hide that task from every other
            // CPU, and a task woken from sleep would then be run by nobody,
            // or worse by this CPU *and* another, because the slot also says
            // which task this CPU's frame belongs to.
            self.assign(cpu, usize::MAX);
            return CallOutcome::Exit;
        };

        self.assign(cpu, next);
        self.switches += 1;

        if let Some(task) = self.tasks.get(next) {
            *frame = task.context;
        }

        // A delivered signal, taken at the one moment it is safe to take it:
        // the frame this epilogue is about to resume is copied from the task,
        // the task is not running anywhere else, and the redirection below
        // touches registers the program has not yet read.  Before the
        // install, the target may have been mid-flight on another CPU; after
        // it, the registers are the program's again.
        //
        self.deliver_pending(next, frame);

        // The frame and the root go together, and both are `next`'s.
        //
        // Reading the root from `next` rather than back from `running[cpu]`
        // makes the pair one fact instead of two that agree by arrangement:
        // `assign` and the read happen with no call between them today, and a
        // later change to `assign` would break that without breaking a test.
        //
        // The write must happen **before the epilogue runs**, because that
        // epilogue's first fetch is through the new root.  Every root shares
        // the kernel's entry 0, so it is safe from anywhere in the kernel, and
        // the register is this CPU's own.
        #[cfg(target_os = "none")]
        if let Some(root) = self.tasks.get(next).and_then(Task::root) {
            // SAFETY: the root is a live table this scheduler's own task owns,
            // and every root shares the kernel's entry 0, which covers the code
            // performing the call.
            unsafe { arch::switch_address_space(root) };
        }

        if exiting {
            CallOutcome::Exit
        } else {
            CallOutcome::Return(arch::return_value(frame))
        }
    }

    /// The same, for the CPU that is asking.
    ///
    /// *Which* CPU is the argument: a switch saves the frame into the task that
    /// CPU was running and marks the next one as that CPU's, so two CPUs
    /// switching at once cannot take the same task.
    pub(crate) fn schedule_with_status(
        &mut self,
        cpu: usize,
        frame: &mut Context,
        exiting: bool,
        save: bool,
        status: Option<usize>,
    ) -> CallOutcome {
        self.schedule_on(cpu, frame, exiting, save, status)
    }

    /// The next task `cpu` may run, by the placement rule.
    ///
    /// A task another CPU is running may not be selected.  That is what
    /// `running` is for: without it, two CPUs asking for the next runnable task
    /// at the same moment would both be told the same one, and both would
    /// install its context.
    ///
    /// ## The rule, in three passes
    ///
    /// The first version was one pass over everything runnable, in rotation
    /// order, with no preference at all.  That is a scheduler whose placement
    /// is decided by whichever task happens to sit after the current one in an
    /// array, and its cost was visible in every boot: `task migrations 6` on a
    /// two-program rotation, because the task a CPU had just preempted was as
    /// likely to be taken by the *other* CPU as by the one that left it.  A
    /// migration is not free — each machine's address-space switch is a whole
    /// TLB flush — so a rule that moves work for no reason is a rule that pays
    /// for every switch.
    ///
    /// So the pass is by preference, and each step exists for a reason a boot
    /// showed:
    ///
    /// 1. **The task this CPU last ran.**  It is warm: its root is the one the
    ///    CPU switched away from, and its pages are the ones that CPU's TLB
    ///    held.  Taking it back is the placement that costs nothing.
    /// 2. **A task that has never run.**  A fresh task has no history to keep
    ///    and every CPU is equally cold to it, so it goes to whichever CPU is
    ///    asking, which spreads the load the way a boot with more work than
    ///    CPUs wants.
    /// 3. **Anything else runnable**, in rotation order — the task CPU 1 ran
    ///    and CPU 0 is now free to take.  This is the **steal**, and it is last
    ///    because it is the only step that makes a migration.
    ///
    /// The rotation's starting point is kept for step 3 only: a CPU with
    /// somewhere warm to go does not care what comes after it in the array, and
    /// a CPU that has to steal reads the array in rotation so no task before it
    /// is starved.
    ///
    /// Deliver the task's pending signal into the frame about to be resumed,
    /// answering whether one was.
    ///
    /// The record travels in the **argument registers** — signal, sender,
    /// payload, and the fourth is where the program was — because the handler
    /// is the program's own `extern "C"` code and reads them the ABI names.
    /// A machine whose answer register is not its first argument register
    /// would otherwise hand a Rust handler its signal in a register the
    /// prologue never reads, which is measured: the shell's handler on
    /// x86_64 spun forever on a check against a register the record never
    /// reached.
    pub(crate) fn deliver_pending(&mut self, index: usize, frame: &mut Context) -> bool {
        let Some(delivery) = self
            .tasks
            .get_mut(index)
            .and_then(|task| task.take_delivery())
        else {
            return false;
        };
        // The displaced **context** goes into the task, for the `SigReturn`
        // the handler ends with: the delivery is transparent or it is a
        // corruption, and the difference is the whole of this frame.
        if let Some(task) = self.tasks.get_mut(index) {
            task.delivery_saved = Some(*frame);
        }
        let resume = arch::resume_address(frame);
        arch::set_argument(frame, 0, delivery.signal);
        arch::set_argument(frame, 1, delivery.sender_pid as usize);
        arch::set_argument(frame, 2, delivery.payload);
        arch::set_argument(frame, 3, resume);
        if let Some(handler) = self
            .tasks
            .get(index)
            .and_then(|task| task.signal_handler_for(delivery.signal))
        {
            arch::set_resume_address(frame, handler);
        }
        self.delivered_signals += 1;
        true
    }

    /// Both scans cover every task, so a CPU whose only runnable task is the
    /// one it holds comes back to it, which is what a preemption with one task
    /// must do.
    fn next_runnable(&mut self, cpu: usize) -> Option<usize> {
        if self.tasks.is_empty() {
            return None;
        }
        let held = self
            .running
            .get(cpu)
            .copied()
            .flatten()
            .filter(|index| *index < self.tasks.len());
        let start = held.map(|index| index + 1).unwrap_or(0);

        // Two scans of the same rotation, and the difference between them is
        // the whole placement rule.
        //
        // **First**: a task this CPU running it would not move.  That is one it
        // last ran — warm in this CPU's TLB and, on every machine here, already
        // the root its address-space register named — or one no CPU has run,
        // which has no home to lose.  The rotation order is kept inside the
        // scan, so fairness between the tasks that qualify is unchanged.
        //
        // **Second**: anything runnable, which is the **steal**.  It is a
        // migration whenever the task last ran on another CPU, and it is only
        // reached when the first scan found nothing — every runnable task
        // belongs to somebody else, and this CPU would otherwise sit idle with
        // work in the queue.
        //
        // The first version had only the second scan.  Its placement was
        // whichever task happened to follow the current one in an array, so the
        // task a CPU had just preempted was as likely to be taken by the other
        // CPU as by the one that left it: `task migrations 6` on every two-CPU
        // boot, and each of those is a whole-TLB flush on every machine here.
        for scanning_for_a_steal in [false, true] {
            for offset in 0..self.tasks.len() {
                let candidate = (start + offset) % self.tasks.len();
                let task = &self.tasks[candidate];
                if task.state != State::Runnable || self.is_running_elsewhere(cpu, candidate) {
                    continue;
                }
                let settles = task.last_cpu == cpu || task.last_cpu == usize::MAX;
                if !scanning_for_a_steal && !settles {
                    continue;
                }
                if settles && task.last_cpu == cpu {
                    self.note_homed(candidate, cpu);
                }
                return Some(candidate);
            }
        }
        None
    }

    /// Record that `task` was placed on the CPU it last ran on.
    ///
    /// One place that writes the count, so no arm can add a placement without
    /// its record.  A first run is not a homecoming: `last_cpu` is
    /// `usize::MAX`, and a task placed where it has never been has no warmth to
    /// keep.
    fn note_homed(&mut self, task: usize, cpu: usize) {
        self.homed += 1;
        self.last_homed = Some((task, cpu));
    }

    /// How many tasks were placed back on the CPU they last ran on, and the
    /// most recent as `(task, cpu)`.
    ///
    /// The counterpart of [`migrations`](Self::migrations): the two partition
    /// the placements, and a boot whose `homed` is zero placed every task
    /// somewhere new.
    pub fn placings_home(&self) -> (usize, Option<(usize, usize)>) {
        (self.homed, self.last_homed)
    }
}

#[cfg(test)]
mod tests {
    //! The placement rule's tests.
    //!
    //! The rule decides **which** CPU runs a task, and the property that makes
    //! it worth having is the one its first version lacked: a task a CPU has
    //! run is offered back to that CPU before it is offered to another.  These
    //! tests name the three arms — warm, fresh, steal — because a rule that
    //! preferred one of them and forgot another is a rule that either pins work
    //! or moves every task on every switch.

    use crate::scheduler::Task;
    use crate::scheduler::core::Scheduler;

    /// A task a CPU has run is taken back by that CPU rather than by another.
    ///
    /// The rule this test pins is the whole of the placement change: a pass
    /// with no preference takes whichever runnable task the rotation reaches
    /// first, and on a two-CPU boot that was as often the other CPU's task as
    /// this one's — `task migrations 6` on a rotation of two programs, and each
    /// of those is a whole-TLB flush.  The property here is narrower than the
    /// boot's and exactly the one the code decides: with one warm task and one
    /// fresh one runnable, the CPU that last ran the warm one gets it.
    ///
    /// The fresh task is placed first because the rule prefers a task with no
    /// home as strongly as it prefers a warm one — both are placements that do
    /// not move work — so the two are separated by rotation order and not by
    /// preference.  What the test asserts is the thing that is *not* ordered:
    /// the warm task never goes to the wrong CPU.
    #[test]
    fn a_cpu_takes_back_the_task_it_last_ran() {
        let mut scheduler = Scheduler::new();
        // A test build describes one CPU, so `assign` can name only slot zero;
        // the second CPU's placement is reached by writing the task's record
        // the way a switch on that CPU would have.  A host that starts no core
        // still holds the state the rule is decided on.
        scheduler.add(Task::without_space("warm"));
        scheduler.add(Task::without_space("fresh"));
        // "warm" last ran on slot 1, which is not this build's only CPU.
        scheduler.tasks[0].last_cpu = 1;
        // "fresh" has run nowhere: `without_space` leaves it `usize::MAX`.

        // The CPU asking is slot 1, which the host cannot place through
        // `claim`; `assign` writes the record directly, which is what a switch
        // on that CPU would have done.
        scheduler.assign(1, usize::MAX);
        let chosen = scheduler.next_runnable(1).expect("two tasks are runnable");
        assert_eq!(
            chosen, 0,
            "the CPU took the fresh task instead of the one it last ran"
        );
    }

    /// A task no CPU has run is preferred over a migration.
    ///
    /// The other half of the same rule, and it is a separate test because it
    /// can fail independently: preferring warmth alone would send a fresh task
    /// to whichever CPU the rotation reached, which is the same migration the
    /// rule exists to avoid when both candidates have homes.
    #[test]
    fn a_fresh_task_is_placed_before_a_task_another_cpu_ran() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("theirs"));
        scheduler.add(Task::without_space("fresh"));
        // "theirs" ran on another CPU; "fresh" has run nowhere.
        scheduler.tasks[0].last_cpu = 1;
        scheduler.tasks[1].last_cpu = usize::MAX;
        scheduler.assign(0, usize::MAX);

        let chosen = scheduler.next_runnable(0).expect("two tasks are runnable");
        assert_eq!(
            chosen, 1,
            "the CPU took another CPU's task while a fresh one was free"
        );
    }

    /// A CPU with nothing else to do steals, rather than sitting idle.
    ///
    /// The rule's last resort, and the one that keeps "prefer warmth" from
    /// becoming "pin every task to its first CPU": when every runnable task
    /// belongs to another CPU, this one takes one anyway.  A rule that refused
    /// would leave a CPU idle with work in the queue, which is the defect the
    /// balance is for.
    #[test]
    fn a_cpu_steals_when_nothing_is_free() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("theirs"));
        scheduler.tasks[0].last_cpu = 1;
        scheduler.assign(0, usize::MAX);

        let chosen = scheduler.next_runnable(0).expect("the task is runnable");
        assert_eq!(chosen, 0, "an idle CPU refused the only runnable task");
    }

    /// A placement that took a task back is recorded, and a steal is not.
    ///
    /// The boot's new line is only worth requiring if it means something: the
    /// count rises on the placement the rule prefers and stays put on the one
    /// it avoids.  A counter that recorded every placement would be a second
    /// switch count and say nothing about placement.
    #[test]
    fn taking_a_task_back_is_counted_and_a_steal_is_not() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("mine"));
        scheduler.add(Task::without_space("theirs"));
        scheduler.tasks[0].last_cpu = 1;
        scheduler.tasks[1].last_cpu = 1;

        // The CPU that last ran task 0 takes it back.
        scheduler.assign(1, usize::MAX);
        assert_eq!(scheduler.next_runnable(1), Some(0));
        let (count, last) = scheduler.placings_home();
        assert_eq!(count, 1, "the homecoming was not counted");
        assert_eq!(last, Some((0, 1)));

        // CPU 0 has only another CPU's tasks to take, so its placement is a
        // steal and the home count does not move — whichever of the two the
        // rotation reaches, both last ran on CPU 1 and neither is CPU 0's.
        scheduler.assign(0, usize::MAX);
        let stolen = scheduler.next_runnable(0).expect("a task is runnable");
        assert_ne!(
            scheduler.tasks[stolen].last_cpu, 0,
            "cpu 0 was given a task it had run, which is not a steal"
        );
        assert_eq!(
            scheduler.placings_home().0,
            1,
            "a steal was counted as a homecoming"
        );
    }
}
