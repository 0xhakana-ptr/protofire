//! kernel/src/scheduler/core.rs
//!
//! The scheduler itself: the tasks, which one is running, and the one operation
//! a switch is made of.
//!
//! ## How a switch happens
//!
//! The trap path builds a frame, hands it to the call handler, and then
//! restores whatever frame it finds and returns.  So a task switch is: copy the
//! current frame into the running task, copy the next task's frame over it, and
//! — if the next task lives in a different address space — switch the root
//! register. There is no assembly here, because the assembly that matters is
//! the epilogue every trap already runs through.

use alloc::vec::Vec;

use arch::CallOutcome;
use arch::Context;

use super::task::State;
use super::task::Task;

/// The tasks, and which one is running.
pub struct Scheduler {
    pub(crate) tasks: Vec<Task>,
    pub(crate) current: usize,
    /// How many switches have happened, which the boot line reports.
    pub(crate) switches: usize,
    /// Programs that have exited.
    pub(crate) exited: usize,
}

impl Scheduler {
    /// A scheduler with no tasks.
    pub fn new() -> Scheduler {
        Scheduler {
            tasks: Vec::new(),
            current: 0,
            switches: 0,
            exited: 0,
        }
    }

    /// Add a program to the rotation.
    pub fn add(&mut self, task: Task) {
        self.tasks.push(task);
    }

    /// The number of programs, for a boot line.
    pub fn len(&self) -> usize {
        self.tasks.len()
    }

    /// Whether there are no programs at all.
    pub fn is_empty(&self) -> bool {
        self.tasks.is_empty()
    }

    /// How many switches have happened.
    pub fn switches(&self) -> usize {
        self.switches
    }

    /// How many programs have exited.
    pub fn exited(&self) -> usize {
        self.exited
    }

    /// The task whose context is installed.
    pub fn current(&self) -> Option<&Task> {
        self.tasks
            .get(self.current)
            .filter(|task| task.state != State::Finished)
    }

    /// The root the current task runs through, if it has one of its own.
    #[cfg(target_os = "none")]
    pub fn current_root(&self) -> Option<usize> {
        self.current().and_then(Task::root)
    }

    /// Install the next task's context over `frame`.
    ///
    /// Answers what the caller should do with the trap path: `Exit` when
    /// `exiting` is set, `Return` with whatever the resumed task's `x0` holds
    /// otherwise.  Either way `frame` now describes the program that runs next,
    /// so the caller's epilogue resumes the right one.
    ///
    /// ## Why the frame is saved even when the task exits
    ///
    /// A finished task has nothing to resume, and saving its frame anyway costs
    /// one copy and removes a branch — the code that decides *whether* to save
    /// is the code that could get it wrong.  What is not done is selecting it
    /// again, which the `finished` flag prevents.
    pub fn schedule(&mut self, frame: &mut Context, exiting: bool) -> CallOutcome {
        self.schedule_from(frame, exiting, true)
    }

    /// Select the next task and install it, optionally saving `frame` first.
    ///
    /// ## Why `save` exists, and what it prevents
    ///
    /// `schedule`'s frame always belongs to the task that is leaving — it is
    /// the trap frame that task was suspended in.  A caller whose frame is a
    /// *kernel* frame has no such claim: the boot's idle loop runs on the
    /// kernel stack, and writing that frame into the sleeping task would put a
    /// kernel address where a program's `ELR` was.  The symptom is an
    /// instruction abort from ring 3 at an address inside the kernel, one boot
    /// in three, and the first version of the sleep path did exactly that.
    ///
    /// So the two callers say which they are.  A trap saves; an idle does not.
    pub(crate) fn schedule_from(
        &mut self,
        frame: &mut Context,
        exiting: bool,
        save: bool,
    ) -> CallOutcome {
        // Where the current task was, kept exactly.
        //
        // `exiting` is the *caller's* claim about what happened, and a sleeping
        // task is neither running nor finished — it was put to sleep before
        // this call, so its state is already `Sleeping` and this must not
        // overwrite it with `Finished`.  That is why the flag only ever sets
        // `Finished` and never the other way.
        if save && let Some(task) = self.tasks.get_mut(self.current) {
            task.context = *frame;
            if exiting {
                task.state = State::Finished;
                self.exited += 1;
            }
        }

        let Some(next) = self.next_runnable() else {
            // Nothing to install.  With every task finished the caller stops
            // the machine; with some asleep the caller waits for the tick that
            // wakes one.  The scheduler does not distinguish the two — that
            // decision belongs to whoever knows whether a timer is armed — so
            // it answers `Exit` and its context says which case it is.
            return CallOutcome::Exit;
        };

        self.current = next;
        self.switches += 1;

        if let Some(task) = self.tasks.get(self.current) {
            *frame = task.context;
        }

        #[cfg(target_os = "none")]
        if let Some(root) = self.current_root() {
            // A different address space: write `TTBR0_EL1` before the epilogue
            // runs, because that epilogue's first fetch is through it.  Every
            // root shares the kernel's entry 0, so this is safe from anywhere
            // in the kernel.
            //
            // SAFETY: the root is a live table this scheduler's own task owns,
            // and every root shares the kernel's entry 0 — which covers the
            // code performing the call.
            unsafe { arch::switch_address_space(root) };
        }

        if exiting {
            CallOutcome::Exit
        } else {
            CallOutcome::Return(arch::return_value(frame))
        }
    }

    /// The next task to run, wrapping and skipping the ones that cannot.
    fn next_runnable(&self) -> Option<usize> {
        if self.tasks.is_empty() {
            return None;
        }
        // One pass from the task after this one: that is the round-robin policy
        // and also the bound.  With every other task finished and this one not,
        // the pass comes back to it.
        for offset in 1..=self.tasks.len() {
            let candidate = (self.current + offset) % self.tasks.len();
            if self.tasks[candidate].state == State::Runnable {
                return Some(candidate);
            }
        }
        None
    }

    /// Put the current task to sleep until the machine's counter reads `until`.
    ///
    /// ## What this does, and what it deliberately does not
    ///
    /// It records a deadline and takes the current task out of the rotation.
    /// It does **not** switch: the caller is a call handler, and the frame it
    /// holds belongs to the program that just asked.  The switch happens when
    /// the handler answers `Exit`-shaped — which is what `process::serve` does
    /// for `Sleep` — and the scheduler then picks the next runnable task.
    ///
    /// ## Why the deadline is a counter reading
    ///
    /// A duration is what a program asks for and a deadline is what a scheduler
    /// compares.  Converting once, here, keeps every comparison in one clock:
    /// the machine's counter, whose rate the caller measured.
    pub fn sleep_until(&mut self, until: u64, frame: &Context) {
        if let Some(task) = self.tasks.get_mut(self.current) {
            // The frame is saved **here**, not by a later `schedule`.
            //
            // A task that sleeps must resume where it asked to, and the only
            // copy of that position is the trap frame the call arrived in.
            // Leaving the save to whichever scheduling call happens next worked
            // only while a call always happened: with every task asleep the
            // boot idles instead, and the task then woke at whatever position
            // its context last held — the first version resumed program 2 at
            // its `Sleep` every time, printing the same line forever.
            task.context = *frame;
            task.state = State::Sleeping { until };
        }
    }

    /// Wake every task whose deadline has passed, answering how many woke.
    ///
    /// Called from the timer's interrupt, before the scheduler is asked for the
    /// next task — a task that slept past its deadline is runnable *now*, and a
    /// pass that ran first would find nothing to do and stop the machine with
    /// work left.
    pub fn wake_expired(&mut self, now: u64) -> usize {
        let mut woken = 0;
        for task in &mut self.tasks {
            if let State::Sleeping { until } = task.state
                && now >= until
            {
                task.state = State::Runnable;
                woken += 1;
            }
        }
        woken
    }

    /// Park the current task until another task wakes it.
    ///
    /// The frame is saved here for the reason `sleep_until` gives: the position
    /// to resume at exists only in the trap frame the call arrived in, and a
    /// blocked task has no later scheduling call to rely on.
    pub fn block(&mut self, frame: &Context) {
        if let Some(task) = self.tasks.get_mut(self.current) {
            task.context = *frame;
            task.state = State::Blocked;
        }
    }

    /// Wake every blocked task, answering how many.
    ///
    /// ## Why this wakes all of them
    ///
    /// A wait queue would record *which* task waits on *which* object, and this
    /// kernel has one blocking object and one blocked task in the boot that
    /// proves it.  Waking all of them is the correct behaviour for a pipe's
    /// reader and a writer — several readers on one pipe may all make progress
    /// — and it is wrong for anything that needs one exact waiter.  The queue
    /// arrives with the second such object; until then a wake that names its
    /// waiters would be a queue with one entry and a lookup.
    pub fn wake_blocked(&mut self) -> usize {
        let mut woken = 0;
        for task in &mut self.tasks {
            if task.state == State::Blocked {
                task.state = State::Runnable;
                woken += 1;
            }
        }
        woken
    }

    /// How many tasks are blocked rather than asleep, runnable or finished.
    pub fn blocked(&self) -> usize {
        self.tasks
            .iter()
            .filter(|task| task.state == State::Blocked)
            .count()
    }

    /// How many tasks are asleep.
    pub fn sleeping(&self) -> usize {
        self.tasks
            .iter()
            .filter(|task| matches!(task.state, State::Sleeping { .. }))
            .count()
    }

    /// Whether a task other than the current one can run.
    ///
    /// A preemption with only one program is a timer tick, not a switch: the
    /// frame would be replaced with the same task's context and the total would
    /// count ticks instead of switches.
    pub fn has_other_runnable(&self) -> bool {
        self.tasks
            .iter()
            .enumerate()
            .any(|(index, task)| index != self.current && task.state == State::Runnable)
    }

    /// Whether any task can still run, or is waiting to.
    ///
    /// A sleeping task counts: it will run again, so the boot has work left and
    /// must not stop the machine.  Only `Finished` is the "nothing left"
    /// answer, which is why this is not the question a dispatcher asks — see
    /// [`Scheduler::has_selectable`].
    pub fn has_runnable(&self) -> bool {
        self.tasks.iter().any(|task| task.state != State::Finished)
    }

    /// Whether any task could be selected right now.
    ///
    /// The question an idle loop asks, and deliberately different from
    /// [`Scheduler::has_runnable`]: a task that is asleep is still work the boot
    /// owes, and a task that is runnable is one the loop can stop waiting for.
    /// A loop written with `has_runnable` never waits at all, because sleeping
    /// tasks make it true — which is the defect the first version of the idle
    /// had.
    pub fn has_selectable(&self) -> bool {
        self.tasks.iter().any(|task| task.state == State::Runnable)
    }

    /// Whether any task is asleep rather than runnable or finished.
    pub fn has_sleeping(&self) -> bool {
        self.tasks
            .iter()
            .any(|task| matches!(task.state, State::Sleeping { .. } | State::Blocked))
    }

    /// Release every finished program's pages.
    ///
    /// # Safety
    ///
    /// Called when nothing is translating through any of them — after the last
    /// program exited, with the kernel's own root installed.
    #[cfg(target_os = "none")]
    pub unsafe fn reap(&mut self) -> usize {
        let mut reaped = 0;
        for task in &mut self.tasks {
            if task.state == State::Finished
                && let Some(space) = task.space.take()
            {
                // SAFETY: the caller promises no task is translating through
                // this space.
                unsafe { space.release() };
                reaped += 1;
            }
        }
        reaped
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}
