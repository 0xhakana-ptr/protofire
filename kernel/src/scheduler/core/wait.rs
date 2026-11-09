//! kernel/src/scheduler/core/wait.rs
//!
//! The two ways a task stops being runnable, and the wakes that undo them.
//!
//! A sleep waits for the clock and a block waits for another task; the state a
//! task carries says which, and the difference is what ends the wait.  Folding
//! them together would mean inventing a deadline for a wait that has none.
//!
//! The frame is saved **here**, not by a later `schedule`.  A task that stops
//! must resume where it asked to, and the only copy of that position is the
//! trap frame the call arrived in.  Leaving the save to whichever scheduling
//! call happens next worked only while a call always happened: with every task
//! asleep the boot idles instead, and the task then woke at whatever position
//! its context last held.

use arch::Context;

use super::Scheduler;
use crate::scheduler::task::State;

impl Scheduler {
    /// Put the current task to sleep until the machine's counter reads `until`.
    ///
    /// It records a deadline and takes the current task out of the rotation.
    /// It does **not** switch: the caller is a call handler, and the frame it
    /// holds belongs to the program that just asked.  The switch happens when
    /// the handler answers `Exit`-shaped, which is what `process::serve` does
    /// for `Sleep`, and the scheduler then picks the next runnable task.
    ///
    /// A duration is what a program asks for and a deadline is what a scheduler
    /// compares.  Converting once, here, keeps every comparison in one clock:
    /// the machine's counter, whose rate the caller measured.
    pub fn sleep_until(&mut self, cpu: usize, until: u64, frame: &Context) {
        if let Some(index) = self.running.get(cpu).copied().flatten()
            && let Some(task) = self.tasks.get_mut(index)
        {
            // The frame is saved **here**, not by a later `schedule`.
            //
            // A task that sleeps must resume where it asked to, and the only
            // copy of that position is the trap frame the call arrived in.
            // Leaving the save to whichever scheduling call happens next worked
            // only while a call always happened: with every task asleep the
            // boot idles instead, and the task then woke at whatever position
            // its context last held, the first version resumed program 2 at
            // its `Sleep` every time, printing the same line forever.
            task.context = *frame;
            task.state = State::Sleeping { until };
        }
    }

    /// Wake every task whose deadline has passed, answering how many woke.
    ///
    /// Called from the timer's interrupt, before the scheduler is asked for the
    /// next task, a task that slept past its deadline is runnable *now*, and a
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
    pub fn block(&mut self, cpu: usize, frame: &Context) {
        if let Some(task) = self.running.get(cpu).copied().flatten()
            && let Some(task) = self.tasks.get_mut(task)
        {
            task.context = *frame;
            task.state = State::Blocked;
        }
    }

    /// Park the current task unless `recheck` answers its wait's question now.
    ///
    /// `Some(answer)` means the fact the task was about to wait for has already
    /// arrived: the task is left runnable and the answer comes back for the
    /// caller to hand the program.  `None` means the wait is real, and the task
    /// is parked here, frame and all, for a wake to end.
    ///
    /// The sequencing with [`Self::wake_blocked`] is the reason this exists.
    /// A caller that checks a fact, then parks, has a gap between the two, and
    /// on a machine with two CPUs the wake can fire inside it — the task then
    /// parks **after** the wake it was waiting for, and nothing will ever wake
    /// it.  The caller of this method holds the same lock
    /// [`Self::wake_blocked`]
    /// takes while `recheck` runs and the state is written, which leaves the
    /// wake and the park exactly two orders: the fact arrived first and the
    /// re-check sees it, or the task is in the blocked set before the wake
    /// looks.  The gap is gone, not narrowed.
    pub fn block_unless<T>(
        &mut self,
        cpu: usize,
        frame: &Context,
        recheck: impl FnOnce() -> Option<T>,
    ) -> Option<T> {
        let answer = recheck();
        if answer.is_none() {
            self.block(cpu, frame);
        }
        answer
    }

    /// Park the current task until a process exits, unless one already has.
    ///
    /// The wait `WaitProcess` makes, written with the same discipline as
    /// [`Self::block_unless`] and for the same reason: the caller's own check
    /// — has a process finished? — and the park have a gap, and on a machine
    /// with two CPUs a child's exit can fire inside it, waking a blocked set
    /// that does not hold the waiter yet.  The re-check reads the exit
    /// statuses under the same lock, so a child that died while the call was
    /// deciding to wait answers the call at once, and one that dies after
    /// finds the task in the blocked set.
    ///
    /// `Some(status)` is the first exit's status, and the caller hands it to
    /// the program; `None` is a parked task.
    pub fn block_unless_exit(&mut self, cpu: usize, frame: &Context) -> Option<usize> {
        let answer = self.first_exited().and_then(|task| task.status());
        if answer.is_none() {
            self.block(cpu, frame);
        }
        answer
    }

    /// Wake every blocked task, answering how many.
    ///
    /// Every blocked task wakes, because a wait queue would record *which*
    /// task waits on *which* object, and this kernel has one blocking object
    /// and one blocked task in the boot that proves it.  Waking all of them is
    /// the correct behaviour for a pipe's reader and a writer, and several
    /// readers on one pipe may all make progress; it is wrong for anything
    /// that needs one exact waiter.  The queue
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
}
