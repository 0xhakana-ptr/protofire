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
