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
    ///
    /// ## The saved resume points back at the call
    ///
    /// A trap leaves `ELR_EL1` at the instruction **after** the `svc`, which
    /// is what an answered call wants: the handler wrote the answer and the
    /// program continues.  A **parked** call was not answered — its handler
    /// found the wait real and is leaving it for a wake — so resuming after
    /// the call would skip it, and the program would continue with whatever its
    /// answer register held from the call before.  The wake is what retries the
    /// call, and that is only true if the saved position is the call itself.
    ///
    /// This lives **here**, in the park, rather than at every caller: the
    /// rewind is part of what parking means, and a caller that had to remember
    /// it would be a caller that could forget.  The first attempt did put it at
    /// the callers and rewound the wrong copy — `task.context = *frame` had
    /// already copied the frame — so the saved position kept pointing past the
    /// call and the wait never resumed.
    pub fn block(&mut self, cpu: usize, frame: &Context) {
        if let Some(task) = self.running.get(cpu).copied().flatten()
            && let Some(task) = self.tasks.get_mut(task)
        {
            task.context = *frame;
            arch::restart_the_call(&mut task.context);
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

    /// Park the current task until the process `pid` exits, unless it has.
    ///
    /// `WaitProcessOf`'s park, with the same lock discipline as
    /// [`Self::block_unless_exit`]: the lookup and the park are one critical
    /// section, so a child's exit either happened before the lookup saw it or
    /// finds the waiter already in the blocked set.
    ///
    /// Answers a [`PidWait`], because the three outcomes are genuinely
    /// different and a caller that folded any two of them together would be
    /// wrong:
    ///
    /// - the process ended, with its status;
    /// - no task has that pid — a fact to report, not a reason to wait;
    /// - it exists and has not ended, which is the one case that parks.
    pub fn block_unless_pid(&mut self, cpu: usize, frame: &Context, pid: u32) -> PidWait {
        let answer = match self.exit_status(pid) {
            Some(Some(status)) => PidWait::Ended(status),
            Some(None) => PidWait::NotYet,
            None => PidWait::NoSuchProcess,
        };
        if matches!(answer, PidWait::NotYet) {
            self.block(cpu, frame);
        }
        answer
    }

    /// Queue a signal for `pid`, from `sender_pid`, and wake what waits.
    ///
    /// The target must exist — an unknown pid is `NotFound`, the answer a
    /// caller checks its own argument against — and a full ring is `Busy`,
    /// which is the target saying it is not consuming rather than the
    /// kernel losing what it was sent.  The wake is the pipe write's: the
    /// waiter retries under the wake, so a signal that arrives while the
    /// waiter is deciding to park finds the task in the blocked set.
    pub fn send_signal_to(
        &mut self,
        sender_pid: u32,
        pid: u32,
        signal: usize,
        payload: usize,
    ) -> Result<(), abi::Error> {
        let target = self
            .tasks
            .iter_mut()
            .find(|task| task.pid == pid)
            .ok_or(abi::Error::NotFound)?;
        // A signal with an installed handler, and unblocked, is **delivered**
        // rather than queued: the target's context is redirected at its next
        // install, which is the POSIX reading of "a handled signal does not
        // wait for a wait".  The delivery slot holds one; a second arrives
        // while the first is undelivered and queues beside it, because a
        // slot overwritten is a signal lost.
        let delivered = target.signal_mask & (1 << signal) == 0
            && target.signal_handler_for(signal).is_some()
            && {
                if target.delivery.is_none() {
                    target.delivery = Some(crate::scheduler::task::PendingSignal {
                        signal,
                        sender_pid,
                        payload,
                    });
                    true
                } else {
                    false
                }
            };
        if !delivered {
            target.queue_signal(signal, sender_pid, payload)?;
        }
        self.wake_blocked();
        Ok(())
    }

    /// Take this task's oldest pending signal, or park it until one arrives.
    ///
    /// The same discipline as [`Self::block_unless_exit`]: the caller's own
    /// check — is a signal here? — and the park have a gap, and a signal
    /// sent inside that gap wakes the blocked set, which is why the send
    /// wakes.  The record travels as the three fields the ABI's
    /// `ProcessSignalRecord` carries.
    pub fn wait_signal_current(
        &mut self,
        cpu: usize,
        frame: &Context,
    ) -> Option<(usize, u32, usize)> {
        let answer = self
            .running
            .get(cpu)
            .copied()
            .flatten()
            .and_then(|index| self.tasks.get_mut(index))
            .and_then(|task| task.take_signal())
            .map(|pending| (pending.signal, pending.sender_pid, pending.payload));
        if answer.is_none() {
            self.block(cpu, frame);
        }
        answer
    }

    /// Set the running task's signal mask, answering what it was.
    ///
    /// A mask bit is a signal's number: bit 10 blocks `SIGUSR1`.  The
    /// answer is the previous mask, which is what lets a caller put back
    /// what it found rather than what it assumed.
    pub fn set_signal_mask_current(&mut self, cpu: usize, mask: u32) -> u32 {
        let previous = self
            .running
            .get(cpu)
            .copied()
            .flatten()
            .and_then(|index| self.tasks.get(index))
            .map(|task| task.signal_mask)
            .unwrap_or(0);
        if let Some(index) = self.running.get(cpu).copied().flatten()
            && let Some(task) = self.tasks.get_mut(index)
        {
            task.signal_mask = mask;
        }
        previous
    }

    /// Run the calling task's ring under `mask`, and answer an unblocked
    /// signal with the mask put back.
    ///
    /// The park is the subtlety: the wake resumes the **call**, so the retry
    /// re-enters with the same argument and cannot know what the mask was
    /// before the first entry.  The task's own slot carries it — set on the
    /// first entry, taken on the answering path — which is what makes the
    /// restore survive a park.
    pub fn sigsuspend_current(
        &mut self,
        cpu: usize,
        frame: &Context,
        mask: u32,
    ) -> Option<(usize, u32, usize)> {
        let answer = self
            .running
            .get(cpu)
            .copied()
            .flatten()
            .and_then(|index| self.tasks.get_mut(index))
            .and_then(|task| {
                if task.suspend_restore.is_none() {
                    task.suspend_restore = Some(task.signal_mask);
                }
                task.signal_mask = mask;
                task.take_signal()
            });
        match answer {
            Some(pending) => {
                if let Some(index) = self.running.get(cpu).copied().flatten()
                    && let Some(task) = self.tasks.get_mut(index)
                {
                    task.signal_mask = task.suspend_restore.take().unwrap_or(task.signal_mask);
                }
                Some((pending.signal, pending.sender_pid, pending.payload))
            }
            None => {
                self.block(cpu, frame);
                None
            }
        }
    }

    /// Install or withdraw the running task's handler for one signal.
    ///
    /// The address is the program's own code, in its own space — the same
    /// trust an exception handler's install already extends, and the reason
    /// the address means nothing until the task's next install names it.
    pub fn set_signal_handler_current(
        &mut self,
        cpu: usize,
        signal: usize,
        action: usize,
        handler: usize,
    ) -> bool {
        let Some(index) = self.running.get(cpu).copied().flatten() else {
            return false;
        };
        let Some(task) = self.tasks.get_mut(index) else {
            return false;
        };
        if !abi::process::is_valid_process_signal(signal) {
            return false;
        }
        match action {
            0 => task.set_signal_handler(signal, None),
            1 if handler != 0 => task.set_signal_handler(signal, Some(handler)),
            _ => return false,
        }
        true
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

/// What a wait on one pid found.
///
/// Three outcomes rather than an `Option<Option<_>>`: the nested option has
/// the same three cases but nothing forces a caller to name them, and the
/// mistake it invites — treating "no such process" as "not yet" — is a wait
/// that parks for ever on a pid nothing will ever have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PidWait {
    /// The process ended, with the status it exited with.
    Ended(usize),
    /// It exists and has not ended: the caller parks, and its exit wakes.
    NotYet,
    /// No task has that pid.
    NoSuchProcess,
}
