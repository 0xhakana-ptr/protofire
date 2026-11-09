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

    /// The next task `cpu` may run, wrapping and skipping the ones that cannot.
    ///
    /// A task another CPU is running may not be selected.  That is what
    /// `running` is for: without
    /// it, two CPUs asking for the next runnable task at the same moment would
    /// both be told the same one, and both would install its context.  The task
    /// one CPU holds is not a candidate for the other, and the pass that finds
    /// nothing answers `None`, which is the scheduler saying "this CPU has no
    /// work" rather than "the machine has none".
    fn next_runnable(&self, cpu: usize) -> Option<usize> {
        if self.tasks.is_empty() {
            return None;
        }
        let held = self
            .running
            .get(cpu)
            .copied()
            .flatten()
            .filter(|index| *index < self.tasks.len());
        // The round-robin order, and the starting point is what makes it a
        // rotation rather than a preference.  A CPU already running a task
        // starts at the one after it, so switching moves the CPU rather than
        // re-selecting what it already has; a CPU with nothing starts at zero,
        // which is where a CPU that has just come up looks first.
        //
        // Both passes cover every task, so a CPU whose only runnable task is
        // the one it holds comes back to it, which is what a preemption with
        // one task must do.
        let start = held.map(|index| index + 1).unwrap_or(0);
        for offset in 0..self.tasks.len() {
            let candidate = (start + offset) % self.tasks.len();
            if self.tasks[candidate].state == State::Runnable
                && !self.is_running_elsewhere(cpu, candidate)
            {
                return Some(candidate);
            }
        }
        None
    }
}
