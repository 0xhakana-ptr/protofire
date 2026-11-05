//! kernel/src/scheduler/core.rs
//!
//! The scheduler itself: the tasks, which one is running, and the one operation
//! a switch is made of.
//!
//! The trap path builds a frame, hands it to the call handler, and then
//! restores whatever frame it finds and returns.  So a task switch is: copy the
//! frame into the task this CPU was running, copy the next task's frame over
//! it, and, if the next task lives in a different address space, switch the
//! root register.  There is no assembly here, because the assembly that matters
//! is the epilogue every trap already runs through.
//!
//! `running` is one slot per CPU, and a switch is a CPU's own: it saves into
//! the task that CPU held and marks the next one as that CPU's.  That is what
//! keeps two CPUs from being handed one task, and it is why the entry points
//! here take `cpu` rather than reading a single field.  A caller that did not
//! say which CPU it was would be moving the whole machine's idea of the current
//! task, which is the state this scheduler had before it could run on two.

use alloc::vec::Vec;

use arch::CallOutcome;
use arch::Context;

use super::task::State;
use super::task::Task;

/// The tasks, and which one each CPU is running.
pub struct Scheduler {
    pub(crate) tasks: Vec<Task>,
    /// The task each CPU is running, by CPU slot.
    ///
    /// One index per CPU and not one index for the machine: with a single
    /// `current`, a second CPU's switch would overwrite the first's, and the
    /// task the first was running would be selected again by the other CPU.
    /// A task in this array is being run by that CPU and is not selectable by
    /// any other; leaving it is what a switch does, and it is why the array is
    /// the exclusion set rather than a separate flag.
    pub(crate) running: [Option<usize>; crate::per_cpu::MAX_CPUS],
    /// How many switches have happened, which the boot line reports.
    pub(crate) switches: usize,
    /// Programs that have exited.
    pub(crate) exited: usize,
    /// The next process id this scheduler will hand out.
    ///
    /// Above every id the boot gave, so a boot's programs and a forked child
    /// cannot collide: the boot numbers its programs 1..=n, and this starts at
    /// n+1 once the boot has added them.
    pub(crate) next_pid: u32,
}

/// What a claim answered.
///
/// Three states, and they are three because a caller has to act differently on
/// each: a task to run, a machine with no work, and a **mistake**.
///
/// The type was `Option<usize>`, and that type could not say "this CPU already
/// has a task".  The past implementation answered `Some` for that case by
/// silently releasing the old task and taking a new one, so a loop that claimed
/// until it saw `None` never terminated: it exhausted memory and the kernel's
/// own OOM killer ended the run, three times, before anyone looked inside the
/// loop.
///
/// With this type the same loop does not compile: `Claim` has no `is_some`, and
/// the pattern that would have to be written, `Claim::Took(_)`, makes a reader
/// ask what happens to the task the CPU was already holding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Claim {
    /// The CPU may run this task, and is now recorded as running it.
    Took(usize),
    /// No task in the machine can run.
    NothingToRun,
    /// This CPU already holds a task.  The caller is wrong, not the machine.
    AlreadyRunning,
}

impl Scheduler {
    pub fn new() -> Scheduler {
        Scheduler {
            tasks: Vec::new(),
            running: [None; crate::per_cpu::MAX_CPUS],
            switches: 0,
            exited: 0,
            next_pid: 1,
        }
    }

    /// Add a program to the rotation.
    ///
    /// A task is added free.  Which CPU runs it is decided by
    /// [`claim`](Self::claim), and the boot claims its own first task through
    /// the same call a started CPU uses: a default here would be a second
    /// answer to "who is running this", and the two would disagree the moment
    /// a second CPU took a task at start.
    pub fn add(&mut self, task: Task) {
        // The id counter follows the ids the boot actually gave, so a forked
        // child cannot collide with a program the boot started.
        if task.pid() >= self.next_pid {
            self.next_pid = task.pid() + 1;
        }
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

    pub fn switches(&self) -> usize {
        self.switches
    }

    pub fn exited(&self) -> usize {
        self.exited
    }

    /// The task `cpu` is running, while it is not finished.
    pub fn current(&self, cpu: usize) -> Option<&Task> {
        self.tasks
            .get(self.running.get(cpu).copied().flatten()?)
            .filter(|task| task.state != State::Finished)
    }

    /// The root the task `cpu` runs through, if it has one of its own.
    #[cfg(target_os = "none")]
    pub fn current_root(&self, cpu: usize) -> Option<usize> {
        self.current(cpu).and_then(Task::root)
    }

    /// Record that `cpu` is running `task`.
    ///
    /// What the entry into a program does: a CPU that installs a program's
    /// context by hand, rather than through a switch, has to say which task it
    /// took, or the other CPUs would consider that task free.
    pub fn assign(&mut self, cpu: usize, task: usize) {
        if let Some(slot) = self.running.get_mut(cpu) {
            // `usize::MAX` is this module's "this CPU owns no task".  Storing
            // it as an index would make `is_running_elsewhere` compare against
            // a task number no task has, which happens to be harmless and is
            // not the statement meant: `None` is.
            *slot = if task == usize::MAX { None } else { Some(task) };
        }
    }

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

    /// Whether a CPU other than `cpu` is running `task`.
    fn is_running_elsewhere(&self, cpu: usize, task: usize) -> bool {
        self.running
            .iter()
            .enumerate()
            .any(|(index, held)| index != cpu && *held == Some(task))
    }

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

    /// Fork the running task.
    ///
    /// Bare metal only: a host has no address space to copy, and a fork that
    /// answered a pid it could not give a space to would be a promise the
    /// machine cannot keep.
    ///
    /// The child is added to the end of the run queue, so a parent that forks
    /// gets its own answer before the child runs: a child that ran first would
    /// return zero before the parent had learned its pid, and a program that
    /// printed the two would show them in the wrong order.
    ///
    /// The frame is handed in rather than read from the task: the context a
    /// task holds is the one its last switch saved, from before
    /// the call that is running now.  A child resuming there would re-execute
    /// its parent's whole path from the last switch, including the `fork` that
    /// created it, and the boot showed exactly that: one fork became seven,
    /// each child forking in turn.
    ///
    /// The frame the trap path holds is the one that names the instruction
    /// **after** the call.  So that is what a child inherits, and the live
    /// frame is also where the parent's answer is written.
    #[cfg(target_os = "none")]
    pub fn fork_current(&mut self, cpu: usize, frame: &Context) -> Option<usize> {
        let parent = self.running.get(cpu).copied().flatten()?;
        let parent_pid = self.tasks.get(parent)?.pid();
        let parent_context = *frame;

        // The parent's space, copied.  A task with no space is one sharing the
        // kernel's, which a program never has: a fork of it would be a fork of
        // nothing.
        let parent_space = self.tasks.get(parent)?.space?;
        // SAFETY: the parent's space is live and this boot is the only writer.
        let child_space = unsafe { crate::address_space::fork_from(&parent_space) }?;

        let pid = self.next_pid;
        self.next_pid += 1;

        let mut child = Task::new("child", 0, 0, child_space);
        child.identify(pid, parent_pid);
        // The context, not a fresh one: the child resumes at the instruction
        // after its parent's `fork`, on the copied stack.
        *child.context_mut() = parent_context;
        // And the child's answer is zero, written into its own copy of the
        // frame.  The parent's register is untouched, so the same instruction
        // returns the pid in one process and zero in the other, which is the
        // whole of what `fork` answers.
        arch::set_return_value(child.context_mut(), 0);
        self.tasks.push(child);
        Some(pid as usize)
    }

    /// The running task's saved context, copied.
    pub fn current_context(&self, cpu: usize) -> Option<Context> {
        self.tasks
            .get(self.running.get(cpu).copied().flatten()?)
            .map(|task| *task.context())
    }

    /// The process id of the task that is running.
    pub fn current_pid(&self, cpu: usize) -> Option<u32> {
        self.tasks
            .get(self.running.get(cpu).copied().flatten()?)
            .map(Task::pid)
    }

    /// The parent of the task that is running.
    pub fn current_parent(&self, cpu: usize) -> Option<u32> {
        self.tasks
            .get(self.running.get(cpu).copied().flatten()?)
            .map(Task::parent)
    }

    /// The status a process exited with, if a task with that id exists.
    pub fn exit_status(&self, pid: u32) -> Option<Option<usize>> {
        self.tasks
            .iter()
            .find(|task| task.pid == pid)
            .map(Task::status)
    }

    /// Every task that exited with a status, in the order it was added.
    pub fn exited_with_status(&self) -> alloc::vec::Vec<(u32, usize)> {
        self.tasks
            .iter()
            .filter_map(|task| task.status.map(|status| (task.pid, status)))
            .collect()
    }

    /// The first task that has exited, in the order it was added.
    pub fn first_exited(&self) -> Option<&Task> {
        self.tasks.iter().find(|task| task.status.is_some())
    }

    /// Whether a task other than the current one can run.
    ///
    /// A preemption with only one program is a timer tick, not a switch: the
    /// frame would be replaced with the same task's context and the total would
    /// count ticks instead of switches.
    pub fn has_other_runnable(&self, cpu: usize) -> bool {
        let mine = self.running.get(cpu).copied().flatten();
        self.tasks.iter().enumerate().any(|(index, task)| {
            index != mine.unwrap_or(usize::MAX)
                && task.state == State::Runnable
                && !self.is_running_elsewhere(cpu, index)
        })
    }

    /// Whether any task can still run, or is waiting to.
    ///
    /// A sleeping task counts: it will run again, so the boot has work left and
    /// must not stop the machine.  Only `Finished` is the "nothing left"
    /// answer, which is why this is not the question a dispatcher asks, see
    /// [`Scheduler::has_selectable`].
    pub fn has_runnable(&self) -> bool {
        self.tasks.iter().any(|task| task.state != State::Finished)
    }

    /// Whether `cpu` holds a task it is running.
    ///
    /// The question a caller asks after a switch to tell the two `Exit`s
    /// apart: one where a next task was installed, and one where the CPU has
    /// nothing and must stop rather than resume a finished program.
    pub fn holds_a_task(&self, cpu: usize) -> bool {
        self.running
            .get(cpu)
            .copied()
            .flatten()
            .is_some_and(|index| {
                self.tasks
                    .get(index)
                    .is_some_and(|task| task.state != State::Finished)
            })
    }

    /// Whether any task could be selected right now.
    ///
    /// The question an idle loop asks, and deliberately different from
    /// [`Scheduler::has_runnable`]: a task that is asleep is still work the boot
    /// owes, and a task that is runnable is one the loop can stop waiting for.
    /// A loop written with `has_runnable` never waits at all, because sleeping
    /// tasks make it true, which is the defect the first version of the idle
    /// had.
    pub fn has_selectable(&self, cpu: usize) -> bool {
        self.tasks.iter().enumerate().any(|(index, task)| {
            task.state == State::Runnable && !self.is_running_elsewhere(cpu, index)
        })
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
    /// Called when nothing is translating through any of them, after the last
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
