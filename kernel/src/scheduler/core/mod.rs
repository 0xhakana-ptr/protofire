//! kernel/src/scheduler/core/mod.rs
//!
//! The scheduler's type, and the questions that read it.
//!
//! ## The files
//!
//! | File | What it holds |
//! |---|---|
//! | this file | what a scheduler is, construction, and "who is running" |
//! | [`switch`] | claiming a task, and installing the next one's context |
//! | [`wait`] | sleeping, blocking, and the wakes that end both |
//! | [`life`] | fork, and the release of a finished program's pages |
//!
//! The split follows the verb.  `switch` moves a CPU between tasks, `wait`
//! moves a task between states, and `life` covers the two events a task has
//! that are neither.  What is left here is the type all three name, plus the
//! read-only questions a trap asks — "who is this CPU running", "is anything
//! runnable" — which have no state to change and belong with the state they
//! read.
//!
//! ## One lock, one queue
//!
//! Every entry takes one global lock.  A task is not pinned to a CPU: nothing
//! says where it may run, so the lock is what keeps two CPUs from being handed
//! one task, and placement is whatever `claim` and `next_runnable` decide.  A
//! per-CPU queue would shard the contention and would not change what a task is
//! allowed to do; this kernel has no load to make that worth doing.
//!
//! A switch saves into the task **that** CPU held and marks the next one as
//! **that** CPU's.  That is what keeps two CPUs from being handed one task, and
//! it is why the entry points take `cpu` rather than reading a single field.

pub mod life;
pub mod switch;
pub mod wait;

use alloc::vec::Vec;

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
    /// How many times a task was placed on a CPU other than the one it last
    /// ran on.
    ///
    /// The scheduler does not balance load and does not decide to move a task:
    /// a task that left its CPU is simply selectable by any other, and this
    /// counts the times one was in fact taken elsewhere.  It is a measurement
    /// of what the placement rule does, not a policy of its own.
    pub(crate) migrations: usize,
    /// The most recent migration: the task index, the CPU it left, and the CPU
    /// it landed on.
    ///
    /// Kept so the boot can name one instead of only a count.  A total tells a
    /// reader that placement moved; the three numbers tell them what moved and
    /// which way, which is what a line a person reads needs.
    pub(crate) last_migration: Option<(usize, usize, usize)>,
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
            migrations: 0,
            last_migration: None,
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

    /// How many times a task was taken onto a CPU other than the one it last
    /// ran on, and the most recent one as `(task, from, to)`.
    pub fn migrations(&self) -> (usize, Option<(usize, usize, usize)>) {
        (self.migrations, self.last_migration)
    }

    /// The process id of a task index, for a line that names a task a reader
    /// can recognise.
    pub fn pid_at(&self, task: usize) -> Option<u32> {
        self.tasks.get(task).map(Task::pid)
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
    ///
    /// A task that arrives on a CPU other than the one it last ran on has
    /// **migrated**, and that is recorded rather than refused.  Nothing pins a
    /// task to a CPU here: the only binding is this array, and leaving it is
    /// what any switch does, so a task that was preempted or woken is free to
    /// be selected anywhere.  Writing `last_cpu` is what turns the placement
    /// into a fact a boot can report, and [`Self::migrations`] counts the
    /// times the two differed.
    pub fn assign(&mut self, cpu: usize, task: usize) {
        if let Some(slot) = self.running.get_mut(cpu) {
            // `usize::MAX` is this module's "this CPU owns no task".  Storing
            // it as an index would make `is_running_elsewhere` compare against
            // a task number no task has, which happens to be harmless and is
            // not the statement meant: `None` is.
            *slot = if task == usize::MAX { None } else { Some(task) };
        }
        if task != usize::MAX
            && let Some(entry) = self.tasks.get_mut(task)
        {
            if entry.last_cpu != usize::MAX && entry.last_cpu != cpu {
                self.migrations += 1;
                self.last_migration = Some((task, entry.last_cpu, cpu));
            }
            entry.last_cpu = cpu;
        }
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

    /// Whether a CPU other than `cpu` is running `task`.
    pub(super) fn is_running_elsewhere(&self, cpu: usize, task: usize) -> bool {
        self.running
            .iter()
            .enumerate()
            .any(|(index, held)| index != cpu && *held == Some(task))
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}
