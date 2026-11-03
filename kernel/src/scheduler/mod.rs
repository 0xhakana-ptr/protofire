//! kernel/src/scheduler/mod.rs
//!
//! Two programs, taking turns.
//!
//! ## What a task is here
//!
//! A saved [`Context`] — the whole 800-byte trap frame — and the address space
//! it runs in.  There is no kernel stack per task, because a task never has one
//! of its own to be suspended on: a program runs at EL0, so the only time it is
//! inside the kernel is inside a trap, and the trap path's frame *is* its saved
//! state.
//!
//! ## How a switch happens
//!
//! The trap path builds a frame, hands it to the call handler, and then
//! restores whatever frame it finds and `eret`s.  So a task switch is:
//!
//! 1. copy the current frame into the running task — it is suspended exactly
//!    where the machine left it;
//! 2. copy the next task's frame over it;
//! 3. if the next task lives in a different address space, write `TTBR0_EL1`.
//!
//! Steps 1 and 2 are two copies and step 3 is one system register.  There is no
//! assembly here, because the assembly that matters is the epilogue every trap
//! already runs through.
//!
//! ## Why round-robin and nothing else
//!
//! A real scheduler decides by priority, by how long a task has run, and by
//! what it is waiting for.  Those are decisions about *when* to switch, and
//! this kernel switches at exactly one moment: a program made a call.
//! Preemption — switching a program that did not ask — needs a timer, and the
//! timer is not programmed.  So the policy is "the next one", and saying so is
//! more useful than a weight table that decides nothing.

use alloc::vec::Vec;

use arch::CallFrame;
use arch::CallOutcome;
use arch::Context;

#[cfg(target_os = "none")]
use crate::address_space::AddressSpace;

/// The address space a task runs in.
///
/// A program's pages are a bare-metal structure: a root table is a frame and a
/// frame is a physical address, neither of which a host has.  So on a host the
/// type is empty and every operation on it is absent — which is why the
/// scheduler's tests exercise the *rotation* and not the switching.  Pretending
/// a host had address spaces would be testing a fiction.
#[cfg(not(target_os = "none"))]
#[derive(Debug, Clone, Copy)]
pub struct AddressSpace;

/// One program the scheduler can run.
pub struct Task {
    /// Its name, for a boot line that reports what ran.
    pub name: &'static str,
    /// Where it is in its execution: everything the epilogue restores.
    context: Context,
    /// The pages it can reach, or `None` for a task sharing the kernel's own.
    space: Option<AddressSpace>,
    /// Whether it has finished.
    finished: bool,
}

impl Task {
    /// A task that starts at `entry`, with its stack at `stack_top`, in
    /// `space`.
    #[cfg(target_os = "none")]
    pub fn new(name: &'static str, entry: usize, stack_top: usize, space: AddressSpace) -> Task {
        Task {
            name,
            context: starting_context(entry, stack_top),
            space: Some(space),
            finished: false,
        }
    }

    /// A task that shares the kernel's address space.
    ///
    /// For a test, and for a machine whose `enter_user` has no path: a task
    /// with no pages is one that would fault the moment it ran, so this exists
    /// to exercise the rotation and nothing else.
    pub fn without_space(name: &'static str) -> Task {
        Task {
            name,
            context: starting_context(0, 0),
            space: None,
            finished: false,
        }
    }

    /// The address space's root, which is what a switch writes.
    #[cfg(target_os = "none")]
    pub fn root(&self) -> Option<usize> {
        self.space.as_ref().map(AddressSpace::root)
    }

    /// A host has no root to switch to, but it does hold the space.
    ///
    /// Reading the field rather than returning a bare `None` keeps the host
    /// build honest about the type: a task on a host *has* no address space,
    /// and the check that says so is this one touching the field it would use.
    #[cfg(not(target_os = "none"))]
    pub fn root(&self) -> Option<usize> {
        self.space.map(|_| None).unwrap_or(None)
    }

    /// The context a switch installs.
    pub fn context(&self) -> &Context {
        &self.context
    }

    /// The context a switch installs, for a caller replacing it.
    pub fn context_mut(&mut self) -> &mut Context {
        &mut self.context
    }
}

/// The context a program begins with.
///
/// Every register zero except the two that decide where it runs: `ELR_EL1`
/// names the entry and `SPSR_EL1` names EL0t.  A program that started with a
/// kernel value in a register would be one whose first instruction ran on it.
pub fn starting_context(entry: usize, stack_top: usize) -> Context {
    let mut context = Context {
        registers: [0; 30],
        link_register: 0,
        elr: entry as u64,
        spsr: 0x340,
        esr: 0,
        far: 0,
        vector: 0,
        simd: [0; 32],
    };
    // `SP_EL0` is not in the frame — the assembly does not save it, because a
    // trap never changes it.  So the stack pointer travels in `x0` and the
    // install path writes it to `SP_EL0` before the `eret`.
    context.registers[0] = stack_top as u64;
    context
}

/// The tasks, and which one is running.
pub struct Scheduler {
    tasks: Vec<Task>,
    current: usize,
    /// How many switches have happened, which the boot line reports.
    switches: usize,
    /// Programs that have exited.
    exited: usize,
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
        self.tasks.get(self.current).filter(|task| !task.finished)
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
        // Where the current task was, kept exactly.
        if let Some(task) = self.tasks.get_mut(self.current) {
            task.context = *frame;
            if exiting {
                task.finished = true;
                self.exited += 1;
            }
        }

        let Some(next) = self.next_runnable() else {
            // Nothing left.  The frame still holds the caller's task, and the
            // trap path would `eret` into a program that just asked to exit —
            // so the answer says so and the caller stops the machine.
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
            CallOutcome::Return(frame.registers[0] as usize)
        }
    }

    /// The next task to run, wrapping and skipping finished ones.
    fn next_runnable(&self) -> Option<usize> {
        if self.tasks.is_empty() {
            return None;
        }
        // One pass from the task after this one: that is the round-robin policy
        // and also the bound.  With every other task finished and this one not,
        // the pass comes back to it.
        for offset in 1..=self.tasks.len() {
            let candidate = (self.current + offset) % self.tasks.len();
            if !self.tasks[candidate].finished {
                return Some(candidate);
            }
        }
        None
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
            .any(|(index, task)| index != self.current && !task.finished)
    }

    /// Whether any task is still runnable.
    pub fn has_runnable(&self) -> bool {
        self.tasks.iter().any(|task| !task.finished)
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
            if task.finished
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

/// The scheduler the boot installed.
///
/// A `static` for the same reason the syscall registry is one: a supervisor
/// call arrives from a trap with no context to be handed anything, so the table
/// it needs has to be reachable without one.
static SCHEDULER: cell::SyncUnsafeCell<Option<Scheduler>> = cell::SyncUnsafeCell::new(None);

/// Install the scheduler the boot built.
///
/// # Safety
///
/// Called once, before any program runs.
pub unsafe fn install(scheduler: Scheduler) {
    // SAFETY: the caller promises this is the only write and that it happens
    // before EL0 is entered.
    unsafe { *SCHEDULER.get() = Some(scheduler) };
}

/// Save the current task, install the next one's context, and answer.
///
/// `None` runs when the boot never installed a scheduler, which is the state a
/// host build is in.
pub fn advance(frame: &mut arch::Context, exiting: bool) -> arch::CallOutcome {
    // SAFETY: the scheduler is written once before any program runs, and this
    // read happens after that.
    let scheduler = unsafe { (*SCHEDULER.get()).as_mut() };
    match scheduler {
        Some(scheduler) => scheduler.schedule(frame, exiting),
        None => arch::CallOutcome::Exit,
    }
}

/// How many switches and exits the installed scheduler has seen.
///
/// `(switches, exited)`, or `(0, 0)` when nothing ran.
pub fn statistics() -> (usize, usize) {
    // SAFETY: as `advance`.
    let scheduler = unsafe { (*SCHEDULER.get()).as_ref() };
    scheduler.map_or((0, 0), |scheduler| {
        (scheduler.switches(), scheduler.exited())
    })
}

/// The root the first task runs through.
///
/// Read out of the static because the boot installs the scheduler and then
/// enters a program: the value it built is gone by then, and the entry into EL0
/// has to translate through the first task's root rather than the kernel's.
#[cfg(target_os = "none")]
pub fn first_root() -> Option<usize> {
    // SAFETY: as `advance`.
    let scheduler = unsafe { (*SCHEDULER.get()).as_ref() };
    scheduler.and_then(|scheduler| scheduler.current_root())
}

/// Whether a scheduler is installed and still has work.
pub fn has_runnable() -> bool {
    // SAFETY: as `advance`.
    let scheduler = unsafe { (*SCHEDULER.get()).as_ref() };
    scheduler.is_some_and(Scheduler::has_runnable)
}

/// Preempt: put the next task's context in `frame` and switch to its space.
///
/// ## Why this is different from `advance`
///
/// `advance` answers a call: the frame it is given belongs to a task that asked
/// for something, and the caller does something with the answer.  This is
/// called from an interrupt, where the frame belongs to whatever the program
/// was doing — so there is no call, no answer, and nothing to report to anyone.
/// The only thing that matters is that the frame the epilogue restores is the
/// next task's.
///
/// ## Why it does not count a switch when nothing else can run
///
/// A timer that fires in a system with one runnable task is a timer, not a
/// switch.  Counting it would make the boot's switch total depend on how long
/// the program ran, and the number would stop describing the scheduler.
pub fn preempt(frame: &mut arch::Context) {
    // Only from a program.
    //
    // A timer fires at EL1 as well as at EL0 — the kernel's own boot code takes
    // ticks, and its saved context is a kernel one.  Installing a program's
    // context over it would resume a ring-3 program from inside a kernel stack
    // that nothing will ever unwind, and the boot stops mid-line: the first run
    // of this printed `program 1 mappe` and nothing more.
    //
    // `SPSR_EL1`'s low bits name the exception level the frame returns to; a
    // kernel frame's are not EL0t.
    if frame.spsr & 0b1111 != 0 {
        return;
    }

    // SAFETY: the scheduler is written once before any program runs.
    let scheduler = unsafe { (*SCHEDULER.get()).as_mut() };
    let Some(scheduler) = scheduler else {
        return;
    };
    if !scheduler.has_other_runnable() {
        return;
    }
    let _ = scheduler.schedule(frame, false);
}

/// Whether a call means the program has finished.
pub fn is_exit(call: &CallFrame) -> bool {
    call.number == syscall::SyscallNumber::Exit as usize
}

#[cfg(test)]
mod tests {
    extern crate alloc;

    use alloc::vec;
    use alloc::vec::Vec;

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
        assert_eq!(context.elr, 0x80_0000_1000);
        assert_eq!(context.spsr, 0x340, "EL0t, IRQ unmasked, D/A/F masked");
        assert_eq!(context.link_register, 0);
        assert!(context.simd.iter().all(|slot| *slot == 0));
        assert!(
            context.registers[1..].iter().all(|slot| *slot == 0),
            "every register but the stack pointer is zero"
        );
        assert_eq!(context.registers[0], 0x80_0000_2000, "the stack pointer");
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
            task.context_mut().elr = index as u64;
            scheduler.add(task);
        }

        let mut frame = starting_context(0, 0);
        let mut order = Vec::new();
        for _ in 0..6 {
            scheduler.schedule(&mut frame, false);
            order.push(frame.elr);
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
            task.context_mut().elr = index as u64;
            scheduler.add(task);
        }

        let mut frame = starting_context(0, 0);
        // Task 0 exits.
        scheduler.schedule(&mut frame, true);
        assert_eq!(scheduler.exited(), 1);

        let mut order = Vec::new();
        for _ in 0..4 {
            scheduler.schedule(&mut frame, false);
            order.push(frame.elr);
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
        let mut frame = starting_context(0, 0);
        scheduler.schedule(&mut frame, true);
        assert_eq!(scheduler.exited(), 1);
        assert!(!scheduler.has_runnable());
        assert!(scheduler.current().is_none());
    }

    /// A task that made a call is resumed with that call's answer in `x0`.
    ///
    /// The value lives in the installed context, which is the frame the
    /// epilogue restores — so this is the same mechanism as the task switch,
    /// and a scheduler that copied contexts but lost `x0` would resume the
    /// program with the wrong answer.
    #[test]
    fn a_resumed_task_finds_the_answer_in_x0() {
        let mut scheduler = Scheduler::new();
        scheduler.add(Task::without_space("a"));
        let mut task = Task::without_space("b");
        task.context_mut().registers[0] = 42;
        scheduler.add(task);

        let mut frame = starting_context(0, 0);
        let outcome = scheduler.schedule(&mut frame, false);
        match outcome {
            arch::CallOutcome::Return(value) => assert_eq!(value, 42),
            arch::CallOutcome::Exit => panic!("nothing exited"),
        }
        assert_eq!(frame.registers[0], 42, "and it is in the restored frame");
    }
}
