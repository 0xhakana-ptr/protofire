//! kernel/src/scheduler/core/life.rs
//!
//! The two events in a task's life that are not a switch: it is forked, and its
//! pages are released.
//!
//! A fork copies the running task's space and its frame, so the child resumes
//! at the instruction after the parent's `fork` with the parent's registers and
//! a copy of its pages.  The release is the other end: pages go back once
//! nothing walks them, and `Scheduler::reap_finished` argues why that moment is
//! the end of the boot rather than each exit.

use super::Scheduler;
#[cfg(target_os = "none")]
use crate::scheduler::task::State;
#[cfg(target_os = "none")]
use crate::scheduler::task::Task;
#[cfg(target_os = "none")]
use arch::Context;

impl Scheduler {
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

    /// Release every finished task's address space, answering how many went
    /// back.
    ///
    /// ## When this is safe, and why the caller must say
    ///
    /// A finished task's pages are free only when nothing will translate
    /// through them again.  Clearing the task's slot is **not** that condition:
    /// the CPU that leaves a task keeps the task's root installed while it
    /// waits for work, and it can be inside its trap path with no lock held.
    /// Releasing at each exit produced 186 page faults at `0x8080000030`,
    /// program 2's stack, in six boots of eight — a frame the kernel still
    /// walked, handed by the pool to someone else.
    ///
    /// So this is called once, after every task has finished and every other
    /// CPU has been told the boot is over.  At that point no CPU is inside a
    /// program and none will enter one, which is the whole of the safety
    /// argument, and it is the caller's to make rather than this function's to
    /// guess.
    ///
    /// A task whose space is already gone is skipped, so a second call answers
    /// zero instead of freeing a frame twice.
    #[cfg(target_os = "none")]
    pub fn reap_finished(&mut self) -> usize {
        let mut reaped = 0;
        for task in &mut self.tasks {
            if task.state != State::Finished {
                continue;
            }
            let Some(space) = task.space.take() else {
                continue;
            };
            // SAFETY: the caller promises the machine is finished, so no CPU is
            // running a program and none will: every task is `Finished` and
            // every other CPU has been told to stop.
            unsafe { space.release() };
            reaped += 1;
        }
        reaped
    }
}
