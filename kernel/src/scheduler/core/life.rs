//! kernel/src/scheduler/core/life.rs
//!
//! The three events in a task's life that are not a switch: it is forked, it
//! becomes another program, and its pages are released.
//!
//! A fork shares the running task's pages with a child, so the child resumes
//! at the instruction after the parent's `fork` with the parent's registers
//! and a read-only view of the parent's pages.  An exec replaces the task's
//! image with another program's and starts it from that image's first
//! instruction, keeping the task, its pid and its window.  The release is the
//! other end: pages go back once nothing walks them, and
//! `Scheduler::reap_finished` argues why that moment is the end of the boot
//! rather than each exit.

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

    /// Replace the running task's image with `image`'s, and start it over.
    ///
    /// This is `exec`: the same task, the same pid, the same parent, running a
    /// different program from that program's first instruction.  What carries
    /// over is the **window** — the virtual addresses the task already owns —
    /// and what does not is everything behind them: a fresh root, a fresh image
    /// frame with the machine's bytes for `image`, a fresh stack, and a context
    /// built from scratch, because a program that asked to become another does
    /// not resume where it was.
    ///
    /// ## The order that makes releasing the old space sound
    ///
    /// The old root is installed on the CPU serving the call when this runs,
    /// and freeing a root the machine is translating through is a fault on the
    /// next instruction.  So the new space is built first, the task is swapped
    /// onto it, and `switch_address_space` installs the new root — which on
    /// every machine is a whole-TLB flush — **before** the old space is
    /// released.  At the moment of the release no CPU translates through the
    /// old root: this one just switched away, the machine's switches all flush,
    /// and the task is marked running here and nowhere else, so no other CPU
    /// ever held it.  A release done before the switch would have the pool
    /// handing the old root's frame to the new space while this CPU still
    /// walked it.
    ///
    /// ## Why the failure is answerless rather than partial
    ///
    /// Every step that can fail happens before the task is touched: the old
    /// layout is read from the old space, the new space is built whole, and
    /// only then is the task's space, context and frame replaced.  A failure
    /// leaves the task exactly as it was, running the program it was running,
    /// and the caller answers an error rather than a pid.
    ///
    /// The layout is read rather than remembered: the task does not carry its
    /// base and stack top as fields, and the table is the truth — the first two
    /// pages in address order are the image and the stack, which is what every
    /// builder in this kernel makes them.
    #[cfg(target_os = "none")]
    pub fn exec_current(&mut self, cpu: usize, frame: &mut Context, image: u16) -> Option<u32> {
        let task_index = self.running.get(cpu).copied().flatten()?;
        // The window the task owns, read from its table before anything moves.
        let old_space = self.tasks.get(task_index)?.space?;
        let mut pages = [crate::address_space::MappedPage {
            virtual_address: 0,
            physical: 0,
            writable: false,
        }; 4];
        let count = crate::address_space::mapped_pages(&old_space, &mut pages)?;
        if count < 2 {
            return None;
        }
        let entry_va = pages[0].virtual_address;
        let stack_va = pages[1].virtual_address;

        let bytes = crate::process::program_bytes(image);
        // SAFETY: the two addresses are this task's own mapped pages, page
        // aligned and mapped by no other space; the image fits in a page,
        // which is what every builder maps.
        let new_space = unsafe { crate::address_space::image_space(&bytes, entry_va, stack_va) }?;
        let new_root = new_space.root();

        let pid = self.tasks.get(task_index)?.pid();
        let task = self.tasks.get_mut(task_index)?;
        let old_space = task.space.replace(new_space)?;
        // A fresh context, not a copy: the program starts at its own first
        // instruction, on a stack that carries nothing from the program it
        // replaced.
        *task.context_mut() =
            crate::scheduler::starting_context(entry_va, stack_va + paging::PAGE_SIZE);
        // And the trap frame resumes the new image, because the caller's
        // epilogue is what returns to a program and this task is the one
        // running.
        *frame = *task.context();

        // SAFETY: the new root is a live table this task owns, and every root
        // shares the kernel's entry 0, which covers the code performing the
        // call.
        unsafe { arch::switch_address_space(new_root) };
        // The switch flushed, so nothing translates through the old root any
        // more, and the release is the safe kind: see the order above.
        //
        // SAFETY: this CPU installed the new root above, no other CPU ever
        // held this task, and nothing walks the old space's pages.
        unsafe { old_space.release() };
        Some(pid)
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
