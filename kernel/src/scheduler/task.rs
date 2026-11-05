//! kernel/src/scheduler/task.rs
//!
//! What a task is: a saved context, the address space it runs in, and the state
//! that decides whether it can be selected.
//!
//! ## Why the state is an enum and not a flag
//!
//! The first version had `finished: bool`, which is two states and describes
//! exactly the two things the scheduler could do before: run a program, or skip
//! it forever.  Sleeping is a third, and it is not "finished" with a timestamp
//! — a sleeping task is *runnable later*, and a scheduler that could not tell
//! the two apart would either wake a dead program or never wake a live one.  A
//! blocked task is a fourth: it waits for another task rather than for a clock,
//! and folding it into `Sleeping` would mean inventing a deadline for a wait
//! that has none.

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

/// Whether a program can run, and when a sleeping one can again.
///
/// ## Why this is a state and not a flag
///
/// The first version had `finished: bool`, which is two states and describes
/// exactly the two things the scheduler could do before: run a program, or skip
/// it forever.  Sleeping is a third, and it is not "finished" with a timestamp
/// — a sleeping task is *runnable later*, and a scheduler that could not tell
/// the two apart would either wake a dead program or never wake a live one.
///
/// The deadline is in the machine's own clock, which is why it is a bare
/// `u64` here and `arch::timer_counter()` is what fills it: comparing two
/// readings from the same counter is the only thing this file may assume about
/// time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum State {
    /// It can be selected.
    Runnable,
    /// It asked to sleep until the counter reads `until`.
    Sleeping { until: u64 },
    /// It is waiting for another task to wake it, and no deadline applies.
    ///
    /// The difference from `Sleeping` is what ends the wait.  A deadline is the
    /// clock's answer and the timer delivers it; this is another task's answer
    /// and nothing but a `wake` delivery ends it.  A scheduler that folded the
    /// two together would have to invent a deadline for a wait that has none,
    /// and any number it invented would be a read that gives up early.
    Blocked,
    /// It exited, and is never selected again.
    Finished,
}

/// One program the scheduler can run.
pub struct Task {
    /// Its name, for a boot line that reports what ran.
    pub name: &'static str,
    /// Where it is in its execution: everything the epilogue restores.
    pub(crate) context: Context,
    /// The pages it can reach, or `None` for a task sharing the kernel's own.
    pub(crate) space: Option<AddressSpace>,
    /// Whether it can run, is waiting for a deadline, or has finished.
    pub(crate) state: State,
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
            state: State::Runnable,
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
            state: State::Runnable,
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
/// Delegated to the machine, because what a frame holds is the machine's: on
/// aarch64 every register but `x0` and `ELR_EL1`, on x86_64 the five words
/// `iretq` pops.  A kernel that built one by naming fields would be a kernel
/// written against one architecture — which is exactly what this file was
/// before the second machine had a ring 3.
pub fn starting_context(entry: usize, stack_top: usize) -> Context {
    arch::starting_context(entry, stack_top)
}
