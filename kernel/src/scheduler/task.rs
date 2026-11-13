//! kernel/src/scheduler/task.rs
//!
//! What a task is: a saved context, the address space it runs in, and the state
//! that decides whether it can be selected.
//!
//! The first version had `finished: bool`, which is two states and describes
//! exactly the two things the scheduler could do before: run a program, or skip
//! it forever.  Sleeping is a third, and it is not "finished" with a timestamp
//! a sleeping task is *runnable later*, and a scheduler that could not tell
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
/// type is empty and every operation on it is absent, which is why the
/// scheduler's tests exercise the *rotation* and not the switching.  Pretending
/// a host had address spaces would be testing a fiction.
#[cfg(not(target_os = "none"))]
#[derive(Debug, Clone, Copy)]
pub struct AddressSpace;

/// Whether a program can run, and when a sleeping one can again.
///
/// The first version had `finished: bool`, which is two states and describes
/// exactly the two things the scheduler could do before: run a program, or skip
/// it forever.  Sleeping is a third, and it is not "finished" with a timestamp
///, a sleeping task is *runnable later*, and a scheduler that could not tell
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
    /// This process's identity, for the calls that ask who is running.
    ///
    /// The boot numbers the tasks it builds 1, 2, 3, with the boot itself as
    /// their parent; a forked child is numbered by the scheduler's counter and
    /// named by the process that forked it.  Either way the number is one the
    /// kernel assigned rather than one the program sent, which is the honest
    /// answer to a question about identity.
    pub(crate) pid: u32,
    /// The process that started this one.
    pub(crate) parent: u32,
    /// What the program answered `Exit` with, once it has exited.
    ///
    /// `None` while it runs: a status before the program chose one would be a
    /// number the kernel invented, and a parent waiting for that answer would
    /// read it as the program's own decision.
    pub(crate) status: Option<usize>,
    /// Where this program's fault handler lives, or `None` for a program that
    /// has none.
    ///
    /// A program installs one with `InstallExceptionHandler`, and a fault it
    /// takes is then **its** to answer rather than the kernel's to kill it
    /// for: the trap path resumes the program at this address with the fault's
    /// description in its registers, and `ReturnFromException` is the program
    /// saying it has finished with it.
    ///
    /// The address is a virtual one in the program's own space, so it is only
    /// meaningful together with the `space` this task runs through — which is
    /// why it lives here and not in the registry.
    pub(crate) handler: Option<usize>,
    /// The CPU slot this task last ran on, or `usize::MAX` before its first
    /// run.
    ///
    /// A task is not bound to a CPU: the only binding is the scheduler's
    /// `running` array, and leaving it is what a switch does.  So a task that
    /// was preempted, slept, blocked or exited and was then selected again may
    /// resume on a different CPU, and that is a migration.  The field is what
    /// makes one visible: without it a migrated task is indistinguishable from
    /// a task on its first run, and the boot could not say the mechanism ran.
    ///
    /// It is **not** an affinity.  Nothing pins a task to the CPU recorded
    /// here; the scheduler is free to place it anywhere, and the record only
    /// says where it was.
    pub(crate) last_cpu: usize,
    /// The last CPU other than the boot one this task ran on, or `usize::MAX`
    /// if it never did.
    ///
    /// A separate field from [`last_cpu`](Self::last_cpu), because the two
    /// answer different questions and only one of them survives a migration.
    /// `last_cpu` is where the task was a moment ago; this is whether it has
    /// **ever** run beside the boot CPU, and a task that is taken back by the
    /// boot CPU keeps the second answer while losing the first.
    ///
    /// The difference is what a boot's own evidence line turns on.  A program
    /// that ran hundreds of ticks on the started CPU and then finished on the
    /// boot one — a migration that `task migrations` reports — was a program
    /// that ran in parallel, and reading the CPU at the moment of its exit said
    /// it had not.  The gate required `program ended on cpu 1` and the boot
    /// printed `parallel, programs ended on 0`, both truthfully, because the
    /// program's last instruction happened to run on the other CPU.
    pub(crate) ran_off_boot_cpu: usize,
    /// The signals other processes have sent this one and not been taken.
    ///
    /// A fixed ring rather than a growable list: a sender that fills it has
    /// a target that is not consuming, and `Busy` is the answer that says so
    /// — an unbounded queue would be one process's runaway loop holding
    /// every other task's memory.  The depth is eight, which is what a boot
    /// whose programs exchange one signal needs and far short of a heap's
    /// worth.
    pub(crate) signals: [Option<PendingSignal>; TASK_SIGNAL_QUEUE],
    /// The mask whose bit `n` blocks signal `n`.
    ///
    /// A masked signal still queues — the sender's send succeeded and the
    /// target is not consuming, which is the ring's business — but a wait
    /// does not take it until something clears the bit.  `0` is the fresh
    /// task's mask: everything deliverable.
    pub(crate) signal_mask: u32,
    /// The mask a `SigSuspend` will put back when its signal answers.
    ///
    /// A suspend parks, and the wake resumes the **call**, which re-enters
    /// with the same argument: without this slot the retry could not tell
    /// the mask to restore from the mask it was told to run under, and the
    /// original would be lost to the suspend's own.  `None` is a task not
    /// inside a suspend.
    pub(crate) suspend_restore: Option<u32>,
}

/// A signal one process sent another, waiting to be taken.
///
/// The sender travels **with** the signal: a signal without a sender is one
/// the receiver cannot blame, and the record `WaitSignal` answers is the
/// three of these fields, not a number alone.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PendingSignal {
    /// Which signal, `1..=31` — the range the ABI validates at the call.
    pub(crate) signal: usize,
    /// The process that sent it.
    pub(crate) sender_pid: u32,
    /// One word the sender chose, and the kernel never reads.
    pub(crate) payload: usize,
}

/// How many unsent signals one task holds.
pub(crate) const TASK_SIGNAL_QUEUE: usize = 8;

impl Task {
    /// Take the oldest pending signal the mask does not block.
    ///
    /// A masked signal stays queued: the wait that skipped it is not a
    /// refusal, it is "not yet", and the day the bit clears the ring
    /// answers.
    pub(crate) fn take_signal(&mut self) -> Option<PendingSignal> {
        let mask = self.signal_mask;
        let taken = self.signals.iter_mut().find(|slot| match slot {
            Some(pending) => mask & (1 << pending.signal) == 0,
            None => false,
        });
        taken.and_then(|slot| slot.take())
    }

    /// Queue a signal another process sent, or refuse when the ring is full.
    pub(crate) fn queue_signal(
        &mut self,
        signal: usize,
        sender_pid: u32,
        payload: usize,
    ) -> Result<(), abi::Error> {
        let slot = self
            .signals
            .iter_mut()
            .find(|slot| slot.is_none())
            .ok_or(abi::Error::Busy)?;
        *slot = Some(PendingSignal {
            signal,
            sender_pid,
            payload,
        });
        Ok(())
    }

    /// A task that starts at `entry`, with its stack at `stack_top`, in
    /// `space`.
    #[cfg(target_os = "none")]
    pub fn new(name: &'static str, entry: usize, stack_top: usize, space: AddressSpace) -> Task {
        Task {
            name,
            context: starting_context(entry, stack_top),
            space: Some(space),
            state: State::Runnable,
            pid: 0,
            parent: 0,
            status: None,
            handler: None,
            last_cpu: usize::MAX,
            ran_off_boot_cpu: usize::MAX,
            signals: [const { None }; TASK_SIGNAL_QUEUE],
            signal_mask: 0,
            suspend_restore: None,
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
            pid: 0,
            parent: 0,
            status: None,
            handler: None,
            last_cpu: usize::MAX,
            ran_off_boot_cpu: usize::MAX,
            signals: [const { None }; TASK_SIGNAL_QUEUE],
            signal_mask: 0,
            suspend_restore: None,
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
        self.space.as_ref().map(|_| None).unwrap_or(None)
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// The process that started this one.
    pub fn parent(&self) -> u32 {
        self.parent
    }

    /// What this process exited with, once it has exited.
    pub fn status(&self) -> Option<usize> {
        self.status
    }

    /// Name this process and its parent.
    ///
    /// The boot calls this once per task it builds, with the boot as the
    /// parent; a fork calls it with the forking process's pid, which is how a
    /// child of a program differs from a child of the boot.
    pub fn identify(&mut self, pid: u32, parent: u32) {
        self.pid = pid;
        self.parent = parent;
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
/// written against one architecture, which is exactly what this file was
/// before the second machine had a ring 3.
pub fn starting_context(entry: usize, stack_top: usize) -> Context {
    arch::starting_context(entry, stack_top)
}
