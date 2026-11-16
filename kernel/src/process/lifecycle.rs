//! kernel/src/process/lifecycle.rs
//!
//! A program's life: exit, fork, spawn, exec, wait, and the two calls that name
//! a process.
//!
//! One family of `serve`'s branches, moved out so the dispatcher reads as a
//! list of families.  `None` means this family does not serve `number` and
//! `serve` tries the next one; `Some(outcome)` is the call's answer and ends
//! the dispatch.

use super::OPEN_PATH_MAX;
use super::copy_user_path;

pub(crate) fn serve_lifecycle(
    call: arch::CallFrame,
    frame: &mut arch::Context,
    number: usize,
    caller: Option<u32>,
) -> Option<arch::CallOutcome> {
    use arch::CallOutcome;
    use syscall::SyscallNumber;
    let _ = (&call, &*frame, number, caller);
    if number == SyscallNumber::Exit as usize {
        // The scheduler decides what runs next and puts that task's context in
        // the frame.  When nothing is left there is nothing to resume, and
        // `eret`-ing into a program that asked to exit would run it again from
        // the instruction after the `svc`, forever.
        // The status is `Exit`'s first argument, which is where every
        // machine's call convention puts it, `edi` on x86_64, `a0`/`x0` on the
        // others.  Reading a return register instead would be wrong on the one
        // machine whose two registers differ.
        let status = call.arguments[0];
        // Which CPU ran this program beside the boot one, reported once per
        // exit so the log says how many programs finished on a CPU other than
        // the boot's.  This is the evidence parallel execution leaves: the two
        // CPUs' switch counts alone cannot say whether a program ran anywhere
        // but CPU 0.
        //
        // The question is **where the program has run**, not where it is
        // exiting.  Those differ whenever a task is migrated back to the boot
        // CPU between its last work and its exit, which this scheduler does,
        // and `task migrations` reports, and reading the exit's own CPU said
        // "no program ran in parallel" about a program whose tick count on the
        // started CPU was in the hundreds.  Four boots in fifteen printed the
        // contradiction.
        let ran_on = crate::scheduler::current_ran_off_boot_cpu();
        if ran_on != usize::MAX {
            crate::programs::note_program_ran_on(ran_on);
        }
        // **An exiting process closes what it held.**  A descriptor is not the
        // table's, it is the process's, and a process that ends releases every
        // slot it owned, the same `Drop` a `Close` runs, which for a pipe end
        // is what moves the pipe's count and ends a reader's wait.  Without
        // this an end stays in the table for ever, keeping a reader parked on
        // a writer that no longer exists.
        if let Some(pid) = crate::scheduler::current_pid()
            && let Some(released) = crate::syscall::release_owned(pid)
            && released > 0
        {
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(pid);
            arch::serial::write_str(" released ");
            arch::serial::write_u32(released as u32);
            arch::serial::write_str(" descriptor(s)\n");
        }
        // A CPU that gets no next task waits for work, or reports and stops
        // when the machine is finished; neither returns an uninstalled frame,
        // which is what makes the `sret` that follows always a real program.
        let outcome = crate::scheduler::advance_with_status(frame, true, status);
        return Some(outcome);
    }
    if number == SyscallNumber::Sleep as usize {
        // `Sleep(microseconds)`.
        //
        // The argument is a duration and the scheduler wants a deadline, so the
        // conversion happens once, in the machine's own clock.  A call with no
        // scheduler behind it answers `NotImplemented` rather than pretending
        // to sleep: a host build has no timer, and a program told it slept
        // would be a program whose timing lied.
        let microseconds = call.arguments[0] as u64;
        match crate::scheduler::sleep_for_microseconds(microseconds, frame) {
            Some(until) => {
                arch::serial::write_str("protofire: a program sleeps until counter ");
                arch::serial::write_u32(until as u32);
                arch::serial::write_str("\n");
                // The program is asleep, so the frame must describe whatever
                // runs next.
                //
                // `advance` saves the frame it was given into the *current*
                // task before choosing the next one, and the current task is
                // the one that just went to sleep, whose context was saved by
                // `sleep_for_microseconds`.  Saving again is harmless; what is
                // not is that `advance` answers `Exit` when nothing else is
                // runnable, and `Exit` tells the trap path to resume the frame
                // it has, a sleeping program.
                //
                // So the two cases are not separate after all, the first
                // version thought they were, and the difference was a ghost.
                // `advance` can answer `Exit` with tasks still runnable: the
                // one runnable task can be the one **another CPU is already
                // running**, excluded by the running array, and an `Exit` here
                // means the frame was not replaced.  Resuming it ran this
                // program while its task was still asleep and no CPU held it
                // a process with no entry in the running array, the one
                // invariant the exclusion set is.  The boot showed the shape in
                // full: the ghost announced, forked (refused, no task to fork
                // from), exec'd (refused the same way), and spun at its end,
                // while the task that owned it slept on; a tick's preemption
                // was what happened to reinstall the real context.  So an
                // `Exit` falls into the same wait the every-task-asleep case
                // uses, and the wake that ends the sleep is what installs
                // whatever runs next, through the call that does *not* save,
                // because the frame arriving here is the boot's kernel frame
                // and the task it would be saved into is asleep with a program
                // context that must not be clobbered.
                match crate::scheduler::advance(frame, false) {
                    // A next task was installed; the epilogue resumes it.
                    arch::CallOutcome::Return(_) => return Some(arch::CallOutcome::Exit),
                    arch::CallOutcome::Exit => {}
                }
                arch::serial::write_str("protofire: nothing runnable for this cpu, waiting\n");
                crate::scheduler::idle_until_woken();
                return Some(crate::scheduler::switch_without_saving(frame));
            }
            None => {
                return Some(CallOutcome::Return(abi::syscall::encode_error(
                    abi::Error::NotImplemented,
                )));
            }
        }
    }

    // Fork: the running process shared with a child.
    //
    // ## The one instruction that answers two ways
    //
    // Both processes resume at the instruction after the `int`/`svc`/`ecall`;
    // the kernel distinguishes them by what it writes into the return register.
    // The **parent** learns the child's pid, and the **child** learns zero.
    // That is the whole of `fork`'s interface, and it is why the answer is not
    // put in the frame here for the child: the child's frame is its parent's,
    // taken whole, and the value this writes is the value only the parent sees.
    if number == SyscallNumber::Fork as usize {
        return Some(match crate::scheduler::fork_current(frame) {
            Some(pid) => {
                arch::serial::write_str("protofire: forked a process, child pid ");
                arch::serial::write_u32(pid);
                arch::serial::write_str("\n");
                CallOutcome::Return(pid as usize)
            }
            None => CallOutcome::Return(abi::syscall::encode_error(abi::Error::OutOfMemory)),
        });
    }

    // Starting a process the caller chose, rather than becoming one.
    //
    // `ExecProcess` replaces the calling task; `SpawnProcess` grows the
    // machine by one task that did not exist, named by the file the caller
    // picked, and answers the pid, which is the number a supervisor needs,
    // because the wait that supervises names a pid.
    if number == SyscallNumber::SpawnProcess as usize {
        let mut path_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(path) = copy_user_path(call.arguments[0], &mut path_bytes) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        };
        match crate::scheduler::spawn_process(path) {
            Some(pid) => {
                // The one line that says the machine grew: the caller, the
                // file it named, and the pid the kernel answered, the
                // number a later wait carries.
                arch::serial::write_str("protofire: process ");
                arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
                arch::serial::write_str(" spawned ");
                arch::serial::write_str(path);
                arch::serial::write_str(" as pid ");
                arch::serial::write_u32(pid);
                arch::serial::write_str("\n");
                return Some(CallOutcome::Return(pid as usize));
            }
            // The same answer exec gives for a machine that could not: no
            // scheduler, no file, or a pool too empty to build the space.
            None => {
                return Some(CallOutcome::Return(abi::syscall::encode_error(
                    abi::Error::OutOfMemory,
                )));
            }
        }
    }

    // Exec: the running process becomes the file it names.
    //
    // The argument is a NUL-terminated path in the caller's memory, copied
    // with the same bound and the same check the `Open` branch uses, an
    // address from ring 3 is a number until something validates it.  The
    // kernel reads the file through the registry's own namespace, loads it,
    // and maps it; the task keeps its pid and its parent, and everything else
    // is the new program's, which is the whole of what `exec` is.
    if number == SyscallNumber::ExecProcess as usize {
        let mut path_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(path) = copy_user_path(call.arguments[0], &mut path_bytes) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        };
        return Some(match crate::scheduler::exec_current(frame, path) {
            Some(pid) => {
                // The one line that says the mechanism ran: the task that
                // called is the task named, and the file is the one it asked
                // to become.  A reader can pair this with the exit statuses
                // the exec'd task's status is the first byte of the file it
                // read, which only a task that ran could report.
                arch::serial::write_str("protofire: process ");
                arch::serial::write_u32(pid);
                arch::serial::write_str(" exec'd ");
                arch::serial::write_str(path);
                arch::serial::write_str("\n");
                CallOutcome::Return(0)
            }
            None => CallOutcome::Return(abi::syscall::encode_error(abi::Error::OutOfMemory)),
        });
    }

    // Who is asking, and who started them.
    //
    // The answers come from the task the scheduler is running, not from the
    // call: a program does not send its own id, and one that could would be a
    // program answering a question about itself.
    if number == SyscallNumber::GetPid as usize {
        return Some(match crate::scheduler::current_pid() {
            Some(pid) => CallOutcome::Return(pid as usize),
            None => CallOutcome::Return(abi::syscall::encode_error(abi::Error::NotImplemented)),
        });
    }
    if number == SyscallNumber::GetPpid as usize {
        return Some(match crate::scheduler::current_parent() {
            Some(parent) => CallOutcome::Return(parent as usize),
            None => CallOutcome::Return(abi::syscall::encode_error(abi::Error::NotImplemented)),
        });
    }

    // Waiting for a process to end.
    //
    // This boot has one process tree, the programs the kernel started, all
    // children of the boot, so the only wait that can be answered is "has any
    // process finished, and with what".  That is a real answer, and it is the
    // one a parent in this tree can ask for: a wait for a *particular* child
    // would need a wait that names a pid, which does not exist yet.
    //
    // A wait with nothing finished **blocks** rather than spinning: the caller
    // is parked like a pipe's reader, and a process exit is what wakes it.  A
    // wait that answered zero would be a parent told its child exited with
    // nothing, which is the kind of invented answer this tree refuses.
    if number == SyscallNumber::WaitProcess as usize {
        if let Some(status) = crate::scheduler::first_exit_status() {
            // Reported, because a wait that answered silently and a wait that
            // never ran print the same exit status two lines later.  The
            // number is the status the wait handed the program, which is what
            // the boot's own `exit statuses` line then repeats.
            arch::serial::write_str("protofire: a wait answered status ");
            arch::serial::write_u32(status as u32);
            arch::serial::write_str("\n");
            return Some(CallOutcome::Return(status));
        }
        if !crate::scheduler::has_other_unfinished() {
            // No other task can finish, so no exit can arrive: answering "no
            // such process" is the truth, and blocking would be a hang.  The
            // question is "unfinished" and not "runnable": a child that is
            // asleep will wake and exit, and the runnable question answered
            // this wait `NotFound` for exactly that child.
            //
            // Reported, for the reason the answer above is: a program that
            // exits with an error's encoding is the one failure here whose
            // cause is invisible in the status line alone.
            arch::serial::write_str("protofire: a wait has nothing to wait for\n");
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::NotFound,
            )));
        }
        // Park, with the same re-check the pipe's read parks under.  The
        // wait's question is "has a process finished?", and a child on
        // another CPU can finish between this call's own check and the park;
        // a task parked after the wake it was waiting for is a task parked
        // for ever.  The re-check and the park are one critical section, so
        // the exit has only two orders to find: its status first, and the
        // call answers it here, or the task first, and the exit's wake ends
        // the wait.
        match crate::scheduler::block_unless_exit(frame) {
            Some(status) => {
                // The re-check under the scheduler's lock found the exit this
                // call's own look a moment earlier had not: a process finished
                // in the deciding instant.  Reported for the reason the
                // immediate answer above is, a wait that answered and a wait
                // that never ran print the same status line otherwise.
                arch::serial::write_str("protofire: a wait answered status ");
                arch::serial::write_u32(status as u32);
                arch::serial::write_str("\n");
                return Some(CallOutcome::Return(status));
            }
            None => {
                arch::serial::write_str("protofire: a program waits for a child\n");
                if !crate::scheduler::has_selectable() {
                    crate::scheduler::idle_until_woken();
                }
                // **Answer with the switch, not `Exit` after throwing it
                // away.**  `switch_without_saving` installs the next task's
                // context into `frame` and answers `Return`; discarding that
                // and answering `Exit` leaves the frame describing *this*
                // task, so the epilogue resumes the waiter at the instruction
                // after its `svc` with `x0` still holding whatever the call
                // before left, the wait skipped, and the program exits with
                // a number the wait never answered.  The sleep path answers
                // the switch this way and has always worked; this branch and
                // the pipe's read were the two that did not.
                return Some(crate::scheduler::switch_without_saving(frame));
            }
        }
    }

    // Waiting for **one named** process: `WaitProcessOf(pid)`.
    //
    // The other half of the wait pair.  `WaitProcess` answers about whichever
    // process finished first, which is all a boot with one process tree could
    // say when it was added, and it is the wrong answer for a parent asking
    // about its own child, because the child's status arrives only if the child
    // happened to be first.  This call names the pid, so what it answers is
    // about the process the caller meant.
    //
    // Three outcomes, and the difference between them is why the answer is not
    // a bare `Option`:
    //
    // - the process ended: its status;
    // - no task has that pid: `NotFound`, which is a fact the caller can check
    //   its own argument against;
    // - it has not ended yet: park, and its exit is what wakes the park.
    if number == SyscallNumber::WaitProcessOf as usize {
        let pid = call.arguments[0] as u32;
        match crate::scheduler::block_unless_pid(frame, pid) {
            Some(crate::scheduler::PidWait::Ended(status)) => {
                arch::serial::write_str("protofire: a wait answered status ");
                arch::serial::write_u32(status as u32);
                arch::serial::write_str(" for process ");
                arch::serial::write_u32(pid);
                arch::serial::write_str("\n");
                return Some(CallOutcome::Return(status));
            }
            Some(crate::scheduler::PidWait::NoSuchProcess) => {
                arch::serial::write_str("protofire: a wait names a process that does not exist\n");
                return Some(CallOutcome::Return(abi::syscall::encode_error(
                    abi::Error::NotFound,
                )));
            }
            Some(crate::scheduler::PidWait::NotYet) => {
                // Parked: its exit is what wakes this, and the retry asks
                // again with the same pid.
                arch::serial::write_str("protofire: a program waits for process ");
                arch::serial::write_u32(pid);
                arch::serial::write_str("\n");
                if !crate::scheduler::has_selectable() {
                    crate::scheduler::idle_until_woken();
                }
                return Some(crate::scheduler::switch_without_saving(frame));
            }
            // No scheduler: nothing can be waited for, and the honest answer
            // is the one a host build gives for anything it cannot serve.
            None => {
                return Some(CallOutcome::Return(abi::syscall::encode_error(
                    abi::Error::NotImplemented,
                )));
            }
        }
    }

    None
}
