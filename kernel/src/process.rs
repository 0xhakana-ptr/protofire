//! kernel/src/process.rs
//!
//! One program, running at EL0, calling back into the kernel.
//!
//! What the kernel does with a program's supervisor call: a handful of calls
//! are served — `Write`, `Exit`, `Sleep`, a pipe's `Read` and `Write`, `Fork`,
//! `ExecProcess`, `GetPid`, `GetPpid`, `WaitProcess` and `Pipe` — and
//! everything else answers `NotImplemented`.
//!
//! The image a program runs is machine code, so it lives in `arch` and this
//! file asks for it.  An array here would have to be right for three
//! architectures, and there is no array that is: `svc` and `x8` are aarch64's,
//! `int $0x80` and `eax` are x86_64's.  The two moved to their machines in the
//! change that added the second machine's ring 3, and the comment that
//! described them stayed behind for a while afterwards.
//!
//! ## Sleeping
//!
//! `Sleep` is the first call that does not answer immediately.  It records a
//! deadline in the scheduler and answers `Exit`-shaped, not because the
//! program has ended, but because the frame the handler holds must describe
//! what runs next, and what runs next is another task.  The program resumes
//! when the timer wakes it, with its context exactly as the trap saved it.

/// A program's bytes, for a caller that writes them into a frame.
///
/// Asked of the machine: a program is machine code, and the array is this
/// architecture's, `svc` and `x8` on aarch64, `int $0x80` and `eax` on x86_64.
/// The kernel names one function and gets whichever machine answered.
pub fn program_bytes(number: u16) -> [u8; arch::PROGRAM_LEN] {
    arch::program_bytes(number)
}

/// A program's length in bytes.
pub const PROGRAM_LEN: usize = arch::PROGRAM_LEN;

/// The number of the program that reads the pipe.
pub const PIPE_READER: u16 = arch::PIPE_READER;

/// The number of the program that writes to it.
pub const PIPE_WRITER: u16 = arch::PIPE_WRITER;

/// Where the `n`th program's pages go.
///
/// Each program gets a gigabyte of the user window, far more than it uses and
/// far enough apart that one overrunning its pages cannot reach another's.  The
/// spacing is the point: two programs at the same address would be two programs
/// whose address spaces differ and whose *virtual* addresses collide, which is
/// correct and makes a log that says "0x80_0000_0000" twice less useful.
pub const fn program_base(number: u16) -> usize {
    crate::address_space::USER_BASE + (number as usize) * 0x4000_0000
}

/// Where the `n`th program's stack top is.
///
/// The **end** of the stack page, not its start.  The page is mapped at
/// `program_base + 0x1000`, and a stack pointer at its first byte has no stack:
/// the first `push` writes the byte before it, which is unmapped.  Every
/// earlier program ran without touching the stack, so this was invisible until
/// one did, the pipe reader's first instruction is a load from `[rsp]`, and it
/// took a page fault.
pub const fn program_stack_top(number: u16) -> usize {
    program_base(number) + 0x2000
}

/// The page the `n`th program's stack lives on.
pub const fn program_stack_page(number: u16) -> usize {
    program_base(number) + 0x1000
}

/// How far below the stack top `exec` starts the image it hands over.
///
/// The stack's top is a boundary, not storage — the same rule the boot's
/// hand-over keeps — so `exec` writes its words below it and starts the image
/// with the pointer moved down to them.  The block is the one inheritance an
/// `exec` has: `[sp]` is a user pointer to a NUL-terminated path the kernel
/// placed at [`EXEC_PATH_OFFSET`], and an image that wants no path simply
/// never reads it.
///
/// The 96 is deliberate: a program's own push writes below its hand-over
/// pointer — 16 bytes down on aarch64 and riscv64, 8 on x86_64 — and the
/// first version's 64-byte block put the path's tail *inside* that push
/// zone.  The aarch64 parent's push overwrote the path's `t` and NUL with
/// the pointer's own bytes, the copy read a truncated string, and the exec
/// failed with a path nobody could have guessed.  The block now ends 32
/// bytes below the hand-over pointer, past every machine's push write.
pub const EXEC_BLOCK_BYTES: usize = 96;

/// Where in the `exec` block the path's bytes begin.
pub const EXEC_PATH_OFFSET: usize = 16;

/// What the kernel does with a program's supervisor call.
///
/// `Write` prints a fixed line, the program's arguments are not read, because
/// a pointer in a register is an address this kernel has no way to validate
/// yet, and reading one would be trusting a value from ring 3.  `Exit` ends the
/// program.  Everything else answers `NotImplemented`, which is what the
/// registry would say anyway and says here without a lookup.
#[cfg(target_os = "none")]
pub fn serve(call: arch::CallFrame, frame: &mut arch::Context) -> arch::CallOutcome {
    use arch::CallOutcome;
    use syscall::SyscallNumber;

    let number = call.number;

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
        // CPU between its last work and its exit — which this scheduler does,
        // and `task migrations` reports — and reading the exit's own CPU said
        // "no program ran in parallel" about a program whose tick count on the
        // started CPU was in the hundreds.  Four boots in fifteen printed the
        // contradiction.
        let ran_on = crate::scheduler::current_ran_off_boot_cpu();
        if ran_on != usize::MAX {
            crate::programs::note_program_ran_on(ran_on);
        }
        // **An exiting process closes what it held.**  A descriptor is not the
        // table's, it is the process's, and a process that ends releases every
        // slot it owned — the same `Drop` a `Close` runs, which for a pipe end
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
        return outcome;
    }
    // A write to a pipe, recognised by the descriptor naming one.
    //
    // The test is the table, not the argument: a program's `Write` is also how
    // it announces which program it is, and that call passes a small number
    // where a pipe's descriptor would be.  A range check could not tell the two
    // apart, aarch64's `x0` holds the stack top for every program, and the
    // first version's did exactly that, so the announcement was served as a
    // pipe write and the program printed once.
    // A pipe write is a write *with a length*, which the announcing `Write`
    // never has.
    //
    // The descriptor test alone is not enough, and this is the defect that
    // showed it: a program's first instructions have no reason to set `edi`, so
    // it holds whatever the boot left, zero, and zero is a valid descriptor
    // once a pipe exists.  The announcement was then served as a pipe write and
    // the program printed nothing.  A length is what the announcing call
    // genuinely lacks and a real write genuinely has.
    if number == SyscallNumber::Write as usize
        && call.arguments[2] != 0
        && crate::pipe::lookup(call.arguments[0]).is_some()
    {
        // `Write(descriptor, buffer, length)`, where the descriptor names a
        // pipe's write end.
        //
        // The same validation the read uses, for the same reason: an address
        // from ring 3 is a number, and reading it because a program said so is
        // the one thing the kernel must not do.
        let descriptor = call.arguments[0];
        let buffer = call.arguments[1];
        let length = call.arguments[2];
        if !crate::address_space::is_user_range(buffer, length) {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        }
        let Some(end) = crate::pipe::lookup(descriptor) else {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        };
        let pipe = end.pipe().clone();
        // SAFETY: the range was validated above and the page tables are this
        // task's, so the buffer is readable from here.
        let source = unsafe { core::slice::from_raw_parts(buffer as *const u8, length) };

        let progress = match end.try_write(&pipe, source) {
            Ok(progress) => progress,
            Err(error) => return CallOutcome::Return(abi::syscall::encode_error(error)),
        };
        return match progress {
            crate::pipe::Progress::Done(count) => {
                // A writer that put bytes in is what a blocked reader was
                // waiting for, so this is where the wake belongs.  Waking
                // before answering means the reader is selectable by the time
                // the next scheduling decision looks.
                if count > 0 {
                    let woken = crate::scheduler::wake_blocked();
                    // Reported **whether or not a task was blocked**.  The
                    // count is the fact, and zero is a fact: the reader was
                    // already awake, or had not yet reached its wait, and the
                    // bytes it asked for are in the pipe either way.  Printing
                    // only the non-zero case made the line a function of an
                    // interleaving, and the gate requires it — 2 of 100 runs
                    // found the reader awake when the write landed and failed
                    // a boot that did everything right.
                    arch::serial::write_str("protofire: a write woke ");
                    arch::serial::write_u32(woken as u32);
                    arch::serial::write_str(" blocked task(s)\n");
                    if woken > 0 {
                        // The task that woke may be held by another CPU, and
                        // that CPU is parked in a wait whose own clock may not
                        // move: without this, the woken task stays Runnable
                        // and unclaimed for ever, and both cores end up
                        // waiting.
                        unsafe { arch::send_ipi_to_others() };
                    }
                }
                CallOutcome::Return(count)
            }
            // A full pipe with a reader: the writer could block here, and this
            // boot does not make it.  Answering zero says the bytes did not go,
            // which is a fact the program can act on; blocking instead would be
            // a second place a task can park and a second place to get wrong,
            // and no program in this tree fills a pipe.
            crate::pipe::Progress::Block => CallOutcome::Return(0),
        };
    }

    if number == SyscallNumber::Write as usize {
        // The program's number is the one value it passes, and it is what makes
        // two programs distinguishable in one log.
        arch::serial::write_str("program ");
        arch::serial::write_u32(call.arguments[1] as u32);
        arch::serial::write_str(" says hello\n");

        // A `Write` does **not** switch.  The first version did, and the bug
        // was invisible in the log and fatal underneath: `advance` replaced the
        // frame with the other task's context, and then this function wrote its
        // own answer into `x0` of *that* context and returned `Return`, so the
        // program resumed was the other one, with its `x0` overwritten by a
        // value meant for this one.  Both printed, and the exit never happened.
        //
        // Switching on exit only is also the honest scheduling policy: a
        // program that made a call and got its answer has no reason to lose the
        // CPU, and nothing here preempts.
        return CallOutcome::Return(PROGRAM_OUTPUT);
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
                // So the two cases are not separate after all — the first
                // version thought they were, and the difference was a ghost.
                // `advance` can answer `Exit` with tasks still runnable: the
                // one runnable task can be the one **another CPU is already
                // running**, excluded by the running array, and an `Exit` here
                // means the frame was not replaced.  Resuming it ran this
                // program while its task was still asleep and no CPU held it —
                // a process with no entry in the running array, the one
                // invariant the exclusion set is.  The boot showed the shape in
                // full: the ghost announced, forked (refused — no task to fork
                // from), exec'd (refused the same way), and spun at its end,
                // while the task that owned it slept on; a tick's preemption
                // was what happened to reinstall the real context.  So an
                // `Exit` falls into the same wait the every-task-asleep case
                // uses, and the wake that ends the sleep is what installs
                // whatever runs next — through the call that does *not* save,
                // because the frame arriving here is the boot's kernel frame
                // and the task it would be saved into is asleep with a program
                // context that must not be clobbered.
                match crate::scheduler::advance(frame, false) {
                    // A next task was installed; the epilogue resumes it.
                    arch::CallOutcome::Return(_) => return arch::CallOutcome::Exit,
                    arch::CallOutcome::Exit => {}
                }
                arch::serial::write_str("protofire: nothing runnable for this cpu, waiting\n");
                crate::scheduler::idle_until_woken();
                return crate::scheduler::switch_without_saving(frame);
            }
            None => {
                return CallOutcome::Return(abi::syscall::encode_error(abi::Error::NotImplemented));
            }
        }
    }

    if number == SyscallNumber::Read as usize && crate::pipe::lookup(call.arguments[0]).is_some() {
        // `Read(descriptor, buffer, length)`, where the descriptor names a
        // pipe.
        //
        // The registry's `Read` takes a path through `Arguments::path`, which
        // is a borrow the boot can hand it because the boot owns the string.  A
        // program does not: it passes an address, and an address from ring 3 is
        // a number until something validates it.  So this is the call the
        // validation exists for.
        //
        // `try_read` answers `Block` only when the pipe could still fill, no
        // bytes now, and a writer alive.  That is the one case where waiting is
        // right: a drained pipe whose writers are gone answers `Done(0)` and a
        // program's loop ends, which is what end-of-file is.
        let descriptor = call.arguments[0];
        let buffer = call.arguments[1];
        let length = call.arguments[2];
        if !crate::address_space::is_user_range(buffer, length) {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        }
        let Some(end) = crate::pipe::lookup(descriptor) else {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        };
        let pipe = end.pipe().clone();
        // SAFETY: the range was validated above and the page tables are the
        // ones this task runs through, so the buffer is writable from here.
        let destination = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, length) };

        // The pipe is behind an `Arc` the descriptor table holds, and its
        // buffer is a cell, so this reads it through the shared reference
        // rather than needing to own it.
        let progress = match end.try_read(&pipe, destination) {
            Ok(progress) => progress,
            Err(error) => return CallOutcome::Return(abi::syscall::encode_error(error)),
        };
        return match progress {
            crate::pipe::Progress::Done(count) => CallOutcome::Return(count),
            crate::pipe::Progress::Block => {
                // Park — but let the park ask the question once more under
                // the scheduler's own lock.  Between the `Block` above and
                // the park, a writer on another CPU can put bytes in or
                // close its write end, and the wake that fact sends can fire
                // into the gap: a task parked after the wake it was waiting
                // for is a task parked for ever.  The re-check and the park
                // are one critical section, so the wake has only two orders
                // to find — the fact first, and this call answers it here,
                // or the task first, and the wake ends the wait.
                match crate::scheduler::block_unless(frame, || {
                    match end.try_read(&pipe, destination) {
                        Ok(crate::pipe::Progress::Done(count)) => Some(count),
                        Ok(crate::pipe::Progress::Block) => None,
                        Err(error) => Some(abi::syscall::encode_error(error)),
                    }
                }) {
                    // The wait answered itself: bytes arrived, or the write
                    // end closed, in the deciding moment.  The answer is the
                    // read's.
                    Some(answer) => CallOutcome::Return(answer),
                    None => {
                        // Parked.  Resume something else; the frame was
                        // saved, so a wake returns here and the call is
                        // retried by the program, which is what makes this a
                        // short read rather than a lost one.
                        arch::serial::write_str("protofire: a program blocks on a pipe\n");
                        if !crate::scheduler::has_selectable() {
                            // Nothing else can run: wait for the wake the
                            // same way a sleep waits for its deadline.
                            crate::scheduler::idle_until_woken();
                        }
                        // Install whatever can run next and answer with it.
                        // This task's frame was saved by the park, so the
                        // wake resumes the read.  The answer is the switch's,
                        // not `Exit` on a frame still describing this task:
                        // that shape resumed the reader at the instruction
                        // after its `svc` with the previous call's answer in
                        // its register, which is a read that never happened.
                        crate::scheduler::switch_without_saving(frame)
                    }
                }
            }
        };
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
        return match crate::scheduler::fork_current(frame) {
            Some(pid) => {
                arch::serial::write_str("protofire: forked a process, child pid ");
                arch::serial::write_u32(pid);
                arch::serial::write_str("\n");
                CallOutcome::Return(pid as usize)
            }
            None => CallOutcome::Return(abi::syscall::encode_error(abi::Error::OutOfMemory)),
        };
    }

    // Exec: the running process becomes the file it names.
    //
    // The argument is a NUL-terminated path in the caller's memory, copied
    // with the same bound and the same check the `Open` branch uses — an
    // address from ring 3 is a number until something validates it.  The
    // kernel reads the file through the registry's own namespace, loads it,
    // and maps it; the task keeps its pid and its parent, and everything else
    // is the new program's, which is the whole of what `exec` is.
    if number == SyscallNumber::ExecProcess as usize {
        let mut path_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(path) = copy_user_path(call.arguments[0], &mut path_bytes) else {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        };
        return match crate::scheduler::exec_current(frame, path) {
            Some(pid) => {
                // The one line that says the mechanism ran: the task that
                // called is the task named, and the file is the one it asked
                // to become.  A reader can pair this with the exit statuses —
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
        };
    }

    // Who is asking, and who started them.
    //
    // The answers come from the task the scheduler is running, not from the
    // call: a program does not send its own id, and one that could would be a
    // program answering a question about itself.
    if number == SyscallNumber::GetPid as usize {
        return match crate::scheduler::current_pid() {
            Some(pid) => CallOutcome::Return(pid as usize),
            None => CallOutcome::Return(abi::syscall::encode_error(abi::Error::NotImplemented)),
        };
    }

    if number == SyscallNumber::GetPpid as usize {
        return match crate::scheduler::current_parent() {
            Some(parent) => CallOutcome::Return(parent as usize),
            None => CallOutcome::Return(abi::syscall::encode_error(abi::Error::NotImplemented)),
        };
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
            return CallOutcome::Return(status);
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
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::NotFound));
        }
        // Park — with the same re-check the pipe's read parks under.  The
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
                // immediate answer above is — a wait that answered and a wait
                // that never ran print the same status line otherwise.
                arch::serial::write_str("protofire: a wait answered status ");
                arch::serial::write_u32(status as u32);
                arch::serial::write_str("\n");
                return CallOutcome::Return(status);
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
                // before left — the wait skipped, and the program exits with
                // a number the wait never answered.  The sleep path answers
                // the switch this way and has always worked; this branch and
                // the pipe's read were the two that did not.
                return crate::scheduler::switch_without_saving(frame);
            }
        }
    }

    // Waiting for **one named** process: `WaitProcessOf(pid)`.
    //
    // The other half of the wait pair.  `WaitProcess` answers about whichever
    // process finished first, which is all a boot with one process tree could
    // say when it was added — and it is the wrong answer for a parent asking
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
    if number == SyscallNumber::InstallExceptionHandler as usize {
        // `InstallExceptionHandler(address)`: the program takes its own faults
        // from here on, and `0` withdraws the handler.  A fault after this is
        // the program's to answer; the kernel reports the hand-off and resumes
        // the program at the address it named.
        let address = call.arguments[0];
        if !crate::scheduler::install_exception_handler(address) {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::NotFound));
        }
        arch::serial::write_str("protofire: process ");
        arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
        if address == 0 {
            arch::serial::write_str(" withdrew its fault handler\n");
        } else {
            arch::serial::write_str(" installed a fault handler at ");
            arch::serial::write_hex(address as u64);
            arch::serial::write_str("\n");
        }
        return CallOutcome::Return(0);
    }

    if number == SyscallNumber::ReturnFromException as usize {
        // `ReturnFromException(value)`: the handler is done, and the value is
        // the call's answer.  The trap path resumes the handler's caller,
        // which is the program at the instruction after this `svc`.
        // `ReturnFromException(resume, value)`: where the handler wants the
        // program to continue, and the call's answer.  The handler supplies
        // both because the address is a fact about the program's own
        // instructions — a fixed-width machine could add one size, x86_64
        // cannot.
        crate::scheduler::return_from_exception(call.arguments[0], call.arguments[1], frame);
        return CallOutcome::Exit;
    }

    if number == SyscallNumber::WaitProcessOf as usize {
        let pid = call.arguments[0] as u32;
        match crate::scheduler::block_unless_pid(frame, pid) {
            Some(crate::scheduler::PidWait::Ended(status)) => {
                arch::serial::write_str("protofire: a wait answered status ");
                arch::serial::write_u32(status as u32);
                arch::serial::write_str(" for process ");
                arch::serial::write_u32(pid);
                arch::serial::write_str("\n");
                return CallOutcome::Return(status);
            }
            Some(crate::scheduler::PidWait::NoSuchProcess) => {
                arch::serial::write_str("protofire: a wait names a process that does not exist\n");
                return CallOutcome::Return(abi::syscall::encode_error(abi::Error::NotFound));
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
                return crate::scheduler::switch_without_saving(frame);
            }
            // No scheduler: nothing can be waited for, and the honest answer
            // is the one a host build gives for anything it cannot serve.
            None => {
                return CallOutcome::Return(abi::syscall::encode_error(abi::Error::NotImplemented));
            }
        }
    }

    if number == SyscallNumber::Pipe as usize {
        // `Pipe()`: make one and answer the read end's descriptor.  The write
        // end is the next number, because a call answers one word and two
        // descriptors do not fit in one.
        //
        // A file can be read at an offset and answered from memory; the answer
        // is there before the call.  A pipe's answer may not exist yet, and
        // that is the whole difference this call exists to make real.
        let pipe = alloc::sync::Arc::new(crate::pipe::Pipe::new(ipc::DEFAULT_PIPE_CAPACITY));
        // Two handles on one buffer, and the pipe's own counts follow: it is
        // created with one reader and one writer, which is exactly the pair
        // this makes.
        // The caller owns both ends: a program that makes a pipe and exits
        // without closing it leaves nothing behind, and the reader of the end
        // it wrote to sees end-of-file.
        let owner = crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS);
        let Some(read) = crate::pipe::attach(crate::pipe::End::reader(pipe.clone()), owner) else {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::OutOfMemory));
        };
        let Some(write) = crate::pipe::attach(crate::pipe::End::writer(pipe), owner) else {
            // The read end is already in the table, and a call that answered an
            // error has no descriptor to give back: leaving it there is a slot
            // a program can never name or close, and a program that retried
            // would leak one per attempt.  `Close` is the same release the
            // caller would have made.
            let mut context =
                syscall::SyscallContext::new(SyscallNumber::Close as usize, [read, 0, 0, 0, 0, 0])
                    .with_identity(security::mac::MAC_TYPE_SYSTEM)
                    .with_caller(
                        crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS),
                    );
            let _ = through_registry(&mut context, None, None);
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::OutOfMemory));
        };
        arch::serial::write_str("protofire: pipe made, read ");
        arch::serial::write_u32(read as u32);
        arch::serial::write_str(", write ");
        arch::serial::write_u32(write as u32);
        arch::serial::write_str("\n");
        // The read end goes in `rax` and the write end above it: the ABI
        // answers one word, and a program reads both from one number rather
        // than making a second call that could not know which pipe it meant.
        return CallOutcome::Return(read | (write << 16));
    }

    // The registry's calls, from a program that has no borrow to hand anyone.
    //
    // The registry's handlers take `Arguments`, whose address-shaped fields are
    // *borrows* — a shape that exists precisely so no handler ever turns a
    // word into a pointer.  A program cannot hand over a borrow: it hands over
    // words, and this is the one place that turns them back, behind the check
    // that makes the turn sound.  `is_user_range` says the range is one a
    // program of this kernel could have mapped; the pages behind it are the
    // calling task's own, installed on this CPU, and a write into one that
    // copy-on-write demoted faults into the resolver, which is why that path
    // exists.
    if number == SyscallNumber::Open as usize {
        // `Open(path, flags)`: the path is a NUL-terminated string in the
        // caller's memory, the flags are the ABI's own open flags, and the two
        // reserved slots stay zero.  A NUL-terminated path needs no length
        // slot, which is what keeps the kernel-side shape — path as a borrow,
        // flags in the first argument — and the ring-3 shape one shape.
        let flags = call.arguments[1];
        let mut path_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(path) = copy_user_path(call.arguments[0], &mut path_bytes) else {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        };

        // The caller's identity is the boot's own label.  A program this boot
        // started speaks with the boot's voice; there is no per-process label
        // yet, and the change that introduces one is the change that decides
        // what a program is allowed to be.
        let mut context = syscall::SyscallContext::new(number, [0, flags, 0, 0, 0, 0])
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, Some(path), None);
        if let CallOutcome::Return(descriptor) = outcome {
            // **Only a descriptor is an open.**  The registry answers an error
            // the same way it answers a value — the ABI's error encoding is a
            // number near `usize::MAX` — so a caller that printed the line
            // without asking printed "opened /greeting.txt" for a path the
            // namespace had refused.  The gate's own evidence then said the
            // mechanism ran when what ran was the refusal, which is the failure
            // mode this tree's rules name: a claim no gate exercises.
            if !abi::syscall::is_error_status(descriptor) {
                arch::serial::write_str("protofire: process ");
                arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
                arch::serial::write_str(" opened ");
                arch::serial::write_str(path);
                arch::serial::write_str("\n");
            }
            return CallOutcome::Return(descriptor);
        }
        return outcome;
    }

    if number == SyscallNumber::Read as usize && !crate::pipe::lookup(call.arguments[0]).is_some() {
        // `Read(descriptor, offset, buffer, length)`: a file descriptor in the
        // registry's table, the buffer a range of the caller's own memory.  A
        // pipe descriptor never reaches here — the branch above answered it —
        // and the registry answers `InvalidArgument` for one anyway, because a
        // pipe's read is the pipe's to block on.
        let buffer = call.arguments[2];
        let length = call.arguments[3];
        if length == 0 {
            return CallOutcome::Return(0);
        }
        if !crate::address_space::is_user_range(buffer, length) {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        }
        let mut context = syscall::SyscallContext::new(
            number,
            [call.arguments[0], call.arguments[1], buffer, length, 0, 0],
        )
        .with_identity(security::mac::MAC_TYPE_SYSTEM)
        .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        // SAFETY: the range is inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind it are the calling
        // task's own mappings, installed on this CPU.  The handler writes only
        // what the filesystem read.
        let destination = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, length) };
        return through_registry(&mut context, None, Some(destination));
    }

    if number == SyscallNumber::Close as usize {
        // `Close(descriptor)`: the registry returns the slot, whether it named
        // a file or a pipe's end.  Dropping the end is the pipe's own
        // accounting moving, which is what makes a reader's end-of-file real.
        //
        // The end is recognised **before** the close: afterwards the descriptor
        // is gone and no answer could tell a pipe's write end from a file's.
        // A write end going away is the fact a blocked reader is parked waiting
        // to learn — no bytes are ever coming — so the close wakes what a
        // write would have woken.  Waking a reader whose pipe still has
        // another write handle is harmless: it retries its read, sees a
        // writer, and parks again.
        let closes_a_write_end = crate::pipe::lookup(call.arguments[0])
            .is_some_and(|end| end.kind() == crate::pipe::Kind::Write);
        let mut context = syscall::SyscallContext::new(number, [call.arguments[0], 0, 0, 0, 0, 0])
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, None, None);
        if closes_a_write_end && matches!(outcome, CallOutcome::Return(0)) {
            let woken = crate::scheduler::wake_blocked();
            // Reported whether or not anyone was blocked, for the reason the
            // write's wake is: the count is the fact, and a zero means the
            // reader was already awake.  A line printed only on the non-zero
            // case would depend on an interleaving rather than on the close
            // having happened.
            arch::serial::write_str("protofire: a close woke ");
            arch::serial::write_u32(woken as u32);
            arch::serial::write_str(" blocked task(s)\n");
            if woken > 0 {
                // The task that woke may be held by another CPU parked in a
                // wait, and only the IPI ends that wait.
                // SAFETY: the boot's own IPI path, installed before any
                // program ran.
                unsafe { arch::send_ipi_to_others() };
            }
        }
        return outcome;
    }

    // Everything else is a call this boot does not serve.  `encode_error` is
    // the ABI's own encoding, so the program reads the same word it would from
    // a handler that answered through the registry.
    CallOutcome::Return(abi::syscall::encode_error(abi::Error::NotImplemented))
}

/// Copy a NUL-terminated path out of the caller's memory, answering it as a
/// `&str` that borrows the buffer the caller hands in.
///
/// One shape for both `Open` and `ExecProcess`, which take the same kind of
/// argument: an address in the caller's memory.  Every byte is checked against
/// the user window before it is read, the length is bounded, the string must
/// be UTF-8, and the copy happens once — the caller's bytes are the kernel's
/// for the length of the call, which is what makes the rest of the handler
/// ordinary kernel code.  The buffer is the caller's: the borrow must not
/// outlive the stack slot the copied bytes live in.
#[cfg(target_os = "none")]
fn copy_user_path(path_ptr: usize, bytes: &mut [u8; OPEN_PATH_MAX]) -> Result<&str, abi::Error> {
    let mut length = 0;
    loop {
        if length == OPEN_PATH_MAX || !crate::address_space::is_user_range(path_ptr + length, 1) {
            return Err(abi::Error::InvalidArgument);
        }
        // SAFETY: the byte is inside the user window, which `is_user_range`
        // just checked, and the pages behind it are the calling task's own
        // mappings, installed on this CPU.
        let byte = unsafe { *((path_ptr + length) as *const u8) };
        bytes[length] = byte;
        if byte == 0 {
            break;
        }
        length += 1;
    }
    core::str::from_utf8(&bytes[..length]).map_err(|_| abi::Error::InvalidArgument)
}

/// The longest path a ring-3 `Open` or `ExecProcess` may name.
///
/// The registry's [`PATH_MAX`](crate::syscall::PATH_MAX) is the format's bound;
/// this is the copy's, because the copy happens on a trap stack that one page
/// of memory has to hold, frame and all.  A path this kernel mounts is a few
/// dozen bytes, and a caller that needs more is a caller a later change can
/// serve from the heap.
#[cfg(target_os = "none")]
const OPEN_PATH_MAX: usize = 128;

#[cfg(target_os = "none")]
/// Hand a built context to the installed registry, and turn its answer into
/// the outcome a program reads.
///
/// One spelling of the registry round-trip: the success value goes back as the
/// call's answer, a registry error goes back encoded the ABI's own way, and no
/// registry at all answers `NotImplemented`, which is the same word the
/// fallthrough below answers for a number no handler serves.
fn through_registry(
    context: &mut syscall::SyscallContext,
    path: Option<&str>,
    buffer: Option<&mut [u8]>,
) -> arch::CallOutcome {
    let mut arguments = crate::syscall::Arguments {
        context,
        path,
        buffer,
    };
    match crate::syscall::serve(&mut arguments) {
        Some(Ok(dispatch)) => arch::CallOutcome::Return(dispatch.value),
        Some(Err(error)) => arch::CallOutcome::Return(abi::syscall::encode_error(error)),
        None => arch::CallOutcome::Return(abi::syscall::encode_error(abi::Error::NotImplemented)),
    }
}

/// What the program's `Write` prints.
///
/// Fixed, and the program passes no pointer: a program's buffer is an address
/// in ring 3, and this kernel has no way to check one yet.  A handler that
/// dereferenced `x1` would be reading whatever the program put there, which is
/// the promise `kernel/src/syscall/mod.rs` refuses to make, and this is the
/// same refusal one layer down.
/// The length `Write` answers with.
///
/// A program compares nothing today, the return path is proven by the exit
/// status of a program that does, but the number is what the call answers and
/// a program that read `x0` would find it here.
#[cfg(target_os = "none")]
const PROGRAM_OUTPUT: usize = 21;

#[cfg(test)]
mod tests {
    /// A program's pages are in its own window, and two windows do not overlap.
    ///
    /// The spacing is what makes an overrun visible: two programs at one
    /// address would be two whose virtual addresses collide, and a fault in one
    /// would read as a fault in the other.
    #[test]
    fn two_programs_get_different_windows() {
        let one = super::program_base(1);
        let two = super::program_base(2);
        assert_ne!(one, two);
        assert!(one >= crate::address_space::USER_BASE);
        assert!(
            two - one >= 0x4000_0000,
            "a gigabyte apart, so an overrun does not reach the next program"
        );
        assert!(super::program_stack_top(1) > super::program_base(1));
        assert!(super::program_stack_top(1) < super::program_base(2));
        assert!(
            super::program_stack_page(1) < super::program_stack_top(1),
            "the stack page is below the pointer that starts in it"
        );
    }
}
