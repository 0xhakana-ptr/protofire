//! kernel/src/process.rs
//!
//! One program, running at EL0, calling back into the kernel.
//!
//! What the kernel does with a program's supervisor call: two kinds of
//! answer.  The calls whose object lives in the scheduler or the pipe —
//! `Exit`, `Sleep`, a pipe's `Read` and `Write`, `Fork`, `ExecProcess`,
//! `GetPid`, `GetPpid`, the three waits and `Pipe` — are served here,
//! because their object is.  Everything else is forwarded to the registry's
//! table, after this file has done the one thing only it can do: turned the
//! ring-3 words into the borrows the handlers take.  A number with neither
//! a branch here nor a handler in the table answers `NotImplemented`.
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
    // Every call that reaches the descriptor table is the running process's,
    // and the table checks that the descriptor belongs to it.  One binding, so
    // a path that forgets it cannot pass the wrong one.
    let caller = crate::scheduler::current_pid();

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
        && crate::pipe::lookup_for(call.arguments[0], caller).is_some()
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
        let Some(end) = crate::pipe::lookup_for(descriptor, caller) else {
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

    // A write to a stream: the bytes go out as one segment, and the answer
    // is the count.  Reached only when the pipe branch above did not
    // return, so the descriptor names a stream the table holds — or it
    // names nothing, and the branch's own test refuses it before a byte is
    // read.
    if number == SyscallNumber::Write as usize
        && call.arguments[2] != 0
        && crate::syscall::tcp_stream_for(call.arguments[0], caller).is_some()
    {
        let descriptor = call.arguments[0];
        let buffer = call.arguments[1];
        let length = call.arguments[2];
        if !crate::address_space::is_user_range(buffer, length) {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        }
        let Some(stream) = crate::syscall::tcp_stream_for(descriptor, caller) else {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        };
        // SAFETY: the range is inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind it are the calling
        // task's own mappings, installed on this CPU.  The stream's send
        // reads the bytes; a copy-on-write page demoted by an earlier write
        // faults into the resolver like any other access.
        let source = unsafe { core::slice::from_raw_parts(buffer as *const u8, length) };
        return match crate::net::tcp_write(stream, source) {
            Ok(count) => {
                arch::serial::write_str("protofire: process ");
                arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
                arch::serial::write_str(" wrote ");
                arch::serial::write_u32(count as u32);
                arch::serial::write_str(" byte(s) to a stream\n");
                CallOutcome::Return(count)
            }
            Err(error) => CallOutcome::Return(abi::syscall::encode_error(error)),
        };
    }

    if number == SyscallNumber::Write as usize && call.arguments[2] != 0 {
        // `Write(descriptor, buffer, length)` to a file, through the registry.
        //
        // Reached only when the pipe branch above did not return, so the
        // descriptor names no pipe of this caller's: it names a file the table
        // holds, or it names nothing, and the registry answers the same
        // refusal for both — the answer that does not tell a caller which
        // numbers exist.  The length is what distinguishes a write from the
        // announcement below, the same distinction the pipe branch reads, and
        // the validation is the read's, for the same reason: an address from
        // ring 3 is a number until something checks it.
        let buffer = call.arguments[1];
        let length = call.arguments[2];
        if !crate::address_space::is_user_range(buffer, length) {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        }
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        // SAFETY: the range is inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind it are the calling
        // task's own mappings, installed on this CPU.  The handler reads the
        // bytes; a copy-on-write page demoted by an earlier write faults into
        // the resolver like any other access.
        let source = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, length) };
        let outcome = through_registry(&mut context, None, None, Some(source));
        if let CallOutcome::Return(count) = outcome
            && !abi::syscall::is_error_status(count)
        {
            // The evidence, printed by the kernel because a program has no
            // other way into this log: a count is only a proof of writing if
            // someone can read it next to the file that holds the bytes.
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(" wrote ");
            arch::serial::write_u32(count as u32);
            arch::serial::write_str(" byte(s) to a file\n");
        }
        return outcome;
    }

    if number == SyscallNumber::Write as usize {
        // The no-length case: a `Write` whose third argument is zero names no
        // bytes, so it is not a write, and it is the announcement.
        //
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

    if number == SyscallNumber::Read as usize
        && crate::pipe::lookup_for(call.arguments[0], caller).is_some()
    {
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
        let Some(end) = crate::pipe::lookup_for(descriptor, caller) else {
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

    // Starting a process the caller chose, rather than becoming one.
    //
    // `ExecProcess` replaces the calling task; `SpawnProcess` grows the
    // machine by one task that did not exist, named by the file the caller
    // picked, and answers the pid — which is the number a supervisor needs,
    // because the wait that supervises names a pid.
    if number == SyscallNumber::SpawnProcess as usize {
        let mut path_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(path) = copy_user_path(call.arguments[0], &mut path_bytes) else {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        };
        match crate::scheduler::spawn_process(path) {
            Some(pid) => {
                // The one line that says the machine grew: the caller, the
                // file it named, and the pid the kernel answered — the
                // number a later wait carries.
                arch::serial::write_str("protofire: process ");
                arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
                arch::serial::write_str(" spawned ");
                arch::serial::write_str(path);
                arch::serial::write_str(" as pid ");
                arch::serial::write_u32(pid);
                arch::serial::write_str("\n");
                return CallOutcome::Return(pid as usize);
            }
            // The same answer exec gives for a machine that could not: no
            // scheduler, no file, or a pool too empty to build the space.
            None => {
                return CallOutcome::Return(abi::syscall::encode_error(abi::Error::OutOfMemory));
            }
        }
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

    // Sending a signal: the target's ring takes the record and the wake
    // runs.  The signal's range and the flags are the ABI's, and a process
    // signalling itself is allowed — the shell does exactly that.
    if number == SyscallNumber::SendSignal as usize {
        let pid = call.arguments[0] as u32;
        let signal = call.arguments[1];
        let payload = call.arguments[2];
        if !abi::process::is_valid_process_signal(signal) {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        }
        if syscall::validate_known_flags(
            call.arguments[3],
            abi::process::PROCESS_SIGNAL_KNOWN_FLAGS,
        )
        .is_err()
        {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        }
        let sender = crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS);
        match crate::scheduler::send_signal(sender, pid, signal, payload) {
            Ok(()) => {
                arch::serial::write_str("protofire: process ");
                arch::serial::write_u32(sender);
                arch::serial::write_str(" sent signal ");
                arch::serial::write_u32(signal as u32);
                arch::serial::write_str(" to process ");
                arch::serial::write_u32(pid);
                arch::serial::write_str("\n");
                return CallOutcome::Return(0);
            }
            Err(error) => {
                return CallOutcome::Return(abi::syscall::encode_error(error));
            }
        }
    }

    if number == SyscallNumber::WaitSignal as usize {
        // Waiting for one: the record is where the kernel writes the ABI's
        // `ProcessSignalRecord` — signal, sender, payload — and the wait
        // parks on the ring, woken by the send that fills it.  The retry is
        // the WaitProcess shape: the parked call resumes at the call, and
        // the retry asks the ring again.
        let record = call.arguments[0];
        let length = call.arguments[1];
        if length < SIGNAL_RECORD_BYTES {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        }
        if !crate::address_space::is_user_range(record, length) {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        }
        // SAFETY: the range is inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind it are the calling
        // task's own mappings, installed on this CPU.  The handler writes
        // the record and nothing past it.
        let destination = unsafe { core::slice::from_raw_parts_mut(record as *mut u8, length) };
        match crate::scheduler::wait_signal(frame) {
            Some((signal, sender_pid, payload)) => {
                write_signal_record(destination, signal, sender_pid, payload);
                arch::serial::write_str("protofire: a signal wait answered signal ");
                arch::serial::write_u32(signal as u32);
                arch::serial::write_str(" from process ");
                arch::serial::write_u32(sender_pid);
                arch::serial::write_str("\n");
                return CallOutcome::Return(0);
            }
            // Parked: the send's wake resumes the call for a retry.
            None => {
                if !crate::scheduler::has_selectable() {
                    crate::scheduler::idle_until_woken();
                }
                return crate::scheduler::switch_without_saving(frame);
            }
        }
    }

    // The mask, and the suspend that runs a ring under one.  Both take the
    // mask as a bit-per-signal word; the mask's known set is the signals'
    // own range, and a bit outside it is a signal this ABI does not define.
    if number == SyscallNumber::SetSignalMask as usize {
        let mask = call.arguments[0];
        let flags = call.arguments[1];
        if syscall::validate_known_flags(flags, abi::process::PROCESS_SIGNAL_KNOWN_FLAGS).is_err()
            || mask & !SIGNAL_KNOWN_MASK != 0
        {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        }
        let previous = crate::scheduler::set_signal_mask(mask as u32);
        return CallOutcome::Return(previous as usize);
    }

    if number == SyscallNumber::SigSuspend as usize {
        let mask = call.arguments[0];
        let flags = call.arguments[1];
        if syscall::validate_known_flags(flags, abi::process::PROCESS_SIGNAL_KNOWN_FLAGS).is_err()
            || mask & !SIGNAL_KNOWN_MASK != 0
        {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        }
        let record = call.arguments[2];
        let length = call.arguments[3];
        if length < SIGNAL_RECORD_BYTES {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        }
        if !crate::address_space::is_user_range(record, length) {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        }
        // SAFETY: the range is inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind it are the calling
        // task's own mappings, installed on this CPU.
        let destination = unsafe { core::slice::from_raw_parts_mut(record as *mut u8, length) };
        match crate::scheduler::sigsuspend(frame, mask as u32) {
            Some((signal, sender_pid, payload)) => {
                write_signal_record(destination, signal, sender_pid, payload);
                arch::serial::write_str("protofire: a suspend answered signal ");
                arch::serial::write_u32(signal as u32);
                arch::serial::write_str(" from process ");
                arch::serial::write_u32(sender_pid);
                arch::serial::write_str(", mask put back\n");
                return CallOutcome::Return(0);
            }
            None => {
                if !crate::scheduler::has_selectable() {
                    crate::scheduler::idle_until_woken();
                }
                return crate::scheduler::switch_without_saving(frame);
            }
        }
    }

    // Arming, and disarming, the handler a program's own code provides for
    // one signal.  The contract is the exception handler's, which is why the
    // address needs no trust the fault path did not already extend: the
    // handler runs in the program, on the program's stack, and its way out
    // is `ReturnFromException`.
    if number == SyscallNumber::SetSignalHandler as usize {
        let signal = call.arguments[0];
        let action = call.arguments[1];
        let handler = call.arguments[2];
        let taken = action <= 1
            && syscall::validate_known_flags(
                call.arguments[3],
                abi::process::PROCESS_SIGNAL_KNOWN_FLAGS,
            )
            .is_ok()
            && crate::scheduler::set_signal_handler(signal, action, handler);
        if taken {
            return CallOutcome::Return(0);
        }
        return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
    }

    if number == SyscallNumber::SigReturn as usize {
        // The delivered-signal handler's exit, and the half that makes the
        // delivery **transparent**: the delivery displaced the program's
        // argument registers for its record, and only the kernel kept them.
        // They go back here, and the interrupted flow resumes at `a0` — the
        // resume the delivery handed the handler — with the registers it
        // would have had had the signal never arrived.
        if !crate::scheduler::signal_return(frame, call.arguments[0]) {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        }
        return CallOutcome::Exit;
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
            let _ = through_registry(&mut context, None, None, None);
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
        let outcome = through_registry(&mut context, Some(path), None, None);
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

    if number == SyscallNumber::Read as usize
        && crate::pipe::lookup_for(call.arguments[0], caller).is_none()
        && crate::syscall::tcp_stream_for(call.arguments[0], caller).is_none()
    {
        // `Read(descriptor, offset, buffer, length)`: a file descriptor in the
        // registry's table, the buffer a range of the caller's own memory.  A
        // pipe descriptor never reaches here — the branch above answered it —
        // and a stream descriptor never does either, because its read is the
        // stream's to park on.  The registry answers `InvalidArgument` for
        // both anyway, because their reads are not the file's to serve.
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
        return through_registry(&mut context, None, None, Some(destination));
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
        let closes_a_write_end = crate::pipe::lookup_for(call.arguments[0], caller)
            .is_some_and(|end| end.kind() == crate::pipe::Kind::Write);
        let mut context = syscall::SyscallContext::new(number, [call.arguments[0], 0, 0, 0, 0, 0])
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, None, None, None);
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

    if number == SyscallNumber::Stat as usize {
        // `Stat(path, record, length)`: the path is a NUL-terminated string in
        // the caller's memory, the record is where the kernel writes the ABI's
        // sixteen-byte `FileStat`, and the length is how much room the caller
        // made.  The copy is the `Open` branch's, and so is the reason for it.
        let mut path_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(path) = copy_user_path(call.arguments[0], &mut path_bytes) else {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        };
        let record = call.arguments[1];
        let length = call.arguments[2];
        if !crate::address_space::is_user_range(record, length) {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        }
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        // SAFETY: the range is inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind it are the calling
        // task's own mappings, installed on this CPU.  The handler writes the
        // record and nothing past it.
        let destination = unsafe { core::slice::from_raw_parts_mut(record as *mut u8, length) };
        let outcome = through_registry(&mut context, Some(path), None, Some(destination));
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
            && let (Ok(kind), Ok(size)) = (
                destination[..8].try_into().map(usize::from_le_bytes),
                destination[8..16].try_into().map(usize::from_le_bytes),
            )
        {
            // The record reached the caller's memory, and the borrow that
            // carried it can be read back here: the line is the kernel
            // reporting what it answered, so the boot log carries the fact
            // without trusting the program to report it.
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(" stat'd ");
            arch::serial::write_str(path);
            arch::serial::write_str(", kind ");
            arch::serial::write_str(stat_kind_name(kind));
            arch::serial::write_str(", size ");
            arch::serial::write_u32(size as u32);
            arch::serial::write_str("\n");
        }
        return outcome;
    }

    // The path mutations: make a directory, take a name away, move a name.
    // They take paths the same way `Open` and `Stat` do, and the rename's
    // second path is the one call whose path borrow arrives in a second slot.
    if number == SyscallNumber::CreateDir as usize || number == SyscallNumber::RemovePath as usize {
        let mut path_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(path) = copy_user_path(call.arguments[0], &mut path_bytes) else {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        };
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, Some(path), None, None);
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
        {
            let verb = if number == SyscallNumber::CreateDir as usize {
                "created directory"
            } else {
                "removed"
            };
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(" ");
            arch::serial::write_str(verb);
            arch::serial::write_str(" ");
            arch::serial::write_str(path);
            arch::serial::write_str("\n");
        }
        return outcome;
    }

    if number == SyscallNumber::Rename as usize {
        let mut old_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(old_path) = copy_user_path(call.arguments[0], &mut old_bytes) else {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        };
        let mut new_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(new_path) = copy_user_path(call.arguments[1], &mut new_bytes) else {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        };
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, Some(old_path), Some(new_path), None);
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
        {
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(" renamed ");
            arch::serial::write_str(old_path);
            arch::serial::write_str(" to ");
            arch::serial::write_str(new_path);
            arch::serial::write_str("\n");
        }
        return outcome;
    }

    if number == SyscallNumber::ReadDir as usize {
        // `ReadDir(path, index, buffer, length)`: one entry of the directory
        // at the path, written into the caller's buffer as the ABI's record
        // with the name packed after it.  The answer is the bytes written,
        // and the evidence line names the path and the index — the entry's
        // name is in the record the caller now holds.
        let mut path_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(path) = copy_user_path(call.arguments[0], &mut path_bytes) else {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        };
        let buffer = call.arguments[2];
        let length = call.arguments[3];
        if !crate::address_space::is_user_range(buffer, length) {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        }
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        // SAFETY: the range is inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind it are the calling
        // task's own mappings, installed on this CPU.  The handler writes the
        // record and the name, and nothing past either.
        let destination = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, length) };
        let outcome = through_registry(&mut context, Some(path), None, Some(destination));
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
        {
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(" read ");
            arch::serial::write_str(path);
            arch::serial::write_str(" entry ");
            arch::serial::write_u32(call.arguments[1] as u32);
            arch::serial::write_str("\n");
        }
        return outcome;
    }

    // The `*At` calls: the same five operations their plain twins serve, with
    // the path anchored at a descriptor instead of at the root.  The
    // descriptor travels in the first argument, the path in the second —
    // including for the rename, whose second name brings its own anchor in
    // the third.
    if number == SyscallNumber::OpenAt as usize
        || number == SyscallNumber::CreateDirAt as usize
        || number == SyscallNumber::RemovePathAt as usize
    {
        let mut path_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(path) = copy_user_path(call.arguments[1], &mut path_bytes) else {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        };
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, Some(path), None, None);
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
        {
            let verb = match number {
                n if n == SyscallNumber::OpenAt as usize => "opened",
                n if n == SyscallNumber::CreateDirAt as usize => "created directory",
                _ => "removed",
            };
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(" ");
            arch::serial::write_str(verb);
            arch::serial::write_str(" ");
            arch::serial::write_str(path);
            arch::serial::write_str(" via descriptor ");
            arch::serial::write_u32(call.arguments[0] as u32);
            arch::serial::write_str("\n");
        }
        return outcome;
    }

    if number == SyscallNumber::StatAt as usize {
        let mut path_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(path) = copy_user_path(call.arguments[1], &mut path_bytes) else {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        };
        let record = call.arguments[2];
        let length = call.arguments[3];
        if !crate::address_space::is_user_range(record, length) {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        }
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        // SAFETY: the range is inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind it are the calling
        // task's own mappings, installed on this CPU.  The handler writes the
        // record and nothing past it.
        let destination = unsafe { core::slice::from_raw_parts_mut(record as *mut u8, length) };
        let outcome = through_registry(&mut context, Some(path), None, Some(destination));
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
            && let (Ok(kind), Ok(size)) = (
                destination[..8].try_into().map(usize::from_le_bytes),
                destination[8..16].try_into().map(usize::from_le_bytes),
            )
        {
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(" stat'd ");
            arch::serial::write_str(path);
            arch::serial::write_str(" via descriptor ");
            arch::serial::write_u32(call.arguments[0] as u32);
            arch::serial::write_str(", kind ");
            arch::serial::write_str(stat_kind_name(kind));
            arch::serial::write_str(", size ");
            arch::serial::write_u32(size as u32);
            arch::serial::write_str("\n");
        }
        return outcome;
    }

    if number == SyscallNumber::RenameAt as usize {
        let mut old_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(old_path) = copy_user_path(call.arguments[1], &mut old_bytes) else {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        };
        let mut new_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(new_path) = copy_user_path(call.arguments[3], &mut new_bytes) else {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        };
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, Some(old_path), Some(new_path), None);
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
        {
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(" renamed ");
            arch::serial::write_str(old_path);
            arch::serial::write_str(" via descriptor ");
            arch::serial::write_u32(call.arguments[0] as u32);
            arch::serial::write_str(" to ");
            arch::serial::write_str(new_path);
            arch::serial::write_str(" via descriptor ");
            arch::serial::write_u32(call.arguments[2] as u32);
            arch::serial::write_str("\n");
        }
        return outcome;
    }

    // The memory calls, in one block because they share everything but their
    // number: none takes a pointer, so each rebuilds the argument words and
    // hands them straight to the registry.
    //
    // **This branch is what makes them reachable.**  `MacGetStatus` and its two
    // siblings are registered in the same table and have no branch here, so a
    // program that calls one gets `NotImplemented` from the fallthrough below
    // and nothing says why.  A handler is reachable from ring 3 only when this
    // function forwards to it.
    if number == SyscallNumber::Mmap as usize
        || number == SyscallNumber::Munmap as usize
        || number == SyscallNumber::Brk as usize
        || number == SyscallNumber::ReclaimPages as usize
    {
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, None, None, None);
        // The answer, printed by the kernel because a program has no way to
        // print one: `Write` prints a fixed line, so a value a program obtained
        // would otherwise reach this log only through its exit status — and an
        // exit status is one byte.
        //
        // The pair of lines is the evidence that the call went **through the
        // page tables** rather than returning a plausible number: `mmap`'s base
        // and `brk`'s answer are addresses inside the program's own window, and
        // a kernel that had not mapped anything could not name them.
        if let CallOutcome::Return(answer) = outcome {
            let is_error = abi::syscall::is_error_status(answer);
            arch::serial::write_str("protofire: program memory call ");
            arch::serial::write_u32(number as u32);
            arch::serial::write_str(" answered ");
            arch::serial::write_hex(answer as u64);
            arch::serial::write_str(if is_error { " (error)\n" } else { "\n" });
        }
        return outcome;
    }

    // The time, randomness and the two information calls.  All four write a
    // record into a buffer the caller named, so all four need the one thing
    // only this file can do: turn a ring-3 address into a borrow, after
    // checking the range.
    //
    // `GetRandom` is the one call in this group whose *length* arrives in the
    // same slot its buffer does not: `a0` is the buffer and `a1` the length,
    // which is the shape the ABI published for it and the shape the handler
    // reads.  The other three take the record and its length in `a1`/`a2` (and
    // `a0` is the clock or the selector), so the pair to validate is the second
    // and third words rather than the first two.
    if number == SyscallNumber::GetTimeOfDay as usize
        || number == SyscallNumber::GetRandom as usize
        || number == SyscallNumber::SystemInfo as usize
        || number == SyscallNumber::AbiInfo as usize
        || number == SyscallNumber::NetworkStatus as usize
        || number == SyscallNumber::Ipv6Status as usize
    {
        // `GetRandom` names its buffer and its length in `a0`/`a1`.  `AbiInfo`
        // and `NetworkStatus` name the record in `a0` and its length in `a1`,
        // because neither has a selector to make room for.  `GetTimeOfDay`
        // and `SystemInfo` each have one, so their record and length are
        // `a1`/`a2`.  Reading the wrong pair here validates an address that
        // is not the buffer, and the refusal it produces looks exactly like
        // a machine that does not serve the call.
        let (record, length) = match number {
            n if n == SyscallNumber::GetRandom as usize => (call.arguments[0], call.arguments[1]),
            n if n == SyscallNumber::AbiInfo as usize => (call.arguments[0], call.arguments[1]),
            n if n == SyscallNumber::NetworkStatus as usize => {
                (call.arguments[0], call.arguments[1])
            }
            // The same shape as `NetworkStatus`: the record in `a0` and its
            // length in `a1`, because this call has no selector to make room
            // for either.
            n if n == SyscallNumber::Ipv6Status as usize => (call.arguments[0], call.arguments[1]),
            _ => (call.arguments[1], call.arguments[2]),
        };
        if !crate::address_space::is_user_range(record, length) {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        }
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        // SAFETY: the range is inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind it are the calling
        // task's own mappings, installed on this CPU.  The handlers write the
        // record and nothing past it, which is what their length check is for.
        let destination = unsafe { core::slice::from_raw_parts_mut(record as *mut u8, length) };
        let outcome = through_registry(&mut context, None, None, Some(destination));
        // The evidence, printed by the kernel because a program has no way to
        // print one.  The line names the call and the first word of what it
        // answered, which is the part that cannot be a constant: a time's
        // seconds move, and a random call's first word is bytes the generator
        // produced.
        //
        // A refused call prints too.  Without that, a call the handler refused
        // is indistinguishable in the log from one the program never made —
        // which is exactly the ambiguity the first boot of this group had, and
        // it cost a boot to find.
        if let CallOutcome::Return(answer) = outcome {
            let refused = abi::syscall::is_error_status(answer);
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(match number {
                n if n == SyscallNumber::GetTimeOfDay as usize => " read the clock, ",
                n if n == SyscallNumber::GetRandom as usize => " drew random bytes, ",
                n if n == SyscallNumber::SystemInfo as usize => " asked the system, ",
                n if n == SyscallNumber::NetworkStatus as usize => " asked the network, ",
                n if n == SyscallNumber::Ipv6Status as usize => " asked the ipv6 side, ",
                _ => " asked the ABI, ",
            });
            arch::serial::write_u32(length as u32);
            arch::serial::write_str(if refused {
                " byte(s) asked, refused\n"
            } else {
                " byte(s)\n"
            });
        }
        return outcome;
    }

    // The datagram calls that answer at once: a bind, and a send.  The
    // receive is the branch below, because it parks — a handler that cannot
    // park does not hold a number whose caller may have to wait.
    if number == SyscallNumber::BindUdp as usize || number == SyscallNumber::SendToUdp as usize {
        // `SendToUdp` carries a buffer: `a2` the bytes, `a3` their length,
        // the same shape a file write is.  `BindUdp` names no address at
        // all, and its slots are the handler's to refuse.
        let send_buffer = if number == SyscallNumber::SendToUdp as usize {
            let buffer = call.arguments[2];
            let length = call.arguments[3];
            if !crate::address_space::is_user_range(buffer, length) {
                return CallOutcome::Return(abi::syscall::encode_error(
                    abi::Error::InvalidArgument,
                ));
            }
            // SAFETY: the range is inside the user window and not empty,
            // which `is_user_range` checked, and the pages behind it are the
            // calling task's own mappings, installed on this CPU.  The
            // handler reads the bytes; a copy-on-write page demoted by an
            // earlier write faults into the resolver like any other access.
            Some(unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, length) })
        } else {
            None
        };
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, None, None, send_buffer);
        // The evidence, printed by the kernel because a program has no way to
        // print one: the port bound and the descriptor it became, or the
        // datagram's own size beside the address and port it named.
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
        {
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            if number == SyscallNumber::BindUdp as usize {
                arch::serial::write_str(" bound port ");
                arch::serial::write_u32(call.arguments[0] as u32);
                arch::serial::write_str(" as descriptor ");
                arch::serial::write_u32(answer as u32);
            } else {
                arch::serial::write_str(" sent ");
                arch::serial::write_u32(call.arguments[3] as u32);
                arch::serial::write_str(" byte(s) to ");
                write_ipv4_word(call.arguments[1]);
                arch::serial::write_str(" port ");
                arch::serial::write_u32(call.arguments[4] as u32);
            }
            arch::serial::write_str("\n");
        }
        return outcome;
    }

    // The receive: one datagram from a bound socket, or a park until one
    // arrives.
    //
    // The park is the pipe reader's shape, and for the same reason: between
    // this call's own check and the park, a sender on another CPU can
    // deliver, and the wake that fact sends can fire into the gap.  The
    // re-check and the park are one critical section, so the delivery has
    // exactly two orders to find — the datagram first, and this call
    // answers it here, or the task parked first, and the delivery's wake
    // ends the wait.
    //
    // Before both, the card's ring is drained: a frame the card is holding
    // is a datagram in a queue rather than a wait that answers nothing.
    if number == SyscallNumber::RecvFromUdp as usize {
        let descriptor = call.arguments[0];
        let buffer = call.arguments[1];
        let length = call.arguments[2];
        let sender_record = call.arguments[3];
        let sender_len = call.arguments[4];
        if !crate::address_space::is_user_range(buffer, length)
            || !crate::address_space::is_user_range(sender_record, sender_len)
            || sender_len < abi::network::UDP_SENDER_RECORD_SIZE
        {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        }
        let Some(socket) = crate::syscall::udp_socket_for(descriptor, caller) else {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        };
        // SAFETY: both ranges are inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind them are the calling
        // task's own mappings, installed on this CPU.  The receive writes the
        // buffer and the sender record and nothing past them, which is what
        // the record's length check is for.
        let destination = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, length) };
        let sender =
            unsafe { core::slice::from_raw_parts_mut(sender_record as *mut u8, sender_len) };

        crate::net::pump();
        let mut answer = receive_datagram_answer(&socket, destination, sender);
        if answer.is_none() {
            answer = crate::scheduler::block_unless(frame, || {
                receive_datagram_answer(&socket, destination, sender)
            });
        }
        return match answer {
            None => {
                // Parked.  Resume something else; the frame was saved at the
                // call, so a wake returns here and the call is retried, and
                // the retry drains the card before it asks its question
                // again.
                arch::serial::write_str("protofire: a program blocks on a datagram socket\n");
                if !crate::scheduler::has_selectable() {
                    crate::scheduler::idle_until_woken();
                }
                crate::scheduler::switch_without_saving(frame)
            }
            Some(status) => {
                if !abi::syscall::is_error_status(status) {
                    // The sender the record now holds is the line's evidence:
                    // a receive that answered names where its datagram came
                    // from, which a caller can compare against the peer it
                    // expected.
                    let address = usize::from_le_bytes(
                        sender[..8].try_into().expect("the record's address word"),
                    );
                    let port = usize::from_le_bytes(
                        sender[8..16].try_into().expect("the record's port word"),
                    );
                    arch::serial::write_str("protofire: process ");
                    arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
                    arch::serial::write_str(" received ");
                    arch::serial::write_u32(status as u32);
                    arch::serial::write_str(" byte(s) from ");
                    write_ipv4_word(address);
                    arch::serial::write_str(" port ");
                    arch::serial::write_u32(port as u32);
                    arch::serial::write_str("\n");
                }
                CallOutcome::Return(status)
            }
        };
    }

    // A read from a stream: the bytes the peer sent that this side has not
    // taken, or a park until some arrive.  The park is the pipe reader's
    // and the datagram receiver's shape, with the same re-check under the
    // scheduler's lock; the card's ring is drained first, so a frame the
    // card is holding is bytes in the stream's inbox rather than a wait
    // that answers nothing.
    //
    // End of file is the read that answers zero, and it comes from a stream
    // whose connection is gone — which an orderly close's last
    // acknowledgement leaves behind.  A read that never answered zero would
    // be a reader parked on a writer that said it was done.
    if number == SyscallNumber::Read as usize
        && crate::syscall::tcp_stream_for(call.arguments[0], caller).is_some()
    {
        // The slots a file read takes, because a stream is a descriptor the
        // same wrapper packs the same way: `a1` the offset, `a2` the buffer,
        // `a3` its length.  A stream has no position to seek, so the offset
        // slot is refused unless it is the read-from-here sentinel — an
        // explicit offset on a stream would be a position neither side
        // tracks.
        let descriptor = call.arguments[0];
        let offset = call.arguments[1];
        let buffer = call.arguments[2];
        let length = call.arguments[3];
        if offset != crate::syscall::READ_OFFSET_CURRENT
            || !crate::address_space::is_user_range(buffer, length)
        {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        }
        let Some(stream) = crate::syscall::tcp_stream_for(descriptor, caller) else {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        };
        // SAFETY: the range is inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind it are the calling
        // task's own mappings, installed on this CPU.  The stream's receive
        // writes the buffer and nothing past it.
        let destination = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, length) };

        crate::net::pump();
        let mut answer = crate::net::tcp_read(stream, destination);
        if answer == Ok(None) {
            match crate::scheduler::block_unless(frame, || {
                match crate::net::tcp_read(stream, destination) {
                    Ok(None) => None,
                    other => Some(other),
                }
            }) {
                Some(retried) => answer = retried,
                None => {
                    arch::serial::write_str("protofire: a program blocks on a stream\n");
                    if !crate::scheduler::has_selectable() {
                        crate::scheduler::idle_until_woken();
                    }
                    return crate::scheduler::switch_without_saving(frame);
                }
            }
        }
        return match answer {
            Ok(Some(count)) => {
                arch::serial::write_str("protofire: process ");
                arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
                arch::serial::write_str(" read ");
                arch::serial::write_u32(count as u32);
                arch::serial::write_str(" byte(s) from a stream\n");
                CallOutcome::Return(count)
            }
            Ok(None) => CallOutcome::Return(0),
            Err(error) => CallOutcome::Return(abi::syscall::encode_error(error)),
        };
    }

    // The stream calls that answer at once: a listen, and a connect.  The
    // accept parks, and it is the branch below.
    if number == SyscallNumber::ListenTcp as usize || number == SyscallNumber::ConnectTcp as usize {
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, None, None, None);
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
        {
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            if number == SyscallNumber::ListenTcp as usize {
                arch::serial::write_str(" listening on port ");
                arch::serial::write_u32(call.arguments[0] as u32);
                arch::serial::write_str(" as descriptor ");
            } else {
                arch::serial::write_str(" connected to ");
                write_ipv4_word(call.arguments[0]);
                arch::serial::write_str(" port ");
                arch::serial::write_u32(call.arguments[1] as u32);
                arch::serial::write_str(" as stream ");
            }
            arch::serial::write_u32(answer as u32);
            arch::serial::write_str("\n");
        }
        return outcome;
    }

    // The accept: one stream from a listener's pending list, or a park
    // until a client's SYN opens one.  The re-check under the scheduler's
    // lock is the same one every park here makes, and the SYN that fills
    // the list is what wakes it — the demux's own wake, which fires when a
    // connection opened or bytes arrived.
    if number == SyscallNumber::AcceptTcp as usize {
        let descriptor = call.arguments[0];
        let Some(listener) = crate::syscall::tcp_listener_for(descriptor, caller) else {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::InvalidArgument));
        };
        crate::net::pump();
        let mut answer = crate::net::tcp_accept(listener);
        if answer == Ok(None) {
            match crate::scheduler::block_unless(frame, || match crate::net::tcp_accept(listener) {
                Ok(None) => None,
                other => Some(other),
            }) {
                Some(retried) => answer = retried,
                None => {
                    arch::serial::write_str("protofire: a program waits to accept a stream\n");
                    if !crate::scheduler::has_selectable() {
                        crate::scheduler::idle_until_woken();
                    }
                    return crate::scheduler::switch_without_saving(frame);
                }
            }
        }
        return match answer {
            Ok(Some(stream)) => {
                let owner =
                    crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS);
                match crate::syscall::attach_tcp_stream(stream, owner) {
                    Some(descriptor) => {
                        arch::serial::write_str("protofire: process ");
                        arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
                        arch::serial::write_str(" accepted a stream as descriptor ");
                        arch::serial::write_u32(descriptor as u32);
                        arch::serial::write_str("\n");
                        CallOutcome::Return(descriptor)
                    }
                    None => {
                        CallOutcome::Return(abi::syscall::encode_error(abi::Error::NotImplemented))
                    }
                }
            }
            Ok(None) => CallOutcome::Return(abi::syscall::encode_error(abi::Error::NotFound)),
            Err(error) => CallOutcome::Return(abi::syscall::encode_error(error)),
        };
    }

    // Everything else is a call this boot does not serve.  `encode_error` is
    // the ABI's own encoding, so the program reads the same word it would from
    // a handler that answered through the registry.
    CallOutcome::Return(abi::syscall::encode_error(abi::Error::NotImplemented))
}

/// The mask bits the ABI defines: one per signal, `1..=31`.  Bit 0 and
/// everything above are signals this ABI does not define, and a mask word
/// that named one would be a promise about a signal no send can carry.
#[cfg(target_os = "none")]
const SIGNAL_KNOWN_MASK: usize = 0xFFFF_FFFE;

/// The byte length of the ABI's `ProcessSignalRecord`, the record `WaitSignal`
/// answers with: three words — signal, sender, payload.
#[cfg(target_os = "none")]
const SIGNAL_RECORD_BYTES: usize = 24;

/// Write a `ProcessSignalRecord` into the caller's memory, little-endian word
/// by word — the same layout rule `Stat`'s record keeps.
#[cfg(target_os = "none")]
fn write_signal_record(buffer: &mut [u8], signal: usize, sender_pid: u32, payload: usize) {
    buffer[..8].copy_from_slice(&signal.to_le_bytes());
    buffer[8..16].copy_from_slice(&(sender_pid as usize).to_le_bytes());
    buffer[16..24].copy_from_slice(&payload.to_le_bytes());
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

/// Take one datagram from a bound socket, answering the call's status word.
///
/// `None` is "nothing arrived", which is the caller's signal to park;
/// `Some` is the answer — the byte count, or an error encoded the ABI's way.
/// The sender record is written here, because the receive that answers and
/// the re-check under the park's lock must fill the same record the same
/// way, and one writer is how that stays true.
#[cfg(target_os = "none")]
fn receive_datagram_answer(
    socket: &alloc::sync::Arc<crate::net::UdpSocket>,
    destination: &mut [u8],
    sender: &mut [u8],
) -> Option<usize> {
    match socket.try_recv(destination) {
        Err(error) => Some(abi::syscall::encode_error(error)),
        Ok(None) => None,
        Ok(Some((source, source_port, count))) => {
            let record = abi::network::UdpSenderRecord {
                address: abi::network::pack_address(source),
                port: source_port as usize,
            };
            sender[..8].copy_from_slice(&record.address.to_le_bytes());
            sender[8..16].copy_from_slice(&record.port.to_le_bytes());
            Some(count)
        }
    }
}

/// Write four bytes as a dotted quad, from the word the ABI packs them in.
///
/// The same shape `devices.rs`'s writer is, one layer down: a byte per
/// octet, through `write_str`, so the line stays one line.
#[cfg(target_os = "none")]
fn write_ipv4_word(word: usize) {
    for (index, byte) in abi::network::unpack_address(word).iter().enumerate() {
        if index != 0 {
            arch::serial::write_str(".");
        }
        arch::serial::write_u32(*byte as u32);
    }
}

/// The name a `Stat` evidence line prints for the ABI's kind word.
///
/// The words are the log's, not the wire's: the record carries the number,
/// and a boot line that printed the number would be one a reader had to
/// decode against the ABI to read at all.
#[cfg(target_os = "none")]
fn stat_kind_name(kind: usize) -> &'static str {
    match kind {
        abi::fs::FILE_KIND_DIRECTORY => "directory",
        abi::fs::FILE_KIND_FILE => "file",
        abi::fs::FILE_KIND_DEVICE => "device",
        abi::fs::FILE_KIND_SYMLINK => "symlink",
        _ => "unknown",
    }
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
    second_path: Option<&str>,
    buffer: Option<&mut [u8]>,
) -> arch::CallOutcome {
    let mut arguments = crate::syscall::Arguments {
        context,
        path,
        second_path,
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
