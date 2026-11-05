//! kernel/src/process.rs
//!
//! One program, running at EL0, calling back into the kernel.
//!
//! ## What this is
//!
//! What the kernel does with a program's supervisor call: three calls are
//! served — `Write`, `Exit` and `Sleep` — and everything else answers
//! `NotImplemented`.
//!
//! ## Why the program is not here
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
//! deadline in the scheduler and answers `Exit`-shaped — not because the
//! program has ended, but because the frame the handler holds must describe
//! what runs next, and what runs next is another task.  The program resumes
//! when the timer wakes it, with its context exactly as the trap saved it.

/// A program's bytes, for a caller that writes them into a frame.
///
/// Asked of the machine: a program is machine code, and the array is this
/// architecture's — `svc` and `x8` on aarch64, `int $0x80` and `eax` on x86_64.
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
/// one did — the pipe reader's first instruction is a load from `[rsp]`, and it
/// took a page fault.
pub const fn program_stack_top(number: u16) -> usize {
    program_base(number) + 0x2000
}

/// The page the `n`th program's stack lives on.
pub const fn program_stack_page(number: u16) -> usize {
    program_base(number) + 0x1000
}

/// What the kernel does with a program's supervisor call.
///
/// ## What a call can be, today
///
/// `Write` prints a fixed line — the program's arguments are not read, because
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
        // the instruction after the `svc` — forever.
        let outcome = crate::scheduler::advance(frame, true);
        if !crate::scheduler::has_runnable() {
            let (switches, exited) = crate::scheduler::statistics();
            let ticks = crate::tick::TIMER_TICKS.load(core::sync::atomic::Ordering::Acquire) as u32;
            arch::serial::write_str("protofire: every program exited, ");
            arch::serial::write_u32(exited as u32);
            arch::serial::write_str(" exit(s), ");
            arch::serial::write_u32(ticks);
            arch::serial::write_str(" tick(s), ");
            arch::serial::write_u32(switches as u32);
            arch::serial::write_str(" switch(es)\n");

            // Whether the timer preempted, as a fact and not a number.
            //
            // The switch count depends on how fast the emulator runs the
            // program's loop, so a line that required a particular count would
            // be a gate on the host's speed.  What does not depend on that is
            // whether *any* switch came from a tick rather than from an exit:
            // with two programs and two exits, more than one switch means the
            // timer moved the CPU.
            //
            // A boot whose preemption sink was not installed prints
            // `1 switch(es)` — one, from the first exit — and says so.
            if switches > 1 && ticks > 0 {
                arch::serial::write_str("protofire: the timer preempted, ");
                arch::serial::write_u32((switches - 1) as u32);
                arch::serial::write_str(" switch(es) from ticks\n");
            } else {
                arch::serial::write_str("protofire: the timer did not preempt\n");
            }
            arch::halt()
        }
        return outcome;
    }
    // A write to a pipe, recognised by the descriptor naming one.
    //
    // The test is the table, not the argument: a program's `Write` is also how
    // it announces which program it is, and that call passes a small number
    // where a pipe's descriptor would be.  A range check could not tell the two
    // apart — aarch64's `x0` holds the stack top for every program — and the
    // first version's did exactly that, so the announcement was served as a
    // pipe write and the program printed once.
    // A pipe write is a write *with a length*, which the announcing `Write`
    // never has.
    //
    // The descriptor test alone is not enough, and this is the defect that
    // showed it: a program's first instructions have no reason to set `edi`, so
    // it holds whatever the boot left — zero — and zero is a valid descriptor
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
                    if woken > 0 {
                        arch::serial::write_str("protofire: a write woke ");
                        arch::serial::write_u32(woken as u32);
                        arch::serial::write_str(" blocked task(s)\n");
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
        // own answer into `x0` of *that* context and returned `Return` — so the
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
                // ## Why this is not `advance(frame, false)` unconditionally
                //
                // `advance` saves the frame it was given into the *current*
                // task before choosing the next one — and the current task is
                // the one that just went to sleep, whose context was saved by
                // `sleep_for_microseconds`.  Saving again is harmless; what is
                // not is that `advance` answers `Exit` when nothing else is
                // runnable, and `Exit` tells the trap path to resume the frame
                // it has — a sleeping program.
                //
                // So the two cases are separate.  With another task runnable,
                // `advance` installs its context and the trap path resumes it.
                // With every task asleep, the boot waits for the tick that
                // wakes one; the timer's handler turns a deadline into a
                // runnable task, and `idle_until_woken` returns when it has.
                if crate::scheduler::has_other_runnable() || !crate::scheduler::has_sleeping() {
                    return crate::scheduler::advance(frame, false);
                }
                // Nothing is selectable, so the frame is not replaced.  The
                // wait happens here, and the task that woke is installed
                // afterwards — through the call that does *not* save, because
                // the frame arriving here is the boot's kernel frame and the
                // task it would be saved into is asleep with a program context
                // that must not be clobbered.
                arch::serial::write_str("protofire: every program is asleep, waiting\n");
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
        // ## Why the descriptor is the first argument and the path is not
        //
        // The registry's `Read` takes a path through `Arguments::path`, which
        // is a borrow the boot can hand it because the boot owns the string.  A
        // program does not: it passes an address, and an address from ring 3 is
        // a number until something validates it.  So this is the call the
        // validation exists for.
        //
        // ## What blocking means here
        //
        // `try_read` answers `Block` only when the pipe could still fill — no
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
        // buffer is a cell — so this reads it through the shared reference
        // rather than needing to own it.
        let progress = match end.try_read(&pipe, destination) {
            Ok(progress) => progress,
            Err(error) => return CallOutcome::Return(abi::syscall::encode_error(error)),
        };
        return match progress {
            crate::pipe::Progress::Done(count) => CallOutcome::Return(count),
            crate::pipe::Progress::Block => {
                // Park, then resume something else.  The frame is saved by
                // `block`, so a wake returns here and the call is retried by
                // the program — which is what makes this a short read rather
                // than a lost one.
                crate::scheduler::block(frame);
                arch::serial::write_str("protofire: a program blocks on a pipe\n");
                if !crate::scheduler::has_selectable() {
                    // Nothing else can run: wait for a writer's wake the same
                    // way a sleep waits, and the timer's handler is what turns
                    // a blocked task back into a runnable one.
                    crate::scheduler::idle_until_woken();
                }
                // Install whatever can run next; this task's frame was saved
                // by `block`, so the wake resumes the read.
                let _ = crate::scheduler::switch_without_saving(frame);
                CallOutcome::Exit
            }
        };
    }

    if number == SyscallNumber::Pipe as usize {
        // `Pipe()`: make one and answer the read end's descriptor.  The write
        // end is the next number, because a call answers one word and two
        // descriptors do not fit in one.
        //
        // ## Why a pipe and not a file
        //
        // A file can be read at an offset and answered from memory; the answer
        // is there before the call.  A pipe's answer may not exist yet, and
        // that is the whole difference this call exists to make real.
        let pipe = alloc::sync::Arc::new(crate::pipe::Pipe::new(ipc::DEFAULT_PIPE_CAPACITY));
        // Two handles on one buffer, and the pipe's own counts follow: it is
        // created with one reader and one writer, which is exactly the pair
        // this makes.
        let Some(read) = crate::pipe::attach(crate::pipe::End::reader(pipe.clone())) else {
            return CallOutcome::Return(abi::syscall::encode_error(abi::Error::OutOfMemory));
        };
        let Some(write) = crate::pipe::attach(crate::pipe::End::writer(pipe)) else {
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

    // Everything else is a call this boot does not serve.  `encode_error` is
    // the ABI's own encoding, so the program reads the same word it would from
    // a handler that answered through the registry.
    CallOutcome::Return(abi::syscall::encode_error(abi::Error::NotImplemented))
}

/// What the program's `Write` prints.
///
/// Fixed, and the program passes no pointer: a program's buffer is an address
/// in ring 3, and this kernel has no way to check one yet.  A handler that
/// dereferenced `x1` would be reading whatever the program put there — which is
/// the promise `kernel/src/syscall/mod.rs` refuses to make, and this is the
/// same refusal one layer down.
/// The length `Write` answers with.
///
/// A program compares nothing today — the return path is proven by the exit
/// status of a program that does — but the number is what the call answers and
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
