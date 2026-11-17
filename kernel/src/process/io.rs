//! kernel/src/process/io.rs
//!
//! The descriptor calls: a pipe, and the filesystem through `open`, `read`,
//! `write`, `stat`, the `*At` forms and the directory calls.
//!
//! One family of `serve`'s branches, moved out so the dispatcher reads as a
//! list of families.  `None` means this family does not serve `number` and
//! `serve` tries the next one; `Some(outcome)` is the call's answer and ends
//! the dispatch.

use super::OPEN_PATH_MAX;
use super::PROGRAM_OUTPUT;
use super::copy_user_path;
use super::stat_kind_name;
use super::through_registry;

pub(crate) fn serve_io(
    call: arch::CallFrame,
    frame: &mut arch::Context,
    number: usize,
    caller: Option<u32>,
) -> Option<arch::CallOutcome> {
    use arch::CallOutcome;
    use syscall::SyscallNumber;
    let _ = (&call, &*frame, number, caller);
    // A write to a local-domain connection: the writer half of the
    // descriptor's two.  The wake is the pipe's, and the count is what the
    // pipe carried: a full pipe answers a short write, which is the contract a
    // program's loop already handles.
    if number == SyscallNumber::Write as usize
        && call.arguments[2] != 0
        && crate::syscall::local_halves_for(call.arguments[0], caller).is_some()
    {
        let descriptor = call.arguments[0];
        let buffer = call.arguments[1];
        let length = call.arguments[2];
        if !crate::address_space::is_user_range(buffer, length) {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        let Some(halves) = crate::syscall::local_halves_for(descriptor, caller) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        };
        let pipe = halves.writer.pipe().clone();
        // SAFETY: the range was validated above and the page tables are the
        // ones this task runs through, so the buffer is readable from here.
        let source = unsafe { core::slice::from_raw_parts(buffer as *const u8, length) };
        let progress = match halves.writer.try_write(&pipe, source) {
            Ok(progress) => progress,
            Err(error) => return Some(CallOutcome::Return(abi::syscall::encode_error(error))),
        };
        return Some(match progress {
            crate::pipe::Progress::Done(count) => {
                if count > 0 {
                    let woken = crate::scheduler::wake_blocked();
                    arch::serial::write_str("protofire: a local write woke ");
                    arch::serial::write_u32(woken as u32);
                    arch::serial::write_str(" blocked task(s)\n");
                    if woken > 0 {
                        // SAFETY: the boot's own IPI path, installed before
                        // any program ran.
                        unsafe { arch::send_ipi_to_others() };
                    }
                }
                CallOutcome::Return(count)
            }
            // A full pipe with a reader: this boot does not park a writer, for
            // the reason the plain pipe's branch gives, and zero says the
            // bytes did not go.
            crate::pipe::Progress::Block => CallOutcome::Return(0),
        });
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
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        let Some(end) = crate::pipe::lookup_for(descriptor, caller) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        };
        let pipe = end.pipe().clone();
        // SAFETY: the range was validated above and the page tables are this
        // task's, so the buffer is readable from here.
        let source = unsafe { core::slice::from_raw_parts(buffer as *const u8, length) };

        let progress = match end.try_write(&pipe, source) {
            Ok(progress) => progress,
            Err(error) => return Some(CallOutcome::Return(abi::syscall::encode_error(error))),
        };
        return Some(match progress {
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
                    // interleaving, and the gate requires it, 2 of 100 runs
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
        });
    }

    // A write to a stream: the bytes go out as one segment, and the answer
    // is the count.  Reached only when the pipe branch above did not
    // return, so the descriptor names a stream the table holds, or it
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
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        let Some(stream) = crate::syscall::tcp_stream_for(descriptor, caller) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        };
        // SAFETY: the range is inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind it are the calling
        // task's own mappings, installed on this CPU.  The stream's send
        // reads the bytes; a copy-on-write page demoted by an earlier write
        // faults into the resolver like any other access.
        let source = unsafe { core::slice::from_raw_parts(buffer as *const u8, length) };
        return Some(match crate::net::tcp_write(stream, source) {
            Ok(count) => {
                arch::serial::write_str("protofire: process ");
                arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
                arch::serial::write_str(" wrote ");
                arch::serial::write_u32(count as u32);
                arch::serial::write_str(" byte(s) to a stream\n");
                CallOutcome::Return(count)
            }
            Err(error) => CallOutcome::Return(abi::syscall::encode_error(error)),
        });
    }
    if number == SyscallNumber::WriteDebug as usize {
        // `WriteDebug(buffer, length)`: a program's bytes into the kernel's own
        // log.  The buffer is a ring-3 address, so it is validated before it is
        // read, the same rule every buffer-taking call keeps.
        //
        // The call exists for a program that has opened nothing yet: `Write`
        // needs a descriptor, and a boot's first program uses this to say what
        // it is before it has anything to write through.
        let buffer = call.arguments[0];
        let length = call.arguments[1];
        if !crate::address_space::is_user_range(buffer, length) {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        // SAFETY: the range is inside the user window, which `is_user_range`
        // checked, and the pages behind it are the calling task's own mappings,
        // installed on this CPU.  The bytes are read and nothing is written.
        let source = unsafe { core::slice::from_raw_parts(buffer as *const u8, length) };
        // Through the arch console and not the registry.  The registry's
        // `Arguments` carries a `&mut [u8]`, which is right for a call that
        // writes into a caller's buffer and a lie for one that only reads it:
        // the handler would need a shared reference cast to an exclusive one,
        // which is exactly the aliasing `Arguments` exists to make impossible.
        // A read-only call goes straight to the sink instead.
        if let Ok(text) = core::str::from_utf8(source) {
            arch::serial::write_str(text);
        }
        let _ = &mut context;
        return Some(CallOutcome::Return(length));
    }
    if number == SyscallNumber::ListBlockDevices as usize {
        // `ListBlockDevices(index, record, length)`: one disk this boot found,
        // described into the caller's buffer.  The buffer is a ring-3 address,
        // so the range is checked before the registry sees it.
        let buffer = call.arguments[1];
        let length = call.arguments[2];
        if length == 0 || !crate::address_space::is_user_range(buffer, length) {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        // SAFETY: the range is inside the user window, which `is_user_range`
        // checked, and the pages behind it are the calling task's own
        // mappings.  The handler writes the record and nothing past it.
        let destination = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, length) };
        let outcome = through_registry(&mut context, None, None, Some(destination));
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
        {
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(" listed block device ");
            arch::serial::write_u32(call.arguments[0] as u32);
            arch::serial::write_str("\n");
        }
        return Some(outcome);
    }
    if number == SyscallNumber::Sync as usize {
        // `Sync()`: every mounted filesystem flushed to its device.  No
        // pointer, so the registry is reached directly, and the reserved slots
        // are the handler's to refuse.
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, None, None, None);
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
        {
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(" flushed every mounted filesystem\n");
        }
        return Some(outcome);
    }
    if number == SyscallNumber::ReadConsole as usize {
        // `ReadConsole(buffer, length)`: the line a reader typed.  This machine
        // has no input device yet, so the handler answers zero, and the branch
        // exists anyway: a call the registry serves but the dispatcher does not
        // forward is a call that answers `NotImplemented`, which is a different
        // word from "nothing typed" and the one a shell would treat as a kernel
        // that has no console at all.
        let buffer = call.arguments[0];
        let length = call.arguments[1];
        if length == 0 {
            return Some(CallOutcome::Return(0));
        }
        if !crate::address_space::is_user_range(buffer, length) {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        // SAFETY: the range is inside the user window, which `is_user_range`
        // checked, and the pages behind it are the calling task's own
        // mappings.  The handler writes the bytes it read and nothing past
        // the length.
        let destination = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, length) };
        return Some(through_registry(
            &mut context,
            None,
            None,
            Some(destination),
        ));
    }
    if number == SyscallNumber::Write as usize && call.arguments[2] != 0 {
        // `Write(descriptor, buffer, length)` to a file, through the registry.
        //
        // Reached only when the pipe branch above did not return, so the
        // descriptor names no pipe of this caller's: it names a file the table
        // holds, or it names nothing, and the registry answers the same
        // refusal for both, the answer that does not tell a caller which
        // numbers exist.  The length is what distinguishes a write from the
        // announcement below, the same distinction the pipe branch reads, and
        // the validation is the read's, for the same reason: an address from
        // ring 3 is a number until something checks it.
        let buffer = call.arguments[1];
        let length = call.arguments[2];
        if !crate::address_space::is_user_range(buffer, length) {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
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
        return Some(outcome);
    }
    if number == SyscallNumber::SetLength as usize {
        // `SetLength(descriptor, length)`: the one call of the descriptor
        // family that takes no pointer, so nothing here has to turn a word
        // into a borrow and the registry is reached directly.  The reserved
        // slots are the handler's to refuse, which is where every other
        // word-shaped call leaves them.
        //
        // The line is the evidence the call ran rather than the fallthrough
        // answering `NotImplemented`, and it names the length because a
        // truncate that answered zero without doing one would otherwise print
        // the same thing the successful one does.
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, None, None, None);
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
        {
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(" set descriptor ");
            arch::serial::write_u32(call.arguments[0] as u32);
            arch::serial::write_str(" to ");
            arch::serial::write_u32(call.arguments[1] as u32);
            arch::serial::write_str(" byte(s)\n");
        }
        return Some(outcome);
    }
    if number == SyscallNumber::Seek as usize {
        // `Seek(descriptor, offset, whence)`: the second call of this family
        // that takes no pointer.  The offset is a **signed** word, which is
        // the ABI's shape and not this branch's choice, so it is passed
        // through as the caller sent it and the handler reads the sign.
        //
        // The line names both the initial position the caller asked for and
        // the one the call answered, because a seek's answer **is** the new
        // position: a line that printed only zero would be indistinguishable
        // from a call that did nothing, and the two differ by the whole of
        // what the call is for.
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, None, None, None);
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
        {
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(" seeked descriptor ");
            arch::serial::write_u32(call.arguments[0] as u32);
            arch::serial::write_str(" to ");
            arch::serial::write_u32(answer as u32);
            arch::serial::write_str("\n");
        }
        return Some(outcome);
    }
    if number == SyscallNumber::Fsync as usize || number == SyscallNumber::Fdatasync as usize {
        // The two flushes, one branch because they differ only in how much of
        // the file they wait for and the handler reads which from the number.
        // Neither takes a pointer.
        //
        // The line is the evidence a refusal cannot give: the answer is zero
        // either way, so a program that flushed nothing and one that flushed
        // everything print the same status.  Naming which of the two ran is
        // what the log can say, and "the file is on the device" is not a fact
        // this boot can observe from ring 3 at all.
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, None, None, None);
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
        {
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(if number == SyscallNumber::Fsync as usize {
                " flushed descriptor "
            } else {
                " flushed the data of descriptor "
            });
            arch::serial::write_u32(call.arguments[0] as u32);
            arch::serial::write_str("\n");
        }
        return Some(outcome);
    }
    if number == SyscallNumber::Fallocate as usize
        || number == SyscallNumber::GetFileFlags as usize
        || number == SyscallNumber::SetFileFlags as usize
    {
        // The punch and the two data-reduction flags.  One branch because none
        // of the three takes a pointer: a descriptor and words, which the
        // handler reads and validates.
        //
        // The line prints the call's own answer rather than a fixed word,
        // because the three answers mean different things: the punch answers
        // zero, the get answers the flags word, and the set answers zero.  A
        // line that printed "zero" for all three would hide the get's, which
        // is the only one of them with anything to report.
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, None, None, None);
        match outcome {
            CallOutcome::Return(answer) if !abi::syscall::is_error_status(answer) => {
                arch::serial::write_str("protofire: process ");
                arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
                arch::serial::write_str(" asked ");
                arch::serial::write_str(if number == SyscallNumber::Fallocate as usize {
                    "for a hole in descriptor "
                } else if number == SyscallNumber::GetFileFlags as usize {
                    "for the flags of descriptor "
                } else {
                    "to change the flags of descriptor "
                });
                arch::serial::write_u32(call.arguments[0] as u32);
                arch::serial::write_str(", answered ");
                arch::serial::write_u32(answer as u32);
                arch::serial::write_str("\n");
            }
            _ => {
                // A refusal is reported too, and with the same words: a punch
                // the volume does not implement and a punch that happened are
                // the two outcomes a reader of this log has to tell apart, and
                // the answer's encoding is what does it.
                arch::serial::write_str("protofire: process ");
                arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
                arch::serial::write_str(" was refused a call on descriptor ");
                arch::serial::write_u32(call.arguments[0] as u32);
                arch::serial::write_str("\n");
            }
        }
        return Some(outcome);
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
        return Some(CallOutcome::Return(PROGRAM_OUTPUT));
    }
    // A read from a local-domain connection: the reader half of the
    // descriptor's two.
    //
    // The slots are a **stream's**, `a1` the offset, `a2` the buffer and `a3`
    // its length, because that is how `sys_read` packs one: the wrapper sends
    // the read-from-here sentinel in `a1` and the address after it.  The pipe
    // branch below reads `a1` and `a2`, which is right only for the boot's own
    // calls, whose arguments are built by hand, and this branch started as a
    // copy of it: every ring-3 read of a local end was therefore refused for a
    // range whose "buffer" was the sentinel `0xffff_ffff_ffff_ffff`.  Both
    // halves of the exchange failed that way, and the exit statuses 243 and
    // 245 are what found it.
    if number == SyscallNumber::Read as usize
        && crate::syscall::local_halves_for(call.arguments[0], caller).is_some()
    {
        let descriptor = call.arguments[0];
        let buffer = call.arguments[2];
        let length = call.arguments[3];
        if length == 0 {
            return Some(CallOutcome::Return(0));
        }
        if !crate::address_space::is_user_range(buffer, length) {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        let Some(halves) = crate::syscall::local_halves_for(descriptor, caller) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        };
        let pipe = halves.reader.pipe().clone();
        // SAFETY: the range was validated above and the page tables are the
        // ones this task runs through, so the buffer is writable from here.
        let destination = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, length) };
        let progress = match halves.reader.try_read(&pipe, destination) {
            Ok(progress) => progress,
            Err(error) => return Some(CallOutcome::Return(abi::syscall::encode_error(error))),
        };
        return Some(match progress {
            crate::pipe::Progress::Done(count) => CallOutcome::Return(count),
            crate::pipe::Progress::Block => {
                // The re-check inside the park is the pipe's own, for the
                // reason its branch gives: a write on another CPU between the
                // `Block` above and the park would otherwise wake a task that
                // had not parked yet, and that task would wait for ever.
                match crate::scheduler::block_unless(frame, || {
                    match halves.reader.try_read(&pipe, destination) {
                        Ok(crate::pipe::Progress::Done(count)) => Some(count),
                        Ok(crate::pipe::Progress::Block) => None,
                        Err(error) => Some(abi::syscall::encode_error(error)),
                    }
                }) {
                    Some(answer) => CallOutcome::Return(answer),
                    None => {
                        arch::serial::write_str("protofire: a program blocks on a local socket\n");
                        if !crate::scheduler::has_selectable() {
                            crate::scheduler::idle_until_woken();
                        }
                        crate::scheduler::switch_without_saving(frame)
                    }
                }
            }
        });
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
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        let Some(end) = crate::pipe::lookup_for(descriptor, caller) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
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
            Err(error) => return Some(CallOutcome::Return(abi::syscall::encode_error(error))),
        };
        return Some(match progress {
            crate::pipe::Progress::Done(count) => CallOutcome::Return(count),
            crate::pipe::Progress::Block => {
                // Park, but let the park ask the question once more under
                // the scheduler's own lock.  Between the `Block` above and
                // the park, a writer on another CPU can put bytes in or
                // close its write end, and the wake that fact sends can fire
                // into the gap: a task parked after the wake it was waiting
                // for is a task parked for ever.  The re-check and the park
                // are one critical section, so the wake has only two orders
                // to find, the fact first, and this call answers it here,
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
        });
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
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::OutOfMemory,
            )));
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
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::OutOfMemory,
            )));
        };
        arch::serial::write_str("protofire: pipe made, read ");
        arch::serial::write_u32(read as u32);
        arch::serial::write_str(", write ");
        arch::serial::write_u32(write as u32);
        arch::serial::write_str("\n");
        // The read end goes in `rax` and the write end above it: the ABI
        // answers one word, and a program reads both from one number rather
        // than making a second call that could not know which pipe it meant.
        return Some(CallOutcome::Return(read | (write << 16)));
    }

    // The registry's calls, from a program that has no borrow to hand anyone.
    //
    // The registry's handlers take `Arguments`, whose address-shaped fields are
    // *borrows*, a shape that exists precisely so no handler ever turns a
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
        // slot, which is what keeps the kernel-side shape, path as a borrow,
        // flags in the first argument, and the ring-3 shape one shape.
        let flags = call.arguments[1];
        let mut path_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(path) = copy_user_path(call.arguments[0], &mut path_bytes) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
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
            // the same way it answers a value, the ABI's error encoding is a
            // number near `usize::MAX`, so a caller that printed the line
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
            return Some(CallOutcome::Return(descriptor));
        }
        return Some(outcome);
    }
    if number == SyscallNumber::Read as usize
        && crate::pipe::lookup_for(call.arguments[0], caller).is_none()
        && crate::syscall::tcp_stream_for(call.arguments[0], caller).is_none()
        // A local end's read is `(descriptor, buffer, length)`, which is the
        // pipe's shape and not this branch's `(descriptor, offset, buffer,
        // length)`.  Without this test the call fell through to here, which
        // read `a2` as a pointer and `a3` as a length: the buffer was the
        // length word and the length was whatever the program's register held,
        // so the read was refused for a range the program never named.  Both
        // halves of this exchange failed that way, and the exit statuses, 243
        // and 245, are what found it.
        && crate::syscall::local_halves_for(call.arguments[0], caller).is_none()
    {
        // `Read(descriptor, offset, buffer, length)`: a file descriptor in the
        // registry's table, the buffer a range of the caller's own memory.  A
        // pipe descriptor never reaches here, the branch above answered it
        // and a stream descriptor never does either, because its read is the
        // stream's to park on.  The registry answers `InvalidArgument` for
        // both anyway, because their reads are not the file's to serve.
        let buffer = call.arguments[2];
        let length = call.arguments[3];
        if length == 0 {
            return Some(CallOutcome::Return(0));
        }
        if !crate::address_space::is_user_range(buffer, length) {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
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
        return Some(through_registry(
            &mut context,
            None,
            None,
            Some(destination),
        ));
    }
    if number == SyscallNumber::Close as usize {
        // `Close(descriptor)`: the registry returns the slot, whether it named
        // a file or a pipe's end.  Dropping the end is the pipe's own
        // accounting moving, which is what makes a reader's end-of-file real.
        //
        // The end is recognised **before** the close: afterwards the descriptor
        // is gone and no answer could tell a pipe's write end from a file's.
        // A write end going away is the fact a blocked reader is parked waiting
        // to learn, no bytes are ever coming, so the close wakes what a
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
        return Some(outcome);
    }
    if number == SyscallNumber::Dup as usize {
        // `Dup(descriptor)`: a second handle on the same thing, on the lowest
        // free number.  No pointer, so the registry is reached directly and the
        // five reserved slots are the handler's to refuse.
        //
        // The line is the new number, which is a fact only this path can
        // report: a program's descriptor numbers are its own and it prints none
        // of them, and a `Dup` that answered without making a handle would be
        // indistinguishable from one that worked.
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, None, None, None);
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
        {
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(" duplicated descriptor ");
            arch::serial::write_u32(call.arguments[0] as u32);
            arch::serial::write_str(" as ");
            arch::serial::write_u32(answer as u32);
            arch::serial::write_str("\n");
        }
        return Some(outcome);
    }
    if number == SyscallNumber::Dup2 as usize {
        // `Dup2(descriptor, target)`: the copy lands on the number the caller
        // named, and whatever that number held is closed first.  The line says
        // where it landed and that the answer was that target, which is the one
        // property separating this call from `Dup`.
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, None, None, None);
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
        {
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(" placed descriptor ");
            arch::serial::write_u32(call.arguments[0] as u32);
            arch::serial::write_str(" on ");
            arch::serial::write_u32(answer as u32);
            arch::serial::write_str("\n");
        }
        return Some(outcome);
    }
    if number == SyscallNumber::Fcntl as usize {
        // `Fcntl(descriptor, command, argument)`: seven commands over one
        // number, none of which takes a user pointer, so the registry is
        // reached directly.
        //
        // The line names the command and its answer.  A command word is a
        // number the program chose, so a boot that printed only the answer
        // could not say which command produced it -- and `F_GETFL` answering
        // three and `F_DUPFD` answering three are two very different facts.
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, None, None, None);
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
        {
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(" fcntl command ");
            arch::serial::write_u32(call.arguments[1] as u32);
            arch::serial::write_str(" on descriptor ");
            arch::serial::write_u32(call.arguments[0] as u32);
            arch::serial::write_str(" answered ");
            arch::serial::write_u32(answer as u32);
            arch::serial::write_str("\n");
        }
        return Some(outcome);
    }
    if number == SyscallNumber::Stat as usize {
        // `Stat(path, record, length)`: the path is a NUL-terminated string in
        // the caller's memory, the record is where the kernel writes the ABI's
        // sixteen-byte `FileStat`, and the length is how much room the caller
        // made.  The copy is the `Open` branch's, and so is the reason for it.
        let mut path_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(path) = copy_user_path(call.arguments[0], &mut path_bytes) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        };
        let record = call.arguments[1];
        let length = call.arguments[2];
        if !crate::address_space::is_user_range(record, length) {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
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
        return Some(outcome);
    }

    // The path mutations: make a directory, take a name away, move a name.
    // They take paths the same way `Open` and `Stat` do, and the rename's
    // second path is the one call whose path borrow arrives in a second slot.
    if number == SyscallNumber::CreateDir as usize || number == SyscallNumber::RemovePath as usize {
        let mut path_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(path) = copy_user_path(call.arguments[0], &mut path_bytes) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
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
        return Some(outcome);
    }
    if number == SyscallNumber::Rename as usize {
        let mut old_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(old_path) = copy_user_path(call.arguments[0], &mut old_bytes) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        };
        let mut new_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(new_path) = copy_user_path(call.arguments[1], &mut new_bytes) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
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
        return Some(outcome);
    }
    if number == SyscallNumber::ReadDir as usize {
        // `ReadDir(path, index, buffer, length)`: one entry of the directory
        // at the path, written into the caller's buffer as the ABI's record
        // with the name packed after it.  The answer is the bytes written,
        // and the evidence line names the path and the index, the entry's
        // name is in the record the caller now holds.
        let mut path_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(path) = copy_user_path(call.arguments[0], &mut path_bytes) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        };
        let buffer = call.arguments[2];
        let length = call.arguments[3];
        if !crate::address_space::is_user_range(buffer, length) {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
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
        return Some(outcome);
    }
    if number == SyscallNumber::StatFd as usize || number == SyscallNumber::ReadDirFd as usize {
        // The two readings asked of a descriptor instead of a path:
        // `StatFd(descriptor, record, length)` and
        // `ReadDirFd(descriptor, index, buffer, length)`.
        //
        // One branch because the two differ only in where the buffer sits and
        // what the handler does with it, which is the same reading the
        // socket-option pair gets: the record is `a1` and `a2` for the stat,
        // `a2` and `a3` for the listing, and the index the listing reads in
        // between is a word the stat does not have.
        //
        // Neither copies a path: the descriptor already resolved one, and the
        // handler reads it from the table.  What this branch does owe the
        // registry is the buffer's validation, because a ring-3 address is a
        // number until something checks it.
        let is_stat = number == SyscallNumber::StatFd as usize;
        let (buffer, length) = if is_stat {
            (call.arguments[1], call.arguments[2])
        } else {
            (call.arguments[2], call.arguments[3])
        };
        if !crate::address_space::is_user_range(buffer, length) {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        // SAFETY: the range is inside the user window and not empty, which
        // `is_user_range` checked, and the pages behind it are the calling
        // task's own mappings, installed on this CPU.  The stat writes the
        // sixteen-byte record and the listing writes the record and the name,
        // nothing past either.
        let destination = unsafe { core::slice::from_raw_parts_mut(buffer as *mut u8, length) };
        let outcome = through_registry(&mut context, None, None, Some(destination));
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
        {
            // The line names the descriptor rather than a path, because the
            // descriptor is all this call was given: a program that never knew
            // the path is the reason the call exists, and a line that printed
            // one would be the kernel reporting a fact it was not told.
            arch::serial::write_str("protofire: process ");
            arch::serial::write_u32(crate::scheduler::current_pid().unwrap_or(0));
            arch::serial::write_str(if is_stat {
                " stat'd descriptor "
            } else {
                " listed descriptor "
            });
            arch::serial::write_u32(call.arguments[0] as u32);
            arch::serial::write_str("\n");
        }
        return Some(outcome);
    }

    // The `*At` calls: the same five operations their plain twins serve, with
    // the path anchored at a descriptor instead of at the root.  The
    // descriptor travels in the first argument, the path in the second
    // including for the rename, whose second name brings its own anchor in
    // the third.
    if number == SyscallNumber::OpenAt as usize
        || number == SyscallNumber::CreateDirAt as usize
        || number == SyscallNumber::RemovePathAt as usize
    {
        let mut path_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(path) = copy_user_path(call.arguments[1], &mut path_bytes) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
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
        return Some(outcome);
    }
    if number == SyscallNumber::StatAt as usize {
        let mut path_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(path) = copy_user_path(call.arguments[1], &mut path_bytes) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        };
        let record = call.arguments[2];
        let length = call.arguments[3];
        if !crate::address_space::is_user_range(record, length) {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
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
        return Some(outcome);
    }
    if number == SyscallNumber::RenameAt as usize {
        let mut old_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(old_path) = copy_user_path(call.arguments[1], &mut old_bytes) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        };
        let mut new_bytes = [0u8; OPEN_PATH_MAX];
        let Ok(new_path) = copy_user_path(call.arguments[3], &mut new_bytes) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
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
        return Some(outcome);
    }

    // A read from a stream: the bytes the peer sent that this side has not
    // taken, or a park until some arrive.  The park is the pipe reader's
    // and the datagram receiver's shape, with the same re-check under the
    // scheduler's lock; the card's ring is drained first, so a frame the
    // card is holding is bytes in the stream's inbox rather than a wait
    // that answers nothing.
    //
    // End of file is the read that answers zero, and it comes from a stream
    // whose connection is gone, which an orderly close's last
    // acknowledgement leaves behind.  A read that never answered zero would
    // be a reader parked on a writer that said it was done.
    if number == SyscallNumber::Read as usize
        && crate::syscall::tcp_stream_for(call.arguments[0], caller).is_some()
    {
        // The slots a file read takes, because a stream is a descriptor the
        // same wrapper packs the same way: `a1` the offset, `a2` the buffer,
        // `a3` its length.  A stream has no position to seek, so the offset
        // slot is refused unless it is the read-from-here sentinel, an
        // explicit offset on a stream would be a position neither side
        // tracks.
        let descriptor = call.arguments[0];
        let offset = call.arguments[1];
        let buffer = call.arguments[2];
        let length = call.arguments[3];
        if offset != crate::syscall::READ_OFFSET_CURRENT
            || !crate::address_space::is_user_range(buffer, length)
        {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
        }
        let Some(stream) = crate::syscall::tcp_stream_for(descriptor, caller) else {
            return Some(CallOutcome::Return(abi::syscall::encode_error(
                abi::Error::InvalidArgument,
            )));
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
                    return Some(crate::scheduler::switch_without_saving(frame));
                }
            }
        }
        return Some(match answer {
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
        });
    }

    None
}
