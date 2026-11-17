//! kernel/src/process/memory.rs
//!
//! The memory calls whose answer depends on the process's own space: `Mmap`'s
//! window arithmetic.
//!
//! One family of `serve`'s branches, moved out so the dispatcher reads as a
//! list of families.  `None` means this family does not serve `number` and
//! `serve` tries the next one; `Some(outcome)` is the call's answer and ends
//! the dispatch.

use super::through_registry;

pub(crate) fn serve_memory(
    call: arch::CallFrame,
    frame: &mut arch::Context,
    number: usize,
    caller: Option<u32>,
) -> Option<arch::CallOutcome> {
    use arch::CallOutcome;
    use syscall::SyscallNumber;
    let _ = (&call, &*frame, number, caller);
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
        // would otherwise reach this log only through its exit status, and an
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
        return Some(outcome);
    }

    // Shared memory.  Three of the four take no buffer and go the way the
    // memory calls above do; `ShmCtl`'s `IPC_STAT` writes a record, so it takes
    // the buffer path and its validation is here because this branch is what
    // turns a ring-3 word into a borrow.
    if number == SyscallNumber::ShmGet as usize
        || number == SyscallNumber::ShmAt as usize
        || number == SyscallNumber::ShmDt as usize
    {
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        let outcome = through_registry(&mut context, None, None, None);
        if let CallOutcome::Return(answer) = outcome
            && !abi::syscall::is_error_status(answer)
        {
            // One line per call that worked, and the answer in it, because the
            // answer is the whole of what the call produced: an identifier, an
            // address, or a region taken down.  A refusal prints nothing here
            // and the program's own status carries it, which is the rule every
            // family in this file keeps.
            arch::serial::write_str("protofire: program shared memory call ");
            arch::serial::write_u32(number as u32);
            arch::serial::write_str(" answered ");
            arch::serial::write_hex(answer as u64);
            arch::serial::write_str("\n");
        }
        return Some(outcome);
    }
    if number == SyscallNumber::ShmCtl as usize {
        // `ShmCtl(identifier, command, record, length)`: `IPC_STAT` writes the
        // record, so the buffer is validated the way every other buffer-taking
        // call validates one, and `IPC_RMID` passes none of it.
        let record = call.arguments[2];
        let length = call.arguments[3];
        let mut context = syscall::SyscallContext::new(number, call.arguments)
            .with_identity(security::mac::MAC_TYPE_SYSTEM)
            .with_caller(crate::scheduler::current_pid().unwrap_or(crate::programs::BOOT_PROCESS));
        if call.arguments[1] == abi::memory::IPC_STAT {
            if length < abi::memory::SHM_STAT_SIZE {
                return Some(CallOutcome::Return(abi::syscall::encode_error(
                    abi::Error::InvalidArgument,
                )));
            }
            if !crate::address_space::user_range(record, length, true) {
                return Some(CallOutcome::Return(abi::syscall::encode_error(
                    abi::Error::InvalidArgument,
                )));
            }
            // SAFETY: the range is inside the user window and mapped in the
            // calling task's own root, which `user_range` checked.  The handler
            // writes the record and nothing past it.
            let destination = unsafe { core::slice::from_raw_parts_mut(record as *mut u8, length) };
            return Some(through_registry(
                &mut context,
                None,
                None,
                Some(destination),
            ));
        }
        return Some(through_registry(&mut context, None, None, None));
    }

    None
}
