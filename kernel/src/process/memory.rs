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

    None
}
