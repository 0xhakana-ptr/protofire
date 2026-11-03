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
pub const fn program_stack_top(number: u16) -> usize {
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
            let ticks = crate::TIMER_TICKS.load(core::sync::atomic::Ordering::Acquire) as u32;
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
        match crate::scheduler::sleep_for_microseconds(microseconds) {
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
                crate::scheduler::advance(frame, false);
                arch::serial::write_str("protofire: every program is asleep, waiting\n");
                crate::idle_until_woken();
                // A task woke, so the scheduler has something to install.  The
                // frame from this call is the sleeper's, and `advance` replaces
                // it with the woken task's.
                return crate::scheduler::advance(frame, false);
            }
            None => {
                return CallOutcome::Return(abi::syscall::encode_error(abi::Error::NotImplemented));
            }
        }
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
    }
}
