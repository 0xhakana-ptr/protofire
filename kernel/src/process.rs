//! kernel/src/process.rs
//!
//! One program, running at EL0, calling back into the kernel.
//!
//! ## What this is
//!
//! The smallest thing that makes the trap path real: a frame of machine code
//! mapped into the kernel's own table with `user: true`, an `eret` that enters
//! EL0 at it, and a supervisor-call handler that answers.  Nothing here
//! schedules, and nothing is preempted — there is one program and it runs until
//! it exits.
//!
//! ## Why the kernel's table holds a user page
//!
//! A program needs its own address space, and giving it one means a second root
//! table plus a `TTBR0_EL1` swap on every entry and exit.  That is the next
//! change; today the program's page lives in the kernel's table with
//! `user: true`, and the kernel's own pages have `user: false`.  So the
//! protection is real — a program that read a kernel address faults — and the
//! isolation of one program from another is not, because there is one.
//!
//! ## The program
//!
//! Twenty-eight bytes of AArch64, written as words rather than assembled, so a
//! reader can check it against the architecture:
//!
//! | word | encoding | meaning |
//! |---|---|---|
//! | `0xD2800021` | `movz x1, #1` | which program this is |
//! | `0xD28000C8` | `movz x8, #6` | syscall 6, which is `Write` |
//! | `0xD4000001` | `svc #0` | call the kernel |
//! | `0xD2800000` | `movz x0, #0` | exit status zero |
//! | `0xD2800068` | `movz x8, #3` | syscall 3, which is `Exit` |
//! | `0xD4000001` | `svc #0` | call the kernel |
//! | `0x14000000` | `b .` | never reached |
//!
//! `x1` is the only word that differs between the two programs: it is the
//! number the kernel prints, so a boot log says *which* program ran and in what
//! order.  Two programs that printed the same thing would be indistinguishable
//! from one running twice.
//!
//! The bytes were disassembled by `llvm-objdump` before they were written here,
//! which is the check that they are the instructions this table says they are.

/// One program's words: its number, then the same three calls.
///
/// Built rather than stored so the number is a parameter: a table of two
/// constants would be two things to keep in step with the encoding.
const fn program_words(number: u16) -> [u32; 13] {
    [
        // A busy loop, so a program outlives a time slice.
        //
        // Without it a program finishes in microseconds, no tick arrives, and a
        // boot that never preempted is indistinguishable from one that could
        // not.  The loop is nested because one register's 16-bit immediate is
        // about twelve microseconds — the first version was one register and
        // the count was zero.
        0xD280_0803, // movz x3, #64      (outer)
        0xD280_2002, // movz x2, #256     (inner)
        0xF100_0442, // subs x2, x2, #1
        0x54FF_FFE1, /* b.ne -1            (inner, to the
                      * subs) */
        0xF100_0463, // subs x3, x3, #1
        0x54FF_FF81, /* b.ne -4            (outer, to the
                      * inner reload) */
        0xD280_0000 | ((number as u32 & 0xFFFF) << 5) | 1, // movz x1, #number
        0xD280_00C8,                                       // movz x8, #6  (Write)
        0xD400_0001,                                       // svc #0
        0xD280_0000,                                       // movz x0, #0
        0xD280_0068,                                       // movz x8, #3  (Exit)
        0xD400_0001,                                       // svc #0
        0x1400_0000,                                       // b .
    ]
}

/// A program's bytes, for a caller that writes them into a frame.
pub fn program_bytes(number: u16) -> [u8; PROGRAM_LEN] {
    let words = program_words(number);
    let mut bytes = [0u8; PROGRAM_LEN];
    for (index, word) in words.iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

/// A program's length in bytes.
pub const PROGRAM_LEN: usize = 13 * 4;

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
        // The interrupt mask as the program left it.  A program that ran with
        // IRQ masked never receives a tick, and the trap frame carries the
        // `SPSR` the exception was taken with — so this reads what the machine
        // actually had, not what the kernel meant to set.
        arch::serial::write_str("protofire: program spsr ");
        arch::serial::write_u32((frame.spsr & 0x3C0) as u32);
        arch::serial::write_str("\n");
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
    use super::program_bytes;
    use super::program_words;

    /// The program's bytes are the words in little-endian order.
    ///
    /// A program built by writing bytes in the wrong order is one the machine
    /// fetches as different instructions, and it would fault at an address the
    /// kernel chose rather than at anything in the program.
    #[test]
    fn the_program_is_little_endian() {
        let bytes = program_bytes(1);
        assert_eq!(bytes.len(), super::PROGRAM_LEN);
        assert_eq!(bytes.len(), 13 * 4);
        assert_eq!(&bytes[0..4], &0xD280_0803u32.to_le_bytes());
        assert_eq!(&bytes[48..52], &0x1400_0000u32.to_le_bytes());
    }

    /// The loop is a real nested countdown, decoded from the encoding.
    ///
    /// A program that ran to its `svc` in a few microseconds never sees a tick,
    /// and the boot then reports a timer that "did not preempt" whether or not
    /// preemption works.  So the shape of the loop is part of what the program
    /// is, and the branch targets are what makes it a loop rather than a
    /// straight line.
    #[test]
    fn the_busy_loop_branches_back_to_itself() {
        let words = program_words(1);

        // movz x3, #64 — the outer count.
        assert_eq!(words[0], 0xD280_0000 | (64 << 5) | 3);
        // movz x2, #256 — the inner count.
        assert_eq!(words[1], 0xD280_0000 | (256 << 5) | 2);

        // subs x2, x2, #1
        assert_eq!(words[2], 0xF100_0000 | (1 << 10) | (2 << 5) | 2);
        // b.ne -1, conditional on `subs` having left the zero flag clear.
        // imm19 is signed, so the field has to be sign-extended: reading it
        // as an unsigned 19-bit number turns -1 into 524287.
        let inner = (((words[3] >> 5) & 0x7FFFF) as i32) << 13 >> 13;
        assert_eq!(inner, -1, "the inner branch loops on itself");
        assert_eq!(
            words[3] & 0xF,
            0b0001,
            "and it is `ne`, not another condition"
        );

        // subs x3, x3, #1
        assert_eq!(words[4], 0xF100_0000 | (1 << 10) | (3 << 5) | 3);
        // b.ne -4: back to the inner reload, so the inner loop runs again.
        let outer = (((words[5] >> 5) & 0x7FFFF) as i32) << 13 >> 13;
        assert_eq!(outer, -4, "the outer branch reloads the inner count");
        assert_eq!(words[5] & 0xF, 0b0001, "and it is `ne` too");
    }

    /// Every word after the loop is the instruction it claims to be.
    #[test]
    fn every_word_is_the_instruction_it_claims() {
        let words = program_words(1);

        // movz x1, #1 — `movz xD, #imm16`: 0xD2800000 | imm16 << 5 | D
        assert_eq!(words[6], 0xD280_0000 | (1 << 5) | 1, "movz x1, #1");
        assert_eq!(words[7], 0xD280_0000 | (6 << 5) | 8, "movz x8, #6");

        assert_eq!(words[8], 0xD400_0001, "svc #0");
        assert_eq!(words[11], 0xD400_0001, "svc #0");

        assert_eq!(words[9], 0xD280_0000, "movz x0, #0");
        assert_eq!(words[10], 0xD280_0000 | (3 << 5) | 8, "movz x8, #3");

        // b . is a branch with offset zero.
        assert_eq!(words[12] & 0xFC00_0000, 0x1400_0000, "b");
        assert_eq!(words[12] & 0x03FF_FFFF, 0, "to itself");
    }

    /// The number is the only word that differs.
    ///
    /// Two programs whose code differed in more than their number would be two
    /// programs, and the test that says "they differ by the number" is the one
    /// that says the log line identifies which one ran.
    #[test]
    fn the_number_is_the_only_word_that_differs() {
        let one = program_words(1);
        let two = program_words(2);
        let differing: alloc::vec::Vec<usize> = (0..one.len())
            .filter(|index| one[*index] != two[*index])
            .collect();
        assert_eq!(differing, alloc::vec![6], "only `movz x1` differs");

        assert_eq!((one[6] >> 5) & 0xFFFF, 1);
        assert_eq!((two[6] >> 5) & 0xFFFF, 2);
    }

    /// The two syscall numbers the program uses are the ABI's own.
    #[test]
    fn the_program_calls_write_and_exit() {
        let words = program_words(1);
        let write = (words[7] >> 5) & 0xFFFF;
        let exit = (words[10] >> 5) & 0xFFFF;
        assert_eq!(
            write as usize,
            syscall::SyscallNumber::Write as usize,
            "the first svc is Write"
        );
        assert_eq!(
            exit as usize,
            syscall::SyscallNumber::Exit as usize,
            "the second svc is Exit"
        );
    }

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
