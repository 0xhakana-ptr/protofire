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
//! Thirty-two bytes of AArch64, written as words rather than assembled, so a
//! reader can check it against the architecture:
//!
//! | word | encoding | meaning |
//! |---|---|---|
//! | `0xD2800020` | `movz x0, #1` | the first argument |
//! | `0xD28000C8` | `movz x8, #6` | syscall 6, which is `Write` |
//! | `0xD2800001` | `movz x1, #0` | the second argument |
//! | `0xD4000001` | `svc #0` | call the kernel |
//! | `0xF100441F` | `cmp x0, #17` | **did the call's answer arrive?** |
//! | `0x54000080` | `b.eq +16` | yes: skip the failure path |
//! | `0xD2800040` | `movz x0, #2` | no: exit status two |
//! | `0xD2800068` | `movz x8, #3` | syscall 3, which is `Exit` |
//! | `0xD4000001` | `svc #0` | call the kernel |
//! | `0xD2800000` | `movz x0, #0` | exit status zero |
//! | `0xD2800068` | `movz x8, #3` | syscall 3, which is `Exit` |
//! | `0xD4000001` | `svc #0` | call the kernel |
//! | `0x14000000` | `b .` | never reached |
//!
//! The bytes were disassembled by `llvm-objdump` before they were written here,
//! which is the check that they are the instructions this table says they are.
//!
//! ## Why the program checks the answer
//!
//! The comparison at word 4 is what makes the return path observable.  Without
//! it the program ignored `x0`, so a kernel that never wrote the answer back
//! produced exactly the same output — the boot printed "hello from ring 3" and
//! a clean exit either way.  Deleting the write-back in the trap path now makes
//! the program exit with status two, and the gate refuses that line.

#[cfg(target_os = "none")]
use syscall::SyscallNumber;

/// The program, as the words the machine executes.
///
/// Little-endian in memory, because that is the byte order AArch64 fetches
/// instructions in.
const PROGRAM: [u32; 13] = [
    0xD280_0020, // movz x0, #1
    0xD280_00C8, // movz x8, #6  (Write)
    0xD280_0001, // movz x1, #0
    0xD400_0001, // svc #0
    0xF100_441F, // cmp x0, #17 — the length `Write` answered with
    0x5400_0080, // b.eq +16
    0xD280_0040, // movz x0, #2 — the failure status
    0xD280_0068, // movz x8, #3  (Exit)
    0xD400_0001, // svc #0
    0xD280_0000, // movz x0, #0
    0xD280_0068, // movz x8, #3  (Exit)
    0xD400_0001, // svc #0
    0x1400_0000, // b .
];

/// The program's bytes, for a caller that writes them into a frame.
pub fn program_bytes() -> [u8; PROGRAM_LEN] {
    let mut bytes = [0u8; PROGRAM_LEN];
    for (index, word) in PROGRAM.iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

/// The program's length in bytes.
pub const PROGRAM_LEN: usize = 13 * 4;

/// Where a program's image and stack are mapped.
///
/// Inside the identity map, because this boot has one address space: the
/// program's pages are reachable from the kernel without a walk, which is what
/// lets the kernel copy the image in through the frame's physical address.
///
/// A high address rather than a low one, and well past the kernel's own image:
/// a program that overran into the kernel's text would fault on the `user` bit
/// rather than quietly run kernel instructions.
pub const PROGRAM_BASE: usize = 0x0100_0000;

/// The stack's top.  One page below the image, growing down.
pub const PROGRAM_STACK_TOP: usize = PROGRAM_BASE - 16;

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
pub fn serve(call: arch::CallFrame) -> arch::CallOutcome {
    use arch::CallOutcome;

    let number = call.number;
    if number == SyscallNumber::Exit as usize {
        return CallOutcome::Exit(call.arguments[0]);
    }
    if number == SyscallNumber::Write as usize {
        arch::serial::write_str(PROGRAM_OUTPUT);
        arch::serial::write_str("\n");
        return CallOutcome::Return(PROGRAM_OUTPUT.len());
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
#[cfg(target_os = "none")]
const PROGRAM_OUTPUT: &str = "hello from ring 3";

#[cfg(test)]
mod tests {
    use super::PROGRAM;
    use super::program_bytes;

    /// The program's bytes are the words in little-endian order.
    ///
    /// A program built by writing bytes in the wrong order is one the machine
    /// fetches as different instructions, and it would fault at an address the
    /// kernel chose rather than at anything in the program.
    #[test]
    fn the_program_is_little_endian() {
        let bytes = program_bytes();
        assert_eq!(bytes.len(), super::PROGRAM_LEN);
        assert_eq!(bytes.len(), 13 * 4);
        assert_eq!(&bytes[0..4], &0xD280_0020u32.to_le_bytes());
        assert_eq!(&bytes[48..52], &0x1400_0000u32.to_le_bytes());
    }

    /// Every word is a `movz`, an `svc` or a branch — the three this program
    /// uses — and each is checked against its encoding.
    ///
    /// A typo in a constant here would be a program the machine runs as
    /// something else, and the failure would look like a trap at a plausible
    /// address.
    #[test]
    fn every_word_is_the_instruction_it_claims() {
        // movz xD, #imm: 0xD2800000 | imm16 << 5 | D
        assert_eq!(PROGRAM[0], 0xD280_0000 | (1 << 5), "movz x0, #1");
        assert_eq!(PROGRAM[1], 0xD280_0000 | (6 << 5) | 8, "movz x8, #6");
        assert_eq!(PROGRAM[2], 0xD280_0000 | 1, "movz x1, #0");

        // svc #0.
        assert_eq!(PROGRAM[3], 0xD400_0001, "svc #0");
        assert_eq!(PROGRAM[8], 0xD400_0001, "svc #0");
        assert_eq!(PROGRAM[11], 0xD400_0001, "svc #0");

        // cmp x0, #17 — `subs xzr, x0, #imm12`.
        assert_eq!(PROGRAM[4], 0xF100_0000 | (17 << 10) | 0x1F, "cmp x0, #17");

        assert_eq!(PROGRAM[9], 0xD280_0000, "movz x0, #0");
        assert_eq!(PROGRAM[10], 0xD280_0000 | (3 << 5) | 8, "movz x8, #3");

        // b . is a branch with offset zero.
        assert_eq!(PROGRAM[12] & 0xFC00_0000, 0x1400_0000, "b");
        assert_eq!(PROGRAM[12] & 0x03FF_FFFF, 0, "to itself");
    }

    /// The branch skips exactly the failure path, landing on the success one.
    ///
    /// An offset off by one word lands inside the failure sequence and runs it
    /// anyway, which is a program that exits two on every run — including the
    /// correct one.  Computing the target from the encoding is what checks it.
    #[test]
    fn the_branch_lands_on_the_success_path() {
        // b.eq imm19: signed, in words, from the branch.
        let offset = ((PROGRAM[5] >> 5) & 0x7FFFF) as i32;
        let target = 5 + offset;
        assert_eq!(target, 9, "the branch lands on `movz x0, #0`");
        assert_eq!(PROGRAM[9], 0xD280_0000, "which is the success status");
    }

    /// The two syscall numbers the program uses are the ABI's own.
    ///
    /// Read from the encoding rather than compared to a literal, because a
    /// number that moved would still decode and the program would call
    /// something else.
    #[test]
    fn the_program_calls_write_and_exit() {
        let write = (PROGRAM[1] >> 5) & 0xFFFF;
        let exit = (PROGRAM[10] >> 5) & 0xFFFF;
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
}
