//! arch/aarch64/src/program.rs
//!
//! The programs a boot runs, as this machine's machine code.
//!
//! A program is machine code, so the array lives with the machine that executes
//! it: `svc` is the call, `x8` is the number, and `x1` holds this program's own
//! number because `Write` prints its second argument.  The kernel names
//! `arch::program_bytes` and gets whichever machine answered.
//!
//! Every instruction is a literal with its decoding beside it.  AArch64 has no
//! small-immediate encoding as regular as RISC-V's `addi`, so the words here
//! are the disassembly, checked by the tests against the ABI numbers they
//! encode.

// The program a boot runs, as this machine's machine code.
//
// A program is machine code, so the array lives with the machine that executes
// it: `svc` is the call, `x8` is the number and `x1` holds this program's own
// number because `Write` prints its second argument.  The kernel names
// `arch::program_bytes` and gets whichever machine answered.

/// Named so a test can find where *this* program ends in a buffer sized for the
/// longest of the four.
pub const PROGRAM_WORDS_FOR_TEST: usize = 34;

/// The longest of the four images: the announcing program, the pipe writer,
/// the pipe reader and the exec target.  A program is copied into a whole
/// page, so this matters only to the copy, but it must be at least the
/// longest, and the reader grew past thirty-two words when its reads, its wait
/// and its status filled out.  Thirty-four leaves the announcing program's own
/// thirty-two untouched and is what every image now fits inside.
pub const PROGRAM_LEN: usize = 42 * 4;

/// The `e_machine` this machine's programs carry, which the loader checks the
/// image against before it maps one page of it.
pub const ELF_MACHINE: u16 = 183; // EM_AARCH64

pub const PIPE_READER: u16 = 3;

pub const PIPE_WRITER: u16 = 2;

/// The writer: announce, sleep, announce again, put bytes in the pipe, close
/// the write end.
///
/// The reader must reach its `Read` first and block, or a write into a pipe
/// nobody has read yet is an ordinary copy.  The reader's loop is shorter and
/// it makes no earlier call; this sleep then makes the order a fact rather
/// than a hope.
///
/// The `Close` is the boot's own proof of end-of-file: the reader's second
/// read can only return because the write end went away, and a close that
/// did not move the pipe's count would leave the reader parked and the boot
/// unfinished.
///
/// The descriptor is loaded from the stack **again** for the close: the pipe
/// write's answer is in `x0` by then, and a close that took its descriptor
/// from there would close whatever descriptor numbered four.
///
/// `[sp]` holds the write end's descriptor and `[sp + 8]` is the four bytes it
/// sends.
const PIPE_WRITER_PROGRAM: [u32; 25] = [
    0xD280_0803, // movz x3, #64
    0xD280_2002, // movz x2, #256
    0xF100_0442, // subs x2, x2, #1
    0x54FF_FFE1, // b.ne -1
    0xF100_0463, // subs x3, x3, #1
    0x54FF_FF81, // b.ne -4
    0xD280_0041, // movz x1, #2   (this program's number)
    0xD280_00C8, // movz x8, #6   (Write)
    0xD400_0001, // svc #0
    0xD289_C400, // movz x0, #20000 (the sleep)
    0xD280_0628, // movz x8, #49  (Sleep)
    0xD400_0001, // svc #0
    0xD280_0041, // movz x1, #2   (Write, after the wake)
    0xD280_00C8, // movz x8, #6
    0xD400_0001, // svc #0
    0xF940_03E0, // ldr x0, [sp]  (the write end)
    0x9100_23E1, // add x1, sp, #8 (the bytes)
    0xD280_0082, // movz x2, #4
    0xD280_00C8, // movz x8, #6   (Write to the pipe)
    0xD400_0001, // svc #0
    // **No `Close`.**  The program exits with its write end still open, and
    // the reader's end-of-file is then the exit's release, the descriptor
    // belongs to the process, so the process ending closes it.  That is the
    // claim this image makes on the boot: a release that did not run would
    // leave the reader parked on a writer that no longer exists, the boot
    // would never finish, and the gate's own report would never print.
    0xD280_0000, // movz x0, #0
    0xD280_0068, // movz x8, #3   (Exit)
    0xD400_0001, // svc #0
    0xD280_0080, // movz x0, #4   (a no-op before the branch)
    0x1400_0000, // b .
];

/// The reader: wait on a descriptor the boot left on its stack, read again
/// after the wake, and then wait for the writer's process to end.
///
/// `[sp]` is the read end's descriptor and `[sp + 8]` the four-byte buffer.
/// The first read blocks, the pipe is empty and its writer is alive, and the
/// writer's syscall is the only thing that ends the wait.
///
/// The **second** read is the boot's own proof of end-of-file.  The pipe is
/// drained by then and the writer's end is closed, so nothing but "no bytes
/// ever" can answer it: a read that returned would have to be end-of-file,
/// and a close that never moved the pipe's count would leave this program
/// parked with the boot unfinished.
///
/// The **third** read is what end-of-file actually answers.  The first read
/// blocked and the writer's four bytes woke it; the second read then *consumed*
/// those four and answered `4`, which is a short read and not a close.  Only a
/// read after the buffer is drained can see "no writer", and a program that
/// stopped at two would have exited with the bytes' count and proved nothing.
/// A close that never moved the pipe's count leaves this third read parked
/// with the boot unfinished, which is what the gate refuses.
///
/// `WaitProcess` after it is the boot's own proof of the wait.  Which of its
/// two paths runs is a race the program cannot control, the writer may have
/// exited while this read was returning, or may still be one call short, and
/// **both are the mechanism working**: a status that has arrived answers at
/// once, and one that has not parks this task until the writer's exit wakes
/// it.  The exit takes its status from the wait's answer, so a wait that
/// answered an error puts that error in the boot's status line and the gate
/// refuses it.
const PIPE_READER_PROGRAM: [u32; 42] = [
    0xD280_0803, // movz x3, #64
    0xD280_2002, // movz x2, #256
    0xF100_0442, // subs x2, x2, #1
    0x54FF_FFE1, // b.ne -1
    0xF100_0463, // subs x3, x3, #1
    0x54FF_FF81, // b.ne -4
    0xD280_0061, // movz x1, #3     (announce)
    0xD280_00C8, // movz x8, #6     (Write)
    0xD400_0001, // svc #0
    0xF940_03E0, // ldr x0, [sp]    (the read end)
    0x9100_23E1, // add x1, sp, #8  (the buffer)
    0xD280_0082, // movz x2, #4
    0xD280_00A8, // movz x8, #5     (Read)
    0xD400_0001, // svc #0
    // The length is cleared before the second announcement: `x2` still holds
    // the read's four, and a write with a length to a pipe descriptor is a pipe
    // write, so the announcement would go into the pipe and print nothing.
    0xD280_0002, // movz x2, #0     (announce has no length)
    0xD280_0061, // movz x1, #3     (Write, after the wait)
    0xD280_00C8, // movz x8, #6
    0xD400_0001, // svc #0
    0xF940_03E0, // ldr x0, [sp]    (the read end, again)
    0x9100_23E1, // add x1, sp, #8  (the buffer)
    0xD280_0082, // movz x2, #4
    0xD280_00A8, // movz x8, #5     (Read, the one end-of-file ends)
    0xD400_0001, // svc #0
    // **Install a fault handler** and then take a fault on purpose.  The
    // store below writes the program's own code page, which is mapped
    // read-execute and not copy-on-write: no resolver answers it, so without a
    // handler the program would be killed.  With one, the kernel resumes the
    // program at the handler with the vector in `x0`, the address in `x1` and
    // the direction in `x2`, and the handler's `ReturnFromException` is what
    // brings it back here.
    // The handler's **virtual** address: this page's base plus the handler's
    // offset.  `movz x0, #offset` alone installs an offset, `0x68`, and the
    // first fault then lands outside the program's mapping, which is a fault
    // the handler answers by faulting again.  Measured: an endless run of
    // `handled its own fault at 0x68`.
    0x9000_0000, // adrp x0, #0     (this page's base)
    0x91022000,  // add x0, x0, #136 (HANDLER_OFFSET)
    0xD280_02C8, // movz x8, #22    (InstallExceptionHandler)
    0xD400_0001, // svc #0
    0x9000_0000, // adrp x0, #0     (this code page's base)
    0xB900_001F, // str wzr, [x0]   (the fault the handler answers)
    // Wait for **the writer**, by pid, and make its status this program's.
    // `WaitProcess` answers about whichever process finished first, and this
    // boot's forked child dies before the writer does, so the status it
    // hands back can be another process's.  `WaitProcessOf(2)` names the one
    // this program is waiting for, and `2` is the writer's own number because
    // the boot names each program after the number it was built with.
    0xD280_0040, // movz x0, #2     (the writer's pid)
    0xD280_1888, // movz x8, #196   (WaitProcessOf)
    0xD400_0001, // svc #0
    0xD280_0068, // movz x8, #3     (Exit, the status is the writer's)
    0xD400_0001, // svc #0
    // The fault handler, at `HANDLER_OFFSET` bytes into the page.  It
    // writes one line saying it ran and returns the fault's vector as the
    // call's answer, so the boot has both a line and a status that only a
    // handler could produce.
    0xD280_0801, // movz x1, #64     (this program's number, the line's text)
    0xD280_00C8, // movz x8, #6      (Write)
    0xD400_0001, // svc #0
    // `ReturnFromException(faulting_instruction + 4, value)`.  The fourth
    // argument, in `x3`, is where the fault happened; this machine's
    // instructions are four bytes, so the instruction after it is `+ 4`.  On
    // x86_64 that size is not a constant and the handler is the only thing
    // that knows it, which is why the kernel asks rather than computes.
    0x9100_1080, // add x0, x4, #4    (the instruction after the fault)
    0xD280_0021, // movz x1, #1      (the value the call answers with)
    0xD280_02E8, // movz x8, #23     (ReturnFromException)
    0xD400_0001, // svc #0
    0x1400_0000, // b .              (never reached: the call above returns)
];

/// Where the reader's fault handler sits, in words from the page's base.
///
/// The program installs it by address, so the two numbers, the one the
/// `InstallExceptionHandler` call carries and the one the array puts the
/// handler at, have to agree.  A test pins them together; a program whose
/// handler offset drifted would install an address inside its own code and the
/// fault it then took would be answered by whatever word happened to be there.
pub const HANDLER_OFFSET: u32 = 136;

/// Long enough to span several time slices, so the wake is observably later
/// than the request rather than inside the same tick.  A sleep the timer could
/// not distinguish from "did not sleep" would be a call that ran and proved
/// nothing.
pub const SLEEP_MICROSECONDS: u64 = 20_000;

/// One program's words: its number, a busy loop, and its calls.
///
/// Built rather than stored so the number is a parameter: a table of two
/// constants would be two things to keep in step with the encoding.
///
/// The first `Write` says which program ran.  `Sleep` then takes it out of the
/// rotation for [`SLEEP_MICROSECONDS`], during which the *other* program runs,
/// /// so a log that shows two "says hello" lines before the second program's
/// is a log where sleeping worked.  The second `Write` after the sleep is what
/// makes the wake visible: a program that never woke prints one line, not two.
///
/// After the fork the two processes part ways on the answer alone, and each
/// writes the stack page it inherited, `sub sp, sp, #16` moving the pointer
/// below the boundary and `str x0, [sp]` writing through it, which is what a
/// `push` would have done.  The page is shared and read-only now, so the
/// write faults, and the kernel's answer to that fault is the whole of what
/// this image exercises.
const fn program_words(number: u16) -> [u32; 34] {
    [
        // A busy loop, so a program outlives a time slice.
        //
        // Without it a program finishes in microseconds, no tick arrives, and a
        // boot that never preempted is indistinguishable from one that could
        // not.  The loop is nested because one register's 16-bit immediate is
        // about twelve microseconds, the first version was one register and
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
        0xD289_C400,                                       /* movz x0, #20000   (the sleep's
                                                            * microseconds) */
        0xD280_0628, // movz x8, #49      (Sleep)
        0xD400_0001, // svc #0
        0xD280_00C8, // movz x8, #6       (Write, after the wake)
        0xD400_0001, // svc #0
        // A pipe of this program's own, so the fork below has something to
        // inherit: two descriptors owned by this process, copied to the child
        // and owned by it.  Without this the inheritance runs on a boot whose
        // programs hold nothing, which is a mechanism nothing observes.
        0xD280_0808, // movz x8, #64      (Pipe)
        0xD400_0001, // svc #0
        // Fork: the two processes that result are told apart by what it
        // answered, and by nothing else.
        0xD280_07C8, // movz x8, #62      (Fork)
        0xD400_0001, // svc #0
        // The answer is kept in `x19`, which no call here writes: `Write` fills
        // `x0`, and `Exit` reads `x0`, so the fork's answer left in `x0` would
        // be the write's count by the time the status is taken.
        0xAA00_03F3, // mov x19, x0       (keep the fork's answer)
        0xAA13_03E1, // mov x1, x19       (Write prints it)
        0xD280_00C8, // movz x8, #6       (Write)
        0xD400_0001, // svc #0
        // The parent holds its child's pid, the child holds zero: `cbz` sends
        // the child five words down, to the same shape with a zero status.
        0xB400_00F3, // cbz x19, +7 words (the child takes the second path)
        // The parent: write the shared page, then become the image `exec`
        // names.  The task survives the change with its pid, and its exit
        // status comes from the image it became, which asks the kernel who it
        // is and exits with the answer.
        // The pointer comes before the sub: `sp` here is the hand-over top,
        // and `[sp, #-32]` is exactly where the boot left the exec path.
        // `x0` survives the copy-on-write fault below, the resolver restores
        // every register, so the exec that follows reads what this loaded.
        0xF85C_03E0, // ldur x0, [sp, #-64] (the boot's exec path)
        0xD100_43FF, // sub sp, sp, #16     (room below the boundary)
        0xF900_03E0, // str x0, [sp]        (the copy-on-write fault)
        0xD280_0348, // movz x8, #26        (ExecProcess)
        0xD400_0001, // svc #0
        0x1400_0000, // b .               (never reached: exec replaced the program)
        // The child: the same write, on its own copy of the page, and then
        // the deliberate one, a store into its own **code** page, read-only
        // and not copy-on-write, which no resolver answers.  The kernel kills
        // the process for it and the machine goes on; the child's status is
        // the kernel's, not its own.
        0xD100_43FF, // sub sp, sp, #16   (room below the boundary)
        0xF900_03E0, // str x0, [sp]      (the child's copy-on-write fault)
        0x9000_0000, // adrp x0, #0       (this page's base)
        0xB900_001F, // str wzr, [x0]     (the fatal write)
        0x1400_0000, // b .               (never reached: the child is dead)
    ]
}

/// A program's bytes, for a caller that writes them into a frame.
pub fn program_bytes(number: u16) -> [u8; PROGRAM_LEN] {
    let mut bytes = [0u8; PROGRAM_LEN];
    let mut words = [0u32; PROGRAM_LEN / 4];
    if number == PIPE_WRITER {
        words[..PIPE_WRITER_PROGRAM.len()].copy_from_slice(&PIPE_WRITER_PROGRAM);
    } else if number == PIPE_READER {
        words[..PIPE_READER_PROGRAM.len()].copy_from_slice(&PIPE_READER_PROGRAM);
    } else {
        let announcing = program_words(number);
        words[..announcing.len()].copy_from_slice(&announcing);
    }
    for (index, word) in words.iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    bytes
}

#[cfg(test)]
mod tests {
    //! The tests for this module.
    //!
    //! The aarch64 program's tests: the words decoded back to the instructions
    //! they claim, the busy loop's branches, and the calls the program makes.
    //!
    //! The two helpers below the header are test-only: a scan for a call's
    //! `movz x8, n` and a lookup of the `movz` that set a register before it.

    /// The syscall numbers a program's words ask for, in order.
    ///
    /// Every call is `movz x8, <number>` followed immediately by `svc #0`, so
    /// the pair names it, a scan for the register write rather than a table of
    /// indices a reader would have to count.
    #[cfg(test)]
    fn call_numbers(words: &[u32]) -> alloc::vec::Vec<usize> {
        let mut calls = alloc::vec::Vec::new();
        for index in 0..words.len().saturating_sub(1) {
            if words[index + 1] != 0xD400_0001 {
                continue;
            }
            // `movz x8, #imm`: `movz` is 0xD280_0000 with the register in bits
            // 0..5.
            let word = words[index];
            let is_movz = (word >> 23) & 0x3F == 0b100101 && (word >> 31) & 1 == 1;
            if is_movz && word & 0x1F == 8 {
                calls.push(((word >> 5) & 0xFFFF) as usize);
            }
        }
        calls
    }

    /// The immediate the `movz reg, #imm` before a call's `svc` carries.
    #[cfg(test)]
    fn immediate_before(words: &[u32], call: abi::SyscallNumber, register: u32) -> i64 {
        let mut value = 0i64;
        for index in 0..words.len().saturating_sub(1) {
            let word = words[index];
            let is_movz = (word >> 23) & 0x3F == 0b100101 && (word >> 31) & 1 == 1;
            if words[index + 1] == 0xD400_0001 {
                if is_movz && word & 0x1F == 8 && ((word >> 5) & 0xFFFF) as usize == call as usize {
                    return value;
                }
                continue;
            }
            if is_movz && word & 0x1F == register {
                value = ((word >> 5) & 0xFFFF) as i64;
            }
        }
        0
    }

    use crate::program::program_bytes;
    use crate::program::program_words;

    /// The program's bytes are the words in little-endian order.
    #[test]
    fn the_program_is_little_endian() {
        let bytes = program_bytes(1);
        assert_eq!(bytes.len(), crate::program::PROGRAM_LEN);
        assert_eq!(&bytes[0..4], &0xD280_0803u32.to_le_bytes());
        // The announcing program ends with `b .`; the buffer is sized for the
        // longest of the three, so the word sits where *this* program ends
        // rather than at the buffer's end.
        let announcing_words = crate::program::PROGRAM_WORDS_FOR_TEST;
        let last = announcing_words * 4 - 4;
        assert_eq!(&bytes[last..last + 4], &0x1400_0000u32.to_le_bytes());
    }

    /// The loop is a real nested countdown, decoded from the encoding.
    #[test]
    fn the_busy_loop_branches_back_to_itself() {
        let words = program_words(1);
        assert_eq!(words[0], 0xD280_0000 | (64 << 5) | 3);
        assert_eq!(words[1], 0xD280_0000 | (256 << 5) | 2);

        let inner = (((words[3] >> 5) & 0x7FFFF) as i32) << 13 >> 13;
        assert_eq!(inner, -1, "the inner branch loops on itself");
        assert_eq!(words[3] & 0xF, 0b0001, "and it is `ne`");

        let outer = (((words[5] >> 5) & 0x7FFFF) as i32) << 13 >> 13;
        assert_eq!(outer, -4, "the outer branch reloads the inner count");
        assert_eq!(words[5] & 0xF, 0b0001, "and it is `ne` too");
    }

    /// Every syscall number the program uses is the ABI's own.
    ///
    /// `Write`, `Sleep`, `Write`, `Fork`, `Write`, `ExecProcess`, and no
    /// `Exit` at all: the parent's path ends in the exec, and the child's ends
    /// in the fault the kernel kills it for, so neither path exits itself.  A
    /// program compiled against a number this build does not serve would print
    /// its first line and then fail silently, which is the one failure a sleep
    /// program could have and still look healthy.
    #[test]
    fn the_program_writes_sleeps_writes_forks_writes_and_execs() {
        let words = program_words(1);
        assert_eq!(
            call_numbers(&words),
            alloc::vec![
                abi::SyscallNumber::Write as usize,
                abi::SyscallNumber::Sleep as usize,
                abi::SyscallNumber::Write as usize,
                abi::SyscallNumber::Pipe as usize,
                abi::SyscallNumber::Fork as usize,
                abi::SyscallNumber::Write as usize,
                abi::SyscallNumber::ExecProcess as usize,
            ],
            "the program writes, sleeps, writes, makes a pipe, forks, writes, and execs"
        );

        // The sleep's duration is the immediate of the `movz x0` that precedes
        // the Sleep call, found by role rather than counted.
        assert_eq!(
            immediate_before(&words, abi::SyscallNumber::Sleep, 0) as u64,
            crate::program::SLEEP_MICROSECONDS
        );
    }

    /// The number is the only word that differs.
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

    /// The writer's calls, in order, and the exit that closes the pipe's end.
    ///
    /// There is no `Close` in this image on purpose.  The writer exits with its
    /// write end still open, so the reader's end-of-file is the **exit's
    /// release**: the descriptor belongs to the process, and the process ending
    /// closes it.  A release that did not run would leave the reader parked on
    /// a writer that no longer exists, the boot would never print its report,
    /// and the gate requires that report.
    #[test]
    fn the_writer_puts_bytes_in_the_pipe_and_exits_with_its_end_open() {
        let words = crate::program::PIPE_WRITER_PROGRAM;
        assert_eq!(
            call_numbers(&words),
            alloc::vec![
                abi::SyscallNumber::Write as usize,
                abi::SyscallNumber::Sleep as usize,
                abi::SyscallNumber::Write as usize,
                abi::SyscallNumber::Write as usize,
                abi::SyscallNumber::Exit as usize,
            ],
            "the writer writes, sleeps, writes, writes the pipe, and exits"
        );
        assert!(
            !call_numbers(&words).contains(&(abi::SyscallNumber::Close as usize)),
            "no close: the exit is what releases the end"
        );
        assert_eq!(
            call_numbers(&words).last(),
            Some(&(abi::SyscallNumber::Exit as usize)),
            "and the exit is the last call it makes"
        );
    }

    /// The reader reads to end-of-file, then waits for the **writer** by pid.
    ///
    /// `WaitProcessOf` rather than `WaitProcess`: the latter answers about
    /// whichever process finished first, and this boot's forked child dies
    /// before the writer, so its status can be another process's.  Naming the
    /// writer's pid makes the answer about the writer, which is why the exit
    /// can hand it straight out as this program's own status.
    #[test]
    fn the_reader_reads_to_end_of_file_and_waits_for_the_writer() {
        let words = crate::program::PIPE_READER_PROGRAM;
        assert_eq!(
            call_numbers(&words),
            alloc::vec![
                abi::SyscallNumber::Write as usize,
                abi::SyscallNumber::Read as usize,
                abi::SyscallNumber::Write as usize,
                abi::SyscallNumber::Read as usize,
                abi::SyscallNumber::InstallExceptionHandler as usize,
                abi::SyscallNumber::WaitProcessOf as usize,
                abi::SyscallNumber::Exit as usize,
                abi::SyscallNumber::Write as usize,
                abi::SyscallNumber::ReturnFromException as usize,
            ],
            "the reader installs a handler, faults, waits by pid, exits, and the handler writes and returns"
        );

        // The handler's address and its place in the array are one fact written
        // twice: the program names an offset into its own page, and the array
        // has to put the handler's first word there.  A drift would install an
        // address inside the program's own code, and the fault would be
        // answered by whatever word happened to sit there.
        let handler_word = crate::program::HANDLER_OFFSET as usize / 4;
        assert!(
            handler_word < words.len(),
            "the handler is inside the array"
        );
        assert_eq!(
            words[handler_word], 0xD280_0801,
            "and its first word is the handler's own `movz x1, #64`"
        );

        // The pid is the writer's own number, in `x0` just before the call.
        let wait = words
            .windows(2)
            .position(|pair| {
                (pair[0] >> 5) & 0xFFFF == abi::SyscallNumber::WaitProcessOf as u32
                    && (pair[0] >> 23) & 0x3F == 0b100101
                    && (pair[0] >> 31) & 1 == 1
                    && pair[0] & 0x1F == 8
                    && pair[1] == 0xD400_0001
            })
            .expect("the reader waits");
        let pid = words[wait - 1];
        assert_eq!(pid & 0x1F, 0, "the pid goes in `x0`");
        assert_eq!(
            (pid >> 5) & 0xFFFF,
            crate::program::PIPE_WRITER as u32,
            "and it is the writer's"
        );

        // The exit takes the wait's answer: the word before `movz x8, #3` is
        // the `svc` itself, with no `movz x0` between.
        let exit = words
            .windows(2)
            .position(|pair| {
                (pair[0] >> 5) & 0xFFFF == abi::SyscallNumber::Exit as u32
                    && (pair[0] >> 23) & 0x3F == 0b100101
                    && (pair[0] >> 31) & 1 == 1
                    && pair[0] & 0x1F == 8
                    && pair[1] == 0xD400_0001
            })
            .expect("the reader exits");
        assert_eq!(
            words[exit - 1],
            0xD400_0001,
            "nothing overwrote the wait's answer before `Exit` took it"
        );
    }
}
