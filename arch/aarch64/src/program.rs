//! arch/aarch64/src/program.rs
//!
//! The programs a boot runs, as this machine's machine code.
//!
//! ## Why the bytes live with the machine
//!
//! A program is machine code, so the array lives with the machine that executes
//! it: `svc` is the call, `x8` is the number, and `x1` holds this program's own
//! number because `Write` prints its second argument.  The kernel names
//! `arch::program_bytes` and gets whichever machine answered.
//!
//! ## Why the words are written out
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

/// How many words the announcing program has.
///
/// Named so a test can find where *this* program ends in a buffer sized for the
/// longest of the three.
pub const PROGRAM_WORDS_FOR_TEST: usize = 24;

/// How long a program's image is, in bytes.
///
/// The longest of the three images: the announcing program, the pipe writer
/// and the pipe reader.  A program is copied into a whole page, so this
/// matters only to the copy.
pub const PROGRAM_LEN: usize = 25 * 4;

/// The number of the program that reads the pipe.
pub const PIPE_READER: u16 = 3;

/// The number of the program that writes to it.
pub const PIPE_WRITER: u16 = 2;

/// The writer: announce, sleep, announce again, then put bytes in the pipe.
///
/// The reader must reach its `Read` first and block, or a write into a pipe
/// nobody has read yet is an ordinary copy.  The reader's loop is shorter and
/// it makes no earlier call; this sleep then makes the order a fact rather
/// than a hope.
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
    0xD280_0000, // movz x0, #0
    0xD280_0068, // movz x8, #3   (Exit)
    0xD400_0001, // svc #0
    0xD280_0080, // movz x0, #4   (a no-op before the branch)
    0x1400_0000, // b .
];

/// The reader: wait on a descriptor the boot left on its stack.
///
/// `[sp]` is the read end's descriptor and `[sp + 8]` the four-byte buffer.
/// The read blocks — the pipe is empty and its writer is alive — and the
/// writer's syscall is the only thing that ends the wait.
const PIPE_READER_PROGRAM: [u32; 21] = [
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
    0xD280_0000, // movz x0, #0
    0xD280_0068, // movz x8, #3     (Exit)
    0xD400_0001, // svc #0
];

/// How long the program sleeps, in microseconds.
///
/// Long enough to span several time slices, so the wake is observably later
/// than the request rather than inside the same tick.  A sleep the timer could
/// not distinguish from "did not sleep" would be a call that ran and proved
/// nothing.
pub const SLEEP_MICROSECONDS: u64 = 20_000;

/// One program's words: its number, a busy loop, and four calls.
///
/// Built rather than stored so the number is a parameter: a table of two
/// constants would be two things to keep in step with the encoding.
///
/// ## Why the order is loop, Write, Sleep, Write, Exit
///
/// The first `Write` says which program ran.  `Sleep` then takes it out of the
/// rotation for [`SLEEP_MICROSECONDS`], during which the *other* program runs —
/// so a log that shows two "says hello" lines before the second program's is a
/// log where sleeping worked.  The second `Write` after the sleep is what makes
/// the wake visible: a program that never woke prints one line, not two.
const fn program_words(number: u16) -> [u32; 24] {
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
        0xD289_C400,                                       /* movz x0, #20000   (the sleep's
                                                            * microseconds) */
        0xD280_0628, // movz x8, #49      (Sleep)
        0xD400_0001, // svc #0
        0xD280_00C8, // movz x8, #6       (Write, after the wake)
        0xD400_0001, // svc #0
        // Who am I, last, so the answer is still in `x0` when `Exit` takes it:
        // the boot reports the exit status, and a status that is the program's
        // own pid is evidence the identity call ran.
        // Fork, at the very end: the two processes that result are told apart
        // by what it answered, and by nothing else.
        0xD280_07C8, // movz x8, #62      (Fork)
        0xD400_0001, // svc #0
        // The answer is kept in `x19`, which no call here writes: `Write` fills
        // `x0`, and `Exit` reads `x0`, so the fork's answer left in `x0` would
        // be the write's count by the time the status is taken.
        0xAA00_03F3, // mov x19, x0       (keep the fork's answer)
        0xAA13_03E1, // mov x1, x19       (Write prints it)
        0xD280_00C8, // movz x8, #6       (Write)
        0xD400_0001, // svc #0
        0xAA13_03E0, // mov x0, x19       (the answer becomes Exit's status)
        0xD280_0068, // movz x8, #3       (Exit)
        0xD400_0001, // svc #0
        0x1400_0000, // b .
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
mod tests;
