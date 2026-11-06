//! arch/aarch64/src/program/mod.rs
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
/// longest of the three.
pub const PROGRAM_WORDS_FOR_TEST: usize = 33;

/// The longest of the three images: the announcing program, the pipe writer
/// and the pipe reader.  A program is copied into a whole page, so this
/// matters only to the copy.
pub const PROGRAM_LEN: usize = 33 * 4;

pub const PIPE_READER: u16 = 3;

pub const PIPE_WRITER: u16 = 2;

/// The image `exec` may name, and the highest number `program_bytes` answers
/// for with a purpose-built program.  One through this are the images this
/// boot has; a call beyond it is one the kernel refuses, there being no
/// program behind the number.
pub const EXEC_IMAGE: u16 = 4;

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
/// The read blocks, the pipe is empty and its writer is alive, and the
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

/// The image `exec` hands a process over to: announce, then prove whose it is.
///
/// The process that execs into this keeps its pid, which is the one thing
/// `exec` must not change, and this image is built to show it: it announces
/// the image's own number, then asks the kernel who it is and exits with the
/// answer — which is already where `GetPid` leaves it, `x0` being both the
/// answer register and `Exit`'s argument on this machine, so the two calls
/// need no move between them.
const EXEC_TARGET_PROGRAM: [u32; 8] = [
    0xD280_0081, // movz x1, #4      (announce the image)
    0xD280_00C8, // movz x8, #6      (Write)
    0xD400_0001, // svc #0
    0xD280_0A28, // movz x8, #81     (GetPid)
    0xD400_0001, // svc #0
    0xD280_0068, // movz x8, #3      (Exit, whose status is x0)
    0xD400_0001, // svc #0
    0x1400_0000, // b .
];

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
/// writes the stack page it inherited — `sub sp, sp, #16` moving the pointer
/// below the boundary and `str x0, [sp]` writing through it, which is what a
/// `push` would have done.  The page is shared and read-only now, so the
/// write faults, and the kernel's answer to that fault is the whole of what
/// this image exercises.
const fn program_words(number: u16) -> [u32; 33] {
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
        0xD100_43FF, // sub sp, sp, #16   (room below the boundary)
        0xF900_03E0, // str x0, [sp]      (the copy-on-write fault)
        0xD280_0080, // movz x0, #4       (the image exec hands the task to)
        0xD280_0348, // movz x8, #26      (ExecProcess)
        0xD400_0001, // svc #0
        0x1400_0000, // b .               (never reached: exec replaced the program)
        // The child: the same write, on its own copy of the page, then an
        // exit whose status is zero.
        0xD100_43FF, // sub sp, sp, #16   (room below the boundary)
        0xF900_03E0, // str x0, [sp]      (the child's copy-on-write fault)
        0xD280_0000, // movz x0, #0       (the child exits zero)
        0xD280_0068, // movz x8, #3       (Exit)
        0xD400_0001, // svc #0
        0x1400_0000, // b .
    ]
}

/// A program's bytes, for a caller that writes them into a frame.
pub fn program_bytes(number: u16) -> [u8; PROGRAM_LEN] {
    let mut bytes = [0u8; PROGRAM_LEN];
    let mut words = [0u32; PROGRAM_LEN / 4];
    if number == EXEC_IMAGE {
        words[..EXEC_TARGET_PROGRAM.len()].copy_from_slice(&EXEC_TARGET_PROGRAM);
    } else if number == PIPE_WRITER {
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
