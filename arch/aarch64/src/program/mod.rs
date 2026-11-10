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
/// longest of the four.
pub const PROGRAM_WORDS_FOR_TEST: usize = 32;

/// The longest of the four images: the announcing program, the pipe writer,
/// the pipe reader and the exec target.  A program is copied into a whole
/// page, so this matters only to the copy — but it must be at least the
/// longest, and the reader grew past thirty-two words when its reads, its wait
/// and its status filled out.  Thirty-four leaves the announcing program's own
/// thirty-two untouched and is what every image now fits inside.
pub const PROGRAM_LEN: usize = 34 * 4;

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
    // the reader's end-of-file is then the exit's release — the descriptor
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
/// two paths runs is a race the program cannot control — the writer may have
/// exited while this read was returning, or may still be one call short — and
/// **both are the mechanism working**: a status that has arrived answers at
/// once, and one that has not parks this task until the writer's exit wakes
/// it.  The exit takes its status from the wait's answer, so a wait that
/// answered an error puts that error in the boot's status line and the gate
/// refuses it.
const PIPE_READER_PROGRAM: [u32; 28] = [
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
    // Wait for **the writer**, by pid, and make its status this program's.
    // `WaitProcess` answers about whichever process finished first, and this
    // boot's forked child dies before the writer does — so the status it
    // hands back can be another process's.  `WaitProcessOf(2)` names the one
    // this program is waiting for, and `2` is the writer's own number because
    // the boot names each program after the number it was built with.
    0xD280_0040, // movz x0, #2     (the writer's pid)
    0xD280_1888, // movz x8, #196   (WaitProcessOf)
    0xD400_0001, // svc #0
    0xD280_0068, // movz x8, #3     (Exit — the status is the writer's)
    0xD400_0001, // svc #0
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
const fn program_words(number: u16) -> [u32; 32] {
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
        // The pointer comes before the sub: `sp` here is the hand-over top,
        // and `[sp, #-32]` is exactly where the boot left the exec path.
        // `x0` survives the copy-on-write fault below — the resolver restores
        // every register — so the exec that follows reads what this loaded.
        0xF85C_03E0, // ldur x0, [sp, #-64] (the boot's exec path)
        0xD100_43FF, // sub sp, sp, #16     (room below the boundary)
        0xF900_03E0, // str x0, [sp]        (the copy-on-write fault)
        0xD280_0348, // movz x8, #26        (ExecProcess)
        0xD400_0001, // svc #0
        0x1400_0000, // b .               (never reached: exec replaced the program)
        // The child: the same write, on its own copy of the page, and then
        // the deliberate one — a store into its own **code** page, read-only
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
mod tests;
