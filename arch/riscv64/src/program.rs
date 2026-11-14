//! arch/riscv64/src/program.rs
//!
//! The programs a boot runs, as this machine's machine code.
//!
//! A program is machine code, so the array lives with the machine that executes
//! it: `ecall` is the call, `a7` carries the number and `a1` holds this
//! program's own number because `Write` prints its second argument.  The kernel
//! names `arch::program_bytes` and gets whichever machine answered, an array
//! in the kernel would have to be right for three architectures, and there is
//! no array that is.
//!
//! Every immediate the ABI needs is an `addi`, and every loop is one branch.
//! Written as raw literals those are thirty numbers a reader cannot check;
//! written as `addi(rd, rs, imm)` the intent is the argument list, and the
//! tests decode what the encoder produced rather than trusting the arithmetic.

// The program a boot runs, as this machine's machine code.
//
// A program is machine code, so the array lives with the machine that
// executes it: `ecall` is the call, `a7` carries the number and `a1` holds
// this program's own number because `Write` prints its second argument.  The
// kernel names `arch::program_bytes` and gets whichever machine answered.

/// The longest of the four images: the announcing program, the pipe writer,
/// the pipe reader and the exec target.  A program is copied into a whole
/// page, so this matters only to the copy, but it must be at least the
/// longest, and the reader grew past thirty-two words when its reads, its wait
/// and its status filled out.
pub const PROGRAM_LEN: usize = 44 * 4;

/// The `e_machine` this machine's programs carry, which the loader checks the
/// image against before it maps one page of it.
pub const ELF_MACHINE: u16 = 243; // EM_RISCV

pub const PIPE_READER: u16 = 3;

pub const PIPE_WRITER: u16 = 2;

/// The image `exec` may name, and the highest number `program_bytes` answers
/// for with a purpose-built program.  One through this are the images this
/// boot has; a call beyond it is one the kernel refuses, there being no
/// program behind the number.
pub const EXEC_IMAGE: u16 = 4;

/// Two thousand, and that is the encoding's answer rather than a preference:
/// the sleep travels in an `addi` immediate, whose twelve signed bits reach
/// two thousand and forty-seven, the aarch64 program's twenty thousand needs
/// the sixteen bits a `movz` has, which this machine's instruction does not.
/// Two milliseconds is twenty time slices at this boot's hundred, which is
/// what the duration is for: a wake observably later than the request, where
/// a sleep the timer could not distinguish from "did not sleep" would be a
/// call that ran and proved nothing.
pub const SLEEP_MICROSECONDS: u64 = 2_000;

use crate::trap::REGISTER_A0;
use crate::trap::REGISTER_A1;
use crate::trap::REGISTER_A6;
use crate::trap::REGISTER_A7;

/// `addi rd, rs, imm`, as the word the machine reads.
///
/// The workhorse of a hand-written program: every immediate the ABI needs, a
/// call number in `a7`, a duration in `a0`, this program's own number in `a1`
///, is one of these.  A helper rather than thirty literals, because an
/// immediate encoded wrong by hand is an instruction the machine reads as
/// something else and the failure is a plausible-looking wrong answer.
const fn addi(rd: u32, rs: u32, immediate: i32) -> u32 {
    // `imm[11:0] | rs1 | funct3 | rd | opcode`, the I-type layout.
    ((immediate as u32) & 0xFFF) << 20 | rs << 15 | rd << 7 | 0x13
}

/// `bne rs, x0, offset`, as the word the machine reads.
///
/// The busy loop's only branch: one register counted down against zero, back
/// to the instruction `offset` bytes before.  Encoded here for the same reason
/// `addi` is, a branch offset in the wrong field loops to an address the
/// program did not mean, and the failure is a fault far from the word that
/// caused it.
const fn bne_against_zero(rs: u32, offset: i32) -> u32 {
    let immediate = (offset as u32) & 0x1FFF;
    // `imm[12|10:5] | rs2=0 | rs1 | funct3 | imm[4:1|11] | opcode`, the
    // B-type layout: the immediate is split around the registers it does not
    // touch.
    (immediate & 0x1000) << 19
        | ((immediate >> 5) & 0x3F) << 25
        | rs << 20
        | 1 << 12
        | (immediate & 0x1E) << 7
        | (immediate & 0x800) >> 4
        | 0x63
}

/// `beq rs, x0, offset`, as the word the machine reads.
///
/// The fork's only branch: the child's answer is zero, and this is the one
/// instruction that sends it down its own path.  The same B-type layout
/// [`bne_against_zero`] spells, with the function bits zero, `beq` and `bne`
/// differ in those three bits and in nothing else, which is why both are
/// encoded here rather than one of them being a masked copy of the other.
const fn beq_against_zero(rs: u32, offset: i32) -> u32 {
    let immediate = (offset as u32) & 0x1FFF;
    (immediate & 0x1000) << 19
        | ((immediate >> 5) & 0x3F) << 25
        | rs << 20
        | (immediate & 0x1E) << 7
        | (immediate & 0x800) >> 4
        | 0x63
}

/// `lb rd, 0(rs)`, as the word the machine reads.
///
/// The read's first byte, into the register `Exit` takes its status from: an
/// I-type load, whose function bits name the byte-width sign-extending form.
/// The immediate is zero and so is not a parameter; the source register is,
/// because the buffer is wherever the program put it.
const fn load_byte(rd: u32, rs: u32) -> u32 {
    rs << 15 | rd << 7 | 0x03
}

/// `sd rs2, 0(sp)`, as the word the machine reads.
///
/// The stack write, at offset zero off the stack pointer: an S-type store,
/// whose immediate is split the way the B-type one is and whose function bits
/// name the doubleword.  The immediate is zero and so is not a parameter; the
/// register is, because both paths write and each holds the fork's answer in
/// its own copy of it.
const fn store_against_sp(rs2: u32) -> u32 {
    rs2 << 20 | 2 << 15 | 3 << 12 | 0x23
}

/// Counted once here rather than inferred: the array length and the word list
/// have to agree, and a literal on both would be two numbers to keep in step.
pub const PROGRAM_WORDS: usize = 34;

/// The busy loop: outer 64, inner 256, one decrement each.
///
/// Without it a program finishes in microseconds, no tick arrives, and a boot
/// that never preempted is indistinguishable from one that could not.  The
/// loop is nested because one register's twelve-bit immediate is a small
/// count, and the counts are the aarch64 program's, the same work per
/// iteration, so the same number of them spans a slice under the same
/// emulator.
const BUSY_LOOP: [u32; 6] = [
    addi(13, 0, 64),           // li a3, #64      (outer)
    addi(12, 0, 256),          // li a2, #256     (inner)
    addi(12, 12, -1),          // addi a2, a2, -1
    bne_against_zero(12, -4),  // bne a2, x0, back to the decrement
    addi(13, 13, -1),          // addi a3, a3, -1
    bne_against_zero(13, -16), // bne a3, x0, back to the inner reload
];

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
/// writes the stack page it inherited, the pointer moved below the boundary
/// and a doubleword stored through it, which is what a push would have done.
/// The page is shared and read-only now, so the write faults, and the
/// kernel's answer to that fault is the whole of what this image exercises.
const fn program_words(number: u16) -> [u32; PROGRAM_WORDS] {
    [
        BUSY_LOOP[0],
        BUSY_LOOP[1],
        BUSY_LOOP[2],
        BUSY_LOOP[3],
        BUSY_LOOP[4],
        BUSY_LOOP[5],
        addi(REGISTER_A1 as u32, 0, number as i32), // li a1, #number
        addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Write as i32),
        0x0000_0073,                                            // ecall
        addi(REGISTER_A0 as u32, 0, SLEEP_MICROSECONDS as i32), // li a0, #the sleep
        addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Sleep as i32),
        0x0000_0073, // ecall
        addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Write as i32),
        0x0000_0073, // ecall
        // A pipe of this program's own before the fork, so the child has
        // something to inherit.
        addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Pipe as i32),
        0x0000_0073, // ecall
        // Fork: the two processes that result are told apart by what `fork`
        // answered, and by nothing else.
        //
        // The answer is kept in `a6`, which no call of this program writes:
        // `Write` fills `a0` with its own answer, and `Exit` reads `a0`, so a
        // fork's answer left in `a0` would be the write's count by the time the
        // status is taken, which is exactly what the first run printed
        // (`1 -> 21`, and 21 is what `Write` answers).
        addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Fork as i32),
        0x0000_0073,                                     // ecall
        addi(REGISTER_A6 as u32, REGISTER_A0 as u32, 0), // mv a6, a0
        addi(REGISTER_A1 as u32, REGISTER_A6 as u32, 0), // mv a1, a6
        addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Write as i32),
        0x0000_0073, // ecall
        // The parent holds its child's pid, the child holds zero: `beq` sends
        // the child seven words down, to the same shape with a zero status.
        beq_against_zero(REGISTER_A6 as u32, 28), // beq a6, x0, the child path
        // The parent: write the shared page, then become the image `exec`
        // names.  The task survives the change with its pid, and its exit
        // status comes from the image it became, which asks the kernel who it
        // is and exits with the answer.
        // The pointer comes before the addi: `sp` here is the hand-over top,
        // and `-32(sp)` is exactly where the boot left the exec path.  `a0`
        // survives the copy-on-write fault below, the resolver restores every
        // register, so the exec that follows reads what this loaded.
        0xFC01_3503,                          // ld a0, -64(sp)     (the boot's exec path)
        addi(2, 2, -16),                      // addi sp, sp, -16
        store_against_sp(REGISTER_A6 as u32), // sd a6, 0(sp) (the fault)
        addi(
            REGISTER_A7 as u32,
            0,
            abi::SyscallNumber::ExecProcess as i32,
        ),
        0x0000_0073, // ecall
        0x0000_006F, // j .   (never reached: exec replaced the program)
        // The child: the same write, on its own copy of the page, and then
        // the deliberate one, a store into its own **code** page, read-only
        // and not copy-on-write, which no resolver answers.  The kernel kills
        // the process for it and the machine goes on; the child's status is
        // the kernel's, not its own.
        addi(2, 2, -16),                      // addi sp, sp, -16
        store_against_sp(REGISTER_A6 as u32), // sd a6, 0(sp) (the fault)
        0x0000_0517,                          // auipc a0, 0  (this page's base)
        0x0005_2023,                          // sw x0, 0(a0) (the fatal write)
        0x0000_006F,                          // j .          (never reached)
    ]
}

/// The image `exec` hands a process over to: announce, then read a file.
///
/// `exec` leaves one word of inheritance below the stack top, a pointer to a
/// NUL-terminated path, the bytes themselves just above it, and this image
/// is the one that uses it: it opens the path, reads thirty-two bytes into
/// its own stack below the block, closes the descriptor, and exits with the
/// **first byte it read**, `a0` being `Exit`'s argument register.  A boot
/// line that reports `process 1 opened /greeting.txt` and an exit status of
/// `116`, the `t` of "the quick brown pyrofox", are the pair that proves a
/// task the exec rebuilt, with its own pid and its own window, read the
/// boot's own file from ring 3.
///
/// The descriptor is kept in `a6`, which no call here writes, for the same
/// reason the announcing program keeps its fork answer there.
const EXEC_TARGET_PROGRAM: [u32; 20] = [
    addi(REGISTER_A1 as u32, 0, 4), // li a1, #4      (announce the image)
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Write as i32),
    0x0000_0073,                    // ecall
    0x0001_3503,                    // ld a0, 0(sp)   (the path, [sp])
    addi(REGISTER_A1 as u32, 0, 1), // li a1, #1      (OPEN_FLAG_READ)
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Open as i32),
    0x0000_0073,                                     // ecall
    addi(REGISTER_A6 as u32, REGISTER_A0 as u32, 0), // mv a6, a0 (the descriptor)
    addi(REGISTER_A0 as u32, REGISTER_A6 as u32, 0), // mv a0, a6
    addi(REGISTER_A1 as u32, 0, -1),                 // li a1, #-1    (READ_OFFSET_CURRENT)
    addi(REGISTER_A0 as u32 + 2, 2, -128),           // addi a2, sp, -128 (the buffer)
    addi(REGISTER_A0 as u32 + 3, 0, 32),             // li a3, #32  (the length)
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Read as i32),
    0x0000_0073,                                     // ecall
    addi(REGISTER_A0 as u32, REGISTER_A6 as u32, 0), // mv a0, a6 (the descriptor again)
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Close as i32),
    0x0000_0073,                                           // ecall
    load_byte(REGISTER_A0 as u32, REGISTER_A0 as u32 + 2), // lb a0, 0(a2) (the first byte)
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Exit as i32),
    0x0000_0073, // ecall
];

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
/// write's answer is in `a0` by then, and a close that took its descriptor
/// from there would close whatever descriptor numbered four.
///
/// `x2`, the stack pointer, points at the write end's descriptor, and the
/// four bytes it sends are the word above it.
const PIPE_WRITER_PROGRAM: [u32; 24] = [
    BUSY_LOOP[0],
    BUSY_LOOP[1],
    BUSY_LOOP[2],
    BUSY_LOOP[3],
    BUSY_LOOP[4],
    BUSY_LOOP[5],
    addi(REGISTER_A1 as u32, 0, 2), // li a1, #2   (this program's number)
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Write as i32),
    0x0000_0073, // ecall
    addi(REGISTER_A0 as u32, 0, SLEEP_MICROSECONDS as i32),
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Sleep as i32),
    0x0000_0073,                    // ecall
    addi(REGISTER_A1 as u32, 0, 2), // li a1, #2   (Write, after the wake)
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Write as i32),
    0x0000_0073,                        // ecall
    0x0001_3503,                        // ld a0, 0(sp)  (the write end)
    addi(REGISTER_A1 as u32, 2, 8),     // addi a1, sp, #8 (the bytes)
    addi(REGISTER_A0 as u32 + 2, 0, 4), // li a2, #4
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Write as i32),
    0x0000_0073, // ecall
    // **No `Close`.**  The writer exits with its write end still open, so the
    // reader's end-of-file is the exit's release: the descriptor belongs to
    // the process, and the process ending closes it.  A release that did not
    // run would leave the reader parked on a writer that no longer exists.
    addi(REGISTER_A0 as u32, 0, 0),
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Exit as i32),
    0x0000_0073, // ecall
    0x0000_006F, // j .
];

/// The reader: wait on a descriptor the boot left on its stack, and read
/// again after the wake.
///
/// `x2` points at the read end's descriptor and the four-byte buffer is the
/// word above it.  The first read blocks, the pipe is empty and its writer is
/// alive, and the writer's syscall is the only thing that ends the wait.
///
/// The **second** read is the boot's own proof of end-of-file.  The pipe is
/// drained by then and the writer's end is closed, so nothing but "no bytes
/// ever" can answer it: a read that returned would have to be end-of-file,
/// and a close that never moved the pipe's count would leave this program
/// parked with the boot unfinished.  The exit takes its status from that
/// read's answer rather than a constant, so the number the boot reports is
/// the one end-of-file gave.
const PIPE_READER_PROGRAM: [u32; 42] = [
    BUSY_LOOP[0],
    BUSY_LOOP[1],
    BUSY_LOOP[2],
    BUSY_LOOP[3],
    BUSY_LOOP[4],
    BUSY_LOOP[5],
    addi(REGISTER_A1 as u32, 0, 3), // li a1, #3     (announce)
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Write as i32),
    0x0000_0073,                        // ecall
    0x0001_3503,                        // ld a0, 0(sp)  (the read end)
    addi(REGISTER_A1 as u32, 2, 8),     // addi a1, sp, #8 (the buffer)
    addi(REGISTER_A0 as u32 + 2, 0, 4), // li a2, #4
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Read as i32),
    0x0000_0073, // ecall
    // The length is cleared before the second announcement: `a2` still holds
    // the read's four, and a write with a length to a pipe descriptor is a
    // pipe write, so the announcement would go into the pipe and print
    // nothing.
    addi(REGISTER_A0 as u32 + 2, 0, 0), // li a2, #0     (announce has no length)
    addi(REGISTER_A1 as u32, 0, 3),     // li a1, #3     (Write, after the wait)
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Write as i32),
    0x0000_0073,                        // ecall
    0x0001_3503,                        // ld a0, 0(sp)  (the read end, again)
    addi(REGISTER_A1 as u32, 2, 8),     // addi a1, sp, #8 (the buffer)
    addi(REGISTER_A0 as u32 + 2, 0, 4), // li a2, #4
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Read as i32),
    0x0000_0073, // ecall
    // Install a fault handler and take a fault on purpose.
    //
    // The address is `auipc`'s own PC plus the distance to the handler's
    // first word.  A delta built as "page base + offset" needs the program's
    // load address, which a program does not know: measured, the first
    // attempt installed a page offset and the handler entry landed outside
    // the mapping.
    0x0000_0517, // auipc a0, 0     (this instruction's own address)
    addi(REGISTER_A0 as u32, REGISTER_A0 as u32, 44), // + to the handler
    addi(
        REGISTER_A7 as u32,
        0,
        abi::SyscallNumber::InstallExceptionHandler as i32,
    ),
    0x0000_0073, // ecall
    0x0000_0517, // auipc a0, 0     (this array's own address)
    0x0005_2023, // sw x0, 0(a0)    (the fault the handler answers)
    // Wait for **the writer**, by pid, and make its status this program's.
    // `WaitProcess` answers about whichever process finished first, and this
    // boot's forked child dies before the writer does.
    addi(REGISTER_A0 as u32, 0, 2), // li a0, #2      (the writer's pid)
    addi(
        REGISTER_A7 as u32,
        0,
        abi::SyscallNumber::WaitProcessOf as i32,
    ),
    0x0000_0073, // ecall
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Exit as i32),
    0x0000_0073, // ecall
    // The fault handler, 56 bytes after the `auipc` that installs it.  Its
    // arguments are a0..a3, so `a3` holds the faulting instruction; this
    // machine's instructions are four bytes and `ReturnFromException` takes
    // the address to continue at.
    addi(REGISTER_A1 as u32, 0, 64), // li a1, #64 (the line)
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Write as i32),
    0x0000_0073,                                         // ecall
    addi(REGISTER_A0 as u32, REGISTER_A0 as u32 + 4, 4), // a0 = a4 + 4
    addi(REGISTER_A1 as u32, 0, 1),                      // li a1, #1
    addi(
        REGISTER_A7 as u32,
        0,
        abi::SyscallNumber::ReturnFromException as i32,
    ),
    0x0000_0073, // ecall
    0x0000_006F, // j .   (never reached)
];

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
mod tests {
    //! The tests for this module.
    //!
    //! The riscv64 program's tests: the encoders decoded back the way the
    //! machine reads them, the busy loop's branches, and the calls this program
    //! makes.
    //!
    //! The two helpers above the tests are test-only, so they live here: a scan
    //! for a call's `li a7, n` and a lookup of the `li` that set a register
    //! before it.

    /// The syscall numbers a program's words ask for, in order.
    ///
    /// Every call is `li a7, <number>` followed immediately by `ecall`, so the
    /// pair is what names it, a scan for the register write rather than a table
    /// of indices a reader would have to count.
    #[cfg(test)]
    fn call_numbers(words: &[u32]) -> alloc::vec::Vec<usize> {
        let mut calls = alloc::vec::Vec::new();
        for pair in words.windows(2) {
            if pair[1] != 0x0000_0073 {
                continue;
            }
            // `addi x17, x0, imm` with the number in the low twelve bits.
            let is_li_a7 = pair[0] & 0x7F == 0x13
                && (pair[0] >> 7) & 0x1F == REGISTER_A7 as u32
                && (pair[0] >> 15) & 0x1F == 0;
            if !is_li_a7 {
                continue;
            }
            calls.push(((pair[0] as i32) >> 20) as usize);
        }
        calls
    }

    /// The immediate the `li reg, imm` before a call's `ecall` carries.
    ///
    /// A linear scan: remember the last `addi reg, x0, imm` that wrote
    /// `register`, and answer it when the matching `ecall` arrives.  The last
    /// write wins, which is what the machine does too, so a program that sets
    /// the register once and leaves it alone is read correctly.
    #[cfg(test)]
    fn immediate_before(words: &[u32], call: abi::SyscallNumber, register: u32) -> i32 {
        let mut value = 0;
        for index in 0..words.len().saturating_sub(1) {
            let word = words[index];
            if words[index + 1] != 0x0000_0073 {
                // Not a call site; remember a `li` if this is one.
                if word & 0x7F == 0x13 && (word >> 7) & 0x1F == register && (word >> 15) & 0x1F == 0
                {
                    value = (word as i32) >> 20;
                }
                continue;
            }
            // This word is `li a7, n` if it writes a7 from zero.
            let is_li_a7 = word & 0x7F == 0x13
                && (word >> 7) & 0x1F == REGISTER_A7 as u32
                && (word >> 15) & 0x1F == 0;
            if is_li_a7 && (((word as i32) >> 20) as usize) == call as usize {
                return value;
            }
        }
        0
    }

    #[cfg(test)]
    use crate::program::REGISTER_A0;
    use crate::program::REGISTER_A1;
    use crate::program::addi;
    use crate::program::bne_against_zero;
    use crate::program::program_bytes;
    use crate::program::program_words;
    use crate::trap::REGISTER_A7;

    /// The immediate an `addi` encodes, decoded back the way the machine
    /// sign-extends it: twelve bits, so a word whose top immediate bit is set
    /// decodes negative, and a decode that stopped at sixteen would call
    /// forty thousand nine hundred and fifty-one the same as minus one.
    fn addi_immediate(word: u32) -> i32 {
        (word as i32) >> 20
    }

    /// The offset a branch word encodes, decoded back the way the machine
    /// reads it: the immediate is split around the register fields, and the
    /// test is what keeps the encoder and the decoder from agreeing on a
    /// reading neither of them got from the layout.
    fn branch_offset(word: u32) -> i32 {
        let immediate = ((word >> 31) & 1) << 12
            | ((word >> 25) & 0x3F) << 5
            | ((word >> 8) & 0xF) << 1
            | ((word >> 7) & 1) << 11;
        // Sign-extend from thirteen bits.
        ((immediate << 19) as i32) >> 19
    }

    /// The program's bytes are the words in little-endian order.
    #[test]
    fn the_program_is_little_endian() {
        let bytes = program_bytes(1);
        assert_eq!(bytes.len(), crate::program::PROGRAM_LEN);
        assert_eq!(&bytes[0..4], &0x0400_0693u32.to_le_bytes());
    }

    /// The immediate an `addi` encodes is the one it decodes to, across the
    /// sign the twelve-bit field carries: a negative decrement must come back
    /// negative, or the busy loop counts up and never ends.
    #[test]
    fn an_addi_immediate_survives_the_round_trip() {
        assert_eq!(addi_immediate(addi(12, 12, -1)), -1);
        assert_eq!(addi_immediate(addi(13, 0, 64)), 64);
        assert_eq!(addi_immediate(addi(17, 0, 6)), 6);
        // The sign is where the decode bites: the field is twelve bits, and
        // an immediate whose eleventh bit is set is negative, not a large
        // positive number the program never asked for.
        assert_eq!(addi_immediate(addi(10, 0, -480)), -480);
        // The register fields, too: an immediate in the wrong field would
        // still decode as *an* addi, just not this one.
        assert_eq!((addi(12, 12, -1) >> 15) & 0x1F, 12, "rs1");
        assert_eq!((addi(12, 12, -1) >> 7) & 0x1F, 12, "rd");
    }

    /// The busy loop branches back to itself, decoded from the encoding: the
    /// inner branch reaches the decrement four bytes up, and the outer one
    /// reaches the inner reload sixteen bytes up.
    #[test]
    fn the_busy_loop_branches_back_to_itself() {
        let words = program_words(1);
        assert_eq!(words[0], addi(13, 0, 64), "li a3, #64");
        assert_eq!(words[1], addi(12, 0, 256), "li a2, #256");

        let inner = branch_offset(words[3]);
        assert_eq!(inner, -4, "the inner branch loops on the decrement");
        assert_eq!(branch_offset(words[5]), -16, "the outer reloads");
    }

    /// Every syscall number the program uses is the ABI's own.
    ///
    /// The calls this program makes, in order.
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
        // By name, not by index: an index a reader has to count goes stale the
        // moment a word is inserted, which is what happened twice while this
        // program grew.
        let calls = call_numbers(&words);
        assert_eq!(
            calls,
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
        // The `Write` after the fork is the one that reports it: both processes
        // reach it, and the number each prints is the fork's answer, the
        // child's pid in the parent, zero in the child.
        // Found by the fork rather than by an index: an index a reader counts
        // goes stale the moment a call is inserted above it, which is what
        // happened when the pipe arrived and pointed this at the fork itself.
        let fork = calls
            .iter()
            .position(|call| *call == abi::SyscallNumber::Fork as usize)
            .expect("the program forks");
        assert_eq!(
            calls[fork + 1],
            abi::SyscallNumber::Write as usize,
            "the call after the fork is a write"
        );
        assert_eq!(
            calls.last(),
            Some(&(abi::SyscallNumber::ExecProcess as usize)),
            "and the program ends in the exec: the parent's path ends there, and the child's is the fault the kernel answers"
        );

        // The sleep's duration is the immediate of the `li a0` that precedes
        // the Sleep call, and the program's own number is the `li a1` before
        // its first Write.  Both are found by their role rather than counted.
        assert_eq!(
            immediate_before(&words, abi::SyscallNumber::Sleep, REGISTER_A0 as u32) as u64,
            crate::program::SLEEP_MICROSECONDS
        );
        assert_eq!(
            immediate_before(&words, abi::SyscallNumber::Write, REGISTER_A1 as u32) as usize,
            1
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
        assert_eq!(differing.len(), 1, "only one word differs");
        // And it is the one that carries the number: the `li a1` before the
        // first Write.
        assert_eq!(
            immediate_before(&one, abi::SyscallNumber::Write, REGISTER_A1 as u32) as usize,
            1
        );
        assert_eq!(
            immediate_before(&two, abi::SyscallNumber::Write, REGISTER_A1 as u32) as usize,
            2
        );
    }

    /// The writer's fourth call names the pipe: the descriptor is loaded from
    /// the stack the boot handed it, the buffer is the word above it, and the
    /// length is the four the payload needs.
    #[test]
    fn the_writer_reads_its_descriptor_from_the_stack() {
        let words = crate::program::PIPE_WRITER_PROGRAM;
        // `ld a0, 0(sp)`, the load's width field is 3 and the register is the
        // stack pointer's.
        assert_eq!(words[15], 0x0001_3503);
        assert_eq!(addi_immediate(words[16]), 8, "the buffer is at sp + 8");
        assert_eq!(addi_immediate(words[17]), 4, "the payload is four bytes");
        assert_eq!(
            addi_immediate(words[18]) as usize,
            abi::SyscallNumber::Write as usize,
            "and the call is a Write"
        );
    }

    /// The writer's calls, in order, and the exit that closes the pipe's end.
    ///
    /// There is no `Close` in this image on purpose.  The writer exits with its
    /// write end still open, so the reader's end-of-file is the **exit's
    /// release**: the descriptor belongs to the process, and the process ending
    /// closes it.
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
    }

    /// The reader clears the length before its second announcement: a write
    /// that still carried the read's four would be a pipe write, and the
    /// announcement would vanish into the pipe.
    #[test]
    fn the_reader_clears_the_length_before_it_announces_again() {
        let words = crate::program::PIPE_READER_PROGRAM;
        assert_eq!(addi_immediate(words[11]), 4, "the read asked for four");
        assert_eq!(
            addi_immediate(words[12]) as usize,
            abi::SyscallNumber::Read as usize,
        );
        assert_eq!(
            addi_immediate(words[14]),
            0,
            "and the announce's length is zero"
        );
        assert_eq!(
            addi_immediate(words[16]) as usize,
            abi::SyscallNumber::Write as usize,
        );
    }

    /// The reader reads twice, then waits for the writer's process to end.
    ///
    /// The first read's wake is the writer's write; the second's only possible
    /// answer is "the write end is gone".  The wait after it is what makes the
    /// boot exercise `WaitProcess`, on whichever of its two paths the race
    /// picks, and the exit status is the wait's answer.
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
            "the reader announces, reads to end-of-file, installs a handler, waits, exits, and the handler writes and returns"
        );

        // The handler's address is the `auipc`'s own PC plus the delta the
        // program adds, and the delta has to land on the handler's first word.
        // A delta that drifted is a handler entry in the middle of a call,
        // which the machine reports as a trap at an address nobody wrote.
        let auipc = words
            .iter()
            .position(|word| *word == 0x0000_0517)
            .expect("the reader takes its own address");
        let delta = words[auipc + 1];
        let immediate = (delta as i32) >> 20;
        let handler = auipc * 4 + immediate as usize;
        assert!(handler < words.len() * 4, "the handler is inside the array");
        assert_eq!(
            words[handler / 4],
            addi(REGISTER_A1 as u32, 0, 64),
            "and its first word is the handler's own `li a1, #64`"
        );
        assert_eq!(
            words[18], 0x0001_3503,
            "the second read's descriptor is loaded from the stack again"
        );
        assert_eq!(
            addi_immediate(words[21]) as usize,
            abi::SyscallNumber::Read as usize,
            "and the second call is a Read"
        );
    }

    /// The branch helper agrees with the encoder it tests, on a positive
    /// offset too, a helper and its subject written from one reading of the
    /// layout would agree on the one value they were both written for.
    #[test]
    fn the_branch_decoder_decodes_what_the_encoder_encoded() {
        assert_eq!(branch_offset(bne_against_zero(12, -4)), -4);
        assert_eq!(branch_offset(bne_against_zero(13, -16)), -16);
        assert_eq!(branch_offset(bne_against_zero(12, 8)), 8);
    }
}
