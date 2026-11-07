//! arch/riscv64/src/program/mod.rs
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
/// page, so this matters only to the copy.
pub const PROGRAM_LEN: usize = 33 * 4;

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
/// [`bne_against_zero`] spells, with the function bits zero — `beq` and `bne`
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
pub const PROGRAM_WORDS: usize = 33;

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
/// writes the stack page it inherited — the pointer moved below the boundary
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
        addi(2, 2, -16),                      // addi sp, sp, -16
        store_against_sp(REGISTER_A6 as u32), // sd a6, 0(sp) (the fault)
        addi(REGISTER_A0 as u32, 0, 4),       // li a0, #4  (the image exec names)
        addi(
            REGISTER_A7 as u32,
            0,
            abi::SyscallNumber::ExecProcess as i32,
        ),
        0x0000_0073, // ecall
        0x0000_006F, // j .   (never reached: exec replaced the program)
        // The child: the same write, on its own copy of the page, then an
        // exit whose status is zero.
        addi(2, 2, -16),                      // addi sp, sp, -16
        store_against_sp(REGISTER_A6 as u32), // sd a6, 0(sp) (the fault)
        addi(REGISTER_A0 as u32, 0, 0),       // li a0, #0
        addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Exit as i32),
        0x0000_0073, // ecall
        0x0000_006F, // j .
    ]
}

/// The image `exec` hands a process over to: announce, then read a file.
///
/// `exec` leaves one word of inheritance below the stack top — a pointer to a
/// NUL-terminated path, the bytes themselves just above it — and this image
/// is the one that uses it: it opens the path, reads thirty-two bytes into
/// its own stack below the block, closes the descriptor, and exits with the
/// **first byte it read**, `a0` being `Exit`'s argument register.  A boot
/// line that reports `process 1 opened /greeting.txt` and an exit status of
/// `116` — the `t` of "the quick brown pyrofox" — are the pair that proves a
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

/// The writer: announce, sleep, announce again, then put bytes in the pipe.
///
/// The reader must reach its `Read` first and block, or a write into a pipe
/// nobody has read yet is an ordinary copy.  The reader's loop is shorter and
/// it makes no earlier call; this sleep then makes the order a fact rather
/// than a hope.
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
    addi(REGISTER_A0 as u32, 0, 0),
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Exit as i32),
    0x0000_0073, // ecall
    0x0000_006F, // j .
];

/// The reader: wait on a descriptor the boot left on its stack.
///
/// `x2` points at the read end's descriptor and the four-byte buffer is the
/// word above it.  The read blocks, the pipe is empty and its writer is
/// alive, and the writer's syscall is the only thing that ends the wait.
const PIPE_READER_PROGRAM: [u32; 21] = [
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
    0x0000_0073, // ecall
    addi(REGISTER_A0 as u32, 0, 0),
    addi(REGISTER_A7 as u32, 0, abi::SyscallNumber::Exit as i32),
    0x0000_0073, // ecall
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
mod tests;
