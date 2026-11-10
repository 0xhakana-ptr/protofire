//! arch/aarch64/src/program/tests.rs
//!
//! The aarch64 program's tests: the words decoded back to the instructions they
//! claim, the busy loop's branches, and the calls the program makes.
//!
//! The two helpers below the header are test-only: a scan for a call's
//! `movz x8, n` and a lookup of the `movz` that set a register before it.

/// The syscall numbers a program's words ask for, in order.
///
/// Every call is `movz x8, <number>` followed immediately by `svc #0`, so the
/// pair names it, a scan for the register write rather than a table of indices
/// a reader would have to count.
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
    // longest of the three, so the word sits where *this* program ends rather
    // than at the buffer's end.
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
/// `Write`, `Sleep`, `Write`, `Fork`, `Write`, `ExecProcess` — and no `Exit`
/// at all: the parent's path ends in the exec, and the child's ends in the
/// fault the kernel kills it for, so neither path exits itself.  A program
/// compiled against a number this build does not serve would print its first
/// line and then fail silently, which is the one failure a sleep program
/// could have and still look healthy.
#[test]
fn the_program_writes_sleeps_writes_forks_writes_and_execs() {
    let words = program_words(1);
    assert_eq!(
        call_numbers(&words),
        alloc::vec![
            abi::SyscallNumber::Write as usize,
            abi::SyscallNumber::Sleep as usize,
            abi::SyscallNumber::Write as usize,
            abi::SyscallNumber::Fork as usize,
            abi::SyscallNumber::Write as usize,
            abi::SyscallNumber::ExecProcess as usize,
        ],
        "the program writes, sleeps, writes, forks, writes, and execs"
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

/// The writer's calls, in order, and the close that ends the pipe.
///
/// The `Close` is the boot's proof of end-of-file: the reader's second read
/// can only return because the write end went away, and a boot whose close
/// moved nothing would leave the reader parked and the boot unfinished.
#[test]
fn the_writer_puts_bytes_in_the_pipe_and_closes_its_end() {
    let words = crate::program::PIPE_WRITER_PROGRAM;
    assert_eq!(
        call_numbers(&words),
        alloc::vec![
            abi::SyscallNumber::Write as usize,
            abi::SyscallNumber::Sleep as usize,
            abi::SyscallNumber::Write as usize,
            abi::SyscallNumber::Write as usize,
            abi::SyscallNumber::Close as usize,
            abi::SyscallNumber::Exit as usize,
        ],
        "the writer writes, sleeps, writes, writes the pipe, closes, exits"
    );

    // The descriptor the `Close` takes is loaded from the stack again, not
    // carried in `x0`: the pipe write's answer is what `x0` holds by then,
    // and a close that read its descriptor from there would close whatever
    // descriptor numbered four.  The load is the word before the `movz x8`.
    let close = words
        .windows(2)
        .position(|pair| {
            (pair[0] >> 5) & 0xFFFF == abi::SyscallNumber::Close as u32
                && (pair[0] >> 23) & 0x3F == 0b100101
                && (pair[0] >> 31) & 1 == 1
                && pair[0] & 0x1F == 8
                && pair[1] == 0xD400_0001
        })
        .expect("the writer closes its write end");
    assert_eq!(
        words[close - 1],
        0xF940_03E0,
        "the close's descriptor is `ldr x0, [sp]`, not the write's answer"
    );
}

/// The reader reads twice, then waits for the writer's process to end.
///
/// The first read's wake is the writer's write; the second's only possible
/// answer is "the write end is gone".  The wait after it is what makes the
/// boot exercise `WaitProcess`: whichever of its two paths the race picks —
/// a status already recorded, or a park the writer's exit wakes — the exit
/// status is the wait's answer, so a wait that answered an error is a boot
/// line the gate refuses.
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
            abi::SyscallNumber::WaitProcess as usize,
            abi::SyscallNumber::Exit as usize,
        ],
        "the reader writes, reads, writes, reads to end-of-file, waits, exits"
    );
    // The exit status is this program's own, not the wait's answer.  `movz x0,
    // #0` sits between the wait's `svc` and the `Exit`'s, and a program that
    // dropped it would report a number about whichever process the wait
    // happened to name.
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
    let status = words[exit - 1];
    assert_eq!((status >> 5) & 0xFFFF, 0, "the status is zero");
    assert_eq!(status & 0x1F, 0, "and it is `movz x0`");
}
