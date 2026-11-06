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
/// `Write`, `Sleep`, `Write`, `Fork`, `Write`, and two `Exit`s — one per path,
/// because the fork leaves two processes and each ends on its own.  A program
/// compiled against a number this build does not serve would print its first
/// line and then fail silently, which is the one failure a sleep program could
/// have and still look healthy.
#[test]
fn the_program_writes_sleeps_writes_forks_writes_execs_and_the_child_exits() {
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
            abi::SyscallNumber::Exit as usize,
        ],
        "the program writes, sleeps, writes, forks, writes, execs, and the child exits"
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

/// The image `exec` hands a process to proves whose it became: it announces,
/// asks the kernel who it is, and exits with the answer — which is already in
/// `x0`, `Exit`'s argument register, so no move is needed between the two.
#[test]
fn the_exec_target_proves_its_identity() {
    let bytes = program_bytes(crate::program::EXEC_IMAGE);
    let words: alloc::vec::Vec<u32> = bytes
        .as_chunks::<4>()
        .0
        .iter()
        .map(|chunk| u32::from_le_bytes(*chunk))
        .take_while(|&word| word != 0)
        .collect();
    assert_eq!(
        call_numbers(&words),
        alloc::vec![
            abi::SyscallNumber::Write as usize,
            abi::SyscallNumber::GetPid as usize,
            abi::SyscallNumber::Exit as usize,
        ],
        "the target announces, asks, and exits with the answer"
    );
}
