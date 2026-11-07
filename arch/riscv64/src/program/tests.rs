//! arch/riscv64/src/tests.rs
//!
//! The riscv64 program's tests: the encoders decoded back the way the machine
//! reads them, the busy loop's branches, and the calls this program makes.
//!
//! The two helpers above the tests are test-only, so they live here: a scan for
//! a call's `li a7, n` and a lookup of the `li` that set a register before it.

/// The syscall numbers a program's words ask for, in order.
///
/// Every call is `li a7, <number>` followed immediately by `ecall`, so the pair
/// is what names it, a scan for the register write rather than a table of
/// indices a reader would have to count.
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
/// A linear scan: remember the last `addi reg, x0, imm` that wrote `register`,
/// and answer it when the matching `ecall` arrives.  The last write wins, which
/// is what the machine does too, so a program that sets the register once and
/// leaves it alone is read correctly.
#[cfg(test)]
fn immediate_before(words: &[u32], call: abi::SyscallNumber, register: u32) -> i32 {
    let mut value = 0;
    for index in 0..words.len().saturating_sub(1) {
        let word = words[index];
        if words[index + 1] != 0x0000_0073 {
            // Not a call site; remember a `li` if this is one.
            if word & 0x7F == 0x13 && (word >> 7) & 0x1F == register && (word >> 15) & 0x1F == 0 {
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
/// `Write`, `Sleep`, `Write`, `Fork`, `Write`, `ExecProcess`, and one `Exit`
/// — the parent's path ends in the exec, so the child's is the only path that
/// exits itself.  A program compiled against a number this build does not
/// serve would print its first line and then fail silently, which is the one
/// failure a sleep program could have and still look healthy.
#[test]
fn the_program_writes_sleeps_writes_forks_writes_execs_and_the_child_exits() {
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
            abi::SyscallNumber::Fork as usize,
            abi::SyscallNumber::Write as usize,
            abi::SyscallNumber::ExecProcess as usize,
            abi::SyscallNumber::Exit as usize,
        ],
        "the program writes, sleeps, writes, forks, writes, execs, and the child exits"
    );
    // The `Write` after the fork is the one that reports it: both processes
    // reach it, and the number each prints is the fork's answer, the child's
    // pid in the parent, zero in the child.
    assert_eq!(
        calls[4],
        abi::SyscallNumber::Write as usize,
        "the call after the fork is a write"
    );
    assert_eq!(
        calls.last(),
        Some(&(abi::SyscallNumber::Exit as usize)),
        "and the program ends where both processes end"
    );

    // The sleep's duration is the immediate of the `li a0` that precedes the
    // Sleep call, and the program's own number is the `li a1` before its first
    // Write.  Both are found by their role rather than counted.
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

/// The branch helper agrees with the encoder it tests, on a positive
/// offset too, a helper and its subject written from one reading of the
/// layout would agree on the one value they were both written for.
#[test]
fn the_branch_decoder_decodes_what_the_encoder_encoded() {
    assert_eq!(branch_offset(bne_against_zero(12, -4)), -4);
    assert_eq!(branch_offset(bne_against_zero(13, -16)), -16);
    assert_eq!(branch_offset(bne_against_zero(12, 8)), 8);
}

/// The image `exec` hands a process to proves whose it became: it announces,
/// asks the kernel who it is, and exits with the answer — which is already in
/// `a0`, `Exit`'s argument register, so no move is needed between the two.
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
