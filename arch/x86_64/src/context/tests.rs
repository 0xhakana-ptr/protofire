//! arch/x86_64/src/context/tests.rs
//!
//! The module's tests.
//!
//! A sibling file because the tests outgrew the module: a reader looking for
//! the mechanism should not scroll past them to find the end of it.

use super::Context;
use super::RAX;
use super::RDI;
use super::REGISTERS;
use super::USER_CS;
use super::USER_RFLAGS;
use super::USER_SS;
use super::UserFrame;
use super::install_context;
use super::is_user_context;
use super::resume_address;
use super::return_value;
use super::set_return_value;
use super::stack_pointer;
use super::starting_context;

/// A program's context names ring 3, the stack, and nothing else.
///
/// The selectors are the test's point: `0x20` would be the same descriptor
/// at `RPL` 0, and `iretq` refuses it.  A context that ran with `IF` clear
/// would never be preempted.
#[test]
fn a_program_starts_at_its_entry_in_ring_three() {
    let context = starting_context(0x80_0000_1000, 0x80_0000_2000);
    assert_eq!(resume_address(&context), 0x80_0000_1000);
    assert_eq!(stack_pointer(&context), 0x80_0000_2000);
    assert!(is_user_context(&context), "cs has RPL 3");

    assert_eq!(context.code_segment, 0x23, "user code, RPL 3");
    assert_eq!(context.stack_segment, 0x1b, "user data, RPL 3");
    assert_eq!(context.flags & (1 << 9), 1 << 9, "IF is set");
    assert!(context.registers.iter().all(|slot| *slot == 0));
}

/// The selectors `iretq` pops carry `RPL` 3.
///
/// This is not decoration: the processor compares the selector's `RPL`
/// against the descriptor's `DPL`, so a selector without the low two bits
/// is a protection fault at the entry into ring 3, a failure that looks
/// like a fault in the program.
#[test]
fn the_ring_three_selectors_carry_their_privilege() {
    assert_eq!(USER_CS & 3, 3);
    assert_eq!(USER_SS & 3, 3);
    assert_eq!(USER_CS & !3, super::USER_CODE_SELECTOR as u64);
    assert_eq!(USER_SS & !3, super::USER_DATA_SELECTOR as u64);
    assert_eq!(USER_RFLAGS, 0x202);
}

/// A kernel frame is not a user frame.
///
/// The scheduler asks this before preempting, so a wrong answer installs a
/// program's context over the boot's and resumes ring 3 from a kernel
/// stack.  `cs` 0x08 is the boot's own code segment.
#[test]
fn a_kernel_frame_is_not_a_user_frame() {
    let mut context = starting_context(0x1000, 0x2000);
    assert!(is_user_context(&context));

    context.code_segment = 0x08;
    assert!(!is_user_context(&context));
}

/// The answer goes back in `rax` and survives a context install.
///
/// A switch is a copy of the whole frame, so a value written before the
/// copy is a value the resumed program reads, which is why the scheduler
/// writes the answer and then installs.
#[test]
fn the_answer_travels_in_rax_through_an_install() {
    let mut frame = starting_context(0, 0);
    set_return_value(&mut frame, 42);
    assert_eq!(return_value(&frame), 42);
    assert_eq!(frame.registers[RAX], 42);

    let mut installed = starting_context(0, 0);
    install_context(&mut installed, &frame);
    assert_eq!(return_value(&installed), 42);
}

/// The user frame is the five words `iretq` pops, in its order.
#[test]
fn the_user_frame_is_the_five_words_iretq_pops() {
    let context = starting_context(0x1234, 0x5678);
    let frame = UserFrame::from_context(&context);
    assert_eq!(frame.stack_segment, 0x1b);
    assert_eq!(frame.stack_pointer, 0x5678);
    assert_eq!(frame.flags, 0x202);
    assert_eq!(frame.code_segment, 0x23);
    assert_eq!(frame.instruction_pointer, 0x1234);
}

/// The register indices name the registers the assembly saves.
///
/// `rax` is zero because it is at the lowest address, and the first
/// argument is `rdi`, not `rsi` and not `rcx`, which is the ordering the
/// architecture's own convention fixes and the one a program is compiled
/// against.
#[test]
fn the_register_indices_are_the_architectures() {
    assert_eq!(RAX, 0);
    assert_eq!(RDI, 5);
    assert_eq!(REGISTERS, 15);

    let mut context = starting_context(0, 0);
    context.set_register(RDI, 7);
    assert_eq!(context.register(RDI), 7);
    assert_eq!(context.register(RAX), 0, "and it touched nothing else");
}

/// The frame is 176 bytes, which is what the stub subtracts.
#[test]
fn the_frame_is_the_size_the_stub_builds() {
    assert_eq!(core::mem::size_of::<Context>(), 22 * 8);
    assert_eq!(core::mem::size_of::<Context>(), 176);
}
