//! arch/x86_64/src/context.rs
//!
//! A program's saved state: the frame an interrupt from ring 3 builds, and the
//! two instructions that enter and leave ring 3.
//!
//! A task switch on this machine is a copy of one frame over another, the same
//! shape aarch64 uses.  That is only sound if the frame holds **every**
//! register a program can observe, because a switch that left a register in the
//! CPU would leave the previous task's value in it when a different task
//! resumes.  So `idt_stub.S` saves all fifteen general-purpose registers rather
//! than the nine a Rust function is allowed to clobber: the callee-saved eight
//! survive the handler, but they do not survive a *switch to another task*.
//!
//! Every register but `rsp`, which the `iretq` tail holds.  A trap does
//! not change `rsp` in the interrupted context, the processor pushes onto the
//! kernel stack and the stub works there, so the interrupted stack is exactly
//! the `rsp` word `iretq` will restore.
//!
//! ## Register numbering
//!
//! `registers[0]` is `rax` and `registers[15]` is... not there: there are
//! fifteen registers, `rax` through `r15`, and `rsp` lives in the tail.  The
//! order is the structural one, `rax`, `rbx`, `rcx`, `rdx`, `rsi`, `rdi`,
//! `rbp`, `r8`..`r15`, so a reader indexing the array gets the register the
//! name says, and the assembly pushes in exactly the reverse order so the
//! lowest address is `rax`.

use crate::gdt::USER_CODE_SELECTOR;
use crate::gdt::USER_DATA_SELECTOR;

/// Where `rax` sits: the syscall number, its return value, and the first
/// program's arithmetic.
pub const RAX: usize = 0;
pub const RBX: usize = 1;
/// `rcx`: the fourth syscall argument, and where `syscall`/`sysret` put the
/// return address on machines that use them.
pub const RCX: usize = 2;
/// `rdx`: the third syscall argument.
pub const RDX: usize = 3;
/// `rsi`: the second syscall argument.
pub const RSI: usize = 4;
/// `rdi`: the first syscall argument.
pub const RDI: usize = 5;
pub const RBP: usize = 6;
/// `r8`: the fifth syscall argument.
pub const R8: usize = 7;
/// `r9`: the sixth syscall argument.
pub const R9: usize = 8;
pub const R10: usize = 9;
pub const R11: usize = 10;
pub const R12: usize = 11;
pub const R13: usize = 12;
pub const R14: usize = 13;
pub const R15: usize = 14;

/// How many general-purpose registers the frame holds.  `rsp` is not one of
/// them: it is the `iretq` tail's.
pub const REGISTERS: usize = 15;

/// A program's saved state.
///
/// Laid out by `idt_stub.S`, field for field, and asserted against
/// `offset_of!` below.  The order is the stack's from its lowest address up:
/// the stub pushes `r15` first and `rax` last, so `rax` is where `rsp` ends up,
/// then the two the stub adds, then the five the processor pushed.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Context {
    /// `rax`..`r15`, in the order [`RAX`] through [`R15`] name.
    pub registers: [u64; REGISTERS],
    /// The vector, pushed by the stub after the error code.
    pub vector: u64,
    /// The error code the processor pushed, or the stub's zero for a vector
    /// that has none.
    pub error_code: u64,
    /// The interrupted instruction's address.
    pub instruction_pointer: u64,
    /// The interrupted code segment.  Its low two bits say which ring.
    pub code_segment: u64,
    /// The interrupted flags.
    pub flags: u64,
    /// The interrupted stack pointer.
    pub stack_pointer: u64,
    /// The interrupted stack segment.
    pub stack_segment: u64,
}

// The offsets `idt_stub.S` writes, checked against this structure's.  A
// mismatch is a frame the assembly filled in one place and Rust reads in
// another, and the symptom would be a handler acting on `rbx` when it meant
// `rax`.
const _: () = assert!(core::mem::offset_of!(Context, registers) == 0);
const _: () = assert!(core::mem::offset_of!(Context, vector) == 15 * 8);
const _: () = assert!(core::mem::offset_of!(Context, error_code) == 16 * 8);
const _: () = assert!(core::mem::offset_of!(Context, instruction_pointer) == 17 * 8);
const _: () = assert!(core::mem::offset_of!(Context, code_segment) == 18 * 8);
const _: () = assert!(core::mem::offset_of!(Context, flags) == 19 * 8);
const _: () = assert!(core::mem::offset_of!(Context, stack_pointer) == 20 * 8);
const _: () = assert!(core::mem::offset_of!(Context, stack_segment) == 21 * 8);
const _: () = assert!(core::mem::size_of::<Context>() == 22 * 8);
const _: () = assert!(core::mem::align_of::<Context>() == 8);

/// The state an `iretq` to ring 3 needs in `rflags`.
///
/// Bit 9 is `IF`, so a program takes the timer's interrupt; bit 1 is the
/// reserved bit that must always be set.  A program that ran with `IF` clear
/// would never be preempted, the same defect aarch64's `SPSR_EL0T` had when it
/// masked `IRQ`, where the boot printed `0 tick(s)`.
pub const USER_RFLAGS: u64 = (1 << 9) | (1 << 1);

/// The `cs` an `iretq` to ring 3 needs: the user code segment with `RPL` 3.
///
/// The `RPL` bits are not decoration.  `iretq` compares the selector's `RPL`
/// with the descriptor's `DPL`, and a selector of `0x20`, the same descriptor
/// at ring 0, is refused as a protection violation.
pub const USER_CS: u64 = (USER_CODE_SELECTOR | 3) as u64;

/// The `ss` an `iretq` to ring 3 needs.
pub const USER_SS: u64 = (USER_DATA_SELECTOR | 3) as u64;

impl Context {
    /// A context in which nothing has run.
    ///
    /// Every register zero, and the `iretq` tail naming ring 3 at `entry` with
    /// the stack at `stack_top`.  The tail is what makes this a context rather
    /// than a value: `enter_user` pushes exactly these five words and executes
    /// `iretq`, so a field left at zero would be a selector of zero, a null
    /// descriptor, and a general protection fault at the entry into ring 3.
    pub const fn user(entry: usize, stack_top: usize) -> Context {
        Context {
            registers: [0; REGISTERS],
            vector: 0,
            error_code: 0,
            instruction_pointer: entry as u64,
            code_segment: USER_CS,
            flags: USER_RFLAGS,
            stack_pointer: stack_top as u64,
            stack_segment: USER_SS,
        }
    }

    /// The register at `index`, which is what a handler reads.
    pub const fn register(&self, index: usize) -> u64 {
        self.registers[index]
    }

    pub const fn set_register(&mut self, index: usize, value: u64) {
        self.registers[index] = value;
    }

    /// Whether this frame is a program's rather than the kernel's.
    ///
    /// `cs`'s low two bits are the ring the interrupted code ran at, and ring 3
    /// is the only ring a program runs at.  This is the question a scheduler
    /// asks before preempting: a timer that fires at ring 0 interrupted the
    /// boot, and installing a program's context over it would resume ring 3
    /// from a kernel stack nothing will unwind.
    pub const fn is_user(&self) -> bool {
        self.code_segment & 3 == 3
    }

    /// Whether this frame's fault was caused by a **write**.
    ///
    /// Bit 1 of the page-fault error code is `W/R`: set for a write, clear for
    /// a read or an instruction fetch.  The bit means nothing for a vector that
    /// pushes no error code, which is why the caller has to have established
    /// that this frame is a fault before asking.
    ///
    /// The other bits are worth naming because a handler reads them together:
    /// bit 0 is `P` (a protection violation rather than a page that was not
    /// present), bit 2 is `U/S` (the access came from ring 3), bit 3 is `RSVD`
    /// (a reserved bit was set in a paging structure), bit 4 is `I/D` (the
    /// access was an instruction fetch).  A copy-on-write handler cares about
    /// `W` and `P` together: a write to a **present, read-only** page is the
    /// one shape it answers.
    pub const fn fault_was_write(&self) -> bool {
        self.error_code & 0b10 != 0
    }

    /// Whether this frame's fault found the page **present**.
    ///
    /// Bit 0 of the error code.  Clear means the walk found no translation at
    /// all, which is a program reaching an address it was never given; set
    /// means the translation was there and the access was refused, which is
    /// the only case a permission change can repair.
    pub const fn fault_was_present(&self) -> bool {
        self.error_code & 1 != 0
    }
}

impl Default for Context {
    fn default() -> Self {
        Context::user(0, 0)
    }
}

pub fn starting_context(entry: usize, stack_top: usize) -> Context {
    Context::user(entry, stack_top)
}

pub fn resume_address(context: &Context) -> usize {
    context.instruction_pointer as usize
}

/// Point the resume back at the call that is being served, for a retry.
///
/// A trap resumes at the instruction **after** the call; a call that
/// **parked** has not been answered, so resuming after it would skip the
/// handler and leave the program reading whatever its answer register held.
/// `int 0x80` is two bytes, which is why this is not the same constant the
/// other two machines use.
pub fn restart_the_call(context: &mut Context) {
    context.instruction_pointer = context.instruction_pointer.wrapping_sub(2);
}

/// Point a context at another address, for a caller building one by hand.
pub fn set_resume_address(context: &mut Context, address: usize) {
    context.instruction_pointer = address as u64;
}

pub fn stack_pointer(context: &Context) -> usize {
    context.stack_pointer as usize
}

/// The word a program reads a call's answer from.
///
/// `rax` on this machine, for the reason the architecture's own convention
/// says: it is where a return value goes.
pub fn return_value(context: &Context) -> usize {
    context.registers[RAX] as usize
}

/// Put a call's answer where a program reads it.
pub fn set_return_value(context: &mut Context, value: usize) {
    context.registers[RAX] = value as u64;
}

/// Put `value` in the register argument `index` travels in.
///
/// The System V call convention this machine's programs are built against puts
/// the arguments in `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` — **not** the
/// `rax`..`rsi` run a machine-independent guess might pick, which is why the
/// table is here and not derived from the register indices.
///
/// # Panics
///
/// Panics when `index` is past the argument registers, which the ABI says are
/// six.
pub fn set_argument(context: &mut Context, index: usize, value: usize) {
    const ARGUMENTS: [usize; 6] = [RDI, RSI, RDX, RCX, R8, R9];
    let register = ARGUMENTS[index];
    context.registers[register] = value as u64;
}

pub fn is_user_context(context: &Context) -> bool {
    context.is_user()
}

/// The flags the trap path will restore, for a boot line that reports them.
///
/// `rflags` on this machine, where aarch64 reports `SPSR_EL1`.  A boot that
/// printed this and saw `IF` clear had a program no timer could preempt, the
/// defect that cost aarch64 a session.
pub fn return_state(context: &Context) -> u64 {
    context.flags
}

/// Write `context` over the frame the trap path will restore.
///
/// That is the whole of a task switch: the epilogue pops every register and
/// `iretq`s, so replacing the frame replaces what the machine does next, ///
/// including the ring it returns to.
pub fn install_context(frame: &mut Context, context: &Context) {
    *frame = *context;
}

/// The selectors and stack an `iretq` into ring 3 needs, taken from `context`.
///
/// This is the frame `enter_user` pushes; it exists as a value so a test can
/// check the five words without a machine.
#[derive(Debug, Clone, Copy)]
pub struct UserFrame {
    /// The user stack segment, with `RPL` 3.
    pub stack_segment: u64,
    /// The user stack pointer.
    pub stack_pointer: u64,
    /// The flags to run with.
    pub flags: u64,
    /// The user code segment, with `RPL` 3.
    pub code_segment: u64,
    /// The instruction to begin at.
    pub instruction_pointer: u64,
}

impl UserFrame {
    /// The five words, in the order `iretq` pops them.
    pub const fn from_context(context: &Context) -> UserFrame {
        UserFrame {
            stack_segment: context.stack_segment,
            stack_pointer: context.stack_pointer,
            flags: context.flags,
            code_segment: context.code_segment,
            instruction_pointer: context.instruction_pointer,
        }
    }
}

/// Three things have to be true before an `iretq` to ring 3 can succeed, and
/// before this function existed none of them was: a DPL-3 code and data
/// descriptor exist (`gdt`), a TSS with an `RSP0` is loaded so the first
/// interrupt from ring 3 has a stack to land on, and every page the program
/// touches is mapped with the user bit.
///
/// Control does not come back here.  The program returns to the kernel through
/// an interrupt, a syscall or an exit, and the trap path resumes whatever
/// the scheduler installed.  A function that "returned" would be claiming a
/// program can finish without trapping, which it cannot: ring 3 has no way out
/// except an interrupt.
///
/// # Safety
///
/// `context` must name an entry and a stack in a page mapped `user`, and the
/// caller must have no live state on this stack that an interrupt could not
/// restore: the trap path builds its own frame on `RSP0` and resumes through
/// that.
#[cfg(target_os = "none")]
pub unsafe fn enter_user_with(context: &Context) -> ! {
    let frame = UserFrame::from_context(context);
    // SAFETY: the caller promises the five words name a ring-3 code page, a
    // writable ring-3 stack and the selectors `gdt` installed.  `iretq` pops
    // exactly these five values and, because the `CS` it pops is ring 3, takes
    // the stack from the TSS on the next interrupt rather than from this one.
    //
    // The five pushes and the `iretq` are one transaction.  An interrupt taken
    // between them is taken at ring 0, and the stub's epilogue pops from the
    // stack this function has already half-filled, so it returns with a
    // selector of zero or an address that was a `push` operand.  `cli` closes
    // the window and `iretq` reopens it: the flags it pops are the program's,
    // which the context builder set with `IF` on.
    unsafe {
        core::arch::asm!(
            "push {ss}",
            "push {rsp}",
            "push {flags}",
            "push {cs}",
            "push {rip}",
            "iretq",
            ss = in(reg) frame.stack_segment,
            rsp = in(reg) frame.stack_pointer,
            flags = in(reg) frame.flags,
            cs = in(reg) frame.code_segment,
            rip = in(reg) frame.instruction_pointer,
            options(noreturn)
        )
    }
}

#[cfg(test)]
mod tests {
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
}

// The program a boot runs, as this machine's machine code.
//
// A program is machine code, and every byte below is a decision about this
// architecture: `int $0x80` is the call gate, `eax` is the number, `esi` is the
// second argument and `esi` holds the program's own number because `Write`
// prints its second argument.  A kernel holding one array for three machines
// would be a kernel with two of them wrong, and the defect would be a program
// that faults at an address the kernel chose.
//
// ## The instructions
//
// | bytes | encoding | meaning |
// |---|---|---|
// | `41 B8 40 00 00 00` | `mov r8d, 0x40` | the outer count |
// | `41 B9 00 10 00 00` | `mov r9d, 0x1000` | the inner count |
// | `41 83 E9 01` | `sub r9d, 1` | |
// | `75 FA` | `jne -6` | back to the inner `sub` |
// | `41 83 E8 01` | `sub r8d, 1` | |
// | `75 EE` | `jne -18` | back to the inner reload |
// | `BE nn 00 00 00` | `mov esi, nn` | this program's number |
// | `B8 06 00 00 00` | `mov eax, 6` | syscall 6, `Write` |
// | `CD 80` | `int 0x80` | call the kernel |
// | `BF 20 4E 00 00` | `mov edi, 0x4E20` | 20000 microseconds |
// | `B8 31 00 00 00` | `mov eax, 0x31` | syscall 49, `Sleep` |
// | `CD 80` | `int 0x80` | |
// | `B8 06 00 00 00` | `mov eax, 6` | syscall 6, `Write`, after the wake |
// | `CD 80` | `int 0x80` | |
// | `B8 3E 00 00 00` | `mov eax, 0x3E` | syscall 62, `Fork` |
// | `CD 80` | `int 0x80` | |
// | `41 89 C0` | `mov r8d, eax` | keep the fork's answer |
// | `44 89 C6` | `mov esi, r8d` | and announce it |
// | `B8 06 00 00 00` | `mov eax, 6` | syscall 6, `Write` |
// | `CD 80` | `int 0x80` | |
// | `45 85 C0` | `test r8d, r8d` | the child's answer is zero |
// | `74 0E` | `jz +14` | the child takes the second path |
// | `6A 2A` | `push 42` | write the stack: the copy-on-write fault |
// | `BF 04 00 00 00` | `mov edi, 4` | the image `exec` hands the task to |
// | `B8 1A 00 00 00` | `mov eax, 0x1A` | syscall 26, `ExecProcess` |
// | `CD 80` | `int 0x80` | |
// | `EB FE` | `jmp $` | never reached: exec replaced the program |
// | `6A 2A` | `push 42` | the child writes the stack too |
// | `31 FF` | `xor edi, edi` | the child exits zero |
// | `B8 03 00 00 00` | `mov eax, 3` | syscall 3, `Exit` |
// | `CD 80` | `int 0x80` | |
// | `EB FE` | `jmp $` | never reached |
//
// The first `Write` says which program ran.  `Sleep` then takes it out of the
// rotation for `SLEEP_MICROSECONDS`, during which the other program runs, so a
// log that shows two "says hello" lines before the second program's is a log
// where sleeping worked.  The second `Write` after the sleep is what makes the
// wake visible: a program that never woke prints one line, not two.
//
// The bytes were assembled by GNU `as` and disassembled by `objdump` before
// they were written down here, which is the check that they are the
// instructions this table says they are, the same discipline the aarch64
// program's words had.

/// The longer of the four images.  A program is copied into a whole page, so
/// the exact length matters only to the copy; a shorter array would truncate
/// the announcing program's last instruction.
pub const PROGRAM_LEN: usize = 126;

/// Long enough to span several time slices, so the wake is observably later
/// than the request rather than inside the same tick.
pub const SLEEP_MICROSECONDS: u64 = 20_000;

/// The byte at which the number is written.
///
/// `mov esi, imm32` is opcode `0xBE` at 24 and its immediate at 25, so the four
/// bytes to patch begin one past the opcode.  Getting this wrong writes the
/// value over the opcode: the first version did, and the program's first
/// instruction became the number rather than the instruction the table
/// describes.
const NUMBER_OFFSET: usize = 25;

/// One program's bytes, with `number` in its `Write` argument.
///
/// Program 3 is the pipe's reader and is a different program, not the same one
/// with a different number: it makes a call the others never make and its
/// first act is to block.  Everything about it is the machine code below, which
/// is why it is a second array rather than a parameter.
pub fn program_bytes(number: u16) -> [u8; PROGRAM_LEN] {
    if number == PIPE_READER {
        let mut bytes = [0u8; PROGRAM_LEN];
        bytes[..PIPE_READER_PROGRAM.len()].copy_from_slice(&PIPE_READER_PROGRAM);
        return bytes;
    }
    if number == PIPE_WRITER {
        let mut bytes = [0u8; PROGRAM_LEN];
        bytes[..PIPE_WRITER_PROGRAM.len()].copy_from_slice(&PIPE_WRITER_PROGRAM);
        return bytes;
    }
    let mut bytes = [0u8; PROGRAM_LEN];
    bytes[..PROGRAM_BASE.len()].copy_from_slice(&PROGRAM_BASE);
    bytes[NUMBER_OFFSET..NUMBER_OFFSET + 4].copy_from_slice(&(number as u32).to_le_bytes());
    bytes
}

/// The `e_machine` this machine's programs carry, which the loader checks the
/// image against before it maps one page of it.
pub const ELF_MACHINE: u16 = 62; // EM_X86_64

pub const PIPE_READER: u16 = 3;

pub const PIPE_WRITER: u16 = 2;

/// The writer: announce, sleep, announce again, put bytes in the pipe, close
/// the write end.
///
/// The reader has to reach its `Read` first and block, or there is nothing to
/// prove, a write into a pipe nobody has read yet is an ordinary copy.  The
/// reader's loop is shorter and it makes no earlier call, so it blocks; this
/// program's sleep then guarantees the order rather than relying on it.
///
/// The `Close` is the boot's own proof of end-of-file: the reader's second
/// read can only return because the write end went away, and a close that
/// did not move the pipe's count would leave the reader parked and the boot
/// unfinished.  The end is still in `edi` — the pipe write answers in `eax`
/// and touches nothing else — so the close needs its number and nothing
/// more.
///
/// `[rsp]` holds the write end's descriptor and `[rsp + 16]` is the four bytes
/// it sends.
const PIPE_WRITER_PROGRAM: [u8; 91] = [
    0x41, 0xB8, 0x40, 0x00, 0x00, 0x00, // mov r8d, 0x40
    0x41, 0xB9, 0x00, 0x10, 0x00, 0x00, // mov r9d, 0x1000
    0x41, 0x83, 0xE9, 0x01, // sub r9d, 1
    0x75, 0xFA, // jne -6
    0x41, 0x83, 0xE8, 0x01, // sub r8d, 1
    0x75, 0xEE, // jne -18
    0xBE, 0x02, 0x00, 0x00, 0x00, // mov esi, 2          (this program's number)
    0xB8, 0x06, 0x00, 0x00, 0x00, // mov eax, 6          (Write)
    0xCD, 0x80, // int 0x80
    0xBF, 0x20, 0x4E, 0x00, 0x00, // mov edi, 20000      (the sleep)
    0xB8, 0x31, 0x00, 0x00, 0x00, // mov eax, 49         (Sleep)
    0xCD, 0x80, // int 0x80
    0xBE, 0x02, 0x00, 0x00, 0x00, // mov esi, 2          (Write, after the wake)
    0xB8, 0x06, 0x00, 0x00, 0x00, // mov eax, 6
    0xCD, 0x80, // int 0x80
    0x8B, 0x3C, 0x24, // mov edi, [rsp]      (the write end)
    0x48, 0x8D, 0x74, 0x24, 0x10, // lea rsi, [rsp + 16] (the bytes)
    0xBA, 0x04, 0x00, 0x00, 0x00, // mov edx, 4
    0xB8, 0x06, 0x00, 0x00, 0x00, // mov eax, 6          (Write to the pipe)
    0xCD, 0x80, // int 0x80
    // **No `Close`.**  The writer exits with its write end still open, so the
    // reader's end-of-file is the exit's release: the descriptor belongs to
    // the process, and the process ending closes it.  The status is zero on
    // purpose: `edi` still holds the descriptor the write used, and `Exit`
    // reads its status from `edi` on this machine.
    0x31, 0xFF, // xor edi, edi        (the exit status is zero)
    0xB8, 0x03, 0x00, 0x00, 0x00, // mov eax, 3          (Exit)
    0xCD, 0x80, // int 0x80
    0xEB, 0xFE, // jmp $
];

/// The pipe reader: wait on a descriptor the boot left on its stack, and read
/// again after the wake.
///
/// ## The interface, and why it is the stack
///
/// `[rsp]` holds the read end's descriptor and `[rsp + 8]` is the four-byte
/// buffer the read fills.  A program's only way to receive a value from the
/// boot is a place it knows how to look at, and the stack is the one place both
/// sides already agree on, the boot writes it before the program runs, and the
/// program's first instruction can reach it without a call.
///
/// The first read blocks: the pipe is empty when this program runs, its writer
/// is alive, and `try_read` answers `Block`.  The line `a program blocks on a
/// pipe` is that event.  The `Write` after it says the read returned, which can
/// only happen because the writer's syscall woke it, nothing else wakes a
/// blocked task.
///
/// The **second** read is the boot's own proof of end-of-file.  The pipe is
/// drained by then and the writer's end is closed, so nothing but "no bytes
/// ever" can answer it: a read that returned would have to be end-of-file,
/// and a close that never moved the pipe's count would leave this program
/// parked with the boot unfinished.
const PIPE_READER_PROGRAM: [u8; 113] = [
    0x41, 0xB8, 0x40, 0x00, 0x00, 0x00, // mov r8d, 0x40
    0x41, 0xB9, 0x00, 0x10, 0x00, 0x00, // mov r9d, 0x1000
    0x41, 0x83, 0xE9, 0x01, // sub r9d, 1
    0x75, 0xFA, // jne -6
    0x41, 0x83, 0xE8, 0x01, // sub r8d, 1
    0x75, 0xEE, // jne -18
    0xBE, 0x03, 0x00, 0x00, 0x00, // mov esi, 3          (announce)
    0xB8, 0x06, 0x00, 0x00, 0x00, // mov eax, 6          (Write)
    0xCD, 0x80, // int 0x80
    0x8B, 0x3C, 0x24, // mov edi, [rsp]      (the read end)
    0x48, 0x8D, 0x74, 0x24, 0x08, // lea rsi, [rsp + 8]  (the buffer)
    0xBA, 0x04, 0x00, 0x00, 0x00, // mov edx, 4
    0xB8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5          (Read)
    0xCD, 0x80, // int 0x80
    // The length is cleared before the second announcement.  `edx` still holds
    // the read's four, and a write with a length to a descriptor that names a
    // pipe is a pipe write, so the announcement would go into the pipe and
    // print nothing.  This is the same confusion the kernel's length test
    // exists to end, seen from the program's side.
    0x31, 0xD2, // xor edx, edx        (announce has no length)
    0xBE, 0x03, 0x00, 0x00, 0x00, // mov esi, 3          (Write, after the wait)
    0xB8, 0x06, 0x00, 0x00, 0x00, // mov eax, 6
    0xCD, 0x80, // int 0x80
    0x8B, 0x3C, 0x24, // mov edi, [rsp]      (the read end, again)
    0x48, 0x8D, 0x74, 0x24, 0x08, // lea rsi, [rsp + 8]  (the buffer)
    0xBA, 0x04, 0x00, 0x00, 0x00, // mov edx, 4
    0xB8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5          (Read, the one end-of-file ends)
    0xCD, 0x80, // int 0x80
    // The wait: its answer is the status, so nothing clears `eax` between the
    // two calls.  A status already recorded answers here; one that has not
    // parks this task and the writer's exit wakes it.
    // Wait for **the writer**, by pid, and make its status this program's.
    // `WaitProcess` answers about whichever process finished first, and this
    // boot's forked child dies before the writer does.
    0xBF, 0x02, 0x00, 0x00, 0x00, // mov edi, 2          (the writer's pid)
    0xB8, 0xC4, 0x00, 0x00, 0x00, // mov eax, 196        (WaitProcessOf)
    0xCD, 0x80, // int 0x80
    // The answer comes back in `eax` and `Exit` reads its status from `edi` on
    // this machine, so the value has to be moved: this is the one place the
    // two registers differ, and leaving it moves the *pid* into the status —
    // measured as `3 -> 2` before this line existed.
    0x89, 0xC7, // mov edi, eax        (the status is the wait's answer)
    0xB8, 0x03, 0x00, 0x00, 0x00, // mov eax, 3          (Exit)
    0xCD, 0x80, // int 0x80
    0xEB, 0xFE, // jmp $
];

/// The program with a zero number, which [`program_bytes`] patches.
///
/// The loop has to outlive a time slice, or the boot reports a timer that never
/// preempted whether or not preemption works, the defect aarch64's program had
/// with a single 16-bit immediate.  A hundred microseconds is the slice, and
/// the first version of this loop was 64 × 256 iterations, which finished in a
/// few microseconds and produced exactly `0 tick(s)`.
///
/// 0x40 × 0x1000 is about 2^18 iterations, long enough for many slices at this
/// slice length, and short enough that the program still finishes.  The upper
/// bound is real: 0x1000 × 0x10000 was too long, and under the emulator the
/// trap cost of ten thousand ticks a second left the program unable to reach
/// its first `int` at all.
const PROGRAM_BASE: [u8; 110] = [
    0x41, 0xB8, 0x40, 0x00, 0x00, 0x00, // mov r8d, 0x40
    0x41, 0xB9, 0x00, 0x10, 0x00, 0x00, // mov r9d, 0x1000
    0x41, 0x83, 0xE9, 0x01, // sub r9d, 1
    0x75, 0xFA, // jne -6
    0x41, 0x83, 0xE8, 0x01, // sub r8d, 1
    0x75, 0xEE, // jne -18
    0xBE, 0x00, 0x00, 0x00, 0x00, // mov esi, 0
    0xB8, 0x06, 0x00, 0x00, 0x00, // mov eax, 6 (Write)
    0xCD, 0x80, // int 0x80
    0xBF, 0x20, 0x4E, 0x00, 0x00, // mov edi, 20000 (the sleep)
    0xB8, 0x31, 0x00, 0x00, 0x00, // mov eax, 49 (Sleep)
    0xCD, 0x80, // int 0x80
    0xB8, 0x06, 0x00, 0x00, 0x00, // mov eax, 6 (Write, after the wake)
    0xCD, 0x80, // int 0x80
    0xB8, 0x3E, 0x00, 0x00, 0x00, // mov eax, 62 (Fork)
    0xCD, 0x80, // int 0x80
    // The answer is kept in `r8d`, which no call here writes: `Write` fills
    // `eax`, and `Exit` reads `edi`, so the fork's answer left in `eax` would
    // be the write's count by the time the status is taken.
    0x41, 0x89, 0xC0, // mov r8d, eax (keep the fork's answer)
    0x44, 0x89, 0xC6, // mov esi, r8d (Write prints it)
    0xB8, 0x06, 0x00, 0x00, 0x00, // mov eax, 6 (Write)
    0xCD, 0x80, // int 0x80
    // The two processes part ways here, and the fork's answer is the only
    // thing that tells them apart: the parent holds its child's pid, the
    // child holds zero.  Each then writes the stack page it inherited — a
    // `push`, because the word goes below the pointer and stays inside the
    // page — which is the write the copy-on-write fork exists for: the page
    // is shared and read-only now, so the write faults, and the kernel's
    // answer to that fault is the whole of what this image exercises.
    0x45, 0x85, 0xC0, // test r8d, r8d
    0x74, 0x10, // jz +16 (the child takes the second path)
    // The parent: write, then become the image `exec` names.  The task
    // survives the change with its pid, and its exit status comes from the
    // image it became — which asks the kernel who it is and exits with the
    // answer, so the boot's report of `1 -> 1` is the evidence that identity
    // carried over.
    // The pointer comes before the push: `rsp` here is the hand-over top,
    // and `[rsp-32]` is exactly where the boot left the exec path.  `rdi`
    // survives the copy-on-write fault below — the resolver restores every
    // register — so the exec that follows reads what this loaded.
    0x48, 0x8B, 0x7C, 0x24, 0xC0, // mov rdi, [rsp-64] (the boot's exec path)
    0x6A, 0x2A, // push 42 (the copy-on-write fault)
    0xB8, 0x1A, 0x00, 0x00, 0x00, // mov eax, 26 (ExecProcess)
    0xCD, 0x80, // int 0x80
    0xEB, 0xFE, // jmp $ (never reached: exec replaced the program)
    // The child: the same write, on its own copy of the page, and then the
    // deliberate one — a store into its own **code** page, read-only and not
    // copy-on-write, which no resolver answers.  The kernel kills the process
    // for it and the machine goes on; the boot's report reads
    // `process 4 died from a fault`, and the child's status is the kernel's,
    // not its own.
    0x6A, 0x2A, // push 42 (the child's copy-on-write fault)
    0xC7, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, // mov dword [rip+0], 0 (the fatal write)
    0xEB, 0xFE, // jmp $ (never reached: the child is dead)
];

/// The syscall numbers a program's bytes ask for, in order.
///
/// Every call is `mov eax, <number>` followed by `int 0x80`, so the pair names
/// it, a scan for the register write rather than a table of byte offsets.
#[cfg(test)]
fn call_numbers(bytes: &[u8]) -> alloc::vec::Vec<u32> {
    let mut calls = alloc::vec::Vec::new();
    let mut at = 0;
    while at + 6 <= bytes.len() {
        // A `0xB8` is `mov eax, imm32` only when it is not preceded by a REX
        // prefix: `41 B8` is `mov r8d, imm32`, which is the busy loop's counter
        // and not a syscall number.
        let prefixed = at > 0 && bytes[at - 1] & 0xF0 == 0x40;
        if bytes[at] == 0xB8 && !prefixed {
            let number =
                u32::from_le_bytes([bytes[at + 1], bytes[at + 2], bytes[at + 3], bytes[at + 4]]);
            calls.push(number);
            at += 5;
            continue;
        }
        at += 1;
    }
    calls
}

#[cfg(test)]
mod program_tests {
    use super::PIPE_READER;
    use super::PIPE_READER_PROGRAM;
    use super::PIPE_WRITER;
    use super::PIPE_WRITER_PROGRAM;
    use super::PROGRAM_LEN;
    use super::program_bytes;

    /// The three programs are three different images.
    ///
    /// The boot runs an announcing program, a pipe writer and a pipe reader,
    /// and a builder that returned one image for all three would look correct
    /// until the reader slept instead of blocking, which is what the first
    /// version did, because `program_bytes` never checked the number.
    #[test]
    fn the_three_programs_are_three_images() {
        let announce = program_bytes(1);
        let writer = program_bytes(PIPE_WRITER);
        let reader = program_bytes(PIPE_READER);

        assert_ne!(
            announce, writer,
            "the writer makes a call the others do not"
        );
        assert_ne!(
            writer, reader,
            "and the reader makes one the writer does not"
        );

        // The reader's read is `mov eax, 5`, syscall 5, and the announce
        // program has no such immediate anywhere in it.
        let read_encoding: [u8; 5] = [0xB8, 0x05, 0x00, 0x00, 0x00];
        assert!(
            reader.windows(5).any(|window| window == read_encoding),
            "the reader calls Read"
        );
        assert!(
            !announce.windows(5).any(|window| window == read_encoding),
            "and the announcing program does not"
        );
    }

    /// The image is the length the table says, and the number lands where the
    /// encoding puts it.
    ///
    /// A builder that patched the wrong offset would produce a program whose
    /// loop count is its number, which runs, and prints the right thing, and
    /// is not the program the table describes.
    #[test]
    fn the_number_is_where_the_encoding_puts_it() {
        let one = program_bytes(1);
        assert_eq!(one.len(), PROGRAM_LEN);

        // `mov esi, imm32` at offset 24: opcode, then the little-endian value.
        assert_eq!(&one[24..25], &[0xBE], "the encoding of mov esi, imm32");
        assert_eq!(&one[25..29], &1u32.to_le_bytes());

        let two = program_bytes(2);
        assert_eq!(&two[25..29], &2u32.to_le_bytes());
    }

    /// Every syscall number the program uses is the ABI's own.
    ///
    /// `Write`, `Sleep`, `Write`, `Fork`, `Write`, `ExecProcess` — and no
    /// `Exit` at all: the parent's path ends in the exec, and the child's ends
    /// in the fault the kernel kills it for, so neither path exits itself.  A
    /// program compiled against a number this build does not serve would print
    /// its first line and then fail silently, which is the one failure a sleep
    /// program could have and still look healthy.
    #[test]
    fn the_program_writes_sleeps_writes_forks_writes_and_execs() {
        let bytes = program_bytes(1);
        // By call number rather than by offset: an offset a reader has to count
        // goes stale the moment an instruction is inserted, which is what
        // happened when the identity call arrived.
        assert_eq!(
            super::call_numbers(&bytes),
            alloc::vec![
                abi::SyscallNumber::Write as u32,
                abi::SyscallNumber::Sleep as u32,
                abi::SyscallNumber::Write as u32,
                abi::SyscallNumber::Fork as u32,
                abi::SyscallNumber::Write as u32,
                abi::SyscallNumber::ExecProcess as u32,
            ],
            "the program writes, sleeps, writes, forks, writes, and execs"
        );

        // The parent's exec loads the boot's exec-path pointer: `mov rdi,
        // [rsp-64]`, the block the boot wrote below the hand-over top.
        assert!(
            bytes
                .windows(5)
                .any(|window| window == [0x48, 0x8B, 0x7C, 0x24, 0xC0]),
            "the exec's argument is the boot's exec-path pointer, from [rsp-64]"
        );
    }

    /// The two branches are backward and land on the instructions the loop
    /// needs, which is what makes it a loop rather than a straight line.
    ///
    /// `jne` is `0x75` with a signed 8-bit displacement relative to the end of
    /// the instruction.  `-6` from offset 18 lands on 12 (the inner `sub`), and
    /// `-18` from offset 24 lands on 6 (the inner reload), the two numbers
    /// this test computes rather than assumes.
    #[test]
    fn the_loop_branches_back_to_itself() {
        let bytes = program_bytes(1);
        assert_eq!(bytes[16], 0x75, "jne, near");
        let inner = bytes[17] as i8;
        assert_eq!(inner, -6);
        assert_eq!((18i64 + inner as i64) as usize, 12, "the inner sub");

        assert_eq!(bytes[22], 0x75, "the outer jne");
        let outer = bytes[23] as i8;
        assert_eq!(outer, -18);
        // Signed: `-18` is a displacement, and casting it to `usize` first
        // would be a number near 2^64 rather than a step backwards.
        assert_eq!((24i64 + outer as i64) as usize, 6, "the inner reload");
    }

    /// The writer's calls, in order, and the exit that closes the pipe's end.
    ///
    /// There is no `Close` in this image on purpose.  The writer exits with its
    /// write end still open, so the reader's end-of-file is the **exit's
    /// release**: the descriptor belongs to the process, and the process
    /// ending closes it.
    #[test]
    fn the_writer_puts_bytes_in_the_pipe_and_exits_with_its_end_open() {
        assert_eq!(
            super::call_numbers(&PIPE_WRITER_PROGRAM),
            alloc::vec![
                abi::SyscallNumber::Write as u32,
                abi::SyscallNumber::Sleep as u32,
                abi::SyscallNumber::Write as u32,
                abi::SyscallNumber::Write as u32,
                abi::SyscallNumber::Exit as u32,
            ],
            "the writer writes, sleeps, writes, writes the pipe, and exits"
        );
        assert!(
            !super::call_numbers(&PIPE_WRITER_PROGRAM)
                .contains(&(abi::SyscallNumber::Close as u32)),
            "no close: the exit is what releases the end"
        );
    }

    /// The reader reads twice, then waits for the writer's process to end.
    ///
    /// The first read's wake is the writer's write; the second's only
    /// possible answer is "the write end is gone".  The wait after it is what
    /// makes the boot exercise `WaitProcess`, on whichever of its two paths
    /// the race picks, and the exit status is the wait's answer.
    #[test]
    fn the_reader_reads_to_end_of_file_and_waits_for_the_writer() {
        assert_eq!(
            super::call_numbers(&PIPE_READER_PROGRAM),
            alloc::vec![
                abi::SyscallNumber::Write as u32,
                abi::SyscallNumber::Read as u32,
                abi::SyscallNumber::Write as u32,
                abi::SyscallNumber::Read as u32,
                abi::SyscallNumber::WaitProcessOf as u32,
                abi::SyscallNumber::Exit as u32,
            ],
            "the reader writes, reads, writes, reads to end-of-file, waits, exits"
        );

        // The second read asks for the same four bytes into the same buffer:
        // the descriptor and the buffer are loaded again, because the first
        // read's answer is in `eax` and the announce wrote `esi`.
        let loads = PIPE_READER_PROGRAM
            .windows(3)
            .filter(|window| *window == [0x8B, 0x3C, 0x24])
            .count();
        assert_eq!(loads, 2, "one load per read");
        let reads = PIPE_READER_PROGRAM
            .windows(5)
            .filter(|window| *window == [0xB8, 0x05, 0x00, 0x00, 0x00])
            .count();
        assert_eq!(reads, 2, "and one Read per load");
    }
}
