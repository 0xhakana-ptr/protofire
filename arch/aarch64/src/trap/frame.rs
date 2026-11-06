//! arch/aarch64/src/trap/frame.rs
//!
//! What the machine saves, offset for offset.
//!
//! `entry.S`'s `exception_entry` builds [`ExceptionFrame`] on the kernel stack
//! before calling the dispatch, and the two files agree on every offset because
//! the offsets are written down in both.  That is a fact no compiler checks — a
//! `repr(C)` struct and a run of `stp`s are two descriptions of one layout — so
//! the offsets are asserted here against `offset_of!` instead of being trusted.
//!
//! The SIMD half is not caution.  `CPACR_EL1.FPEN` is open, so the compiler
//! emits NEON for a `memcpy`; a handler that saved only `x0`..`x30` would
//! return to code whose vector operands it had destroyed.  The first aarch64
//! boot printed four lines and stopped, and `ESR_EL1.EC` = 7 at a NEON word was
//! why.

use super::dispatch::IRQ_KIND;
use super::dispatch::USER_SUPERVISOR_CALL_VECTOR;

/// The saved context of an interrupted instruction.
///
/// Laid out by `entry.S`, offset for offset, and asserted against
/// `offset_of!` below.  The fields are public because they are what the machine
/// saved and a handler reads them; nothing here has an invariant a setter would
/// protect.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExceptionFrame {
    /// `x0`..`x29`, in the order the assembly stores them.
    pub registers: [u64; 30],
    /// `x30`, the link register at the time of the exception.
    pub link_register: u64,
    /// `ELR_EL1`: the instruction that was interrupted.
    pub elr: u64,
    /// `SPSR_EL1`: the state to return to, the EL, the masks, the flags.
    pub spsr: u64,
    /// `ESR_EL1`: what the exception was.
    pub esr: u64,
    /// `FAR_EL1`: the address a faulting access named.
    pub far: u64,
    /// The entry's index, 0..16.
    pub vector: u64,
    /// `q0`..`q31`.  Saved because the compiler uses them for `memcpy`.
    pub simd: [u128; 32],
    /// The interrupted `SP_EL0`, at the end so every `q` pair keeps its offset.
    ///
    /// A system register, and the hardware does not push it, so without this
    /// field a task switch carries every register but the stack pointer, and a
    /// program that uses its stack resumes with the previous task's.  The pipe
    /// reader is what found it: it took a data abort at an address inside
    /// another program's memory.
    pub sp_el0: u64,
}

/// An `irq::Frame` needs a vector and nothing else from a machine that has no
/// process to hand a fault to, but the syndrome is what makes a log line
/// diagnosable, so `class_name` names it.
impl ExceptionFrame {
    /// The exception class, `ESR_EL1.EC`, bits 31..26.
    ///
    /// The class is what says *why*: an undefined instruction, a data abort, a
    /// system-register trap, or a supervisor call.  A log that printed only the
    /// vector would say which slot fired and not what arrived in it.
    pub fn class(&self) -> u32 {
        ((self.esr >> 26) & 0x3F) as u32
    }

    /// A short name for this exception class.
    ///
    /// Only the classes this machine has actually produced, plus the one a
    /// supervisor call uses.  An unnamed class reports `None` rather than
    /// inventing a name for it.
    pub fn class_name(&self) -> Option<&'static str> {
        match self.class() {
            0x00 => Some("unknown"),
            0x07 => Some("fp/simd trapped"),
            0x0E => Some("illegal execution state"),
            0x15 => Some("supervisor call"),
            0x18 => Some("trapped msr/mrs"),
            0x20 | 0x21 => Some("instruction abort"),
            0x24 | 0x25 => Some("data abort"),
            0x26 => Some("stack-pointer alignment fault"),
            0x2C => Some("fp/simd access trapped"),
            _ => None,
        }
    }

    /// Whether this exception is a supervisor call, which returns.
    pub fn is_supervisor_call(&self) -> bool {
        self.class() == 0x15
    }

    /// Whether this exception is a data abort.
    ///
    /// Two classes, and the difference between them is the same one x86_64
    /// makes with the page-fault error code's `P` bit: 0x24 is a
    /// **translation** fault, where the walk found no valid entry, and 0x25 is
    /// a **permission** fault, where the walk found the translation and
    /// refused the access.  Only the second can be repaired by changing the
    /// mapping, which is what a copy-on-write handler does.
    pub fn is_data_abort(&self) -> bool {
        matches!(self.class(), 0x24 | 0x25)
    }

    /// Whether this data abort was caused by a **write**.
    ///
    /// `ESR_EL1` bit 6 is `WnR`, and it is defined only for a data abort; on
    /// every other class it is a different field or reserved.  A caller has to
    /// have established the class before asking, which is why this is guarded
    /// rather than masked unconditionally.
    pub fn fault_was_write(&self) -> bool {
        self.is_data_abort() && (self.esr >> 6) & 1 == 1
    }

    /// Whether this data abort found the translation **present**.
    ///
    /// Class 0x25 and not 0x24, for the reason [`Self::is_data_abort`] gives.
    pub fn fault_was_present(&self) -> bool {
        self.class() == 0x25
    }

    /// Whether this exception is a supervisor call from a program.
    ///
    /// The vector is entry 8, `Lower64`'s synchronous kind, and the class is
    /// `0x15`.  Both, because either alone is a different thing: entry 8 with
    /// another class is a program's fault, and an `svc` at EL1 is the kernel
    /// calling itself, which `install_table` does as its self-test.
    pub fn is_user_supervisor_call(&self) -> bool {
        self.vector == USER_SUPERVISOR_CALL_VECTOR && self.is_supervisor_call()
    }

    /// The syscall number a program put in `x8`.
    ///
    /// The register is the ABI's choice, and it is the one every caller sets
    /// before `svc`.  Reading it here rather than from `x0` keeps the number
    /// and the first argument from sharing a register.
    pub fn syscall_number(&self) -> usize {
        self.registers[8] as usize
    }

    /// The six arguments a program put in `x0..x5`.
    pub fn syscall_arguments(&self) -> [usize; 6] {
        let mut arguments = [0usize; 6];
        for (index, slot) in arguments.iter_mut().enumerate() {
            *slot = self.registers[index] as usize;
        }
        arguments
    }

    /// Put a syscall's result in `x0`, which is where a caller reads it.
    pub fn set_return(&mut self, value: usize) {
        self.registers[0] = value as u64;
    }

    /// Whether this exception arrived on one of the four IRQ entries.
    ///
    /// The vector is `(group * 4) + kind`, and every group's `Irq` kind has the
    /// index 1.  So the question is `vector % 4 == 1`, the same arithmetic for
    /// an IRQ taken from the kernel and one taken from a user program, which is
    /// what makes one check enough.
    pub fn is_irq(&self) -> bool {
        self.vector % 4 == IRQ_KIND
    }
}

// The offsets `entry.S` writes, checked against this structure's.  A mismatch
// is a frame the assembly filled in one place and Rust reads in another, and
// the symptom would be a handler acting on `x0` when it meant `x7`.
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, registers) == 0);
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, link_register) == 240);
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, elr) == 248);
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, spsr) == 256);
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, esr) == 264);
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, far) == 272);
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, vector) == 280);
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, sp_el0) == 800);
const _: () = assert!(core::mem::offset_of!(ExceptionFrame, simd) == 288);
const _: () = assert!(core::mem::size_of::<ExceptionFrame>() == 816);
const _: () = assert!(core::mem::align_of::<ExceptionFrame>() == 16);
