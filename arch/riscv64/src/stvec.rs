//! arch/riscv64/src/stvec.rs
//!
//! The trap vector, and the register that installs it.
//!
//! ## The simplest of the three
//!
//! `stvec` names **one** address.  Every trap, an interrupt, a page fault, an
//! illegal instruction, a system call, enters there, and the handler reads
//! `scause` to find out what happened.  There is no table, no offset per
//! vector, and no group by origin: x86_64's 256 gates and aarch64's sixteen
//! entries both exist to save a handler the work of asking, and riscv64 asks.
//!
//! ## The two modes
//!
//! `stvec`'s low two bits say what the address means:
//!
//! | mode | meaning |
//! |---|---|
//! | 0 | direct: every trap enters at the address |
//! | 1 | vectored: an interrupt enters at `base + cause * 4`; an exception still enters at `base` |
//!
//! Vectored mode is what a machine with a controller per source uses, and its
//! stride is **four bytes**, one instruction, which is why the entries it
//! dispatches to can only be a jump.
//!
//! This tree uses direct mode: one entry, and the cause read there.  A vectored
//! table would be one instruction per cause with a jump in each, which is the
//! same work with a table to keep in step.

/// `stvec` mode: every trap enters at the address.
pub const MODE_DIRECT: usize = 0;
/// `stvec` mode: an interrupt enters at `base + cause * 4`.
pub const MODE_VECTORED: usize = 1;

/// The stride of a vectored table's entries: one instruction, four bytes.
///
/// The reason a vectored table holds jumps rather than handlers: four bytes is
/// one instruction, and a `jal` to the real handler is what fits.
pub const VECTOR_STRIDE: usize = 4;

/// Why a trap was taken, as `scause` reports it.
///
/// Bit 63 is the interrupt flag; the rest is the code.  The two are read
/// together because the same code number means different things as an interrupt
/// and as an exception, cause 1 is a supervisor software interrupt and also a
/// fault on an instruction fetch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cause {
    /// Whether this was an interrupt rather than an exception.
    pub interrupt: bool,
    /// The code, with the interrupt flag removed.
    pub code: usize,
}

impl Cause {
    /// Split a raw `scause` into its two parts.
    ///
    /// The flag is bit 63 on a 64-bit machine, and the code is what remains.
    /// A reader that masked with `0xFF` would lose the flag on a machine whose
    /// codes are wider, and one that did not mask at all would report a code
    /// with 2^63 added to it.
    pub const fn of(raw: usize) -> Cause {
        Cause {
            interrupt: raw & (1 << 63) != 0,
            code: raw & !(1 << 63),
        }
    }

    /// A summary for a log line, because a trap the kernel cannot handle is one
    /// whose cause is the only thing there is to report.
    pub const fn name(self) -> &'static str {
        match (self.interrupt, self.code) {
            (true, 1) => "supervisor software interrupt",
            (true, 5) => "supervisor timer interrupt",
            (true, 9) => "supervisor external interrupt",
            (false, 0) => "instruction address misaligned",
            (false, 1) => "instruction access fault",
            (false, 2) => "illegal instruction",
            (false, 3) => "breakpoint",
            (false, 5) => "load access fault",
            (false, 7) => "store access fault",
            (false, 8) => "environment call from U-mode",
            (false, 9) => "environment call from S-mode",
            (false, 12) => "instruction page fault",
            (false, 13) => "load page fault",
            (false, 15) => "store page fault",
            (true, _) => "interrupt",
            (false, _) => "exception",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Cause;
    use super::MODE_DIRECT;
    use super::MODE_VECTORED;
    use super::VECTOR_STRIDE;

    /// The two modes are the register's low two bits.
    #[test]
    fn the_modes_are_the_registers_low_bits() {
        assert_eq!(MODE_DIRECT, 0);
        assert_eq!(MODE_VECTORED, 1);
        assert_eq!(VECTOR_STRIDE, 4);
    }

    /// A cause's interrupt flag is bit 63 and its code is what remains.
    ///
    /// The same code number means an interrupt and an exception depending on
    /// that bit: cause 1 is a supervisor software interrupt and also a fault on
    /// an instruction fetch.  A reader that dropped the flag would call a timer
    /// tick a page fault.
    #[test]
    fn a_cause_splits_into_flag_and_code() {
        let exception = Cause::of(13);
        assert!(!exception.interrupt);
        assert_eq!(exception.code, 13);
        assert_eq!(exception.name(), "load page fault");

        let interrupt = Cause::of((1usize << 63) | 5);
        assert!(interrupt.interrupt);
        assert_eq!(interrupt.code, 5);
        assert_eq!(interrupt.name(), "supervisor timer interrupt");
    }

    /// The same code names different things by the flag, which is why the flag
    /// is part of the cause rather than a separate question.
    #[test]
    fn one_code_two_events() {
        assert_eq!(Cause::of(1).name(), "instruction access fault");
        assert_eq!(
            Cause::of((1usize << 63) | 1).name(),
            "supervisor software interrupt"
        );
    }

    /// An unknown cause still names something, so a log line is never empty.
    #[test]
    fn an_unknown_cause_still_has_a_name() {
        assert_eq!(Cause::of(200).name(), "exception");
        assert_eq!(Cause::of((1usize << 63) | 200).name(), "interrupt");
    }
}
