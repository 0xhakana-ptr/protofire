//! arch/riscv64/src/port.rs
//!
//! Port I/O, which this machine does not have.
//!
//! ## Why the module exists
//!
//! x86_64 gives a device a separate 16-bit I/O space reached by `in` and `out`.
//! Neither aarch64 nor riscv64 has one: a device's registers are mapped into
//! the address space, and PCI on these machines is memory-mapped throughout,
//! //! ECAM for configuration space, a BAR for everything else.
//!
//! The functions exist because the crate above asks for them through `arch` and
//! must not have to know which machine it is on.  Reading one reports "no such
//! port", which is what a PCI scan above treats as "no device here", the true
//! statement on a machine whose devices are not behind ports.
//!
//! ## Why not `compile_error!`
//!
//! Because a machine that does not have a thing is not an error at the call
//! site: the caller asked a question with an answer, and the answer is "none".

/// No I/O space: `0xFF` is what a machine without the port would read.
pub fn inb(_port: u16) -> u8 {
    0xFF
}

/// No I/O space: a write goes nowhere.
pub fn outb(_port: u16, _value: u8) {}

/// No I/O space.
pub fn inl(_port: u16) -> u32 {
    0xFFFF_FFFF
}

/// No I/O space.
pub fn outl(_port: u16, _value: u32) {}

#[cfg(test)]
mod tests {
    /// A machine without ports answers as if nothing were there.
    #[test]
    fn a_machine_without_ports_reads_absent() {
        assert_eq!(super::inb(0xCF8), 0xFF);
        assert_eq!(super::inl(0xCF8), 0xFFFF_FFFF);
    }
}
