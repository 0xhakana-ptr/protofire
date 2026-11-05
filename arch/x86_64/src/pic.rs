//! arch/x86_64/src/pic.rs
//!
//! The 8259 Programmable Interrupt Controller, and why a PC boot has to deal
//! with it before it enables interrupts.
//!
//! ## What an unmapped 8259 does
//!
//! The 8259 is the PC's original interrupt controller: two chips, eight lines
//! each.  Reset puts their vector *bases* at 8 and 0x70, and vector 8 is the
//! double fault.  So a machine whose timer is still routed to the 8259 and
//! whose interrupts are enabled takes a timer tick as a double fault, and the
//! handler it finds is one the kernel wrote for a fault it will never raise.
//!
//! That is not a hypothetical: this tree found it the first time it executed
//! `sti`.  The boot line said `unhandled interrupt 8` and the log showed the
//! instruction after `enable`, which reads as a fault in the enable rather than
//! in the controller.
//!
//! ## What this does about it
//!
//! Masks every line.  Not remaps: this machine has an IOAPIC, the 8259 is the
//! legacy path, and a kernel that remapped instead would leave two controllers
//! able to raise the same line.  Masking makes the 8259 silent, which is what a
//! machine using the IOAPIC wants.
//!
//! A machine that *did* want the 8259 would remap it here, and the constants
//! for both bases are below so that change is one function rather than a
//! search.

/// The master's command port.
pub const MASTER_COMMAND: u16 = 0x20;
/// The master's data port.
pub const MASTER_DATA: u16 = 0x21;
/// The slave's command port.
pub const SLAVE_COMMAND: u16 = 0xA0;
/// The slave's data port.
pub const SLAVE_DATA: u16 = 0xA1;

/// The vector base a remapped master would use: the first free vector after the
/// processor's 32 exceptions.
pub const MASTER_BASE: u8 = 0x20;
/// The vector base a remapped slave would use.
pub const SLAVE_BASE: u8 = 0x28;

/// Mask every line on both chips.
///
/// A line whose bit is set is masked; writing all ones silences the chip.  The
/// two writes are to the data ports, which is where the mask register lives
/// after any initialisation.
pub fn mask_all() {
    // SAFETY: `out` writes one byte to an I/O port.  Both ports are the 8259's,
    // the kernel is at ring 0, and a machine with no 8259 ignores the write.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") MASTER_DATA, in("al") 0xFFu8,
            options(nomem, nostack, preserves_flags));
        core::arch::asm!("out dx, al", in("dx") SLAVE_DATA, in("al") 0xFFu8,
            options(nomem, nostack, preserves_flags));
    }
}

#[cfg(test)]
mod tests {
    use super::MASTER_BASE;
    use super::SLAVE_BASE;

    /// The remapped bases are the ones a PC needs, and the first is not 8.
    ///
    /// Vector 8 is the double fault.  A master base of 8, the reset value, ///
    /// is a timer tick that arrives as a fault, which is the defect this module
    /// exists for.
    #[test]
    fn the_bases_are_not_the_reset_values() {
        assert_eq!(
            MASTER_BASE, 0x20,
            "the first free vector after the exceptions"
        );
        assert_eq!(SLAVE_BASE, 0x28, "eight lines after the master's base");
        assert_ne!(
            MASTER_BASE, 8,
            "the reset value collides with the double fault"
        );
    }
}
