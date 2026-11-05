//! arch/x86_64/src/port.rs
//!
//! Port I/O: the instruction pair that reaches a device whose registers are not
//! in memory.
//!
//! ## Why this is a machine module and not a PCI detail
//!
//! x86_64 gives a device two ways to be reached: mapped into the address space
//! (MMIO), or behind a separate 16-bit I/O space that only `in` and `out`
//! touch. The second is x86_64's, not PCI's, aarch64 and riscv64 have no I/O
//! space at all, and PCI on those machines is memory-mapped throughout.
//!
//! So the instructions live here and the PCI crate asks for them through
//! `arch`, which is what keeps `i686`'s `outb` out of a crate that has to build
//! for three machines.
//!
//! ## The host arm
//!
//! A host has no I/O ports and no privilege to touch them, so every function
//! here reads zero and discards writes.  That is the honest arm for a test: a
//! PCI scan on a host finds no device, which is the true statement, and the
//! enumeration logic above it can still be exercised by a fake register file.

/// Read one byte from `port`.
#[cfg(target_os = "none")]
pub fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: `in` reads one byte from the I/O port named.  It is a privileged
    // instruction and this kernel runs in ring 0; every port this tree reads is
    // one the machine documents, and reading a port nothing decodes returns
    // 0xFF rather than faulting.
    unsafe {
        core::arch::asm!("in al, dx", in("dx") port, out("al") value, options(nomem, nostack, preserves_flags));
    }
    value
}

/// Write one byte to `port`.
#[cfg(target_os = "none")]
pub fn outb(port: u16, value: u8) {
    // SAFETY: as `inb`, a ring-0 write to one byte of the I/O space.
    unsafe {
        core::arch::asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags));
    }
}

/// Read one 32-bit word from `port`.
#[cfg(target_os = "none")]
pub fn inl(port: u16) -> u32 {
    let value: u32;
    // SAFETY: as `inb`, four bytes wide.  The PCI configuration mechanism uses
    // aligned 32-bit accesses on its two ports.
    unsafe {
        core::arch::asm!("in eax, dx", in("dx") port, out("eax") value, options(nomem, nostack, preserves_flags));
    }
    value
}

/// Write one 32-bit word to `port`.
#[cfg(target_os = "none")]
pub fn outl(port: u16, value: u32) {
    // SAFETY: as `inl`.
    unsafe {
        core::arch::asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags));
    }
}

/// A host has no I/O space; a read returns the value a missing port gives.
#[cfg(not(target_os = "none"))]
pub fn inb(_port: u16) -> u8 {
    0xFF
}

/// A host has no I/O space; a write goes nowhere.
#[cfg(not(target_os = "none"))]
pub fn outb(_port: u16, _value: u8) {}

/// A host has no I/O space.
#[cfg(not(target_os = "none"))]
pub fn inl(_port: u16) -> u32 {
    0xFFFF_FFFF
}

/// A host has no I/O space.
#[cfg(not(target_os = "none"))]
pub fn outl(_port: u16, _value: u32) {}

#[cfg(test)]
mod tests {
    /// A host's ports read as absent, which is what a scan above them has to
    /// interpret correctly.
    ///
    /// A host arm that returned zero would be indistinguishable from a device
    /// whose first register happens to be zero, and a PCI scan would report
    /// one device per bus position.  `0xFF` is what a real machine returns for
    /// an address nothing decodes.
    #[test]
    fn a_host_port_reads_as_absent() {
        assert_eq!(super::inb(0xCF8), 0xFF);
        assert_eq!(super::inl(0xCF8), 0xFFFF_FFFF);
    }

    /// Writing to a host port is accepted and has no effect.
    #[test]
    fn a_host_port_write_goes_nowhere() {
        super::outb(0xCF8, 0x12);
        super::outl(0xCF8, 0x1234_5678);
        assert_eq!(super::inl(0xCF8), 0xFFFF_FFFF);
    }
}
