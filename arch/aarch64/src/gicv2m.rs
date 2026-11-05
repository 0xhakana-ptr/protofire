//! arch/aarch64/src/gicv2m.rs
//!
//! The GICv2m frame: where a memory write becomes an interrupt.
//!
//! An MSI-X device raises an interrupt by **writing to an address**, and the
//! platform decides what that write means.  On a GICv2 that decision is a
//! *frame*: a small window where a write at one offset produces one of a
//! contiguous run of shared peripheral interrupts.
//!
//! Two registers, and both are needed:
//!
//! | offset | register | what it says |
//! |---|---|---|
//! | `0x008` | `GICV2M_MSI_TYPER` | the first interrupt number the frame can raise, and how many |
//! | `0x000` + `4 * n` | `GICV2M_MSI_SET_SPI` | writing here raises the frame's n-th interrupt |
//!
//! The address a device writes **is** the interrupt selector: the frame decodes
//! the low bits of the address to choose which of its interrupts to raise, and
//! the value written is irrelevant.  So an MSI-X entry's address is computed
//! from the frame's base and a slot index, not chosen, and a driver that wrote
//! an arbitrary address would raise whichever interrupt that address selected,
//! or none.
//!
//! The two registers and the arithmetic that turns a slot into an address.  Not
//! here: the frame's per-interrupt masking (`GICV2M_MSI_SETSPI_NS` has no mask;
//! the distributor's does), and GICv3's ITS, which replaces the whole scheme
//! with a command queue.

/// `GICV2M_MSI_TYPER`: the interrupt range this frame raises.
pub const MSI_TYPER: usize = 0x008;
/// The first `GICV2M_MSI_SETSPI_NS` register; slot `n` is four bytes past it.
///
/// A GICv2m frame has **two aliases** of the same array: `0x0000` for secure
/// accesses and `0x0040` for non-secure ones.  A kernel running at non-secure
/// EL1, which is every kernel that arrived through EL2, and the one this tree
/// boots, must use the non-secure alias.
///
/// A write to the secure alias from non-secure state is not an error and does
/// not fault: the frame simply does not act on it.  `ISPENDR` stays zero, the
/// interrupt never exists, and the symptom is indistinguishable from a
/// misconfigured distributor.  Six separate things were checked before this one
///, the line's enable, its group, its trigger, its target, its priority, and
/// the distributor's own enable, all of which read back correct, because a
/// silent write to the wrong alias looks exactly like a correct write that did
/// nothing.
pub const MSI_SET_SPI: usize = 0x040;
/// The secure alias's first register, which this kernel must not use.
pub const MSI_SET_SPI_SECURE: usize = 0x000;

/// The first interrupt number, from `MSI_TYPER` bits 0..10.
pub const TYPER_FIRST_MASK: u32 = 0x03FF;
/// How many interrupts, from `MSI_TYPER` bits 16..26.
pub const TYPER_COUNT_SHIFT: u32 = 16;
/// The count field's width.
pub const TYPER_COUNT_MASK: u32 = 0x03FF;

/// A frame the machine's device tree described.
#[derive(Debug, Clone, Copy)]
pub struct Frame {
    base: usize,
    first_interrupt: u32,
    count: u32,
}

impl Frame {
    /// A frame at `base`, raising `first_interrupt` and the `count - 1` numbers
    /// after it.
    ///
    /// Both numbers come from `MSI_TYPER`, which the caller read: the frame is
    /// the machine's, and which interrupts it was wired to is the platform's
    /// decision rather than a constant.
    pub const fn new(base: usize, first_interrupt: u32, count: u32) -> Frame {
        Frame {
            base,
            first_interrupt,
            count,
        }
    }

    /// The register is two ten-bit fields, not one number: the first interrupt
    /// in bits 0..10 and the count in bits 16..26.  A driver that read it as
    /// one value would treat `count << 16 | first` as an interrupt number.
    pub const fn from_typer(base: usize, typer: u32) -> Frame {
        Frame {
            base,
            first_interrupt: typer & TYPER_FIRST_MASK,
            count: (typer >> TYPER_COUNT_SHIFT) & TYPER_COUNT_MASK,
        }
    }

    pub const fn first_interrupt(&self) -> u32 {
        self.first_interrupt
    }

    pub const fn count(&self) -> u32 {
        self.count
    }

    pub const fn holds(&self, slot: u32) -> bool {
        slot < self.count
    }

    /// `None` for a slot past the frame's count, which is an interrupt the
    /// frame would not raise at all, and a driver that used the number anyway
    /// would enable a line nothing can produce.
    pub const fn interrupt(&self, slot: u32) -> Option<u32> {
        if self.holds(slot) {
            Some(self.first_interrupt + slot)
        } else {
            None
        }
    }

    /// The address a device writes to raise `slot`'s interrupt.
    ///
    /// This is the address an MSI-X table entry holds.  The value the device
    /// writes is not part of the selection: **the address is**, which is why
    /// this is a computed value and a caller cannot pick one.
    ///
    /// It is the **non-secure** alias, because that is the only one this
    /// kernel's exception level may use.
    pub const fn address(&self, slot: u32) -> Option<u64> {
        if self.holds(slot) {
            Some((self.base + MSI_SET_SPI + (slot as usize) * 4) as u64)
        } else {
            None
        }
    }

    /// The value a device writes there.
    ///
    /// The frame acts on the *address*, so the payload is not read, but the
    /// specification requires the write to be a dword, and a device that wrote
    /// zero is a write like any other.  This returns the slot index, which is
    /// what a log would want to show and what a device's driver would write.
    pub const fn data(&self, slot: u32) -> u32 {
        slot
    }

    /// # Safety
    ///
    /// `base` must be an `arm,gic-v2m-frame` window the machine's device tree
    /// named, mapped uncached.
    #[cfg(target_os = "none")]
    pub unsafe fn probe(base: usize) -> Frame {
        // SAFETY: the caller promises `base` is a frame's window.
        let typer = unsafe { core::ptr::read_volatile((base + MSI_TYPER) as *const u32) };
        Frame::from_typer(base, typer)
    }
}

#[cfg(test)]
mod tests;
