//! arch/riscv64/src/plic.rs
//!
//! The PLIC: the platform's external interrupt controller.
//!
//! ## What the machine has
//!
//! A PLIC is three register groups in one window (the tree's `reg`):
//!
//! | group | what it does |
//! |---|---|
//! | priority | one 32-bit word per source, 0 meaning "never deliver" |
//! | pending | one bit per source, read-only, set by the device |
//! | enables | one bit per source **per context**, in a bank per context |
//!
//! plus, per context, a threshold and a claim/complete pair.  A context is one
//! hart's one privilege mode: the tree's `interrupts-extended` lists them as
//! `(phandle, number)` pairs, and S-mode on hart N is context `2N+1` on the
//! `virt` machine — the M-mode consumer of each hart comes first.
//!
//! ## How an interrupt is taken
//!
//! The source raises its line, the PLIC sets its pending bit if the source's
//! priority is above zero and the context's enable bit is set, and the hart
//! takes the external interrupt.  The handler reads `claim`, which answers the
//! highest-priority pending source and **clears its pending bit**; work it,
//! then read `complete` with the same number, which lets the PLIC deliver the
//! source again.  A claimed source that is never completed is one the machine
//! will not deliver a second time — the same in-service idea as a GIC's `EOIR`.
//!
//! ## Why the register half is gated
//!
//! The offsets and the volatile accesses mean nothing on a host: there is no
//! window, and no test can read one.  What a host *can* check is the arithmetic
//! — which bank a context uses — so that stays outside the gate and the tests
//! exercise it.

/// The PLIC's register groups, as byte offsets into the window.
///
/// From the SiFive PLIC specification: priorities start at zero, the pending
/// array starts at `0x1000`, the enable banks at `0x2000` with `0x80` bytes per
/// context, and the context blocks at `0x20_0000` with `0x1000` per context.
pub const PRIORITY_BASE: usize = 0x0000_0000;
pub const PENDING_BASE: usize = 0x0000_1000;
pub const ENABLE_BASE: usize = 0x0000_2000;
pub const CONTEXT_BASE: usize = 0x0020_0000;
pub const ENABLE_STRIDE: usize = 0x80;
pub const CONTEXT_STRIDE: usize = 0x1000;

/// Within a context block: the threshold, then a reserved word, then claim.
pub const THRESHOLD: usize = 0x0;
pub const CLAIM: usize = 0x4;

/// The most sources a PLIC on the machines this tree boots declares.
pub const MAX_SOURCES: usize = 128;

/// The enable-bank offset a context's enables live at.
///
/// The one piece of this file where a mistake silently delivers one hart's
/// device to another, so it is a function a host test can check without a
/// `Plic` and without a window.
pub const fn enable_offset(context: usize) -> usize {
    ENABLE_BASE + context * ENABLE_STRIDE
}

/// The context block's offset — its threshold and claim registers.
pub const fn context_offset(context: usize) -> usize {
    CONTEXT_BASE + context * CONTEXT_STRIDE
}

/// A PLIC, as the boot found it.
#[derive(Debug, Clone, Copy)]
pub struct Plic {
    /// The window the tree's `reg` named.
    base: usize,
    /// The context this hart claims through.
    context: usize,
    /// How many sources the tree declared.
    sources: usize,
}

impl Plic {
    /// The PLIC at `base`, claiming through `context`, with `sources` sources.
    pub const fn new(base: usize, context: usize, sources: usize) -> Plic {
        Plic {
            base,
            context,
            sources,
        }
    }

    /// The window this PLIC occupies.
    pub const fn base(&self) -> usize {
        self.base
    }

    /// The context this hart claims through.
    pub const fn context(&self) -> usize {
        self.context
    }

    /// How many sources the machine declared.
    pub const fn sources(&self) -> usize {
        self.sources
    }

    /// The enable bank this instance's context uses.
    pub const fn enable_bank(&self) -> usize {
        enable_offset(self.context)
    }

    /// This instance's context block.
    pub const fn context_block(&self) -> usize {
        context_offset(self.context)
    }

    /// Raise a source from software, as a device would.
    ///
    /// The PLIC has no such register: a source is a device's wire, and nothing
    /// in the controller can pull one.  This says `false` rather than claiming
    /// a raise it cannot make.
    pub const fn can_raise() -> bool {
        false
    }
}

#[cfg(target_os = "none")]
mod registers {
    use super::CLAIM;
    use super::MAX_SOURCES;
    use super::PENDING_BASE;
    use super::PRIORITY_BASE;
    use super::Plic;
    use super::THRESHOLD;
    use super::context_offset;
    use super::enable_offset;

    impl Plic {
        /// One register, read.
        ///
        /// # Safety
        ///
        /// The window must be mapped and this must not race another access to
        /// the same register.
        unsafe fn read(&self, offset: usize) -> u32 {
            // SAFETY: the window is the tree's `reg` and the boot mapped it.
            unsafe { core::ptr::read_volatile((self.base() + offset) as *const u32) }
        }

        /// One register, written.
        ///
        /// # Safety
        ///
        /// As [`Plic::read`].
        unsafe fn write(&self, offset: usize, value: u32) {
            // SAFETY: as `read`.
            unsafe { core::ptr::write_volatile((self.base() + offset) as *mut u32, value) }
        }

        /// Take over the controller: every source's priority above the
        /// threshold, every enable clear, the threshold open.
        ///
        /// A source at priority zero is one the PLIC never delivers, so every
        /// source this machine declares gets one.  The threshold is the lowest
        /// priority this context will take, and zero takes everything above it.
        ///
        /// # Safety
        ///
        /// Called once, after the page table mapped the window as device
        /// memory.
        pub unsafe fn enable(&self) {
            for source in 1..self.sources().min(MAX_SOURCES) {
                // SAFETY: the caller's contract is this function's.
                unsafe { self.write(PRIORITY_BASE + source * 4, 1) };
            }
            for bank in 0..(MAX_SOURCES / 32) {
                // SAFETY: as above.
                unsafe { self.write(enable_offset(self.context()) + bank * 4, 0) };
            }
            // SAFETY: as above.
            unsafe { self.write(context_offset(self.context()) + THRESHOLD, 0) };
        }

        /// Let source `number` reach this context.
        ///
        /// # Safety
        ///
        /// Called after [`Plic::enable`], once per line, before the device that
        /// raises it is told to start signalling.
        pub unsafe fn enable_source(&self, number: usize) -> bool {
            if number == 0 || number >= self.sources().min(MAX_SOURCES) {
                return false;
            }
            let bank = number / 32;
            let bit = number % 32;
            // SAFETY: the caller's contract is this function's.
            unsafe {
                let offset = enable_offset(self.context()) + bank * 4;
                let current = self.read(offset);
                self.write(offset, current | (1 << bit));
            }
            true
        }

        /// Whether source `number` is enabled for this context, read back.
        ///
        /// # Safety
        ///
        /// Read-only.
        pub unsafe fn source_enabled(&self, number: usize) -> bool {
            if number >= self.sources().min(MAX_SOURCES) {
                return false;
            }
            let bank = number / 32;
            let bit = number % 32;
            // SAFETY: a read-only register access.
            unsafe { self.read(enable_offset(self.context()) + bank * 4) & (1 << bit) != 0 }
        }

        /// Claim the highest-priority pending source, or `None` when nothing is
        /// pending.
        ///
        /// A claim of zero means there was nothing to take — an interrupt can
        /// be withdrawn between the line being raised and the claim being read.
        ///
        /// # Safety
        ///
        /// Called from the trap path, for the external interrupt's cause.
        pub unsafe fn claim(&self) -> Option<usize> {
            // SAFETY: the caller's contract is this function's.
            let number = unsafe { self.read(context_offset(self.context()) + CLAIM) } as usize;
            (number != 0).then_some(number)
        }

        /// Finish a source, letting the PLIC deliver it again.
        ///
        /// # Safety
        ///
        /// `number` must be what [`Plic::claim`] answered, and the work it
        /// named must be done.
        pub unsafe fn complete(&self, number: usize) {
            // SAFETY: the caller's contract is this function's.
            unsafe { self.write(context_offset(self.context()) + CLAIM, number as u32) };
        }

        /// Whether the pending register holds `number`.
        ///
        /// # Safety
        ///
        /// Read-only.
        pub unsafe fn is_pending(&self, number: usize) -> bool {
            if number >= self.sources().min(MAX_SOURCES) {
                return false;
            }
            let bank = number / 32;
            let bit = number % 32;
            // SAFETY: a read-only register access.
            unsafe { self.read(PENDING_BASE + bank * 4) & (1 << bit) != 0 }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::MAX_SOURCES;
    use super::Plic;
    use super::context_offset;
    use super::enable_offset;

    /// The enable bank a context uses is one stride per context past the base.
    ///
    /// That arithmetic is the whole of what a driver of this controller has to
    /// get right on a machine with more than one hart: hart 0's S-mode context
    /// is 1, so its bank starts at `0x2000 + 0x80`; a driver that used the hart
    /// id would write hart 1's bank for hart 0 and deliver one hart's device to
    /// the other.
    #[test]
    fn the_enable_bank_follows_the_context() {
        assert_eq!(enable_offset(0), 0x2000, "context zero is the first bank");
        assert_eq!(enable_offset(1), 0x2000 + 0x80, "hart 0's S-mode context");
        assert_eq!(
            enable_offset(3),
            0x2000 + 3 * 0x80,
            "hart 1's S-mode context"
        );
    }

    /// The context block follows the context at a page each, and the two
    /// offsets a `Plic` reports are the ones its context names.
    #[test]
    fn the_context_block_is_a_page_per_context() {
        assert_eq!(context_offset(0), 0x20_0000);
        assert_eq!(context_offset(1), 0x20_0000 + 0x1000);

        let plic = Plic::new(0xc00_0000, 1, 95);
        assert_eq!(plic.base(), 0xc00_0000);
        assert_eq!(plic.context(), 1);
        assert_eq!(plic.sources(), 95);
        assert_eq!(plic.enable_bank(), enable_offset(1));
        assert_eq!(plic.context_block(), context_offset(1));
    }

    /// The enable banks end before the context blocks begin, which is what
    /// makes this file's register map the specification's rather than an
    /// opinion.
    #[test]
    fn the_enable_banks_end_before_the_contexts_start() {
        let last = enable_offset(2 * 4) + (MAX_SOURCES / 32) * 4;
        assert!(last <= context_offset(0), "banks end at {last:#x}");
    }

    /// This controller cannot be asked to raise a line, and says so.
    #[test]
    fn a_plic_cannot_raise_a_source() {
        assert!(!Plic::can_raise());
    }
}
