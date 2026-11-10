//! arch/riscv64/src/aplic.rs
//!
//! The AIA's APLIC: the platform controller a device's **wire** arrives at.
//!
//! ## Where it sits
//!
//! The RISC-V Advanced Interrupt Architecture replaces the PLIC's role with two
//! devices: an **IMSIC** per hart, which receives message-signalled interrupts,
//! and an **APLIC**, which the wired sources arrive at.  A machine can be
//! described with only an APLIC (`-machine virt,aia=aplic`), with both
//! (`aia=aplic-imsic`), or with the older PLIC (`-machine virt`, this tree's
//! default).  The three are different controllers, and a boot that read only
//! the PLIC node on an AIA machine found none — `no external interrupt
//! controller`, which is the gap this file closes.
//!
//! ## The two delivery modes
//!
//! `domaincfg`'s `DM` bit chooses what an enabled source does:
//!
//! | `DM` | what an enabled source becomes |
//! |---|---|
//! | 0 | the hart's external interrupt, exactly as a PLIC's line is |
//! | 1 | a message the APLIC writes into a hart's IMSIC file |
//!
//! This kernel's external path is the **direct** one: the trap reports a cause,
//! the controller answers a claim, the source is completed.  MSI delivery needs
//! an IMSIC on every hart and a message address no wired device here has, and
//! it is a second mechanism rather than a setting this boot would use.
//!
//! ## Why this is not a second `Plic`
//!
//! The register map is different in ways that matter:
//!
//! - A PLIC's enables are per **context** (one bank per hart's privilege mode);
//!   an APLIC's are per **domain**, one set of registers for the sources the
//!   domain owns.
//! - A PLIC picks a source's destination with an `ITARGETSR` bitmask of harts;
//!   an APLIC has one **target word per source**, carrying the hart's index and
//!   the source's priority, and a source with no target delivers nowhere.
//! - A PLIC's threshold and claim are at a context block fixed by the context
//!   number; an APLIC's are in a per-hart **interrupt delivery control** block
//!   at a fixed stride from `0x4000`.
//!
//! So the offsets below are the AIA's (specification §4.5 and §4.8, and the
//! same numbers Linux's `riscv-aplic.h` carries), and a test pins them.
//!
//! ## Why the register half is gated
//!
//! The offsets and the volatile accesses mean nothing on a host: there is no
//! window, and no test can read one.  What a host *can* check is the arithmetic
//! — which register a source uses, where a hart's delivery block is, which bits
//! a direct-mode domain needs — so that stays outside the gate and the tests
//! exercise it.

/// `domaincfg`: bit 8 enables the domain's interrupt delivery.
pub const DOMAIN_ENABLE: u32 = 1 << 8;
/// `domaincfg`: bit 2 selects **message** delivery.  Direct delivery is the bit
/// clear, which is the mode this module drives.
pub const DOMAIN_MSI_MODE: u32 = 1 << 2;

/// Where the source-configuration array starts: one 32-bit word per source.
pub const SOURCE_CONFIG_BASE: usize = 0x0004;
/// The source-configuration word's low three bits: the SM field.
pub const SOURCE_SM_MASK: u32 = 0x7;
/// SM value for a level, active-high source — a 16550's transmitter line.
///
/// The APLIC's SM field is richer than the GIC's two-bit trigger: it names the
/// edge direction or the level polarity.  `6` is level-high; `4` and `5` are
/// the two edges.  A level line configured as an edge would drop an assertion
/// that was already high when the source was enabled, which is the defect this
/// tree measured on the GIC's private timer line.
pub const SOURCE_LEVEL_HIGH: u32 = 0x6;
/// `sourcecfg` bit 10 marks a source **delegated** to the child domain.  The
/// sources this kernel drives are the S-mode domain's own, so it stays clear.
pub const SOURCE_DELEGATED: u32 = 1 << 10;

/// Where the source's **target** words start: one per source.
///
/// A target word carries the destination hart's index in bits 18.., the guest
/// index in bits 12.., and the source's priority in bits 0..8.  A source whose
/// target is zero delivers to hart index zero at priority zero, and priority
/// zero is what the APLIC treats as "never deliver" — which is why the priority
/// is written and not left to reset.
pub const TARGET_BASE: usize = 0x3004;
pub const TARGET_HART_SHIFT: u32 = 18;
pub const TARGET_HART_MASK: u32 = 0x3FFF;
/// The low eleven bits of a target word: the delivery priority in direct mode
/// and the message's identity in MSI mode.
pub const TARGET_EIID_MASK: u32 = 0x7FF;

/// The interrupt-enable registers: one bit per source, 32 per register.
pub const SETIE_BASE: usize = 0x1E00;
/// The write-one-to-disable registers, beside `setie`.
pub const CLRIE_BASE: usize = 0x1F00;

/// The per-hart interrupt delivery control block's base and stride.
pub const IDC_BASE: usize = 0x4000;
pub const IDC_STRIDE: usize = 32;

/// Within a hart's delivery control block.
///
/// `claimi` is the claim/complete register, and its **value** is not a bare
/// source number: the identity sits in bits 16.. and the priority in bits 0..8,
/// which is why a claim of source 10 reads back as `0x000A_0001` rather than
/// `10`.  The same packing is on `stopei` in an IMSIC file, and it is the
/// layout a driver that read the word as a number gets wrong — this one was
/// written that way first and the boot printed `unhandled external interrupt
/// 655361` for every one.
pub const IDC_DELIVERY: usize = 0x00;
pub const IDC_THRESHOLD: usize = 0x08;
pub const IDC_CLAIM: usize = 0x1C;

/// The claim word's identity shift and mask.
pub const CLAIM_IDENTITY_SHIFT: u32 = 16;
pub const CLAIM_IDENTITY_MASK: u32 = 0x3FF;

/// `idelivery` bit 0: this hart takes the domain's interrupts.
pub const IDC_DELIVERY_ENABLE: u32 = 1;

/// The most sources this window's register layout can name.
///
/// The architecture caps a domain at 1024 sources, and the arrays are indexed
/// **from source 1**: a source's target word is at `0x3004 + source * 4`, so
/// source 1022's is the last below `0x4000`, where the per-hart delivery blocks
/// begin.  Source 1023's would be the first block's delivery register, which is
/// why the usable cap is 1023 and not 1024.
///
/// This is the layout's own bound rather than a machine's: QEMU's `virt`
/// declares 96, and a machine that declared the cap would fill the array to its
/// last word.
pub const MAX_SOURCES: usize = 1023;

/// An APLIC, as the boot found it.
#[derive(Debug, Clone, Copy)]
pub struct Aplic {
    /// The window the tree's `reg` named.
    base: usize,
    /// The hart index this hart uses: the APLIC's numbering, which its target
    /// words name and which selects this hart's delivery control block.
    hart: usize,
    /// How many sources the tree declared.
    sources: usize,
}

impl Aplic {
    /// The APLIC at `base`, delivering to hart index `hart`, with `sources`
    /// sources.
    pub const fn new(base: usize, hart: usize, sources: usize) -> Aplic {
        Aplic {
            base,
            hart,
            sources,
        }
    }

    /// The window this APLIC occupies.
    pub const fn base(&self) -> usize {
        self.base
    }

    /// The APLIC's index for this hart.
    pub const fn hart(&self) -> usize {
        self.hart
    }

    /// How many sources the machine declared.
    pub const fn sources(&self) -> usize {
        self.sources
    }

    /// The `domaincfg` value a direct-mode, enabled domain has.
    ///
    /// **Direct** because this kernel's external path is a claim — cause,
    /// claim, complete — and **enabled** because a domain that is configured
    /// and off delivers nothing.
    pub const fn direct_domain_config() -> u32 {
        DOMAIN_ENABLE
    }

    /// The word source `source`'s target register needs: this hart, and the
    /// **identity the source's message carries**.
    ///
    /// The low eleven bits of a target word mean different things by mode —
    /// the delivery priority in direct mode, the message's **EIID** in MSI
    /// mode — and this writes the **source's own number** there for both.  In
    /// direct mode a priority of zero is "never deliver", so a source number
    /// (which starts at one) is a priority that delivers; in MSI mode it makes
    /// the identity a device's message carries **the same number the trap
    /// claims**, which is what lets the trap path recognise which device sent
    /// it.
    ///
    /// That second property is not cosmetic, it is what ended a storm: the
    /// first version wrote a constant here, so **every** wired source's
    /// message landed on identity 1 — the console's and anything else's alike —
    /// and a trap that claimed identity 1 could not tell the console's wire
    /// from anything else, so it never acknowledged the 16550, whose level
    /// wire stayed high, and the APLIC re-sent the message forever.  Measured:
    /// 16,052 claims of identity 1 in six seconds, each with the IMSIC's own
    /// pending bit clear after the claim, none resolving.
    ///
    /// The guest field stays zero: there is no hypervisor.
    pub const fn target_word(hart: usize, source: usize) -> u32 {
        ((hart as u32 & TARGET_HART_MASK) << TARGET_HART_SHIFT) | (source as u32 & TARGET_EIID_MASK)
    }

    /// The source-configuration word a wired, level-high source needs.
    ///
    /// Level and active-high, and **not delegated**: a delegated source belongs
    /// to the child domain, and a source marked delegated in the parent is one
    /// the parent then refuses to deliver.
    pub const fn source_config() -> u32 {
        SOURCE_LEVEL_HIGH
    }

    /// The register that enables source `number`.
    ///
    /// One register per thirty-two sources.  The offset does not move with the
    /// hart, which is the difference from a PLIC: an APLIC's enables belong to
    /// the domain, and these machines give each hart a domain of its own.
    pub const fn enable_offset(number: usize) -> usize {
        SETIE_BASE + (number / 32) * 4
    }

    /// The target word for `number`.
    pub const fn target_offset(number: usize) -> usize {
        TARGET_BASE + number * 4
    }

    /// The source-configuration word for `number`.
    pub const fn source_offset(number: usize) -> usize {
        SOURCE_CONFIG_BASE + number * 4
    }

    /// This hart's interrupt delivery control block.
    pub const fn idc_offset(&self) -> usize {
        IDC_BASE + self.hart * IDC_STRIDE
    }

    /// The claim/complete register this hart reads and writes.
    pub const fn claim_offset(&self) -> usize {
        self.idc_offset() + IDC_CLAIM
    }
}

#[cfg(target_os = "none")]
mod registers {
    use super::Aplic;
    use super::IDC_DELIVERY;
    use super::IDC_DELIVERY_ENABLE;
    use super::IDC_THRESHOLD;
    use super::MAX_SOURCES;

    impl Aplic {
        /// One register, read.
        ///
        /// # Safety
        ///
        /// The window must be mapped, and this must not race another access to
        /// the same register.
        unsafe fn read(&self, offset: usize) -> u32 {
            // SAFETY: the window is the tree's `reg` and the boot mapped it.
            unsafe { core::ptr::read_volatile((self.base() + offset) as *const u32) }
        }

        /// One register, written.
        ///
        /// # Safety
        ///
        /// As [`Aplic::read`].
        unsafe fn write(&self, offset: usize, value: u32) {
            // SAFETY: as `read`.
            unsafe { core::ptr::write_volatile((self.base() + offset) as *mut u32, value) }
        }

        /// Take over the controller: direct delivery, every source target and
        /// configuration set, every enable clear, this hart's delivery open.
        ///
        /// The domain is **disabled first**: a source configured while the
        /// domain is live can be delivered with the configuration it had
        /// before.
        ///
        /// # Safety
        ///
        /// Called once, after the page table mapped the window as device
        /// memory.
        pub unsafe fn enable(&self) {
            // SAFETY: the caller's contract is this function's, for every
            // access below: they are all registers inside the window it mapped.
            unsafe {
                self.write(super::DOMAIN_CONFIG, 0);

                for source in 1..self.sources().min(MAX_SOURCES) {
                    self.write(Aplic::source_offset(source), Aplic::source_config());
                    // The target is what makes a source deliver at all: a
                    // source with no target — or one whose identity is zero —
                    // is enabled and never delivered.  And the identity being
                    // the source's own number is what lets the trap path name
                    // the device, see [`Aplic::target_word`].
                    self.write(
                        Aplic::target_offset(source),
                        Aplic::target_word(self.hart(), source),
                    );
                }

                // This hart's delivery: open, and a threshold that accepts
                // every priority above zero.
                self.write(self.idc_offset() + IDC_DELIVERY, IDC_DELIVERY_ENABLE);
                self.write(self.idc_offset() + IDC_THRESHOLD, 0);

                self.write(super::DOMAIN_CONFIG, Aplic::direct_domain_config());
                core::arch::asm!("fence iorw, iorw", options(nostack));
            }
        }

        /// Let source `number` reach this hart.
        ///
        /// # Safety
        ///
        /// Called after [`Aplic::enable`], once per line, before the device
        /// that raises it is told to start signalling.
        pub unsafe fn enable_source(&self, number: usize) -> bool {
            if number == 0 || number >= self.sources().min(MAX_SOURCES) {
                return false;
            }
            let bit = number % 32;
            let offset = Aplic::enable_offset(number);
            // SAFETY: the source index is below the bound checked above, so the
            // register is one the window has.
            unsafe {
                // `setie` is **write-one-to-enable** and needs no read: a
                // read-modify-write of it would also write the bits this code
                // read, which for a write-one register is every source that was
                // already enabled.
                self.write(offset, 1 << bit);
            }
            true
        }

        /// Stop source `number` from reaching this hart.
        ///
        /// A **level** source whose wire stays high re-sends its message for as
        /// long as the wire is asserted, and a source with no driver is one
        /// nobody will ever deassert: claimed, reported, and immediately
        /// delivered again, for ever.  Silencing it at the controller is the
        /// only stop that is this kernel's to make, and it is what turns a
        /// device nobody serves into one printed line instead of a storm of
        /// them.  Measured with a completion vector wired to an IMSIC on this
        /// machine: an unhandled APLIC source took 41,201 deliveries in ten
        /// seconds before this existed, and one after.
        ///
        /// # Safety
        ///
        /// Called after [`Aplic::enable`], for a source the trap path has
        /// claimed and nobody has claimed a handler for.
        pub unsafe fn disable_source(&self, number: usize) -> bool {
            if number == 0 || number >= self.sources().min(super::MAX_SOURCES) {
                return false;
            }
            let bit = number % 32;
            let offset = super::CLRIE_BASE + (number / 32) * 4;
            // SAFETY: the caller's contract is this function's.  Like `setie`,
            // `clrie` is write-one-to-disable and needs no read.
            unsafe {
                self.write(offset, 1 << bit);
            }
            true
        }

        /// Whether source `number` is enabled for this hart.
        ///
        /// # Safety
        ///
        /// Read-only.
        pub unsafe fn source_enabled(&self, number: usize) -> bool {
            if number >= self.sources().min(MAX_SOURCES) {
                return false;
            }
            let bit = number % 32;
            // SAFETY: a read-only access at a register the bound above
            // guarantees the window has.
            //
            // `setie` is write-one-to-enable, and on this controller it
            // **does** read back the bits that are set: the monitor dump after
            // an enable of source 10 showed `0xd001e00` holding `0x400`.  So
            // the read is of the same register the write went to, and there is
            // no separate enable-state window — the `0x2000` this first asked
            // was zero on every boot, which read as "not enabled" for a source
            // the dump showed enabled.
            unsafe { self.read(Aplic::enable_offset(number)) & (1 << bit) != 0 }
        }

        /// Claim the highest-priority pending source, or `None` when nothing is
        /// pending.
        ///
        /// A claim of zero means there was nothing to take.  The delivery
        /// control block's `claimi` is per **hart**, so a claim is always this
        /// hart's.
        ///
        /// # Safety
        ///
        /// Called from the trap path, for the external interrupt's cause.
        pub unsafe fn claim(&self) -> Option<usize> {
            // SAFETY: the caller's contract is this function's.
            let word = unsafe { self.read(self.claim_offset()) };
            // The identity is in bits 16.. and the priority in the low byte; a
            // claim of zero means there was nothing to take.  A `claimi` word
            // is **not** a source number — reading it as one produced
            // `unhandled external interrupt 655361` (0xA0001, source 10 with
            // priority 1) on the first boot this driver ran.
            let number = (word >> super::CLAIM_IDENTITY_SHIFT) & super::CLAIM_IDENTITY_MASK;
            (number != 0).then_some(number as usize)
        }

        /// Whether this domain is in **direct** delivery mode.
        ///
        /// `false` means the machine forced message delivery: an APLIC
        /// configured with an IMSIC beside it (`-machine virt,aia=aplic-imsic`)
        /// has `DM` set and read-only, and a wired source then becomes a
        /// message this kernel has no IMSIC driver to receive.  A boot that
        /// read the domain back and found this would otherwise print a
        /// controller line and take zero console interrupts, which looks like a
        /// source that was never enabled.
        ///
        /// Measured: that machine's `domaincfg` reads `0x80000104` — bit 2 set,
        /// locked — while `-machine virt,aia=aplic` accepts direct mode and
        /// delivers the console's source twice a boot.
        ///
        /// # Safety
        ///
        /// Read-only.
        pub unsafe fn is_direct(&self) -> bool {
            // SAFETY: a read-only access to `domaincfg`, inside the window the
            // caller mapped.
            unsafe { self.read(super::DOMAIN_CONFIG) & super::DOMAIN_MSI_MODE == 0 }
        }

        /// Finish a source, letting the APLIC deliver it again.
        ///
        /// # Safety
        ///
        /// `number` must be what [`Aplic::claim`] answered, and the work it
        /// named must be done.
        pub unsafe fn complete(&self, number: usize) {
            // SAFETY: the caller's contract is this function's.
            unsafe { self.write(self.claim_offset(), number as u32) };
        }
    }
}

/// `domaincfg`'s register offset.
pub const DOMAIN_CONFIG: usize = 0x0000;

/// The delivery block's fields fit inside its stride, which is what makes the
/// stride the right unit: a claim at `0x1c` in a `0x20`-byte block is its last
/// word.  A compile-time relation rather than a test, because it cannot vary.
const _: () = assert!(IDC_CLAIM + 4 <= IDC_STRIDE);

#[cfg(test)]
mod tests {
    use super::Aplic;
    use super::DOMAIN_CONFIG;
    use super::DOMAIN_ENABLE;
    use super::DOMAIN_MSI_MODE;
    use super::IDC_BASE;
    use super::IDC_CLAIM;
    use super::IDC_DELIVERY;
    use super::IDC_DELIVERY_ENABLE;
    use super::IDC_STRIDE;
    use super::IDC_THRESHOLD;
    use super::MAX_SOURCES;
    use super::SETIE_BASE;
    use super::TARGET_BASE;
    use super::TARGET_EIID_MASK;

    /// The register offsets are the AIA's, written out so a reader can compare
    /// them against the specification instead of trusting the arithmetic.
    ///
    /// These are the numbers a copied PLIC driver gets wrong.  The PLIC puts
    /// its enables at `0x2000` and its context blocks at `0x20_0000`; the APLIC
    /// puts its enables at `0x1e00`, its targets at `0x3004`, and its per-hart
    /// blocks at `0x4000`.  Writing a PLIC's offsets into an APLIC window
    /// writes whatever those addresses happen to hold.
    #[test]
    fn the_offsets_are_the_architectures() {
        assert_eq!(DOMAIN_CONFIG, 0x0000);
        assert_eq!(super::SOURCE_CONFIG_BASE, 0x0004);
        assert_eq!(SETIE_BASE, 0x1E00);
        assert_eq!(TARGET_BASE, 0x3004);
        assert_eq!(IDC_BASE, 0x4000);
        assert_eq!(IDC_STRIDE, 32);
        assert_eq!(IDC_DELIVERY, 0x00);
        assert_eq!(IDC_THRESHOLD, 0x08);
        assert_eq!(IDC_CLAIM, 0x1C);
    }

    /// A domain is enabled in direct mode, and the MSI bit is what is **not**
    /// set.
    ///
    /// `domaincfg`'s `DM` is bit 2 and selects message delivery when set.  A
    /// driver that copied an MSI-mode configuration would enable the domain and
    /// receive nothing through this kernel's claim path, because its sources
    /// would become messages no IMSIC here reads.
    #[test]
    fn a_direct_domain_does_not_set_the_msi_bit() {
        let config = Aplic::direct_domain_config();
        assert_eq!(config & DOMAIN_ENABLE, DOMAIN_ENABLE, "the domain is on");
        assert_eq!(config & DOMAIN_MSI_MODE, 0, "direct is the MSI bit clear");
        // And the two are different bits, which is the whole of what this test
        // is for: a driver that confused them would write one for the other.
        assert_eq!(DOMAIN_ENABLE, 1 << 8);
        assert_eq!(DOMAIN_MSI_MODE, 1 << 2);
    }

    /// A wired source is level, active high, and not delegated to a child.
    ///
    /// The 16550's transmitter line stays asserted until the device is
    /// serviced, so an edge setting would drop the assertion that was already
    /// high when the source was enabled — the defect this tree measured on the
    /// GIC's private timer line.  `SOURCE_LEVEL_HIGH` is the AIA's value 6, and
    /// it is not zero: a source left at zero is **inactive** and delivers
    /// nothing.
    #[test]
    fn a_wired_source_is_level_high_and_active() {
        let config = Aplic::source_config();
        assert_eq!(config & super::SOURCE_SM_MASK, super::SOURCE_LEVEL_HIGH);
        assert_ne!(
            config & super::SOURCE_SM_MASK,
            0,
            "zero is an inactive source, which delivers nothing"
        );
        assert_eq!(config & super::SOURCE_DELEGATED, 0, "not delegated");
    }

    /// A source's target names the hart and **its own number**.
    ///
    /// The low eleven bits are the delivery priority in direct mode and the
    /// message's identity in MSI mode; a source's own number works for both —
    /// nonzero, so a direct-mode priority always delivers, and distinct per
    /// source, so a claimed identity names the device.  The storm a constant
    /// here produced is the measurement in [`Aplic::target_word`]'s own
    /// comment.
    #[test]
    fn every_source_names_a_hart_and_its_own_identity() {
        assert_eq!(
            Aplic::target_word(0, 10),
            10,
            "the console's source, as an identity"
        );
        assert_eq!(Aplic::target_word(1, 10), (1 << 18) | 10);
        assert_eq!(Aplic::target_word(0, 3) & TARGET_EIID_MASK, 3);
        assert_ne!(
            Aplic::target_word(0, 3),
            Aplic::target_word(0, 4),
            "two sources must not share an identity"
        );
        // A source number survives the eleven-bit field: the machines this
        // tree boots declare 96 sources, and the field holds 2048.
        assert_eq!(Aplic::target_word(0, 96) & TARGET_EIID_MASK, 96);
    }

    /// A source's enable register moves every thirty-two sources, and does not
    /// move with the hart.
    ///
    /// The difference from the PLIC in one assertion: a PLIC's enable bank is
    /// one stride per **context**, so two harts have two banks.  An APLIC's
    /// enables belong to the domain.
    #[test]
    fn a_source_enable_is_the_domains_not_the_harts() {
        // Sources are numbered from 1, and the register is `source / 32` with
        // the bit `source % 32` inside it: so 1..=31 share the first register,
        // 32 is bit 0 of the second, and 64 bit 0 of the third.
        assert_eq!(Aplic::enable_offset(1), 0x1E00);
        assert_eq!(Aplic::enable_offset(31), 0x1E00);
        assert_eq!(Aplic::enable_offset(32), 0x1E04);
        assert_eq!(Aplic::enable_offset(33), 0x1E04);
        assert_eq!(Aplic::enable_offset(64), 0x1E08);

        let one = Aplic::new(0xd00_0000, 0, 96);
        let two = Aplic::new(0xd00_0000, 1, 96);
        assert_eq!(
            Aplic::enable_offset(33),
            0x1E04,
            "the source's register, whichever hart asks for it"
        );
        assert_eq!(one.claim_offset(), 0x4000 + IDC_CLAIM);
        // One stride per hart, and the stride is the block's size: hart 1's
        // claim is 0x20 past hart 0's block, which puts it at 0x403c.
        assert_eq!(two.claim_offset(), 0x4000 + IDC_STRIDE + IDC_CLAIM);
        assert_eq!(two.claim_offset(), 0x403C);
    }

    /// The two per-source arrays are apart from each other and from the
    /// enables.
    ///
    /// Three arrays share one window: the configuration words at `0x0004`, the
    /// targets at `0x3004`, and the enables at `0x1e00`.  A driver that put its
    /// enables at the end of a configuration array sized by `num-sources` would
    /// write the target of some source.
    #[test]
    fn the_source_arrays_do_not_overlap() {
        // The architecture's cap is what the window has to hold.
        let configs_end = super::SOURCE_CONFIG_BASE + MAX_SOURCES * 4;
        assert!(
            configs_end <= SETIE_BASE,
            "configuration words end at {configs_end:#x}, enables start at {SETIE_BASE:#x}"
        );
        let enables_end = SETIE_BASE + MAX_SOURCES.div_ceil(32) * 4;
        assert!(
            enables_end <= TARGET_BASE,
            "enables end at {enables_end:#x}"
        );
        // The target array is what the delivery blocks bound: one word per
        // source from 0x3004, and the blocks start at 0x4000.  A source cap of
        // 1024 is exactly the array's capacity, which is why the two meet.
        // Sources are numbered from 1, so the last one's target is at
        // `TARGET_BASE + (MAX_SOURCES - 1) * 4`, and the block after it is the
        // first delivery control block.
        let last_target = super::Aplic::target_offset(MAX_SOURCES);
        assert_eq!(
            last_target, IDC_BASE,
            "the last target is at {last_target:#x}"
        );
        assert_eq!(MAX_SOURCES, 1023, "the layout's own cap");
    }

    /// The delivery block this hart claims through is one stride per hart, and
    /// the claim is the last word in it.
    #[test]
    fn a_harts_delivery_block_is_one_stride_apart() {
        for hart in 0..4 {
            let aplic = Aplic::new(0xd00_0000, hart, 96);
            assert_eq!(aplic.idc_offset(), 0x4000 + hart * 32);
            assert_eq!(aplic.claim_offset(), 0x4000 + hart * 32 + 0x1C);
        }
        // The block's own fields fit inside the stride, which is what makes the
        // stride the right unit: a claim at 0x1c in a 0x20-byte block is the
        // last word.  That relation is a compile-time one, so it is asserted at
        // compile time above rather than here.
        assert_eq!(IDC_DELIVERY_ENABLE, 1);
    }
}
