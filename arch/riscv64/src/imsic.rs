//! arch/riscv64/src/imsic.rs
//!
//! The AIA's IMSIC: the per-hart controller an **MSI** arrives at.
//!
//! ## What it is
//!
//! An IMSIC has one **interrupt file** per hart.  A file is two things at once:
//!
//! | part | how it is reached |
//! |---|---|
//! | the MSI page | a plain 4-byte store of an identity marks that interrupt pending |
//! | the register file | **indirectly**, through the supervisor CSRs `siselect`/`sireg` |
//!
//! That split is the whole design: a device needs only an address and a word,
//! so its MSI-X table entry is `(file address, identity)` and nothing else,
//! while the hart's own settings (`eidelivery`, `eithreshold`, `eie`) live in
//! registers a device cannot reach.
//!
//! ## Why this machine is the only one that can touch it
//!
//! `siselect` and `sireg` exist only where the machine implements the AIA's
//! supervisor half.  On a machine without it they are **illegal
//! instructions**, not reads that return zero.  Measured on this tree's QEMU:
//!
//! | machine | `csrr` of `sireg` |
//! |---|---|
//! | `virt` (PLIC) | `unhandled exception 2 (illegal instruction)`, `address 0x15051073` |
//! | `virt,aia=aplic` | the same illegal instruction |
//! | `virt,aia=aplic-imsic` | reads; `eidelivery` and `eithreshold` both 0 |
//!
//! So **every** function here is gated on the device tree having named a
//! supervisor IMSIC, and the gate is checked at the boot rather than assumed:
//! one unconditional `csrr` is an illegal instruction that stops the machine.
//!
//! ## The claim
//!
//! `stopei` is a read-and-claim in one instruction: `csrrw stopei, zero`
//! answers the identity on top and claims it.  The value is **packed** —
//! identity in bits 16.., priority in bits 0..8 — exactly as the APLIC's
//! `claimi` is, and a driver that read it as a number gets a source it cannot
//! match.  That defect cost this tree a boot on the APLIC (`unhandled external
//! interrupt 655361`), and this file's tests pin the packing so it cannot cost
//! another.

/// The select number of `eidelivery`: the file's delivery switch.
pub const EIDELIVERY: u64 = 0x70;
/// The select number of `eithreshold`: priorities below it are not delivered.
pub const EITHRESHOLD: u64 = 0x72;
/// The first select number of the `eie` enable words.
pub const EIE0: u64 = 0xC0;
/// The first select number of the `eip` pending words, which are read-only.
pub const EIP0: u64 = 0x80;

/// `eidelivery` bit 0: this file delivers interrupts to the hart.
pub const EIDELIVERY_ENABLE: u64 = 1;
/// A threshold of zero delivers every priority.
pub const EITHRESHOLD_ACCEPT_ALL: u64 = 0;

/// The `siselect` step between consecutive 64-bit register words.
///
/// The specification gives each register an even/odd pair of 32-bit slots and,
/// on RV64, the even one addresses the whole word.  So a 64-bit bitset's word
/// `n` is select `base + n * 2`, not `base + n`.
pub const SELECT_STRIDE: u64 = 2;

/// The identity OpenSBI's S-mode inter-processor interrupt arrives as.
///
/// The firmware enables this identity in every hart's supervisor file at hart
/// start — measured: `eie` read `0x2` before this kernel enabled anything but
/// the self-test's own identity — and delivers an IPI by writing it into the
/// target hart's file.  A kernel that mapped a device onto identity 1 would be
/// mapped onto the machine's IPI, and the two would be counted as each other.
///
/// The kernel's own IPI send goes through the firmware's call, so this is a
/// fact about the machine's firmware and not a choice this tree made.
pub const IPI_IDENTITY: u32 = 1;

/// The shift and mask `stopei` packs an identity into.
pub const CLAIM_IDENTITY_SHIFT: u32 = 16;
pub const CLAIM_IDENTITY_MASK: u64 = 0x3FF;

/// How many identities one IMSIC file holds on the machines this tree boots.
///
/// The device tree says (`riscv,num-ids`, 256 on QEMU's `virt`); this is the
/// architecture's ceiling, the point past which the bitset select numbers leave
/// the register file.
pub const MAX_IDENTITIES: u32 = 2047;

/// The select number of the word holding identity `irq` in the register whose
/// first word is `base`.
pub const fn select_for(base: u64, irq: u32) -> u64 {
    base + (irq as u64 / 64) * SELECT_STRIDE
}

/// The bit identity `irq` uses inside its word.
pub const fn identity_bit(irq: u32) -> u64 {
    1 << (irq % 64)
}

/// The identity a `stopei`/`claimi` word packs, or `None` when there was none.
pub const fn claimed_identity(claim: u64) -> Option<u32> {
    let identity = ((claim >> CLAIM_IDENTITY_SHIFT) & CLAIM_IDENTITY_MASK) as u32;
    if identity == 0 { None } else { Some(identity) }
}

/// An IMSIC, as the boot found it.
///
/// One value for the whole group: every hart's file is at `base + index * 2 ^
/// log2_stride`, and the CSRs below reach **this hart's own** file without
/// naming it, which is why the arithmetic here is only for building the address
/// a device's message must name.
#[derive(Debug, Clone, Copy)]
pub struct Imsic {
    /// The window the tree's `reg` named — hart index zero's file.
    base: usize,
    /// The distance between consecutive harts' files.
    stride: usize,
    /// How many identities each file holds, from `riscv,num-ids`.
    identities: u32,
}

impl Imsic {
    /// The group at `base`, with `stride` between harts' files and `identities`
    /// per file.
    pub const fn new(base: usize, stride: usize, identities: u32) -> Imsic {
        Imsic {
            base,
            stride,
            identities,
        }
    }

    /// The window this IMSIC occupies.
    pub const fn base(&self) -> usize {
        self.base
    }

    /// The distance between consecutive harts' files.
    pub const fn stride(&self) -> usize {
        self.stride
    }

    /// How many identities each file holds.
    pub const fn identities(&self) -> u32 {
        if self.identities < MAX_IDENTITIES {
            self.identities
        } else {
            MAX_IDENTITIES
        }
    }

    /// The **MSI page** of hart `index`: where a device's message is written.
    ///
    /// This is the one address a device needs.  It is the file's first page —
    /// the register file is reached through CSRs, not through memory — so a
    /// message is four bytes at exactly this address.
    pub const fn msi_page(&self, index: usize) -> usize {
        self.base + index * self.stride
    }

    /// Whether `identity` is one this file can hold.
    pub const fn holds(&self, identity: u32) -> bool {
        identity > 0 && identity < self.identities()
    }
}

/// The IMSIC the boot brought up, behind the static the trap path reads.
///
/// The same shape the APLIC's controller static is: written once, before any
/// line can arrive, read from the trap path where there is no context to be
/// handed one.  `None` on a machine whose tree names no IMSIC, which is the
/// state the CSR pair's legality rides on — see this module's table.
#[cfg(target_os = "none")]
static CONTROLLER: cell::SyncUnsafeCell<Option<Imsic>> = cell::SyncUnsafeCell::new(None);

/// Record the IMSIC the boot enabled.
///
/// # Safety
///
/// Called once, from the boot, before any message can arrive.
#[cfg(target_os = "none")]
pub unsafe fn set_controller(imsic: Imsic) {
    // SAFETY: the caller promises this is the only write, and that it happens
    // before any device can send a message.
    unsafe { *CONTROLLER.get() = Some(imsic) };
}

/// The IMSIC the boot enabled, if its tree named one.
///
/// `None` is the answer that keeps the CSR pair untouched: a machine without an
/// IMSIC implements no `siselect`/`sireg`, and reading one there is an illegal
/// instruction.
#[cfg(target_os = "none")]
pub fn controller() -> Option<Imsic> {
    // SAFETY: written once by the boot before any message can arrive.
    unsafe { *CONTROLLER.get() }
}

/// Where a device's message must be written: the **boot hart's** MSI page.
///
/// `None` on a machine with no IMSIC, which is also the answer that keeps the
/// CSR pair untouched.  The boot hart is the right file for this kernel's
/// devices because the code that submits to them runs on the boot CPU, and a
/// message addressed to another hart's file is one delivered to a hart whose
/// trap path has no reason to expect it.
///
/// The identity is the caller's to choose and to enable; this answers only the
/// address.
#[cfg(target_os = "none")]
pub fn message_page() -> Option<usize> {
    let imsic = controller()?;
    // The file index is the tree's pairing, not the hart id: see
    // `boot::imsic_file_index_for_hart`, whose failure here is a hart with no
    // file, which cannot receive a message at all.
    let index = crate::boot::imsic_file_index_for_hart(crate::smp::boot_hart())?;
    Some(imsic.msi_page(index))
}

/// Allow `identity` to be delivered to the boot hart's file.
///
/// An identity the file does not have enabled is one whose messages are held
/// pending for ever — the device did its part, the file kept them — which looks
/// exactly like a device that never sent anything.  So the enable is part of
/// wiring a device's message path, not an optimisation.
///
/// `false` when there is no IMSIC, or when the identity is not one the file
/// holds.
///
/// # Safety
///
/// The tree named an IMSIC; this is reachable only through
/// [`message_page`](Self::message_page) having answered.
#[cfg(target_os = "none")]
pub unsafe fn enable_message_identity(identity: u32) -> bool {
    let Some(imsic) = controller() else {
        return false;
    };
    if !imsic.holds(identity) {
        return false;
    }
    // SAFETY: the tree named an IMSIC, so the CSR pair exists.
    unsafe { imsic.enable_identity(identity) };
    true
}

#[cfg(target_os = "none")]
mod registers {
    use super::EIDELIVERY;
    use super::EIDELIVERY_ENABLE;
    use super::EIE0;
    use super::EITHRESHOLD;
    use super::EITHRESHOLD_ACCEPT_ALL;
    use super::Imsic;
    use super::claimed_identity;
    use super::identity_bit;
    use super::select_for;

    /// Select a register, then read it.
    ///
    /// # Safety
    ///
    /// The machine must implement the AIA's supervisor half.  On one that does
    /// not, both instructions are illegal and stop the machine — see this
    /// module's own table of measurements.  Every caller of this function is
    /// reached only when the device tree named an IMSIC.
    unsafe fn read(register: u64) -> u64 {
        let value: u64;
        // SAFETY: the caller's contract is this function's.
        unsafe {
            core::arch::asm!(
                "csrw 0x150, {}",
                in(reg) register,
                options(nostack)
            );
            core::arch::asm!("csrr {}, 0x151", out(reg) value, options(nostack));
        }
        value
    }

    /// Select a register, then write it.
    ///
    /// # Safety
    ///
    /// As [`read`].
    unsafe fn write(register: u64, value: u64) {
        // SAFETY: the caller's contract is this function's.
        unsafe {
            core::arch::asm!(
                "csrw 0x150, {}",
                in(reg) register,
                options(nostack)
            );
            core::arch::asm!("csrw 0x151, {}", in(reg) value, options(nostack));
        }
    }

    /// Claim the highest-priority pending identity, if any.
    ///
    /// `csrrw` with zero is the claim: reading `stopei` answers the identity
    /// and writing zero claims it, in one instruction, which is what a message
    /// needs — a read that did not claim would leave the identity pending and
    /// the interrupt would arrive again.
    ///
    /// # Safety
    ///
    /// As [`read`].
    unsafe fn claim_top() -> Option<u32> {
        let claimed: u64;
        // SAFETY: the caller's contract is this function's.
        unsafe {
            core::arch::asm!(
                "csrrw {}, 0x15c, zero",
                out(reg) claimed,
                options(nostack)
            );
        }
        claimed_identity(claimed)
    }

    impl Imsic {
        /// Turn this hart's file on: delivery enabled, every priority accepted.
        ///
        /// This is the whole of what a hart must do to receive an MSI.  A file
        /// left with `eidelivery` clear holds messages — a device's write still
        /// sets the pending bit — and delivers none of them, which looks
        /// exactly like a device that never sent one.
        ///
        /// # Safety
        ///
        /// Called once per hart, after the device tree named an IMSIC.
        pub unsafe fn enable_this_hart(&self) {
            // SAFETY: the caller's contract is this function's.
            unsafe {
                write(EITHRESHOLD, EITHRESHOLD_ACCEPT_ALL);
                write(EIDELIVERY, EIDELIVERY_ENABLE);
            }
        }

        /// Allow `identity` to be delivered to this hart.
        ///
        /// # Safety
        ///
        /// As [`enable_this_hart`](Self::enable_this_hart).
        pub unsafe fn enable_identity(&self, identity: u32) {
            let select = select_for(EIE0, identity);
            let bit = identity_bit(identity);
            // SAFETY: the caller's contract is this function's, and
            // `csrrs` is the correct form: it sets one bit and leaves every
            // other identity's enable alone.
            unsafe {
                core::arch::asm!("csrw 0x150, {}", in(reg) select, options(nostack));
                core::arch::asm!(
                    "csrrs zero, 0x151, {}",
                    in(reg) bit,
                    options(nostack)
                );
            }
        }

        /// Claim the identity this hart's file has on top, if any.
        ///
        /// # Safety
        ///
        /// As [`enable_this_hart`](Self::enable_this_hart).
        pub unsafe fn claim(&self) -> Option<u32> {
            // SAFETY: the caller's contract is this function's.
            unsafe { claim_top() }
        }

        /// Whether `identity` is pending in this hart's file.
        ///
        /// # Safety
        ///
        /// As [`enable_this_hart`](Self::enable_this_hart).
        pub unsafe fn is_pending(&self, identity: u32) -> bool {
            let select = select_for(super::EIP0, identity);
            // SAFETY: the caller's contract is this function's.
            let word = unsafe { read(select) };
            word & identity_bit(identity) != 0
        }

        /// Whether this hart's file has delivery enabled, read back.
        ///
        /// # Safety
        ///
        /// As [`enable_this_hart`](Self::enable_this_hart).
        pub unsafe fn delivery_enabled(&self) -> bool {
            // SAFETY: the caller's contract is this function's.
            unsafe { read(EIDELIVERY) & EIDELIVERY_ENABLE != 0 }
        }

        /// Deliver `identity` to hart `index`'s file exactly as a device would.
        ///
        /// The 4-byte store is the whole message protocol: the address selects
        /// the file and the word is the identity, bare — no bit set above it.
        /// The older `setip`-style encoding put a bit above the identity and
        /// this machine reads the word as the identity alone, so a message
        /// carrying `(1 << 31) | identity` is dropped as out of range.
        ///
        /// This is what a boot uses to walk the path with no device attached,
        /// and what a driver's MSI-X table entry performs at runtime.
        ///
        /// # Safety
        ///
        /// This hart's MSI page must be mapped, and the identity must be one
        /// the file holds.
        pub unsafe fn deliver(&self, index: usize, identity: u32) -> bool {
            if !self.holds(identity) {
                return false;
            }
            // SAFETY: the caller promises the page is mapped; the write is the
            // message, and the address is this group's own arithmetic.
            unsafe {
                core::ptr::write_volatile(self.msi_page(index) as *mut u32, identity);
            }
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CLAIM_IDENTITY_SHIFT;
    use super::EIE0;
    use super::EIP0;
    use super::Imsic;
    use super::MAX_IDENTITIES;
    use super::claimed_identity;
    use super::identity_bit;
    use super::select_for;

    /// `stopei`'s answer is packed, and reading it as a number is the defect
    /// this test exists to prevent.
    ///
    /// The identity sits sixteen bits up.  Measured on the APLIC, whose claim
    /// word has the same packing: a driver that used the word as a source index
    /// printed `unhandled external interrupt 655361` — `0x000A_0001`, identity
    /// 10 with priority 1 — for every interrupt the boot took.
    #[test]
    fn a_claim_word_packs_the_identity_above_the_priority() {
        // Identity 10 at priority 1 is what a real claim looks like.
        assert_eq!(claimed_identity(0x000A_0001), Some(10));
        assert_eq!(claimed_identity(0x000A_0000), Some(10));
        assert_eq!(claimed_identity(0x00FF_00FF), Some(0xFF));
        // Zero is "nothing was pending", not identity zero.
        assert_eq!(claimed_identity(0), None);
        assert_eq!(claimed_identity(0x0000_0001), None, "a bare priority");
        assert_eq!(CLAIM_IDENTITY_SHIFT, 16);
    }

    /// The bitset word for an identity is `base + irq / 64 * 2`, not `+ irq /
    /// 64`.
    ///
    /// The specification gives each 64-bit register an even/odd pair of 32-bit
    /// select numbers, and on RV64 the even one addresses the whole word.  A
    /// driver that stepped by one would write a different register's word —
    /// which on a file with 256 identities is the difference between enabling
    /// identity 64 and enabling nothing.
    #[test]
    fn a_bitset_word_steps_by_two_per_sixty_four_identities() {
        assert_eq!(select_for(EIE0, 0), 0xC0);
        assert_eq!(select_for(EIE0, 63), 0xC0);
        assert_eq!(select_for(EIE0, 64), 0xC2, "the next word, two selects on");
        assert_eq!(select_for(EIE0, 128), 0xC4);
        // The pending array is the same shape, a different base.
        assert_eq!(select_for(EIP0, 64), 0x82);
    }

    /// The bit inside the word is the identity modulo sixty-four.
    #[test]
    fn an_identity_bit_is_the_identity_modulo_sixty_four() {
        assert_eq!(identity_bit(0), 1);
        assert_eq!(identity_bit(1), 2);
        assert_eq!(identity_bit(63), 1 << 63);
        assert_eq!(identity_bit(64), 1, "the next word's bit zero");
    }

    /// A file's MSI pages are one stride apart, and the stride is not the
    /// window's size.
    ///
    /// The device tree's `reg` says `0x2000` — one file's own two pages — while
    /// consecutive harts' files are `0x4000` apart on this machine.  A driver
    /// that stepped by the `reg` size would address the second hart's file for
    /// hart one, and every message would arrive at a hart with no handler.
    #[test]
    fn a_harts_msi_page_is_one_stride_past_the_last() {
        let imsic = Imsic::new(0x2800_0000, 0x4000, 256);
        assert_eq!(imsic.msi_page(0), 0x2800_0000);
        assert_eq!(imsic.msi_page(1), 0x2800_4000);
        assert_eq!(imsic.msi_page(3), 0x2800_c000);
        assert_ne!(
            imsic.msi_page(1) - imsic.msi_page(0),
            0x2000,
            "the stride is not the window's size"
        );
    }

    /// An identity the file holds is one above zero and below its count.
    ///
    /// Identity zero is not an interrupt — it is what a claim of nothing reads
    /// as — and an identity at the count is past the last the file has.
    #[test]
    fn a_file_holds_identities_above_zero_and_below_its_count() {
        let imsic = Imsic::new(0x2800_0000, 0x4000, 256);
        assert!(!imsic.holds(0), "zero is the empty claim, not an identity");
        assert!(imsic.holds(1));
        assert!(imsic.holds(255));
        assert!(!imsic.holds(256), "past the last the file has");
        assert!(!imsic.holds(MAX_IDENTITIES + 1));
    }

    /// A machine that declares more identities than the register file can
    /// address is capped rather than believed.
    ///
    /// The bitset select numbers leave the register file past the
    /// architecture's ceiling, so a tree claiming more than that would name a
    /// select the machine does not implement.
    #[test]
    fn a_count_past_the_architectures_ceiling_is_capped() {
        let imsic = Imsic::new(0, 0x4000, 100_000);
        assert_eq!(imsic.identities(), MAX_IDENTITIES);
    }
}
