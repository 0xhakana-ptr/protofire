//! arch/riscv64/src/external.rs
//!
//! The external interrupt controller, as the trap path asks about it.
//!
//! ## Two controllers, one claim
//!
//! This machine can describe either a **PLIC** or the AIA's **APLIC**, and the
//! trap path's job is the same for both: claim the source that arrived, run the
//! handler, complete it.  The registers differ, a PLIC's enables are per
//! context and its target is a bitmask of harts, an APLIC's are per domain and
//! its target is a word per source, which is why the two drivers are separate
//! modules, and why this is the one place the trap path names either.
//!
//! An enum rather than a trait object: the set is closed, the machine is known
//! at boot, and a `dyn` here would put a vtable lookup in the trap path for a
//! choice that was made once.

/// The controller the boot enabled.
///
/// `Copy` because the trap path reads it out of a static on every external
/// interrupt, and no variant holds more than four words.
///
/// The **order of the arms is the order of the machines**: an AIA machine that
/// pairs its APLIC with an IMSIC delivers every external interrupt as a message
/// into a hart's interrupt file, its APLIC is locked in message mode, so
/// nothing arrives through `claimi`, and the IMSIC is what the trap claims
/// through there.  On the other two machines a wired source arrives through the
/// controller's own claim register, and no IMSIC exists.
#[derive(Debug, Clone, Copy)]
pub enum External {
    /// The platform's level controller, on a machine that describes one.
    Plic(crate::plic::Plic),
    /// The AIA's platform controller, in direct delivery mode.
    Aplic(crate::aplic::Aplic),
    /// The AIA's per-hart message controller, whose claim is `stopei`.
    Imsic(crate::imsic::Imsic),
}

impl External {
    /// The window this controller occupies.
    pub const fn base(&self) -> usize {
        match self {
            External::Plic(plic) => plic.base(),
            External::Aplic(aplic) => aplic.base(),
            External::Imsic(imsic) => imsic.base(),
        }
    }

    /// The context, domain or hart file this hart claims through.
    ///
    /// A PLIC calls it a context and an APLIC a domain; an IMSIC's per-hart
    /// file is named by the hart's index in its group.  All three answer "which
    /// of the controller's per-hart consumers is this hart", which is what a
    /// boot line names so a reader can compare it against the tree.
    pub fn consumer(&self) -> usize {
        match self {
            External::Plic(plic) => plic.context(),
            External::Aplic(aplic) => aplic.hart(),
            External::Imsic(_) => crate::smp::boot_hart(),
        }
    }

    /// How many sources the machine declared.
    ///
    /// For the IMSIC this is the identities one file holds, which is the same
    /// question in that controller's own units: what a device may be assigned.
    pub const fn sources(&self) -> usize {
        match self {
            External::Plic(plic) => plic.sources(),
            External::Aplic(aplic) => aplic.sources(),
            External::Imsic(imsic) => imsic.identities() as usize,
        }
    }

    /// Whether one of the two can be asked to raise a line from software.
    ///
    /// Neither can: a PLIC's sources are wires and an APLIC's are too, and the
    /// self-test raises the software interrupt instead.
    pub const fn can_raise_source() -> bool {
        false
    }

    /// Claim the highest-priority pending source, or `None` when nothing is.
    ///
    /// # Safety
    ///
    /// Called from the trap path, for the external interrupt's cause, with the
    /// window mapped and this hart the one the controller delivers to.
    #[cfg(target_os = "none")]
    pub unsafe fn claim(&self) -> Option<usize> {
        match self {
            // SAFETY: the caller's contract is this function's.
            External::Plic(plic) => unsafe { plic.claim() },
            // SAFETY: as above.
            External::Aplic(aplic) => unsafe { aplic.claim() },
            // SAFETY: as above, the claim is `stopei`, which this hart's own
            // file answers.
            External::Imsic(imsic) => unsafe { imsic.claim() }.map(|identity| identity as usize),
        }
    }

    /// Finish source `number`, letting the controller deliver it again.
    ///
    /// # Safety
    ///
    /// `number` must be what [`Self::claim`] answered, and the work it named
    /// must be done.
    /// Silence source `number`, for a delivery nobody claimed a handler for.
    ///
    /// A **level** source with no driver re-delivers for as long as its wire is
    /// asserted, so a print per delivery is a print per turn of a storm.  The
    /// controller's enable bit is the one stop this kernel owns, and taking it
    /// is what turns an unhandled source into one reported line.  `false` when
    /// the controller has no such source.
    ///
    /// # Safety
    ///
    /// Called from the trap path, after `number` was claimed and the sink said
    /// nothing took it.
    #[cfg(target_os = "none")]
    pub unsafe fn silence_source(&self, number: usize) -> bool {
        match self {
            // SAFETY: the caller's contract is this function's.
            External::Plic(plic) => unsafe { plic.disable_source(number) },
            // SAFETY: as above.
            External::Aplic(aplic) => unsafe { aplic.disable_source(number) },
            // The IMSIC's claim **is** its own completion, so there is nothing
            // here to silence at the file, but on this machine the message may
            // have come **through the APLIC**, whose level wire re-sends for as
            // long as it is asserted, and the APLIC's source enable is the stop
            // this kernel owns.  So an unhandled identity is silenced at the
            // APLIC when there is one, by its own number (the identity the
            // APLIC sends is its source's, see [`aplic::Aplic::target_word`]).
            External::Imsic(_) => {
                match crate::boot::aplic() {
                    Some((base, hart, sources)) => {
                        let aplic = crate::aplic::Aplic::new(base, hart, sources);
                        // SAFETY: the caller's contract is this function's.
                        unsafe { aplic.disable_source(number) }
                    }
                    None => false,
                }
            }
        }
    }

    /// # Safety
    ///
    /// `number` must be what [`Self::claim`] answered, and the work it named
    /// must be done.
    #[cfg(target_os = "none")]
    pub unsafe fn complete(&self, number: usize) {
        match self {
            // SAFETY: the caller's contract is this function's.
            External::Plic(plic) => unsafe { plic.complete(number) },
            // SAFETY: as above.
            External::Aplic(aplic) => unsafe { aplic.complete(number) },
            // An IMSIC's claim **is** its completion: `csrrw stopei, zero`
            // answers the identity and clears its pending bit in one
            // instruction, so there is nothing to finish afterwards.  A driver
            // that wrote the identity back anyway would claim whichever
            // identity had arrived in the meantime.
            External::Imsic(_) => {}
        }
    }
}
