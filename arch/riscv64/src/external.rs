//! arch/riscv64/src/external.rs
//!
//! The external interrupt controller, as the trap path asks about it.
//!
//! ## Two controllers, one claim
//!
//! This machine can describe either a **PLIC** or the AIA's **APLIC**, and the
//! trap path's job is the same for both: claim the source that arrived, run the
//! handler, complete it.  The registers differ — a PLIC's enables are per
//! context and its target is a bitmask of harts, an APLIC's are per domain and
//! its target is a word per source — which is why the two drivers are separate
//! modules, and why this is the one place the trap path names either.
//!
//! An enum rather than a trait object: the set is closed, the machine is known
//! at boot, and a `dyn` here would put a vtable lookup in the trap path for a
//! choice that was made once.

/// The controller the boot enabled.
///
/// `Copy` because the trap path reads it out of a static on every external
/// interrupt, and neither variant holds more than four words.
#[derive(Debug, Clone, Copy)]
pub enum External {
    /// The platform's level controller, on a machine that describes one.
    Plic(crate::plic::Plic),
    /// The AIA's platform controller, in direct delivery mode.
    Aplic(crate::aplic::Aplic),
}

impl External {
    /// The window this controller occupies.
    pub const fn base(&self) -> usize {
        match self {
            External::Plic(plic) => plic.base(),
            External::Aplic(aplic) => aplic.base(),
        }
    }

    /// The context or domain this hart claims through.
    ///
    /// A PLIC calls it a context and an APLIC a domain; both are "which of the
    /// controller's per-hart consumers is this hart", which is what a boot line
    /// names so a reader can compare it against the tree.
    pub const fn consumer(&self) -> usize {
        match self {
            External::Plic(plic) => plic.context(),
            External::Aplic(aplic) => aplic.hart(),
        }
    }

    /// How many sources the machine declared.
    pub const fn sources(&self) -> usize {
        match self {
            External::Plic(plic) => plic.sources(),
            External::Aplic(aplic) => aplic.sources(),
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
        }
    }

    /// Finish source `number`, letting the controller deliver it again.
    ///
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
        }
    }
}
