//! abi/src/system.rs
//!
//! The wire shape of what a program may ask the kernel about itself: which
//! build this is, and what the machine has been doing.
//!
//! ## Why two records and not one
//!
//! They answer different questions and change at different rates.  [`AbiInfo`]
//! is the **contract**: a version and a syscall count that only move when the
//! ABI does, and a program reads it once to decide whether the calls it wants
//! exist.  [`SystemInfo`] is the **state**: counters that are different on
//! every call and mean nothing to a program that is not reporting them.  One
//! record holding both would make a caller that wanted a version number depend
//! on a page of scheduler counters, and every added counter a change to what
//! the first caller reads.
//!
//! ## What is deliberately not here
//!
//! The old tree's `SystemInfo` had ten selectors and answered a different
//! struct per selector, which is a tagged union a caller has to match on and a
//! kernel has to keep every arm of.  This build has one selector and one
//! record: the fields below are what this kernel can answer for real, and a
//! selector it does not have is refused rather than approximated.

use core::mem::offset_of;
use core::mem::size_of;

/// The version of the interface these numbers and records describe.
///
/// It moves when an existing number's meaning does, not when a number is
/// added: a program that checks this and sees a version it knows can rely on
/// every call that version served, and a new number is found by its own
/// presence rather than by a bumped version.  The frozen range is what makes
/// that safe, a number at or below 120 cannot be reassigned, so nothing a
/// program already calls can become something else under it.
pub const ABI_VERSION: usize = 1;

/// The one `SystemInfo` selector this build serves.
pub const SYSTEM_INFO_SCHEDULER: usize = 0;

/// The selectors this build understands, and therefore the ids a caller may
/// name.
pub const SYSTEM_INFO_KNOWN: usize = SYSTEM_INFO_SCHEDULER;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// What this build's interface is, as `AbiInfo` answers it.
///
/// `syscall_count` is the ABI's own [`crate::number::PUBLIC_SYSCALL_COUNT`]:
/// the one number both sides agree on before the first call, and the one a
/// program compares against the highest number it means to use.
pub struct AbiInfo {
    pub version: usize,
    /// The highest number this build has a slot for, plus one.
    pub syscall_count: usize,
    /// The frozen boundary: every number below it keeps its meaning for ever.
    pub frozen_count: usize,
}

impl AbiInfo {
    pub const fn new(version: usize, syscall_count: usize, frozen_count: usize) -> Self {
        Self {
            version,
            syscall_count,
            frozen_count,
        }
    }
}

pub const ABI_INFO_SIZE: usize = size_of::<AbiInfo>();
pub const ABI_INFO_VERSION_OFFSET: usize = offset_of!(AbiInfo, version);
pub const ABI_INFO_SYSCALL_COUNT_OFFSET: usize = offset_of!(AbiInfo, syscall_count);
pub const ABI_INFO_FROZEN_COUNT_OFFSET: usize = offset_of!(AbiInfo, frozen_count);

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// What the scheduler has been doing, as `SystemInfo` answers it.
///
/// Counters, not rates: a program that wants a rate takes two readings and
/// subtracts, which is the only arithmetic that does not need the kernel to
/// remember when the previous caller asked.
pub struct SystemInfo {
    /// How many context switches the scheduler has made.
    pub switches: usize,
    /// How many tasks have ended, by any status.
    pub exited: usize,
    /// How many tasks are installed and neither runnable nor asleep.
    pub blocked: usize,
    /// How many tasks are waiting for a deadline.
    pub sleeping: usize,
    /// How many signals were delivered to a program's own handler.
    pub delivered_signals: usize,
    /// How many CPUs the boot started.
    pub online_cpus: usize,
    /// How many frames the frame pool manages.
    pub managed_frames: usize,
    /// How many of those it can still hand out.
    pub free_frames: usize,
}

impl SystemInfo {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        switches: usize,
        exited: usize,
        blocked: usize,
        sleeping: usize,
        delivered_signals: usize,
        online_cpus: usize,
        managed_frames: usize,
        free_frames: usize,
    ) -> Self {
        Self {
            switches,
            exited,
            blocked,
            sleeping,
            delivered_signals,
            online_cpus,
            managed_frames,
            free_frames,
        }
    }
}

pub const SYSTEM_INFO_SIZE: usize = size_of::<SystemInfo>();
pub const SYSTEM_INFO_SWITCHES_OFFSET: usize = offset_of!(SystemInfo, switches);
pub const SYSTEM_INFO_EXITED_OFFSET: usize = offset_of!(SystemInfo, exited);
pub const SYSTEM_INFO_BLOCKED_OFFSET: usize = offset_of!(SystemInfo, blocked);
pub const SYSTEM_INFO_SLEEPING_OFFSET: usize = offset_of!(SystemInfo, sleeping);
pub const SYSTEM_INFO_DELIVERED_SIGNALS_OFFSET: usize = offset_of!(SystemInfo, delivered_signals);
pub const SYSTEM_INFO_ONLINE_CPUS_OFFSET: usize = offset_of!(SystemInfo, online_cpus);
pub const SYSTEM_INFO_MANAGED_FRAMES_OFFSET: usize = offset_of!(SystemInfo, managed_frames);
pub const SYSTEM_INFO_FREE_FRAMES_OFFSET: usize = offset_of!(SystemInfo, free_frames);

#[cfg(test)]
mod tests {
    use super::ABI_INFO_FROZEN_COUNT_OFFSET;
    use super::ABI_INFO_SIZE;
    use super::ABI_INFO_SYSCALL_COUNT_OFFSET;
    use super::ABI_INFO_VERSION_OFFSET;
    use super::ABI_VERSION;
    use super::SYSTEM_INFO_BLOCKED_OFFSET;
    use super::SYSTEM_INFO_DELIVERED_SIGNALS_OFFSET;
    use super::SYSTEM_INFO_EXITED_OFFSET;
    use super::SYSTEM_INFO_FREE_FRAMES_OFFSET;
    use super::SYSTEM_INFO_KNOWN;
    use super::SYSTEM_INFO_MANAGED_FRAMES_OFFSET;
    use super::SYSTEM_INFO_ONLINE_CPUS_OFFSET;
    use super::SYSTEM_INFO_SCHEDULER;
    use super::SYSTEM_INFO_SIZE;
    use super::SYSTEM_INFO_SLEEPING_OFFSET;
    use super::SYSTEM_INFO_SWITCHES_OFFSET;
    use super::SystemInfo;

    /// The records are laid out as a program reads them, and the selector is
    /// the wire value.
    #[test]
    fn the_records_are_the_wire_layout() {
        assert_eq!(ABI_VERSION, 1);
        assert_eq!(SYSTEM_INFO_SCHEDULER, 0);
        assert_eq!(SYSTEM_INFO_KNOWN, SYSTEM_INFO_SCHEDULER);

        assert_eq!(ABI_INFO_SIZE, 24);
        assert_eq!(ABI_INFO_VERSION_OFFSET, 0);
        assert_eq!(ABI_INFO_SYSCALL_COUNT_OFFSET, 8);
        assert_eq!(ABI_INFO_FROZEN_COUNT_OFFSET, 16);

        assert_eq!(SYSTEM_INFO_SIZE, 64);
        assert_eq!(SYSTEM_INFO_SWITCHES_OFFSET, 0);
        assert_eq!(SYSTEM_INFO_EXITED_OFFSET, 8);
        assert_eq!(SYSTEM_INFO_BLOCKED_OFFSET, 16);
        assert_eq!(SYSTEM_INFO_SLEEPING_OFFSET, 24);
        assert_eq!(SYSTEM_INFO_DELIVERED_SIGNALS_OFFSET, 32);
        assert_eq!(SYSTEM_INFO_ONLINE_CPUS_OFFSET, 40);
        assert_eq!(SYSTEM_INFO_MANAGED_FRAMES_OFFSET, 48);
        assert_eq!(SYSTEM_INFO_FREE_FRAMES_OFFSET, 56);
    }

    /// Every field arrives in the slot it was put in.
    ///
    /// An eight-field record built with eight different numbers is the one
    /// shape where a transposed pair of fields still compiles; comparing the
    /// whole record against the constructor is what catches it.
    #[test]
    fn a_system_info_keeps_every_field() {
        let info = SystemInfo::new(1, 2, 3, 4, 5, 6, 7, 8);
        assert_eq!(info.switches, 1);
        assert_eq!(info.exited, 2);
        assert_eq!(info.blocked, 3);
        assert_eq!(info.sleeping, 4);
        assert_eq!(info.delivered_signals, 5);
        assert_eq!(info.online_cpus, 6);
        assert_eq!(info.managed_frames, 7);
        assert_eq!(info.free_frames, 8);
    }
}
