//! kernel/src/per_cpu.rs
//!
//! Per-CPU state: which CPUs exist, which is running now, and what each one has
//! seen.
//!
//! ## Why a trap has to ask which CPU it is on
//!
//! Every per-CPU decision starts here: which record counts this tick, which
//! slot the scheduler's `running` array is indexed by, which kernel stack a
//! trap frame belongs to, which line buffer a console write appends to.  A
//! single shared answer would make two CPUs write one record, and the failure
//! that produces, a task resumed with another CPU's context, is the kind of
//! corruption a log shows as a fault far from its cause.
//!
//! This module's records are atomics, so it is the one part of the kernel that
//! is safe to touch from any CPU without a lock.  Everything built on it is
//! not: the scheduler takes a lock, the page tables take one, and the console
//! takes one.
//!
//! ## How a CPU knows its slot
//!
//! The machine answers, in a register.  On riscv64 that is `tp`, which the trap
//! entry computes from the kernel stack it just switched to — a program's `tp`
//! is the program's own and is restored from the frame, so the kernel cannot
//! read it for its own identity.  On the machines that start no second CPU the
//! answer is always slot zero.
//!
//! A kernel constant would be a second opinion about a value the machine
//! already has, and the first version's constant is why this file says so: it
//! put the slot in `tp` at boot, a program zeroed the register, and the second
//! CPU reported itself as the first.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

/// How many CPUs a machine may start past the boot one.
///
/// Four is `arch`'s `smp::MAX_SECONDARY_HARTS`, the constant the entry
/// assembly's stack reservation is sized from.  It is written here as well
/// because the two crates cannot see each other's constants, and the pair is
/// kept in step by each naming the other rather than by a number that looks the
/// same in two files for no stated reason.
pub const MAX_SECONDARY_CPUS: usize = 4;

/// The most CPUs this kernel describes: the boot CPU and the ones it may start.
///
/// Five, not four, and the difference is a slot the fourth secondary would
/// otherwise share with the boot CPU: the boot is slot zero and a started CPU
/// is one past its index among the started ones, so four secondaries need
/// slots 1..=4.
pub const MAX_CPUS: usize = 1 + MAX_SECONDARY_CPUS;

/// One CPU, as the boot and a trap both see it.
pub struct Cpu {
    /// The machine's own id for this CPU, a hart, a core, a processor.
    ///
    /// `usize::MAX` before the boot fills it, so an unstarted slot cannot be
    /// mistaken for a machine whose CPU zero is the one that answered.
    id: AtomicUsize,
    /// Whether the CPU is running this kernel.
    online: AtomicBool,
    /// Timer interrupts this CPU has taken.
    ticks: AtomicUsize,
    /// Inter-processor interrupts this CPU has taken.
    ipis: AtomicUsize,
    /// Whether this CPU is the boot CPU, which owns the scheduler.
    boot: AtomicBool,
}

impl Cpu {
    const fn new() -> Cpu {
        Cpu {
            id: AtomicUsize::new(usize::MAX),
            online: AtomicBool::new(false),
            ticks: AtomicUsize::new(0),
            ipis: AtomicUsize::new(0),
            boot: AtomicBool::new(false),
        }
    }

    /// The machine's id for this CPU.
    pub fn id(&self) -> usize {
        self.id.load(Ordering::Acquire)
    }

    /// Whether this CPU is running this kernel.
    pub fn online(&self) -> bool {
        self.online.load(Ordering::Acquire)
    }

    /// How many timer interrupts this CPU has taken.
    pub fn ticks(&self) -> usize {
        self.ticks.load(Ordering::Acquire)
    }

    /// How many inter-processor interrupts this CPU has taken.
    pub fn ipis(&self) -> usize {
        self.ipis.load(Ordering::Acquire)
    }

    /// Whether this CPU is the one that owns the scheduler.
    pub fn is_boot_cpu(&self) -> bool {
        self.boot.load(Ordering::Acquire)
    }
}

/// Every slot, live for the whole boot.
static CPUS: [Cpu; MAX_CPUS] = [const { Cpu::new() }; MAX_CPUS];

/// The CPU this code is running on.
fn cpu(slot: usize) -> &'static Cpu {
    &CPUS[slot.min(MAX_CPUS - 1)]
}

/// The boot CPU's slot.
pub const BOOT_SLOT: usize = 0;

/// Record a CPU the machine reports.
///
/// Called by the boot for its own CPU and by each started CPU for itself, once.
pub fn register(slot: usize, id: usize, boot: bool) {
    let cpu = cpu(slot);
    cpu.id.store(id, Ordering::Release);
    cpu.boot.store(boot, Ordering::Release);
    cpu.online.store(true, Ordering::Release);
}

/// Count a timer interrupt on the CPU that took it.
pub fn count_tick(slot: usize) {
    cpu(slot).ticks.fetch_add(1, Ordering::Release);
}

/// Count an inter-processor interrupt on the CPU that took it.
pub fn count_ipi(slot: usize) {
    cpu(slot).ipis.fetch_add(1, Ordering::Release);
}

/// The CPU this code runs on, as the machine reports it.
///
/// Slot zero on a machine that starts no second CPU, and the machine's own
/// answer where it has one: on riscv64 the `tp` register, which the entry
/// assembly writes before anything Rust runs.
pub fn current_slot() -> usize {
    #[cfg(target_os = "none")]
    {
        arch::current_cpu_slot()
    }
    #[cfg(not(target_os = "none"))]
    {
        0
    }
}

/// Whether this CPU owns the scheduler.
pub fn on_boot_cpu() -> bool {
    cpu(current_slot()).is_boot_cpu()
}

/// The CPUs the boot started, including its own.
pub fn online_count() -> usize {
    CPUS.iter().filter(|cpu| cpu.online()).count()
}

/// One CPU's record, for a boot line.
pub fn slot(index: usize) -> &'static Cpu {
    cpu(index)
}

#[cfg(test)]
mod tests {
    /// A slot that was never registered is not online, and its id is a value no
    /// machine reports, so "nothing recorded" cannot read as "CPU zero".
    #[test]
    fn an_unregistered_slot_is_not_online() {
        // The array is process-wide, and other tests in this crate do not touch
        // it, so the slot past anything a test registers is free.
        let cpu = super::slot(super::MAX_CPUS - 1);
        if !cpu.online() {
            assert_eq!(cpu.id(), usize::MAX);
            assert_eq!(cpu.ticks(), 0);
        }
    }

    /// A host has one CPU and it is slot zero: a host build has no second CPU
    /// to be on, and a slot that varied would make a test that asks which CPU
    /// it runs on non-deterministic.
    #[test]
    fn a_host_is_slot_zero() {
        assert_eq!(super::current_slot(), 0);
    }
}
