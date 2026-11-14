//! kernel/src/per_cpu.rs
//!
//! Per-CPU state: which CPUs exist, which is running now, and what each one has
//! seen.
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
//! The slot is the machine's own answer, in a register.  On riscv64 that is
//! `tp`, which the trap entry computes from the kernel stack it just switched
//! to: a program's `tp` is the program's own and is restored from the frame, so
//! the kernel cannot read it for its own identity.  On the machines that start
//! no second CPU the answer is always slot zero.
//!
//! A kernel constant would be a second opinion about a value the machine
//! already has, and the first version's constant is why this file says so: it
//! put the slot in `tp` at boot, a program zeroed the register, and the second
//! CPU reported itself as the first.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

/// How many CPUs a machine may start past the boot one, as `arch` answers it.
///
/// Asked rather than written.  This constant used to be a four in this file and
/// a four in `arch/riscv64/src/smp.rs`, kept in step by a comment telling the
/// next reader to keep them in step, which is the arrangement that produced
/// the bug this file's own history records: `MAX_CPUS` was four while the slots
/// a boot uses were 1..=4, so the fourth started CPU shared the boot CPU's
/// arrays.
///
/// The machine knows how many CPUs it starts; this module knows what it does
/// with them.  The count is the machine's answer, so it comes from `arch`.
pub const MAX_SECONDARY_CPUS: usize = arch::MAX_SECONDARY_HARTS;

/// The most CPUs this kernel describes: the boot CPU and the ones it may start.
///
/// One plus the cap, because the boot CPU owns slot zero and a started CPU's
/// slot is one past its index among the started ones.
///
/// The defect this replaces was two fours in two crates kept in step by a
/// comment, and a compile-time `assert!` tying them is the obvious fix.  It is
/// the wrong one here: this constant is *derived* from `arch`'s, so an
/// assertion comparing the two would reduce to `x == x` and could never fail,
/// decoration that reads like a proof.
///
/// What actually removes the defect is that there is now one number.  A machine
/// that raises `arch::MAX_SECONDARY_HARTS` moves this constant with it, every
/// array sized from `MAX_CPUS` moves too, and the state the old code could
/// reach, a slot the machine starts and this module has no room for, cannot
/// be written down.  The `panic` in `cpu` is the belt for the case derivation
/// cannot see: a slot that comes from outside, such as a register.
pub const MAX_CPUS: usize = 1 + MAX_SECONDARY_CPUS;

/// One CPU, as the boot and a trap both see it.
pub struct Cpu {
    /// The machine's own id for this CPU, a hart, a core, a processor.
    ///
    /// `usize::MAX` before the boot fills it, so an unstarted slot cannot be
    /// mistaken for a machine whose CPU zero is the one that answered.
    id: AtomicUsize,
    online: AtomicBool,
    ticks: AtomicUsize,
    ipis: AtomicUsize,
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

    pub fn id(&self) -> usize {
        self.id.load(Ordering::Acquire)
    }

    pub fn online(&self) -> bool {
        self.online.load(Ordering::Acquire)
    }

    pub fn ticks(&self) -> usize {
        self.ticks.load(Ordering::Acquire)
    }

    pub fn ipis(&self) -> usize {
        self.ipis.load(Ordering::Acquire)
    }

    pub fn is_boot_cpu(&self) -> bool {
        self.boot.load(Ordering::Acquire)
    }
}

/// Every slot, live for the whole boot.
static CPUS: [Cpu; MAX_CPUS] = [const { Cpu::new() }; MAX_CPUS];

/// One CPU's record, by slot.
///
/// A slot past the end is a panic and not a clamp.  This was
/// `slot.min(MAX_CPUS - 1)`, which turned a slot the kernel never
/// numbered into the last one, and the last one is a CPU that really exists.
/// Two CPUs then wrote one record while both believed they were distinct, and
/// the symptom is a task resumed with another CPU's context, which is the shape
/// of the defect `MAX_CPUS` was raised to fix.  A clamp is the wrong answer to
/// "this slot does not exist": the honest one is a stop at the place the slot
/// was asked for, with the number in the message.
fn cpu(slot: usize) -> &'static Cpu {
    match CPUS.get(slot) {
        Some(cpu) => cpu,
        None => panic!(
            "per_cpu: slot {} is past the {} this kernel describes",
            slot, MAX_CPUS
        ),
    }
}

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

pub fn count_tick(slot: usize) {
    cpu(slot).ticks.fetch_add(1, Ordering::Release);
}

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

pub fn on_boot_cpu() -> bool {
    cpu(current_slot()).is_boot_cpu()
}

/// The CPUs that have said they will not touch a user space again.
///
/// The address spaces are released once, at the end of a boot, and the argument
/// that makes it safe is "no CPU is inside a program and none will enter one".
/// `FINISHED` alone does not make that true: a CPU that has the flag in its
/// hand may still be walking a page table, restoring a frame, or one
/// instruction away from reading a user address.  Releasing then is a race, and
/// it is the race that produced a data abort inside the heap allocator's
/// free-list walk and an instruction abort at 0x0, both on the started CPU's
/// behalf, in a table the boot CPU had already handed back to the pool.
///
/// So the claim is counted rather than assumed.  Each CPU records itself here
/// on the path where it stops running programs, and the reaping side waits
/// until every CPU that is online has recorded itself.  A single CPU's boot
/// satisfies this at once, which is why the one-CPU boots never showed the
/// defect.
static PARKED: [AtomicBool; MAX_CPUS] = [const { AtomicBool::new(false) }; MAX_CPUS];

/// Record that `slot` will not reach into a user space again.
pub fn park(slot: usize) {
    if slot < MAX_CPUS {
        PARKED[slot].store(true, Ordering::Release);
    }
}

/// Whether `slot` has parked.
pub fn is_parked(slot: usize) -> bool {
    slot < MAX_CPUS && PARKED[slot].load(Ordering::Acquire)
}

/// Every online CPU has parked, so no CPU can name a user address again.
pub fn all_parked() -> bool {
    CPUS.iter()
        .enumerate()
        .filter(|(_, cpu)| cpu.online())
        .all(|(index, _)| is_parked(index))
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

    /// A slot past the end stops with its number in the message, rather than
    /// being clamped to the last CPU.
    ///
    /// This is the property the clamp lacked.  A clamp made a slot the kernel
    /// never numbered read as the highest one it did, so two CPUs wrote one
    /// record and each believed it was distinct, the arithmetic that made a
    /// task resume with another CPU's context.  A stop names the slot and the
    /// count, which is the one thing a reader of a broken boot needs.
    #[test]
    #[should_panic(expected = "past the")]
    fn a_slot_past_the_end_stops_with_its_number() {
        let _ = super::slot(super::MAX_CPUS);
    }
}
