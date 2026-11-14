//! kernel/src/shootdown.rs
//!
//! Making a translation change visible to the other CPUs.
//!
//! ## What needs this, and what does not
//!
//! A task switch installs a root, and every machine's switch flushes the TLB
//! it is written on: x86_64 rewrites `cr3`, aarch64 runs `tlbi vmalle1`,
//! riscv64 runs `sfence.vma`.  So a CPU that stops running a task cannot keep a
//! translation for that task's pages, and a CPU that starts one pays the flush
//! on the way in.  Most of what a per-CPU scheduler does needs no shootdown at
//! all, and saying so is the first half of this file's subject.
//!
//! What is left is the table that is **shared**: the kernel's own.  Every
//! program root copies the kernel root's entry 0, so the identity map, the
//! device windows and the image's own sections are one set of tables that every
//! CPU walks.  A change to those tables from one CPU is invisible to another
//! until the other is told, and the boot has a live case: the second CPU is
//! online before the first one remaps a device window uncached, so the second
//! keeps reading those registers through a cached translation, and a store can
//! sit in a write-combining buffer instead of reaching the device.
//!
//! So the unit here is a whole-TLB invalidation on every other CPU, sent as the
//! inter-processor interrupt the machine already delivers, with an
//! acknowledgement the sender waits for.  It is deliberately not narrowed to a
//! page range: the machine's flush primitives are whole-TLB, this kernel's
//! table changes are rare, and a range form would need a range to be identical
//! on three architectures before it could be correct.
//!
//! ## The protocol
//!
//! One epoch counter and one acknowledgement word per CPU.  A sender increments
//! the counter, sends the interrupt, and waits for every online other CPU to
//! record an acknowledgement at or past the epoch it is waiting on.  A receiver
//! flushes first and records second, and repeats if the epoch moved while it
//! was flushing, so the word it stores always names a flush that really covered
//! that epoch.  The stores are release and the reads acquire: the table writes
//! that preceded the increment are what the flushing CPU's next walk must see.
//!
//! The wait is bounded.  A CPU that never answers is a CPU this boot cannot
//! reach, and the honest answer is a line on the console rather than a machine
//! that stops in a function whose name says "flush".
//!
//! ## What a caller must not do
//!
//! Take the scheduler's lock and then send a shootdown: the receiver's handler
//! flushes and returns and needs no lock, so nothing deadlocks today, but the
//! sender would be holding the lock across a wait for another CPU, and the
//! second CPU's next scheduling decision would be behind it.  A caller that
//! holds a lock the *receiver* also takes would deadlock outright, and the
//! page-table lock is the one to watch: a receiver never takes it, which is
//! why the table code may send.

use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

/// How many TLBs have been invalidated for another CPU's benefit.
static INVALIDATIONS: AtomicUsize = AtomicUsize::new(0);

/// How many acknowledgements those invalidations collected.
static ACKNOWLEDGEMENTS: AtomicUsize = AtomicUsize::new(0);

/// How many waits ended without every target answering.
static TIMEOUTS: AtomicUsize = AtomicUsize::new(0);

/// The epoch of the most recent invalidation.
///
/// Zero before the first one, and every acknowledgement word starts at zero,
/// so a send's first epoch is one and a CPU that has never flushed is correctly
/// behind it.
///
/// Bare metal only: a host has no other CPU to invalidate for, so nothing here
/// sends or acknowledges one and the counters would be dead weight the warning
/// pass is right to name.
#[cfg(target_os = "none")]
static EPOCH: AtomicUsize = AtomicUsize::new(0);

/// The epoch each CPU has flushed up to, by slot.
///
/// The array is indexed like every other per-CPU one, and an index past its end
/// is not written: a slot the kernel does not describe is a slot this file has
/// no record to update, and the sender's wait does not count it either.
#[cfg(target_os = "none")]
static ACKNOWLEDGED: [AtomicUsize; crate::per_cpu::MAX_CPUS] =
    [const { AtomicUsize::new(0) }; crate::per_cpu::MAX_CPUS];

/// How long a sender waits for the other CPUs to answer.
///
/// The wait covers one interrupt delivery per CPU, not a start: the CPUs that
/// are sent to are online by the sender's own definition.  A generous bound
/// because the host is an emulator, and a bound at all because a CPU that
/// stopped answering must not stop the one that is still working.
#[cfg(target_os = "none")]
const MAX_ACK_SPINS: u64 = 20_000_000;

/// What one invalidation asked for and got.
///
/// `asked` is the number of online CPUs other than the sender, and it is zero
/// on a machine with one CPU.  That is a completed invalidation and not a
/// failure, which is why it is a field of the report rather than an `Option`:
/// a caller would read `None` as "no flush happened" and stop trusting the
/// count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// The online CPUs other than the caller.
    pub asked: usize,
    /// How many of them answered.
    pub acknowledged: usize,
    /// Whether the wait ran out with an answer outstanding.
    pub timed_out: bool,
}

impl Report {
    /// An invalidation with no other CPU to tell, which is the answer a host
    /// build and a one-CPU machine give.
    pub const NOTHING_TO_TELL: Report = Report {
        asked: 0,
        acknowledged: 0,
        timed_out: false,
    };
}

/// Invalidate every other online CPU's TLB, and wait for them to say so.
///
/// The caller must have made its table change first: this function's contract
/// is about making a change visible, not about the change.  A caller that has
/// only written the tables and not flushed locally still has to flush locally
/// too, because the sender's own TLB is not covered by the interrupt it sends.
#[cfg(target_os = "none")]
pub fn invalidate_others() -> Report {
    let me = crate::per_cpu::current_slot();
    let asked = online_others(me);
    if asked == 0 {
        return Report::NOTHING_TO_TELL;
    }

    // The increment is the announcement, and it must be `AcqRel`: every table
    // write the caller made happens-before the receivers' flush, and the
    // receivers' acknowledgements happen-before the caller's return.
    let epoch = EPOCH.fetch_add(1, Ordering::AcqRel) + 1;
    INVALIDATIONS.fetch_add(1, Ordering::Relaxed);

    // SAFETY: the machines' send is `unsafe` only because it writes a
    // controller register; every CPU that is online installed its vector and
    // enables the line before it recorded that it was online.
    let sent = unsafe { arch::send_ipi_to_others() };
    if !sent {
        // Nothing took the interrupt, so the wait cannot be satisfied by any
        // CPU this sender could reach.  The tables are changed and the sender
        // has flushed its own; the line this produces is what says the other
        // CPUs may be stale.
        TIMEOUTS.fetch_add(1, Ordering::Relaxed);
        return Report {
            asked,
            acknowledged: 0,
            timed_out: true,
        };
    }

    let mut spins = 0u64;
    loop {
        if every_target_answered_now(me, epoch) {
            let acknowledged = online_others(me);
            ACKNOWLEDGEMENTS.fetch_add(acknowledged, Ordering::Relaxed);
            return Report {
                asked,
                acknowledged,
                timed_out: false,
            };
        }
        if spins >= MAX_ACK_SPINS {
            TIMEOUTS.fetch_add(1, Ordering::Relaxed);
            ACKNOWLEDGEMENTS.fetch_add(count_acknowledged(me, epoch), Ordering::Relaxed);
            return Report {
                asked,
                acknowledged: count_acknowledged(me, epoch),
                timed_out: true,
            };
        }
        spins += 1;
    }
}

/// The host form: a host has no other CPU, so there is nothing to tell.
#[cfg(not(target_os = "none"))]
pub fn invalidate_others() -> Report {
    Report::NOTHING_TO_TELL
}

/// Flush this CPU's TLB and record the epoch the flush covered.
///
/// Called from the inter-processor interrupt's handler, on the CPU that took
/// it.  The loop is what makes the stored word mean a real flush: an epoch that
/// arrived while the flush was running is not covered by it, so the CPU flushes
/// again rather than acknowledging a change it may not have seen.
///
/// The bound is a count of flush rounds, not of time.  Two advances during one
/// flush is a sender that arrived while this CPU was already answering it, and
/// a third round covers it; a machine that keeps advancing the epoch faster
/// than this CPU can flush is one whose sender is waiting too, and stopping
/// after a few rounds leaves the last epoch recorded, which is the honest thing
/// to record, the flush covered everything up to what the store says.
#[cfg(target_os = "none")]
pub fn acknowledge() {
    let slot = crate::per_cpu::current_slot();
    let Some(acknowledged) = ACKNOWLEDGED.get(slot) else {
        return;
    };
    for _ in 0..MAX_ACK_ROUNDS {
        let target = EPOCH.load(Ordering::Acquire);
        if acknowledged.load(Ordering::Acquire) >= target {
            return;
        }
        // SAFETY: a TLB maintenance operation with no memory operand of its
        // own; the tables it makes visible belong to whoever bumped the epoch.
        arch::flush_translation();
        acknowledged.store(target, Ordering::Release);
    }
}

/// How many flush rounds one acknowledgement may take.
///
/// Each round covers every epoch up to the one it read, so a second round is
/// only needed when another invalidation arrived mid-flush.  Four is more than
/// one interrupt handler can see on any boot this tree runs.
#[cfg(target_os = "none")]
const MAX_ACK_ROUNDS: usize = 4;

/// The host form: nothing to flush, because a host has no table of its own.
#[cfg(not(target_os = "none"))]
pub fn acknowledge() {}

/// How many online CPUs other than `me` exist.
#[cfg(target_os = "none")]
fn online_others(me: usize) -> usize {
    (0..crate::per_cpu::MAX_CPUS)
        .filter(|slot| *slot != me && crate::per_cpu::slot(*slot).online())
        .count()
}

/// Whether every other online CPU has acknowledged `epoch`, read from the
/// machine's own records.
///
/// The live form of [`every_target_answered`], which takes plain slices so it
/// can be tested without a machine.  Both exist because the decision and the
/// reading of it are different subjects: the decision is arithmetic a test can
/// pin, and the reading is three statics that only a boot has.
#[cfg(target_os = "none")]
fn every_target_answered_now(me: usize, epoch: usize) -> bool {
    let mut asked = 0;
    for slot in 0..crate::per_cpu::MAX_CPUS {
        if slot == me || !crate::per_cpu::slot(slot).online() {
            continue;
        }
        asked += 1;
        let answered = ACKNOWLEDGED
            .get(slot)
            .is_some_and(|word| word.load(Ordering::Acquire) >= epoch);
        if !answered {
            return false;
        }
    }
    asked > 0
}

/// How many of the other online CPUs have acknowledged `epoch`.
#[cfg(target_os = "none")]
fn count_acknowledged(me: usize, epoch: usize) -> usize {
    (0..crate::per_cpu::MAX_CPUS)
        .filter(|slot| *slot != me && crate::per_cpu::slot(*slot).online())
        .filter(|slot| {
            ACKNOWLEDGED
                .get(*slot)
                .is_some_and(|word| word.load(Ordering::Acquire) >= epoch)
        })
        .count()
}

/// Whether an epoch has been answered by every CPU that is meant to answer it.
///
/// The decision behind the wait, as arithmetic over plain slices rather than
/// over the machine's statics, so a test can exercise it without one: a stale
/// acknowledgement is the whole failure mode, and a loop that counted "some CPU
/// answered" instead of "every CPU answered at or past the epoch" would pass a
/// boot whose second CPU never flushed.
///
/// `acks` is indexed by CPU slot, `online` says which slots are CPUs, and `me`
/// is the sender, which never answers its own interrupt.
#[cfg(test)]
pub(crate) fn every_target_answered(
    me: usize,
    epoch: usize,
    acks: &[usize],
    online: &[bool],
) -> bool {
    let mut asked = 0;
    for slot in 0..online.len().min(acks.len()) {
        if slot == me || !online[slot] {
            continue;
        }
        asked += 1;
        if acks[slot] < epoch {
            return false;
        }
    }
    asked > 0
}

/// How many invalidations have been sent, how many were acknowledged, and how
/// many timed out.
///
/// The boot line's numbers.  They are counted here rather than derived from the
/// epoch because an invalidation that timed out still moved the epoch, and a
/// reader of the line has to see the difference between "nobody was asked" and
/// "somebody was asked and did not answer".
pub fn totals() -> (usize, usize, usize) {
    (
        INVALIDATIONS.load(Ordering::Acquire),
        ACKNOWLEDGEMENTS.load(Ordering::Acquire),
        TIMEOUTS.load(Ordering::Acquire),
    )
}

#[cfg(test)]
mod tests {
    use super::every_target_answered;

    /// A single-CPU machine has nobody to tell, and that is not a satisfied
    /// wait: there was no wait.
    #[test]
    fn a_machine_with_one_cpu_has_no_target() {
        assert!(!every_target_answered(0, 1, &[1], &[true]));
    }

    /// A CPU that has not flushed this epoch is a target that has not answered.
    ///
    /// This is the failure a "did anybody answer" test would pass: the sender's
    /// own word is already at the epoch, and counting it would make every
    /// invalidation look acknowledged.
    #[test]
    fn a_stale_acknowledgement_does_not_count() {
        let acks = [7, 6];
        let online = [true, true];
        assert!(!every_target_answered(0, 7, &acks, &online));
        assert!(every_target_answered(0, 6, &acks, &online));
    }

    /// The sender's own word is never a target, even when it is the only one
    /// that has moved.
    #[test]
    fn the_sender_does_not_answer_for_itself() {
        let acks = [9, 3];
        let online = [true, true];
        assert!(!every_target_answered(0, 9, &acks, &online));
    }

    /// A slot that is not online is not waited on: a CPU that never came up
    /// has no TLB to invalidate, and waiting for it would turn every
    /// invalidation into a timeout.
    #[test]
    fn an_offline_slot_is_not_a_target() {
        let acks = [5, 5, 0];
        let online = [true, true, false];
        assert!(every_target_answered(2, 5, &acks, &online));
    }
}
