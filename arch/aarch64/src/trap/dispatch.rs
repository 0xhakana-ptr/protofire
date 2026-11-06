//! arch/aarch64/src/trap/dispatch.rs
//!
//! The vector table, the sink an exception goes to, the controller, and the
//! self-test that proves the path.
//!
//! ## The sixteen entries become sixteen numbers
//!
//! The architecture's table is four groups of four, and `entry.S` moves the
//! entry's index into `x16` before branching to the common path.  So the vector
//! reported is `(group * 4) + kind`, which is exactly what
//! [`crate::vbar::entry_offset`] divides by, and a test checks the two agree
//! rather than leaving the arithmetic in two places to drift.
//!
//! An exception has no context to hand a function, which is the same reason the
//! x86_64 dispatch reads its sink from a static.  The kernel installs one with
//! `set_sink`; until then every exception is unhandled, and an unhandled one
//! stops the machine with its number and syndrome on the console.

#[cfg(target_os = "none")]
use core::sync::atomic::AtomicBool;
#[cfg(target_os = "none")]
use core::sync::atomic::AtomicUsize;
#[cfg(target_os = "none")]
use core::sync::atomic::Ordering;

use crate::vbar::ENTRIES;
use crate::vbar::ENTRY_STRIDE;

#[cfg(target_os = "none")]
pub type Sink = fn(irq::Frame) -> bool;

#[cfg(target_os = "none")]
static SINK: cell::SyncUnsafeCell<Option<Sink>> = cell::SyncUnsafeCell::new(None);

/// Install the function that handles an exception frame.
///
/// Called once by the kernel, after its console is up and before any vector can
/// be raised.  A frame that arrived with no sink is answered by stopping, which
/// is the only answer a machine can give to an exception nobody registered for.
///
/// # Safety
///
/// Called once, before any vector can be raised.  The function must not
/// allocate, block, or enable interrupts: it runs on the kernel stack the
/// exception found, with the interrupted code's SIMD state in the frame rather
/// than in the registers.
#[cfg(target_os = "none")]
pub unsafe fn set_sink(sink: Sink) {
    // SAFETY: the caller promises this is the only call, and the write is what
    // makes a frame reachable rather than unhandled.
    unsafe { *SINK.get() = Some(sink) };
}

#[cfg(target_os = "none")]
pub(super) fn sink() -> Option<Sink> {
    // SAFETY: written once by `set_sink` before any vector can be raised, and
    // read here after that.
    unsafe { *SINK.get() }
}

// The vector table's address, as the assembly defined it.
#[cfg(target_os = "none")]
unsafe extern "C" {
    /// The 2 KiB table `exception_vectors:` labels.
    static exception_vectors: u8;
}

/// The address the machine should branch to for an exception.
#[cfg(target_os = "none")]
fn table_address() -> usize {
    // `addr_of!` takes the address without creating a reference; there is a run
    // of instructions there, not a value.
    core::ptr::addr_of!(exception_vectors) as usize
}

#[cfg(target_os = "none")]
fn installed_table() -> usize {
    let value: u64;
    // SAFETY: reading `VBAR_EL1` at EL1 has no side effect; the low eleven bits
    // are reserved and the address is what remains.
    unsafe {
        core::arch::asm!(
            "mrs {}, vbar_el1",
            out(reg) value,
            options(nomem, nostack, preserves_flags)
        )
    };
    (value as usize) & !0x7FF
}

/// What a self-test raised and what came back.
///
/// Two atomics rather than a mutex: the trap path runs with interrupts masked
/// and cannot take a lock the interrupted code might hold, and there is exactly
/// one writer and one reader, in that order.
#[cfg(target_os = "none")]
static TEST_RAISED: AtomicUsize = AtomicUsize::new(0);
#[cfg(target_os = "none")]
static TEST_RETURNED: AtomicBool = AtomicBool::new(false);

/// The sink the self-test installs: record the frame and claim it.
///
/// It returns `true`, which is what makes the exception return: the common path
/// ends in `eret` either way, but a sink that answered `false` would have the
/// dispatch stop the machine, and a self-test that halted the boot would be a
/// test the boot never reported on.
#[cfg(target_os = "none")]
fn recording_sink(frame: irq::Frame) -> bool {
    TEST_RAISED.store(frame.vector, Ordering::Release);
    TEST_RETURNED.store(true, Ordering::Release);
    true
}

/// Install the table, then prove the path works by taking one exception.
///
/// Returns whether the machine will now deliver an exception through this
/// module.  Two things make that true, and the second is why the answer is a
/// claim rather than a hope:
///
/// 1. `VBAR_EL1` names `exception_vectors`, read back rather than assumed, a
///    register written and never re-read is a value a later change can break
///    silently.
/// 2. A supervisor call raised from EL1 arrives at entry 4, reaches this
///    module, and returns to the instruction after it.  That exercises the
///    assembly's save/restore, the vector numbering, the sink indirection and
///    the `eret` together; the frame's own offsets are what the return path
///    restored, so a frame laid out wrong would return into garbage rather than
///    here.
///
/// The sink the kernel installed is swapped out for the duration and put back
/// afterwards, so the probe adds no branch to the steady-state path.
///
/// # Safety
///
/// Called once, after `set_sink` and before the kernel enables interrupts.
/// It writes `VBAR_EL1` and executes one `svc`, which the machine takes as an
/// exception; that is safe at EL1 with the kernel's stack valid, and not safe
/// anywhere else.
#[cfg(target_os = "none")]
pub unsafe fn install_table() -> bool {
    let table = table_address();

    // SAFETY: written below and read back here; the register's reserved bits
    // are cleared by `installed_table`.
    unsafe {
        core::arch::asm!(
            "msr vbar_el1, {}",
            "isb",
            in(reg) table as u64,
            options(nostack)
        );
    }
    if installed_table() != table {
        return false;
    }

    let previous = sink();
    // SAFETY: this runs before any vector can arrive, and the sink is put back
    // before this function returns.  A vector that arrived between the two
    // stores would be answered by the recording sink, which claims it.
    unsafe { *SINK.get() = Some(recording_sink) };

    TEST_RAISED.store(usize::MAX, Ordering::Release);
    TEST_RETURNED.store(false, Ordering::Release);
    // SAFETY: `svc #0` from EL1 is taken as a synchronous exception at entry 4
    // and returns to the following instruction.  `esr_el1` must be told the
    // immediate is ours; the machine does that, not this code.
    unsafe {
        core::arch::asm!("svc #0", options(nostack));
    }

    let returned = TEST_RETURNED.load(Ordering::Acquire);
    let raised = TEST_RAISED.load(Ordering::Acquire);

    // SAFETY: putting back what was there.  The kernel's sink was installed
    // before this call by contract.
    unsafe { *SINK.get() = previous };

    returned && raised == SUPERVISOR_CALL_VECTOR
}

/// The vector `install_table`'s self-test expects.
///
/// Group `CurrentSpX` (offset 4) and kind `Synchronous` (offset 0), so entry 4,
/// *not* 0 and *not* 8.  Entry 0 is the same kind with `SP_EL0` selected, and
/// entry 8 is a supervisor call from a lower EL, which is what a user program's
/// system call takes.  Three numbers that differ by one bit of `PSTATE.SP` or
/// one exception level is why this constant is named rather than written as a
/// literal wherever it is needed.
pub const SUPERVISOR_CALL_VECTOR: usize = 4;

/// The index of `Kind::Irq` within a group.
pub(super) const IRQ_KIND: u64 = 1;

/// The vector a program's supervisor call arrives on.
///
/// `Lower64` (offset 8) and `Synchronous` (offset 0) is entry 8, which is a
/// different entry from the kernel's own `svc` at entry 4, the one
/// `install_table` uses as its self-test.  The two being one number apart in
/// nobody's arithmetic is why this is named.
pub const USER_SUPERVISOR_CALL_VECTOR: u64 = 8;

/// The controller, once the boot has found and enabled one.
#[cfg(target_os = "none")]
pub(super) static GIC: cell::SyncUnsafeCell<Option<crate::gic::Gic>> =
    cell::SyncUnsafeCell::new(None);

/// Record the controller the boot enabled, so an IRQ can be acknowledged.
///
/// # Safety
///
/// Called once, after [`crate::gic::Gic::enable`], before any line is
/// unmasked.  The two windows must stay mapped for the life of the boot.
#[cfg(target_os = "none")]
pub unsafe fn set_controller(gic: crate::gic::Gic) {
    // SAFETY: the caller promises this is the only write, and it happens before
    // any interrupt can arrive.
    unsafe { *GIC.get() = Some(gic) };
}

/// The controller the boot installed, if it installed one.
///
/// A started core asks for it so it can enable **its own** CPU interface: the
/// distributor is one device for the machine, but `GICC_CTLR` and `GICC_PMR`
/// are per-core registers, and a core that never wrote them takes no interrupt
/// at all.  That is what left a started core with `0 tick(s)` while it was
/// running a program: its timer fired, the distributor knew, and the interface
/// in front of the core was still disabled.
#[cfg(target_os = "none")]
pub fn controller() -> Option<crate::gic::Gic> {
    // SAFETY: written once by the boot before any core starts, read after.
    unsafe { *GIC.get() }
}

const _: () = assert!(ENTRIES == 16);
const _: () = assert!(ENTRY_STRIDE * ENTRIES == 2048);
const _: () = assert!(SUPERVISOR_CALL_VECTOR == 4);
