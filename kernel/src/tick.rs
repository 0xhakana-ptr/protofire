//! kernel/src/tick.rs
//!
//! The timer's line, its time slice, and the count of ticks.
//!
//! ## Why the line is enabled here and the timer armed elsewhere
//!
//! A tick that arrives while the boot is still at ring 0 is a full trap for
//! every one of them, and the boot spends its remaining work in trap entry
//! instead of in starting.  So the line is enabled once, early, and the timer
//! is armed by the code that is about to enter a program — which is the last
//! moment a tick is wanted rather than a tax.

/// How long a time slice is, in microseconds.
///
/// A hundred microseconds at about a gigahertz is a hundred thousand ticks,
/// which is long enough that a program gets work done between ticks and short
/// enough that three programs interleave visibly in a log even under an
/// emulator whose trap cost dwarfs the work.  The number is set by that
/// measurement and not by a scheduler weighing anything, because this kernel
/// has no load to weigh.
#[cfg(target_os = "none")]
pub const TIME_SLICE_US: u64 = 100;

/// How many times the timer has fired.
pub static TIMER_TICKS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// The timer's interrupt, as the machine reports it.
///
/// Asked of the machine and not written here: 30 is aarch64's private timer
/// interrupt and `0x20` is x86_64's local APIC vector, and a constant in this
/// file would be one machine's answer installed on the other.
#[cfg(target_os = "none")]
fn timer_interrupt() -> usize {
    arch::timer_interrupt()
}

/// Report the external interrupt controller, and enable its hart line.
///
/// The two halves are separate and both needed: the controller's per-source
/// bit decides whether a source reaches the PLIC's pending array, and the
/// hart's `sie` bit decides whether the PLIC can reach the hart at all.  A
/// machine whose tree names no controller prints that and boots on — every
/// machine here is useful without one.
#[cfg(target_os = "none")]
pub fn bring_up_external() {
    let Some((base, context, sources)) = arch::external_controller() else {
        arch::serial::write_str("protofire: no external interrupt controller\n");
        return;
    };

    // SAFETY: the trap table is installed by now, and this is the line the
    // controller reaches this hart on.
    let line = unsafe { arch::enable_interrupt_line(arch::external_interrupt()) };
    arch::serial::write_str("protofire: external controller at ");
    arch::serial::write_hex(base as u64);
    arch::serial::write_str(", context ");
    arch::serial::write_u32(context as u32);
    arch::serial::write_str(", ");
    arch::serial::write_u32(sources as u32);
    arch::serial::write_str(" source(s), hart line ");
    arch::serial::write_str(if line { "on" } else { "off" });
    arch::serial::write_str("\n");
}

/// Enable the timer's line, arm it once, and say what the machine reported.
#[cfg(target_os = "none")]
pub fn bring_up() {
    // SAFETY: the controller is enabled and the vector table is installed by
    // the time this runs; the line is the architecture's private timer
    // interrupt.
    let line = timer_interrupt();
    if !unsafe { arch::enable_interrupt_line(line) } {
        arch::serial::write_str("protofire: timer line not enabled\n");
        return;
    }

    // SAFETY: as above, and the line being enabled is what makes a fire a
    // delivered interrupt rather than a silent status bit.
    let Some(frequency) = (unsafe { arch::timer_frequency() }) else {
        arch::serial::write_str("protofire: timer has no frequency, not armed\n");
        return;
    };

    // The line is enabled here; the timer is armed by the code that enters a
    // program.  Arming now would fire during the rest of the boot — which runs
    // unmasked, takes a full trap per tick, and cannot be preempted — and the
    // log would stop in the middle of a line.  The first version armed here and
    // did exactly that.
    TIMER_TICKS.store(0, core::sync::atomic::Ordering::Release);

    // SAFETY: read-only; reports what the controller kept.
    let kept = unsafe { arch::interrupt_line_enabled(line) };
    arch::serial::write_str("protofire: timer line enabled = ");
    arch::serial::write_u32(usize::from(kept) as u32);
    arch::serial::write_str("\n");

    // The counter, read while the timer is armed and running.
    //
    // This has to happen here and not before: a counter that is not running
    // reads the same value twice, so a probe that armed nothing would report
    // `0 ticks apart` on a machine whose timer works.
    //
    // SAFETY: the controller is enabled and recorded by `timer_frequency`.
    unsafe { arch::arm_timer(frequency, TIME_SLICE_US * 1000) };
    // SAFETY: read-only.
    let first = unsafe { arch::timer_counter() };
    let mut spin = 0u64;
    while spin < 100_000 {
        spin += 1;
    }
    // SAFETY: read-only.
    let second = unsafe { arch::timer_counter() };
    arch::serial::write_str("protofire: timer counter ");
    // `second - first`, not the other way: this machine's counter counts up.
    // The subtraction was written for the APIC's countdown and kept its
    // direction when the clock changed, which made the line print zero on a
    // counter that was running.
    arch::serial::write_u32(second.saturating_sub(first) as u32);
    arch::serial::write_str(" ticks apart\n");

    arch::serial::write_str("protofire: timer control ");
    // SAFETY: as above.
    arch::serial::write_u32(unsafe { arch::timer_control() } as u32);
    arch::serial::write_str("\n");

    // Disarmed again: the code that enters a program arms it, so the boot does
    // not spend its remaining work taking traps at ring 0.
    //
    // SAFETY: as above; this is the end of the boot's own use of the timer.
    unsafe { arch::disarm_timer() };

    arch::serial::write_str("protofire: timer armed at ");
    arch::serial::write_u32((frequency / 1000) as u32);
    arch::serial::write_str(" ticks/ms\n");

    // There is no second self-check here.
    //
    // One was written — the timer's own vector, sent to this CPU — and it was
    // the wrong instrument twice over: on aarch64 the controller cannot raise a
    // timer's private interrupt on demand, so it printed "not raised" on every
    // boot; and on x86_64 it proved the same thing `raise_test_interrupt`
    // already proves.  What the timer needs proved is that its *countdown*
    // runs, which the counter line above does, and that a tick preempts, which
    // the last line of the boot does.
}
