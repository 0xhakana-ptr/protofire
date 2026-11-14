//! kernel/src/tick.rs
//!
//! The timer's line, its time slice, and the count of ticks.
//!
//! A tick that arrives while the boot is still at ring 0 is a full trap for
//! every one of them, and the boot spends its remaining work in trap entry
//! instead of in starting.  So the line is enabled once, early, and the timer
//! is armed by the code that is about to enter a program, which is the last
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
/// machine whose tree names no controller prints that and boots on, every
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

/// Claim the console's interrupt source, and report what the controller kept.
///
/// The controller was programmed and its claim path had never carried a device:
/// no source was enabled, so nothing arrived through the external line, and
/// "the claim path works" was a statement about code rather than about a boot.
/// The console is the device this boot has, and its transmitter raises the line
/// on its own once asked, which makes the first real claim a thing a boot runs.
#[cfg(target_os = "none")]
pub fn bring_up_console_source() {
    // SAFETY: the interrupt table is installed by now, and this enables one
    // source at a controller the boot has already programmed.
    let Some(source) = (unsafe { arch::claim_console_source() }) else {
        arch::serial::write_str("protofire: console source not claimed\n");
        return;
    };
    // SAFETY: read-only, and the controller is the one the boot programmed.
    let enabled = unsafe { arch::external_source_enabled(source) };
    arch::serial::write_str("protofire: console source ");
    arch::serial::write_u32(source as u32);
    arch::serial::write_str(if enabled {
        " enabled at the controller\n"
    } else {
        " NOT enabled at the controller\n"
    });
}

/// Report how many console interrupts were taken.
///
/// A source enabled at the controller and never taken leaves this zero, which
/// is the difference between a claim path that is installed and one that ran.
/// The report comes after the boot has written a great deal, because a
/// transmit interrupt can only arrive after a byte was given to the device.
#[cfg(target_os = "none")]
pub fn report_console() {
    let count = crate::CONSOLE_INTERRUPTS.load(core::sync::atomic::Ordering::Acquire);
    arch::serial::write_str("protofire: console interrupt(s) taken = ");
    arch::serial::write_u32(count as u32);
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
    // program.  Arming now would fire during the rest of the boot, which runs
    // unmasked, takes a full trap per tick, and cannot be preempted, and the
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
    let advanced = second.saturating_sub(first);
    arch::serial::write_str("protofire: timer counter ");
    // `second - first`, not the other way: this machine's counter counts up.
    // The subtraction was written for the APIC's countdown and kept its
    // direction when the clock changed, which made the line print zero on a
    // counter that was running.
    arch::serial::write_u32(advanced as u32);
    arch::serial::write_str(" ticks apart\n");

    // The clock's **claim** and the counter's **movement**, on one line.
    //
    // A counter that moves slower than the rate it reports is the defect this
    // line exists for: `CNTFRQ_EL0` said 1 GHz on the machine where a slice
    // computed from it was a wait longer than the boot, and nothing in the log
    // said so because nothing compared the two.  This is the comparison, not a
    // proof, since a spin loop's duration is not known in seconds, but a number
    // a reader can sanity-check: a gigahertz counter crosses millions of ticks
    // while a hundred thousand instructions run, and one that crosses a handful
    // is not running at the rate it claims.
    //
    // Reported as "thousands of ticks per claimed megahertz of spin", which is
    // a ratio rather than a duration for exactly that reason: the ratio should
    // be in the thousands on a clock telling the truth, and the line does not
    // pretend to know how long the spin took.
    let per_claim = if frequency >= 1_000_000 {
        advanced.saturating_mul(1_000) / (frequency / 1_000_000).max(1)
    } else {
        0
    };
    arch::serial::write_str("protofire: timer clock claims ");
    arch::serial::write_u32((frequency / 1_000_000) as u32);
    arch::serial::write_str(" MHz, moved ");
    arch::serial::write_u32(per_claim as u32);
    arch::serial::write_str(" ticks per claimed MHz of spin\n");

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
    // One was written, the timer's own vector, sent to this CPU, and it was
    // the wrong instrument twice over: on aarch64 the controller cannot raise a
    // timer's private interrupt on demand, so it printed "not raised" on every
    // boot; and on x86_64 it proved the same thing `raise_test_interrupt`
    // already proves.  What the timer needs proved is that its *countdown*
    // runs, which the counter line above does, and that a tick preempts, which
    // the last line of the boot does.
}
