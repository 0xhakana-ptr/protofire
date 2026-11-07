//! kernel/src/cpus.rs
//!
//! The machine's other CPUs: starting them, and counting them.
//!
//! A machine that starts a CPU and does not wait for it is a boot that cannot
//! tell "the CPU came up" from "the firmware accepted the request and nothing
//! ran".  The wait is bounded, a CPU that never comes up is a line on the
//! console rather than a boot that hangs, and the line names the CPU, so a
//! reader of the log can tell a start nobody made from one that made and
//! failed.
//!
//! A machine with one CPU gets zero, and zero is an answer rather than a gap:
//! `start_secondary_harts` answers how many CPUs it *accepted*, and every
//! machine in this tree answers honestly, zero where nothing starts one.  A
//! caller that asked `is this machine done starting its CPUs` gets a fact,
//! which is what the boot line needs.
//!
//! "The hart came up" is a flag the hart stored about itself, and a flag is not
//! a CPU.  What separates the two is a line the hart **took**, and the one line
//! this boot can aim at another CPU is the inter-processor interrupt: the
//! firmware delivers it, the hart's own dispatch acknowledges it, and the
//! kernel's handler counts it on the CPU that received it.  So the start is
//! followed by one IPI and a bounded wait for that count, and the line says
//! which of the two happened.

/// Start the machine's other CPUs, and report each one.
///
/// The lines are the evidence: this CPU's start is a request the firmware
/// accepts asynchronously, so what the log can say is what the CPU itself
/// recorded before the request returned.
#[cfg(target_os = "none")]
pub fn start_the_others() {
    // SAFETY: called once, from the boot CPU, with the tables up.
    let started = unsafe { arch::start_secondary_harts(crate::tick::TIME_SLICE_US) };
    for slot in 0..started {
        let hart = arch::secondary_hart_id(slot);
        // A CPU that never stores its flag is a failure with a line rather
        // than a hang: the bound is a policy about how long a boot waits for
        // a CPU it can no longer do anything about, and it is generous because
        // a slow emulator is still an emulator.
        let mut spins = 0u64;
        while !arch::secondary_online(slot) && spins < MAX_START_SPINS {
            spins += 1;
        }
        // A CPU that did not come up is **not** registered.  Registering it
        // anyway would make `online_count` and the activity line count a CPU
        // the line above just said failed, and the two answers would come from
        // the same boot.
        if arch::secondary_online(slot) {
            let slot_index = crate::per_cpu::BOOT_SLOT + 1 + slot;
            crate::per_cpu::register(slot_index, hart, false);
        }
        arch::serial::write_str("protofire: hart ");
        arch::serial::write_u32(hart as u32);
        if arch::secondary_online(slot) {
            arch::serial::write_str(" online\n");
        } else {
            arch::serial::write_str(" did not come up\n");
        }
    }

    let refused = arch::refused_harts();
    if refused > 0 {
        arch::serial::write_str("protofire: ");
        arch::serial::write_u32(refused as u32);
        arch::serial::write_str(" hart(s) the firmware refused to start\n");
    }

    prove_an_ipi_reaches_them(started);
}

/// Wake the started CPUs once there is work for them.
///
/// The first interrupt proved the CPUs take interrupts; this one tells them
/// there is something to run.  The boot starts the other CPUs before it builds
/// the scheduler, so a CPU that asked for work at start would be told "nothing
/// yet" and would have to poll.  It waits on this instead: the scheduler is
/// installed by the time this is called, so the answer is a task.
///
/// Called after the scheduler exists and before the boot enters its own first
/// program, so a started CPU and the boot CPU begin at nearly the same moment,
/// which is what makes the concurrency observable rather than theoretical.
#[cfg(target_os = "none")]
pub fn wake_them() {
    if crate::per_cpu::online_count() < 2 {
        return;
    }
    // SAFETY: every started CPU installed its vector and enabled its software
    // line before it recorded that it was online.
    let sent = unsafe { arch::send_ipi_to_others() };
    arch::serial::write_str("protofire: work available, ");
    arch::serial::write_str(if sent {
        "started cpus woken\n"
    } else {
        "no started cpu took the wake\n"
    });
}

/// Send one inter-processor interrupt, and require that a CPU took it.
///
/// A hart that stored its flag and then stopped is indistinguishable from a
/// working CPU in every line the boot has printed so far.  An interrupt it
/// actually took is not: it means the firmware delivered, `stvec` was installed
/// where this hart reads it, the trap entry built a frame on this hart's stack,
/// and the kernel's handler ran far enough to count.  Every one of those is a
/// step the start alone does not exercise.
///
/// The firmware's answer says the call was accepted, which is the same kind of
/// claim as `hart N online`.  The count is the CPU's own record, and it is read
/// here after a bounded wait, so a delivery that never happened prints
/// `not taken` rather than a success the firmware promised.
#[cfg(target_os = "none")]
fn prove_an_ipi_reaches_them(started: usize) {
    if started == 0 {
        return;
    }
    // A mask of no one is a call that would be a self-interrupt on some
    // machines and an error on others, and there is nothing to prove either
    // way.
    let sent = unsafe { arch::send_ipi_to_others() };
    if !sent {
        arch::serial::write_str("protofire: no ipi sent, no started cpu to take one\n");
        return;
    }

    let mut spins = 0u64;
    while spins < MAX_IPI_SPINS && !any_secondary_took_an_ipi(started) {
        spins += 1;
    }
    arch::serial::write_str("protofire: ipi to ");
    arch::serial::write_u32(started as u32);
    arch::serial::write_str(" other cpu(s), ");
    arch::serial::write_str(if any_secondary_took_an_ipi(started) {
        "taken\n"
    } else {
        "not taken\n"
    });
}

/// Whether any started CPU recorded taking an inter-processor interrupt.
#[cfg(target_os = "none")]
fn any_secondary_took_an_ipi(started: usize) -> bool {
    (0..started).any(|slot| {
        let slot_index = crate::per_cpu::BOOT_SLOT + 1 + slot;
        crate::per_cpu::slot(slot_index).ipis() > 0
    })
}

/// How long the boot waits for a started CPU to record that it is running.
///
/// A policy about the *report*, not about the start: the firmware's answer is
/// asynchronous, so the wait is what turns "accepted" into "came up", and a
/// CPU that never records is reported rather than waited on forever.
#[cfg(target_os = "none")]
const MAX_START_SPINS: u64 = 50_000_000;

/// How long the boot waits for the interrupt it sent to be taken.
///
/// Shorter than [`MAX_START_SPINS`] and for a different reason: the CPU is
/// already online by the time this runs, so the wait covers a firmware call and
/// one trap, not a hart coming out of reset.  A wait that ran as long as the
/// start's would turn a lost interrupt into a boot that looked slow.
#[cfg(target_os = "none")]
const MAX_IPI_SPINS: u64 = 5_000_000;

/// What each CPU has actually taken, after the boot's programs have run.
///
/// The count is the evidence the start cannot give: a CPU that stored its flag
/// and then stopped prints "online" and nothing else, while a CPU doing work
/// prints a number that grew.  A started CPU here counts its own timer and the
/// interrupt the boot sent it, and the programs it ran to their exits are
/// counted where they ended, which is the boot line that names a process
/// having run on a CPU other than the boot's.
#[cfg(target_os = "none")]
pub fn report_activity() {
    arch::serial::write_str("protofire: cpus online = ");
    arch::serial::write_u32(crate::per_cpu::online_count() as u32);
    arch::serial::write_str("\n");
    for index in 0..crate::per_cpu::MAX_CPUS {
        let cpu = crate::per_cpu::slot(index);
        if !cpu.online() {
            continue;
        }
        arch::serial::write_str("protofire: cpu ");
        arch::serial::write_u32(index as u32);
        arch::serial::write_str(" id ");
        arch::serial::write_u32(cpu.id() as u32);
        if cpu.is_boot_cpu() {
            arch::serial::write_str(", scheduler owner, ");
        } else {
            // The interrupt count before the tick count because it is the one
            // that is exact: the boot sends one and the CPU records one, where
            // the tick count depends on how long the programs ran.
            arch::serial::write_str(", ticking, ");
            arch::serial::write_u32(cpu.ipis() as u32);
            arch::serial::write_str(" ipi(s), ");
        }
        arch::serial::write_u32(cpu.ticks() as u32);
        arch::serial::write_str(" tick(s)\n");
    }

    // The other CPUs' translations, after everything that changed one.  A boot
    // remaps device windows *after* the started CPUs are online, and those
    // tables are the kernel's own: every program root copies entry 0, so a CPU
    // that is not told keeps the cached translation.  The count is what says
    // the mechanism ran; the timeout count is what says every CPU heard it,
    // and a boot whose second CPU was deaf would print a number here instead
    // of the line being absent.
    let (sent, acknowledged, timed_out) = crate::shootdown::totals();
    arch::serial::write_str("protofire: tlb shootdown ");
    arch::serial::write_u32(sent as u32);
    arch::serial::write_str(" sent, ");
    arch::serial::write_u32(acknowledged as u32);
    arch::serial::write_str(" acknowledged, ");
    arch::serial::write_u32(timed_out as u32);
    arch::serial::write_str(" timed out\n");
}
