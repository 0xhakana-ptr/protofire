//! kernel/src/cpus.rs
//!
//! The machine's other CPUs: starting them, and counting them.
//!
//! ## Why the boot reports a count instead of a claim
//!
//! A machine that starts a CPU and does not wait for it is a boot that cannot
//! tell "the CPU came up" from "the firmware accepted the request and nothing
//! ran".  The wait is bounded — a CPU that never comes up is a line on the
//! console rather than a boot that hangs — and the line names the CPU, so a
//! reader of the log can tell a start nobody made from one that made and
//! failed.
//!
//! ## What a machine with one CPU answers
//!
//! Zero, and that is an answer rather than a gap: `start_secondary_harts`
//! answers how many CPUs it *accepted*, and every machine in this tree answers
//! honestly — zero where nothing starts one.  A caller that asked `is this
//! machine done starting its CPUs` gets a fact, which is what the boot line
//! needs.

/// Start the machine's other CPUs, and report each one.
///
/// The lines are the evidence: this CPU's start is a request the firmware
/// accepts asynchronously, so what the log can say is what the CPU itself
/// recorded before the request returned.
#[cfg(target_os = "none")]
pub fn start_the_others() {
    // SAFETY: called once, from the boot CPU, with the tables up.
    let started = unsafe { arch::start_secondary_harts() };
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
        let slot_index = crate::per_cpu::BOOT_SLOT + 1 + slot;
        crate::per_cpu::register(slot_index, hart, false);
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
}

/// How long the boot waits for a started CPU to record that it is running.
///
/// A policy about the *report*, not about the start: the firmware's answer is
/// asynchronous, so the wait is what turns "accepted" into "came up" — and a
/// CPU that never records is reported rather than waited on forever.
#[cfg(target_os = "none")]
const MAX_START_SPINS: u64 = 50_000_000;

/// What each CPU has actually taken, after the boot's programs have run.
///
/// The count is the evidence the start cannot give: a CPU that stored its flag
/// and then stopped prints "online" and nothing else, while a CPU doing work
/// prints a number that grew.  On this tree the started CPU takes no interrupt
/// — the trap entry is one address and the sink behind it is the boot CPU's —
/// so its count stays zero, and the line says that rather than implying work it
/// is not doing.
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
        arch::serial::write_str(if cpu.is_boot_cpu() {
            ", scheduler owner, "
        } else {
            ", parked, "
        });
        arch::serial::write_u32(cpu.ticks() as u32);
        arch::serial::write_str(" tick(s)\n");
    }
}
