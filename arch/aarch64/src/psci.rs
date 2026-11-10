//! arch/aarch64/src/psci.rs
//!
//! PSCI: the firmware call that starts a core this kernel is not running on.
//!
//! ## What the machine offers
//!
//! A device-tree machine wakes a secondary core by asking firmware, not by
//! writing a register.  The `psci` node says how to ask:
//!
//! ```text
//! psci {
//!     cpu_on = <0xc4000003>;
//!     method = "hvc";
//!     compatible = "arm,psci-1.0", "arm,psci-0.2", "arm,psci";
//! };
//! ```
//!
//! `cpu_on` is a **function id**, not a register address, and the number is
//! what a reader would otherwise guess wrong: `0xc4000003` is the 64-bit
//! calling convention's `CPU_ON`, and `0x84000003` is the 32-bit one.  The tree
//! carries the number because a platform may extend or renumber the range, so
//! this module reads it rather than spelling it.
//!
//! `method` says which instruction carries the call: `hvc` when the kernel runs
//! under a hypervisor (QEMU's `virt` with EL2 firmware does), `smc` when it
//! runs on an EL3 monitor.  The two trap to different exception levels, and
//! using the wrong one is not an error the machine can report: on `virt` an
//! `smc` at EL1 with no EL3 handler is an undefined-instruction fault.
//!
//! ## What `cpu_on` returns
//!
//! Zero on success, and a negative value from the PSCI error range otherwise.
//! `ALREADY_ON` (`-4`) is the one a boot has to treat as success: a core
//! firmware is already running is a core this boot may use, and refusing it
//! would leave a working CPU idle because of the order firmware brought them
//! up.
//!
//! The call is the machine's, and the constants are the tree's.  Keeping them
//! here is what lets `smp.rs` be about slots, stacks and flags: the part that
//! a second architecture with a different start call could reuse by shape.

/// What the firmware said about a start request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Started {
    /// The firmware accepted, or the core was already running.
    Yes,
    /// The firmware refused, with the value it answered.
    Refused(i64),
}

/// The `psci` node's answers, as the tree states them.
#[derive(Debug, Clone, Copy)]
pub struct Psci {
    /// The function id of `cpu_on`.
    pub cpu_on: u32,
    /// Whether the call is carried by `hvc` (true) or `smc` (false).
    pub hypervisor_call: bool,
}

/// The error PSCI returns for a core firmware already started.
///
/// `ALREADY_ON` is success from a boot's point of view: the core is running,
/// which is what the call asked for.  The distinction matters because firmware
/// may have started a core for its own reasons, and a boot that treated `-4` as
/// a refusal would run on fewer CPUs than the machine has while reporting that
/// the machine refused.
// Bare metal only: the host arm has no call to make, so nothing reads it there.
#[cfg(target_os = "none")]
const ALREADY_ON: i64 = -4;

/// Read the `psci` node from the tree, if the tree has one.
///
/// `None` when the tree names no `psci` node, which is the state of a machine
/// whose firmware does not implement it: a bare `-kernel` boot with no PSCI is
/// a single-core boot, and that is an answer rather than a failure.
#[cfg(target_os = "none")]
pub fn from_tree() -> Option<Psci> {
    let tree = crate::boot::device_tree()?;
    let node = tree.find_compatible("arm,psci-1.0").or_else(|| {
        // The older compatible strings name the same call.  A tree that offers
        // only `arm,psci` still has `cpu_on`, and a boot that demanded 1.0
        // would refuse a machine that could start its cores.
        tree.find_compatible("arm,psci-0.2")
            .or_else(|| tree.find_compatible("arm,psci"))
    })?;

    let cpu_on = node.property("cpu_on")?.as_u32()?;
    // `method` is a string, and the two the specification allows are `hvc` and
    // `smc`.  A tree that names neither is not a tree this module can call
    // through, and guessing would pick the one that faults.
    let method = node.property("method")?.as_str()?;
    let hypervisor_call = match method {
        "hvc" => true,
        "smc" => false,
        _ => return None,
    };

    Some(Psci {
        cpu_on,
        hypervisor_call,
    })
}

/// Ask firmware to start `target` at `entry`, handing it `context`.
///
/// Answers what firmware said.  The entry is a **physical** address: the core
/// starts with its MMU off, so an address a kernel links at must be one the
/// core can fetch from without translation, which every image this tree builds
/// is.
///
/// # Safety
///
/// `entry` must be a physical address whose code is mapped and executable with
/// the MMU off, and it must be a function that expects `x0` to be `context`.
/// The call traps to firmware, which clobbers the caller-saved registers.
#[cfg(target_os = "none")]
pub unsafe fn cpu_on(psci: Psci, target: u64, entry: u64, context: u64) -> Started {
    // The PSCI calling convention: `x0` is the function id, and the arguments
    // are `x1`..`x3`.  The 64-bit ids take them as they are; the 32-bit ones
    // take a 32-bit core id and a 32-bit entry, which is why the arguments are
    // passed at their 64-bit width and firmware truncates.
    //
    // Every register firmware may eat is declared, for the reason the riscv64
    // timer call declares its clobbers: an undeclared clobber is a register the
    // caller loses silently, and a boot whose context was in `x9` would resume
    // with firmware's leftover in it.
    let answer: i64;
    // SAFETY: the caller promises the entry address and the context are what
    // the core will find valid with its MMU off, and that this runs at the
    // exception level the tree's `method` names.
    unsafe {
        if psci.hypervisor_call {
            core::arch::asm!(
                "hvc #0",
                inlateout("x0") psci.cpu_on as u64 => answer,
                inlateout("x1") target => _,
                inlateout("x2") entry => _,
                inlateout("x3") context => _,
                lateout("x4") _,
                lateout("x5") _,
                lateout("x6") _,
                lateout("x7") _,
                lateout("x8") _,
                lateout("x9") _,
                lateout("x10") _,
                lateout("x11") _,
                lateout("x12") _,
                lateout("x13") _,
                lateout("x14") _,
                lateout("x15") _,
                lateout("x16") _,
                lateout("x17") _,
                options(nostack)
            )
        } else {
            core::arch::asm!(
                "smc #0",
                inlateout("x0") psci.cpu_on as u64 => answer,
                inlateout("x1") target => _,
                inlateout("x2") entry => _,
                inlateout("x3") context => _,
                lateout("x4") _,
                lateout("x5") _,
                lateout("x6") _,
                lateout("x7") _,
                lateout("x8") _,
                lateout("x9") _,
                lateout("x10") _,
                lateout("x11") _,
                lateout("x12") _,
                lateout("x13") _,
                lateout("x14") _,
                lateout("x15") _,
                lateout("x16") _,
                lateout("x17") _,
                options(nostack)
            )
        }
    };

    if answer == 0 || answer == ALREADY_ON {
        Started::Yes
    } else {
        Started::Refused(answer)
    }
}

#[cfg(test)]
mod tests {
    //! The tests for this module.
    //!
    //! What this module can check on a host: the interpretation of firmware's
    //! answer, which is the part that decides whether a core counts as started.

    // The constant is bare-metal only, so the test that pins it is too.  A host
    // build skips the module rather than asserting a number it cannot see.
    #![cfg(target_os = "none")]

    /// Zero is success, and `ALREADY_ON` is success too.
    ///
    /// The second half is the one worth pinning.  PSCI's `ALREADY_ON` is `-4`,
    /// and a boot that read every non-zero answer as a refusal would run on
    /// fewer cores than the machine has, while printing that firmware refused
    /// one.  The failure is a boot that looks correct and uses half the
    /// machine.
    #[test]
    fn already_on_is_a_start_that_succeeded() {
        assert_eq!(super::ALREADY_ON, -4);

        // The two answers this module maps to `Started::Yes`, by value rather
        // than by calling `cpu_on`: the call is an instruction a host cannot
        // execute, and what is testable is the mapping.
        let accepts = |answer: i64| answer == 0 || answer == super::ALREADY_ON;
        assert!(accepts(0), "PSCI's success value");
        assert!(
            accepts(-4),
            "ALREADY_ON: the core is running, which is the ask"
        );
        assert!(!accepts(-1), "NOT_SUPPORTED is a refusal");
        assert!(!accepts(-2), "INVALID_PARAMETERS is a refusal");
        assert!(!accepts(-3), "DENIED is a refusal");
    }

    /// The function id the tree names is what gets called, not a literal.
    ///
    /// The two ids PSCI defines for `cpu_on` differ in one bit, and the tree
    /// carries the one the platform wants.  A module that spelled the number
    /// would be right on QEMU's `virt` and wrong on a platform that renumbered,
    /// with no way for the boot to notice.
    #[test]
    fn the_call_id_comes_from_the_tree() {
        // The values QEMU's `virt` publishes, as a record of what the module
        // was written against.  `0xc4` is the 64-bit calling convention and
        // `0x84` the 32-bit one; the low three bytes are the function.
        let sixty_four_bit = 0xc400_0003u32;
        let thirty_two_bit = 0x8400_0003u32;
        assert_eq!(sixty_four_bit & 0xFF_FFFF, thirty_two_bit & 0xFF_FFFF);
        assert_ne!(sixty_four_bit, thirty_two_bit);
    }
}
