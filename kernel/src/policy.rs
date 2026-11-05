//! kernel/src/policy.rs
//!
//! The MAC policy, asked both ways through the real handler.
//!
//! ## Why this goes through `open` and not through `check_file`
//!
//! The first version of this called `check_file` directly.  Deleting the check
//! from the `open` handler changed no output at all: the probe was testing the
//! policy, which was already known to work, and not the **wiring**, which is
//! the only thing in question.
//!
//! So both cases here are `open` calls through the installed registry, with the
//! one field that differs being the caller's identity.  Deleting the check
//! makes the untrusted open succeed, the boot prints `MISPOLICED`, and the gate
//! goes red — which is the property the line is for.

use crate::volume::BOOT_VOLUME_LABEL;

/// The path the policy is asked about, and the one the boot reads.
const BOOT_GREETING_PATH: &str = "/greeting.txt";

/// Enable the policy, install one rule, and make `open` decide both ways.
///
/// The rule is installed for `MAC_TYPE_UNLABELED`, which is what
/// `object_type_for_path` answers for a path under no labelled prefix on this
/// boot's volume.  That is not a guess: `security/src/mac/check.rs` falls back
/// to unlabelled for anything outside `/system`, `/apps`, `/data`, `/dev` and
/// `/tmp`.
pub fn exercise() {
    use security::mac;

    // One rule: the system label may read an unlabelled file.
    {
        let mut state = mac::policy_state().lock();
        state.policy.add_rule(
            mac::MacRule {
                subject: mac::MAC_TYPE_SYSTEM,
                object: mac::MAC_TYPE_UNLABELED,
                class: mac::MAC_CLASS_FILE,
                perms: mac::MAC_PERM_READ,
            },
            true,
        );
        state.policy.enabled = true;
    }

    let (rules, labels) = {
        let state = mac::policy_state().lock();
        (state.policy.rule_count(), state.label_count())
    };
    arch::serial::write_str("protofire: mac policy enabled, ");
    arch::serial::write_u32(rules as u32);
    arch::serial::write_str(" rule(s), ");
    arch::serial::write_u32(labels as u32);
    arch::serial::write_str(" label(s)\n");

    // The same open twice, differing only in who is asking.
    for (identity, expected, name) in [
        (mac::MAC_TYPE_SYSTEM, true, "system"),
        (mac::MAC_TYPE_UNTRUSTED, false, "untrusted"),
    ] {
        let outcome = open_as(identity);
        arch::serial::write_str("protofire: mac ");
        arch::serial::write_str(match outcome {
            true if expected => "allowed ",
            false if !expected => "denied ",
            _ => "MISPOLICED ",
        });
        arch::serial::write_str(name);
        arch::serial::write_str(" read of ");
        arch::serial::write_str(BOOT_GREETING_PATH);
        arch::serial::write_str("\n");
    }

    // The label is named here rather than in the caller because the line above
    // reports it; keeping the constant beside its one use is what stops it from
    // drifting into a second copy.
    let _ = BOOT_VOLUME_LABEL;
}

/// Open the boot's file as `identity`, answering whether it was allowed.
///
/// Through the installed registry and the real handler, so the answer covers
/// the policy **and** the decision to consult it.  The descriptor is closed
/// again, because a probe that leaked one would make the boot's own read fail
/// for a reason that is this function's.
fn open_as(identity: u32) -> bool {
    use crate::syscall::Arguments;
    use ::syscall::SyscallContext;

    let mut context = SyscallContext::new(
        ::syscall::SyscallNumber::Open as usize,
        [0, abi::fs::OPEN_FLAG_READ, 0, 0, 0, 0],
    )
    .with_identity(identity);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some(BOOT_GREETING_PATH),
        buffer: None,
    };

    match crate::syscall::serve(&mut arguments) {
        Some(Ok(dispatch)) => {
            let mut context = SyscallContext::new(
                ::syscall::SyscallNumber::Close as usize,
                [dispatch.value, 0, 0, 0, 0, 0],
            );
            let mut arguments = Arguments::plain(&mut context);
            let _ = crate::syscall::serve(&mut arguments);
            true
        }
        _ => false,
    }
}
