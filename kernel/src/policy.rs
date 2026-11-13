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
//! goes red, which is the property the line is for.

use crate::volume::BOOT_VOLUME_LABEL;

/// The path the policy is asked about, and the one the boot reads.
const BOOT_GREETING_PATH: &str = "/greeting.txt";

/// Enable the policy, install one rule granting read and write, and make
/// `open` decide both ways.
///
/// The rule is installed for `MAC_TYPE_UNLABELED`, which is what
/// `object_type_for_path` answers for a path under no labelled prefix on this
/// boot's volume.  That is not a guess: `security/src/mac/check.rs` falls back
/// to unlabelled for anything outside `/system`, `/apps`, `/data`, `/dev` and
/// `/tmp`.
///
/// The rule grants **write** as well as read, because the boot's programs do
/// more than read.  Write is what every file-creating call a program makes is
/// policed by — `open` with the create flag, the path mutations and their
/// `*At` forms all ask it.  Without it the policy's read-only rule would let
/// a program read everything and write nothing, and the first program to try
/// would have met a denial whose reason was a rule the boot never chose to
/// have.
pub fn exercise() {
    use security::mac;

    // Two rules granting two permissions each: the system label may read and
    // write an unlabelled file, and it may read and write the scratch zone.
    //
    // A rule's permission field is a set — `decision` answers allow when the
    // rule holds every permission the request asks for — so read and write
    // are one rule per object, not two that would otherwise have to be added
    // with `replace` off to avoid displacing each other: `add_rule` with
    // `replace` on removes every rule for the same subject, object and class
    // before adding, which is how a second add would have taken the read
    // rule away.
    //
    // The second object is `MAC_TYPE_TMP`, because `/tmp` is not unlabelled:
    // the layout resolves it to the scratch type, and the scratch zone is
    // the one the boot mounts *for its programs* — a policy whose system
    // label could not write the filesystem it provided for writing would
    // have every one of its programs' first writes meet a denial whose
    // reason was a rule the boot never chose to have.
    {
        let mut state = mac::policy_state().lock();
        for object in [mac::MAC_TYPE_UNLABELED, mac::MAC_TYPE_TMP] {
            state.policy.add_rule(
                mac::MacRule {
                    subject: mac::MAC_TYPE_SYSTEM,
                    object,
                    class: mac::MAC_CLASS_FILE,
                    perms: mac::MAC_PERM_READ | mac::MAC_PERM_WRITE,
                },
                true,
            );
        }
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
        second_path: None,
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
