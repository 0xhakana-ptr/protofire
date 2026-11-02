//! security/src/mac/check.rs
//!
//! MAC enforcement entry points: classify objects by path, decide access
//! against the policy, and emit an audit record on denial.

use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

use alloc::string::String;

use abi::Error;
use abi::Result;

use super::audit::Denial;
use super::policy::policy_state;
use super::types::MAC_CLASS_NETWORK;
use super::types::MAC_CLASS_PROCESS;
use super::types::MAC_TYPE_APPS;
use super::types::MAC_TYPE_DEVICE;
use super::types::MAC_TYPE_NETWORK;
use super::types::MAC_TYPE_SYSTEM;
use super::types::MAC_TYPE_TMP;
use super::types::MAC_TYPE_UNLABELED;
use super::types::MAC_TYPE_UNTRUSTED;
use super::types::MAC_TYPE_USER;
use super::types::MacClass;
use super::types::MacPermission;
use super::types::MacType;

/// Monotonic id for MAC-denial audit records.
static MAC_AUDIT_ID: AtomicU64 = AtomicU64::new(1);

/// Derive the object security type for a normalized path: an exact runtime
/// override wins first, then the layout/zone prefix, else UNLABELED.
pub fn object_type_for_path(normalized: &str) -> MacType {
    let state = policy_state().lock();
    if let Some(&t) = state.path_types.get(normalized) {
        return t;
    }
    drop(state);
    if path_is_exact_or_child_of(normalized, "/system") {
        MAC_TYPE_SYSTEM
    } else if path_is_exact_or_child_of(normalized, "/apps") {
        MAC_TYPE_APPS
    } else if path_is_exact_or_child_of(normalized, "/data") {
        MAC_TYPE_USER
    } else if path_is_exact_or_child_of(normalized, "/dev") {
        MAC_TYPE_DEVICE
    } else if path_is_exact_or_child_of(normalized, "/tmp") {
        MAC_TYPE_TMP
    } else {
        MAC_TYPE_UNLABELED
    }
}

/// Whether `path == prefix` or `path` starts with `prefix + "/"`.
fn path_is_exact_or_child_of(path: &str, prefix: &str) -> bool {
    if path == prefix {
        return true;
    }
    if let Some(rest) = path.strip_prefix(prefix) {
        return rest.starts_with('/');
    }
    false
}

/// Report a MAC denial.
///
/// The record itself is the audit layer's, and so is the question of who the
/// current actor is: this function states what was refused, in the terms the
/// decision was made in, and `set_sink` is where the kernel decides what to do
/// about it.  See `security/src/mac/audit.rs` for why this is a sink rather
/// than a direct call.
fn emit_mac_denial(
    subject: MacType,
    object: MacType,
    class: MacClass,
    perms: MacPermission,
    uid: u32,
) {
    let id = MAC_AUDIT_ID.fetch_add(1, Ordering::Relaxed);
    let _ = id; // Reserved for the sink's own numbering; see `audit::Denial`.
    super::audit::report(&Denial {
        subject,
        object,
        class,
        permissions: perms,
        uid,
    });
}

/// Decide a MAC access request.  Returns `Ok(())` when allowed (or the policy
/// is not enabled), `Err(PermissionDenied)` when denied by policy.
fn decide(
    subject: MacType,
    object: MacType,
    class: MacClass,
    perms: MacPermission,
    uid: u32,
) -> Result<()> {
    let state = policy_state().lock();
    match state.policy.decision(subject, object, class, perms) {
        Some(false) => {
            drop(state);
            emit_mac_denial(subject, object, class, perms, uid);
            Err(Error::PermissionDenied)
        }
        _ => Ok(()),
    }
}

/// Check file/directory access for `subject` against the object at `path`.
pub fn check_file(
    subject: MacType,
    normalized: &str,
    class: MacClass,
    perms: MacPermission,
    audit_uid: u32,
) -> Result<()> {
    let object = object_type_for_path(normalized);
    decide(subject, object, class, perms, audit_uid)
}

/// Check inter-process access (e.g. signal, ptrace) from `subject` to a
/// process of type `target`.
pub fn check_process(
    subject: MacType,
    target: MacType,
    perms: MacPermission,
    audit_uid: u32,
) -> Result<()> {
    decide(subject, target, MAC_CLASS_PROCESS, perms, audit_uid)
}

/// Check network capability access for `subject`.
///
/// The object is the network itself, not the subject.  A socket operation has
/// an object, and naming it is what lets a rule read as an authority rather
/// than as a self-reference; the subject-as-object pairing this replaces was a
/// placeholder from when the entry point had no caller.
pub fn check_network(subject: MacType, perms: MacPermission, audit_uid: u32) -> Result<()> {
    decide(
        subject,
        MAC_TYPE_NETWORK,
        MAC_CLASS_NETWORK,
        perms,
        audit_uid,
    )
}

/// Build a human-readable type name (for diagnostics and tests).
pub fn type_name(t: MacType) -> &'static str {
    match t {
        MAC_TYPE_SYSTEM => "system",
        MAC_TYPE_APPS => "apps",
        MAC_TYPE_USER => "user",
        MAC_TYPE_UNTRUSTED => "untrusted",
        MAC_TYPE_DEVICE => "device",
        MAC_TYPE_TMP => "tmp",
        _ => "unlabeled",
    }
}

/// The path override map (for the management syscall to insert labels).
pub fn set_path_type(normalized: &str, mac_type: MacType) {
    policy_state()
        .lock()
        .path_types
        .insert(String::from(normalized), mac_type);
}
