//! security/src/mac/mod.rs
//!
//! The mandatory access control policy: subject and object labels, a policy
//! table, and the decision that compares them.
//!
//! A *subject* is what asks — the label a process carries.  An *object* is what
//! is asked about — a path, a network endpoint, a process.  The policy says
//! which pairs may do what, and a denial is reported through a sink rather than
//! written into an audit record directly, so this crate does not have to know
//! how the audit layer finds the running process.

pub mod audit;
pub mod check;
pub mod policy;
pub mod types;

#[cfg(test)]
mod audit_tests;

#[cfg(test)]
mod tests;

pub use audit::Denial;
pub use audit::set_sink;
pub use check::check_file;
pub use check::check_network;
pub use check::check_process;
pub use check::object_type_for_path;
pub use check::set_path_type;
pub use check::type_name;
pub use policy::policy_state;
pub use types::MAC_CLASS_FILE;
pub use types::MAC_CLASS_NETWORK;
pub use types::MAC_CLASS_PROCESS;
pub use types::MAC_PERM_READ;
pub use types::MAC_PERM_WRITE;
pub use types::MAC_TYPE_APPS;
pub use types::MAC_TYPE_DEVICE;
pub use types::MAC_TYPE_NETWORK;
pub use types::MAC_TYPE_SYSTEM;
pub use types::MAC_TYPE_TMP;
pub use types::MAC_TYPE_UNLABELED;
pub use types::MAC_TYPE_UNTRUSTED;
pub use types::MAC_TYPE_USER;
pub use types::MacClass;
pub use types::MacPermission;
pub use types::MacRule;
pub use types::MacType;
pub use types::is_known_class;
pub use types::is_known_type;
