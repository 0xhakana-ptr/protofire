//! security/src/lib.rs
//!
//! Identities, the token a request runs as, and the MAC policy that labels
//! subjects and objects.
//!
//! ## Where this sits
//!
//! Below both the process layer and the filesystem.  The filesystem has to know
//! who is asking before it answers a read, and the process layer has to decide
//! what a token may do; neither should have to name the other to ask, which is
//! what this crate is: the question, the answer, and the label on both sides.
//!
//! ## What it names
//!
//! `abi` for the error type, `rights` for the handle flags it re-exports, and
//! `sync` for the policy's lock.  Not the kernel, and not the audit layer: a
//! denial is reported through a sink (`mac::set_sink`) because a security
//! decision should not have to know how to find the current process in order to
//! say that it denied something.  A comment claiming that while the code
//! reaches for the process is the mismatch this arrangement removes.
//!
//! ## Tests
//!
//! The policy's decisions, in `mac/tests.rs`: which label may read which path,
//! what an unlabelled object falls back to, and that a denial reaches the sink
//! that was installed.

#![no_std]

extern crate alloc;

// The MAC tests use `std`'s `Mutex` to serialise themselves: the policy is one
// process-wide value, so two tests that each install a rule set would decide
// against each other's.  A test build is not the kernel, and a `no_std` crate
// can still link `std` in its test configuration, which is what the previous
// tree relies on for the same file.
#[cfg(test)]
extern crate std;

pub mod mac;
pub mod token;

pub use mac::MAC_TYPE_SYSTEM;
pub use mac::MAC_TYPE_UNTRUSTED;
pub use mac::MAC_TYPE_USER;
pub use mac::MacType;
pub use token::DEFAULT_GUEST_GROUP_ID;
pub use token::DEFAULT_GUEST_USER_ID;
pub use token::GroupId;
pub use token::IntegrityLevel;
pub use token::ROOT_GROUP_ID;
pub use token::ROOT_USER_ID;
pub use token::SecurityToken;
pub use token::UserId;
