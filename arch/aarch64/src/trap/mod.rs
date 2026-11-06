//! arch/aarch64/src/trap/mod.rs
//!
//! What an exception arrives as, and the one path that answers it.
//!
//! ## The files
//!
//! | File | What it holds |
//! |---|---|
//! | [`frame`] | the saved state, and the offsets `entry.S` writes it at |
//! | [`dispatch`] | the vector table, the sink, the controller, the self-test |
//! | [`call`] | what a supervisor call is given and answers |
//! | [`context`] | the frame read as a scheduler's context |
//! | [`serve`] | the two paths a frame takes: a call served, an IRQ finished |
//!
//! The split follows what a reader is asking.  "What does the machine save" is
//! `frame`, "where does an exception go" is `dispatch`, and "how does a program
//! get suspended and resumed" is `context` and `serve`.

pub mod call;
pub mod context;
pub mod dispatch;
pub mod frame;
pub mod serve;

pub use call::CallFrame;
pub use call::CallOutcome;
#[cfg(target_os = "none")]
pub use call::CallSink;
#[cfg(target_os = "none")]
pub use call::PreemptSink;
#[cfg(target_os = "none")]
pub use call::set_call_sink;
#[cfg(target_os = "none")]
pub use call::set_preempt_sink;
pub use context::Context;
#[cfg(target_os = "none")]
pub use context::install_context;
pub use context::is_user_context;
pub use context::resume_address;
pub use context::return_state;
pub use context::return_value;
pub use context::set_resume_address;
pub use context::set_return_value;
pub use context::stack_pointer;
pub use context::starting_context;
pub use dispatch::SUPERVISOR_CALL_VECTOR;
#[cfg(target_os = "none")]
pub use dispatch::Sink;
pub use dispatch::USER_SUPERVISOR_CALL_VECTOR;
#[cfg(target_os = "none")]
pub use dispatch::controller;
#[cfg(target_os = "none")]
pub use dispatch::install_table;
#[cfg(target_os = "none")]
pub use dispatch::set_controller;
#[cfg(target_os = "none")]
pub use dispatch::set_sink;
pub use frame::ExceptionFrame;

#[cfg(test)]
mod tests;
