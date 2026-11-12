//! async_io/src/lib.rs
//!
//! Requests and completions: a request, a service that finishes it later, and
//! the bounded queue the completions go through.
//!
//! ## Where this is going
//!
//! This crate is the foundation of **everything is a service**: a driver, a
//! timer, a kernel thread and a user program are all things that accept a
//! request and complete it later, and one trait describes all of them.  That is
//! the part worth designing for, and it is why the request is opaque — a
//! service decides what it accepts, so a new kind of service does not extend a
//! wire format and does not have to understand operations it does not provide.
//!
//! The layer above this one is a **registry**: a name a caller can ask for, and
//! a handle it submits through.  It does not exist yet, and neither does the
//! first service that is not a byte slice.
//!
//! ## What uses this, today
//!
//! No device.  Every driver submits through `block`'s `QueuedBlockDevice` or
//! through a virtio queue of its own: a typed method per operation, a ticket
//! per request, and an `unsafe` buffer contract.  That is a working shape and
//! it is where the devices are; moving one onto this trait is what would turn
//! the idea above into a tested claim rather than a design.
//!
//! The one implementation here is
//! [`MemoryBlockService`], which is a byte slice rather than a device: its job
//! is to be the shape a driver would have.
//!
//! ## The model
//!
//! An operation is a [`Request`] that a [`Service`] accepts.  The service does
//! not run it to completion in the call, it either finishes it immediately or
//! leaves it [`Pending`](request::RequestState::Pending), and a later
//! [`Service::poll`] makes progress.  A [`Completion`] is delivered once, with
//! the request's own token so the caller can tell which submission it belongs
//! to.
//!
//! That is the whole of it, and it is deliberately smaller than an executor.
//! There is no task, no future, no runtime and no scheduler: those are what
//! *drive* a service, and a crate that also drove one could not be used by the
//! kernel (which has a scheduler) and by a test (which does not) at once.
//!
//! ## Why this is a trait and not a queue of operation codes
//!
//! The obvious design is a submission queue and a completion queue with an
//! operation code in each entry.  The previous tree has exactly that, its
//! `io_uring` syscall decodes an opcode and calls the subsystem, and it is the
//! wrong shape here because it puts the *set of operations* in the ABI.  Adding
//! one would mean extending a wire format, and every service would have to
//! understand operations it does not provide.
//!
//! Here a request is opaque to the queue.  A service decides what it accepts
//! and the crate never learns what an operation is.  The io_uring ABI stays
//! what it is, a program's view of a submission, and is translated into these
//! requests at the syscall boundary.
//!
//! ## What a service is
//!
//! Anything that accepts a request and completes it later: a disk queue, a
//! socket's read half, a timer, and, this is the part worth designing for, a
//! kernel thread or a user program.  The last two are what "everything is a
//! service" means: starting a program is a request whose completion is its exit
//! status, and it satisfies this trait the same way a disk does.
//!
//! A service that never completes anything would hang its callers, so the trait
//! has one obligation beyond its three methods: a request it accepted must
//! eventually be completed or cancelled, and [`Completion`] is the only place a
//! caller hears about either.

#![no_std]

// The queue is a `VecDeque`, and a service that completes four thousand
// requests in one call is the shape that needs one.  `alloc` rather than a
// fixed array because the ring's capacity is the caller's to choose, the
// io_uring ABI makes a program size its own, and a const-generic queue would
// have to name a maximum in this crate, which is a policy it has no basis for.
extern crate alloc;

pub mod block;
pub mod completion;

pub mod queue;
pub mod request;
pub mod service;
#[cfg(test)]
mod service_tests;

pub use block::BlockOp;
pub use block::MemoryBlockService;
pub use completion::Completion;
pub use queue::CompletionQueue;
pub use queue::SubmitError;
pub use request::CompletionStatus;
pub use request::Request;
pub use request::RequestId;
pub use request::RequestState;
pub use service::Service;
