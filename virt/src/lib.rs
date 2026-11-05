//! virt/src/lib.rs
//!
//! Virtualisation: what this kernel provides to a guest, and what it needs in
//! order to be one.
//!
//! ## Two directions, and this crate is about both
//!
//! A kernel with a `virt` module is doing one of two things, and the names
//! collide often enough that this header states which:
//!
//! - **Host**, running other kernels.  A hypervisor owns the hardware, a guest
//!   does not, and the exit path from a guest to this kernel is a convention
//!   the machine defines (VMX/SVM on x86_64, EL2 on aarch64, the H-extension on
//!   riscv64).  The kernel's job here is the trap handler, the guest's memory,
//!   and the device model.
//!
//! - **Guest**, running under someone else's hypervisor.  Then the kernel is
//!   the one taking exits, and it needs to know which paravirtualised
//!   interfaces are present: a hypercall page, a shared-info structure, a
//!   paravirt clock, and the "do not touch this device, the host owns it" list.
//!
//! Both are one crate because both are the same question, "what of this
//! machine is not the machine, and who is answering for it", and two crates
//! would end up disagreeing about what a guest is.
//!
//! ## Why it names `arch`
//!
//! Every mechanism above is the architecture's: the exit reason encoding, the
//! hypercall instruction, the register a guest's state is saved in.  A
//! hypervisor written above `arch` would have to spell them, which is the edge
//! `scripts/check-arch-fanout.sh` counts to zero.  So this crate asks `arch`
//! the machine questions, and `arch` answers with values rather than with
//! instructions.
//!
//! ## What is here, today
//!
//! Nothing, and this header says so rather than letting an empty file imply a
//! decision.  Which direction is built first is not arbitrary:
//!
//! - **The guest side comes first in practice**, because a kernel that detects
//!   it is running under an emulator needs that answer before it can boot well:
//!   a machine that polls a paravirt clock it does not have waits forever on a
//!   timer that will not tick.
//!
//! - **The host side needs a trap handler**, and a trap handler needs the
//!   interrupt path to be able to return to the code that caused the trap, //!
//!   which is the scheduler's problem, so that half arrives after the scheduler
//!   does.
//!
//! Neither is written yet.  This is a header because the next change that
//! touches this crate has a place to put its argument, and a `#![no_std]`
//! one-liner is not one.

#![no_std]
