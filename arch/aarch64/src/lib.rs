//! arch/aarch64/src/lib.rs
//!
//! The aarch64 machine, as far as the kernel can ask it anything today.
//!
//! This crate is a sibling of `arch/x86_64` and the two share no code: what
//! they share is the *names* the kernel calls, which is the whole interface.
//! A machine's differences are allowed to be large; the point of the split is
//! that the rest of the tree never learns which ones they are.
//!
//! ## No crate-level architecture gate
//!
//! The first version of this file had `#![cfg(target_arch = "aarch64")]`, so
//! that `cargo build --workspace`, which builds every member for the host, //!
//! would not try to assemble `wfi` into an x86 binary.  What that also did was
//! make the whole crate empty on a host, *including its tests*:
//! `cargo test -p arch_aarch64` reported zero, and every assertion in
//! `interrupts.rs` was dead code that had never been compiled once.
//!
//! A gate that makes a build succeed by removing the code is the wrong tool.
//! Each module keeps its own `cfg(target_os)` arms instead: a host has no
//! `DAIF` and no `wfi`, so those arms are no-ops a test can still run, and the
//! crate stays compilable wherever it is named.

#![no_std]

// The host arm of the console records bytes instead of writing a port.
#[cfg(not(target_os = "none"))]
extern crate alloc;

// The entry: the stack, the bss clear, the drop to EL1 and the vector table.
//
// Here rather than in `bootloader` for the reason the x86_64 entry is: every
// instruction is a fact about this machine, and the protocol crate is not the
// machine.
#[cfg(target_os = "none")]
core::arch::global_asm!(include_str!("entry.S"));

pub mod boot;
pub mod gic;
pub mod gicv2m;
pub mod interrupts;
pub mod paging;
pub mod port;
pub mod program;
pub mod serial;
pub mod timer;
pub mod trap;

pub use program::PIPE_READER;
pub use program::PIPE_WRITER;
pub use program::PROGRAM_LEN;
pub use program::SLEEP_MICROSECONDS;
pub use program::program_bytes;
pub use trap::CallFrame;
pub use trap::CallOutcome;
pub use trap::Context;
#[cfg(target_os = "none")]
pub use trap::install_context;
pub use trap::is_user_context;
pub use trap::resume_address;
pub use trap::return_state;
pub use trap::return_value;
#[cfg(target_os = "none")]
pub use trap::set_call_sink;
#[cfg(target_os = "none")]
pub use trap::set_preempt_sink;
pub use trap::set_resume_address;
pub use trap::set_return_value;
pub use trap::stack_pointer;
pub use trap::starting_context;
pub mod vbar;

/// Stop this CPU until an interrupt arrives.
///
/// `wfi` is the wait-for-interrupt hint, and the loop around it is what makes
/// the function `-> !`: an interrupt that returns here would fall into whatever
/// follows, and there is nothing after a stop.
///
/// A host has no `wfi`.  The no-op arm does not loop, which would be a spin,
/// /// it stops the process the way the real one stops the core, so a test that
/// calls it returns rather than hanging.  That difference is the honest one:
/// this is the only function in the crate a test has no reason to call, and a
/// test build that hung would be worse than one that did not run it.
#[cfg(target_os = "none")]
pub fn halt() -> ! {
    loop {
        // SAFETY: `wfi` is a hint that permits the core to enter a low-power
        // state until an interrupt is pending.  On this kernel's paths the DAIF
        // mask is set, so no interrupt is taken and the loop does not exit.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
    }
}

/// The host build's stop: end the process, because a host has no core to idle.
///
/// Only reachable from a test, and only if one calls it deliberately.
#[cfg(not(target_os = "none"))]
pub fn halt() -> ! {
    panic!("halt() called on a host: this is the kernel's stop, not a test's")
}

/// Stop the core until an interrupt arrives, leaving interrupts enabled.
///
/// `wfi` is the wait-for-interrupt hint.  `halt` masks interrupts first and is
/// the machine's final stop; this one is the idle a scheduler uses when every
/// program is asleep, so it returns as soon as the timer has something to say.
///
/// ## Why there is no unmask here
///
/// x86_64 needs `sti` before its `hlt` because a supervisor call arrives
/// through an interrupt gate, which clears the flag.  aarch64's exception
/// entry restores `PSTATE` from `SPSR_EL1` on the way out and masks nothing on
/// the way in for this path, so there is no flag to set, and `wfi` returns
/// when an interrupt is pending whether or not one is masked at the time.
///
/// A host has no `wfi` and no interrupt to wait for, so the host arm returns
/// immediately; a test that called it in a loop would spin, which is the one
/// thing its caller must not rely on.
#[cfg(target_os = "none")]
pub fn wait_for_a_wakeup() {
    // ## Why this unmasks
    //
    // The same reason x86_64's `sti; hlt` does, in this machine's words.  A
    // supervisor call arrives through an exception, and `entry.S` masks `IRQ`
    // on the way in, so the kernel runs with interrupts off for the whole of
    // a served call, and a wait that did not unmask them never takes the tick
    // that would end it.  `wfi` alone then returns immediately for ever: it is
    // a hint about the core's power state, not an enable.
    //
    // `msr daifclr, #2` clears the `I` bit.  The trap path's `eret` puts the
    // program's `PSTATE` back, so this mask does not outlive the call.
    //
    // SAFETY: `daifclr` is unprivileged at EL1.  `wfi` is a hint that permits
    // the core to enter a low-power state until an interrupt is pending; with
    // `I` clear, a pending one wakes it.
    unsafe {
        core::arch::asm!("msr daifclr, #2", options(nomem, nostack));
        core::arch::asm!("wfi", options(nomem, nostack));
    };
}

/// The host build: nothing to wait for.
#[cfg(not(target_os = "none"))]
pub fn wait_for_a_wakeup() {}

/// Install the exception vector table, and prove it delivers.
///
/// Returns whether this machine will now take an exception through
/// [`trap::aarch64_exception_dispatch`].  The table itself is `entry.S`'s, ///
/// sixteen entries that record their index in `x16` and branch to one common
/// save/restore path, and this installs the register that names it.
///
/// The answer is not "the register was written".  A register written and never
/// exercised is the recurring defect in this tree: code that is written, wired,
/// and never executed.  So [`trap::install_table`] raises a supervisor call
/// from EL1 after installing, and the supervisor call has to arrive at entry 4
/// and return.  That exercises the save, the restore, the vector numbering, the
/// sink and the `eret` in one go, and the frame's offsets are what the return
/// path restored, a frame laid out wrong would return into garbage instead of
/// returning at all.
///
/// It runs here rather than in a separate probe because it needs nothing the
/// boot has not done: the stack is up, the console is up, and the sink is
/// installed by the caller immediately before.
///
/// # Safety
///
/// Called once, after [`set_interrupt_dispatch`], before the kernel enables
/// interrupts.  It writes `VBAR_EL1` and executes one `svc`, which the machine
/// takes as an exception; that is safe at EL1 with the kernel's stack valid and
/// not safe anywhere else.
#[cfg(target_os = "none")]
pub unsafe fn install_interrupt_table() -> bool {
    // SAFETY: the caller's contract is this function's, once, with the sink
    // installed and the stack valid.
    let installed = unsafe { trap::install_table() };
    if !installed {
        return false;
    }

    // And the controller, which is what turns a vector into an interrupt.
    //
    // A vector table with no controller behind it takes exceptions the kernel
    // raises and nothing a device raises: the machine has a way to arrive and
    // no way to be called.  This is the half the boot line was reporting as
    // "installed" while a device's line went nowhere.
    let Some((distributor, cpu)) = boot::interrupt_controller() else {
        return true;
    };

    let gic = gic::Gic::new(distributor, cpu);
    // SAFETY: the two windows are the ones a `arm,cortex-gic` node describes,
    // and the boot mapped the region below four gigabytes as device memory
    // already.  Called once, on this CPU.
    unsafe {
        gic.enable();
        trap::set_controller(gic);
    }
    true
}

/// The machine's message-signalled interrupt frame, probed.
///
/// `None` when the tree names no frame.  The two numbers this answers are the
/// ones `MSI_TYPER` holds, read from the register, not assumed, so a caller
/// learns which interrupts the frame can raise rather than inheriting a guess.
///
/// # Safety
///
/// Called after the page table maps the GIC's region as device memory.
#[cfg(target_os = "none")]
pub unsafe fn message_frame() -> Option<gicv2m::Frame> {
    let base = boot::msi_frame()?;
    // SAFETY: `base` is the `arm,gic-v2m-frame` window the tree named.
    Some(unsafe { gicv2m::Frame::probe(base) })
}

/// The exception level a program runs at.
///
/// Named because it appears in `SPSR_EL1`'s `M` field, and a bare `0b0000` in
/// that field is a value a reader has to decode every time.
pub const USER_EXCEPTION_LEVEL: u64 = 0;

/// `SPSR_EL1` for a return to EL0.
///
/// The `M` field is `0b0000`, EL0t, the only state a program runs in, and the
/// DAIF bits are set, so a program does not take an interrupt directly.  A
/// program that could would be one taking an exception the kernel has no frame
/// for.
///
/// Bit 9 (`D`) is set rather than clear for a reason worth naming: with it
/// clear at EL0, a program's debug exception would arrive on a vector the
/// kernel installed for something else.  This kernel has no debugger to attach,
/// so the mask is the honest setting.
pub const SPSR_EL0T: u64 = 0x340;

/// Enter EL0 at `entry` with the stack at `stack_top`.
///
/// ## What this does that nothing else in this tree did
///
/// Everything up to here runs at EL1.  Returning to a lower exception level is
/// an `eret` with `SPSR_EL1` naming EL0 and `ELR_EL1` naming where in the
/// program to start, the same instruction the trap path already ends with,
/// pointed somewhere new.  What made it impossible before is not the
/// instruction: it is that no mapping was `user` and no frame carried a
/// program.
///
/// ## Why it does not return
///
/// Control does not come back here.  The program returns to the kernel through
/// a trap, a syscall or an exit, and the trap path is what resumes the
/// kernel.  A function that "returned" would be claiming a program can finish
/// without trapping, which it cannot: EL0 has no way out except an exception.
///
/// # Safety
///
/// `entry` must be a virtual address mapped `user` and executable, `stack_top`
/// must be a `user`-accessible page's end, and the caller must have no live
/// state on the kernel stack that an exception could not restore, the trap
/// path builds its own frame and resumes through it.
/// Enter EL0 with a context, which is the form a scheduler has.
///
/// `enter_user` takes the two numbers a first program needs; this takes the
/// whole frame, which is what a scheduler builds and what `eret` restores.
///
/// # Safety
///
/// As [`enter_user`].
///  ## Why interrupts are masked across this
///
///  The three `msr`s and the `eret` are one transaction, and a timer tick
///  between them destroys it.  An exception taken here is taken at EL1, so
///  `entry.S` saves the interrupted `ELR_EL1`/`SPSR_EL1` **and restores them
///  on the way out**, clobbering the entry this function just wrote.  The
///  `eret` then returns to whatever address the tick interrupted, which is
///  inside this very function, and it does so at EL0 because the `spsr` was
///  rewritten to EL0t again.  The machine takes an instruction abort on a
///  kernel address from ring 3.
///
///  That is not hypothetical: it is what `unhandled exception 8 (ec 32,
///  instruction abort) at 0x400c92a0` was, at one to four thousand ticks a
///  second, and the address moved with whichever `msr` the tick landed after.
///
///  `daifset` masks IRQ, and `eret` needs no matching unmask: it loads PSTATE
///  from `SPSR_EL1`, which names EL0t with `I` clear, so the program is
///  entered with interrupts enabled again.  The mask covers this window and
///  nothing else.
#[cfg(target_os = "none")]
pub unsafe fn enter_user_with_context(context: &Context) -> ! {
    // SAFETY: the caller's contract is `enter_user`'s.
    unsafe {
        core::arch::asm!(
            "msr daifset, #2",
            "msr elr_el1, {entry}",
            "msr sp_el0, {stack}",
            "msr spsr_el1, {spsr}",
            "isb",
            "eret",
            entry = in(reg) context.elr,
            stack = in(reg) context.registers[0],
            spsr = in(reg) context.spsr,
            options(noreturn)
        )
    }
}

/// Enter EL0 at `entry` with the stack at `stack_top`.
///
/// # Safety
///
/// `entry` must be a virtual address mapped `user` and executable, `stack_top`
/// must be a `user`-accessible page's end, and the caller must have no live
/// state on the kernel stack that an exception could not restore, the trap
/// path builds its own frame and resumes through it.
#[cfg(target_os = "none")]
pub unsafe fn enter_user(entry: usize, stack_top: usize) -> ! {
    // SAFETY: the caller promises the two addresses are mapped for EL0.  The
    // `eret` is the architecture's own return-to-lower-EL instruction, and
    // `isb` is what makes the system-register writes visible to it.
    // Interrupts masked for the three `msr`s and the `eret`; see
    // `enter_user_with_context` for why a tick in this window sends the program
    // to a kernel address.  `eret` restores the mask from `SPSR_EL1`.
    unsafe {
        core::arch::asm!(
            "msr daifset, #2",
            "msr elr_el1, {entry}",
            "msr sp_el0, {stack}",
            "msr spsr_el1, {spsr}",
            "isb",
            "eret",
            entry = in(reg) entry as u64,
            stack = in(reg) stack_top as u64,
            spsr = in(reg) SPSR_EL0T,
            options(noreturn)
        )
    }
}

/// Translate through a different root table from now on.
///
/// ## What this does not do
///
/// It writes `TTBR0_EL1` and flushes and nothing else.  The **caller** must be
/// running through a mapping both tables share, because the next instruction
/// fetch happens through the new one: a switch made from an address only the
/// old table maps faults on the instruction after the write.
///
/// That is why this kernel's program roots copy the kernel's entry 0, the
/// kernel's code, its stack and the trap vectors are reachable through every
/// root, so a switch can happen anywhere in the kernel and the trap path does
/// not have to be careful about where it is.
///
/// ## Why no ASID
///
/// An address-space identifier would let two roots' translations coexist in the
/// TLB and remove the flush.  It also has to be allocated, kept unique and
/// cleared at the right moment, and this kernel has one CPU and a switch per
/// scheduling decision.  The flush is the cheap correct answer; the identifier
/// is the optimisation that needs a reason to exist first.
///
/// # Safety
///
/// `root` must be a page-aligned root table whose entry 0 maps every address
/// the kernel is running on, its text, its stack and the vectors, because the
/// next fetch happens through it.
#[cfg(target_os = "none")]
pub unsafe fn switch_address_space(root: usize) -> bool {
    // SAFETY: the caller promises the new root covers the code performing this
    // call.  The barriers are the ones the architecture requires around a
    // change to translation.
    unsafe {
        core::arch::asm!("msr ttbr0_el1, {}", in(reg) root as u64, options(nostack));
        core::arch::asm!("dsb sy", options(nostack));
        core::arch::asm!("tlbi vmalle1", options(nostack));
        core::arch::asm!("dsb sy", options(nostack));
        core::arch::asm!("isb", options(nostack));
    }
    paging::current_root_table() == root
}

/// The generic timer's frequency, or `None` when the machine does not report
/// one.
///
/// # Safety
///
/// Reads a system register; no side effects.
#[cfg(target_os = "none")]
pub unsafe fn timer_frequency() -> Option<u64> {
    // SAFETY: the caller's contract is this function's.
    unsafe { timer::frequency() }
}

/// The monotonic clock's rate.
///
/// The same register `timer_frequency` reads, and the same number: this
/// machine's counter and its timer are one clock, which x86_64's are not.
///
/// # Safety
///
/// Reads a system register; no side effect.
#[cfg(target_os = "none")]
pub unsafe fn clock_frequency() -> Option<u64> {
    // SAFETY: the caller's contract is this function's.
    unsafe { timer::frequency() }
}

/// The counter's current value.
///
/// # Safety
///
/// Reads a system register; no side effects.
#[cfg(target_os = "none")]
pub unsafe fn timer_counter() -> u64 {
    // SAFETY: the caller's contract is this function's.
    unsafe { timer::counter() }
}

/// Arm the timer to fire `milliseconds` from now.
///
/// # Safety
///
/// Called after the timer's interrupt line is enabled in the controller: a
/// timer whose line is not enabled counts and tells nobody.
#[cfg(target_os = "none")]
pub unsafe fn arm_timer(frequency: u64, microseconds: u64) -> u64 {
    let ticks = timer::ticks_for_microseconds(frequency, microseconds);
    // SAFETY: the caller's contract is this function's.
    unsafe { timer::arm(ticks) };
    ticks
}

/// Stop the timer.
///
/// # Safety
///
/// As [`arm_timer`].
#[cfg(target_os = "none")]
pub unsafe fn disarm_timer() {
    // SAFETY: the caller's contract is this function's.
    unsafe { timer::disarm() };
}

/// How many of this machine's timer ticks are `microseconds` long.
///
/// The same question x86_64 answers for its APIC timer: a deadline is a counter
/// reading, and the conversion from a duration is the machine's because the
/// counter's rate is.
pub const fn ticks_for_microseconds(frequency: u64, microseconds: u64) -> u64 {
    timer::ticks_for_microseconds(frequency, microseconds)
}

/// The timer's control register, as it reads after arming.
///
/// A timer that was "armed" and never fires is one whose control register did
/// not keep the write, and the register is the only thing that says which
/// happened.
///
/// # Safety
///
/// Reads a system register; no side effects.
#[cfg(target_os = "none")]
pub unsafe fn timer_control() -> u64 {
    // SAFETY: the caller's contract is this function's.
    unsafe { timer::control() }
}

/// Whether the timer has fired since it was last armed.
///
/// # Safety
///
/// Reads a system register; no side effects.
#[cfg(target_os = "none")]
pub unsafe fn timer_fired() -> bool {
    // SAFETY: as `timer_frequency`.
    unsafe { timer::has_fired() }
}

/// The line a boot raises to prove the interrupt path.
///
/// Zero, because `GICD_SGIR` generates software interrupts 0..15 and nothing
/// above them, a device's line is raised by its device, and the only line this
/// controller can be *asked* for is one of the sixteen.
pub const fn test_interrupt() -> usize {
    0
}

/// The timer's interrupt as a private interrupt number.
pub const fn timer_interrupt() -> usize {
    timer::TIMER_INTERRUPT
}

/// Raise one interrupt from the controller, as a device would.
///
/// Answers whether this machine has a controller that can do it.  It is the
/// only way a boot can prove the path from the distributor to a handler without
/// waiting on hardware that may never speak: a device raises its line when it
/// has something to say, and there is no way to ask it to.
///
/// # Safety
///
/// Called after [`install_interrupt_table`] and after the line was enabled with
/// [`enable_interrupt_line`], with a handler that will finish it.
#[cfg(target_os = "none")]
pub unsafe fn raise_interrupt(number: usize) -> bool {
    let Some((distributor, cpu)) = boot::interrupt_controller() else {
        return false;
    };
    let gic = gic::Gic::new(distributor, cpu);
    // SAFETY: the caller's contract is this function's.
    unsafe { gic.raise(number) }
}

/// Whether the controller kept the enable bit for `number`.
///
/// Reads the distributor back rather than trusting the write: a line enabled in
/// a register that did not keep it is a line that never arrives, and the two
/// states are indistinguishable from the caller's side.
///
/// # Safety
///
/// As [`enable_interrupt_line`].
#[cfg(target_os = "none")]
pub unsafe fn interrupt_line_enabled(number: usize) -> bool {
    let Some((distributor, _)) = boot::interrupt_controller() else {
        return false;
    };
    let gic = gic::Gic::new(distributor, distributor);
    // SAFETY: the caller's contract is this function's.
    unsafe { gic.line_is_enabled(number) }
}

/// Enable one of the machine's interrupt lines.
///
/// Answers whether the machine has a controller that can route it.  A line a
/// device raises is only delivered once this has been called for its number,
/// and a driver that enabled its own device but not its line is one that waits
/// forever for an interrupt the machine is not forwarding.
///
/// # Safety
///
/// Called after [`install_interrupt_table`], once per line, before the device
/// that raises it is told to start signalling.
#[cfg(target_os = "none")]
pub unsafe fn enable_interrupt_line(number: usize) -> bool {
    let Some((distributor, cpu)) = boot::interrupt_controller() else {
        return false;
    };
    let gic = gic::Gic::new(distributor, cpu);
    // SAFETY: the caller's contract is this function's, after the controller
    // is enabled, once per line.
    unsafe { gic.enable_interrupt(number) }
}

/// Install the sink a trap frame goes to.
///
/// The frame reaches [`trap::aarch64_exception_dispatch`], which calls this
/// sink and stops the machine when it answers `false`.  Installing one is what
/// makes an exception observable rather than a silent `wfe`, which is exactly
/// what this machine's first boot was, and why it printed four lines and
/// stopped with nothing after them.
///
/// # Safety
///
/// The caller promises to call this once, before any vector can be raised.  The
/// function must not allocate, block, or enable interrupts: it runs on the
/// kernel stack the exception found.
#[cfg(target_os = "none")]
pub unsafe fn set_interrupt_dispatch(sink: fn(irq::Frame) -> bool) {
    // SAFETY: passed through to the module that owns the static; the caller's
    // promise is the same one that function states.
    unsafe { trap::set_sink(sink) };
}

/// There is no descriptor table on this machine.
///
/// A vector table is an address in `VBAR_EL1`, not a table of descriptors plus
/// a task state segment: the architecture has no ring transition that needs a
/// stack the CPU finds for itself, so `false` is the honest answer and a boot
/// that reports it is reporting a fact about the machine.
///
/// # Safety
///
/// Called once, with the console up.  Nothing is touched.
#[cfg(target_os = "none")]
pub unsafe fn install_descriptor_tables(_interrupt_stack_top: usize) -> bool {
    false
}

/// Where an interrupt from a lower exception level lands.
///
/// This machine has no TSS: an exception taken from EL0 uses the kernel stack
/// the exception was taken on, and the vector table needs no stack pointer of
/// its own.  `0` is the answer a caller that checks it will find unremarkable.
#[cfg(target_os = "none")]
pub fn interrupt_stack_top() -> usize {
    0
}

/// Start this machine's other cores: this machine starts none.
///
/// A device-tree machine wakes a secondary core through PSCI, the firmware
/// call its tree names in the `psci` node's `cpu_on` function, but this
/// machine's boot reads no PSCI node and has no secondary entry to name, so
/// the honest answer is zero: a machine with more than one core runs one,
/// and a count without a path behind it is the claim this tree's boot lines
/// exist to refuse.
///
/// # Safety
///
/// As the riscv64 arm: called once, from the boot core, with the tables up.
/// This arm touches nothing, which keeps its half of the promise.
#[cfg(target_os = "none")]
pub unsafe fn start_secondary_harts(_timer_slice_us: u64) -> usize {
    0
}

/// The core id started into `slot`: this machine starts none, so every slot
/// is empty and the answer is zero.
pub fn secondary_hart_id(_slot: usize) -> usize {
    0
}

/// Whether the core started into `slot` came up: this machine starts none, so
/// no slot is online.
pub fn secondary_online(_slot: usize) -> bool {
    false
}

/// The cores the firmware refused to start: this machine asks for none, so
/// none were refused.
pub fn refused_harts() -> usize {
    0
}

/// Which CPU this code runs on: this machine runs one, so slot zero.
pub fn current_cpu_slot() -> usize {
    0
}

/// The machine's own id for this CPU.
///
/// This machine reads no affinity register, so the core it runs on is the one
/// the firmware booted and zero is the only id it has.  A machine that read
/// `MPIDR_EL1` would answer with it here, and the slot would stay the kernel's
/// numbering.
pub fn current_cpu_id() -> usize {
    0
}

/// Whether the trap being dispatched belongs to the CPU that owns the
/// scheduler: this machine has one CPU, so it always does.
pub fn boot_cpu_owns_this_trap() -> bool {
    true
}

/// Send an inter-processor interrupt: this machine starts no second core, so
/// there is none to send to.
///
/// # Safety
///
/// As the riscv64 arm.  This one touches nothing.
#[cfg(target_os = "none")]
pub unsafe fn send_ipi_to_others() -> bool {
    false
}

/// The kernel's source of work for a started CPU: this machine starts none, so
/// nothing ever asks and nothing is installed.
///
/// The signature exists because the kernel's boot installs it on every machine,
/// and a machine that had to omit the call would be a boot with an `if` about
/// which machine it is running on.  The same reason `install_interrupt_table`
/// answers `false` here rather than not existing.
///
/// # Safety
///
/// As the riscv64 arm: called once, before any started CPU could ask.
#[cfg(target_os = "none")]
pub unsafe fn set_work_sink(_sink: fn(usize) -> Option<(usize, Context)>) {}

/// The kernel's end-of-boot predicate: as `set_work_sink`, this machine starts
/// no CPU that could ask it.
///
/// # Safety
///
/// As the riscv64 arm.
#[cfg(target_os = "none")]
pub unsafe fn set_finished_sink(_sink: fn() -> bool) {}

/// The external interrupt controller this machine drives as a window: none.
///
/// x86_64 reaches its devices through the local APIC and an IOAPIC the boot
/// does not programme; aarch64 has a GIC whose lines arrive through its own
/// vector table rather than a claim/complete pair.  Neither is the shape this
/// question asks about, and `None` is the answer a boot reports.
#[cfg(target_os = "none")]
pub fn external_controller() -> Option<(usize, usize, usize)> {
    None
}

/// The external interrupt's number, as this machine reports it: zero, because
/// no line of this machine is delivered as a claimable external source.
pub const fn external_interrupt() -> usize {
    0
}

/// The console's interrupt source: none on this machine.
///
/// This console is write-only from the kernel's side and raises no line the
/// kernel asks for, so there is no source to claim.
#[cfg(target_os = "none")]
pub fn console_source() -> Option<usize> {
    None
}

/// Claim the console's interrupt: there is none to claim.
///
/// # Safety
///
/// As the riscv64 arm.  This one touches nothing.
#[cfg(target_os = "none")]
pub unsafe fn claim_console_source() -> Option<usize> {
    None
}

/// Acknowledge the console's interrupt: there is none.
///
/// # Safety
///
/// As the riscv64 arm.  This one touches nothing.
#[cfg(target_os = "none")]
pub unsafe fn acknowledge_console() -> bool {
    false
}

/// Silence the console's interrupt: there is none to silence.
///
/// # Safety
///
/// As the riscv64 arm.  This one touches nothing.
#[cfg(target_os = "none")]
pub unsafe fn silence_console() {}

/// Whether a source is enabled at the controller: this machine has no
/// claim/complete controller, so no source is.
///
/// # Safety
///
/// Read-only.  This one touches nothing.
#[cfg(target_os = "none")]
pub unsafe fn external_source_enabled(_number: usize) -> bool {
    false
}
