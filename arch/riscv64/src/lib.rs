//! arch/riscv64/src/lib.rs
//!
//! The riscv64 machine, as far as the kernel can ask it anything today.
//!
//! This crate is a sibling of `arch/x86_64` and `arch/aarch64` and shares no
//! code with either: what they share is the *names* the kernel calls, which is
//! the whole interface.
//!
//! ## No crate-level architecture gate
//!
//! The first version of this file had one, so that `cargo build --workspace` —
//! which builds every member for the host — would not try to assemble `wfi`
//! into an x86 binary.  What that also did was make the whole crate empty on a
//! host, including the tests: `cargo test -p arch_aarch64` reported zero, and
//! every assertion in `interrupts.rs` was dead code that had never been
//! compiled.
//!
//! A gate that silences a build by removing the code is the wrong tool.  Each
//! module keeps its own `cfg(target_os)` arms — a host has no `satp` and no
//! `wfi`, so those arms are no-ops that a test can still run — and the crate
//! stays compilable everywhere it is named.

#![no_std]

// The host arm of the console records bytes instead of writing a port.
#[cfg(not(target_os = "none"))]
extern crate alloc;

// The entry: the global pointer, the stack, `sscratch`, the bss clear and the
// S-mode hand-off.  The trap path lives in the same file: one entry for every
// trap, because `stvec` names one address.
//
// Here rather than in `bootloader` for the reason the other machines' entries
// are: every instruction is a fact about this machine, and the protocol crate
// is not the machine.
#[cfg(target_os = "none")]
core::arch::global_asm!(include_str!("entry.S"));

pub mod boot;
pub mod interrupts;
pub mod paging;
pub mod port;
pub mod serial;
pub mod stvec;
pub mod timer;
pub mod trap;

pub use trap::CallFrame;
pub use trap::CallOutcome;
pub use trap::Context;
pub use trap::PIPE_READER;
pub use trap::PIPE_WRITER;
pub use trap::PROGRAM_LEN;
pub use trap::SLEEP_MICROSECONDS;
#[cfg(target_os = "none")]
pub use trap::install_context;
pub use trap::is_user_context;
pub use trap::program_bytes;
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

// The kernel stack a program's trap lands on.  `sscratch` holds it while a
// program runs, and the trap entry's swap turns a program's `sp` into this
// one.  The symbol is the entry assembly's, which is where the stack is
// defined — a second definition here would be a second opinion about where
// the kernel's stack is.  A `//` and not a `///`: a doc comment on an extern
// block decorates nothing.
#[cfg(target_os = "none")]
unsafe extern "C" {
    static _stack_top: u8;
}

/// Stop this CPU until an interrupt arrives.
///
/// `wfi` in S-mode waits for an interrupt.  The loop is what makes the function
/// `-> !`: a stop that returned would fall into whatever follows, and there is
/// nothing after a stop.
#[cfg(target_os = "none")]
pub fn halt() -> ! {
    loop {
        // SAFETY: `wfi` is the wait-for-interrupt hint.  `sstatus.SIE` is clear
        // on every path that reaches here, so no interrupt is taken and the
        // loop does not exit.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
    }
}

/// The host build's stop: end the process, because a host has no hart to idle.
#[cfg(not(target_os = "none"))]
pub fn halt() -> ! {
    panic!("halt() called on a host: this is the kernel's stop, not a test's")
}

/// Stop the core until an interrupt arrives, leaving interrupts enabled.
///
/// ## Why this zeroes `sscratch` first
///
/// The trap entry tells "a program's trap" from "the kernel's own" by whether
/// the `sscratch` swap produced a stack.  While a program runs, `sscratch`
/// parks the program's `sp` — and a tick taken inside this window is the
/// **kernel's own** trap, which that parked value would misroute onto the
/// program's stack.  The value is not lost: the frame the trap already built
/// carries it, and the return path re-arms `sscratch` from the frame it
/// resumes.  What the zero buys is that a nested tick is routed as what it is.
///
/// ## Why this unmasks
///
/// The same reason x86_64's `sti; hlt` does, in this machine's words.  A
/// program's trap arrives with `SIE` cleared by the hardware, so the kernel
/// runs with interrupts masked for the whole of a served call, and a wait that
/// did not unmask them never takes the tick that would end it.  `wfi` alone
/// then returns for every reason but the right one: it is a hint, not an
/// enable.
///
/// The `csrci` after puts the mask back, and the `sret` that eventually leaves
/// this trap restores the interrupted state anyway — the mask covers the wait
/// and nothing else.
#[cfg(target_os = "none")]
pub fn wait_for_a_wakeup() {
    // SAFETY: three supervisor CSR writes and a hint instruction, from S-mode.
    // `sscratch` is re-armed by the trap return path, the enable is paired
    // with the disable below, and `wfi` stops the hart until an interrupt is
    // pending.
    unsafe {
        core::arch::asm!("csrw sscratch, x0", options(nomem, nostack));
        core::arch::asm!("csrsi sstatus, 2", options(nomem, nostack, preserves_flags));
        core::arch::asm!("wfi", options(nomem, nostack));
        core::arch::asm!("csrci sstatus, 2", options(nomem, nostack, preserves_flags));
    };
}

/// The host build: nothing to wait for.
#[cfg(not(target_os = "none"))]
pub fn wait_for_a_wakeup() {}

/// Install the trap vector.
///
/// Returns whether one was installed, which on this machine means whether the
/// register kept the write — the entry assembly exists and `stvec` can name
/// it.  There is no self-test `ecall` here, and the absence is not an
/// omission: an `ecall` from S-mode is the firmware's door, the same
/// instruction that arms the timer, and raising one as a probe would be a
/// request to OpenSBI rather than a trap into this kernel.  The line the boot
/// proves the path with is the software interrupt, which this machine raises
/// itself.
///
/// # Safety
///
/// Called once, with the sink already installed and the console up.
#[cfg(target_os = "none")]
pub unsafe fn install_interrupt_table() -> bool {
    // SAFETY: the caller's contract is this function's — once, with the sink
    // installed and the stack valid.
    unsafe { trap::install_table() }
}

/// Install the sink a trap frame goes to.
///
/// # Safety
///
/// The caller promises to call this once, before any vector can be raised.
#[cfg(target_os = "none")]
pub unsafe fn set_interrupt_dispatch(sink: fn(irq::Frame) -> bool) {
    // SAFETY: passed through to the module that owns the static; the caller's
    // promise is the same one that function states.
    unsafe { trap::set_sink(sink) };
}

/// Enable one of the machine's interrupt lines.
///
/// The two lines this machine has are the supervisor timer's and the
/// supervisor software one, and both are bits in `sie` rather than registers
/// in a controller — the enable is a CSR write, which is what makes it cheap
/// and also what makes it per-line.  Anything else is a line this crate does
/// not drive, and `false` is the answer a caller reports rather than a gap it
/// works around.
///
/// # Safety
///
/// After [`install_interrupt_table`], once per line.
#[cfg(target_os = "none")]
pub unsafe fn enable_interrupt_line(number: usize) -> bool {
    match number {
        trap::TIMER_INTERRUPT => {
            // SAFETY: setting the timer's enable bit in `sie` — the line the
            // caller is turning on.
            unsafe { set_sie_bit(timer::ENABLE_TIMER) };
            true
        }
        trap::SOFTWARE_INTERRUPT => {
            // SAFETY: setting the software line's enable bit, which the
            // self-test raises on demand.
            unsafe { set_sie_bit(1 << trap::SOFTWARE_INTERRUPT) };
            true
        }
        _ => false,
    }
}

/// Set one bit of `sie`, the register that gates this mode's interrupts.
///
/// # Safety
///
/// Called once per line, from [`enable_interrupt_line`].
#[cfg(target_os = "none")]
unsafe fn set_sie_bit(bit: u64) {
    // SAFETY: a CSR set of the caller's own enable bit; no memory effects.
    unsafe {
        core::arch::asm!("csrs sie, {}", in(reg) bit, options(nomem, nostack));
    }
}

/// Whether a line's enable bit is set, read back rather than remembered.
///
/// # Safety
///
/// Read-only.
#[cfg(target_os = "none")]
pub unsafe fn interrupt_line_enabled(number: usize) -> bool {
    let sie: u64;
    // SAFETY: a read-only CSR read; no side effect.
    unsafe {
        core::arch::asm!(
            "csrr {}, sie",
            out(reg) sie,
            options(nomem, nostack, preserves_flags)
        )
    };
    match number {
        trap::TIMER_INTERRUPT => sie & timer::ENABLE_TIMER != 0,
        trap::SOFTWARE_INTERRUPT => sie & (1 << trap::SOFTWARE_INTERRUPT) != 0,
        _ => false,
    }
}

/// Raise one interrupt from the machine, as a device would.
///
/// The one line this machine can be *asked* for is its software interrupt:
/// `sip`'s own bit, which S-mode may set on itself.  A timer's fire is a
/// deadline, not a raise, and an external interrupt belongs to a device.
/// Unlike a GIC's software interrupts — whose enable bits reset set — this
/// line's enable resets clear, so the raise includes it: a line that can be
/// raised on demand must be deliverable on demand.
///
/// # Safety
///
/// Called after [`install_interrupt_table`] and with the sink installed.
#[cfg(target_os = "none")]
pub unsafe fn raise_interrupt(number: usize) -> bool {
    if number != trap::SOFTWARE_INTERRUPT {
        return false;
    }
    // SAFETY: the caller's contract is this function's.
    unsafe { enable_interrupt_line(number) };
    // SAFETY: setting the pending bit of the line this machine raises on
    // itself; the trap is taken as soon as the hart is able.
    unsafe {
        core::arch::asm!(
            "csrs sip, {}",
            in(reg) (1u64 << trap::SOFTWARE_INTERRUPT),
            options(nomem, nostack)
        )
    };
    true
}

/// The machine's message-signalled interrupt frame: none this crate drives.
///
/// A PLIC is a level controller a hart claims through, and an IMSIC — the
/// AIA's message device — is not part of this machine's tree.  `None` is the
/// honest answer, and the boot that reads it learns there is no MSI frame
/// rather than inheriting a guess.
///
/// # Safety
///
/// As the aarch64 arm.
#[cfg(target_os = "none")]
pub unsafe fn message_frame() -> Option<()> {
    None
}

/// Enter U-mode at `entry` with the stack at `stack_top`.
///
/// ## What this does that nothing else in this tree did
///
/// Everything up to here runs in S-mode.  Returning to a lower privilege is an
/// `sret` with `sstatus` naming U-mode and `sepc` naming where in the program
/// to start — the same instruction the trap path already ends with, pointed
/// somewhere new.
///
/// ## Why it does not return
///
/// Control does not come back here.  The program returns to the kernel through
/// a trap — a syscall or an exit — and the trap path is what resumes the
/// kernel.  A function that "returned" would be claiming a program can finish
/// without trapping, which it cannot: U-mode has no way out except an
/// exception.
///
/// ## Why interrupts are masked across this
///
/// The three CSR writes and the `sret` are one transaction, and a timer tick
/// between them destroys it: a trap taken here saves the interrupted `sepc`
/// **and restores it on the way out**, clobbering the entry this function just
/// wrote, and the `sret` then returns to a kernel address in U-mode.  That is
/// not hypothetical — it is the aarch64 entry race, found at four thousand
/// ticks a second on the machine whose story is written down beside it.
///
/// `csrci sstatus, 2` masks, and `sret` needs no matching unmask: it loads the
/// state from `sstatus`, which names a program.  The mask covers this window
/// and nothing else.
///
/// # Safety
///
/// `entry` must be a virtual address mapped `user` and executable, `stack_top`
/// must be a `user`-accessible page's end, and the caller must have no live
/// state on the kernel stack that a trap could not restore — the trap path
/// builds its own frame and resumes through it.
#[cfg(target_os = "none")]
pub unsafe fn enter_user(entry: usize, stack_top: usize) -> ! {
    // SAFETY: the caller promises the two addresses are mapped for U-mode.
    // The `sscratch` write is what makes the first trap back land on the
    // kernel's stack: the trap entry swaps a program's `sp` with whatever
    // `sscratch` holds.
    unsafe {
        core::arch::asm!(
            "csrci sstatus, 2",
            "csrw sepc, {entry}",
            "csrw sstatus, {spsr}",
            "csrw sscratch, {kernel_stack}",
            "mv sp, {user_stack}",
            "sret",
            entry = in(reg) entry as u64,
            spsr = in(reg) trap::USER_SSTATUS,
            kernel_stack = in(reg) core::ptr::addr_of!(_stack_top) as usize as u64,
            user_stack = in(reg) stack_top as u64,
            options(noreturn)
        )
    }
}

/// Enter U-mode with a whole context, which is the form a scheduler has.
///
/// `enter_user` takes the two numbers a first program needs; this takes the
/// whole frame, which is what a scheduler builds and what `sret` restores.
///
/// # Safety
///
/// As [`enter_user`].
#[cfg(target_os = "none")]
pub unsafe fn enter_user_with_context(context: &Context) -> ! {
    // SAFETY: the caller's contract is `enter_user`'s.  The context's own
    // `sstatus` is what a resumed program returns under; a first program's is
    // [`trap::USER_SSTATUS`], which `starting_context` wrote.
    unsafe {
        core::arch::asm!(
            "csrci sstatus, 2",
            "csrw sepc, {entry}",
            "csrw sstatus, {spsr}",
            "csrw sscratch, {kernel_stack}",
            "mv sp, {user_stack}",
            "sret",
            entry = in(reg) context.sepc,
            spsr = in(reg) context.sstatus,
            kernel_stack = in(reg) core::ptr::addr_of!(_stack_top) as usize as u64,
            user_stack = in(reg) stack_pointer(context) as u64,
            options(noreturn)
        )
    }
}

/// Translate through a different root table from now on.
///
/// ## What this does not do
///
/// It writes `satp` and flushes and nothing else.  The **caller** must be
/// running through a mapping both tables share, because the next instruction
/// fetch happens through the new one: a switch made from an address only the
/// old table maps faults on the instruction after the write.
///
/// That is why this kernel's program roots copy the kernel's entry 0 — the
/// kernel's code, its stack and the trap vector are reachable through every
/// root, so a switch can happen anywhere in the kernel and the trap path does
/// not have to be careful about where it is.
///
/// ## Why no ASID
///
/// An address-space identifier would let two roots' translations coexist in
/// the TLB and remove the flush.  It also has to be allocated, kept unique and
/// cleared at the right moment, and this kernel has one CPU and a switch per
/// scheduling decision.  The flush is the cheap correct answer; the identifier
/// is the optimisation that needs a reason to exist first.
///
/// # Safety
///
/// `root` must be a page-aligned root table whose entry 0 maps every address
/// the kernel is running on — its text, its stack and the trap vector —
/// because the next fetch happens through it.
#[cfg(target_os = "none")]
pub unsafe fn switch_address_space(root: usize) -> bool {
    let previous = paging::current_root_table();
    if previous == root {
        return true;
    }
    let ppn = (root as u64 >> paging::PAGE_NUMBER_SHIFT) & ((1u64 << 44) - 1);
    // SAFETY: the caller promises the new root covers the code performing
    // this call.  The `sfence.vma` is what the architecture requires after a
    // `satp` write, and without it a change the TLB never observes is a change
    // that did not happen.
    unsafe {
        core::arch::asm!(
            "csrw satp, {}",
            "sfence.vma",
            in(reg) paging::SATP_MODE_SV48 | ppn,
            options(nostack)
        );
    }
    paging::current_root_table() == root
}

/// The timer's frequency, from the tree, or `None` when the tree did not say.
///
/// # Safety
///
/// Read-only.
#[cfg(target_os = "none")]
pub unsafe fn timer_frequency() -> Option<u64> {
    // SAFETY: the caller's contract is this function's.
    unsafe { timer::frequency() }
}

/// The monotonic clock's rate.
///
/// The same counter the timer arms against: `time` is this machine's only
/// clock, which x86_64's are not — there the APIC counts at one rate and the
/// TSC at another, and a deadline computed against the wrong one sleeps the
/// wrong amount.
///
/// # Safety
///
/// Read-only.
#[cfg(target_os = "none")]
pub unsafe fn clock_frequency() -> Option<u64> {
    // SAFETY: the caller's contract is this function's.
    unsafe { timer::frequency() }
}

/// The counter's current value.
///
/// # Safety
///
/// Read-only.
#[cfg(target_os = "none")]
pub unsafe fn timer_counter() -> u64 {
    // SAFETY: the caller's contract is this function's.
    unsafe { timer::counter() }
}

/// Arm the timer to fire `microseconds` from now.
///
/// # Safety
///
/// Called after the timer's line is enabled: a timer whose line is not enabled
/// counts and tells nobody.
#[cfg(target_os = "none")]
pub unsafe fn arm_timer(frequency: u64, microseconds: u64) -> u64 {
    let ticks = timer::ticks_for_microseconds(frequency, microseconds);
    // SAFETY: the caller's contract is this function's.
    unsafe { timer::arm(ticks) };
    ticks
}

/// Stop the timer, which on this machine means a deadline no boot reaches.
///
/// # Safety
///
/// As [`arm_timer`].
#[cfg(target_os = "none")]
pub unsafe fn disarm_timer() {
    // SAFETY: the caller's contract is this function's.
    unsafe { timer::disarm() }
}

/// How many of this machine's timer ticks are `microseconds` long.
///
/// The same question the other machines answer for their counters: a deadline
/// is a counter reading, and the conversion from a duration is the machine's
/// because the counter's rate is.
pub const fn ticks_for_microseconds(frequency: u64, microseconds: u64) -> u64 {
    timer::ticks_for_microseconds(frequency, microseconds)
}

/// The register that holds the timer's enable, as it reads.
///
/// # Safety
///
/// Read-only.
#[cfg(target_os = "none")]
pub unsafe fn timer_control() -> u64 {
    // SAFETY: the caller's contract is this function's.
    unsafe { timer::control() }
}

/// Whether the timer has fired since it was last armed.
///
/// # Safety
///
/// Read-only.
#[cfg(target_os = "none")]
pub unsafe fn timer_fired() -> bool {
    // SAFETY: the caller's contract is this function's.
    unsafe { timer::has_fired() }
}

/// The line a boot raises to prove the interrupt path.
///
/// The software interrupt, because it is the only one this machine can be
/// *asked* for: a timer's fire is a deadline, and an external interrupt
/// belongs to a device that raises it when it has something to say.
pub const fn test_interrupt() -> usize {
    trap::SOFTWARE_INTERRUPT
}

/// The timer's interrupt number, as the cause reports it.
pub const fn timer_interrupt() -> usize {
    trap::TIMER_INTERRUPT
}

/// There is no descriptor table on this machine, and no boot entry to load one
/// from.
///
/// A trap vector is an address in `stvec`, not a table of descriptors plus a
/// task state segment: the architecture has no privilege transition that needs
/// a stack the CPU finds for itself — the entry assembly swaps one in — so
/// `false` is the honest answer and a boot that reports it is reporting a fact
/// about the machine.
///
/// # Safety
///
/// Called once, with the console up.  Nothing is touched.
#[cfg(target_os = "none")]
pub unsafe fn install_descriptor_tables(_interrupt_stack_top: usize) -> bool {
    false
}

/// Where a trap from a program lands.
///
/// On the kernel stack the entry assembly swaps in, which is `sscratch`'s
/// answer and not this function's — there is no TSS to name one, and `0` is
/// the answer a caller that checks it will find unremarkable.
#[cfg(target_os = "none")]
pub fn interrupt_stack_top() -> usize {
    0
}
