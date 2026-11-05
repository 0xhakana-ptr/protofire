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
//! The first version of this file had one, so that `cargo build --workspace`,
//! //! which builds every member for the host, would not try to assemble `wfi`
//! into an x86 binary.  What that also did was make the whole crate empty on a
//! host, including the tests: `cargo test -p arch_aarch64` reported zero, and
//! every assertion in `interrupts.rs` was dead code that had never been
//! compiled.
//!
//! A gate that silences a build by removing the code is the wrong tool.  Each
//! module keeps its own `cfg(target_os)` arms, a host has no `satp` and no
//! `wfi`, so those arms are no-ops that a test can still run, and the crate
//! stays compilable everywhere it is named.

#![no_std]

// The host arm of the console records bytes instead of writing a port.
#[cfg(not(target_os = "none"))]
extern crate alloc;

// The entry: the global pointer, the stack, `sscratch`, the bss clear and the
// S-mode hand-off.  The trap path and the secondary harts' entry live in the
// same file: one entry for every trap, because `stvec` names one address, and
// one road in for every hart the firmware starts.
//
// The constant the assembly needs from the Rust side, how big one parked
// hart's stack is, is interpolated, so `smp`'s bound and the assembly's
// reservation are one fact.
//
// Here rather than in `bootloader` for the reason the other machines' entries
// are: every instruction is a fact about this machine, and the protocol crate
// is not the machine.
#[cfg(target_os = "none")]
core::arch::global_asm!(
    include_str!("entry.S"),
    SECONDARY_STACK_BYTES = const smp::SECONDARY_STACK_BYTES,
    KERNEL_STACK_RESERVATION = const smp::kernel_stack_reservation(),
);

pub mod boot;
pub mod interrupts;
pub mod paging;
pub mod plic;
pub mod port;
pub mod program;
pub mod serial;
pub mod smp;
pub mod stvec;
pub mod timer;
pub mod trap;

pub use program::PIPE_READER;
pub use program::PIPE_WRITER;
pub use program::PROGRAM_LEN;
pub use program::SLEEP_MICROSECONDS;
pub use program::program_bytes;
pub use smp::refused_harts;
pub use smp::secondary_hart_id;
pub use smp::secondary_online;
#[cfg(target_os = "none")]
pub use smp::set_finished_sink;
#[cfg(target_os = "none")]
pub use smp::set_work_sink;
#[cfg(target_os = "none")]
pub use smp::start_secondary_harts;
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

/// Which CPU this code runs on, as the machine reports it.
///
/// ## Why the answer is in `tp` and how it gets there
///
/// `tp` is one register, no memory, and the answer a trap needs without a
/// lock.  It is **not** where the answer comes from at boot: `tp` belongs to
/// the interrupted program, and a program's `tp` is whatever it made it.  The
/// trap entry computes the slot from the kernel stack it just switched to and
/// puts it in `tp` for the length of the trap; the epilogue restores the
/// program's value from the frame like every other register.
///
/// So inside the kernel this reads the trap's slot, and outside a trap it
/// reads whatever the current program left, which is why every caller of this
/// function is kernel code running under a trap or the boot before any program
/// exists.  Putting the slot in `tp` at boot instead was the first version, and
/// it was wrong in a way a single CPU could not show: the second hart's program
/// zeroed the register and the hart came back as CPU 0.
#[cfg(target_os = "none")]
pub fn current_cpu_slot() -> usize {
    let slot: usize;
    // SAFETY: a register read with no side effect.  `trap_entry` writes the
    // slot before it calls anything that could ask, and the epilogue restores
    // the interrupted program's own value.
    unsafe { core::arch::asm!("mv {}, tp", out(reg) slot, options(nomem, nostack)) };
    slot
}

/// A host has one CPU and it is slot zero.
#[cfg(not(target_os = "none"))]
pub fn current_cpu_slot() -> usize {
    0
}

/// The machine's own id for the CPU this code runs on.
///
/// `tp` says which **slot** this CPU is, which is the kernel's numbering and
/// what a trap needs; the machine's id is the hart the firmware named, and the
/// two differ the moment a machine does not cold-boot hart zero.  A boot line
/// that reports `id` is reporting the machine's answer, so this is the accessor
/// that gives it.
#[cfg(target_os = "none")]
pub fn current_cpu_id() -> usize {
    let slot = current_cpu_slot();
    if slot == 0 {
        smp::boot_hart()
    } else {
        smp::secondary_hart_id(slot - 1)
    }
}

/// A host has one CPU and no hart id, so zero is the answer and the slot.
#[cfg(not(target_os = "none"))]
pub fn current_cpu_id() -> usize {
    0
}

/// Whether the trap being dispatched belongs to the CPU that owns the
/// scheduler.
///
/// The dispatch asks before it calls the kernel's sink: a CPU that is not the
/// boot CPU answers its own interrupt and returns, because the sink and the
/// scheduler behind it are the boot CPU's and nothing locks them.
#[cfg(target_os = "none")]
pub fn boot_cpu_owns_this_trap() -> bool {
    current_cpu_slot() == 0
}

/// A host has one CPU, so every trap belongs to its scheduler's owner.
#[cfg(not(target_os = "none"))]
pub fn boot_cpu_owns_this_trap() -> bool {
    true
}

/// Send an inter-processor interrupt to every started CPU.
///
/// The supervisor software interrupt is per-hart, so "every other hart" is the
/// firmware's IPI: the SBI extension takes a hart mask, and the mode says which
/// harts it means.  The mask is built from the harts **this boot started and
/// saw online**, not from the machine's list: naming a hart the firmware
/// refused or one that never came up is a call whose error says nothing about
/// the harts that are running.  The caller's own hart is not in the mask, and
/// that is a restriction worth stating: a self-directed IPI would make the
/// boot's own software line pending, which its dispatch would then have to
/// acknowledge for a reason it cannot name.
///
/// Answers whether the firmware accepted the call.  A call with an empty mask
/// is not made and answers `false`: there is no one to interrupt.
///
/// # Safety
///
/// Called after every hart's trap vector is installed and its lines enabled.
/// The interrupt the others take is the software line, which their own dispatch
/// answers.
#[cfg(target_os = "none")]
pub unsafe fn send_ipi_to_others() -> bool {
    // SBI extension "IPI", function 0: send_ipi.
    const SBI_EXT_IPI: u64 = 0x0073_5049;
    // `hart_mask_base` of zero means "bit N of the mask names hart N".
    let mask = smp::started_harts_mask();
    if mask == 0 {
        return false;
    }
    let error: i64;
    // SAFETY: the SBI IPI call, with every register the firmware may eat
    // declared late-out.
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") mask => error,
            inlateout("a1") 0u64 => _,
            lateout("a2") _,
            lateout("a3") _,
            lateout("a4") _,
            lateout("a5") _,
            inlateout("a6") 0u64 => _,
            inlateout("a7") SBI_EXT_IPI => _,
            options(nostack)
        )
    };
    error == 0
}

/// The entry the assembly calls with the boot hart's id, by the name the
/// linker resolves.
///
/// The firmware cold-boots exactly one hart, and which one it chose is a fact
/// of this entry, not an assumption about hart zero.  It reaches the same
/// kind of static the device-tree pointer does, for the same reason.
///
/// # Safety
///
/// Called once, from the entry, with the register the firmware handed over.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn riscv64_set_boot_hart(hart: usize) {
    smp::set_boot_hart(hart);
}

// The per-CPU kernel stacks, as the entry assembly laid them out.  One array,
// indexed by slot, and the trap path reads the top of this CPU's slice out of
// it.  The symbol is the entry assembly's, which is where the stacks are
// defined; a second definition here would be a second opinion about where the
// kernel's stacks are.
#[cfg(target_os = "none")]
unsafe extern "C" {
    static kernel_stacks: u8;
}

/// The top of this CPU's kernel stack.
///
/// ## Why this is asked rather than written
///
/// `sscratch` holds the stack a program's trap lands on, and it is per-hart: a
/// value written by the boot hart is a stack the second hart would build its
/// frame on, which is two frames over one region and an unwind into the wrong
/// program.  The slot is what tells them apart, and the array is indexed by it.
///
/// The symbol's address plus the slot's slice is the answer, so the stack a CPU
/// boots on, the stack its trap path swaps in, and the stack a resumed
/// program's next trap lands on are all one stack.
#[cfg(target_os = "none")]
pub fn kernel_stack_top() -> usize {
    let slot = current_cpu_slot();
    // `addr_of!` takes the base of the array without creating a reference:
    // there is storage there, not a value.
    core::ptr::addr_of!(kernel_stacks) as usize + (slot + 1) * smp::SECONDARY_STACK_BYTES
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
/// parks the program's `sp`, and a tick taken inside this window is the
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
/// this trap restores the interrupted state anyway, the mask covers the wait
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

/// Enter a program on this CPU, with its root table already installed.
///
/// ## Why this is not `enter_user_with_context`
///
/// That one is the *first* entry on the boot CPU, and it installs the context
/// it is handed over this CPU's kernel frame.  This one is a CPU that came up
/// on its own and has just been handed a task by the scheduler: its kernel
/// stack holds whatever the trap path that woke it left there, and the context
/// it enters is the task's, which the scheduler chose.  Both end in the same
/// `sret`; what differs is who chose the context and what is on the stack.
///
/// ## Why `sscratch` is written here
///
/// The value is per-hart, and a CPU that entered a program with the boot hart's
/// stack in its `sscratch` would take its first trap on another CPU's stack.
/// [`kernel_stack_top`] is this CPU's, so the trap path's swap lands on the
/// stack this CPU is already using.
///
/// # Safety
///
/// `context` must be a program's saved frame whose `sepc` and `sp` name
/// `user`-mapped pages in the installed root, and this CPU must be running on
/// its own kernel stack.
#[cfg(target_os = "none")]
pub unsafe fn enter_program_here(context: &Context) -> ! {
    // SAFETY: the caller promises the context is a program's and the root is
    // installed.  The mask covers the four writes and the `sret`, for the
    // reason `enter_user_with_context` gives: a trap between them would clobber
    // `sepc`.
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
            kernel_stack = in(reg) kernel_stack_top() as u64,
            user_stack = in(reg) stack_pointer(context) as u64,
            options(noreturn)
        )
    }
}

/// The host build has no U-mode to enter.
///
/// # Safety
///
/// Never returns and never enters anything: a host has no U-mode, so this stops
/// the process rather than pretending to have run a program.
#[cfg(not(target_os = "none"))]
pub unsafe fn enter_program_here(_context: &Context) -> ! {
    panic!("enter_program_here called on a host: there is no U-mode to enter")
}

/// Install the trap vector.
///
/// Returns whether one was installed, which on this machine means whether the
/// register kept the write, the entry assembly exists and `stvec` can name
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
    // SAFETY: the caller's contract is this function's, once, with the sink
    // installed and the stack valid.
    let installed = unsafe { trap::install_table() };
    if !installed {
        return false;
    }

    // And the external controller, which is what turns a source into an
    // interrupt.  A vector table with no controller behind it takes traps the
    // machine raises itself and nothing a device raises.
    let Some((base, _contexts)) = boot::interrupt_controller() else {
        return true;
    };
    let Some(sources) = boot::plic_sources() else {
        return true;
    };
    let Some(context) = boot::plic_context_for_hart(boot_hart_id()) else {
        return true;
    };
    let plic = plic::Plic::new(base, context, sources);
    // SAFETY: the window is the tree's `reg`, the boot mapped it below RAM as
    // device memory, and this runs once on the boot hart.
    unsafe {
        plic.enable();
        trap::set_controller(plic);
    }
    true
}

/// This hart's id as the entry recorded it, for a PLIC context lookup.
#[cfg(target_os = "none")]
fn boot_hart_id() -> usize {
    // The hart the firmware cold-booted, recorded by the entry: the PLIC's
    // context list is per hart, and which hart this is decides which context
    // claims.
    crate::smp::boot_hart()
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
/// in a controller, the enable is a CSR write, which is what makes it cheap
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
            // SAFETY: setting the timer's enable bit in `sie`, the line the
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
        trap::EXTERNAL_INTERRUPT => {
            // SAFETY: the external line's own enable bit in `sie`; the PLIC's
            // per-source enable is the controller's half and is turned on by
            // the driver that wants the source.
            unsafe { set_sie_bit(1 << trap::EXTERNAL_INTERRUPT) };
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
        trap::EXTERNAL_INTERRUPT => sie & (1 << trap::EXTERNAL_INTERRUPT) != 0,
        _ => false,
    }
}

/// Raise one interrupt from the machine, as a device would.
///
/// The one line this machine can be *asked* for is its software interrupt:
/// `sip`'s own bit, which S-mode may set on itself.  A timer's fire is a
/// deadline, not a raise, and an external interrupt belongs to a device.
/// Unlike a GIC's software interrupts, whose enable bits reset set, this
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
/// A PLIC is a level controller a hart claims through, and an IMSIC, the
/// AIA's message device, is not part of this machine's tree.  `None` is the
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
/// to start, the same instruction the trap path already ends with, pointed
/// somewhere new.
///
/// ## Why it does not return
///
/// Control does not come back here.  The program returns to the kernel through
/// a trap, a syscall or an exit, and the trap path is what resumes the
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
/// not hypothetical, it is the aarch64 entry race, found at four thousand
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
/// state on the kernel stack that a trap could not restore, the trap path
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
            kernel_stack = in(reg) kernel_stack_top() as u64,
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
            kernel_stack = in(reg) kernel_stack_top() as u64,
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
/// That is why this kernel's program roots copy the kernel's entry 0, the
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
/// the kernel is running on, its text, its stack and the trap vector, ///
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
/// clock, which x86_64's are not, there the APIC counts at one rate and the
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

/// The external controller, as the boot found and enabled it.
///
/// `(windows, context, sources)`, the PLIC's base and size from the tree, the
/// context this hart claims through, and how many sources the tree declares.
/// `None` on a machine whose tree names no controller, which is a fact a boot
/// reports rather than a failure it works around.
#[cfg(target_os = "none")]
pub fn external_controller() -> Option<(usize, usize, usize)> {
    // From the controller the trap path holds, not from the device tree: a line
    // built from the tree prints the same words on a boot whose driver was
    // never installed, which is exactly what a mutation showed.
    let plic = trap::controller()?;
    Some((plic.base(), plic.context(), plic.sources()))
}

/// Enable one source at the controller, and answer whether it did.
///
/// The line's own enable is [`enable_interrupt_line`]`(EXTERNAL_INTERRUPT)`;
/// this is the controller's per-source bit, and both are needed, a source
/// enabled at the PLIC still needs the hart's external line, and a hart taking
/// the external line still needs the source's bit.
///
/// # Safety
///
/// Called after [`install_interrupt_table`], before the device that raises the
/// source is told to start signalling.
#[cfg(target_os = "none")]
pub unsafe fn enable_external_source(number: usize) -> bool {
    let Some((base, _contexts)) = boot::interrupt_controller() else {
        return false;
    };
    let Some(sources) = boot::plic_sources() else {
        return false;
    };
    let Some(context) = boot::plic_context_for_hart(smp::boot_hart()) else {
        return false;
    };
    let plic = plic::Plic::new(base, context, sources);
    // SAFETY: the caller's contract is this function's.
    unsafe { plic.enable_source(number) }
}

/// Whether a source's enable bit is set at the controller, read back.
///
/// # Safety
///
/// Read-only.
#[cfg(target_os = "none")]
pub unsafe fn external_source_enabled(number: usize) -> bool {
    let Some((base, _contexts)) = boot::interrupt_controller() else {
        return false;
    };
    let Some(sources) = boot::plic_sources() else {
        return false;
    };
    let Some(context) = boot::plic_context_for_hart(smp::boot_hart()) else {
        return false;
    };
    let plic = plic::Plic::new(base, context, sources);
    // SAFETY: the caller's contract is this function's.
    unsafe { plic.source_enabled(number) }
}

/// The PLIC source the console's UART is wired to.
///
/// Read from the tree rather than written here: the platform decides which
/// source a device is, and a board that moved the UART would have a tree that
/// says so.  Ten on the `virt` machine.
#[cfg(target_os = "none")]
pub fn console_source() -> Option<usize> {
    let tree = boot::device_tree()?;
    let node = tree.find_compatible("ns16550a")?;
    // A cell, not a four-byte read: `interrupts` is a list even when it holds
    // one number, and a reader that demanded exactly one word refused the
    // property the tree actually has.
    node.property("interrupts")?
        .as_cells()?
        .next()
        .map(|cell| cell as usize)
}

/// Claim the console's interrupt: enable the source at the controller, and ask
/// the UART to raise it once.
///
/// ## Why the console is the device this boot claims
///
/// The PLIC was programmed and its claim path had never carried a device's
/// interrupt: no source was enabled, so nothing ever arrived through the
/// external line.  The console is the device this boot has and trusts, and its
/// transmitter raises the line on its own, so enabling it turns the claim path
/// from something a boot could run into something a boot ran.
///
/// Asking for *one* interrupt is deliberate.  A 16550 raises its transmitter
/// interrupt whenever the holding register is empty, which is nearly always, so
/// leaving it enabled is an interrupt per printed byte, and every one of those
/// arrives inside the print that is trying to report it.  The interrupt is
/// silenced by the handler the first time it is taken.
///
/// # Safety
///
/// Called once, after [`install_interrupt_table`] and with the console up.
#[cfg(target_os = "none")]
pub unsafe fn claim_console_source() -> Option<usize> {
    let source = console_source()?;
    // SAFETY: the caller's contract is this function's.
    if !unsafe { enable_external_source(source) } {
        return None;
    }
    // SAFETY: the source is enabled, so the device's line reaches this hart.
    unsafe { serial::enable_transmit_interrupt() };
    Some(source)
}

/// Stop the console raising its line, and answer whether it had one pending.
///
/// The 16550 has no acknowledge register: reading `IIR` is the acknowledge, and
/// the read also says whether the interrupt was this device's.
///
/// # Safety
///
/// Called from the trap path for [`console_source`].
#[cfg(target_os = "none")]
pub unsafe fn acknowledge_console() -> bool {
    // SAFETY: the caller's contract is this function's.
    unsafe { serial::acknowledge() }
}

/// Stop the console raising its line again.
///
/// # Safety
///
/// Called from the trap path, after [`acknowledge_console`].
#[cfg(target_os = "none")]
pub unsafe fn silence_console() {
    // SAFETY: the caller's contract is this function's.
    unsafe { serial::disable_interrupts() };
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

/// The external interrupt's number, as the cause reports it.
pub const fn external_interrupt() -> usize {
    trap::EXTERNAL_INTERRUPT
}

/// There is no descriptor table on this machine, and no boot entry to load one
/// from.
///
/// A trap vector is an address in `stvec`, not a table of descriptors plus a
/// task state segment: the architecture has no privilege transition that needs
/// a stack the CPU finds for itself, the entry assembly swaps one in, so
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
/// answer and not this function's, there is no TSS to name one, and `0` is
/// the answer a caller that checks it will find unremarkable.
#[cfg(target_os = "none")]
pub fn interrupt_stack_top() -> usize {
    0
}
