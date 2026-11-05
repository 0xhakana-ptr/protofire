//! arch/x86_64/src/lib.rs
//!
//! The x86_64 machine: what the kernel asks it, and nothing else.
//!
//! Everything here is a fact about this architecture, a port, an instruction,
//! a register, and none of it may be spelled outside this crate.  The test is
//! mechanical: a `#[cfg(target_arch = ...)]` anywhere else in the tree is a
//! question this crate should answer instead.

#![no_std]

// The host arm of the console records bytes instead of writing a port.
#[cfg(not(target_os = "none"))]
extern crate alloc;

pub mod apic;
pub mod boot;
pub mod context;
pub mod gdt;
pub mod idt;
pub mod interrupts;
pub mod paging;
pub mod pic;
pub mod port;
pub mod serial;
pub mod trap;

/// The local APIC, by name: the boot asks the machine whether it has one, and
/// the answer decides whether a timer exists at all.
pub use apic::Apic;
/// The calibration, by name: it is the one measurement a boot reports.
pub use apic::calibrate as calibrate_timer;

/// The descriptor table, by name.
///
/// Bare metal only on the `install` half, a host has no `lgdt`, so the arm is
/// gated here rather than making the module's name differ per build.  A caller
/// that named this on a host would be a caller entering ring 3, which a host
/// has no way to do.
/// The stack an interrupt from ring 3 lands on: the boot's.
///
/// Published by `boot-x86-64.S` as `kstack_top`, and not a second stack
/// declared for the purpose, see `gdt::kernel_stack_top`.
#[cfg(target_os = "none")]
pub fn interrupt_stack_top() -> usize {
    gdt::kernel_stack_top()
}

/// Load the descriptor table and the task state segment.
///
/// Answers whether the machine kept both.  `interrupt_stack_top` is what `RSP0`
/// names, so it must be a live kernel stack.
///
/// # Safety
///
/// Called once, with the console up and before anything enters ring 3.  A
/// second call reloads the selectors under code that has already cached them.
#[cfg(target_os = "none")]
pub unsafe fn install_descriptor_tables(interrupt_stack_top: usize) -> bool {
    // SAFETY: the caller's contract is this function's, once, before ring 3.
    unsafe { gdt::install(interrupt_stack_top) }
}

/// A program's saved state, and the operations a scheduler asks about it.
///
/// The type is this crate's, and the kernel reaches the fields through the
/// free functions below rather than by name: what a frame looks like is the
/// machine's, and a kernel that read `context.elr` would be a kernel written
/// against one machine.
pub use context::Context;
pub use context::PIPE_READER;
pub use context::PIPE_WRITER;
pub use context::PROGRAM_LEN;
pub use context::SLEEP_MICROSECONDS;
pub use context::install_context;
pub use context::is_user_context;
pub use context::program_bytes;
pub use context::resume_address;
pub use context::return_state;
pub use context::return_value;
pub use context::set_resume_address;
pub use context::set_return_value;
pub use context::stack_pointer;
pub use context::starting_context;

/// Enter ring 3: bare metal only, because a host has no ring 3 to enter.
#[cfg(target_os = "none")]
pub use context::enter_user_with;

// The machine's entry, assembled from `src/boot-x86-64.S`.
//
// It is here rather than in `bootloader` because everything in it is a fact
// about this architecture: the multiboot2 header's checksum, the PVH note's
// type, the identity map's page-table layout, the GDT's descriptor bits.  A
// machine that entered differently writes its own file and `bootloader` does
// not change.
//
// `bootloader` supplies the symbol it calls.  The direction is a link-time
// reference rather than a crate dependency, because `arch` sits below
// `bootloader` and an upward `use` is the edge this tree's layering forbids.
#[cfg(target_os = "none")]
core::arch::global_asm!(include_str!("boot-x86-64.S"));

/// Stop this CPU until an interrupt arrives.
///
/// Interrupts are disabled first, so this does not return unless something
/// enables them; every caller in the kernel treats it as a final stop.
pub fn halt() -> ! {
    loop {
        // SAFETY: `cli` clears the interrupt flag and `hlt` stops the core
        // until an interrupt is pending.  With the flag clear there is none to
        // take, so the pair cannot leave this loop.
        unsafe { core::arch::asm!("cli; hlt", options(nomem, nostack)) };
    }
}

/// The machine's message-signalled interrupt frame: none this crate drives.
///
/// x86_64's is an MSI capability's address and data pair, which
/// `drivers/bus/pci` writes directly; the frame itself is the local APIC's, not
/// a separate window the way GICv2m is.  So there is nothing for this crate to
/// probe and `None` is the honest answer, a caller treats it as "no frame",
/// not as a failure.
///
/// # Safety
///
/// As the aarch64 arm.
#[cfg(target_os = "none")]
pub unsafe fn message_frame() -> Option<()> {
    None
}

/// What a supervisor call's handler answers.
///
/// Re-exported from `trap` rather than defined here: the call path and the
/// interrupt path are one dispatch on this machine, and a second definition in
/// this file would be a second description of one decision.
pub use trap::CallFrame;
pub use trap::CallOutcome;

/// Enter ring 3 at `entry` with the stack at `stack_top`.
///
/// ## What had to exist first
///
/// The earlier version of this function was `unreachable!`, and its comment
/// named the three things it needed: a TSS with an `RSP0`, a user-accessible
/// GDT segment, and a gate at `DPL` 3.  All three exist now, `gdt` builds the
/// descriptors and loads the TSS, `idt` installs the call gate at `DPL` 3, and
/// `enter_user_with` builds the five words `iretq` pops, so this is a thin
/// wrapper that gives the caller the aarch64 signature.
///
/// The context it builds has no registers set, which is correct for an entry:
/// a program's first instruction runs with whatever the kernel mapped, and
/// `starting_context` is where a boot sets them if it wants to.
///
/// # Safety
///
/// `entry` must be a virtual address mapped `user` and executable, `stack_top`
/// must be a `user`-accessible page's end, and the caller must have loaded the
/// descriptor table with [`install_descriptor_tables`] and chosen the address
/// space with [`switch_address_space`].
#[cfg(target_os = "none")]
pub unsafe fn enter_user(entry: usize, stack_top: usize) -> ! {
    let context = Context::user(entry, stack_top);
    // SAFETY: the caller's contract is this function's.
    unsafe { enter_user_with(&context) }
}

/// Enter ring 3 with a context, which is the form a scheduler has.
///
/// # Safety
///
/// As [`enter_user`].
#[cfg(target_os = "none")]
pub unsafe fn enter_user_with_context(context: &Context) -> ! {
    // SAFETY: the caller's contract is `enter_user`'s.
    unsafe { enter_user_with(context) }
}

/// Translate through a different root table from now on.
///
/// `cr3` is the register, and writing it is the whole of the switch, the
/// processor discards the TLB for the new address space on the next walk.
/// Reading it back is what makes the answer a fact rather than a claim: a `cr3`
/// whose low bits held flags would read back as a different number, and the
/// low twelve bits are cleared by `current_root_table` for that reason.
///
/// ## What this does not do
///
/// It does not make the new table's pages reachable.  The **caller** must run
/// through a mapping both tables share, because the next instruction fetch
/// happens through the new one.  This kernel's program roots copy the kernel's
/// entry 0 for exactly that reason, the same as aarch64's copy the kernel's
/// second-level table.
///
/// # Safety
///
/// `root` must be a page-aligned root table whose entry 0 maps every address
/// the kernel is running on, its text, its stack and the interrupt table, ///
/// because the next fetch happens through it.
#[cfg(target_os = "none")]
pub unsafe fn switch_address_space(root: usize) -> bool {
    // SAFETY: the caller promises the new root covers the code performing this
    // call.
    unsafe { paging::install(root) };

    // An install that answered `false` means the root was already installed;
    // either way the question is what the register holds now, which is what
    // this reads.
    paging::current_root_table() == root
}

/// The timer's frequency, as measured against the PIT.
///
/// `None` when the machine reports no local APIC, or when the calibration did
/// not produce a number.  A caller treats that as "no timer" rather than as a
/// frequency of zero, which would be a timer that fires immediately and
/// forever.
///
/// # Safety
///
/// Called once, after the page table mapped the APIC's page as device memory
/// and interrupts are still disabled.  The calibration programs the PIT, which
/// nothing else in this kernel uses.
#[cfg(target_os = "none")]
pub unsafe fn timer_frequency() -> Option<u64> {
    // Calibrated once and remembered.
    //
    // ## Why this is cached and not measured per call
    //
    // The kernel's interrupt handler re-arms the timer on every tick, and it
    // asks for the frequency when it does.  A `timer_frequency` that measured
    // each time would program the PIT for fifty-five milliseconds and disarm
    // the timer it was asked about, so the boot took exactly one tick, and
    // every tick spent its whole slice re-measuring the clock.  The log showed
    // it as `1 tick(s)` after programs that had run long enough for hundreds.
    //
    // aarch64's answers from `CNTFRQ_EL0` and costs an MSR, which is why the
    // same shape was correct there and wrong here.  The step that is expensive
    // on one machine is the step that has to be remembered.
    if let Some(frequency) = measured_frequency() {
        return Some(frequency);
    }

    // SAFETY: the caller's contract is this function's.
    let apic = unsafe { Apic::probe() }?;
    // SAFETY: as above, the APIC is mapped and interrupts are off.
    unsafe { apic.enable() };
    // SAFETY: as above.
    let frequency = unsafe { calibrate_timer(&apic) }?;
    // SAFETY: the calibration disarmed the timer; this records the controller
    // for the handlers that will use it.
    unsafe { trap::set_timer_controller(apic) };
    set_measured_frequency(frequency);
    Some(frequency)
}

/// The APIC timer's rate, measured once.
///
/// Separate from [`CALIBRATED`] because the two clocks differ: an APIC count is
/// not a TSC count, and a conversion that used one for the other would make a
/// time slice wrong by the ratio of the bus clock to the core clock.
#[cfg(target_os = "none")]
static APIC_RATE: cell::SyncUnsafeCell<Option<u64>> = cell::SyncUnsafeCell::new(None);

/// The frequency this boot measured, once.
///
/// A `SyncUnsafeCell` rather than an atomic because the value is written once
/// with interrupts off and read afterwards; the write happens before any timer
/// can fire, which is what makes the read on the handler's path sound.
#[cfg(target_os = "none")]
static CALIBRATED: cell::SyncUnsafeCell<Option<u64>> = cell::SyncUnsafeCell::new(None);

/// The frequency this boot measured, if it has measured one.
#[cfg(target_os = "none")]
fn measured_frequency() -> Option<u64> {
    // SAFETY: written once by `timer_frequency` before any timer can fire, and
    // read after that.
    unsafe { *CALIBRATED.get() }
}

/// Record the measured frequency.
#[cfg(target_os = "none")]
fn set_measured_frequency(frequency: u64) {
    // SAFETY: as above, the only write, and it happens before any tick.
    unsafe { *CALIBRATED.get() = Some(frequency) };
}

/// The monotonic clock's rate, in ticks per second.
///
/// ## Why this is separate from `timer_frequency`
///
/// They are two clocks: `timer_counter` reads the TSC and `arm_timer` loads an
/// APIC count, and nothing in the architecture says the two run at one rate.
/// On this emulator they happen to agree, a boot was measured with the sleep
/// conversion using either number and behaved identically, so this is not a
/// fix for anything observed.  It is the honest signature: a caller that
/// compares against `timer_counter` asks how fast *that* counts, and a caller
/// that loads a countdown asks how fast *that* counts, and one function
/// answering both would be right only where the two coincide.
///
/// Calibrated once and remembered, for the reason `timer_frequency` gives.
///
/// # Safety
///
/// Called once, with interrupts disabled.
#[cfg(target_os = "none")]
pub unsafe fn clock_frequency() -> Option<u64> {
    if let Some(rate) = measured_clock() {
        return Some(rate);
    }
    // SAFETY: the caller's contract is this function's.
    let rate = unsafe { apic::calibrate_clock() }?;
    // SAFETY: as above, the only write, and it happens before any program.
    unsafe { *CLOCK_RATE.get() = Some(rate) };
    Some(rate)
}

/// The clock's rate, measured once.
#[cfg(target_os = "none")]
static CLOCK_RATE: cell::SyncUnsafeCell<Option<u64>> = cell::SyncUnsafeCell::new(None);

/// The clock's rate, if this boot has measured one.
#[cfg(target_os = "none")]
fn measured_clock() -> Option<u64> {
    // SAFETY: written once by `clock_frequency` before any program runs.
    unsafe { *CLOCK_RATE.get() }
}

/// Arm the timer to fire every `microseconds`.
///
/// Answers the count it loaded, so a boot line can report a number rather than
/// a claim.
///
/// # Safety
///
/// Called after [`timer_frequency`], which is what enabled the APIC and
/// recorded it.
#[cfg(target_os = "none")]
pub unsafe fn arm_timer(frequency: u64, microseconds: u64) -> u64 {
    let Some(apic) = (unsafe { trap::timer_controller() }) else {
        return 0;
    };
    // The APIC's own rate, not the TSC's: `frequency` is the argument the
    // caller has, and the count this arms with is in APIC ticks.
    // SAFETY: written once by `timer_frequency`, read after.
    let rate = unsafe { *APIC_RATE.get() }.unwrap_or(frequency);
    let count = apic::ticks_for_microseconds(rate, microseconds);
    // SAFETY: the caller's contract is this function's.
    unsafe { apic.arm_timer(count) };
    count as u64
}

/// The timer's control register: the LVTTL, read back.
///
/// A timer "armed" whose LVTTL has the mask bit set is a timer that never
/// fires, and the register is the only thing that says which happened.
///
/// # Safety
///
/// Has no side effect; reads the APIC's page.
#[cfg(target_os = "none")]
pub unsafe fn timer_control() -> u64 {
    let Some(apic) = (unsafe { trap::timer_controller() }) else {
        return 0;
    };
    // SAFETY: the APIC was probed and mapped by `timer_frequency`.
    unsafe { apic.timer_vector() as u64 }
}

/// Stop the timer.
///
/// # Safety
///
/// Called after [`arm_timer`]; disarming a timer that is already disarmed has
/// no effect beyond clearing a mask bit that was already set.
#[cfg(target_os = "none")]
pub unsafe fn disarm_timer() {
    let Some(apic) = (unsafe { trap::timer_controller() }) else {
        return;
    };
    // SAFETY: the APIC was probed and mapped by `timer_frequency`.
    unsafe { apic.disarm_timer() };
}

/// How many of this machine's timer ticks are `microseconds` long.
///
/// The same question aarch64 answers from its generic counter, so a scheduler
/// that needs a deadline asks one function whichever machine it is on.  The
/// machine's answer is a `u32` because that is what its counter register takes,
/// and widening it here is what keeps the two signatures equal.
pub const fn ticks_for_microseconds(frequency: u64, microseconds: u64) -> u64 {
    apic::ticks_for_microseconds(frequency, microseconds) as u64
}

/// The timer's counter, which counts down.
///
/// # Safety
///
/// As [`timer_control`].
#[cfg(target_os = "none")]
pub unsafe fn timer_counter() -> u64 {
    // The timestamp counter, not the APIC's count.
    //
    // ## Why this is the TSC and not the timer
    //
    // `CNTPCT_EL0` on aarch64 counts **up** from boot and never resets, which
    // is what makes `now >= deadline` a deadline.  The APIC's current count is
    // the opposite in both respects: it counts **down**, and it reloads every
    // time the timer fires.  A deadline computed from it is a number that will
    // never be reached, and a scheduler that waited on one waited forever, //
    // which is exactly what a boot whose programs slept showed: 76,000 ticks
    // with one task asleep and none of them waking it.
    //
    // `rdtsc` is the machine's monotonic counter and the only one it has that
    // behaves like the register aarch64 reads.
    //
    // SAFETY: `rdtsc` reads the counter; it is unprivileged and has no side
    // effect.  `lfence` orders it after any earlier instruction so two reads
    // cannot appear out of order, the same reason `CPUID` was needed before it
    // on older machines.
    unsafe { apic::read_tsc() }
}

/// Whether the timer has fired: the counter reaching zero is not observable
/// after the fact, so this answers what the boot's tick count is not needed
/// for.
///
/// The local APIC's status is a bit in the LVTTL that the processor clears when
/// the interrupt is delivered, so a read after the fact answers "delivered",
/// not "fired".  The count of ticks is what a boot reports, and it is the
/// kernel's.
///
/// # Safety
///
/// As [`timer_control`].
#[cfg(target_os = "none")]
pub unsafe fn timer_fired() -> bool {
    false
}

/// The line a boot raises to prove the interrupt path: the timer's.
///
/// ## Why not a spare vector
///
/// Vector zero is the divide error, so a self-directed interrupt at zero is a
/// fault the processor takes and the dispatch never sees, a boot reported
/// "raised but not delivered" on every run with nothing actually wrong.
///
/// A spare vector above the timer's is worse rather than better: the local APIC
/// records what it delivers as in-service, and a vector the kernel's sink does
/// not claim leaves the controller in a state a real tick never produces.  The
/// boot then reported the test as delivered and took no tick afterwards.
///
/// So the instrument is the timer's own vector.  Nothing has armed the timer
/// when the boot raises it, so this is the only delivery on that vector, and a
/// sink that counts it is a sink that will count the real ones.
pub const fn test_interrupt() -> usize {
    crate::apic::TIMER_VECTOR as usize
}

/// The timer's interrupt as a vector.
pub const fn timer_interrupt() -> usize {
    apic::TIMER_VECTOR as usize
}

/// Whether an interrupt line is enabled: this machine's controller has no
/// per-line enable, so a line is enabled when the controller is.
///
/// The local APIC delivers every unmasked vector and has no mask register per
/// line; masking is an IOAPIC concept for lines that arrive through it, and
/// this kernel's only line is the timer's, which the APIC owns.
///
/// # Safety
///
/// As [`timer_control`].
#[cfg(target_os = "none")]
pub unsafe fn interrupt_line_enabled(_number: usize) -> bool {
    // SAFETY: the answer is the controller's existence, which the probe gives.
    unsafe { Apic::probe() }.is_some()
}

/// Stop the core until an interrupt arrives, leaving interrupts enabled.
///
/// `sti; hlt` is the pair a kernel idles with: `sti` takes effect after the
/// next instruction, so the `hlt` cannot miss the interrupt it is about to
/// wait for, the order matters, and `hlt; sti` would sleep through it.
///
/// A host has no `hlt`, so its arm returns immediately.
#[cfg(target_os = "none")]
pub fn wait_for_a_wakeup() {
    // SAFETY: `sti` sets `RFLAGS.IF` and `hlt` stops the core until an
    // interrupt is pending.  Interrupts are on by the time this is called, //
    // every program runs with `IF` set, so the `hlt` returns.
    unsafe { core::arch::asm!("sti; hlt", options(nomem, nostack)) };
}

/// The host build: nothing to wait for.
#[cfg(not(target_os = "none"))]
pub fn wait_for_a_wakeup() {}

/// Enable one of the machine's interrupt lines.
///
/// True when the machine reports a local APIC: this machine enables lines by
/// enabling the controller, which [`timer_frequency`] does.  A machine with no
/// APIC answers `false`, and a caller reports that rather than working around
/// it.
///
/// # Safety
///
/// Called after [`install_interrupt_table`], once per line.
#[cfg(target_os = "none")]
pub unsafe fn enable_interrupt_line(_number: usize) -> bool {
    // SAFETY: the caller's contract is this function's.
    unsafe { Apic::probe() }.is_some()
}

/// Raise one interrupt from the controller: the local APIC can raise any
/// vector to itself, and this asks for the boot's test vector.
///
/// ## Why this is a software interrupt
///
/// A device raises its line when it has something to say and cannot be asked
/// to say it on demand.  The local APIC's ICR can send an interrupt to a CPU,
/// /// including this one, with a vector of the caller's choosing, which is the
/// same instrument aarch64's `GICD_SGIR` is, and it drives the identical
/// delivery path a timer tick does.
///
/// # Safety
///
/// Called after [`install_interrupt_table`] with a sink that will claim the
/// vector.
///
/// # Safety
///
/// The controller must be enabled and the vector must be one this machine can
/// raise: on this machine that is the timer's own vector, and the self-test is
/// the caller that proves the path.
#[cfg(target_os = "none")]
pub unsafe fn raise_interrupt(number: usize) -> bool {
    // SAFETY: the caller's contract.
    let Some(apic) = (unsafe { Apic::probe() }) else {
        return false;
    };
    // SAFETY: `probe` answered a base address and the boot mapped it.
    unsafe { apic.raise_to_self(number as u8) }
}

/// TEMPORARY PROBE SUPPORT.  `None`: the local APIC's per-line state is not
/// what this probe is for.
///
/// # Safety
///
/// Reads only.
#[cfg(target_os = "none")]
pub unsafe fn interrupt_probe_state(_number: usize) -> Option<(bool, bool, bool)> {
    None
}

/// The most CPUs past the boot one this machine starts: none.
pub const MAX_SECONDARY_HARTS: usize = 0;

/// Start this machine's other CPUs: this machine starts none.
///
/// The local APIC's ICR can reach another CPU, an INIT-SIPI-SIPI sequence is
/// how an application processor is woken, but there is no discovery behind it
/// on this machine: no MADT is read, so there is no list of processors to
/// start and no place to start them into.  Zero is the honest answer today: a
/// machine with more than one CPU runs one, and a count without a path behind
/// it is exactly the claim this tree's boot lines exist to refuse.
///
/// # Safety
///
/// As the riscv64 arm: called once, from the boot CPU, with the tables up.
/// This arm touches nothing, which keeps its half of the promise.
#[cfg(target_os = "none")]
pub unsafe fn start_secondary_harts(_timer_slice_us: u64) -> usize {
    0
}

/// The CPU id started into `slot`: this machine starts none, so every slot is
/// empty and the answer is zero.
pub fn secondary_hart_id(_slot: usize) -> usize {
    0
}

/// Whether the CPU started into `slot` came up: this machine starts none, so
/// no slot is online.
pub fn secondary_online(_slot: usize) -> bool {
    false
}

/// The CPUs the firmware refused to start: this machine asks for none, so
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
/// This machine reads no processor table, so the CPU it runs on is the one the
/// firmware booted and zero is the only id it has.  A machine that read an APIC
/// id would answer with it here, and the slot would stay the kernel's
/// numbering.
pub fn current_cpu_id() -> usize {
    0
}

/// Whether this is the CPU the boot started on: this machine starts one, so it
/// always is.
///
/// The same question `arch_riscv64` answers by reading its slot.  What the trap
/// path asks it for is whether this CPU may touch the external interrupt
/// controller, and a machine with one CPU has one controller context.
pub fn boot_cpu_owns_this_trap() -> bool {
    true
}

/// Send an inter-processor interrupt: this machine starts no second CPU, so
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
