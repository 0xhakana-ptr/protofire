//! arch/riscv64/src/smp.rs
//!
//! The machine's other harts: which ones exist, and the one call that starts
//! one.
//!
//! ## What the machine has
//!
//! The device tree lists the harts, `/cpus`'s `cpu@` children, each `reg`
//! naming its hart id and `status` saying whether firmware means to use it,
//! and the firmware owns the power state.  A hart that is not running is parked
//! in M-mode, and S-mode cannot wake one by writing a register: it
//! **asks**, through the HSM extension, and the firmware enters the hart at
//! the address the ask names, with the hart's id in `a0` and the asker's
//! opaque word in `a1`.
//!
//! ## What a started hart does
//!
//! A started hart gets a stack of its own, the kernel's page table, its own
//! timer, its own lines, and then asks the kernel for a task.  It takes its
//! timer and inter-processor interrupts on its own, and it enters U-mode on the
//! task it was given: two harts run two programs at once, and the scheduler,
//! which is one lock, is what keeps them from being handed the same one.
//!
//! ## What it does not do
//!
//! It does not claim an external interrupt.  The `Plic` the boot installed
//! carries the boot hart's context, so a claim through it from another hart
//! completes a source nobody finishes.  The line stays disabled on a started
//! hart, and the dispatch says so if a machine ever enables it.
//!
//! It also has no load balancing and no task migration: a task stays on the CPU
//! that claimed it, because moving one would need a TLB shootdown and
//! `paging::flush_translation` is local to the hart that calls it.  A machine
//! with more work than CPUs runs what it has; one with more CPUs than work
//! leaves the extra CPUs in `wait_for_work`, which is the shape this tree
//! scales in.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

/// How many harts past the boot one this tree starts.
///
/// The gate's machine asks for two harts in total.  The stacks the entry
/// assembly reserves are sized from this number through
/// [`kernel_stack_reservation`], one fact, interpolated into the assembly
/// rather than written there a second time, and a machine whose tree names more
/// harts than the cap has a boot that starts the first of them rather than one
/// that guesses at a bigger reservation.
pub const MAX_SECONDARY_HARTS: usize = 4;

/// The stack one started hart owns, in bytes.
///
/// The hart runs the trap path and the kernel's handler, which is the boot's
/// own code: the size is the boot stack's, and it is generous on purpose.  A
/// bound that tight has to be re-derived the first time the hart's job grows,
/// and the memory it reserves is address space the machine has.
pub const SECONDARY_STACK_BYTES: usize = 65536;

/// How much `.bss` the entry assembly's stack region reserves.
///
/// One stack per **CPU slot**, and the boot hart owns one of them: the array is
/// indexed by slot, zero for the boot hart, and a started hart's is its slot
/// plus one.  So the count is `MAX_SECONDARY_HARTS + 1`, and a reservation that
/// counted only the started harts left the last slot pointing past its end.
pub const fn kernel_stack_reservation() -> usize {
    SECONDARY_STACK_BYTES * (MAX_SECONDARY_HARTS + 1)
}

/// The hart the firmware cold-booted, as the entry assembly recorded it.
static BOOT_HART: AtomicUsize = AtomicUsize::new(0);

/// Record the boot hart the entry assembly saw in `a0`.
///
/// Called once, from the entry assembly, before anything reads it.  The boot
/// hart is not assumed to be hart zero: it is whichever hart the firmware
/// chose, and the list of harts to start is the machine's minus this one.
pub fn set_boot_hart(hart: usize) {
    BOOT_HART.store(hart, Ordering::Release);
}

/// The hart the firmware cold-booted.
pub fn boot_hart() -> usize {
    BOOT_HART.load(Ordering::Acquire)
}

/// The hart id each started slot was given.
static SLOT_HART: [AtomicUsize; MAX_SECONDARY_HARTS] =
    [const { AtomicUsize::new(0) }; MAX_SECONDARY_HARTS];

/// The flag a started hart stores the moment it is running.
static ONLINE: [AtomicBool; MAX_SECONDARY_HARTS] =
    [const { AtomicBool::new(false) }; MAX_SECONDARY_HARTS];

/// How many harts the firmware refused to start, if it refused any.
static REFUSED: AtomicUsize = AtomicUsize::new(0);

/// The root table every started hart installs in its own `satp`.
///
/// `satp` is per-hart, so a hart that never writes it runs with translation
/// off while the boot hart runs through a table.  The two look alike on a
/// machine whose kernel is identity mapped, which is exactly what makes the
/// difference easy to miss: with `satp` clear there is no `U` bit, no
/// read-only text and no device window, and the first permission the kernel
/// leans on would not be enforced on that hart.
#[cfg(target_os = "none")]
static KERNEL_ROOT: AtomicUsize = AtomicUsize::new(0);

/// The timer slice a started hart arms for itself, in microseconds.
#[cfg(target_os = "none")]
static TIMER_SLICE_US: AtomicUsize = AtomicUsize::new(0);

/// The firmware's answer for the harts it would not start.
///
/// A refusal is a fact about the machine's state, not a reason to stop: the
/// boot reports it and carries on with the harts it has, which is what makes
/// the count a line a reader can act on rather than an error nobody sees.
pub fn refused_harts() -> usize {
    REFUSED.load(Ordering::Acquire)
}

/// The hart id the boot hart asked the firmware to start into `slot`.
pub fn secondary_hart_id(slot: usize) -> usize {
    SLOT_HART[slot].load(Ordering::Acquire)
}

/// Whether the hart started into `slot` has recorded that it is running.
pub fn secondary_online(slot: usize) -> bool {
    ONLINE[slot].load(Ordering::Acquire)
}

/// The harts this boot started that are online, as SBI's hart mask names them.
///
/// Built from what the firmware accepted rather than from the tree's list: a
/// mask that named a hart the firmware refused is a call the firmware may
/// answer with an error, and the error would say nothing about the harts that
/// are running.  Bit N is hart N, which is the encoding `hart_mask_base` of
/// zero selects; ids past the mask's reach are left out and the count of them
/// is what a caller learns from the mask being smaller than the list.
pub fn started_harts_mask() -> u64 {
    let mut mask = 0u64;
    let mut slot = 0;
    while slot < MAX_SECONDARY_HARTS {
        let hart = SLOT_HART[slot].load(Ordering::Acquire);
        if ONLINE[slot].load(Ordering::Acquire) && hart < 64 {
            mask |= 1u64 << hart;
        }
        slot += 1;
    }
    mask
}

/// The firmware's HSM extension, and the function that starts a hart.
///
/// The extension id is the ASCII of `"HSM"`, which is how the specification
/// names them: three bytes, big-endian, in the register that names them.
#[cfg(target_os = "none")]
const SBI_EXT_HSM: u64 = 0x48534D;
#[cfg(target_os = "none")]
const SBI_HSM_HART_START: u64 = 0;

/// Ask the firmware to enter `hart` at `start`, handing it `opaque`.
///
/// # Safety
///
/// Called once per hart, from the boot hart, after the bss is clear and the
/// trap vector's address is one a hart can be entered at.  The firmware
/// enters the target hart in S-mode with `a0` = the hart id and `a1` =
/// `opaque`, which is the contract the entry assembly's secondary path is
/// written against.
#[cfg(target_os = "none")]
unsafe fn sbi_hart_start(hart: u64, start: u64, opaque: u64) -> i64 {
    let error: i64;
    // SAFETY: the HSM hart-start call.  Every register the firmware can eat
    // is declared late-out, for the same reason the timer call's are: an
    // undeclared clobber is a register the interrupted code loses silently.
    unsafe {
        core::arch::asm!(
            "ecall",
            inlateout("a0") hart => error,
            inlateout("a1") start => _,
            inlateout("a2") opaque => _,
            lateout("a3") _,
            lateout("a4") _,
            lateout("a5") _,
            inlateout("a6") SBI_HSM_HART_START => _,
            inlateout("a7") SBI_EXT_HSM => _,
            options(nostack)
        )
    };
    error
}

/// Start every hart the machine names past the boot one.
///
/// Answers how many the firmware **accepted**, the count of slots the boot
/// can wait on.  A hart the tree lists but the firmware refuses is counted in
/// [`refused_harts`] and reported, not dropped: the difference between "the
/// machine has one hart" and "the machine has two and one refused" is the
/// whole of what a reader of the log needs.
///
/// `timer_slice_us` is the slice each started hart arms its own timer with.
/// It is the kernel's policy and the kernel passes it: this crate knows how to
/// arm a timer and not how long a slice should be.
///
/// The boot hart runs this after its own tables are up and the bss is clear:
/// the bss clear is the boot hart's, and a hart started before it would find
/// whatever the firmware left in the flags it is about to store.
///
/// # Safety
///
/// Called once, from the boot hart, with the trap vector installed and the
/// page table built.  The started hart is entered at
/// [`secondary_entry_address`], whose path touches only its own stack, the
/// vector, the page table, its own lines and the flags this module owns.
#[cfg(target_os = "none")]
pub unsafe fn start_secondary_harts(timer_slice_us: u64) -> usize {
    let Some((harts, count)) = crate::boot::hart_list() else {
        // A machine that cannot say what it has starts none of it, which is
        // the same answer the device tree's absence gets everywhere else.
        return 0;
    };
    // The table the started harts must translate through, read here because
    // the boot is the only caller and its `satp` is the one to copy.
    KERNEL_ROOT.store(crate::paging::current_root_table(), Ordering::Release);
    TIMER_SLICE_US.store(timer_slice_us as usize, Ordering::Release);
    let boot = boot_hart();
    let mut asked = 0usize;
    for &hart in &harts[..count] {
        if hart == boot {
            continue;
        }
        if asked == MAX_SECONDARY_HARTS {
            break;
        }
        let slot = asked;
        SLOT_HART[slot].store(hart, Ordering::Release);
        // SAFETY: the caller's contract is this function's, once per hart,
        // from the boot hart, with the entry address the secondary path owns.
        let error =
            unsafe { sbi_hart_start(hart as u64, secondary_entry_address() as u64, slot as u64) };
        if error == 0 {
            asked += 1;
        } else {
            REFUSED.fetch_add(1, Ordering::Release);
        }
    }
    asked
}

// The address the firmware enters a started hart at, as the assembly defined
// it.  A `//` and not a `///`: a doc comment on an extern block decorates
// nothing.
#[cfg(target_os = "none")]
unsafe extern "C" {
    static secondary_entry: u8;
}

#[cfg(target_os = "none")]
fn secondary_entry_address() -> usize {
    // `addr_of!` takes the address without creating a reference; there is a
    // run of instructions there, not a value.
    core::ptr::addr_of!(secondary_entry) as usize
}

/// The function a started hart runs, by the name the entry assembly calls.
///
/// The firmware hands back what the boot hart put in the ask: the hart's own
/// id in `a0` and the slot the boot hart chose in `a1`.  The slot is the only
/// thing the hart needs, its stack and its flag are both indexed by it, and
/// the boot hart only ever hands out slots the reservation holds, which is
/// the promise the entry assembly's stack setup is written against.
///
/// # Safety
///
/// `extern "C"` because the entry assembly calls it, with the registers the
/// firmware's start contract names.  It does not return: a hart with nothing
/// to run parks, and a park that returned would fall into whatever follows.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn riscv64_secondary_main(hart: usize, slot: usize) -> ! {
    let _ = hart;

    // The slot, for the window before this hart runs a program: `tp` is where
    // the kernel asks "which CPU am I", and firmware leaves whatever it likes
    // in the register.
    //
    // **One past `slot`**, because slot zero is the boot CPU's.
    //
    // This is a *starting* value and not the identity.  Once a program runs,
    // `trap_entry` computes the slot from the kernel stack it switched to and
    // restores the program's own `tp` on the way out, because a program's
    // register is the program's: the first version relied on this write alone,
    // and a program that zeroed `tp` made this hart report itself as CPU 0 and
    // take slot zero's task.
    let cpu_slot = slot + 1;
    // SAFETY: `tp` is the thread pointer, reserved by the ABI for exactly this.
    unsafe { core::arch::asm!("mv tp, {}", in(reg) cpu_slot, options(nomem, nostack)) };

    // The kernel's page table, on this hart.  `satp` is a per-hart register and
    // the firmware enters a started hart with it clear, so without this write
    // this hart runs untranslated while the boot hart runs through a table.
    // The addresses still resolve, which is what made the omission invisible;
    // what would not have held is every permission the table encodes.
    let root = KERNEL_ROOT.load(Ordering::Acquire);
    // SAFETY: the root is the table the boot hart is already running through,
    // it covers the code performing this call, and this hart has not yet
    // touched memory through any other mapping.
    unsafe { crate::paging::install(root) };

    // This hart's own timer.  A deadline is per-hart state the firmware holds,
    // so the boot hart arming its own would leave this one with none: the
    // enable without an arm is a line that never fires.
    //
    // SAFETY: the tree named the counter's rate, which is what the boot checked
    // before it armed its own, and this hart is about to enable the line.
    if let Some(frequency) = unsafe { crate::timer::frequency() } {
        let slice = TIMER_SLICE_US.load(Ordering::Acquire) as u64;
        // SAFETY: as above, on this hart's own clock.
        unsafe { crate::timer::arm(crate::timer::ticks_for_microseconds(frequency, slice)) };
    }

    // The two lines this hart answers: its clock, and the inter-processor
    // interrupt another CPU sends it.  Not the external line: the controller
    // object the boot installed is the boot hart's context, and a source
    // claimed through the wrong context is a source nobody completes.
    //
    // SAFETY: `stvec` is installed by the entry assembly, the sink is installed
    // by the boot before it starts any hart, and this hart has a stack.
    unsafe {
        let _ = crate::enable_interrupt_line(crate::trap::TIMER_INTERRUPT);
        let _ = crate::enable_interrupt_line(crate::trap::SOFTWARE_INTERRUPT);
    }

    // Online, and then waiting with the machine's own enable set: `SIE` is what
    // turns a pending line into a trap, and the firmware leaves it clear on
    // entry.  The flag is stored **after** the enable, so "online" means the
    // hart can take an interrupt and not merely that its instructions ran.
    // SAFETY: this hart's own interrupt enable, set once the vector, the sink
    // and the stack behind them are all in place.
    unsafe { core::arch::asm!("csrsi sstatus, 2", options(nomem, nostack)) };
    ONLINE[slot].store(true, Ordering::Release);
    wait_for_work()
}

/// Wait here until the kernel has a task for this CPU, then run it.
///
/// The boot hart starts the other CPUs *before* it builds the scheduler, so a
/// started CPU that asked for a task immediately would find none.  It waits for
/// the boot to say work exists, and the way the boot says it is an
/// inter-processor interrupt: the same call the boot uses to prove a CPU takes
/// interrupts at all, sent again once the scheduler is installed.
///
/// `wfi` returns on the interrupt, the trap path counts it, and the loop asks
/// the kernel again.  A CPU spinning on a flag would burn its host's core for
/// the length of the boot, which on an emulator is the difference between two
/// CPUs and one CPU running twice as hot.
#[cfg(target_os = "none")]
fn wait_for_work() -> ! {
    loop {
        // The boot's own end, which a CPU has to notice for itself: `halt` on
        // another CPU stops that CPU, and this one is still running.
        if crate::smp::boot_finished() {
            crate::halt();
        }
        // The kernel's answer, asked as often as a wake arrives: `None` means
        // the scheduler has no task for this CPU, and the next IPI will ask
        // again.
        if let Some((root, context)) = take_work() {
            // SAFETY: the scheduler handed this CPU a task, so its root is a
            // live table, and the context is that task's saved frame, whose
            // entry and stack are `user` pages in it.
            unsafe {
                crate::paging::install(root);
                crate::enter_program_here(&context);
            }
        }
        // SAFETY: `SIE` is set, so an enabled line is taken rather than only
        // clearing the hint; the trap path re-arms this CPU's clock.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack)) };
    }
}

/// What a started CPU asks the kernel for: a root table and a frame to enter.
///
/// The kernel's half, injected: `arch` cannot name `kernel` without a cycle,
/// and the alternative, the kernel polling a flag this crate sets, would put
/// the scheduler's choice on the wrong side of the boundary.  The shape is the
/// one every other upward call in this tree uses, a sink installed once before
/// anything can reach it.
pub type WorkSink = fn(cpu: usize) -> Option<(usize, crate::Context)>;

/// The boot's end, as the kernel publishes it.
///
/// A second injected value beside the work source, and for the same reason:
/// `arch` cannot name `kernel`.  A direct call would be the cycle the layering
/// refuses; the flag lives in the kernel and this crate asks.
static FINISHED: cell::SyncUnsafeCell<Option<fn() -> bool>> = cell::SyncUnsafeCell::new(None);

/// Install the kernel's end-of-boot predicate.
///
/// # Safety
///
/// Called once, before any started CPU can ask.
pub unsafe fn set_finished_sink(sink: fn() -> bool) {
    // SAFETY: the caller promises this is the only write, and that it happens
    // before a started CPU looks.
    unsafe { *FINISHED.get() = Some(sink) };
}

/// Whether the boot is over.
///
/// Public because the trap path asks it: a CPU that takes any trap after the
/// boot ended must stop rather than resume a task whose pages are gone.
#[cfg(target_os = "none")]
pub fn boot_finished() -> bool {
    // SAFETY: written once before any started CPU asks, read after.
    unsafe { *FINISHED.get() }.is_some_and(|sink| sink())
}

/// The kernel's answer to "what should this CPU run", if it has installed one.
static WORK: cell::SyncUnsafeCell<Option<WorkSink>> = cell::SyncUnsafeCell::new(None);

/// Install the kernel's work source.
///
/// # Safety
///
/// Called once, before any started CPU can look for work.
pub unsafe fn set_work_sink(sink: WorkSink) {
    // SAFETY: the caller promises this is the only write, and that it happens
    // before a started CPU asks.
    unsafe { *WORK.get() = Some(sink) };
}

/// Ask the kernel what this CPU should run.
#[cfg(target_os = "none")]
fn take_work() -> Option<(usize, crate::Context)> {
    // SAFETY: written once before any started CPU asks, read after.
    let sink = unsafe { *WORK.get() };
    sink?(crate::current_cpu_slot())
}
