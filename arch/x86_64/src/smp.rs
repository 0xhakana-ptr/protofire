//! arch/x86_64/src/smp.rs
//!
//! The machine's other CPUs: the page a started one is entered at, the INIT
//! and SIPI that start it, and what it does before it asks for work.
//!
//! There is no firmware call here.  An application processor on this machine
//! is started by the boot CPU's local APIC: an INIT interrupt resets it, and a
//! start-up interrupt names the page it begins executing at, in 16-bit real
//! mode, with nothing but that page.  [`ap-start.S`](../asm) is that page, and
//! this module is everything around it: how many CPUs to ask for, the
//! per-start handoff, the stack and the controller each started CPU sets up
//! for itself, and the wait loop it shares in shape with the other machines'
//! started cores.
//!
//! How many CPUs exist is asked of the firmware configuration interface,
//! `fw_cfg`, whose selector `0x0005` answers the count.  No ACPI table is
//! parsed, so the count is the machine's own word rather than this kernel's
//! guess, and a count that reads as garbage (no interface, or a number past
//! any machine) means none are asked for, which is the same honest zero the
//! other machines answer when their firmware names no start.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

/// How many CPUs past the boot one this tree starts.
///
/// The gate's machine asks for two in total.  The stack reservation is sized
/// from this number through [`kernel_stack_reservation`].
pub const MAX_SECONDARY_HARTS: usize = 4;

/// The stack one started CPU owns, in bytes.
///
/// The core runs the trap path and the kernel's handler, which is the boot
/// stack's own size.
pub const SECONDARY_STACK_BYTES: usize = 65536;

/// How much `.bss` the trampoline's stack region reserves.
///
/// One stack per **CPU slot**; the boot CPU runs on the boot stack it arrived
/// with, so the boot's slice here is spare, and the CPU started into slot `s`
/// runs on slice `s + 1`.
pub const fn kernel_stack_reservation() -> usize {
    SECONDARY_STACK_BYTES * (MAX_SECONDARY_HARTS + 1)
}

/// The page a SIPI starts a CPU into, and the vector that names it.
///
/// Vector 8 names the page at `8 * 0x1000`, which is where the linker places
/// the `.trampoline` section.  The address is a fact of the linker script and
/// the vector is its arithmetic, and both are here because the boot CPU writes
/// the handoff through one and sends the other.
pub const TRAMPOLINE_ADDRESS: usize = 0x8000;
pub const TRAMPOLINE_VECTOR: u8 = 0x08;

/// The handoff words on the trampoline page.
///
/// The offsets are `ap-start.S`'s own: the page opens with the jump over them,
/// and the words sit from the sixteenth byte.  This side only writes through
/// them.  The fourth word, the boot page table's address, is resolved at link
/// time and never written.
#[cfg(target_os = "none")]
const HANDOFF_ENTRY: usize = 16;
#[cfg(target_os = "none")]
const HANDOFF_STACK: usize = 20;
#[cfg(target_os = "none")]
const HANDOFF_SLOT: usize = 24;

/// The MSR that holds this CPU's `GS` base, which is where the slot lives.
///
/// The kernel uses no segment otherwise, and a program at ring 3 can neither
/// read nor write the base, so one write per CPU at its start is the whole of
/// the per-CPU identity.
#[cfg(target_os = "none")]
const IA32_GS_BASE: u32 = 0xC000_0101;

/// The `fw_cfg` ports: a selector written to one, data read from the other.
#[cfg(target_os = "none")]
const FW_CFG_SELECTOR: u16 = 0x510;
#[cfg(target_os = "none")]
const FW_CFG_DATA: u16 = 0x511;
/// The selector for `NB_CPU`, the machine's own CPU count.
#[cfg(target_os = "none")]
const FW_CFG_NB_CPU: u16 = 0x0005;

/// The MPIDR-equivalent each started slot was given: the APIC id this boot
/// asked to start into it.
static SLOT_CORE: [AtomicUsize; MAX_SECONDARY_HARTS] =
    [const { AtomicUsize::new(0) }; MAX_SECONDARY_HARTS];

/// The flag a started CPU stores the moment it is running.
static ONLINE: [AtomicBool; MAX_SECONDARY_HARTS] =
    [const { AtomicBool::new(false) }; MAX_SECONDARY_HARTS];

/// The root table every started CPU installs in its own `cr3`.
#[cfg(target_os = "none")]
static KERNEL_ROOT: AtomicUsize = AtomicUsize::new(0);

/// The time slice a started CPU arms for itself when it enters a program.
#[cfg(target_os = "none")]
static TIMER_SLICE_US: AtomicUsize = AtomicUsize::new(0);

/// The APIC id this boot asked to start into `slot`.
pub fn secondary_hart_id(slot: usize) -> usize {
    SLOT_CORE[slot].load(Ordering::Acquire)
}

/// Whether the CPU started into `slot` has recorded that it is running.
pub fn secondary_online(slot: usize) -> bool {
    ONLINE[slot].load(Ordering::Acquire)
}

/// Which CPU this code runs on, read back from the `GS` base this CPU wrote.
///
/// The boot CPU writes zero, a started CPU its slot, each at its own start, so
/// the register is never firmware's answer to a question the kernel asked.
#[cfg(target_os = "none")]
pub fn current_cpu_slot() -> usize {
    // SAFETY: reads the `GS` base MSR, which this kernel wrote on every CPU.
    unsafe { crate::apic::read_msr(IA32_GS_BASE) as usize }
}

/// The host build's answer: one CPU, slot zero.
#[cfg(not(target_os = "none"))]
pub fn current_cpu_slot() -> usize {
    0
}

/// Write this CPU's slot into its `GS` base.
///
/// # Safety
///
/// Called once, on each CPU, before any trap can arrive on it.
#[cfg(target_os = "none")]
pub unsafe fn set_cpu_slot(slot: usize) {
    // The segment register's selector write comes first, on purpose: writing
    // a selector to `GS` loads the descriptor's base into the register's MSR,
    // and the descriptor's base is zero, so a selector written after the MSR
    // would answer the slot write with zero, and the CPU would spend its life
    // reporting itself as the boot one, taking its ticks and its IPIs onto
    // slot zero's record.  The selector itself matters only if something uses
    // a `gs:`-prefixed access; nothing does, and the write says so rather
    // than leaving the reset value.  `ax` is named as an output, because the
    // instruction writes it and the compiler is entitled to keep a value in
    // the register across the block: an undeclared clobber turned one
    // register's low half into 0x10 and sent a TSS index of one to sixteen.
    // SAFETY: writes a data selector to `gs`.
    unsafe {
        core::arch::asm!(
            "mov ax, 0x10",
            "mov gs, ax",
            out("ax") _,
            options(nostack, preserves_flags)
        );
    }
    // SAFETY: the MSR is this kernel's per-CPU slot, and this is the last
    // write it gets.
    unsafe { crate::apic::write_msr(IA32_GS_BASE, slot as u64) };
}

/// The machine's own id for the CPU this code runs on: the local APIC's id.
///
/// The register is per-CPU at one address, which is the whole reason the id is
/// readable this way: every CPU reads its own.
pub fn current_cpu_id() -> usize {
    #[cfg(target_os = "none")]
    {
        // SAFETY: reads the APIC's id register, whose window the boot's page
        // table maps.
        match unsafe { crate::apic::Apic::probe() } {
            Some(apic) => (unsafe { apic.id() }) as usize,
            None => 0,
        }
    }
    #[cfg(not(target_os = "none"))]
    {
        0
    }
}

/// The top of the stack slice the CPU started into `slot` runs on.
#[cfg(target_os = "none")]
fn secondary_stack_top(slot: usize) -> usize {
    // The symbol is the trampoline's `.bss`, and `addr_of!` takes its base
    // without creating a reference: there is storage there, not a value.
    unsafe extern "C" {
        static kernel_stacks: u8;
    }
    core::ptr::addr_of!(kernel_stacks) as usize + (slot + 2) * SECONDARY_STACK_BYTES
}

// The trampoline's bytes, as the image carries them.  The section lives in
// `.rodata`, and the linker names its two ends; the boot CPU copies what is
// between them to the entry address before the first start.  The symbols are
// the linker script's, and `addr_of!` takes their addresses without creating
// a reference, because a section boundary is storage and not a value.  A
// plain comment rather than a doc comment: rustdoc generates nothing for an
// extern block, and a doc comment here is a warning the gate refuses.
unsafe extern "C" {
    static __trampoline_image_start: u8;
    static __trampoline_image_end: u8;
}

/// The machine's own CPU count, from `fw_cfg`.
///
/// `None` when the answer is not a count: an interface that is not there reads
/// back ones, and a count of zero names no machine.  The bound is generosity
/// rather than knowledge, any real machine is below it, and a count above it
/// is an answer this kernel refuses to act on.
///
/// The count arrives lowest byte first.  The interface's other fields are
/// big-endian, the RAM size reads `20 00 00 00` for half a gigabyte, and the
/// count read the same way said `02 00 00 00` for a two-CPU machine, which is
/// one byte shifted and no count at all; read low byte first it says two.  The
/// probe that established this is gone and the boot line is what checks the
/// answer: a count the gate cannot reach prints as a start nobody made.
#[cfg(target_os = "none")]
fn fw_cfg_cpu_count() -> Option<u32> {
    crate::port::outw(FW_CFG_SELECTOR, FW_CFG_NB_CPU);
    let mut count = 0u32;
    for shift in [0u32, 8, 16, 24] {
        count |= (crate::port::inb(FW_CFG_DATA) as u32) << shift;
    }
    if count == 0 || count > 4096 {
        None
    } else {
        Some(count)
    }
}

/// A wait that costs no controller state: one port write to the POST port per
/// unit.
///
/// The delays an INIT-SIPI sequence wants are the firmware's, ten milliseconds
/// and two hundred microseconds, and nothing on this machine measures time
/// this early in the boot.  The counts below are chosen generously against an
/// emulator's port speed, because a too-long settle costs boot time and a
/// too-short one costs a start that never happened.
#[cfg(target_os = "none")]
fn wait(units: u32) {
    for _ in 0..units {
        crate::port::outb(0x80, 0);
    }
}

/// Start every CPU the machine reports past the boot one, one at a time.
///
/// One at a time, not as a broadcast, because the trampoline's handoff words
/// are one page's: a second CPU entering it while the first was still reading
/// would build its stack from the first's.  Each start is followed by a bounded
/// wait for the CPU to record that it is running, which is what makes the next
/// start's handoff write safe.
///
/// Answers how many starts were attempted.  A CPU the sequence reached but
/// that never ran is not registered here; the boot's own loop reports it per
/// slot, and the count is what the boot can wait on.
///
/// # Safety
///
/// Called once, from the boot CPU, with the interrupt table installed and the
/// kernel's root table active.  The started CPU is entered at the trampoline,
/// whose code runs untranslated through the boot page table.
#[cfg(target_os = "none")]
pub unsafe fn start_secondary_harts(timer_slice_us: u64) -> usize {
    let Some(apic) = (unsafe { crate::apic::Apic::probe() }) else {
        return 0;
    };
    let Some(count) = fw_cfg_cpu_count() else {
        return 0;
    };
    KERNEL_ROOT.store(crate::paging::current_root_table(), Ordering::Release);
    TIMER_SLICE_US.store(timer_slice_us as usize, Ordering::Release);

    // The trampoline, copied down to the page its code names.  Once, before
    // any start: the bytes are position-fixed to the entry address, so the
    // copy is the last thing between the image's copy and a CPU that executes
    // it.
    //
    // SAFETY: the destination is the page the kernel mapped as a device
    // window, and the source is the image's own bytes.
    unsafe {
        let from = core::ptr::addr_of!(__trampoline_image_start) as usize;
        let to = core::ptr::addr_of!(__trampoline_image_end) as usize;
        core::ptr::copy_nonoverlapping(from as *const u8, TRAMPOLINE_ADDRESS as *mut u8, to - from);
    }

    let entry = x86_64_secondary_main as *const () as usize;
    let candidates = (count as usize - 1).min(MAX_SECONDARY_HARTS);
    let mut asked = 0usize;
    for slot in 0..candidates {
        let apic_id = (slot + 1) as u32;
        SLOT_CORE[slot].store(apic_id as usize, Ordering::Release);

        // The handoff, written through the window the kernel mapped for this
        // page.  Every address in the image is below four gigabytes, which is
        // what makes the `u32` words the trampoline reads the whole story.
        //
        // SAFETY: the trampoline page is mapped as a device window, uncached,
        // so the writes are visible to a CPU that starts after they land.
        unsafe {
            core::ptr::write_volatile(
                (TRAMPOLINE_ADDRESS + HANDOFF_ENTRY) as *mut u32,
                entry as u32,
            );
            core::ptr::write_volatile(
                (TRAMPOLINE_ADDRESS + HANDOFF_STACK) as *mut u32,
                secondary_stack_top(slot) as u32,
            );
            core::ptr::write_volatile((TRAMPOLINE_ADDRESS + HANDOFF_SLOT) as *mut u32, slot as u32);
        }

        // INIT: reset the target CPU and leave it waiting for a start-up.
        //
        // SAFETY: the caller's contract is this function's, once per CPU,
        // from the boot CPU.
        unsafe {
            apic.send_init(apic_id);
        }
        wait(100_000);
        // The start-up interrupt.  The convention's second send is reserved
        // for a target that never took the first, and it is sent below only
        // for one: this machine's controller applies a start-up to a running
        // CPU rather than ignoring it, and a running CPU that took one finds
        // itself back at the trampoline's first byte with its flags at their
        // reset value, mid-boot.
        //
        // SAFETY: as above.
        unsafe {
            apic.send_startup(apic_id, TRAMPOLINE_VECTOR);
        }
        // The first send's own wait: a started CPU records that it is running
        // within milliseconds of the interrupt, so a target still silent
        // after this many spins is one the second send is for.
        let mut spins = 0u64;
        while !ONLINE[slot].load(Ordering::Acquire) && spins < 5_000_000 {
            spins += 1;
        }
        if !ONLINE[slot].load(Ordering::Acquire) {
            //
            // SAFETY: as above.
            unsafe {
                apic.send_startup(apic_id, TRAMPOLINE_VECTOR);
            }
        }

        // Bounded: a CPU that never records is reported by the boot's own
        // loop, and waiting here forever for it would hang the boot on a CPU
        // it can no longer do anything about.
        let mut spins = 0u64;
        while !ONLINE[slot].load(Ordering::Acquire) && spins < 50_000_000 {
            spins += 1;
        }
        asked += 1;
    }
    asked
}

/// The function a started CPU runs, by the name the trampoline's handoff calls.
///
/// The slot is the trampoline's handoff word.  The CPU writes its own slot,
/// installs the kernel's root table, loads its own descriptor table and task
/// state segment, brings up its own local APIC, and asks the kernel for work;
/// the same wait loop the other machines' started cores run, and for the same
/// reason.
///
/// # Safety
///
/// `extern "C"` because the trampoline jumps to it.  It does not return: a
/// CPU with nothing to run belongs to the kernel's wait loop, not to this
/// function's caller.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn x86_64_secondary_main(slot: usize) -> ! {
    // The slot in `GS` base, **one past `slot`**, because slot zero is the
    // boot CPU's.  A CPU that wrote its raw index would read as the boot CPU
    // and take slot zero's task, the defect the other machines found by
    // running two programs.
    //
    // The kernel's page table in this CPU's own `cr3`.  The trampoline ran the
    // boot page table, which maps everything identity and writable; the
    // kernel's root is what the permissions and the program spaces live in.
    let root = KERNEL_ROOT.load(Ordering::Acquire);
    // SAFETY: the root is the table the boot CPU is already running through,
    // and it covers the code performing this call.
    unsafe { crate::paging::install(root) };

    // This CPU's own descriptor table and task state segment.  The `RSP0` a
    // ring-3 interrupt loads is per-CPU, and a second CPU loading the boot's
    // TSS would have both CPUs' interrupts land on one stack.
    //
    // SAFETY: the boot installed slot zero's before it started any CPU, and
    // this slot's table is a distinct static.
    unsafe { crate::gdt::install_for(slot + 1, secondary_stack_top(slot)) };

    // The slot in `GS` base, **one past `slot`**, because slot zero is the
    // boot CPU's, and **after** the descriptor tables: the table install
    // reloads every segment register, and a selector written to `GS` sets the
    // register's base MSR to the descriptor's base, which is zero, so a slot
    // written before it would be answered with zero from here on, and the CPU
    // would report itself as the boot one, taking its ticks and its IPIs onto
    // slot zero's record.
    //
    // SAFETY: once per CPU, before any trap can arrive on it.
    unsafe { set_cpu_slot(slot + 1) };

    // The interrupt table, into this CPU's own `IDTR`.  The table itself is
    // shared memory the boot CPU filled; only the register is per-CPU.
    //
    // SAFETY: the table was built by the boot before any CPU was started.
    unsafe { crate::idt::load_on_this_cpu() };

    // This CPU's own local APIC, enabled and recorded.  The record is the one
    // the trap path reads to end an interrupt, and a first IPI can arrive
    // before the boot's own timer bring-up would have recorded it, so the
    // started CPU records it itself; the value is the machine's one APIC
    // window, identical to what the boot CPU writes later.
    //
    // SAFETY: the APIC's window is mapped, and this is the CPU's own
    // controller.
    match unsafe { local_apic_up() } {
        Some(apic) => unsafe { crate::trap::set_timer_controller(apic) },
        None => crate::serial::write_str("protofire: a started cpu has no apic\n"),
    }

    // And this CPU's own clock, armed from the rate the boot measured before
    // it started anyone: a CPU whose first tick never comes is one that never
    // preempts, and the boot's measurement is the only one there is.  The
    // registers are this CPU's own, at the one address every CPU's local APIC
    // answers at.
    if let Some(frequency) = unsafe { crate::timer_frequency() } {
        let slice = TIMER_SLICE_US.load(Ordering::Acquire) as u64;
        // SAFETY: the APIC is enabled and the table installed, so a tick is a
        // delivered interrupt rather than a silent countdown.
        unsafe { crate::arm_timer(frequency, slice) };
    }

    // And this CPU's interrupts, on.  The legacy controller was masked by the
    // boot CPU before it enabled its own flag, and the mask is the chip's,
    // shared, so there is nothing to repeat here.
    crate::interrupts::enable();

    ONLINE[slot].store(true, Ordering::Release);
    wait_for_work()
}

/// This CPU's local APIC, enabled: the global bit set if the INIT cleared it,
/// the spurious vector written, the answer recorded.
///
/// # Safety
///
/// Called once per started CPU, on the APIC window the boot's page table maps.
#[cfg(target_os = "none")]
unsafe fn local_apic_up() -> Option<crate::apic::Apic> {
    // SAFETY: reads and writes the APIC's base MSR; the write only sets the
    // enable bit the boot CPU's already has.
    let base = unsafe { crate::apic::read_msr(crate::apic::IA32_APIC_BASE) };
    if base & crate::apic::APIC_BASE_ENABLE == 0 {
        // SAFETY: as above.
        unsafe {
            crate::apic::write_msr(
                crate::apic::IA32_APIC_BASE,
                base | crate::apic::APIC_BASE_ENABLE,
            )
        };
    }
    // SAFETY: the base is enabled and mapped.
    let apic = unsafe { crate::apic::Apic::probe() }?;
    // SAFETY: the window is mapped; this is the CPU's own controller.
    unsafe { apic.enable() };
    Some(apic)
}

/// Wait until the kernel has a task for this CPU, then run it.
#[cfg(target_os = "none")]
fn wait_for_work() -> ! {
    loop {
        if crate::smp::boot_finished() {
            crate::halt();
        }
        if let Some((root, context)) = take_work() {
            // SAFETY: the scheduler handed this CPU a task, so its root is a
            // live table, and the context is that task's saved frame.
            unsafe {
                crate::paging::install(root);
                crate::enter_user_with_context(&context);
            }
        }
        // Interrupts are enabled, so a delivered vector is taken rather than
        // only ending the halt; the trap path re-arms this CPU's clock.
        crate::wait_for_a_wakeup();
    }
}

/// What a started CPU asks the kernel for: a root table and a frame to enter.
pub type WorkSink = fn(cpu: usize) -> Option<(usize, crate::Context)>;

/// The kernel's answer to what this core should run, if it installed one.
static WORK: cell::SyncUnsafeCell<Option<WorkSink>> = cell::SyncUnsafeCell::new(None);

/// The boot's end, as the kernel publishes it.
static FINISHED: cell::SyncUnsafeCell<Option<fn() -> bool>> = cell::SyncUnsafeCell::new(None);

/// # Safety
///
/// Called once, before any started CPU can look for work.
pub unsafe fn set_work_sink(sink: WorkSink) {
    // SAFETY: the caller promises this is the only write, and that it happens
    // before a started CPU asks.
    unsafe { *WORK.get() = Some(sink) };
}

/// # Safety
///
/// Called once, before any started CPU can ask.
pub unsafe fn set_finished_sink(sink: fn() -> bool) {
    // SAFETY: the caller promises this is the only write.
    unsafe { *FINISHED.get() = Some(sink) };
}

#[cfg(target_os = "none")]
pub fn boot_finished() -> bool {
    // SAFETY: written once before any started core asks, read after.
    unsafe { *FINISHED.get() }.is_some_and(|sink| sink())
}

#[cfg(target_os = "none")]
fn take_work() -> Option<(usize, crate::Context)> {
    // SAFETY: written once before any started core asks, read after.
    let sink = unsafe { *WORK.get() };
    sink?(crate::current_cpu_slot())
}

// The page a started CPU is entered at, assembled from `src/ap-start.S`.
#[cfg(target_os = "none")]
core::arch::global_asm!(include_str!("ap-start.S"), SECONDARY_STACK_RESERVATION = const kernel_stack_reservation());
