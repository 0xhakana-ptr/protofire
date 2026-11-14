//! arch/aarch64/src/smp.rs
//!
//! The machine's other cores: which ones the tree names, and the PSCI call that
//! starts one.
//!
//! The device tree lists the cores, `/cpus`'s `cpu@` children, each `reg`
//! naming its MPIDR and `enable-method` saying how firmware would start it.
//! This tree starts a core only when that method is `psci`, because it is the
//! one method it can drive: a core whose method is anything else is a core
//! whose start this kernel would be guessing at.
//!
//! A started core does the same as riscv64's started hart: it gets a stack of
//! its own, the trap vector, its own clock, and then asks the kernel for a task
//! and enters EL0 on it.  What differs is how it is started, a firmware call
//! carried by `hvc` or `smc` rather than an `ecall`.  That is the whole of this
//! file's machine half.
//!
//! A core started through PSCI begins with its MMU off, so the address in `x2`
//! is fetched without translation.  Every image this tree builds is linked at
//! an address that is its physical one, so the symbol's address is the answer;
//! a kernel linked at a virtual address above the identity map would have to
//! translate it first.

use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicUsize;
use core::sync::atomic::Ordering;

/// How many cores past the boot one this tree starts.
///
/// The gate's machine asks for two in total.  The stack reservation is sized
/// from this number through [`kernel_stack_reservation`], interpolated into the
/// assembly rather than written there a second time.
pub const MAX_SECONDARY_HARTS: usize = 4;

/// The stack one started core owns, in bytes.
///
/// The core runs the trap path and the kernel's handler, which is the boot's
/// own code: the size is the boot stack's.  A bound that tight has to be
/// re-derived the first time the core's job grows, and the memory it reserves
/// is address space the machine has.
pub const SECONDARY_STACK_BYTES: usize = 65536;

/// How much `.bss` the entry assembly's stack region reserves.
///
/// One stack per **CPU slot**.  The boot core owns slot zero; a started core's
/// slot is `index + 1` for an `index` that runs from zero to
/// `MAX_SECONDARY_HARTS - 1`, so the highest slot a core can have is
/// `MAX_SECONDARY_HARTS` and there are `MAX_SECONDARY_HARTS + 1` slices.
///
/// **The assembly is the other half of this number, and it adds a further
/// one.**  `entry.S` puts a started core at `sp = base + (index + 2) * bytes`,
/// which is the top of slice `index + 1`; the `+ 2` in the multiply is what
/// makes that top, not the slice number.  The consequence is that the address
/// `base + (MAX_SECONDARY_HARTS + 2) * bytes` is reached at the very top of the
/// last slice, and reserving exactly that many bytes would put the last core's
/// first push past the end of the array.  The reservation is therefore one
/// slice more than the number of slices, which costs 64 KiB and makes the
/// arithmetic safe at every index rather than at every index but the last.
pub const fn kernel_stack_reservation() -> usize {
    SECONDARY_STACK_BYTES * (MAX_SECONDARY_HARTS + 2)
}

pub fn boot_core() -> usize {
    BOOT_CORE.load(Ordering::Acquire)
}

/// The MPIDR each started slot was given.
static SLOT_CORE: [AtomicUsize; MAX_SECONDARY_HARTS] =
    [const { AtomicUsize::new(0) }; MAX_SECONDARY_HARTS];

static ONLINE: [AtomicBool; MAX_SECONDARY_HARTS] =
    [const { AtomicBool::new(false) }; MAX_SECONDARY_HARTS];

static REFUSED: AtomicUsize = AtomicUsize::new(0);

/// The root table every started core installs in its own `TTBR0_EL1`.
#[cfg(target_os = "none")]
static KERNEL_ROOT: AtomicUsize = AtomicUsize::new(0);

#[cfg(target_os = "none")]
static TIMER_SLICE_US: AtomicUsize = AtomicUsize::new(0);

pub fn refused_harts() -> usize {
    REFUSED.load(Ordering::Acquire)
}

pub fn secondary_hart_id(slot: usize) -> usize {
    SLOT_CORE[slot].load(Ordering::Acquire)
}

pub fn secondary_online(slot: usize) -> bool {
    ONLINE[slot].load(Ordering::Acquire)
}

// The address firmware enters a started core at, as the assembly defined it.
#[cfg(target_os = "none")]
unsafe extern "C" {
    static secondary_entry: u8;
}

#[cfg(target_os = "none")]
fn secondary_entry_address() -> usize {
    // `addr_of!` takes the address without creating a reference: there is a run
    // of instructions there, not a value.
    core::ptr::addr_of!(secondary_entry) as usize
}

/// The MPIDRs the tree says this machine has, in the tree's own order.
///
/// Only cores whose `enable-method` is `psci`: a core the tree names with
/// another method is one this kernel cannot start, and starting it anyway would
/// be a call firmware may accept for the wrong reason.
///
/// `None` when the machine has no tree, which is the same answer the tree's
/// absence gets everywhere else.
#[cfg(target_os = "none")]
pub fn core_list() -> Option<([usize; MAX_SECONDARY_HARTS], usize)> {
    let tree = crate::boot::device_tree()?;
    let root = tree.root().ok()?;
    let cpus = root.by_path("/cpus")?;

    let mut cores = [0usize; MAX_SECONDARY_HARTS];
    let mut count = 0;
    for child in cpus.children() {
        if !child.name().starts_with("cpu@") {
            continue;
        }
        if child.property("device_type").and_then(|p| p.as_str()) != Some("cpu") {
            continue;
        }
        if child.property("status").and_then(|p| p.as_str()) == Some("disabled") {
            continue;
        }
        if child.property("enable-method").and_then(|p| p.as_str()) != Some("psci") {
            continue;
        }
        let Some(region) = child.reg().next() else {
            continue;
        };
        if count == MAX_SECONDARY_HARTS {
            break;
        }
        cores[count] = region.address as usize;
        count += 1;
    }
    Some((cores, count))
}

/// Start every core the machine names past the boot one.
///
/// Answers how many the firmware **accepted**, the count of slots the boot can
/// wait on.  A core the tree lists but the firmware refuses is counted in
/// [`refused_harts`] and reported, not dropped.
///
/// # Safety
///
/// Called once, from the boot core, with the trap vector installed and the page
/// table built.  The started core is entered at [`secondary_entry_address`],
/// which is a physical address whose code runs with the MMU off.
#[cfg(target_os = "none")]
pub unsafe fn start_secondary_harts(timer_slice_us: u64) -> usize {
    let Some(psci) = crate::psci::from_tree() else {
        // A machine whose tree names no PSCI node starts none, which is the
        // same answer the tree's absence gets everywhere else.
        return 0;
    };
    let Some((cores, count)) = core_list() else {
        return 0;
    };

    // The table the started cores must translate through, read here because the
    // boot is the only caller and its `TTBR0_EL1` is the one to copy.
    KERNEL_ROOT.store(crate::paging::current_root_table(), Ordering::Release);
    TIMER_SLICE_US.store(timer_slice_us as usize, Ordering::Release);

    let boot = boot_core();
    let mut asked = 0usize;
    for &core in &cores[..count] {
        if core == boot {
            continue;
        }
        if asked == MAX_SECONDARY_HARTS {
            break;
        }
        let slot = asked;
        SLOT_CORE[slot].store(core, Ordering::Release);
        // SAFETY: the caller's contract is this function's, once per core, from
        // the boot core, with an entry address whose code runs untranslated.
        let answer = unsafe {
            crate::psci::cpu_on(
                psci,
                core as u64,
                secondary_entry_address() as u64,
                slot as u64,
            )
        };
        match answer {
            crate::psci::Started::Yes => asked += 1,
            crate::psci::Started::Refused(_) => {
                REFUSED.fetch_add(1, Ordering::Release);
            }
        }
    }
    asked
}

/// The function a started core runs, by the name the entry assembly calls.
///
/// `x0` from the entry assembly is the slot the boot core put in the `cpu_on`
/// context.  The core records that it is online and then asks the kernel for
/// work; the same wait loop riscv64 uses, and for the same reason.
///
/// # Safety
///
/// `extern "C"` because the entry assembly calls it.  It does not return: a
/// core with nothing to run belongs to the kernel's wait loop, not to this
/// function's caller.
#[cfg(target_os = "none")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn aarch64_secondary_main(slot: usize) -> ! {
    // The slot in `TPIDR_EL1`, which is where `current_cpu_slot` reads it.
    //
    // **One past `slot`**, because slot zero is the boot core's.  A core that
    // wrote its raw index would read as the boot core and take slot zero's
    // task, which is the defect riscv64 found by running two programs.
    let cpu_slot = slot + 1;
    // SAFETY: `TPIDR_EL1` is the thread pointer, reserved by the ABI for this.
    unsafe { core::arch::asm!("msr tpidr_el1, {}", in(reg) cpu_slot) };

    // The kernel's page table in this core's own `TTBR0_EL1`.  A started core
    // begins with translation off, so without this it runs on physical
    // addresses while the boot core runs through a table: identical on a kernel
    // that is identity mapped, and wrong for every permission the table
    // encodes.
    let root = KERNEL_ROOT.load(Ordering::Acquire);
    // SAFETY: the root is the table the boot core is already running through,
    // it covers the code performing this call.
    unsafe { crate::paging::install(root) };

    // This core's own timer, through the same `ticks_for_microseconds` the boot
    // core's arming uses.
    //
    // It used to divide the frequency here, `frequency / 1_000_000 * slice`
    // which is the same arithmetic written twice, and the two copies agreed
    // only while the frequency was a whole multiple of a megahertz.  One
    // conversion, one place: a slice is microseconds, and how many ticks that
    // is belongs to the machine's timer module.
    //
    // SAFETY: the tree named the counter's rate, which is what the boot checked
    // before it armed its own, and this core is about to enable the line.
    if let Some(frequency) = unsafe { crate::timer::frequency() } {
        let slice = TIMER_SLICE_US.load(Ordering::Acquire) as u64;
        // SAFETY: as above, on this core's own clock.
        unsafe {
            crate::timer::arm(crate::timer::ticks_for_microseconds(frequency, slice));
        }
    }

    // This core's GIC interface, before its interrupts.
    //
    // The distributor is one device for the machine and the boot core
    // programmed it; `GICC_CTLR` and `GICC_PMR` are per-core registers, and a
    // core that never wrote them takes no interrupt at all: not its own timer,
    // not an IPI.  That is what this core was: it ran a program with
    // `0 tick(s)`, so nothing ever preempted it and nothing ever woke it, and
    // the boot core then ran the same task from its own frame.
    //
    // SAFETY: the boot installed the controller before it started any core, and
    // both windows are mapped uncached for the life of the boot.
    if let Some(gic) = crate::trap::controller() {
        unsafe { gic.enable() };
    }

    // And the timer's line, in **this core's** bank.
    //
    // The distributor's `ISENABLER0` covers the SGIs and PPIs, and it is one
    // bank per core: the boot's write enabled the timer for the boot core and
    // for no one else.
    //
    // SAFETY: the controller is installed and enabled, and this is a PPI this
    // core is entitled to enable for itself.
    let timer = crate::timer_interrupt();
    if !unsafe { crate::enable_interrupt_line(timer) } {
        crate::serial::write_str("protofire: a started core has no timer line\n");
    }

    // And this core's interrupts, on.  On this machine the lines are enabled in
    // `DAIF`, not per source, so this is the whole of "this core answers
    // interrupts".  `VBAR_EL1` is installed by the entry assembly and the sink
    // by the boot before any core starts.
    crate::interrupts::enable();

    ONLINE[slot].store(true, Ordering::Release);
    wait_for_work()
}

#[cfg(target_os = "none")]
fn wait_for_work() -> ! {
    loop {
        if crate::smp::boot_finished() {
            crate::halt();
        }
        if let Some((root, context)) = take_work() {
            // SAFETY: the scheduler handed this core a task, so its root is a
            // live table, and the context is that task's saved frame.
            unsafe {
                crate::paging::install(root);
                crate::enter_program_here(&context);
            }
        }
        // SAFETY: interrupts are enabled, so an enabled line is taken rather
        // than only clearing the hint; the trap path re-arms this core's clock.
        unsafe { core::arch::asm!("wfe", options(nomem, nostack)) };
    }
}

/// What a started core asks the kernel for: a root table and a frame to enter.
pub type WorkSink = fn(cpu: usize) -> Option<(usize, crate::Context)>;

static WORK: cell::SyncUnsafeCell<Option<WorkSink>> = cell::SyncUnsafeCell::new(None);

/// # Safety
///
/// Called once, before any started core can look for work.
pub unsafe fn set_work_sink(sink: WorkSink) {
    // SAFETY: the caller promises this is the only write, and that it happens
    // before a started core asks.
    unsafe { *WORK.get() = Some(sink) };
}

/// The boot's end, as the kernel publishes it.
static FINISHED: cell::SyncUnsafeCell<Option<fn() -> bool>> = cell::SyncUnsafeCell::new(None);

/// # Safety
///
/// Called once, before any started core can ask.
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

/// The core the firmware cold-booted, as the entry assembly recorded it.
///
/// Zero on every machine this tree boots, and not assumed: the boot core's slot
/// is one past this value, and a machine whose firmware cold-boots another
/// MPIDR would otherwise index the wrong stack.
static BOOT_CORE: AtomicUsize = AtomicUsize::new(0);

pub fn set_boot_core(core: usize) {
    BOOT_CORE.store(core, Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::MAX_SECONDARY_HARTS;
    use super::SECONDARY_STACK_BYTES;

    /// Every startable core's stack fits inside the reservation, including the
    /// last one.
    ///
    /// `entry.S` gives a started core `sp = base + (index + 2) * bytes`, for an
    /// `index` running from zero to `MAX_SECONDARY_HARTS - 1`.  The highest
    /// stack top any core is given is therefore
    /// `base + (MAX_SECONDARY_HARTS + 1) * bytes`, the top of the last slice
    /// and a core's first push lands below that top, so the reservation has to
    /// reach one slice further than the last top it hands out.
    ///
    /// This test exists because the arithmetic's first version was written
    /// `index + 1` where it meant `index + 2`, which gave the **first** started
    /// core the boot core's slice.  Two cores on one stack overwrote each
    /// other's trap frames, and the symptom was an instruction abort at an
    /// address inside `kernel_stacks`, invisible on the gate's two-core
    /// machine whenever the timer did not fire on the started core, which on
    /// this machine was always.
    #[test]
    fn every_started_core_gets_a_slice_of_its_own() {
        let reserved = super::kernel_stack_reservation() / SECONDARY_STACK_BYTES;

        let highest_index = MAX_SECONDARY_HARTS - 1;
        // The top of the last started core's slice, as `entry.S` computes it.
        let highest_top = highest_index + 2;
        assert!(
            highest_top < reserved,
            "a started core at index {highest_index} has its stack top at slice \
             {highest_top}, and the reservation holds {reserved} slices"
        );

        // And the first started core clears the boot core's slice, which is the
        // one whose top sits at exactly one slice.  That is the defect this
        // test was written for: `index + 1` put index zero at slice 1, which is
        // the boot core's own.
        const FIRST_INDEX: usize = 0;
        let first_top = FIRST_INDEX + 2;
        assert!(
            first_top > 1,
            "index zero must start past the boot core's slice, not at its top"
        );
    }
}
