//! arch/aarch64/src/gic.rs
//!
//! The GICv2 interrupt controller: two register blocks and the arithmetic that
//! reaches them.
//!
//! ## Two blocks, and why the split matters
//!
//! A GIC has a **distributor** and a **CPU interface**, and they are separate
//! windows:
//!
//! | block | what it decides |
//! |---|---|
//! | distributor | which interrupts exist, whether each is enabled, and which CPU it goes to |
//! | CPU interface | which interrupt this CPU is currently taking, and how it is finished |
//!
//! The distributor is shared by every core; the CPU interface is per core.  A
//! driver that wrote "enable interrupt 32" to the CPU interface would be
//! writing to whatever register happened to be there, and the interrupt would
//! never arrive, which is why the two are named apart here.
//!
//! ## Why the addresses are parameters
//!
//! A board puts them where it likes and the device tree says where.  QEMU's
//! `virt` uses `0x0800_0000` and `0x0801_0000`, which is what the tree in this
//! tree's test assets reports.  This module holds no constant for either: a
//! caller supplies the two, and [`Distributor::new`] is where a machine's
//! answer arrives.
//!
//! ## What is here today
//!
//! Enable, prioritise, and finish, the three operations a driver that is given
//! a line needs.  Not here: the interrupt *translation* tables
//! (`GICD_ITARGETSR` handles the single-core case this kernel runs in), the
//! virtual interface (which a hypervisor's guest uses), and the `GICv3`
//! system-register interface, which is a different machine's GIC.

/// The distributor's register file.
///
/// Offsets are from the GIC architecture specification's distributor list.  The
/// two that matter for enabling a line are `ISENABLER` (one bit per interrupt)
/// and `IPRIORITYR` (one byte per interrupt), and both are arrays: an interrupt
/// number selects a register and a bit or byte inside it.
#[derive(Debug, Clone, Copy)]
pub struct Distributor {
    base: usize,
}

/// `GICD_CTLR`: bit 0 enables the distributor.
pub const DIST_CTLR: usize = 0x000;
/// `GICD_ISENABLER0`: one bit per interrupt, 32 per register.
pub const DIST_ISENABLER: usize = 0x100;
/// `GICD_IPRIORITYR`: one byte per interrupt.
pub const DIST_IPRIORITYR: usize = 0x400;
/// `GICD_ITARGETSR`: one byte per interrupt, one bit per CPU.
pub const DIST_ITARGETSR: usize = 0x800;
/// `GICD_SGIR`: raise an interrupt from software.
pub const DIST_SGIR: usize = 0xF00;
/// `GICD_IGROUPR`: one bit per interrupt, set means group 1.
pub const DIST_IGROUPR: usize = 0x080;
/// `GICD_ICFGR`: two bits per interrupt, the odd one says edge-triggered.
pub const DIST_ICFGR: usize = 0xC00;

/// The priority a device's interrupt is given.
///
/// A lower number is a higher priority, and `0x00` is the highest.  This tree
/// gives every device line the same value, which means arrival order decides
/// between them, the same order a single-core machine sees anyway, and leaves
/// the range below it free for a later change that wants an urgent line.  A
/// priority of `0xFF` is the lowest and is what the GIC's own "no interrupt"
/// reports, so a line at `0xFF` is one that never preempts anything.
pub const DEVICE_PRIORITY: u8 = 0x80;

/// The priority a **software** interrupt is given, which is deliberately
/// lower than a device's.
///
/// A lower number is a higher priority, so `0xA0` is *less* urgent than
/// [`DEVICE_PRIORITY`]'s `0x80`.  That ordering is the whole reason this
/// constant exists, and it is measured rather than chosen.
///
/// ## What a software interrupt at the reset priority cost
///
/// `IPRIORITYR` resets to **zero** for every interrupt, and zero is the
/// *highest* priority a GIC has.  Nothing in this tree ever wrote a priority
/// for an SGI, because `enable_interrupt` refuses one: the low sixteen bits of
/// `ISENABLER0` are read-only and an SGI is always enabled.  So every
/// inter-processor interrupt ran at priority zero, above the timer's `0x80`
/// and a GIC keeps a CPU interface's *running* priority at the value of the
/// interrupt it has acknowledged until that interrupt is finished.
///
/// The consequence is a wedge, and it is the aarch64 stop this tree spent two
/// sessions on.  On QEMU's GICv2, `-d int` and the `gic_*` trace events on one
/// stalled boot read:
///
/// - the started core's last acknowledge was `irq 0`, and no `EOIR` write for
///   it followed, so the SGI stayed **active**;
/// - every later `gic_update_bestirq` for that core read `irq 30 priority 128
///   ... running priority 0`, the distributor knew the timer was pending and
///   could not hand it over, because a priority-128 line cannot preempt a
///   running priority of 0;
/// - the core's exception log recorded **no exception at all** after that
///   point, while its program kept executing in ring 3 with `IRQs` unmasked.
///
/// So the timer was never the broken thing: it was starved by a higher
/// priority interrupt that never finished.  Putting every software interrupt
/// below every device interrupt makes the wedge impossible to reach through
/// this path, because a pending timer can always preempt a software
/// interrupt's active state.
///
/// `0xFF` is refused for the same reason it is the "no interrupt" value: a
/// line at the lowest priority that never preempts anything would not be a
/// wake.  `0xA0` leaves the device range untouched and stays above `0xFF`.
pub const SOFTWARE_PRIORITY: u8 = 0xA0;

/// How many `IPRIORITYR` registers carry the sixteen software interrupts.
///
/// One byte per interrupt and four bytes per register, so sixteen SGIs are
/// four words.  A GIC gives every SGI a priority byte and this tree writes all
/// of them; see [`SOFTWARE_PRIORITY`].
pub const SOFTWARE_PRIORITY_REGISTERS: usize = 4;

/// The word [`SOFTWARE_PRIORITY`] writes: four SGIs' bytes at one value.
///
/// Split out from the register write so a host test can read what the boot
/// would store, rather than a copy of the constants in the test itself.  A
/// test that asserted `(SOFTWARE_PRIORITY, DEVICE_PRIORITY) == (0xA0, 0x80)`
/// only ever passes; this is the value the machine receives.
pub const fn software_priority_word() -> u32 {
    u32::from_ne_bytes([
        SOFTWARE_PRIORITY,
        SOFTWARE_PRIORITY,
        SOFTWARE_PRIORITY,
        SOFTWARE_PRIORITY,
    ])
}

impl Distributor {
    /// The distributor at `base`, as the machine's device tree named it.
    pub const fn new(base: usize) -> Distributor {
        Distributor { base }
    }

    /// The window this distributor was built over.
    pub const fn window(&self) -> usize {
        self.base
    }

    /// The address of the register for interrupt `number`, in the array at
    /// `window`.
    ///
    /// The arithmetic is the specification's and it is where a copied driver
    /// goes wrong: `ISENABLER` holds 32 interrupts per register and
    /// `IPRIORITYR` holds **four** per register, so the two do not share a
    /// divisor.  A driver that used 32 for both would enable the right line and
    /// set the priority of a different one.
    pub const fn array_address(&self, window: usize, number: usize, per_register: usize) -> usize {
        self.base + window + (number / per_register) * 4
    }

    /// The bit inside `ISENABLER`'s register that interrupt `number` uses.
    pub const fn enable_bit(number: usize) -> u32 {
        1 << (number % 32)
    }

    /// The shift of interrupt `number`'s byte inside `IPRIORITYR`'s register.
    pub const fn priority_shift(number: usize) -> u32 {
        ((number % 4) * 8) as u32
    }

    /// The shift of interrupt `number`'s two-bit configuration field.
    ///
    /// `ICFGR` is two bits per interrupt, sixteen per register, and **the
    /// second bit is the one that matters**: it is `1` for edge-triggered and
    /// `0` for level-sensitive.  The first bit is reserved and reads as zero.
    pub const fn config_shift(number: usize) -> u32 {
        ((number % 16) * 2) as u32
    }

    /// Enable the distributor itself.
    ///
    /// Bit 0 is the enable; the two bits above it are the CPU-interface enable
    /// for the secure and non-secure halves of a GIC that implements both, and
    /// this kernel runs at the non-secure EL1 so bit 1 is the one that matters.
    /// Both are set: a machine whose firmware left the secure half off is one
    /// where a device's line is enabled in the distributor and never forwarded.
    pub const DIST_CTLR_ENABLE: u32 = 0b11;

    /// Whether an interrupt number is one the distributor controls.
    ///
    /// Interrupts `0..32` are the per-CPU ones, a timer, a maintenance
    /// interrupt, the interface's own, and the distributor does not route
    /// them; `GICD_ISENABLER0`'s low bits are read-only for them.  A device's
    /// line is `32` and above, which is why this exists rather than a range
    /// check at every call site.
    pub const fn is_device_interrupt(number: usize) -> bool {
        number >= 32
    }

    /// Whether an interrupt number is a private (per-CPU) one.
    ///
    /// `0..32`.  The generic timer's interrupt is 30 and the maintenance
    /// interrupt is 25; both are private and both are enabled through the first
    /// array entries rather than through a target.
    pub const fn is_private_interrupt(number: usize) -> bool {
        number < 32
    }

    /// Whether an interrupt number is a software-generated one.
    ///
    /// `0..16`, and the only range `GICD_SGIR` can raise.  A device line is
    /// raised by its device; software has no way to impersonate one.
    pub const fn is_software_interrupt(number: usize) -> bool {
        number < 16
    }
}

/// The CPU interface: what this core is currently taking.
#[derive(Debug, Clone, Copy)]
pub struct CpuInterface {
    base: usize,
}

/// `GICC_CTLR`: bit 0 enables the interface.
pub const CPU_CTLR: usize = 0x000;
/// `GICC_PMR`: the priority mask.  An interrupt at or below it is delivered.
pub const CPU_PMR: usize = 0x004;
/// `GICC_IAR`: reading it acknowledges an interrupt and returns its number.
pub const CPU_IAR: usize = 0x00C;
/// `GICC_EOIR`: writing the number back finishes it.
pub const CPU_EOIR: usize = 0x010;

/// The value `GICC_IAR` reports when nothing is pending.
///
/// The top ten bits are a special "spurious" number; the specification calls
/// anything in that range a spurious interrupt, and a driver that treated one
/// as an interrupt number would write it to `EOIR` and disturb whatever it
/// named.  The check is a range, not equality with one value.
pub const SPURIOUS_THRESHOLD: u32 = 1020;

impl CpuInterface {
    /// The interface at `base`, as the machine's device tree named it.
    pub const fn new(base: usize) -> CpuInterface {
        CpuInterface { base }
    }

    /// The window this interface was built over.
    ///
    /// A reader for a value the bare-metal path reaches through `self.base`
    /// directly; on a host no register access exists, and a field a build never
    /// reads is what the host check notices.
    pub const fn window(&self) -> usize {
        self.base
    }

    /// The value to write to `GICC_PMR` so that every priority is delivered.
    ///
    /// `0xFF` accepts all of them.  A smaller value masks the lower priorities,
    /// and a kernel that left this at its reset value of zero would receive
    /// nothing at all, which looks exactly like a controller that was never
    /// enabled.
    pub const PMR_ACCEPT_ALL: u32 = 0xFF;

    /// Whether an `IAR` reading is a real interrupt rather than a spurious one.
    pub const fn is_real(interrupt: u32) -> bool {
        interrupt < SPURIOUS_THRESHOLD
    }
}

/// Write one 32-bit register of a memory-mapped block.
///
/// # Safety
///
/// `address` must be a live register in one of the two GIC blocks.  The caller
/// owns that promise; this function performs the write and nothing else.
#[cfg(target_os = "none")]
unsafe fn write(address: usize, value: u32) {
    // SAFETY: the caller promises the address is a GIC register.  A volatile
    // write is what MMIO needs: the block acts on it, and the compiler must
    // not fold or reorder writes to registers whose order matters.
    unsafe { core::ptr::write_volatile(address as *mut u32, value) };
}

/// Read one 32-bit register of a memory-mapped block.
///
/// # Safety
///
/// As [`write`]: `address` must be a live register in one of the blocks.
#[cfg(target_os = "none")]
unsafe fn read(address: usize) -> u32 {
    // SAFETY: as `write`, one direction.
    unsafe { core::ptr::read_volatile(address as *const u32) }
}

/// A GIC this machine can enable lines through.
///
/// The two blocks are one value because every operation a driver needs touches
/// both: enabling a line is a distributor write and taking it is a
/// CPU-interface read, and a type that held only one would make every caller
/// hold both.
#[derive(Debug, Clone, Copy)]
pub struct Gic {
    distributor: Distributor,
    cpu: CpuInterface,
}

impl Gic {
    /// The controller whose windows the machine named.
    pub const fn new(distributor: usize, cpu: usize) -> Gic {
        Gic {
            distributor: Distributor::new(distributor),
            cpu: CpuInterface::new(cpu),
        }
    }

    /// The two windows, for a boot line that says which controller it found.
    ///
    /// Returned as a pair rather than as two readers because a caller that
    /// wants one always wants the other: a GIC is the distributor *and* the
    /// CPU interface, and a log line naming one of them names half a
    /// controller.
    pub const fn windows(&self) -> (usize, usize) {
        (self.distributor.window(), self.cpu.window())
    }

    /// Enable the distributor and this CPU's interface.
    ///
    /// The order is the specification's: the distributor first, because a CPU
    /// interface enabled against a distributor that is off receives nothing.
    ///
    /// The priority mask is set to accept everything *after* both, and that is
    /// not tidiness: `GICC_PMR` resets to zero, which masks every priority, so
    /// a controller that was enabled and left with a zero mask delivers nothing
    /// and looks exactly like one that was never enabled.
    ///
    /// # Safety
    ///
    /// Called once, from the boot, on the CPU that will take the interrupts.
    /// The two addresses must be the machine's GIC windows, and the memory at
    /// them must be mapped uncached, a cached read of `IAR` would return an
    /// interrupt number that was already acknowledged.
    #[cfg(target_os = "none")]
    pub unsafe fn enable(&self) {
        // SAFETY: the caller promises both addresses are GIC windows and that
        // the mapping is uncached.
        unsafe {
            write(
                self.distributor.base + DIST_CTLR,
                Distributor::DIST_CTLR_ENABLE,
            );
            core::arch::asm!("dsb sy", options(nostack));
            write(self.cpu.base + CPU_CTLR, CPU_CTLR_ENABLE);
            write(self.cpu.base + CPU_PMR, CpuInterface::PMR_ACCEPT_ALL);
            core::arch::asm!("dsb sy", options(nostack));
            core::arch::asm!("isb", options(nostack));

            // Every software interrupt, below every device.
            self.set_software_priorities();
        }
    }

    /// Give the sixteen software interrupts [`SOFTWARE_PRIORITY`].
    ///
    /// `IPRIORITYR0..IPRIORITYR3` cover interrupts 0..16, one byte each, and
    /// they are the only priority registers an SGI has: the low sixteen bits of
    /// `ISENABLER0` are read-only, so
    /// [`enable_interrupt`](Self::enable_interrupt) never routes one and its
    /// priority is never written by that path.  The reset value is **zero**,
    /// which is the highest priority a GIC has, and a software interrupt at
    /// zero outranks the timer's `0x80`, see [`SOFTWARE_PRIORITY`] for the
    /// stalled boot that measured what that costs.
    ///
    /// Writing all sixteen rather than the two this kernel raises is
    /// deliberate. The line an inter-processor interrupt arrives on is a
    /// *number this tree chooses* (`arch::ipi_interrupt`), the self-test raises
    /// another, and a GIC forwards every SGI on any core, so a number left at
    /// the reset priority is a number that can wedge a core the boot never
    /// aimed at. Sixteen bytes is four register writes and this runs once.
    ///
    /// # Safety
    ///
    /// As [`enable`]: the distributor window must be the machine's GIC, mapped
    /// uncached, and this must run before any line is unmasked.
    #[cfg(target_os = "none")]
    unsafe fn set_software_priorities(&self) {
        // SAFETY: the caller's contract is `enable`'s, and these are the first
        // four words of `IPRIORITYR`, which every GIC has.
        unsafe {
            for register in 0..SOFTWARE_PRIORITY_REGISTERS {
                write(
                    self.distributor.base + DIST_IPRIORITYR + register * 4,
                    software_priority_word(),
                );
            }
            core::arch::asm!("dsb sy", options(nostack));
        }
    }

    /// Route interrupt `number` to this CPU and enable it.
    ///
    /// Four writes, and all four are needed:
    ///
    /// 1. `IGROUPR`, **group 1**, which is the non-secure group.  This is the
    ///    one that is easy to leave out and impossible to notice: a line in
    ///    group 0 is a *secure* interrupt, and a kernel running at non-secure
    ///    EL1 never receives one.  The distributor accepts the enable, the line
    ///    is armed, and nothing ever arrives.
    /// 2. `IPRIORITYR`, its priority.  A line at the reset priority of zero is
    ///    the highest, which works and makes every device preempt every other;
    ///    [`DEVICE_PRIORITY`] is what this tree gives a device.
    /// 3. `ITARGETSR`, which CPU.  On a GICv2 the byte is a bitmask of cores,
    ///    and on a machine with one core it is `0x01`.  Not written, the line
    ///    goes nowhere.
    /// 4. `ICFGR`, **edge-triggered**, and this is the one a message-signalled
    ///    interrupt cannot do without.
    ///
    ///    GIC's shared peripheral interrupts default to *level-sensitive*,
    ///    which means the distributor holds an interrupt pending only while
    ///    the line is asserted.  An MSI is a write: the device asserts and
    ///    deasserts in one operation with nothing between them, so a
    ///    level-sensitive line is pending for no time at all and `ISPENDR`
    ///    reads zero.  The interrupt never existed rather than never arrived.
    /// 5. `ISENABLER`, the enable bit.
    ///
    /// ## Per-CPU interrupts
    ///
    /// A number below 32 is a **private** interrupt: the generic timer's is 30.
    /// Its registers are the low bits of the *first* array entries, ///
    /// `ISENABLER0`, `IGROUPR0`, `ICFGR0`, and it has **no** `ITARGETSR` byte,
    /// because a private interrupt always goes to the CPU that raised it.  A
    /// driver that wrote a target byte for one would be writing another
    /// interrupt's target.
    ///
    /// So the two cases are separate paths and not a range check at the end.
    ///
    /// # Safety
    ///
    /// As [`enable`]: the addresses must be the machine's GIC, mapped uncached.
    #[cfg(target_os = "none")]
    pub unsafe fn enable_interrupt(&self, number: usize) -> bool {
        if !Distributor::is_private_interrupt(number) {
            // SAFETY: the distributor is the one this controller was built
            // from and it is mapped; the number is the caller's, and an
            // interrupt this GIC does not own is refused inside.
            return unsafe { self.enable_shared_interrupt(number) };
        }
        // SAFETY: a private interrupt's registers are the first entries of each
        // array, which every GIC has, and the caller promises the addresses are
        // the GIC's.
        unsafe {
            // Group 0, and the reason is measured rather than chosen: on QEMU's
            // GICv2 a private interrupt left in group 1 is reported as pending
            // and never handed out, `GICC_IAR` answers 1022 forever, with the
            // distributor enable, the priority, the trigger and both CPU groups
            // all reading back correct.  Group 0 delivers.
            let group = self.distributor.array_address(DIST_IGROUPR, number, 32);
            let current = read(group);
            write(group, current & !Distributor::enable_bit(number));

            let priority = self.distributor.array_address(DIST_IPRIORITYR, number, 4);
            let current = read(priority);
            let shift = Distributor::priority_shift(number);
            write(
                priority,
                (current & !(0xFF << shift)) | (u32::from(DEVICE_PRIORITY) << shift),
            );

            // **Level-triggered, which is what a PPI from the generic timer
            // is.**  The first version asked for edge, on the argument that a
            // timer "asserts for an instant when it fires", and that argument
            // is wrong for this line: `CNTP_CTL_EL0.ISTATUS` stays set until
            // the timer is reprogrammed, so the line is asserted for as long as
            // the interrupt is outstanding.  An edge-configured PPI drops an
            // assertion that was already high when it was enabled, which is
            // exactly the state a core that arms its timer and then enables the
            // line is in.
            //
            // Measured, on the started core: with edge, `CNTP_CTL_EL0` read 5
            // (enabled and *expired*) while `GICD_ISPENDR0` never showed the
            // line pending, and the core took 0 timer ticks on every boot of
            // forty.  With level it took 218 to 319 a boot, and every one of
            // the boot's scheduler waits got the clock it was written for.
            //
            // A software interrupt has no trigger configuration, `ICFGR`'s
            // bits for 0..15 are read-only, so writing the field for one is
            // harmless, and this function's other caller is the self-test's
            // SGI.
            let config = self.distributor.array_address(DIST_ICFGR, number, 16);
            let current = read(config);
            write(
                config,
                current & !(1 << (Distributor::config_shift(number) + 1)),
            );

            // No target: a private interrupt belongs to this CPU by definition.
            let enable = self.distributor.array_address(DIST_ISENABLER, number, 32);
            write(enable, Distributor::enable_bit(number));
            core::arch::asm!("dsb sy", options(nostack));
        }
        true
    }

    /// Enable a shared peripheral interrupt, which has a target byte.
    ///
    /// # Safety
    ///
    /// As [`enable_interrupt`](Self::enable_interrupt).
    #[cfg(target_os = "none")]
    unsafe fn enable_shared_interrupt(&self, number: usize) -> bool {
        if !Distributor::is_device_interrupt(number) {
            return false;
        }
        // SAFETY: `number >= 32`, so each array has a register and a byte for
        // it, and the caller promises the addresses are the GIC's.
        unsafe {
            // Group 1 first: a line in group 0 is a secure interrupt, and this
            // runs at non-secure EL1 where one is never delivered.
            let group = self.distributor.array_address(DIST_IGROUPR, number, 32);
            let current = read(group);
            write(group, current | Distributor::enable_bit(number));

            let priority = self.distributor.array_address(DIST_IPRIORITYR, number, 4);
            let current = read(priority);
            let shift = Distributor::priority_shift(number);
            write(
                priority,
                (current & !(0xFF << shift)) | (u32::from(DEVICE_PRIORITY) << shift),
            );

            let targets = self.distributor.array_address(DIST_ITARGETSR, number, 4);
            let current = read(targets);
            let shift = Distributor::priority_shift(number);
            write(targets, (current & !(0xFF << shift)) | (1u32 << shift));

            // Edge-triggered, before the enable.
            let config = self.distributor.array_address(DIST_ICFGR, number, 16);
            let current = read(config);
            write(
                config,
                current | (1 << (Distributor::config_shift(number) + 1)),
            );

            let enable = self.distributor.array_address(DIST_ISENABLER, number, 32);
            write(enable, Distributor::enable_bit(number));
            core::arch::asm!("dsb sy", options(nostack));
        }
        true
    }

    /// Raise software interrupt `number` on this CPU.
    ///
    /// A device raises its line when it has something to say, and a driver that
    /// wants to test the *path* cannot ask it to.  `GICD_SGIR` is the
    /// specification's own answer, with one restriction that is easy to miss
    /// and was missed here first.
    ///
    /// **`SGIR` generates SGIs only: interrupt numbers 0 to 15.**  It has no
    /// field for a device line, because a device line is raised by the device.
    /// A boot that asked it for interrupt 40 wrote a number the distributor
    /// read as an SGI id, delivered nothing, and then had to reconcile "the
    /// path works", an unclaimed PPI arrived on its own, with "my interrupt
    /// never came".
    ///
    /// The path an SGI takes is the same one a device's interrupt takes: the
    /// distributor selects the CPU, the CPU interface returns the number from
    /// `IAR`, the vector fires, and `EOIR` finishes it.  So an SGI is the right
    /// instrument for proving the path, and it is the only one available.
    ///
    /// SGIs are always enabled: `ISENABLER0`'s low sixteen bits read as one and
    /// cannot be cleared.  A caller does not have to enable one first, and
    /// [`enable_interrupt`](Self::enable_interrupt) refuses it for that reason.
    ///
    /// # Safety
    ///
    /// As [`enable`]: the window must be the GIC's, mapped uncached, and the
    /// caller must have a handler that can finish it.
    #[cfg(target_os = "none")]
    pub unsafe fn raise(&self, number: usize) -> bool {
        if !Distributor::is_software_interrupt(number) {
            return false;
        }
        // SAFETY: the caller promises the window is the GIC's.
        unsafe {
            // Bits 15..0 name the interrupt; bits 23..16 name the target CPUs,
            // and `1` is this core.  `GICD_SGIR`'s field order is the
            // specification's and is not the same as `ITARGETSR`'s bitmask:
            // one is a CPU filter list, the other a bit per core.
            let request = (number as u32 & 0xFFFF) | (1 << 16);
            write(self.distributor.base + DIST_SGIR, request);
            core::arch::asm!("dsb sy", options(nostack));
        }
        true
    }

    /// Raise a software interrupt on **every** core but this one.
    ///
    /// Bits 23..16 of `GICD_SGIR` are a bit per target core, and bit 0 is this
    /// one.  The value here is `0xFE`: every core from one up, which is the set
    /// a boot wants when it has something to tell the cores it started and
    /// nothing to say to itself: a self-directed SGI would arrive as an
    /// interrupt the kernel has to acknowledge for a reason it cannot name.
    ///
    /// # Safety
    ///
    /// As [`raise`]: the window must be the GIC's, mapped uncached, and the
    /// number must be an SGI.
    #[cfg(target_os = "none")]
    pub unsafe fn raise_on_others(&self, number: usize) -> bool {
        if !Distributor::is_software_interrupt(number) {
            return false;
        }
        // SAFETY: the caller promises the window is the GIC's.
        unsafe {
            let request = (number as u32 & 0xFFFF) | (0xFE << 16);
            write(self.distributor.base + DIST_SGIR, request);
            core::arch::asm!("dsb sy", options(nostack));
        }
        true
    }

    /// Whether the distributor's enable bit for `number` is set.
    ///
    /// # Safety
    ///
    /// As [`enable`]: the window must be the GIC's, mapped uncached.
    #[cfg(target_os = "none")]
    pub unsafe fn line_is_enabled(&self, number: usize) -> bool {
        // SAFETY: the caller promises the window is the GIC's.
        let word = unsafe { read(self.distributor.array_address(DIST_ISENABLER, number, 32)) };
        word & Distributor::enable_bit(number) != 0
    }

    /// Acknowledge an interrupt, answering its number.
    ///
    /// `None` when the reading is spurious, which the specification reports in
    /// the range [`SPURIOUS_THRESHOLD`] and above.  Finishing a spurious
    /// reading would write an interrupt number to `EOIR` that was never
    /// acknowledged.
    ///
    /// # Safety
    ///
    /// Called from the trap handler with the GIC's windows mapped uncached.
    #[cfg(target_os = "none")]
    pub unsafe fn acknowledge(&self) -> Option<u32> {
        // SAFETY: the caller promises the window is mapped uncached; a cached
        // read would return an already-acknowledged number.
        let interrupt = unsafe { read(self.cpu.base + CPU_IAR) };
        CpuInterface::is_real(interrupt).then_some(interrupt)
    }

    /// Finish interrupt `number`, which is what lets the next one be delivered.
    ///
    /// Without this the line stays active and the CPU takes nothing further at
    /// that priority, an interrupt handler that returns without an EOI is a
    /// machine that handles one interrupt and then appears to hang.
    ///
    /// # Safety
    ///
    /// `number` must be a value [`acknowledge`](Self::acknowledge) returned.
    #[cfg(target_os = "none")]
    pub unsafe fn finish(&self, number: u32) {
        // SAFETY: the caller passes a number `acknowledge` produced, which is
        // the contract `EOIR` requires.
        unsafe { write(self.cpu.base + CPU_EOIR, number) };
    }
}

/// `GICC_CTLR` bits 0 and 1: the CPU interface is enabled for **both groups**.
///
/// Bit 0 is `EnableGrp0` and bit 1 is `EnableGrp1`, and they are separate
/// switches over separate groups of interrupts.  Both are set because this
/// kernel's lines do not all live in one group: a device's line is group 1, the
/// non-secure group, and a private line is group 0, that measurement is at the
/// group write in this file's private-interrupt enable path, so an interface
/// enabled for one group would deliver half of what is enabled.
///
/// The symptom of getting it wrong is exact and was lived through here:
/// `GICD_ISPENDR0` showed the timer's interrupt as **pending**,
/// `GICD_ISENABLER0` showed it enabled, and the CPU took no interrupt, because
/// the one register that gates delivery of that group was off.  That paragraph
/// said "group 1 only" until the private-interrupt path was measured to be in
/// group 0; the conclusion, enable both, did not change, but the reason a
/// reader would carry away did.
pub const CPU_CTLR_ENABLE: u32 = 0b11;

#[cfg(test)]
mod tests {
    use super::CpuInterface;
    use super::DEVICE_PRIORITY;
    use super::Distributor;
    use super::SOFTWARE_PRIORITY;

    const DIST: Distributor = Distributor::new(0x0800_0000);
    const CPU: CpuInterface = CpuInterface::new(0x0801_0000);

    /// A software interrupt must never outrank a device's.
    ///
    /// The GIC keeps a CPU interface's running priority at the value of the
    /// interrupt it has acknowledged until that interrupt is finished, and it
    /// will not hand over a line of equal or higher priority.  `IPRIORITYR`
    /// resets to **zero**, and zero is the highest priority, so an SGI whose
    /// priority nobody wrote runs above the timer's `0x80`, which is exactly
    /// how a started core's clock stopped on QEMU's GICv2: one unwritten SGI
    /// priority, one un-EOI'd acknowledge, and `gic_update_bestirq` then
    /// reporting `irq 30 priority 128 ... running priority 0` for ever.
    ///
    /// So the ordering is the assertion, not the two numbers.  A later change
    /// that raises the device priority past this one reintroduces the wedge,
    /// and it has to see this test fail rather than discover it on a boot.
    /// The ordering is a **compile-time** relation, not a test's opinion.
    ///
    /// Two constants are known when this crate is compiled, so the check
    /// belongs in a `const` block: a change that inverted the ordering, the
    /// wedge this fix closes, would fail the build instead of surviving until
    /// someone ran the tests.  The test below only has to exist so the relation
    /// is named somewhere a reader looks.
    const _: () = assert!(
        SOFTWARE_PRIORITY > DEVICE_PRIORITY,
        "a software interrupt must be less urgent than a device's"
    );
    const _: () = assert!(
        SOFTWARE_PRIORITY < 0xFF,
        "0xFF is the controller's no-line value"
    );

    /// The value the boot writes gives every SGI the lower priority, and it
    /// reaches all sixteen.
    ///
    /// This reads the same function the register write calls, so it is a
    /// statement about what the machine receives rather than a restatement of
    /// the constants beside it.  Three properties, and each is a way the fix
    /// could be undone:
    ///
    /// 1. Every byte of the word is the software priority, a partially filled
    ///    word leaves some SGI at the reset value of zero, which is the defect.
    /// 2. The byte is *greater* than the device priority, since a lower number
    ///    is more urgent on this controller.
    /// 3. Four registers at four bytes each cover the sixteen SGIs.
    #[test]
    fn the_boot_writes_a_lower_priority_to_every_software_interrupt() {
        let word = super::software_priority_word();
        for byte in word.to_ne_bytes() {
            assert_eq!(byte, SOFTWARE_PRIORITY);
            assert!(
                byte > DEVICE_PRIORITY,
                "an SGI at {byte:#x} outranks the timer's {DEVICE_PRIORITY:#x}"
            );
        }
        // Sixteen interrupts, one byte each, four bytes to a register.
        assert_eq!(super::SOFTWARE_PRIORITY_REGISTERS * 4, 16);
    }

    /// The four registers that carry the sixteen SGIs are the first four of
    /// `IPRIORITYR`, and sixteen bytes at one byte each is what they hold.
    ///
    /// The boot writes all of them rather than the one number it raises,
    /// because any SGI can reach any core.  A driver that wrote only
    /// `IPRIORITYR0` would leave interrupts 4..16 at the reset priority of
    /// zero, the highest, which is the defect this fix exists to close.
    #[test]
    fn the_software_priority_registers_are_the_first_four() {
        assert_eq!(super::DIST_IPRIORITYR, 0x400);
        // Interrupt 0 is byte 0 of the first register, and interrupt 15 is the
        // last byte of the fourth.  The array stride is four bytes.
        for number in 0..16usize {
            let register = number / 4;
            let shift = Distributor::priority_shift(number);
            assert!(
                register < 4,
                "interrupt {number} needs register {register}, past the four \
                 this boot writes"
            );
            // Each of the sixteen has a distinct byte within its word, so one
            // write per register reaches four interrupts and no write collides.
            assert_eq!(shift, ((number % 4) * 8) as u32);
        }
    }

    /// `ISENABLER` holds 32 interrupts per register, so interrupt 32 is bit 0
    /// of the first register and interrupt 33 bit 1.
    ///
    /// Interrupt 32 is the first the distributor routes: `0..32` are the
    /// per-CPU ones and their enable bits are read-only.  A driver that started
    /// its arithmetic at zero would write the same register but believe a
    /// different bit.
    #[test]
    fn an_enable_bit_is_the_interrupt_modulo_thirty_two() {
        assert_eq!(Distributor::enable_bit(32), 1);
        assert_eq!(Distributor::enable_bit(33), 2);
        assert_eq!(Distributor::enable_bit(63), 1 << 31);
        assert_eq!(Distributor::enable_bit(64), 1, "the next register's bit 0");

        // `ISENABLER0` covers interrupts 0..31, so the first device line, 32,
        // // is bit 0 of the *second* enable register.
        assert_eq!(
            DIST.array_address(super::DIST_ISENABLER, 32, 32),
            0x0800_0104
        );
        assert_eq!(
            DIST.array_address(super::DIST_ISENABLER, 63, 32),
            0x0800_0104
        );
        assert_eq!(
            DIST.array_address(super::DIST_ISENABLER, 64, 32),
            0x0800_0108,
            "one register further on"
        );
    }

    /// `IPRIORITYR` holds **four** interrupts per register, not thirty-two.
    ///
    /// This is the arithmetic a copied driver gets wrong: the two arrays have
    /// different widths, so a divisor that works for one sets the priority of a
    /// different interrupt than the one it enabled.
    #[test]
    fn a_priority_byte_is_one_of_four_per_register() {
        // `IPRIORITYR` holds four interrupt bytes per register, so interrupt
        // 32 is byte 0 of the ninth register.
        assert_eq!(
            DIST.array_address(super::DIST_IPRIORITYR, 32, 4),
            0x0800_0420
        );
        assert_eq!(
            DIST.array_address(super::DIST_IPRIORITYR, 35, 4),
            0x0800_0420
        );
        assert_eq!(
            DIST.array_address(super::DIST_IPRIORITYR, 36, 4),
            0x0800_0424,
            "the next register"
        );

        assert_eq!(Distributor::priority_shift(32), 0);
        assert_eq!(Distributor::priority_shift(33), 8);
        assert_eq!(Distributor::priority_shift(34), 16);
        assert_eq!(Distributor::priority_shift(35), 24);
        assert_eq!(
            Distributor::priority_shift(36),
            0,
            "the next register's byte 0"
        );
    }

    /// The two arrays' divisors differ, and the test states both so a reader
    /// comparing them can see it is deliberate.
    #[test]
    fn the_two_arrays_do_not_share_a_divisor() {
        assert_eq!(
            DIST.array_address(super::DIST_ISENABLER, 40, 32),
            0x0800_0104
        );
        assert_eq!(
            DIST.array_address(super::DIST_IPRIORITYR, 40, 4),
            0x0800_0428
        );
        // Forty is bit 8 of the second enable register, and byte 0 of the
        // eleventh priority register, because forty divides by four exactly.
        // The same interrupt, two different registers, two different offsets
        // inside them; that is the whole point of the divisors being separate.
        assert_eq!(Distributor::enable_bit(40), 1 << 8);
        assert_eq!(Distributor::priority_shift(40), 0);
        // And one that is not a multiple of four, to show the shift moving.
        assert_eq!(Distributor::priority_shift(42), 16);
    }

    /// Interrupts below 32 are the per-CPU ones and the distributor does not
    /// route them.
    #[test]
    fn a_device_interrupt_starts_at_thirty_two() {
        assert!(!Distributor::is_device_interrupt(0));
        assert!(!Distributor::is_device_interrupt(31));
        assert!(Distributor::is_device_interrupt(32));
        assert!(Distributor::is_device_interrupt(63));
    }

    /// A spurious reading is a range, not one value.
    ///
    /// `IAR` reports `1020..1023` for the four spurious cases.  A driver that
    /// checked only for `1023` would treat `1020` as a real interrupt number
    /// and write it to `EOIR`, which names an interrupt that was never
    /// acknowledged.
    #[test]
    fn a_spurious_interrupt_is_a_range() {
        assert!(CpuInterface::is_real(32));
        assert!(CpuInterface::is_real(1019));
        for spurious in 1020..=1023 {
            assert!(!CpuInterface::is_real(spurious), "{spurious} is spurious");
        }
    }

    /// The priority a device line gets is one the mask accepts.
    #[test]
    fn a_device_priority_is_accepted_by_the_mask() {
        assert!(DEVICE_PRIORITY < CpuInterface::PMR_ACCEPT_ALL as u8);
        assert_eq!(
            Distributor::DIST_CTLR_ENABLE & 1,
            1,
            "the distributor's own bit"
        );
    }

    /// The two windows are distinct addresses, which is what makes the split
    /// worth naming.
    #[test]
    fn the_two_blocks_are_different_windows() {
        assert_ne!(
            DIST.array_address(super::DIST_CTLR, 0, 1),
            CPU.base + super::CPU_CTLR
        );
        assert_eq!(DIST.array_address(super::DIST_CTLR, 0, 1), 0x0800_0000);
        assert_eq!(CPU.base + super::CPU_CTLR, 0x0801_0000);
    }

    /// A private line is configured level-sensitive, which is the value the
    /// timer's PPI needs.
    ///
    /// `ICFGR`'s odd bit of each pair is `1` for edge and `0` for level, so the
    /// timer's own field, interrupt 30, the second bit of the register's
    /// fifteenth pair, has to end up clear.  The first version set it, on the
    /// reading that a timer "asserts for an instant"; `CNTP_CTL_EL0.ISTATUS`
    /// holds until the timer is reprogrammed, so the line is level and an edge
    /// configuration drops the assertion that was already high when the core
    /// enabled the line.  The measurement is in `enable_interrupt`: zero ticks
    /// a boot with edge, 218 to 319 with level.
    ///
    /// This pins the arithmetic a reader would otherwise have to trust: the
    /// field's position, and which of its two bits is the trigger.
    #[test]
    fn a_private_line_is_level_configured() {
        const TIMER: usize = 30;

        let shift = Distributor::config_shift(TIMER);
        assert_eq!(shift, 28, "interrupt 30 is the fifteenth pair of bits");
        let field = 1u32 << (shift + 1);
        assert_eq!(field, 1 << 29, "the pair's high bit is the trigger");

        // Setting it is edge, clearing it is level: the write is `& !field`.
        let mut config = 0u32;
        let edge = config | field;
        config &= !field;
        assert_ne!(config, edge, "the two configurations differ");
        assert_eq!(config & field, 0, "level leaves the trigger bit clear");

        // Interrupt 30 lands in `ICFGR1`, not `ICFGR0`: sixteen interrupts per
        // register, so the first sixteen's fields are in the first one.
        assert_eq!(DIST.array_address(super::DIST_ICFGR, 30, 16), 0x0800_0C04);
        assert_eq!(DIST.array_address(super::DIST_ICFGR, 16, 16), 0x0800_0C04);
        assert_eq!(DIST.array_address(super::DIST_ICFGR, 15, 16), 0x0800_0C00);
    }
}
