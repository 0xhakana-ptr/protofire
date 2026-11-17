//! arch/x86_64/src/apic.rs
//!
//! The local APIC: its timer, its spurious-interrupt vector, and the
//! end-of-interrupt write.
//!
//! The 8259 is masked by `pic::mask_all` before the kernel enables interrupts,
//! and that is deliberate: q35 has an IOAPIC, so the legacy controller is a
//! second source for the same lines.  What is left to drive a timer is the
//! local APIC's own timer, which needs no IOAPIC routing at all, it is
//! per-CPU, it raises a vector directly, and on a machine with one CPU it is
//! the shortest path from "arm a countdown" to "take an interrupt".
//!
//! ## The addresses
//!
//! The local APIC's registers are a memory-mapped page, and where it is is
//! not architecturally fixed: on a PC the `IA32_APIC_BASE` MSR holds it, and
//! firmware leaves it enabled at `0xFEE0_0000` with a bit saying so.  This
//! module reads the MSR rather than assuming the address, and reports
//! [`Apic::probe`]'s `None` when the bit is clear, the same shape every other
//! machine question here has.
//!
//! ## The timer's frequency, and why it is measured
//!
//! The APIC timer counts at the bus clock, which nothing reports.  The only
//! portable way to learn it is to count against a clock that is known: the PIT,
//! whose input crystal is a documented 1.193182 MHz.  So [`calibrate`] runs the
//! PIT's channel 2 for a fixed number of its ticks and counts APIC ticks
//! alongside, which gives the APIC's frequency as a measured ratio.
//!
//! That is more machinery than a hard-coded constant, and it is the difference
//! between a time slice that is a hundred microseconds here and one that is a
//! hundred microseconds on a machine whose bus clock is the other one.  A
//! constant would have worked on the emulator and been wrong on hardware, which
//! is the failure mode this tree keeps recording for cached MMIO.

/// The MSR naming the local APIC's base address.
pub const IA32_APIC_BASE: u32 = 0x1B;

/// Bit 11 of `IA32_APIC_BASE`: the APIC is enabled globally.
pub const APIC_BASE_ENABLE: u64 = 1 << 11;

/// Bits 12..51 hold the base address, page-aligned.
///
/// The low twelve bits are flags and the high twelve are reserved, so a mask of
/// `!0xFFF` would keep flags in the address and read a register at an address
/// no machine has, the same defect the page-table address mask had.
pub const APIC_BASE_MASK: u64 = ((1u64 << 52) - 1) & !0xFFF;

/// Register offsets from the base.
pub mod register {
    /// The spurious-interrupt vector register.
    pub const SPURIOUS_VECTOR: usize = 0x0F0;
    /// The task priority register.
    pub const TASK_PRIORITY: usize = 0x080;
    /// The end-of-interrupt register.
    pub const END_OF_INTERRUPT: usize = 0x0B0;
    /// The local APIC's own id, in the byte at bits 24..31.
    pub const ID: usize = 0x020;
    /// The timer's initial count.
    pub const TIMER_INITIAL_COUNT: usize = 0x380;
    /// The timer's current count, which counts *down* to zero.
    pub const TIMER_CURRENT_COUNT: usize = 0x390;
    /// The timer's divide configuration.
    pub const TIMER_DIVIDE: usize = 0x3E0;
    /// The LVTTL: the timer's local vector table entry.
    pub const TIMER_VECTOR: usize = 0x320;
}

/// The vector the local APIC's spurious interrupt arrives on.
///
/// Every APIC has one and it must be enabled, bit 8 of the spurious-vector
/// register, or the APIC delivers nothing at all.  `0xFF` is the conventional
/// choice, and it is above the vectors this kernel assigns.
pub const SPURIOUS_VECTOR: u8 = 0xFF;

/// The vector the timer raises.
///
/// 32 is the first vector above the processor's 32 exceptions, which is where a
/// PC's interrupts start for the reason the 8259's remapped base is 0x20: a
/// device's line must not be numbered like a fault.
pub const TIMER_VECTOR: u8 = 32;

/// The vector one CPU raises to reach another: the inter-processor interrupt.
///
/// The first vector above the timer's, because the timer was the first thing
/// this machine delivered and the IPI is the second; the vectors above the
/// exceptions are this kernel's to assign, and assigning them in delivery
/// order is one fact where a table of chosen numbers would be several.  It is
/// above the 32 exceptions, which is the only architectural bound, and below
/// the spurious vector, which is the convention that keeps the highest one
/// unassigned.
pub const IPI_VECTOR: u8 = 33;

// The relation a test cannot assert without checking a literal: a device's
// vector is above every processor exception, of which there are 32.
const _: () = assert!(TIMER_VECTOR >= 32);

/// The divide configuration's value for a divide by 16.
///
/// The field is not a number: `0b0011` is 16, and the encodings are a table
/// rather than arithmetic, `0b1011` is 1, not 11.  Dividing by 16 is the
/// conventional choice: it keeps the counter's range large enough for a
/// millisecond at a bus clock near a gigahertz and small enough that the count
/// is a number a reader can sanity-check.
pub const DIVIDE_BY_16: u32 = 0b0011;

/// The PIT's input frequency, in hertz.
///
/// 1.193182 MHz exactly: the PIT's crystal is a third of the NTSC colour
/// burst's 3.579545 MHz, which is why the number is not round.  It is the
/// calibration's only constant and the only thing this module assumes about the
/// machine, and it is the one thing the PC architecture documents.
pub const PIT_FREQUENCY: u64 = 1_193_182;

/// The PIT's channel 2 data port.
pub const PIT_CHANNEL2: u16 = 0x42;
/// The PIT's mode/command port.
pub const PIT_COMMAND: u16 = 0x43;
/// Port `0x61`, whose bits gate channel 2 and read its output.
pub const PIT_GATE: u16 = 0x61;

/// The mode/command byte for channel 2, lobyte/hibyte, mode 0 (interrupt on
/// terminal count), binary.
///
/// `0b1011_0000`: channel 2 (`0b10 << 6`), access lobyte/hibyte (`0b11 << 4`),
/// mode 0 (`0b000 << 1`), binary (`0`).  Mode 0 counts down once and stops,
/// which is what a calibration wants: a one-shot of a known length.
pub const PIT_CHANNEL2_ONE_SHOT: u8 = 0b1011_0000;

/// The most the PIT's 16-bit counter can hold.
pub const PIT_MAX_COUNT: u16 = 0xFFFF;

/// One local APIC, at the address its MSR named.
#[derive(Debug, Clone, Copy)]
pub struct Apic {
    base: usize,
}

impl Apic {
    /// The local APIC, if this machine reports one enabled.
    ///
    /// # Safety
    ///
    /// Reads an MSR.  The base address it answers must be mapped as device
    /// memory before any register is touched, the boot's identity map covers
    /// `0xFEE0_0000` only because that address is below four gigabytes and the
    /// kernel's table re-mapped it uncached.
    pub unsafe fn probe() -> Option<Apic> {
        // SAFETY: `IA32_APIC_BASE` is a register every x86_64 here defines, and
        // its value is an address rather than a pointer into memory, so the
        // read depends on nothing unmapped.
        let base = unsafe { read_msr(IA32_APIC_BASE) };
        if base & APIC_BASE_ENABLE == 0 {
            return None;
        }
        let address = (base & APIC_BASE_MASK) as usize;
        if address == 0 {
            return None;
        }
        Some(Apic { base: address })
    }

    pub const fn base(&self) -> usize {
        self.base
    }

    /// This CPU's APIC id, from the id register's byte at bits 24..31.
    ///
    /// The register is per-CPU at one address, which is why the id is readable
    /// this way: every CPU reads its own.
    ///
    /// # Safety
    ///
    /// The base must be mapped as device memory, which is the caller's
    /// promise from [`Apic::probe`].
    pub unsafe fn id(&self) -> u32 {
        // SAFETY: the caller promises the base is a mapped device page.
        let raw = unsafe { self.read(register::ID) };
        raw >> 24
    }

    /// Read a register.
    ///
    /// # Safety
    ///
    /// The base must be mapped as device memory, which is the caller's
    /// promise from [`Apic::probe`].
    pub unsafe fn read(&self, offset: usize) -> u32 {
        // SAFETY: the caller promises the base is a mapped device page.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }

    /// Write a register.
    ///
    /// # Safety
    ///
    /// As [`Apic::read`].
    pub unsafe fn write(&self, offset: usize, value: u32) {
        // SAFETY: as `read`.  A volatile store is what keeps the compiler from
        // eliding a write whose value it believes nothing reads.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) }
    }

    /// Enable this APIC by naming its spurious vector.
    ///
    /// Bit 8 is the "this APIC is enabled" bit and it is not optional: an APIC
    /// with it clear delivers no interrupt at all, and a timer armed against
    /// one counts down in silence.  The low four bits of the field are the
    /// vector and must be at least 16, a spurious interrupt numbered below the
    /// exceptions is one the processor would treat as a fault.
    ///
    /// # Safety
    ///
    /// Called once, on a mapped APIC, before any line is unmasked.
    pub unsafe fn enable(&self) {
        // SAFETY: the caller's contract.
        unsafe {
            self.write(
                register::SPURIOUS_VECTOR,
                (SPURIOUS_VECTOR as u32) | (1 << 8),
            );
            // A task priority of zero accepts every priority class.  The
            // default is zero already; writing it says so rather than relying
            // on firmware.
            self.write(register::TASK_PRIORITY, 0);
        }
    }

    /// Acknowledge the interrupt that just ran.
    ///
    /// The local APIC holds a line in service until this is written, and a
    /// handler that returned without it takes exactly one interrupt and then
    /// appears to hang, the same failure aarch64's `EOIR` exists to prevent.
    ///
    /// # Safety
    ///
    /// Called from the handler for a vector the APIC raised.
    pub unsafe fn end_of_interrupt(&self) {
        // SAFETY: the caller's contract.
        unsafe { self.write(register::END_OF_INTERRUPT, 0) };
    }

    /// Program the timer to raise [`TIMER_VECTOR`] every `count` ticks.
    ///
    /// The initial count is loaded first and the LVTTL second, which is the
    /// order the manual requires: a timer enabled before its count is set fires
    /// immediately with whatever the counter held.
    ///
    /// # Safety
    ///
    /// As [`Apic::enable`].
    pub unsafe fn arm_timer(&self, count: u32) {
        // SAFETY: the caller's contract.
        unsafe {
            self.write(register::TIMER_DIVIDE, DIVIDE_BY_16);
            // The LVTTL is written **before** the count and with the mask bit
            // clear.  The reverse order is what a first version did, and it is
            // wrong twice over: bit 16 is left set by `disarm_timer`, so a
            // count loaded first starts a masked timer, and the LVTTL write
            // then masks the count it was meant to enable.  The boot's own
            // report showed it, `timer control 65568`, which is `0x10020`,
            // with bit 16 set, and the tick count was zero.
            //
            // Bit 17 is the mode: 0 is one-shot, 1 is periodic.  Periodic is
            // what a scheduler wants: it re-arms itself, so a handler that
            // forgot to would still get the next tick.
            self.write(register::TIMER_VECTOR, (TIMER_VECTOR as u32) | (1 << 17));
            self.write(register::TIMER_INITIAL_COUNT, count);
        }
    }

    /// Stop the timer.
    ///
    /// # Safety
    ///
    /// As [`Apic::enable`].
    pub unsafe fn disarm_timer(&self) {
        // SAFETY: the caller's contract.
        unsafe {
            // The mask bit is 16: set means masked.
            self.write(register::TIMER_VECTOR, (TIMER_VECTOR as u32) | (1 << 16));
            self.write(register::TIMER_INITIAL_COUNT, 0);
        }
    }

    /// The timer's current count, which counts down.
    ///
    /// # Safety
    ///
    /// As [`Apic::read`].
    pub unsafe fn timer_count(&self) -> u32 {
        // SAFETY: the caller's contract.
        unsafe { self.read(register::TIMER_CURRENT_COUNT) }
    }

    /// The LVTTL, read back: a value of zero has the timer masked.
    ///
    /// # Safety
    ///
    /// As [`Apic::read`].
    pub unsafe fn timer_vector(&self) -> u32 {
        // SAFETY: the caller's contract.
        unsafe { self.read(register::TIMER_VECTOR) }
    }

    /// Send an interrupt to this CPU, with `vector`.
    ///
    /// ## The encoding
    ///
    /// The ICR's low half holds the vector in bits 0..7 and the **destination
    /// shorthand** in bits 18..19: `0b01` means "self", which is the mode that
    /// needs no APIC identifier and no arbitration.  The high half names a
    /// destination APIC id, and the self-shorthand ignores it.
    ///
    /// The ICR's bit 12 is "delivery status", and it reads 1 while a send is in
    /// flight.  A second write before it clears is dropped, so this waits for
    /// it, bounded, because a machine whose APIC does not answer should report
    /// `false` rather than hang the boot.
    ///
    /// # Safety
    ///
    /// The base must be a mapped device page, and the caller must have a
    /// handler for `vector`.
    pub unsafe fn raise_to_self(&self, vector: u8) -> bool {
        // Wait for any previous send to complete, so this one is not dropped.
        let mut spins = 0u32;
        loop {
            // SAFETY: the caller's contract.
            let status = unsafe { self.read(ICR_COMMAND) };
            if status & (1 << 12) == 0 {
                break;
            }
            spins += 1;
            if spins > 1_000_000 {
                return false;
            }
        }

        // Self shorthand (`0b01 << 18`), fixed delivery, and the vector.  The
        // high half is cleared first: the shorthand ignores it, and writing it
        // says the field is not part of this command.
        // SAFETY: the caller's contract.
        unsafe {
            self.write(ICR_DESTINATION, 0);
            self.write(ICR_COMMAND, (1 << 18) | (vector as u32));
        }
        true
    }

    /// Send an INIT interrupt to the CPU whose APIC id is `target`.
    ///
    /// The target CPU resets and waits for a start-up interrupt.  One write,
    /// asserted: the deassert half of the pair the old machines wanted is a
    /// broadcast, the manuals' arbitration-id sync for systems whose APICs
    /// latch the level, and on this machine it arrives at every CPU including
    /// the sender, which is the sender resetting itself mid-boot.  The target
    /// that needs resetting got the assert.
    ///
    /// # Safety
    ///
    /// The base must be a mapped device page.  The target CPU must have a
    /// page to be started into, because a reset CPU that takes a start-up
    /// interrupt for a vector nothing mapped is reset twice and lost.
    pub unsafe fn send_init(&self, target: u32) -> bool {
        // SAFETY: the caller's contract.
        unsafe { self.icr(target << 24, ICR_DELIVERY_INIT | ICR_LEVEL_ASSERT) }
    }

    /// Send a start-up interrupt: the target CPU begins at `vector * 0x1000`
    /// in 16-bit real mode.
    ///
    /// The convention is to send it twice, the second covering a target that
    /// had not finished resetting when the first arrived; the caller sends
    /// both, because the sequence is the caller's to own.
    ///
    /// # Safety
    ///
    /// As [`Apic::send_init`], and `vector * 0x1000` must name the page a
    /// started CPU should execute.
    pub unsafe fn send_startup(&self, target: u32, vector: u8) -> bool {
        // SAFETY: the caller's contract.
        unsafe {
            self.icr(
                target << 24,
                ICR_DELIVERY_STARTUP | ICR_LEVEL_ASSERT | vector as u32,
            )
        }
    }

    /// Send a fixed interrupt on `vector` to every CPU but this one.
    ///
    /// The destination shorthand `0b11` names them all without an id, which is
    /// what makes this a wake rather than an address: a CPU that has nothing
    /// enabled on the vector takes nothing, and one that does re-checks its
    /// wait because of it.
    ///
    /// # Safety
    ///
    /// The base must be a mapped device page, and every other CPU must have a
    /// handler for `vector`.
    pub unsafe fn send_to_others(&self, vector: u8) -> bool {
        // SAFETY: the caller's contract.
        unsafe { self.icr(0, ICR_SHORTHAND_OTHERS | vector as u32) }
    }

    /// The ICR write every send is: wait for any previous send to clear, name
    /// the destination, write the command.
    ///
    /// The ICR's bit 12 reads 1 while a send is in flight, and a second write
    /// before it clears is dropped, so the wait is what makes two sends in a
    /// row two sends.  Bounded, because a controller that never clears should
    /// report `false` rather than hang the boot.
    ///
    /// # Safety
    ///
    /// The base must be a mapped device page, and the target must have a
    /// handler for whatever the command delivers.
    unsafe fn icr(&self, destination: u32, command: u32) -> bool {
        let mut spins = 0u32;
        loop {
            // SAFETY: the caller promises the base is a mapped device page.
            let status = unsafe { self.read(ICR_COMMAND) };
            if status & (1 << 12) == 0 {
                break;
            }
            spins += 1;
            if spins > 1_000_000 {
                return false;
            }
        }
        // SAFETY: as above.
        unsafe {
            self.write(ICR_DESTINATION, destination);
            self.write(ICR_COMMAND, command);
        }
        true
    }
}

/// The ICR's high half: where the destination goes.
///
/// The destination is the field's **top byte**, bits 24..31 of this dword,
/// which are bits 56..63 of the 64-bit register: a destination of 1 is written
/// as `1 << 24`, and a value written whole names no CPU at all, which is the
/// mistake that sends an INIT to the sender.
pub const ICR_DESTINATION: usize = 0x310;
/// The ICR's low half: the vector, the delivery mode and the destination
/// shorthand.
pub const ICR_COMMAND: usize = 0x300;

/// The ICR's delivery-mode field, bits 8..10: `0b101` is INIT, `0b110` is
/// start-up, and both name the target CPU rather than using the shorthand.
pub const ICR_DELIVERY_INIT: u32 = 0b101 << 8;
pub const ICR_DELIVERY_STARTUP: u32 = 0b110 << 8;
/// The ICR's level bit, bit 14: set is assert, clear is deassert.  An INIT
/// pairs the two; a start-up asserts.
pub const ICR_LEVEL_ASSERT: u32 = 1 << 14;
/// The destination shorthand, bits 18..19: `0b11` is every CPU but this one,
/// which is what an inter-processor interrupt means.
pub const ICR_SHORTHAND_OTHERS: u32 = 0b11 << 18;

/// Read a model-specific register.
///
/// # Safety
///
/// `msr` must be one this machine defines and the read must not be of a
/// register whose value depends on something unmapped.
pub unsafe fn read_msr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: the caller promises the register is defined on this machine.
    // `rdmsr` reads the pair and has no other effect.
    unsafe {
        core::arch::asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((high as u64) << 32) | low as u64
}

/// Write a model-specific register.
///
/// # Safety
///
/// As [`read_msr`], and the value must be one the register accepts: a write to
/// a control register with an invalid bit is a general protection fault.
pub unsafe fn write_msr(msr: u32, value: u64) {
    // SAFETY: the caller's contract.  `wrmsr` writes the pair and has no other
    // effect.
    unsafe {
        core::arch::asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nomem, nostack, preserves_flags)
        );
    }
}

/// Measure the APIC timer's frequency against the PIT.
///
/// Channel 2 is put into mode 0, count down once, then stop, with a known
/// initial count.  The APIC's timer is started at its maximum count at the same
/// moment.  When the PIT reaches zero (its output bit in port `0x61` goes
/// high), the APIC's counter is read: the difference is how many APIC ticks
/// elapsed while the PIT counted its own.
///
/// The ratio is the measurement, and multiplying it by the PIT's frequency
/// gives the APIC's.  Nothing is assumed about the bus clock, which is the
/// whole point: a machine whose clock is 100 MHz and one whose clock is 24 MHz
/// both come out right.
///
/// The measurement needs the timer running, and a timer left running would fire
/// before the boot has a handler.  So it is disarmed here and armed again by
/// whichever code wants a tick, which is the same discipline the generic timer
/// follows on the other machine.
///
/// # Safety
///
/// Called once, after [`Apic::enable`], with interrupts disabled: a timer
/// interrupt arriving mid-measurement would be delivered against a table whose
/// handler expects the boot to have finished.
pub unsafe fn calibrate(apic: &Apic) -> Option<u64> {
    let pit_count = PIT_MAX_COUNT;

    // The gate's bits: bit 0 gates channel 2, bit 1 its speaker output.  They
    // are cleared before the count is loaded, a counter that was already
    // counting would start from wherever it was.
    let gate = crate::port::inb(PIT_GATE);
    // SAFETY: as above; bit 0 low disables the gate and bit 1 low disables the
    // speaker, which is what keeps channel 2's output from being audible.
    crate::port::outb(PIT_GATE, gate & !0b11);

    // Mode 0, channel 2, lobyte/hibyte.
    crate::port::outb(PIT_COMMAND, PIT_CHANNEL2_ONE_SHOT);
    crate::port::outb(PIT_CHANNEL2, (pit_count & 0xFF) as u8);
    crate::port::outb(PIT_CHANNEL2, (pit_count >> 8) as u8);

    // The APIC's counter, started at its maximum so it cannot wrap during a
    // measurement this short.
    // SAFETY: the caller promises the APIC is mapped and enabled.
    unsafe {
        apic.write(register::TIMER_DIVIDE, DIVIDE_BY_16);
        apic.write(register::TIMER_VECTOR, (TIMER_VECTOR as u32) | (1 << 16));
        apic.write(register::TIMER_INITIAL_COUNT, u32::MAX);
    }
    // SAFETY: as above.
    let started = unsafe { apic.timer_count() };

    // Gate channel 2 open, which starts the count.
    //
    // Bit 0 set opens the gate, and bit 1 is left clear so the speaker stays
    // silent.
    crate::port::outb(PIT_GATE, (gate | 0b0000_0001) & 0b1111_1101);

    // Wait for the output bit (bit 5 of port 0x61) to go high: mode 0 sets it
    // when the count reaches zero.
    //
    // The bound is not a timeout in the error sense, it exists so a machine
    // whose PIT does not answer returns `None` instead of hanging the boot.  A
    // million reads is generously more than 65536 PIT ticks.
    let mut spins = 0u32;
    loop {
        let status = crate::port::inb(PIT_GATE);
        if status & 0b0010_0000 != 0 {
            break;
        }
        spins += 1;
        if spins > 10_000_000 {
            // SAFETY: leaving the timer disarmed is the correct state for a
            // failed measurement.
            unsafe { apic.disarm_timer() };
            return None;
        }
    }
    // SAFETY: as above.
    let finished = unsafe { apic.timer_count() };

    // SAFETY: the timer's job is done.
    unsafe { apic.disarm_timer() };

    // Both counts are downward, and the measurement is the difference.  A
    // difference of zero means the timer did not run, which is a failure
    // rather than a frequency of zero.
    let elapsed = started.wrapping_sub(finished) as u64;
    if elapsed == 0 {
        return None;
    }

    // The APIC's frequency: elapsed APIC ticks per `pit_count` PIT ticks, times
    // the PIT's frequency.  Dividing by the divide-by-16 factor is part of the
    // definition, the counter counts at bus/16, so the bus clock is sixteen
    // times what was measured per second.
    let per_second = elapsed * PIT_FREQUENCY / pit_count as u64;
    Some(per_second * 16)
}

/// Measure the timestamp counter's rate against the PIT.
///
/// The APIC's timer and the TSC are different clocks with different rates.  A
/// deadline is a TSC reading, so converting a duration to a deadline needs the
/// TSC's rate; a countdown is an APIC count, so arming the timer needs the
/// APIC's.  One number cannot serve both, and the first version of this code
/// used the APIC's for the TSC as well, which worked on this emulator because
/// a twenty-millisecond sleep has enough slack to absorb being sixteen times
/// too short, and would not have worked on anything that asked for a small one.
///
/// The method is the PIT, for the reason it was used the first time: its
/// crystal is documented and needs no firmware table.
///
/// # Safety
///
/// Called once, with interrupts disabled.  It programs the PIT's channel 2,
/// which nothing else in this kernel uses.
pub unsafe fn calibrate_clock() -> Option<u64> {
    let pit_count = PIT_MAX_COUNT;

    let gate = crate::port::inb(PIT_GATE);
    crate::port::outb(PIT_GATE, gate & !0b11);
    crate::port::outb(PIT_COMMAND, PIT_CHANNEL2_ONE_SHOT);
    crate::port::outb(PIT_CHANNEL2, (pit_count & 0xFF) as u8);
    crate::port::outb(PIT_CHANNEL2, (pit_count >> 8) as u8);

    // SAFETY: `rdtsc` reads the counter.
    let started = unsafe { read_tsc() };
    crate::port::outb(PIT_GATE, (gate | 0b0000_0001) & 0b1111_1101);

    let mut spins = 0u32;
    loop {
        if crate::port::inb(PIT_GATE) & 0b0010_0000 != 0 {
            break;
        }
        spins += 1;
        if spins > 10_000_000 {
            return None;
        }
    }
    // SAFETY: as above.
    let finished = unsafe { read_tsc() };

    let elapsed = finished.wrapping_sub(started);
    if elapsed == 0 {
        return None;
    }
    // TSC ticks per PIT tick, times the PIT's frequency.  No divide factor:
    // the TSC is not behind the APIC's divide configuration.
    Some(elapsed * PIT_FREQUENCY / pit_count as u64)
}

/// The timestamp counter, read and serialised.
///
/// `lfence` before `rdtsc` is what orders the read after earlier instructions:
/// without it the processor may perform the read early, and two readings around
/// a delay can come back in the wrong order.
///
/// # Safety
///
/// Reads a counter; unprivileged and with no side effect.
pub unsafe fn read_tsc() -> u64 {
    let low: u32;
    let high: u32;
    // SAFETY: the caller's contract.
    unsafe {
        core::arch::asm!(
            "lfence",
            "rdtsc",
            out("eax") low,
            out("edx") high,
            options(nomem, nostack)
        );
    }
    ((high as u64) << 32) | low as u64
}

/// How many APIC ticks are `microseconds` long, at `frequency`.
///
/// At least one: a request shorter than a single tick would give zero, and a
/// counter loaded with zero fires immediately, which reads as a timer that
/// works and is actually a tight loop of interrupts.
pub const fn ticks_for_microseconds(frequency: u64, microseconds: u64) -> u32 {
    // **Multiply first, then divide.**  Dividing the frequency by a million
    // first threw away its remainder, and a frequency below one megahertz
    // divided to zero so every slice became one tick whatever the caller asked
    // for.  Both other machines had the same defect in their copies of this
    // function, and the aarch64 copy records what it cost: a boot that never
    // ended.
    //
    // The product is taken in `u128` so that a large frequency and a large
    // slice cannot wrap: a wrapped count is a *short* slice, the opposite of
    // the failure the floor below avoids.
    let ticks = (frequency as u128 * microseconds as u128) / 1_000_000;
    if ticks == 0 {
        1
    } else if ticks > u32::MAX as u128 {
        u32::MAX
    } else {
        ticks as u32
    }
}

#[cfg(test)]
mod tests {
    use super::APIC_BASE_ENABLE;
    use super::APIC_BASE_MASK;
    use super::DIVIDE_BY_16;
    use super::IA32_APIC_BASE;
    use super::PIT_CHANNEL2_ONE_SHOT;
    use super::PIT_FREQUENCY;
    use super::PIT_MAX_COUNT;
    use super::SPURIOUS_VECTOR;
    use super::TIMER_VECTOR;
    use super::ticks_for_microseconds;

    /// The APIC's base mask keeps the flags out of the address.
    ///
    /// The low twelve bits of `IA32_APIC_BASE` are flags, the enabled bit, the
    /// BSP bit, and one reserved, so a mask of `!0xFFF` would keep them in the
    /// address and read a register at a misaligned address no machine has.
    #[test]
    fn the_apic_address_does_not_reach_the_flags() {
        // Firmware's usual value: enabled, at 0xFEE0_0000.
        let value = 0xFEE0_0000u64 | APIC_BASE_ENABLE;
        let address = value & APIC_BASE_MASK;
        assert_eq!(address, 0xFEE0_0000);
        assert_eq!(address & 0xFFF, 0, "page-aligned");
        assert_eq!(value & APIC_BASE_ENABLE, APIC_BASE_ENABLE);
    }

    /// The PIT's calibration divisor is not the division factor.
    ///
    /// `0b0011` means sixteen and `0b1011` means one; the field is a table and
    /// not arithmetic, which is the kind of constant a reader would "fix".
    #[test]
    fn the_divide_field_is_a_table_and_not_a_number() {
        assert_eq!(DIVIDE_BY_16, 0b0011);
        assert_ne!(DIVIDE_BY_16 as u64, 16, "the field is not the divisor");
    }

    /// A time slice converts to a count, and never to zero.
    ///
    /// A count of zero fires immediately, which looks like a working timer and
    /// is a loop of interrupts, the same defect a zero-length time slice would
    /// be.
    #[test]
    fn a_request_shorter_than_one_tick_becomes_one_tick() {
        let frequency = 100_000_000;
        assert_eq!(ticks_for_microseconds(frequency, 100), 10_000);
        assert_eq!(ticks_for_microseconds(frequency, 0), 1, "never zero");
        assert_eq!(ticks_for_microseconds(1_000, 1), 1, "rounds up to one");
        assert_eq!(
            ticks_for_microseconds(u64::MAX / 2, u64::MAX / 2),
            u32::MAX,
            "clamped rather than wrapped"
        );
    }

    /// The vectors are above the processor's exceptions, and the two differ.
    ///
    /// A device's line numbered like a fault is a fault handler entered by a
    /// device, the defect the 8259's reset vector base of 8 produced here,
    /// where a timer tick arrived as a double fault.
    ///
    /// These are `const` assertions and not a test, because they are relations
    /// between constants: `TIMER_VECTOR >= 32` is a fact about a literal, and a
    /// test that asserted it would run every time to check something the
    /// compiler had already decided.  The spurious vector is separately pinned
    /// to `u8::MAX`, the APIC's convention is the highest vector, above every
    /// one this kernel assigns, and a value in the middle would collide with a
    /// device's line.
    #[test]
    fn the_vectors_are_above_the_exceptions_and_differ() {
        assert_ne!(TIMER_VECTOR, SPURIOUS_VECTOR, "two purposes, two vectors");
        assert_eq!(SPURIOUS_VECTOR, u8::MAX, "the highest vector");
    }

    /// The PIT's frequency is the documented crystal, and the command byte's
    /// fields say what the calibration needs.
    #[test]
    fn the_pit_constants_are_the_architecture_s() {
        assert_eq!(PIT_FREQUENCY, 1_193_182);
        assert_eq!(PIT_MAX_COUNT, 0xFFFF);

        // Channel 2, lobyte/hibyte, mode 0, binary.
        assert_eq!(PIT_CHANNEL2_ONE_SHOT >> 6, 0b10, "channel 2");
        assert_eq!((PIT_CHANNEL2_ONE_SHOT >> 4) & 0b11, 0b11, "lobyte/hibyte");
        assert_eq!((PIT_CHANNEL2_ONE_SHOT >> 1) & 0b111, 0b000, "mode 0");
        assert_eq!(PIT_CHANNEL2_ONE_SHOT & 1, 0, "binary");
    }

    /// The MSR is the one `IA32_APIC_BASE` names.
    #[test]
    fn the_apic_base_msr_is_the_documented_one() {
        assert_eq!(IA32_APIC_BASE, 0x1B);
    }
}
