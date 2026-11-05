//! arch/riscv64/src/serial.rs
//!
//! The NS16550A UART, which is how a boot says anything at all.
//!
//! `qemu-system-riscv64 -machine virt` puts an NS16550A at a fixed address that
//! OpenSBI hands over in the device tree, and a boot has to be able to speak
//! before it can parse one.  The same argument as x86_64's COM1 and aarch64's
//! PL011: the kernel's first output cannot be a discovered device.
//!
//! ## The address
//!
//! `0x1000_0000` is where `virt` places its UART, and where QEMU's generated
//! device tree reports it.  A real board's address comes from firmware; until
//! this tree parses one, the constant is the statement "this is the machine the
//! boot gates run on".

/// The NS16550A's data register.
#[cfg(target_os = "none")]
const UART_BASE: usize = 0x1000_0000;

// The 16550's register offsets.  With DLAB set, `DATA` and `IER` become the
// divisor latch's low and high halves.
#[cfg(target_os = "none")]
const DATA: usize = 0;
#[cfg(target_os = "none")]
const IER: usize = 1;
#[cfg(target_os = "none")]
const FCR: usize = 2;
#[cfg(target_os = "none")]
const LCR: usize = 3;
#[cfg(target_os = "none")]
const LSR: usize = 5;

/// The interrupt-enable register's bits, as the 16550 defines them.
///
/// Bit 0 is "a byte arrived", bit 1 is "the transmitter is empty", bit 2 is the
/// line status (an error), and bit 3 is the modem.  This kernel uses the second
/// and only the second: it talks, it does not listen, and a transmit interrupt
/// is the one the device raises on its own once told to.
#[cfg(target_os = "none")]
pub const IER_RECEIVED: u8 = 0x01;
#[cfg(target_os = "none")]
pub const IER_TRANSMIT_EMPTY: u8 = 0x02;

/// The interrupt-identification register's "nothing pending" value.
///
/// Reading it is what acknowledges the interrupt: the 16550 has no separate
/// acknowledge register, and its lowest bit is set while an interrupt is still
/// waiting to be serviced.
#[cfg(target_os = "none")]
const IIR: usize = 2;

/// # Safety
///
/// `address` must be a mapped, writable MMIO address this machine has.
#[cfg(target_os = "none")]
unsafe fn write_reg(address: usize, value: u8) {
    // SAFETY: the caller promises a live MMIO register; volatile keeps the
    // compiler from folding two writes the device must both see.
    unsafe { core::ptr::write_volatile(address as *mut u8, value) };
}

/// # Safety
///
/// As `write_reg`.
#[cfg(target_os = "none")]
unsafe fn read_reg(address: usize) -> u8 {
    // SAFETY: the caller promises a live MMIO register.
    unsafe { core::ptr::read_volatile(address as *const u8) }
}

/// Initialise the UART for 115200 baud, 8 bits, no parity, one stop bit.
#[cfg(target_os = "none")]
pub fn init() {
    // SAFETY: UART_BASE is where the emulated platform places its UART, and
    // each write below is the documented 16550 initialisation sequence.
    unsafe {
        write_reg(UART_BASE + IER, 0x00);
        write_reg(UART_BASE + LCR, 0x80); // DLAB: the next two writes are the divisor
        write_reg(UART_BASE + DATA, 0x01); // 115200 with a 1.8432 MHz clock
        write_reg(UART_BASE + IER, 0x00);
        write_reg(UART_BASE + LCR, 0x03); // 8 bits, no parity, one stop bit
        write_reg(UART_BASE + FCR, 0xC7); // enable and clear the FIFOs
    }
}

/// Ask the UART to raise its line when the transmitter empties.
///
/// The console is the boot's output and the gate reads it as a log; a kernel
/// that also listened would consume the bytes a reader typed, and the gate's
/// own log would be a second thing on the same wire.  A transmit interrupt is
/// the device's own work: it says "I sent the byte you gave me", which is a
/// fact the kernel already depends on and can count without touching input.
///
/// # Safety
///
/// Called after [`init`], once, when the PLIC source for this UART is enabled.
#[cfg(target_os = "none")]
pub unsafe fn enable_transmit_interrupt() {
    // SAFETY: `IER` is the 16550's interrupt-enable register, and the value is
    // the one bit this function is named for.
    unsafe { write_reg(UART_BASE + IER, IER_TRANSMIT_EMPTY) };
}

/// Stop the UART raising its line.
///
/// # Safety
///
/// As [`enable_transmit_interrupt`].
#[cfg(target_os = "none")]
pub unsafe fn disable_interrupts() {
    // SAFETY: as above, with no bits set.
    unsafe { write_reg(UART_BASE + IER, 0) };
}

/// Acknowledge one interrupt the UART raised, and say whether it was ours.
///
/// The 16550 answers a read of `IIR`, and the read *is* the acknowledge: its
/// lowest bit is clear while an interrupt is pending, and the other bits name
/// which one.  A value whose low bit is set means the device had nothing for
/// us, an interrupt the controller delivered for a source that had already
/// been serviced, which happens and is not an error.
///
/// # Safety
///
/// Called from the trap path, for this source's identity.
#[cfg(target_os = "none")]
pub unsafe fn acknowledge() -> bool {
    // SAFETY: reading `IIR` at the UART's window both reads and acknowledges.
    let identity = unsafe { read_reg(UART_BASE + IIR) };
    identity & 0x01 == 0
}
#[cfg(target_os = "none")]
fn transmit_ready() -> bool {
    // Bit 5 of the line status register is "transmit holding register empty".
    // SAFETY: reading the status of a UART `init` has programmed.
    unsafe { read_reg(UART_BASE + LSR) & 0x20 != 0 }
}

/// Write one byte, waiting for the transmitter.
#[cfg(target_os = "none")]
pub fn write_byte(byte: u8) {
    if byte == b'\n' {
        write_byte(b'\r');
    }
    while !transmit_ready() {
        core::hint::spin_loop();
    }
    // SAFETY: the transmitter reported room, and UART_BASE is the register
    // `init` programmed.
    unsafe { write_reg(UART_BASE + DATA, byte) };
}

#[cfg(not(target_os = "none"))]
pub fn write_byte(byte: u8) {
    // The newline expansion is here too, and that is the point of the arm: a
    // host build that recorded a bare `\n` would let the test below pass while
    // the real console did something else.  The two arms have to differ in
    // *where* the byte goes, not in what a newline means.
    if byte == b'\n' {
        HOST_CONSOLE.lock().push(b'\r');
    }
    HOST_CONSOLE.lock().push(byte);
}

#[cfg(not(target_os = "none"))]
static HOST_CONSOLE: spin::Mutex<alloc::vec::Vec<u8>> = spin::Mutex::new(alloc::vec::Vec::new());

/// What a host build "wrote" to the console, in order.
///
/// A host has no UART at the address this machine puts one, so the real arm
/// would fault the moment a test formatted a line.  This records the bytes
/// instead, which makes `write_str` testable and is also the only way to assert
/// what a boot path printed without an emulator.
#[cfg(not(target_os = "none"))]
pub fn host_console_take() -> alloc::vec::Vec<u8> {
    core::mem::take(&mut *HOST_CONSOLE.lock())
}

/// A host build has no port to program.
///
/// The console's host arm records bytes, so there is nothing to initialise;
/// the function exists because the kernel calls it on every machine, and a host
/// build of the kernel is a typecheck rather than a boot.
#[cfg(not(target_os = "none"))]
pub fn init() {}

/// A boot line is not one call.  `protofire: cpu 1 id 1, ticking, 1 ipi(s)`
/// is eight calls to `write_str`, `write_u32` and `write_hex`, and a lock
/// taken per call would let a second CPU's line land between any two of them:
/// the log this produced read `pro0tofire: unhandled exception 12 label(s)`,
/// which is two lines interleaved at a call boundary and worse than either.
///
/// So each CPU buffers its own line and the buffer is written out at the
/// newline, in one locked burst.  Two properties follow and both are what a
/// reader needs: a line is atomic, and a CPU's own output keeps its order
/// without any lock held between calls.
///
/// The buffer is per-CPU because the alternative, one shared buffer, would
/// need the lock held from the first byte of a line to the last, which is a
/// lock held across whatever the caller does between two prints.  A slot
/// indexes it exactly as it indexes the kernel stacks.
pub fn write_str(text: &str) {
    for byte in text.bytes() {
        push(byte);
    }
}

/// Add one byte to this CPU's line, writing the line out at a newline.
///
/// Every console function goes through here, including the number formatters:
/// a formatter that wrote straight to the device would put its digits where
/// the device was at that instant, which is ahead of the text still waiting in
/// the buffer.  The first version of this did exactly that and the log read
/// `2515587protofire: a program sleeps until counter`.
fn push(byte: u8) {
    // A slot past the array would be a CPU the kernel never numbered, and the
    // boot's own bound is what stops one: the last slot is the one a started
    // hart is given.  Clamping rather than panicking keeps the console usable
    // from a fault handler, which is where a wrong slot would be discovered.
    let slot = crate::current_cpu_slot().min(LINE_SLOTS - 1);
    // SAFETY: the slot is this CPU's own, from `tp`, and no other CPU reads or
    // writes this buffer.  The buffer's own flush takes the console lock.
    let line = unsafe { &mut *LINE_BUFFERS[slot].get() };
    if byte != b'\n' {
        line.push(byte);
        return;
    }

    // The newline ends the line, so everything before it goes out together.
    // The mask is taken here and not earlier: buffering is this CPU's own
    // state, and holding the mask across it would lengthen a critical section
    // for no exclusion.
    let enabled = crate::interrupts::save_and_disable();
    // SAFETY: interrupts are masked on this CPU, and the release below is the
    // one matching acquisition.
    unsafe {
        CONSOLE_LOCK.acquire();
        for buffered in line.drain() {
            write_byte(buffered);
        }
        write_byte(b'\n');
        CONSOLE_LOCK.release();
    }
    crate::interrupts::restore(enabled);
}

/// How long one buffered line may be.
///
/// The longest line this tree prints is a boot report of a few hundred bytes.
/// A line longer than this is written out early rather than truncated: a
/// console that dropped bytes would be a log that lied, and the cost of the
/// flush is one lock.
const LINE_CAPACITY: usize = 512;

/// One line buffer per CPU slot.
///
/// A `SyncUnsafeCell` per slot and not one shared buffer: each CPU owns its
/// own, and no lock is held between two calls that build one line.  The type
/// is `cell`'s for the reason the crate exists, and the safety argument is the
/// slot: only the CPU whose `tp` names a slot ever reads or writes it.
static LINE_BUFFERS: [cell::SyncUnsafeCell<LineBuffer>; LINE_SLOTS] =
    [const { cell::SyncUnsafeCell::new(LineBuffer::new()) }; LINE_SLOTS];

/// How many line buffers there are: one per CPU slot the kernel can number.
///
/// The count is `smp`'s, because this machine starts other CPUs and the kernel
/// numbers them past the boot one.  The other two machines answer one, and
/// each says so where its own constant is.
const LINE_SLOTS: usize = 1 + crate::smp::MAX_SECONDARY_HARTS;

/// A line being assembled, as a fixed array and a length.
///
/// Fixed rather than a `Vec`: the console is used before the heap exists and
/// from inside the allocator's failure path, so it cannot allocate.  The
/// length is what a flush drains.
struct LineBuffer {
    bytes: [u8; LINE_CAPACITY],
    length: usize,
}

impl LineBuffer {
    const fn new() -> LineBuffer {
        LineBuffer {
            bytes: [0; LINE_CAPACITY],
            length: 0,
        }
    }

    /// Add one byte, flushing early when the buffer is full.
    ///
    /// Flushing here rather than dropping is the choice this makes: a line
    /// past the capacity is split across two console writes, which is visible
    /// as two lines rather than as a corrupted one.
    fn push(&mut self, byte: u8) {
        if self.length == self.bytes.len() {
            self.flush();
        }
        self.bytes[self.length] = byte;
        self.length += 1;
    }

    /// Hand back every buffered byte, in order.
    fn drain(&mut self) -> impl Iterator<Item = u8> + '_ {
        let length = core::mem::take(&mut self.length);
        self.bytes[..length].iter().copied()
    }

    /// Write what is buffered straight out.
    ///
    /// Called by `push` when a line overflows, and it takes the lock itself
    /// because it is reached from inside a line rather than at its end.
    fn flush(&mut self) {
        // SAFETY: the caller is inside `write_str`'s mask, and this is the one
        // matching release.
        unsafe {
            CONSOLE_LOCK.acquire();
            for byte in self.drain() {
                write_byte(byte);
            }
            CONSOLE_LOCK.release();
        }
    }
}

/// The cross-CPU half of the console's exclusion.
///
/// A lock here rather than in `kernel`: the console is the machine's, the
/// function that writes it is the machine's, and every caller of `write_str`
/// would otherwise have to remember to take one first.  `sync::SpinLock` cannot
/// be named from an architecture crate, which is why `cell` carries the bit.
static CONSOLE_LOCK: cell::RawSpin = cell::RawSpin::new();

/// Write a `u32` as decimal, without allocating.
pub fn write_u32(value: u32) {
    if value == 0 {
        push(b'0');
        return;
    }
    let mut buffer = [0u8; 10];
    let mut position = buffer.len();
    let mut remaining = value;
    while remaining > 0 {
        position -= 1;
        buffer[position] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
    }
    for byte in &buffer[position..] {
        push(*byte);
    }
}

/// Write a `u64` as lower-case hexadecimal, without allocating.
pub fn write_hex(value: u64) {
    write_str("0x");
    if value == 0 {
        push(b'0');
        return;
    }
    let mut started = false;
    for shift in (0..16).rev() {
        let digit = ((value >> (shift * 4)) & 0xF) as u8;
        if digit == 0 && !started {
            continue;
        }
        started = true;
        push(if digit < 10 {
            b'0' + digit
        } else {
            b'a' + digit - 10
        });
    }
}

#[cfg(test)]
mod tests {

    /// Serialise the console tests: they share one recording buffer.
    ///
    /// `HOST_CONSOLE` is a process-wide static, because it stands in for a
    /// machine's one console.  Two tests that each clear it and then assert
    /// what they wrote are therefore racing for a resource only one of them
    /// can own, and the harness runs tests in parallel by default: the pair
    /// passed alone and failed in a workspace run, which is the shape of a
    /// flake that a serial run hides.  Holding this lock makes the buffer one
    /// resource again.
    static CONSOLE_TESTS: spin::Mutex<()> = spin::Mutex::new(());

    fn serialize() -> spin::MutexGuard<'static, ()> {
        CONSOLE_TESTS.lock()
    }
    /// A host build records what the console was asked to write.
    ///
    /// This is the arm that makes the console testable at all: the real one
    /// writes a port or an MMIO register that a host does not have, so without
    /// this every assertion about a boot's output would need an emulator.
    ///
    /// The unit is a **line**, because the console writes one: text without a
    /// newline is still buffered, and a test that asserted the buffer's
    /// contents would be asserting a state the console does not promise.  What
    /// it promises is that a line arrives whole, which is what this checks.
    #[cfg(not(target_os = "none"))]
    #[test]
    fn a_host_records_a_whole_line() {
        let _guard = serialize();
        let _ = super::host_console_take();
        super::write_str("heap\n");
        assert_eq!(super::host_console_take(), b"heap\r\n");
    }

    /// Two calls that build one line arrive as one line.
    ///
    /// This is the property the buffer exists for: `protofire: cpu 1 id ` is
    /// one call and `1` is another, and a console that wrote each call's bytes
    /// as it received them would let a second CPU's line land between them.
    #[cfg(not(target_os = "none"))]
    #[test]
    fn two_calls_build_one_line() {
        let _guard = serialize();
        let _ = super::host_console_take();
        super::write_str("cpu ");
        super::write_u32(1);
        super::write_str("\n");
        assert_eq!(super::host_console_take(), b"cpu 1\r\n");
    }

    /// A newline is written as CRLF, because the reader is a terminal.
    ///
    /// The gate that reads a boot's serial log strips the CR, so this is not
    /// what that check is about, but a sink that dropped it would make every
    /// log unusable in a terminal, and nothing else in the tree would notice.
    #[cfg(not(target_os = "none"))]
    #[test]
    fn a_newline_is_two_bytes() {
        let _guard = serialize();
        let _ = super::host_console_take();
        super::write_byte(b'\n');
        assert_eq!(super::host_console_take(), b"\r\n");
    }

    /// Hexadecimal is written with a `0x` prefix, lower case, no padding.
    ///
    /// The boot's address line is read by a human comparing it against a linker
    /// script, so the shape matters and is pinned here.
    #[cfg(not(target_os = "none"))]
    #[test]
    fn hexadecimal_has_the_shape_a_reader_expects() {
        let _guard = serialize();
        let _ = super::host_console_take();
        super::write_hex(0);
        super::write_str("\n");
        assert_eq!(super::host_console_take(), b"0x0\r\n");

        let _ = super::host_console_take();
        super::write_hex(0x11d790);
        super::write_str("\n");
        assert_eq!(super::host_console_take(), b"0x11d790\r\n");

        let _ = super::host_console_take();
        super::write_hex(u64::MAX);
        super::write_str("\n");
        assert_eq!(super::host_console_take(), b"0xffffffffffffffff\r\n");
    }
}
