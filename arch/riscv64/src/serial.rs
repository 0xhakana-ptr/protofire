//! arch/riscv64/src/serial.rs
//!
//! The NS16550A UART, which is how a boot says anything at all.
//!
//! ## Why this is here and not a driver crate
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

/// Write one byte to a memory-mapped register.
///
/// # Safety
///
/// `address` must be a mapped, writable MMIO address this machine has.
#[cfg(target_os = "none")]
unsafe fn write_reg(address: usize, value: u8) {
    // SAFETY: the caller promises a live MMIO register; volatile keeps the
    // compiler from folding two writes the device must both see.
    unsafe { core::ptr::write_volatile(address as *mut u8, value) };
}

/// Read one byte from a memory-mapped register.
///
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
/// ## Why this interrupt and not "a byte arrived"
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

/// Write a string, one byte at a time.
pub fn write_str(text: &str) {
    for byte in text.bytes() {
        write_byte(byte);
    }
}

/// Write a `u32` as decimal, without allocating.
pub fn write_u32(value: u32) {
    if value == 0 {
        write_byte(b'0');
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
        write_byte(*byte);
    }
}

/// Write a `u64` as lower-case hexadecimal, without allocating.
pub fn write_hex(value: u64) {
    write_str("0x");
    if value == 0 {
        write_byte(b'0');
        return;
    }
    let mut started = false;
    for shift in (0..16).rev() {
        let digit = ((value >> (shift * 4)) & 0xF) as u8;
        if digit == 0 && !started {
            continue;
        }
        started = true;
        write_byte(if digit < 10 {
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
    #[cfg(not(target_os = "none"))]
    #[test]
    fn a_host_records_what_was_written() {
        let _guard = serialize();
        let _ = super::host_console_take();
        super::write_str("heap");
        assert_eq!(super::host_console_take(), b"heap");
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
        assert_eq!(super::host_console_take(), b"0x0");

        let _ = super::host_console_take();
        super::write_hex(0x11d790);
        assert_eq!(super::host_console_take(), b"0x11d790");

        let _ = super::host_console_take();
        super::write_hex(u64::MAX);
        assert_eq!(super::host_console_take(), b"0xffffffffffffffff");
    }
}
