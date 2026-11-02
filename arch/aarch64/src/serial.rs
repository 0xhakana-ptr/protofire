//! arch/aarch64/src/serial.rs
//!
//! The PL011 UART, which is how a boot says anything at all.
//!
//! ## Why this is here and not a driver crate
//!
//! `qemu-system-aarch64 -machine virt` puts a PL011 at a fixed address that
//! firmware hands over in the device tree, and a boot has to be able to speak
//! before it can parse a device tree.  The kernel's first output therefore
//! cannot be a discovered device, and cannot wait for a driver registry — the
//! same argument as x86_64's COM1, on a machine where the address is a
//! constant of the emulated platform.
//!
//! ## The address
//!
//! `0x0900_0000` is where `virt` places its first PL011, and where QEMU's own
//! generated device tree reports it.  A real board's address comes from
//! firmware; until this tree parses one, the constant is the statement "this
//! is the machine the boot gates run on", and a board with a different address
//! gets no output rather than wrong output.

/// The PL011's data register.
#[cfg(target_os = "none")]
const UART_BASE: usize = 0x0900_0000;

/// Offsets of the registers this file touches.
#[cfg(target_os = "none")]
const DR: usize = 0x00;
/// The flag register: bit 5 is `TXFF`, transmit FIFO full.
#[cfg(target_os = "none")]
const FR: usize = 0x18;
/// The control register: bit 0 enables the UART, bit 8 enables transmit.
#[cfg(target_os = "none")]
const CR: usize = 0x30;
/// The line control register: 8 bits, FIFOs enabled.
#[cfg(target_os = "none")]
const LCR_H: usize = 0x2C;
/// The integer baud-rate divisor.  QEMU ignores it; a real board does not.
#[cfg(target_os = "none")]
const IBRD: usize = 0x24;
/// The fractional baud-rate divisor.
#[cfg(target_os = "none")]
const FBRD: usize = 0x28;

/// Write one byte to a memory-mapped register.
///
/// # Safety
///
/// `address` must be a mapped, writable MMIO address this machine has.  The
/// caller owns that promise; this function performs the write and nothing else.
#[cfg(target_os = "none")]
unsafe fn write_reg(address: usize, value: u32) {
    // SAFETY: the caller promises the address is a live MMIO register.  A
    // volatile write is what MMIO needs: the compiler must not fold two writes
    // to the same register, because each one is an operation the device
    // observes.
    unsafe { core::ptr::write_volatile(address as *mut u32, value) };
}

/// Read one byte from a memory-mapped register.
///
/// # Safety
///
/// As `write_reg`: `address` must be a live MMIO register.
#[cfg(target_os = "none")]
unsafe fn read_reg(address: usize) -> u32 {
    // SAFETY: the caller promises the address is a live MMIO register, and a
    // volatile read is what keeps the compiler from caching it.
    unsafe { core::ptr::read_volatile(address as *const u32) }
}

/// Initialise the PL011 for 115200 baud, 8 bits, no parity, one stop bit.
///
/// This is the configuration every serial console expects.  QEMU's PL011 model
/// ignores the divisor — the host side of the emulated line runs at whatever
/// the terminal is set to — but a real board does not, so the divisors are
/// programmed from the 24 MHz reference clock `virt` describes.
#[cfg(target_os = "none")]
pub fn init() {
    // SAFETY: UART_BASE is where the emulated platform places its PL011, and
    // each write below is the documented sequence from the PL011 manual.
    unsafe {
        // Disable the UART while its baud rate is changed.
        write_reg(UART_BASE + CR, 0);
        // 115200 from a 24 MHz reference: 24_000_000 / (16 * 115200) = 13.02.
        write_reg(UART_BASE + IBRD, 13);
        write_reg(UART_BASE + FBRD, 1);
        // 8 bits, FIFOs on, one stop bit, no parity.
        write_reg(UART_BASE + LCR_H, (1 << 4) | (1 << 5) | (1 << 6));
        // Enable the UART and its transmitter.
        write_reg(UART_BASE + CR, (1 << 0) | (1 << 8));
    }
}

/// Whether the transmitter can take a byte.
#[cfg(target_os = "none")]
fn transmit_ready() -> bool {
    // SAFETY: reading the flag register of a UART `init` has programmed.
    unsafe { read_reg(UART_BASE + FR) & (1 << 5) == 0 }
}

/// Write one byte, waiting for the transmitter.
#[cfg(target_os = "none")]
pub fn write_byte(byte: u8) {
    // A terminal needs both bytes of a newline; a bare `\n` moves down without
    // returning to column zero.
    if byte == b'\n' {
        write_byte(b'\r');
    }
    while !transmit_ready() {
        core::hint::spin_loop();
    }
    // SAFETY: the transmitter reported room, and UART_BASE is the register
    // `init` programmed.
    unsafe { write_reg(UART_BASE + DR, byte as u32) };
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
    /// A host build records what the console was asked to write.
    ///
    /// This is the arm that makes the console testable at all: the real one
    /// writes a port or an MMIO register that a host does not have, so without
    /// this every assertion about a boot's output would need an emulator.
    #[cfg(not(target_os = "none"))]
    #[test]
    fn a_host_records_what_was_written() {
        let _ = super::host_console_take();
        super::write_str("heap");
        assert_eq!(super::host_console_take(), b"heap");
    }

    /// A newline is written as CRLF, because the reader is a terminal.
    ///
    /// The gate that reads a boot's serial log strips the CR, so this is not
    /// what that check is about — but a sink that dropped it would make every
    /// log unusable in a terminal, and nothing else in the tree would notice.
    #[cfg(not(target_os = "none"))]
    #[test]
    fn a_newline_is_two_bytes() {
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
