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
const UART_BASE: usize = 0x1000_0000;

// The 16550's register offsets.  With DLAB set, `DATA` and `IER` become the
// divisor latch's low and high halves.
const DATA: usize = 0;
const IER: usize = 1;
const FCR: usize = 2;
const LCR: usize = 3;
const LSR: usize = 5;

/// Write one byte to a memory-mapped register.
///
/// # Safety
///
/// `address` must be a mapped, writable MMIO address this machine has.
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
unsafe fn read_reg(address: usize) -> u8 {
    // SAFETY: the caller promises a live MMIO register.
    unsafe { core::ptr::read_volatile(address as *const u8) }
}

/// Initialise the UART for 115200 baud, 8 bits, no parity, one stop bit.
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

/// Whether the transmitter is ready for a byte.
fn transmit_ready() -> bool {
    // Bit 5 of the line status register is "transmit holding register empty".
    // SAFETY: reading the status of a UART `init` has programmed.
    unsafe { read_reg(UART_BASE + LSR) & 0x20 != 0 }
}

/// Write one byte, waiting for the transmitter.
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
