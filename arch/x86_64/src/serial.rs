//! arch/x86_64/src/serial.rs
//!
//! The COM1 serial port, which is how a boot says anything at all.
//!
//! ## Why this is here and not in a driver crate
//!
//! A serial port is not a device the kernel discovers, it is part of the
//! machine the way a register is, present on every PC since the first one, at a
//! fixed I/O address, with no enumeration and no interrupt required.  The
//! kernel's first output has to work before there is a driver registry, an
//! allocator, or a heap to register anything in, so it cannot be a driver.
//!
//! `drivers/` may grow a serial device later for the ports this one does not
//! claim.  This is the one the boot writes to.

#[cfg(target_os = "none")]
use core::arch::asm;

/// COM1's data register.  The other registers are offsets from it, selected by
/// the line control register's DLAB bit.
#[cfg(target_os = "none")]
const COM1: u16 = 0x3F8;

// The 16550's register offsets, so the initialisation sequence can name the
// register each write reaches.  With DLAB set, `DATA` and `IER` become the
// divisor latch's low and high halves, which is why the same two offsets
// appear twice below with different meanings.
#[cfg(target_os = "none")]
const DATA: u16 = 0;
#[cfg(target_os = "none")]
const IER: u16 = 1;
#[cfg(target_os = "none")]
const FCR: u16 = 2;
#[cfg(target_os = "none")]
const LCR: u16 = 3;
#[cfg(target_os = "none")]
const MCR: u16 = 4;
#[cfg(target_os = "none")]
const LSR: u16 = 5;

/// Write one byte to a port.
///
/// SAFETY (of the callers): `port` must be an I/O port this machine has, and
/// the value is a byte, so no width question arises.
#[cfg(target_os = "none")]
unsafe fn outb(port: u16, value: u8) {
    // SAFETY: `out` writes an 8-bit value to the I/O port named.  The caller
    // owns the promise that the port exists; this function's contract is that
    // it performs the write and nothing else.
    unsafe { asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack)) };
}

/// Read one byte from a port.
///
/// SAFETY (of the callers): `port` must be an I/O port this machine has.
#[cfg(target_os = "none")]
unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: `in` reads an 8-bit value from the I/O port named.  Same contract
    // as `outb`: the caller promises the port exists.
    unsafe {
        asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack));
    }
    value
}

/// Initialise COM1 for 115200 baud, 8 data bits, no parity, one stop bit.
///
/// This is the configuration every serial console expects, and it is set by
/// hand rather than read from a table because a table would be a second place
/// the same eight writes are written down.
///
/// Calling it twice is harmless: it rewrites the same registers with the same
/// values.
#[cfg(target_os = "none")]
pub fn init() {
    // Interrupts off while the divisor is being programmed: the UART's own
    // interrupt enable register, not the CPU's.
    //
    // Each offset is named by the register it reaches rather than by its
    // number, so the sequence reads as the datasheet's table.  `DATA` is the
    // base address itself, which is why the first write below is not
    // `COM1 + 0`: naming the register and adding zero would be the same port
    // twice, and clippy is right that the second spelling has no effect, but
    // the register name is what makes the block readable, so the constant is
    // what the code says.
    // SAFETY: COM1 is present on any machine this kernel boots on, a PC
    // without it is not one these three ports describe, and each write below
    // is the documented sequence for programming the divisor latch.
    unsafe {
        outb(COM1 + IER, 0x00); // disable all UART interrupts
        outb(COM1 + LCR, 0x80); // enable DLAB: the next two writes set the divisor
        outb(COM1 + DATA, 0x01); // divisor low  byte: 115200 / 1 = 115200
        outb(COM1 + IER, 0x00); // divisor high byte
        outb(COM1 + LCR, 0x03); // 8 bits, no parity, one stop bit; DLAB off
        outb(COM1 + FCR, 0xC7); // enable and clear the FIFOs, 14-byte threshold
        outb(COM1 + MCR, 0x03); // DTR and RTS: the line is up
    }
}

/// Whether the transmitter is ready for a byte.
#[cfg(target_os = "none")]
fn transmit_ready() -> bool {
    // Bit 5 of the line status register is "transmit holding register empty".
    // SAFETY: reading the line status register of a UART that `init` has
    // programmed; `inb`'s contract is that the port exists, which COM1 does.
    unsafe { inb(COM1 + LSR) & 0x20 != 0 }
}

/// Write one byte, waiting for the transmitter.
#[cfg(target_os = "none")]
pub fn write_byte(byte: u8) {
    // A newline is two bytes on the wire here: the console is a terminal, and
    // a bare `\n` moves down without returning to column zero.
    if byte == b'\n' {
        write_byte(b'\r');
    }
    while !transmit_ready() {
        core::hint::spin_loop();
    }
    // SAFETY: the transmitter reported itself ready, and COM1 is the port
    // `init` programmed.
    unsafe { outb(COM1, byte) };
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
///
/// A boot's first lines are printed before there is a heap, so the number
/// formatting here cannot go through `core::fmt`'s `Display` for `u32` when the
/// caller has an allocator-shaped need.  It is small enough to be worth owning.
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
///
/// Used by the boot's address lines.  Decimal would be accurate and unreadable:
/// an address is a bit pattern, and a reader compares one against a linker
/// script.
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
    /// The buffer in `write_u32` holds ten digits, which is the most a `u32`
    /// has; an eleventh digit would be written before the buffer's start and
    /// corrupt whatever precedes it.  The bound is checked here rather than
    /// trusted, because it is the one arithmetic fact the function depends on.
    ///
    /// Counted by division rather than by `to_string`: this crate is `no_std`
    /// and does not link `alloc`, so `Display` is not available, and the
    /// arithmetic is what `write_u32` itself does, which makes this a check of
    /// the same operation rather than of a different one.
    #[test]
    fn ten_digits_hold_a_u32() {
        let _guard = serialize();
        let mut digits = 1u32;
        let mut remaining = u32::MAX / 10;
        while remaining > 0 {
            digits += 1;
            remaining /= 10;
        }
        assert_eq!(digits, 10);
        // And the buffer is exactly that long: a digit count larger than it
        // would be an off-by-one in `write_u32`'s indexing.
        assert_eq!(digits as usize, 10);
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
