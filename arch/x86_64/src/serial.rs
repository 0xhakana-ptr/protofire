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
/// Write a string to the console.
///
/// ## Why a line is buffered rather than locked
///
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
    // One buffer, because this machine reports one CPU: the slot is zero and
    // the array holds it.  A machine that started a second CPU would index by
    // its slot instead, which is what the riscv64 arm does.
    let slot = 0;
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
/// This machine starts no second processor, so one CPU is one line buffer; a
/// machine that read a MADT would change this beside its AP start.
const LINE_SLOTS: usize = 1;

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
///
/// A boot's first lines are printed before there is a heap, so the number
/// formatting here cannot go through `core::fmt`'s `Display` for `u32` when the
/// caller has an allocator-shaped need.  It is small enough to be worth owning.
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
///
/// Used by the boot's address lines.  Decimal would be accurate and unreadable:
/// an address is a bit pattern, and a reader compares one against a linker
/// script.
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
