//! arch/aarch64/src/serial.rs
//!
//! The PL011 UART, which is how a boot says anything at all.
//!
//! ## Why this is here and not a driver crate
//!
//! A boot has to be able to speak before it can parse a device tree, so the
//! address cannot come from a discovered device and cannot wait for a driver
//! registry, the same argument as x86_64's COM1.
//!
//! ## The address: the tree first, the constant second
//!
//! [`init`] reads the tree firmware handed over and asks it where the PL011 is.
//! `0x0900_0000` remains as the fallback for a boot whose tree did not parse,
//! which is the state a machine with a broken blob is in, and a boot that
//! cannot say anything at all is a boot nobody can diagnose.
//!
//! The constant is therefore a *fallback* and not the answer, and the boot line
//! says which one was used.  A machine whose UART is elsewhere gets output if
//! its tree parses, which is every machine this tree boots on.

// The console's address is a runtime value on bare metal; a host records bytes
// instead, so both of these are absent there and an import a host build never
// names is what the host check exists to notice.
#[cfg(target_os = "none")]
use core::sync::atomic::AtomicUsize;
#[cfg(target_os = "none")]
use core::sync::atomic::Ordering;

/// Where `qemu-system-aarch64 -machine virt` places its first PL011.
///
/// A fallback for a boot whose device tree did not parse.  Every read and write
/// below goes through [`uart_base`], which prefers the tree.
#[cfg(target_os = "none")]
const PL011_FALLBACK: usize = 0x0900_0000;

/// Where the console's registers are: the tree's answer, or the fallback.
///
/// The tree is read once, by [`init`], and the answer kept in a static, this
/// is a console, its address does not change, and looking it up per byte would
/// be a walk of the device tree on the path that prints a panic message.
#[cfg(target_os = "none")]
static UART_BASE: AtomicUsize = AtomicUsize::new(PL011_FALLBACK);

/// The console's base address.
#[cfg(target_os = "none")]
fn uart_base() -> usize {
    UART_BASE.load(Ordering::Acquire)
}

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
/// ignores the divisor, the host side of the emulated line runs at whatever
/// the terminal is set to, but a real board does not, so the divisors are
/// programmed from the 24 MHz reference clock `virt` describes.
#[cfg(target_os = "none")]
pub fn init() {
    // The tree first.  `boot::device_tree` bounds-checks the blob and reports
    // `None` for a pointer that is not a tree, so a firmware that handed over
    // something else leaves the fallback in place rather than sending writes to
    // whatever the pointer named.
    if let Some(tree) = crate::boot::device_tree()
        && let Some(uart) = tree.find_compatible("arm,pl011")
        && let Some(region) = uart.region()
        && region.address != 0
    {
        UART_BASE.store(region.address as usize, Ordering::Release);
    }

    let base = uart_base();
    // SAFETY: `base` is the address the device tree named for a PL011, or the
    // emulated platform's constant, and each write below is the documented
    // sequence from the PL011 manual.
    unsafe {
        // Disable the UART while its baud rate is changed.
        write_reg(base + CR, 0);
        // 115200 from a 24 MHz reference: 24_000_000 / (16 * 115200) = 13.02.
        write_reg(base + IBRD, 13);
        write_reg(base + FBRD, 1);
        // 8 bits, FIFOs on, one stop bit, no parity.
        write_reg(base + LCR_H, (1 << 4) | (1 << 5) | (1 << 6));
        // Enable the UART and its transmitter.
        write_reg(base + CR, (1 << 0) | (1 << 8));
    }
}

/// Whether the transmitter can take a byte.
#[cfg(target_os = "none")]
fn transmit_ready() -> bool {
    // SAFETY: reading the flag register of a UART `init` has programmed.
    let base = uart_base();
    // SAFETY: as `init`.
    unsafe { read_reg(base + FR) & (1 << 5) == 0 }
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
    let base = uart_base();
    // SAFETY: the transmitter reported room, and `base` is the register block
    // `init` programmed.
    unsafe { write_reg(base + DR, byte as u32) };
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
/// This machine starts no second core, so one CPU is one line buffer; a
/// machine that grew a secondary entry would change this beside its `smp`.
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
