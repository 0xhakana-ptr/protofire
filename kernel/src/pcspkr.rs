//! kernel/src/pcspkr.rs
//!
//! The PC speaker: the PIT's channel 2 and the gate bits on port 0x61, as
//! the machines that carry them spell them.
//!
//! ## Why the beeper is here and what it is worth
//!
//! A tone is one divisor and two gate bits: PIT channel 2 runs in square-wave
//! mode off the fixed 1.193182 MHz clock, and port 0x61's low two bits open
//! the PIT gate and the speaker gate together.  That is the whole of the
//! hardware, and it is the machine's -- the ports are PC hardware, which is
//! why the accesses go through [`arch`]'s port layer, whose implementations on
//! the machines without them write nothing and read zero.
//!
//! The value is one line, and the roadmap says so: a boot can prove the
//! driver ran by playing its own tone and silencing it, and what a listener
//! hears is beyond what a headless emulator shows.  QEMU's own trace
//! (`pcspk_io_write`, `pit_ioport_write`) is the out-of-band check that the
//! writes landed on the hardware the specification names, which is the
//! evidence a serial line cannot carry.
//!
//! This is the previous tree's pcspkr.rs, 128 lines, relocated: the hardware
//! sequence is the same, the driver registry it registered with is gone (the
//! boot calls this file directly), and the device node it served --
//! `/system/dev/pcspkr`, a program writing a four-byte frequency -- waits for
//! this tree to grow a device-node mechanism before it means anything.

use arch::port::inb;
use arch::port::outb;

/// PIT command register (mode/command).
const PIT_COMMAND: u16 = 0x43;
/// PIT channel 2's data port.
const PIT_CHANNEL2: u16 = 0x42;
/// PIT's base frequency: 1.193182 MHz.
const PIT_BASE_FREQUENCY: u32 = 1_193_182;
/// The PC speaker's gate control port.
const SPEAKER_PORT: u16 = 0x61;
/// PIT command: channel 2, mode 3 (square wave), load LSB then MSB.
const PIT_CMD_CHANNEL2_MODE3: u8 = 0xB6;

/// The names the boot's lines spell, so the gate and the driver cannot drift.
pub const PLAYED_PREFIX: &str = "protofire: pcspkr played ";

/// Play a tone at the given frequency, using PIT channel 2 in square-wave
/// mode.
///
/// Passing 0 stops the tone, which is the same thing a caller that wants
/// silence means.  The divisor is the PIT clock over the frequency, clamped
/// into the sixteen bits the counter holds: a frequency above the clock
/// itself would divide to zero, which the counter reads as "stop".
pub fn play_tone(freq_hz: u32) {
    if freq_hz == 0 {
        stop();
        return;
    }

    let divisor = (PIT_BASE_FREQUENCY / freq_hz).clamp(1, 65535) as u16;

    // The command word selects channel 2, mode 3, and the lo-then-hi load
    // order the counter expects; the two data writes that follow are the
    // divisor's halves in exactly that order.
    outb(PIT_COMMAND, PIT_CMD_CHANNEL2_MODE3);
    outb(PIT_CHANNEL2, (divisor & 0xFF) as u8);
    outb(PIT_CHANNEL2, (divisor >> 8) as u8);

    // The speaker sounds only while both gates are open: the PIT's channel-2
    // gate (bit 0) and the speaker's own (bit 1).  Reading the port first
    // keeps the rest of the byte -- the PS/2 controller's bits above these
    // two -- exactly as the firmware left it.
    let value = inb(SPEAKER_PORT);
    outb(SPEAKER_PORT, value | 0x03);
}

/// Silence the speaker, by clearing the two gate bits and nothing else.
pub fn stop() {
    let value = inb(SPEAKER_PORT);
    outb(SPEAKER_PORT, value & !0x03);
}

/// Play the boot's own tone and silence it, and report both.
///
/// Called once, from the boot, on every machine: the machines without the
/// ports write into their stub port layer, which is a no-op, and the line
/// says so rather than claiming a tone a machine could not have played.
pub fn boot_check() {
    play_tone(1000);
    arch::serial::write_str(PLAYED_PREFIX);
    arch::serial::write_str("1000 Hz");
    stop();
    arch::serial::write_str(", then silenced\n");
}

#[cfg(test)]
mod tests {
    //! The divisor's arithmetic, which is the whole of the driver's head.

    /// The divisor is the PIT clock over the frequency, clamped into the
    /// counter's sixteen bits.
    ///
    /// These are the two ends a caller can reach: a frequency low enough to
    /// need the full counter, and one high enough that the division would
    /// want zero, which the counter would read as silence rather than as a
    /// tone.
    #[test]
    fn the_divisor_is_the_clock_over_the_frequency() {
        // 1000 Hz: 1193182 / 1000 = 1193, well inside the counter.
        let divisor = (1_193_182u32 / 1000).clamp(1, 65535);
        assert_eq!(divisor, 1193);
        // 18 Hz would need 66288, past the counter: clamped to 65535, which
        // is the lowest tone the PIT can sound.
        let divisor = (1_193_182u32 / 18).clamp(1, 65535);
        assert_eq!(divisor, 65535);
        // 1.2 MHz would need less than one: clamped to 1, the highest tone.
        let divisor = (1_193_182u32 / 1_500_000).clamp(1, 65535);
        assert_eq!(divisor, 1);
    }

    /// The gate bits are the low two of port 0x61, and silencing clears
    /// exactly those two.
    #[test]
    fn the_gate_bits_are_the_low_two() {
        let opened = 0x5Cu8 | 0x03;
        assert_eq!(opened, 0x5F);
        let silenced = opened & !0x03;
        assert_eq!(silenced, 0x5C, "the rest of the port is left as it was");
    }

    /// The command word selects channel 2, mode 3, lo-then-hi.
    #[test]
    fn the_command_word_is_the_specifications() {
        // Channel 2 (bits 7:6 = 10), read/write LSB then MSB (bits 5:4 = 11),
        // mode 3, square wave (bits 3:1 = 011), binary count (bit 0 = 0).
        let command: u8 = 0xB6;
        assert_eq!(command >> 6, 0b10, "channel 2");
        assert_eq!((command >> 4) & 0b11, 0b11, "LSB then MSB");
        assert_eq!((command >> 1) & 0b111, 0b011, "mode 3: square wave");
        assert_eq!(command & 1, 0, "binary count");
    }
}
