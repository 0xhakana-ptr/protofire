//! arch/aarch64/src/gicv2m/tests.rs
//!
//! The GICv2m frame: the two identities MSI_TYPER reports, and the doorbell an
//! MSI writes.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

use crate::gicv2m::Frame;
use crate::gicv2m::MSI_SET_SPI;

const BASE: usize = 0x0802_0000;

/// `MSI_TYPER` holds two ten-bit fields, and a driver that read it as one
/// number would treat `count << 16 | first` as an interrupt number.
///
/// QEMU's `virt` reports `count = 64` and `first = 64` for its frame, which
/// is `0x0040_0040`.
#[test]
fn the_typer_is_two_fields() {
    let frame = Frame::from_typer(BASE, 0x0040_0040);
    assert_eq!(frame.first_interrupt(), 64);
    assert_eq!(frame.count(), 64);
    // As one number the register would be 4194368, which is not an
    // interrupt any controller has.
    assert_ne!(frame.first_interrupt(), 0x0040_0040);
}

/// A slot's address is its `MSI_SET_SPI` register, and the address is what
/// selects the interrupt.
#[test]
fn a_slot_is_addressed_by_its_offset() {
    let frame = Frame::from_typer(BASE, 0x0040_0040);
    assert_eq!(frame.address(0), Some((BASE + MSI_SET_SPI) as u64));
    assert_eq!(frame.address(1), Some((BASE + MSI_SET_SPI + 4) as u64));
    assert_eq!(frame.address(63), Some((BASE + MSI_SET_SPI + 252) as u64));
    // The last slot of the frame.
    assert_eq!(frame.interrupt(63), Some(127));
}

/// A slot past the count is refused, and both the address and the interrupt
/// number are `None`.
///
/// A caller that took the number anyway would enable a line nothing can
/// produce, and then wait for it.
#[test]
fn a_slot_past_the_count_is_refused() {
    let frame = Frame::from_typer(BASE, 0x0040_0040);
    assert_eq!(frame.interrupt(64), None);
    assert_eq!(frame.address(64), None);
    assert!(!frame.holds(64));
    assert!(frame.holds(63));
}

/// Every slot's interrupt is distinct and inside the frame's run.
///
/// Two slots naming one interrupt is a device whose second queue's
/// completion wakes the first queue's handler, which is the kind of defect
/// that appears as an occasional hang.
#[test]
fn every_slot_names_a_distinct_interrupt() {
    let frame = Frame::from_typer(BASE, 0x0040_0040);
    let mut seen = [false; 64];
    for slot in 0..frame.count() {
        let interrupt = frame.interrupt(slot).expect("inside the frame");
        assert!(
            (64..128).contains(&interrupt),
            "slot {slot} names {interrupt}, outside the run"
        );
        let index = (interrupt - 64) as usize;
        assert!(!seen[index], "interrupt {interrupt} named twice");
        seen[index] = true;
    }
    assert!(seen.iter().all(|used| *used), "every interrupt was named");
}

/// The payload is the slot, which is what a log shows and what a device
/// writes — but the frame acts on the address, so a wrong payload still
/// raises the right interrupt.
#[test]
fn the_payload_does_not_select_the_interrupt() {
    let frame = Frame::from_typer(BASE, 0x0040_0040);
    assert_eq!(frame.data(0), 0);
    assert_eq!(frame.data(5), 5);
    // Two slots, two addresses, two interrupts — whatever the payload.
    assert_ne!(frame.address(0), frame.address(1));
    assert_ne!(frame.interrupt(0), frame.interrupt(1));
}

/// A frame with a count of zero raises nothing, which is a frame the
/// platform described but did not populate.
#[test]
fn a_frame_with_no_interrupts_raises_nothing() {
    let frame = Frame::from_typer(BASE, 0);
    assert_eq!(frame.count(), 0);
    assert_eq!(frame.interrupt(0), None);
}
