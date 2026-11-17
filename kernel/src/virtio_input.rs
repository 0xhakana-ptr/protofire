//! kernel/src/virtio_input.rs
//!
//! The VirtIO keyboard, when the machine has one: the device found on the
//! bus, its event queue's buffers posted, and the events its tick drains
//! turned into what the console's queue holds.
//!
//! ## Why this driver is here and the queue is not
//!
//! `virtio_input` holds the device: the queue's shape, the event's wire
//! shape, and the buffers a driver keeps posted.  What it does not hold is
//! what an event *means* -- a Linux key code is a number, and the console's
//! queue wants scancodes -- and a meaning is this boot's decision, which is
//! why this file is the one that calls the translation and hands the queue
//! its bytes.  The same split `xhci.rs` makes against `xhci`.
//!
//! ## Why there are two keyboards
//!
//! The machine's other keyboard is the USB one, and the monitor's `sendkey`
//! is what both of them hear: QEMU's input layer is a broadcast, so one
//! typed key arrives twice -- once as an HID report the controller posts,
//! once as an evdev event this device fills -- and the gate asserts both,
//! because two paths that read the same key and answer the same numbers are
//! the evidence that each one works on its own.

use alloc::sync::Arc;

use virtio_input::VirtioInput;

/// The device this boot brought up, and the state its tick drains.
static DEVICE: spin::Mutex<Option<Arc<VirtioInput>>> = spin::Mutex::new(None);

/// The names the boot's lines spell, so the gate and the driver cannot drift.
pub const EVENT_PREFIX: &str = "[vioin] device event: ";

/// Bring the device up, and report it.
///
/// `false` on a machine with no device, which is the ordinary state on two of
/// the three machines and the honest one on this one if the bus scan found
/// nothing.
pub fn bring_up() -> bool {
    if DEVICE.lock().is_some() {
        return true;
    }
    let Some(found) = crate::devices::find_virtio_input() else {
        return false;
    };
    let transport: Arc<dyn virtio_core::Transport> = found.transport.clone();
    let device = match VirtioInput::new(transport) {
        Ok(device) => device,
        Err(error) => {
            arch::serial::write_str("protofire: virtio-input refused, ");
            arch::serial::write_str(match error {
                virtio_core::transport::TransportError::Unsupported => "not the modern interface",
                _ => "the transport refused",
            });
            arch::serial::write_str("\n");
            return false;
        }
    };
    *DEVICE.lock() = Some(device);
    arch::serial::write_str("protofire: virtio-input up, event queue posted\n");
    true
}

/// Drain the device's events, and put the keys in the console's queue.
///
/// Called from the tick, beside the USB controller's own drain: a key that
/// arrives between ticks waits for the tick that drains it, and a keyboard
/// nobody is reading holds its events rather than inventing some.
///
/// The translation is the keyboard report's own: the evdev code is the
/// Linux key code, `usb_hid`'s table maps it to a PS/2 Set 1 scancode, and
/// the queue takes scancodes.  The line is what turns "the queue was
/// posted" into "the device delivered", and it is the evidence the gate
/// asserts.
pub fn poll() {
    let Some(device) = DEVICE.lock().clone() else {
        return;
    };
    device.drain(|event| {
        // Key events go to the console's queue, through the keyboard report's
        // own table.  The codes past 255 are the pointer's buttons, which are
        // key *kinds* but not keys a console types -- and the table is an
        // eight-bit table, so a driver that cast a button's code down would
        // inject the scancode of whichever low byte it landed on.  They are
        // printed and nothing more.
        if event.kind == virtio_input::event_kind::KEY && event.code <= 0xFF {
            let scancode = crate::usb_hid::usb_hid_to_scancode_set1(event.code as u8);
            if scancode != 0 {
                crate::xhci::KeyboardQueue::inject(scancode);
            }
        }
        arch::serial::write_str(EVENT_PREFIX);
        arch::serial::write_str("kind=");
        arch::serial::write_u32(u32::from(event.kind));
        arch::serial::write_str(", code=");
        arch::serial::write_u32(u32::from(event.code));
        arch::serial::write_str(", value=");
        arch::serial::write_u32(event.value as u32);
        arch::serial::write_str("\n");
    });
}
