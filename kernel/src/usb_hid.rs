//! kernel/src/usb_hid.rs
//!
//! The USB HID reports, and the devices they come from.
//!
//! This is the previous tree's usb_hid.rs, 642 lines, relocated with the
//! controller that delivers the reports; what it injects into is this tree's
//! own keyboard queue, which is what `ReadConsole` drains.
//!
//! USB Human Interface Device (keyboard/mouse) driver.
//! USB HID (Human Interface Device) driver -- boot protocol keyboard/mouse.
//!
//! Parses USB HID boot protocol keyboard reports (mapping HID keycodes to
//! PS/2 Set 1 scancodes for the keyboard core) and mouse reports (injecting
//! relative motion into the mouse core).  Also owns the real HID device
//! discovery: walking a configuration descriptor for the HID interface's
//! interrupt IN endpoint and classifying the device as keyboard or mouse --
//! the xHCI probe calls [`classify_hid_device`] instead of hard-coding an
//! endpoint.
//!
//! ## Activation
//!
//! Depends on the xHCI controller driver for USB transport.  Both require
//! high-MMIO page mapping for PCI BAR access.

// USB HID class codes

pub const USB_CLASS_HID: u8 = 0x03;
pub const USB_SUBCLASS_BOOT: u8 = 0x01;
pub const USB_PROTOCOL_KEYBOARD: u8 = 0x01;
pub const USB_PROTOCOL_MOUSE: u8 = 0x02;

// Boot protocol keyboard report (8 bytes)

/// USB HID Boot Protocol Keyboard Input Report.
///
/// Byte 0: Modifier keys (bitfield).
/// Byte 1: Reserved (0).
/// Bytes 2–7: Key codes (up to 6 simultaneous keys, 0 = no event).
#[derive(Debug, Clone, Copy)]
#[repr(C)]
pub struct UsbKeyboardReport {
    pub modifiers: u8,
    _reserved: u8,
    pub keycodes: [u8; 6],
}

// Modifier bits.
pub const MOD_LEFT_CTRL: u8 = 1 << 0;
pub const MOD_LEFT_SHIFT: u8 = 1 << 1;
pub const MOD_LEFT_ALT: u8 = 1 << 2;
pub const MOD_LEFT_GUI: u8 = 1 << 3;
pub const MOD_RIGHT_CTRL: u8 = 1 << 4;
pub const MOD_RIGHT_SHIFT: u8 = 1 << 5;
pub const MOD_RIGHT_ALT: u8 = 1 << 6;
pub const MOD_RIGHT_GUI: u8 = 1 << 7;

// USB HID to PS/2 scancode mapping (subset -- common keys)

/// Map a USB HID keycode to a PS/2 Set 1 scancode (for integration with
/// the existing keyboard driver).
///
/// Returns 0 if the keycode is not in the mapping table.
pub fn usb_hid_to_scancode_set1(hid_code: u8) -> u8 {
    match hid_code {
        0x04 => 0x1E, // A
        0x05 => 0x30, // B
        0x06 => 0x2E, // C
        0x07 => 0x20, // D
        0x08 => 0x12, // E
        0x09 => 0x21, // F
        0x0A => 0x22, // G
        0x0B => 0x23, // H
        0x0C => 0x17, // I
        0x0D => 0x24, // J
        0x0E => 0x25, // K
        0x0F => 0x26, // L
        0x10 => 0x32, // M
        0x11 => 0x31, // N
        0x12 => 0x18, // O
        0x13 => 0x19, // P
        0x14 => 0x10, // Q
        0x15 => 0x13, // R
        0x16 => 0x1F, // S
        0x17 => 0x14, // T
        0x18 => 0x16, // U
        0x19 => 0x2F, // V
        0x1A => 0x11, // W
        0x1B => 0x2D, // X
        0x1C => 0x15, // Y
        0x1D => 0x2C, // Z
        0x1E => 0x02, // 1
        0x1F => 0x03, // 2
        0x20 => 0x04, // 3
        0x21 => 0x05, // 4
        0x22 => 0x06, // 5
        0x23 => 0x07, // 6
        0x24 => 0x08, // 7
        0x25 => 0x09, // 8
        0x26 => 0x0A, // 9
        0x27 => 0x0B, // 0
        0x28 => 0x1C, // Enter
        0x29 => 0x01, // Escape
        0x2A => 0x0E, // Backspace
        0x2B => 0x0F, // Tab
        0x2C => 0x39, // Space
        0x2D => 0x0C, // Minus
        0x2E => 0x0D, // Equals
        0x2F => 0x1A, // Left Bracket
        0x30 => 0x1B, // Right Bracket
        0x31 => 0x2B, // Backslash
        0x33 => 0x27, // Semicolon
        0x34 => 0x28, // Apostrophe
        0x35 => 0x29, // Grave
        0x36 => 0x33, // Comma
        0x37 => 0x34, // Period
        0x38 => 0x35, // Slash
        0x39 => 0x3A, // Caps Lock
        0x3A => 0x3B, // F1
        0x3B => 0x3C, // F2
        0x3C => 0x3D, // F3
        0x3D => 0x3E, // F4
        0x3E => 0x3F, // F5
        0x3F => 0x40, // F6
        0x40 => 0x41, // F7
        0x41 => 0x42, // F8
        0x42 => 0x43, // F9
        0x43 => 0x44, // F10
        0x44 => 0x57, // F11
        0x45 => 0x58, // F12
        0x4F => 0x4B, // Right Arrow → PS/2 Left Arrow equivalent area
        0x50 => 0x4D, // Left Arrow  → PS/2 Right Arrow equivalent area
        0x51 => 0x50, // Down Arrow
        0x52 => 0x48, // Up Arrow
        0xE0 => 0x1D, // Left Control
        0xE1 => 0x2A, // Left Shift
        0xE2 => 0x38, // Left Alt
        0xE3 => 0x5B, // Left GUI
        0xE4 => 0x1D, // Right Control
        0xE5 => 0x36, // Right Shift
        0xE6 => 0x38, // Right Alt
        _ => 0,
    }
}

// Keyboard report processing

use core::sync::atomic::AtomicU8;
use core::sync::atomic::Ordering;

/// Previous keyboard report state for detecting key releases.
static PREV_MODIFIERS: AtomicU8 = AtomicU8::new(0);
static PREV_KEYCODES: [AtomicU8; 6] = [
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
    AtomicU8::new(0),
];

/// Process a USB HID Boot Protocol keyboard input report (8 bytes).
///
/// Extracts pressed keycodes, maps them to PS/2 Set 1 scancodes, and
/// injects them into the keyboard subsystem via `inject_scancode`.
/// Tracks previous report state to generate break codes for released keys.
pub fn handle_keyboard_report(report: &[u8; 8]) {
    use crate::xhci::KeyboardQueue;

    // A report arriving is the event the interrupt-IN endpoint exists for, and
    // the line is what turns "the endpoint was configured" into "the endpoint
    // delivered": a boot whose keyboard is attached and never prints this has
    // a device it cannot hear.  Every report prints, because the keys are the
    // payload a reader wants to see.
    crate::usb_log!(
        "[hid  ] keyboard report: modifiers={:#04x} keys=[{:02x},{:02x},{:02x},{:02x},{:02x},{:02x}]",
        report[0],
        report[2],
        report[3],
        report[4],
        report[5],
        report[6],
        report[7]
    );

    let modifiers = report[0];
    let prev_mods = PREV_MODIFIERS.swap(modifiers, Ordering::Relaxed);
    let keycodes = &report[2..8]; // bytes 2–7 are up to 6 simultaneous keycodes

    // Release modifier keys that were pressed but are no longer held.
    let released_mods = prev_mods & !modifiers;
    inject_modifier_break(released_mods);

    // Press modifier keys that are now held but weren't before.
    let pressed_mods = modifiers & !prev_mods;
    inject_modifier_make(pressed_mods);

    // Process regular keycodes.
    for i in 0..6 {
        let hid_code = keycodes[i];
        let prev_code = PREV_KEYCODES[i].swap(hid_code, Ordering::Relaxed);

        if prev_code != 0 && prev_code != hid_code {
            // Previous key at this slot was released.
            let sc = usb_hid_to_scancode_set1(prev_code);
            if sc != 0 {
                KeyboardQueue::inject(sc | 0x80); // break code
            }
        }
        if hid_code != 0 {
            let scancode = usb_hid_to_scancode_set1(hid_code);
            if scancode != 0 {
                KeyboardQueue::inject(scancode); // make code
            }
        }
    }
}

fn inject_modifier_make(modifiers: u8) {
    use crate::xhci::KeyboardQueue;
    // Left modifiers: single-byte PS/2 make codes.
    if modifiers & MOD_LEFT_CTRL != 0 {
        KeyboardQueue::inject(0x1D);
    }
    if modifiers & MOD_LEFT_SHIFT != 0 {
        KeyboardQueue::inject(0x2A);
    }
    if modifiers & MOD_LEFT_ALT != 0 {
        KeyboardQueue::inject(0x38);
    }
    // Right modifiers: Right Ctrl/Alt/GUI use E0-prefixed make codes.
    if modifiers & MOD_RIGHT_CTRL != 0 {
        KeyboardQueue::inject(0xE0);
        KeyboardQueue::inject(0x1D);
    }
    if modifiers & MOD_RIGHT_SHIFT != 0 {
        KeyboardQueue::inject(0x36);
    }
    if modifiers & MOD_RIGHT_ALT != 0 {
        KeyboardQueue::inject(0xE0);
        KeyboardQueue::inject(0x38);
    }
    if modifiers & MOD_LEFT_GUI != 0 {
        KeyboardQueue::inject(0xE0);
        KeyboardQueue::inject(0x5B);
    }
    if modifiers & MOD_RIGHT_GUI != 0 {
        KeyboardQueue::inject(0xE0);
        KeyboardQueue::inject(0x5C);
    }
}

fn inject_modifier_break(modifiers: u8) {
    use crate::xhci::KeyboardQueue;
    // Left modifiers: single-byte PS/2 break codes.
    if modifiers & MOD_LEFT_CTRL != 0 {
        KeyboardQueue::inject(0x9D);
    }
    if modifiers & MOD_LEFT_SHIFT != 0 {
        KeyboardQueue::inject(0xAA);
    }
    if modifiers & MOD_LEFT_ALT != 0 {
        KeyboardQueue::inject(0xB8);
    }
    // Right modifiers: break codes with or without E0 prefix.
    if modifiers & MOD_RIGHT_CTRL != 0 {
        KeyboardQueue::inject(0xE0);
        KeyboardQueue::inject(0x9D);
    }
    if modifiers & MOD_RIGHT_SHIFT != 0 {
        KeyboardQueue::inject(0xB6);
    }
    if modifiers & MOD_RIGHT_ALT != 0 {
        KeyboardQueue::inject(0xE0);
        KeyboardQueue::inject(0xB8);
    }
    if modifiers & MOD_LEFT_GUI != 0 {
        KeyboardQueue::inject(0xE0);
        KeyboardQueue::inject(0xDB);
    }
    if modifiers & MOD_RIGHT_GUI != 0 {
        KeyboardQueue::inject(0xE0);
        KeyboardQueue::inject(0xDC);
    }
}

// Boot protocol mouse report processing

/// Process a USB HID Boot Protocol mouse input report (up to 4 bytes) into
/// an explicit mouse core.
///
/// Byte 0: buttons (bitfield).  Bytes 1–2: signed X/Y deltas.  Byte 3 (when
/// present): wheel.  Relative motion is injected into `core`.
pub fn handle_mouse_report_into(core: &crate::usb_mouse::MouseCore, report: &[u8]) {
    if report.len() < 3 {
        return;
    }
    let buttons = report[0];
    let dx = report[1] as i8;
    let dy = report[2] as i8;
    let wheel = if report.len() > 3 { report[3] as i8 } else { 0 };
    core.inject_motion(buttons, dx, dy, wheel);
}

/// Process a USB HID Boot Protocol mouse input report, injecting relative
/// motion into the global mouse core, which the `/system/dev/mouse` device
/// node drains.
pub fn handle_mouse_report(report: &[u8]) {
    let core = crate::usb_mouse::init_global();
    handle_mouse_report_into(&core, report);
}

// Real HID device discovery (configuration descriptor walking)

/// Classification of a discovered HID device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HidDeviceKind {
    Keyboard,
    Mouse,
}

/// HID device discovered from a configuration descriptor: the boot-protocol
/// kind plus its interrupt IN endpoint, so the xHCI driver can configure the
/// endpoint and arm the right report length.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HidDeviceInfo {
    pub kind: HidDeviceKind,
    pub endpoint_address: u8,
    pub max_packet_size: u16,
    pub interval: u8,
    pub interface_number: u8,
    /// Bytes per input report (endpoint max-packet-size, floored to the
    /// boot-protocol minimum for the device kind).
    pub report_len: usize,
}

impl HidDeviceInfo {
    /// Minimum report size for a boot-protocol device kind.
    const fn min_report_len(kind: HidDeviceKind) -> usize {
        match kind {
            HidDeviceKind::Keyboard => 8,
            HidDeviceKind::Mouse => 4,
        }
    }

    /// The doorbell Device Context Index for this interrupt IN endpoint.
    /// xHCI maps an IN endpoint N to DCI 2*N+1.
    pub const fn dci(&self) -> u32 {
        2u32 * (self.endpoint_address & 0x0F) as u32 + 1
    }
}

/// The parts of a class interface's interrupt IN endpoint that the xHCI
/// driver programs a ring with.
///
/// A HID device and a hub both declare one -- the keyboard sends its reports
/// there, and a hub sends *which of its ports changed* there -- so the walk
/// that finds it is shared, and only what the reports mean differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InterfaceInterruptIn {
    pub interface_number: u8,
    pub interface_protocol: u8,
    pub endpoint_address: u8,
    pub max_packet_size: u16,
    pub interval: u8,
}

/// Walk a USB configuration descriptor for the interrupt IN endpoint of the
/// first interface whose class is `class`.
pub fn interface_interrupt_in(config: &[u8], class: u8) -> Option<InterfaceInterruptIn> {
    let mut i = 0usize;
    while i + 1 < config.len() {
        let dlen = config[i] as usize;
        if dlen < 2 {
            break;
        }
        let dtype = config[i + 1];
        if dtype == 4 && i + 7 < config.len() {
            // INTERFACE descriptor: bInterfaceNumber=2, bNumEndpoints=4,
            // bInterfaceClass=5, bInterfaceSubClass=6, bInterfaceProtocol=7.
            let if_class = config[i + 5];
            if if_class != class {
                i += dlen;
                continue;
            }

            let if_number = config[i + 2];
            let num_eps = config[i + 4];
            let if_proto = config[i + 7];

            // Walk the interface's subordinate descriptors (bLength-sized),
            // skipping HID and other non-endpoint descriptors between them,
            // until all `num_eps` endpoint descriptors have been examined.
            // The endpoint may follow one or more HID descriptors, so the
            // iteration count is endpoints found, not descriptors stepped.
            let mut pos = i + dlen;
            let mut eps_found = 0;
            while eps_found < num_eps as usize && pos + 5 < config.len() {
                let sub_dlen = config[pos] as usize;
                if sub_dlen < 2 {
                    break;
                }
                if config[pos + 1] == 5 {
                    // ENDPOINT descriptor: bEndpointAddress=2, bmAttributes=3,
                    // wMaxPacketSize=4-5, bInterval=6.
                    let ea = config[pos + 2];
                    let attr = config[pos + 3];
                    let mps = u16::from_le_bytes([config[pos + 4], config[pos + 5]]);
                    let interval = if pos + 6 < config.len() {
                        config[pos + 6]
                    } else {
                        0
                    };
                    eps_found += 1;
                    if (attr & 3) == 3 && (ea & 0x80) != 0 {
                        return Some(InterfaceInterruptIn {
                            interface_number: if_number,
                            interface_protocol: if_proto,
                            endpoint_address: ea,
                            max_packet_size: mps,
                            interval,
                        });
                    }
                }
                pos += sub_dlen;
            }
        }
        i += dlen;
    }
    None
}

/// Walk a USB configuration descriptor and classify the HID interface,
/// returning its interrupt IN endpoint.
///
/// `fallback_proto` is the device-descriptor `bDeviceProtocol`, used only when
/// the interface reports protocol 0 (boot-class devices on some emulators
/// leave the interface protocol unset).
///
/// Returns `None` when the configuration has no HID interface with an
/// interrupt IN endpoint.
pub fn classify_hid_device(config: &[u8], fallback_proto: u8) -> Option<HidDeviceInfo> {
    let interface = interface_interrupt_in(config, USB_CLASS_HID)?;
    let kind = match interface.interface_protocol {
        USB_PROTOCOL_MOUSE => HidDeviceKind::Mouse,
        USB_PROTOCOL_KEYBOARD => HidDeviceKind::Keyboard,
        // Protocol 0: fall back to the device-level boot protocol.
        _ => match fallback_proto {
            USB_PROTOCOL_MOUSE => HidDeviceKind::Mouse,
            _ => HidDeviceKind::Keyboard,
        },
    };
    let report_len = interface
        .max_packet_size
        .max(HidDeviceInfo::min_report_len(kind) as u16) as usize;
    Some(HidDeviceInfo {
        kind,
        endpoint_address: interface.endpoint_address,
        max_packet_size: interface.max_packet_size,
        interval: interface.interval,
        interface_number: interface.interface_number,
        report_len,
    })
}
