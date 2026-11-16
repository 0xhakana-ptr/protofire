//! kernel/src/usb_mouse.rs
//!
//! The boot-protocol mouse's core: a bounded stream of relative-motion
//! reports that a program reads, and that a USB HID mouse injects into.
//!
//! ## What moved, and what it lost on the way
//!
//! This is the previous tree's mouse.rs, 236 lines, relocated with the USB
//! files it feeds.  What did not move is the wait framework its blocking
//! read went through -- `process::wait`'s condition variables, which this
//! tree has not grown yet -- so the core keeps its bounded queue and its
//! non-blocking read, and a caller that wants to block waits the way every
//! polling driver here waits: by asking again.

use alloc::collections::VecDeque;
use alloc::sync::Arc;
use spin::Mutex;

pub const MOUSE_REPORT_LEN: usize = 4;

/// Maximum number of buffered motion reports before the oldest is dropped.
const MAX_BUFFERED_MOTIONS: usize = 16;

/// A boot-protocol mouse motion report: buttons, X/Y deltas, wheel.
///
/// Deltas are relative and signed; `0` means "no movement".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct MouseMotion {
    /// Button bitfield (bit 0 = left, bit 1 = right, bit 2 = middle).
    pub buttons: u8,
    /// Horizontal delta (positive = right).
    pub dx: i8,
    /// Vertical delta (positive = down in screen coordinates).
    pub dy: i8,
    /// Wheel delta (positive = scroll up).
    pub wheel: i8,
}

impl MouseMotion {
    pub const fn new(buttons: u8, dx: i8, dy: i8, wheel: i8) -> Self {
        Self {
            buttons,
            dx,
            dy,
            wheel,
        }
    }

    /// Serialise as the boot-protocol byte stream (buttons, dx, dy, wheel).
    pub const fn to_bytes(self) -> [u8; MOUSE_REPORT_LEN] {
        [self.buttons, self.dx as u8, self.dy as u8, self.wheel as u8]
    }
}

// Mouse core

/// The canonical mouse input source: a bounded motion-report queue.
pub struct MouseCore {
    motions: Mutex<VecDeque<MouseMotion>>,
}

impl Default for MouseCore {
    fn default() -> Self {
        Self::new()
    }
}

impl MouseCore {
    pub fn new() -> Self {
        Self {
            motions: Mutex::new(VecDeque::new()),
        }
    }

    /// Drop any buffered motion so host tests start from a known-empty state.
    pub fn clear(&self) {
        self.motions.lock().clear();
    }

    /// Number of buffered motion reports.
    pub fn pending_count(&self) -> usize {
        self.motions.lock().len()
    }

    /// Buffer one relative-motion report (bounded, dropping the oldest).
    pub fn inject_motion(&self, buttons: u8, dx: i8, dy: i8, wheel: i8) {
        {
            let mut motions = self.motions.lock();
            if motions.len() >= MAX_BUFFERED_MOTIONS {
                motions.pop_front();
            }
            motions.push_back(MouseMotion::new(buttons, dx, dy, wheel));
        }
    }

    /// Read one buffered motion report without blocking.
    pub fn try_read_motion(&self) -> Option<MouseMotion> {
        self.motions.lock().pop_front()
    }
}

// Global mouse core

static MOUSE_CORE: Mutex<Option<Arc<MouseCore>>> = Mutex::new(None);

/// Return the global mouse core, creating it on first use.
pub fn init_global() -> Arc<MouseCore> {
    let mut slot = MOUSE_CORE.lock();
    if let Some(ref core) = *slot {
        return core.clone();
    }
    let core = Arc::new(MouseCore::new());
    *slot = Some(core.clone());
    core
}

/// Clear the global mouse core (host tests).
pub fn clear_global() {
    init_global().clear();
}

/// Inject a relative-motion report into the global mouse core.
pub fn inject_motion(buttons: u8, dx: i8, dy: i8, wheel: i8) {
    init_global().inject_motion(buttons, dx, dy, wheel);
}

/// Read one buffered motion report without blocking.
pub fn try_read_motion() -> Option<MouseMotion> {
    init_global().try_read_motion()
}

// Tests

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn motion_round_trips_through_bytes() {
        let motion = MouseMotion::new(0x01, -3, 7, 1);
        assert_eq!(motion.to_bytes(), [0x01, 0xFD, 0x07, 0x01]);
        assert_eq!(
            MouseMotion::new(0x00, 0, 0, 0).to_bytes(),
            [0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn inject_then_read_returns_fifo() {
        let core = MouseCore::new();
        core.inject_motion(0x01, 1, 0, 0);
        core.inject_motion(0x00, -1, 2, 0);
        assert_eq!(
            core.try_read_motion(),
            Some(MouseMotion::new(0x01, 1, 0, 0))
        );
        assert_eq!(
            core.try_read_motion(),
            Some(MouseMotion::new(0x00, -1, 2, 0))
        );
        assert_eq!(core.try_read_motion(), None);
    }

    #[test]
    fn read_drops_oldest_when_full() {
        let core = MouseCore::new();
        for i in 0..(MAX_BUFFERED_MOTIONS + 4) {
            core.inject_motion(0, i as i8, 0, 0);
        }
        // The oldest four reports were dropped, so the first remaining is 4.
        assert_eq!(core.try_read_motion(), Some(MouseMotion::new(0, 4, 0, 0)));
        assert_eq!(core.pending_count(), MAX_BUFFERED_MOTIONS - 1);
    }

    #[test]
    fn clear_resets_pending() {
        let core = MouseCore::new();
        core.inject_motion(0x02, 5, 5, 0);
        core.clear();
        assert_eq!(core.pending_count(), 0);
        assert_eq!(core.try_read_motion(), None);
    }
}
