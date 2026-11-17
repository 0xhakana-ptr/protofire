//! drivers/display/virtio_gpu/src/display.rs
//!
//! The display-info answer: what the device says its scanouts are, and which
//! one a boot should use.
//!
//! ## Why the parse is here and the query is not
//!
//! The answer's bytes are the specification's: a 24-byte header and sixteen
//! 24-byte display records, each a rectangle, an `enabled` word and a flags
//! word.  Turning those bytes into "the first enabled display, and its size" is
//! arithmetic over a layout, which is testable on a host; sending the command
//! that asks for them needs a control queue and a device, which is not.
//!
//! ## The number that matters
//!
//! A driver that sized its framebuffer from a guess and then pointed the
//! scanout at it would be showing a device a region the device never asked for.
//! So the mode comes from the device's own answer, and the answer is also what
//! a boot's line prints: the size a reader sees is the size the device
//! reported, not the size the driver requested.

use crate::command::CTRL_HEADER_SIZE;

/// How many displays the answer can carry: `VIRTIO_GPU_MAX_SCANOUTS`.
pub const MAX_SCANOUTS: usize = 16;

/// One display record's size: a rectangle (16), `enabled` (4), `flags` (4).
pub const DISPLAY_ENTRY_SIZE: usize = 24;

/// The whole answer's size: the header and every record.
pub const RESPONSE_DISPLAY_INFO_SIZE: usize = CTRL_HEADER_SIZE + MAX_SCANOUTS * DISPLAY_ENTRY_SIZE;

/// One display, as the device described it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayMode {
    /// The rectangle's width, in pixels.
    pub width: u32,
    /// The rectangle's height, in pixels.
    pub height: u32,
    /// The rectangle's left edge, which a scanout may place off zero.
    pub x: u32,
    /// The rectangle's top edge.
    pub y: u32,
    /// Whether the device says this display is on.
    pub enabled: bool,
}

/// The display-info answer, parsed.
///
/// The modes are kept as an array of `Option`s rather than a `Vec`: the answer
/// has a fixed sixteen entries, this compiles with no allocator, and a display
/// the device left disabled is absent rather than zero-sized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayInfo {
    modes: [Option<DisplayMode>; MAX_SCANOUTS],
    /// How many entries the device enabled.
    enabled: usize,
}

impl DisplayInfo {
    /// Parse an answer the device wrote.
    ///
    /// The header's type is **not** checked here: a caller that got an error
    /// response has no display info to parse, and the number it should report
    /// is the one it read, which is the caller's line to print.  What this
    /// function refuses is a buffer too short to hold the header, because a
    /// record read past the end of a buffer is worse than an empty answer.
    pub fn parse(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < RESPONSE_DISPLAY_INFO_SIZE {
            return None;
        }
        let mut modes = [None; MAX_SCANOUTS];
        let mut enabled = 0usize;
        for (index, mode) in modes.iter_mut().enumerate() {
            let at = CTRL_HEADER_SIZE + index * DISPLAY_ENTRY_SIZE;
            let width = word(bytes, at + 8);
            let height = word(bytes, at + 12);
            let is_enabled = word(bytes, at + 16) != 0;
            if is_enabled && width > 0 && height > 0 {
                *mode = Some(DisplayMode {
                    x: word(bytes, at),
                    y: word(bytes, at + 4),
                    width,
                    height,
                    enabled: true,
                });
                enabled += 1;
            }
        }
        Some(Self { modes, enabled })
    }

    /// How many displays the device says are enabled.
    pub fn enabled_count(&self) -> usize {
        self.enabled
    }

    /// The first enabled display, which is the one a boot uses.
    ///
    /// "First" is the answer's own order, not the largest and not the
    /// preferred: a device that enabled one display and left the rest off has
    /// said which one it is, and a driver that picked another would be
    /// second-guessing it.
    pub fn preferred(&self) -> Option<DisplayMode> {
        self.modes.iter().flatten().copied().next()
    }

    /// The display at `index`, if the device enabled one there.
    pub fn mode(&self, index: usize) -> Option<DisplayMode> {
        self.modes.get(index).copied().flatten()
    }
}

fn word(bytes: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::Command;
    use crate::command::Response;

    /// Build an answer with one enabled display at `index` and the rest off.
    fn answer_with(index: usize, width: u32, height: u32) -> [u8; RESPONSE_DISPLAY_INFO_SIZE] {
        let mut bytes = [0u8; RESPONSE_DISPLAY_INFO_SIZE];
        bytes[0..4].copy_from_slice(&(Response::OkDisplayInfo as u32).to_le_bytes());
        let at = CTRL_HEADER_SIZE + index * DISPLAY_ENTRY_SIZE;
        bytes[at..at + 4].copy_from_slice(&0u32.to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&0u32.to_le_bytes());
        bytes[at + 8..at + 12].copy_from_slice(&width.to_le_bytes());
        bytes[at + 12..at + 16].copy_from_slice(&height.to_le_bytes());
        bytes[at + 16..at + 20].copy_from_slice(&1u32.to_le_bytes());
        bytes
    }

    /// The answer is the header and sixteen records, which is the size the
    /// device writes and the size a buffer must be.
    #[test]
    fn the_answer_is_a_header_and_sixteen_records() {
        assert_eq!(CTRL_HEADER_SIZE, 24);
        assert_eq!(DISPLAY_ENTRY_SIZE, 24);
        assert_eq!(MAX_SCANOUTS, 16);
        assert_eq!(RESPONSE_DISPLAY_INFO_SIZE, 24 + 16 * 24);
        assert_eq!(RESPONSE_DISPLAY_INFO_SIZE, 408);
    }

    /// The first enabled display is the one the device enabled, whatever its
    /// index, and the ones it left off are absent rather than zero-sized.
    #[test]
    fn the_first_enabled_display_is_the_preferred_one() {
        let bytes = answer_with(2, 1024, 768);
        let info = DisplayInfo::parse(&bytes).expect("a full answer");
        assert_eq!(info.enabled_count(), 1);
        let mode = info.preferred().expect("one display is on");
        assert_eq!(mode.width, 1024);
        assert_eq!(mode.height, 768);
        assert!(mode.enabled);
        assert_eq!(info.mode(0), None, "the device left this one off");
        assert_eq!(info.mode(2), Some(mode));
    }

    /// A display with a zero dimension is not a display: the device says it is
    /// enabled but named no area, and a framebuffer of zero pixels is not a
    /// mode a driver can set.
    #[test]
    fn a_zero_sized_display_is_not_a_display() {
        let bytes = answer_with(0, 0, 768);
        let info = DisplayInfo::parse(&bytes).expect("a full answer");
        assert_eq!(info.enabled_count(), 0);
        assert_eq!(info.preferred(), None);
    }

    /// A buffer too short to hold the answer is refused rather than read past.
    #[test]
    fn a_short_answer_is_refused() {
        let bytes = answer_with(0, 640, 480);
        assert!(DisplayInfo::parse(&bytes[..RESPONSE_DISPLAY_INFO_SIZE - 1]).is_none());
        assert!(DisplayInfo::parse(&bytes[..10]).is_none());
        assert!(DisplayInfo::parse(&bytes).is_some());
    }

    /// Two enabled displays: the answer's own order decides, and both are
    /// readable by index.
    #[test]
    fn two_displays_are_both_readable() {
        let mut bytes = answer_with(0, 640, 480);
        let at = CTRL_HEADER_SIZE + DISPLAY_ENTRY_SIZE;
        bytes[at + 8..at + 12].copy_from_slice(&800u32.to_le_bytes());
        bytes[at + 12..at + 16].copy_from_slice(&600u32.to_le_bytes());
        bytes[at + 16..at + 20].copy_from_slice(&1u32.to_le_bytes());
        let info = DisplayInfo::parse(&bytes).expect("a full answer");
        assert_eq!(info.enabled_count(), 2);
        assert_eq!(info.preferred().map(|mode| mode.width), Some(640));
        assert_eq!(info.mode(1).map(|mode| mode.width), Some(800));
    }

    /// A display placed off the origin keeps its offset, which a scanout needs
    /// to place the rectangle the way the device described it.
    #[test]
    fn a_display_off_the_origin_keeps_its_offset() {
        let mut bytes = answer_with(0, 320, 240);
        let at = CTRL_HEADER_SIZE;
        bytes[at..at + 4].copy_from_slice(&64u32.to_le_bytes());
        bytes[at + 4..at + 8].copy_from_slice(&32u32.to_le_bytes());
        let mode = DisplayInfo::parse(&bytes)
            .expect("a full answer")
            .preferred()
            .expect("one display is on");
        assert_eq!((mode.x, mode.y), (64, 32));
        assert_eq!((mode.width, mode.height), (320, 240));
    }

    /// An answer whose header names an error is still parseable; it is the
    /// caller that decides an error means there is no display to use.  What
    /// makes this true is the header's type being a field this parse does not
    /// read.
    #[test]
    fn the_header_is_not_the_parse_s_business() {
        let mut bytes = answer_with(0, 640, 480);
        bytes[0..4].copy_from_slice(&0x1200u32.to_le_bytes());
        assert!(DisplayInfo::parse(&bytes).is_some());
        let info = DisplayInfo::parse(&bytes).expect("still the right size");
        assert_eq!(info.enabled_count(), 1, "and its records are still read");
        assert_eq!(
            Command::GetDisplayInfo as u32,
            0x0100,
            "the command it answers"
        );
    }
}
