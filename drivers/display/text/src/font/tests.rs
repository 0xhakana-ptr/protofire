//! drivers/display/text/src/font/tests.rs
//!
//! The font's shape: how many glyphs, which byte maps to which, and the bit
//! order a renderer reads.

use super::FIRST_GLYPH;
use super::GLYPH_COUNT;
use super::GLYPH_HEIGHT;
use super::GLYPH_WIDTH;
use super::LAST_GLYPH;
use super::glyph;
use super::row_pixel;

/// The table is 96 glyphs of 16 rows, and the printable range accounts for 95
/// of them.
///
/// The arithmetic is the fallback's existence: `0x7E - 0x20 + 1` is 95, so a
/// 96th entry is the box drawn for a byte with no glyph.  A table with 95 would
/// index past its end on the first non-ASCII byte, and a table with 97 would
/// have a glyph nothing reaches.
#[test]
fn the_table_holds_the_printable_range_and_one_fallback() {
    assert_eq!(LAST_GLYPH - FIRST_GLYPH + 1, 95);
    assert_eq!(GLYPH_COUNT, 96);
    assert_eq!(GLYPH_WIDTH, 8);
    assert_eq!(GLYPH_HEIGHT, 16);
}

/// Every glyph in the printable range is addressable and distinct from its
/// neighbours.
///
/// Distinctness is the check that catches an off-by-one in the index: a table
/// read one entry late would answer the next character's shape for every glyph,
/// which is legible and wrong.
#[test]
fn adjacent_glyphs_are_different() {
    for byte in FIRST_GLYPH..LAST_GLYPH {
        assert_ne!(
            glyph(byte),
            glyph(byte + 1),
            "{} and {} must not be the same glyph",
            byte as char,
            (byte + 1) as char
        );
    }
}

/// A byte outside the range answers the fallback, and never panics.
///
/// Both ends: a control byte below the space and a byte above the tilde.  A
/// console that dropped what it could not draw would lose a byte from a log,
/// which is worse than a visible box.
#[test]
fn a_byte_without_a_glyph_answers_the_fallback() {
    let fallback = glyph(0x7F);
    for byte in [0x00_u8, 0x01, 0x1F, 0x7F, 0x80, 0xFF] {
        assert_eq!(glyph(byte), fallback, "{byte:#04x} answers the fallback");
    }
}

/// The leftmost pixel is the most significant bit.
///
/// The generator's ASCII art reads `#####...` as five set pixels starting at
/// the left, and a console that read the bits the other way would draw every
/// glyph mirrored.  `0x80` is one pixel at column zero and `0x01` is one at
/// column seven.
#[test]
fn the_bit_order_puts_the_leftmost_pixel_first() {
    assert!(row_pixel(0x80, 0));
    assert!(!row_pixel(0x80, 1));
    assert!(!row_pixel(0x80, 7));
    assert!(row_pixel(0x01, 7));
    assert!(!row_pixel(0x01, 0));
    // `0xF0` is the top four pixels, and they are the left four.
    for column in 0..4 {
        assert!(row_pixel(0xF0, column), "column {column} is set");
    }
    for column in 4..8 {
        assert!(!row_pixel(0xF0, column), "column {column} is clear");
    }
}

/// A space draws nothing, which is what makes it a blank cell.
#[test]
fn a_space_has_no_pixels() {
    assert!(
        glyph(b' ').iter().all(|&row| row == 0),
        "every row of a space is empty"
    );
}

/// Every glyph that is not a space has at least one pixel.
///
/// A glyph with no pixels would be an invisible character, and a console that
/// drew it would leave the reader unable to tell it from a space.
#[test]
fn every_visible_glyph_marks_the_screen() {
    for byte in FIRST_GLYPH..=LAST_GLYPH {
        if byte == b' ' {
            continue;
        }
        assert!(
            glyph(byte).iter().any(|&row| row != 0),
            "{} has no set pixel",
            byte as char
        );
    }
}
