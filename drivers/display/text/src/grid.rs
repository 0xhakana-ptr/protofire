//! drivers/display/text/src/grid.rs
//!
//! The character grid: what a screen holds, where the cursor is, and what a
//! byte does to it.
//!
//! ## Why the grid is a crate and not a field in the kernel
//!
//! A grid is arithmetic: columns, rows, a cursor, and the four control
//! characters a console honours.  None of that needs a machine, so all of it is
//! testable on a host, and the part that needs one, writing pixels into a
//! mapped framebuffer, is a separate trait the kernel implements.  That is the
//! same split `vga` makes for the register block, and for the same reason: the
//! interesting arithmetic should not be reachable only by booting.
//!
//! ## What a byte does
//!
//! Only four control characters are honoured, and each is a decision:
//!
//! - `\n` moves to the next row at **column zero**.  A console that kept the
//!   column would make every line after a short one start where the previous
//!   stopped, which is not what a log reader expects.
//! - `\r` returns to column zero without moving down.
//! - `\t` advances to the next eight-column stop, which is the only width a log
//!   reader can predict.
//! - Everything else, including bytes with no glyph, occupies one cell.
//!
//! `\x08` (backspace) is deliberately **not** honoured: a console is a log, and
//! a log whose bytes delete earlier ones reports history it did not have.

use crate::font::GLYPH_HEIGHT;
use crate::font::GLYPH_WIDTH;
use crate::font::glyph;

/// How many columns a tab advances to the next stop of.
pub const TAB_WIDTH: usize = 8;

/// Where a pixel comes from, according to the grid.
///
/// The grid knows its characters and its cursor; it does not know a
/// framebuffer.  A renderer implements this with a mapped address and a pitch,
/// and a host test implements it with a vector, so the same grid code draws a
/// screen in both.
pub trait CellSurface {
    /// Paint `columns` cells wide and `rows` tall of cell `(column, row)`.
    ///
    /// `byte` is the character; the surface draws it with `foreground` where
    /// the glyph has a pixel and `background` where it does not, which is what
    /// makes a cell opaque: a console that drew only foreground pixels would
    /// leave the previous screen's glyphs showing through the gaps.
    fn paint(&mut self, column: usize, row: usize, byte: u8, foreground: u32, background: u32);

    /// How many columns the surface holds.
    fn columns(&self) -> usize;

    /// How many rows the surface holds.
    fn rows(&self) -> usize;
}

/// A screen of characters and a cursor.
///
/// The grid holds the characters rather than only the pixels because a redraw
/// is a thing a console needs: a resize, a scroll, or a repaint after something
/// else wrote to the framebuffer all need the text that was there, and a
/// framebuffer cannot be read back reliably.
#[derive(Debug)]
pub struct Grid {
    columns: usize,
    rows: usize,
    cells: alloc::vec::Vec<u8>,
    column: usize,
    row: usize,
}

impl Grid {
    /// A grid of `columns` by `rows`, every cell blank.
    pub fn new(columns: usize, rows: usize) -> Self {
        Self {
            columns,
            rows,
            cells: alloc::vec![b' '; columns.saturating_mul(rows)],
            column: 0,
            row: 0,
        }
    }

    /// A grid sized to a framebuffer of `width` by `height` pixels.
    ///
    /// The cell is `GLYPH_WIDTH` by `GLYPH_HEIGHT`, and the division is exact
    /// because a partial cell at the edge would be a character drawn off the
    /// screen.  A framebuffer smaller than one cell answers a grid of one cell
    /// rather than zero, which is what keeps every later index inside the
    /// vector.
    pub fn for_pixels(width: usize, height: usize) -> Self {
        Self::new((width / GLYPH_WIDTH).max(1), (height / GLYPH_HEIGHT).max(1))
    }

    /// How many columns.
    pub fn columns(&self) -> usize {
        self.columns
    }

    /// How many rows.
    pub fn rows(&self) -> usize {
        self.rows
    }

    /// Where the cursor is.
    pub fn cursor(&self) -> (usize, usize) {
        (self.column, self.row)
    }

    /// What is in cell `(column, row)`.
    pub fn cell(&self, column: usize, row: usize) -> Option<u8> {
        if column >= self.columns || row >= self.rows {
            return None;
        }
        Some(self.cells[row * self.columns + column])
    }

    /// The whole row as a string, trailing blanks removed.
    ///
    /// Answered for a test and for a caller that wants to know what a line says
    /// without reading pixels.  The trailing blanks go because they are the
    /// grid's own blank, not text.
    pub fn row_text(&self, row: usize) -> Option<alloc::string::String> {
        if row >= self.rows {
            return None;
        }
        let start = row * self.columns;
        let text = &self.cells[start..start + self.columns];
        let end = text
            .iter()
            .rposition(|&byte| byte != b' ')
            .map_or(0, |at| at + 1);
        Some(alloc::string::String::from_utf8_lossy(&text[..end]).into_owned())
    }

    /// Write one byte at the cursor and advance.
    ///
    /// The control characters are handled first and each returns without
    /// touching a cell, so the cursor's arithmetic is in one place.
    pub fn put(&mut self, byte: u8) {
        match byte {
            b'\n' => self.newline(),
            b'\r' => self.column = 0,
            b'\t' => {
                // The next stop, not one tab width: a tab that advanced eight
                // columns from wherever it was would make a column's alignment
                // depend on how many tabs preceded it.
                let next = (self.column / TAB_WIDTH + 1) * TAB_WIDTH;
                self.column = next.min(self.columns.saturating_sub(1));
                if next >= self.columns {
                    self.newline();
                }
            }
            _ => {
                self.cells[self.row * self.columns + self.column] = byte;
                self.column += 1;
                if self.column == self.columns {
                    self.newline();
                }
            }
        }
    }

    /// Write every byte of `text`.
    pub fn write(&mut self, text: &[u8]) {
        for &byte in text {
            self.put(byte);
        }
    }

    /// Move to the next row, scrolling when the grid is full.
    pub fn newline(&mut self) {
        self.column = 0;
        self.row += 1;
        if self.row == self.rows {
            self.scroll();
        }
    }

    /// Move every row up one, and clear the last.
    ///
    /// The cursor stays on the last row, which is where the next character
    /// belongs: a scroll that left the cursor past the end would write the next
    /// byte outside the grid.
    fn scroll(&mut self) {
        let row_bytes = self.columns;
        self.cells.copy_within(row_bytes.., 0);
        let last = (self.rows - 1) * row_bytes;
        for cell in &mut self.cells[last..] {
            *cell = b' ';
        }
        self.row = self.rows - 1;
    }

    /// Paint every cell of the grid into `surface`.
    ///
    /// The whole screen, not a delta: a caller repainting after something else
    /// wrote to the framebuffer has no way to know what changed, and a console
    /// is not on a path where a full repaint costs anything a reader can see.
    pub fn repaint(&self, surface: &mut dyn CellSurface, foreground: u32, background: u32) {
        for row in 0..self.rows.min(surface.rows()) {
            for column in 0..self.columns.min(surface.columns()) {
                surface.paint(
                    column,
                    row,
                    self.cells[row * self.columns + column],
                    foreground,
                    background,
                );
            }
        }
    }
}

/// The bytes one glyph occupies, for a caller that draws a cell itself.
///
/// Exposed so a surface implementation does not have to import the font: the
/// grid hands it the sixteen rows and it decides where each pixel goes.
pub fn glyph_rows(byte: u8) -> &'static [u8; GLYPH_HEIGHT] {
    glyph(byte)
}

#[cfg(test)]
mod tests;
