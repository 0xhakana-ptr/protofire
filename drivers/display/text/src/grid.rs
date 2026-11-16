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
#[cfg(test)]
mod tests {
    //! The grid's tests: where a byte lands, what the control characters do,
    //! the scroll, and the repaint.
    //!
    //! The surface is an array, so every one of these is arithmetic rather than
    //! a machine.

    use super::CellSurface;
    use super::Grid;
    use super::TAB_WIDTH;

    /// A surface that records what was painted, in order.
    struct Recording {
        columns: usize,
        rows: usize,
        painted: alloc::vec::Vec<(usize, usize, u8, u32, u32)>,
    }

    impl Recording {
        fn new(columns: usize, rows: usize) -> Self {
            Self {
                columns,
                rows,
                painted: alloc::vec::Vec::new(),
            }
        }

        /// What was painted at one cell, if anything.
        fn at(&self, column: usize, row: usize) -> Option<u8> {
            self.painted
                .iter()
                .find(|(c, r, ..)| *c == column && *r == row)
                .map(|(_, _, byte, ..)| *byte)
        }
    }

    impl CellSurface for Recording {
        fn paint(&mut self, column: usize, row: usize, byte: u8, foreground: u32, background: u32) {
            self.painted
                .push((column, row, byte, foreground, background));
        }

        fn columns(&self) -> usize {
            self.columns
        }

        fn rows(&self) -> usize {
            self.rows
        }
    }

    /// A grid built from pixels is the framebuffer divided into cells.
    ///
    /// The division is exact, and the remainder is dropped: a partial cell at
    /// the edge is a character drawn off the screen.  1024x768 at an 8x16 cell
    /// is 128 by 48, which is the grid the console mode was chosen for.
    #[test]
    fn the_grid_divides_the_framebuffer_into_cells() {
        let grid = Grid::for_pixels(1024, 768);
        assert_eq!(grid.columns(), 128);
        assert_eq!(grid.rows(), 48);

        // A framebuffer with a remainder keeps the whole cells and drops the
        // rest.
        let grid = Grid::for_pixels(1023, 767);
        assert_eq!(grid.columns(), 127);
        assert_eq!(grid.rows(), 47);
    }

    /// A framebuffer smaller than one cell still answers a one-cell grid.
    ///
    /// Zero columns would be a grid every later index divides by, and the
    /// boot's own display could be smaller than a character if the mode were
    /// refused.
    #[test]
    fn a_tiny_framebuffer_answers_one_cell() {
        let grid = Grid::for_pixels(4, 4);
        assert_eq!(grid.columns(), 1);
        assert_eq!(grid.rows(), 1);
    }

    /// Text lands left to right, one cell per byte.
    #[test]
    fn text_fills_the_row_in_order() {
        let mut grid = Grid::new(10, 3);
        grid.write(b"abc");
        assert_eq!(grid.cell(0, 0), Some(b'a'));
        assert_eq!(grid.cell(1, 0), Some(b'b'));
        assert_eq!(grid.cell(2, 0), Some(b'c'));
        assert_eq!(grid.cursor(), (3, 0));
        assert_eq!(grid.row_text(0).as_deref(), Some("abc"));
    }

    /// A newline moves to the next row **and to column zero**.
    ///
    /// A console that kept the column would start every line after a short one
    /// where the previous stopped, which is not what a log reader expects and
    /// not what a terminal does.
    #[test]
    fn a_newline_returns_to_column_zero() {
        let mut grid = Grid::new(10, 3);
        grid.write(b"abc\nde");
        assert_eq!(grid.row_text(0).as_deref(), Some("abc"));
        assert_eq!(grid.row_text(1).as_deref(), Some("de"));
        assert_eq!(grid.cell(0, 1), Some(b'd'));
        assert_eq!(grid.cursor(), (2, 1));
    }

    /// A carriage return goes to column zero without moving down.
    #[test]
    fn a_carriage_return_rewinds_the_column() {
        let mut grid = Grid::new(10, 3);
        grid.write(b"abc\rX");
        assert_eq!(grid.cell(0, 0), Some(b'X'), "the X overwrote the a");
        assert_eq!(grid.cell(1, 0), Some(b'b'), "and the rest is untouched");
        assert_eq!(grid.cursor(), (1, 0));
    }

    /// A tab advances to the next stop, not by a fixed width.
    ///
    /// From column two a tab lands on eight; from column nine it lands on
    /// sixteen. A tab that advanced eight from wherever it was would make a
    /// column's alignment depend on how many tabs preceded it.
    #[test]
    fn a_tab_advances_to_the_next_stop() {
        assert_eq!(TAB_WIDTH, 8);

        let mut grid = Grid::new(32, 2);
        grid.write(b"ab\tX");
        assert_eq!(
            grid.cell(8, 0),
            Some(b'X'),
            "from column two, the stop is 8"
        );

        let mut grid = Grid::new(32, 2);
        grid.write(b"12345678\tX");
        assert_eq!(
            grid.cell(16, 0),
            Some(b'X'),
            "from column eight, the stop is 16"
        );
    }

    /// Writing past the last column wraps to the next row.
    #[test]
    fn a_full_row_wraps() {
        let mut grid = Grid::new(4, 3);
        grid.write(b"abcde");
        assert_eq!(grid.row_text(0).as_deref(), Some("abcd"));
        assert_eq!(grid.row_text(1).as_deref(), Some("e"));
        assert_eq!(grid.cursor(), (1, 1));
    }

    /// A full grid scrolls, and the oldest row goes.
    ///
    /// The trace matters, because a four-column grid wraps `three` in the
    /// middle: `thre` fills the last row, the wrap scrolls, and `e` lands on
    /// the row the scroll made.  So the three rows a reader sees are the tail
    /// of one line, the whole next one, and the blank the scroll left.  The
    /// cursor ends on the last row, which is where the next character belongs:
    /// a scroll that left it past the end would write the next byte outside the
    /// grid.
    #[test]
    fn a_full_grid_scrolls_and_keeps_the_newest_rows() {
        let mut grid = Grid::new(4, 3);
        grid.write(b"one\ntwo\nthree\nfour");

        assert_eq!(
            grid.row_text(0).as_deref(),
            Some("e"),
            "the tail of `three`"
        );
        assert_eq!(grid.row_text(1).as_deref(), Some("four"));
        assert_eq!(
            grid.row_text(2).as_deref(),
            Some(""),
            "the scroll's blank row"
        );
        assert_eq!(grid.cursor(), (0, 2), "on the last row, after the newline");
    }

    /// A scroll blanks the row it makes empty.
    ///
    /// Without the blanking, the last row would keep whatever the row above it
    /// had and the console would show text it never wrote.  The check is the
    /// **empty** row: a scroll that moved the rows up and left the last one as
    /// it was would answer `ij` twice.
    #[test]
    fn a_scroll_clears_the_row_it_empties() {
        let mut grid = Grid::new(4, 2);
        // `abcd` fills the row and wraps, so the wrap scrolls once before
        // `efgh` is written; the second wrap scrolls again.
        grid.write(b"abcd\nefgh\n");

        assert_eq!(grid.row_text(0).as_deref(), Some(""));
        assert_eq!(grid.row_text(1).as_deref(), Some(""));
        assert_eq!(grid.cursor(), (0, 1));
    }

    /// A repaint paints every cell exactly once, with both colours.
    ///
    /// The background is the half that matters: a cell drawn with only its
    /// foreground pixels would leave the previous screen showing through the
    /// gaps, which is a console that never erases anything.
    #[test]
    fn a_repaint_paints_every_cell_once() {
        let mut grid = Grid::new(4, 2);
        grid.write(b"ab");
        let mut surface = Recording::new(4, 2);
        grid.repaint(&mut surface, 0xFFFFFF, 0x000000);

        assert_eq!(
            surface.painted.len(),
            8,
            "four columns by two rows, each once"
        );
        assert_eq!(surface.at(0, 0), Some(b'a'));
        assert_eq!(surface.at(1, 0), Some(b'b'));
        assert_eq!(
            surface.at(0, 1),
            Some(b' '),
            "the blank cell is painted too"
        );

        let (_, _, _, foreground, background) = surface.painted[0];
        assert_eq!(foreground, 0xFFFFFF);
        assert_eq!(background, 0x000000);
    }

    /// A repaint into a smaller surface stops at the surface's edge.
    ///
    /// The two sizes can disagree, a framebuffer resized under a grid that was
    /// built for the old mode, and indexing past the surface would be a write
    /// into whatever the surface's memory happened to hold next.
    #[test]
    fn a_repaint_stops_at_the_surface_edge() {
        let mut grid = Grid::new(8, 4);
        grid.write(b"abcdefgh");
        let mut surface = Recording::new(3, 2);
        grid.repaint(&mut surface, 0, 0);

        assert_eq!(surface.painted.len(), 6, "three columns by two rows");
        assert!(
            surface.painted.iter().all(|(c, r, ..)| *c < 3 && *r < 2),
            "nothing outside the surface"
        );
    }

    /// A byte with no glyph still takes a cell.
    ///
    /// The grid stores the byte and the font draws the fallback, so the cell is
    /// occupied either way: a console that skipped an undrawable byte would
    /// shift the rest of the line by one and lose a character from the log.
    #[test]
    fn an_undrawable_byte_still_occupies_a_cell() {
        let mut grid = Grid::new(4, 1);
        grid.write(&[0x01, b'X']);
        assert_eq!(grid.cell(0, 0), Some(0x01));
        assert_eq!(grid.cell(1, 0), Some(b'X'));
        assert_eq!(grid.cursor(), (2, 0));
    }
}
