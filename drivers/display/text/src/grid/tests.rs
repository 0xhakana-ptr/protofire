//! drivers/display/text/src/grid/tests.rs
//!
//! The grid's tests: where a byte lands, what the control characters do, the
//! scroll, and the repaint.
//!
//! The surface is an array, so every one of these is arithmetic rather than a
//! machine.

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
/// The division is exact, and the remainder is dropped: a partial cell at the
/// edge is a character drawn off the screen.  1024x768 at an 8x16 cell is 128
/// by 48, which is the grid the console mode was chosen for.
#[test]
fn the_grid_divides_the_framebuffer_into_cells() {
    let grid = Grid::for_pixels(1024, 768);
    assert_eq!(grid.columns(), 128);
    assert_eq!(grid.rows(), 48);

    // A framebuffer with a remainder keeps the whole cells and drops the rest.
    let grid = Grid::for_pixels(1023, 767);
    assert_eq!(grid.columns(), 127);
    assert_eq!(grid.rows(), 47);
}

/// A framebuffer smaller than one cell still answers a one-cell grid.
///
/// Zero columns would be a grid every later index divides by, and the boot's
/// own display could be smaller than a character if the mode were refused.
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
/// where the previous stopped, which is not what a log reader expects and not
/// what a terminal does.
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
/// From column two a tab lands on eight; from column nine it lands on sixteen.
/// A tab that advanced eight from wherever it was would make a column's
/// alignment depend on how many tabs preceded it.
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
/// The trace matters, because a four-column grid wraps `three` in the middle:
/// `thre` fills the last row, the wrap scrolls, and `e` lands on the row the
/// scroll made.  So the three rows a reader sees are the tail of one line, the
/// whole next one, and the blank the scroll left.  The cursor ends on the last
/// row, which is where the next character belongs: a scroll that left it past
/// the end would write the next byte outside the grid.
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
/// Without the blanking, the last row would keep whatever the row above it had
/// and the console would show text it never wrote.  The check is the **empty**
/// row: a scroll that moved the rows up and left the last one as it was would
/// answer `ij` twice.
#[test]
fn a_scroll_clears_the_row_it_empties() {
    let mut grid = Grid::new(4, 2);
    // `abcd` fills the row and wraps, so the wrap scrolls once before `efgh`
    // is written; the second wrap scrolls again.
    grid.write(b"abcd\nefgh\n");

    assert_eq!(grid.row_text(0).as_deref(), Some(""));
    assert_eq!(grid.row_text(1).as_deref(), Some(""));
    assert_eq!(grid.cursor(), (0, 1));
}

/// A repaint paints every cell exactly once, with both colours.
///
/// The background is the half that matters: a cell drawn with only its
/// foreground pixels would leave the previous screen showing through the gaps,
/// which is a console that never erases anything.
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
/// built for the old mode, and indexing past the surface would be a write into
/// whatever the surface's memory happened to hold next.
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
/// occupied either way: a console that skipped an undrawable byte would shift
/// the rest of the line by one and lose a character from the log.
#[test]
fn an_undrawable_byte_still_occupies_a_cell() {
    let mut grid = Grid::new(4, 1);
    grid.write(&[0x01, b'X']);
    assert_eq!(grid.cell(0, 0), Some(0x01));
    assert_eq!(grid.cell(1, 0), Some(b'X'));
    assert_eq!(grid.cursor(), (2, 0));
}
