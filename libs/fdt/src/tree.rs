//! libs/fdt/src/tree.rs
//!
//! The header, the structure block, and the walks over them.
//!
//! ## The header
//!
//! Ten big-endian words, and this crate reads six of them:
//!
//! | offset | field |
//! |---|---|
//! | 0 | magic, `0xd00dfeed` |
//! | 4 | total size of the blob |
//! | 8 | offset of the structure block |
//! | 12 | offset of the strings block |
//! | 20 | version |
//! | 32 | size of the strings block |
//! | 36 | size of the structure block |
//!
//! ## The structure block
//!
//! A token stream with a four-byte alignment on everything:
//!
//! | token | value | followed by |
//! |---|---|---|
//! | `FDT_BEGIN_NODE` | 1 | the node's name, NUL-terminated, padded to 4 |
//! | `FDT_END_NODE` | 2 | nothing |
//! | `FDT_PROP` | 3 | length, name offset, then the value padded to 4 |
//! | `FDT_NOP` | 4 | nothing; skipped |
//! | `FDT_END` | 9 | nothing; the block is over |
//!
//! A node's properties come before its children, and the block is one tree
//! depth-first.  So finding a node's children is "walk until the matching
//! `FDT_END_NODE`", which is the only place this code has to count depth.
//!
//! ## Every read is checked
//!
//! Firmware wrote this blob.  Nothing about it is guaranteed to this kernel,
//! and a parser that indexed past a truncated blob would fault in the boot with
//! the cause three functions from a log line.  So every offset is
//! bounds-checked and every malformed blob is an [`Error`].

use crate::property::Property;

/// The token that begins a node.
const TOKEN_BEGIN_NODE: u32 = 1;
/// The token that ends a node.
const TOKEN_END_NODE: u32 = 2;
/// The token that names a property.
const TOKEN_PROP: u32 = 3;
/// The token to skip.
const TOKEN_NOP: u32 = 4;
/// The token that ends the structure block.
const TOKEN_END: u32 = 9;

/// The `#address-cells` this crate assumes when a node does not say.
///
/// The device-tree specification's own default, and it is a default because a
/// blob is allowed to omit it at the root.  Two cells is a 64-bit address.
const DEFAULT_ADDRESS_CELLS: u8 = 2;
/// The `#size-cells` this crate assumes when a node does not say.
const DEFAULT_SIZE_CELLS: u8 = 1;

/// Why a blob is not a device tree this crate can read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The blob is shorter than a header.
    TooSmall,
    /// The first word is not `0xd00dfeed`.
    BadMagic,
    /// The header's version is outside what this crate reads.
    UnsupportedVersion(u32),
    /// An offset or size in the header names bytes the blob does not have.
    BadHeader,
    /// A token appeared where the walk did not expect one.
    BadToken(u32),
    /// The structure block ended before the tree did.
    Truncated,
    /// A name offset pointed outside the strings block, or at bytes that are
    /// not UTF-8.
    BadString,
}

/// Read a big-endian word at `offset`.
fn word(blob: &[u8], offset: usize) -> Option<u32> {
    let bytes = blob.get(offset..offset.checked_add(4)?)?;
    let array: [u8; 4] = bytes.try_into().ok()?;
    Some(u32::from_be_bytes(array))
}

/// The most cells a `reg` field may be declared as.
///
/// Two is what an address needs, thirty-two or sixty-four bits, but a PCI
/// host bridge declares **three**: the address space (`0x2000_0000` for a
/// 32-bit non-prefetchable window), then the address.  Clamping three to two
/// would drop the space selector and decode the rest as a shifted address,
/// which is a number, so it would not fail.
///
/// Four is the bound because a `reg` entry is at most that many address cells
/// plus the same in size cells, and a declaration above it is a firmware this
/// tree reads conservatively.
const MAX_CELLS: u8 = 4;

/// How many cells a node's `#address-cells` or `#size-cells` declares.
///
/// A declaration of zero is legal and means "this node has none".  Anything
/// above [`MAX_CELLS`] is clamped rather than refused: a blob asking for more
/// than this tree reads gets a bounded reading rather than a crash.
const fn cell_count(declared: u32) -> u8 {
    if declared > MAX_CELLS as u32 {
        MAX_CELLS
    } else {
        declared as u8
    }
}

/// Round `value` up to a four-byte boundary.
const fn align4(value: usize) -> usize {
    (value + 3) & !3
}

impl PartialEq for Fdt<'_> {
    fn eq(&self, other: &Self) -> bool {
        core::ptr::eq(self.blob.as_ptr(), other.blob.as_ptr())
            && self.blob.len() == other.blob.len()
            && self.struct_offset == other.struct_offset
            && self.strings_offset == other.strings_offset
    }
}

impl Eq for Fdt<'_> {}

/// One region a node claims: an address and a length.
///
/// Decoded from `reg`, whose width is the *parent's* `#address-cells` and
/// `#size-cells`.  Those are inherited down the tree, which is why [`Node`]
/// carries them instead of reading them on demand: a `reg` read with the wrong
/// widths is a plausible number for a wrong reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reg {
    /// The address, without the space selector.
    pub address: u64,
    /// The length of the region.
    pub size: u64,
    /// The address-space selector, for a node whose parent declared more than
    /// two address cells.
    ///
    /// Zero for every ordinary MMIO node, and `0x0200_0000` for a 32-bit
    /// non-prefetchable PCI memory window.  A caller that maps an ordinary
    /// device region does not need it; the one that enumerates a PCI bus does.
    pub space: u64,
}

/// A device tree, borrowed from the blob firmware handed over.
///
/// `PartialEq` compares what the header named, the blob and the two block
/// extents, because two `Fdt`s over the same bytes are the same tree, and that
/// is what a test asserting `Err(BadMagic)` needs.
#[derive(Debug, Clone, Copy)]
pub struct Fdt<'a> {
    blob: &'a [u8],
    struct_offset: usize,
    struct_end: usize,
    strings_offset: usize,
    strings_end: usize,
}

impl<'a> Fdt<'a> {
    /// Read the blob at `blob`, refusing anything that is not a device tree.
    ///
    /// Nothing is copied: every accessor returns slices into `blob`, and the
    /// firmware's memory stays where the firmware put it.
    pub fn new(blob: &'a [u8]) -> Result<Fdt<'a>, Error> {
        if blob.len() < 40 {
            return Err(Error::TooSmall);
        }
        if word(blob, 0) != Some(crate::MAGIC) {
            return Err(Error::BadMagic);
        }
        let total = word(blob, 4).ok_or(Error::BadHeader)? as usize;
        let version = word(blob, 20).ok_or(Error::BadHeader)?;
        if version < crate::MINIMUM_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }
        // A version *newer* than this crate knows is accepted: the header's
        // layout is fixed from 17 onwards and a blob only ever adds fields
        // before `size_dt_struct`... but it does not, so a newer blob's header
        // is read as this one's.  Refusing it would make a firmware update look
        // like a broken kernel; the fields this crate reads are the same.
        let struct_offset = word(blob, 8).ok_or(Error::BadHeader)? as usize;
        let strings_offset = word(blob, 12).ok_or(Error::BadHeader)? as usize;
        let strings_size = word(blob, 32).ok_or(Error::BadHeader)? as usize;
        let struct_size = word(blob, 36).ok_or(Error::BadHeader)? as usize;

        // The blob's own claim bounds every read.  A `total` larger than the
        // slice is a firmware that overstated it, and one smaller is a caller
        // that passed less than the blob.
        let available = blob.len();
        let total = total.min(available);
        let struct_end = struct_offset
            .checked_add(struct_size)
            .filter(|end| *end <= total)
            .ok_or(Error::BadHeader)?;
        let strings_end = strings_offset
            .checked_add(strings_size)
            .filter(|end| *end <= total)
            .ok_or(Error::BadHeader)?;

        Ok(Fdt {
            blob: &blob[..total],
            struct_offset,
            struct_end,
            strings_offset,
            strings_end,
        })
    }

    /// The blob's total size, as its header states it.
    pub fn size(&self) -> usize {
        self.blob.len()
    }

    /// The version the header reports.
    pub fn version(&self) -> Option<u32> {
        word(self.blob, 20)
    }

    /// The token at `offset` in the structure block.
    fn token(&self, offset: usize) -> Result<u32, Error> {
        if offset >= self.struct_end {
            return Err(Error::Truncated);
        }
        word(self.blob, offset).ok_or(Error::Truncated)
    }

    /// The NUL-terminated string in the strings block at `offset`.
    fn string(&self, offset: usize) -> Result<&'a str, Error> {
        let start = self
            .strings_offset
            .checked_add(offset)
            .filter(|start| *start < self.strings_end)
            .ok_or(Error::BadString)?;
        let rest = &self.blob[start..self.strings_end];
        let length = rest
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(rest.len());
        core::str::from_utf8(&rest[..length]).map_err(|_| Error::BadString)
    }

    /// The node name that follows a `FDT_BEGIN_NODE` token at `offset`.
    ///
    /// The root's name is the empty string, which the format allows and which
    /// a caller must expect: a blob whose root is named would be one a
    /// generator invented.
    fn node_name(&self, token_offset: usize) -> Result<&'a str, Error> {
        let start = token_offset + 4;
        if start >= self.struct_end {
            return Err(Error::Truncated);
        }
        let rest = &self.blob[start..self.struct_end];
        let length = rest
            .iter()
            .position(|byte| *byte == 0)
            .ok_or(Error::Truncated)?;
        core::str::from_utf8(&rest[..length]).map_err(|_| Error::Truncated)
    }

    /// The offset of the `FDT_END_NODE` that closes the node beginning at
    /// `begin_offset`.
    ///
    /// This is the one walk that counts depth, and every other walk is built on
    /// it: a node's children are the nodes between its name and this offset.
    fn end_of_node(&self, begin_offset: usize) -> Result<usize, Error> {
        let name = self.node_name(begin_offset)?;
        let mut cursor = begin_offset + 4 + align4(name.len() + 1);
        let mut depth = 1_usize;
        loop {
            let token = self.token(cursor)?;
            match token {
                TOKEN_BEGIN_NODE => {
                    depth += 1;
                    let inner = self.node_name(cursor)?;
                    cursor += 4 + align4(inner.len() + 1);
                }
                TOKEN_END_NODE => {
                    depth -= 1;
                    if depth == 0 {
                        return Ok(cursor);
                    }
                    cursor += 4;
                }
                TOKEN_PROP => {
                    let length = word(self.blob, cursor + 4).ok_or(Error::Truncated)? as usize;
                    cursor += 12 + align4(length);
                }
                TOKEN_NOP => cursor += 4,
                TOKEN_END => return Err(Error::Truncated),
                other => return Err(Error::BadToken(other)),
            }
        }
    }

    /// The tree's root node.
    pub fn root(&self) -> Result<Node<'a>, Error> {
        let mut cursor = self.struct_offset;
        // Leading `FDT_NOP`s are legal.
        while self.token(cursor)? == TOKEN_NOP {
            cursor += 4;
        }
        let token = self.token(cursor)?;
        if token != TOKEN_BEGIN_NODE {
            return Err(Error::BadToken(token));
        }
        // The root has no parent, so its own `reg`, which it does not
        // have, is decoded with the format's defaults; its declaration is
        // what every other node's `reg` inherits.
        let node = Node::at(self, cursor, DEFAULT_ADDRESS_CELLS, DEFAULT_SIZE_CELLS)?;
        Ok(node)
    }

    /// The first node anywhere in the tree whose `compatible` list contains
    /// `wanted`.
    ///
    /// Depth-first, in the blob's own order, so the answer is the same one a
    /// second reader would get.  A node may claim several names, ///
    /// `"arm,pl011"` then `"arm,primecell"`, and any of them matching is a
    /// match, which is what the property means.
    pub fn find_compatible(&self, wanted: &str) -> Option<Node<'a>> {
        self.root().ok()?.find_descendant(wanted)
    }

    /// Every node whose `compatible` list contains `wanted`, depth-first.
    ///
    /// A device tree may have six `virtio,mmio` nodes, and a boot that is
    /// asking "which disks are there" needs all of them.
    pub fn all_compatible(&self, wanted: &'a str) -> CompatibleIter<'a> {
        CompatibleIter {
            fdt: *self,
            wanted,
            cursor: self.struct_offset,
            widths: [(DEFAULT_ADDRESS_CELLS, DEFAULT_SIZE_CELLS); MAX_DEPTH],
            depth: 0,
        }
    }
}

/// The iterator [`Fdt::all_compatible`] returns.
///
/// ## A cursor, not a stack
///
/// The structure block is already in the order this walk wants: a node's
/// `FDT_BEGIN_NODE` comes after its parent's, and its `FDT_END_NODE` after all
/// of its children.  So "every node, in blob order" is a linear scan of the
/// tokens, and this iterator is one offset and nothing else.
///
/// The first version kept a fixed stack of pending children, which had a bound
/// nobody had justified and which silently dropped nodes past it: QEMU's `virt`
/// tree has fifty-one children under the root and thirty-two `virtio,mmio`
/// transports, and the stack of thirty-two found twenty-eight of them.  An
/// iteration whose answer depends on a constant in its own header is the kind
/// of defect that reads as correct until the day a machine has one device more.
pub struct CompatibleIter<'a> {
    fdt: Fdt<'a>,
    wanted: &'a str,
    /// The next token to examine.
    cursor: usize,
    /// The cell widths in force, one entry per open node.
    ///
    /// A declaration governs a node's **children** and stops applying when the
    /// node ends, so the walk has to restore what it had.  The first version of
    /// this walk carried one pair forward forever, and QEMU's tree defeated it:
    /// `platform-bus@c000000` declares `#address-cells = <1>` and appears
    /// before the `virtio_mmio` nodes, so every transport after it decoded its
    /// `reg` with the wrong width and answered address zero.
    ///
    /// The depth is the bounded quantity here and the breadth is not: a device
    /// tree is a handful of levels deep whatever its width, so a fixed stack is
    /// the right shape.  [`MAX_DEPTH`] is far past anything real, and a blob
    /// that exceeded it reports the nodes it cannot decode rather than reading
    /// a sibling's widths.
    widths: [(u8, u8); MAX_DEPTH],
    depth: usize,
}

/// The deepest nesting this walk follows.
///
/// QEMU's `virt` tree is seven levels at its deepest (`/cpus/cpu-map/socket0/`
/// `cluster0/core0/cpu@0`).  Sixty-four is not a measurement of how deep a tree
/// may be; it is far enough past anything a generator produces that the bound
/// is never the answer to a question about a real machine.
const MAX_DEPTH: usize = 64;

impl<'a> Iterator for CompatibleIter<'a> {
    type Item = Node<'a>;

    fn next(&mut self) -> Option<Node<'a>> {
        while self.cursor < self.fdt.struct_end {
            let offset = self.cursor;
            let token = self.fdt.token(offset).ok()?;
            match token {
                TOKEN_BEGIN_NODE => {
                    let name = self.fdt.node_name(offset).ok()?;
                    self.cursor = offset + 4 + align4(name.len() + 1);

                    // The widths this node's own `reg` decodes with are the
                    // ones in force, which are its parent's.
                    let inherited = if self.depth == 0 {
                        (DEFAULT_ADDRESS_CELLS, DEFAULT_SIZE_CELLS)
                    } else {
                        self.widths[self.depth - 1]
                    };
                    let node = Node::at(&self.fdt, offset, inherited.0, inherited.1).ok()?;

                    // Its own declaration governs what follows, which is its
                    // children, and is popped when it ends.
                    let declared = node.child_cells();
                    if self.depth < MAX_DEPTH {
                        self.widths[self.depth] = declared;
                    }
                    self.depth += 1;

                    if node.is_compatible(self.wanted) {
                        return Some(node);
                    }
                }
                TOKEN_END_NODE => {
                    self.depth = self.depth.saturating_sub(1);
                    self.cursor = offset + 4;
                }
                TOKEN_NOP => self.cursor = offset + 4,
                TOKEN_PROP => {
                    let length = word(self.fdt.blob, offset + 4)? as usize;
                    self.cursor = offset + 12 + align4(length);
                }
                TOKEN_END => self.cursor = self.fdt.struct_end,
                _ => return None,
            }
        }
        None
    }
}

/// One node in the tree.
///
/// ## Two pairs of cell widths, and why they are not one
///
/// A device tree node's `#address-cells` and `#size-cells` say how wide **its
/// children's** `reg` properties are.  The node's *own* `reg` is decoded with
/// the widths its **parent** declared.
///
/// That is easy to get backwards, and getting it backwards is silent: a PCI
/// host bridge declares `#address-cells = <3>` because a PCI address is three
/// cells, but the bridge's own `reg` is an ordinary two-cell MMIO address under
/// its parent.  Reading the bridge's `reg` with three cells takes the first
/// three words, `0x40, 0x1000_0000, 0x00`, as one address of
/// `0x0040_1000_0000_0000`, which is a number, so nothing fails.
///
/// So a node carries both: [`Self::reg_cells`] for what it was given, and
/// [`Self::child_cells`] for what it gives.
#[derive(Debug, Clone, Copy)]
pub struct Node<'a> {
    fdt: Fdt<'a>,
    /// The offset of this node's `FDT_BEGIN_NODE` token.
    offset: usize,
    /// The offset of this node's `FDT_END_NODE` token.
    end: usize,
    /// Widths for **this** node's `reg`: inherited from the parent.
    reg_address_cells: u8,
    reg_size_cells: u8,
    /// Widths for **this node's children's** `reg`: this node's own
    /// `#address-cells`, or the inherited value when it declares none.
    child_address_cells: u8,
    child_size_cells: u8,
}

impl<'a> Node<'a> {
    /// Build a node from the offset of its `FDT_BEGIN_NODE` token.
    ///
    /// `reg_*` are the parent's declared widths, which this node's own `reg` is
    /// decoded with.  This node's declaration, if it has one, is kept for its
    /// children instead.
    fn at(
        fdt: &Fdt<'a>,
        offset: usize,
        reg_address_cells: u8,
        reg_size_cells: u8,
    ) -> Result<Node<'a>, Error> {
        let end = fdt.end_of_node(offset)?;
        let mut node = Node {
            fdt: *fdt,
            offset,
            end,
            reg_address_cells,
            reg_size_cells,
            child_address_cells: reg_address_cells,
            child_size_cells: reg_size_cells,
        };
        // The declaration governs the children, and only the children.
        if let Some(cells) = node.property("#address-cells").and_then(|p| p.as_u32()) {
            node.child_address_cells = cell_count(cells);
        }
        if let Some(cells) = node.property("#size-cells").and_then(|p| p.as_u32()) {
            node.child_size_cells = cell_count(cells);
        }
        Ok(node)
    }

    /// The node's name, as the blob spells it.
    ///
    /// The root's name is empty.  A node's *unit address* is part of the name,
    /// /// `pl011@9000000`, and the part after `@` is the address in
    /// hexadecimal; [`Self::unit_base`] reads it.
    pub fn name(&self) -> &'a str {
        self.fdt.node_name(self.offset).unwrap_or("")
    }

    /// The name without its unit address: `pl011` for `pl011@9000000`.
    pub fn base_name(&self) -> &'a str {
        match self.name().split_once('@') {
            Some((base, _)) => base,
            None => self.name(),
        }
    }

    /// The unit address after `@`, if the name has one.
    pub fn unit_base(&self) -> Option<u64> {
        let (_, base) = self.name().split_once('@')?;
        u64::from_str_radix(base, 16).ok()
    }

    /// The `(#address-cells, #size-cells)` that decode **this node's** `reg`.
    ///
    /// The parent's declaration, not this node's.  [`Self::child_cells`] is the
    /// other half of that pair.
    pub fn reg_cells(&self) -> (u8, u8) {
        (self.reg_address_cells, self.reg_size_cells)
    }

    /// The `(#address-cells, #size-cells)` that decode this node's
    /// **children's** `reg` properties.
    pub fn child_cells(&self) -> (u8, u8) {
        (self.child_address_cells, self.child_size_cells)
    }

    /// The value of `name`, if this node has it.
    pub fn property(&self, name: &str) -> Option<Property<'a>> {
        self.properties().find(|property| property.name == name)
    }

    /// Every property of this node, in the blob's order.
    ///
    /// Stops at the first child, because the format puts a node's properties
    /// before its children: a property token after a `FDT_BEGIN_NODE` belongs
    /// to the child.
    pub fn properties(&self) -> Properties<'a> {
        Properties {
            fdt: self.fdt,
            cursor: self.offset + 4 + align4(self.name().len() + 1),
            end: self.end,
            done: false,
        }
    }

    /// Whether `wanted` is in this node's `compatible` list.
    pub fn is_compatible(&self, wanted: &str) -> bool {
        self.property("compatible")
            .is_some_and(|property| property.has_string(wanted))
    }

    /// The child nodes, in the blob's order.
    pub fn children(&self) -> Children<'a> {
        // The first child, if any, is the first `FDT_BEGIN_NODE` after this
        // node's properties.
        let mut cursor = self.offset + 4 + align4(self.name().len() + 1);
        let mut first = None;
        while cursor < self.end {
            match self.fdt.token(cursor) {
                Ok(TOKEN_PROP) => {
                    let length = match word(self.fdt.blob, cursor + 4) {
                        Some(length) => length as usize,
                        None => break,
                    };
                    cursor += 12 + align4(length);
                }
                Ok(TOKEN_NOP) => cursor += 4,
                Ok(TOKEN_BEGIN_NODE) => {
                    first = Some(cursor);
                    break;
                }
                _ => break,
            }
        }
        Children {
            fdt: self.fdt,
            parent_end: self.end,
            cursor: first.unwrap_or(self.end),
            // A child's `reg` is decoded with *this* node's declaration, and a
            // child that declares nothing of its own passes this value on.
            address_cells: self.child_address_cells,
            size_cells: self.child_size_cells,
            done: first.is_none(),
        }
    }

    /// A child by its exact name.
    pub fn child(&self, name: &str) -> Option<Node<'a>> {
        self.children().find(|child| child.name() == name)
    }

    /// Descend a path like `/soc/pl011@9000000`.
    ///
    /// Leading and trailing slashes are ignored, so `/` and the empty string
    /// both name the root, a caller reading `stdout-path` will meet both
    /// forms.
    pub fn by_path(&self, path: &str) -> Option<Node<'a>> {
        let mut node = *self;
        for component in path.split('/').filter(|part| !part.is_empty()) {
            node = node.child(component)?;
        }
        Some(node)
    }

    /// `reg`, decoded with the widths that apply to this node.
    ///
    /// A device tree allows several `reg` entries in one property, and several
    /// `reg` properties.  Both are read: a node with two discontiguous regions
    /// is one device, and answering only the first would map half of it.
    pub fn reg(&self) -> Regs<'a> {
        Regs {
            property: self.property("reg"),
            consumed: 0,
            address_cells: self.reg_address_cells,
            size_cells: self.reg_size_cells,
        }
    }

    /// The first `reg` entry, which is what a caller asking "where is this
    /// device" wants.
    pub fn region(&self) -> Option<Reg> {
        self.reg().next()
    }

    /// Depth-first search under this node, this node included.
    fn find_descendant(&self, wanted: &str) -> Option<Node<'a>> {
        if self.is_compatible(wanted) {
            return Some(*self);
        }
        for child in self.children() {
            if let Some(found) = child.find_descendant(wanted) {
                return Some(found);
            }
        }
        None
    }
}

/// The cursor over a node's properties.
pub struct Properties<'a> {
    fdt: Fdt<'a>,
    cursor: usize,
    end: usize,
    done: bool,
}

impl<'a> Iterator for Properties<'a> {
    type Item = Property<'a>;

    fn next(&mut self) -> Option<Property<'a>> {
        if self.done {
            return None;
        }
        loop {
            if self.cursor >= self.end {
                self.done = true;
                return None;
            }
            let token = self.fdt.token(self.cursor).ok()?;
            match token {
                TOKEN_NOP => self.cursor += 4,
                TOKEN_PROP => {
                    let length = word(self.fdt.blob, self.cursor + 4)? as usize;
                    let name_offset = word(self.fdt.blob, self.cursor + 8)? as usize;
                    let value_start = self.cursor + 12;
                    let value_end = value_start.checked_add(length)?;
                    let value = self.fdt.blob.get(value_start..value_end)?;
                    let name = self.fdt.string(name_offset).ok()?;
                    self.cursor = value_end + (align4(length) - length);
                    return Some(Property { name, value });
                }
                // Properties come before children, so the first child ends
                // this node's list.
                _ => {
                    self.done = true;
                    return None;
                }
            }
        }
    }
}

/// The cursor over a node's children.
pub struct Children<'a> {
    fdt: Fdt<'a>,
    parent_end: usize,
    cursor: usize,
    address_cells: u8,
    size_cells: u8,
    done: bool,
}

impl<'a> Iterator for Children<'a> {
    type Item = Node<'a>;

    fn next(&mut self) -> Option<Node<'a>> {
        if self.done || self.cursor >= self.parent_end {
            self.done = true;
            return None;
        }
        let token = self.fdt.token(self.cursor).ok()?;
        if token != TOKEN_BEGIN_NODE {
            self.done = true;
            return None;
        }
        // The widths the parent declared are what this child's `reg` decodes
        // with; `Node::at` keeps the child's own declaration for *its*
        // children.
        let node = Node::at(&self.fdt, self.cursor, self.address_cells, self.size_cells).ok()?;
        // The next sibling begins after this node's `FDT_END_NODE`.
        self.cursor = node.end + 4;
        Some(node)
    }
}

/// The cursor over a node's `reg` entries.
///
/// One entry is `#address-cells` cells of address followed by `#size-cells`
/// cells of size.  A property with two regions holds two such groups back to
/// back, and this walks them one group at a time, with a cursor into the
/// bytes, not a fixed-size array, because the number of groups is the
/// firmware's and a buffer sized for the common case is a bound nothing
/// checked.
pub struct Regs<'a> {
    property: Option<Property<'a>>,
    consumed: usize,
    address_cells: u8,
    size_cells: u8,
}

impl Iterator for Regs<'_> {
    type Item = Reg;

    fn next(&mut self) -> Option<Reg> {
        let property = self.property?;
        let width = self.address_cells as usize + self.size_cells as usize;
        if width == 0 {
            return None;
        }
        let total = property.value.len() / 4;
        if self.consumed + width > total {
            return None;
        }

        // Read one cell at a time, accumulating: a 64-bit address is two
        // big-endian words, high first, and shifting rather than reinterpreting
        // means a 1-cell address on a 32-bit node needs no special case.
        // A PCI address's first cell is a *space selector*, not part of the
        // number: `0x0100_0000` is the I/O window and `0x0200_0000` is
        // memory.  Shifting it in gives a 96-bit value that does not fit a
        // `u64`, so the highest cell is taken as a selector and the rest as the
        // address.  A caller that wants the space reads `Reg::space`.
        let cells = property.as_cells()?.skip(self.consumed);
        let mut values = [0_u32; 2 * MAX_CELLS as usize];
        let mut seen = 0;
        for cell in cells.take(width) {
            *values.get_mut(seen)? = cell;
            seen += 1;
        }
        if seen < width {
            return None;
        }

        let address_cells = self.address_cells as usize;
        let mut space: u64 = 0;
        let mut start = 0;
        if address_cells > 2 {
            space = u64::from(values[0]);
            start = 1;
        }
        let mut address: u64 = 0;
        for cell in &values[start..address_cells] {
            address = (address << 32) | u64::from(*cell);
        }
        let mut size: u64 = 0;
        for cell in &values[address_cells..width] {
            size = (size << 32) | u64::from(*cell);
        }

        self.consumed += width;
        Some(Reg {
            address,
            size,
            space,
        })
    }
}
