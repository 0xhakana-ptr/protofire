//! kernel/src/loader/mod.rs
//!
//! The ELF64 reader: what a program file must say before the kernel will map
//! it into an address space.
//!
//! ## Where this file ends and `programs` begins
//!
//! This module **reads** an image and says what it is: the entry point, the
//! segments, and the page plan for each.  It takes bytes and answers a value.
//! It never allocates a frame, never touches a page table, and never asks the
//! filesystem for anything, which is why every test here runs on a host
//! against ELF bytes built one field at a time.
//!
//! [`crate::programs`] is the other half and the opposite kind of code: it is
//! what the **boot** does with a program, pick a space, copy machine code in,
//! hand a pipe end through the stack, and enter it.  The exec path inside the
//! scheduler is the third caller: it builds a space from a file for a `fork`
//! or an `ExecProcess`.  Both of them call [`load`] and then map what it
//! answered; neither one parses a byte of ELF itself.
//!
//! So the test of the split is what a caller needs: to know whether a file is
//! a program this kernel can run, ask this module; to actually run one, the
//! caller must own the address space and the scheduler, and this module owns
//! neither.
//!
//! The parser is pure, bytes in, a layout out, and names no machine and no
//! page table, which is why its tests run on a host against ELF files built
//! one field at a time.  The *machine* answers one question only, which
//! program images are for: the expected `e_machine`, handed in by the caller
//! from `arch`'s own constant, because a loader that named a machine would be
//! a kernel file wearing an architecture's badge.
//!
//! What is accepted is deliberately narrow.  A fixed-base `ET_EXEC` with
//! page-aligned `PT_LOAD` segments and no writable-executable page is exactly
//! what this tree's toolchain produces, and everything else is refused with a
//! named reason rather than interpreted: a loader that "handles" formats it
//! was not given is a loader that maps bytes whose meaning it guessed.

use crate::address_space::is_user_range;
use paging::PAGE_SIZE;

/// The most bytes one program image may carry.
///
/// The exec path reads a file **whole** before it maps any of it, and the
/// bound is what makes that honest: a file this size is one the caller
/// refuses before it allocates.  A quarter of the boot disk, the delivery
/// channel, is the honest ceiling, because a program bigger than the disk
/// that carries it cannot be delivered at all.
pub const MAX_IMAGE_BYTES: usize = 256 * 1024;

/// The most `PT_LOAD` segments one accepted image may carry.
///
/// A fixed bound rather than a growable list: the segments come from a file a
/// caller handed over, and a count the file chooses is a count the caller
/// chooses.  This tree's toolchain emits two or three; the bound is generous
/// relative to that, and an image past it is one whose layout is refused
/// rather than one whose segments are silently dropped.
pub const MAX_SEGMENTS: usize = 8;

/// One `PT_LOAD` segment, as the loader will map it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    /// The virtual address the segment was linked at, page-aligned.
    pub virtual_address: usize,
    /// Where the segment's file bytes begin in the image.
    pub file_offset: usize,
    /// How many bytes the file carries for this segment.
    pub file_size: usize,
    /// How much memory the segment occupies, `file_size` plus the zero-fill
    /// a `memsz > filesz` segment asks for, which is what a BSS is.
    pub memory_size: usize,
    /// Whether the segment may be written.
    pub writable: bool,
    /// Whether the segment may be executed.
    pub executable: bool,
}

/// A program image the loader accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Image {
    /// The address the program starts at, inside one of the segments.
    pub entry: usize,
    /// The accepted `PT_LOAD` segments, in file order.
    pub segments: [Segment; MAX_SEGMENTS],
    /// How many of `segments` are in use.
    pub segment_count: usize,
}

impl Image {
    /// The segments, as a slice.
    pub fn segments(&self) -> &[Segment] {
        &self.segments[..self.segment_count]
    }

    /// The last byte of the last segment, which is where the stack the exec
    /// maps goes: one page above the image's own end.
    pub fn image_top(&self) -> Option<usize> {
        self.segments()
            .iter()
            .map(|segment| segment.virtual_address + segment.memory_size)
            .max()
    }
}

/// Why an image was refused, as the words a boot line can carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadError {
    /// Fewer than the ELF header's 64 bytes.
    TooShort,
    /// The bytes do not begin with the ELF magic.
    BadMagic,
    /// The image is 32-bit or otherwise not this kernel's width.
    NotElf64,
    /// The image is big-endian; this kernel reads little-endian.
    BadEndian,
    /// `e_type` is neither `ET_EXEC` nor a dynamic-free `ET_DYN`: this loader
    /// maps no image that expects relocation processing or an interpreter,
    /// there being no linker and no interpreter to give it what it wants.
    NotExecutable,
    /// `e_machine` is not the machine the caller expected.
    WrongMachine,
    /// The program-header table is missing, undersized, or past the file.
    BadProgramHeaders,
    /// More `PT_LOAD` segments than [`MAX_SEGMENTS`].
    TooManySegments,
    /// A segment this loader will not map: misaligned, past the file, beyond
    /// the user window, unreadable, writable-and-executable, or overlapping a
    /// previous one.
    BadSegment,
    /// The entry point is not inside an executable segment.
    EntryOutsideCode,
}

impl LoadError {
    /// The reason, as the words a log line carries.
    pub fn as_str(self) -> &'static str {
        match self {
            LoadError::TooShort => "truncated",
            LoadError::BadMagic => "not an elf image",
            LoadError::NotElf64 => "not a 64-bit elf image",
            LoadError::BadEndian => "not little-endian",
            LoadError::NotExecutable => "not a fixed-base executable",
            LoadError::WrongMachine => "built for another machine",
            LoadError::BadProgramHeaders => "no readable program-header table",
            LoadError::TooManySegments => "too many loadable segments",
            LoadError::BadSegment => "a segment the loader will not map",
            LoadError::EntryOutsideCode => "the entry point is outside the code",
        }
    }
}

/// The ELF header's own constants, spelled once.
const MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
const CLASS_ELF64: u8 = 2;
const DATA_LITTLE_ENDIAN: u8 = 1;
const ET_EXEC: u16 = 2;
const ET_DYN: u16 = 3;
const PT_LOAD: u32 = 1;
const PT_DYNAMIC: u32 = 2;
const PT_INTERP: u32 = 3;
const PROGRAM_HEADER_SIZE: usize = 56;
const HEADER_SIZE: usize = 64;
const FLAG_EXECUTE: u32 = 1;
const FLAG_WRITE: u32 = 2;
const FLAG_READ: u32 = 4;

/// Read a u16 at `offset`, little-endian, or fail.
fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

/// Read a u32 at `offset`, little-endian, or fail.
fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

/// Read a u64 at `offset`, little-endian, or fail.
fn u64_at(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}

/// Read one `PT_LOAD` program header at `offset`, or fail.
fn segment_at(bytes: &[u8], offset: usize) -> Option<(Segment, u32)> {
    let p_type = u32_at(bytes, offset)?;
    let p_flags = u32_at(bytes, offset + 4)?;
    let p_offset = u64_at(bytes, offset + 8)?;
    let p_vaddr = u64_at(bytes, offset + 16)?;
    let p_filesz = u64_at(bytes, offset + 32)?;
    let p_memsz = u64_at(bytes, offset + 40)?;

    if p_type != PT_LOAD {
        return None;
    }

    let _ = u64_at(bytes, offset + 24)?; // p_paddr, ignored: the vaddr is the truth.
    let _ = u64_at(bytes, offset + 48)?; // p_align, ignored: alignment is checked directly.

    Some((
        Segment {
            virtual_address: p_vaddr as usize,
            file_offset: p_offset as usize,
            file_size: p_filesz as usize,
            memory_size: p_memsz as usize,
            writable: p_flags & FLAG_WRITE != 0,
            executable: p_flags & FLAG_EXECUTE != 0,
        },
        p_flags,
    ))
}

/// Validate one segment against the image it came from and the rules this
/// kernel maps by, answering it unchanged.
fn checked(segment: Segment, flags: u32, bytes: &[u8]) -> Result<Segment, LoadError> {
    // Page congruence: the mapping walks page by page, and the file offset
    // and the virtual address must agree *within* a page or the file's bytes
    // would land on the wrong one.  Real linkers emit offsets congruent to
    // the addresses (padding the file as little as possible), not individually
    // aligned, requiring alignment would refuse every real image.
    //
    // The file-range test uses `checked_add`, and that is the point of this
    // change.  `file_offset + file_size` is a sum of two numbers the **file**
    // chose: a shaped ELF can put `u64::MAX` in `p_offset`, and the debug
    // build then panics inside the kernel with an overflow while the release
    // build wraps to a small number that passes the length test.  The window
    // check below is not this check, which is what the comment here used to
    // claim: it covers `vaddr + memsz`, two different sums.  A program that
    // writes a shaped file into the filesystem and calls `ExecProcess`
    // reaches both.
    let Some(file_end) = segment.file_offset.checked_add(segment.file_size) else {
        return Err(LoadError::BadSegment);
    };
    if segment.file_offset % PAGE_SIZE != segment.virtual_address % PAGE_SIZE
        || segment.memory_size < segment.file_size
        || file_end > bytes.len()
    {
        return Err(LoadError::BadSegment);
    }
    // The window check is also the overflow check for `vaddr + memsz`:
    // `is_user_range` does its own `checked_add`, so a sum that wrapped
    // answers "outside" rather than wrapping into the window.  That is a
    // property of the function and not of this caller, which is why `pages`,
    // `overlaps`, the entry test and the dynamic test may add the two fields
    // without their own checks: every one of them runs on a segment this
    // function admitted.  A future caller that builds a `Segment` some other
    // way does not get that guarantee, which is what this paragraph is for.
    if !is_user_range(segment.virtual_address, segment.memory_size) {
        return Err(LoadError::BadSegment);
    }
    // Readable is the floor, the flag bit, not an inference: a segment the
    // program cannot read is not a segment this toolchain produces, and
    // mapping one would be interpreting a flag combination the loader has no
    // story for.
    if flags & FLAG_READ == 0 {
        return Err(LoadError::BadSegment);
    }
    // W^X: a page both written and executed is the one permission pair a
    // kernel refuses, because the program it belongs to is the program that
    // can rewrite its own code.
    if segment.writable && segment.executable {
        return Err(LoadError::BadSegment);
    }
    Ok(segment)
}

/// Whether two accepted segments' pages overlap.
fn overlaps(a: &Segment, b: &Segment) -> bool {
    // The loader's window check has already refused every segment whose
    // `vaddr + memsz` would overflow, so plain addition cannot wrap here.
    a.virtual_address < b.virtual_address + b.memory_size
        && b.virtual_address < a.virtual_address + a.memory_size
}

/// One page's worth of a segment's mapping.
///
/// The loader's segments are *ranges*, and the mapping walks pages: which
/// page, which file bytes to copy into the frame (none for a page the file
/// does not reach, BSS), and how many.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PagePlan {
    /// The page-aligned virtual address the frame maps at.
    pub virtual_address: usize,
    /// Where the copied bytes begin in the image file.
    pub file_offset: usize,
    /// How many bytes to copy from the file into the frame.  The frame the
    /// pool hands out is already zeroed, so the rest of the page is BSS by
    /// construction.
    pub copy_len: usize,
    /// Where in the **frame** the copied bytes land: the segment's own start
    /// can sit mid-page, and a plan whose segment begins `0x78` bytes into
    /// the page copies at frame offset `0x78`, the bytes before it belonging
    /// to no segment.
    pub frame_offset: usize,
}

/// The pages one segment maps, yielded lowest first.
///
/// A plain iterator rather than an array: the page count is
/// `ceil((vaddr + memsz) / PAGE) - (vaddr / PAGE)`, which no fixed bound fits
/// honestly, and the caller allocates one frame per yield.
#[derive(Debug, Clone, Copy)]
pub struct SegmentPages {
    /// The segment's own start: the first page's copy begins here, because
    /// the bytes before it in the frame belong to no segment.
    vaddr: usize,
    /// The next page-aligned address to yield.
    next: usize,
    /// The segment's end, exclusive.
    end: usize,
    /// The file offset that corresponds to `vaddr`.
    file_offset: usize,
    /// The file offset where the segment's file bytes end, past this, the
    /// memory is the zero-fill.
    file_end: usize,
}

impl Iterator for SegmentPages {
    type Item = PagePlan;

    fn next(&mut self) -> Option<PagePlan> {
        if self.next >= self.end {
            return None;
        }
        let page_start = self.next;
        let page_end = (page_start + PAGE_SIZE) & !(PAGE_SIZE - 1);
        // The segment's portion of this page: the bytes before `vaddr` and
        // past `end` belong to no segment, and the frame is zeroed already.
        let memory_lo = self.vaddr.max(page_start);
        let memory_hi = self.end.min(page_end);
        // The file position that corresponds to `memory_lo`, and the copy's
        // length clipped at the file's end, everything past it is the
        // zero-fill.
        let file_at = self.file_offset + (memory_lo - self.vaddr);
        let copy_len = memory_hi - memory_lo;
        let copy_len = copy_len.min(self.file_end.saturating_sub(file_at));
        self.next = page_end;
        Some(PagePlan {
            virtual_address: page_start,
            file_offset: file_at,
            copy_len,
            frame_offset: memory_lo - page_start,
        })
    }
}

/// The pages one accepted segment maps, lowest first.
///
/// The first page typically carries the segment's own start inside it, a
/// segment whose `vaddr` is `...078` maps its first frame at `...000`, with
/// the file's bytes beginning `0x78` bytes into the frame and nothing before
/// them, and the last page is BSS whenever `memsz` outruns `filesz`.
pub fn pages(segment: &Segment) -> SegmentPages {
    SegmentPages {
        vaddr: segment.virtual_address,
        next: segment.virtual_address & !(PAGE_SIZE - 1),
        end: segment.virtual_address + segment.memory_size,
        file_offset: segment.file_offset,
        file_end: segment.file_offset + segment.file_size,
    }
}

/// Parse `bytes` as an ELF64 program image for `expected_machine`.
///
/// Pure: no allocation, no machine, no page table, the answer is a layout
/// the caller maps.  Every refusal is a named [`LoadError`], and every
/// accepted segment has been checked against the file it came from and the
/// window it will be mapped into, so the caller's mapping loop can be as
/// plain as the layout it was handed.
pub fn load(bytes: &[u8], expected_machine: u16) -> Result<Image, LoadError> {
    if bytes.len() < HEADER_SIZE {
        return Err(LoadError::TooShort);
    }
    if bytes[..4] != MAGIC {
        return Err(LoadError::BadMagic);
    }
    if bytes[4] != CLASS_ELF64 {
        return Err(LoadError::NotElf64);
    }
    if bytes[5] != DATA_LITTLE_ENDIAN {
        return Err(LoadError::BadEndian);
    }
    let e_type = u16_at(bytes, 16).ok_or(LoadError::TooShort)?;
    let e_machine = u16_at(bytes, 18).ok_or(LoadError::TooShort)?;
    // ET_EXEC is the fixed-base shape.  ET_DYN is accepted **conditionally**:
    // a position-independent *file* whose bytes are linked at a fixed base
    // and carry no dynamic section is the same thing at load time, the bytes
    // are the whole truth, no relocation processing will happen, and
    // rust-lld emits exactly that for a ring-3 program.  A DYN image with a
    // dynamic segment or an interpreter is a file the loader would have to
    // fix up, and no fixup exists here.
    let allow_dynamic = e_type == ET_DYN;
    if e_type != ET_EXEC && !allow_dynamic {
        return Err(LoadError::NotExecutable);
    }
    if e_machine != expected_machine {
        return Err(LoadError::WrongMachine);
    }
    let entry = u64_at(bytes, 24).ok_or(LoadError::TooShort)? as usize;
    let e_phoff = u64_at(bytes, 32).ok_or(LoadError::TooShort)? as usize;
    let e_phentsize = u16_at(bytes, 54).ok_or(LoadError::TooShort)? as usize;
    let e_phnum = u16_at(bytes, 56).ok_or(LoadError::TooShort)? as usize;

    if e_phentsize != PROGRAM_HEADER_SIZE || e_phnum == 0 {
        return Err(LoadError::BadProgramHeaders);
    }
    let table_end = e_phoff
        .checked_add(
            e_phnum
                .checked_mul(PROGRAM_HEADER_SIZE)
                .ok_or(LoadError::BadProgramHeaders)?,
        )
        .ok_or(LoadError::BadProgramHeaders)?;
    if table_end > bytes.len() {
        return Err(LoadError::BadProgramHeaders);
    }

    let mut image = Image {
        entry,
        segments: [Segment {
            virtual_address: 0,
            file_offset: 0,
            file_size: 0,
            memory_size: 0,
            writable: false,
            executable: false,
        }; MAX_SEGMENTS],
        segment_count: 0,
    };

    for header in 0..e_phnum {
        let Some((segment, flags)) = segment_at(bytes, e_phoff + header * PROGRAM_HEADER_SIZE)
        else {
            continue;
        };
        if image.segment_count == MAX_SEGMENTS {
            return Err(LoadError::TooManySegments);
        }
        let segment = checked(segment, flags, bytes)?;
        // Segments arrive in file order and must not overlap: an image whose
        // segments overlap is one whose bytes mean two things, and a mapping
        // loop would map the last one over the first.
        if image.segments[..image.segment_count]
            .iter()
            .any(|mapped| overlaps(mapped, &segment))
        {
            return Err(LoadError::BadSegment);
        }
        image.segments[image.segment_count] = segment;
        image.segment_count += 1;
    }

    if image.segment_count == 0 {
        return Err(LoadError::BadProgramHeaders);
    }

    // A DYN image's honesty check, after the LOADs are known.  A dynamic
    // segment whose bytes a mapped segment **carries** is dead data: nothing
    // reads it, no relocation is processed, and the loader maps it the way it
    // maps any other byte.  A dynamic segment (or an interpreter) *outside*
    // every mapped segment names machinery this loader does not have
    // relocation processing, another program to load the file, and that is a
    // refusal, by name.
    //
    // Both sums are checked, and both had to be.  `at` is `e_phoff + header *
    // size`, which the table-end test above already bounds, but `p_offset +
    // p_filesz` is read straight out of a header **before** `checked` sees the
    // segment, so nothing has vouched for it: a dynamic header naming
    // `u64::MAX` panics a debug kernel here and wraps in a release one, and the
    // wrapped number is what the containment test would then judge.
    for header in 0..e_phnum {
        let at = e_phoff
            .checked_add(
                header
                    .checked_mul(PROGRAM_HEADER_SIZE)
                    .ok_or(LoadError::BadProgramHeaders)?,
            )
            .ok_or(LoadError::BadProgramHeaders)?;
        let p_type = u32_at(bytes, at).ok_or(LoadError::BadProgramHeaders)?;
        if p_type != PT_DYNAMIC && p_type != PT_INTERP {
            continue;
        }
        let p_offset = u64_at(bytes, at + 8).ok_or(LoadError::BadProgramHeaders)? as usize;
        let p_filesz = u64_at(bytes, at + 32).ok_or(LoadError::BadProgramHeaders)? as usize;
        let Some(segment_end) = p_offset.checked_add(p_filesz) else {
            return Err(LoadError::NotExecutable);
        };
        if p_type == PT_INTERP
            || !image.segments().iter().any(|segment| {
                let start = segment.file_offset;
                // `checked` admitted this segment, so its own sum did not
                // overflow; the addition is safe here for that reason.
                let end = start + segment.file_size;
                p_offset >= start && segment_end <= end
            })
        {
            return Err(LoadError::NotExecutable);
        }
    }

    // The entry must be inside executable code the loader is about to map: an
    // entry anywhere else is an address the program can never fetch from, and
    // the boot would learn it as a fault far from the cause.
    //
    // The range's end is a plain addition because `checked` admitted every
    // segment here and its window test is what proves `vaddr + memsz` does not
    // wrap.  A `checked_add` that fell back to "not inside" would say the same
    // thing twice and read as if the earlier check could not be trusted.
    let inside_code = image.segments().iter().any(|segment| {
        segment.executable
            && (segment.virtual_address..segment.virtual_address + segment.memory_size)
                .contains(&image.entry)
    });
    if !inside_code {
        return Err(LoadError::EntryOutsideCode);
    }

    Ok(image)
}

#[cfg(test)]
mod tests;
