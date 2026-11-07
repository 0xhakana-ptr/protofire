//! kernel/src/loader.rs
//!
//! The ELF64 reader: what a program file must say before the kernel will map
//! it into an address space.
//!
//! The parser is pure — bytes in, a layout out — and names no machine and no
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
    /// How much memory the segment occupies — `file_size` plus the zero-fill
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
    /// `e_type` is not `ET_EXEC`: this loader maps no dynamic or relocatable
    /// image, there being no linker to fix one up.
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
const PT_LOAD: u32 = 1;
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
    // Page alignment: the mapping walks page by page, and a segment that
    // straddles a page's start would put the file's bytes on the wrong page.
    if !segment.virtual_address.is_multiple_of(PAGE_SIZE)
        || !segment.file_offset.is_multiple_of(PAGE_SIZE)
        || segment.memory_size < segment.file_size
        || segment.file_offset + segment.file_size > bytes.len()
    {
        return Err(LoadError::BadSegment);
    }
    // The window check is also the overflow check: `is_user_range` does its
    // own `checked_add`, so a `vaddr + memsz` that wrapped answers "outside"
    // rather than wrapping into the window.
    if !is_user_range(segment.virtual_address, segment.memory_size) {
        return Err(LoadError::BadSegment);
    }
    // Readable is the floor — the flag bit, not an inference: a segment the
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

/// Parse `bytes` as an ELF64 program image for `expected_machine`.
///
/// Pure: no allocation, no machine, no page table — the answer is a layout
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
    if e_type != ET_EXEC {
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

    // The entry must be inside executable code the loader is about to map: an
    // entry anywhere else is an address the program can never fetch from, and
    // the boot would learn it as a fault far from the cause.
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
