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

/// The most bytes one program image may carry.
///
/// The exec path reads a file **whole** before it maps any of it, and the
/// bound is what makes that honest: a file this size is one the caller
/// refuses before it allocates.  A quarter of the boot disk — the delivery
/// channel — is the honest ceiling, because a program bigger than the disk
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
    // aligned — requiring alignment would refuse every real image.
    if segment.file_offset % PAGE_SIZE != segment.virtual_address % PAGE_SIZE
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

/// One page's worth of a segment's mapping.
///
/// The loader's segments are *ranges*, and the mapping walks pages: which
/// page, which file bytes to copy into the frame (none for a page the file
/// does not reach — BSS), and how many.
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
    /// The file offset where the segment's file bytes end — past this, the
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
        // length clipped at the file's end — everything past it is the
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
/// The first page typically carries the segment's own start inside it — a
/// segment whose `vaddr` is `...078` maps its first frame at `...000`, with
/// the file's bytes beginning `0x78` bytes into the frame and nothing before
/// them — and the last page is BSS whenever `memsz` outruns `filesz`.
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
    // ET_EXEC is the fixed-base shape.  ET_DYN is accepted **conditionally**:
    // a position-independent *file* whose bytes are linked at a fixed base
    // and carry no dynamic section is the same thing at load time — the bytes
    // are the whole truth, no relocation processing will happen — and
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
    // every mapped segment names machinery this loader does not have —
    // relocation processing, another program to load the file — and that is a
    // refusal, by name.
    for header in 0..e_phnum {
        let at = e_phoff + header * PROGRAM_HEADER_SIZE;
        let p_type = u32_at(bytes, at).ok_or(LoadError::BadProgramHeaders)?;
        if p_type != PT_DYNAMIC && p_type != PT_INTERP {
            continue;
        }
        let p_offset = u64_at(bytes, at + 8).ok_or(LoadError::BadProgramHeaders)? as usize;
        let p_filesz = u64_at(bytes, at + 32).ok_or(LoadError::BadProgramHeaders)? as usize;
        if p_type == PT_INTERP
            || !image.segments().iter().any(|segment| {
                let start = segment.file_offset;
                let end = start + segment.file_size;
                p_offset >= start && p_offset + p_filesz <= end
            })
        {
            return Err(LoadError::NotExecutable);
        }
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
mod tests {
    //! kernel/src/loader/tests.rs
    //!
    //! The loader's tests: ELF files built one field at a time, so a test that
    //! asserts a refusal can point at the field that earns it.
    //!
    //! A real toolchain's output is the wrong fixture here — it would be right
    //! in ways nobody wrote down, and a parser that passed on it might still
    //! refuse the image the linker emits after one flag changes.  Every image
    //! below is assembled by [`elf`], whose arguments are the fields the loader
    //! reads, so each case names the bytes it varies.  The helper writes only
    //! what fits in the file it builds, which is what makes "file bytes past
    //! the file's own end" a state the fixture can produce rather than one the
    //! helper repairs.

    use super::LoadError;
    use super::MAX_IMAGE_BYTES;
    use super::MAX_SEGMENTS;
    use super::load;
    use super::pages;
    use alloc::vec;
    use alloc::vec::Vec;
    use paging::PAGE_SIZE;

    /// A machine the tests present as "the machine this build is for".
    const MACHINE: u16 = 62;

    /// One PT_LOAD segment's description, as [`elf`] encodes it.
    struct SegmentSpec {
        vaddr: u64,
        offset: u64,
        filesz: u64,
        memsz: u64,
        flags: u32,
    }

    const FLAG_X: u32 = 1;
    const FLAG_W: u32 = 2;
    const FLAG_R: u32 = 4;

    /// The file offset past the header block: a real linker's segments begin
    /// after the ELF header and the program-header table, and offset 0 would
    /// put a segment's bytes over the magic itself.
    const FIRST_OFFSET: u64 = 0x1000;

    /// Build a minimal ELF64 image: a header, one program header per segment,
    /// and whatever of the segments' file bytes the file is long enough to
    /// hold.
    fn elf(machine: u16, entry: u64, segments: &[SegmentSpec]) -> Vec<u8> {
        // The file is as long as its longest segment needs: a real file carries
        // its segments' bytes.  The one truncated-file test shortens the
        // finished image explicitly rather than this helper guessing.
        let header_end = 64 + segments.len() * 56;
        let data_end = segments
            .iter()
            .map(|segment| segment.offset as usize + segment.filesz as usize)
            .max()
            .unwrap_or(header_end);
        let mut bytes = vec![0u8; header_end.max(data_end)];
        bytes[..4].copy_from_slice(&[0x7F, b'E', b'L', b'F']);
        bytes[4] = 2; // class: ELF64
        bytes[5] = 1; // data: little-endian
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // e_type: ET_EXEC
        bytes[18..20].copy_from_slice(&machine.to_le_bytes());
        bytes[24..32].copy_from_slice(&entry.to_le_bytes()); // e_entry
        bytes[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        bytes[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        bytes[56..58].copy_from_slice(&(segments.len() as u16).to_le_bytes()); // e_phnum

        for (index, segment) in segments.iter().enumerate() {
            let at = 64 + index * 56;
            bytes[at..at + 4].copy_from_slice(&1u32.to_le_bytes()); // p_type: PT_LOAD
            bytes[at + 4..at + 8].copy_from_slice(&segment.flags.to_le_bytes());
            bytes[at + 8..at + 16].copy_from_slice(&segment.offset.to_le_bytes());
            bytes[at + 16..at + 24].copy_from_slice(&segment.vaddr.to_le_bytes());
            bytes[at + 32..at + 40].copy_from_slice(&segment.filesz.to_le_bytes());
            bytes[at + 40..at + 48].copy_from_slice(&segment.memsz.to_le_bytes());
            // The segment's file bytes, distinguishable by segment so a mix-up
            // is visible.
            for offset in 0..segment.filesz as usize {
                let at = segment.offset as usize + offset;
                bytes[at] = (index as u8).wrapping_add(0x40);
            }
        }
        bytes
    }

    /// The ordinary image: one executable segment at the base, page-aligned.
    fn good_image() -> Vec<u8> {
        elf(
            MACHINE,
            0x8040000008,
            &[SegmentSpec {
                vaddr: 0x8040000000,
                offset: FIRST_OFFSET,
                filesz: 0x1000,
                memsz: 0x1000,
                flags: FLAG_R | FLAG_X,
            }],
        )
    }

    #[test]
    fn an_ordinary_image_loads_with_its_entry_and_segment() {
        let image = load(&good_image(), MACHINE).expect("the ordinary image loads");
        assert_eq!(image.entry, 0x8040000008);
        assert_eq!(image.segment_count, 1);
        let segment = image.segments()[0];
        assert_eq!(segment.virtual_address, 0x8040000000);
        assert_eq!(segment.file_offset, FIRST_OFFSET as usize);
        assert_eq!(segment.file_size, 0x1000);
        assert_eq!(segment.memory_size, 0x1000);
        assert!(segment.executable);
        assert!(!segment.writable);
    }

    #[test]
    fn a_bss_segment_loads_with_memory_past_the_file() {
        let image = load(
            &elf(
                MACHINE,
                0x8040000008,
                &[
                    SegmentSpec {
                        vaddr: 0x8040000000,
                        offset: FIRST_OFFSET,
                        filesz: 0x1000,
                        memsz: 0x1000,
                        flags: FLAG_R | FLAG_X,
                    },
                    SegmentSpec {
                        vaddr: 0x8040001000,
                        offset: 0x2000,
                        filesz: 0x100,
                        memsz: 0x2000,
                        flags: FLAG_R | FLAG_W,
                    },
                ],
            ),
            MACHINE,
        )
        .expect("two segments load");
        assert_eq!(image.segment_count, 2);
        let data = image.segments()[1];
        assert!(data.writable);
        assert!(!data.executable);
        assert_eq!(data.file_size, 0x100);
        assert_eq!(data.memory_size, 0x2000, "the BSS is the zero-fill");
    }

    #[test]
    fn every_truncation_and_wrong_field_is_refused_by_name() {
        let good = good_image();

        let mut short = good.clone();
        short.truncate(32);
        assert_eq!(load(&short, MACHINE), Err(LoadError::TooShort));

        let mut magic = good.clone();
        magic[0] = 0x00;
        assert_eq!(load(&magic, MACHINE), Err(LoadError::BadMagic));

        let mut class = good.clone();
        class[4] = 1; // ELF32
        assert_eq!(load(&class, MACHINE), Err(LoadError::NotElf64));

        let mut endian = good.clone();
        endian[5] = 2; // big-endian
        assert_eq!(load(&endian, MACHINE), Err(LoadError::BadEndian));

        let mut core = good.clone();
        core[16..18].copy_from_slice(&4u16.to_le_bytes()); // ET_CORE
        assert_eq!(load(&core, MACHINE), Err(LoadError::NotExecutable));

        // ET_DYN with a dynamic segment *outside* every mapped segment: the
        // file expects relocation processing, which no loader here performs.
        // (A dynamic segment a LOAD carries is dead data, and loads — the real
        // linker's own shape.)
        let mut dynamic = elf(
            MACHINE,
            0x8040000008,
            &[SegmentSpec {
                vaddr: 0x8040000000,
                offset: FIRST_OFFSET,
                filesz: 0x1000,
                memsz: 0x1000,
                flags: FLAG_R | FLAG_X,
            }],
        );
        dynamic[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
        // A second program header, PT_DYNAMIC at an offset no LOAD covers.
        dynamic[120..124].copy_from_slice(&2u32.to_le_bytes());
        dynamic[128..136].copy_from_slice(&0xF000u64.to_le_bytes()); // p_offset
        dynamic[160..168].copy_from_slice(&0x100u64.to_le_bytes()); // p_filesz
        dynamic[56..58].copy_from_slice(&2u16.to_le_bytes()); // e_phnum: 2
        assert_eq!(load(&dynamic, MACHINE), Err(LoadError::NotExecutable));

        let mut machine = good.clone();
        machine[18..20].copy_from_slice(&183u16.to_le_bytes());
        assert_eq!(load(&machine, MACHINE), Err(LoadError::WrongMachine));

        let mut phentsize = good.clone();
        phentsize[54..56].copy_from_slice(&64u16.to_le_bytes());
        assert_eq!(load(&phentsize, MACHINE), Err(LoadError::BadProgramHeaders));

        let mut phnum = good.clone();
        phnum[56..58].copy_from_slice(&0u16.to_le_bytes());
        assert_eq!(load(&phnum, MACHINE), Err(LoadError::BadProgramHeaders));

        // A program-header table whose end runs past the file.
        let mut phoff = good.clone();
        phoff[32..40].copy_from_slice(&0xFFFF_0000u64.to_le_bytes());
        assert_eq!(load(&phoff, MACHINE), Err(LoadError::BadProgramHeaders));

        // No PT_LOAD at all: the type field is the segment's own.
        let mut no_load = good.clone();
        no_load[64..68].copy_from_slice(&6u32.to_le_bytes()); // PT_PHDR
        assert_eq!(load(&no_load, MACHINE), Err(LoadError::BadProgramHeaders));
    }

    #[test]
    fn the_machine_check_is_the_callers_answer_not_the_loaders() {
        // The same bytes load when the caller expects the machine they name:
        // the loader has no machine of its own to be right about.
        let image = elf(
            183,
            0x8040000008,
            &[SegmentSpec {
                vaddr: 0x8040000000,
                offset: FIRST_OFFSET,
                filesz: 0x1000,
                memsz: 0x1000,
                flags: FLAG_R | FLAG_X,
            }],
        );
        assert!(load(&image, 183).is_ok(), "the expected machine loads");
        assert_eq!(load(&image, 62), Err(LoadError::WrongMachine));
    }

    #[test]
    fn segments_the_loader_will_not_map_are_refused_by_name() {
        // Misaligned virtual address.
        assert_eq!(
            load(
                &elf(
                    MACHINE,
                    0x8040000008,
                    &[SegmentSpec {
                        vaddr: 0x8040000001,
                        offset: FIRST_OFFSET,
                        filesz: 0x1000,
                        memsz: 0x1000,
                        flags: FLAG_R | FLAG_X,
                    }],
                ),
                MACHINE,
            ),
            Err(LoadError::BadSegment),
            "the entry check never runs: the segment refuses first"
        );

        // Writable and executable: the one permission pair a kernel refuses.
        assert_eq!(
            load(
                &elf(
                    MACHINE,
                    0x8040000008,
                    &[SegmentSpec {
                        vaddr: 0x8040000000,
                        offset: FIRST_OFFSET,
                        filesz: 0x1000,
                        memsz: 0x1000,
                        flags: FLAG_R | FLAG_W | FLAG_X,
                    }],
                ),
                MACHINE,
            ),
            Err(LoadError::BadSegment),
            "W^X is the policy"
        );

        // No read permission.
        assert_eq!(
            load(
                &elf(
                    MACHINE,
                    0x8040000008,
                    &[SegmentSpec {
                        vaddr: 0x8040000000,
                        offset: FIRST_OFFSET,
                        filesz: 0x1000,
                        memsz: 0x1000,
                        flags: FLAG_X,
                    }],
                ),
                MACHINE,
            ),
            Err(LoadError::BadSegment)
        );

        // File bytes past the file's own end: the file is shortened after the
        // image is built, which is what a truncated read delivers.
        let mut truncated = elf(
            MACHINE,
            0x8040000008,
            &[SegmentSpec {
                vaddr: 0x8040000000,
                offset: FIRST_OFFSET,
                filesz: 0x4000,
                memsz: 0x4000,
                flags: FLAG_R | FLAG_X,
            }],
        );
        truncated.truncate(0x2000);
        assert_eq!(load(&truncated, MACHINE), Err(LoadError::BadSegment));

        // Beyond the user window: the loader maps into one window and nowhere
        // else.
        assert_eq!(
            load(
                &elf(
                    MACHINE,
                    0x8084000008,
                    &[SegmentSpec {
                        vaddr: 0x1_0000_0000_0000,
                        offset: FIRST_OFFSET,
                        filesz: 0x1000,
                        memsz: 0x1000,
                        flags: FLAG_R | FLAG_X,
                    }],
                ),
                MACHINE,
            ),
            Err(LoadError::BadSegment)
        );

        // memsz smaller than filesz: the file carries bytes memory does not
        // hold.
        assert_eq!(
            load(
                &elf(
                    MACHINE,
                    0x8040000008,
                    &[SegmentSpec {
                        vaddr: 0x8040000000,
                        offset: FIRST_OFFSET,
                        filesz: 0x2000,
                        memsz: 0x1000,
                        flags: FLAG_R | FLAG_X,
                    }],
                ),
                MACHINE,
            ),
            Err(LoadError::BadSegment)
        );

        // Two segments whose pages overlap.
        let overlap = elf(
            MACHINE,
            0x8040000008,
            &[
                SegmentSpec {
                    vaddr: 0x8040000000,
                    offset: FIRST_OFFSET,
                    filesz: 0x2000,
                    memsz: 0x2000,
                    flags: FLAG_R | FLAG_X,
                },
                SegmentSpec {
                    vaddr: 0x8040001000,
                    offset: 0x2000,
                    filesz: 0x1000,
                    memsz: 0x1000,
                    flags: FLAG_R | FLAG_W,
                },
            ],
        );
        assert_eq!(load(&overlap, MACHINE), Err(LoadError::BadSegment));
    }

    #[test]
    fn a_congruent_segment_loads_where_a_stranger_is_refused() {
        // The shape a real linker emits: file offset and vaddr agree *within*
        // the page (0x78 ≡ 0x78) without either being page-aligned.  The first
        // page's bytes begin 0x78 bytes into the frame, which is exactly what
        // the congruence check is for.
        let image = load(
            &elf(
                MACHINE,
                0x8040000078,
                &[SegmentSpec {
                    vaddr: 0x8040000078,
                    offset: 0x1078,
                    filesz: 0x1000,
                    memsz: 0x1000,
                    flags: FLAG_R | FLAG_X,
                }],
            ),
            MACHINE,
        )
        .expect("a congruent segment loads");
        assert_eq!(image.segments()[0].virtual_address, 0x8040000078);

        // The same shape broken: the offset moved by one page *and one byte*,
        // so the two no longer agree within the page — the file's bytes would
        // land one byte off.
        assert_eq!(
            load(
                &elf(
                    MACHINE,
                    0x8040000078,
                    &[SegmentSpec {
                        vaddr: 0x8040000078,
                        offset: 0x2079,
                        filesz: 0x1000,
                        memsz: 0x1000,
                        flags: FLAG_R | FLAG_X,
                    }],
                ),
                MACHINE,
            ),
            Err(LoadError::BadSegment)
        );
    }

    #[test]
    fn the_page_plan_slices_a_congruent_segment_honestly() {
        // The x86_64 linker's own shape: text at ...078, one page's head holds
        // the file's bytes and the second page finishes them.
        let image = load(
            &elf(
                MACHINE,
                0x8040000078,
                &[SegmentSpec {
                    vaddr: 0x8040000078,
                    offset: 0x1078,
                    filesz: 0xf96,
                    memsz: 0xf96,
                    flags: FLAG_R | FLAG_X,
                }],
            ),
            MACHINE,
        )
        .expect("the congruent image loads");
        let pages: alloc::vec::Vec<_> = crate::loader::pages(&image.segments()[0]).collect();
        assert_eq!(pages.len(), 2, "0x78 + 0xf96 spans two pages");
        assert_eq!(pages[0].virtual_address, 0x8040000000);
        assert_eq!(pages[0].file_offset, 0x1078);
        assert_eq!(
            pages[0].copy_len,
            0x1000 - 0x78,
            "the head page ends mid-file"
        );
        assert_eq!(pages[0].frame_offset, 0x78, "the bytes land mid-frame");
        assert_eq!(pages[1].virtual_address, 0x8040001000);
        assert_eq!(
            pages[1].copy_len,
            0xf96 - (0x1000 - 0x78),
            "the tail finishes it"
        );

        // A BSS segment: the file's bytes end inside the second page, and the
        // rest is the zero-fill the pool's frames already carry.
        let image = load(
            &elf(
                MACHINE,
                0x8040000008,
                &[
                    SegmentSpec {
                        vaddr: 0x8040000000,
                        offset: FIRST_OFFSET,
                        filesz: 0x1000,
                        memsz: 0x1000,
                        flags: FLAG_R | FLAG_X,
                    },
                    SegmentSpec {
                        vaddr: 0x8040001000,
                        offset: 0x2000,
                        filesz: 0x100,
                        memsz: 0x2000,
                        flags: FLAG_R | FLAG_W,
                    },
                ],
            ),
            MACHINE,
        )
        .expect("the bss image loads");
        let pages: alloc::vec::Vec<_> = crate::loader::pages(&image.segments()[1]).collect();
        assert_eq!(pages.len(), 2);
        assert_eq!(pages[0].copy_len, 0x100, "the file's bytes");
        assert_eq!(pages[1].copy_len, 0, "pure BSS: nothing to copy");
        assert_eq!(pages[1].virtual_address, 0x8040002000);
    }

    #[test]
    fn the_entry_must_be_inside_executable_code() {
        // The entry in a writable segment: data, not code.
        let entry_in_data = elf(
            MACHINE,
            0x8040001000,
            &[
                SegmentSpec {
                    vaddr: 0x8040000000,
                    offset: FIRST_OFFSET,
                    filesz: 0x1000,
                    memsz: 0x1000,
                    flags: FLAG_R | FLAG_X,
                },
                SegmentSpec {
                    vaddr: 0x8040001000,
                    offset: 0x2000,
                    filesz: 0x1000,
                    memsz: 0x1000,
                    flags: FLAG_R | FLAG_W,
                },
            ],
        );
        assert_eq!(
            load(&entry_in_data, MACHINE),
            Err(LoadError::EntryOutsideCode)
        );

        // The entry past every segment.
        let entry_outside = elf(
            MACHINE,
            0x8040003000,
            &[SegmentSpec {
                vaddr: 0x8040000000,
                offset: FIRST_OFFSET,
                filesz: 0x1000,
                memsz: 0x1000,
                flags: FLAG_R | FLAG_X,
            }],
        );
        assert_eq!(
            load(&entry_outside, MACHINE),
            Err(LoadError::EntryOutsideCode)
        );
    }

    #[test]
    fn more_segments_than_the_bound_refuse_rather_than_drop() {
        let segments: Vec<SegmentSpec> = (0..=MAX_SEGMENTS)
            .map(|index| SegmentSpec {
                vaddr: 0x8040000000 + (index as u64) * 0x1000,
                offset: FIRST_OFFSET,
                filesz: 0x1000,
                memsz: 0x1000,
                flags: FLAG_R | FLAG_X,
            })
            .collect();
        assert_eq!(
            load(&elf(MACHINE, 0x8040000008, &segments), MACHINE),
            Err(LoadError::TooManySegments),
            "one past the bound, refused whole rather than silently partial"
        );
    }

    #[test]
    fn an_image_at_the_byte_bound_yields_a_page_for_every_frame_the_space_can_hold() {
        // The regression this pins: the loader's byte bound and the space's
        // frame-record bound described the same set of pages and disagreed —
        // 256 KiB admits 64 pages, and the record array held 16, so a legal
        // image was refused by a bound whose own documentation described a
        // smaller thing.  No boot had a program large enough to notice.
        //
        // One segment spanning the whole admissible file is the worst case the
        // bounds have to agree on: every page is the image's, and `exec` adds
        // one more for the stack.
        let pages_at_bound = MAX_IMAGE_BYTES / PAGE_SIZE;
        let image = elf(
            MACHINE,
            0x8040000000,
            &[SegmentSpec {
                vaddr: 0x8040000000,
                offset: FIRST_OFFSET,
                filesz: MAX_IMAGE_BYTES as u64,
                memsz: MAX_IMAGE_BYTES as u64,
                flags: FLAG_R | FLAG_X,
            }],
        );
        let loaded = load(&image, MACHINE).expect("an image at the byte bound is legal");
        let planned = loaded
            .segments()
            .iter()
            .map(|segment| pages(segment).count())
            .sum::<usize>();
        assert_eq!(
            planned, pages_at_bound,
            "every page of the largest admissible image is planned"
        );
        assert!(
            crate::address_space::space::MAX_OWNED_FRAMES > planned,
            "the space records at least the image's {planned} pages plus the stack"
        );
    }
}
