//! kernel/src/loader/tests.rs
//!
//! The loader's tests: ELF files built one field at a time, so a test that
//! asserts a refusal can point at the field that earns it.
//!
//! A real toolchain's output is the wrong fixture here — it would be right in
//! ways nobody wrote down, and a parser that passed on it might still refuse
//! the image the linker emits after one flag changes.  Every image below is
//! assembled by [`elf`], whose arguments are the fields the loader reads, so
//! each case names the bytes it varies.  The helper writes only what fits in
//! the file it builds, which is what makes "file bytes past the file's own
//! end" a state the fixture can produce rather than one the helper repairs.

use crate::loader::LoadError;
use crate::loader::MAX_SEGMENTS;
use crate::loader::load;
use alloc::vec;
use alloc::vec::Vec;

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
/// after the ELF header and the program-header table, and offset 0 would put
/// a segment's bytes over the magic itself.
const FIRST_OFFSET: u64 = 0x1000;

/// Build a minimal ELF64 image: a header, one program header per segment,
/// and whatever of the segments' file bytes the file is long enough to hold.
fn elf(machine: u16, entry: u64, segments: &[SegmentSpec]) -> Vec<u8> {
    // The file is as long as its longest segment needs: a real file carries
    // its segments' bytes.  The one truncated-file test shortens the finished
    // image explicitly rather than this helper guessing.
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

    let mut dynamic = good.clone();
    dynamic[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN
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
    // The same bytes load when the caller expects the machine they name: the
    // loader has no machine of its own to be right about.
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

    // Beyond the user window: the loader maps into one window and nowhere else.
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

    // memsz smaller than filesz: the file carries bytes memory does not hold.
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
