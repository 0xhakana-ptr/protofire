//! kernel/src/loader/tests.rs
//!
//! The module's tests.
//!
//! A sibling file because the tests outgrew the module: a reader looking for
//! the mechanism should not scroll past them to find the end of it.

//! kernel/src/loader/tests.rs
//!
//! The loader's tests: ELF files built one field at a time, so a test that
//! asserts a refusal can point at the field that earns it.
//!
//! A real toolchain's output is the wrong fixture here, it would be right
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
    // (A dynamic segment a LOAD carries is dead data, and loads, the real
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
    // so the two no longer agree within the page, the file's bytes would
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
    // frame-record bound described the same set of pages and disagreed
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

/// A segment whose file range overflows is refused, not wrapped and accepted.
///
/// This is the loader's defect in its smallest form.  `p_offset` is a `u64`
/// the file chooses, and the check was `file_offset + file_size > len`: in a
/// debug build that addition panics **inside the kernel**, and in a release
/// build it wraps, so a segment naming `u64::MAX` has a file range of a few
/// bytes and passes.  Any ring-3 program can write such an image into the
/// filesystem and call `ExecProcess`.
///
/// The image is the ordinary one with one header field overwritten, because
/// the test helper sizes its file from the segment it is given and would try
/// to allocate the whole offset.  What the loader sees is exactly what a
/// shaped file would give it.
#[test]
fn a_segment_whose_file_range_overflows_is_refused() {
    let mut image = good_image();
    // The first program header's `p_offset`, at 64 bytes' header block plus
    // the offset field's position inside the entry.
    //
    // The value is congruent to the segment's virtual address modulo the page
    // size, on purpose: `u64::MAX` is `-1`, which is **not** congruent with
    // `0x8040000000`'s zero, so the congruence test would refuse the image
    // first and this test would pass without ever reaching the sum.  A probe
    // replacing the `checked_add` with `wrapping_add` proved exactly that.
    let congruent_to_the_top = u64::MAX - (u64::MAX % 4096);
    let offset_field = 64 + 8;
    image[offset_field..offset_field + 8].copy_from_slice(&congruent_to_the_top.to_le_bytes());
    assert_eq!(
        load(&image, MACHINE),
        Err(LoadError::BadSegment),
        "a wrapping file range is a refusal, not a wrapped acceptance"
    );
}

/// A file size that overflows the segment's own end is refused the same way.
///
/// The other half of the same pair: an offset near the top with a size beside
/// it, so neither operand alone is absurd and only their sum is.
#[test]
fn a_segment_whose_file_end_overflows_is_refused() {
    let mut image = good_image();
    let offset_field = 64 + 8;
    let size_field = 64 + 32;
    image[offset_field..offset_field + 8].copy_from_slice(&(u64::MAX - 8).to_le_bytes());
    image[size_field..size_field + 8].copy_from_slice(&64u64.to_le_bytes());
    assert_eq!(
        load(&image, MACHINE),
        Err(LoadError::BadSegment),
        "the sum overflows even though neither field does"
    );
}

/// A dynamic header's file range is refused before any segment vouches for it.
///
/// The dynamic check runs over the program headers **before** `checked` sees a
/// segment, so its `p_offset + p_filesz` is not covered by the segment test.
/// A `PT_DYNAMIC` entry naming `u64::MAX` would panic a debug kernel here and
/// wrap in a release one, and the wrapped number is what the containment test
/// would then judge.
#[test]
fn a_dynamic_header_whose_file_range_overflows_is_refused() {
    // Two headers: a real `PT_LOAD` and the shaped `PT_DYNAMIC`.  One header
    // alone would be refused earlier, by the "no loadable segment" test, and
    // the assertion would pass without reaching the sum this test is about.
    let image = elf(
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
                vaddr: 0,
                offset: 0,
                filesz: 0,
                memsz: 0,
                flags: 0,
            },
        ],
    );
    let mut image = image;
    let header = 64 + 56;
    image[header..header + 4].copy_from_slice(&2u32.to_le_bytes()); // PT_DYNAMIC
    // The pair whose **sum** overflows and wraps to something inside the
    // loadable segment, which is what makes this a test of the sum: with
    // `wrapping_add` the containment test below reads the wrapped value as
    // inside and the image is accepted.  `u64::MAX` alone would be refused by
    // the containment test whether the sum was checked or not.
    image[header + 8..header + 16].copy_from_slice(&(u64::MAX - 0xFFF).to_le_bytes());
    image[header + 32..header + 40].copy_from_slice(&0x1000u64.to_le_bytes());
    assert_eq!(
        load(&image, MACHINE),
        Err(LoadError::NotExecutable),
        "a dynamic header the loader cannot bound is named as what it is"
    );
}
