//! fs/src/iso9660/susp/tests.rs
//!
//! SUSP: the alternate-name entry, the parsed record, and the bytes a malformed
//! one is refused for.
//!
//! Extracted from the module so that a reader following the mechanism does
//! not have to scroll past every case it has to satisfy; see
//! `docs/fmts/testing.md` §1.

use crate::iso9660::susp::LinkComponent;
use crate::iso9660::susp::SystemUse;
use crate::iso9660::susp::render_link;
use alloc::vec;
use alloc::vec::Vec;

/// Build one SUSP entry: signature, length including the header, version.
fn entry(signature: &[u8; 2], body: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(4 + body.len());
    bytes.extend_from_slice(signature);
    bytes.push((4 + body.len()) as u8);
    bytes.push(1);
    bytes.extend_from_slice(body);
    bytes
}

fn nm(name: &[u8], flags: u8) -> Vec<u8> {
    let mut body = alloc::vec![flags];
    body.extend_from_slice(name);
    entry(b"NM", &body)
}

/// An `NM` entry gives the name.
#[test]
fn a_name_entry_gives_the_name() {
    let area = nm(b"hello.txt", 0);
    let parsed = SystemUse::parse(&area);
    assert_eq!(parsed.name.as_deref(), Some("hello.txt"));
}

/// A name split across two `NM` entries is one name.
///
/// Reading only the first returns a truncated name that looks real — the
/// failure mode this concatenation exists to prevent.
#[test]
fn a_continued_name_is_assembled() {
    let mut area = nm(b"a-rather-long-", crate::iso9660::susp::NM_CONTINUE);
    area.extend_from_slice(&nm(b"name.txt", 0));
    let parsed = SystemUse::parse(&area);
    assert_eq!(parsed.name.as_deref(), Some("a-rather-long-name.txt"));
}

/// A continued name whose run never ends leaves no name at all, rather
/// than a truncated one.
///
/// A truncated name the caller cannot tell from a complete one is worse
/// than none: the first opens the wrong file.
#[test]
fn an_unterminated_name_is_not_a_name() {
    let area = nm(b"partial-", crate::iso9660::susp::NM_CONTINUE);
    let parsed = SystemUse::parse(&area);
    assert_eq!(parsed.name, None);
}

/// `PX` gives the POSIX attributes.
#[test]
fn a_posix_entry_gives_the_attributes() {
    let mut body = Vec::new();
    body.extend_from_slice(&0o100644u32.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(&1000u32.to_le_bytes());
    body.extend_from_slice(&1000u32.to_le_bytes());
    let area = entry(b"PX", &body);
    let parsed = SystemUse::parse(&area);
    let posix = parsed.posix.expect("attributes");
    assert_eq!(posix.mode, 0o100644);
    assert_eq!(posix.links, 1);
    assert_eq!(posix.uid, 1000);
    assert_eq!(posix.gid, 1000);
}

/// `SL` gives a link's components, and the special ones are structure and
/// not text.
#[test]
fn a_link_entry_gives_its_components() {
    let mut body = vec![0u8]; // entry flags
    body.extend_from_slice(&[0x02, 0x00]); // CURRENT, no name
    body.extend_from_slice(&[0x04, 0x00]); // PARENT, no name
    body.extend_from_slice(&[0x00, 0x03]); // a name of length 3
    body.extend_from_slice(b"lib");
    let area = entry(b"SL", &body);
    let parsed = SystemUse::parse(&area);
    let link = parsed.symlink.expect("a link");
    assert_eq!(link[0], LinkComponent::Current);
    assert_eq!(link[1], LinkComponent::Parent);
    assert_eq!(link[2], LinkComponent::Name(b"lib".to_vec()));
}

/// A link's components render as a path.
#[test]
fn a_link_renders_as_a_path() {
    let components = vec![
        LinkComponent::Name(b"usr".to_vec()),
        LinkComponent::Name(b"lib".to_vec()),
    ];
    assert_eq!(render_link(&components), "usr/lib");

    let absolute = vec![LinkComponent::Root, LinkComponent::Name(b"usr".to_vec())];
    assert_eq!(
        render_link(&absolute),
        "/usr",
        "a root component leads with one slash, not two"
    );

    let relative = vec![LinkComponent::Parent, LinkComponent::Name(b"x".to_vec())];
    assert_eq!(render_link(&relative), "../x");
}

/// A `CE` entry says where the area continues, and nothing here follows it.
#[test]
fn a_continuation_entry_is_reported() {
    let mut body = Vec::new();
    body.extend_from_slice(&32u32.to_le_bytes());
    body.extend_from_slice(&32u32.to_be_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(&100u32.to_le_bytes());
    body.extend_from_slice(&100u32.to_be_bytes());
    let area = entry(b"CE", &body);
    let parsed = SystemUse::parse(&area);
    let continuation = parsed.continuation.expect("a continuation");
    assert_eq!(continuation.block, 32);
    assert_eq!(continuation.offset, 0);
    assert_eq!(continuation.length, 100);
}

/// A malformed entry ends the parse rather than stepping by its length.
///
/// A length of zero would loop forever; a length past the area would walk
/// off it.  Either way the entries after it are lost, which is the honest
/// answer to an area this reader cannot walk.
#[test]
fn a_malformed_entry_ends_the_parse() {
    let mut area = nm(b"first", 0);
    area.extend_from_slice(&[b'N', b'M', 0, 1]); // length 0
    area.extend_from_slice(&nm(b"second", 0));
    let parsed = SystemUse::parse(&area);
    assert_eq!(
        parsed.name.as_deref(),
        Some("first"),
        "the first entry was read and the malformed one ended the walk"
    );
}

/// An area with no Rock Ridge yields no fields, and does not fail.
#[test]
fn an_empty_area_yields_nothing() {
    let parsed = SystemUse::parse(&[]);
    assert_eq!(parsed, SystemUse::default());
    let parsed = SystemUse::parse(b"SP\x07\x01\xbe\xef\x00");
    assert_eq!(parsed.name, None);
}

/// The terminator ends the walk, so an entry after it is padding.
#[test]
fn the_terminator_ends_the_walk() {
    let mut area = entry(b"ST", &[0]);
    area.extend_from_slice(&nm(b"after", 0));
    let parsed = SystemUse::parse(&area);
    assert_eq!(parsed.name, None, "nothing after the terminator was read");
}
