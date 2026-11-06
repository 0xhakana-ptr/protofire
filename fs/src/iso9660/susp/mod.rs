//! fs/src/iso9660/susp/mod.rs
//!
//! SUSP, the System Use Sharing Protocol, and Rock Ridge on top of it.
//!
//! ## What a System Use area is
//!
//! A directory record has a field the format calls "System Use": bytes the
//! standard does not define, for a system to put what it wants in.  SUSP gives
//! those bytes a shape, a run of entries, each with a two-byte signature, a
//! length that includes the header, and a version, so that two extensions can
//! share the area without understanding each other.
//!
//! Rock Ridge is the extension Linux, and this reader, uses: `NM` for the POSIX
//! name the author meant, `PX` for the mode and ownership, `SL` for a symbolic
//! link's target.  A disc without it is still readable, the identifiers are
//! the names, which is why every field here is optional.
//!
//! ## The entry a reader must skip
//!
//! `CE` (continuation) says the System Use area continues in another block.  A
//! reader that did not follow it would stop at the end of the record and lose
//! every entry after the first 255 bytes, on a record with a long name, that
//! is the name.  This module reports the continuation rather than following it,
//! because following it needs the device and this module has none; the volume
//! does the read and calls back.
//!
//! ## The name is in pieces
//!
//! A name longer than one `NM` entry's room is written as several `NM` entries,
//! each with a continuation flag.  Reading only the first returns a truncated
//! name that looks real, which is why [`SystemUse::name`] concatenates the run.

use alloc::string::String;
use alloc::vec::Vec;

/// A SUSP entry's header: signature, length (including the header), version.
pub const ENTRY_HEADER_LEN: usize = 4;

/// The most a name may be assembled from, so a corrupt area cannot make this
/// module allocate without bound.
pub const MAX_NAME_LEN: usize = 255 * 4;

/// The `NM` entry's continuation flag.
pub const NM_CONTINUE: u8 = 0x01;
/// The `NM` entry's "this name is the current directory" flag.
pub const NM_CURRENT: u8 = 0x02;
/// The `NM` entry's "this name is the parent directory" flag.
pub const NM_PARENT: u8 = 0x04;
/// The `NM` entry's "this name is the root" flag.
pub const NM_ROOT: u8 = 0x08;

/// A component of a symbolic link's target.
///
/// The three special components are not text: a link target is a path, and
/// `.`, `..` and `/` are structure rather than characters.  A reader that
/// appended them as text would turn `../x` into the string `"..x"` when a
/// component carried an empty name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkComponent {
    /// A path component, as bytes.
    Name(Vec<u8>),
    /// The parent directory.
    Parent,
    /// The current directory.
    Current,
    /// The filesystem root.
    Root,
}

/// A directory record's System Use area, parsed.
///
/// Every field is optional: a disc without Rock Ridge has none of them, and a
/// disc with it may still choose not to name a particular record.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SystemUse {
    /// The POSIX name, assembled from its `NM` run.
    pub name: Option<String>,
    /// The POSIX attributes: mode, links, uid, gid.
    pub posix: Option<PosixAttributes>,
    /// A symbolic link's target, from its `SL` run.
    pub symlink: Option<Vec<LinkComponent>>,
    /// Where the area continues, when a `CE` entry says it does.
    ///
    /// `(block, offset, length)` is the format's own triple, and the caller
    /// reads it: this module has no device.
    pub continuation: Option<Continuation>,
    /// Whether an `ER` entry names the extension this area implements.
    pub has_extension_reference: bool,
}

/// POSIX attributes a `PX` entry carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PosixAttributes {
    pub mode: u32,
    pub links: u32,
    pub uid: u32,
    pub gid: u32,
}

/// Where a System Use area continues.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Continuation {
    /// The logical block the continuation starts at.
    pub block: u32,
    /// The byte offset within that block.
    pub offset: u32,
    /// How many bytes the continuation holds.
    pub length: u32,
}

impl SystemUse {
    /// Parse a System Use area.
    ///
    /// A malformed entry ends the parse rather than being skipped: an entry
    /// whose length is smaller than its header or larger than what is left is
    /// not an entry, and stepping by its length would walk off the area or
    /// loop forever on a length of zero.
    pub fn parse(bytes: &[u8]) -> SystemUse {
        let mut parsed = SystemUse::default();
        let mut name = String::new();
        let mut name_open = false;
        let mut link: Vec<LinkComponent> = Vec::new();
        let mut link_open = false;
        let mut rest = bytes;

        while rest.len() >= ENTRY_HEADER_LEN {
            let signature = [rest[0], rest[1]];
            let length = rest[2] as usize;
            if length < ENTRY_HEADER_LEN || length > rest.len() {
                break;
            }
            let body = &rest[ENTRY_HEADER_LEN..length];

            match &signature {
                b"NM" => {
                    if let Some(&flags) = body.first() {
                        let piece = &body[1..];
                        if !name_open {
                            name.clear();
                        }
                        match piece {
                            _ if flags & NM_ROOT != 0 => name.push('/'),
                            _ if flags & NM_PARENT != 0 => name.push_str(".."),
                            _ if flags & NM_CURRENT != 0 => name.push('.'),
                            _ => name.push_str(&String::from_utf8_lossy(piece)),
                        }
                        name_open = flags & NM_CONTINUE != 0;
                        if name.len() > MAX_NAME_LEN {
                            name.truncate(MAX_NAME_LEN);
                            name_open = false;
                        }
                        if !name_open {
                            parsed.name = Some(name.clone());
                        }
                    }
                }
                b"PX" => {
                    if body.len() >= 16 {
                        parsed.posix = Some(PosixAttributes {
                            mode: u32::from_le_bytes([body[0], body[1], body[2], body[3]]),
                            links: u32::from_le_bytes([body[4], body[5], body[6], body[7]]),
                            uid: u32::from_le_bytes([body[8], body[9], body[10], body[11]]),
                            gid: u32::from_le_bytes([body[12], body[13], body[14], body[15]]),
                        });
                    }
                }
                b"SL" => {
                    if let Some(&flags) = body.first() {
                        if !link_open {
                            link.clear();
                        }
                        let mut components = &body[1..];
                        while components.len() >= 2 {
                            let component_flags = components[0];
                            let component_len = components[1] as usize;
                            if 2 + component_len > components.len() {
                                break;
                            }
                            let data = &components[2..2 + component_len];
                            link.push(if component_flags & 0x08 != 0 {
                                LinkComponent::Root
                            } else if component_flags & 0x04 != 0 {
                                LinkComponent::Parent
                            } else if component_flags & 0x02 != 0 {
                                LinkComponent::Current
                            } else {
                                LinkComponent::Name(data.to_vec())
                            });
                            components = &components[2 + component_len..];
                        }
                        link_open = flags & NM_CONTINUE != 0;
                        if !link_open {
                            parsed.symlink = Some(link.clone());
                        }
                    }
                }
                b"CE" => {
                    // block, offset and length are each `both32`; the little
                    // half is what a reader takes.
                    if body.len() >= 24 {
                        parsed.continuation = Some(Continuation {
                            block: u32::from_le_bytes([body[0], body[1], body[2], body[3]]),
                            offset: u32::from_le_bytes([body[8], body[9], body[10], body[11]]),
                            length: u32::from_le_bytes([body[16], body[17], body[18], body[19]]),
                        });
                    }
                }
                b"ER" => {
                    parsed.has_extension_reference = true;
                }
                b"ST" => {
                    // The terminator: every entry after it is padding.
                    break;
                }
                _ => {}
            }

            rest = &rest[length..];
        }

        parsed
    }
}

/// Render a symbolic link's components as the path a caller reads.
///
/// Components are joined with `/` and the three special ones render as `/`,
/// `..` and `.`.  A root component is absolute, so it leads with `/`; joining
/// naively would turn `/usr/lib` into `//usr/lib`.
pub fn render_link(components: &[LinkComponent]) -> String {
    let mut path = String::new();
    for (index, component) in components.iter().enumerate() {
        let piece: &str = match component {
            LinkComponent::Root => "/",
            LinkComponent::Parent => "..",
            LinkComponent::Current => ".",
            LinkComponent::Name(bytes) => core::str::from_utf8(bytes).unwrap_or("?"),
        };
        let needs_separator = index > 0 && !path.ends_with('/') && piece != "/";
        if needs_separator {
            path.push('/');
        }
        if piece == "/" && index == 0 {
            path.push('/');
        } else {
            path.push_str(piece);
        }
    }
    path
}

#[cfg(test)]
mod tests;
