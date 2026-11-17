//! drivers/display/virtio_gpu/src/command.rs
//!
//! The control header, the command numbers, and the bodies the 2D and 3D
//! commands carry.
//!
//! ## Why the bodies are byte arrays with builders
//!
//! The device reads a fixed byte layout, and the specification writes that
//! layout as a C struct whose field order is not always the natural one:
//! `TRANSFER_TO_HOST_2D` puts its rectangle first, then a 64-bit offset, and
//! only then the resource id, which is the order the device reads and the
//! opposite of the order a reader would guess.  A `#[repr(C)]` struct would
//! reproduce the layout only if every field were declared in that order, and a
//! mistake would be a silently misread field rather than a compile error.
//!
//! So each body is a fixed-size byte array, and a builder writes each field at
//! its offset.  The sizes are named constants, the tests assert them against
//! the specification's numbers, and a body that grew is a test failure rather
//! than a device reading the next field's bytes.
//!
//! ## The header every command carries
//!
//! Twenty-four bytes, `virtio_gpu_ctrl_hdr`:
//!
//! ```text
//! 0  u32  type        one of [`Command`]
//! 4  u32  flags       VIRTIO_GPU_FLAG_FENCE and VIRTIO_GPU_FLAG_INFO_RING_IDX
//! 8  u64  fence_id    the fence to signal, zero when none was asked for
//! 16 u32  ctx_id      the context, zero for the 2D commands
//! 20 u8   ring_idx    which command ring the fence belongs to
//! 21 u8   padding[3]
//! ```
//!
//! That is 24 bytes and not 16: the byte after `ctx_id` is `ring_idx`, and the
//! three bytes after it are padding, which is what makes the header 24.  A
//! driver that wrote 16 and put the next field there would have its
//! `resource_id` read as `ring_idx` and padding.

/// The control header's size, on the wire.
pub const CTRL_HEADER_SIZE: usize = 24;
/// The command number's offset, the first field of every command.
pub const TYPE_OFFSET: usize = 0;
/// The flags' offset.
pub const FLAGS_OFFSET: usize = 4;
/// The fence id's offset, a `le64`.
pub const FENCE_OFFSET: usize = 8;
/// The context id's offset.
pub const CTX_ID_OFFSET: usize = 16;
/// The command ring index's offset.
pub const RING_INDEX_OFFSET: usize = 20;

/// `flags` bit 0: the command asks for a fence.
pub const FLAG_FENCE: u32 = 1 << 0;
/// `flags` bit 1: the fence belongs to the ring `ring_idx` names.
pub const FLAG_INFO_RING_INDEX: u32 = 1 << 1;

/// The commands this crate builds.
///
/// The numbers are the specification's enum, which counts each group in
/// sequence from its first member.  The 2D group starts at `0x0100` and runs
/// `GET_DISPLAY_INFO`, `RESOURCE_CREATE_2D`, `RESOURCE_UNREF`, `SET_SCANOUT`,
/// `RESOURCE_FLUSH`, `TRANSFER_TO_HOST_2D`, `RESOURCE_ATTACH_BACKING`.  The 3D
/// group starts at `0x0200` and runs `CTX_CREATE`, `CTX_DESTROY`,
/// `CTX_ATTACH_RESOURCE`, `CTX_DETACH_RESOURCE`, `RESOURCE_CREATE_3D`,
/// `TRANSFER_TO_HOST_3D`, `TRANSFER_FROM_HOST_3D`, `SUBMIT_3D`.
///
/// The values are spelled out rather than computed because a reader checking
/// one against the specification should not have to count an enum, and because
/// the previous tree's `CTX_CREATE = 0x0201` is exactly the mistake a table of
/// literals makes visible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Command {
    /// Ask which displays are attached and how big they are.
    GetDisplayInfo = 0x0100,
    /// Make a 2D resource with a format and a size.
    ResourceCreate2d = 0x0101,
    /// Drop a resource.
    ResourceUnref = 0x0102,
    /// Point a scanout at a resource, so the device shows it.
    SetScanout = 0x0103,
    /// Push a resource's region to the display.
    ResourceFlush = 0x0104,
    /// Upload guest memory into the host's image of a resource.
    TransferToHost2d = 0x0105,
    /// Attach guest memory to a resource as its backing.
    ResourceAttachBacking = 0x0106,
    /// Make a VIRGL context.
    CtxCreate = 0x0200,
    /// Drop a VIRGL context.
    CtxDestroy = 0x0201,
    /// Attach a resource to a context.
    CtxAttachResource = 0x0202,
    /// Detach a resource from a context.
    CtxDetachResource = 0x0203,
    /// Make a 3D resource.
    ResourceCreate3d = 0x0204,
    /// Upload guest memory into a 3D resource.
    TransferToHost3d = 0x0205,
    /// Read a 3D resource's region back into guest memory.
    TransferFromHost3d = 0x0206,
    /// Submit a VIRGL command stream to a context.
    Submit3d = 0x0207,
}

/// The responses this crate reads.
///
/// Only the two a boot acts on are named.  The error family starts at `0x1200`
/// and a driver that prints the number it got is better served by the value
/// than by a name this crate would have to keep in step with the
/// specification.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Response {
    /// The command succeeded and carried no payload.
    OkNoData = 0x1100,
    /// The command succeeded and the answer is a display-info record.
    OkDisplayInfo = 0x1101,
}

/// The first error response number: anything at or above it is a refusal.
pub const RESPONSE_ERROR_BASE: u32 = 0x1200;

/// Whether a response number is an error rather than an answer.
pub const fn response_is_error(header_type: u32) -> bool {
    header_type >= RESPONSE_ERROR_BASE
}

/// The pixel format the scanout uses: 32 bits per pixel, blue in byte zero.
///
/// `B8G8R8X8_UNORM` is what the bochs display's flat framebuffer already
/// carries, so a pixel written for one is a pixel the other shows and the
/// console's writer does not need a second format.
pub const FORMAT_B8G8R8X8_UNORM: u32 = 2;

/// Write a control header for `command` into the first [`CTRL_HEADER_SIZE`]
/// bytes of `bytes`.
///
/// `ctx_id` is zero for every command this boot's 2D path sends and the VIRGL
/// context for the 3D ones.  The flags, the fence and the ring index are zero:
/// this driver never asks the device to fence a command, so the device never
/// has to signal one.
pub fn ctrl_header(bytes: &mut [u8], command: Command, ctx_id: u32) {
    bytes[TYPE_OFFSET..TYPE_OFFSET + 4].copy_from_slice(&(command as u32).to_le_bytes());
    bytes[FLAGS_OFFSET..FLAGS_OFFSET + 4].copy_from_slice(&0u32.to_le_bytes());
    bytes[FENCE_OFFSET..FENCE_OFFSET + 8].copy_from_slice(&0u64.to_le_bytes());
    bytes[CTX_ID_OFFSET..CTX_ID_OFFSET + 4].copy_from_slice(&ctx_id.to_le_bytes());
    bytes[RING_INDEX_OFFSET] = 0;
}

/// A header with a fence on it, for a caller that wants the device's word that
/// a command finished.
///
/// This driver does not use one: its control queue is drained by polling and
/// only one command is in flight at a time, so a fence would be a second answer
/// to a question the used ring already answers.  It is here because the field
/// is part of the format, and a reader comparing this file with the
/// specification should find every field accounted for rather than a header
/// that quietly dropped one.
pub fn ctrl_header_fenced(bytes: &mut [u8], command: Command, ctx_id: u32, fence: u64) {
    ctrl_header(bytes, command, ctx_id);
    bytes[FLAGS_OFFSET..FLAGS_OFFSET + 4].copy_from_slice(&FLAG_FENCE.to_le_bytes());
    bytes[FENCE_OFFSET..FENCE_OFFSET + 8].copy_from_slice(&fence.to_le_bytes());
}

/// The `RESOURCE_CREATE_2D` body: `hdr` (24) and four words.
pub const RESOURCE_CREATE_2D_SIZE: usize = 40;

/// Build a `RESOURCE_CREATE_2D` command.
pub fn resource_create_2d(resource_id: u32, format: u32, width: u32, height: u32) -> [u8; 40] {
    let mut bytes = [0u8; RESOURCE_CREATE_2D_SIZE];
    ctrl_header(&mut bytes, Command::ResourceCreate2d, 0);
    bytes[24..28].copy_from_slice(&resource_id.to_le_bytes());
    bytes[28..32].copy_from_slice(&format.to_le_bytes());
    bytes[32..36].copy_from_slice(&width.to_le_bytes());
    bytes[36..40].copy_from_slice(&height.to_le_bytes());
    bytes
}

/// The `RESOURCE_UNREF` body: `hdr` (24), the id (4) and padding (4).
pub const RESOURCE_UNREF_SIZE: usize = 32;

/// Build a `RESOURCE_UNREF` command.
pub fn resource_unref(resource_id: u32) -> [u8; 32] {
    let mut bytes = [0u8; RESOURCE_UNREF_SIZE];
    ctrl_header(&mut bytes, Command::ResourceUnref, 0);
    bytes[24..28].copy_from_slice(&resource_id.to_le_bytes());
    bytes
}

/// The `SET_SCANOUT` body: `hdr` (24), a rectangle (16), the scanout (4) and
/// the resource (4).
pub const SET_SCANOUT_SIZE: usize = 48;

/// Build a `SET_SCANOUT` command that shows `resource_id` on `scanout_id`.
pub fn set_scanout(resource_id: u32, scanout_id: u32, width: u32, height: u32) -> [u8; 48] {
    let mut bytes = [0u8; SET_SCANOUT_SIZE];
    ctrl_header(&mut bytes, Command::SetScanout, 0);
    bytes[24..28].copy_from_slice(&0u32.to_le_bytes());
    bytes[28..32].copy_from_slice(&0u32.to_le_bytes());
    bytes[32..36].copy_from_slice(&width.to_le_bytes());
    bytes[36..40].copy_from_slice(&height.to_le_bytes());
    bytes[40..44].copy_from_slice(&scanout_id.to_le_bytes());
    bytes[44..48].copy_from_slice(&resource_id.to_le_bytes());
    bytes
}

/// The `RESOURCE_FLUSH` body: `hdr` (24), a rectangle (16), the id (4) and
/// padding (4).
pub const RESOURCE_FLUSH_SIZE: usize = 48;

/// Build a `RESOURCE_FLUSH` command for the whole of `resource_id`.
pub fn resource_flush(resource_id: u32, width: u32, height: u32) -> [u8; 48] {
    let mut bytes = [0u8; RESOURCE_FLUSH_SIZE];
    ctrl_header(&mut bytes, Command::ResourceFlush, 0);
    bytes[24..28].copy_from_slice(&0u32.to_le_bytes());
    bytes[28..32].copy_from_slice(&0u32.to_le_bytes());
    bytes[32..36].copy_from_slice(&width.to_le_bytes());
    bytes[36..40].copy_from_slice(&height.to_le_bytes());
    bytes[40..44].copy_from_slice(&resource_id.to_le_bytes());
    bytes
}

/// The `TRANSFER_TO_HOST_2D` body: `hdr` (24), a rectangle (16), a 64-bit
/// offset (8), the id (4) and padding (4).
///
/// The layout is the specification's and it is not the natural order: the
/// resource id sits **after** the 64-bit offset.  A driver that put the id
/// first, the way a struct reader would naturally order it, hands the device
/// the rectangle's `x` as an id, and QEMU answers
/// `VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID` -- which reads as "there is no
/// such resource" rather than "the field is in the wrong place".
pub const TRANSFER_TO_HOST_2D_SIZE: usize = 56;

/// Build a `TRANSFER_TO_HOST_2D` command that uploads the whole resource.
pub fn transfer_to_host_2d(resource_id: u32, width: u32, height: u32) -> [u8; 56] {
    let mut bytes = [0u8; TRANSFER_TO_HOST_2D_SIZE];
    ctrl_header(&mut bytes, Command::TransferToHost2d, 0);
    bytes[24..28].copy_from_slice(&0u32.to_le_bytes());
    bytes[28..32].copy_from_slice(&0u32.to_le_bytes());
    bytes[32..36].copy_from_slice(&width.to_le_bytes());
    bytes[36..40].copy_from_slice(&height.to_le_bytes());
    bytes[40..48].copy_from_slice(&0u64.to_le_bytes());
    bytes[48..52].copy_from_slice(&resource_id.to_le_bytes());
    bytes
}

/// One memory entry's size: `addr` (8), `length` (4) and padding (4).
pub const MEM_ENTRY_SIZE: usize = 16;

/// The `RESOURCE_ATTACH_BACKING` body with one entry: `hdr` (24), the id (4),
/// the entry count (4) and the entry (16).
///
/// The entry is **inline**, immediately after the count, which is how the
/// device reads it.  A version that left a gap and chained the entry in a
/// second descriptor made the device read the padding as a zero-length entry
/// and answer `VIRTIO_GPU_RESP_ERR_UNSPEC`.
pub const ATTACH_BACKING_SIZE: usize = 48;

/// Build a `RESOURCE_ATTACH_BACKING` command with one contiguous entry.
pub fn attach_backing(resource_id: u32, address: u64, length: u32) -> [u8; 48] {
    let mut bytes = [0u8; ATTACH_BACKING_SIZE];
    ctrl_header(&mut bytes, Command::ResourceAttachBacking, 0);
    bytes[24..28].copy_from_slice(&resource_id.to_le_bytes());
    bytes[28..32].copy_from_slice(&1u32.to_le_bytes());
    bytes[32..40].copy_from_slice(&address.to_le_bytes());
    bytes[40..44].copy_from_slice(&length.to_le_bytes());
    bytes
}

/// The `RESOURCE_CREATE_3D` body: `hdr` (24) and twelve 32-bit fields.
///
/// The fields are `resource_id`, `target`, `format`, `bind`, `width`, `height`,
/// `depth`, `array_size`, `last_level`, `nr_samples`, `flags`, `padding`.
/// Four of those names are the specification's, and the previous tree had all
/// four wrong: it called `last_level` `levels`, `nr_samples` `num_samples`,
/// `flags` `stride`, and dropped the padding, so its last three words carried a
/// different meaning than the device read.
pub const RESOURCE_CREATE_3D_SIZE: usize = 80;

/// Build a `RESOURCE_CREATE_3D` command from its eleven meaningful fields.
#[allow(clippy::too_many_arguments)]
pub fn resource_create_3d(
    resource_id: u32,
    target: u32,
    format: u32,
    bind: u32,
    width: u32,
    height: u32,
    depth: u32,
    array_size: u32,
    last_level: u32,
    nr_samples: u32,
    flags: u32,
) -> [u8; 80] {
    let mut bytes = [0u8; RESOURCE_CREATE_3D_SIZE];
    ctrl_header(&mut bytes, Command::ResourceCreate3d, 0);
    let fields = [
        resource_id,
        target,
        format,
        bind,
        width,
        height,
        depth,
        array_size,
        last_level,
        nr_samples,
        flags,
        0,
    ];
    for (index, field) in fields.iter().enumerate() {
        let at = 24 + index * 4;
        bytes[at..at + 4].copy_from_slice(&field.to_le_bytes());
    }
    bytes
}

/// The `TRANSFER_TO_HOST_3D` body: `hdr` (24), a box (24), a 64-bit offset
/// (8), the id (4), the level (4) and two strides (8).
///
/// The box is `x`, `y`, `z`, `w`, `h`, `d`, and the offset sits **between** the
/// box and the resource id.  The previous tree put the resource id first, after
/// the header, so the device read the box's `x` as the resource id.
pub const TRANSFER_TO_HOST_3D_SIZE: usize = 72;

/// Build a `TRANSFER_TO_HOST_3D` command for a whole resource region.
pub fn transfer_to_host_3d(
    resource_id: u32,
    width: u32,
    height: u32,
    depth: u32,
    level: u32,
    stride: u32,
    layer_stride: u32,
) -> [u8; 72] {
    let mut bytes = [0u8; TRANSFER_TO_HOST_3D_SIZE];
    ctrl_header(&mut bytes, Command::TransferToHost3d, 0);
    bytes[24..28].copy_from_slice(&0u32.to_le_bytes());
    bytes[28..32].copy_from_slice(&0u32.to_le_bytes());
    bytes[32..36].copy_from_slice(&0u32.to_le_bytes());
    bytes[36..40].copy_from_slice(&width.to_le_bytes());
    bytes[40..44].copy_from_slice(&height.to_le_bytes());
    bytes[44..48].copy_from_slice(&depth.to_le_bytes());
    bytes[48..56].copy_from_slice(&0u64.to_le_bytes());
    bytes[56..60].copy_from_slice(&resource_id.to_le_bytes());
    bytes[60..64].copy_from_slice(&level.to_le_bytes());
    bytes[64..68].copy_from_slice(&stride.to_le_bytes());
    bytes[68..72].copy_from_slice(&layer_stride.to_le_bytes());
    bytes
}

/// The `SUBMIT_3D` body: `hdr` (24), the stream's length (4) and padding (4).
pub const SUBMIT_3D_SIZE: usize = 32;

/// Build a `SUBMIT_3D` command carrying `length` bytes of command stream.
///
/// The stream itself follows this body in a second device-readable descriptor,
/// which is why the length is here and the bytes are not.
pub fn submit_3d(ctx_id: u32, length: u32) -> [u8; 32] {
    let mut bytes = [0u8; SUBMIT_3D_SIZE];
    ctrl_header(&mut bytes, Command::Submit3d, ctx_id);
    bytes[24..28].copy_from_slice(&length.to_le_bytes());
    bytes
}

/// The `CTX_CREATE` body: `hdr` (24), the name's length (4), the context's
/// initial state (4) and a 64-byte debug name.
pub const CTX_CREATE_SIZE: usize = 96;

/// Build a `CTX_CREATE` command whose context is `ctx_id`.
///
/// `context_init` is zero, which the specification reads as "the device's
/// default capset".  Its low eight bits are a capset id, and a driver that has
/// not asked which capsets the host offers has no business naming one.
pub fn ctx_create(ctx_id: u32, name: &[u8]) -> [u8; 96] {
    let mut bytes = [0u8; CTX_CREATE_SIZE];
    ctrl_header(&mut bytes, Command::CtxCreate, ctx_id);
    let length = name.len().min(63);
    bytes[24..28].copy_from_slice(&(length as u32).to_le_bytes());
    bytes[28..32].copy_from_slice(&0u32.to_le_bytes());
    bytes[32..32 + length].copy_from_slice(&name[..length]);
    bytes
}

/// The `CTX_DESTROY` body: the header and nothing else.
pub const CTX_DESTROY_SIZE: usize = 24;

/// Build a `CTX_DESTROY` command.
pub fn ctx_destroy(ctx_id: u32) -> [u8; 24] {
    let mut bytes = [0u8; CTX_DESTROY_SIZE];
    ctrl_header(&mut bytes, Command::CtxDestroy, ctx_id);
    bytes
}

#[cfg(test)]
mod tests {
    //! The layouts, asserted field by field against the specification's
    //! numbers.  Several of these are places the previous tree was wrong.

    use super::*;

    fn word(bytes: &[u8], at: usize) -> u32 {
        u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
    }

    fn long(bytes: &[u8], at: usize) -> u64 {
        u64::from_le_bytes([
            bytes[at],
            bytes[at + 1],
            bytes[at + 2],
            bytes[at + 3],
            bytes[at + 4],
            bytes[at + 5],
            bytes[at + 6],
            bytes[at + 7],
        ])
    }

    /// The header is 24 bytes, and its last three are padding, which is what
    /// puts the first body field at 24.
    #[test]
    fn the_control_header_is_twenty_four_bytes() {
        assert_eq!(CTRL_HEADER_SIZE, 24);
        let mut bytes = [0u8; CTRL_HEADER_SIZE];
        ctrl_header(&mut bytes, Command::GetDisplayInfo, 0);
        assert_eq!(word(&bytes, 0), 0x0100);
        assert_eq!(word(&bytes, 4), 0, "flags");
        assert_eq!(long(&bytes, 8), 0, "fence");
        assert_eq!(word(&bytes, 16), 0, "context");
        assert_eq!(bytes[20], 0, "ring index");
        assert_eq!(&bytes[21..24], &[0, 0, 0], "padding");
    }

    /// A fenced header sets the flag and carries the fence, and a plain one
    /// leaves both at zero.
    #[test]
    fn a_fence_is_a_flag_and_an_id() {
        let mut bytes = [0u8; CTRL_HEADER_SIZE];
        ctrl_header(&mut bytes, Command::ResourceFlush, 0);
        assert_eq!(word(&bytes, 4), 0, "no fence was asked for");

        ctrl_header_fenced(&mut bytes, Command::ResourceFlush, 0, 0x1122_3344_5566_7788);
        assert_eq!(word(&bytes, 4), FLAG_FENCE);
        assert_eq!(long(&bytes, 8), 0x1122_3344_5566_7788);
        // The two flags are different bits, so a driver that wanted both can
        // ask for both and a header carrying one does not mean the other.
        assert_eq!(FLAG_FENCE, 1);
        assert_eq!(FLAG_INFO_RING_INDEX, 2);
        assert_eq!(FLAG_FENCE | FLAG_INFO_RING_INDEX, 3);
    }

    /// Every command number is the specification's, counted from its group's
    /// first member.
    ///
    /// The previous tree wrote `CTX_CREATE` as `0x0201` and `SUBMIT_3D` as
    /// `0x0208`, which are `CTX_DESTROY` and the number after `SUBMIT_3D`.
    #[test]
    fn the_command_numbers_are_the_specifications() {
        assert_eq!(Command::GetDisplayInfo as u32, 0x0100);
        assert_eq!(Command::ResourceCreate2d as u32, 0x0101);
        assert_eq!(Command::ResourceUnref as u32, 0x0102);
        assert_eq!(Command::SetScanout as u32, 0x0103);
        assert_eq!(Command::ResourceFlush as u32, 0x0104);
        assert_eq!(Command::TransferToHost2d as u32, 0x0105);
        assert_eq!(Command::ResourceAttachBacking as u32, 0x0106);
        assert_eq!(Command::CtxCreate as u32, 0x0200);
        assert_eq!(Command::CtxDestroy as u32, 0x0201);
        assert_eq!(Command::CtxAttachResource as u32, 0x0202);
        assert_eq!(Command::CtxDetachResource as u32, 0x0203);
        assert_eq!(Command::ResourceCreate3d as u32, 0x0204);
        assert_eq!(Command::TransferToHost3d as u32, 0x0205);
        assert_eq!(Command::TransferFromHost3d as u32, 0x0206);
        assert_eq!(Command::Submit3d as u32, 0x0207);
    }

    /// Each group is dense from its first member, so no member is missing from
    /// the table above and no number was invented.
    #[test]
    fn each_group_is_dense_from_its_first_member() {
        let two_d = [
            Command::GetDisplayInfo,
            Command::ResourceCreate2d,
            Command::ResourceUnref,
            Command::SetScanout,
            Command::ResourceFlush,
            Command::TransferToHost2d,
            Command::ResourceAttachBacking,
        ];
        for (index, command) in two_d.iter().enumerate() {
            assert_eq!(*command as u32, 0x0100 + index as u32);
        }
        let three_d = [
            Command::CtxCreate,
            Command::CtxDestroy,
            Command::CtxAttachResource,
            Command::CtxDetachResource,
            Command::ResourceCreate3d,
            Command::TransferToHost3d,
            Command::TransferFromHost3d,
            Command::Submit3d,
        ];
        for (index, command) in three_d.iter().enumerate() {
            assert_eq!(*command as u32, 0x0200 + index as u32);
        }
    }

    /// The responses: two successes and an error family from `0x1200` up.
    #[test]
    fn the_responses_are_the_specifications() {
        assert_eq!(Response::OkNoData as u32, 0x1100);
        assert_eq!(Response::OkDisplayInfo as u32, 0x1101);
        assert!(!response_is_error(Response::OkNoData as u32));
        assert!(!response_is_error(Response::OkDisplayInfo as u32));
        assert!(response_is_error(0x1200), "unspecified");
        assert!(response_is_error(0x1201), "out of memory");
        assert!(response_is_error(0x1204), "invalid resource id");
        assert!(
            !response_is_error(0x11FF),
            "the last success below the family"
        );
    }

    /// `RESOURCE_CREATE_2D` is the header and four words, and the last two are
    /// the dimensions.
    #[test]
    fn create_2d_names_its_resource_and_its_size() {
        let bytes = resource_create_2d(7, FORMAT_B8G8R8X8_UNORM, 1024, 768);
        assert_eq!(RESOURCE_CREATE_2D_SIZE, 40);
        assert_eq!(RESOURCE_CREATE_2D_SIZE, CTRL_HEADER_SIZE + 4 * 4);
        assert_eq!(word(&bytes, 0), Command::ResourceCreate2d as u32);
        assert_eq!(word(&bytes, 24), 7, "resource id");
        assert_eq!(word(&bytes, 28), 2, "B8G8R8X8_UNORM");
        assert_eq!(word(&bytes, 32), 1024, "width");
        assert_eq!(word(&bytes, 36), 768, "height");
    }

    /// `RESOURCE_UNREF` names one resource and pads the word after it.
    #[test]
    fn unref_names_one_resource() {
        let bytes = resource_unref(9);
        assert_eq!(RESOURCE_UNREF_SIZE, 32);
        assert_eq!(word(&bytes, 0), Command::ResourceUnref as u32);
        assert_eq!(word(&bytes, 24), 9);
        assert_eq!(word(&bytes, 28), 0, "padding");
    }

    /// `SET_SCANOUT` carries a rectangle, then the scanout id, then the
    /// resource, which is the specification's order and not the reverse.
    #[test]
    fn set_scanout_carries_the_rectangle_then_the_pair() {
        let bytes = set_scanout(3, 1, 640, 480);
        assert_eq!(SET_SCANOUT_SIZE, 48);
        assert_eq!(word(&bytes, 0), Command::SetScanout as u32);
        assert_eq!(word(&bytes, 24), 0, "rect x");
        assert_eq!(word(&bytes, 28), 0, "rect y");
        assert_eq!(word(&bytes, 32), 640, "rect width");
        assert_eq!(word(&bytes, 36), 480, "rect height");
        assert_eq!(word(&bytes, 40), 1, "scanout id");
        assert_eq!(word(&bytes, 44), 3, "resource id");
    }

    /// `RESOURCE_FLUSH` is 48 bytes: the rectangle, then the id, then padding.
    #[test]
    fn resource_flush_is_forty_eight_bytes() {
        let bytes = resource_flush(9, 800, 600);
        assert_eq!(RESOURCE_FLUSH_SIZE, 48);
        assert_eq!(word(&bytes, 0), Command::ResourceFlush as u32);
        assert_eq!(word(&bytes, 32), 800, "rect width");
        assert_eq!(word(&bytes, 36), 600, "rect height");
        assert_eq!(word(&bytes, 40), 9, "resource id");
        assert_eq!(word(&bytes, 44), 0, "padding");
    }

    /// `TRANSFER_TO_HOST_2D`'s order: the rectangle, then the 64-bit offset,
    /// then the resource id.
    ///
    /// The previous tree put the id first and QEMU read the padding as an id,
    /// answering `VIRTIO_GPU_RESP_ERR_INVALID_RESOURCE_ID` -- a message that
    /// names the wrong field.
    #[test]
    fn transfer_2d_puts_the_offset_before_the_resource() {
        let bytes = transfer_to_host_2d(11, 320, 200);
        assert_eq!(TRANSFER_TO_HOST_2D_SIZE, 56);
        assert_eq!(word(&bytes, 0), Command::TransferToHost2d as u32);
        assert_eq!(word(&bytes, 32), 320, "rect width");
        assert_eq!(word(&bytes, 36), 200, "rect height");
        assert_eq!(long(&bytes, 40), 0, "offset");
        assert_eq!(word(&bytes, 48), 11, "resource id");
        assert_eq!(word(&bytes, 52), 0, "padding");
    }

    /// `ATTACH_BACKING` carries its single entry inline, immediately after the
    /// entry count, and nothing sits between them.
    #[test]
    fn attach_backing_puts_its_entry_inline() {
        let bytes = attach_backing(5, 0x1234_5000, 0x18_0000);
        assert_eq!(ATTACH_BACKING_SIZE, 48);
        assert_eq!(ATTACH_BACKING_SIZE, CTRL_HEADER_SIZE + 8 + MEM_ENTRY_SIZE);
        assert_eq!(word(&bytes, 0), Command::ResourceAttachBacking as u32);
        assert_eq!(word(&bytes, 24), 5, "resource id");
        assert_eq!(word(&bytes, 28), 1, "one entry");
        assert_eq!(long(&bytes, 32), 0x1234_5000, "the entry's address");
        assert_eq!(word(&bytes, 40), 0x18_0000, "its length");
        assert_eq!(word(&bytes, 44), 0, "its padding");
    }

    /// `RESOURCE_CREATE_3D`'s twelve fields, in the specification's order, and
    /// the last one is padding rather than the stride the previous tree named.
    #[test]
    fn create_3d_names_all_twelve_fields() {
        let bytes = resource_create_3d(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11);
        assert_eq!(RESOURCE_CREATE_3D_SIZE, 80);
        assert_eq!(RESOURCE_CREATE_3D_SIZE, CTRL_HEADER_SIZE + 14 * 4);
        assert_eq!(word(&bytes, 0), Command::ResourceCreate3d as u32);
        for (index, expected) in [1u32, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 0].iter().enumerate() {
            assert_eq!(word(&bytes, 24 + index * 4), *expected, "field {index}");
        }
        assert_eq!(word(&bytes, 76), 0, "the last word is padding");
    }

    /// `TRANSFER_TO_HOST_3D` puts its box, then a 64-bit offset, then the
    /// resource id, the level and the two strides.
    #[test]
    fn transfer_3d_orders_the_box_before_the_resource() {
        let bytes = transfer_to_host_3d(13, 64, 32, 1, 0, 256, 0);
        assert_eq!(TRANSFER_TO_HOST_3D_SIZE, 72);
        assert_eq!(word(&bytes, 0), Command::TransferToHost3d as u32);
        assert_eq!(word(&bytes, 24), 0, "box x");
        assert_eq!(word(&bytes, 28), 0, "box y");
        assert_eq!(word(&bytes, 32), 0, "box z");
        assert_eq!(word(&bytes, 36), 64, "box w");
        assert_eq!(word(&bytes, 40), 32, "box h");
        assert_eq!(word(&bytes, 44), 1, "box d");
        assert_eq!(long(&bytes, 48), 0, "offset");
        assert_eq!(word(&bytes, 56), 13, "resource id");
        assert_eq!(word(&bytes, 60), 0, "level");
        assert_eq!(word(&bytes, 64), 256, "stride");
        assert_eq!(word(&bytes, 68), 0, "layer stride");
    }

    /// `SUBMIT_3D` carries its context in the header and the stream's length
    /// after it; the bytes ride a second descriptor.
    #[test]
    fn submit_3d_carries_its_context_and_length() {
        let bytes = submit_3d(3, 512);
        assert_eq!(SUBMIT_3D_SIZE, 32);
        assert_eq!(word(&bytes, 0), Command::Submit3d as u32);
        assert_eq!(word(&bytes, 16), 3, "the header's context");
        assert_eq!(word(&bytes, 24), 512, "the stream's length");
        assert_eq!(word(&bytes, 28), 0, "padding");
    }

    /// `CTX_CREATE` carries a debug name of at most 63 bytes and its length.
    #[test]
    fn ctx_create_carries_a_named_context() {
        let bytes = ctx_create(4, b"protofire");
        assert_eq!(CTX_CREATE_SIZE, 96);
        assert_eq!(word(&bytes, 0), Command::CtxCreate as u32);
        assert_eq!(word(&bytes, 16), 4, "the header's context");
        assert_eq!(word(&bytes, 24), 9, "the name's length");
        assert_eq!(word(&bytes, 28), 0, "context_init");
        assert_eq!(&bytes[32..41], b"protofire");

        let long = [b'x'; 100];
        let bytes = ctx_create(5, &long);
        assert_eq!(word(&bytes, 24), 63, "a name is truncated at 63");
        assert_eq!(bytes[32 + 63], 0, "and the rest of the field stays zero");
    }

    /// `CTX_DESTROY` is the header alone, and its context is the header's.
    #[test]
    fn ctx_destroy_is_the_header_alone() {
        let bytes = ctx_destroy(6);
        assert_eq!(CTX_DESTROY_SIZE, CTRL_HEADER_SIZE);
        assert_eq!(word(&bytes, 0), Command::CtxDestroy as u32);
        assert_eq!(word(&bytes, 16), 6);
    }
}
