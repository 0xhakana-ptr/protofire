//! drivers/virtio/net/src/header.rs
//!
//! `virtio_net_hdr`: the bytes the device puts in front of every frame.
//!
//! ## Twelve bytes, and why that is not the ten the structure lists
//!
//! Section 5.1.6.1 gives the header as six fields totalling ten bytes, and
//! section 5.1.6.1.1 appends `le16 num_buffers`, making twelve, "if
//! `VIRTIO_NET_F_MRG_RXBUF` was negotiated".  This driver negotiates no
//! offloads and does not ask for `MRG_RXBUF`.
//!
//! QEMU's virtio-net uses **twelve regardless**.  Measured: with the ten-byte
//! header the card sent the guest's frames starting two bytes late, a probe
//! that filled the frame with its own byte indices had the wire carry
//! `2, 3, 4, …`, so the device had skipped twelve bytes of a buffer whose
//! header the driver had written as ten.  Two more probes pinned it: a header
//! descriptor declaring eight bytes shifted the frame to `4, 5, 6, …`, and a
//! single buffer with twelve leading zero bytes delivered the frame whole.
//!
//! A device is entitled to be read as the specification describes it, and this
//! tree's rule is the opposite of following another system's implementation.
//! The twelve is therefore what this driver *sends*, because a header shorter
//! than the device skips is a frame nobody can parse, and the comment says
//! which measurement decided that rather than which kernel does it.
//!
//! ```text
//! struct virtio_net_hdr {
//!     u8  flags;
//!     u8  gso_type;
//!     le16 hdr_len;
//!     le16 gso_size;
//!     le16 csum_start;
//!     le16 csum_offset;
//!     le16 num_buffers;       // section 5.1.6.1.1
//! };
//! ```

/// The header's length on the wire (sections 5.1.6.1 and 5.1.6.1.1).
///
/// Twelve, not ten: see the module note.  A driver that wrote ten had its
/// frames arrive two bytes short at the front.
pub const HEADER_LEN: usize = 12;

/// `u8 flags`, at zero.
pub const FLAGS: usize = 0;
/// `u8 gso_type`, at one.
pub const GSO_TYPE: usize = 1;
/// `le16 hdr_len`, at two.
pub const HDR_LEN: usize = 2;
/// `le16 gso_size`, at four.
pub const GSO_SIZE: usize = 4;
/// `le16 csum_start`, at six.
pub const CSUM_START: usize = 6;
/// `le16 csum_offset`, at eight.
pub const CSUM_OFFSET: usize = 8;
/// `le16 num_buffers`, at ten: zero for a single-buffer frame.
pub const NUM_BUFFERS: usize = 10;

/// The header this driver writes: every field zero, which is "no offload".
///
/// A `static` rather than a `const` because the descriptor has to name an
/// address the device can read for as long as the request is outstanding.  A
/// `const` is substituted at each use, so `&PLAIN` would be a fresh temporary
/// with a frame's lifetime, and the device would read a stack slot that another
/// call had already reused.
pub static PLAIN: [u8; HEADER_LEN] = [0; HEADER_LEN];

/// Whether `header` says the device did nothing this driver did not ask for.
///
/// Checked on every received frame rather than assumed.  A device that set a
/// flag here applied an offload the driver did not negotiate, and the bytes
/// after the header are then not the frame they look like, a checksum the
/// driver would take as the sender's, a segment boundary that does not exist.
/// A driver that ignored the field would hand those bytes up as a frame.
pub fn is_plain(header: &[u8]) -> bool {
    header.len() >= HEADER_LEN && header[..HEADER_LEN].iter().all(|byte| *byte == 0)
}

#[cfg(test)]
mod tests {
    use super::CSUM_OFFSET;
    use super::CSUM_START;
    use super::FLAGS;
    use super::GSO_SIZE;
    use super::GSO_TYPE;
    use super::HDR_LEN;
    use super::HEADER_LEN;
    use super::NUM_BUFFERS;
    use super::PLAIN;
    use super::is_plain;

    /// The field offsets are the structure's, and the sizes add up to twelve.
    #[test]
    fn the_header_layout_is_the_specifications() {
        assert_eq!(HEADER_LEN, 12);
        assert_eq!(FLAGS, 0);
        assert_eq!(GSO_TYPE, 1);
        assert_eq!(HDR_LEN, 2);
        assert_eq!(GSO_SIZE, 4);
        assert_eq!(CSUM_START, 6);
        assert_eq!(CSUM_OFFSET, 8);
        assert_eq!(NUM_BUFFERS, 10);
        assert_eq!(
            NUM_BUFFERS + 2,
            HEADER_LEN,
            "the last field ends the header"
        );
        assert_eq!(
            PLAIN.len(),
            HEADER_LEN,
            "the header written is exactly the header read"
        );
    }

    /// A plain header is ten zero bytes, and anything else is not plain.
    #[test]
    fn a_plain_header_is_all_zero_and_nothing_else_is() {
        assert!(is_plain(&PLAIN));
        assert!(is_plain(&[0; 64]), "a longer buffer starts with the header");

        let mut flags_set = PLAIN;
        flags_set[FLAGS] = 1;
        assert!(!is_plain(&flags_set), "the device applied an offload");
    }

    /// A buffer shorter than the header is not a plain one.
    ///
    /// A device that reported fewer bytes than the header wrote nothing this
    /// driver can interpret, and treating the absence as "no offload" would
    /// read the frame from bytes that were never written.
    #[test]
    fn a_short_buffer_is_not_a_plain_header() {
        assert!(!is_plain(&[]));
        assert!(!is_plain(&[0; HEADER_LEN - 1]));
    }
}
