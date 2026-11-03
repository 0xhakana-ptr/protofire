//! virtio/block/src/request.rs
//!
//! What a block request looks like on the wire: a header, the data, a status
//! byte.
//!
//! ## The header (specification 5.2.6)
//!
//! ```text
//! struct virtio_blk_req {
//!     le32 type;
//!     le32 reserved;   // must be zero; the device may reject a request with it set
//!     le64 sector;
//! };
//! ```
//!
//! Sixteen bytes, always first in the chain, always written by the driver.
//! `sector` is an absolute 512-byte sector number — not a byte offset, which
//! is the confusion this header's comment exists to prevent.
//!
//! ## The status byte (5.2.6.1)
//!
//! One byte, always last in the chain, always written by the device:
//!
//! | value | meaning |
//! |---|---|
//! | 0 | the request succeeded |
//! | 1 | the device failed the request |
//! | 2 | the device does not support this request type |
//!
//! There is no other error channel.  The used ring reports a *length*, not a
//! result, so a request whose status is not zero failed even though the device
//! completed it — and a driver that only checked the length would report a
//! failed write as a success.
//!
//! ## Why the types are explicit
//!
//! `RequestType` is `u32` and the wire says nothing about which values are
//! valid, so this file enumerates the ones Virtio 1.2 defines.  A driver that
//! wrote a bare `2` would be as correct and would say less.

/// The request types Virtio 1.2 defines for a block device (5.2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum RequestType {
    /// Read `data` from the device into the buffer.
    In = 0,
    /// Write `data` from the buffer to the device.
    Out = 1,
    /// Flush the device's write cache.
    Flush = 4,
    /// Read the device's identity (5.2.6.3).  Not used by this driver.
    GetId = 8,
}

/// The status byte the device writes (5.2.6.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Status {
    /// The request succeeded.
    Ok = 0,
    /// The device failed it.
    IoError = 1,
    /// The device does not support it.
    Unsupported = 2,
}

impl Status {
    /// Read the device's byte into a status.
    ///
    /// A value the specification does not define becomes [`Status::IoError`]:
    /// the device did not say "ok", and treating an unknown answer as success
    /// is the direction that loses a write silently.
    pub fn from_byte(byte: u8) -> Status {
        match byte {
            0 => Status::Ok,
            1 => Status::IoError,
            2 => Status::Unsupported,
            _ => Status::IoError,
        }
    }
}

/// The sixteen bytes a request's header occupies.
pub const HEADER_LEN: u32 = 16;

/// The one byte a request's status occupies.
pub const STATUS_LEN: u32 = 1;

/// Encode a request header into its wire bytes.
///
/// Little-endian, because that is what the specification says the fields are —
/// not because this tree's machines happen to be little-endian.  A big-endian
/// machine would need this to stay exactly as it is.
pub fn encode_header(request_type: RequestType, sector: u64) -> [u8; HEADER_LEN as usize] {
    let mut bytes = [0u8; HEADER_LEN as usize];
    bytes[0..4].copy_from_slice(&(request_type as u32).to_le_bytes());
    // bytes[4..8] is `reserved`, and it stays zero: the specification says the
    // device may reject a request that sets it, so leaving it zero is not
    // tidiness.
    bytes[8..16].copy_from_slice(&sector.to_le_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use super::HEADER_LEN;
    use super::RequestType;
    use super::Status;
    use super::encode_header;

    /// The header's layout is the specification's: type at 0, reserved at 4,
    /// sector at 8.
    #[test]
    fn the_header_layout_is_the_specifications() {
        let bytes = encode_header(RequestType::Out, 0x1122_3344_5566_7788);
        assert_eq!(&bytes[0..4], &1u32.to_le_bytes(), "OUT is type 1");
        assert_eq!(&bytes[4..8], &[0, 0, 0, 0], "reserved stays zero");
        assert_eq!(
            &bytes[8..16],
            &0x1122_3344_5566_7788u64.to_le_bytes(),
            "sector is a le64 at offset 8"
        );
    }

    /// Every type has the number the specification gives it.
    ///
    /// These are wire values: a device compares the number, so a rename in
    /// this enum would be free and a renumber would not.
    #[test]
    fn the_request_types_are_the_specifications() {
        assert_eq!(RequestType::In as u32, 0);
        assert_eq!(RequestType::Out as u32, 1);
        assert_eq!(RequestType::Flush as u32, 4);
        assert_eq!(RequestType::GetId as u32, 8);
    }

    /// A status the specification does not define is a failure, not a success.
    ///
    /// This is the direction that matters: an unknown answer read as `Ok` is a
    /// write reported as durable when the device said nothing of the kind.
    #[test]
    fn an_unknown_status_is_an_error() {
        assert_eq!(Status::from_byte(0), Status::Ok);
        assert_eq!(Status::from_byte(1), Status::IoError);
        assert_eq!(Status::from_byte(2), Status::Unsupported);
        assert_eq!(Status::from_byte(3), Status::IoError);
        assert_eq!(Status::from_byte(0xFF), Status::IoError);
    }

    /// The header is sixteen bytes and the status one, and a driver that
    /// allocated a different size would have the device write past its buffer.
    #[test]
    fn the_fixed_sizes_are_the_specifications() {
        assert_eq!(HEADER_LEN, 16);
        assert_eq!(super::STATUS_LEN, 1);
        assert_eq!(encode_header(RequestType::In, 0).len(), 16);
    }
}
