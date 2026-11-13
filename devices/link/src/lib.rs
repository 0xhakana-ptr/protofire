//! devices/link/src/lib.rs
//!
//! What a network card is, as the layer above it needs one.
//!
//! ## Why this crate exists
//!
//! A protocol stack has to send a frame and receive a frame, and it must not
//! know which card did it.  Without a trait, the stack either names a driver —
//! and then a second card is a second stack — or the driver names the stack,
//! and then the driver has to know what an ARP is.  Both shapes were in this
//! tree before this crate: `virtio_net` carried `arp_request` and `parse_arp`,
//! which are the protocol's, not the device's.
//!
//! So this is the `block` crate's shape, one layer up: a small trait at the
//! bottom, drivers that implement it, the stack above, and the kernel joining
//! them.  `block` is `BlockDevice` and `QueuedBlockDevice`; `virtio_block`
//! implements both; `fs` reads through them and knows nothing about virtio.
//! Here the trait is [`LinkDevice`], `virtio_net` implements it, and `net`
//! sends frames through it.
//!
//! ## What a frame is, and what it is not
//!
//! A frame here is the bytes a card puts on the wire: an Ethernet header and
//! whatever follows it.  This crate says nothing about the Ethernet layout —
//! that is a format, and it lives in `net` beside the protocols that read it.
//!
//! The header length is not part of the contract either, and deliberately:
//! `virtio_net` prepends ten bytes of its own before the frame and strips them
//! on receive, so a caller that saw a device header here would be writing one
//! into a protocol's frame.  The bytes [`LinkDevice::submit_frame`] takes are
//! the bytes the wire sees.
//!
//! ## What this crate names
//!
//! `abi` for the error type and nothing else.  Not `sync`: a device behind this
//! trait is shared, and how it serialises its own queues is its business.  Not
//! `arch`: a card is not a machine.

#![no_std]

use abi::Result;

/// A device that moves Ethernet frames.
///
/// The two directions are separate methods rather than one round trip because
/// they are separate on the hardware: a transmit and a receive travel through
/// different queues and complete independently, which is what lets a stack ask
/// for a frame without waiting for a reply that may never come.
pub trait LinkDevice: Send + Sync {
    /// The address the device publishes, six bytes.
    fn hardware_address(&self) -> [u8; 6];

    /// Put one frame on the wire.
    ///
    /// The frame is an Ethernet header and its payload, with no device header
    /// in front of it.  The bytes are copied before this returns: the device
    /// reads them until it is finished, and the caller's borrow ends here.
    fn submit_frame(&self, frame: &[u8]) -> Result<()>;

    /// Take the next frame the device has received, if any.
    ///
    /// `Ok(None)` is "nothing arrived, ask again" — not an error, and not the
    /// same as a frame of zero length.  The frame is written at the start of
    /// `into` and its length is answered; a buffer too short for the frame is
    /// [`abi::Error::InvalidArgument`] rather than a truncated frame, because a
    /// caller handed half a frame would parse the half that arrived.
    fn receive_frame(&self, into: &mut [u8]) -> Result<Option<usize>>;

    /// The largest frame this device will hand to [`Self::receive_frame`].
    ///
    /// A caller allocates its buffer from this rather than guessing: a stack
    /// that guessed short would get `InvalidArgument` on the one frame that
    /// mattered, and one that guessed long would waste the space on every
    /// receive.
    fn maximum_frame_len(&self) -> usize;
}

/// The length of an Ethernet header, which every frame here begins with.
///
/// Written down because a receive buffer is sized from it and because a
/// protocol parser needs to know where its own header starts.  It is a fact
/// about the format, so it is here rather than in a driver: two drivers that
/// disagreed about it would disagree about what a frame is.
pub const ETHERNET_HEADER_LEN: usize = 14;

/// Read the ethertype a frame carries, or `None` when the frame is too short.
///
/// The ethertype is the two bytes after the two addresses, and it is what says
/// which protocol the payload belongs to.  Big-endian on the wire, which is
/// why this does not read a `u16` through a cast.
pub fn ethertype(frame: &[u8]) -> Option<u16> {
    let field = frame.get(12..14)?;
    Some(u16::from_be_bytes([field[0], field[1]]))
}

#[cfg(test)]
mod tests {
    use super::ETHERNET_HEADER_LEN;
    use super::ethertype;

    /// The header is the length every frame here starts with.
    #[test]
    fn the_header_is_fourteen_bytes() {
        assert_eq!(ETHERNET_HEADER_LEN, 14);
        // Two addresses and a type, which is what the number is made of.
        assert_eq!(ETHERNET_HEADER_LEN, 6 + 6 + 2);
    }

    /// The ethertype is read from its own offset, in the wire's byte order.
    ///
    /// Big-endian: `0x0806` is on the wire as `08 06`, and a caller that read
    /// it as the host's byte order would see `0x0608` and dispatch an ARP to
    /// no protocol at all.
    #[test]
    fn the_ethertype_is_big_endian_at_its_offset() {
        let mut frame = [0_u8; ETHERNET_HEADER_LEN];
        frame[12] = 0x08;
        frame[13] = 0x06;
        assert_eq!(ethertype(&frame), Some(0x0806), "ARP");

        frame[12] = 0x08;
        frame[13] = 0x00;
        assert_eq!(ethertype(&frame), Some(0x0800), "IPv4");
    }

    /// A frame too short to hold a type has none, rather than a zero.
    ///
    /// The difference matters: zero is a valid ethertype for some protocols,
    /// so answering `Some(0)` for a truncated frame would dispatch it.
    #[test]
    fn a_short_frame_has_no_ethertype() {
        assert_eq!(ethertype(&[]), None);
        assert_eq!(ethertype(&[0_u8; 12]), None);
        assert_eq!(ethertype(&[0_u8; 13]), None);
    }
}
