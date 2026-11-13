//! abi/src/network.rs
//!
//! The wire shape of what a program may ask the kernel about the network:
//! whether a card is up, and the addresses it answers for.
//!
//! ## What is deliberately not here
//!
//! Socket records, port sets, the address families a fuller stack would
//! name.  They arrive with the calls they answer, in the changes that serve
//! those calls — a record the kernel does not fill is a promise about a
//! machine state nothing observes, and this crate does not make those.

use core::mem::offset_of;
use core::mem::size_of;

/// The state word a `NetworkStatusRecord` carries for a card the kernel
/// drives.
pub const NETWORK_STATUS_UP: usize = 1;

/// How many bytes of addresses the record carries: the card's hardware
/// address in six, its protocol address in four, and the gateway's in four —
/// packed in that order, as the wire carries them.
pub const NETWORK_ADDRESSES_BYTES: usize = 14;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// What the network answers, as `NetworkStatus` fills it.
///
/// One interface, one address, one gateway — which is this build's whole
/// routing table, and the record says so rather than pretending a program
/// asked about a network.  The state word exists because "is a card up" is
/// the question this call exists for; a machine with no card answers the
/// call with `NotFound` rather than a record that says `DOWN`, because a
/// record implies addresses and a machine with no card has none.
pub struct NetworkStatusRecord {
    /// Whether the card is up: [`NETWORK_STATUS_UP`].
    pub state: usize,
    /// The three addresses, packed: hardware, protocol, gateway.
    pub addresses: [u8; NETWORK_ADDRESSES_BYTES],
}

impl NetworkStatusRecord {
    /// The record for an interface the kernel drives.
    pub fn new(state: usize, hardware: [u8; 6], protocol: [u8; 4], gateway: [u8; 4]) -> Self {
        let mut addresses = [0_u8; NETWORK_ADDRESSES_BYTES];
        addresses[0..6].copy_from_slice(&hardware);
        addresses[6..10].copy_from_slice(&protocol);
        addresses[10..14].copy_from_slice(&gateway);
        Self { state, addresses }
    }
}

pub const NETWORK_STATUS_SIZE: usize = size_of::<NetworkStatusRecord>();

/// Where a datagram came from, as `RecvFromUdp` answers it: a word of
/// address and a word of port.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpSenderRecord {
    /// The sender's protocol address, packed by [`pack_address`].
    pub address: usize,
    /// The sender's port, as the datagram's header carried it.
    pub port: usize,
}

pub const UDP_SENDER_RECORD_SIZE: usize = size_of::<UdpSenderRecord>();
pub const UDP_SENDER_ADDRESS_OFFSET: usize = offset_of!(UdpSenderRecord, address);
pub const UDP_SENDER_PORT_OFFSET: usize = offset_of!(UdpSenderRecord, port);

/// Pack an IPv4 address into a word, the first byte in the highest byte of
/// the low word: `10.0.2.2` is `0x0A000202`.
///
/// Both directions live here because the address crosses the boundary as a
/// word — `SendToUdp` carries its destination in one, `RecvFromUdp` answers
/// its sender with one — and a caller that packed it in the host's order
/// would send to `0x0202000A` and call the silence the wire's.
pub const fn pack_address(address: [u8; 4]) -> usize {
    ((address[0] as usize) << 24)
        | ((address[1] as usize) << 16)
        | ((address[2] as usize) << 8)
        | address[3] as usize
}

/// The word [`pack_address`] made, back as the four bytes the wire carries.
pub const fn unpack_address(word: usize) -> [u8; 4] {
    [
        (word >> 24) as u8,
        (word >> 16) as u8,
        (word >> 8) as u8,
        word as u8,
    ]
}

#[cfg(test)]
mod tests {
    use super::NETWORK_ADDRESSES_BYTES;
    use super::NETWORK_STATUS_SIZE;
    use super::NETWORK_STATUS_UP;
    use super::NetworkStatusRecord;
    use super::UDP_SENDER_RECORD_SIZE;
    use super::UdpSenderRecord;
    use super::pack_address;
    use super::unpack_address;

    /// The record's layout is the wire's: a word of state, then the fourteen
    /// address bytes in the order the boot's own exchange names them.
    #[test]
    fn the_record_carries_a_word_and_three_addresses() {
        assert_eq!(NETWORK_STATUS_SIZE, 24, "a word, then the addresses");
        assert_eq!(NETWORK_ADDRESSES_BYTES, 14, "six, then four, then four");

        let record = NetworkStatusRecord::new(
            NETWORK_STATUS_UP,
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
            [10, 0, 2, 15],
            [10, 0, 2, 2],
        );
        assert_eq!(record.addresses[0..6], [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        assert_eq!(record.addresses[6..10], [10, 0, 2, 15]);
        assert_eq!(record.addresses[10..14], [10, 0, 2, 2]);
    }

    /// The sender record is two words, and the address packing round-trips
    /// through the word both sides of the boundary carry.
    #[test]
    fn the_sender_record_is_two_words_and_the_address_packs() {
        assert_eq!(UDP_SENDER_RECORD_SIZE, 16);
        let record = UdpSenderRecord {
            address: pack_address([10, 0, 2, 2]),
            port: 8612,
        };
        assert_eq!(record.address, 0x0A00_0202, "the first byte is the highest");
        assert_eq!(unpack_address(record.address), [10, 0, 2, 2]);
        assert_eq!(unpack_address(pack_address([255, 255, 255, 255])), [255; 4]);
    }
}
