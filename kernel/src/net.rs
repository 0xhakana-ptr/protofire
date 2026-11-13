//! kernel/src/net.rs
//!
//! The kernel's network half: the interface the boot brought up, and the
//! state the network calls answer from.
//!
//! ## Why this is a module and not a field of the boot
//!
//! The probes in `devices.rs` prove the wire; this module holds what the
//! probes found, so a call made after the boot has finished answers from
//! state rather than from constants a caller would have to guess.  The
//! interface is installed once, when the card comes up, and every network
//! call reads through it — which is what makes `NetworkStatus` a fact about
//! this boot's machine rather than about the QEMU defaults a reader could
//! have looked up.
//!
//! ## What is not here yet
//!
//! The sockets.  A socket is a handle a program holds and the descriptor
//! table routes, and the table they hang off is the descriptor table's third
//! variant — that arrives with the datagram calls, which are the change that
//! grows this module into the stack's own half of the kernel.

use abi::network::NETWORK_STATUS_UP;
use abi::network::NetworkStatusRecord;
use sync::Mutex;

/// An interface: the addresses the boot's card answers for.
///
/// One interface, one address, one gateway — this build's whole routing
/// table, and the struct is honest about that by having no more fields than
/// the wire has.
pub struct Interface {
    hardware: [u8; 6],
    protocol: [u8; 4],
    gateway: [u8; 4],
}

impl Interface {
    /// The interface a boot installed, from the facts its card and its wire
    /// gave it.
    pub fn new(hardware: [u8; 6], protocol: [u8; 4], gateway: [u8; 4]) -> Self {
        Self {
            hardware,
            protocol,
            gateway,
        }
    }
}

/// The interface this boot drives, installed once by the network exercise
/// and read by every network call after.
///
/// A `Mutex<Option<_>>` for the reason the registry is: the boot writes it
/// before any program exists, and every reader after is a call that arrived
/// without a context to be handed one.
static INTERFACE: Mutex<Option<Interface>> = Mutex::new(None);

/// Install the interface the boot brought up.
///
/// Called once.  A second call replaces it, which is a second boot's
/// exercise in one address space, and this kernel has one boot.
pub fn install(interface: Interface) {
    *INTERFACE.lock() = Some(interface);
}

/// What the network answers about itself: the record `NetworkStatus` fills,
/// or `None` when this boot has no interface.
pub fn status() -> Option<NetworkStatusRecord> {
    let interface = INTERFACE.lock();
    interface.as_ref().map(|interface| {
        NetworkStatusRecord::new(
            NETWORK_STATUS_UP,
            interface.hardware,
            interface.protocol,
            interface.gateway,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::Interface;
    use super::install;
    use super::status;
    use abi::network::NETWORK_STATUS_UP;

    /// The addresses a boot installed are the addresses the record carries,
    /// in the order the wire names them: hardware, protocol, gateway.
    ///
    /// The static is one boot's state, and each test installs the interface
    /// it reads back, so a test that found another test's addresses would
    /// fail this comparison.
    #[test]
    fn the_addresses_installed_are_the_addresses_answered() {
        let hardware = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let protocol = [10, 0, 2, 15];
        let gateway = [10, 0, 2, 2];
        install(Interface::new(hardware, protocol, gateway));

        let record = status().expect("an interface");
        assert_eq!(record.state, NETWORK_STATUS_UP);
        assert_eq!(record.addresses[0..6], hardware);
        assert_eq!(record.addresses[6..10], protocol);
        assert_eq!(record.addresses[10..14], gateway);
    }
}
