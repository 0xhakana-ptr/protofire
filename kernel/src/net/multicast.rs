//! kernel/src/net/multicast.rs
//!
//! The forwarder's two tables and the frame it produces.
//!
//! One section of `kernel/src/net/mod.rs`.  The sections call each other in
//! both directions: the demux reaches every protocol's delivery and a protocol
//! reaches the interface, so each names what it needs through `super::`.  What
//! the split buys is that a reader looking for one protocol opens one file.

use sync::Mutex;

use abi::Error;
use abi::Result;

use super::core::INTERFACE;

/// Multicast routing's two tables, and the one machine-wide switch that says
/// whether forwarding happens at all.
///
/// The arithmetic is [`net::multicast`]'s and the locks are here, the same
/// arrangement the filter and the fragment cache use: `net` computes a decision
/// over values, and this file decides when the decision is asked.
///
/// The three are one `Mutex` and not three, because no read of one is useful
/// without the others: a forwarding decision reads the cache, then every
/// interface the entry names.  Two locks would be two chances to take them in
/// opposite orders on two CPUs, which is the defect this tree already paid for
/// once.
pub(crate) struct Multicast {
    /// Whether `MrtInit` ran and `MrtDone` has not, which is what makes a
    /// forwarding decision happen at all.
    pub(crate) routing: bool,
    pub(crate) interfaces: net::multicast::Interfaces,
    pub(crate) cache: net::multicast::Cache,
}

impl Multicast {
    const fn new() -> Self {
        Self {
            routing: false,
            interfaces: net::multicast::Interfaces::new(),
            cache: net::multicast::Cache::new(),
        }
    }
}

pub(crate) static MULTICAST: Mutex<Multicast> = Mutex::new(Multicast::new());

/// Enable multicast routing: the local interface, a link interface, and the
/// switch.
///
/// The link interface is installed here rather than by the caller, because
/// there is exactly one card and `MrtAddVif` cannot install it without naming a
/// number: a caller that had to add it would be a caller whose routing works
/// only if it also knew which index `MrtInit` reserved.  A second `MrtInit` is
/// a no-op rather than an error, which is what makes a restart cheap.
pub fn multicast_init() -> Result<()> {
    let mut state = MULTICAST.lock();
    if state.routing {
        return Ok(());
    }
    if !state.interfaces.is_empty() {
        // An init over tables a previous session left is an init over state
        // nothing vetted: `done` clears both, so a table here means a caller
        // installed entries between a done and this init, which is the state
        // that makes the switch unsafe to turn on.
        return Err(Error::Busy);
    }
    state.interfaces.install_local();
    state.interfaces.add(0, net::multicast::Vif::Link, 1, 0)?;
    state.routing = true;
    Ok(())
}

/// Disable multicast routing and forget both tables.
///
/// Answered as `NotFound` when routing was not on, which is the difference
/// between "it is off" and "you turned off something that was on": a program
/// that disables twice should learn the second call did nothing.
pub fn multicast_done() -> Result<()> {
    let mut state = MULTICAST.lock();
    if !state.routing {
        return Err(Error::NotFound);
    }
    state.routing = false;
    state.interfaces = net::multicast::Interfaces::new();
    state.cache.clear();
    Ok(())
}

/// Add a virtual interface, answering the index it was given.
pub fn multicast_add_vif(record: &abi::network::MrtVifDef) -> Result<u32> {
    let vif = match record.flags
        & !(abi::network::MRT_VIF_FLAG_LOCAL | abi::network::MRT_VIF_FLAG_LINK)
    {
        abi::network::MRT_VIF_FLAG_LOCAL => net::multicast::Vif::Local,
        abi::network::MRT_VIF_FLAG_LINK => net::multicast::Vif::Link,
        _ => return Err(Error::InvalidArgument),
    };
    if record.reserved0 != 0 || record.reserved1 != 0 {
        return Err(Error::InvalidArgument);
    }
    MULTICAST
        .lock()
        .interfaces
        .add(record.vif_index, vif, record.threshold, record.rate_limit)
}

/// Remove a virtual interface.
pub fn multicast_del_vif(index: u32) -> Result<()> {
    let mut state = MULTICAST.lock();
    if index == net::multicast::VIF_LOCAL {
        return Err(Error::InvalidArgument);
    }
    state.interfaces.remove(index)
}

/// Add a forwarding-cache entry, answering whether it replaced one.
pub fn multicast_add_mfc(record: &abi::network::MrtMfcDef) -> Result<bool> {
    let count = record.num_out_vifs as usize;
    if count > record.out_vifs.len() {
        return Err(Error::InvalidArgument);
    }
    let outgoing: alloc::vec::Vec<(u32, u32)> = record.out_vifs[..count]
        .iter()
        .map(|entry| (entry.vif, entry.ttl))
        .collect();
    MULTICAST
        .lock()
        .cache
        .add(record.source, record.group, record.in_vif, &outgoing)
}

/// Remove a forwarding-cache entry.
pub fn multicast_del_mfc(source: [u8; 4], group: [u8; 4]) -> Result<()> {
    if !MULTICAST.lock().cache.remove(source, group) {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// What one arriving multicast packet does, answering the interfaces it
/// forwarded by.
///
/// Called from the demux, which is the one place a frame from the card is read.
/// The three refusals are ordered so the cheap ones come first: routing off is
/// one load, a group nobody forwards is a walk, and only then is the interface
/// table read.
///
/// `None` when nothing was forwarded.  A packet that was **limited** by a
/// threshold returns `Some` with an empty set, which the caller reports: "a
/// loop or a low hop count kept it" and "no entry named it" are different
/// silences and a boot's line should tell them apart.
pub(crate) fn multicast_forward(
    source: [u8; 4],
    group: [u8; 4],
    arriving: u32,
    time_to_live: u8,
    bytes: usize,
) -> Option<net::multicast::Forwarding> {
    let mut state = MULTICAST.lock();
    if !state.routing {
        return None;
    }
    let decision = net::multicast::decide(
        &state.cache,
        &state.interfaces,
        source,
        group,
        arriving,
        time_to_live,
    )?;
    if !decision.outgoing.is_empty() {
        state.cache.note_forwarded(source, group, bytes);
    }
    Some(decision)
}

/// The groups this machine forwards for, as the demux's receive test asks.
///
/// A group is "joined" when a forwarding entry names it, which is the whole of
/// what multicast routing adds to a host's receive set: a router reads a group
/// because it forwards that group, and a host that installed no entry reads
/// none.  The list is built here rather than stored, because it is derived from
/// the cache and a second copy would be a second thing to keep in step.
///
/// Four entries at most, which is the ABI's own bound on the outgoing set and
/// the number of groups a boot's own report says it forwards; a group past the
/// fourth is one the receive test would miss, so the list is the cap and the
/// cap is stated rather than silently truncating at a call site.
pub(crate) fn forwarded_groups() -> [[u8; 4]; 4] {
    let mut groups = [[0_u8; 4]; 4];
    let state = MULTICAST.lock();
    let mut count = 0;
    for entry in state.cache.entries() {
        if count == groups.len() {
            break;
        }
        if !groups[..count].contains(&entry.group) {
            groups[count] = entry.group;
            count += 1;
        }
    }
    groups
}

/// Send one copy of a multicast packet out of each interface a forwarding
/// decision named.
///
/// The frame is rebuilt rather than forwarded byte for byte, because one field
/// must change: the time-to-live drops by one, which is what makes a loop
/// terminate, and the header's checksum covers it.  The payload is the
/// sender's, copied exactly, so a forwarded datagram is the datagram that
/// arrived.
///
/// An interface that is not [`net::multicast::Vif::Link`] gets nothing: the
/// local interface is the delivery this packet already had by being read, and a
/// copy "to" it would be the host sending itself what it just received.
pub(crate) fn forward_multicast(
    packet: &net::ipv4::Packet,
    payload: &[u8],
    forwarding: &net::multicast::Forwarding,
) {
    if forwarding.outgoing.is_empty() {
        #[cfg(target_os = "none")]
        {
            arch::serial::write_str("protofire: multicast for ");
            arch::serial::write_u32(abi::network::pack_address(packet.header.destination) as u32);
            arch::serial::write_str(" was limited by ");
            arch::serial::write_u32(forwarding.limited.len() as u32);
            arch::serial::write_str(" interface(s)\n");
        }
        return;
    }

    // The time-to-live a copy leaves with, which is the arriving one minus the
    // hop it just made.  `decide` already refused a copy whose count did not
    // clear the interface's threshold, so this cannot underflow into a packet
    // that leaves with a count it did not have.
    let time_to_live = packet.header.time_to_live.saturating_sub(1);
    let interface = INTERFACE.lock();
    let Some(interface) = interface.as_ref() else {
        return;
    };
    let (hardware, local) = (interface.hardware, interface.protocol);
    let frame_len = netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + payload.len();
    for _ in forwarding.outgoing.iter() {
        let mut frame = alloc::vec![0; frame_len];
        net::ethernet::write_header(
            &mut frame,
            net::ipv4::multicast_mac(packet.header.destination),
            hardware,
            net::ethernet::ETHERTYPE_IPV4,
        );
        net::ipv4::write_header(
            &mut frame[netdev::ETHERNET_HEADER_LEN..],
            packet.header.source,
            packet.header.destination,
            packet.header.protocol,
            payload.len(),
        );
        // The header's own field, and then the sum it is covered by: a writer
        // puts `TIME_TO_LIVE` in and this is the one send whose count is not
        // that constant.
        frame[netdev::ETHERNET_HEADER_LEN + 8] = time_to_live;
        let header_end = netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN;
        frame[netdev::ETHERNET_HEADER_LEN + 10..netdev::ETHERNET_HEADER_LEN + 12]
            .copy_from_slice(&[0, 0]);
        let sum = net::ipv4::checksum(&frame[netdev::ETHERNET_HEADER_LEN..header_end]);
        frame[netdev::ETHERNET_HEADER_LEN + 10..netdev::ETHERNET_HEADER_LEN + 12]
            .copy_from_slice(&sum.to_be_bytes());
        frame[header_end..].copy_from_slice(payload);
        let _ = interface.card.submit_frame(&frame);
    }
    let _ = local;

    #[cfg(target_os = "none")]
    {
        arch::serial::write_str("protofire: forwarded multicast from ");
        arch::serial::write_u32(abi::network::pack_address(packet.header.source) as u32);
        arch::serial::write_str(" to ");
        arch::serial::write_u32(abi::network::pack_address(packet.header.destination) as u32);
        arch::serial::write_str(" with ttl ");
        arch::serial::write_u32(time_to_live as u32);
        arch::serial::write_str(", ");
        arch::serial::write_u32(forwarding.outgoing.len() as u32);
        arch::serial::write_str(" interface(s)\n");
    }
}
