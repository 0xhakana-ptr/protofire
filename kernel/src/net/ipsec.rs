//! kernel/src/net/ipsec.rs
//!
//! The security policies and the two AEADs, plus the trust anchors a program
//! adds.
//!
//! One section of `kernel/src/net/mod.rs`.  The sections call each other in
//! both directions: the demux reaches every protocol's delivery and a protocol
//! reaches the interface, so each names what it needs through `super::`.  What
//! the split buys is that a reader looking for one protocol opens one file.

use alloc::vec::Vec;

use sync::Mutex;

use abi::Error;
use abi::Result;

/// The trust anchors programs have added at run time.
///
/// Separate from the built-in set, which is compiled from `certs/` and which no
/// call can change: a program's anchor is its own trust decision, and a table
/// that mixed the two would let a program withdraw one the image was built to
/// trust.
static ANCHORS: Mutex<net::x509::Anchors> = Mutex::new(net::x509::Anchors::new());

/// Trust a DER-encoded root, answering the id that withdraws it.
pub fn trust_anchor_add(der: &[u8]) -> Result<u32> {
    ANCHORS.lock().add(der)
}

/// Withdraw an anchor by id, answering whether one had it.
pub fn trust_anchor_remove(id: u32) -> Result<()> {
    if !ANCHORS.lock().remove(id) {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// How many run-time anchors are held, for a boot's own report.
pub fn trust_anchor_count() -> usize {
    ANCHORS.lock().len()
}

/// IPsec's two databases.
///
/// The encapsulation is [`net::ipsec`]'s and the lock is here, the arrangement
/// every other table in this file uses.  What this file decides is **where**
/// the decision is asked: on the send path before a frame is composed, and on
/// the receive path before a packet's payload is read.
static IPSEC: Mutex<net::ipsec::Tables> = Mutex::new(net::ipsec::Tables::new());

/// Add a security policy, answering its id.
pub fn ipsec_add_sp(record: &abi::network::IpsecSpDef) -> Result<u32> {
    IPSEC.lock().add_policy(record)
}

/// Remove a security policy by id.
pub fn ipsec_del_sp(id: u32) -> Result<()> {
    if !IPSEC.lock().remove_policy(id) {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// Add a security association, answering its id.
pub fn ipsec_add_sa(record: &abi::network::IpsecSaDef) -> Result<u32> {
    IPSEC.lock().add_association(record)
}

/// Remove a security association by SPI, and the policies that named it.
pub fn ipsec_del_sa(spi: u32) -> Result<()> {
    if !IPSEC.lock().remove_association(spi) {
        return Err(Error::NotFound);
    }
    Ok(())
}

/// What the two databases have done, as `IpsecGetStats` reports it.
pub fn ipsec_status() -> (usize, usize, u64, u64, u64, u64) {
    let tables = IPSEC.lock();
    let (policies, associations) = tables.counts();
    let (sealed, opened, integrity, replay) = tables.statistics();
    (policies, associations, sealed, opened, integrity, replay)
}

/// Decapsulate one arriving ESP payload, answering the bytes inside and what
/// they were.
///
/// `None` is the packet the demux drops: an SPI no association names, a tag
/// that did not verify, a sequence the window refused, or a payload too short
/// to be an ESP packet.  Every one of them is a **silent** drop, which is what
/// ESP is for: a receiver that answered a bad packet would tell a stranger
/// which part of it was wrong, and the whole construction exists to give that
/// stranger nothing.
///
/// The counters are the diagnostic a boot's line reads, and they are separate
/// on purpose: an integrity failure is a packet that was not the peer's, and a
/// replay drop is a packet that was and arrived twice.
pub(crate) fn ipsec_open(payload: &[u8]) -> Option<(Vec<u8>, u8)> {
    let mut tables = IPSEC.lock();
    // The SPI is the first four bytes and it is what names the association on
    // the wire, so it is read before anything else is trusted.
    if payload.len() < 4 {
        return None;
    }
    let spi = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let association = tables.by_spi_mut(spi)?;
    match association.open(payload) {
        Ok((inner, next_header)) => {
            tables.note_opened();
            Some((inner, next_header))
        }
        Err(Error::PermissionDenied) => {
            // The two failures share a word from the association's side and
            // not from a boot's: a sequence the window refused is a replay,
            // and one whose tag failed is an integrity failure.  The window is
            // asked before the tag, so a payload whose sequence was already
            // accepted is counted as a replay without its tag being checked.
            tables.note_replay_drop();
            None
        }
        Err(_) => {
            tables.note_integrity_failure();
            None
        }
    }
}

/// Encapsulate one outbound payload under the association a policy names.
///
/// Answers `None` when nothing protects it, which is the bypass and the
/// no-match case both: the caller sends plaintext.  Answers `Some` with the ESP
/// payload when a policy protects it.  `Discard` never reaches this function,
/// because a caller that matched a discard policy does not build a frame at
/// all.
///
/// The lookup asks the same question the sender would: the five-tuple, with the
/// ports read from the transport header the caller is about to send.  A caller
/// that has no ports passes `None`, and a policy that names a port does not
/// match it, which is the rule every selector in this tree follows.
pub(crate) fn ipsec_seal(
    source: [u8; 4],
    destination: [u8; 4],
    protocol: u8,
    ports: Option<(u16, u16)>,
    inner: &[u8],
) -> Result<Option<Vec<u8>>> {
    let mut tables = IPSEC.lock();
    match tables.outbound(source, destination, protocol, ports) {
        net::ipsec::Outcome::Bypass => Ok(None),
        net::ipsec::Outcome::Discard => Err(Error::PermissionDenied),
        net::ipsec::Outcome::Protect(id) => {
            let Some(association) = tables.association_mut(id) else {
                // A policy whose association is gone is a state the table's own
                // removal prevents, and reaching it means the two tables
                // disagreed: refusing is the one answer that cannot send
                // plaintext.
                return Err(Error::NotFound);
            };
            let sealed = association.seal(inner, protocol)?;
            tables.note_sealed();
            Ok(Some(sealed))
        }
    }
}
