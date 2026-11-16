//! kernel/src/net/filter.rs
//!
//! The rule list and the flows a stateful rule fills.
//!
//! One section of `kernel/src/net/mod.rs`.  The sections call each other in
//! both directions: the demux reaches every protocol's delivery and a protocol
//! reaches the interface, so each names what it needs through `super::`.  What
//! the split buys is that a reader looking for one protocol opens one file.

use netdev::LinkDevice;
use sync::Mutex;

use abi::Error;
use abi::Result;

use super::core::micros_since_boot;

/// The packet filter: the rules a program installed, the flows they remember,
/// and the action for a packet no rule matches.
///
/// The lock is here and the arithmetic is [`net::filter`]'s, the way the
/// fragment cache and the stream table are.  What this file decides is the two
/// places a packet crosses the machine, and those are the two calls below.
static FILTER: Mutex<net::filter::Filter> = Mutex::new(net::filter::Filter::new());

/// The filter's opinion of a packet arriving from the wire.
///
/// `false` is a silent drop: the demux returns without reading the payload,
/// and nothing answers the sender.  A starting state of allow means a boot
/// whose filter never had a rule added behaves exactly as it did before this
/// module existed, which is what makes a filter's arrival testable.
pub(crate) fn filter_inbound(packet: &net::filter::Packet) -> bool {
    FILTER
        .lock()
        .permits(net::filter::Direction::Inbound, packet, micros_since_boot())
        .allowed
}

/// The filter's opinion of a packet about to leave.
///
/// The same decision as [`filter_inbound`] with the other direction, and a
/// separate function so the two call sites cannot pass the wrong one: a filter
/// asked `Inbound` about an outbound frame is a rule set applied backwards,
/// which is a policy that is wrong in the direction that matters most.
fn filter_outbound(packet: &net::filter::Packet) -> bool {
    FILTER
        .lock()
        .permits(
            net::filter::Direction::Outbound,
            packet,
            micros_since_boot(),
        )
        .allowed
}

/// Hand one outbound frame to the card, unless a rule refuses it.
///
/// The one place the outbound filter runs, so a sender that forgot it is a
/// sender that did not call this: three callers used to reach `submit_frame`
/// directly and each would have needed its own copy of the decision.
///
/// `packet` is what the filter is asked about, and it is built by the caller
/// from the header it just wrote rather than parsed back out of the frame: the
/// frame's bytes are the caller's own, and a parse would be reading them to
/// learn what the caller already knew.
///
/// A refused frame answers [`Error::PermissionDenied`], which is the honest
/// answer to a program's own send: unlike a received packet, whose sender is
/// someone else and whom this machine tells nothing, a program whose call was
/// dropped learns that its packet did not leave.
pub(crate) fn submit_filtered(
    card: &dyn LinkDevice,
    frame: &[u8],
    packet: &net::filter::Packet,
) -> Result<()> {
    if !filter_outbound(packet) {
        return Err(Error::PermissionDenied);
    }
    card.submit_frame(frame)
}

/// The filter's rules and counters, as `FilterGetStats` reports them.
pub fn filter_status() -> (net::filter::Action, u32, u32, u64, u64) {
    let filter = FILTER.lock();
    let (allowed, dropped) = filter.counts();
    (
        filter.default_action(),
        filter.len() as u32,
        filter.flows() as u32,
        allowed,
        dropped,
    )
}

/// Add one rule, answering the id it was given.
pub fn filter_add(record: &abi::network::FilterRuleDef) -> Result<u32> {
    let rule = net::filter::Rule::from_record(record)?;
    FILTER.lock().add(rule)
}

/// Remove one rule by id, answering whether one was there.
pub fn filter_remove(id: u32) -> bool {
    FILTER.lock().remove(id)
}

/// Set the action a packet no rule matches gets.
///
/// The flows are forgotten in the same call, because they were remembered
/// under the rules that are being changed: an entry that outlived its rules
/// would allow traffic the new set was written to stop, which is the direction
/// a policy change must not fail in.
pub fn filter_set_default(action: net::filter::Action) {
    let mut filter = FILTER.lock();
    filter.forget_flows();
    filter.set_default_action(action);
}
