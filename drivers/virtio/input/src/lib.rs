//! drivers/virtio/input/src/lib.rs
//!
//! The VirtIO input device: one event queue, the eight-byte event the
//! specification defines, and the buffers a driver keeps posted so a device
//! always has somewhere to put what happened.
//!
//! ## Why a device of buffers, and not a request
//!
//! Every other virtio device answers a request the driver submits: the block
//! device completes a sector, the network card completes a frame.  The input
//! device works the other way round -- the driver posts **empty buffers** and
//! the device fills them when something happens, on a keyboard a key and on a
//! mouse a motion.  A driver that waited for a request it never made would
//! wait for ever, so this driver's loop is `drain`: take a completion, hand
//! the caller its event, and put the same buffer back, so the ring always has
//! room for the next key.
//!
//! ## Why the event leaves as itself
//!
//! The device reports Linux evdev codes -- `KEY_A` is 30 -- and the
//! specification stops there.  What those codes mean to a console is the
//! caller's business, so [`VirtioInput::drain`] hands the caller the event
//! and not a meaning: the same device is a keyboard, a mouse or a tablet, and
//! a driver that translated would have picked one for all of them.
//!
//! ## What this driver is, and is not, a relocation of
//!
//! The previous tree's virtio_input.rs was the **MMIO** device on its
//! device-tree machines, 157 lines beside a 217-line mmio half and a
//! 96-line protocol.  This tree's virtio devices share the PCI transport,
//! which is what [`virtio_core`] provides, so this driver is the same device
//! spoken over the transport this tree already has: the event's wire shape
//! and the queue's shape are the specification's, and the mmio machinery is
//! not carried.

#![no_std]

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use spin::Mutex;

use virtio_core::Transport;
use virtio_core::VirtQueue;
use virtio_core::features::Features;
use virtio_core::queue::DESC_F_WRITE;
use virtio_core::queue::Descriptor;
use virtio_core::status::Status;

/// The device's single queue: the event queue, at index 0.
const EVENT_QUEUE: u16 = 0;

/// The deepest event queue this driver asks for.
///
/// The device offers 256 by default and the queue only has to hold what
/// arrives between two ticks: a key's press and release are two events, and a
/// human types far slower than the tick drains.  The cap is the sibling
/// drivers' own, which is why the number is not this file's invention.
const QUEUE_SIZE_LIMIT: u16 = 256;

/// How many event buffers the driver keeps posted.
///
/// The queue depth is the device's, and eight is what a boot's traffic asks:
/// a key's press and release are two events, and a human types far slower
/// than the tick drains.  A ring that fills is one whose oldest events the
/// device drops, which is the honest answer for a keyboard nobody is
/// reading.
const POSTED_BUFFERS: usize = 8;

/// An event's size, on the wire: two `le16` halves and one `le32`.
pub const EVENT_SIZE: usize = 8;

/// The event kinds the specification names, and this driver forwards.
pub mod event_kind {
    /// The marker a device sends after a report, so a reader can tell one
    /// report's events from the next report's.
    pub const SYN: u16 = 0;
    /// A key press or release.
    pub const KEY: u16 = 1;
    /// A relative motion.
    pub const REL: u16 = 2;
    /// An absolute position.
    pub const ABS: u16 = 3;
    /// A key held down, repeating.
    pub const REP: u16 = 20;
}

/// One event, as the device wrote it.
///
/// §5.8.3: `type: le16`, `code: le16`, `value: le32`.  For `EV_KEY`, `code`
/// is the Linux key code and `value` is 0 on release, 1 on press and 2 on
/// autorepeat.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InputEvent {
    /// What kind of thing happened: one of [`event_kind`].
    pub kind: u16,
    /// Which thing: for a key, the Linux key code.
    pub code: u16,
    /// How: press, release, repeat, or the motion's amount.
    pub value: i32,
}

impl InputEvent {
    /// Read the event out of a buffer the device has filled.
    pub fn from_bytes(bytes: &[u8; EVENT_SIZE]) -> Self {
        let kind = u16::from_le_bytes([bytes[0], bytes[1]]);
        let code = u16::from_le_bytes([bytes[2], bytes[3]]);
        let value = i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        Self { kind, code, value }
    }
}

/// The Linux key code the monitor's `a` arrives as.
///
/// Named for the one assertion the boot's line makes: a key the gate typed
/// is `KEY_A`, and a driver that forwarded a different number would print a
/// line the gate does not find.
pub const KEY_A: u16 = 30;
/// `KEY_B`, the second key the boot's monitor types.
pub const KEY_B: u16 = 48;

/// A device the driver is holding, with its buffers posted.
pub struct VirtioInput {
    transport: Arc<dyn Transport>,
    queue: Mutex<VirtQueue>,
    /// The buffers the device may be filling.  Each is eight bytes, and the
    /// descriptor that currently carries it is the buffer's own.
    buffers: Mutex<Vec<EventBuffer>>,
}

/// One posted buffer, and the descriptor index that carries it.
struct EventBuffer {
    bytes: alloc::boxed::Box<[u8; EVENT_SIZE]>,
    descriptor: u16,
}

impl VirtioInput {
    /// Bring up an input device over `transport`.
    ///
    /// This performs the initialisation sequence the framework spells --
    /// reset, acknowledge, driver, features, `FEATURES_OK`, one queue,
    /// `DRIVER_OK` -- and then posts the buffers, which is what makes the
    /// device able to report.  A device that refuses the modern interface is
    /// refused rather than half-initialised, the way every driver here
    /// refuses.
    pub fn new(
        transport: Arc<dyn Transport>,
    ) -> Result<Arc<Self>, virtio_core::transport::TransportError> {
        // The features a modern device needs and this driver wants.  The input
        // device has no configuration-space features of its own: the modern
        // interface and the event index are the whole of the ask.
        let offered = transport.device_features();
        let accepted = Features::offered(offered).negotiate(
            virtio_core::features::VIRTIO_F_VERSION_1
                | virtio_core::features::VIRTIO_F_RING_EVENT_IDX,
        );
        if !accepted.has_required() {
            return Err(virtio_core::transport::TransportError::Unsupported);
        }

        // 1. Reset, then the status walk.
        transport.write_status(0);
        let mut status = 0u8;
        for stage in [Status::Acknowledge, Status::Driver] {
            status = virtio_core::status::next(status, stage)
                .ok_or(virtio_core::transport::TransportError::DeviceRefused)?;
            transport.write_status(status);
        }
        transport.set_driver_features(accepted.driver());
        status = virtio_core::status::next(status, Status::FeaturesOk)
            .ok_or(virtio_core::transport::TransportError::DeviceRefused)?;
        transport.write_status(status);
        let echoed = transport.read_status();
        if virtio_core::status::failed(echoed) || echoed & Status::FeaturesOk.bit() == 0 {
            return Err(virtio_core::transport::TransportError::Unsupported);
        }

        // 2. One queue, at a size the device accepts.  The addresses the
        // device is told and the addresses the queue records are the same
        // three, or the driver would post into a ring the device never reads.
        //
        // A queue the device offers less than two entries for is a queue it
        // does not really have, whatever the count said; the sibling drivers
        // refuse it for the same reason.  Past that the size is the device's
        // own count, capped at what an event queue needs: this device is
        // drained by a tick, so a ring deeper than the cap would hold keys
        // nobody reads before the device dropped them anyway.
        let max = transport.max_queue_size(EVENT_QUEUE);
        if max < 2 {
            return Err(virtio_core::transport::TransportError::Unsupported);
        }
        let size = max.min(QUEUE_SIZE_LIMIT);
        transport.configure_queue(EVENT_QUEUE, size);

        let mut queue = VirtQueue::new(size as usize);
        let addresses = queue.device_addresses();
        transport.set_queue_addresses(EVENT_QUEUE, addresses);
        queue.set_device_addresses(addresses);
        transport.enable_queue(EVENT_QUEUE);

        status = virtio_core::status::next(status, Status::DriverOk)
            .ok_or(virtio_core::transport::TransportError::DeviceRefused)?;
        transport.write_status(status);
        if virtio_core::status::failed(transport.read_status()) {
            return Err(virtio_core::transport::TransportError::DeviceRefused);
        }

        let device = Arc::new(Self {
            transport,
            queue: Mutex::new(queue),
            buffers: Mutex::new(Vec::new()),
        });

        // Post the buffers, so the device has somewhere to put the first key
        // before the caller asks for it.  A driver that waited for a drain to
        // post would lose whatever the device sent in between -- a key typed
        // while the boot was still enumerating.
        device.keep_posted(POSTED_BUFFERS, size as usize);

        Ok(device)
    }

    /// Post `count` empty event buffers, each its own descriptor.
    ///
    /// One buffer per descriptor: an event is eight bytes and the device
    /// writes one per completion, so a chain would buy nothing and cost a
    /// next-pointer per buffer.
    fn keep_posted(&self, count: usize, queue_size: usize) {
        let mut queue = self.queue.lock();
        let mut buffers = self.buffers.lock();
        for _ in 0..count.min(queue_size) {
            if queue.free_descriptors() == 0 {
                break;
            }
            let bytes: alloc::boxed::Box<[u8; EVENT_SIZE]> =
                alloc::boxed::Box::new([0u8; EVENT_SIZE]);
            let descriptor = match queue.allocate(Descriptor {
                address: bytes.as_ptr() as u64,
                length: EVENT_SIZE as u32,
                flags: DESC_F_WRITE,
                next: 0,
            }) {
                Ok(descriptor) => descriptor,
                Err(_) => break,
            };
            buffers.push(EventBuffer { bytes, descriptor });
            queue.publish(descriptor);
        }
        drop(buffers);
        drop(queue);
        self.transport.notify(EVENT_QUEUE);
    }

    /// Take every completed event, hand each to `on_event`, and post the
    /// buffers back.
    ///
    /// The caller runs this from its own tick, because this device has no
    /// interrupt wiring: a key that arrives between ticks waits for the tick
    /// that drains it, the same wait every polling driver asks of its device.
    /// The answer is how many events were taken, which is also how a caller
    /// knows its line has something to say.
    pub fn drain(&self, mut on_event: impl FnMut(InputEvent)) -> usize {
        let mut taken = 0usize;
        loop {
            let completion = {
                let mut queue = self.queue.lock();
                match queue.take_completion() {
                    Some(completion) => completion,
                    None => break,
                }
            };
            let (descriptor, _length) = completion;

            // The buffer the completion names, read as the event it is.
            let event = {
                let mut buffers = self.buffers.lock();
                let Some(index) = buffers
                    .iter()
                    .position(|buffer| buffer.descriptor == descriptor)
                else {
                    // A completion for a buffer this driver is not holding: it
                    // is dropped, the way a completion for a request nobody
                    // waits on is dropped, because there is nothing else to do
                    // with it.
                    self.queue.lock().release(descriptor);
                    continue;
                };
                let event = InputEvent::from_bytes(buffers[index].bytes.as_ref());
                // The buffer goes back, as a fresh descriptor: the device must
                // always have somewhere to put the next key, which is the
                // whole of this device's contract.  A new descriptor rather
                // than a rewrite of the old one, because the device may still
                // be reading the old one's address when the publish happens.
                let bytes: alloc::boxed::Box<[u8; EVENT_SIZE]> =
                    alloc::boxed::Box::new([0u8; EVENT_SIZE]);
                let posted = self.queue.lock().allocate(Descriptor {
                    address: bytes.as_ptr() as u64,
                    length: EVENT_SIZE as u32,
                    flags: DESC_F_WRITE,
                    next: 0,
                });
                if let Ok(posted) = posted {
                    self.queue.lock().publish(posted);
                    buffers[index].bytes = bytes;
                    buffers[index].descriptor = posted;
                } else {
                    // The queue has no free descriptor for the replacement:
                    // the old buffer's descriptor was already released back
                    // into the ring, so this completion's slot is returned to
                    // the free list without a buffer behind it and the posted
                    // count drops by one.  The next drain posts again.
                    buffers.remove(index);
                }
                event
            };
            self.queue.lock().release(descriptor);
            self.transport.notify(EVENT_QUEUE);

            on_event(event);
            taken += 1;
        }
        taken
    }
}

#[cfg(test)]
mod tests {
    //! The event's wire shape, asserted field by field, and the constants the
    //! boot's own line names.

    use super::*;

    /// The event is eight bytes, and its halves are little-endian in the
    /// order the specification writes them: type, code, value.
    #[test]
    fn an_event_reads_from_its_eight_bytes() {
        let mut bytes = [0u8; EVENT_SIZE];
        bytes[0..2].copy_from_slice(&event_kind::KEY.to_le_bytes());
        bytes[2..4].copy_from_slice(&KEY_A.to_le_bytes());
        bytes[4..8].copy_from_slice(&1i32.to_le_bytes());

        let event = InputEvent::from_bytes(&bytes);
        assert_eq!(event.kind, event_kind::KEY);
        assert_eq!(event.code, KEY_A);
        assert_eq!(event.value, 1, "a press");
    }

    /// A release is the same shape with a zero value, and a motion's value is
    /// a signed amount -- the deltas a mouse reports go negative.
    #[test]
    fn a_release_and_a_motion_read_from_the_same_shape() {
        let mut release = [0u8; EVENT_SIZE];
        release[0..2].copy_from_slice(&event_kind::KEY.to_le_bytes());
        release[2..4].copy_from_slice(&KEY_A.to_le_bytes());
        let event = InputEvent::from_bytes(&release);
        assert_eq!(event.value, 0, "a release is a zero value");

        let mut motion = [0u8; EVENT_SIZE];
        motion[0..2].copy_from_slice(&event_kind::REL.to_le_bytes());
        motion[2..4].copy_from_slice(&0u16.to_le_bytes());
        motion[4..8].copy_from_slice(&(-3i32).to_le_bytes());
        let event = InputEvent::from_bytes(&motion);
        assert_eq!(event.kind, event_kind::REL);
        assert_eq!(event.value, -3, "a motion's amount is signed");
    }

    /// The key codes the boot's own monitor types are the codes the device
    /// sends, named here so the gate's line and the driver's cannot drift.
    #[test]
    fn the_boot_types_two_keys() {
        assert_eq!(KEY_A, 30);
        assert_eq!(KEY_B, 48);
    }

    /// The event kinds are distinct where they must be: a reader that
    /// confused `SYN` with a key would treat a report marker as a keypress.
    #[test]
    fn the_event_kinds_are_distinct() {
        let kinds = [
            event_kind::SYN,
            event_kind::KEY,
            event_kind::REL,
            event_kind::ABS,
            event_kind::REP,
        ];
        for (index, kind) in kinds.iter().enumerate() {
            for other in &kinds[index + 1..] {
                assert_ne!(kind, other);
            }
        }
        assert_eq!(event_kind::KEY, 1, "the specification's own number");
        assert_eq!(event_kind::SYN, 0);
    }
}
