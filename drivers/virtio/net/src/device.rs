//! drivers/virtio/net/src/device.rs
//!
//! A virtio network card: the initialisation a device goes through, and the two
//! queues it owns.
//!
//! ## The initialisation order (specification 2.1.1)
//!
//! The same sequence a block device goes through, reset, `ACKNOWLEDGE`,
//! `DRIVER`, features, `FEATURES_OK` read back, queues, `DRIVER_OK`, because
//! it is the protocol's sequence and not any one device's.  What differs is the
//! second queue and the address the device publishes instead of a capacity.
//!
//! ## The two queues, and why they are two
//!
//! Section 5.1.2: a network card has a receive queue at index 0 and a transmit
//! queue at index 1.  A block device puts every request on one queue; a card
//! cannot, because a frame arriving and a frame leaving are different
//! directions of the same ring and the device fills one while the driver fills
//! the other.
//!
//! This is the driver that made the queue index a parameter of every queue
//! operation.  Before that, `set_queue_addresses` and `enable_queue` acted on
//! whichever queue `configure_queue` last selected, which for one queue is
//! indistinguishable from correct and for two is a transmit ring the device
//! reads while the driver writes a receive ring.
//!
//! ## What this does not do yet
//!
//! No frames.  The queues exist, are programmed and are enabled, and the card
//! is `DRIVER_OK`; putting a buffer on one and taking the reply off the other
//! is the next change, and it is a change to this file rather than to the
//! framework.  The boot prints the address the card gave and the two depths, so
//! "the card came up" is a fact about a boot rather than about this comment.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use spin::Mutex;
use virtio_core::Features;
use virtio_core::Status;
use virtio_core::Transport;
use virtio_core::VirtQueue;
use virtio_core::queue::DESC_F_NEXT;
use virtio_core::queue::DESC_F_WRITE;
use virtio_core::queue::Descriptor;

use crate::config;
use crate::features::NETWORK_KNOWN;
use crate::features::VIRTIO_NET_F_MAC;
use crate::header;

use abi::Error;
use abi::Result;

/// The queue a card's received frames arrive on (specification 5.1.2).
pub const RECEIVE_QUEUE: u16 = 0;

/// The queue a card's frames leave on.
///
/// `pub` because the boot programs the card's MSI-X vector for **this** queue,
/// exactly as it does for the block device's one, and a queue index the boot
/// guessed at would be a second fact about the driver kept in a second place.
pub const TRANSMIT_QUEUE: u16 = 1;

/// The largest queue this driver asks for.
///
/// A card may offer 256 or more; a receive ring costs a buffer per entry and
/// this driver has no frame path yet, so the depth is a bound rather than a
/// tuning.  256 entries is what the block driver asks for and is a power of
/// two, which [`VirtQueue::new`] requires.
const QUEUE_SIZE_LIMIT: u16 = 256;

/// The largest frame this driver accepts, header included.
///
/// 1514 is the largest Ethernet frame with a VLAN tag, and 1526 is that plus
/// the twelve-byte header a mergeable-receive device would write.  This driver
/// negotiates neither, so the buffer is 1514 and a device that writes more is
/// [degraded](Health::Degraded) rather than believed, a length past the
/// buffer would be a read past the allocation.
pub const RECEIVE_BUFFER_LEN: usize = 1514;

/// What the driver has asked the card to send.
///
/// The frame is the driver's: it was copied into storage the request owns,
/// because the device reads it after `submit` returns.  The header is the
/// shared [`header::PLAIN`] static, which needs no owner.
struct Pending {
    /// The ticket the caller was given.
    ticket: u64,
    /// The descriptor chain's head, which is what the used ring names.
    head: u16,
    /// The frame's bytes, which the device reads.
    ///
    /// Never read by this driver again, the device is the reader, and held
    /// anyway, because the descriptor points at it.
    #[allow(dead_code)]
    _frame: Box<[u8]>,
}

/// A buffer the driver has posted for the card to fill.
struct Received {
    /// The descriptor the buffer sits in, which is what the used ring names.
    head: u16,
    /// The bytes: the device's header, then the frame, then whatever the buffer
    /// had left.
    buffer: Box<[u8; RECEIVE_BUFFER_LEN]>,
}

/// How the card is behaving, as far as the driver can tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Nothing has gone wrong that the driver noticed.
    Healthy,
    /// A frame arrived that the driver cannot interpret.  The card works; what
    /// it sent was not something this driver accepts, and the count is worth a
    /// reader's attention rather than a panic.
    Degraded,
    /// The card said `FAILED`, and it is not going to work.
    Failed,
}

/// A ticket naming one submitted frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ticket(u64);

impl Ticket {
    /// The identifier this ticket carries.
    pub const fn id(self) -> u64 {
        self.0
    }

    const fn new(id: u64) -> Self {
        Self(id)
    }
}

/// A virtio network card.
pub struct VirtioNet {
    transport: Arc<dyn Transport>,
    receive: Mutex<VirtQueue>,
    transmit: Mutex<VirtQueue>,
    features: Features,
    /// The address the card published, and the one frames will carry.
    mac: [u8; 6],
    /// The frames submitted and not yet completed, by ticket.
    pending: Mutex<Vec<Pending>>,
    /// The buffers posted for receive and not yet completed.
    received: Mutex<Vec<Received>>,
    /// The frames the device has delivered, waiting for a reader.
    delivered: Mutex<Vec<Vec<u8>>>,
    /// The next ticket number to hand out.
    next_ticket: Mutex<u64>,
    health: Mutex<Health>,
}

impl VirtioNet {
    /// Bring up a network card over `transport`.
    ///
    /// Performs the whole initialisation sequence and programs both queues.
    /// A device that does not speak the modern interface, does not offer
    /// `VIRTIO_NET_F_MAC`, or has fewer than two queues is refused rather than
    /// half-driven: each of those is a device whose receive path would be a
    /// ring nothing fills, and a card that came up and never received would
    /// look like a quiet network.
    pub fn new(transport: Arc<dyn Transport>) -> Result<Arc<Self>> {
        // 1. Reset.
        transport.write_status(0);

        // 2-3. Acknowledge, then Driver.
        let mut status = 0u8;
        for stage in [Status::Acknowledge, Status::Driver] {
            status = virtio_core::status::next(status, stage).ok_or(Error::DeviceError)?;
            transport.write_status(status);
        }

        // 4. Features: the framework's bits plus the address, and nothing else.
        let offered = transport.device_features();
        let accepted = Features::offered(offered).negotiate(NETWORK_KNOWN);
        if !accepted.has_required() {
            return Err(Error::Unsupported);
        }
        if !accepted.accepts(VIRTIO_NET_F_MAC) {
            // The address is not optional here.  A card that publishes no
            // address is one whose frames the driver would have to invent a
            // source for, and an invented source is a claim about a network
            // nobody described.
            return Err(Error::Unsupported);
        }
        transport.set_driver_features(accepted.driver());

        // 5. FEATURES_OK, then read it back: this is where a device says no.
        status = virtio_core::status::next(status, Status::FeaturesOk).ok_or(Error::DeviceError)?;
        transport.write_status(status);
        let echoed = transport.read_status();
        if virtio_core::status::failed(echoed) || echoed & Status::FeaturesOk.bit() == 0 {
            return Err(Error::Unsupported);
        }

        // 6. Two queues, each at a size its own answer allows.
        //
        // The count is checked before anything is selected because
        // `queue_select` naming a queue the device does not have is a write
        // whose meaning the device does not define, and enabling such a queue
        // yields a ring the device never reads.
        if transport.queue_count() < TRANSMIT_QUEUE + 1 {
            return Err(Error::Unsupported);
        }
        let receive = Self::bring_up_queue(&*transport, RECEIVE_QUEUE)?;
        let transmit = Self::bring_up_queue(&*transport, TRANSMIT_QUEUE)?;

        status = virtio_core::status::next(status, Status::DriverOk).ok_or(Error::DeviceError)?;
        transport.write_status(status);
        if virtio_core::status::failed(transport.read_status()) {
            return Err(Error::DeviceError);
        }

        // The address is this crate's to read: the framework hands over the
        // configuration region as opaque dwords, and which of them is an
        // address is a network card's business.
        let mac = config::mac(|offset| transport.read_device_config_dword(offset));

        Ok(Arc::new(Self {
            transport,
            receive: Mutex::new(receive),
            transmit: Mutex::new(transmit),
            features: accepted,
            mac,
            pending: Mutex::new(Vec::new()),
            received: Mutex::new(Vec::new()),
            delivered: Mutex::new(Vec::new()),
            next_ticket: Mutex::new(0),
            health: Mutex::new(Health::Healthy),
        }))
    }

    /// Size, address and enable one queue, in the order the specification
    /// requires.
    ///
    /// The three steps are one function because they are one fact: a queue the
    /// device was told about but not enabled is a ring the driver fills and the
    /// device ignores, and an enabled queue whose addresses were never written
    /// is a device reading address zero.
    fn bring_up_queue(transport: &dyn Transport, index: u16) -> Result<VirtQueue> {
        let max = transport.max_queue_size(index);
        if max < 2 {
            // A queue the device offers no depth for is a queue it does not
            // really have, whatever the count said.
            return Err(Error::Unsupported);
        }
        let size = max.min(QUEUE_SIZE_LIMIT);
        transport.configure_queue(index, size);

        let mut queue = VirtQueue::new(size as usize);
        // One value, used twice on purpose: the addresses the device is told
        // and the addresses the queue records have to be the same three, or the
        // driver would submit into a ring the device never reads.
        let addresses = queue.device_addresses();
        transport.set_queue_addresses(index, addresses);
        queue.set_device_addresses(addresses);
        transport.enable_queue(index);
        Ok(queue)
    }

    /// The address the card published.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// The features the card and this driver agreed on.
    pub fn features(&self) -> Features {
        self.features
    }

    /// How many entries the receive ring holds.
    pub fn receive_queue_size(&self) -> u16 {
        self.receive.lock().size() as u16
    }

    /// How many entries the transmit ring holds.
    pub fn transmit_queue_size(&self) -> u16 {
        self.transmit.lock().size() as u16
    }

    /// The card's transport, for a caller that has to ask the device something
    /// the driver has no method for yet.
    ///
    /// The boot's MSI-X wiring is that caller: it names the queue vector and
    /// the table entry, and neither is the driver's state.
    pub fn transport(&self) -> &Arc<dyn Transport> {
        &self.transport
    }

    /// Put one frame on the transmit queue.
    ///
    /// The chain is the specification's (section 5.1.6.2): a driver-readable
    /// header, then the frame's bytes.  The header is [`header::PLAIN`], ten
    /// zero bytes saying "no offload", which is what a driver that negotiated
    /// no offload features must send.
    ///
    /// Returns a ticket; [`VirtioNet::submit_frame_blocking`] is the caller
    /// that waits on one.
    /// The frame is copied into storage the request owns: the device reads it
    /// until it finishes, and the caller's borrow ends when this returns.
    pub fn submit_frame(&self, frame: &[u8]) -> Result<Ticket> {
        if *self.health.lock() == Health::Failed {
            return Err(Error::DeviceError);
        }
        if frame.is_empty() {
            return Err(Error::InvalidArgument);
        }
        // The device reads the frame until it finishes, and the caller's borrow
        // is over when this returns.  Copy it into storage the request owns,
        // and point the descriptor at the copy; the alternative is a descriptor
        // naming a slice that no longer exists, which works on a quiet machine.
        let owned: Box<[u8]> = frame.to_vec().into_boxed_slice();

        let mut queue = self.transmit.lock();
        if queue.free_descriptors() < 2 {
            return Err(Error::Busy);
        }
        // The header is the shared `static`, not a copy: it is ten zero bytes
        // that never change, so its address is valid for the device to read for
        // as long as the device exists, and no request has to own one.
        let header_desc = queue
            .allocate(Descriptor {
                address: header::PLAIN.as_ptr() as u64,
                length: header::HEADER_LEN as u32,
                flags: DESC_F_NEXT,
                next: 0,
            })
            .map_err(|_| Error::Busy)?;
        let frame_desc = queue
            .allocate(Descriptor {
                address: owned.as_ptr() as u64,
                length: owned.len() as u32,
                flags: 0,
                next: 0,
            })
            .map_err(|_| Error::Busy)?;
        queue.set_next(header_desc, frame_desc);

        let id = {
            let mut next = self.next_ticket.lock();
            let id = *next;
            *next = next.wrapping_add(1);
            id
        };
        queue.publish(header_desc);
        drop(queue);

        // The request is recorded **before** the doorbell, for the reason the
        // block driver records before its own: a device may complete
        // synchronously, and a completion that arrives first is one `drain`
        // cannot match to a ticket.
        self.pending.lock().push(Pending {
            ticket: id,
            head: header_desc,
            // Held for as long as the device may read it: the descriptor points
            // at these bytes, and dropping them would leave the card reading
            // memory the allocator has taken back.
            _frame: owned,
        });

        self.transport.notify(TRANSMIT_QUEUE);
        Ok(Ticket::new(id))
    }

    /// Wait for a submitted frame to be taken, bounded so a wedged card cannot
    /// hang a caller for ever.
    ///
    /// The bound is the block driver's, and for the same reason: a card that
    /// never answers is a real failure mode, and a loop with no exit turns it
    /// into a hang nobody can diagnose.
    pub fn submit_frame_blocking(&self, frame: &[u8]) -> Result<()> {
        let ticket = self.submit_frame(frame)?;
        const POLL_LIMIT: u32 = 50_000_000;
        let mut polls = 0;
        loop {
            self.drain_transmit();
            if self.is_complete(ticket.id()) {
                return if *self.health.lock() == Health::Failed {
                    Err(Error::DeviceError)
                } else {
                    Ok(())
                };
            }
            polls += 1;
            if polls > POLL_LIMIT {
                return Err(Error::TimedOut);
            }
            core::hint::spin_loop();
        }
    }

    /// Post a receive buffer the device can fill with one frame.
    ///
    /// The chain is one device-writable descriptor holding the header and a
    /// frame's worth of bytes: the device writes the header and the frame into
    /// it and reports how many bytes it wrote.  The buffer is
    /// [`RECEIVE_BUFFER_LEN`] bytes, which is the largest frame this driver
    /// accepts.
    pub fn post_receive_buffer(&self) -> Result<()> {
        let buffer = Box::new([0_u8; RECEIVE_BUFFER_LEN]);
        let address = buffer.as_ptr() as u64;

        let mut queue = self.receive.lock();
        let descriptor = queue
            .allocate(Descriptor {
                address,
                length: RECEIVE_BUFFER_LEN as u32,
                flags: DESC_F_WRITE,
                next: 0,
            })
            .map_err(|_| Error::Busy)?;
        queue.publish(descriptor);
        drop(queue);

        self.received.lock().push(Received {
            head: descriptor,
            buffer,
        });
        self.transport.notify(RECEIVE_QUEUE);
        Ok(())
    }

    /// Take one frame the card has received, if any.
    ///
    /// Writes the frame's bytes, without the device's header, into `into` and
    /// answers how many there are.  `None` when the card has nothing waiting,
    /// and an error when `into` is too short for the frame: a short buffer is
    /// the caller's mistake, and truncating would hand up a frame that is not
    /// the one the card sent.
    ///
    /// A completion whose header says the device applied an offload is dropped
    /// rather than returned: the bytes after it are not the frame they look
    /// like, and a caller that was handed them would read a checksum it did not
    /// ask for.
    ///
    /// The buffer the frame came in is spent by the taking, so this posts
    /// another: a stack that drains the ring in a loop is the caller this
    /// driver has now, and a card whose ring empties drops the next frame on
    /// the wire.  Posting here, where the buffer's death is visible, keeps
    /// the ring full without every caller remembering to.
    pub fn receive_frame(&self, into: &mut [u8]) -> Result<Option<usize>> {
        self.drain_receive();
        let mut delivered = self.delivered.lock();
        let Some(frame) = delivered.first() else {
            return Ok(None);
        };
        if frame.len() > into.len() {
            return Err(Error::InvalidArgument);
        }
        let length = frame.len();
        into[..length].copy_from_slice(frame);
        delivered.remove(0);
        drop(delivered);
        // One buffer in, one buffer back: the posted count stays what the
        // boot made it, whatever the caller's loop does.
        let _ = self.post_receive_buffer();
        Ok(Some(length))
    }

    /// Collect the transmit completions the card has published.
    fn drain_transmit(&self) -> usize {
        let mut taken = 0;
        loop {
            let completion = {
                let mut queue = self.transmit.lock();
                match queue.take_completion() {
                    Some(completion) => {
                        queue.release(completion.0);
                        Some(completion)
                    }
                    None => None,
                }
            };
            let Some((head, _length)) = completion else {
                break;
            };

            let mut pending = self.pending.lock();
            let Some(index) = pending.iter().position(|request| request.head == head) else {
                continue;
            };
            pending.swap_remove(index);
            taken += 1;
        }

        // Tell the device where the driver's interest now ends, for the reason
        // the block driver does: an event index left behind is one the device
        // stops interrupting for until the counter wraps.
        let mut queue = self.transmit.lock();
        let processed_through = queue.last_used_index();
        queue.set_used_event(processed_through);
        taken
    }

    /// Collect the frames the card has written into posted buffers.
    fn drain_receive(&self) -> usize {
        let mut taken = 0;
        loop {
            let completion = {
                let mut queue = self.receive.lock();
                match queue.take_completion() {
                    Some(completion) => {
                        queue.release(completion.0);
                        Some(completion)
                    }
                    None => None,
                }
            };
            let Some((head, length)) = completion else {
                break;
            };

            let mut received = self.received.lock();
            let Some(index) = received.iter().position(|buffer| buffer.head == head) else {
                // A completion for a buffer this driver did not post.  Nothing
                // can be done with it, and retiring a different buffer would
                // hand up a frame from the wrong slot.
                continue;
            };
            let posted = received.swap_remove(index);
            drop(received);

            let length = length as usize;
            if length <= header::HEADER_LEN || length > RECEIVE_BUFFER_LEN {
                // The device wrote no frame, or claimed more than the buffer
                // holds.  Neither is a frame this driver can hand up, and the
                // second would be a read past the allocation if it were
                // believed.
                *self.health.lock() = Health::Degraded;
                taken += 1;
                continue;
            }
            if !header::is_plain(&posted.buffer[..header::HEADER_LEN]) {
                // An offload this driver never negotiated.
                *self.health.lock() = Health::Degraded;
                taken += 1;
                continue;
            }
            let frame_len = length - header::HEADER_LEN;
            let mut frame_bytes = Vec::with_capacity(frame_len);
            frame_bytes.extend_from_slice(&posted.buffer[header::HEADER_LEN..length]);
            self.delivered.lock().push(frame_bytes);
            taken += 1;
        }

        let mut queue = self.receive.lock();
        let processed_through = queue.last_used_index();
        queue.set_used_event(processed_through);
        taken
    }

    /// Whether the ticket's request has finished, successfully or not.
    fn is_complete(&self, ticket: u64) -> bool {
        !self
            .pending
            .lock()
            .iter()
            .any(|request| request.ticket == ticket)
    }

    /// The card's health, as the driver sees it.
    pub fn health(&self) -> Health {
        *self.health.lock()
    }
}

/// The card, as the protocol stack above it sees one.
///
/// The trait is `netdev`'s, and this is the only place a card's own vocabulary
/// meets it.  Three of the four methods are the driver's own under a name the
/// stack knows: the address the device published, a frame on the transmit
/// queue, the next frame off the receive queue.  The fourth is new, and it is
/// here because a stack has to size a receive buffer and only the device knows
/// the answer.
///
/// `submit_frame` is the one that is not a rename.  The driver's own version
/// answers a [`Ticket`], because its caller wants to know when the transmit
/// queue retired the request; a stack does not.  So this blocks until the
/// device has taken the frame, and reports the failure the ticket would have.
impl netdev::LinkDevice for VirtioNet {
    fn hardware_address(&self) -> [u8; 6] {
        self.mac()
    }

    fn submit_frame(&self, frame: &[u8]) -> Result<()> {
        self.submit_frame_blocking(frame)
    }

    fn receive_frame(&self, into: &mut [u8]) -> Result<Option<usize>> {
        VirtioNet::receive_frame(self, into)
    }

    fn maximum_frame_len(&self) -> usize {
        RECEIVE_BUFFER_LEN
    }
}

#[cfg(test)]
mod tests {
    //! The tests for this module.
    //!
    //! A fake network card behind the transport trait: the initialisation
    //! sequence, the feature negotiation, and the two queues.

    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use core::sync::atomic::AtomicU64;
    use core::sync::atomic::Ordering;

    use spin::Mutex;
    use virtio_core::Transport;
    use virtio_core::features::VIRTIO_F_RING_EVENT_IDX;
    use virtio_core::features::VIRTIO_F_VERSION_1;
    use virtio_core::queue::DeviceAddresses;

    use crate::device::RECEIVE_QUEUE;
    use crate::device::TRANSMIT_QUEUE;
    use crate::device::VirtioNet;
    use crate::features::VIRTIO_NET_F_MAC;

    /// A card that records what the driver asked it to do, and services the
    /// two queues when the doorbell rings.
    ///
    /// The recording half is what the bring-up tests ask about: which queue was
    /// configured, at which size, with which addresses, and whether it was
    /// enabled.  The servicing half is what the frame tests need: it reads the
    /// descriptor chain the driver published, and answers the way a device
    /// does, the transmit completion on the used ring, and for an ARP request,
    /// a reply written into a posted receive buffer.
    struct RecordingCard {
        status: AtomicU64,
        driver_features: AtomicU64,
        /// The offered features, so a test can leave one out.
        offered: AtomicU64,
        queues: u16,
        /// Each queue's own answer, indexed by queue number.
        sizes: Vec<u16>,
        configured: Mutex<Vec<(u16, u16)>>,
        addresses: Mutex<Vec<(u16, DeviceAddresses)>>,
        enabled: Mutex<Vec<u16>>,
        mac: [u8; 6],
        /// What the device sends back once the driver has transmitted anything.
        ///
        /// An echo, not a protocol answer: this fake exists to prove the driver
        /// moves bytes in both directions, and it has no business knowing what
        /// the bytes mean.  It used to hold an ARP reply and match on the frame
        /// being an ARP request, which made the driver's own tests depend on a
        /// protocol the driver no longer carries.
        echo: Mutex<Option<Vec<u8>>>,
        /// How many completions the device has published on each queue.
        transmit_used: AtomicU64,
        receive_used: AtomicU64,
        /// How many requests the device has taken off each available ring.
        transmit_consumed: AtomicU64,
        receive_consumed: AtomicU64,
        /// The frames the driver put on the transmit queue, in order.
        transmitted: Mutex<Vec<Vec<u8>>>,
    }

    impl RecordingCard {
        fn new(queues: u16, sizes: Vec<u16>) -> Arc<Self> {
            Arc::new(Self {
                status: AtomicU64::new(0),
                driver_features: AtomicU64::new(0),
                offered: AtomicU64::new(
                    VIRTIO_F_VERSION_1 | VIRTIO_F_RING_EVENT_IDX | VIRTIO_NET_F_MAC,
                ),
                queues,
                sizes,
                configured: Mutex::new(Vec::new()),
                addresses: Mutex::new(Vec::new()),
                enabled: Mutex::new(Vec::new()),
                mac: [0x02, 0x11, 0x22, 0x33, 0x44, 0x55],
                echo: Mutex::new(None),
                transmit_used: AtomicU64::new(0),
                receive_used: AtomicU64::new(0),
                transmit_consumed: AtomicU64::new(0),
                receive_consumed: AtomicU64::new(0),
                transmitted: Mutex::new(Vec::new()),
            })
        }

        fn addresses_for(&self, index: u16) -> Option<DeviceAddresses> {
            self.addresses
                .lock()
                .iter()
                .find(|(queue, _)| *queue == index)
                .map(|(_, addresses)| *addresses)
        }

        /// Take one request off `queue`'s available ring, if the driver
        /// published one the device has not consumed.
        fn next_available(&self, queue: u16, consumed: &AtomicU64) -> Option<u16> {
            let addresses = self.addresses_for(queue)?;
            let size = self.sizes.get(queue as usize).copied()? as usize;
            if size == 0 {
                return None;
            }
            // SAFETY: the addresses came from the driver's own `VirtQueue`,
            // which lives as long as the driver, and `size` is the depth the
            // device was told.
            unsafe {
                let index = *((addresses.available as *const u8).add(2) as *const u16);
                let taken = consumed.load(Ordering::Relaxed) as u16;
                if taken == index {
                    return None;
                }
                let ring = (addresses.available as *const u8).add(4) as *const u16;
                let slot = (taken as usize) & (size - 1);
                let head = *ring.add(slot);
                consumed.store(taken.wrapping_add(1) as u64, Ordering::Relaxed);
                Some(head)
            }
        }

        /// Publish one completion on `queue`'s used ring.
        fn publish_completion(&self, queue: u16, head: u16, length: u32, used: &AtomicU64) {
            let Some(addresses) = self.addresses_for(queue) else {
                return;
            };
            let Some(size) = self.sizes.get(queue as usize).copied() else {
                return;
            };
            let size = size as usize;
            if size == 0 {
                return;
            }
            // SAFETY: as `next_available`: the used ring is the driver's, and
            // the slot is inside the depth the device was told.
            unsafe {
                let index = used.load(Ordering::Relaxed) as u16;
                let slot = (index as usize) & (size - 1);
                let element = (addresses.used as *mut u8).add(4 + slot * 8);
                core::ptr::write_unaligned(element as *mut u32, head as u32);
                core::ptr::write_unaligned(element.add(4) as *mut u32, length);
                let counter = (addresses.used as *mut u8).add(2) as *mut u16;
                core::ptr::write_unaligned(counter, index.wrapping_add(1));
                used.store(index.wrapping_add(1) as u64, Ordering::Relaxed);
            }
        }

        /// Read the descriptor at `index` of `queue`, as the device sees it.
        fn descriptor(&self, queue: u16, index: u16) -> Option<WireDescriptor> {
            let addresses = self.addresses_for(queue)?;
            // SAFETY: the descriptor table is the driver's and `index` is one
            // the driver allocated.
            Some(unsafe { *((addresses.descriptors as *const WireDescriptor).add(index as usize)) })
        }

        /// Service the transmit queue the way a card does.
        fn service_transmit(&self) {
            while let Some(head) = self.next_available(TRANSMIT_QUEUE, &self.transmit_consumed) {
                let Some(header) = self.descriptor(TRANSMIT_QUEUE, head) else {
                    return;
                };
                let Some(frame) = self.descriptor(TRANSMIT_QUEUE, header.next) else {
                    return;
                };
                let header_bytes = read_bytes(header.address as *const u8, header.length as usize);
                let frame_bytes = read_bytes(frame.address as *const u8, frame.length as usize);
                let total = header.length + frame.length;
                self.transmitted.lock().push(frame_bytes.clone());

                // What the fake sends back, if it was told to send anything.
                //
                // An echo and not a protocol answer: the driver's job is to
                // move a frame in each direction, and a fake that inspected
                // the frame would be testing a parser that is not here.
                if let Some(reply) = self.echo.lock().as_ref() {
                    self.deliver(reply);
                }
                // The header is ten bytes and is not part of the frame the
                // driver wrote: the device consumed it and the length it
                // reports is everything it read.
                let _ = header_bytes;
                self.publish_completion(TRANSMIT_QUEUE, head, total, &self.transmit_used);
            }
        }

        /// Service the receive queue: write `frame` into a posted buffer, with
        /// a plain ten-byte header in front of it, the way a device does.
        fn deliver(&self, frame: &[u8]) {
            let Some(head) = self.next_available(RECEIVE_QUEUE, &self.receive_consumed) else {
                // No buffer posted: a real card drops the frame.  Saying so is
                // what makes a test that forgot to post one fail on the frame
                // rather than on a timeout.
                return;
            };
            let Some(descriptor) = self.descriptor(RECEIVE_QUEUE, head) else {
                return;
            };
            let capacity = descriptor.length as usize;
            let length = crate::header::HEADER_LEN + frame.len();
            if length > capacity {
                return;
            }
            // SAFETY: the buffer is the driver's, device-writable, and the
            // write is inside the length the descriptor declares.
            unsafe {
                let base = descriptor.address as *mut u8;
                core::ptr::write_bytes(base, 0, crate::header::HEADER_LEN);
                core::ptr::copy_nonoverlapping(
                    frame.as_ptr(),
                    base.add(crate::header::HEADER_LEN),
                    frame.len(),
                );
            }
            self.publish_completion(RECEIVE_QUEUE, head, length as u32, &self.receive_used);
        }

        /// Service both queues, as a device does after a doorbell.
        fn perform(&self) {
            self.service_transmit();
        }
    }

    /// The descriptor as the device reads it: sixteen bytes, the same fields.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct WireDescriptor {
        address: u64,
        length: u32,
        flags: u16,
        next: u16,
    }

    /// Read `length` bytes from `address`, which the driver published.
    fn read_bytes(address: *const u8, length: usize) -> Vec<u8> {
        let mut bytes = alloc::vec![0_u8; length];
        // SAFETY: the address and length are from a descriptor the driver
        // published for the device to read, and the driver keeps it alive until
        // the completion this is part of.
        unsafe {
            core::ptr::copy_nonoverlapping(address, bytes.as_mut_ptr(), length);
        }
        bytes
    }

    impl Transport for RecordingCard {
        fn device_features(&self) -> u64 {
            self.offered.load(Ordering::Relaxed)
        }

        fn set_driver_features(&self, features: u64) {
            self.driver_features.store(features, Ordering::Relaxed);
        }

        fn read_status(&self) -> u8 {
            self.status.load(Ordering::Relaxed) as u8
        }

        fn write_status(&self, status: u8) {
            self.status.store(status as u64, Ordering::Relaxed);
        }

        fn queue_count(&self) -> u16 {
            self.queues
        }

        fn max_queue_size(&self, index: u16) -> u16 {
            // A card answers whatever its register holds, and a register for a
            // queue the device does not have holds the last value written or
            // the device's default, a *plausible* number, not zero.  That is
            // why the queue count has to be checked before anything is
            // selected: the size answer cannot be trusted to reveal that the
            // queue does not exist.
            self.sizes.get(index as usize).copied().unwrap_or(8)
        }

        fn configure_queue(&self, index: u16, size: u16) {
            self.configured.lock().push((index, size));
        }

        fn set_queue_addresses(&self, index: u16, addresses: DeviceAddresses) {
            self.addresses.lock().push((index, addresses));
        }

        fn enable_queue(&self, index: u16) {
            self.enabled.lock().push(index);
        }

        fn notify_offset(&self, _queue: u16) -> u16 {
            0
        }

        fn notify(&self, _queue: u16) {
            self.perform();
        }

        fn read_device_config_dword(&self, offset: u64) -> u32 {
            // The address lives at 0x00 as six bytes, so the low dword is the
            // first four bytes and the high dword's low half is the last two.
            let bytes = |start: usize| -> [u8; 4] {
                let mut word = [0u8; 4];
                for (index, slot) in word.iter_mut().enumerate() {
                    *slot = self.mac.get(start + index).copied().unwrap_or(0);
                }
                word
            };
            match offset {
                0 => u32::from_le_bytes(bytes(0)),
                _ => u32::from_le_bytes(bytes(4)),
            }
        }
    }

    /// The clause this change exists for: two queues, each programmed with its
    /// own rings.
    ///
    /// This is the test that would have caught the queue-selection defect.  The
    /// driver reads the addresses out of each `VirtQueue` and hands them to the
    /// transport with the queue's index; a transport that ignored the index
    /// would record queue 1's call with queue 0's addresses, and a driver that
    /// reused one address set for both queues fails here.
    #[test]
    fn both_queues_are_programmed_with_their_own_rings() {
        let card = RecordingCard::new(2, alloc::vec![8, 8]);
        let net = VirtioNet::new(card.clone()).expect("bring up");

        let addresses = card.addresses.lock().clone();
        assert_eq!(addresses.len(), 2, "both queues were programmed");
        assert_eq!(addresses[0].0, RECEIVE_QUEUE);
        assert_eq!(addresses[1].0, TRANSMIT_QUEUE);

        let receive = addresses[0].1;
        let transmit = addresses[1].1;
        assert_ne!(
            receive.descriptors, transmit.descriptors,
            "each queue has its own descriptor table"
        );
        assert_ne!(
            receive.available, transmit.available,
            "each queue has its own available ring"
        );
        assert_ne!(
            receive.used, transmit.used,
            "each queue has its own used ring"
        );
        assert_ne!(receive.descriptors, 0, "the address was never built");

        assert_eq!(
            *card.enabled.lock(),
            alloc::vec![RECEIVE_QUEUE, TRANSMIT_QUEUE],
            "both queues were enabled, each by its own index"
        );
        assert_eq!(net.receive_queue_size(), 8);
        assert_eq!(net.transmit_queue_size(), 8);
    }

    /// Each queue is sized from its own answer, not from queue 0's.
    ///
    /// `max_queue_size` took no index before this change, so a two-queue driver
    /// would have asked for queue 0's size twice.  A card whose queues differ
    /// is what makes that visible: here the receive ring offers 4 and the
    /// transmit ring 16.
    #[test]
    fn each_queue_is_sized_from_its_own_answer() {
        let card = RecordingCard::new(2, alloc::vec![4, 16]);
        let net = VirtioNet::new(card.clone()).expect("bring up");

        assert_eq!(
            *card.configured.lock(),
            alloc::vec![(RECEIVE_QUEUE, 4), (TRANSMIT_QUEUE, 16)],
            "each queue was configured with its own size"
        );
        assert_eq!(net.receive_queue_size(), 4);
        assert_eq!(net.transmit_queue_size(), 16);
    }

    /// The address comes out of the configuration region in the card's order.
    #[test]
    fn the_driver_reads_the_address_the_card_gave_it() {
        let card = RecordingCard::new(2, alloc::vec![8, 8]);
        let net = VirtioNet::new(card).expect("bring up");
        assert_eq!(net.mac(), [0x02, 0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    /// The card is left at `DRIVER_OK`, which is the stage that says it may be
    /// used, and the driver accepted the modern interface and the address bit.
    #[test]
    fn the_device_is_left_ready_with_the_address_feature() {
        let card = RecordingCard::new(2, alloc::vec![8, 8]);
        let net = VirtioNet::new(card.clone()).expect("bring up");
        assert_eq!(
            card.read_status(),
            15,
            "ACKNOWLEDGE|DRIVER|FEATURES_OK|DRIVER_OK"
        );
        let accepted = card.driver_features.load(Ordering::Relaxed);
        assert_ne!(accepted & VIRTIO_F_VERSION_1, 0);
        assert_ne!(accepted & VIRTIO_NET_F_MAC, 0);
        assert!(net.features().accepts(VIRTIO_NET_F_MAC));
    }

    /// A card with one queue is refused rather than driven as if it had two.
    ///
    /// A one-queue card would take the driver's transmit addresses for a queue
    /// it does not have, and the failure on a machine would be a card that
    /// came up and never sent anything.
    ///
    /// The card still **answers** for queue 1, because a register for a queue a
    /// device does not have holds something plausible rather than zero.  The
    /// refusal therefore has to come from the queue count; this test fails if
    /// that check is removed.
    #[test]
    fn a_card_with_one_queue_is_refused() {
        let card = RecordingCard::new(1, alloc::vec![8]);
        assert_eq!(VirtioNet::new(card).err(), Some(abi::Error::Unsupported));
    }

    /// A card that offers a queue no depth for is refused.
    ///
    /// The other half of the same question: a card may report the queue in
    /// `num_queues` and still answer zero for its size, and enabling a queue
    /// with no entries is a ring the device never reads.
    #[test]
    fn a_queue_with_no_depth_is_refused() {
        let card = RecordingCard::new(2, alloc::vec![8, 0]);
        assert_eq!(VirtioNet::new(card).err(), Some(abi::Error::Unsupported));
    }

    /// A card that publishes no address is refused.
    ///
    /// Without `VIRTIO_NET_F_MAC` the configuration region holds no address,
    /// so a driver that read one would read whatever the device put there and
    /// then send frames from it.
    #[test]
    fn a_card_without_an_address_is_refused() {
        let card = RecordingCard::new(2, alloc::vec![8, 8]);
        card.offered.store(
            VIRTIO_F_VERSION_1 | VIRTIO_F_RING_EVENT_IDX,
            Ordering::Relaxed,
        );
        assert_eq!(VirtioNet::new(card).err(), Some(abi::Error::Unsupported));
    }

    /// A card that does not speak the modern interface is refused.
    #[test]
    fn a_legacy_card_is_refused() {
        let card = RecordingCard::new(2, alloc::vec![8, 8]);
        card.offered.store(VIRTIO_NET_F_MAC, Ordering::Relaxed);
        assert_eq!(VirtioNet::new(card).err(), Some(abi::Error::Unsupported));
    }

    /// A frame leaves on transmit, and the device's answer comes back on
    /// receive.
    ///
    /// The whole exchange through the real driver: the transmit chain is
    /// published with a ten-byte header in front, the device reads the frame,
    /// answers with bytes of its own, and the driver takes the answer off the
    /// receive queue with the header stripped.  Nothing here is stubbed except
    /// the card.
    ///
    /// The bytes are opaque on purpose.  This test is about a driver moving a
    /// frame in each direction; what the frame *means* is `net`'s business, and
    /// when this driver also carried an ARP parser the two got tested together
    /// and could only fail together.
    #[test]
    fn a_frame_leaves_and_the_devices_answer_comes_back() {
        let card = RecordingCard::new(2, alloc::vec![8, 8]);

        // A frame with a recognisable pattern at every offset, so a driver that
        // shifted a byte is visible rather than plausible.
        let outgoing: Vec<u8> = (0..60u8).collect();
        let incoming: Vec<u8> = (100..160u8).collect();
        *card.echo.lock() = Some(incoming.clone());

        let net = VirtioNet::new(card.clone()).expect("bring up");
        net.post_receive_buffer().expect("post a receive buffer");
        net.submit_frame_blocking(&outgoing).expect("send");

        // What the device was handed: the frame the driver was given, behind
        // the ten zero bytes of header.
        let sent = card.transmitted.lock().clone();
        assert_eq!(sent.len(), 1, "the device was sent one frame");
        assert_eq!(sent[0], outgoing, "the frame the caller wrote");

        let mut buffer = [0_u8; crate::device::RECEIVE_BUFFER_LEN];
        let length = net
            .receive_frame(&mut buffer)
            .expect("a frame was waiting")
            .expect("the answer arrived");
        assert_eq!(length, incoming.len(), "the answer, without the header");
        assert_eq!(
            &buffer[..length],
            incoming.as_slice(),
            "every byte at its offset"
        );
        assert_eq!(net.health(), crate::device::Health::Healthy);
    }

    /// The header in front of a received frame is stripped, not kept.
    ///
    /// A driver that handed the whole buffer up would put ten bytes of device
    /// header in front of every frame, and an ARP parser reads the ethertype
    /// from bytes 12 and 13, so the frame would parse as something else and
    /// the mistake would look like a device sending garbage.
    #[test]
    fn the_devices_header_is_not_part_of_the_frame() {
        let card = RecordingCard::new(2, alloc::vec![8, 8]);
        let net = VirtioNet::new(card.clone()).expect("bring up");
        net.post_receive_buffer().expect("post");

        let frame = alloc::vec![0xAB_u8; 60];
        card.deliver(&frame);

        let mut buffer = [0_u8; crate::device::RECEIVE_BUFFER_LEN];
        let length = net.receive_frame(&mut buffer).unwrap().unwrap();
        assert_eq!(length, frame.len(), "the frame's own length");
        assert_eq!(
            &buffer[..length],
            frame.as_slice(),
            "the first byte is the frame's, not the header's"
        );
    }

    /// A frame the device says it offloaded is dropped, and the card is
    /// degraded rather than trusted.
    ///
    /// This driver negotiates no offloads, so a header with a flag set is a
    /// device doing something it was not asked to.  The bytes after it are then
    /// not the frame they look like, and handing them up would read a checksum
    /// the driver never asked for as if it were the sender's.
    #[test]
    fn a_frame_with_an_unnegotiated_offload_is_dropped() {
        let card = RecordingCard::new(2, alloc::vec![8, 8]);
        let net = VirtioNet::new(card.clone()).expect("bring up");
        net.post_receive_buffer().expect("post");

        // Deliver through the card, then set a flag in the header the device
        // wrote before the driver drains it.
        card.deliver(&alloc::vec![0xAB_u8; 60]);
        {
            let addresses = card.addresses_for(RECEIVE_QUEUE).expect("programmed");
            // SAFETY: the buffer is the one the driver posted and the device
            // wrote into; the flag is its first byte.
            unsafe {
                let head = *((addresses.available as *const u8).add(4) as *const u16);
                let descriptor = card.descriptor(RECEIVE_QUEUE, head).expect("posted");
                *(descriptor.address as *mut u8) = 0x01;
            }
        }

        let mut buffer = [0_u8; crate::device::RECEIVE_BUFFER_LEN];
        assert_eq!(
            net.receive_frame(&mut buffer).expect("drained"),
            None,
            "the frame was not handed up"
        );
        assert_eq!(net.health(), crate::device::Health::Degraded);
    }

    /// A frame the device never wrote is not handed up as an empty one.
    ///
    /// A completed receive buffer that reports ten bytes or fewer wrote no
    /// frame: a frame of zero length is what a driver that trusted the length
    /// would hand up, and an ARP parser would then read past it.
    #[test]
    fn a_receive_completion_with_no_frame_is_dropped() {
        let card = RecordingCard::new(2, alloc::vec![8, 8]);
        let net = VirtioNet::new(card.clone()).expect("bring up");
        net.post_receive_buffer().expect("post");

        // Publish a completion that wrote only the header.
        let head = {
            let addresses = card.addresses_for(RECEIVE_QUEUE).expect("programmed");
            // SAFETY: the available ring is the driver's, and the driver
            // published one entry before this.
            unsafe { *((addresses.available as *const u8).add(4) as *const u16) }
        };
        card.receive_consumed.store(1, Ordering::Relaxed);
        card.publish_completion(
            RECEIVE_QUEUE,
            head,
            crate::header::HEADER_LEN as u32,
            &card.receive_used,
        );

        let mut buffer = [0_u8; crate::device::RECEIVE_BUFFER_LEN];
        assert_eq!(net.receive_frame(&mut buffer).expect("drained"), None);
        assert_eq!(
            net.health(),
            crate::device::Health::Degraded,
            "the completion was noticed and not believed"
        );
    }
}
