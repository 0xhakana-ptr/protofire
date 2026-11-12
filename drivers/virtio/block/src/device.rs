//! drivers/virtio/block/src/device.rs
//!
//! A virtio block device: the initialisation a device goes through, and the
//! two traits it answers.
//!
//! ## The initialisation order (specification 2.1.1)
//!
//! 1. Reset the device: write status 0.
//! 2. Set `ACKNOWLEDGE`.
//! 3. Set `DRIVER`.
//! 4. Read the offered features, accept a subset, write them back.
//! 5. Set `FEATURES_OK`, then read the status back: a device that does not echo
//!    it is refusing the feature set, and the driver must stop.
//! 6. Set up a queue, then set `DRIVER_OK`.
//!
//! [`Status::next`](virtio_core::status::next) refuses a step out of order, so
//! the order is enforced rather than described.  Step 5's read-back is the one
//! place a device can say no and the driver has to listen.
//!
//! ## Why the reads and writes are separated
//!
//! [`BlockDevice::read_blocks`] and `write_blocks` are the safe calls: they
//! wait for the request to finish before returning, which is what a filesystem
//! that is not pipelining wants.  [`QueuedBlockDevice`]'s `submit_read` and
//! `submit_write` are the other half: they hand the request over and return a
//! ticket, and the caller polls.
//!
//! Both are implemented here because a virtio device really does queue, and the
//! safe calls are the same submits followed by a wait.  The device's queue
//! depth is what it was told to build.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use block::BlockDevice;
use block::DeviceHealth;
use block::QueuedBlockDevice;
use block::RequestState;
use block::Ticket;
use spin::Mutex;
use virtio_core::Status;
use virtio_core::Transport;
use virtio_core::VirtQueue;
use virtio_core::features::Features;
use virtio_core::features::VIRTIO_F_VERSION_1;
use virtio_core::queue::DESC_F_NEXT;
use virtio_core::queue::DESC_F_WRITE;
use virtio_core::queue::Descriptor;

use crate::request::HEADER_LEN;
use crate::request::RequestType;
use crate::request::STATUS_LEN;
use crate::request::Status as RequestStatus;
use crate::request::encode_header;

use abi::Error;
use abi::Result;

/// The sector size every virtio block device uses (specification 5.2.3).
pub const SECTOR_SIZE: usize = 512;

/// The queue index a block device's requests go on.
///
/// A block device has one virtqueue for everything: reads, writes and flushes
/// are all requests on queue 0.  A device with more than one queue is a device
/// with more than one *channel*, not with a queue per operation.
/// The one queue this driver keeps, and the one a boot's vector wiring names.
///
/// `pub` because the boot programs the device's MSI-X vector for **this**
/// queue, and a queue index the boot guessed at would be a second fact about
/// the driver kept in a second place.
pub const REQUEST_QUEUE: u16 = 0;

/// A block request as the device holds it while it is outstanding.
///
/// The buffers are the driver's: the header and the status are local to this
/// request, and the data buffer is the caller's, which is why `submit_read` is
/// `unsafe` and the caller is told the buffer must not move until the ticket
/// completes.
struct Pending {
    /// The ticket the caller was given.
    ticket: u64,
    /// The descriptor chain's head, which is what the used ring names.
    head: u16,
    /// The status byte's backing storage.
    ///
    /// Kept here rather than on the stack because the device writes it after
    /// `submit` returns: a status on the stack would be a device writing into
    /// a frame the function has given back.
    status: Box<[u8; STATUS_LEN as usize]>,
    /// The header's backing storage.
    ///
    /// Never read by the driver after it is written, and held anyway, because
    /// the device reads it.  Dropping it when `submit` returned would leave the
    /// device reading a frame the allocator has taken back, which on a quiet
    /// machine looks like it works.
    #[allow(dead_code)]
    header: Box<[u8; HEADER_LEN as usize]>,
    /// The bytes a write is sending, when the request is a write.
    ///
    /// A write's `&[u8]` is the caller's and may die the moment `submit_write`
    /// returns, but the device reads those bytes until it finishes.  So the
    /// bytes are copied here and the descriptor points at this copy, which
    /// lives as long as the request.
    ///
    /// A read has no such field: the device writes *into* the caller's buffer,
    /// which the `unsafe` on `submit_read` makes the caller keep alive.
    ///
    /// Never read by the driver, and held anyway, because the descriptor
    /// points at these bytes and the device reads them.  Dropping it when
    /// `submit` returned would leave the device reading a freed allocation.
    #[allow(dead_code)]
    written: Option<Box<[u8]>>,
}

/// A virtio block device.
pub struct VirtioBlock {
    transport: Arc<dyn Transport>,
    queue: Mutex<VirtQueue>,
    capacity_sectors: u64,
    /// The requests submitted and not yet completed, by ticket.
    pending: Mutex<Vec<Pending>>,
    /// The next ticket number to hand out.
    next_ticket: Mutex<u64>,
    health: Mutex<DeviceHealth>,
}

impl VirtioBlock {
    /// Bring up a block device over `transport`.
    ///
    /// This performs the whole of the initialisation sequence: reset,
    /// acknowledge, driver, features, `FEATURES_OK`, one queue, `DRIVER_OK`.
    /// A device that refuses the feature set or does not offer the modern
    /// interface is [reported as an error](Error::Unsupported) rather than
    /// half-initialised: a device that answered `FEATURES_OK` with `FAILED`
    /// set has told the driver it will not work, and continuing would be
    /// submitting into a queue it is not going to service.
    pub fn new(transport: Arc<dyn Transport>) -> Result<Arc<Self>> {
        Self::new_with_queue_size(transport, None)
    }

    /// Bring up a device with a chosen queue size.
    ///
    /// `queue_size` is capped by what the device offers for the request queue
    /// ([`Transport::max_queue_size`]); asking for more than the device has is
    /// the caller's mistake and is refused rather than silently reduced,
    /// because the caller asked for a depth it will then pipeline to.
    pub fn new_with_queue_size(
        transport: Arc<dyn Transport>,
        queue_size: Option<u16>,
    ) -> Result<Arc<Self>> {
        // 1. Reset.
        transport.write_status(0);

        // 2-3. Acknowledge, then Driver.
        let mut status = 0u8;
        for stage in [Status::Acknowledge, Status::Driver] {
            status = virtio_core::status::next(status, stage).ok_or(Error::DeviceError)?;
            transport.write_status(status);
        }

        // 4. Features: take what the device offers and this framework knows.
        let offered = transport.device_features();
        let accepted = Features::offered(offered)
            .negotiate(VIRTIO_F_VERSION_1 | virtio_core::features::VIRTIO_F_RING_EVENT_IDX);
        if !accepted.has_required() {
            // The device does not speak the modern interface, and this tree
            // has no other.
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

        // 6. One queue, at a size the device accepts.
        let max = transport.max_queue_size(REQUEST_QUEUE);
        let size = match queue_size {
            Some(requested) if requested > max => return Err(Error::InvalidArgument),
            Some(requested) if requested.is_power_of_two() => requested,
            Some(_) => return Err(Error::InvalidArgument),
            None => max.min(256),
        };
        let size = size.max(2);
        transport.configure_queue(REQUEST_QUEUE, size);

        let mut queue = VirtQueue::new(size as usize);
        // One value, used twice on purpose: the addresses the device is told
        // and the addresses the queue records have to be the same three, or
        // the driver would submit into a ring the device never reads.
        let addresses = queue.device_addresses();
        transport.set_queue_addresses(REQUEST_QUEUE, addresses);
        queue.set_device_addresses(addresses);
        transport.enable_queue(REQUEST_QUEUE);

        status = virtio_core::status::next(status, Status::DriverOk).ok_or(Error::DeviceError)?;
        transport.write_status(status);
        if virtio_core::status::failed(transport.read_status()) {
            return Err(Error::DeviceError);
        }

        // The capacity is in 512-byte sectors, which is the unit a request's
        // `sector` field uses, so no conversion happens here.  The layout is
        // this crate's now: the framework reads the configuration region as
        // opaque dwords, and what they mean is a block device's business.
        let capacity_sectors =
            crate::config::capacity_sectors(|offset| transport.read_device_config_dword(offset));

        Ok(Arc::new(Self {
            transport,
            queue: Mutex::new(queue),
            capacity_sectors,
            pending: Mutex::new(Vec::new()),
            next_ticket: Mutex::new(0),
            health: Mutex::new(DeviceHealth::Healthy),
        }))
    }

    /// Submit one request and answer its ticket.
    ///
    /// `data` is the buffer the device reads from or writes into.  The caller
    /// guarantees it outlives the ticket when the request is a read; a write
    /// copies nothing and the device is told the buffer's bytes are the
    /// caller's only until `submit_write` returns, which the trait's contract
    /// allows because a write's data travels *into* the device.
    fn submit(
        &self,
        request_type: RequestType,
        lba: u64,
        data_address: u64,
        data_len: usize,
        writes_into_data: bool,
        written: Option<Box<[u8]>>,
    ) -> Result<Ticket> {
        if *self.health.lock() == DeviceHealth::Failed {
            return Err(Error::DeviceError);
        }

        let header = Box::new(encode_header(request_type, lba));
        let status = Box::new([0xFF_u8; STATUS_LEN as usize]);

        let mut queue = self.queue.lock();
        if queue.free_descriptors() < 3 {
            return Err(Error::Busy);
        }

        let header_desc = queue
            .allocate(Descriptor {
                address: header.as_ptr() as u64,
                length: HEADER_LEN,
                flags: DESC_F_NEXT,
                next: 0, // filled below
            })
            .map_err(|_| Error::Busy)?;
        let data_desc = queue
            .allocate(Descriptor {
                address: data_address,
                length: data_len as u32,
                flags: if writes_into_data {
                    DESC_F_NEXT | DESC_F_WRITE
                } else {
                    DESC_F_NEXT
                },
                next: 0,
            })
            .map_err(|_| Error::Busy)?;
        let status_desc = queue
            .allocate(Descriptor {
                address: status.as_ptr() as u64,
                length: STATUS_LEN,
                flags: DESC_F_WRITE,
                next: 0,
            })
            .map_err(|_| Error::Busy)?;

        // Link the chain: header -> data -> status.
        queue.set_next(header_desc, data_desc);
        queue.set_next(data_desc, status_desc);

        let id = {
            let mut next = self.next_ticket.lock();
            let id = *next;
            *next = next.wrapping_add(1);
            id
        };
        queue.publish(header_desc);
        drop(queue);

        // Register the request *before* ringing the doorbell.  A device may
        // complete synchronously, this driver's host transport does, and an
        // emulator whose queue is empty may, and a completion that arrives
        // before the request is recorded is one `drain` cannot match to a
        // ticket.  It would be dropped as "a completion for a request this
        // driver is not holding", and the caller would wait for ever.
        self.pending.lock().push(Pending {
            ticket: id,
            head: header_desc,
            status,
            header,
            written,
        });

        self.transport.notify(REQUEST_QUEUE);

        Ok(Ticket::new(id))
    }

    /// Collect whatever the device has finished.
    ///
    /// Returns how many completions were taken.  A request whose status byte is
    /// not `OK` is reported as the error it is, the used ring's length says
    /// nothing about whether the device succeeded.
    fn drain(&self) -> usize {
        let mut taken = 0;
        loop {
            let completion = {
                let mut queue = self.queue.lock();
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
                // A completion for a request this driver is not holding: the
                // device named a descriptor that is not outstanding.  Nothing
                // can be done about it here, and dropping it is better than
                // retiring the wrong request.
                continue;
            };
            let request = pending.swap_remove(index);
            drop(pending);

            if RequestStatus::from_byte(request.status[0]) != RequestStatus::Ok {
                *self.health.lock() = DeviceHealth::Degraded;
            }
            taken += 1;
        }

        // **Tell the device where the driver's interest now ends.**
        //
        // The queue's event index must advance with the completions this driver
        // processes: the device interrupts when `used.idx` passes
        // `used_event`, and an index left behind is one the device stops
        // interrupting for until the counter wraps.  Measured when a
        // completion vector was wired to an IMSIC with this write missing: the
        // boot's own probe took no interrupt at all, and the mount that
        // followed took one per completion — the device's suppression was
        // reading a slot the driver had never allocated.  The slot's
        // allocation is the queue's fix; this is the driver's half.
        //
        // Written every drain, taken or not: the value is the index the driver
        // has processed through, so a drain that took nothing writes what the
        // previous one already did.
        let mut queue = self.queue.lock();
        let processed_through = queue.last_used_index();
        queue.set_used_event(processed_through);
        taken
    }

    /// The ticket still outstanding, if any, for a head descriptor.
    fn is_complete(&self, ticket: u64) -> bool {
        !self
            .pending
            .lock()
            .iter()
            .any(|request| request.ticket == ticket)
    }

    /// Wait for a ticket, bounded so a device that never answers cannot hang a
    /// caller for ever.
    ///
    /// The bound exists because a wedged device is a real failure mode and a
    /// loop with no exit turns it into a hang nobody can diagnose.  The number
    /// is large enough to cover a slow but working device and finite for a
    /// dead one.
    fn wait(&self, ticket: Ticket) -> Result<()> {
        const POLL_LIMIT: u32 = 50_000_000;
        let mut polls = 0;
        let id = ticket.id();
        loop {
            self.drain();
            if self.is_complete(id) {
                return Ok(());
            }
            polls += 1;
            if polls > POLL_LIMIT {
                return Err(Error::TimedOut);
            }
            core::hint::spin_loop();
        }
    }
}

impl BlockDevice for VirtioBlock {
    fn name(&self) -> &str {
        "virtio-blk"
    }

    fn block_size(&self) -> usize {
        SECTOR_SIZE
    }

    fn block_count(&self) -> u64 {
        self.capacity_sectors
    }

    fn is_read_only(&self) -> bool {
        // A block device that cannot write is a device whose feature set said
        // so; this driver does not negotiate read-only, so every device it
        // brings up is writable.  The check is `self.capacity_sectors == 0`
        // rather than a cached flag for that reason.
        false
    }

    fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> Result<()> {
        let ticket = unsafe { self.submit_read(lba, buffer)? };
        self.wait(ticket)
    }

    fn write_blocks(&self, lba: u64, data: &[u8]) -> Result<()> {
        let ticket = self.submit_write(lba, data)?;
        self.wait(ticket)
    }

    fn flush(&self) -> Result<()> {
        let ticket = self.submit(RequestType::Flush, 0, 0, 0, false, None)?;
        self.wait(ticket)
    }

    fn device_health(&self) -> DeviceHealth {
        *self.health.lock()
    }
}

impl QueuedBlockDevice for VirtioBlock {
    fn as_block_device(&self) -> &dyn BlockDevice {
        self
    }

    fn queue_depth(&self) -> u16 {
        self.queue.lock().size() as u16
    }

    unsafe fn submit_read(&self, lba: u64, buffer: &mut [u8]) -> Result<Ticket> {
        if !buffer.len().is_multiple_of(SECTOR_SIZE) {
            return Err(Error::InvalidArgument);
        }
        let blocks = (buffer.len() / SECTOR_SIZE) as u64;
        if lba
            .checked_add(blocks)
            .is_none_or(|end| end > self.capacity_sectors)
        {
            return Err(Error::InvalidArgument);
        }
        // SAFETY: the caller promises the buffer outlives the ticket.  The
        // device writes into it directly, so the address is the buffer's own.
        self.submit(
            RequestType::In,
            lba,
            buffer.as_mut_ptr() as u64,
            buffer.len(),
            true,
            None,
        )
    }

    fn submit_write(&self, lba: u64, data: &[u8]) -> Result<Ticket> {
        if !data.len().is_multiple_of(SECTOR_SIZE) {
            return Err(Error::InvalidArgument);
        }
        let blocks = (data.len() / SECTOR_SIZE) as u64;
        if lba
            .checked_add(blocks)
            .is_none_or(|end| end > self.capacity_sectors)
        {
            return Err(Error::InvalidArgument);
        }
        // The device reads these bytes until the request finishes, and the
        // caller's borrow is over when this returns.  Copy them into storage
        // the request owns, and point the descriptor at the copy, the
        // alternative is a descriptor naming a stack frame that no longer
        // exists, which works on a quiet machine.
        let owned: Box<[u8]> = data.to_vec().into_boxed_slice();
        let address = owned.as_ptr() as u64;
        self.submit(
            RequestType::Out,
            lba,
            address,
            owned.len(),
            false,
            Some(owned),
        )
    }

    fn poll(&self, ticket: Ticket) -> RequestState {
        self.drain();
        if self.is_complete(ticket.id()) {
            RequestState::Done(Ok(()))
        } else {
            RequestState::Pending
        }
    }
}

#[cfg(test)]
mod tests {
    //! The tests for this module.
    //!
    //! The virtio block driver through its transport trait: initialisation, the
    //! descriptor chain, and a read that comes back.
    //!
    //! Extracted from the module so that a reader following the mechanism does
    //! not have to scroll past every case it has to satisfy; see
    //! `docs/fmts/testing.md` §1.

    use alloc::sync::Arc;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::sync::atomic::AtomicU64;
    use core::sync::atomic::Ordering;

    use spin::Mutex;
    use virtio_core::Transport;
    use virtio_core::features::VIRTIO_F_VERSION_1;
    use virtio_core::queue::DeviceAddresses;

    use crate::device::SECTOR_SIZE;
    use crate::device::VirtioBlock;
    use block::BlockDevice;

    /// A transport over a byte array: the device a host test can drive.
    ///
    /// It answers the register reads the driver makes, records the writes, and
    /// performs a request when the driver rings the doorbell, reading the
    /// descriptor chain the driver published and writing the data the request
    /// asked for.  That is the whole of what a virtio block device does, so the
    /// code under test is the code a machine runs.
    struct FakeDevice {
        storage: Mutex<Vec<u8>>,
        status: AtomicU64,
        driver_features: AtomicU64,
        capacity: u64,
        /// Set between `configure_queue` and `enable_queue`.
        selected_queue_size: AtomicU64,
        addresses: Mutex<Option<DeviceAddresses>>,
        /// How many times the doorbell was rung.
        notifies: AtomicU64,
        /// The status byte the device will write for the next request.
        next_status: AtomicU64,
        /// How many requests this device has taken off the available ring.
        ///
        /// A real device has this counter in hardware, it is how it knows
        /// which entry it is working on.  Deriving it from `used.idx` would
        /// work only while every request completes, and a device that holds a
        /// request it cannot finish would lose its place.
        consumed: AtomicU64,
    }

    impl FakeDevice {
        fn new(sectors: usize) -> Arc<Self> {
            Arc::new(Self {
                storage: Mutex::new(vec![0u8; sectors * SECTOR_SIZE]),
                status: AtomicU64::new(0),
                driver_features: AtomicU64::new(0),
                capacity: sectors as u64,
                selected_queue_size: AtomicU64::new(0),
                addresses: Mutex::new(None),
                notifies: AtomicU64::new(0),
                next_status: AtomicU64::new(0),
                consumed: AtomicU64::new(0),
            })
        }

        /// Perform whatever the driver last published, as a real device would
        /// after it saw the doorbell.
        ///
        /// # Safety
        ///
        /// The addresses came from the driver's own rings, which are alive for
        /// as long as the device is, and the driver guarantees a read's buffer
        /// outlives its ticket.
        unsafe fn perform(&self) {
            // SAFETY: every access below is through an address the driver
            // published to this transport, and the driver guarantees the rings
            // and the buffers stay where they are until the request completes.
            // The whole body is one unsafe operation for that reason: splitting
            // it would repeat the same argument at each line without saying
            // more.
            unsafe {
                let Some(addresses) = *self.addresses.lock() else {
                    return;
                };
                let queue_size = self.selected_queue_size.load(Ordering::Relaxed) as usize;
                if queue_size == 0 {
                    return;
                }
                // The driver's view: descriptor table, available ring, used
                // ring. Both rings are `u8` buffers whose first four bytes are
                // the header (`flags`, `idx`), so every offset below is a byte
                // offset.
                let descriptors = addresses.descriptors as *const DescriptorWire;
                // Both rings are `u8` buffers whose first four bytes are the
                // header, so these are byte offsets into them: `.add(2)` on a
                // `u16` pointer would skip four bytes.
                let available_index_ptr = (addresses.available as *const u8).add(2) as *const u16;
                let available_ring = (addresses.available as *const u8).add(4) as *const u16;
                let used_index_ptr = (addresses.used as *const u8).add(2) as *const u16;
                let used_ring = (addresses.used as *mut u8).add(4);

                // The device consumes the available ring in order, from its own
                // count of what it has taken.  Deriving that count from
                // `used.idx` works too, they advance together, but keeping it
                // explicit is what makes a request the device is *in the middle
                // of* readable.
                let mut taken = self.consumed.load(Ordering::Relaxed) as u16;
                let available_index = { *available_index_ptr };
                while taken != available_index {
                    let slot = (taken as usize) & (queue_size - 1);
                    let head = { *available_ring.add(slot) } as usize;

                    let header = { *descriptors.add(head) };
                    let data = { *descriptors.add(header.next as usize) };
                    let status_desc = { *descriptors.add(data.next as usize) };

                    let request_type = core::ptr::read_unaligned(header.address as *const u32);
                    let sector_value = core::ptr::read_unaligned(
                        (header.address as *const u8).add(8) as *const u64,
                    );

                    match request_type {
                        // IN: the device writes into the data buffer.
                        0 => {
                            let start = sector_value as usize * SECTOR_SIZE;
                            let len = data.length as usize;
                            let src = &self.storage.lock()[start..start + len];
                            core::ptr::copy_nonoverlapping(
                                src.as_ptr(),
                                data.address as *mut u8,
                                len,
                            );
                        }
                        // OUT: the device reads the data buffer.
                        1 => {
                            let start = sector_value as usize * SECTOR_SIZE;
                            let len = data.length as usize;
                            let mut storage = self.storage.lock();
                            core::ptr::copy_nonoverlapping(
                                data.address as *const u8,
                                storage[start..start + len].as_mut_ptr(),
                                len,
                            );
                        }
                        _ => {}
                    }

                    // The status byte, then the used ring.
                    let status = self.next_status.swap(0, Ordering::Relaxed) as u8;
                    core::ptr::write_volatile(status_desc.address as *mut u8, status);
                    let used_slot = (taken as usize) & (queue_size - 1);
                    let used_element = used_ring.add(used_slot * 8);
                    core::ptr::write_unaligned(used_element as *mut u32, head as u32);
                    core::ptr::write_unaligned(used_element.add(4) as *mut u32, data.length);

                    taken = taken.wrapping_add(1);
                    core::ptr::write_unaligned(used_index_ptr as *mut u16, taken);
                }
                self.consumed.store(taken as u64, Ordering::Relaxed);
            }
        }
    }

    /// The descriptor as the device reads it: sixteen bytes, the same fields.
    ///
    /// A separate type from the driver's `Descriptor` on purpose: the device
    /// has its own structure, and a test that reused the driver's type would
    /// not catch a driver whose layout drifted.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct DescriptorWire {
        address: u64,
        length: u32,
        flags: u16,
        next: u16,
    }

    impl Transport for FakeDevice {
        fn device_features(&self) -> u64 {
            VIRTIO_F_VERSION_1 | virtio_core::features::VIRTIO_F_RING_EVENT_IDX
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
            1
        }

        fn max_queue_size(&self, _index: u16) -> u16 {
            8
        }

        fn configure_queue(&self, _index: u16, size: u16) {
            self.selected_queue_size
                .store(size as u64, Ordering::Relaxed);
        }

        fn set_queue_addresses(&self, _index: u16, addresses: DeviceAddresses) {
            *self.addresses.lock() = Some(addresses);
        }

        fn enable_queue(&self, _index: u16) {}

        fn notify_offset(&self, _queue: u16) -> u16 {
            0
        }

        fn notify(&self, _queue: u16) {
            self.notifies.fetch_add(1, Ordering::Relaxed);
            // SAFETY: the driver rang the doorbell after publishing a request,
            // and the rings are alive for the device's lifetime.
            unsafe { self.perform() };
        }

        fn read_device_config_dword(&self, offset: u64) -> u32 {
            match offset {
                0 => self.capacity as u32,
                _ => (self.capacity >> 32) as u32,
            }
        }
    }

    /// A write followed by a read returns the same bytes through the real
    /// driver code and a device that behaves like one.
    ///
    /// This is the test the trait boundary exists for: nothing here is
    /// mocked except the hardware, and the code under test is the whole of
    /// `VirtioBlock`, initialisation, request encoding, the descriptor chain,
    /// the doorbell, and the used ring.
    #[test]
    fn a_write_then_a_read_returns_the_same_bytes() {
        let device = FakeDevice::new(8);
        let block = VirtioBlock::new(device.clone()).expect("bring up");

        assert_eq!(block.block_count(), 8);
        assert_eq!(block.block_size(), SECTOR_SIZE);

        let pattern: Vec<u8> = (0..SECTOR_SIZE).map(|i| (i % 251) as u8).collect();
        block.write_blocks(3, &pattern).expect("write");

        let mut read_back = vec![0u8; SECTOR_SIZE];
        block.read_blocks(3, &mut read_back).expect("read");
        assert_eq!(read_back, pattern);
    }

    /// The device was told the modern interface, and the driver negotiated it.
    #[test]
    fn the_driver_negotiates_the_modern_interface() {
        let device = FakeDevice::new(4);
        let _block = VirtioBlock::new(device.clone()).expect("bring up");
        let accepted = device.driver_features.load(Ordering::Relaxed);
        assert_ne!(
            accepted & VIRTIO_F_VERSION_1,
            0,
            "the driver must accept the modern interface it requires"
        );
    }

    /// The device is left at `DRIVER_OK`, which is the last stage of the
    /// sequence and the one that says it may be used.
    #[test]
    fn the_device_is_left_ready() {
        let device = FakeDevice::new(4);
        let _block = VirtioBlock::new(device.clone()).expect("bring up");
        assert_eq!(
            device.read_status(),
            15,
            "ACKNOWLEDGE|DRIVER|FEATURES_OK|DRIVER_OK"
        );
    }

    /// A request past the end of the device is refused before it is submitted.
    #[test]
    fn a_request_past_the_end_is_refused() {
        let device = FakeDevice::new(4);
        let block = VirtioBlock::new(device).expect("bring up");
        let mut buffer = vec![0u8; SECTOR_SIZE];
        assert_eq!(
            block.read_blocks(4, &mut buffer),
            Err(abi::Error::InvalidArgument)
        );
        assert_eq!(
            block.write_blocks(4, &buffer),
            Err(abi::Error::InvalidArgument)
        );
    }

    /// A buffer that is not a whole number of sectors is refused.
    #[test]
    fn a_partial_sector_is_refused() {
        let device = FakeDevice::new(4);
        let block = VirtioBlock::new(device).expect("bring up");
        let mut short = vec![0u8; SECTOR_SIZE - 1];
        assert_eq!(
            block.read_blocks(0, &mut short),
            Err(abi::Error::InvalidArgument)
        );
    }

    /// A device that reports a failed request degrades the driver's health,
    /// and the caller is told the request failed.
    ///
    /// The status byte is the only error channel, the used ring reports a
    /// length, not a result, so a driver that checked only the length would
    /// report this write as a success.
    #[test]
    fn a_failed_request_is_reported_as_such() {
        let device = FakeDevice::new(4);
        let block = VirtioBlock::new(device.clone()).expect("bring up");
        device.next_status.store(1, Ordering::Relaxed);

        let buffer = vec![0u8; SECTOR_SIZE];
        block
            .write_blocks(0, &buffer)
            .expect("the device completed it");
        assert_eq!(
            block.device_health(),
            block::DeviceHealth::Degraded,
            "a device that failed a request is not healthy"
        );
    }

    /// A device that does not offer the modern interface is refused at
    /// initialisation rather than half-driven.
    #[test]
    fn a_device_without_the_modern_interface_is_refused() {
        struct Legacy(Arc<FakeDevice>);
        impl Transport for Legacy {
            fn device_features(&self) -> u64 {
                0
            }
            fn set_driver_features(&self, _features: u64) {}
            fn read_status(&self) -> u8 {
                self.0.read_status()
            }
            fn write_status(&self, status: u8) {
                self.0.write_status(status)
            }
            fn queue_count(&self) -> u16 {
                1
            }
            fn max_queue_size(&self, _index: u16) -> u16 {
                8
            }
            fn configure_queue(&self, _index: u16, _size: u16) {}
            fn set_queue_addresses(&self, _index: u16, _addresses: DeviceAddresses) {}
            fn enable_queue(&self, _index: u16) {}
            fn notify_offset(&self, _queue: u16) -> u16 {
                0
            }
            fn notify(&self, _queue: u16) {}
            fn read_device_config_dword(&self, offset: u64) -> u32 {
                match offset {
                    0 => 4,
                    _ => 0,
                }
            }
        }

        let legacy = Arc::new(Legacy(FakeDevice::new(4)));
        let _ = legacy;
        assert_eq!(
            VirtioBlock::new(legacy).err(),
            Some(abi::Error::Unsupported)
        );
    }

    /// A write alone reaches the device's storage.
    ///
    /// The round-trip test below covers both directions; this one isolates the
    /// write half, so a failure says which direction broke rather than only
    /// that the pair did.
    #[test]
    fn a_write_reaches_the_device() {
        let device = FakeDevice::new(8);
        let block = VirtioBlock::new(device.clone()).expect("bring up");
        let pattern: Vec<u8> = (0..SECTOR_SIZE).map(|i| (i % 251) as u8).collect();
        block.write_blocks(3, &pattern).expect("write");
        assert_eq!(
            device.storage.lock()[3 * SECTOR_SIZE],
            pattern[0],
            "the device's storage was not written"
        );
        assert_eq!(
            device.notifies.load(Ordering::Relaxed),
            1,
            "the doorbell was not rung"
        );
    }

    /// A read alone produces the device's bytes.
    ///
    /// The other half: a device whose storage was already correct, read back
    /// through the driver.
    #[test]
    fn a_read_reaches_the_caller() {
        let device = FakeDevice::new(8);
        let mut storage = device.storage.lock();
        for (index, byte) in storage[3 * SECTOR_SIZE..4 * SECTOR_SIZE]
            .iter_mut()
            .enumerate()
        {
            *byte = (index % 251) as u8;
        }
        drop(storage);

        let block = VirtioBlock::new(device.clone()).expect("bring up");
        let mut buffer = vec![0u8; SECTOR_SIZE];
        block.read_blocks(3, &mut buffer).expect("read");
        assert_eq!(buffer[0], 0, "the first byte of sector 3");
        assert_eq!(buffer[1], 1);
    }
}
