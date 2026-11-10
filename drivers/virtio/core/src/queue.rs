//! drivers/virtio/core/src/queue.rs
//!
//! The split virtqueue: a descriptor table, an available ring, and a used ring,
//! all in memory the driver owns and the device reads.
//!
//! ## The layout (specification section 2.7)
//!
//! ```text
//! descriptor table   [ {addr, len, flags, next} ; queue_size ]
//! available ring     [ flags, idx, ring[queue_size], used_event ]
//! used ring          [ flags, idx, ring[queue_size]{id, len}, avail_event ]
//! ```
//!
//! The descriptor table is a pool: the driver writes an entry's buffer address
//! and length, links entries with `next` when one request needs several
//! buffers, and the available ring carries the index of the head of each
//! request.  The used ring is the device's answer, which descriptor heads it
//! finished, and how many bytes it wrote.
//!
//! The *arithmetic* of those three rings: allocating a descriptor, publishing
//! it, reading a completion, and wrapping around.  It is not responsible for
//! allocating the memory they live in, for the doorbell, or for interrupts,
//! those are the transport's, and splitting them here is what lets the rings be
//! tested against a `Vec` on a host.
//!
//! ## The wrapping
//!
//! `idx` fields are free-running `u16` counters that wrap at 65536; the
//! *index into the ring* is `idx % queue_size`.  A queue that wrapped its
//! index instead of modulo-ing a counter would lose track after 65536
//! requests, which on a disk is minutes and which no test that submits five
//! requests would ever see.  [`Rings::available_index`] and
//! [`Rings::used_index`] are the two counters, and `VirtQueue::slot` is the one
//! place that turns a counter into a ring index; both are tested at the wrap.

use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;
use core::sync::atomic::fence;

/// One descriptor: a buffer the device may read or write.
///
/// The layout is the specification's (2.7.5), not this tree's: the device reads
/// these sixteen bytes, so the field order and sizes are fixed.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Descriptor {
    /// The buffer's physical address.
    pub address: u64,
    /// Its length in bytes.
    pub length: u32,
    /// `NEXT` and `WRITE` are the two this driver sets.
    pub flags: u16,
    /// The next descriptor in the chain, when `NEXT` is set.
    pub next: u16,
}

/// The longest descriptor chain this driver can release.
///
/// A request uses three descriptors, and a device is entitled to accept a
/// longer chain; a bound is needed because the walk follows a `next` field the
/// device's completion names, and a corrupt one would loop.  64 is far more
/// than any request this driver builds and small enough to live on the stack.
const MAX_CHAIN: usize = 64;

/// `flags` bit 0: `next` names another descriptor.
pub const DESC_F_NEXT: u16 = 1;
/// `flags` bit 1: the device writes into this buffer rather than reading it.
pub const DESC_F_WRITE: u16 = 2;

/// The available ring: what the driver has published.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct AvailableRing {
    pub flags: u16,
    /// Free-running count of requests published.
    pub idx: u16,
}

/// The used ring's entry: one request the device finished.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UsedElement {
    /// The descriptor that headed the request.
    pub id: u32,
    /// How many bytes the device wrote into the request's buffers.
    pub length: u32,
}

/// The used ring: what the device has finished.
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UsedRing {
    pub flags: u16,
    /// Free-running count of requests finished.
    pub idx: u16,
}

/// Why a queue operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtQueueError {
    /// Every descriptor is in use, or a chain needed more than are free.
    NoDescriptors,
    /// The request's size does not match the queue's expectations.
    InvalidLength,
    /// The queue has not been set up.
    NotReady,
}

/// The three rings, laid out the way the device reads them.
///
/// The specification's structures are *one object each*:
///
/// ```text
/// struct virtq_avail { le16 flags; le16 idx; le16 ring[queue_size]; };
/// struct virtq_used  { le16 flags; le16 idx; struct { le32 id; le32 len; }
///                      ring[queue_size]; };
/// ```
///
/// The device is given the address of `flags` and computes `ring` from it.  A
/// driver that held the header and the array in two allocations would hand the
/// device an address whose neighbours are not the array it expects, and the
/// device would read and write wherever those bytes happened to be, which on
/// a quiet machine can look like it works.
///
/// So each ring is a byte buffer sized by the structure, and the accessors are
/// the only code that knows where the fields are.
pub struct Rings {
    /// The descriptor table, `queue_size` entries.
    descriptors: Vec<Descriptor>,
    /// The available ring: header, then `queue_size` `u16`s.
    available: Vec<u8>,
    /// The used ring: header, then `queue_size` elements of `{u32, u32}`.
    used: Vec<u8>,
    /// How many entries each ring holds.
    queue_size: usize,
}

/// The available ring's header: `flags` then `idx`.
const AVAIL_HEADER_LEN: usize = 4;
/// One available-ring entry.
const AVAIL_ENTRY_LEN: usize = 2;
/// The available ring's trailing `used_event` slot: the used-ring index at
/// which the driver wants the device to interrupt it.
///
/// The slot exists only when `VIRTIO_F_RING_EVENT_IDX` is negotiated, and this
/// driver negotiates it — but the first version **allocated no slot**, so the
/// device read the event index from whatever memory followed the ring.  A
/// driver that does not maintain the slot therefore gets a device whose
/// suppression is decided by garbage: notifications that arrive late, or a
/// notification per completion.  Measured once a completion vector was wired
/// to an IMSIC: the boot's own probe took **no** interrupt (the garbage said
/// "do not notify"), and the mount that followed took one per completion —
/// hundreds — because the adjacent bytes had changed.
const AVAIL_EVENT_LEN: usize = 2;
/// The used ring's header: `flags` then `idx`.
const USED_HEADER_LEN: usize = 4;
/// One used-ring entry: `id` then `length`, both `u32`.
const USED_ENTRY_LEN: usize = 8;
/// The used ring's trailing `avail_event` slot, which the device writes to say
/// where it is reading.  The driver never sets the used-ring flags the device
/// would suppress on, so the slot is allocated for the layout's sake and left
/// alone.
const USED_EVENT_LEN: usize = 2;

impl Rings {
    /// Allocate the three rings for a queue of `queue_size` entries.
    ///
    /// A `Vec` rather than frames: the caller owns the memory and hands the
    /// device its physical addresses, so a host test can build this without a
    /// frame allocator and the transport can build it over frames just as
    /// well.
    pub fn new(queue_size: usize) -> Self {
        Self {
            descriptors: vec![Descriptor::default(); queue_size],
            available: vec![0; AVAIL_HEADER_LEN + queue_size * AVAIL_ENTRY_LEN + AVAIL_EVENT_LEN],
            used: vec![0; USED_HEADER_LEN + queue_size * USED_ENTRY_LEN + USED_EVENT_LEN],
            queue_size,
        }
    }

    /// The descriptor table's address, which the device must be told.
    pub fn descriptors_address(&self) -> usize {
        self.descriptors.as_ptr() as usize
    }

    /// The available ring's address, the header's, because the device
    /// computes the array from it.
    pub fn available_address(&self) -> usize {
        self.available.as_ptr() as usize
    }

    pub fn used_address(&self) -> usize {
        self.used.as_ptr() as usize
    }

    /// The available ring's `idx` counter.
    pub fn available_index(&self) -> u16 {
        u16::from_ne_bytes([self.available[2], self.available[3]])
    }

    /// Set the available ring's `idx`.
    pub fn set_available_index(&mut self, idx: u16) {
        self.available[2..4].copy_from_slice(&idx.to_ne_bytes());
    }

    /// The `i`th available-ring entry.
    pub fn available_entry(&self, index: usize) -> u16 {
        let offset = AVAIL_HEADER_LEN + index * AVAIL_ENTRY_LEN;
        u16::from_ne_bytes([self.available[offset], self.available[offset + 1]])
    }

    /// Set the `i`th available-ring entry.
    pub fn set_available_entry(&mut self, index: usize, head: u16) {
        let offset = AVAIL_HEADER_LEN + index * AVAIL_ENTRY_LEN;
        self.available[offset..offset + 2].copy_from_slice(&head.to_ne_bytes());
    }

    /// The used ring's `idx` counter.
    pub fn used_index(&self) -> u16 {
        u16::from_ne_bytes([self.used[2], self.used[3]])
    }

    /// Set the used ring's `idx`, which a device does and a test stands in for.
    pub fn set_used_index(&mut self, idx: u16) {
        self.used[2..4].copy_from_slice(&idx.to_ne_bytes());
    }

    /// The `i`th used-ring element: `(id, length)`.
    pub fn used_element(&self, index: usize) -> (u32, u32) {
        let offset = USED_HEADER_LEN + index * USED_ENTRY_LEN;
        let id = u32::from_ne_bytes([
            self.used[offset],
            self.used[offset + 1],
            self.used[offset + 2],
            self.used[offset + 3],
        ]);
        let length = u32::from_ne_bytes([
            self.used[offset + 4],
            self.used[offset + 5],
            self.used[offset + 6],
            self.used[offset + 7],
        ]);
        (id, length)
    }

    /// Set the `i`th used-ring element, which a device does and a test stands
    /// in for.
    pub fn set_used_element(&mut self, index: usize, id: u32, length: u32) {
        let offset = USED_HEADER_LEN + index * USED_ENTRY_LEN;
        self.used[offset..offset + 4].copy_from_slice(&id.to_ne_bytes());
        self.used[offset + 4..offset + 8].copy_from_slice(&length.to_ne_bytes());
    }

    pub fn descriptor(&self, index: usize) -> Descriptor {
        self.descriptors[index]
    }

    pub fn set_descriptor(&mut self, index: usize, descriptor: Descriptor) {
        self.descriptors[index] = descriptor;
    }

    pub fn queue_size(&self) -> usize {
        self.queue_size
    }

    /// The available ring's length in bytes, as the device computes it.
    #[cfg(test)]
    pub fn available_length(&self) -> usize {
        self.available.len()
    }

    /// The used ring's length in bytes.
    #[cfg(test)]
    pub fn used_length(&self) -> usize {
        self.used.len()
    }

    /// The available buffer's own address, for the contiguity test.
    #[cfg(test)]
    pub fn available_buffer_address(&self) -> usize {
        self.available.as_ptr() as usize
    }

    /// The used buffer's own address, for the contiguity test.
    #[cfg(test)]
    pub fn used_buffer_address(&self) -> usize {
        self.used.as_ptr() as usize
    }
}

/// A split virtqueue the driver drives and the device reads.
pub struct VirtQueue {
    rings: Rings,
    /// How many descriptors the queue has; a power of two, per the
    /// specification.
    queue_size: usize,
    /// The next descriptor to allocate on the free list.
    free_head: u16,
    /// How many descriptors are free.
    num_free: u16,
    /// The last `used.idx` this driver has consumed.
    last_used_index: u16,
    /// The physical address the device was told for each ring.
    ///
    /// Kept because the driver's view, a `Vec`'s virtual address on a host, ///
    /// and the device's, a physical address on a machine, are not always the
    /// same number, and only the transport knows both.
    device_addresses: Option<DeviceAddresses>,
}

/// The three physical addresses a device is told, in the order it reads them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceAddresses {
    pub descriptors: u64,
    pub available: u64,
    pub used: u64,
}

impl Rings {
    /// Write the available ring's trailing `used_event` slot.
    ///
    /// The offset is the header plus the ring: the slot is the allocation's
    /// last two bytes, which is why the allocation grew for it.
    fn set_used_event(&mut self, index: u16) {
        let at = AVAIL_HEADER_LEN + self.queue_size * AVAIL_ENTRY_LEN;
        // SAFETY: `at + 2` is the allocation's own length, and this is a `u16`
        // write into that slot.
        unsafe {
            core::ptr::write_unaligned(self.available.as_mut_ptr().add(at) as *mut u16, index);
        }
        fence(Ordering::Release);
    }
}

impl VirtQueue {
    /// A queue of `queue_size` entries, with every descriptor free.
    ///
    /// `queue_size` must be a power of two: the specification requires it, and
    /// the masking in `VirtQueue::slot` relies on it.
    pub fn new(queue_size: usize) -> Self {
        assert!(
            queue_size.is_power_of_two(),
            "a virtqueue's size is a power of two (specification 2.7.3)"
        );
        assert!(
            queue_size <= 32768,
            "a virtqueue holds at most 32768 entries"
        );
        let mut rings = Rings::new(queue_size);
        // Chain every descriptor onto the free list, and terminate it.
        //
        // The free list is implicit in this driver: a free descriptor's `next`
        // names the next free one.  Initialising the table to zero and
        // starting `free_head` at zero leaves every descriptor's `next` at
        // zero, so allocating pops 0, then 0 again, and `release` walks a
        // one-element cycle forever.  The chain is built here, once, and the
        // last entry's `next` is irrelevant because `num_free` bounds
        // allocation.
        for index in 0..queue_size {
            let next = if index + 1 < queue_size {
                (index + 1) as u16
            } else {
                0
            };
            rings.set_descriptor(
                index,
                Descriptor {
                    next,
                    ..Descriptor::default()
                },
            );
        }
        Self {
            rings,
            queue_size,
            free_head: 0,
            num_free: queue_size as u16,
            last_used_index: 0,
            device_addresses: None,
        }
    }

    pub fn size(&self) -> usize {
        self.queue_size
    }

    /// The descriptor table's address, for the transport to program.
    pub fn descriptors_address(&self) -> usize {
        self.rings.descriptors_address()
    }

    pub fn available_address(&self) -> usize {
        self.rings.available_address()
    }

    pub fn used_address(&self) -> usize {
        self.rings.used_address()
    }

    /// The three addresses, as one value the transport can program.
    pub fn device_addresses(&self) -> DeviceAddresses {
        DeviceAddresses {
            descriptors: self.rings.descriptors_address() as u64,
            available: self.rings.available_address() as u64,
            used: self.rings.used_address() as u64,
        }
    }

    /// Link `from` to `to`, for a request that needs more than one buffer.
    ///
    /// The `NEXT` flag is set here rather than by the caller because the flag
    /// and the link are one fact: a descriptor that names a successor without
    /// the flag is a chain the device stops at, and a flag without a successor
    /// is a device reading descriptor zero.
    pub fn set_next(&mut self, from: u16, to: u16) {
        let mut descriptor = self.rings.descriptor(from as usize);
        descriptor.next = to;
        descriptor.flags |= DESC_F_NEXT;
        self.rings.set_descriptor(from as usize, descriptor);
    }

    pub fn free_descriptors(&self) -> u16 {
        self.num_free
    }

    /// Record the physical addresses the device was told.
    ///
    /// The transport calls this after programming the device, so the driver
    /// knows whether a ring it is about to read is the one the device writes.
    /// A queue whose addresses were never recorded is one the device was never
    /// told about, and submitting to it would fill a ring no device reads.
    pub fn set_device_addresses(&mut self, addresses: DeviceAddresses) {
        self.device_addresses = Some(addresses);
    }

    /// Whether the device has been told where the rings are.
    pub fn is_ready(&self) -> bool {
        self.device_addresses.is_some()
    }

    /// Allocate one descriptor and fill it in.
    ///
    /// Returns its index, which the caller publishes with
    /// [`VirtQueue::publish`].  Allocating and publishing are separate because
    /// a request with several buffers allocates them all and publishes once:
    /// the device must not see a chain whose tail is not filled in yet.
    pub fn allocate(&mut self, descriptor: Descriptor) -> Result<u16, VirtQueueError> {
        if !self.is_ready() {
            return Err(VirtQueueError::NotReady);
        }
        if self.num_free == 0 {
            return Err(VirtQueueError::NoDescriptors);
        }

        let index = self.free_head;
        // Read the free list's successor *before* overwriting the descriptor:
        // the caller's `next` is the chain link it wants, and the free list's
        // `next` is where the pool continues.  They are the same field, so an
        // allocate that installed the caller's descriptor first and then read
        // `next` would follow the caller's chain instead of the pool's, and
        // hand out the same descriptor twice.
        let next_free = self.rings.descriptor(index as usize).next;
        self.rings.set_descriptor(index as usize, descriptor);
        self.free_head = next_free;
        self.num_free -= 1;
        Ok(index)
    }

    /// Publish a chain's head to the available ring.
    ///
    /// This is the step that makes the request visible to the device: before
    /// it, the descriptors are written but not offered.  The fence is the
    /// specification's (2.7.13): the device may read the descriptors the
    /// moment `idx` changes, so the writes to them have to be visible first.
    pub fn publish(&mut self, head: u16) {
        let counter = self.rings.available_index();
        let slot = self.slot(counter);
        self.rings.set_available_entry(slot, head);
        fence(Ordering::Release);
        self.rings.set_available_index(counter.wrapping_add(1));
    }

    /// The slot in either ring a free-running counter value names.
    ///
    /// A counter modulo the queue size, not the counter itself: the 65536th
    /// request goes in slot 0 of a 256-entry queue, and a driver that used the
    /// counter as an index would write past the ring.  It is a mask rather
    /// than a remainder because the size is a power of two, which is why
    /// [`VirtQueue::new`] asserts that.
    fn slot(&self, counter: u16) -> usize {
        (counter as usize) & (self.queue_size - 1)
    }

    /// Take the next completion the device has published, if any.
    ///
    /// Returns the head descriptor and how many bytes the device wrote.  The
    /// `Acquire` fence is the other half of the publish fence: the device's
    /// writes to the buffers happen before it updates `used.idx`, and the
    /// driver must see them after.
    pub fn take_completion(&mut self) -> Option<(u16, u32)> {
        let used_idx = self.rings.used_index();
        if self.last_used_index == used_idx {
            return None;
        }
        fence(Ordering::Acquire);
        let slot = self.slot(self.last_used_index);
        let (id, length) = self.rings.used_element(slot);
        self.last_used_index = self.last_used_index.wrapping_add(1);
        Some((id as u16, length))
    }

    /// Tell the device to interrupt the driver once `used.idx` passes `index`.
    ///
    /// This writes the available ring's trailing `used_event` slot, and it is
    /// what a driver that has processed its completions owes the device: an
    /// event index left at a value the device has already passed is one the
    /// device will not interrupt for until the counter wraps, and a driver
    /// waiting on an interrupt would wait for ever.
    ///
    /// The write is `Release`: the completions the driver has read from the
    /// used ring must be seen as consumed before the device is told where the
    /// driver's interest now ends, or the device could notify and the driver
    /// would miss what it was notified about.
    pub fn set_used_event(&mut self, index: u16) {
        self.rings.set_used_event(index)
    }

    /// The used-ring index the driver has processed through, which is the value
    /// the device should be told to interrupt past.
    pub fn last_used_index(&self) -> u16 {
        self.last_used_index
    }

    /// Return a chain to the free list.
    ///
    /// The chain is walked through `next` until a descriptor without `NEXT`,
    /// and each is pushed onto the free list.  Every descriptor a request used
    /// has to come back, or the queue shrinks to nothing one leak at a time.
    pub fn release(&mut self, head: u16) {
        // Walk the chain first, gathering indices, and relink afterwards.
        //
        // The walk cannot be interleaved with the relink: releasing overwrites
        // each descriptor's `next` with the free-list link, so a loop that read
        // `next` after writing it would follow the free list on its second
        // step and release descriptors that were already free.
        let mut chain = [0u16; MAX_CHAIN];
        let mut len = 0;
        let mut index = head;
        loop {
            if len == MAX_CHAIN || (index as usize) >= self.queue_size {
                // A chain longer than any queue this driver builds, or a link
                // past the table: the descriptors are corrupt, and following
                // the next one would read memory that is not a descriptor.
                break;
            }
            let descriptor = self.rings.descriptor(index as usize);
            chain[len] = index;
            len += 1;
            if descriptor.flags & DESC_F_NEXT == 0 {
                break;
            }
            index = descriptor.next;
        }

        // Push in reverse: the chain was walked head-to-tail and the free list
        // is a stack, so pushing head-first would leave the tail on top and the
        // next allocation would take the last descriptor of the old chain.
        for &entry in chain[..len].iter().rev() {
            let mut descriptor = self.rings.descriptor(entry as usize);
            descriptor.next = self.free_head;
            self.rings.set_descriptor(entry as usize, descriptor);
            self.free_head = entry;
            self.num_free = self.num_free.saturating_add(1);
        }
    }

    /// The descriptor at `index`, for a test or a driver that needs to check
    /// what it wrote.
    pub fn descriptor(&self, index: u16) -> Descriptor {
        self.rings.descriptor(index as usize)
    }

    /// The number of completions the device has published and the driver has
    /// not yet taken.
    pub fn pending_completions(&self) -> u16 {
        self.rings.used_index().wrapping_sub(self.last_used_index)
    }

    /// The raw rings, for a test that stands in for the device.
    ///
    /// A device is not a Rust caller: it reads the rings through the addresses
    /// the transport programmed.  A host test has no device, so this is how it
    /// writes a completion the way one would.
    #[cfg(test)]
    pub fn rings_mut(&mut self) -> &mut Rings {
        &mut self.rings
    }

    /// Move the "taken" counter to where a test needs it.
    ///
    /// Reaching the `u16` wrap by submitting 65536 requests is not what a
    /// test of the wrap is about, and a test that did would be slow enough
    /// that nobody would run it.  The counter is the state under test, so the
    /// test sets it.
    #[cfg(test)]
    pub fn set_last_used_index(&mut self, index: u16) {
        self.last_used_index = index;
    }

    /// The rings, for a test that checks their layout rather than their use.
    #[cfg(test)]
    pub fn rings_mut_for_address_check(&mut self) -> &Rings {
        &self.rings
    }
}

#[cfg(test)]
mod tests {
    use super::DESC_F_NEXT;
    use super::DESC_F_WRITE;
    use super::Descriptor;
    use super::DeviceAddresses;
    use super::VirtQueue;
    use super::VirtQueueError;

    fn ready_queue(size: usize) -> VirtQueue {
        let mut queue = VirtQueue::new(size);
        queue.set_device_addresses(DeviceAddresses {
            descriptors: 0x1000,
            available: 0x2000,
            used: 0x3000,
        });
        queue
    }

    /// The descriptor is sixteen bytes with the fields where the device reads
    /// them.
    ///
    /// The device reads these bytes through its own structure; a Rust type
    /// whose layout differed would be a driver writing a descriptor the device
    /// interprets differently, and the failure would look like a corrupt
    /// request rather than a layout error.
    #[test]
    fn the_descriptor_layout_is_the_specifications() {
        use core::mem::offset_of;
        use core::mem::size_of;
        assert_eq!(size_of::<Descriptor>(), 16);
        assert_eq!(offset_of!(Descriptor, address), 0);
        assert_eq!(offset_of!(Descriptor, length), 8);
        assert_eq!(offset_of!(Descriptor, flags), 12);
        assert_eq!(offset_of!(Descriptor, next), 14);
    }

    /// A queue that has not been told to the device refuses to accept work.
    ///
    /// Submitting to it would fill a ring no device reads, and the failure
    /// would be a hang rather than an error.
    #[test]
    fn a_queue_the_device_was_not_told_refuses_descriptors() {
        let mut queue = VirtQueue::new(8);
        assert!(!queue.is_ready());
        assert_eq!(
            queue.allocate(Descriptor::default()),
            Err(VirtQueueError::NotReady)
        );
    }

    /// A published request is visible in the available ring at the slot its
    /// counter names, and the counter moves.
    #[test]
    fn publishing_moves_the_available_counter() {
        let mut queue = ready_queue(8);
        let head = queue
            .allocate(Descriptor {
                address: 0x4000,
                length: 512,
                flags: DESC_F_WRITE,
                next: 0,
            })
            .expect("a free descriptor");
        assert_eq!(head, 0);
        assert_eq!(queue.pending_completions(), 0);

        queue.publish(head);
        assert_eq!(queue.rings_mut().available_entry(0), 0);
        assert_eq!(queue.rings_mut().available_index(), 1);
    }

    /// The rings are laid out the way the device reads them.
    ///
    /// The available ring is `flags, idx, ring[], used_event` in one object,
    /// and the used ring is `flags, idx, {id, len}[], avail_event`.  A driver
    /// that held the header and the array in two allocations would hand the
    /// device an address whose neighbours are not the array it computes, a bug
    /// that looks like it works on a quiet machine.
    ///
    /// The two trailing slots are pinned by their own lengths because the
    /// first version allocated neither: the device then read `used_event` from
    /// whatever followed the ring, and its suppression was decided by garbage
    /// — measured once a completion vector reached an IMSIC, as no interrupt
    /// during the driver's probe and one per completion afterwards.
    #[test]
    fn the_rings_are_contiguous() {
        let mut queue = ready_queue(8);
        let rings = queue.rings_mut_for_address_check();
        // The available ring: 4 bytes of header, then 8 entries of 2 bytes,
        // then the `used_event` slot.
        assert_eq!(rings.available_length(), 4 + 8 * 2 + 2);
        // The used ring: 4 bytes of header, then 8 entries of 8 bytes, then
        // the `avail_event` slot.
        assert_eq!(rings.used_length(), 4 + 8 * 8 + 2);
        // And the device is told the header's address, which is the buffer's.
        assert_eq!(rings.available_address(), rings.available_buffer_address());
        assert_eq!(rings.used_address(), rings.used_buffer_address());
    }

    /// A completion written by the "device" is taken once, in order, with the
    /// length it reports.
    #[test]
    fn a_completion_is_taken_once() {
        let mut queue = ready_queue(8);
        let head = queue.allocate(Descriptor::default()).expect("allocate");
        queue.publish(head);

        // Stand in for the device: it finished request 0 having written 512.
        queue.rings_mut().set_used_element(0, 0, 512);
        queue.rings_mut().set_used_index(1);

        assert_eq!(queue.pending_completions(), 1);
        assert_eq!(queue.take_completion(), Some((0, 512)));
        assert_eq!(queue.take_completion(), None, "a completion is taken once");
    }

    /// The available ring wraps at the queue size, not at 65536.
    ///
    /// A driver that used the free-running counter as a ring index would write
    /// past the array on the 9th request of an 8-entry queue, which a test
    /// that submits five requests never reaches.
    #[test]
    fn the_available_ring_wraps_at_the_queue_size() {
        let mut queue = ready_queue(8);
        for request in 0..20u16 {
            let head = queue.allocate(Descriptor::default()).expect("allocate");
            queue.publish(head);
            let slot = (request as usize) & 7;
            queue.rings_mut().set_used_element(slot, head as u32, 0);
            queue.rings_mut().set_used_index(request.wrapping_add(1));
            assert!(queue.take_completion().is_some());
            queue.release(head);
        }
        assert_eq!(
            queue.rings_mut().available_index(),
            20,
            "the counter is free-running"
        );
        assert_eq!(queue.free_descriptors(), 8, "every descriptor came back");
    }

    /// A chain of two descriptors comes back as a chain: releasing the head
    /// returns both.
    #[test]
    fn releasing_a_chain_returns_every_descriptor() {
        let mut queue = ready_queue(8);
        let first = queue
            .allocate(Descriptor {
                flags: DESC_F_NEXT,
                next: 1,
                ..Descriptor::default()
            })
            .expect("first");
        let second = queue
            .allocate(Descriptor {
                flags: 0,
                ..Descriptor::default()
            })
            .expect("second");
        assert_eq!(first, 0);
        assert_eq!(second, 1);
        assert_eq!(queue.free_descriptors(), 6);

        queue.release(first);
        assert_eq!(
            queue.free_descriptors(),
            8,
            "the chain was walked and both came back"
        );
    }

    /// `set_next` sets the link and the flag together, because they are one
    /// fact.
    #[test]
    fn linking_sets_the_flag_and_the_successor() {
        let mut queue = ready_queue(8);
        let a = queue.allocate(Descriptor::default()).expect("a");
        let b = queue.allocate(Descriptor::default()).expect("b");
        queue.set_next(a, b);
        let descriptor = queue.descriptor(a);
        assert_eq!(descriptor.next, b);
        assert_eq!(descriptor.flags & DESC_F_NEXT, DESC_F_NEXT);
    }

    /// An exhausted queue refuses rather than overwriting a live descriptor.
    ///
    /// Overwriting one would leave the device reading a buffer the driver
    /// believes it has moved on from.
    #[test]
    fn an_exhausted_queue_refuses_rather_than_overwriting() {
        let mut queue = ready_queue(4);
        for _ in 0..4 {
            queue.allocate(Descriptor::default()).expect("allocate");
        }
        assert_eq!(
            queue.allocate(Descriptor::default()),
            Err(VirtQueueError::NoDescriptors)
        );
        assert_eq!(queue.free_descriptors(), 0);
    }

    /// The completion counter and the taken counter differ by exactly what is
    /// outstanding, across the point where the `u16` counters wrap.
    ///
    /// The arithmetic that matters is `wrapping_sub`: plain subtraction at the
    /// wrap gives a huge number for a small difference, and a driver that used
    /// `used.idx - last_used` would read 65535 completions where there was one.
    #[test]
    fn the_completion_count_survives_the_counter_wrap() {
        let mut queue = ready_queue(8);

        // Put the driver one short of the wrap, as if 65534 completions had
        // been taken.
        queue.set_last_used_index(u16::MAX - 1);
        let slot = (u16::MAX as usize - 1) & 7;
        queue.rings_mut().set_used_element(slot, 3, 1);
        queue.rings_mut().set_used_index(u16::MAX);
        assert_eq!(queue.pending_completions(), 1);
        assert_eq!(queue.take_completion(), Some((3, 1)));
        assert_eq!(queue.pending_completions(), 0);

        // The device finishes two more: `used.idx` goes MAX -> 0 -> 1, and the
        // slots are MAX & 7 and 0 & 7.
        queue
            .rings_mut()
            .set_used_element(u16::MAX as usize & 7, 4, 2);
        queue.rings_mut().set_used_element(0, 5, 3);
        queue.rings_mut().set_used_index(1);
        assert_eq!(
            queue.pending_completions(),
            2,
            "wrapping_sub, not subtraction"
        );
        assert_eq!(queue.take_completion(), Some((4, 2)));
        assert_eq!(queue.take_completion(), Some((5, 3)));
        assert_eq!(queue.pending_completions(), 0);
    }
}
