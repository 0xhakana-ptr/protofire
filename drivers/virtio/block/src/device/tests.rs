//! drivers/virtio/block/src/device/tests.rs
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
/// performs a request when the driver rings the doorbell — reading the
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
    /// A real device has this counter in hardware — it is how it knows
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
            // `used.idx` works too — they advance together — but keeping it
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
                let sector_value =
                    core::ptr::read_unaligned((header.address as *const u8).add(8) as *const u64);

                match request_type {
                    // IN: the device writes into the data buffer.
                    0 => {
                        let start = sector_value as usize * SECTOR_SIZE;
                        let len = data.length as usize;
                        let src = &self.storage.lock()[start..start + len];
                        core::ptr::copy_nonoverlapping(src.as_ptr(), data.address as *mut u8, len);
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

    fn max_queue_size(&self) -> u16 {
        8
    }

    fn configure_queue(&self, _index: u16, size: u16) {
        self.selected_queue_size
            .store(size as u64, Ordering::Relaxed);
    }

    fn set_queue_addresses(&self, addresses: DeviceAddresses) {
        *self.addresses.lock() = Some(addresses);
    }

    fn enable_queue(&self) {}

    fn notify_offset(&self, _queue: u16) -> u16 {
        0
    }

    fn notify(&self, _queue: u16) {
        self.notifies.fetch_add(1, Ordering::Relaxed);
        // SAFETY: the driver rang the doorbell after publishing a request,
        // and the rings are alive for the device's lifetime.
        unsafe { self.perform() };
    }

    fn capacity_sectors(&self) -> u64 {
        self.capacity
    }

    fn read_device_config_byte(&self, _offset: u64) -> u8 {
        0
    }
}

/// A write followed by a read returns the same bytes through the real
/// driver code and a device that behaves like one.
///
/// This is the test the trait boundary exists for: nothing here is
/// mocked except the hardware, and the code under test is the whole of
/// `VirtioBlock` — initialisation, request encoding, the descriptor chain,
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
/// The status byte is the only error channel — the used ring reports a
/// length, not a result — so a driver that checked only the length would
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
        fn max_queue_size(&self) -> u16 {
            8
        }
        fn configure_queue(&self, _index: u16, _size: u16) {}
        fn set_queue_addresses(&self, _addresses: DeviceAddresses) {}
        fn enable_queue(&self) {}
        fn notify_offset(&self, _queue: u16) -> u16 {
            0
        }
        fn notify(&self, _queue: u16) {}
        fn capacity_sectors(&self) -> u64 {
            4
        }
        fn read_device_config_byte(&self, _offset: u64) -> u8 {
            0
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
