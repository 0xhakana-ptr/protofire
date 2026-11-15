//! fs/src/block_cache/tests.rs
//!
//! The module's tests.
//!
//! A sibling file because the tests outgrew the module: a reader looking for
//! the mechanism should not scroll past them to find the end of it.

use super::*;
use abi::Error;
use block::BlockDevice;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use sync::Mutex as TestMutex;

struct CountingDevice {
    name: &'static str,
    storage: TestMutex<Vec<u8>>,
    read_count: AtomicU64,
    block_count: u64,
}

impl CountingDevice {
    fn with_blocks(name: &'static str, num_blocks: u64) -> Self {
        let size = num_blocks as usize * BLOCK_SIZE;
        Self {
            name,
            storage: TestMutex::new(vec![0_u8; size]),
            read_count: AtomicU64::new(0),
            block_count: num_blocks,
        }
    }

    fn read_count(&self) -> u64 {
        self.read_count.load(Ordering::Relaxed)
    }
}

impl BlockDevice for CountingDevice {
    fn name(&self) -> &str {
        self.name
    }

    fn block_count(&self) -> u64 {
        self.block_count
    }

    fn is_read_only(&self) -> bool {
        false
    }

    fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> Result<()> {
        self.read_count.fetch_add(1, Ordering::Relaxed);
        let storage = self.storage.lock();
        let start = lba as usize * BLOCK_SIZE;
        let end = start + buffer.len();
        buffer.copy_from_slice(&storage[start..end]);
        Ok(())
    }

    fn write_blocks(&self, lba: u64, data: &[u8]) -> Result<()> {
        let mut storage = self.storage.lock();
        let start = lba as usize * BLOCK_SIZE;
        let end = start + data.len();
        storage[start..end].copy_from_slice(data);
        Ok(())
    }
}

impl QueuedBlockDevice for CountingDevice {
    fn as_block_device(&self) -> &dyn BlockDevice {
        self
    }
}

fn make_test_data(pattern: u8) -> [u8; BLOCK_SIZE] {
    let mut data = [0_u8; BLOCK_SIZE];
    data.fill(pattern);
    data
}

#[test]
fn read_cached_miss_reads_from_device() {
    let device = Arc::new(CountingDevice::with_blocks("miss-device", 4));
    // Pre-seed LBA 0 with pattern 0xAB.
    device.write_blocks(0, &make_test_data(0xAB)).unwrap();

    let cache = BlockCache::new(device.clone());
    let mut buf = [0_u8; BLOCK_SIZE];
    cache.read_cached(0, &mut buf).unwrap();

    assert_eq!(buf, make_test_data(0xAB));
    assert_eq!(device.read_count(), 1);
    assert_eq!(cache.populated_slots(), 1);
    let stats = cache.stats();
    assert_eq!(stats.misses, 1);
    assert_eq!(stats.hits, 0);
}

#[test]
fn read_cached_hit_avoids_device_read() {
    let device = Arc::new(CountingDevice::with_blocks("hit-device", 4));
    device.write_blocks(0, &make_test_data(0xCD)).unwrap();

    let cache = BlockCache::new(device.clone());
    let mut buf = [0_u8; BLOCK_SIZE];

    cache.read_cached(0, &mut buf).unwrap();
    assert_eq!(device.read_count(), 1);

    // Second read of the same LBA must not touch the device.
    let mut buf2 = [0_u8; BLOCK_SIZE];
    cache.read_cached(0, &mut buf2).unwrap();
    assert_eq!(buf2, make_test_data(0xCD));
    assert_eq!(device.read_count(), 1);
    assert_eq!(cache.populated_slots(), 1);
    let stats = cache.stats();
    assert_eq!(stats.misses, 1);
    assert_eq!(stats.hits, 1);
}

#[test]
fn read_cached_different_lbas_do_not_collide() {
    let device = Arc::new(CountingDevice::with_blocks("multi-device", 4));
    device.write_blocks(0, &make_test_data(0x11)).unwrap();
    device.write_blocks(1, &make_test_data(0x22)).unwrap();

    let cache = BlockCache::new(device.clone());
    let mut buf = [0_u8; BLOCK_SIZE];

    cache.read_cached(0, &mut buf).unwrap();
    assert_eq!(buf, make_test_data(0x11));
    cache.read_cached(1, &mut buf).unwrap();
    assert_eq!(buf, make_test_data(0x22));

    assert_eq!(device.read_count(), 2);
    assert_eq!(cache.populated_slots(), 2);

    // Both should be cache hits now.
    cache.read_cached(0, &mut buf).unwrap();
    assert_eq!(buf, make_test_data(0x11));
    cache.read_cached(1, &mut buf).unwrap();
    assert_eq!(buf, make_test_data(0x22));
    assert_eq!(device.read_count(), 2);
}

#[test]
fn write_through_persists_data_to_device() {
    let device = Arc::new(CountingDevice::with_blocks("wt-device", 4));
    let cache = BlockCache::new(device.clone());

    cache.write_through(0, &make_test_data(0xEE)).unwrap();

    // Read directly from the device to confirm persistence.
    let mut buf = [0_u8; BLOCK_SIZE];
    device.read_blocks(0, &mut buf).unwrap();
    assert_eq!(buf, make_test_data(0xEE));
    // The read through the device path increments read_count, but the
    // write_through itself does not.
}

#[test]
fn write_through_updates_cache_so_subsequent_read_is_cached() {
    let device = Arc::new(CountingDevice::with_blocks("wt-cache-device", 4));
    let cache = BlockCache::new(device.clone());

    // Prime the cache with a read first, then overwrite via write_through.
    let mut buf = [0_u8; BLOCK_SIZE];
    device.write_blocks(0, &make_test_data(0xAA)).unwrap();
    cache.read_cached(0, &mut buf).unwrap();
    assert_eq!(buf, make_test_data(0xAA));
    assert_eq!(cache.populated_slots(), 1);

    cache.write_through(0, &make_test_data(0x55)).unwrap();

    let reads_before = device.read_count();

    let mut buf2 = [0_u8; BLOCK_SIZE];
    cache.read_cached(0, &mut buf2).unwrap();
    assert_eq!(buf2, make_test_data(0x55));
    // The cache was already populated by the initial read and then updated
    // by write_through, so read_cached should not trigger a device read.
    assert_eq!(device.read_count(), reads_before);
    assert_eq!(cache.populated_slots(), 1);
}

#[test]
fn invalidate_forces_device_read_after_cache_hit() {
    let device = Arc::new(CountingDevice::with_blocks("inv-device", 4));
    device.write_blocks(0, &make_test_data(0x77)).unwrap();

    let cache = BlockCache::new(device.clone());
    let mut buf = [0_u8; BLOCK_SIZE];

    cache.read_cached(0, &mut buf).unwrap();
    assert_eq!(device.read_count(), 1);

    cache.invalidate(0);
    assert_eq!(cache.populated_slots(), 0);

    cache.read_cached(0, &mut buf).unwrap();
    assert_eq!(device.read_count(), 2);
    assert_eq!(buf, make_test_data(0x77));

    let stats = cache.stats();
    // Both reads were misses because invalidate cleared the cache between
    // them.
    assert_eq!(stats.hits, 0);
    assert_eq!(stats.misses, 2);
    assert_eq!(stats.evictions, 1);
}

#[test]
fn eviction_replaces_least_recently_used_entry() {
    // Device needs at least CACHE_CAPACITY + 2 blocks: one for each
    // cache slot prime, plus the eviction-triggering read, plus one
    // re-read slot.
    let device_blocks = CACHE_CAPACITY as u64 + 2;
    let device = Arc::new(CountingDevice::with_blocks("evict-device", device_blocks));
    let cache = BlockCache::new(device.clone());

    // Prime all cache slots.
    for lba in 0..CACHE_CAPACITY as u64 {
        device
            .write_blocks(lba, &make_test_data(lba as u8))
            .unwrap();
        let mut buf = [0_u8; BLOCK_SIZE];
        cache.read_cached(lba, &mut buf).unwrap();
    }
    assert_eq!(cache.populated_slots(), CACHE_CAPACITY);

    // Re-read LBA 0 to make it the most-recently-used entry.
    let reads_before = device.read_count();
    let mut buf = [0_u8; BLOCK_SIZE];
    cache.read_cached(0, &mut buf).unwrap();
    // LBA 0 was a cache hit; no new device read.
    assert_eq!(device.read_count(), reads_before);

    // Read a new LBA beyond the cache capacity that forces eviction.
    // LBA 1 is now the LRU entry (it was accessed at the same time as
    // 2..(C-1) initially, but 1 has the lowest generation among the
    // untouched entries).
    let evict_lba = CACHE_CAPACITY as u64;
    device
        .write_blocks(evict_lba, &make_test_data(0x10))
        .unwrap();
    cache.read_cached(evict_lba, &mut buf).unwrap();
    assert_eq!(buf, make_test_data(0x10));

    // LBA 1 should have been evicted. Reading it again must hit the device.
    let reads_mid = device.read_count();
    cache.read_cached(1, &mut buf).unwrap();
    assert!(device.read_count() > reads_mid);
    assert_eq!(buf, make_test_data(0x01));

    // LBA 0 must still be cached (it was the MRU before the eviction).
    let reads_end = device.read_count();
    cache.read_cached(0, &mut buf).unwrap();
    assert_eq!(device.read_count(), reads_end);
    assert_eq!(buf, make_test_data(0x00));

    let stats = cache.stats();
    // C initial primes + LBA C miss + LBA 1 re-read miss = C + 2 misses.
    assert_eq!(stats.misses, CACHE_CAPACITY as u64 + 2);
    // LBA 0 re-read + LBA 0 final read = 2 hits.
    assert_eq!(stats.hits, 2);
    // LBA C evicted LBA 1; then LBA 1 re-read evicted LBA 2
    // (the LRU at that point).
    assert_eq!(stats.evictions, 2);
}

#[test]
fn write_through_for_uncached_lba_does_not_insert_into_cache() {
    // write_through only updates the cache if the LBA is already present;
    // it does not proactively cache new LBAs.
    let device = Arc::new(CountingDevice::with_blocks("wt-noinsert", 4));
    let cache = BlockCache::new(device.clone());

    cache.write_through(0, &make_test_data(0x99)).unwrap();

    // The write went to the device, but no cache slot should be occupied.
    assert_eq!(cache.populated_slots(), 0);

    // A subsequent read must go to the device.
    let reads_before = device.read_count();
    let mut buf = [0_u8; BLOCK_SIZE];
    cache.read_cached(0, &mut buf).unwrap();
    assert_eq!(device.read_count(), reads_before + 1);
    assert_eq!(buf, make_test_data(0x99));
}

// write-back tests

#[test]
fn write_back_does_not_touch_device() {
    let device = Arc::new(CountingDevice::with_blocks("wb-nodev", 4));
    let cache = BlockCache::new(device.clone());

    cache.write_back(0, &make_test_data(0xBB)).unwrap();

    // write_back must not call device.write_blocks, verify by checking
    // that the device storage is still zeroed.
    let mut buf = [0_u8; BLOCK_SIZE];
    device.read_blocks(0, &mut buf).unwrap();
    assert_eq!(buf, [0_u8; BLOCK_SIZE]);

    // But a cached read should see the dirty data.
    cache.read_cached(0, &mut buf).unwrap();
    assert_eq!(buf, make_test_data(0xBB));
}

#[test]
fn write_back_and_read_cached_maintains_data() {
    let device = Arc::new(CountingDevice::with_blocks("wb-read", 4));
    let cache = BlockCache::new(device.clone());

    cache.write_back(0, &make_test_data(0xCC)).unwrap();

    let mut buf = [0_u8; BLOCK_SIZE];
    cache.read_cached(0, &mut buf).unwrap();
    assert_eq!(buf, make_test_data(0xCC));
    // read_cached on a dirty block is a cache hit, no device I/O.
    assert_eq!(cache.populated_slots(), 1);
    assert_eq!(cache.dirty_slots(), 1);
}

#[test]
fn flush_persists_dirty_blocks_to_device() {
    let device = Arc::new(CountingDevice::with_blocks("wb-flush", 4));
    let cache = BlockCache::new(device.clone());

    cache.write_back(0, &make_test_data(0xDD)).unwrap();
    cache.write_back(1, &make_test_data(0xEE)).unwrap();
    assert_eq!(cache.dirty_slots(), 2);

    cache.flush().unwrap();

    // After flush, the device must contain the written data.
    let mut buf = [0_u8; BLOCK_SIZE];
    device.read_blocks(0, &mut buf).unwrap();
    assert_eq!(buf, make_test_data(0xDD));
    device.read_blocks(1, &mut buf).unwrap();
    assert_eq!(buf, make_test_data(0xEE));

    // Cache entries should now be clean.
    assert_eq!(cache.dirty_slots(), 0);
    assert_eq!(cache.stats().dirty_writebacks, 2);
}

/// A write a test asks the device to perform in the cache, as a writer
/// arriving while a write is in flight would.
type PlotRewrite = (Arc<BlockCache>, u64, [u8; BLOCK_SIZE]);

/// A device that queues writes and remembers the most it ever held at
/// once.
struct QueuedWriteDevice {
    name: &'static str,
    storage: TestMutex<Vec<u8>>,
    block_count: u64,
    depth: u16,
    pending: TestMutex<Vec<u64>>,
    next_ticket: AtomicU64,
    max_in_flight: AtomicU64,
    /// The most writes the device was asked for at once, as its own
    /// evidence that the flush overlapped rather than serialized.
    writes_seen: AtomicU64,
    next_read: AtomicU64,
    /// A rewrite to perform the next time the device is polled, which is
    /// how a test puts a writer *between* a submit and its completion.
    rewrite: TestMutex<Option<PlotRewrite>>,
}

impl QueuedWriteDevice {
    fn with_blocks(name: &'static str, num_blocks: u64, depth: u16) -> Arc<Self> {
        Self::from_storage(vec![0_u8; num_blocks as usize * BLOCK_SIZE], name, depth)
    }

    fn from_storage(storage: Vec<u8>, name: &'static str, depth: u16) -> Arc<Self> {
        let block_count = (storage.len() / BLOCK_SIZE) as u64;
        Arc::new(Self {
            name,
            storage: TestMutex::new(storage),
            block_count,
            depth,
            pending: TestMutex::new(Vec::new()),
            next_ticket: AtomicU64::new(0),
            max_in_flight: AtomicU64::new(0),
            writes_seen: AtomicU64::new(0),
            next_read: AtomicU64::new(0),
            rewrite: TestMutex::new(None),
        })
    }

    /// Rewrite `lba` in `cache` the next time this device is polled, as a
    /// writer arriving while a write is in flight would.
    fn rewrite_cache_on_next_poll(&self, cache: Arc<BlockCache>, lba: u64, data: &[u8]) {
        let mut block = [0_u8; BLOCK_SIZE];
        block.copy_from_slice(data);
        *self.rewrite.lock() = Some((cache, lba, block));
    }

    fn bytes_at(&self, lba: u64) -> [u8; BLOCK_SIZE] {
        let storage = self.storage.lock();
        let start = lba as usize * BLOCK_SIZE;
        let mut block = [0_u8; BLOCK_SIZE];
        block.copy_from_slice(&storage[start..start + BLOCK_SIZE]);
        block
    }
}

impl BlockDevice for QueuedWriteDevice {
    fn name(&self) -> &str {
        self.name
    }

    fn block_count(&self) -> u64 {
        self.block_count
    }

    fn is_read_only(&self) -> bool {
        false
    }

    fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> Result<()> {
        let _ = self.next_read.fetch_add(1, Ordering::Relaxed);
        let storage = self.storage.lock();
        let start = lba as usize * BLOCK_SIZE;
        buffer.copy_from_slice(&storage[start..start + buffer.len()]);
        Ok(())
    }

    fn write_blocks(&self, lba: u64, data: &[u8]) -> Result<()> {
        let mut storage = self.storage.lock();
        let start = lba as usize * BLOCK_SIZE;
        storage[start..start + data.len()].copy_from_slice(data);
        self.writes_seen.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

impl QueuedBlockDevice for QueuedWriteDevice {
    fn as_block_device(&self) -> &dyn BlockDevice {
        self
    }

    fn queue_depth(&self) -> u16 {
        self.depth
    }

    fn submit_write(&self, lba: u64, data: &[u8]) -> Result<Ticket> {
        let mut pending = self.pending.lock();
        if pending.len() as u16 >= self.depth {
            return Err(Error::Busy);
        }
        // The bytes land here, at submit, on the terms the interface
        // promises: the caller's borrow is over when this returns.
        let mut storage = self.storage.lock();
        let start = lba as usize * BLOCK_SIZE;
        storage[start..start + data.len()].copy_from_slice(data);
        self.writes_seen.fetch_add(1, Ordering::Relaxed);

        let id = self.next_ticket.fetch_add(1, Ordering::Relaxed);
        pending.push(id);
        self.max_in_flight
            .fetch_max(pending.len() as u64, Ordering::Relaxed);
        Ok(Ticket::new(id))
    }

    fn poll(&self, ticket: Ticket) -> RequestState {
        if let Some((cache, lba, data)) = self.rewrite.lock().take() {
            let _ = cache.write_back(lba, &data);
        }
        let mut pending = self.pending.lock();
        match pending.iter().position(|id| *id == ticket.id()) {
            Some(index) => {
                pending.swap_remove(index);
                RequestState::Done(Ok(()))
            }
            None => RequestState::Done(Err(Error::InvalidArgument)),
        }
    }
}

#[test]
fn a_flush_of_several_blocks_holds_two_on_a_device_that_queues() {
    let device = QueuedWriteDevice::with_blocks("queued-flush", 8, 2);
    let cache = BlockCache::new(device.clone());

    for lba in 0..4u64 {
        cache.write_back(lba, &make_test_data(lba as u8)).unwrap();
    }
    assert_eq!(cache.dirty_slots(), 4);

    cache.flush().unwrap();

    assert_eq!(
        device.max_in_flight.load(Ordering::Relaxed),
        2,
        "the flush holds two writes on a device that can take two"
    );
    for lba in 0..4u64 {
        assert_eq!(
            device.bytes_at(lba),
            make_test_data(lba as u8),
            "every dirty block reached the device"
        );
    }
    assert_eq!(cache.dirty_slots(), 0);
}

#[test]
fn a_flush_serializes_on_a_device_that_does_not_queue() {
    let device = QueuedWriteDevice::with_blocks("serial-flush", 8, 1);
    let cache = BlockCache::new(device.clone());

    for lba in 0..4u64 {
        cache.write_back(lba, &make_test_data(lba as u8)).unwrap();
    }
    cache.flush().unwrap();

    assert_eq!(
        device.max_in_flight.load(Ordering::Relaxed),
        1,
        "a depth-one device is on exactly the path it was"
    );
    assert_eq!(cache.dirty_slots(), 0);
}

#[test]
fn a_block_rewritten_while_its_write_is_in_flight_stays_dirty() {
    let device = QueuedWriteDevice::with_blocks("rewrite-race", 4, 2);
    let cache = Arc::new(BlockCache::new(device.clone()));

    cache.write_back(0, &make_test_data(0x11)).unwrap();
    // The device rewrites LBA 0 the first time it is polled: from the
    // cache's point of view a writer arrived after the block was submitted
    // and before its write completed.
    device.rewrite_cache_on_next_poll(cache.clone(), 0, &make_test_data(0x22));

    cache.flush().unwrap();

    // The device holds what was submitted, the block as it was when the
    // write went out ...
    assert_eq!(device.bytes_at(0), make_test_data(0x11));
    // ... and the cache holds the newer content, still marked for the next
    // flush, because the device does not have it.
    assert_eq!(cache.dirty_slots(), 1);
    let mut buffer = [0_u8; BLOCK_SIZE];
    cache.read_cached(0, &mut buffer).unwrap();
    assert_eq!(buffer, make_test_data(0x22));

    cache.flush().unwrap();
    assert_eq!(device.bytes_at(0), make_test_data(0x22));
    assert_eq!(cache.dirty_slots(), 0);
}

#[test]
fn write_back_inserts_uncached_lba() {
    // Unlike write_through, write_back proactively caches new LBAs.
    let device = Arc::new(CountingDevice::with_blocks("wb-insert", 4));
    let cache = BlockCache::new(device.clone());

    cache.write_back(0, &make_test_data(0xFF)).unwrap();

    assert_eq!(cache.populated_slots(), 1);
    assert_eq!(cache.dirty_slots(), 1);

    // Verify cached read returns the dirty data without device I/O.
    let reads_before = device.read_count();
    let mut buf = [0_u8; BLOCK_SIZE];
    cache.read_cached(0, &mut buf).unwrap();
    assert_eq!(device.read_count(), reads_before);
    assert_eq!(buf, make_test_data(0xFF));
}

#[test]
fn eviction_prefers_clean_entries_over_dirty() {
    // Fill the cache: half the entries are dirty, half are clean.
    let device_blocks = CACHE_CAPACITY as u64 + 1;
    let device = Arc::new(CountingDevice::with_blocks("evict-pref", device_blocks));
    let cache = BlockCache::new(device.clone());

    // Populate first half with dirty entries via write_back.
    let half = CACHE_CAPACITY / 2;
    for lba in 0..half as u64 {
        device.write_blocks(lba, &make_test_data(0x10)).unwrap();
        cache.write_back(lba, &make_test_data(0x10)).unwrap();
    }

    // Populate second half with clean entries via read_cached.
    for lba in half as u64..CACHE_CAPACITY as u64 {
        device.write_blocks(lba, &make_test_data(0x20)).unwrap();
        let mut buf = [0_u8; BLOCK_SIZE];
        cache.read_cached(lba, &mut buf).unwrap();
    }

    assert_eq!(cache.dirty_slots(), half);

    // Now insert one more entry. It should evict a clean entry
    // (from the second half), not a dirty one.
    let new_lba = CACHE_CAPACITY as u64;
    device.write_blocks(new_lba, &make_test_data(0x30)).unwrap();
    let mut buf = [0_u8; BLOCK_SIZE];
    cache.read_cached(new_lba, &mut buf).unwrap();

    // All dirty entries should still be present.
    // Re-read each dirty LBA, they must still be hits.
    let reads_before = device.read_count();
    for lba in 0..half as u64 {
        cache.read_cached(lba, &mut buf).unwrap();
        assert_eq!(buf, make_test_data(0x10), "dirty LBA {lba} was evicted");
    }
    assert_eq!(
        device.read_count(),
        reads_before,
        "dirty entries caused device reads"
    );
    assert_eq!(cache.dirty_slots(), half);
}

#[test]
fn eviction_of_dirty_block_writes_back_to_device() {
    // Use a small cache to force all-dirty eviction.
    // CACHE_CAPACITY is 512 which is too large for this test.
    // We instead mark every entry dirty and force an eviction.
    let device_blocks = CACHE_CAPACITY as u64 + 1;
    let device = Arc::new(CountingDevice::with_blocks("evict-dirty", device_blocks));
    let cache = BlockCache::new(device.clone());

    // Mark every cache slot dirty with a unique LBA.
    for lba in 0..CACHE_CAPACITY as u64 {
        device
            .write_blocks(lba, &make_test_data((lba + 1) as u8))
            .unwrap();
        cache
            .write_back(lba, &make_test_data((lba + 1) as u8))
            .unwrap();
    }
    assert_eq!(cache.dirty_slots(), CACHE_CAPACITY);

    // Inserting one more entry must evict a dirty block, which must be
    // written back first.
    let new_lba = CACHE_CAPACITY as u64;
    cache.write_back(new_lba, &make_test_data(0xAB)).unwrap();

    // The dirty_writebacks counter should have incremented.
    assert!(cache.stats().dirty_writebacks >= 1);

    // The evicted LBA's data must be on the device.
    // We don't know exactly which LBA was evicted (it's the LRU = LBA 0
    // or LBA 1 depending on generation ordering), but at least one of
    // the dirty LBAs must have been flushed.
    let mut found = false;
    let mut buf = [0_u8; BLOCK_SIZE];
    for lba in 0..CACHE_CAPACITY as u64 {
        device.read_blocks(lba, &mut buf).unwrap();
        if buf == make_test_data((lba + 1) as u8) {
            found = true;
            break;
        }
    }
    assert!(found, "no dirty block was written back to the device");
}

// read-ahead tests

#[test]
fn prefetch_populates_cache() {
    let device = Arc::new(CountingDevice::with_blocks("prefetch-dev", 16));
    let cache = BlockCache::with_read_ahead(device.clone(), 2);

    // Pre-seed device data.
    for lba in 0..10u64 {
        device
            .write_blocks(lba, &make_test_data(lba as u8))
            .unwrap();
    }

    // Prefetch blocks 3, 4, 5.
    cache.prefetch(3, 3);
    assert_eq!(cache.stats().prefetches_issued, 3);

    // They should now be cache hits.
    let reads_before = device.read_count();
    let mut buf = [0_u8; BLOCK_SIZE];
    for lba in 3..6u64 {
        cache.read_cached(lba, &mut buf).unwrap();
        assert_eq!(buf, make_test_data(lba as u8));
    }
    // No new device reads, all prefetched blocks are cached.
    assert_eq!(device.read_count(), reads_before);
}

#[test]
fn sequential_read_triggers_read_ahead() {
    let device = Arc::new(CountingDevice::with_blocks("seq-dev", 16));
    let cache = BlockCache::with_read_ahead(device.clone(), 2);

    for lba in 0..10u64 {
        device
            .write_blocks(lba, &make_test_data(lba as u8))
            .unwrap();
    }

    // Read LBA 0 (miss, last was MAX → no read-ahead).
    let mut buf = [0_u8; BLOCK_SIZE];
    cache.read_cached(0, &mut buf).unwrap();
    assert_eq!(cache.stats().misses, 1);
    assert_eq!(device.read_count(), 1);

    // Read LBA 1 (miss, last=0 → sequential → triggers read-ahead for 2,3).
    cache.read_cached(1, &mut buf).unwrap();
    assert_eq!(cache.stats().misses, 2);
    // One request covered the demand *and* its lookahead: two blocks,
    // 1024 bytes, one device command.  This is the shape RFC 0008 keeps,
    // and the assertion is what makes that a gate rather than a comment, //
    // a split into two overlapping requests fails here.
    assert_eq!(
        device.read_count(),
        2,
        "a sequential miss is one request for the demand and its lookahead"
    );
    let prefetches_after = cache.stats().prefetches_issued;
    assert!(
        prefetches_after >= 1,
        "read-ahead should have been triggered"
    );

    // Read LBA 2: a sequential hit, and in this case one that read-ahead
    // put there.
    cache.read_cached(2, &mut buf).unwrap();
    assert_eq!(cache.stats().sequential_hits, 1);
    assert_eq!(device.read_count(), 2, "the lookahead was already read");
}

#[test]
fn prefetch_skips_already_cached_blocks() {
    let device = Arc::new(CountingDevice::with_blocks("skip-dev", 16));
    let cache = BlockCache::with_read_ahead(device.clone(), 2);

    for lba in 0..5u64 {
        device
            .write_blocks(lba, &make_test_data(lba as u8))
            .unwrap();
    }

    // Read LBA 2 to cache it.
    let mut buf = [0_u8; BLOCK_SIZE];
    cache.read_cached(2, &mut buf).unwrap();

    // Prefetch LBAs 1..4. LBA 2 is already cached, should skip.
    cache.prefetch(1, 4);
    // Only 3 new prefetches: LBAs 1, 3, 4 (LBA 2 already cached).
    assert_eq!(cache.stats().prefetches_issued, 3);
}

// aged (persistent) write-back tests

/// Serializes tests that manipulate the shared global cache clock.
static AGED_TEST_LOCK: TestMutex<()> = TestMutex::new(());

#[test]
fn flush_aged_persists_only_blocks_older_than_the_threshold() {
    let _guard = AGED_TEST_LOCK.lock();
    set_cache_tick_for_test(1000);
    let device = Arc::new(CountingDevice::with_blocks("aged-dev", 4));
    let cache = BlockCache::new(device.clone());

    // Two dirty blocks stamped at tick 1000.
    cache.write_back(0, &make_test_data(0xAA)).unwrap();
    cache.write_back(1, &make_test_data(0xBB)).unwrap();
    assert_eq!(cache.dirty_slots(), 2);
    assert_eq!(cache.aged_dirty_count(0), 2);

    // Advance the clock 50 ticks: still young for an age of 100.
    advance_cache_ticks(50);
    assert_eq!(cache.aged_dirty_count(100), 0);
    assert_eq!(cache.flush_aged(100).unwrap(), 0);
    // Nothing persisted yet.
    let mut buf = [0_u8; BLOCK_SIZE];
    device.read_blocks(0, &mut buf).unwrap();
    assert_eq!(buf, [0_u8; BLOCK_SIZE]);

    // Advance another 60 ticks (total 110 > 100): both are now expired.
    advance_cache_ticks(60);
    assert_eq!(cache.aged_dirty_count(100), 2);
    assert_eq!(cache.flush_aged(100).unwrap(), 2);
    assert_eq!(cache.dirty_slots(), 0);

    // Data is on the device, the persistent-cache guarantee.
    device.read_blocks(0, &mut buf).unwrap();
    assert_eq!(buf, make_test_data(0xAA));
    device.read_blocks(1, &mut buf).unwrap();
    assert_eq!(buf, make_test_data(0xBB));
    assert_eq!(cache.stats().aged_writebacks, 2);
}

#[test]
fn flush_aged_age_zero_flushes_everything() {
    let _guard = AGED_TEST_LOCK.lock();
    set_cache_tick_for_test(0);
    let device = Arc::new(CountingDevice::with_blocks("aged-zero", 4));
    let cache = BlockCache::new(device.clone());

    cache.write_back(0, &make_test_data(0x11)).unwrap();
    cache.write_back(1, &make_test_data(0x22)).unwrap();
    assert_eq!(cache.flush_aged(0).unwrap(), 2);
    assert_eq!(cache.dirty_slots(), 0);
}

#[test]
fn fresh_write_after_advance_is_not_flushed_until_it_ages() {
    let _guard = AGED_TEST_LOCK.lock();
    set_cache_tick_for_test(2000);
    let device = Arc::new(CountingDevice::with_blocks("aged-fresh", 4));
    let cache = BlockCache::new(device.clone());

    cache.write_back(0, &make_test_data(0x33)).unwrap();
    // Advance far past the age threshold, then write a fresh block.
    advance_cache_ticks(500);
    cache.write_back(1, &make_test_data(0x44)).unwrap();

    // Only the old block is eligible; the fresh one keeps its timestamp.
    assert_eq!(cache.aged_dirty_count(400), 1);
    assert_eq!(cache.flush_aged(400).unwrap(), 1);
    let mut buf = [0_u8; BLOCK_SIZE];
    device.read_blocks(1, &mut buf).unwrap();
    assert_eq!(buf, [0_u8; BLOCK_SIZE], "fresh block must not be flushed");
    assert_eq!(cache.dirty_slots(), 1);
}

#[test]
fn overwriting_a_dirty_block_restarts_its_age() {
    let _guard = AGED_TEST_LOCK.lock();
    set_cache_tick_for_test(0);
    let device = Arc::new(CountingDevice::with_blocks("aged-rewrite", 4));
    let cache = BlockCache::new(device.clone());

    cache.write_back(0, &make_test_data(0xAA)).unwrap();
    advance_cache_ticks(100);
    // Re-write the same block: its age clock restarts.
    cache.write_back(0, &make_test_data(0xBB)).unwrap();

    assert_eq!(cache.aged_dirty_count(50), 0);
    advance_cache_ticks(60);
    assert_eq!(cache.aged_dirty_count(50), 1);
    assert_eq!(cache.flush_aged(50).unwrap(), 1);
    let mut buf = [0_u8; BLOCK_SIZE];
    device.read_blocks(0, &mut buf).unwrap();
    assert_eq!(buf, make_test_data(0xBB));
}
