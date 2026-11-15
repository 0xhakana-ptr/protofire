//! fs/src/block_cache/mod.rs
//!
//! A fixed-capacity block cache that wraps a BlockDevice and provides
//! cached reads with both write-through and write-back modes.
//!
//! Write-through (the default for metadata) writes directly to the device
//! and updates the cached copy.  Write-back (preferred for file data) writes
//! only to the cache and marks the entry dirty; dirty blocks are flushed
//! to the device on explicit `flush` / `flush_range` calls or when the
//! entry is evicted.

use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use abi::Result;
use block::BLOCK_SIZE;
use block::QueuedBlockDevice;
use block::RequestState;
use block::Ticket;
use sync::Mutex;

// Persistent write-back clock

/// Monotonic cache clock used to age dirty blocks.  The scheduler advances it
/// once per timer tick; a block written at tick `T` is "expired" once the
/// clock reaches `T + WRITE_BACK_AGE_TICKS`, at which point the periodic
/// background write-back persists it to the device.  This is what makes the
/// write-back cache durable even when the application never calls `fsync`.
static BLOCK_CACHE_TICK: AtomicU64 = AtomicU64::new(0);

/// Advance the cache clock by one tick.  Called from the scheduler's timer
/// tick (cheap, lock-free).
pub fn advance_cache_tick() {
    advance_cache_ticks(1);
}

/// Advance the cache clock by `n` ticks.
pub fn advance_cache_ticks(n: u64) {
    BLOCK_CACHE_TICK.fetch_add(n, Ordering::Relaxed);
}

/// Current cache-clock value.
pub fn cache_tick() -> u64 {
    BLOCK_CACHE_TICK.load(Ordering::Relaxed)
}

/// Set the cache-clock value (host tests that need deterministic aging).
#[cfg(test)]
pub(crate) fn set_cache_tick_for_test(value: u64) {
    BLOCK_CACHE_TICK.store(value, Ordering::Relaxed);
}

/// Period (in scheduler ticks) between automatic background write-back scans.
/// 300 ticks @ 100 Hz = every 3 seconds.
pub const WRITE_BACK_PERIOD_TICKS: u64 = 300;
/// Minimum age (in scheduler ticks) before a dirty block is eligible for the
/// automatic background write-back.  600 ticks @ 100 Hz = 6 seconds.
///
/// Six seconds is a choice about how much work a crash may cost, not a
/// compatibility target.  It is long enough that a file rewritten in a burst is
/// written once rather than once per edit, and short enough that a power loss
/// costs a few seconds of edits rather than a session's.  A caller that cannot
/// accept six seconds calls `fsync` and does not wait for this.
pub const WRITE_BACK_AGE_TICKS: u64 = 600;

/// Maximum number of cached blocks.  Increased from 64 to 512 to reduce
/// eviction pressure under the write-back model, at a cost of 256 KiB of
/// heap (512 × 512 bytes).  This is ~1.6% of the 16 MiB kernel heap.
const CACHE_CAPACITY: usize = 512;

/// When the number of dirty blocks reaches this fraction of `CACHE_CAPACITY`
/// (50 % = 256 dirty blocks), `write_back` automatically triggers a full flush
/// to avoid cascading eviction writes later.  The threshold is deliberately
/// conservative so short bursts of writes don't hit the device on every call.
const WRITE_BACK_PRESSURE_THRESHOLD: usize = CACHE_CAPACITY / 2;

/// Most blocks one read-ahead request covers.  The scratch buffer that holds
/// a run is this many blocks on the stack, so it is a bound on stack use as
/// much as on request size.
const PREFETCH_RUN_BLOCKS: usize = 4;

/// The most times one queued write is polled before a flush gives up on it.
///
/// A bound, like the read path's: a device that never completes a write must
/// not hang a flush for ever, and the error it returns is the caller's to
/// retry.
const FLUSH_POLL_LIMIT: u32 = 50_000_000;

/// One write a flush has handed to the device and not yet retired.
struct PendingWrite {
    ticket: Ticket,
    lba: u64,
    /// The entry generation that was submitted.  A completion clears the
    /// block's dirty flag only while the entry still carries it.
    generation: u64,
}

/// Sentinel value for an empty cache slot.
const EMPTY_LBA: u64 = u64::MAX;

pub use crate::stats::CacheStats;

#[derive(Debug, Clone)]
struct CacheEntry {
    lba: u64,
    data: [u8; BLOCK_SIZE],
    generation: u64,
    /// Whether this block has been modified in the cache but not yet written
    /// to the underlying device.
    dirty: bool,
    /// Cache-clock tick at which this block last became dirty; `0` when clean.
    /// Used by the aged background write-back to persist old dirty data.
    dirty_since: u64,
}

impl CacheEntry {
    const fn empty() -> Self {
        Self {
            lba: EMPTY_LBA,
            data: [0_u8; BLOCK_SIZE],
            generation: 0,
            dirty: false,
            dirty_since: 0,
        }
    }

    fn is_empty(&self) -> bool {
        self.lba == EMPTY_LBA
    }
}

pub struct BlockCache {
    device: Arc<dyn QueuedBlockDevice>,
    entries: Mutex<Vec<CacheEntry>>,
    generation: Mutex<u64>,
    stats: Mutex<CacheStats>,
    /// Last LBA accessed via `read_cached`, used for sequential-access
    /// detection and lightweight read-ahead.
    last_read_lba: Mutex<u64>,
    /// Read-ahead depth: number of extra blocks to prefetch after a
    /// sequential miss.  0, the default, disables read-ahead; a volume that
    /// wants it asks for it with [`BlockCache::with_read_ahead`].
    read_ahead_depth: usize,
}

impl BlockCache {
    pub fn new(device: Arc<dyn QueuedBlockDevice>) -> Self {
        Self {
            device,
            entries: Mutex::new(vec![CacheEntry::empty(); CACHE_CAPACITY]),
            generation: Mutex::new(0),
            stats: Mutex::new(CacheStats::default()),
            last_read_lba: Mutex::new(u64::MAX),
            read_ahead_depth: 0, // disabled by default; enable via `with_read_ahead()`
        }
    }

    /// Create a cache with sequential read-ahead enabled.
    ///
    /// When enabled, a sequential cache miss prefetches the next two blocks
    /// so that subsequent sequential reads are hits.
    pub fn with_read_ahead(device: Arc<dyn QueuedBlockDevice>, depth: usize) -> Self {
        Self {
            read_ahead_depth: depth,
            ..Self::new(device)
        }
    }

    /// Return a snapshot of the current cache statistics.
    pub fn stats(&self) -> CacheStats {
        *self.stats.lock()
    }

    /// Whether the underlying block device is read-only.
    pub fn is_read_only(&self) -> bool {
        self.device.is_read_only()
    }

    /// Read a block through the cache. On hit the cached data is returned
    /// without touching the device; on miss the block is read from the
    /// underlying device and stored in the cache before returning.
    ///
    /// When sequential access is detected (consecutive LBAs), the next
    /// two blocks are speculatively read into the cache so the caller
    /// avoids device round-trips on subsequent reads.
    pub fn read_cached(&self, lba: u64, buffer: &mut [u8]) -> Result<()> {
        let buffer_len = buffer.len();
        assert!(
            buffer_len == BLOCK_SIZE,
            "read_cached buffer must be BLOCK_SIZE bytes"
        );

        {
            let entries = self.entries.lock();
            if let Some(entry) = entries.iter().find(|e| e.lba == lba) {
                buffer.copy_from_slice(&entry.data);
                drop(entries);
                self.bump_generation_and_update(lba);
                self.inc_hits();

                // Count a sequential hit: this block follows the one read
                // before it, so whatever put it in the cache had read up to
                // here.
                let mut last = self.last_read_lba.lock();
                if *last != u64::MAX && lba == *last + 1 {
                    self.inc_sequential_hits();
                }
                *last = lba;
                // Read-ahead is only triggered on MISS, not on hit,
                // because a hit means the block is already in cache.
                return Ok(());
            }
        }

        // Cache miss.  Whether this read is part of a sequential stream is
        // decided first, because a sequential miss reads the block *and* the
        // lookahead after it in one request: the demand and the read-ahead are
        // contiguous, a device charges per request rather than per byte, and
        // one request that serves the caller and warms four blocks is strictly
        // better than two.
        let is_sequential = {
            let mut last = self.last_read_lba.lock();
            let sequential = *last != u64::MAX && lba == *last + 1;
            *last = lba;
            sequential
        };
        // The lookahead runs only as far as the first block that is already
        // cached: those blocks are exactly the ones a previous request read
        // ahead, and asking for them again would pay for them twice.
        let mut lookahead = 0usize;
        if is_sequential {
            let depth = self.read_ahead_depth.min(PREFETCH_RUN_BLOCKS);
            while lookahead < depth && !self.is_cached(lba + lookahead as u64 + 1) {
                lookahead += 1;
            }
        }

        if lookahead == 0 {
            self.device.read_blocks(lba, buffer)?;
            self.inc_misses();
            self.insert(lba, buffer, false);
            return Ok(());
        }

        // One request covers the caller's block and the blocks after it.  The
        // scratch buffer is a constant on the stack, like the prefetch's.
        let mut run = [0_u8; (1 + PREFETCH_RUN_BLOCKS) * BLOCK_SIZE];
        let blocks = lookahead + 1;
        self.device
            .read_blocks(lba, &mut run[..blocks * BLOCK_SIZE])?;
        buffer.copy_from_slice(&run[..BLOCK_SIZE]);
        self.inc_misses();
        for i in 0..blocks {
            let offset = i * BLOCK_SIZE;
            self.insert(lba + i as u64, &run[offset..offset + BLOCK_SIZE], false);
            if i > 0 {
                // The caller's own block is the miss; the rest are lookahead.
                self.inc_prefetches_issued();
            }
        }
        Ok(())
    }

    /// Write through to the underlying device and update the cached copy
    /// if present, so subsequent reads see the new data without a device
    /// round-trip.  The cached entry is marked clean (it matches the device).
    pub fn write_through(&self, lba: u64, data: &[u8]) -> Result<()> {
        assert!(
            data.len() == BLOCK_SIZE,
            "write_through data must be BLOCK_SIZE bytes"
        );

        self.device.write_blocks(lba, data)?;

        let mut entries = self.entries.lock();
        if let Some(entry) = entries.iter_mut().find(|e| e.lba == lba) {
            entry.data.copy_from_slice(data);
            entry.dirty = false;
            entry.dirty_since = 0;
            drop(entries);
            self.bump_generation_and_update(lba);
        }

        Ok(())
    }

    /// Write data into the cache and mark the entry dirty, deferring the
    /// device write until `flush()` or eviction.
    ///
    /// If the LBA is not currently cached it is inserted (possibly evicting
    /// another entry).  The underlying device is **not** touched by this call.
    pub fn write_back(&self, lba: u64, data: &[u8]) -> Result<()> {
        assert!(
            data.len() == BLOCK_SIZE,
            "write_back data must be BLOCK_SIZE bytes"
        );

        {
            let mut entries = self.entries.lock();
            if let Some(entry) = entries.iter_mut().find(|e| e.lba == lba) {
                entry.data.copy_from_slice(data);
                entry.dirty = true;
                entry.dirty_since = cache_tick();
                drop(entries);
                self.bump_generation_and_update(lba);
                return Ok(());
            }
        }

        // Not present, insert as dirty.
        self.insert(lba, data, true);
        Ok(())
    }

    /// Return `true` when the number of dirty blocks meets or exceeds the
    /// write-back pressure threshold.  Callers that batch many write-back
    /// operations (e.g., filesystem transaction commit) can use this to
    /// decide when to insert an early `flush()` so that later evictions
    /// don't synchronously write back under lock contention.
    pub fn write_back_under_pressure(&self) -> bool {
        self.dirty_slots() >= WRITE_BACK_PRESSURE_THRESHOLD
    }

    /// Trigger a full flush if the dirty-block count exceeds the write-back
    /// pressure threshold.  Best-effort: errors are silently ignored because
    /// dirty data remains safe in the cache and will be retried on eviction
    /// or explicit `flush()`.
    ///
    /// Increments `pressure_flushes` each time it triggers.
    pub fn flush_if_under_pressure(&self) {
        if self.write_back_under_pressure() {
            let _ = self.flush();
            self.inc_pressure_flushes();
        }
    }

    /// Write every dirty cached block to the underlying device.
    /// Dirty flags are cleared after successful writes.
    pub fn flush(&self) -> Result<()> {
        let count = self.flush_selected(|_| true)?;
        if count > 0 {
            self.add_dirty_writebacks(count as u64);
        }
        Ok(())
    }

    /// Write dirty cached blocks whose age meets or exceeds `age_ticks` to
    /// the underlying device.  A block written at cache-clock `T` is eligible
    /// once the clock reaches `T + age_ticks`.
    ///
    /// This is the "persistent cache" durability path: the scheduler drives
    /// it periodically so dirty data reaches stable storage without waiting
    /// for an explicit `fsync`/`sync`.  Returns the number of blocks written.
    pub fn flush_aged(&self, age_ticks: u64) -> Result<usize> {
        let now = cache_tick();
        let flushed =
            self.flush_selected(|entry| now.wrapping_sub(entry.dirty_since) >= age_ticks)?;
        if flushed > 0 {
            self.add_aged_writebacks(flushed as u64);
        }
        Ok(flushed)
    }

    /// Write the dirty blocks `select` accepts, through the device's queue.
    ///
    /// This is the one place the cache writes deferred data back, so `flush`,
    /// `flush_aged` and `flush_range` cannot drift apart.  The shape:
    ///
    /// * the dirty blocks are taken under the lock and submitted up to what the
    ///   device can hold, the driver copies each block before its submit
    ///   returns, so the lock is held only while the queue is being filled;
    /// * the lock is **dropped** while the writes are in flight, so a reader no
    ///   longer waits behind the whole flush;
    /// * a block's dirty flag is cleared only when its own write completes
    ///   *and* the entry still carries the generation that was submitted.  A
    ///   block rewritten while its write was in flight keeps its flag, and the
    ///   newer content goes out with the next flush, which is what "the cache
    ///   copy is newer than the device" means.  Each block is written at most
    ///   once per flush, so a writer that keeps rewriting cannot make a flush
    ///   chase it without end.
    ///
    /// A device that queues answers `queue_depth()` > 1 and the blocks go out
    /// together; a device of depth one gets exactly the serialized shape it
    /// had before.
    fn flush_selected(&self, select: impl Fn(&CacheEntry) -> bool) -> Result<usize> {
        let depth = core::cmp::max(1usize, self.device.queue_depth() as usize);
        let mut pending: Vec<PendingWrite> = Vec::new();
        // Every LBA this flush has written.  A block rewritten while its write
        // was in flight is dirty again, and without this the flush would pick
        // it up in the same pass and never finish under a busy writer.
        let mut attempted: Vec<u64> = Vec::new();
        let mut flushed = 0usize;
        let mut failure: Option<abi::Error> = None;

        loop {
            // Top up only while nothing has failed: a flush that has seen one
            // error stops asking the device for more work.
            if failure.is_none()
                && let Err(error) =
                    self.submit_selected(&select, depth, &mut pending, &mut attempted)
            {
                failure = Some(error);
            }

            if pending.is_empty() {
                break;
            }

            // Wait for the oldest write, then retire it.  A ticket nobody
            // polls is a slot nobody frees, so the queue is drained before
            // this returns even on the error path.
            let write = pending.remove(0);
            match self.wait_for_write(write.ticket) {
                Ok(()) => {
                    if self.retire_write(&write) {
                        flushed += 1;
                    }
                }
                Err(error) => {
                    // The block keeps its dirty flag: its data is still only
                    // in the cache.
                    if failure.is_none() {
                        failure = Some(error);
                    }
                }
            }
        }

        match failure {
            Some(error) => Err(error),
            None => Ok(flushed),
        }
    }

    /// Submit selected dirty blocks until the device's queue is full.
    ///
    /// The lock is held for this and nothing else: every block is copied by
    /// the device during its submit, so nothing the entries own has to outlive
    /// the call.
    fn submit_selected(
        &self,
        select: &impl Fn(&CacheEntry) -> bool,
        depth: usize,
        pending: &mut Vec<PendingWrite>,
        attempted: &mut Vec<u64>,
    ) -> Result<()> {
        let mut entries = self.entries.lock();
        while pending.len() < depth {
            let Some(index) = entries.iter().position(|entry| {
                entry.dirty
                    && select(entry)
                    // One write per block per flush.  This is also what keeps
                    // two writes to one LBA from being in flight together,
                    // where the device may complete them out of order and
                    // leave the older content on it.
                    && !attempted.contains(&entry.lba)
            }) else {
                return Ok(());
            };

            // The generation marks the content that is on its way out.  A
            // rewrite while the write is in flight takes a new one, which is
            // how the completion knows the entry moved on.
            let generation = self.next_generation();
            entries[index].generation = generation;
            let entry = &entries[index];
            let ticket = self.device.submit_write(entry.lba, &entry.data)?;
            attempted.push(entry.lba);
            pending.push(PendingWrite {
                ticket,
                lba: entry.lba,
                generation,
            });
        }
        Ok(())
    }

    /// Wait for one queued write, bounded so a wedged device cannot hang a
    /// flush for ever.
    fn wait_for_write(&self, ticket: Ticket) -> Result<()> {
        let mut polls = 0u32;
        loop {
            match self.device.poll(ticket) {
                RequestState::Pending => {
                    polls += 1;
                    if polls > FLUSH_POLL_LIMIT {
                        return Err(abi::Error::TimedOut);
                    }
                    core::hint::spin_loop();
                }
                RequestState::Done(result) => return result,
            }
        }
    }

    /// Clear the dirty flag a completed write was for, and say whether the
    /// write is one to count.
    ///
    /// The entry has to still be the one that was submitted *and* still be
    /// dirty: a block rewritten while its write was in flight is a different
    /// content than the device now holds, so it stays dirty for the next
    /// flush.
    fn retire_write(&self, write: &PendingWrite) -> bool {
        let mut entries = self.entries.lock();
        let Some(entry) = entries
            .iter_mut()
            .find(|entry| entry.lba == write.lba && entry.generation == write.generation)
        else {
            // The block was evicted, or rewritten into a different generation;
            // the write still happened, so it counts.
            return true;
        };
        if !entry.dirty {
            return false;
        }
        entry.dirty = false;
        entry.dirty_since = 0;
        true
    }

    /// Number of dirty blocks that have aged past `age_ticks` (visible for
    /// tests and diagnostics).
    pub fn aged_dirty_count(&self, age_ticks: u64) -> usize {
        let now = cache_tick();
        let entries = self.entries.lock();
        entries
            .iter()
            .filter(|e| e.dirty && now.wrapping_sub(e.dirty_since) >= age_ticks)
            .count()
    }

    /// Write dirty cached blocks within `[start_lba, start_lba + count)` to
    /// the underlying device.  Dirty flags are cleared after successful writes.
    pub fn flush_range(&self, start_lba: u64, count: u64) -> Result<()> {
        let end_lba = start_lba.saturating_add(count);
        let flushed = self.flush_selected(|entry| entry.lba >= start_lba && entry.lba < end_lba)?;
        if flushed > 0 {
            self.add_dirty_writebacks(flushed as u64);
        }
        Ok(())
    }

    /// Remove a specific LBA from the cache so the next read fetches fresh
    /// data from the underlying device.
    pub fn invalidate(&self, lba: u64) {
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.iter_mut().find(|e| e.lba == lba) {
            *entry = CacheEntry::empty();
            drop(entries);
            self.inc_evictions();
        }
    }

    /// Invalidate every cached block whose LBA falls in
    /// `[start_lba, start_lba + count)`.
    pub fn invalidate_range(&self, start_lba: u64, count: u64) {
        let end_lba = start_lba.saturating_add(count);
        let mut entries = self.entries.lock();
        let mut evicted = 0_u64;
        for entry in entries.iter_mut() {
            if !entry.is_empty() && entry.lba >= start_lba && entry.lba < end_lba {
                *entry = CacheEntry::empty();
                evicted += 1;
            }
        }
        drop(entries);
        if evicted > 0 {
            self.add_evictions(evicted);
        }
    }

    /// Current number of populated cache slots (visible for tests).
    pub fn populated_slots(&self) -> usize {
        let entries = self.entries.lock();
        entries.iter().filter(|e| !e.is_empty()).count()
    }

    /// Number of dirty blocks currently in the cache (visible for tests).
    pub fn dirty_slots(&self) -> usize {
        let entries = self.entries.lock();
        entries.iter().filter(|e| e.dirty).count()
    }

    /// Populate the cache with data for `lba` without marking the entry
    /// dirty.  The caller has already written the data to the device and
    /// only wants to warm the cache so that subsequent reads are hits.
    /// If the LBA is already cached the entry is updated in place (still
    /// clean); otherwise a new clean entry is inserted, evicting if needed.
    pub fn populate_clean(&self, lba: u64, data: &[u8]) {
        assert!(
            data.len() == BLOCK_SIZE,
            "populate_clean data must be BLOCK_SIZE bytes"
        );
        self.insert(lba, data, false);
    }

    /// Read-ahead the next `count` blocks after `start_lba`, on their own.
    ///
    /// The read path does not call this: a sequential miss reads its own block
    /// and the lookahead after it in one request, which is strictly better
    /// than a second one.  This is the explicit form, a caller that wants the
    /// cache warmed ahead of a read it has not made yet, and what the cache's
    /// own tests drive.
    ///
    /// The blocks that are not already cached are read from the device **as
    /// runs**, one request per contiguous stretch rather than one per block.
    /// That is the shape a device wants (a single command covering a
    /// kilobyte costs far less than two covering 512 bytes each), and it is
    /// the shape a queue would be handed if this ever became asynchronous.
    /// The read is still synchronous, so read-ahead gets *cheaper* here, not
    /// concurrent; `docs/status.md` records what that means for enabling it.
    pub fn prefetch(&self, start_lba: u64, count: usize) {
        let mut run_start: Option<u64> = None;
        let mut run_blocks = 0usize;
        for offset in 0..count {
            let lba = start_lba.saturating_add(offset as u64);
            if self.is_cached(lba) {
                self.read_run(&mut run_start, &mut run_blocks);
                continue;
            }
            if run_start.is_none() {
                run_start = Some(lba);
            }
            run_blocks += 1;
        }
        self.read_run(&mut run_start, &mut run_blocks);
    }

    /// Read one run of uncached blocks from the device and insert them clean.
    ///
    /// A run longer than [`PREFETCH_RUN_BLOCKS`] is split, so the scratch
    /// buffer is a constant size on the stack rather than an allocation in
    /// the read path.
    fn read_run(&self, run_start: &mut Option<u64>, run_blocks: &mut usize) {
        let Some(start) = run_start.take() else {
            *run_blocks = 0;
            return;
        };
        let mut blocks = core::mem::take(run_blocks);
        let mut lba = start;
        while blocks > 0 {
            let chunk = core::cmp::min(blocks, PREFETCH_RUN_BLOCKS);
            let mut buffer = [0_u8; PREFETCH_RUN_BLOCKS * BLOCK_SIZE];
            if self
                .device
                .read_blocks(lba, &mut buffer[..chunk * BLOCK_SIZE])
                .is_err()
            {
                // A failed read is not cached and not counted: whatever asked
                // for the block will read it itself and see the error.
                return;
            }
            for i in 0..chunk {
                let offset = i * BLOCK_SIZE;
                self.insert(lba + i as u64, &buffer[offset..offset + BLOCK_SIZE], false);
                self.inc_prefetches_issued();
            }
            lba += chunk as u64;
            blocks -= chunk;
        }
    }

    /// Whether a block is in the pool.
    fn is_cached(&self, lba: u64) -> bool {
        self.entries.lock().iter().any(|e| e.lba == lba)
    }

    /// Copy the cached copy of `lba`, if there is one.
    ///
    /// Unlike [`read_cached`](Self::read_cached), a hit here leaves the hit
    /// and sequential-read counters and the read-ahead heuristic alone, and a
    /// miss does not read the device.  A caller that compares a block it is
    /// about to write against the copy already in the slot is doing
    /// bookkeeping, and charging that to the counters would describe the
    /// comparison instead of the workload the counters are there to report.
    pub fn cached(&self, lba: u64) -> Option<[u8; BLOCK_SIZE]> {
        let entries = self.entries.lock();
        entries
            .iter()
            .find(|entry| entry.lba == lba)
            .map(|entry| entry.data)
    }

    // internal helpers

    fn next_generation(&self) -> u64 {
        let mut generation_value = self.generation.lock();
        let current = *generation_value;
        *generation_value = current.wrapping_add(1);
        current
    }

    fn bump_generation_and_update(&self, lba: u64) {
        let generation_value = self.next_generation();
        let mut entries = self.entries.lock();
        if let Some(entry) = entries.iter_mut().find(|e| e.lba == lba) {
            entry.generation = generation_value;
        }
    }

    /// Insert `data` for `lba` into the cache.  When `dirty` is true the
    /// entry is marked as needing write-back; otherwise it is considered
    /// clean (matches the device).
    ///
    /// If the cache is full, eviction prefers clean entries first so that
    /// dirty data is not prematurely flushed.  When a dirty entry must be
    /// evicted its contents are written to the device first.
    fn insert(&self, lba: u64, data: &[u8], dirty: bool) {
        let generation_value = self.next_generation();
        let dirty_since = if dirty { cache_tick() } else { 0 };
        let mut entries = self.entries.lock();

        // If the same LBA is already present, just update in place.
        if let Some(entry) = entries.iter_mut().find(|e| e.lba == lba) {
            entry.data.copy_from_slice(data);
            entry.generation = generation_value;
            entry.dirty = dirty;
            entry.dirty_since = dirty_since;
            return;
        }

        // Prefer an empty slot.
        if let Some(slot) = entries.iter_mut().find(|e| e.is_empty()) {
            slot.lba = lba;
            slot.data.copy_from_slice(data);
            slot.generation = generation_value;
            slot.dirty = dirty;
            slot.dirty_since = dirty_since;
            return;
        }

        // Cache is full, choose an eviction victim.
        // Strategy: prefer the least-recently-used *clean* entry so dirty
        // blocks stay resident and are only written back when necessary.
        {
            let clean_lru = entries
                .iter()
                .enumerate()
                .filter(|(_, e)| !e.dirty)
                .min_by_key(|(_, e)| e.generation)
                .map(|(i, _)| i);

            if let Some(idx) = clean_lru {
                // Evict a clean entry, cheap, no device I/O needed.
                let victim = &mut entries[idx];
                victim.lba = lba;
                victim.data.copy_from_slice(data);
                victim.generation = generation_value;
                victim.dirty = dirty;
                victim.dirty_since = dirty_since;
                drop(entries);
                self.inc_evictions();
                return;
            }
        }

        // All entries are dirty.  Pick the LRU one and flush it first.
        {
            let victim_idx = entries
                .iter()
                .enumerate()
                .min_by_key(|(_, e)| e.generation)
                .map(|(i, _)| i)
                .expect("cache capacity must be > 0");

            let flush_lba = entries[victim_idx].lba;
            let flush_data = entries[victim_idx].data;
            // Mark the slot empty while we hold the lock so it isn't
            // double-counted; the write happens below outside the lock.
            entries[victim_idx] = CacheEntry::empty();
            drop(entries);

            // Write the dirty victim back to the device.
            let _ = self.device.write_blocks(flush_lba, &flush_data);
            self.inc_evictions();
            self.inc_dirty_writebacks();
        }

        // The victim was flushed and its slot is now empty.  Re-acquire
        // and find that (or any) empty slot.  In the single-threaded kernel
        // no other thread can steal it, but we re-check to be safe.
        let mut entries = self.entries.lock();
        let slot = entries
            .iter_mut()
            .find(|e| e.is_empty())
            .expect("a slot must have been freed by eviction");
        slot.lba = lba;
        slot.data.copy_from_slice(data);
        slot.generation = generation_value;
        slot.dirty = dirty;
        slot.dirty_since = dirty_since;
    }

    // stats helpers

    fn inc_hits(&self) {
        self.stats.lock().hits += 1;
    }

    fn inc_misses(&self) {
        self.stats.lock().misses += 1;
    }

    fn inc_evictions(&self) {
        self.stats.lock().evictions += 1;
    }

    fn add_evictions(&self, count: u64) {
        self.stats.lock().evictions += count;
    }

    fn inc_dirty_writebacks(&self) {
        self.stats.lock().dirty_writebacks += 1;
    }

    fn add_dirty_writebacks(&self, count: u64) {
        self.stats.lock().dirty_writebacks += count;
    }

    fn add_aged_writebacks(&self, count: u64) {
        self.stats.lock().aged_writebacks += count;
    }

    fn inc_pressure_flushes(&self) {
        self.stats.lock().pressure_flushes += 1;
    }

    fn inc_sequential_hits(&self) {
        self.stats.lock().sequential_hits += 1;
    }

    fn inc_prefetches_issued(&self) {
        self.stats.lock().prefetches_issued += 1;
    }
}

#[cfg(test)]
mod tests;
