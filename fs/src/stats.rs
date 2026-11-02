//! fs/src/stats.rs
//!
//! The counters a filesystem and its cache report.
//!
//! ## Why these are here and not with the cache
//!
//! `FileSystem::cache_stats` returns a `CacheStats` and
//! `FileSystem::fs_profiler_snapshot` a `FsProfilerSnapshot`, so both are part
//! of the interface whether or not the crate that *produces* them is present.
//! A trait whose method returned a type from a crate the implementor has to
//! add is a trait that names that crate; these two structs are the reply, and
//! the reply belongs with the question.
//!
//! They are plain counters.  Nothing here reads a device or reaches a cache,
//! which is the property that lets them sit at the interface layer: a struct of
//! `u64`s is not a dependency, and a `Default` returning zeros is what a
//! filesystem with no cache of its own answers.

// The counters are produced elsewhere and read by a boot-work line; the doc on
// each is the definition of what it counts, which is why they are long.

/// Counters from the block cache under a filesystem.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheStats {
    /// Blocks found in the cache.
    pub hits: u64,
    /// Blocks not found, and read from the device.
    pub misses: u64,
    /// Blocks dropped to make room.
    pub evictions: u64,
    /// Dirty blocks written back to the device, at eviction or at a flush.
    pub dirty_writebacks: u64,
    /// Hits on the block right after the one read before it.
    ///
    /// This is what a cache can tell from its own last access.  It is *not* a
    /// read-ahead hit count: a block that arrived by read-ahead and one the
    /// caller read are the same entry once inserted, so telling them apart
    /// would need an entry to remember where it came from.
    pub sequential_hits: u64,
    /// Sequential read-ahead blocks prefetched.
    pub prefetches_issued: u64,
    /// Flushes triggered because the dirty count passed the write-back
    /// pressure threshold.
    pub pressure_flushes: u64,
    /// Dirty blocks written back by the aged pass, which the maintenance thread
    /// drives rather than a caller.
    pub aged_writebacks: u64,
}

#[cfg(test)]
mod tests {
    use super::CacheStats;

    /// A filesystem with no cache answers zeros, and the answer is a value.
    ///
    /// `Default` is what `FileSystem`'s default methods return, so a struct
    /// whose `Default` was not all-zero would report counters nobody counted.
    #[test]
    fn the_defaults_are_zero() {
        let cache = CacheStats::default();
        assert_eq!(cache.hits, 0);
        assert_eq!(cache.misses, 0);
        assert_eq!(cache.evictions, 0);
    }

    /// The two are `Copy`, so a trait method can return one without the caller
    /// holding the cache it came from.
    ///
    /// This is a compile-time property written as a test: making either type
    /// non-`Copy` would break every `fn cache_stats(&self) -> CacheStats`
    /// implementor, and the error would name the trait rather than the reason.
    #[test]
    fn the_counters_are_copy() {
        fn takes_by_value<T: Copy>(_: T) {}
        takes_by_value(CacheStats::default());
    }
}
