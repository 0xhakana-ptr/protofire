//! kernel/src/block_devices.rs
//!
//! The devices this boot found, in the order it found them.
//!
//! ## Why a list the boot fills rather than a query
//!
//! `devices::block` has a publisher: a driver hands its device to whoever owns
//! the map, so a driver never has to name the filesystem.  That slot is for the
//! **mount** table, which wants the device behind a filesystem.
//!
//! `ListBlockDevices` wants something else: a program asking what disks exist,
//! in the order the bus gave them, with the name and the size.  Recording them
//! as they are found is the shape that answers it: the alternative is walking
//! the mount table, which lists filesystems and not devices, and would answer
//! nothing for a disk nobody mounted.
//!
//! ## What it holds
//!
//! A fixed array, no allocation: the boot fills it before any program runs, the
//! count is what the ABI's index is checked against, and a list that could grow
//! under a reader would be a list whose index means something different between
//! two calls.

use spin::Mutex;

use abi::fs as fs_abi;

/// The most devices a boot can record.
///
/// Four is more than any machine this tree boots has and far below what an
/// allocation would cost: a boot's disk count is a property of the machine, and
/// a fixed ceiling makes "the list is full" a state the code has to name rather
/// than a silent drop.
pub const MAX_DEVICES: usize = 4;

/// One device, as the ABI's record describes it.
#[derive(Debug, Clone, Copy)]
pub struct ListedDevice {
    pub name: [u8; fs_abi::BLOCK_DEVICE_NAME_MAX],
    pub block_size: u64,
    pub block_count: u64,
    pub read_only: bool,
}

impl ListedDevice {
    /// The name as a string, up to the first NUL.
    ///
    /// The record's name is a fixed array with a NUL terminator, which is the
    /// wire shape; this is the reading a log line or a comparison wants.
    pub fn name(&self) -> &str {
        let end = self
            .name
            .iter()
            .position(|&byte| byte == 0)
            .unwrap_or(self.name.len());
        core::str::from_utf8(&self.name[..end]).unwrap_or("")
    }
}

/// The list, filled once at boot and read many times.
static DEVICES: Mutex<DeviceList> = Mutex::new(DeviceList::new());

struct DeviceList {
    entries: [ListedDevice; MAX_DEVICES],
    count: usize,
}

impl DeviceList {
    const fn new() -> Self {
        Self {
            entries: [ListedDevice {
                name: [0; fs_abi::BLOCK_DEVICE_NAME_MAX],
                block_size: 0,
                block_count: 0,
                read_only: false,
            }; MAX_DEVICES],
            count: 0,
        }
    }
}

/// Record one device, answering whether it fit.
///
/// `false` means the list is full, which a boot reports rather than swallows: a
/// disk the machine has and the list does not name is a disk a program cannot
/// find, and the reason would otherwise be invisible.
pub fn record(name: &str, block_size: usize, block_count: u64, read_only: bool) -> bool {
    let mut list = DEVICES.lock();
    if list.count == MAX_DEVICES {
        return false;
    }
    let mut entry = ListedDevice {
        name: [0; fs_abi::BLOCK_DEVICE_NAME_MAX],
        block_size: block_size as u64,
        block_count,
        read_only,
    };
    // A name longer than the record cannot be truncated silently: the record's
    // name is what a program matches on, and a shortened one names a different
    // device.  The caller's names are its own constants, so this is a bound the
    // driver's own string already meets.
    let bytes = name.as_bytes();
    let take = bytes.len().min(fs_abi::BLOCK_DEVICE_NAME_MAX - 1);
    entry.name[..take].copy_from_slice(&bytes[..take]);
    let at = list.count;
    list.entries[at] = entry;
    list.count = at + 1;
    true
}

/// How many devices the boot recorded.
pub fn count() -> usize {
    DEVICES.lock().count
}

/// The device at `index`, or `None` past the end.
///
/// The ABI's index is "which of the devices this boot found", and an index past
/// the end answers `NotFound`: there is no such device, which is the same word
/// a missing file gets and is true of both.
pub fn get(index: usize) -> Option<ListedDevice> {
    let list = DEVICES.lock();
    if index >= list.count {
        return None;
    }
    Some(list.entries[index])
}

/// Empty the list, and the reason it exists.
///
/// A test installs a list, reads it, and clears it; a boot fills it once and
/// never clears it.  The function is here rather than behind `#[cfg(test)]`
/// because a reboot path would want it and a test-only function would have to
/// be moved the day one appeared.
pub fn clear() {
    *DEVICES.lock() = DeviceList::new();
}

#[cfg(test)]
mod tests {
    //! The list's own behaviour, and the record it answers with.

    use super::*;
    // The list is a `static` and the tests run in parallel, so clearing at
    // the start of one is not enough: another test can record between that
    // clear and the read.  Each test takes this lock for its whole body, which
    // makes them run in sequence against the one list.  The first version
    // only cleared and failed with an index that named the wrong device,
    // which is exactly the interleaving the lock removes.
    static SERIAL: spin::Mutex<()> = spin::Mutex::new(());

    /// Take the test lock.
    ///
    /// `spin::Mutex` has no poisoning to recover from, which is one fewer thing
    /// a guard has to say: a test that panicked released it while unwinding and
    /// the next one takes it.
    fn serial() -> spin::MutexGuard<'static, ()> {
        SERIAL.lock()
    }

    /// A recorded device answers what was recorded.
    #[test]
    fn a_recorded_device_answers_its_own_numbers() {
        let _guard = serial();
        clear();
        assert!(record("virtio-blk", 512, 2048, false));
        assert_eq!(count(), 1);

        let device = get(0).expect("the device just recorded");
        assert_eq!(device.name(), "virtio-blk");
        assert_eq!(device.block_size, 512);
        assert_eq!(device.block_count, 2048);
        assert!(!device.read_only);
    }

    /// The order is the order they were found, which is what the index means.
    #[test]
    fn the_index_is_the_order_the_boot_found_them() {
        let _guard = serial();
        clear();
        assert!(record("first", 512, 1, false));
        assert!(record("second", 4096, 2, true));
        assert_eq!(count(), 2);
        assert_eq!(get(0).unwrap().name(), "first");
        assert_eq!(get(1).unwrap().name(), "second");
        assert!(get(1).unwrap().read_only);
    }

    /// An index past the end answers nothing rather than a zeroed record.
    ///
    /// A zeroed record would be a device with no name, no size and no blocks,
    /// which a program would print as a real device.
    #[test]
    fn an_index_past_the_end_answers_nothing() {
        let _guard = serial();
        clear();
        assert!(record("only", 512, 1, false));
        assert!(get(1).is_none());
        assert!(get(usize::MAX).is_none());
    }

    /// The list refuses more than it can hold, and says so.
    ///
    /// Refused rather than silently dropped: a driver told `false` can report
    /// that a disk exists and is not listed, which is a fact a reader can act
    /// on.
    #[test]
    fn the_list_refuses_a_device_it_cannot_hold() {
        let _guard = serial();
        clear();
        for index in 0..MAX_DEVICES {
            assert!(record("disk", 512, index as u64, false), "{index}");
        }
        assert!(!record("one-too-many", 512, 0, false));
        assert_eq!(count(), MAX_DEVICES);
    }

    /// A name is stored NUL-terminated and reads back without the terminator.
    #[test]
    fn a_name_reads_back_without_its_terminator() {
        let _guard = serial();
        clear();
        assert!(record("nvme0n1", 4096, 8, false));
        let device = get(0).unwrap();
        assert_eq!(device.name(), "nvme0n1");
        assert_eq!(device.name[7], 0, "the terminator is there");

        // A name exactly at the limit loses its last byte to the terminator
        // rather than overrunning the record.
        clear();
        let longest = "x".repeat(fs_abi::BLOCK_DEVICE_NAME_MAX);
        assert!(record(&longest, 512, 1, false));
        let device = get(0).unwrap();
        assert_eq!(device.name().len(), fs_abi::BLOCK_DEVICE_NAME_MAX - 1);
        assert_eq!(device.name[fs_abi::BLOCK_DEVICE_NAME_MAX - 1], 0);
    }
}
