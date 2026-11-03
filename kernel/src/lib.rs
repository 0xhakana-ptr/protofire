//! kernel/src/lib.rs
//!
//! The kernel's core: the subsystems that are not a crate of their own.
//!
//! ## What lives here, and what does not
//!
//! A subsystem becomes a crate when something else needs to name it without
//! naming the kernel.  `fs`, `memory`, `net`, `ipc` and `power` are crates for
//! that reason — they are asked questions by `syscall`, by drivers, and by each
//! other, and a crate boundary is what makes "who may name whom" a compiler
//! error rather than a convention.  What stays here is what only the kernel
//! core organises: scheduling, and the boot sequence that puts the subsystems
//! in order.
//!
//! `ipc` and `power` are crates of their own even though the kernel is their
//! only caller today.  A ring buffer and a governor are arithmetic over values,
//! and arithmetic that can only be tested by booting is arithmetic nobody
//! tests; naming them through a manifest is what keeps a test on the host
//! cheap.  Their halves that need a machine — the pipe endpoints that park a
//! reader, the `cpufreq` dispatchers that ask for an MSR — arrive in those
//! crates and reach the kernel through an injected hook, not by moving the
//! crate here.
//!
//! ## The boot sequence
//!
//! `kernel_main` is the whole of the ordering decision, and it is a function a
//! host test can call.  The bootloader's contribution is the handshake and the
//! two symbols a `no_std` binary must define; nothing about *what order* lives
//! there.

#![no_std]

// The boot builds a filesystem image in memory and mounts it, and both need a
// heap.  The `#[global_allocator]` below is what provides one, so this line and
// that static arrived together: an `alloc` without an allocator is a link
// error, and an allocator nobody allocates from is a heap with no caller.
extern crate alloc;

pub mod scheduler;
pub mod syscall;

// The heap's global allocator, installed here because this is the crate that
// knows it is a kernel.
//
// `libs/allocator` deliberately does not install one: a library that did could
// not be a dependency of a test binary, and two global allocators is a link
// error.  But something has to install one before the first `Vec`, and the
// first `Vec` is `async_io`'s completion queue — which is why this arrived with
// the wiring rather than before it.
//
// SAFETY: `KernelGlobalAllocator` implements `GlobalAlloc` with every method
// taking `&self` and reaching its state only through a lock, so it is safe to
// share as the process-wide allocator.  Its arena is a `static` array and its
// free lists are laid out on the first call.
#[cfg(target_os = "none")]
#[global_allocator]
static GLOBAL_ALLOCATOR: allocator::KernelGlobalAllocator = allocator::KernelGlobalAllocator::new();

/// The stage a boot has reached, as one word, for a log line that cannot yet
/// afford to be wrong.
///
/// This exists so the first thing the kernel does is observable.  A machine
/// that dies before its console is up otherwise leaves nothing behind, and
/// "nothing was printed" is not a diagnosis — it covers a bad image, a bad
/// stack, a bad page table, and a correct kernel that has not been written
/// yet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum BootStage {
    /// The handshake arrived; nothing has been touched.
    Entered = 0,
    /// The machine's serial port, if it has one, is writing.
    ConsoleUp = 1,
}

/// What the bootloader handed over.
///
/// Defined in `abi` rather than here: the architecture crate parses the
/// handshake and the kernel consumes it, so a type either side has to name
/// belongs where both can reach it.  The re-export keeps the spelling this
/// crate's callers use.
pub use abi::BootInfo;
pub use abi::Loader;

/// The boot, from the point where a machine is up to the point where it stops.
///
/// This takes a [`BootInfo`] rather than a loader's registers: parsing the
/// handshake is the architecture's business, and the previous tree's entry took
/// x86_64's convention for the whole tree's.  A new machine supplies its own
/// `arch::boot_info()` and nothing here changes.
///
/// The console is what makes this boot observable, so it comes first: every
/// line below is a claim, and a claim nothing can read is not evidence.
pub fn kernel_main() -> ! {
    arch::serial::init();

    // The heap's diagnostics go to the same console, and this is where that is
    // decided.  `allocator` reports through a sink it is handed rather than
    // through a kernel macro, which is what lets its tests run on a host; the
    // price is this line, and a boot that omitted it would lose every
    // allocation-failure message without failing anything.
    //
    // SAFETY: `write_to_console` is a `fn(&str)` that writes the UART and
    // allocates nothing — required, because the allocator may call it from
    // inside a failed allocation.
    unsafe { allocator::diag::set_writer(Some(write_to_console)) };

    let boot = arch::boot_info();

    arch::serial::write_str("protofire 0.1.0: entered via ");
    arch::serial::write_str(boot.loader.as_str());
    arch::serial::write_str(", console up, stage ");
    arch::serial::write_u32(BootStage::ConsoleUp as u32);
    arch::serial::write_str("\n");

    // Initialise the heap and say where it is.
    //
    // This is not a probe left behind: `bounds()` is what makes the allocator
    // lay out its free lists, so a boot that did not call it would hand out
    // memory from a heap with no free list at all.  The line is how that
    // arrangement becomes observable — and how the allocator's diagnostic sink
    // is proven to reach the console, because the sink and this line are the
    // same path.
    let heap = allocator::HeapAllocator::new();
    let (heap_start, heap_end) = heap.bounds();
    arch::serial::write_str("protofire: heap at ");
    arch::serial::write_hex(heap_start as u64);
    arch::serial::write_str("..");
    arch::serial::write_hex(heap_end as u64);
    arch::serial::write_str("\n");

    // A real filesystem, end to end: build a PyroFS image, mount it over an
    // in-memory device, and read a file back through the `VNode` contract.
    //
    // This is the first run of the three layers together — `block` gives the
    // device, `fs` the interface, `pyrofs` the format — and it is what turns
    // "the crates compile" into "the filesystem works on a machine".  The
    // volume is built by this boot rather than shipped: an image that is a
    // constant in the tree would be one nobody rebuilt, and a format change
    // would find the stale copy before it found the code.
    let image = match fs::pyrofs::PyroFs::build_image(
        BOOT_VOLUME_LABEL,
        &[fs::pyrofs::ImageEntry {
            path: "/greeting.txt",
            data: BOOT_VOLUME_CONTENT,
        }],
    ) {
        Ok(image) => image,
        Err(_) => {
            arch::serial::write_str("protofire: filesystem image build FAILED\n");
            halt()
        }
    };

    // The device the volume mounts on.  `MemoryBlockDevice::from_image` takes
    // the bytes a builder produced, which is the same shape a driver's device
    // has once it has read its first sectors.
    let device: alloc::sync::Arc<dyn block::QueuedBlockDevice> =
        block::MemoryBlockDevice::new(BOOT_VOLUME_LABEL, image, false);

    let volume = match fs::pyrofs::PyroFs::open(device, true) {
        Ok(volume) => fs::pyrofs::PyroFsVolume::new(volume),
        Err(error) => {
            arch::serial::write_str("protofire: filesystem mount FAILED: ");
            arch::serial::write_str(error.as_str());
            arch::serial::write_str("\n");
            halt()
        }
    };

    // The read happens through a syscall, not through the filesystem.
    //
    // The registry is handed the mounted volume and is then the only thing
    // that can reach it: every later step names a descriptor and a number, and
    // the only code that reaches a `VNode` is the handler `open` leads to.
    // That is what makes this a boot of the syscall path rather than a boot
    // that happens to have one compiled in — and it is the step the previous
    // version of this function skipped, which is why the table was written and
    // never executed.
    let mut table = crate::syscall::SyscallTable::new();
    table.set_volume(alloc::sync::Arc::new(volume));
    table.register(::syscall::SyscallNumber::Open, crate::syscall::open);
    table.register(::syscall::SyscallNumber::Read, crate::syscall::read);
    table.register(::syscall::SyscallNumber::Close, crate::syscall::close);

    let read_ok = read_greeting_through_syscall(&mut table);

    arch::serial::write_str("protofire: filesystem ");
    if read_ok {
        arch::serial::write_str(
            "mounted and read /greeting.txt through syscall open/read/close, label ",
        );
        arch::serial::write_str(BOOT_VOLUME_LABEL);
    } else {
        arch::serial::write_str("FAILED to read /greeting.txt through syscall open/read/close");
    }
    arch::serial::write_str("\n");

    halt()
}

/// The label the boot's volume carries.
const BOOT_VOLUME_LABEL: &str = "protofire";

/// What the boot writes into its volume and reads back.
///
/// A string no other file in the tree contains: a check that compared a
/// constant against itself would pass on a volume that was never written.
const BOOT_VOLUME_CONTENT: &[u8] = b"the quick brown pyrofox";

/// The path the boot opens and reads.
const BOOT_VOLUME_PATH: &str = "/greeting.txt";

/// Read the boot's file through the syscall table.
///
/// Three calls — open, read, close — each built the way a program builds one:
/// a number, six argument words, and a value or an error back.  The result is
/// whether the bytes are the ones the image was built with; a caller that wants
/// the reason a boot failed has the console, which is what the boot prints.
///
/// The buffer is a local rather than a fixed address, and it reaches the
/// handler as a borrow.  That is the whole of this function's contribution to
/// safety: nothing here turns a number into a pointer.
fn read_greeting_through_syscall(table: &mut crate::syscall::SyscallTable) -> bool {
    use crate::syscall::Arguments;
    use ::syscall::SyscallContext;

    // open(path, flags)
    let mut context = SyscallContext::new(
        ::syscall::SyscallNumber::Open as usize,
        [0, abi::fs::OPEN_FLAG_READ, 0, 0, 0, 0],
    );
    let mut arguments = Arguments {
        context: &mut context,
        path: Some(BOOT_VOLUME_PATH),
        buffer: None,
    };
    let Ok(dispatch) = table.dispatch(&mut arguments) else {
        return false;
    };
    let descriptor = dispatch.value;

    // read(descriptor, offset, buffer)
    let mut buffer = [0u8; BOOT_VOLUME_CONTENT.len()];
    let mut context = SyscallContext::new(
        ::syscall::SyscallNumber::Read as usize,
        [descriptor, crate::syscall::READ_OFFSET_CURRENT, 0, 0, 0, 0],
    );
    let mut arguments = Arguments {
        context: &mut context,
        path: None,
        buffer: Some(&mut buffer),
    };
    let read_ok = match table.dispatch(&mut arguments) {
        Ok(dispatch) => {
            dispatch.value == BOOT_VOLUME_CONTENT.len() && buffer == *BOOT_VOLUME_CONTENT
        }
        Err(_) => false,
    };

    // close(descriptor)
    //
    // The close runs even when the read failed: a slot left open in a table
    // this small is the kind of leak that shows up as a limit much later.
    let mut context = SyscallContext::new(
        ::syscall::SyscallNumber::Close as usize,
        [descriptor, 0, 0, 0, 0, 0],
    );
    let mut arguments = Arguments::plain(&mut context);
    let close_ok = table.dispatch(&mut arguments).is_ok();

    read_ok && close_ok && table.open_descriptors() == 0
}

/// The allocator's diagnostic sink: the console, one string at a time.
///
/// A free function rather than a closure because `set_writer` takes a `fn`, and
/// because this is the one place the allocator's output and the machine's
/// console are joined — naming it makes that join visible in a search.
fn write_to_console(text: &str) {
    arch::serial::write_str(text);
    arch::serial::write_str("\n");
}

/// Stop this CPU.
///
/// Delegated to the architecture crate: the instructions belong there, and
/// this file naming `hlt` would be the exact leak `arch` exists to prevent.
/// A `-> !` function that only stops is `pub` because every later stage — the
/// idle loop, a panic, an unhandled exception — ends here rather than each
/// writing its own stop.
pub fn halt() -> ! {
    arch::halt()
}

#[cfg(test)]
mod tests {
    use super::BootStage;

    /// The stage values are written into a log line, so their discriminants are
    /// part of what a reader sees.  A reordering that changed them would make
    /// every previously captured log a lie without failing to compile.
    #[test]
    fn boot_stages_keep_their_values() {
        assert_eq!(BootStage::Entered as u32, 0);
        assert_eq!(BootStage::ConsoleUp as u32, 1);
    }
}
