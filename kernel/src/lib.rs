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

pub mod address_space;
pub mod devices;
pub mod interrupts;
pub mod iso_disc;
pub mod pipe;
pub mod process;
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

/// The line the boot raises to prove the interrupt path.
///
/// The machine's own, and on x86_64 it is the **timer's** vector rather than a
/// spare one.  A spare vector proved the gate but cost the timer: the local
/// APIC records every vector it delivers as in-service, and ending an
/// interrupt for a vector the kernel's sink does not claim leaves the
/// controller's state ordered differently from what a real tick produces.  The
/// boot then reported a delivered test interrupt and never took a tick.
///
/// The timer's vector is the honest instrument anyway: it is the line the
/// scheduler depends on, so proving it is proving the thing that matters.
#[cfg(target_os = "none")]
fn test_interrupt() -> usize {
    arch::test_interrupt()
}

/// The sentinel [`TEST_INTERRUPT_RAISED`] holds before an interrupt arrives.
///
/// `usize::MAX` is not an interrupt number any controller reports, so it is
/// distinguishable from every real one — including zero, which is the line this
/// boot raises.
const NO_INTERRUPT: usize = usize::MAX;

/// The interrupt the test raised, if any.
///
/// A static because the sink is a plain `fn` and has no context to be handed
/// one — the same shape the trap sink itself has.
pub static TEST_INTERRUPT_RAISED: core::sync::atomic::AtomicUsize =
    core::sync::atomic::AtomicUsize::new(NO_INTERRUPT);

/// Raise one interrupt from the controller and require that it arrived.
///
/// Prints what happened either way.  A line that was published and never
/// delivered is the failure this reports, and a boot log that said "interrupts
/// on" without it has said nothing about whether the machine can take one.
#[cfg(target_os = "none")]
fn raise_test_interrupt() {
    use core::sync::atomic::Ordering;

    // A value no interrupt can have, so "nothing arrived" is distinguishable
    // from "interrupt 0 arrived".
    //
    // This is the defect that made the first version of this probe useless: the
    // line raised is interrupt *zero*, the counter's initial value was zero,
    // and so a boot that raised nothing printed exactly what a boot that raised
    // something printed.  A test that cannot fail is worse than no test, and
    // this one could not fail.
    TEST_INTERRUPT_RAISED.store(NO_INTERRUPT, Ordering::Release);
    let line = test_interrupt();

    // SAFETY: the controller is enabled and the sink is installed by the time
    // this runs.  An SGI needs no enable — its bit is always set — and a
    // self-directed APIC interrupt needs none either, so this asks the
    // controller to raise it and nothing else.
    let raised = unsafe { arch::raise_interrupt(line) };

    if !raised {
        arch::serial::write_str(
            "protofire: interrupt path not exercised (this machine has no controller to raise one)",
        );
        arch::serial::write_str("\n");
        return;
    }

    let delivered = TEST_INTERRUPT_RAISED.load(Ordering::Acquire);
    if delivered == line {
        arch::serial::write_str("protofire: interrupt delivered to its handler\n");
    } else {
        arch::serial::write_str("protofire: interrupt raised but not delivered");
        if delivered != NO_INTERRUPT {
            arch::serial::write_str(" (handler saw ");
            arch::serial::write_u32(delivered as u32);
            arch::serial::write_str(")");
        }
        arch::serial::write_str("\n");
    }
}

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

    // What the machine's handshake actually contained.
    //
    // A device-tree machine puts a pointer in a register and the pointer may
    // name anything: firmware that handed over something unauthoritative, a
    // loader that cleared the register, a blob whose header disagrees with its
    // bytes.  So the answer is a line rather than an assumption — and it is the
    // line that says whether the console's address, the memory map and the
    // boot's device windows came from a tree or from a fallback.
    arch::serial::write_str("protofire: device tree ");
    match arch::device_tree_summary() {
        Some(summary) => {
            arch::serial::write_str("v");
            arch::serial::write_u32(summary.version);
            arch::serial::write_str(", ");
            arch::serial::write_u32(summary.memory_regions);
            arch::serial::write_str(" memory region(s), uart at ");
            arch::serial::write_hex(summary.uart as u64);
        }
        None => arch::serial::write_str("not handed over (using this machine's constants)"),
    }
    arch::serial::write_str("\n");

    // Replace the boot's page table with one this kernel built.
    //
    // The assembly's table maps four gigabytes identity with 2 MiB pages, every
    // one writable and cached — the smallest thing that lets Rust run, and
    // wrong for everything after.  This builds a second table with the same
    // translations at a 4 KiB granule, so text is read-execute, read-only data
    // is read, and the kernel's own state is read-write.  Every address the
    // boot already touched translates the same, which is what makes the swap
    // invisible; what changes is what each region is allowed to do.
    //
    // It runs before the heap because the table's backing is a static array
    // rather than allocated frames — a table built from frames would have to be
    // built before the thing that hands them out.
    //
    // SAFETY: called once, from the kernel's entry, with the console up so a
    // failure past this point is visible.  The table it installs covers the
    // code performing the install.
    arch::serial::write_str("protofire: page table ");
    #[cfg(target_os = "none")]
    {
        // SAFETY: called once, from the kernel's entry, with the console up so
        // a failure past this point is visible.  The table it installs covers
        // the code performing the install.
        let installed = unsafe { address_space::install() };
        if installed {
            arch::serial::write_str("built and installed, 4 KiB granule\n");
        } else {
            arch::serial::write_str("was already installed\n");
        }
    }
    #[cfg(not(target_os = "none"))]
    arch::serial::write_str("not installed (a host has no address space to install)\n");

    // The frames the machine really has, for the tables past the reserved ones.
    //
    // Printed here rather than beside the heap because it is the page table's
    // input: a boot that managed a pool larger than RAM would map a device
    // window into memory that is not there, and the line is how that shows.
    #[cfg(target_os = "none")]
    {
        arch::serial::write_str("protofire: frame pool ");
        arch::serial::write_u32(crate::address_space::managed_frames() as u32);
        arch::serial::write_str(" frame(s), ");
        arch::serial::write_u32(crate::address_space::free_frames() as u32);
        arch::serial::write_str(" free, ");
        arch::serial::write_u32(crate::address_space::frames_taken_for_tables() as u32);
        arch::serial::write_str(" in page tables");

        // And the allocator itself, exercised rather than described.
        //
        // SAFETY: the pool is initialised and nothing else has allocated from
        // it; the frame is released before the call returns.
        let pool_ok = unsafe { crate::address_space::self_check_frame_pool() };
        arch::serial::write_str(if pool_ok {
            ", pool check ok\n"
        } else {
            ", pool check FAILED\n"
        });
    }

    // Interrupts: a table of gates, and the sink a frame goes to.
    //
    // The order is the point.  The sink is installed first, so a vector that
    // arrived between the table being loaded and the handler existing would be
    // one the dispatch could not answer.  Then the table, then the flag.
    //
    // Nothing raises a vector yet: the boot has not programmed an interrupt
    // controller and no driver has registered a line.  That is what makes this
    // a proof rather than a claim — an interrupt raised with no controller
    // configured is exactly the spurious case the dispatch has to survive, and
    // a boot that stays up past `sti` has handled that case.
    // The machine is asked, not named: `install_interrupt_table` answers
    // whether this one has a table to install, and a machine whose entry
    // assembly is not written says `false` rather than making this function ask
    // which machine it is running on.
    #[cfg(target_os = "none")]
    {
        // The descriptor table and the task state segment, before the interrupt
        // table.  On a machine that needs a TSS, the `RSP0` it names is the
        // stack every interrupt from ring 3 lands on, and a table installed
        // without one would take its first ring-3 interrupt as a triple fault.
        //
        // A machine with no such table answers `false`, and that is not a
        // failure: aarch64's vector table needs no descriptor and its answer
        // says so.
        //
        // SAFETY: called once, with the console up and before any program can
        // run.  The stack it names as `RSP0` is the kernel's, which is live.
        let descriptors = unsafe { arch::install_descriptor_tables(kernel_interrupt_stack_top()) };
        if descriptors {
            arch::serial::write_str("protofire: descriptor tables installed, TSS loaded\n");
        }

        // SAFETY: called once, with the console up.  The sink answers "not
        // handled" for everything, so a vector that arrives stops the machine
        // with its number on the console rather than jumping into nothing.
        unsafe { arch::set_interrupt_dispatch(interrupts::handle) };
        // SAFETY: called once, after the sink exists and before any vector can
        // be raised.
        let installed = unsafe { arch::install_interrupt_table() };
        arch::serial::write_str("protofire: interrupt table ");
        if installed {
            arch::serial::write_str("installed");
        } else {
            arch::serial::write_str("not installed (this machine has no entry yet)");
        }

        // And enabled, if there is a table behind the flag.
        //
        // The 8259 is masked first, and that is not tidiness.  Its reset vector
        // bases are 8 and 0x70; vector 8 is the double fault.  A machine whose
        // timer still reaches the 8259 takes its first tick as a double fault
        // through a gate this kernel wrote for a fault it will never raise —
        // which is exactly what happened the first time this line existed.
        // q35 has an IOAPIC, so the legacy controller is masked rather than
        // remapped: two controllers able to raise one line is a worse state
        // than one controller silent.  A machine whose
        // controllers are not programmed raises nothing, so a boot that stays
        // up past this line has run the path that matters: a vector with no
        // handler is answered rather than jumping into nothing.
        //
        // SAFETY: the table is installed and the sink is set, so a vector that
        // arrives is one the dispatch can answer.
        if installed {
            // The legacy controller is silenced before the flag, not after and
            // not as part of building the table: its pending lines are latched
            // until the mask is written, so the order is mask then enable.  The
            // machine owns both halves — `enable` would be a flag over a
            // controller that raises vector 8.
            arch::interrupts::silence_legacy_controller();
            arch::interrupts::enable();
            arch::serial::write_str(", interrupts on\n");

            // Then prove the path, rather than reporting it.
            //
            // "Interrupts on" is a flag; a flag is not an interrupt.  The
            // recurring defect in this tree is code that is written, wired and
            // never executed, and the only thing that separates "the table is
            // installed" from "an interrupt arrives through it" is an
            // interrupt arriving through it.
            //
            // A device raises its line when it has something to say and cannot
            // be asked to say it on demand — so the controller raises one
            // itself.  `raise` makes the distributor deliver interrupt 40
            // exactly as a device would, and the sink below counts it.
            //
            // A machine whose controller cannot do that reports it and boots
            // on: this is evidence, and a machine without the mechanism is not
            // a machine that must refuse to start.
            raise_test_interrupt();
        } else {
            arch::serial::write_str("\n");
        }
    }

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

    // The device the volume mounts on: a real one if the machine has it, and
    // the image above if it does not.
    //
    // The order is deliberate.  A boot that only knew the disk could not say
    // anything on a machine without one; a boot that only knew the image would
    // never run a driver.  Trying the bus first means the driver path is the
    // one a machine with a disk exercises, and the image is the fallback that
    // keeps a machine without one bootable.
    let (device, source): (alloc::sync::Arc<dyn block::QueuedBlockDevice>, &str) =
        match devices::find_virtio_block() {
            Some(found) => {
                let transport: alloc::sync::Arc<dyn virtio_core::Transport> =
                    found.transport.clone();
                match virtio_block::VirtioBlock::new(transport) {
                    Ok(device) => (device, SOURCE_VIRTIO),
                    Err(_) => {
                        let memory =
                            block::MemoryBlockDevice::new(BOOT_VOLUME_LABEL, image.clone(), false);
                        (memory, "memory (the virtio driver refused the device)")
                    }
                }
            }
            None => {
                let memory = block::MemoryBlockDevice::new(BOOT_VOLUME_LABEL, image.clone(), false);
                (memory, "memory (no virtio-blk on the bus)")
            }
        };

    arch::serial::write_str("protofire: block device from ");
    arch::serial::write_str(source);
    arch::serial::write_str("\n");

    // A write and a read back, before the filesystem touches the device.
    //
    // The mount below would exercise the same path and would fail on an empty
    // disk for a reason that says nothing about the driver.  This is the
    // driver's own check: one sector written, the same sector read back, and
    // the bytes compared.  It runs only when a real device answered — the
    // in-memory fallback has no disk to write.
    if source == SOURCE_VIRTIO {
        let mut probe_sector = [0u8; 512];
        probe_sector[..BOOT_DISK_PROBE.len()].copy_from_slice(BOOT_DISK_PROBE);
        let mut read_back = [0u8; 512];
        let written = device.write_blocks(BOOT_DISK_PROBE_SECTOR, &probe_sector);
        let read = device.read_blocks(BOOT_DISK_PROBE_SECTOR, &mut read_back);
        arch::serial::write_str("protofire: virtio-blk ");
        if written.is_ok() && read.is_ok() && read_back == probe_sector {
            arch::serial::write_str("wrote and read back sector ");
            arch::serial::write_u32(BOOT_DISK_PROBE_SECTOR as u32);
        } else {
            arch::serial::write_str("FAILED the write-and-read-back probe: write=");
            match written {
                Ok(()) => arch::serial::write_str("ok"),
                Err(error) => arch::serial::write_str(error.as_str()),
            }
            arch::serial::write_str(" read=");
            match read {
                Ok(()) => arch::serial::write_str("ok"),
                Err(error) => arch::serial::write_str(error.as_str()),
            }
            arch::serial::write_str(" first=");
            arch::serial::write_hex(read_back[0] as u64);
        }
        arch::serial::write_str("\n");
    }

    // A disk that is not a PyroFS volume gets one written to it.
    //
    // The image the boot built is the volume this machine's boot wants, and a
    // real disk is where it should live.  QEMU's disk starts empty, so the
    // first boot writes the image and every later step reads it back through
    // the driver — which is what makes the mount below a read from a device
    // rather than from a `Vec`.
    //
    // The check is the mount itself: a volume that opens is one to use, and one
    // that does not is a disk to format.  Trying to open first is what keeps a
    // second boot from overwriting what the first wrote.
    let needs_format = fs::pyrofs::PyroFs::open(device.clone(), true).is_err();
    if needs_format {
        if source != SOURCE_VIRTIO {
            // The in-memory device already holds exactly this image; rebuilding
            // it would be the same bytes twice.
        } else {
            arch::serial::write_str("protofire: formatting the disk with the boot image\n");
            if device.write_blocks(0, &image).is_err() {
                arch::serial::write_str("protofire: writing the image to the disk FAILED\n");
                halt()
            }
        }
    }

    let volume = match fs::pyrofs::PyroFs::open(device, true) {
        Ok(volume) => fs::pyrofs::PyroFsVolume::new(volume),
        Err(error) => {
            arch::serial::write_str("protofire: filesystem mount FAILED: ");
            arch::serial::write_str(error.as_str());
            arch::serial::write_str("\n");
            halt()
        }
    };

    // The namespace: two filesystems, mounted by prefix.
    //
    // The boot's volume owns `/` — it is where `/greeting.txt` lives, and it is
    // what the disk was formatted with.  A tmpfs owns `/tmp`, which is a second
    // filesystem answering for a prefix of the same namespace and the reason
    // the mount table exists: a path is answered by the volume whose prefix is
    // longest, so `/tmp/x` belongs to the tmpfs while everything else belongs
    // to PyroFS.
    //
    // Nothing reads `/tmp` on this boot.  It is mounted anyway, because a
    // mount table with one entry has never resolved anything, and the line
    // below is where the two volumes are named.
    let mut namespace = fs::MountTable::new();
    namespace
        .mount(
            "/",
            "pyrofs",
            BOOT_VOLUME_LABEL,
            alloc::sync::Arc::new(volume),
        )
        .unwrap_or_else(|_| halt());
    let scratch = fs::TmpFsVolume::new("tmpfs", TMPFS_BYTES);
    namespace
        .mount("/tmp", "tmpfs", "memory", alloc::sync::Arc::new(scratch))
        .unwrap_or_else(|_| halt());

    // A third filesystem, on a disc the boot builds.
    //
    // ISO 9660 is read-only, which is why it is the one that proves the
    // namespace rather than the two before it: it cannot be written, so what
    // it holds is what the image was built with, and a read that returns those
    // bytes came from the disc.
    //
    // The image is built here for the same reason the PyroFS one is: an image
    // in the tree would be one nobody rebuilt, and a format change would find
    // the stale copy before it found the code.
    let disc = iso_disc::build();
    let disc_device: alloc::sync::Arc<dyn block::QueuedBlockDevice> =
        block::MemoryBlockDevice::new(ISO_LABEL, disc, true);
    match fs::iso9660::Iso9660Volume::open(disc_device) {
        Ok(volume) => {
            namespace
                .mount("/cdrom", "iso9660", ISO_LABEL, volume)
                .unwrap_or_else(|_| halt());
        }
        Err(_) => {
            arch::serial::write_str("protofire: iso9660 disc FAILED to mount\n");
            halt()
        }
    }

    arch::serial::write_str("protofire: namespace: ");
    arch::serial::write_str(&fs::mount::describe(&namespace));
    arch::serial::write_str("\n");

    // A file read off the disc, through the namespace rather than from the
    // volume directly.
    //
    // The tmpfs on `/tmp` is empty and the boot's own volume is written by the
    // boot; the disc is the one filesystem whose contents came from an image
    // and cannot have been changed since.  A read that returns those bytes
    // came from the disc, through the mount table, and no other explanation
    // fits — which is what a boot line is for.
    arch::serial::write_str("protofire: /cdrom/README.TXT ");
    match namespace.lookup("/cdrom/README.TXT") {
        Ok(node) => {
            let mut buffer = [0u8; 64];
            match node.read(0, &mut buffer) {
                Ok(count)
                    if count == iso_disc::DISC_CONTENT.len()
                        && buffer[..count] == *iso_disc::DISC_CONTENT =>
                {
                    arch::serial::write_str("reads back from the disc\n")
                }
                Ok(count) => {
                    arch::serial::write_str("read ");
                    arch::serial::write_u32(count as u32);
                    arch::serial::write_str(" bytes that are not the disc's\n")
                }
                Err(error) => {
                    arch::serial::write_str("FAILED to read: ");
                    arch::serial::write_str(error.as_str());
                    arch::serial::write_str("\n")
                }
            }
        }
        Err(_) => arch::serial::write_str("FAILED to find\n"),
    }

    // The read happens through a syscall, not through the filesystem.
    //
    // The registry is handed the namespace and is then the only thing that can
    // reach it: every later step names a descriptor and a number, and the only
    // code that reaches a `VNode` is the handler `open` leads to.  That is what
    // makes this a boot of the syscall path rather than a boot that happens to
    // have one compiled in.
    let mut table = crate::syscall::SyscallTable::new();
    table.set_namespace(alloc::sync::Arc::new(namespace));
    table.register(::syscall::SyscallNumber::Open, crate::syscall::open);
    table.register(::syscall::SyscallNumber::Read, crate::syscall::read);
    table.register(::syscall::SyscallNumber::Close, crate::syscall::close);
    table.register(
        ::syscall::SyscallNumber::MacGetStatus,
        crate::syscall::mac_get_status,
    );
    table.register(
        ::syscall::SyscallNumber::MacSetMode,
        crate::syscall::mac_set_mode,
    );
    table.register(
        ::syscall::SyscallNumber::MacAddRule,
        crate::syscall::mac_add_rule,
    );
    let served = table.served();

    // The registry outlives this function.
    //
    // Until now the table was a local: built here, used three times, dropped.
    // That proves the handlers work and is not a syscall interface — a table
    // that exists only inside one call is a table nothing else can reach, and
    // the first thing that would have discovered it is the first trap that
    // tried to serve a call.
    //
    // SAFETY: called once, after the namespace is set and every handler is
    // registered, before anything can serve a call.
    unsafe { crate::syscall::install(table) };

    arch::serial::write_str("protofire: syscall table installed, ");
    arch::serial::write_u32(served as u32);
    arch::serial::write_str(" number(s) served\n");

    // The policy, and both of its answers.
    //
    // Everything below is why this is not a claim about a crate that compiles.
    // The MAC engine was complete and consulted by nothing: `open` had no
    // identity to check and no check to run.  These two calls make it decide
    // twice — once for a subject it allows and once for one it denies — and the
    // second is the one that would go green if the wiring were missing.
    exercise_mac_policy();

    let read_ok = read_greeting_through_syscall();

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

    // The timer, and the preemption it makes possible.
    //
    // A scheduler that switches only when a program calls is a scheduler that
    // cannot stop a program that does not.  The timer is what makes the other
    // kind possible, and the boot proves it by arming one and reporting whether
    // an interrupt arrived — the same shape as the software-interrupt check
    // above, for the same reason: a mechanism nobody saw fire is a mechanism
    // nobody knows works.
    #[cfg(target_os = "none")]
    start_timer();

    // A program, at EL0, calling back.
    //
    // Everything above runs at EL1 and talks to the kernel directly.  This is
    // the first thing in the tree that does not: it is mapped `user`, entered
    // through an `eret` that names EL0, and its only way back is a supervisor
    // call.  Reaching the line below means the whole path ran.
    run_programs();

    halt()
}

/// Build two programs, map them, and let the scheduler run them.
///
/// ## Why two, and why they call `Write` before exiting
///
/// One program proves the entry path; it cannot prove a switch, because a
/// switch needs something to switch to.  Two programs that each print their own
/// number and then exit, with a switch on every `Write`, exercise: a second
/// address space, `TTBR0_EL1` written between two running programs, two
/// contexts saved and restored, and two exits reaped.
///
/// A log that shows `program 1` and `program 2` interleaved is the evidence;
/// one program twice looks the same as one program once, which is why the
/// number is the program's own value and not the kernel's counter.
#[cfg(target_os = "none")]
fn run_programs() {
    use crate::address_space::AddressSpace;
    use crate::process;
    use crate::scheduler::Scheduler;
    use crate::scheduler::Task;

    // SAFETY: both sinks are installed once, before EL0 is entered.
    unsafe {
        arch::set_call_sink(process::serve);
        arch::set_preempt_sink(crate::scheduler::preempt);
    }

    // The pipe table, before any program can make one.
    //
    // SAFETY: called once, before EL0 is entered.
    unsafe { crate::pipe::install() };

    // The pipe the reader waits on, made before either program runs.
    //
    // The writer is program 2 and the reader is program 3, so the ordering is
    // the point: the reader reaches its `Read` first — its loop is shorter and
    // it makes no earlier call — and the pipe is empty, so it blocks.  Program
    // 2's write is what ends that wait, and nothing else can.
    let pipe = alloc::sync::Arc::new(crate::pipe::Pipe::new(ipc::DEFAULT_PIPE_CAPACITY));
    let reader_end = match crate::pipe::attach(crate::pipe::End::reader(pipe.clone())) {
        Some(end) => end,
        None => {
            arch::serial::write_str("protofire: no room for a pipe end\n");
            return;
        }
    };
    let writer_end = match crate::pipe::attach(crate::pipe::End::writer(pipe)) {
        Some(end) => end,
        None => {
            arch::serial::write_str("protofire: no room for a pipe end\n");
            return;
        }
    };

    let mut scheduler = Scheduler::new();
    for number in [1u16, 2, 3] {
        let mut handed_stack_top: Option<usize> = None;
        let Some(mut space) = (unsafe { AddressSpace::new() }) else {
            arch::serial::write_str("protofire: no root table for a program\n");
            return;
        };
        let Some(image) = crate::address_space::allocate_image_frame() else {
            arch::serial::write_str("protofire: no frame for a program image\n");
            return;
        };
        let Some(stack) = crate::address_space::allocate_image_frame() else {
            arch::serial::write_str("protofire: no frame for a program stack\n");
            return;
        };
        space.own(image);
        space.own(stack);

        let bytes = process::program_bytes(number);
        // SAFETY: `image` is a live frame the allocator handed out and zeroed,
        // and the program is smaller than one page; this boot is identity
        // mapped, so the frame's physical address is one the kernel can write.
        unsafe {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), image as *mut u8, bytes.len());
        }

        // The pipe's end, on the stack where the program's first instruction
        // looks for it.
        //
        // A program receives a value from the boot through the one place both
        // sides agree on, and this boot writes it before the program runs: the
        // reader reads `[rsp]` for its descriptor, and the writer finds its own
        // at `[rsp]` too.  The byte above it is the writer's payload.
        let handed = match number {
            n if n == process::PIPE_READER => Some(reader_end),
            n if n == process::PIPE_WRITER => Some(writer_end),
            _ => None,
        };
        if let Some(descriptor) = handed {
            // The stack's top is a boundary, not storage: a program's `rsp`
            // points at it and `[rsp]` is the first four bytes *above* it.  So
            // the words go below the boundary and the stack pointer moves down
            // to them — which is what a `push` would have done, done early.
            // The **physical** frame, not its virtual address.
            //
            // A program's pages are mapped in its own address space, and the
            // boot is running through the kernel's — so `0x8080000fe0` is an
            // address this walk does not reach, and the first version faulted
            // writing it.  The frame is identity-mapped here, so the kernel
            // writes the bytes where they will be and the program reads them
            // through its own mapping of the same page.
            let base = (stack + paging::PAGE_SIZE - 32) as *mut u64;
            // SAFETY: `stack` is the frame this space owns for its stack, the
            // program has not run, and the four words are inside it.
            unsafe {
                base.write(descriptor as u64);
                base.add(1).write(0x64_63_62_61); // "abcd", little-endian
            }
            // The stack pointer the task starts with points at those words, in
            // the program's own address space.
            handed_stack_top = Some(process::program_stack_top(number) - 32);
        }

        let base = process::program_base(number);
        let stack_page = process::program_stack_page(number);
        // SAFETY: both frames belong to this space, and the two virtual
        // addresses are this program's own window.
        let mapped = unsafe { space.map(base, image, false) && space.map(stack_page, stack, true) };
        if !mapped {
            arch::serial::write_str("protofire: a program could not be mapped\n");
            return;
        }

        arch::serial::write_str("protofire: program ");
        arch::serial::write_u32(number as u32);
        arch::serial::write_str(" mapped at ");
        arch::serial::write_hex(base as u64);
        arch::serial::write_str("\n");

        let stack_top = handed_stack_top
            .take()
            .unwrap_or_else(|| process::program_stack_top(number));
        scheduler.add(Task::new(
            match number {
                n if n == process::PIPE_READER => "reader",
                n if n == process::PIPE_WRITER => "writer",
                _ => "one",
            },
            base,
            stack_top,
            space,
        ));
    }

    // Install it, then enter the first program in it.
    //
    // `enter_user` does not return: the first program's trap brings us back
    // into the kernel and the scheduler takes it from there.  So the entry is
    // the first task's context installed by hand rather than through a switch.
    let first = scheduler.current().map(|task| *task.context());
    // SAFETY: called once, before any program runs.
    unsafe { crate::scheduler::install(scheduler) };

    let Some(context) = first else {
        arch::serial::write_str("protofire: no program to run\n");
        return;
    };

    // Now, and not before: everything that runs at EL1 is done.
    //
    // SAFETY: the timer's line is enabled, so a fire is a delivered interrupt,
    // and the sink and the scheduler are both installed.
    if let Some(frequency) = unsafe { arch::timer_frequency() } {
        // SAFETY: the line is enabled, the sink is installed and the scheduler
        // is installed, so a tick is a delivered interrupt that can switch.
        unsafe { arch::arm_timer(frequency, TIME_SLICE_US) };
    } else {
        arch::serial::write_str("protofire: no timer to arm for the programs\n");
    }

    arch::serial::write_str("protofire: entering ring 3\n");
    // SAFETY: the entry is mapped `user` in the installed space — the first
    // task's root is not yet installed, so this switches to it as it enters.
    unsafe {
        arch::switch_address_space(crate::scheduler_first_root());
        arch::enter_user_with_context(&context)
    }
}

/// The root the first task runs through, for the entry into EL0.
///
/// A separate function because `install` moved the scheduler: the root has to
/// be read back out of the static rather than from the value the boot still
/// holds.
#[cfg(target_os = "none")]
fn scheduler_first_root() -> usize {
    crate::scheduler::first_root().unwrap_or(0)
}

/// The host build has no ring 3 to enter.
#[cfg(not(target_os = "none"))]
fn run_programs() {}

/// Enable the MAC policy, install one rule, and make `open` decide both ways.
///
/// ## Why this goes through `open` and not through `check_file`
///
/// The first version of this called `check_file` directly.  Deleting the check
/// from the `open` handler changed no output at all: the probe was testing the
/// policy, which was already known to work, and not the **wiring**, which is
/// the only thing in question.
///
/// So both cases here are `open` calls through the installed registry, with the
/// one field that differs being the caller's identity.  Deleting the check
/// makes the untrusted open succeed, the boot prints `MISPOLICED`, and the gate
/// goes red — which is the property the line is for.
///
/// The rule is installed for `MAC_TYPE_UNLABELED`, which is what
/// `object_type_for_path` answers for a path under no labelled prefix on this
/// boot's volume.  That is not a guess: `security/src/mac/check.rs` falls back
/// to unlabelled for anything outside `/system`, `/apps`, `/data`, `/dev` and
/// `/tmp`.
fn exercise_mac_policy() {
    use security::mac;

    // One rule: the system label may read an unlabelled file.
    {
        let mut state = mac::policy_state().lock();
        state.policy.add_rule(
            mac::MacRule {
                subject: mac::MAC_TYPE_SYSTEM,
                object: mac::MAC_TYPE_UNLABELED,
                class: mac::MAC_CLASS_FILE,
                perms: mac::MAC_PERM_READ,
            },
            true,
        );
        state.policy.enabled = true;
    }

    let (rules, labels) = {
        let state = mac::policy_state().lock();
        (state.policy.rule_count(), state.label_count())
    };
    arch::serial::write_str("protofire: mac policy enabled, ");
    arch::serial::write_u32(rules as u32);
    arch::serial::write_str(" rule(s), ");
    arch::serial::write_u32(labels as u32);
    arch::serial::write_str(" label(s)\n");

    // The same open twice, differing only in who is asking.
    for (identity, expected, name) in [
        (mac::MAC_TYPE_SYSTEM, true, "system"),
        (mac::MAC_TYPE_UNTRUSTED, false, "untrusted"),
    ] {
        let outcome = open_as(identity);
        arch::serial::write_str("protofire: mac ");
        arch::serial::write_str(match outcome {
            true if expected => "allowed ",
            false if !expected => "denied ",
            _ => "MISPOLICED ",
        });
        arch::serial::write_str(name);
        arch::serial::write_str(" read of ");
        arch::serial::write_str(BOOT_GREETING_PATH);
        arch::serial::write_str("\n");
    }
}

/// Open the boot's file as `identity`, answering whether it was allowed.
///
/// Through the installed registry and the real handler, so the answer covers
/// the policy **and** the decision to consult it.  The descriptor is closed
/// again, because a probe that leaked one would make the boot's own read fail
/// for a reason that is this function's.
fn open_as(identity: u32) -> bool {
    use crate::syscall::Arguments;
    use ::syscall::SyscallContext;

    let mut context = SyscallContext::new(
        ::syscall::SyscallNumber::Open as usize,
        [0, abi::fs::OPEN_FLAG_READ, 0, 0, 0, 0],
    )
    .with_identity(identity);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some(BOOT_GREETING_PATH),
        buffer: None,
    };

    match crate::syscall::serve(&mut arguments) {
        Some(Ok(dispatch)) => {
            let mut context = SyscallContext::new(
                ::syscall::SyscallNumber::Close as usize,
                [dispatch.value, 0, 0, 0, 0, 0],
            );
            let mut arguments = Arguments::plain(&mut context);
            let _ = crate::syscall::serve(&mut arguments);
            true
        }
        _ => false,
    }
}

/// The path the boot reads, and the one the policy is asked about.
const BOOT_GREETING_PATH: &str = "/greeting.txt";

/// The timer's interrupt, as the machine reports it.
///
/// Asked of the machine and not written here: 30 is aarch64's private timer
/// interrupt and `0x20` is x86_64's local APIC vector, and a constant in this
/// file would be one machine's answer installed on the other.  The two are one
/// number apart in nobody's arithmetic, which is why the machine says it.
#[cfg(target_os = "none")]
fn timer_interrupt() -> usize {
    arch::timer_interrupt()
}

/// The stack an interrupt from a program lands on.
///
/// Asked of the machine rather than chosen here: on x86_64 it is the boot's own
/// stack, published as a symbol, and on a machine with no TSS the answer is
/// unused.  A constant in this file would be a second stack whose address the
/// kernel guessed.
#[cfg(target_os = "none")]
fn kernel_interrupt_stack_top() -> usize {
    arch::interrupt_stack_top()
}

/// How long a time slice is, in microseconds.
///
/// A twenty-microsecond slice at about a gigahertz is twenty thousand ticks,
/// which is long enough that a program gets work done between ticks and short
/// enough that two programs interleave visibly in a log even under an emulator
/// whose trap cost dwarfs the work.  The first value, a hundred, produced a
/// boot whose programs finished inside a single slice; the number is set by
/// that measurement and not by a scheduler weighing anything, because this
/// kernel has no load to weigh.
#[cfg(target_os = "none")]
pub const TIME_SLICE_US: u64 = 100;

/// How many times the timer has fired.
pub static TIMER_TICKS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Enable the timer's line, arm it, and say what the machine reported.
#[cfg(target_os = "none")]
fn start_timer() {
    // SAFETY: the controller is enabled and the vector table is installed by
    // the time this runs; the line is the architecture's private timer
    // interrupt.
    let line = timer_interrupt();
    if !unsafe { arch::enable_interrupt_line(line) } {
        arch::serial::write_str("protofire: timer line not enabled\n");
        return;
    }

    // SAFETY: as above, and the line being enabled is what makes a fire a
    // delivered interrupt rather than a silent status bit.
    let Some(frequency) = (unsafe { arch::timer_frequency() }) else {
        arch::serial::write_str("protofire: timer has no frequency, not armed\n");
        return;
    };

    // The line is enabled here; the timer is armed by the code that enters EL0.
    //
    // Arming now would fire during the rest of the boot — which runs at EL1,
    // takes a full trap per tick, and cannot be preempted — and the boot would
    // spend its time in trap entry rather than in starting.  The first version
    // armed here and the log stopped in the middle of a line.
    TIMER_TICKS.store(0, core::sync::atomic::Ordering::Release);

    // SAFETY: read-only; reports what the controller kept.
    let kept = unsafe { arch::interrupt_line_enabled(line) };
    arch::serial::write_str("protofire: timer line enabled = ");
    arch::serial::write_u32(usize::from(kept) as u32);
    arch::serial::write_str("\n");

    // The counter, read while the timer is armed and running.
    //
    // This has to happen here and not before: a counter that is not running
    // reads the same value twice, so a probe that armed nothing would report
    // `0 ticks apart` on a machine whose timer works.  The first version read
    // the counter after the calibration had already disarmed it, and printed
    // exactly that.
    //
    // Arming a slice here and disarming it immediately leaves no interrupt to
    // take: the count is far larger than the spin below, so nothing fires
    // during it.
    //
    // SAFETY: the APIC is enabled and recorded by `timer_frequency`.
    unsafe { arch::arm_timer(frequency, TIME_SLICE_US * 1000) };
    // SAFETY: read-only.
    let first = unsafe { arch::timer_counter() };
    let mut spin = 0u64;
    while spin < 100_000 {
        spin += 1;
    }
    // SAFETY: read-only.
    let second = unsafe { arch::timer_counter() };
    arch::serial::write_str("protofire: timer counter ");
    // `second - first`, not the other way: this machine's counter counts up.
    // The subtraction was written for the APIC's countdown and kept its
    // direction when the clock changed, which made the line print zero on a
    // counter that was running.
    arch::serial::write_u32(second.saturating_sub(first) as u32);
    arch::serial::write_str(" ticks apart\n");

    arch::serial::write_str("protofire: timer control ");
    arch::serial::write_u32(unsafe { arch::timer_control() } as u32);
    arch::serial::write_str("\n");

    // Disarmed again: the code that enters a program arms it, so the boot does
    // not spend its remaining work taking traps at ring 0.
    //
    // SAFETY: as above; this is the end of the boot's own use of the timer.
    unsafe { arch::disarm_timer() };

    arch::serial::write_str("protofire: timer armed at ");
    arch::serial::write_u32((frequency / 1000) as u32);
    arch::serial::write_str(" ticks/ms\n");

    // There is no second self-check here.
    //
    // One was written — the timer's own vector, sent to this CPU — and it was
    // the wrong instrument twice over: on aarch64 the controller cannot raise a
    // timer's private interrupt on demand, so it printed "not raised" on every
    // boot; and on x86_64 it proved the same thing `raise_test_interrupt`
    // already proves, because an APIC self-interrupt takes the identical path
    // through the gate and the stub.  What the timer needs proved is that its
    // *countdown* runs, which the counter line above does, and that a tick
    // preempts, which the last line of the boot does.
}

/// The label the boot's volume carries.
const BOOT_VOLUME_LABEL: &str = "protofire";

/// Where the block device came from, when it came from the bus.
///
/// A constant rather than a string compare against a literal in two places:
/// the boot line and the probe's condition are one fact.
const SOURCE_VIRTIO: &str = "virtio-blk on pci";

/// The label the boot's ISO 9660 disc carries.
const ISO_LABEL: &str = "bootdisc";

/// The tmpfs mounted at `/tmp`, sized to what a boot's scratch space is worth.
///
/// A megabyte, and a bound rather than a promise: the volume refuses a write
/// past it, which is what stops a scratch filesystem from being a heap leak
/// with a path.
const TMPFS_BYTES: usize = 1024 * 1024;

/// The sector the driver's probe writes and reads back.
///
/// A sector no filesystem structure uses — the mount below reads sector 0 for
/// the superblock — so the probe cannot corrupt what it is about to mount.
const BOOT_DISK_PROBE_SECTOR: u64 = 63;

/// The bytes the probe writes.
///
/// A string no other file in the tree contains, for the same reason the volume
/// content is: a comparison against a constant that the device never received
/// would pass on a device that was never written.
const BOOT_DISK_PROBE: &[u8] = b"protofire writes this sector";

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
fn read_greeting_through_syscall() -> bool {
    use crate::syscall::Arguments;
    use ::syscall::SyscallContext;

    // open(path, flags)
    //
    // The identity is the boot's own: the kernel reads its volume as the system
    // label, which is the subject the installed policy allows.  A caller with
    // no identity is unlabelled, and the same policy denies it — which is what
    // the boot's deny case demonstrates rather than asserts.
    let mut context = SyscallContext::new(
        ::syscall::SyscallNumber::Open as usize,
        [0, abi::fs::OPEN_FLAG_READ, 0, 0, 0, 0],
    )
    .with_identity(security::mac::MAC_TYPE_SYSTEM);
    let mut arguments = Arguments {
        context: &mut context,
        path: Some(BOOT_VOLUME_PATH),
        buffer: None,
    };
    // Through the installed registry, not a table this function was handed.
    // The boot's own read is the first call served by the static the boot
    // installed, which is what makes "the registry outlives the boot" a claim
    // with a call behind it.
    let Some(Ok(dispatch)) = crate::syscall::serve(&mut arguments) else {
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
    let read_ok = match crate::syscall::serve(&mut arguments) {
        Some(Ok(dispatch)) => {
            dispatch.value == BOOT_VOLUME_CONTENT.len() && buffer == *BOOT_VOLUME_CONTENT
        }
        _ => false,
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
    let close_ok = matches!(crate::syscall::serve(&mut arguments), Some(Ok(_)));

    read_ok && close_ok && crate::syscall::open_descriptors() == 0
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

/// Wait here until a sleeping program's deadline passes.
///
/// ## What this replaces
///
/// A `halt` loop.  When every program is asleep the scheduler has nothing to
/// resume, and the trap path's `eret` would return to a program that is not
/// runnable.  The choices are to stop the machine or to wait for the tick that
/// wakes one; stopping is the boot ending with work left.
///
/// ## How the wake happens
///
/// The timer keeps firing, and its handler calls `scheduler::wake_expired` —
/// which is what turns a deadline into a runnable task.  The loop below takes
/// the interrupt, the handler wakes a task, and `wait_for_a_wakeup` returns
/// once one is runnable.  The scheduler is then asked for a context and the
/// trap path resumes it.
///
/// ## Why this is safe with the frame
///
/// `idle` runs *after* the handler returned `Exit`, so the frame this function
/// never touches was already saved by `advance`.  The loop does not return a
/// context: it returns to `serve`, which returns `Exit`, which lets the trap
/// path restore whatever the last preemption installed — and the preemption
/// inside the tick is what installs the woken task.
///
/// A boot with no timer would spin here forever.  That is the honest state: a
/// machine that cannot count cannot wake a sleeper, and the line the boot
/// printed said so.
pub fn idle_until_woken() {
    // ## Why the machine does the waiting
    //
    // The three things this loop needs are all the machine's, and each differs
    // between the two that have a ring 3.  A supervisor call arrives through an
    // **interrupt gate**, which clears the interrupt flag on entry — so the
    // kernel runs with interrupts masked for the whole of a served call, and a
    // wait that did not unmask them waits for a tick that can never be
    // delivered.  x86_64's `sti` is that unmask and aarch64 has no such flag to
    // clear.  The instruction that stops the core is `hlt` on one and `wfi` on
    // the other.
    //
    // So `arch::wait_for_a_wakeup` is the whole of the machine half: it unmasks
    // where there is something to unmask and stops the core until an interrupt
    // arrives.  The boot hung once with `every program is asleep, waiting` and
    // no tick, because this file had tried to spell `sti` itself.
    // No spin bound.
    //
    // One was here, at a million waits, on the argument that a machine whose
    // timer does not tick should say so rather than hang.  It fired on a
    // healthy aarch64 boot: a `wfi` returns on every tick whether or not that
    // tick ended the wait, so the counter measured the boot's speed and not a
    // fault.  What ends the loop is `wake_expired` turning a deadline into a
    // runnable task, and a machine that never does that is a machine that hangs
    // — with a log that already said "every program is asleep, waiting".
    while crate::scheduler::has_sleeping() && !crate::scheduler::has_selectable() {
        arch::wait_for_a_wakeup();
    }
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
