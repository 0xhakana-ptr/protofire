//! kernel/src/volume.rs
//!
//! The boot's storage: the image it builds, the device it mounts on, the
//! namespace it assembles, and the one read that proves the whole path.
//!
//! ## Why the image is built rather than shipped
//!
//! A volume in the tree would be one nobody rebuilt, and a format change would
//! find the stale copy before it found the code.  So the boot builds its PyroFS
//! image, writes it to a real disk when the machine has one, mounts it through
//! the driver, and reads a file back, which is what turns "the crates compile"
//! into "the filesystem works on a machine".
//!
//! ## Why three filesystems
//!
//! A mount table with one entry has never resolved anything.  The boot's volume
//! owns `/`, a tmpfs owns `/tmp` so the table answers by longest prefix, and an
//! ISO 9660 disc owns `/cdrom`, read-only, and therefore the one whose
//! contents cannot have been changed since the image was built.

use crate::halt;

/// The label the boot's volume carries.
pub const BOOT_VOLUME_LABEL: &str = "protofire";

/// The label the boot's ISO 9660 disc carries.
const ISO_LABEL: &str = "bootdisc";

/// Where the block device came from, when it came from the bus.
///
/// A constant rather than a string compare against a literal in two places:
/// the boot line and the probe's condition are one fact.
const SOURCE_VIRTIO: &str = "virtio-blk on pci";

/// The tmpfs mounted at `/tmp`, sized to what a boot's scratch space is worth.
///
/// A megabyte, and a bound rather than a promise: the volume refuses a write
/// past it, which is what stops a scratch filesystem from being a heap leak
/// with a path.
const TMPFS_BYTES: usize = 1024 * 1024;

/// The sector the driver's probe writes and reads back.
///
/// The disk's **far end** — the boot's volume is built at block 0 and a
/// loaded image plus the filesystem's own tables reach only a few hundred
/// blocks — so the probe writes on bytes no filesystem structure uses, at a
/// distance no growth of the volume reaches.  It used to sit at block 63,
/// "past the superblock" being the whole of the argument, and a volume that
/// grew a real program into it would have taken the probe's bytes as its
/// own.
const BOOT_DISK_PROBE_SECTOR: u64 = 2040;

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

/// The path the boot opens and reads, and the one `exec` hands the image it
/// starts.
pub(crate) const BOOT_VOLUME_PATH: &str = "/greeting.txt";

/// Build the boot's volume, attach it to a device, and assemble the namespace.
///
/// Answers the namespace, which is what the syscall registry is handed.
pub fn mount_everything() -> fs::MountTable {
    // The image the boot builds, rather than one shipped in the tree.
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

    let (device, source) = attach_device(image.clone());
    arch::serial::write_str("protofire: block device from ");
    arch::serial::write_str(source);
    arch::serial::write_str("\n");

    if source == SOURCE_VIRTIO {
        probe_device(&device);
    }

    format_if_empty(&device, &image, source);
    let volume = open_volume(device);

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
    mount_disc(&mut namespace);

    arch::serial::write_str("protofire: namespace: ");
    arch::serial::write_str(&fs::mount::describe(&namespace));
    arch::serial::write_str("\n");

    read_the_disc(&namespace);
    namespace
}

/// Pick the device the volume mounts on, and say where it came from.
///
/// The order is deliberate.  A boot that only knew the disk could not say
/// anything on a machine without one; a boot that only knew the image would
/// never run a driver.  Trying the bus first means the driver path is the one a
/// machine with a disk exercises, and the image is the fallback that keeps a
/// machine without one bootable.
fn attach_device(
    image: alloc::vec::Vec<u8>,
) -> (alloc::sync::Arc<dyn block::QueuedBlockDevice>, &'static str) {
    match crate::devices::find_virtio_block() {
        Some(found) => {
            let transport: alloc::sync::Arc<dyn virtio_core::Transport> = found.transport.clone();
            let device = match virtio_block::VirtioBlock::new(transport) {
                Ok(device) => device,
                Err(_) => {
                    let memory = block::MemoryBlockDevice::new(BOOT_VOLUME_LABEL, image, false);
                    return (memory, "memory (the virtio driver refused the device)");
                }
            };
            // **After** the driver, and that order is the whole of it: the
            // driver's first step is a device reset, and a reset is the device
            // forgetting every queue's interrupt state.  Wired before it, the
            // table entry and the queue vector are both discarded and the
            // device's completions are dropped at the transport with nothing
            // printed anywhere — measured, 0 of 4 boots, against 8 of 8 with
            // the wiring here.
            //
            // The result is not checked because there is nothing a boot could
            // do differently: a machine whose tree names no IMSIC answers
            // `false`, and the driver polls either way.  The line the wiring
            // prints is the evidence for a reader.
            let _ = crate::devices::wire_block_message_interrupt(&found);
            (device, SOURCE_VIRTIO)
        }
        None => {
            let memory = block::MemoryBlockDevice::new(BOOT_VOLUME_LABEL, image, false);
            (memory, "memory (no virtio-blk on the bus)")
        }
    }
}

/// Write one sector and read it back, before the filesystem touches the device.
///
/// The mount below would exercise the same path and would fail on an empty disk
/// for a reason that says nothing about the driver.  This is the driver's own
/// check, and it runs only when a real device answered, the in-memory fallback
/// has no disk to write.
fn probe_device(device: &alloc::sync::Arc<dyn block::QueuedBlockDevice>) {
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

    // The count of the device's own completion interrupts is reported at the
    // boot's end, beside the other machine facts, and not here: on a machine
    // whose hart line comes up after this probe, the device's message is held
    // pending until that line is on, so a count read here would describe the
    // ordering of the boot rather than the mechanism.  See
    // `programs::report_and_finish`, where the total is the boot's.
}

/// Write the image to a disk that is not a PyroFS volume.
///
/// QEMU's disk starts empty, so the first boot writes the image and every later
/// step reads it back through the driver, which is what makes the mount a read
/// from a device rather than from a `Vec`.  The check is the mount itself: a
/// volume that opens is one to use, and one that does not is a disk to format.
/// Trying to open first is what keeps a second boot from overwriting what the
/// first wrote.
fn format_if_empty(
    device: &alloc::sync::Arc<dyn block::QueuedBlockDevice>,
    image: &[u8],
    source: &str,
) {
    if fs::pyrofs::PyroFs::open(device.clone(), true).is_ok() {
        return;
    }
    if source == SOURCE_VIRTIO {
        arch::serial::write_str("protofire: formatting the disk with the boot image\n");
        if device.write_blocks(0, image).is_err() {
            arch::serial::write_str("protofire: writing the image to the disk FAILED\n");
            halt()
        }
    }
    // An in-memory device already holds exactly this image; rebuilding it would
    // be the same bytes twice.
}

/// Open the volume, or stop with the reason.
fn open_volume(device: alloc::sync::Arc<dyn block::QueuedBlockDevice>) -> fs::pyrofs::PyroFsVolume {
    match fs::pyrofs::PyroFs::open(device, true) {
        Ok(volume) => fs::pyrofs::PyroFsVolume::new(volume),
        Err(error) => {
            arch::serial::write_str("protofire: filesystem mount FAILED: ");
            arch::serial::write_str(error.as_str());
            arch::serial::write_str("\n");
            halt()
        }
    }
}

/// Mount the ISO 9660 disc the boot builds.
///
/// ISO 9660 is read-only, which is why it is the one that proves the namespace
/// rather than the two before it: it cannot be written, so what it holds is
/// what the image was built with, and a read that returns those bytes came from
/// the disc.  The image is built here for the same reason the PyroFS one is.
fn mount_disc(namespace: &mut fs::MountTable) {
    let disc = crate::iso_disc::build();
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
}

/// Read a file off the disc, through the namespace rather than the volume.
///
/// The tmpfs on `/tmp` is empty and the boot's own volume was written by the
/// boot; the disc is the one filesystem whose contents came from an image and
/// cannot have been changed since.  A read that returns those bytes came from
/// the disc, through the mount table, and no other explanation fits.
fn read_the_disc(namespace: &fs::MountTable) {
    arch::serial::write_str("protofire: /cdrom/README.TXT ");
    match namespace.lookup("/cdrom/README.TXT") {
        Ok(node) => {
            let mut buffer = [0u8; 64];
            match node.read(0, &mut buffer) {
                Ok(count)
                    if count == crate::iso_disc::DISC_CONTENT.len()
                        && buffer[..count] == *crate::iso_disc::DISC_CONTENT =>
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
}

/// Read the boot's file through the syscall table.
///
/// Three calls, open, read, close, each built the way a program builds one: a
/// number, six argument words, and a value or an error back.  The result is
/// whether the bytes are the ones the image was built with; a caller that wants
/// the reason a boot failed has the console, which is what the boot prints.
///
/// The buffer is a local rather than a fixed address, and it reaches the
/// handler as a borrow.  That is the whole of this function's contribution to
/// safety: nothing here turns a number into a pointer.
pub fn read_greeting_through_syscall() -> bool {
    use crate::syscall::Arguments;
    use ::syscall::SyscallContext;

    // open(path, flags)
    //
    // The identity is the boot's own: the kernel reads its volume as the system
    // label, which is the subject the installed policy allows.  A caller with
    // no identity is unlabelled, and the same policy denies it, which is what
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
