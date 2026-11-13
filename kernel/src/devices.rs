//! kernel/src/devices.rs
//!
//! Finding the machine's devices, and handing the ones it has to the driver
//! that wants them.
//!
//! A scan is a *policy*: which bus, how many of them, which devices are worth
//! keeping, and what happens when the one you wanted is absent.  The bus crate
//! knows how to walk a bus; only the kernel knows that this boot wants a block
//! device and that a machine without one still has to boot.
//!
//! ## The identity map
//!
//! A driver hands the device physical addresses: the virtqueue's rings, and the
//! buffers a request names.  This boot runs on an identity map, the first
//! gigabyte of physical memory is at the same virtual address, so a `Vec`'s
//! address *is* its physical address and the two need no conversion.
//!
//! That is a property of this boot and not of the driver, which is why
//! [`physical_address`] is a function with its argument: when the kernel gets a
//! real address space, this is the one place that has to learn to translate.

use alloc::sync::Arc;

use pci::ConfigSpace;
use pci::Device;
use pci::EcamConfig;
use pci::PortConfig;
use virtio_core::PciTransport;
use virtio_core::RegisterFile;

/// The class code a storage controller carries.
///
/// The PCI code is three bytes: class, subclass, interface.  `0x01` is mass
/// storage, and virtio's block device reports `0x01 / 0x00 / 0x00`.
const CLASS_STORAGE: u8 = 0x01;

/// Vendors whose storage devices this boot can drive.
///
/// QEMU's `virtio-blk-pci` reports vendor `0x1AF4`, Red Hat's virtio ID, and
/// device `0x1001` for the legacy interface or `0x1042` for the modern one.
/// Only the modern device is usable here, because the transport this tree
/// implements is the modern one.
const VENDOR_REDHAT: u16 = 0x1AF4;
const DEVICE_VIRTIO_BLOCK_MODERN: u16 = 0x1042;
const DEVICE_VIRTIO_BLOCK_TRANSITIONAL: u16 = 0x1001;

/// The class code a network controller carries.
///
/// `0x02` is network and `0x00` is Ethernet, so a virtio network card reports
/// `0x02 / 0x00 / 0x00`.  It is a separate constant from the storage class
/// because a device is found by what it *is*, not by what driver happens to be
/// looking for it: a scan that matched only the vendor and device id would
/// hand a block driver a network card on a machine where the two ids collided.
///
/// A host build has no bus to scan, so the family is only compiled where its
/// only user is: `exercise_network`.
#[cfg(target_os = "none")]
const CLASS_NETWORK: u8 = 0x02;

/// QEMU's `virtio-net-pci`: device `0x1041` for the modern interface,
/// `0x1000` for the transitional one.
#[cfg(target_os = "none")]
const DEVICE_VIRTIO_NET_MODERN: u16 = 0x1041;
#[cfg(target_os = "none")]
const DEVICE_VIRTIO_NET_TRANSITIONAL: u16 = 0x1000;

/// A mapped region of device memory.
///
/// The identity map again: a BAR's address is already the address this code
/// can read, so the file is a pointer and a length.  On a machine whose
/// physical memory is not the virtual one, this is the second place that has to
/// learn to map.
struct MappedBar {
    base: usize,
    length: usize,
}

impl RegisterFile for MappedBar {
    fn read32(&self, offset: u64) -> u32 {
        let offset = offset as usize;
        assert!(offset + 4 <= self.length, "read past the mapped BAR");
        // SAFETY: `offset` is inside the region `map_bar` was asked for, and
        // the region is the device's memory as the machine mapped it.  A
        // volatile read is what MMIO needs: the compiler must not fold two
        // reads of a register the device may have changed between them.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }

    fn write32(&self, offset: u64, value: u32) {
        let offset = offset as usize;
        assert!(offset + 4 <= self.length, "write past the mapped BAR");
        // SAFETY: as `read32`.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) }
    }

    fn read8(&self, offset: u64) -> u8 {
        let offset = offset as usize;
        assert!(offset < self.length, "read past the mapped BAR");
        // SAFETY: as `read32`, one byte wide.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u8) }
    }

    fn write8(&self, offset: u64, value: u8) {
        let offset = offset as usize;
        assert!(offset < self.length, "write past the mapped BAR");
        // SAFETY: as `read32`, one byte wide.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u8, value) }
    }

    fn read16(&self, offset: u64) -> u16 {
        let offset = offset as usize;
        assert!(offset + 2 <= self.length, "read past the mapped BAR");
        // SAFETY: as `read32`, two bytes wide and 16-bit aligned by the
        // specification's layout.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u16) }
    }

    fn write16(&self, offset: u64, value: u16) {
        let offset = offset as usize;
        assert!(offset + 2 <= self.length, "write past the mapped BAR");
        // SAFETY: as `read32`, two bytes wide.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u16, value) }
    }
}

/// How this machine's configuration space is reached.
///
/// Two mechanisms, one trait.  x86_64 has the `0xCF8`/`0xCFC` ports and no
/// memory-mapped window, so [`arch::pcie_ecam_window`] answers `None` and a
/// `PortConfig` is what runs.  A device-tree machine has the window and no port
/// space, so it gets an [`EcamConfig`].  Everything above this function, ///
/// enumeration, capability walks, BAR decoding, is written against
/// `ConfigSpace` and never learns which one it is.
///
/// Before it, aarch64's scan asked a `PortConfig` about a machine with no I/O
/// space: `arch::port`'s aarch64 arm returns all ones, so every bus, device and
/// function answered "nothing here" and the boot printed `pci scan found 0
/// device(s)`.  That was correct and it was not the machine's fault, there was
/// no ECAM, so there was no way to ask.
fn configuration_space() -> Arc<dyn ConfigSpace> {
    if let Some((base, length)) = arch::pcie_ecam_window() {
        arch::serial::write_str("protofire: pcie ecam at ");
        arch::serial::write_hex(base as u64);
        arch::serial::write_str(", window ");
        arch::serial::write_u32((length / 1024) as u32);
        arch::serial::write_str(" KiB");

        // The window must be mapped before the first read of it.  A device-tree
        // machine's ECAM sits wherever the firmware put it, which on `virt` is
        // past the identity map's four gigabytes, so this is not a permission
        // change but the creation of a mapping, and reading before it faults at
        // an address nothing chose.  The first version of this function did
        // exactly that and the boot printed `data abort` at `0x4010000000`.
        //
        // SAFETY: the region is the ECAM window a `pci-host-ecam-generic` node
        // declared, so it is the machine's configuration space and nothing
        // else.
        #[cfg(target_os = "none")]
        let mapped = unsafe { crate::address_space::map_device(base, length) };
        #[cfg(not(target_os = "none"))]
        let mapped = false;

        arch::serial::write_str(if mapped {
            ", mapped"
        } else {
            ", already mapped"
        });
        arch::serial::write_str("\n");
        return Arc::new(EcamConfig::new(base, length));
    }
    Arc::new(PortConfig::new())
}

/// The most functions this boot enumerates.
///
/// A bus has 32 slots of 8 functions; the number that are ever populated is a
/// handful.  64 covers every machine this tree boots and is one array rather
/// than a growable structure, because the enumeration runs before anything has
/// an allocator to grow.
const MAX_FUNCTIONS: usize = 64;

/// The PCI bus this boot scans.
///
/// One bus, and that is the machine's statement rather than a limit of the
/// code: QEMU's `q35` puts every device a boot cares about on bus 0, and a
/// second bus is behind a bridge, which [`pci::device::scan`] reports and does
/// not descend into.
const BUS_COUNT: u8 = 1;

/// A virtio function found on the PCI bus, ready for its driver.
///
/// One type for both devices because what a boot has, after the scan, is the
/// same three things whatever the function does: the transport its driver
/// submits through, the PCI address its message table hangs off, and the
/// configuration space that answers questions about it.  A second struct per
/// device would have carried three identical fields and a name.
pub struct FoundVirtio {
    pub transport: Arc<virtio_core::PciTransport>,
    pub device: Device,
    /// The bus's configuration space, for a caller that has to ask the
    /// function a question after the driver has taken the transport — the
    /// message wiring's MSI-X capability walk is one.
    pub config: Arc<dyn ConfigSpace>,
}

/// Where one device's message is armed: which identity it carries, and which
/// MSI-X vector carries it.
///
/// The numbers are the boot's because a message's identity is the kernel's
/// numbering and not the device's: an MSI-X table entry is `(address, word)`
/// and the word is whatever the driver put there.  Choosing them here, once
/// per device, is what makes a colliding pair a compile-time question rather
/// than a delivery that served two drivers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessagePlan {
    /// The identity the message carries into the IMSIC file.
    pub identity: u32,
    /// The MSI-X vector the device's queue is mapped to.
    pub vector: u16,
    /// The queue whose completions this message reports.
    pub queue: u16,
    /// A word for the line the wiring prints, so a reader can tell two
    /// devices' lines apart.
    pub name: &'static str,
}

/// The block device's completion message.
///
/// Above the wired sources an APLIC owns (this machine declares 96) so it
/// cannot be confused with one, and below the identity the IMSIC self-test
/// takes (one past the last), so the two never share a pending bit.
pub const BLOCK_MESSAGE: MessagePlan = MessagePlan {
    identity: 200,
    // Vector zero is reserved for the device's configuration-change message,
    // which this tree does not use; the queue gets the next one.
    vector: 2,
    queue: virtio_block::REQUEST_QUEUE,
    name: "block",
};

/// The network card's receive message.
///
/// Receive is the queue a message is worth having for: a frame arriving is the
/// event a driver cannot poll for cheaply, because it has nothing to check
/// until one does.  Transmit completes into the driver's own count and needs
/// no message.
///
/// The identity is the block device's plus one, which is the whole of the
/// numbering: two devices, two bits in the file, two entries in the handler
/// table.  It stays below the self-test's 254 for the reason the block
/// device's does.
pub const NETWORK_MESSAGE: MessagePlan = MessagePlan {
    identity: 201,
    vector: 2,
    queue: virtio_net::RECEIVE_QUEUE,
    name: "net",
};

/// Wire one device's queue completion to this machine's IMSIC.
///
/// ## Why this runs after the driver is built
///
/// The driver's construction begins with a device reset (`write_status(0)`),
/// and a reset is the device forgetting every queue's interrupt state.  A
/// wiring before it arms a table entry and a queue vector the reset then
/// discards, and the failure is completely silent: the device finishes its
/// requests, QEMU's `virtio_notify` trace records each one, and the transport
/// drops every one of them because the queue's vector is `VIRTIO_NO_VECTOR`
/// again.  Measured: the same wiring before the reset took **0 of 4** boots,
/// and after it **8 of 8**, with every step of the wiring reading back what it
/// wrote in both runs.
///
/// ## Why the plan is a parameter and the handler is not
///
/// The numbers differ per device and the mechanism does not, so the numbers
/// are [`MessagePlan`] and the mechanism is this function.  A second copy of
/// it for the network card was the alternative, and it would have been the
/// second place a bug in the table arithmetic could hide.
///
/// The handler is separate because it has to be a `fn`, not a closure: the
/// registry stores a function pointer, and an identity is what the trap path
/// hands it.  So each device names its own counter and this function registers
/// it under the identity from the plan.
///
/// ## What it returns
///
/// The line it prints is the evidence, and every fact on it was read back from
/// the device: the table entry's address and word, the MSI-X enable, the queue
/// vector, and the IMSIC file's enable.  A machine whose tree names no IMSIC
/// answers `false` and gains nothing — the driver completes through its polling
/// as every other machine's does, so this is an extra, not a dependency.
pub fn wire_device_message(found: &FoundVirtio, plan: MessagePlan, handler: irq::Handler) -> bool {
    wire_device_message_inner(found, plan, handler)
}

/// The wiring itself, on a machine.
#[cfg(target_os = "none")]
fn wire_device_message_inner(
    found: &FoundVirtio,
    plan: MessagePlan,
    handler: irq::Handler,
) -> bool {
    let config = &*found.config;
    let device = found.device;

    let Some(page) = arch::message_page() else {
        return false;
    };

    // The MSI-X capability, found by walking the list.  A virtio function that
    // reported `STATUS_CAPABILITY_LIST` and no MSI-X is one with nothing to
    // wire, which is not an error: the driver polls.
    let Some(offset) = device.capabilities(config, |id, offset, _word| {
        (id == pci::msix::CAPABILITY_ID).then_some(offset)
    }) else {
        return false;
    };
    let Some(capability) = pci::msix::capability(config, device.address, offset) else {
        return false;
    };

    // The table's BAR, read by **register** number: that is what the
    // capability's `bar` field counts, and it is not the slot a BAR-walk array
    // uses, because a 64-bit BAR occupies one slot and two registers.
    let Some(bar) = device.bar_register(config, capability.table_bar) else {
        return false;
    };
    let bar_base = physical_address(bar.address);
    // SAFETY: the region is a BAR the bus reported, so it is a device's memory
    // and nothing else.
    #[cfg(target_os = "none")]
    unsafe {
        crate::address_space::map_device(bar_base, 0x1000);
    }

    // The entry, written and read back.  The address is this hart's MSI page
    // and the word is the bare identity: the file reads the 4-byte store as an
    // identity and nothing else, so a word with a bit above it is dropped.
    let entry_address = pci::msix::entry_address(bar_base, &capability, plan.vector as usize);
    let entry = pci::msix::Entry::new(page as u64, plan.identity).unmasked();
    write_table_entry(entry_address, entry);
    let read_back = read_table_entry(entry_address);
    if read_back != entry {
        arch::serial::write_str("protofire: ");
        arch::serial::write_str(plan.name);
        arch::serial::write_str(" message entry did not stick\n");
        return false;
    }

    // MSI-X on, then the queue's vector, then the file's enable.  The order
    // matters at the last step only: a message whose identity the file has not
    // enabled is held pending for ever, which looks exactly like a device that
    // never sent one.
    let msix_enabled = pci::msix::enable(config, device.address, &capability);
    let vector_set =
        virtio_core::Transport::set_queue_vector(&*found.transport, plan.queue, plan.vector);
    // SAFETY: `message_page` answered, so the tree named an IMSIC and the CSR
    // pair exists on this hart.
    let identity_enabled = unsafe { arch::enable_message_identity(plan.identity) };
    if !msix_enabled || !vector_set || !identity_enabled {
        arch::serial::write_str("protofire: ");
        arch::serial::write_str(plan.name);
        arch::serial::write_str(" message wiring refused: msix ");
        arch::serial::write_str(if msix_enabled { "on" } else { "off" });
        arch::serial::write_str(", queue vector ");
        arch::serial::write_str(if vector_set { "set" } else { "cleared" });
        arch::serial::write_str(", identity ");
        arch::serial::write_str(if identity_enabled {
            "enabled"
        } else {
            "not enabled"
        });
        arch::serial::write_str("\n");
        return false;
    }

    // The handler, registered under the identity the message carries, which is
    // the number the trap path hands the registry for an IMSIC delivery.
    irq::register(plan.identity as usize, handler);

    arch::serial::write_str("protofire: ");
    arch::serial::write_str(plan.name);
    arch::serial::write_str(" message wired to imsic page ");
    arch::serial::write_hex(page as u64);
    arch::serial::write_str(", identity ");
    arch::serial::write_u32(plan.identity);
    arch::serial::write_str(", vector ");
    arch::serial::write_u32(plan.vector as u32);
    arch::serial::write_str(", queue ");
    arch::serial::write_u32(plan.queue as u32);
    arch::serial::write_str("\n");
    true
}

/// A host has no device and no IMSIC, so there is nothing to wire.
///
/// `false` rather than an invented table write: the function's caller treats
/// the answer as "the driver polls", which is also what a boot on a machine
/// whose tree names no IMSIC does.
#[cfg(not(target_os = "none"))]
fn wire_device_message_inner(
    _found: &FoundVirtio,
    _plan: MessagePlan,
    _handler: irq::Handler,
) -> bool {
    false
}

/// Count one completion message from the block device.
///
/// The handler does one thing, because there is one thing to do: the completion
/// itself is in the queue's used ring, and the driver takes it on its next
/// drain whether or not a message arrived.  So a message is a **notification**,
/// and the count is what makes "the device's MSI arrived" a fact about a boot
/// rather than about the wiring's print.
#[cfg(target_os = "none")]
pub fn note_block_message_interrupt(_identity: usize) -> bool {
    crate::note_block_message_interrupt();
    true
}

/// Count one message from the network card's receive queue, and wake a waiter.
///
/// The frame itself is taken from the used ring by the driver's own drain, so
/// the message is a notification — but unlike the block device's it is the
/// **only** thing that ends a wait.  The block device is read and written by a
/// caller that already knows it asked for something; a received frame arrives
/// when nobody asked, which is the case a poll cannot answer cheaply and the
/// reason this queue has an identity at all.
///
/// So the handler does two things: it counts, which is what makes "the card's
/// message arrived" a fact about a boot, and it wakes the blocked set, which is
/// what makes the frame reach a caller that parked rather than spun.  The wake
/// is [`crate::scheduler::wake_blocked`], the same call a pipe's write makes
/// and with the same discipline: the waiter re-checks before it parks, under
/// the lock that wake takes, so the two have exactly two orders and neither
/// loses a frame.
#[cfg(target_os = "none")]
pub fn note_network_message_interrupt(_identity: usize) -> bool {
    crate::note_network_message_interrupt();
    // A wake with nothing blocked is not an error: the boot's own exchange
    // polls before it parks, and the message can land between those two.  The
    // count reports it either way, for the reason the pipe's wake line reports
    // a zero.
    let woken = crate::scheduler::wake_blocked();
    if woken > 0 {
        // The woken task may be held by another CPU parked in a wait whose own
        // clock may never move, and only the IPI ends that wait.
        // SAFETY: the boot's own IPI path, installed before any program ran.
        unsafe { arch::send_ipi_to_others() };
    }
    true
}

/// Write one MSI-X table entry, as its sixteen bytes.
#[cfg(target_os = "none")]
fn write_table_entry(address: usize, entry: pci::msix::Entry) {
    for (index, word) in entry.encode().chunks(4).enumerate() {
        let value = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
        // SAFETY: the address is inside the table's BAR, at the entry the
        // capability's own arithmetic named, and the write is four bytes.
        unsafe {
            core::ptr::write_volatile((address + index * 4) as *mut u32, value);
        }
    }
}

/// Read one MSI-X table entry back, as its sixteen bytes.
#[cfg(target_os = "none")]
fn read_table_entry(address: usize) -> pci::msix::Entry {
    let mut bytes = [0_u8; pci::msix::ENTRY_SIZE];
    for (index, slot) in bytes.chunks_mut(4).enumerate() {
        // SAFETY: as `write_table_entry`, reading the entry that was written.
        let value = unsafe { core::ptr::read_volatile((address + index * 4) as *const u32) };
        slot.copy_from_slice(&value.to_le_bytes());
    }
    pci::msix::Entry::decode(&bytes)
}

/// What a virtio function is, so a scan can match one family.
///
/// The bus reports a vendor, a device id and a class, and a driver cares about
/// a combination of them: the vendor is Red Hat's either way, and the class is
/// what says whether this is a disk or a card.
struct VirtioIds {
    modern: u16,
    transitional: u16,
    class: u8,
}

/// A block device's ids.
const BLOCK_IDS: VirtioIds = VirtioIds {
    modern: DEVICE_VIRTIO_BLOCK_MODERN,
    transitional: DEVICE_VIRTIO_BLOCK_TRANSITIONAL,
    class: CLASS_STORAGE,
};

/// A network card's ids.  Only a machine scans for one.
#[cfg(target_os = "none")]
const NETWORK_IDS: VirtioIds = VirtioIds {
    modern: DEVICE_VIRTIO_NET_MODERN,
    transitional: DEVICE_VIRTIO_NET_TRANSITIONAL,
    class: CLASS_NETWORK,
};

/// Bring up a virtio function's transport, with the BARs mapped uncached.
///
/// The steps are the machine's and not any device's: the ECAM window or the
/// port pair, the BAR assignment pass a firmware-less machine needs, the
/// capability walk, and the mapping that makes a register a register.  Both
/// drivers reach their transport through here so that a machine whose BARs are
/// not addressed is a question with one answer.
fn virtio_transport(config: &Arc<dyn ConfigSpace>, device: Device) -> Option<Arc<PciTransport>> {
    // Give the devices their addresses before anything reads a BAR.
    //
    // On a machine with firmware this does nothing: every BAR already holds an
    // address and the pass reports them as `already`.  On a device-tree machine
    // booted directly there is no firmware to have run it, so every BAR reads
    // zero and nothing behind one is reachable, the registers, the queues, and
    // the MSI-X table, which lives in a BAR.
    //
    // The window is the host bridge's, from its `ranges` property. A machine
    // that has no window is one where this cannot be done, and the driver below
    // then fails with a reason.
    if let Some((base, size)) = arch::pcie_memory_window() {
        let mut listing = [Device::ABSENT; MAX_FUNCTIONS];
        let found = pci::scan_all(&**config, BUS_COUNT, &mut listing);
        let assignment =
            pci::assign_memory_bars(&**config, &listing[..found.min(MAX_FUNCTIONS)], base, size);
        arch::serial::write_str("protofire: pci bars assigned ");
        arch::serial::write_u32(assignment.assigned as u32);
        arch::serial::write_str(", kept ");
        arch::serial::write_u32(assignment.already as u32);
        arch::serial::write_str(", no room ");
        arch::serial::write_u32(assignment.no_room as u32);
        arch::serial::write_str(", refused ");
        arch::serial::write_u32(assignment.refused as u32);
        arch::serial::write_str("\n");
    }
    // A transitional device (0x1001) offers the legacy interface *and* the
    // modern one: the modern capabilities are still in its capability list,
    // and `PciTransport` walks for them.  So it is not refused here, refusing
    // it would mean QEMU's default `virtio-blk-pci` could never be driven.
    // A device with no modern capabilities fails inside `PciTransport::new`,
    // which is where the list is actually read.

    let map_bar = |_bar: u8, address: u64, length: u64| -> Option<Arc<dyn RegisterFile>> {
        let base = physical_address(address);
        // The boot's table maps this window cached, which for a device's
        // registers means a read returns whatever was true when the line was
        // fetched and a store may never arrive.  Re-mapping it uncached is what
        // makes the registers the device's rather than the cache's.
        //
        // SAFETY: the region is a BAR the bus reported, so it is a device's
        // memory and nothing else.
        #[cfg(target_os = "none")]
        unsafe {
            crate::address_space::map_device(base, length as usize);
        }
        Some(Arc::new(MappedBar {
            base,
            length: length as usize,
        }))
    };

    // The same mechanism the scan used.  A transport built on a `PortConfig`
    // while the scan ran over ECAM reads every capability as `0xFF`, which is
    // what a port that does not exist answers, and reports the device as
    // having none.
    match PciTransport::new(config.clone(), device, &map_bar) {
        Ok(transport) => Some(Arc::new(transport)),
        Err(error) => {
            arch::serial::write_str("protofire: virtio transport failed: ");
            arch::serial::write_str(match error {
                virtio_core::transport::TransportError::NoDevice => "no device",
                virtio_core::transport::TransportError::BadCapability => "bad capability",
                virtio_core::transport::TransportError::DeviceRefused => "device refused",
                virtio_core::transport::TransportError::Unsupported => "unsupported",
                virtio_core::transport::TransportError::MissingCapability(which, seen) => {
                    arch::serial::write_str("missing ");
                    arch::serial::write_str(match which {
                        virtio_core::Capability::Common => "common",
                        virtio_core::Capability::Notify => "notify",
                        virtio_core::Capability::Device => "device",
                        virtio_core::Capability::SharedMemory => "shared memory",
                    });
                    arch::serial::write_str("; the walk saw ");
                    arch::serial::write_u32(seen.count as u32);
                    arch::serial::write_str(" structure(s), types");
                    for kind in seen.types.iter().take(seen.walked) {
                        arch::serial::write_str(" ");
                        arch::serial::write_u32(*kind as u32);
                    }
                    ""
                }
            });
            arch::serial::write_str("\n");
            None
        }
    }
}

/// Find one virtio function of a family, and bring up its transport.
fn find_virtio(
    ids: &VirtioIds,
    what: &str,
) -> Option<(Arc<PciTransport>, Device, Arc<dyn ConfigSpace>)> {
    let config = configuration_space();
    let (scan_result, found) = pci::device::scan(&*config, BUS_COUNT, |device| {
        let modern = device.vendor == VENDOR_REDHAT
            && device.device == ids.modern
            && device.class == ids.class;
        let transitional = device.vendor == VENDOR_REDHAT
            && device.device == ids.transitional
            && device.class == ids.class;
        if modern || transitional {
            Some((device, modern))
        } else {
            None
        }
    });

    // A probe that found nothing is worth reporting: "no virtio-blk" and "the
    // bus answered for nothing" are different states, and only the second means
    // the scan itself is not reaching the machine.
    arch::serial::write_str("protofire: pci scan found ");
    arch::serial::write_u32(scan_result.devices as u32);
    arch::serial::write_str(" device(s) on ");
    arch::serial::write_u32(scan_result.buses as u32);
    arch::serial::write_str(" bus, looking for ");
    arch::serial::write_str(what);
    arch::serial::write_str("\n");

    let (device, _modern) = found?;
    let transport = virtio_transport(&config, device)?;
    Some((transport, device, config))
}

/// Scan the bus for a virtio block device, and bring up its transport.
///
/// Returns `None` when the machine has no such device, which is a normal
/// state: a boot with no disk still has a console and a heap, and a machine
/// that refused to boot because a disk was absent could not be debugged.
pub fn find_virtio_block() -> Option<FoundVirtio> {
    let (transport, device, config) = find_virtio(&BLOCK_IDS, "virtio-blk")?;
    Some(FoundVirtio {
        transport,
        device,
        config,
    })
}

/// The gateway a boot asks about, as QEMU's user-mode network answers it.
///
/// `-netdev user` puts the guest on `10.0.2.0/24` with the gateway at `.2`, and
/// it answers an ARP request for that address without any configuration.  The
/// guest's own address is `.15`, which is the one the request carries as its
/// sender.  Neither number is negotiated: they are QEMU's defaults, named here
/// because a request for an address nothing owns gets no reply and the exchange
/// would look like a card that does not receive.
#[cfg(target_os = "none")]
const GATEWAY_PROTOCOL: [u8; 4] = [10, 0, 2, 2];

/// The address this boot claims on that network.
#[cfg(target_os = "none")]
const OUR_PROTOCOL: [u8; 4] = [10, 0, 2, 15];

/// How long one bounded wait's slice is, and how many of them a probe spends
/// before it reports its request unanswered.
///
/// Two seconds in slices of a twentieth of a second: enough for QEMU's
/// user-mode network, and short enough that a card that will never answer
/// ends the boot with a line instead of a checker's timeout.
#[cfg(target_os = "none")]
const TURN_US: u64 = 50_000;
#[cfg(target_os = "none")]
const TURNS: u32 = 40;

/// Ask the gateway who it is, and print the answer.
///
/// This is the self-test the frame path exists for.  It exercises four things a
/// bring-up cannot: the transmit chain with a real frame in it, the device's
/// own send path, the receive chain, and the device's receive path.  The
/// evidence is the line, and every field on it came out of the reply's bytes.
///
/// ## Why the reply is not waited for with a timeout
///
/// It is.  A card that never answers is a card that is not working, and the
/// line says which of the four steps failed instead of hanging the boot: the
/// request's own completion, the reply's arrival, and the two addresses the
/// reply names.
///
/// ## What a machine without a card prints
///
/// Nothing, and that is the design: a boot with no network is the ordinary
/// state on two of the three machines, and a line that said so on every boot
/// would be noise a reader learns to skip.
#[cfg(target_os = "none")]
pub fn exercise_network() -> bool {
    let Some((transport, device, config)) = find_virtio(&NETWORK_IDS, "virtio-net") else {
        return false;
    };

    let card = match virtio_net::VirtioNet::new(transport.clone()) {
        Ok(card) => card,
        Err(error) => {
            arch::serial::write_str("protofire: virtio-net refused the device: ");
            arch::serial::write_str(match error {
                abi::Error::Unsupported => "unsupported",
                abi::Error::DeviceError => "device error",
                abi::Error::InvalidArgument => "invalid argument",
                abi::Error::Busy => "busy",
                abi::Error::TimedOut => "timed out",
                _ => "error",
            });
            arch::serial::write_str("\n");
            return false;
        }
    };

    let mac = card.mac();
    arch::serial::write_str("protofire: virtio-net up, address ");
    write_mac(mac);
    arch::serial::write_str(", receive queue ");
    arch::serial::write_u32(card.receive_queue_size() as u32);
    arch::serial::write_str(", transmit queue ");
    arch::serial::write_u32(card.transmit_queue_size() as u32);
    arch::serial::write_str("\n");

    // The receive queue's message, wired **after** the driver for the reason
    // the block device's is: the driver's first step is a reset, and a reset
    // forgets every queue's vector.
    #[cfg(target_os = "none")]
    let wired = {
        let found = FoundVirtio {
            transport: transport.clone(),
            device,
            config,
        };
        wire_device_message(&found, NETWORK_MESSAGE, note_network_message_interrupt)
    };
    #[cfg(not(target_os = "none"))]
    let wired = false;
    let _ = wired;

    // A buffer posted **before** the request goes out.  A driver that sent
    // first would be relying on the card holding the answer until a buffer
    // appeared, and a real card drops a frame it has nowhere to put.
    if card.post_receive_buffer().is_err() {
        arch::serial::write_str("protofire: virtio-net could not post a receive buffer\n");
        return false;
    }

    // The ARP exchange asks the wire who holds the gateway's address, and the
    // cache keeps the answer: every later consumer of that address resolves
    // through the table first, and the wire is asked only what it does not
    // hold.  The ping that follows is the first such consumer.
    let mut cache = net::arp::Cache::new();
    if !arp_exchange(&card, mac, &mut cache) {
        return false;
    }

    // The ping: an echo request to the gateway, and the reply parsed.  A reply
    // that matches the request's identifier, sequence and data is a packet
    // another machine built — the round trip IPv4 can carry, on a wire that
    // answers without being configured.
    if !ping_gateway(&card, mac, &cache) {
        return false;
    }

    // The datagram: one UDP send to a port nothing owns, and the refusal
    // that comes back — the peer's proof that a datagram this stack built
    // arrived with its header intact.
    send_udp_probe(&card, mac, &cache)
}

/// Ask the wire who holds the gateway's address, and put the answer in the
/// cache.
///
/// This is the exchange the frame path exists for: the transmit chain with a
/// real frame in it, the device's send path, the receive chain, and the
/// device's receive path.  The evidence is the reply's line, and every field
/// on it came out of the reply's bytes.
#[cfg(target_os = "none")]
fn arp_exchange(card: &virtio_net::VirtioNet, mac: [u8; 6], cache: &mut net::arp::Cache) -> bool {
    // **Submitted, not completed.**  The request goes out and this boot does
    // not wait for the transmit queue to retire it, because the reply is what
    // it wants and the two travel independently: waiting for the send first
    // hides the receive wait entirely — measured, the reply was already in the
    // ring by the time the send finished, so the receive loop took zero turns
    // and could not tell a working message from a poll that never needed one.
    let mut questions_asked = 0;
    let request = net::arp::request(mac, OUR_PROTOCOL, GATEWAY_PROTOCOL);
    questions_asked += 1;
    if let Err(error) = card.submit_frame(&request) {
        arch::serial::write_str("protofire: virtio-net could not send the arp request: ");
        arch::serial::write_str(match error {
            abi::Error::TimedOut => "timed out",
            abi::Error::Busy => "busy",
            abi::Error::DeviceError => "device error",
            _ => "error",
        });
        arch::serial::write_str("\n");
        return false;
    }

    let mut frame = [0_u8; virtio_net::RECEIVE_BUFFER_LEN];
    let mut waits = 0;
    // SAFETY: the timer's line is enabled by `tick::bring_up`, which the boot
    // ran before this.
    let frequency = unsafe { arch::timer_frequency() };
    loop {
        match card.receive_frame(&mut frame) {
            Ok(Some(length)) => {
                let Some(arp) = net::arp::parse(&frame[..length]) else {
                    arch::serial::write_str(
                        "protofire: virtio-net received a frame that is not arp\n",
                    );
                    return false;
                };
                if arp.operation != 2 {
                    arch::serial::write_str("protofire: virtio-net received an arp request\n");
                    return false;
                }
                // The wait count is the evidence that the message did the
                // work: a reply that arrives after one wait was delivered by
                // the card's interrupt, and one that arrives after many is
                // the bound's doing.  Printed before the reply's fields so a
                // reader sees how the frame got here beside what it says.
                arch::serial::write_str("protofire: virtio-net waited ");
                arch::serial::write_u32(waits);
                arch::serial::write_str(" time(s) for the reply\n");
                arch::serial::write_str("protofire: virtio-net arp reply ");
                write_mac(arp.sender_hardware);
                arch::serial::write_str(" holds ");
                write_ipv4(arp.sender_protocol);
                arch::serial::write_str(", asked by ");
                write_mac(arp.target_hardware);
                arch::serial::write_str(" for ");
                write_ipv4(arp.target_protocol);
                arch::serial::write_str("\n");
                // The answer goes in the table, and the table is read back
                // for the same question — the second resolve answers from the
                // cache, which is the whole reason the answer was kept.  The
                // wire was asked once, and stays asked once for the rest of
                // the boot: the ping and the datagram that follow resolve
                // here first.
                cache.learn(arp.sender_protocol, arp.sender_hardware);
                arch::serial::write_str("protofire: arp cache holds ");
                write_ipv4(arp.sender_protocol);
                arch::serial::write_str(" at ");
                write_mac(arp.sender_hardware);
                arch::serial::write_str(", the wire asked ");
                arch::serial::write_u32(questions_asked as u32);
                arch::serial::write_str(" time(s)\n");
                if cache.hardware_for(GATEWAY_PROTOCOL) == Some(arp.sender_hardware) {
                    arch::serial::write_str("protofire: arp cache answered ");
                    write_ipv4(GATEWAY_PROTOCOL);
                    arch::serial::write_str(" again without the wire\n");
                }
                // The reply has to be the answer to the question this boot
                // asked, or it is a frame from somewhere else that happened to
                // parse.  Checked rather than assumed: a card that received its
                // own request would pass every test above.
                return arp.target_hardware == mac
                    && arp.target_protocol == OUR_PROTOCOL
                    && arp.sender_protocol == GATEWAY_PROTOCOL;
            }
            Ok(None) => {
                waits += 1;
                if waits > TURNS {
                    arch::serial::write_str(
                        "protofire: virtio-net arp request went unanswered after ",
                    );
                    arch::serial::write_u32(waits);
                    arch::serial::write_str(" turn(s)\n");
                    return false;
                }
                wait_one_turn(frequency);
            }
            Err(_) => {
                arch::serial::write_str("protofire: virtio-net receive buffer too small\n");
                return false;
            }
        }
    }
}

/// Ping the gateway: one echo request out, and the reply parsed and matched.
///
/// The exchange proves the IPv4 layer on a machine, which no host test can:
/// the request is built through `net`'s own writers, and the reply that comes
/// back was built by QEMU's user-mode network — a checksum it verified, an
/// identifier and sequence it carried back, and the data it echoed.  A reply
/// that does not match all three is somebody else's packet, and the boot says
/// so instead of claiming the round trip.
///
/// ## Why the wait is bounded the way the ARP exchange's is
///
/// By the machine's own timer, one slice per turn: `wait_for_a_wakeup` does
/// not return without an interrupt, so a card that never answers would sit in
/// the wait for ever on a turn count.  The timer's interrupt is the one that
/// ends a turn where the card's never comes.
#[cfg(target_os = "none")]
fn ping_gateway(card: &virtio_net::VirtioNet, mac: [u8; 6], cache: &net::arp::Cache) -> bool {
    // The gateway's hardware address, from the cache: the exchange's answer
    // being reused, which is the reason it was kept.  A boot that reaches the
    // ping without an ARP reply has no address to send to, and the line says
    // that rather than sending to nobody.
    let Some(gateway_hardware) = cache.hardware_for(GATEWAY_PROTOCOL) else {
        arch::serial::write_str("protofire: icmp has no gateway address to ping\n");
        return false;
    };

    const PAYLOAD: &[u8] = b"protofire";
    const IDENTIFIER: u16 = 1;
    const SEQUENCE: u16 = 1;
    let icmp_len = net::icmp::echo_len(PAYLOAD.len());
    let packet_len = netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + icmp_len;

    // The request: an Ethernet header to the gateway, an IPv4 header to its
    // address, and the echo message in the payload — each layer written at
    // the offset the one before it ended at, which is the wire's own order.
    let mut frame = [0_u8; virtio_net::RECEIVE_BUFFER_LEN];
    net::ethernet::write_header(
        &mut frame,
        gateway_hardware,
        mac,
        net::ethernet::ETHERTYPE_IPV4,
    );
    net::ipv4::write_header(
        &mut frame[netdev::ETHERNET_HEADER_LEN..],
        OUR_PROTOCOL,
        GATEWAY_PROTOCOL,
        net::ipv4::PROTOCOL_ICMP,
        icmp_len,
    );
    net::icmp::write_echo_request(
        &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..],
        IDENTIFIER,
        SEQUENCE,
        PAYLOAD,
    );

    // A buffer posted **before** the request goes out, for the reason the
    // ARP exchange's was: a real card drops a frame it has nowhere to put,
    // and the reply is the whole point of the send.
    if card.post_receive_buffer().is_err() {
        arch::serial::write_str("protofire: icmp could not post a receive buffer\n");
        return false;
    }
    if let Err(error) = card.submit_frame(&frame[..packet_len]) {
        arch::serial::write_str("protofire: icmp could not send the echo request: ");
        arch::serial::write_str(match error {
            abi::Error::TimedOut => "timed out",
            abi::Error::Busy => "busy",
            abi::Error::DeviceError => "device error",
            _ => "error",
        });
        arch::serial::write_str("\n");
        return false;
    }

    let mut waits = 0;
    // SAFETY: the timer's line is enabled by `tick::bring_up`, which the boot
    // ran before this.
    let frequency = unsafe { arch::timer_frequency() };
    loop {
        match card.receive_frame(&mut frame) {
            Ok(Some(length)) => {
                // The buffer the frame came in is spent; the next one to
                // arrive needs another, which is what re-posting here is for.
                let _ = card.post_receive_buffer();
                let frame = &frame[..length];
                // Demux by what the frame says, not by what this loop wants:
                // a frame that is not an IPv4 echo reply is skipped, because
                // the wire carries strangers' frames too and a match that
                // could not refuse one would claim the first thing that
                // parsed.
                if netdev::ethertype(frame) != Some(net::ethernet::ETHERTYPE_IPV4) {
                    continue;
                }
                let Some(packet) = net::ipv4::parse(&frame[netdev::ETHERNET_HEADER_LEN..]) else {
                    continue;
                };
                if packet.header.protocol != net::ipv4::PROTOCOL_ICMP {
                    continue;
                }
                let at = netdev::ETHERNET_HEADER_LEN + packet.payload_at;
                let icmp = &frame[at..at + packet.payload_len];
                let Some(echo) = net::icmp::parse(icmp) else {
                    continue;
                };
                if echo.kind != net::icmp::ECHO_REPLY
                    || echo.identifier != IDENTIFIER
                    || echo.sequence != SEQUENCE
                {
                    continue;
                }
                if icmp[net::icmp::HEADER_LEN..] != *PAYLOAD {
                    continue;
                }
                // The line is the evidence, and every number on it came out
                // of the reply: the address it names, the length it echoed,
                // and the wait that says how the frame got here.
                arch::serial::write_str("protofire: icmp echo reply from ");
                write_ipv4(packet.header.source);
                arch::serial::write_str(", ");
                arch::serial::write_u32(packet.payload_len as u32);
                arch::serial::write_str(" byte(s), waited ");
                arch::serial::write_u32(waits);
                arch::serial::write_str(" time(s)\n");
                return true;
            }
            Ok(None) => {
                waits += 1;
                if waits > TURNS {
                    arch::serial::write_str("protofire: icmp echo request went unanswered after ");
                    arch::serial::write_u32(waits);
                    arch::serial::write_str(" turn(s)\n");
                    return false;
                }
                wait_one_turn(frequency);
            }
            Err(_) => {
                arch::serial::write_str("protofire: icmp receive buffer too small\n");
                return false;
            }
        }
    }
}

/// Send one UDP datagram to a port on the gateway nothing owns, and read
/// the refusal back.
///
/// A port nothing listens on is the one datagram a peer is guaranteed to
/// answer, and the answer is ICMP's port unreachable carrying the original
/// datagram's first bytes — which is how the line proves a peer received a
/// datagram this stack built, parsed its header, and named the port it came
/// from.  The exchange is a real one: the refusal was built by QEMU's
/// user-mode network, and the port it names on the line came out of the
/// embedded original, not out of this boot's own constants alone.
#[cfg(target_os = "none")]
fn send_udp_probe(card: &virtio_net::VirtioNet, mac: [u8; 6], cache: &net::arp::Cache) -> bool {
    let Some(gateway_hardware) = cache.hardware_for(GATEWAY_PROTOCOL) else {
        arch::serial::write_str("protofire: udp has no gateway address to send to\n");
        return false;
    };

    const PAYLOAD: &[u8] = b"protofire";
    const OUR_PORT: u16 = 40000;
    const THEIR_PORT: u16 = 8612;
    let udp_len = net::udp::datagram_len(PAYLOAD.len());
    let packet_len = netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN + udp_len;

    // The datagram: Ethernet to the gateway, IPv4 to its address, and the
    // datagram in the payload — the same three layers the ping wrote, with
    // UDP's pseudo-header checksum in the place ICMP's message checksum was.
    let mut frame = [0_u8; virtio_net::RECEIVE_BUFFER_LEN];
    net::ethernet::write_header(
        &mut frame,
        gateway_hardware,
        mac,
        net::ethernet::ETHERTYPE_IPV4,
    );
    net::ipv4::write_header(
        &mut frame[netdev::ETHERNET_HEADER_LEN..],
        OUR_PROTOCOL,
        GATEWAY_PROTOCOL,
        net::ipv4::PROTOCOL_UDP,
        udp_len,
    );
    net::udp::write_datagram(
        &mut frame[netdev::ETHERNET_HEADER_LEN + net::ipv4::HEADER_LEN..],
        OUR_PROTOCOL,
        GATEWAY_PROTOCOL,
        OUR_PORT,
        THEIR_PORT,
        PAYLOAD,
    );

    if card.post_receive_buffer().is_err() {
        arch::serial::write_str("protofire: udp could not post a receive buffer\n");
        return false;
    }
    if let Err(error) = card.submit_frame(&frame[..packet_len]) {
        arch::serial::write_str("protofire: udp could not send the datagram: ");
        arch::serial::write_str(match error {
            abi::Error::TimedOut => "timed out",
            abi::Error::Busy => "busy",
            abi::Error::DeviceError => "device error",
            _ => "error",
        });
        arch::serial::write_str("\n");
        return false;
    }

    let mut waits = 0;
    // SAFETY: the timer's line is enabled by `tick::bring_up`, which the boot
    // ran before this.
    let frequency = unsafe { arch::timer_frequency() };
    loop {
        match card.receive_frame(&mut frame) {
            Ok(Some(length)) => {
                let _ = card.post_receive_buffer();
                let frame = &frame[..length];
                if netdev::ethertype(frame) != Some(net::ethernet::ETHERTYPE_IPV4) {
                    continue;
                }
                let Some(packet) = net::ipv4::parse(&frame[netdev::ETHERNET_HEADER_LEN..]) else {
                    continue;
                };
                if packet.header.protocol != net::ipv4::PROTOCOL_ICMP {
                    continue;
                }
                let at = netdev::ETHERNET_HEADER_LEN + packet.payload_at;
                let icmp = &frame[at..at + packet.payload_len];
                let Some(message) = net::icmp::parse(icmp) else {
                    continue;
                };
                if message.kind != net::icmp::DESTINATION_UNREACHABLE
                    || message.code != net::icmp::PORT_UNREACHABLE
                {
                    continue;
                }
                // The original datagram the error carries names the sender
                // this stack claimed to be: its IPv4 header parses, and the
                // UDP header inside it answers the port the datagram was
                // sent from.  A refusal about somebody else's datagram is
                // not this boot's evidence.
                let original = &icmp[net::icmp::ORIGINAL_DATAGRAM_AT..];
                let Some(embedded) = net::ipv4::parse(original) else {
                    continue;
                };
                let Some(datagram) = net::udp::parse(
                    &original[embedded.payload_at..],
                    embedded.header.source,
                    embedded.header.destination,
                ) else {
                    continue;
                };
                if datagram.source_port != OUR_PORT {
                    continue;
                }
                arch::serial::write_str("protofire: udp sent from port ");
                arch::serial::write_u32(OUR_PORT as u32);
                arch::serial::write_str(", refused by ");
                write_ipv4(packet.header.source);
                arch::serial::write_str(": port unreachable, waited ");
                arch::serial::write_u32(waits);
                arch::serial::write_str(" time(s)\n");
                return true;
            }
            Ok(None) => {
                waits += 1;
                if waits > TURNS {
                    arch::serial::write_str("protofire: udp datagram went unanswered after ");
                    arch::serial::write_u32(waits);
                    arch::serial::write_str(" turn(s)\n");
                    return false;
                }
                wait_one_turn(frequency);
            }
            Err(_) => {
                arch::serial::write_str("protofire: udp receive buffer too small\n");
                return false;
            }
        }
    }
}

/// Spend one bounded turn waiting for a frame: arm the machine's timer for a
/// slice, then stop this core until an interrupt ends it.
///
/// ## Why the wait is bounded this way at all
///
/// The first version of the ARP exchange counted turns and stopped after a
/// `WAIT_LIMIT` of them, which is not a bound at all: `wait_for_a_wakeup`
/// does not return until an interrupt arrives, so a card that never sent one
/// left the count at 1 and the boot in the wait for ever — measured, the
/// checker's own timeout was what ended that boot.  So the bound is the
/// machine's timer: each turn arms it for a slice, and the interrupt that
/// ends the wait is either the card's — which is the one that matters — or
/// the timer's, which is a turn spent and nothing more.  The loop re-checks
/// the ring after every wake, so a wake from the timer or an IPI costs a
/// turn and nothing else.
#[cfg(target_os = "none")]
fn wait_one_turn(frequency: Option<u64>) {
    if let Some(frequency) = frequency {
        // SAFETY: the timer's line is enabled, which is `arm_timer`'s
        // contract; the boot brought the timer up before this ran.
        unsafe { arch::arm_timer(frequency, TURN_US) };
    }
    arch::wait_for_a_wakeup();
}

/// Write six bytes as an address a reader recognizes.
///
/// Two hex digits per octet, through `write_str`, which is what the rest of the
/// boot uses and what keeps a line in one buffer: `write_byte` goes straight to
/// the UART on x86_64, so a line that mixed the two came out with the address's
/// digits ahead of the text before them.
#[cfg(target_os = "none")]
fn write_mac(mac: [u8; 6]) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    for (index, byte) in mac.iter().enumerate() {
        if index != 0 {
            arch::serial::write_str(":");
        }
        let pair = [
            DIGITS[(byte >> 4) as usize] as char,
            DIGITS[(byte & 0x0F) as usize] as char,
        ];
        arch::serial::write_str(pair.iter().collect::<alloc::string::String>().as_str());
    }
}

/// Write four bytes as a dotted quad, which is how the request carries them.
#[cfg(target_os = "none")]
fn write_ipv4(address: [u8; 4]) {
    for (index, byte) in address.iter().enumerate() {
        if index != 0 {
            arch::serial::write_str(".");
        }
        arch::serial::write_u32(*byte as u32);
    }
}

/// The address the device sees, for an address this code can use.
///
/// Identity, and that is this boot's arrangement rather than a fact about
/// memory: the boot assembly maps the first gigabyte at the same virtual
/// address, so a pointer and its physical address are the same number.  When
/// the kernel gets an address space of its own, this is where the translation
/// goes, and it is a function so that becomes one change rather than a search.
pub fn physical_address(virtual_address: u64) -> usize {
    virtual_address as usize
}

// The devices' identities are clear of every other user of the file, and these
// are compile-time assertions because an identity that collides is not a case a
// test catches at run time — it is a constant the next editor can break, and
// the break has to fail the build rather than a boot.
//
// An IMSIC file holds one pending bit per identity, so two users sharing one is
// one delivery for two of them.  The firmware enables identity 1 in every
// hart's file at hart start (OpenSBI's S-mode IPI); an APLIC in message mode
// uses each wired source's own number, and this machine declares 96 of them;
// identity 10 is the console's own source on that machine; and the boot's
// IMSIC self-test takes the last identity the file holds (254 of 255), so a
// device has to sit strictly below it or the two share the bit the self-test
// reads back.
//
// Written over the plans rather than over each device's number so that adding a
// third device is a row in this list and not a new set of assertions the next
// author has to remember.  The pairwise check is the one a per-device pair of
// assertions could not make.
const DEVICE_MESSAGES: [MessagePlan; 2] = [BLOCK_MESSAGE, NETWORK_MESSAGE];

const _: () = {
    let mut index = 0;
    while index < DEVICE_MESSAGES.len() {
        let plan = DEVICE_MESSAGES[index];
        assert!(
            plan.identity > 96,
            "an APLIC source's own number is its identity, and 96 are declared"
        );
        assert!(plan.identity != 1, "the firmware's IPI");
        assert!(plan.identity != 10, "the console's source");
        assert!(
            plan.identity < 254,
            "the self-test takes the last identity the file holds"
        );
        // Virtio reserves vector zero for configuration-change messages, so a
        // queue mapped onto it would have its completions counted as
        // configuration changes the kernel never asks for.
        assert!(plan.vector != 0);

        // Two devices sharing an identity share one pending bit, and two
        // sharing a vector have one table entry written twice.
        let mut other = index + 1;
        while other < DEVICE_MESSAGES.len() {
            assert!(
                plan.identity != DEVICE_MESSAGES[other].identity,
                "two devices cannot share a message identity"
            );
            other += 1;
        }
        index += 1;
    }
};
