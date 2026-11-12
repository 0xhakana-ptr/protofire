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
#[cfg(target_os = "none")]
pub fn note_block_message_interrupt(_identity: usize) -> bool {
    crate::note_block_message_interrupt();
    true
}

/// Count one message from the network card's receive queue.
///
/// The frame itself is taken from the used ring by the driver's own drain, so
/// this is a notification too — and the count is what says the card's message
/// reached this kernel rather than being held in the file.
#[cfg(target_os = "none")]
#[cfg(target_os = "none")]
pub fn note_network_message_interrupt(_identity: usize) -> bool {
    crate::note_network_message_interrupt();
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

    let request = virtio_net::arp_request(mac, OUR_PROTOCOL, GATEWAY_PROTOCOL);
    if let Err(error) = card.submit_frame_blocking(&request) {
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

    // The reply is polled for, bounded, because a card that does not answer is
    // a card that does not answer: waiting for an interrupt this boot has not
    // wired would wait for something nobody asked for.
    let mut frame = [0_u8; virtio_net::RECEIVE_BUFFER_LEN];
    const POLL_LIMIT: u32 = 50_000_000;
    let mut polls = 0;
    loop {
        match card.receive_frame(&mut frame) {
            Ok(Some(length)) => {
                let Some(arp) = virtio_net::parse_arp(&frame[..length]) else {
                    arch::serial::write_str(
                        "protofire: virtio-net received a frame that is not arp\n",
                    );
                    return false;
                };
                if arp.operation != 2 {
                    arch::serial::write_str("protofire: virtio-net received an arp request\n");
                    return false;
                }
                arch::serial::write_str("protofire: virtio-net arp reply ");
                write_mac(arp.sender_hardware);
                arch::serial::write_str(" holds ");
                write_ipv4(arp.sender_protocol);
                arch::serial::write_str(", asked by ");
                write_mac(arp.target_hardware);
                arch::serial::write_str(" for ");
                write_ipv4(arp.target_protocol);
                arch::serial::write_str("\n");
                // The reply has to be the answer to the question this boot
                // asked, or it is a frame from somewhere else that happened to
                // parse.  Checked rather than assumed: a card that received its
                // own request would pass every test above.
                return arp.target_hardware == mac
                    && arp.target_protocol == OUR_PROTOCOL
                    && arp.sender_protocol == GATEWAY_PROTOCOL;
            }
            Ok(None) => {
                polls += 1;
                if polls > POLL_LIMIT {
                    arch::serial::write_str("protofire: virtio-net arp request went unanswered\n");
                    return false;
                }
                core::hint::spin_loop();
            }
            Err(_) => {
                arch::serial::write_str("protofire: virtio-net receive buffer too small\n");
                return false;
            }
        }
    }
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
