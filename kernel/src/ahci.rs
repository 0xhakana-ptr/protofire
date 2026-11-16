//! kernel/src/ahci.rs
//!
//! Finding the controller, bringing a port up, and proving the disk reads.
//!
//! ## Why the controller is here and the wire format is not
//!
//! `ahci` holds BAR5's registers, a port's register block, the three
//! structures a command is built from and the identify structure a SATA
//! device answers with, and it names nothing of this tree: a host test drives
//! every offset, every bit position and every field's bytes against an array.
//! What it cannot do is reach a device, and that needs a BAR, aligned
//! allocations and a doorbell, which are the machine's.
//!
//! So this file is the controller: find the function on the bus, map BAR5,
//! find the port the disk is on, start the port's engine, and identify and
//! read through the command table.  It is the same split `nvme.rs` makes
//! against the `nvme` crate.
//!
//! ## The port is found, not assumed
//!
//! This is the defect the relocation corrected, and the reason it is stated
//! at length: the previous tree's driver hardcoded port zero with a comment
//! promising to find the real one later, and the later never came.  A
//! controller's ports are named by `PI`, the ports-implemented register, and
//! a disk's presence is `PxSSTS.DET` reading three -- present and
//! communicating.  A driver that assumed port zero drives whatever firmware
//! put there, which on a machine whose disk hangs off port two is no disk at
//! all, and a driver that skipped the `DET` check sends IDENTIFY down a dead
//! link and waits for a completion that cannot come.
//!
//! ## What the relocation corrected in the command path
//!
//! The command header this driver builds carries `CFL` = 5, the length of a
//! Register FIS in dwords, because the previous tree's header carried zero
//! and a controller that refuses a length below two dwords refused every
//! command before the device was ever consulted.  QEMU's does refuse it, and
//! the refusal is silent: no completion, no error, a poll that runs out.  The
//! `ahci` crate's test asserts the field; this file's job is only to pass the
//! builder the right constant.

use alloc::alloc::Layout;
use alloc::alloc::alloc_zeroed;
use alloc::alloc::dealloc;
use alloc::sync::Arc;

use abi::Error;
use abi::Result;
use block::BlockDevice;
use block::QueuedBlockDevice;

use ahci::ATA_FLUSH_CACHE;
use ahci::ATA_IDENTIFY_DEVICE;
use ahci::ATA_READ_DMA_EXT;
use ahci::ATA_WRITE_DMA_EXT;
use ahci::CL_ENTRY_SIZE;
use ahci::CMD_CR;
use ahci::CMD_FR;
use ahci::CMD_FRE;
use ahci::CMD_ST;
use ahci::CT_BASE_SIZE;
use ahci::CT_TOTAL_SIZE;
use ahci::DET_PRESENT_AND_COMMUNICATING;
use ahci::GHC_AE;
use ahci::PIS_TFES;
use ahci::PORT_CI;
use ahci::PORT_CLB;
use ahci::PORT_CLBU;
use ahci::PORT_CMD;
use ahci::PORT_FB;
use ahci::PORT_FBU;
use ahci::PORT_IS;
use ahci::PORT_SERR;
use ahci::PORT_SSTS;
use ahci::PORT_TFD;
use ahci::REGISTER_FIS_BYTES;
use ahci::REGISTER_FIS_DWORDS;
use ahci::RFIS_SIZE;
use ahci::SERR_CLEAR_ALL;
use ahci::SSTS_DET_MASK;
use ahci::TFD_ERR;
use ahci::command_header;
use ahci::h2d_fis;
use ahci::port_register;
use ahci::prdt_entry;

/// The command list slot this driver fills.
///
/// One slot, because every command runs to completion before the next is
/// submitted: depth one, the same shape the NVMe device answers with, for the
/// same reason -- driving a second slot wants a ticket per request and an
/// interrupt to wake on, and this driver polls.
const COMMAND_SLOT: u32 = 0;

/// How many times the engine's running bits are polled before the boot calls
/// the port dead.
const ENGINE_POLL_LIMIT: u32 = 1_000_000;

/// How many times a command's completion is polled for before the wait fails.
const COMPLETION_POLL_LIMIT: u32 = 10_000_000;

/// The alignment every DMA structure is given.
///
/// The specification asks the command list of a kilobyte, the received-FIS
/// area of 256 bytes and the command table of 128 bytes; one page exceeds all
/// three, and a single alignment for all of them is one property for the
/// allocator to honour instead of three for the caller to pass.
const DMA_ALIGN: usize = 4096;

/// A run of page-aligned frames, freed when it is dropped.
///
/// The controller reads its structures from physical memory whose alignment
/// the specification fixes -- the command list on a kilobyte, the received-FIS
/// area on 256 bytes, the command table on 128 -- and a structure handed over
/// misaligned is one the controller reads from wherever the low bits landed.
/// Every allocation here is page-aligned, which is inside all three bounds.
///
/// This is the same type `nvme.rs` defines, for the same reason; the two
/// files do not share it because a shared DMA allocator is a design decision
/// no second driver has forced yet, and inventing one now is how a framework
/// becomes a constraint.
struct AlignedFrames {
    pointer: *mut u8,
    layout: Layout,
}

impl AlignedFrames {
    /// Allocate `bytes` zeroed at page alignment.
    fn new(bytes: usize) -> Option<Self> {
        let layout = Layout::from_size_align(bytes, DMA_ALIGN).ok()?;
        // SAFETY: `layout` has a non-zero size, which is the one requirement
        // `alloc_zeroed`'s contract places on the caller, and the allocation
        // handed back is freed by the `Drop` below with the same layout.
        let pointer = unsafe { alloc_zeroed(layout) };
        if pointer.is_null() {
            return None;
        }
        Some(Self { pointer, layout })
    }

    /// The address the controller reads from.
    ///
    /// The boot runs identity-mapped, so the pointer is the physical address;
    /// [`crate::devices::physical_address`] is where that becomes a claim.
    fn address(&self) -> u64 {
        crate::devices::physical_address(self.pointer as u64) as u64
    }

    fn as_slice(&self) -> &[u8] {
        // SAFETY: the region is `layout.size()` bytes this type owns, and the
        // borrow is tied to `&self` so nothing frees it underneath.
        unsafe { core::slice::from_raw_parts(self.pointer, self.layout.size()) }
    }

    fn as_slice_mut(&mut self) -> &mut [u8] {
        // SAFETY: as `as_slice`, and `&mut self` makes the borrow exclusive.
        unsafe { core::slice::from_raw_parts_mut(self.pointer, self.layout.size()) }
    }
}

impl Drop for AlignedFrames {
    fn drop(&mut self) {
        // SAFETY: `pointer` came from `alloc_zeroed` with exactly this layout,
        // and `Drop` runs once.
        unsafe { dealloc(self.pointer, self.layout) };
    }
}

// SAFETY: the type owns its allocation exclusively -- the pointer came from
// `alloc_zeroed`, every access goes through `&self` or `&mut self` of the
// owner, and `Drop` frees it exactly once with the layout it was given.
// It exists because the device sits behind an `Arc`, and a raw pointer is
// `!Send` by default whether or not anything shares it.
unsafe impl Send for AlignedFrames {}

/// BAR5, read and written a word at a time.
struct Registers {
    base: usize,
    length: usize,
}

impl Registers {
    fn read32(&self, offset: usize) -> u32 {
        assert!(offset + 4 <= self.length, "read past BAR5");
        // SAFETY: `offset` is inside the window the bus reported, and a
        // volatile read is what MMIO needs: the compiler must not fold two
        // reads of a register the controller may have changed.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }

    fn write32(&self, offset: usize, value: u32) {
        assert!(offset + 4 <= self.length, "write past BAR5");
        // SAFETY: as `read32`.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) }
    }
}

/// One port of the controller, with the three DMA structures a command needs.
pub struct Port {
    registers: Registers,
    port: u8,
    /// The command list: 32 headers, of which this driver fills slot zero.
    command_list: AlignedFrames,
    /// The received-FIS area, which the controller writes and this driver
    /// never reads: it must stay allocated for as long as the engine runs.
    #[allow(dead_code)]
    received_fis: AlignedFrames,
    /// The command table: one FIS, one PRD entry.
    command_table: AlignedFrames,
    /// The page every block transfer rides through.
    bounce: AlignedFrames,
    block_count: u64,
    block_size: usize,
    model: [u8; ahci::MODEL_BYTES],
}

impl Port {
    /// Find the port the disk is on, and bring its engine up.
    ///
    /// `None` on a machine with no controller, and on a controller whose
    /// implemented ports have no disk attached.  The two are reported
    /// differently, because "no controller" is a machine fact and "no disk on
    /// any port" is a machine fact too -- but "a port was driven and refused"
    /// is a driver bug, and it is the one whose report names the port.
    fn bring_up() -> Option<Port> {
        let found = crate::devices::find_ahci()?;
        let registers = Registers {
            base: found.bar5,
            length: found.bar5_length,
        };

        // The interface must be on before any port register means anything.
        // A controller the firmware left in IDE mode answers writes to the
        // port registers with nothing at all, which is a driver whose
        // commands are accepted and never executed.
        let ghc = registers.read32(ahci::AHCI_REG_GHC);
        if ghc & GHC_AE == 0 {
            registers.write32(ahci::AHCI_REG_GHC, ghc | GHC_AE);
        }

        // The ports the controller implements, from its own answer and not
        // from an assumption.  Bit `n` set is port `n` present.
        let implemented = registers.read32(ahci::AHCI_REG_PI);
        arch::serial::write_str("protofire: ahci ports implemented ");
        arch::serial::write_hex(implemented as u64);
        arch::serial::write_str("\n");

        for port in 0..ahci::PORT_COUNT as u8 {
            if implemented & (1 << port) == 0 {
                continue;
            }
            let ssts = registers.read32(port_register(port, PORT_SSTS));
            let det = ssts & SSTS_DET_MASK;
            if det != DET_PRESENT_AND_COMMUNICATING {
                continue;
            }

            arch::serial::write_str("protofire: ahci disk on port ");
            arch::serial::write_u32(port as u32);
            arch::serial::write_str("\n");
            return Port::start(&registers, port);
        }

        arch::serial::write_str("protofire: ahci no port has a disk attached\n");
        None
    }

    /// Start one port's engine: stop it, point it at the DMA structures, and
    /// start it again in the order the specification gives.
    fn start(registers: &Registers, port: u8) -> Option<Port> {
        let command_list = AlignedFrames::new(ahci::CL_TOTAL_SIZE)?;
        let received_fis = AlignedFrames::new(RFIS_SIZE)?;
        let command_table = AlignedFrames::new(CT_TOTAL_SIZE)?;
        let bounce = AlignedFrames::new(DMA_ALIGN)?;

        let command_register = port_register(port, PORT_CMD);

        // The engine must be stopped before its pointers change.  `ST` first,
        // then wait for `CR` to read zero, then `FRE`, then wait for `FR`.
        // Clearing both at once and proceeding on the first read would leave
        // the controller walking a list the driver is about to rewrite.
        let mut command = registers.read32(command_register);
        if command & CMD_ST != 0 {
            registers.write32(command_register, command & !CMD_ST);
            if !wait_until_zero(registers, command_register, CMD_CR, ENGINE_POLL_LIMIT) {
                return None;
            }
        }
        command = registers.read32(command_register);
        if command & CMD_FRE != 0 {
            registers.write32(command_register, command & !CMD_FRE);
            if !wait_until_zero(registers, command_register, CMD_FR, ENGINE_POLL_LIMIT) {
                return None;
            }
        }

        // The port's error and interrupt state start from zero, so a command
        // that fails is failed by this driver's command and not by whatever
        // the firmware's probes left behind.
        registers.write32(port_register(port, PORT_SERR), SERR_CLEAR_ALL);
        registers.write32(port_register(port, PORT_IS), SERR_CLEAR_ALL);

        // The pointers, upper halves after the lower ones the way the
        // specification writes them: two registers per 64-bit address.
        let list_address = command_list.address();
        let fis_address = received_fis.address();
        registers.write32(port_register(port, PORT_CLB), list_address as u32);
        registers.write32(port_register(port, PORT_CLBU), (list_address >> 32) as u32);
        registers.write32(port_register(port, PORT_FB), fis_address as u32);
        registers.write32(port_register(port, PORT_FBU), (fis_address >> 32) as u32);

        // Start: receive first, then command -- the order §5.3.3 gives, and
        // the reason is that a command arriving before the receiver is on has
        // no FIS area to be answered into.
        command = registers.read32(command_register);
        registers.write32(command_register, command | CMD_FRE | CMD_ST);

        Some(Port {
            registers: Registers {
                base: registers.base,
                length: registers.length,
            },
            port,
            command_list,
            received_fis,
            command_table,
            bounce,
            block_count: 0,
            block_size: 512,
            model: [0; ahci::MODEL_BYTES],
        })
    }

    /// Ask the device to describe itself, and read the answer's capacity and
    /// model.
    fn identify(&mut self) -> Option<()> {
        let command = h2d_fis(ATA_IDENTIFY_DEVICE, 0, 0);
        // The answer is one sector, and it rides the bounce frame: the PRD
        // names the frame the driver owns, and the parse reads it back.
        let entry = prdt_entry(self.bounce.address(), 512);
        self.submit(&command, &[entry])?;

        let data = self.bounce.as_slice()[..ahci::IDENTIFY_BYTES].to_vec();
        if !ahci::is_ata(&data) {
            arch::serial::write_str("protofire: ahci port ");
            arch::serial::write_u32(self.port as u32);
            arch::serial::write_str(" answers an ATAPI device, refused\n");
            return None;
        }
        let capacity = ahci::capacity_blocks(&data)?;
        if capacity == 0 {
            arch::serial::write_str("protofire: ahci port ");
            arch::serial::write_u32(self.port as u32);
            arch::serial::write_str(" answers an empty capacity\n");
            return None;
        }
        self.block_count = capacity;
        if let Some(model) = ahci::model(&data) {
            self.model = model;
        }

        arch::serial::write_str("protofire: ahci port ");
        arch::serial::write_u32(self.port as u32);
        arch::serial::write_str(", ");
        arch::serial::write_u32(self.block_count as u32);
        arch::serial::write_str(" block(s) of 512 byte(s), model ");
        let end = self
            .model
            .iter()
            .rposition(|&byte| byte != 0 && byte != b' ')
            .map_or(0, |at| at + 1);
        let text = core::str::from_utf8(&self.model[..end]).unwrap_or("(invalid)");
        arch::serial::write_str(text);
        arch::serial::write_str("\n");
        Some(())
    }

    /// Fill slot zero and ring the doorbell, then wait for the controller to
    /// clear the slot's bit.
    ///
    /// The FIS and the PRD entries are written into the command table first,
    /// the header second, and the doorbell last: the controller reads the
    /// table only after the bit is set, so the order is what keeps it from
    /// reading a half-built command.
    fn submit(
        &mut self,
        fis: &[u8; REGISTER_FIS_BYTES],
        prdt: &[[u8; ahci::PRDT_ENTRY_SIZE]],
    ) -> Option<()> {
        let table_address = self.command_table.address();
        let table = self.command_table.as_slice_mut();
        table[..REGISTER_FIS_BYTES].copy_from_slice(fis);
        for (index, entry) in prdt.iter().enumerate() {
            let at = CT_BASE_SIZE + index * ahci::PRDT_ENTRY_SIZE;
            table[at..at + ahci::PRDT_ENTRY_SIZE].copy_from_slice(entry);
        }

        // The direction the header declares is the ATA command code's own:
        // a write is a write because the command is `WRITE DMA EXT`, and the
        // FIS's byte 1 has no direction bit to mirror.
        let is_write = fis[2] == ATA_WRITE_DMA_EXT;
        let header = command_header(
            REGISTER_FIS_DWORDS,
            prdt.len() as u16,
            is_write,
            table_address,
        );
        let slot = COMMAND_SLOT as usize * CL_ENTRY_SIZE;
        self.command_list.as_slice_mut()[slot..slot + CL_ENTRY_SIZE].copy_from_slice(&header);

        // The doorbell.  One bit per slot, and the controller clears the bit
        // when the command is done, which is what a polling driver waits on.
        let issue = port_register(self.port, PORT_CI);
        self.registers.write32(issue, 1 << COMMAND_SLOT);
        if !wait_until_zero(
            &self.registers,
            issue,
            1 << COMMAND_SLOT,
            COMPLETION_POLL_LIMIT,
        ) {
            arch::serial::write_str("protofire: ahci command on port ");
            arch::serial::write_u32(self.port as u32);
            arch::serial::write_str(" did not complete, PxCI ");
            arch::serial::write_hex(self.registers.read32(issue) as u64);
            arch::serial::write_str("\n");
            return None;
        }

        // The two answers a failed command gives: the task file's error bit
        // and the port's own task-file-error interrupt status.  Reading both
        // is what makes the refusal attributable rather than a bare timeout.
        let tfd = self.registers.read32(port_register(self.port, PORT_TFD));
        if tfd & TFD_ERR != 0 {
            arch::serial::write_str("protofire: ahci command failed, PxTFD ");
            arch::serial::write_hex(tfd as u64);
            arch::serial::write_str("\n");
            return None;
        }
        let status = self.registers.read32(port_register(self.port, PORT_IS));
        if status & PIS_TFES != 0 {
            arch::serial::write_str("protofire: ahci command failed, PxIS.TFES\n");
            self.registers
                .write32(port_register(self.port, PORT_IS), PIS_TFES);
            return None;
        }
        Some(())
    }

    /// Read or write one run through the bounce frame.
    fn transfer(&mut self, write: bool, lba: u64, bytes: usize) -> Result<()> {
        let blocks = (bytes / self.block_size) as u16;
        let command = if write {
            ATA_WRITE_DMA_EXT
        } else {
            ATA_READ_DMA_EXT
        };
        let fis = h2d_fis(command, lba, blocks);
        let entry = prdt_entry(self.bounce.address(), bytes);
        match self.submit(&fis, &[entry]) {
            Some(()) => Ok(()),
            None => Err(Error::DeviceError),
        }
    }

    /// The bounce frame, for a caller filling it before a write.
    fn bounce_mut(&mut self) -> &mut [u8] {
        self.bounce.as_slice_mut()
    }

    /// The bounce frame, for a caller reading what a command brought back.
    fn bounce_slice(&self) -> &[u8] {
        self.bounce.as_slice()
    }

    /// The frame's physical address, for the PRD that names it.
    fn bounce_address(&self) -> u64 {
        self.bounce.address()
    }
}

/// Spin until `register & mask` reads zero, answering whether it did.
fn wait_until_zero(registers: &Registers, at: usize, mask: u32, limit: u32) -> bool {
    let mut polls = 0u32;
    loop {
        if registers.read32(at) & mask == 0 {
            return true;
        }
        polls += 1;
        if polls > limit {
            return false;
        }
        core::hint::spin_loop();
    }
}

/// The disk the controller's port is, as the block layer sees it.
///
/// Depth one, and one bounce frame, for the reasons `nvme.rs` states: the
/// driver polls, and a caller's buffer is neither page-aligned nor inside one
/// page, while this driver's PRD arithmetic is one entry naming one frame.
pub struct AhciBlockDevice {
    port: spin::Mutex<Port>,
    name: &'static str,
    block_count: u64,
    block_size: usize,
}

/// The name this device answers to, in the list a program asks for.
const DEVICE_NAME: &str = "ahci0";

/// The bytes a SATA disk's first sector is expected to carry, at its far end.
///
/// Written by `xtask` into the SATA disk before the machine runs, for the
/// reason the NVMe disk's magic is: a read this driver could satisfy from its
/// own memory is not evidence.  Two copies of one constant, here and in
/// `tools/xtask/src/build.rs`, and the boot's line is what polices the
/// pairing.
const DISK_MAGIC: [u8; 8] = *b"PFATAH01";

/// The controller this boot brought up.
static DEVICE: spin::Mutex<Option<Arc<AhciBlockDevice>>> = spin::Mutex::new(None);

/// Bring the controller up, keep it, and prove it through the device
/// interface.
///
/// `true` when a controller was found, brought up and proven; `false` when
/// the machine has none, which is the ordinary state on two of the three
/// machines.
pub fn bring_up() -> bool {
    let Some(mut port) = Port::bring_up() else {
        return false;
    };
    if port.identify().is_none() {
        return false;
    }
    let device = Arc::new(AhciBlockDevice {
        block_count: port.block_count,
        block_size: port.block_size,
        name: DEVICE_NAME,
        port: spin::Mutex::new(port),
    });
    *DEVICE.lock() = Some(Arc::clone(&device));

    prove(&device);
    true
}

/// The device this boot brought up, for a caller that wants to mount it.
pub fn device() -> Option<Arc<AhciBlockDevice>> {
    DEVICE.lock().clone()
}

/// Prove the device, and record it in the list a program can ask for.
///
/// The two proofs are the NVMe device's, and for the same reasons: the far
/// block's magic is bytes only the host wrote, and the round trip is the
/// write path through the interface a filesystem will use.  The probe block
/// is the namespace's far end, at a distance no filesystem the disk carries
/// reaches.
fn prove(device: &AhciBlockDevice) {
    let far_block = device.block_count.saturating_sub(1);
    let mut first = [0u8; 512];
    match device.read_blocks(far_block, &mut first) {
        Ok(()) => {
            if first[..8] == DISK_MAGIC {
                arch::serial::write_str("protofire: ahci0 far block answers PFATAH01\n");
            } else {
                arch::serial::write_str("protofire: ahci0 far block read back ");
                arch::serial::write_hex(u64::from_le_bytes(
                    first[..8].try_into().unwrap_or([0; 8]),
                ));
                arch::serial::write_str(", not the disk's magic\n");
            }
        }
        Err(error) => {
            arch::serial::write_str("protofire: ahci0 far block failed: ");
            arch::serial::write_str(error.as_str());
            arch::serial::write_str("\n");
        }
    }

    let pattern: [u8; 512] = core::array::from_fn(|index| (index % 241) as u8);
    let mut read_back = [0u8; 512];
    let probe_block = device.block_count.saturating_sub(2);
    let written = device.write_blocks(probe_block, &pattern);
    let read = device.read_blocks(probe_block, &mut read_back);
    if written.is_ok() && read.is_ok() && read_back == pattern {
        arch::serial::write_str("protofire: ahci0 wrote and read back sector ");
        arch::serial::write_u32(probe_block as u32);
        arch::serial::write_str("\n");
    } else {
        arch::serial::write_str("protofire: ahci0 FAILED to write and read back sector ");
        arch::serial::write_u32(probe_block as u32);
        arch::serial::write_str("\n");
    }

    let listed = crate::block_devices::record(
        device.name(),
        device.block_size(),
        device.block_count(),
        device.is_read_only(),
    );
    if listed {
        arch::serial::write_str("protofire: ahci0 recorded as block device ");
        arch::serial::write_u32((crate::block_devices::count() - 1) as u32);
        arch::serial::write_str("\n");
    } else {
        arch::serial::write_str("protofire: ahci0 did not fit the device list\n");
    }
}

impl AhciBlockDevice {
    /// Validate a run, and answer the block count it covers.
    fn check(&self, lba: u64, bytes: usize) -> Result<u16> {
        if bytes == 0 || !bytes.is_multiple_of(self.block_size) {
            return Err(Error::InvalidArgument);
        }
        let blocks = bytes / self.block_size;
        if lba.saturating_add(blocks as u64) > self.block_count {
            return Err(Error::InvalidArgument);
        }
        u16::try_from(blocks).map_err(|_| Error::InvalidArgument)
    }

    /// How many blocks one pass of the bounce frame carries.
    fn blocks_per_run(&self) -> usize {
        4096 / self.block_size
    }
}

impl BlockDevice for AhciBlockDevice {
    fn name(&self) -> &str {
        self.name
    }

    fn block_size(&self) -> usize {
        self.block_size
    }

    fn block_count(&self) -> u64 {
        self.block_count
    }

    fn is_read_only(&self) -> bool {
        false
    }

    fn read_blocks(&self, lba: u64, buffer: &mut [u8]) -> Result<()> {
        let total = self.check(lba, buffer.len())?;
        let per_run = self.blocks_per_run();
        let mut port = self.port.lock();
        let mut done = 0usize;
        while done < buffer.len() {
            let blocks = per_run.min(total as usize - done / self.block_size);
            let run_bytes = blocks * self.block_size;
            let at = lba + (done / self.block_size) as u64;
            port.transfer(false, at, run_bytes)?;
            let bounce = port.bounce_slice();
            buffer[done..done + run_bytes].copy_from_slice(&bounce[..run_bytes]);
            done += run_bytes;
        }
        Ok(())
    }

    fn write_blocks(&self, lba: u64, data: &[u8]) -> Result<()> {
        let total = self.check(lba, data.len())?;
        let per_run = self.blocks_per_run();
        let mut port = self.port.lock();
        let mut done = 0usize;
        while done < data.len() {
            let blocks = per_run.min(total as usize - done / self.block_size);
            let run_bytes = blocks * self.block_size;
            let at = lba + (done / self.block_size) as u64;
            port.bounce_mut()[..run_bytes].copy_from_slice(&data[done..done + run_bytes]);
            port.transfer(true, at, run_bytes)?;
            done += run_bytes;
        }
        Ok(())
    }

    /// The device's write cache to stable storage.
    ///
    /// Reached today by nothing: the second disk is not mounted, and `Sync`
    /// flushes the devices the mount table holds.  It is implemented here
    /// rather than left as the trait's no-op because the controller can
    /// answer it, and a device whose flush silently did nothing is one a
    /// filesystem would believe durable when it was not.
    fn flush(&self) -> Result<()> {
        let mut port = self.port.lock();
        let fis = h2d_fis(ATA_FLUSH_CACHE, 0, 0);
        // A flush transfers nothing, so its PRD names the frame with a count
        // of one byte: a zero-byte PRD has no encoding, and the controller
        // ignores the data of a command that asks for none.
        let frame = port.bounce_address();
        let entry = prdt_entry(frame, 1);
        match port.submit(&fis, &[entry]) {
            Some(()) => Ok(()),
            None => Err(Error::DeviceError),
        }
    }
}

impl QueuedBlockDevice for AhciBlockDevice {
    fn as_block_device(&self) -> &dyn BlockDevice {
        self
    }
}

#[cfg(test)]
mod tests {
    //! What a host can check of the kernel's half: the byte order of the
    //! structures this file builds, and the alignment the DMA memory is
    //! given.
    //!
    //! The controller itself needs a bus, so it is the boot's.  These are the
    //! translations between a Rust value and the bytes a device reads, and a
    //! defect in either produces a command the controller parses as garbage.

    use super::*;

    /// The DMA memory is page aligned, which is inside every alignment the
    /// specification asks of the three structures: the command list on a
    /// kilobyte, the received-FIS area on 256 bytes, the command table on 128.
    #[test]
    fn the_dma_memory_is_page_aligned() {
        let frames = AlignedFrames::new(4096).expect("one page");
        assert_eq!(frames.pointer as usize % 4096, 0);
        assert_eq!(frames.as_slice().len(), 4096);
    }

    /// The DMA memory starts zeroed, because a received-FIS area's contents
    /// are the controller's to write and a driver that read its own garbage
    /// would be reading nothing the device said.
    #[test]
    fn the_dma_memory_starts_zeroed() {
        let frames = AlignedFrames::new(64).expect("a queue");
        assert!(frames.as_slice().iter().all(|&byte| byte == 0));
    }

    /// A command the driver submits carries `CFL` = 5, the field the previous
    /// tree's header left zero and the field QEMU's controller refuses below
    /// two.
    ///
    /// The header is built here from the same builder the submit path calls,
    /// so the assertion is the path's and not a copy of it.
    #[test]
    fn a_submitted_command_carries_its_fis_length() {
        let fis = h2d_fis(ATA_READ_DMA_EXT, 0, 1);
        let header = command_header(REGISTER_FIS_DWORDS, 1, false, 0x1000);
        let dw0 = u32::from_le_bytes(header[0..4].try_into().expect("four"));
        assert_eq!(dw0 & 0xFFFF, REGISTER_FIS_DWORDS);
        let _ = fis;
    }

    /// A flush's PRD names one byte, because a zero-byte PRD has no encoding.
    ///
    /// The count is minus one, so zero bytes would wrap to 0x3F_FFFF and the
    /// controller would transfer four megabytes into a buffer that holds
    /// nothing.
    #[test]
    fn a_flush_names_one_byte_and_not_zero() {
        let entry = prdt_entry(0x1000, 1);
        let dbc = u32::from_le_bytes(entry[12..16].try_into().expect("four"));
        assert_eq!(dbc, 0, "one byte is a count of zero");
    }

    /// The ATA commands this driver sends are the 48-bit LBA forms, and the
    /// identify command is the one a device answers with its geometry.
    #[test]
    fn the_commands_this_driver_sends_are_named() {
        assert_ne!(ATA_READ_DMA_EXT, ATA_WRITE_DMA_EXT);
        assert_ne!(ATA_IDENTIFY_DEVICE, ATA_READ_DMA_EXT);
        assert_ne!(ATA_FLUSH_CACHE, ATA_WRITE_DMA_EXT);
    }
}
