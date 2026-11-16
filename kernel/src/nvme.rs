//! kernel/src/nvme.rs
//!
//! Finding the controller, bringing it up, and proving it reads.
//!
//! ## Why the controller is here and the wire format is not
//!
//! `nvme` holds BAR0's registers, the two queue entries, the ring arithmetic
//! and the commands that create the queues, and it names nothing of this tree:
//! a host test drives every offset, every bit position and the whole phase walk
//! against an array.  What it cannot do is reach a device, and that needs a
//! BAR, an aligned allocation and a doorbell, which are the machine's.
//!
//! So this file is the controller: find the function on the bus, map BAR0,
//! reset it, point it at the admin queues, create an I/O pair, and read.  It is
//! the same split `framebuffer` makes against `vga`.
//!
//! ## The four defects this driver had, and where each is now checked
//!
//! One: the queues were allocated from a `Vec`, which has alignment one, and a
//! controller handed a misaligned ring answered `CSTS = 0x2` and never started.
//! `AlignedFrames` is what fixes it, and it is the only allocation here.
//!
//! Two: `Create I/O Submission Queue` was given `DW11` bit 1 on the belief it
//! was an enable bit.  It is `QPRIO`'s low bit, and QEMU's `nvme_create_sq`
//! validates only `PC`, so the bit changed nothing and the real defect survived
//! it.  The command builder no longer sets it, and its test asserts bits 2:1
//! are zero.
//!
//! Three: the I/O completion queue's doorbell was never written.  It is written
//! here, once, at the point the queue is filled.
//!
//! Four, and the one that took three rounds to find: `nvme::doorbell` computed
//! the wrong address, laying the array out as every submission bell followed by
//! every completion bell.  Queue 1's submission tail came out as `0x1004`,
//! which is completion queue 0's head, so the driver acknowledged a completion
//! on a queue nothing had posted to while the command sat unread.  The formula
//! is now the specification's and its test asserts that the two sets are
//! disjoint over every queue a controller can have.
//!
//! ## Why the first completion is the proof
//!
//! A queue pair that was created, a doorbell that was rung and a submission
//! that was accepted are three claims about what the driver did.  A completion
//! is the device's own word that it read the command and answered it, and the
//! data behind it is the fourth claim: that the transfer landed in the buffer
//! the driver named.  The boot's line reports all four as one sentence because
//! a reader wants the answer, and the reader can tell from the sentence which
//! part answered.

use alloc::alloc::Layout;
use alloc::alloc::alloc_zeroed;
use alloc::alloc::dealloc;
use alloc::sync::Arc;

use abi::Error;
use abi::Result;
use block::BlockDevice;
use block::QueuedBlockDevice;
use nvme::ADMIN_DELETE_IOCQ;
use nvme::ADMIN_DELETE_IOSQ;
use nvme::CAP_DSTRD_MASK;
use nvme::CAP_DSTRD_SHIFT;
use nvme::CAP_MQES_MASK;
use nvme::CC_EN;
use nvme::CNS_IDENTIFY_CONTROLLER;
use nvme::CNS_IDENTIFY_NAMESPACE;
use nvme::CSTS_RDY;
use nvme::CompletionQueue;
use nvme::NVME_PAGE_SIZE;
use nvme::NVME_REG_ACQ;
use nvme::NVME_REG_AQA;
use nvme::NVME_REG_ASQ;
use nvme::NVME_REG_CAP;
use nvme::NVME_REG_CC;
use nvme::NVME_REG_CSTS;
use nvme::NvmeCqe;
use nvme::NvmeSqe;
use nvme::SubmissionQueue;

/// The administrative queue pair is always queue zero.
const ADMIN_QUEUE: u16 = 0;

/// The first I/O queue pair a driver creates is queue one.
///
/// Zero is the admin pair, so a driver that created "its" queues at zero would
/// replace the pair it is talking through.
const IO_QUEUE: u16 = 1;

/// How many times the controller is asked whether it is ready before the boot
/// calls it dead.
///
/// A reset on real hardware takes milliseconds and this is a spin, not a sleep:
/// the count is the tree's other poll limits' order of magnitude, so a
/// controller that never answers costs a bounded moment rather than a boot.
const READY_POLL_LIMIT: u32 = 10_000_000;

/// How many times a command's completion is polled for before the wait fails.
const COMPLETION_POLL_LIMIT: u32 = 10_000_000;

/// A run of page-aligned frames, freed when it is dropped.
///
/// The controller reads its queues from physical memory at an address whose low
/// twelve bits are zero: the specification requires it, and a controller that
/// is handed anything else either refuses the command or reads the ring from
/// wherever the low bits happened to land.  `Vec` guarantees alignment one, and
/// that was the first defect this driver had.
///
/// The allocation is zeroed because a completion queue's phase tags are read
/// before anything writes them: a ring of uninitialised memory would have
/// arbitrary phase bits, and the driver's first poll would accept an entry the
/// controller never posted.
struct AlignedFrames {
    pointer: *mut u8,
    layout: Layout,
}

impl AlignedFrames {
    /// Allocate `bytes` zeroed at `NVME_PAGE_SIZE` alignment.
    fn new(bytes: usize) -> Option<Self> {
        let layout = Layout::from_size_align(bytes, NVME_PAGE_SIZE).ok()?;
        // SAFETY: `layout` has a non-zero size, which is the one requirement
        // `alloc_zeroed`'s contract places on the caller and the allocation
        // handed back is freed by the `Drop` below with the same layout.
        let pointer = unsafe { alloc_zeroed(layout) };
        if pointer.is_null() {
            return None;
        }
        Some(Self { pointer, layout })
    }

    /// The address the controller reads from.
    ///
    /// The boot runs identity-mapped, so the pointer is the physical address.
    /// [`crate::devices::physical_address`] is where that becomes a claim
    /// rather than an assumption, which is why it is called and not skipped.
    fn address(&self) -> u64 {
        crate::devices::physical_address(self.pointer as u64) as u64
    }

    /// The frames, as a slice.
    fn as_slice(&self) -> &[u8] {
        // SAFETY: the region is `layout.size()` bytes this type owns, and the
        // borrow is tied to `&self` so nothing frees it underneath.
        unsafe { core::slice::from_raw_parts(self.pointer, self.layout.size()) }
    }

    /// The frames, as a mutable slice.
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
// owner, and `Drop` frees it exactly once with the layout it was given.  Moving
// the struct moves that ownership, which is the whole of what `Send` asks.  It
// exists because the device sits behind an `Arc`, and a raw pointer is `!Send`
// by default whether or not anything shares it.
unsafe impl Send for AlignedFrames {}

/// BAR0, read and written a word at a time.
///
/// The registers are 32 and 64 bits.  A 64-bit read is two 32-bit reads for the
/// same reason the doorbell is a word: the controller's register block is a
/// device window, and a wider access than the specification names would be a
/// request the bus might not honour.
struct Registers {
    base: usize,
    length: usize,
}

impl Registers {
    fn read32(&self, offset: usize) -> u32 {
        assert!(offset + 4 <= self.length, "read past BAR0");
        // SAFETY: `offset` is inside the window the bus reported, and a
        // volatile read is what MMIO needs: the compiler must not fold two
        // reads of a register the controller may have changed.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u32) }
    }

    fn write32(&self, offset: usize, value: u32) {
        assert!(offset + 4 <= self.length, "write past BAR0");
        // SAFETY: as `read32`.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u32, value) }
    }

    fn read64(&self, offset: usize) -> u64 {
        assert!(offset + 8 <= self.length, "read past BAR0");
        // SAFETY: as `read32`, eight bytes wide.  The read is one 64-bit access
        // because `CAP` is one register, and two 32-bit reads could straddle a
        // device update.
        unsafe { core::ptr::read_volatile((self.base + offset) as *const u64) }
    }

    fn write64(&self, offset: usize, value: u64) {
        assert!(offset + 8 <= self.length, "write past BAR0");
        // SAFETY: as `read64`.
        unsafe { core::ptr::write_volatile((self.base + offset) as *mut u64, value) }
    }
}

/// A controller that is up, with one I/O queue pair and a namespace.
pub struct Controller {
    registers: Registers,
    /// `CAP`'s `DSTRD`, decoded once at probe.
    dstrd: u32,
    admin_submission: SubmissionQueue,
    admin_completion: CompletionQueue,
    io_submission: SubmissionQueue,
    io_completion: CompletionQueue,
    admin_submission_frames: AlignedFrames,
    admin_completion_frames: AlignedFrames,
    io_submission_frames: AlignedFrames,
    io_completion_frames: AlignedFrames,
    /// The namespace this driver reads.
    nsid: u32,
    block_count: u64,
    block_size: usize,
    /// The command id every submission takes, incremented per command.
    next_command_id: u16,
    /// The page every block transfer rides through, behind the same lock as the
    /// rings it is named in.
    bounce: AlignedFrames,
}

impl Controller {
    /// Find the controller on the bus, bring it up, and return it as a device.
    ///
    /// `None` on a machine with no controller, which is a normal state: the
    /// emulator's other two machines have no NVMe function, and a boot that
    /// refused to start because one was absent could not be debugged.
    ///
    /// Every step reports what it found rather than only that it succeeded,
    /// because the four defects this driver had were each invisible in a
    /// sentence that said "worked".
    fn bring_up() -> Option<Controller> {
        let found = crate::devices::find_nvme()?;

        let registers = Registers {
            base: found.bar0,
            length: found.bar0_length,
        };

        arch::serial::write_str("protofire: nvme at ");
        arch::serial::write_hex(found.bar0 as u64);
        arch::serial::write_str("\n");

        let cap = registers.read64(NVME_REG_CAP);
        let version = registers.read32(nvme::NVME_REG_VS);
        arch::serial::write_str("protofire: nvme capability ");
        arch::serial::write_hex(cap);
        arch::serial::write_str(", version ");
        arch::serial::write_u32(version & 0xFFFF);

        let dstrd = ((cap >> CAP_DSTRD_SHIFT) & CAP_DSTRD_MASK) as u32;
        let entries = nvme::queue_size(cap)?;
        arch::serial::write_str(", queues up to ");
        arch::serial::write_u32((cap & CAP_MQES_MASK) as u32 + 1);
        arch::serial::write_str(" entr(ies), stride ");
        arch::serial::write_u32(dstrd);
        arch::serial::write_str("\n");

        // Step 1: reset.  `CC.EN` to zero and wait for `CSTS.RDY` to clear.  A
        // controller the firmware left enabled is still reset here, because a
        // driver that took over a running controller would inherit queues it
        // knows nothing about.
        registers.write32(NVME_REG_CC, 0);
        if !wait_ready(&registers, false) {
            arch::serial::write_str("protofire: nvme did not reset\n");
            return None;
        }

        // Step 2: the queue memory, page aligned and zeroed.
        let submission_bytes = entries * nvme::SQE_SIZE;
        let completion_bytes = entries * nvme::CQE_SIZE;
        let admin_submission_frames = AlignedFrames::new(submission_bytes)?;
        let admin_completion_frames = AlignedFrames::new(completion_bytes)?;
        let io_submission_frames = AlignedFrames::new(submission_bytes)?;
        let io_completion_frames = AlignedFrames::new(completion_bytes)?;
        let bounce = AlignedFrames::new(NVME_PAGE_SIZE)?;

        // Step 3: the admin pair.  Both queues are the same size, which is why
        // one write sets both halves of `AQA`.
        let size_minus_one = (entries - 1) as u32;
        registers.write32(NVME_REG_AQA, size_minus_one | (size_minus_one << 16));
        registers.write64(NVME_REG_ASQ, admin_submission_frames.address());
        registers.write64(NVME_REG_ACQ, admin_completion_frames.address());

        // Step 4: enable.  `IOSQES` and `IOCQES` are the entry sizes as
        // powers of two: 6 for 64 bytes and 4 for 16.
        let cc = CC_EN | (6 << 16) | (4 << 20);
        registers.write32(NVME_REG_CC, cc);
        if !wait_ready(&registers, true) {
            arch::serial::write_str("protofire: nvme did not enable, CSTS ");
            arch::serial::write_hex(registers.read32(NVME_REG_CSTS) as u64);
            arch::serial::write_str("\n");
            return None;
        }

        let mut controller = Self {
            registers,
            dstrd,
            admin_submission: SubmissionQueue::new(entries)?,
            admin_completion: CompletionQueue::new(entries)?,
            io_submission: SubmissionQueue::new(entries)?,
            io_completion: CompletionQueue::new(entries)?,
            admin_submission_frames,
            admin_completion_frames,
            io_submission_frames,
            io_completion_frames,
            nsid: 1,
            block_count: 0,
            block_size: 0,
            next_command_id: 0,
            bounce,
        };

        // Step 5: identify.  The controller first, which says whether there is
        // a namespace at all, and then the namespace itself, which says how big
        // its blocks are.
        let identify_frames = AlignedFrames::new(nvme::IDENTIFY_CONTROLLER_SIZE)?;
        let command = nvme::queue::identify(CNS_IDENTIFY_CONTROLLER, 0, identify_frames.address());
        let cqe = controller.admin_command(&command)?;
        if !cqe.is_success() {
            arch::serial::write_str("protofire: nvme Identify Controller failed, status ");
            arch::serial::write_u32(cqe.status_code() as u32);
            arch::serial::write_str("\n");
            return None;
        }
        let count = nvme::namespace_count(identify_frames.as_slice())?;
        if count == 0 {
            arch::serial::write_str("protofire: nvme has no namespace\n");
            return None;
        }

        let command = nvme::queue::identify(
            CNS_IDENTIFY_NAMESPACE,
            controller.nsid,
            identify_frames.address(),
        );
        let cqe = controller.admin_command(&command)?;
        if !cqe.is_success() {
            arch::serial::write_str("protofire: nvme Identify Namespace failed, status ");
            arch::serial::write_u32(cqe.status_code() as u32);
            arch::serial::write_str("\n");
            return None;
        }
        let (blocks, block_size) = nvme::namespace_geometry(identify_frames.as_slice())?;
        controller.block_count = blocks;
        controller.block_size = block_size;
        arch::serial::write_str("protofire: nvme namespace ");
        arch::serial::write_u32(controller.nsid);
        arch::serial::write_str(", ");
        arch::serial::write_u32(blocks as u32);
        arch::serial::write_str(" block(s) of ");
        arch::serial::write_u32(block_size as u32);
        arch::serial::write_str(" byte(s)\n");

        // Step 6: create the I/O pair.  The completion queue first, because a
        // submission queue names the queue it posts to and a controller refuses
        // a submission queue that names one that does not exist.
        controller.create_io_queues(entries)?;

        // Step 7: the namespace's block size, against what this driver can
        // carry.  A block bigger than the bounce frame is a run the driver
        // cannot split, and a driver that accepted it would transfer past the
        // frame the command names.
        if block_size > NVME_PAGE_SIZE {
            arch::serial::write_str("protofire: nvme blocks of ");
            arch::serial::write_u32(block_size as u32);
            arch::serial::write_str(" byte(s) are bigger than a page, refused\n");
            return None;
        }

        Some(controller)
    }

    /// Create the I/O completion queue and then the submission queue.
    fn create_io_queues(&mut self, entries: usize) -> Option<()> {
        let completion = nvme::queue::create_completion_queue(
            IO_QUEUE,
            entries,
            self.io_completion_frames.address(),
            0,
            // No interrupt: this driver polls, which is what the tree's other
            // drivers do and what a machine with no vector to claim needs.
            false,
        );
        let cqe = self.admin_command(&completion)?;
        if !cqe.is_success() {
            arch::serial::write_str("protofire: nvme Create I/O CQ failed, status ");
            arch::serial::write_u32(cqe.status_code() as u32);
            arch::serial::write_str("\n");
            return None;
        }

        let submission = nvme::queue::create_submission_queue(
            IO_QUEUE,
            IO_QUEUE,
            entries,
            self.io_submission_frames.address(),
        );
        let cqe = self.admin_command(&submission)?;
        if !cqe.is_success() {
            arch::serial::write_str("protofire: nvme Create I/O SQ failed, status ");
            arch::serial::write_u32(cqe.status_code() as u32);
            arch::serial::write_str("\n");
            return None;
        }

        // The completion queue's head is reported once, at the point the queue
        // is empty and the driver knows where it will start reading.  A driver
        // that never wrote this had a queue the controller considered full from
        // the start, so every completion it posted was dropped.
        self.ring_completion(IO_QUEUE, &self.io_completion);

        arch::serial::write_str("protofire: nvme I/O queue pair up, ");
        arch::serial::write_u32(entries as u32);
        arch::serial::write_str(" entr(ies)\n");
        Some(())
    }

    /// Submit on the admin queue and wait for that command's completion.
    fn admin_command(&mut self, command: &NvmeSqe) -> Option<NvmeCqe> {
        let mut command = *command;
        command.set_command_id(self.take_command_id());

        let offset = self.admin_submission.tail_offset();
        let bytes = command_bytes(&command);
        self.admin_submission_frames.as_slice_mut()[offset..offset + bytes.len()]
            .copy_from_slice(&bytes);
        self.admin_submission.advance();
        self.ring_submission(ADMIN_QUEUE, self.admin_submission.doorbell_after_submit());

        let answered = self.wait_for(ADMIN_QUEUE, command.command_id());
        // The admin pair sends its completion head back as soon as the entry is
        // consumed, so the controller may post the next one.
        self.ring_completion(ADMIN_QUEUE, &self.admin_completion);
        answered
    }

    /// Submit on the I/O queue and wait for that command's completion.
    fn io_command(&mut self, command: &NvmeSqe) -> Option<NvmeCqe> {
        let mut command = *command;
        command.set_command_id(self.take_command_id());

        let offset = self.io_submission.tail_offset();
        let bytes = command_bytes(&command);
        self.io_submission_frames.as_slice_mut()[offset..offset + bytes.len()]
            .copy_from_slice(&bytes);
        self.io_submission.advance();
        self.ring_submission(IO_QUEUE, self.io_submission.doorbell_after_submit());

        let answered = self.wait_for(IO_QUEUE, command.command_id());
        self.ring_completion(IO_QUEUE, &self.io_completion);
        answered
    }

    /// Wait for the completion that names `command_id`.
    ///
    /// A completion for a different command is consumed and skipped: the
    /// controller answers in order, so this only happens if a previous wait
    /// left an entry behind, and dropping it is right either way because no
    /// caller is holding that request.
    fn wait_for(&mut self, queue: u16, command_id: u16) -> Option<NvmeCqe> {
        let mut polls = 0u32;
        loop {
            let head = match queue {
                ADMIN_QUEUE => self.admin_completion.head(),
                _ => self.io_completion.head(),
            };
            let offset = CompletionQueue::entry_offset(head);
            let frames = match queue {
                ADMIN_QUEUE => &self.admin_completion_frames,
                _ => &self.io_completion_frames,
            };
            let entry = read_completion(&frames.as_slice()[offset..offset + nvme::CQE_SIZE]);

            let taken = match queue {
                ADMIN_QUEUE => self.admin_completion.take(&entry),
                _ => self.io_completion.take(&entry),
            };
            if taken.is_some() {
                // The head moved, so the controller is told the entry is taken
                // before the next one is looked at.
                let ring = match queue {
                    ADMIN_QUEUE => self.admin_completion,
                    _ => self.io_completion,
                };
                self.ring_completion(queue, &ring);
                if entry.command_id == command_id {
                    return Some(entry);
                }
                continue;
            }

            polls += 1;
            if polls > COMPLETION_POLL_LIMIT {
                let head = match queue {
                    ADMIN_QUEUE => self.admin_completion.head(),
                    _ => self.io_completion.head(),
                };
                arch::serial::write_str("protofire: nvme command ");
                arch::serial::write_u32(command_id as u32);
                arch::serial::write_str(" did not complete, queue ");
                arch::serial::write_u32(queue as u32);
                arch::serial::write_str(" head ");
                arch::serial::write_u32(head as u32);
                arch::serial::write_str("\n");
                return None;
            }
            core::hint::spin_loop();
        }
    }

    /// Ring a submission queue's tail doorbell.
    fn ring_submission(&self, queue: u16, tail: u16) {
        let offset = nvme::doorbell(queue, false, self.dstrd);
        self.registers.write32(offset, tail as u32);
    }

    /// Ring a completion queue's head doorbell.
    fn ring_completion(&self, queue: u16, ring: &CompletionQueue) {
        let offset = nvme::doorbell(queue, true, self.dstrd);
        self.registers
            .write32(offset, ring.doorbell_after_take() as u32);
    }

    /// The next command id, wrapping.
    ///
    /// A `u16` that wraps is the field's own width, and a driver holding fewer
    /// than 65,536 requests in flight cannot have two live commands sharing
    /// one.
    fn take_command_id(&mut self) -> u16 {
        let id = self.next_command_id;
        self.next_command_id = self.next_command_id.wrapping_add(1);
        id
    }
}

impl Controller {
    /// The transfer frame, for a caller filling it before a write.
    fn bounce_mut(&mut self) -> &mut [u8] {
        self.bounce.as_slice_mut()
    }

    /// The transfer frame, for a caller reading what a command brought back.
    fn bounce_slice(&self) -> &[u8] {
        self.bounce.as_slice()
    }

    /// The frame's physical address, for the command that names it.
    fn bounce_address(&self) -> u64 {
        self.bounce.address()
    }
}

impl Drop for Controller {
    /// Delete the I/O queues on the way out.
    ///
    /// A controller left with queues the driver no longer owns is one whose
    /// next driver inherits rings it has no memory for.  The result is not
    /// checked: a machine that is shutting down cannot be told anything, and a
    /// controller that refused to delete a queue is one the next reset will
    /// clear anyway.
    fn drop(&mut self) {
        let mut delete = NvmeSqe::zeroed();
        delete.set_opcode(ADMIN_DELETE_IOSQ);
        delete.set_cdw10(IO_QUEUE as u32);
        let _ = self.admin_command(&delete);
        delete.set_opcode(ADMIN_DELETE_IOCQ);
        let _ = self.admin_command(&delete);
    }
}

/// The 64 bytes of a command, as they go into the ring.
fn command_bytes(command: &NvmeSqe) -> [u8; nvme::SQE_SIZE] {
    let mut bytes = [0u8; nvme::SQE_SIZE];
    for (index, word) in bytes.as_chunks_mut::<4>().0.iter_mut().enumerate() {
        *word = command.word(index).to_le_bytes();
    }
    bytes
}

/// Read the 16 bytes of a completion entry.
fn read_completion(bytes: &[u8]) -> NvmeCqe {
    let word = |at: usize| {
        let mut word = [0u8; 4];
        word.copy_from_slice(&bytes[at..at + 4]);
        u32::from_le_bytes(word)
    };
    let half = |at: usize| {
        let mut half = [0u8; 2];
        half.copy_from_slice(&bytes[at..at + 2]);
        u16::from_le_bytes(half)
    };
    NvmeCqe {
        dw0: word(0),
        reserved: word(4),
        sq_head: half(8),
        sq_id: half(10),
        command_id: half(12),
        status: half(14),
    }
}

/// Spin until `CSTS.RDY` matches `ready`, answering whether it did.
fn wait_ready(registers: &Registers, ready: bool) -> bool {
    let mut polls = 0u32;
    loop {
        let csts = registers.read32(NVME_REG_CSTS);
        if (csts & CSTS_RDY != 0) == ready {
            return true;
        }
        polls += 1;
        if polls > READY_POLL_LIMIT {
            return false;
        }
        core::hint::spin_loop();
    }
}

/// The disk the controller's namespace is, as the block layer sees it.
///
/// One device of **depth one**: every read and write runs to completion before
/// it returns, which is the shape [`block`] gives a device that has nothing to
/// pipeline behind.  The virtio disk queues and this one does not, and the
/// difference is a property of the drivers rather than of the bus: NVMe's own
/// rings are deep, but driving more than one command at a time wants a ticket
/// per request and an interrupt to wake on, and this driver polls.
///
/// Every transfer rides one page-aligned frame.  The controller reads and
/// writes DMA memory by physical address, and a caller's buffer is neither
/// page-aligned nor guaranteed to sit inside one page, so a transfer that is
/// neither would need a PRP list to describe it.  Bouncing through a frame
/// costs a copy and buys a driver whose PRP arithmetic is always `PRP1` alone,
/// which is the arithmetic the host tests check.
pub struct NvmeBlockDevice {
    controller: spin::Mutex<Controller>,
    name: &'static str,
    nsid: u32,
    block_count: u64,
    block_size: usize,
}

/// The name this device answers to.
///
/// `nvme0n1` is the shape a program matches on, and it is the same string the
/// device list's own tests use.
const DEVICE_NAME: &str = "nvme0n1";

/// What the disk's first block is expected to say.
///
/// Written by `xtask` into the NVMe disk before the machine runs, for the same
/// reason the volume's label is written there: a read this driver could satisfy
/// from its own memory is not evidence.  Two copies of one constant, here and
/// in `tools/xtask/src/build.rs`, and the boot's line is what polices the
/// pairing.
const DISK_MAGIC: [u8; 8] = *b"PFNVME01";

/// The controller this boot brought up, and the reason it outlives the boot's
/// own function.
///
/// `kernel_main` runs for the machine's whole life, but a local that outlives
/// its scope only by convention is a local that will be dropped the day the
/// boot is restructured.  A `static` says the device stays up in words, and
/// [`device`] is how the next step -- a namespace mounted over it -- reaches
/// it.
static DEVICE: spin::Mutex<Option<Arc<NvmeBlockDevice>>> = spin::Mutex::new(None);

/// Bring the controller up, keep it, and prove it through the device interface.
///
/// `true` when a controller was found, brought up and proven; `false` when the
/// machine has none, which is the ordinary state on two of the three machines.
pub fn bring_up() -> bool {
    let Some(controller) = Controller::bring_up() else {
        return false;
    };
    let device = Arc::new(NvmeBlockDevice {
        nsid: controller.nsid,
        block_count: controller.block_count,
        block_size: controller.block_size,
        name: DEVICE_NAME,
        controller: spin::Mutex::new(controller),
    });
    *DEVICE.lock() = Some(Arc::clone(&device));

    prove(&device);
    true
}

/// The device this boot brought up, for a caller that wants to mount it.
///
/// `None` on a machine with no controller and on one whose controller refused
/// to come up, which are different states the boot's own lines tell apart.
pub fn device() -> Option<Arc<NvmeBlockDevice>> {
    DEVICE.lock().clone()
}

/// Prove the device, and record it in the list a program can ask for.
///
/// Two proofs, and they answer different doubts.  The first reads a block the
/// **host** wrote before the machine ran, which nothing in this boot could have
/// written: if the bytes come back, the whole path from the device's own disk
/// through the controller, the queues and the DMA transfer into the driver's
/// frame happened.  The second writes a pattern and reads it back through the
/// same interface a filesystem will use, which is the proof the **write** path
/// works, and through [`NvmeBlockDevice`] rather than through a raw command so
/// the code that is proven is the code a caller runs.
fn prove(device: &NvmeBlockDevice) {
    let mut first = [0u8; 512];
    match device.read_blocks(0, &mut first) {
        Ok(()) => {
            if first[..8] == DISK_MAGIC {
                arch::serial::write_str("protofire: nvme0n1 block 0 answers PFNVME01\n");
            } else {
                arch::serial::write_str("protofire: nvme0n1 block 0 read back ");
                arch::serial::write_hex(u64::from_le_bytes(
                    first[..8].try_into().unwrap_or([0; 8]),
                ));
                arch::serial::write_str(", not the disk's magic\n");
            }
        }
        Err(error) => {
            arch::serial::write_str("protofire: nvme0n1 block 0 failed: ");
            arch::serial::write_str(error.as_str());
            arch::serial::write_str("\n");
        }
    }

    let pattern: [u8; 512] = core::array::from_fn(|index| (index % 251) as u8);
    let mut read_back = [0u8; 512];
    let last_block = device.block_count.saturating_sub(1);
    let written = device.write_blocks(last_block, &pattern);
    let read = device.read_blocks(last_block, &mut read_back);
    if written.is_ok() && read.is_ok() && read_back == pattern {
        arch::serial::write_str("protofire: nvme0n1 wrote and read back sector ");
        arch::serial::write_u32(last_block as u32);
        arch::serial::write_str("\n");
    } else {
        arch::serial::write_str("protofire: nvme0n1 FAILED to write and read back sector ");
        arch::serial::write_u32(last_block as u32);
        arch::serial::write_str("\n");
    }

    // Recorded after the proof, so a device that cannot transfer is a device
    // the list does not name: a program asking for index 1 would otherwise
    // hear about a disk it cannot read.
    let listed = crate::block_devices::record(
        device.name(),
        device.block_size(),
        device.block_count(),
        device.is_read_only(),
    );
    if listed {
        arch::serial::write_str("protofire: nvme0n1 recorded as block device ");
        arch::serial::write_u32((crate::block_devices::count() - 1) as u32);
        arch::serial::write_str("\n");
    } else {
        arch::serial::write_str("protofire: nvme0n1 did not fit the device list\n");
    }
}

impl NvmeBlockDevice {
    /// Validate a run, and answer the block count it covers.
    ///
    /// The block layer's contract is that a buffer is a whole number of blocks
    /// and covers them all, and the same check as every other device's: a run
    /// past the end would transfer into blocks the namespace does not have,
    /// which on a real controller is a write to whoever owns them.
    fn check(&self, lba: u64, bytes: usize) -> Result<u32> {
        if bytes == 0 || !bytes.is_multiple_of(self.block_size) {
            return Err(Error::InvalidArgument);
        }
        let blocks = bytes / self.block_size;
        if lba.saturating_add(blocks as u64) > self.block_count {
            return Err(Error::InvalidArgument);
        }
        Ok(blocks as u32)
    }

    /// How many blocks one pass of the bounce frame carries.
    ///
    /// The frame is the controller's, and its length is fixed at one page, so
    /// the number is a division and not a state the lock would have to guard.
    fn blocks_per_run(&self) -> u32 {
        (NVME_PAGE_SIZE / self.block_size) as u32
    }
}

impl BlockDevice for NvmeBlockDevice {
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
        let mut controller = self.controller.lock();
        let mut done = 0u32;
        while done < total {
            let blocks = per_run.min(total - done);
            let run_bytes = blocks as usize * self.block_size;
            let at = lba + done as u64;
            let command = nvme::queue::read(self.nsid, at, blocks, controller.bounce_address(), 0);
            let cqe = controller.io_command(&command).ok_or(Error::TimedOut)?;
            if !cqe.is_success() {
                return Err(Error::DeviceError);
            }
            buffer[done as usize * self.block_size..done as usize * self.block_size + run_bytes]
                .copy_from_slice(&controller.bounce_slice()[..run_bytes]);
            done += blocks;
        }
        Ok(())
    }

    fn write_blocks(&self, lba: u64, data: &[u8]) -> Result<()> {
        let total = self.check(lba, data.len())?;
        let per_run = self.blocks_per_run();
        let mut controller = self.controller.lock();
        let mut done = 0u32;
        while done < total {
            let blocks = per_run.min(total - done);
            let run_bytes = blocks as usize * self.block_size;
            let at = lba + done as u64;
            controller.bounce_mut()[..run_bytes]
                .copy_from_slice(&data[done as usize * self.block_size..][..run_bytes]);
            let command = nvme::queue::write(self.nsid, at, blocks, controller.bounce_address(), 0);
            let cqe = controller.io_command(&command).ok_or(Error::TimedOut)?;
            if !cqe.is_success() {
                return Err(Error::DeviceError);
            }
            done += blocks;
        }
        Ok(())
    }

    /// The namespace's write cache to stable storage.
    ///
    /// Reached today by nothing: the mount this boot does is virtio's, and
    /// `Sync` flushes the devices the mount table holds.  It is implemented
    /// here rather than left as the trait's no-op because the controller can
    /// answer it, and a device whose flush silently did nothing is one a
    /// filesystem would believe durable when it was not.
    fn flush(&self) -> Result<()> {
        let mut controller = self.controller.lock();
        let command = nvme::queue::flush(self.nsid);
        let cqe = controller.io_command(&command).ok_or(Error::TimedOut)?;
        if !cqe.is_success() {
            return Err(Error::DeviceError);
        }
        Ok(())
    }
}

impl QueuedBlockDevice for NvmeBlockDevice {
    fn as_block_device(&self) -> &dyn BlockDevice {
        self
    }
}

#[cfg(test)]
mod tests {
    //! What a host can check of the kernel's half: the byte order of a command
    //! and of a completion, and the alignment the queue memory is given.
    //!
    //! The controller itself needs a bus, so it is the boot's.  These are the
    //! two translations between a Rust value and the bytes a device reads, and
    //! a defect in either produces a command the controller parses as garbage.

    use super::*;
    use nvme::NVM_READ;

    extern crate std;

    /// A command's bytes are its words, little endian, in order.
    ///
    /// The ring holds bytes and the controller reads words from it, so a
    /// driver that wrote the struct's own memory would be relying on the
    /// layout matching, which it does here only by coincidence.
    #[test]
    fn a_command_is_written_as_its_words_little_endian() {
        let command = nvme::queue::read(1, 0x1122_3344_5566_7788, 1, 0x9000, 0);
        let bytes = command_bytes(&command);
        assert_eq!(bytes.len(), nvme::SQE_SIZE);

        // Opcode in the first byte.
        assert_eq!(bytes[0], NVM_READ);
        // NSID is word 1.
        assert_eq!(&bytes[4..8], &1u32.to_le_bytes());
        // CDW10 and CDW11 are the LBA, low half first.
        assert_eq!(&bytes[40..44], &0x5566_7788u32.to_le_bytes());
        assert_eq!(&bytes[44..48], &0x1122_3344u32.to_le_bytes());
        // CDW12 is the count minus one.
        assert_eq!(&bytes[48..52], &0u32.to_le_bytes());
        // PRP1 is words 6 and 7.
        assert_eq!(&bytes[24..28], &0x9000u32.to_le_bytes());
        assert_eq!(&bytes[28..32], &0u32.to_le_bytes());
    }

    /// A completion's fields are read from the offsets the specification names.
    ///
    /// The phase bit lives in the status word's low bit, and a reader that
    /// took the status first would see a success as an error half the time,
    /// which is a defect this tree's `NvmeCqe` exists to not repeat.
    #[test]
    fn a_completion_is_read_from_its_sixteen_bytes() {
        let mut bytes = [0u8; nvme::CQE_SIZE];
        bytes[0..4].copy_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        bytes[8..10].copy_from_slice(&3u16.to_le_bytes());
        bytes[10..12].copy_from_slice(&1u16.to_le_bytes());
        bytes[12..14].copy_from_slice(&0x0042u16.to_le_bytes());
        // Status code 2, phase set.
        bytes[14..16].copy_from_slice(&((2u16 << 1) | 1).to_le_bytes());

        let entry = read_completion(&bytes);
        assert_eq!(entry.dw0, 0xDEAD_BEEF);
        assert_eq!(entry.sq_head, 3);
        assert_eq!(entry.sq_id, 1);
        assert_eq!(entry.command_id, 0x0042);
        assert_eq!(entry.status_code(), 2);
        assert!(entry.phase());
        assert!(!entry.is_success());
    }

    /// The queue memory is page aligned, which is the first defect's assertion.
    ///
    /// A `Vec` has alignment one, and a controller handed a misaligned ring
    /// answered `CSTS = 0x2` and never started.  This checks the alignment of
    /// what the allocation actually returns, not of the type's declaration.
    #[test]
    fn the_queue_memory_is_page_aligned() {
        let frames = AlignedFrames::new(4096).expect("one page");
        assert_eq!(
            frames.pointer as usize % NVME_PAGE_SIZE,
            0,
            "the controller reads the ring from this address"
        );
        assert_eq!(frames.as_slice().len(), 4096);
    }

    /// The queue memory is zeroed, because a completion ring's phase tags are
    /// read before anything writes them.
    #[test]
    fn the_queue_memory_starts_zeroed() {
        let frames = AlignedFrames::new(64).expect("a queue");
        assert!(frames.as_slice().iter().all(|&byte| byte == 0));
    }
}
