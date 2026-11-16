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
}

/// What a probe learned, for the boot's lines.
#[derive(Debug, Clone, Copy)]
pub struct Report {
    pub bar0: u64,
    pub version: u32,
    pub nsid: u32,
    pub block_count: u64,
    pub block_size: usize,
    pub queue_entries: usize,
    /// Whether the read came back with the bytes that were written first.
    pub round_trip: bool,
    /// The first eight bytes read from block zero, so a line can say what was
    /// there rather than only that something was.
    pub first_bytes: [u8; 8],
}

impl Controller {
    /// Find the controller on the bus, bring it up, and read a block.
    ///
    /// `None` on a machine with no controller, which is a normal state: the
    /// emulator's other two machines have no NVMe function, and a boot that
    /// refused to start because one was absent could not be debugged.
    ///
    /// Every step reports what it found rather than only that it succeeded,
    /// because the four defects this driver had were each invisible in a
    /// sentence that said "worked".
    pub fn probe() -> Option<Report> {
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

        // Step 7: read.  A read of block zero is the proof: the driver created
        // the queues, the controller read a command from one and wrote a
        // completion to the other, and the data is in the buffer the driver
        // named.
        let data = AlignedFrames::new(NVME_PAGE_SIZE)?;
        let command = nvme::queue::read(controller.nsid, 0, 1, data.address(), 0);
        let cqe = controller.io_command(&command)?;
        let mut first_bytes = [0u8; 8];
        if cqe.is_success() {
            first_bytes.copy_from_slice(&data.as_slice()[..8]);
        } else {
            arch::serial::write_str("protofire: nvme read failed, status ");
            arch::serial::write_u32(cqe.status_code() as u32);
            arch::serial::write_str("\n");
        }

        Some(Report {
            bar0: found.bar0 as u64,
            version,
            nsid: controller.nsid,
            block_count: controller.block_count,
            block_size: controller.block_size,
            queue_entries: entries,
            round_trip: cqe.is_success(),
            first_bytes,
        })
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

/// The names the boot's lines spell, so the gate and the probe cannot drift.
pub const REPORT_PREFIX: &str = "protofire: nvme identified, namespace ";

/// A boot line that says the read happened and what it read.
///
/// The first eight bytes are printed as one word rather than as eight
/// `write_hex` calls: `write_hex` puts `0x` in front of its value, and eight of
/// them read as eight numbers where this is one.
pub fn report_read(report: &Report) {
    arch::serial::write_str(REPORT_PREFIX);
    arch::serial::write_u32(report.nsid);
    arch::serial::write_str(" of ");
    arch::serial::write_u32(report.block_count as u32);
    arch::serial::write_str(" block(s), first block starts ");
    arch::serial::write_hex(u64::from_le_bytes(report.first_bytes));
    arch::serial::write_str("\n");
}

/// The controller's own record, for anything that wants to drive it later.
///
/// Nothing does yet: a block device over NVMe needs a run buffer per request
/// and a namespace that is mounted, and the mount this boot does is virtio's.
/// The probe is what proves the driver, and the type is here because the next
/// step is to hand it to [`block`] rather than to print a line.
pub struct Found {
    pub controller: Arc<spin::Mutex<Controller>>,
    pub report: Report,
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
