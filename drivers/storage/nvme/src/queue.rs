//! drivers/storage/nvme/src/queue.rs
//!
//! Where a ring's entries are, how far around it the driver has walked, and the
//! commands that create the pair.
//!
//! ## Why the walk is here and not in the controller
//!
//! Three of the four defects this driver has had were arithmetic rather than
//! plumbing: a base address that was not page aligned, a doorbell that named
//! another queue, and -- the one that took longest -- a completion ring walked
//! by a counter when the hardware tracks it by phase.  A counter works until
//! the ring wraps once and then it does not, so it is a defect that a boot with
//! light traffic never shows.
//!
//! All three are pure arithmetic over numbers, so all three can be checked on a
//! host.  What cannot is mapping BAR0 and writing a doorbell, and that is the
//! kernel's file.
//!
//! ## The phase bit, stated once
//!
//! A completion entry carries a phase tag that flips every time the ring wraps.
//! The driver keeps the phase it expects, and an entry belongs to it when the
//! entry's tag equals the expected one.  An entry left over from the previous
//! pass has the other tag and is skipped with no bookkeeping at all -- which is
//! exactly why a head counter is wrong: it counts entries rather than deciding
//! which pass each one belongs to.

use crate::command::CQE_SIZE;
use crate::command::NvmeCqe;
use crate::command::NvmeSqe;
use crate::command::SQE_SIZE;
use crate::registers::ADMIN_CREATE_IOCQ;
use crate::registers::ADMIN_CREATE_IOSQ;
use crate::registers::ADMIN_IDENTIFY;
use crate::registers::CAP_MQES_MASK;
use crate::registers::DEFAULT_QUEUE_SIZE;
use crate::registers::NVM_FLUSH;
use crate::registers::NVM_READ;
use crate::registers::NVM_WRITE;

/// How many entries a driver should ask for, given the controller's `CAP`.
///
/// `CAP.MQES` is "the most entries a queue may have, minus one", so a
/// controller that answers zero supports one entry and a queue of two is one it
/// refuses. The answer is the smaller of what a boot wants and what the device
/// allows, and `None` when the device allows nothing a driver can use: a
/// controller whose maximum is zero cannot hold the single admin command it
/// takes to learn anything about itself.
pub fn queue_size(cap: u64) -> Option<usize> {
    let most = (cap & CAP_MQES_MASK) as usize + 1;
    if most < 2 {
        return None;
    }
    Some(most.min(DEFAULT_QUEUE_SIZE))
}

/// A submission queue: where the next command goes, and how big the ring is.
///
/// The driver owns the tail; the controller owns the head, and a driver that
/// kept its own idea of the head would be disagreeing with the only authority
/// there is.  So this type tracks one number and the size, and the completion
/// ring tracks the other end.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SubmissionQueue {
    entries: usize,
    tail: usize,
}

impl SubmissionQueue {
    /// A ring of `entries` entries, starting at the beginning.
    ///
    /// `None` for fewer than two entries: a ring of one has no wrap, so the
    /// distinction between full and empty is gone and the tail's value can no
    /// longer say anything.
    pub fn new(entries: usize) -> Option<Self> {
        if entries < 2 {
            return None;
        }
        Some(Self { entries, tail: 0 })
    }

    /// How many entries the ring has.
    pub fn entries(&self) -> usize {
        self.entries
    }

    /// The byte offset of `slot`, inside the ring's own memory.
    ///
    /// The controller reads 64-byte entries from the queue's base address, so
    /// the offset is the slot's index times that size and nothing else.
    pub fn entry_offset(slot: usize) -> usize {
        slot * SQE_SIZE
    }

    /// The byte offset the next command goes at.
    pub fn tail_offset(&self) -> usize {
        Self::entry_offset(self.tail)
    }

    /// Where the next command goes, as a ring index.
    pub fn tail(&self) -> usize {
        self.tail
    }

    /// The value a tail doorbell is rung with, after the command is written.
    ///
    /// A doorbell carries the **new** tail, which is the slot *after* the
    /// command just written.  A driver that rang the slot it wrote tells the
    /// controller the queue still ends before that command, so the command is
    /// never read and the wait times out with nothing naming why.
    pub fn doorbell_after_submit(&self) -> u16 {
        self.tail as u16
    }

    /// Move to the next slot, wrapping at the end.
    pub fn advance(&mut self) {
        self.tail += 1;
        if self.tail == self.entries {
            self.tail = 0;
        }
    }
}

/// A completion queue: which entry the driver is looking at, and which pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompletionQueue {
    entries: usize,
    head: usize,
    /// The phase tag the driver expects.  It flips on every wrap.
    phase: bool,
}

impl CompletionQueue {
    /// A ring of `entries` entries, expecting the controller's first pass.
    ///
    /// A freshly created completion queue is initialised to all zeroes, so
    /// every entry's phase tag reads zero and the driver expects a **set** tag.
    /// That is not a convention this driver chose: it is what makes the first
    /// entry the controller writes distinguishable from the zeroed memory
    /// around it.
    pub fn new(entries: usize) -> Option<Self> {
        if entries < 2 {
            return None;
        }
        Some(Self {
            entries,
            head: 0,
            phase: true,
        })
    }

    /// How many entries the ring has.
    pub fn entries(&self) -> usize {
        self.entries
    }

    /// The byte offset of `slot`, inside the ring's own memory.
    pub fn entry_offset(slot: usize) -> usize {
        slot * CQE_SIZE
    }

    /// The byte offset the driver is looking at.
    pub fn head_offset(&self) -> usize {
        Self::entry_offset(self.head)
    }

    /// The ring index the driver is looking at.
    pub fn head(&self) -> usize {
        self.head
    }

    /// The phase the driver is waiting for.
    pub fn phase(&self) -> bool {
        self.phase
    }

    /// Whether `entry` was written in the pass the driver is looking for.
    ///
    /// This is the whole of the walk.  A zeroed entry has phase clear, and the
    /// first pass expects it set, so an entry nothing has written is refused
    /// without the driver knowing how many entries the ring has.
    pub fn is_new(&self, entry: &NvmeCqe) -> bool {
        entry.phase() == self.phase
    }

    /// Consume the entry the driver is looking at, and move on.
    ///
    /// `None` when the entry belongs to another pass, which is "nothing has
    /// arrived" and not an error: it is the ordinary state of a queue whose
    /// command has not finished.
    pub fn take(&mut self, entry: &NvmeCqe) -> Option<NvmeCqe> {
        if !self.is_new(entry) {
            return None;
        }
        let answered = *entry;
        self.head += 1;
        if self.head == self.entries {
            self.head = 0;
            self.phase = !self.phase;
        }
        Some(answered)
    }

    /// The value a head doorbell is rung with, after an entry is consumed.
    pub fn doorbell_after_take(&self) -> u16 {
        self.head as u16
    }
}

/// `Create I/O Completion Queue`: `DW10` and `DW11`.
///
/// The command's fields, per NVMe 1.0 §5.4:
///
/// ```text
/// DW10: bits 15:0  QID
///       bits 31:16 QSIZE, which is the entry count **minus one**
/// DW11: bit  0     PC   -- physically contiguous
///       bit  1     IEN  -- raise an interrupt when an entry is posted
///       bits 31:16 IV   -- the interrupt vector
/// ```
///
/// The `PRP1` is the queue's base address, and it **must be page aligned**: a
/// controller that is handed a misaligned ring answers `Invalid PRP Offset` or,
/// on a controller that validates less, reads entries from wherever the low
/// bits landed.
pub fn create_completion_queue(
    cqid: u16,
    entries: usize,
    address: u64,
    vector: u16,
    interrupts: bool,
) -> NvmeSqe {
    let mut command = NvmeSqe::zeroed();
    command.set_opcode(ADMIN_CREATE_IOCQ);
    command.set_prp1(address);
    let size_minus_one = entries.saturating_sub(1) as u32;
    command.set_cdw10((cqid as u32) | (size_minus_one << 16));
    // PC is required: a queue that is not physically contiguous is one the
    // controller has to walk a list for, which nothing here builds.
    let mut flags = CREATE_PC;
    if interrupts {
        flags |= CREATE_CQ_IEN;
    }
    command.set_cdw11(flags | ((vector as u32) << 16));
    command
}

/// `Create I/O Submission Queue`: `DW10` and `DW11`.
///
/// ```text
/// DW10: bits 15:0  QID
///       bits 31:16 QSIZE, which is the entry count **minus one**
/// DW11: bit  0     PC     -- physically contiguous
///       bits 2:1   QPRIO  -- the queue's priority
///       bits 31:16 CQID   -- the completion queue this one posts to
/// ```
///
/// **There is no enable bit.**  A previous attempt at this driver set `DW11`
/// bit 1 on the belief that it was `EN`, and recorded that the queue then
/// worked.  The bit is `QPRIO`'s low bit, so the change made the queue urgent
/// rather than enabled, and QEMU's own `nvme_create_sq` validates only `PC` --
/// it never reads bits 2:1 at all.  The claim survives in the roadmap because a
/// bit that changes nothing is indistinguishable from a bit that fixes
/// something when the real defect is still there.
pub fn create_submission_queue(sqid: u16, cqid: u16, entries: usize, address: u64) -> NvmeSqe {
    let mut command = NvmeSqe::zeroed();
    command.set_opcode(ADMIN_CREATE_IOSQ);
    command.set_prp1(address);
    let size_minus_one = entries.saturating_sub(1) as u32;
    command.set_cdw10((sqid as u32) | (size_minus_one << 16));
    command.set_cdw11(CREATE_PC | ((cqid as u32) << 16));
    command
}

/// `DW11` bit 0: the queue is physically contiguous.
pub const CREATE_PC: u32 = 1 << 0;

/// `Create I/O Completion Queue`'s `DW11` bit 1: post a completion interrupt.
pub const CREATE_CQ_IEN: u32 = 1 << 1;

/// `Identify`: ask the controller or a namespace to describe itself.
///
/// `CNS` picks which structure is asked for and lands in `DW10`'s low byte; a
/// namespace is named in `NSID`, and `Identify Controller` passes zero there
/// because the controller is not a namespace.
pub fn identify(cns: u32, nsid: u32, address: u64) -> NvmeSqe {
    let mut command = NvmeSqe::zeroed();
    command.set_opcode(ADMIN_IDENTIFY);
    command.set_nsid(nsid);
    command.set_prp1(address);
    command.set_cdw10(cns);
    command
}

/// A read or a write of a run of blocks, from one physical buffer.
///
/// `CDW10`/`CDW11` are the 64-bit starting LBA, low half first, and `CDW12`'s
/// low sixteen bits are the block count **minus one**.  A run of `blocks` that
/// covered one more block than asked would write past the caller's buffer, so
/// the count and the buffer have to agree and that is the caller's contract.
pub fn run(opcode: u8, nsid: u32, lba: u64, blocks: u32, prp1: u64, prp2: u64) -> NvmeSqe {
    debug_assert!(blocks > 0, "a run of zero blocks has no encoding");
    let mut command = NvmeSqe::zeroed();
    command.set_opcode(opcode);
    command.set_nsid(nsid);
    command.set_prp1(prp1);
    command.set_prp2(prp2);
    command.set_cdw(
        lba as u32,
        (lba >> 32) as u32,
        (blocks.saturating_sub(1)) & 0xFFFF,
    );
    command
}

/// A read of a run of blocks.
pub fn read(nsid: u32, lba: u64, blocks: u32, prp1: u64, prp2: u64) -> NvmeSqe {
    run(NVM_READ, nsid, lba, blocks, prp1, prp2)
}

/// A write of a run of blocks.
pub fn write(nsid: u32, lba: u64, blocks: u32, prp1: u64, prp2: u64) -> NvmeSqe {
    run(NVM_WRITE, nsid, lba, blocks, prp1, prp2)
}

/// A flush: the namespace's write cache to stable storage.
///
/// No data, so no `PRP` at all, and `NSID` is the namespace whose cache is
/// flushed.  A driver that sent this with a `PRP1` would be asking the
/// controller to write something into a buffer the command does not use.
pub fn flush(nsid: u32) -> NvmeSqe {
    let mut command = NvmeSqe::zeroed();
    command.set_opcode(NVM_FLUSH);
    command.set_nsid(nsid);
    command
}

#[cfg(test)]
mod tests {
    //! The ring arithmetic and the two create commands' words.

    use super::*;
    use crate::registers::CAP_DSTRD_MASK;
    use crate::registers::CAP_DSTRD_SHIFT;

    /// The queue size is the smaller of what a boot wants and what `CAP`
    /// allows.
    #[test]
    fn the_queue_size_is_bounded_by_the_controller() {
        // MQES = 63 means 64 entries, which is exactly what a boot asks for.
        assert_eq!(queue_size(63), Some(64));
        // A controller that allows fewer gets asked for fewer.
        assert_eq!(queue_size(15), Some(16));
        // A controller that allows thousands is not given thousands.
        assert_eq!(queue_size(0xFFFF), Some(DEFAULT_QUEUE_SIZE));
        // One entry cannot hold the admin command that learns anything.
        assert_eq!(queue_size(0), None);
        // The stride bits above the mask do not leak into the size.
        assert_eq!(
            queue_size((CAP_DSTRD_MASK << CAP_DSTRD_SHIFT) | 63),
            Some(64)
        );
    }

    /// A ring of fewer than two entries is refused rather than accepted.
    ///
    /// A ring of one has no wrap, so its tail's value cannot distinguish full
    /// from empty: the doorbell would say "there is a command" forever.
    #[test]
    fn a_ring_of_one_entry_is_refused() {
        assert!(SubmissionQueue::new(1).is_none());
        assert!(CompletionQueue::new(1).is_none());
        assert!(SubmissionQueue::new(0).is_none());
        assert!(SubmissionQueue::new(2).is_some());
    }

    /// A submission doorbell carries the slot **after** the command written.
    ///
    /// This is the defect that reads as a timeout: ringing the slot just
    /// written says the queue still ends before it, so the controller never
    /// reads it.
    #[test]
    fn the_submission_doorbell_names_the_next_slot() {
        let mut queue = SubmissionQueue::new(4).expect("four entries");
        assert_eq!(queue.tail(), 0);
        queue.advance();
        assert_eq!(
            queue.tail(),
            1,
            "one command written, so the doorbell says 1"
        );
        assert_eq!(queue.doorbell_after_submit(), 1);
    }

    /// The tail wraps, and the offset is the slot times the entry size.
    #[test]
    fn the_tail_wraps_at_the_end_of_the_ring() {
        let mut queue = SubmissionQueue::new(4).expect("four entries");
        for expected in [1usize, 2, 3, 0, 1] {
            queue.advance();
            assert_eq!(queue.tail(), expected);
        }
        assert_eq!(SubmissionQueue::entry_offset(0), 0);
        assert_eq!(SubmissionQueue::entry_offset(1), SQE_SIZE);
        assert_eq!(SubmissionQueue::entry_offset(3), 3 * 64);
    }

    /// A zeroed completion entry is not new: the first pass expects a set tag.
    ///
    /// This is the assertion that makes the phase walk work.  A driver that
    /// expected a clear first tag would treat every untouched entry in a fresh
    /// ring as a completion, and would answer garbage for the first command it
    /// submitted.
    #[test]
    fn a_fresh_completion_ring_expects_a_set_phase() {
        let queue = CompletionQueue::new(4).expect("four entries");
        assert!(queue.phase());
        assert!(!queue.is_new(&NvmeCqe::zeroed()));

        let written = NvmeCqe {
            status: 1,
            ..NvmeCqe::zeroed()
        };
        assert!(queue.is_new(&written));
    }

    /// The phase flips when the head wraps, and not before.
    ///
    /// A walk that used a counter instead would answer the entry from the
    /// previous pass on the second time around, which is a command's completion
    /// attributed to a different command.
    #[test]
    fn the_phase_flips_only_when_the_head_wraps() {
        let mut queue = CompletionQueue::new(2).expect("two entries");

        // First pass: two entries, tag set.
        let set = NvmeCqe {
            status: 1,
            ..NvmeCqe::zeroed()
        };
        assert!(queue.take(&set).is_some());
        assert!(queue.phase(), "one entry of two is not a wrap");
        assert!(queue.take(&set).is_some());
        assert!(!queue.phase(), "the head wrapped, so the phase flipped");

        // Second pass: the tag is clear, so the old entries are skipped.
        assert!(
            queue.take(&set).is_none(),
            "a set tag belongs to the pass that ended"
        );
        assert_eq!(queue.head(), 0, "a refused entry does not move the head");

        let clear = NvmeCqe::zeroed();
        assert!(
            queue.take(&clear).is_some(),
            "the new pass accepts a clear tag"
        );
    }

    /// `Create I/O Completion Queue`'s words, asserted field by field.
    #[test]
    fn the_completion_queue_command_names_its_size_minus_one() {
        let command = create_completion_queue(1, 64, 0x1000, 0, false);
        assert_eq!(command.opcode(), ADMIN_CREATE_IOCQ);
        assert_eq!(command.word(1), 0, "a create names no namespace");
        assert_eq!(command.word(10) & 0xFFFF, 1, "QID is the low half");
        assert_eq!(
            command.word(10) >> 16,
            63,
            "QSIZE is the entry count minus one"
        );
        assert_eq!(command.word(11) & CREATE_PC, CREATE_PC, "PC is required");

        // And the interrupt bit when asked for, with the vector above it.
        let with_interrupt = create_completion_queue(1, 64, 0x1000, 3, true);
        assert_eq!(with_interrupt.word(11) & CREATE_CQ_IEN, CREATE_CQ_IEN);
        assert_eq!(with_interrupt.word(11) >> 16, 3, "IV is the high half");
    }

    /// `Create I/O Submission Queue` names its completion queue and no
    /// priority.
    ///
    /// The assertion on bits 2:1 is the one that matters: a driver that set
    /// them on the belief that bit 1 was an enable bit made the queue urgent
    /// instead, and QEMU validates only `PC`, so nothing ever contradicted it.
    #[test]
    fn the_submission_queue_command_names_its_completion_queue() {
        let command = create_submission_queue(1, 1, 64, 0x2000);
        assert_eq!(command.opcode(), ADMIN_CREATE_IOSQ);
        assert_eq!(command.word(10) & 0xFFFF, 1, "SQID is the low half");
        assert_eq!(command.word(10) >> 16, 63, "QSIZE is the count minus one");
        assert_eq!(command.word(11) & CREATE_PC, CREATE_PC, "PC is required");
        assert_eq!(command.word(11) >> 16, 1, "CQID is the high half");
        assert_eq!(
            command.word(11) & 0b110,
            0,
            "bits 2:1 are QPRIO, and this driver asks for no priority"
        );
    }

    /// The base address lands in `PRP1` as a physical address.
    #[test]
    fn the_queue_base_address_is_prp1() {
        let command = create_completion_queue(1, 8, 0x0000_0001_0000_2000, 0, false);
        assert_eq!(command.word(6), 0x0000_2000);
        assert_eq!(command.word(7), 0x0000_0001);
    }

    /// `Identify` puts `CNS` in `DW10` and the namespace in `DW1`.
    #[test]
    fn identify_names_the_structure_and_the_namespace() {
        let controller = identify(0x01, 0, 0x3000);
        assert_eq!(controller.opcode(), ADMIN_IDENTIFY);
        assert_eq!(controller.word(10), 0x01, "CNS 1 is the controller");
        assert_eq!(controller.word(1), 0, "the controller is not a namespace");

        let namespace = identify(0x00, 1, 0x3000);
        assert_eq!(namespace.word(10), 0x00);
        assert_eq!(namespace.word(1), 1);
    }

    /// A run's block count is the count **minus one**, and the LBA is 64 bits.
    #[test]
    fn a_run_names_the_lba_and_the_count_minus_one() {
        let lba = 0x0000_0001_2345_6789u64;
        let command = read(1, lba, 8, 0x4000, 0x5000);
        assert_eq!(command.opcode(), NVM_READ);
        assert_eq!(command.word(10), 0x2345_6789, "the low half first");
        assert_eq!(command.word(11), 0x0000_0001, "and the high half");
        assert_eq!(command.word(12), 7, "eight blocks is a count of seven");
        assert_eq!(command.word(8), 0x5000, "PRP2 names the second page");

        // One block is a count of zero, which is the encoding that catches a
        // driver writing the count rather than the count minus one.
        let single = write(1, 0, 1, 0x4000, 0);
        assert_eq!(single.word(12), 0);
        assert_eq!(single.word(9), 0, "one page needs no PRP2");
    }

    /// A flush carries no data pointer and names its namespace.
    #[test]
    fn a_flush_names_the_namespace_and_no_buffer() {
        let command = flush(3);
        assert_eq!(command.opcode(), NVM_FLUSH);
        assert_eq!(command.word(1), 3);
        assert_eq!(command.word(6), 0, "PRP1 is unused");
        assert_eq!(command.word(7), 0);
        assert_eq!(command.word(10), 0);
    }
}
