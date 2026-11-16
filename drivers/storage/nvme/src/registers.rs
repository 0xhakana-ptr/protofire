//! drivers/storage/nvme/src/registers.rs
//!
//! BAR0's register block: the offsets, the bits, and the opcodes the admin and
//! NVM command sets define.
//!
//! ## Why the offsets are asserted rather than trusted
//!
//! A register offset is a number from a specification, and a wrong one is a
//! driver that writes a field the controller does not have.  The failure is not
//! a refusal, it is a controller that ignores a bit and reports itself ready
//! when it is not, so every offset here is pinned by a test against the
//! specification's own value.

/// The controller's capability register: what the device can do.
///
/// 64-bit, read-only.  The low sixteen bits are `MQES`, the maximum number of
/// queue entries the controller supports minus one.
pub const NVME_REG_CAP: usize = 0x0000;

/// The controller's configuration register: the bits that turn it on.
///
/// 32-bit.  Writing `EN` starts the controller's own reset-to-ready sequence,
/// and `CSTS.RDY` is what says it finished.
pub const NVME_REG_CC: usize = 0x0014;

/// The controller's status register.
///
/// 32-bit, read-only.  Bit 0 is `RDY`: the controller has finished its own
/// initialisation and may be given commands.
pub const NVME_REG_CSTS: usize = 0x001C;

/// The admin queue attributes: the two queue sizes, each a count minus one.
///
/// 32-bit.  The low sixteen bits are the submission queue's size minus one, the
/// high sixteen the completion queue's.  Both queues are the same size for the
/// admin pair, which is why one write sets both.
pub const NVME_REG_AQA: usize = 0x0024;

/// The admin submission queue's base address.
///
/// 64-bit, and **physical**: the controller reads memory, so the address is the
/// one the device sees and not the one the kernel writes through.
pub const NVME_REG_ASQ: usize = 0x0028;

/// The admin completion queue's base address.  64-bit, physical.
pub const NVME_REG_ACQ: usize = 0x0030;

/// Where the doorbell array begins.
///
/// The array is one `u32` per queue, submission queues from the start and
/// completion queues at `4 * (queue_count)`.  A queue's arithmetic is in
/// [`doorbell`].
pub const NVME_DOORBELL_BASE: usize = 0x1000;

/// The mask over `CAP`'s low sixteen bits: the maximum queue entries, minus
/// one.
pub const CAP_MQES_MASK: u64 = 0xFFFF;

/// `CSTS.RDY`: the controller is ready for commands.
pub const CSTS_RDY: u32 = 1 << 0;

/// `CC.EN`: enable the controller.
///
/// Writing this to zero starts a reset, and writing it to one starts the
/// controller's initialisation.  Both are followed by a wait on `CSTS.RDY`
/// changing to match, which is why the bit and the status bit are named apart.
pub const CC_EN: u32 = 1 << 0;

/// The admin command opcodes this driver uses.
pub const ADMIN_DELETE_IOSQ: u8 = 0x00;
/// Create an I/O submission queue.
pub const ADMIN_CREATE_IOSQ: u8 = 0x01;
/// Delete an I/O completion queue.
pub const ADMIN_DELETE_IOCQ: u8 = 0x04;
/// Create an I/O completion queue.
pub const ADMIN_CREATE_IOCQ: u8 = 0x05;
/// Identify: ask the controller or a namespace to describe itself.
pub const ADMIN_IDENTIFY: u8 = 0x06;

/// `Identify`'s two selectors: which structure the answer is.
pub const CNS_IDENTIFY_NAMESPACE: u32 = 0x00;
/// The controller's own structure.
pub const CNS_IDENTIFY_CONTROLLER: u32 = 0x01;

/// The NVM command set: three opcodes, and the three things a block device
/// does.
pub const NVM_FLUSH: u8 = 0x00;
/// Write logical blocks.
pub const NVM_WRITE: u8 = 0x01;
/// Read logical blocks.
pub const NVM_READ: u8 = 0x02;

/// The page size this driver builds PRP lists in.
///
/// The specification allows the host to choose; this tree's frame size is 4096,
/// so a page of a buffer is a page of memory and a PRP list's entries are one
/// per frame.
pub const NVME_PAGE_SIZE: usize = 4096;

/// Default number of entries per queue.
///
/// Small on purpose: a boot's traffic is one request at a time, and a queue is
/// memory the controller reads whether or not it is full.
pub const DEFAULT_QUEUE_SIZE: usize = 64;

/// Where a queue's doorbell is, in BAR0.
///
/// NVMe 1.0 §3.1.9 gives the two formulae, and they **interleave**:
///
/// ```text
/// SQ y Tail Doorbell = 0x1000 + (2y    ) * (4 << DSTRD)
/// CQ y Head Doorbell = 0x1000 + (2y + 1) * (4 << DSTRD)
/// ```
///
/// One queue's two doorbells are adjacent, and a queue's pair sits one stride
/// apart from the next queue's.  This is not "every submission queue, then
/// every completion queue": that layout puts queue 1's submission doorbell
/// exactly where queue 0's completion doorbell is, so a driver that ringed
/// "submission queue 1" wrote the completion head of queue 0.  QEMU's own
/// dispatch is the check: it reads a doorbell's queue id as
/// `(addr - 0x1000) >> 3`, and a completion's as `(addr - 0x1004) >> 3`, which
/// is this formula with `DSTRD` zero.
///
/// `dstrd` is `CAP`'s bits 35:32, which the controller reports because it is
/// the device's stride and not a constant.  The previous version took the queue
/// count instead, on the belief that the two groups were laid out one after the
/// other, and its test asserted that layout.
pub const fn doorbell(queue: u16, is_completion: bool, dstrd: u32) -> usize {
    let stride = 4usize << dstrd;
    let index = queue as usize * 2 + if is_completion { 1 } else { 0 };
    NVME_DOORBELL_BASE + index * stride
}

/// Where `CAP`'s `DSTRD` field begins.
///
/// The field is bits 35:32: the doorbell stride as a power of two on top of the
/// four bytes a doorbell is.
pub const CAP_DSTRD_SHIFT: u32 = 32;

/// The mask over `CAP`'s `DSTRD` field.
pub const CAP_DSTRD_MASK: u64 = 0xF;

/// The doorbell stride a `CAP` value asks for.
///
/// Separate from [`doorbell`] so a caller decodes the controller's own number
/// once, at probe, and passes the same one to every ring.
pub const fn doorbell_stride(cap: u64) -> u32 {
    ((cap >> CAP_DSTRD_SHIFT) & CAP_DSTRD_MASK) as u32
}

/// The PRP entries for a run of `bytes` out of a buffer that starts at `base`.
///
/// A run of one page is `PRP1` alone, with `PRP2` zero.  A run of exactly two
/// pages puts the second in `PRP2`.  Anything longer needs a PRP list, which is
/// why a driver that can only pass two entries keeps its run buffer to two
/// frames: a `PRP2` that named a list the controller expected to be a page
/// would be a transfer into memory the caller did not name.
pub const fn run_prp(base: u64, bytes: usize) -> (u64, u64) {
    let prp2 = if bytes > NVME_PAGE_SIZE {
        base + NVME_PAGE_SIZE as u64
    } else {
        0
    };
    (base, prp2)
}

#[cfg(test)]
mod tests {
    //! The offsets are the specification's, asserted as literals.
    //!
    //! A wrong offset here is not a refusal: it is a controller that ignores a
    //! write and reports itself ready, so the only way to catch it is to know
    //! where the register is.

    use super::*;

    /// The register offsets are the ones NVMe 1.0 §3.1 defines.
    #[test]
    fn the_register_offsets_are_the_specifications() {
        assert_eq!(NVME_REG_CAP, 0x0000);
        assert_eq!(NVME_REG_CC, 0x0014);
        assert_eq!(NVME_REG_CSTS, 0x001C);
        assert_eq!(NVME_REG_AQA, 0x0024);
        assert_eq!(NVME_REG_ASQ, 0x0028);
        assert_eq!(NVME_REG_ACQ, 0x0030);
        assert_eq!(NVME_DOORBELL_BASE, 0x1000);
    }

    /// The two control bits are bit zero of two different registers.
    ///
    /// `CC.EN` and `CSTS.RDY` are the same bit in different registers, and a
    /// driver that confused them would wait for a status write that never
    /// lands.
    #[test]
    fn the_control_and_status_bits_are_bit_zero() {
        assert_eq!(CC_EN, 1);
        assert_eq!(CSTS_RDY, 1);
        assert_eq!(CAP_MQES_MASK, 0xFFFF);
    }

    /// The opcodes are the ones the specification names.
    ///
    /// These are the numbers the controller dispatches on, so a wrong one is a
    /// command the device rejects with an error code rather than an opcode it
    /// does not know, which reads like a protocol error and is a constant.
    #[test]
    fn the_opcodes_are_the_specifications() {
        assert_eq!(ADMIN_DELETE_IOSQ, 0x00);
        assert_eq!(ADMIN_CREATE_IOSQ, 0x01);
        assert_eq!(ADMIN_DELETE_IOCQ, 0x04);
        assert_eq!(ADMIN_CREATE_IOCQ, 0x05);
        assert_eq!(ADMIN_IDENTIFY, 0x06);
        assert_eq!(NVM_FLUSH, 0x00);
        assert_eq!(NVM_WRITE, 0x01);
        assert_eq!(NVM_READ, 0x02);
    }

    /// A queue's two doorbells are adjacent, and the next queue's pair follows.
    ///
    /// With `DSTRD` zero a doorbell is four bytes: queue 0's tail is at
    /// `0x1000` and its head at `0x1004`, queue 1's tail at `0x1008` and its
    /// head at `0x100c`.  The numbers are QEMU's own dispatch read backwards:
    /// it takes a submission doorbell's queue id as `(addr - 0x1000) >> 3` and
    /// a completion's as `(addr - 0x1004) >> 3`, and both answer the queue the
    /// formula above names.
    ///
    /// The version this replaced laid the groups out separately, so
    /// `doorbell(1, false, 4)` answered `0x1004` -- **completion queue 0's
    /// head** -- and the test below asserted that.  A driver ringing that when
    /// it meant to submit tells the controller a completion was taken from a
    /// queue nothing had put anything on, and the command sits in a ring nobody
    /// reads.  That is the defect the controller's I/O timeout turned out to
    /// be.
    #[test]
    fn a_queues_two_doorbells_are_adjacent() {
        assert_eq!(doorbell(0, false, 0), 0x1000);
        assert_eq!(doorbell(0, true, 0), 0x1004);
        assert_eq!(doorbell(1, false, 0), 0x1008);
        assert_eq!(doorbell(1, true, 0), 0x100c);
        assert_eq!(doorbell(4, false, 0), 0x1020);
        assert_eq!(doorbell(4, true, 0), 0x1024);
    }

    /// No submission doorbell ever lands on a completion doorbell.
    ///
    /// This is the invariant the interleaved layout exists for, stated as a
    /// search rather than as four literals: over every queue a controller can
    /// have, the two sets do not meet.  A layout where they meet is one where a
    /// driver's submit is silently a completion acknowledged, which is the
    /// failure that reads as a timeout and names nothing.
    #[test]
    fn the_two_doorbell_sets_are_disjoint() {
        for queue in 0..64u16 {
            let submission = doorbell(queue, false, 0);
            for other in 0..64u16 {
                assert_ne!(
                    submission,
                    doorbell(other, true, 0),
                    "submission queue {queue} and completion queue {other} share a doorbell"
                );
            }
        }
    }

    /// `DSTRD` widens the stride, and it is the controller's number.
    ///
    /// Bits 35:32 of `CAP` are the stride as a power of two on top of the four
    /// bytes a doorbell is, so `DSTRD = 2` makes each doorbell sixteen bytes
    /// and a queue's pair sixty-four apart from the next.  A driver that
    /// assumed four would ring inside a neighbour's register on a device that
    /// reported anything else.
    #[test]
    fn the_stride_comes_from_cap() {
        assert_eq!(doorbell_stride(0), 0);
        assert_eq!(doorbell_stride(CAP_DSTRD_MASK << CAP_DSTRD_SHIFT), 0xF);

        // DSTRD = 2: a doorbell is 16 bytes.
        assert_eq!(doorbell(0, false, 2), 0x1000);
        assert_eq!(doorbell(0, true, 2), 0x1010);
        assert_eq!(doorbell(1, false, 2), 0x1020);
        assert_eq!(doorbell(1, true, 2), 0x1030);
    }

    /// One page of data is PRP1 alone.
    #[test]
    fn a_single_page_needs_no_second_entry() {
        assert_eq!(run_prp(0x1000, 4096), (0x1000, 0));
        assert_eq!(run_prp(0x1000, 1), (0x1000, 0));
    }

    /// Two pages put the second in PRP2, and PRP2 is the next page along.
    #[test]
    fn two_pages_name_both_entries() {
        assert_eq!(run_prp(0x2000, 8192), (0x2000, 0x3000));
        assert_eq!(run_prp(0x2000, 4097), (0x2000, 0x3000));
    }

    /// The page size is the frame size, which is what makes a PRP list one
    /// entry per frame.
    #[test]
    fn the_page_size_is_the_trees_frame_size() {
        assert_eq!(NVME_PAGE_SIZE, 4096);
    }
}
