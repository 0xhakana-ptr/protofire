//! drivers/storage/nvme/src/command.rs
//!
//! The two queue entries and the namespace record: 64 bytes out, 16 back.
//!
//! ## The layout, and why every field is a `raw` word
//!
//! A submission entry is sixteen 32-bit words whose meaning depends on the
//! opcode: word 0 carries the opcode, the command id and the fuse bits in one
//! number, and words 10 to 15 are command-specific.  Naming the fields as
//! struct members would be a separate type per opcode and a `union` to hold
//! them, so this type is the specification's own shape, a word array with
//! setters that know the bit positions, and the setters are the only thing that
//! knows the layout.
//!
//! The size is checked rather than assumed: 64 and 16 are the numbers a
//! controller reads and writes, and a type whose padding grew would corrupt the
//! ring it sits in without any error at all.

/// A submission queue entry: exactly 64 bytes.
///
/// The layout is NVMe 1.0 §4.2.1, and the doc comment on each setter names the
/// words it touches rather than repeating the whole table at the top, because
/// the setters are what a reader follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct NvmeSqe {
    raw: [u32; 16],
}

/// A completion queue entry: exactly 16 bytes.
pub const SQE_SIZE: usize = 64;
/// What a completion entry is.
pub const CQE_SIZE: usize = 16;

impl NvmeSqe {
    /// A command that does nothing until something sets a field.
    pub const fn zeroed() -> Self {
        Self { raw: [0u32; 16] }
    }

    /// Set the opcode, in `DW0`'s low byte.
    pub fn set_opcode(&mut self, opcode: u8) {
        self.raw[0] = (self.raw[0] & !0xFF) | (opcode as u32);
    }

    /// Set the namespace id, `DW1`.
    ///
    /// `0xFFFFFFFF` is the "every namespace" selector and `0` the "no
    /// namespace" one; a driver that meant one namespace and wrote either would
    /// get an answer about a different thing without an error.
    pub fn set_nsid(&mut self, nsid: u32) {
        self.raw[1] = nsid;
    }

    /// Set the command id, `DW0`'s high sixteen bits.
    ///
    /// A completion names the command it answers by this number, so a driver
    /// holding more than one request matches on it rather than on "the next
    /// completion to arrive".
    pub fn set_command_id(&mut self, id: u16) {
        self.raw[0] = (self.raw[0] & !0xFFFF_0000) | ((id as u32) << 16);
    }

    /// The command id this entry carries.
    pub fn command_id(&self) -> u16 {
        (self.raw[0] >> 16) as u16
    }

    /// Store a physical address into `PRP1`, words 6 and 7.
    ///
    /// NVMe splits a 64-bit address across two 32-bit words, low first.  The
    /// assertion is that the address is a **physical** one: a kernel virtual
    /// address on x86_64 has its high bits set, and a controller handed one
    /// writes into whatever the bus decodes there.
    pub fn set_prp1(&mut self, prp1: u64) {
        debug_assert!(
            prp1 < (1 << 52),
            "set_prp1: {prp1:#018x} is past the 52-bit physical limit, so it is \
             probably a virtual address"
        );
        self.raw[6] = prp1 as u32;
        self.raw[7] = (prp1 >> 32) as u32;
    }

    /// Store a physical address into `PRP2`, words 8 and 9.
    pub fn set_prp2(&mut self, prp2: u64) {
        debug_assert!(
            prp2 < (1 << 52),
            "set_prp2: {prp2:#018x} is past the 52-bit physical limit, so it is \
             probably a virtual address"
        );
        self.raw[8] = prp2 as u32;
        self.raw[9] = (prp2 >> 32) as u32;
    }

    /// Store the three command-specific words a read or write uses.
    ///
    /// `dw10` is the command's first specific word, and for a read or write it
    /// is the starting LBA's low half; `dw11` is the high half; `dw12` is the
    /// transfer length minus one, in logical blocks.
    pub fn set_cdw(&mut self, dw10: u32, dw11: u32, dw12: u32) {
        self.raw[10] = dw10;
        self.raw[11] = dw11;
        self.raw[12] = dw12;
    }

    /// Set `CDW10` alone, which is what `Identify` and `Create` use.
    pub fn set_cdw10(&mut self, dw10: u32) {
        self.raw[10] = dw10;
    }

    /// Set `CDW11` alone, which is what the two create commands use.
    ///
    /// Separate from [`NvmeSqe::set_cdw`] because a create command leaves
    /// `CDW12` alone, and a word the command does not define is not a word a
    /// driver should be writing.
    pub fn set_cdw11(&mut self, dw11: u32) {
        self.raw[11] = dw11;
    }

    /// The opcode this entry carries.
    pub fn opcode(&self) -> u8 {
        (self.raw[0] & 0xFF) as u8
    }

    /// The namespace id this entry carries.
    pub fn nsid(&self) -> u32 {
        self.raw[1]
    }

    /// One word, for a test that checks the layout landed where it meant to.
    pub fn word(&self, index: usize) -> u32 {
        self.raw[index]
    }
}

/// A completion queue entry: 16 bytes, words 0 to 3.
///
/// The controller writes it, so the fields are public: a driver reads `dw0` for
/// a command's result, and the command id to match it to a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct NvmeCqe {
    /// The command-specific result.
    pub dw0: u32,
    /// Reserved.
    pub reserved: u32,
    /// Where the submission queue's head is now.
    pub sq_head: u16,
    /// Which submission queue completed this.
    pub sq_id: u16,
    /// Which command this answers.
    pub command_id: u16,
    /// The phase bit in bit 0 and the status field above it.
    pub status: u16,
}

impl NvmeCqe {
    /// A completion nothing has written yet.
    pub const fn zeroed() -> Self {
        Self {
            dw0: 0,
            reserved: 0,
            sq_head: 0,
            sq_id: 0,
            command_id: 0,
            status: 0,
        }
    }

    /// The status code, bits 15:1 of the status word.
    ///
    /// Bit 0 is the **phase tag**, not part of the status: a driver that read
    /// the whole word as a status would see every successful completion as
    /// status 1 whenever the phase happened to be set, which is half the time.
    pub fn status_code(&self) -> u16 {
        (self.status >> 1) & 0x7FFF
    }

    /// Whether this completion says the command succeeded.
    pub fn is_success(&self) -> bool {
        self.status_code() == 0
    }

    /// Whether this entry belongs to the phase the driver is waiting for.
    ///
    /// The bit flips every time the completion ring wraps, so a ring is walked
    /// by "phase bit equals the phase the driver expects" rather than by a
    /// counter: an entry left over from the previous pass has the other bit and
    /// is skipped without any bookkeeping.
    pub fn phase(&self) -> bool {
        self.status & 1 != 0
    }
}

/// A namespace: what a controller has, and how big its blocks are.
///
/// One of these per namespace is what the block interface above sees.  It is
/// kept here rather than in the driver because it is the shape the identify
/// structures answer with, and a second driver later reads the same two
/// numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NvmeNamespace {
    /// The namespace id a command names.
    pub nsid: u32,
    /// How many logical blocks it has.
    pub block_count: u64,
    /// How many bytes one logical block is.
    pub block_size: usize,
}

/// Default number of entries per queue.  See `registers` for why it is small.
pub const DEFAULT_QUEUE_SIZE: usize = 64;

/// The NVM command set's opcodes, repeated here because a driver that builds a
/// read imports this module and not the register map.
pub const NVM_FLUSH: u8 = 0x00;
/// Write logical blocks.
pub const NVM_WRITE: u8 = 0x01;
/// Read logical blocks.
pub const NVM_READ: u8 = 0x02;

#[cfg(test)]
mod tests {
    //! The sizes and the bit positions, asserted rather than assumed.

    use super::*;

    /// The two entries are the sizes the controller reads and writes.
    ///
    /// A type whose padding grew would corrupt the ring it sits in silently:
    /// the controller reads 64 bytes from where the driver put 68 and the next
    /// command is misaligned.
    #[test]
    fn the_entries_are_the_sizes_the_specification_names() {
        assert_eq!(core::mem::size_of::<NvmeSqe>(), 64);
        assert_eq!(core::mem::size_of::<NvmeCqe>(), 16);
    }

    /// The opcode and the command id share `DW0` without overlapping.
    ///
    /// The opcode is the low byte and the id is the high sixteen bits, so
    /// setting one must not clear the other.  A driver that wrote the id first
    /// and the opcode second would lose the id if the mask were wrong, and the
    /// completion would name a command nothing is holding.
    #[test]
    fn the_opcode_and_command_id_do_not_overwrite_each_other() {
        let mut command = NvmeSqe::zeroed();
        command.set_opcode(NVM_READ);
        command.set_command_id(0xBEEF);
        assert_eq!(command.opcode(), NVM_READ);
        assert_eq!(command.command_id(), 0xBEEF);

        // And the other order.
        let mut command = NvmeSqe::zeroed();
        command.set_command_id(0x1234);
        command.set_opcode(NVM_WRITE);
        assert_eq!(command.opcode(), NVM_WRITE);
        assert_eq!(command.command_id(), 0x1234);
    }

    /// A 64-bit address lands in the two words the specification names.
    ///
    /// `PRP1` is words 6 and 7 and `PRP2` is words 8 and 9, low half first.  A
    /// driver that wrote the high half first would hand the controller an
    /// address four gigabytes away from the buffer.
    #[test]
    fn an_address_is_split_low_half_first() {
        let mut command = NvmeSqe::zeroed();
        command.set_prp1(0x0000_0001_2345_6789);
        assert_eq!(command.word(6), 0x2345_6789);
        assert_eq!(command.word(7), 0x0000_0001);

        command.set_prp2(0x0000_0002_AAAA_BBBB);
        assert_eq!(command.word(8), 0xAAAA_BBBB);
        assert_eq!(command.word(9), 0x0000_0002);
    }

    /// The three command-specific words land in 10, 11 and 12.
    #[test]
    fn the_command_specific_words_are_where_a_read_uses_them() {
        let mut command = NvmeSqe::zeroed();
        command.set_cdw(0x1111_1111, 0x2222_2222, 0x0000_0007);
        assert_eq!(command.word(10), 0x1111_1111);
        assert_eq!(command.word(11), 0x2222_2222);
        assert_eq!(command.word(12), 0x0000_0007);
    }

    /// The namespace id is `DW1`.
    #[test]
    fn the_namespace_id_is_the_second_word() {
        let mut command = NvmeSqe::zeroed();
        command.set_nsid(1);
        assert_eq!(command.nsid(), 1);
        assert_eq!(command.word(1), 1);
    }

    /// A status word's low bit is the phase, not part of the status.
    ///
    /// The test is the defect it prevents: reading the whole word as a status
    /// makes every success look like an error half the time, depending on which
    /// pass of the ring the completion came from.
    #[test]
    fn the_phase_bit_is_not_part_of_the_status() {
        // Success with the phase clear.
        let a = NvmeCqe {
            status: 0x0000,
            ..NvmeCqe::zeroed()
        };
        assert!(a.is_success());
        assert!(!a.phase());

        // Success with the phase set: the status code is still zero.
        let b = NvmeCqe {
            status: 0x0001,
            ..NvmeCqe::zeroed()
        };
        assert!(b.is_success(), "a phase-set success is still a success");
        assert_eq!(b.status_code(), 0);
        assert!(b.phase());

        // A real error: status code 2 is "invalid field in command".
        let c = NvmeCqe {
            status: 0x0004,
            ..NvmeCqe::zeroed()
        };
        assert!(!c.is_success());
        assert_eq!(c.status_code(), 2);
    }

    /// The phase bit flips with bit 0 of the word, which is what makes the
    /// walk work.
    #[test]
    fn the_phase_is_the_low_bit() {
        for (word, expected) in [(0u16, false), (1, true), (0x0002, false), (0x0003, true)] {
            let entry = NvmeCqe {
                status: word,
                ..NvmeCqe::zeroed()
            };
            assert_eq!(entry.phase(), expected, "status word {word:#06x}");
        }
    }
}
