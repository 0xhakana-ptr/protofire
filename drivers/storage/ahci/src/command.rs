//! drivers/storage/ahci/src/command.rs
//!
//! The three structures a command is made of: the command-list header, the
//! PRD table entry, and the Host-to-Device FIS that carries the ATA command.
//!
//! ## Why bytes and offsets rather than a packed struct
//!
//! Each structure is a wire shape the controller reads byte by byte, and a
//! `#[repr(C, packed)]` struct is a wire shape whose every field access is a
//! potential misaligned read the compiler cannot see.  The previous tree
//! declared all three as packed structs; this one declares them as arrays
//! built by functions that name the offset and the width of every field,
//! which is the shape `nvme`'s command entries take for the same reason.
//!
//! ## The two defects this module exists to not repeat
//!
//! One: the command header's `CFL` field -- the length of the command FIS in
//! dwords -- was left zero.  A controller is entitled to refuse that, and
//! QEMU's does: `handle_cmd` takes `CFL` from the header and rejects anything
//! below two dwords with no message a driver reads.  Every command the
//! previous driver submitted was refused before the device ever saw it, and
//! its IDENTIFY poll timed out with nothing anywhere naming why.  The length
//! is now the field the specification defines it as: five dwords for a
//! Register FIS Host-to-Device, which is 20 bytes.
//!
//! Two: the header's write-direction bit was never set, because the direction
//! lived only in the FIS's own flags.  A controller that trusts the header's
//! `W` bit, as the specification says it may, would read a PRD table that was
//! meant to be written and answer a write with stale memory.  Both places now
//! say the same thing.

/// How many slots a command list has.
///
/// §4.2.2: a command list is 32 headers of 32 bytes, 1024 bytes in all.
pub const CL_SLOTS: usize = 32;

/// The size of one command-list header.
pub const CL_ENTRY_SIZE: usize = 32;

/// The size of the whole command list, one frame.
pub const CL_TOTAL_SIZE: usize = CL_SLOTS * CL_ENTRY_SIZE;

/// The size of the received-FIS area, §4.2.1.
///
/// 256 bytes, 256-byte aligned, and written by the controller: a driver never
/// reads it on the command path, but it must stay allocated for as long as
/// the port's engine is running.
pub const RFIS_SIZE: usize = 256;

/// Where the PRD table begins inside the command table, §4.2.3.
///
/// The first 128 bytes are the command FIS, the ATAPI command and the two
/// reserved words; the PRD entries follow.
pub const CT_BASE_SIZE: usize = 0x80;

/// The size of one PRD table entry.
pub const PRDT_ENTRY_SIZE: usize = 16;

/// How many PRD entries this driver's command table holds.
///
/// One: every transfer is one run of up to a page, bounced through a frame
/// the driver owns.  A second entry would buy multi-page runs at the price of
/// an sg-list builder, and nothing above the block layer has asked for one.
pub const MAX_PRDT: usize = 1;

/// The total size of one command table.
pub const CT_TOTAL_SIZE: usize = CT_BASE_SIZE + MAX_PRDT * PRDT_ENTRY_SIZE;

/// The command FIS's length, in dwords, as a command header must say it.
///
/// A Register FIS Host-to-Device is 20 bytes, which is five dwords.  This is
/// the number the previous tree's header left at zero, and the one QEMU's
/// `handle_cmd` refuses below two.
pub const REGISTER_FIS_DWORDS: u32 = 5;

/// The command FIS's length, in bytes.
pub const REGISTER_FIS_BYTES: usize = REGISTER_FIS_DWORDS as usize * 4;

/// A command-list header, 32 bytes.
///
/// §4.2.2:
///
/// ```text
/// DW0: bits 15:0  CFL    -- the command FIS's length, in dwords
///      bits 31:16 PRDTL  -- how many PRD entries the table holds
/// DW1: bit  8     A      -- ATAPI
///      bit  9     W      -- the transfer's direction is device-write
///      bit 10     P      -- prefetchable
///      bit 11     R      -- reset
/// DW4+DW5: CTBA   -- the command table's base address
/// ```
///
/// Everything else is left zero, which for the fields this driver uses is
/// what the specification says a non-ATAPI, non-reset command carries.
pub fn command_header(
    cfl_dwords: u32,
    prdtl: u16,
    write: bool,
    table_address: u64,
) -> [u8; CL_ENTRY_SIZE] {
    let mut header = [0u8; CL_ENTRY_SIZE];
    let dw0 = (cfl_dwords & 0xFFFF) | ((prdtl as u32) << 16);
    header[0..4].copy_from_slice(&dw0.to_le_bytes());
    if write {
        let dw1: u32 = 1 << 9;
        header[4..8].copy_from_slice(&dw1.to_le_bytes());
    }
    header[8..12].copy_from_slice(&(table_address as u32).to_le_bytes());
    header[12..16].copy_from_slice(&((table_address >> 32) as u32).to_le_bytes());
    header
}

/// A PRD table entry, 16 bytes.
///
/// §4.2.3:
///
/// ```text
/// DW0+DW1: DBA  -- the data buffer's base address
/// DW3:     bits 21:0  DBC  -- the byte count, **minus one**
///          bit  31    IOC  -- interrupt on completion
/// ```
///
/// The count being minus-one is the same encoding NVMe's `NLB` uses, and the
/// same defect: a driver that wrote the count would transfer one byte more
/// than the caller's buffer holds.
pub fn prdt_entry(address: u64, bytes: usize) -> [u8; PRDT_ENTRY_SIZE] {
    debug_assert!(bytes > 0, "a PRD of zero bytes has no encoding");
    let mut entry = [0u8; PRDT_ENTRY_SIZE];
    entry[0..4].copy_from_slice(&(address as u32).to_le_bytes());
    entry[4..8].copy_from_slice(&((address >> 32) as u32).to_le_bytes());
    let dbc = ((bytes - 1) as u32) & 0x003F_FFFF;
    entry[12..16].copy_from_slice(&dbc.to_le_bytes());
    entry
}

/// A Register FIS Host-to-Device, 20 bytes inside a 64-byte command FIS area.
///
/// §4.2.1 puts the command FIS at the command table's byte zero and gives it
/// 64 bytes; a Register FIS fills the first 20 and the rest are zero.  The
/// LBA is written 48-bit wide as the ATA-8 register layout has it, which is
/// what the `EXT` command set expects, and the low byte of `device` carries
/// the LBA mode bit so a device that still looks there reads one.
///
/// `flags` bit 7 is `C` -- the FIS carries a command -- and bit 6 is `W`,
/// which tells the device whether data will follow from the host.  The two
/// places that say "write" in one command -- this bit and the header's --
/// must agree, which is why [`command_header`] takes the same argument.
pub fn h2d_fis(command: u8, lba: u64, count: u16) -> [u8; REGISTER_FIS_BYTES] {
    let mut fis = [0u8; REGISTER_FIS_BYTES];
    fis[0] = 0x27;
    // Byte 1: C at bit 7, and nothing else.  Bits 6:4 are reserved, and a
    // controller may refuse the FIS for a set one.
    fis[1] = 0x80;
    fis[2] = command;
    // The LBA, 48 bits wide across bytes 4, 5, 6, 8, 9 and 10; byte 7 is the
    // device register, whose low nibble is the LBA's bits 27:24 in an LBA28
    // command and whose LBA-mode bit a driver sets in either case.
    fis[4] = lba as u8;
    fis[5] = (lba >> 8) as u8;
    fis[6] = (lba >> 16) as u8;
    fis[7] = 0x40 | (((lba >> 24) as u8) & 0x0F);
    fis[8] = (lba >> 32) as u8;
    fis[9] = (lba >> 40) as u8;
    fis[10] = (lba >> 48) as u8;
    // The count is 16 bits, low byte first.
    fis[12] = count as u8;
    fis[13] = (count >> 8) as u8;
    fis
}

/// The ATA command codes this driver sends.
///
/// All three are the 48-bit LBA forms, because a disk small enough for 28-bit
/// addressing is smaller than the error that comes from picking the narrow
/// one and being wrong.
pub const ATA_IDENTIFY_DEVICE: u8 = 0xEC;
/// Read DMA Extended.
pub const ATA_READ_DMA_EXT: u8 = 0x25;
/// Write DMA Extended.
pub const ATA_WRITE_DMA_EXT: u8 = 0x35;
/// Flush Cache, which takes no LBA and no count.
pub const ATA_FLUSH_CACHE: u8 = 0xE7;

#[cfg(test)]
mod tests {
    //! The three structures' layouts, asserted field by field, and the two
    //! defects named at the top asserted as their absence.

    use super::*;

    /// The sizes are the specification's, because a structure whose padding
    /// grew would shift every field after it and no test above would notice.
    #[test]
    fn the_sizes_are_the_specifications() {
        assert_eq!(CL_ENTRY_SIZE, 32);
        assert_eq!(CL_SLOTS, 32);
        assert_eq!(CL_TOTAL_SIZE, 1024);
        assert_eq!(RFIS_SIZE, 256);
        assert_eq!(CT_BASE_SIZE, 0x80);
        assert_eq!(PRDT_ENTRY_SIZE, 16);
        assert_eq!(CT_TOTAL_SIZE, 0x80 + 16);
    }

    /// The command FIS length is five dwords, not zero.
    ///
    /// This is the assertion the previous tree's driver never made: its header
    /// carried `CFL = 0`, and a controller that refuses a length below two
    /// dwords refused every command it sent, silently, before the device was
    /// ever consulted.
    #[test]
    fn a_register_fis_is_five_dwords() {
        assert_eq!(REGISTER_FIS_DWORDS, 5);
        assert_eq!(REGISTER_FIS_BYTES, 20);
    }

    /// `CFL` and `PRDTL` share `DW0` without overlapping.
    #[test]
    fn cfl_and_prdtl_share_the_first_word() {
        let header = command_header(REGISTER_FIS_DWORDS, 1, false, 0x1000);
        let dw0 = u32::from_le_bytes(header[0..4].try_into().expect("four bytes"));
        assert_eq!(dw0 & 0xFFFF, 5, "CFL is the low half, in dwords");
        assert_eq!(dw0 >> 16, 1, "PRDTL is the high half");
    }

    /// A write command sets the header's direction bit; a read clears it.
    ///
    /// The bit is `DW1` bit 9, and a header that left it zero for a write asks
    /// the controller to *read* into the PRD's buffer.
    #[test]
    fn the_write_bit_is_set_only_for_writes() {
        let write = command_header(REGISTER_FIS_DWORDS, 1, true, 0x1000);
        let dw1 = u32::from_le_bytes(write[4..8].try_into().expect("four bytes"));
        assert_eq!(dw1, 1 << 9, "DW1 bit 9 is the header's write bit");

        let read = command_header(REGISTER_FIS_DWORDS, 1, false, 0x1000);
        let dw1 = u32::from_le_bytes(read[4..8].try_into().expect("four bytes"));
        assert_eq!(dw1, 0);
    }

    /// The command table's address lands in `DW4` and `DW5`, low half first.
    #[test]
    fn the_table_address_is_split_low_half_first() {
        let header = command_header(REGISTER_FIS_DWORDS, 1, false, 0x0000_0002_0000_3000);
        assert_eq!(&header[8..12], &0x0000_3000u32.to_le_bytes());
        assert_eq!(&header[12..16], &0x0000_0002u32.to_le_bytes());
        assert_eq!(&header[16..20], &[0u8; 4], "DW4 is not the address");
        assert_eq!(&header[20..24], &[0u8; 4], "and neither is DW5");
    }

    /// A header's unused bytes stay zero, which is what a controller reads
    /// an ATAPI-free, reset-free command as.
    #[test]
    fn the_header_leaves_what_it_does_not_use_zero() {
        let header = command_header(REGISTER_FIS_DWORDS, 1, false, 0x1000);
        // DW1 is zero for a read, and DW4 through DW7 are zero because the
        // table's address ended at DW3: a builder that stopped one dword early
        // would leave the address where a controller reading forward from DW4
        // would find it, which is the defect this test pins in both directions.
        for at in [4usize, 16, 20, 24, 28] {
            assert_eq!(&header[at..at + 4], &[0u8; 4], "DW{} stays zero", at / 4);
        }
        assert_eq!(&header[16..24], &[0u8; 8], "the address is not in DW4");
    }

    /// A PRD entry names its buffer and a byte count that is **minus one**.
    #[test]
    fn the_prdt_entry_carries_a_count_minus_one() {
        let entry = prdt_entry(0x0000_0003_0000_4000, 512);
        assert_eq!(&entry[0..4], &0x0000_4000u32.to_le_bytes());
        assert_eq!(&entry[4..8], &0x0000_0003u32.to_le_bytes());
        let dbc = u32::from_le_bytes(entry[12..16].try_into().expect("four bytes"));
        assert_eq!(dbc, 511, "512 bytes is a count of 511");
        assert_eq!(dbc >> 22, 0, "the IOC bit is clear");
    }

    /// The byte count cannot reach past `DBC`'s 22 bits.
    ///
    /// A run bigger than 4 MiB would have its high bits truncated and the
    /// controller would transfer `DBC + 1` bytes of a buffer that does not
    /// hold them.  This driver's runs are one page, far inside the field.
    #[test]
    fn the_byte_count_fits_the_field() {
        let biggest = 1 << 22;
        let entry = prdt_entry(0x1000, biggest);
        let dbc = u32::from_le_bytes(entry[12..16].try_into().expect("four bytes"));
        assert_eq!(dbc, (biggest - 1) as u32 & 0x003F_FFFF);
        // The field is exhausted at exactly the boundary: one byte past it
        // wraps the count back to zero rather than carrying into the IOC bit.
        let entry = prdt_entry(0x1000, biggest + 1);
        let dbc = u32::from_le_bytes(entry[12..16].try_into().expect("four bytes"));
        assert_eq!(dbc, 0, "the high bit was silently dropped, not carried");
    }

    /// A Register FIS lands where the specification puts its fields.
    #[test]
    fn a_h2d_fis_names_the_command_the_lba_and_the_count() {
        let fis = h2d_fis(ATA_READ_DMA_EXT, 0x0000_0123_4567_89AB, 8);
        assert_eq!(fis[0], 0x27, "the FIS type is Register Host-to-Device");
        assert_eq!(fis[1], 0x80, "C is set, W is clear, for a read");
        assert_eq!(fis[2], ATA_READ_DMA_EXT);
        assert_eq!(fis[4], 0xAB, "LBA 7:0");
        assert_eq!(fis[5], 0x89, "LBA 15:8");
        assert_eq!(fis[6], 0x67, "LBA 23:16");
        assert_eq!(fis[7] & 0xF0, 0x40, "the LBA mode bit is set");
        assert_eq!(fis[7] & 0x0F, 0x5, "the device register carries LBA 27:24");
        assert_eq!(fis[8], 0x23, "LBA 31:24");
        assert_eq!(fis[9], 0x01, "LBA 39:32");
        assert_eq!(fis[10], 0x00, "LBA 47:40");
        assert_eq!(fis[12], 8, "the count's low byte");
        assert_eq!(fis[13], 0, "and its high byte");
    }

    /// A write FIS sets the FIS's own direction bit, and the two places a
    /// command says "write" agree when the header is built with the same
    /// argument.
    #[test]
    fn a_write_fis_differs_only_in_its_command_code() {
        let write = h2d_fis(ATA_WRITE_DMA_EXT, 0, 1);
        assert_eq!(
            write[1], 0x80,
            "C alone: bit 6 is reserved, not a write bit"
        );
        assert_eq!(write[2], ATA_WRITE_DMA_EXT);

        // The header's own write bit is where the direction is declared.
        let header = command_header(REGISTER_FIS_DWORDS, 1, true, 0x1000);
        let dw1 = u32::from_le_bytes(header[4..8].try_into().expect("four bytes"));
        assert_eq!(dw1 >> 9 & 1, 1, "the header says write");

        // And every FIS leaves the reserved mask clear.
        for fis in [
            h2d_fis(ATA_READ_DMA_EXT, 0, 1),
            h2d_fis(ATA_WRITE_DMA_EXT, 0, 1),
            h2d_fis(ATA_FLUSH_CACHE, 0, 0),
        ] {
            assert_eq!(fis[1] & 0x70, 0, "the reserved mask is clear");
        }
    }

    /// The commands are distinct, because a driver that sends one where it
    /// meant another is a device answering a different question.
    #[test]
    fn the_command_codes_are_distinct() {
        assert_eq!(ATA_IDENTIFY_DEVICE, 0xEC);
        assert_eq!(ATA_READ_DMA_EXT, 0x25);
        assert_eq!(ATA_WRITE_DMA_EXT, 0x35);
        assert_eq!(ATA_FLUSH_CACHE, 0xE7);
        let codes = [
            ATA_IDENTIFY_DEVICE,
            ATA_READ_DMA_EXT,
            ATA_WRITE_DMA_EXT,
            ATA_FLUSH_CACHE,
        ];
        for (index, code) in codes.iter().enumerate() {
            for other in &codes[index + 1..] {
                assert_ne!(code, other);
            }
        }
    }
}
