//! drivers/storage/ahci/src/registers.rs
//!
//! BAR5's register block: the HBA's registers, the bits that turn a port's
//! engine on, and the arithmetic that reaches a port's own register set.
//!
//! ## Why the offsets are asserted rather than trusted
//!
//! A register offset is a number from a specification, and a wrong one is a
//! driver that writes a field the controller does not have.  The failure is
//! not a refusal -- a write to an unimplemented register is silently ignored
//! -- so every offset here is pinned by a test against the value AHCI 1.3
//! names.  The same reasoning `nvme` states for the same class of number.

/// HBA Capabilities: what the controller and its ports can do.
///
/// 32-bit, read-only, §3.1.1.  This driver reads none of it -- a port count
/// from `CAP.NCS` and a speed mask are facts about a controller that answers
/// for itself in `PI` and `PxSSTS` -- but it is named here because the boot's
/// line reports the register, and a reader of a dump will ask where it came
/// from.
pub const AHCI_REG_CAP: usize = 0x0000;

/// Global HBA Control, §3.1.2.
///
/// 32-bit.  `AE` turns the interface on, `HR` starts a HBA reset, `IE`
/// enables interrupts.  A polling driver writes `AE` and nothing else.
pub const AHCI_REG_GHC: usize = 0x0004;

/// Interrupt Status, §3.1.3.
///
/// 32-bit, write-one-to-clear per bit.  A polling driver clears it before a
/// command and reads it for the task-file-error bit afterwards.
pub const AHCI_REG_IS: usize = 0x0008;

/// Ports Implemented, §3.1.5.
///
/// 32-bit, read-only.  Bit `n` set means port `n` is implemented, and this is
/// the register a driver must read before it touches any port: a port the
/// controller does not implement has no register set behind its slot in the
/// array, and a write there lands nowhere at all.
pub const AHCI_REG_PI: usize = 0x000C;

/// AHCI Version, §3.1.6.
///
/// 32-bit, read-only.  BCD: `0x0001_0300` is version 1.3.
pub const AHCI_REG_VS: usize = 0x0010;

/// BIOS/OS Handoff Control and Status, §3.1.8.
pub const AHCI_REG_BOHC: usize = 0x0028;

/// Where the port register blocks begin, in BAR5.
///
/// §3.1.11: the first port's registers sit at `0x100`, and every port's block
/// is `0x80` bytes, up to 32 ports.
pub const PORT_BASE: usize = 0x0100;

/// The stride between two ports' register blocks.
pub const PORT_STRIDE: usize = 0x80;

/// How many ports the specification lets a controller have.
///
/// The `PI` register has one bit per port, so 32 is the width of the answer.
pub const PORT_COUNT: usize = 32;

/// The byte offset of a port register inside a port's block.
///
/// §3.1.11 names these once for every port, so a driver that hardcoded an
/// address per port would be writing the same table thirty-two times.
pub const PORT_CLB: usize = 0x00;
/// Upper half of the command list's base address.
pub const PORT_CLBU: usize = 0x04;
/// The received FIS area's base address.
pub const PORT_FB: usize = 0x08;
/// Upper half of the received FIS area's base address.
pub const PORT_FBU: usize = 0x0C;
/// The port's interrupt status, write-one-to-clear per bit.
pub const PORT_IS: usize = 0x10;
/// The port's interrupt enable.
pub const PORT_IE: usize = 0x14;
/// Command and Status: the engine's start, stop and running bits.
pub const PORT_CMD: usize = 0x18;
/// Task File Data: the device's ATA status and error registers, as the last
/// FIS received carried them.
pub const PORT_TFD: usize = 0x20;
/// The signature the attached device answered its first identify with.
pub const PORT_SIG: usize = 0x24;
/// SATA Status: the link's state, and `DET` in bits 3:0 is what says whether
/// a device is attached.
pub const PORT_SSTS: usize = 0x28;
/// SATA Control, the link's speed and power state, as a driver may set them.
pub const PORT_SCTL: usize = 0x2C;
/// SATA Error, write-one-to-clear per bit.
pub const PORT_SERR: usize = 0x30;
/// SATA Active, the NCQ command bitmap.
pub const PORT_SACT: usize = 0x34;
/// Command Issue: one bit per command-list slot, and the **doorbell**.  A
/// driver sets bit `n` to tell the controller a command is in slot `n`, and
/// the controller clears the bit when the command is done.  A polling driver
/// waits for its bit to clear.
pub const PORT_CI: usize = 0x38;

/// `GHC.AE`: the AHCI interface is enabled.
///
/// A controller the firmware left in IDE mode answers writes to the port
/// registers with nothing at all, which is a driver whose commands are
/// accepted and never executed -- the same silence a wrong doorbell produces,
/// and the reason this bit is checked before any port is touched.
pub const GHC_AE: u32 = 1 << 31;

/// `GHC.HR`: start a HBA reset.
///
/// The bit self-clears, and the reset also clears `AE`, so a driver that
/// resets must re-enable the interface after.
pub const GHC_HR: u32 = 1 << 0;

/// `PxCMD.ST`: the port's command engine is running.
pub const CMD_ST: u32 = 1 << 0;
/// `PxCMD.FRE`: the port receives FISes into the received-FIS area.
pub const CMD_FRE: u32 = 1 << 4;
/// `PxCMD.FR`: the FIS receiver is running, read-only.
///
/// A driver that cleared `FRE` and touched the received-FIS area while `FR`
/// was still set would be rewriting memory the controller is writing.
pub const CMD_FR: u32 = 1 << 14;
/// `PxCMD.CR`: the command list is running, read-only.
///
/// The rule §5.3.3 gives: `ST` may only be cleared after `CR` reads zero, and
/// the command list's pointers may only be written when `CR` and `FR` are
/// both zero.
pub const CMD_CR: u32 = 1 << 15;

/// `PxIS.DHR`: a Device-to-Host Register FIS arrived.
///
/// This is the bit a completed command sets: the device answered the command
/// with its status.
pub const PIS_DHR: u32 = 1 << 0;

/// `PxIS.TFES`: the task file reports an error.
///
/// The bit a failed command sets, and the one a driver reads to distinguish
/// "the command finished" from "the command finished by refusing".
pub const PIS_TFES: u32 = 1 << 30;

/// The value that clears every SError bit at once.
///
/// `PxSERR` is write-one-to-clear, and a driver bringing a port up writes
/// all ones to start the port's error count from zero rather than inherit
/// whatever the firmware's probes left.
pub const SERR_CLEAR_ALL: u32 = 0xFFFF_FFFF;

/// The mask over `PxSSTS.DET`, bits 3:0.
pub const SSTS_DET_MASK: u32 = 0xF;

/// The `DET` value that says a device is attached and the link is up.
///
/// §3.3.2: 3 means "device present and communication established".  1 means
/// present but the link never came up, and 0 means nothing is attached --
/// three states a driver that only checked "non-zero" would confuse.
pub const DET_PRESENT_AND_COMMUNICATING: u32 = 3;

/// The mask over `PxTFD.ERR`, bit 0.
///
/// `PxTFD` carries the ATA status in bits 15:8 and the ATA error register in
/// bits 7:0, and its bit 0 is `ERR`: the last command ended with an error.
pub const TFD_ERR: u32 = 1;

/// The byte offset of a port's register `reg`, in BAR5.
///
/// A port the controller does not implement has no register set behind its
/// slot, so the caller's duty is to have read `PI` first; the arithmetic here
/// is only the specification's stride.
pub const fn port_register(port: u8, reg: usize) -> usize {
    PORT_BASE + (port as usize) * PORT_STRIDE + reg
}

#[cfg(test)]
mod tests {
    //! The offsets are the specification's, asserted as literals.

    use super::*;

    /// The HBA's registers are the ones AHCI 1.3 §3.1 names.
    #[test]
    fn the_hba_registers_are_at_the_specifications_offsets() {
        assert_eq!(AHCI_REG_CAP, 0x0000);
        assert_eq!(AHCI_REG_GHC, 0x0004);
        assert_eq!(AHCI_REG_IS, 0x0008);
        assert_eq!(AHCI_REG_PI, 0x000C);
        assert_eq!(AHCI_REG_VS, 0x0010);
        assert_eq!(AHCI_REG_BOHC, 0x0028);
    }

    /// A port's block starts where the specification puts it, one stride apart.
    #[test]
    fn a_ports_block_is_one_stride_past_the_previous_ports() {
        assert_eq!(port_register(0, PORT_CLB), 0x0100);
        assert_eq!(port_register(1, PORT_CLB), 0x0180);
        assert_eq!(port_register(2, PORT_CLB), 0x0200);
        assert_eq!(port_register(31, PORT_CLB), 0x0100 + 31 * 0x80);
        assert_eq!(PORT_COUNT, 32);
    }

    /// Every port register sits at its own offset inside the block.
    ///
    /// These are the numbers a driver's command path names one by one, and a
    /// wrong one -- `CI` read where `SACT` lives -- is a wait on a bitmap the
    /// controller never clears.
    #[test]
    fn the_port_registers_are_at_the_specifications_offsets() {
        assert_eq!(PORT_CLB, 0x00);
        assert_eq!(PORT_CLBU, 0x04);
        assert_eq!(PORT_FB, 0x08);
        assert_eq!(PORT_FBU, 0x0C);
        assert_eq!(PORT_IS, 0x10);
        assert_eq!(PORT_IE, 0x14);
        assert_eq!(PORT_CMD, 0x18);
        assert_eq!(PORT_TFD, 0x20);
        assert_eq!(PORT_SIG, 0x24);
        assert_eq!(PORT_SSTS, 0x28);
        assert_eq!(PORT_SCTL, 0x2C);
        assert_eq!(PORT_SERR, 0x30);
        assert_eq!(PORT_SACT, 0x34);
        assert_eq!(PORT_CI, 0x38);
    }

    /// The three engine bits and the two status bits are the bits a driver's
    /// sequence reads and writes.
    #[test]
    fn the_engine_and_status_bits_are_the_specifications() {
        assert_eq!(GHC_AE, 1 << 31);
        assert_eq!(GHC_HR, 1);
        assert_eq!(CMD_ST, 1);
        assert_eq!(CMD_FRE, 1 << 4);
        assert_eq!(CMD_FR, 1 << 14);
        assert_eq!(CMD_CR, 1 << 15);
        assert_eq!(PIS_DHR, 1);
        assert_eq!(PIS_TFES, 1 << 30);
        assert_eq!(TFD_ERR, 1);
    }

    /// `DET` is decoded by value, not by "anything non-zero".
    ///
    /// 1 is a device present whose link never came up and 0 is an absent one;
    /// a driver that treated both as "a disk is here" would send IDENTIFY to
    /// a port whose link is dead and wait for a completion that cannot come.
    #[test]
    fn det_is_decoded_by_value() {
        assert_eq!(SSTS_DET_MASK, 0xF);
        assert_eq!(DET_PRESENT_AND_COMMUNICATING, 3);
    }

    /// The port register arithmetic is the stride times the port number.
    #[test]
    fn the_port_arithmetic_is_the_specifications_stride() {
        assert_eq!(port_register(0, PORT_CI), 0x0100 + 0x38);
        assert_eq!(port_register(3, PORT_TFD), 0x0100 + 3 * 0x80 + 0x20);
    }
}
