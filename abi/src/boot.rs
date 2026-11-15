//! abi/src/boot.rs
//!
//! What a loader handed over, in terms no machine owns.
//!
//! The architecture crate parses the handshake, multiboot2 registers, a PVH
//! note, a device tree in a register the machine's own convention names, and
//! the kernel consumes the result.  If the type lived in the kernel, `arch`
//! would have to name it, and that is the one edge this tree exists to forbid:
//! a machine crate that reaches into the scheduler through its own trap handler
//! cannot be read, or tested, without the whole kernel.
//!
//! A type both sides name belongs where both sides can reach it, which is here.
//!
//! The information structure's address, the device tree's address, the memory
//! map.  Those are a loader's own layout, and the architecture crate is what
//! turns one into the other.  This is the *answer* the kernel needs: which
//! loader, so the boot can say so, and whatever else a machine-independent boot
//! step learns for its next stage.

/// What a device tree said, in the terms a boot line reports.
///
/// `arch` produces it and `kernel` prints it, which is the definition this file
/// gives for "a type both sides name".  It is deliberately a summary and not
/// the tree: the tree borrows firmware's memory and lives in `fdt`, and a boot
/// line that carried it would be a line that owned a slice of somebody else's
/// address space.
///
/// Four numbers because four is what a reader comparing a log against a machine
/// needs: whether the blob parsed, what version it claims, how much memory it
/// describes, and where the console is.  A boot whose tree did not parse leaves
/// a different log line and a console at the machine's constant, so these
/// numbers are how the two states are told apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceTreeSummary {
    /// The header's version.
    pub version: u32,
    /// How many `device_type = "memory"` regions the tree describes.
    pub memory_regions: u32,
    /// Where the tree says the console is, or zero if it does not say.
    pub uart: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BootInfo {
    /// Which loader brought this image up, for the boot's first line.
    pub loader: Loader,
}

/// Named rather than numbered because it is printed: a reader comparing a log
/// line against a boot argument is doing the work this enum saves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Loader {
    /// GRUB or another multiboot2 loader.
    Multiboot2,
    /// QEMU's `-kernel`, through the PVH ELF note.
    Pvh,
    /// A device tree handed over by firmware.
    DeviceTree,
}

impl Loader {
    /// The word the boot's first line uses.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Multiboot2 => "multiboot2",
            Self::Pvh => "pvh",
            Self::DeviceTree => "dtb",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Loader;

    /// The words appear in boot logs, and a log line that said "pvh" for a
    /// device-tree boot would send a reader to the wrong code.
    #[test]
    fn each_loader_has_its_own_word() {
        let words = [
            Loader::Multiboot2.as_str(),
            Loader::Pvh.as_str(),
            Loader::DeviceTree.as_str(),
        ];
        for (i, word) in words.iter().enumerate() {
            assert!(!word.is_empty());
            for other in &words[i + 1..] {
                assert_ne!(word, other);
            }
        }
    }
}
