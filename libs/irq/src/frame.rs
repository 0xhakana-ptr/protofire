//! libs/irq/src/frame.rs
//!
//! What a machine hands its dispatch: the vector, and as much of the
//! interrupted context as every machine agrees on.
//!
//! ## Why this is here and not in `arch`
//!
//! A handler that wanted to know "which vector" would have to name three
//! machines' frame types.  The vector is the one thing every machine reports;
//! a page-fault handler also wants the faulting address, which every machine
//! also has, and the direction the access went, which each machine reports in
//! its own currency.  Those are the two extra fields this type carries.
//!
//! What is deliberately not here: the register set.  x86_64 saves fifteen
//! registers and pushes an error code, aarch64 saves thirty-one and a syndrome,
//! riscv64 saves thirty-two and a cause.  A type that carried all of them would
//! be a union of three machines' conventions, and the first handler to read a
//! field that meant something else would be a bug no test would catch.
//!
//! A handler that needs the interrupted registers asks the machine's `arch`
//! crate for them, which is the same rule every other machine question follows.

/// What the kernel knows about an interrupt before anyone handles it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame {
    /// Which vector the machine raised.
    ///
    /// A machine's own numbering.  The kernel treats it as the identity a
    /// handler registers under, because on every machine here the number a
    /// controller assigns is the number a handler claims.
    pub vector: usize,
    /// The address a faulting access named, or zero for a vector that is not a
    /// fault.
    ///
    /// `CR2` on x86_64, `FAR_EL1` on aarch64, `stval` on riscv64.  A handler
    /// for a page fault needs it, and every machine has it, which is why it is
    /// the one field besides the vector that a frame carries.
    pub fault_address: usize,
    /// Whether the faulting access was a write, or `None` when the vector did
    /// not fault.
    ///
    /// The direction is what separates a page that may not be read from one
    /// that may not be written, and a copy-on-write handler cannot work without
    /// it: a write fault on a shared page is the whole event that a copy
    /// answers, and a read fault on the same page is a program reaching an
    /// address it was never given.
    ///
    /// `Option` and not a `bool` because a device's interrupt has no
    /// direction.  A `false` there would read as "the access was a read",
    /// which is a statement about an access that never happened — the same
    /// reason [`fault_address`](Self::fault_address) is zero rather than
    /// meaningful for a device's frame.
    ///
    /// Every machine reports it differently: x86_64 in the error code's bit 1,
    /// aarch64 in `ESR_EL1`'s WnR bit (bit 6), riscv64 in the cause's own
    /// value, where a store page fault and a load page fault are two numbers.
    pub write: Option<bool>,
}

impl Frame {
    /// A frame for `vector` with no faulting address.
    ///
    /// What a device's interrupt reports: the line it arrived on says
    /// everything there is to know, and a fault address of zero is the
    /// machine's own answer for a vector that did not fault.
    pub const fn device(vector: usize) -> Frame {
        Frame {
            vector,
            fault_address: 0,
            write: None,
        }
    }

    /// A frame for `vector` whose `write` access faulted at `fault_address`.
    pub const fn fault(vector: usize, fault_address: usize, write: bool) -> Frame {
        Frame {
            vector,
            fault_address,
            write: Some(write),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Frame;

    /// A device's frame carries its vector and no fault address.
    #[test]
    fn a_device_frame_has_no_fault_address() {
        let frame = Frame::device(32);
        assert_eq!(frame.vector, 32);
        assert_eq!(frame.fault_address, 0);
    }

    /// A device's frame has no access direction.
    ///
    /// `None` and not `Some(false)`: a device's line is not a read, and a
    /// handler that treated it as one would be answering a question the
    /// machine never asked.
    #[test]
    fn a_device_frame_has_no_direction() {
        assert_eq!(Frame::device(32).write, None);
    }

    /// A fault's frame carries both.
    ///
    /// The page-fault handler needs the address, and a frame that dropped it
    /// would leave that handler asking the machine a second question about an
    /// event that has already passed.
    #[test]
    fn a_fault_frame_carries_the_address() {
        let frame = Frame::fault(14, 0xDEAD_0000, true);
        assert_eq!(frame.vector, 14);
        assert_eq!(frame.fault_address, 0xDEAD_0000);
    }

    /// A fault's frame carries its direction, and the two differ.
    ///
    /// This is the field a copy-on-write handler branches on, and a frame that
    /// reported every fault as a read would send a write to a shared page
    /// down the "the program reached an address it was never given" path.
    #[test]
    fn a_fault_frame_carries_its_direction() {
        assert_eq!(Frame::fault(14, 0x1000, true).write, Some(true));
        assert_eq!(Frame::fault(14, 0x1000, false).write, Some(false));
    }
}
