//! arch/x86_64/src/gdt.rs
//!
//! The descriptor table, the segments in it, and the task state segment.
//!
//! ## Why the boot's table is not enough
//!
//! `boot-x86-64.S` builds a three-entry table so the kernel can run in long
//! mode: a null descriptor, a ring-0 code segment and a ring-0 data segment.
//! That is the whole of what an image needs to execute its first instruction,
//! and it is not enough for a program, for two separate reasons.
//!
//! **A program needs a segment it may enter.**  `iretq` to ring 3 loads `CS`
//! and `SS` from selectors the caller pushes, and the processor checks the two
//! descriptors' DPL against the ring being entered.  With no DPL-3 descriptors
//! there is no selector that would pass, so ring 3 is not "not implemented" in
//! the sense of missing code — it is not *representable* in this table.
//!
//! **A ring transition needs a stack the CPU can find.**  Entering ring 0 from
//! ring 3, the processor refuses to use the ring-3 stack: it must load `RSP`
//! from somewhere privileged, and that somewhere is `TSS.RSP0`.  A machine with
//! no TSS loaded therefore cannot take an interrupt from ring 3 at all — it
//! takes a triple fault instead, which is exactly what an empty `RSP0` would
//! produce.
//!
//! ## Why the descriptors are written as constants
//!
//! A long-mode descriptor is eight bytes of bit fields, and the three that
//! matter here are the same three the boot's table already spells: present,
//! DPL, and the type.  Writing them as named constants with the bit positions
//! beside them is what makes the user descriptors checkable by a test; a
//! builder with a dozen arguments would be a second description of the same
//! bits, and the two would drift.
//!
//! ## What this module does not do
//!
//! It does not allocate an interrupt stack, and it does not use `IST`.  An
//! `IST` entry is for a vector that must run even when the current stack is
//! suspect — a double fault, a machine check, an NMI.  This kernel's ring-3
//! path uses `RSP0`, which is the ordinary mechanism, and a second stack per
//! CPU would be a promise about the stack's size that nothing here needs yet.

/// The kernel's code segment, as the boot's table gives it.
pub const KERNEL_CODE_SELECTOR: u16 = 0x08;

/// The kernel's data segment, as the boot's table gives it.
pub const KERNEL_DATA_SELECTOR: u16 = 0x10;

/// The entry a program's data segment occupies.
///
/// Entry 3, selector `0x18`.  The value has to agree with the descriptor index
/// `install` writes, and the two are one fact: a selector is its index times
/// eight, which is why this is arithmetic on the index rather than a second
/// constant.
pub const USER_DATA_INDEX: usize = 3;

/// The entry a program's code segment occupies.
pub const USER_CODE_INDEX: usize = 4;

/// The entry the task state segment's descriptor occupies.
///
/// A TSS descriptor is **sixteen** bytes in long mode — a normal descriptor
/// plus the upper half of a 64-bit base address — so it occupies two entries.
/// That is why the table has seven slots for five descriptors.
pub const TSS_INDEX: usize = 5;

/// The selector naming the user data segment.
pub const USER_DATA_SELECTOR: u16 = (USER_DATA_INDEX as u16) * 8;

/// The selector naming the user code segment.
pub const USER_CODE_SELECTOR: u16 = (USER_CODE_INDEX as u16) * 8;

/// The selector naming the TSS descriptor.
pub const TSS_SELECTOR: u16 = (TSS_INDEX as u16) * 8;

/// A descriptor for a 64-bit code segment at `dpl`.
///
/// The bits, and where they live in the eight-byte word:
///
/// ```text
/// bits 0..15    limit 0..15
/// bits 16..39   base 0..23          (zero: long mode ignores the base)
/// bits 40..43   type                0b1010 is "code, execute/read"
/// bit  44       S                   must be 1 for code or data
/// bits 45..46   DPL                 the ring the segment belongs to
/// bit  47       P                   present
/// bits 48..51   limit 16..19
/// bit  53       L                   long mode: this is a 64-bit segment
/// bit  55       G                   granularity
/// ```
///
/// ## Why the shifts are 40 and not 8
///
/// The type byte, `S`, the DPL and `P` are the descriptor's **second** byte as
/// the processor reads it — bits 40..47 of the 64-bit word.  The first version
/// of this function wrote them at bits 8..15, which is the limit's low half, so
/// every descriptor it built had a type of zero, `P` of zero and a limit of
/// `0xE200`.  The processor refused the first `mov ds` with a general
/// protection fault carrying selector index 2 — the segment this table had just
/// failed to define.  QEMU's `-d int` showed `v=0d e=0010` at the `mov %ax,%ds`
/// one instruction after a `lgdt` that had already succeeded, which is what
/// pointed at the descriptor rather than at the register.
///
/// The values below are the boot table's own, which is what a descriptor has to
/// agree with: `boot-x86-64.S` enters long mode with `0x00AF_9A00_0000_FFFF`
/// as its code segment, and a kernel table that disagreed would fault on the
/// first `retf` rather than here.
pub const fn code_descriptor(dpl: u8) -> u64 {
    const BASE: u64 = 0x00AF_9A00_0000_FFFF;
    (BASE & !(0b11 << 45)) | (((dpl & 0b11) as u64) << 45)
}

/// A descriptor for a 64-bit data segment at `dpl`.
///
/// Type `0b0010` is read/write data and the rest matches the boot's
/// `0x00AF_9200_0000_FFFF`.  In long mode a data segment's base and limit are
/// ignored, so the only bits that matter are the type, `S`, `P` and the DPL —
/// and a descriptor that omitted `P` is one the processor refuses to load,
/// which is the failure this table's shape has already produced once.
pub const fn data_descriptor(dpl: u8) -> u64 {
    const BASE: u64 = 0x00AF_9200_0000_FFFF;
    (BASE & !(0b11 << 45)) | (((dpl & 0b11) as u64) << 45)
}

/// The task state segment.
///
/// Only three fields of it mean anything in long mode, and only one is written
/// by this kernel: `privilege_stack_table[0]`, the `RSP0` a ring transition to
/// ring 0 loads.  The rest exist because the descriptor's limit describes this
/// layout and the processor reads it at fixed offsets — a structure that
/// omitted a field would put `RSP0` at the wrong offset.
///
/// The I/O map base is set past the end of the structure, which is how a TSS
/// says "this process may not use `in`/`out`": a base beyond the limit makes
/// every port access trap.  That matters even at ring 3, where `in`/`out` are
/// already privileged — an unset base of zero would have the processor read the
/// beginning of this structure as a permission bitmap.
#[repr(C, packed)]
pub struct TaskStateSegment {
    reserved0: u32,
    /// `RSP0..RSP2`: the stack a transition to ring 0, 1 or 2 loads.
    privilege_stack_table: [u64; 3],
    reserved1: u64,
    /// The stacks an `IST` index names.  Unused, and present because the
    /// offsets below them are fixed.
    interrupt_stack_table: [u64; 7],
    reserved2: u64,
    reserved3: u16,
    /// Where the I/O permission bitmap begins, as an offset into this
    /// structure.  Past the end means no ports.
    io_map_base: u16,
}

/// The TSS's size, which is its descriptor's limit plus one.
pub const TSS_SIZE: usize = core::mem::size_of::<TaskStateSegment>();

impl TaskStateSegment {
    /// A TSS with no stack and no I/O permission.
    pub const fn new() -> TaskStateSegment {
        TaskStateSegment {
            reserved0: 0,
            privilege_stack_table: [0; 3],
            reserved1: 0,
            interrupt_stack_table: [0; 7],
            reserved2: 0,
            reserved3: 0,
            io_map_base: TSS_SIZE as u16,
        }
    }

    /// The stack a ring transition to ring 0 will use.
    ///
    /// This is the one field a boot must write: an `RSP0` of zero is a stack
    /// pointer of zero, and the first interrupt from ring 3 pushes its frame
    /// there and takes a page fault — at ring 0, with no frame, which is a
    /// triple fault and a reset.
    pub fn set_rsp0(&mut self, stack_top: usize) {
        self.privilege_stack_table[0] = stack_top as u64;
    }

    /// The `RSP0` the descriptor describes, read back.
    pub fn rsp0(&self) -> u64 {
        self.privilege_stack_table[0]
    }

    /// Whether the I/O map base is past the structure, which is "no ports".
    pub const fn denies_ports(&self) -> bool {
        (self.io_map_base as usize) >= TSS_SIZE
    }
}

impl Default for TaskStateSegment {
    fn default() -> Self {
        Self::new()
    }
}

/// The eight-byte words of a table with room for all five descriptors.
///
/// Seven words: null, kernel code, kernel data, user data, user code, and the
/// two halves of the TSS.
pub const TABLE_WORDS: usize = 7;

/// Build the table's words, given the TSS's address.
///
/// A free function over an array so a host test can check the bits without a
/// machine, which is the same reason `idt::Gate` is a plain structure: the
/// descriptor layout is arithmetic and the only machine part is where the table
/// goes.
pub const fn table_words(tss_address: u64) -> [u64; TABLE_WORDS] {
    let limit = (TSS_SIZE - 1) as u64;
    // The TSS descriptor's low half: limit 0..15, base 0..23, type `0b1001`
    // (available 64-bit TSS), S = 0, DPL 0, present.
    //
    // The type is `0b1001` and not `0b1011`: `0b1011` is a *busy* TSS, which
    // the processor sets when it starts using one, and loading a busy TSS with
    // `ltr` faults.
    let low = (limit & 0xFFFF)
        | ((tss_address & 0x00FF_FFFF) << 16)
        | (0b1001 << 40)
        | (1 << 47)
        | (((limit >> 16) & 0xF) << 48)
        | (((tss_address >> 24) & 0xFF) << 56);
    let high = tss_address >> 32;

    [
        0,
        code_descriptor(0),
        data_descriptor(0),
        data_descriptor(3),
        code_descriptor(3),
        low,
        high,
    ]
}

/// What `lgdt` reads: the table's length minus one, and its address.
#[repr(C, packed)]
pub struct DescriptorPointer {
    limit: u16,
    base: u64,
}

impl DescriptorPointer {
    /// The pointer for a table of `TABLE_WORDS` words.
    pub const fn new(base: u64) -> DescriptorPointer {
        DescriptorPointer {
            limit: (core::mem::size_of::<[u64; TABLE_WORDS]>() - 1) as u16,
            base,
        }
    }

    /// The limit, which is the last valid byte's offset.
    pub const fn limit(&self) -> u16 {
        self.limit
    }

    /// The table's address.
    pub const fn base(&self) -> u64 {
        self.base
    }
}

// The descriptors' bits, checked rather than described.
//
// These are `const` assertions and not tests because they are relations between
// constants: a data descriptor whose DPL said ring 0 would make the user code
// segment unreachable from ring 3, and the failure would be a general
// protection fault at the first `iretq` with no clue which descriptor was
// wrong.
const _: () = assert!(USER_DATA_SELECTOR == 0x18);
const _: () = assert!(USER_CODE_SELECTOR == 0x20);
const _: () = assert!(TSS_SELECTOR == 0x28);
const _: () = assert!(TABLE_WORDS * 8 == 56);
// A TSS descriptor is two entries, so the table holds five descriptors in
// seven words — the relation that makes the size of the array a fact.
const _: () = assert!(TSS_INDEX + 2 == TABLE_WORDS);

#[cfg(target_os = "none")]
mod bare {
    use super::DescriptorPointer;
    use super::TABLE_WORDS;
    use super::TaskStateSegment;
    use super::table_words;

    /// The table the machine is loaded with.
    ///
    /// Written by [`install`] and read back by [`installed`]: the words depend
    /// on the TSS's address, which is only known at run time.
    static TABLE: cell::SyncUnsafeCell<[u64; TABLE_WORDS]> =
        cell::SyncUnsafeCell::new([0; TABLE_WORDS]);

    /// The TSS itself.
    ///
    /// A `static` rather than an allocation because `ltr` takes a selector and
    /// the descriptor names an address, and an address into the heap would
    /// become invalid the moment the heap moved anything — which nothing does,
    /// but a TSS whose location is a promise about an allocator is a worse
    /// promise than one whose location is a symbol.
    static TSS: cell::SyncUnsafeCell<TaskStateSegment> =
        cell::SyncUnsafeCell::new(TaskStateSegment::new());

    /// Load the table, load the TSS, and reload every segment selector.
    ///
    /// Answers whether the machine kept both.  The read-back is the point: a
    /// `lgdt` whose table was not where the pointer said leaves the processor
    /// on the boot's table, and the first `iretq` to ring 3 then faults on a
    /// missing descriptor rather than at anything this function did.
    ///
    /// ## Why the segments are reloaded
    ///
    /// The boot's table already gave `DS`, `ES` and `SS` the value `0x10`, and
    /// this table's entry 2 is the same descriptor — so the reload is not
    /// strictly needed for them.  It is done anyway because a segment register
    /// caches the descriptor it was loaded with, and this table's descriptors
    /// are new words at a new address; a cached descriptor from the old table
    /// would be a descriptor this module did not write.  `CS` needs no reload:
    /// it is repositioned by the `retf` the boot already performed, and entry 1
    /// holds the same bits.
    ///
    /// # Safety
    ///
    /// Called once, after the console is up and before anything enters ring 3.
    /// `stack_top` must be a writable kernel stack with room for a trap frame,
    /// because it is what every interrupt from ring 3 will run on.
    pub unsafe fn install(stack_top: usize) -> bool {
        // SAFETY: both statics are this module's, and this is the only writer.
        let tss = unsafe { &mut *TSS.get() };
        tss.set_rsp0(stack_top);

        let tss_address = tss as *mut TaskStateSegment as u64;
        // SAFETY: as above — the table's only writer.
        let table = unsafe { &mut *TABLE.get() };
        *table = table_words(tss_address);

        let descriptor = DescriptorPointer::new(table.as_ptr() as u64);
        let address = &descriptor as *const DescriptorPointer;
        // SAFETY: `descriptor` names the table just filled, which is a
        // seven-word static; `lgdt` takes effect for the next descriptor load.
        unsafe {
            core::arch::asm!("lgdt [{}]", in(reg) address, options(readonly, nostack, preserves_flags));
        }

        // The data segments, then the TSS.  `ltr` reads entry 5, which is why
        // it comes after `lgdt` and not before.
        //
        // SAFETY: the selectors name entries of the table just loaded, and the
        // ring-0 data descriptor is entry 2 — the same bits the boot loaded.
        unsafe {
            core::arch::asm!(
                "mov ax, 0x10",
                "mov ds, ax",
                "mov es, ax",
                "mov fs, ax",
                "mov gs, ax",
                "mov ss, ax",
                options(nostack, preserves_flags)
            );
            core::arch::asm!("ltr ax", in("ax") super::TSS_SELECTOR, options(nostack, preserves_flags));
        }

        // Both registers read back, and the TSS's descriptor is what `str`
        // answers: a selector, so a machine that ignored `ltr` reports zero.
        let loaded = installed();
        let task = task_register();
        loaded.base() == table.as_ptr() as u64 && task == super::TSS_SELECTOR
    }

    /// The table the processor is reading, from `sgdt`.
    pub fn installed() -> DescriptorPointer {
        let mut descriptor = DescriptorPointer { limit: 0, base: 0 };
        let address = &mut descriptor as *mut DescriptorPointer;
        // SAFETY: `sgdt` writes ten bytes into the structure this declares,
        // which is exactly its size.
        unsafe {
            core::arch::asm!("sgdt [{}]", in(reg) address, options(nostack));
        }
        descriptor
    }

    /// The task register, which holds the TSS selector once `ltr` ran.
    pub fn task_register() -> u16 {
        let selector: u16;
        // SAFETY: `str` reads the task register; unprivileged at ring 0 and
        // with no side effect.
        // `str` writes a 16-bit selector, so the register is formatted as one:
        // the default for a `u16` operand is the full-width name, which the
        // assembler accepts and warns about.
        unsafe {
            core::arch::asm!(
                "str {selector:x}",
                selector = out(reg) selector,
                options(nomem, nostack, preserves_flags)
            );
        }
        selector
    }

    /// The `RSP0` the loaded TSS holds, by reading it back through the
    /// descriptor.
    ///
    /// A boot line reports this rather than the value it wrote: `set_rsp0` is a
    /// store into a static, and the claim that matters is that the processor
    /// will find the stack where the descriptor says.
    pub fn rsp0_in_memory() -> u64 {
        // SAFETY: the static is this module's, and the read is after `install`.
        let tss = unsafe { &*TSS.get() };
        tss.rsp0()
    }
}

#[cfg(target_os = "none")]
pub use bare::install;
#[cfg(target_os = "none")]
pub use bare::installed;
#[cfg(target_os = "none")]
pub use bare::rsp0_in_memory;
#[cfg(target_os = "none")]
pub use bare::task_register;

/// The kernel stack's top, as the boot assembly published it.
///
/// `RSP0` has to name a stack this kernel is actually running on: an interrupt
/// from ring 3 pushes its frame at that address, and a separate stack declared
/// here would be one nothing else uses — the trap would land somewhere the
/// kernel has no state, and the return path would push onto a stack the boot's
/// call frames had already described differently.
#[cfg(target_os = "none")]
pub fn kernel_stack_top() -> usize {
    unsafe extern "C" {
        static kstack_top: u8;
    }
    // `addr_of!` takes the address without creating a reference: the symbol
    // marks the end of the boot stack's storage, and there is no value there.
    core::ptr::addr_of!(kstack_top) as usize
}

#[cfg(test)]
mod tests {
    use super::TABLE_WORDS;
    use super::TSS_SELECTOR;
    use super::TSS_SIZE;
    use super::USER_CODE_SELECTOR;
    use super::USER_DATA_SELECTOR;
    use super::code_descriptor;
    use super::data_descriptor;
    use super::table_words;

    /// The descriptors agree with the boot table's, bit for bit.
    ///
    /// This is the test the first version needed and did not have.  That
    /// version asserted the DPL at bits 13..14 and `P` at bit 15 — the limit's
    /// low half — so the assertions passed on descriptors the processor
    /// refused to load, and a boot died at `mov %ax,%ds` with
    /// `v=0d e=0010` one instruction after a successful `lgdt`.
    ///
    /// The boot's own words are the oracle: `boot-x86-64.S` enters long mode
    /// with `0x00AF_9A00_0000_FFFF` as its code segment.  A kernel table that
    /// disagreed with the table the processor is already running in is a table
    /// that faults at the first segment reload.
    #[test]
    fn the_descriptors_are_the_boots_own_words() {
        assert_eq!(code_descriptor(0), 0x00AF_9A00_0000_FFFF);
        assert_eq!(data_descriptor(0), 0x00AF_9200_0000_FFFF);
    }

    /// The type byte, `S`, the DPL and `P` are bits 40..47 — the descriptor's
    /// second byte as the processor reads it, and not the limit's low half.
    #[test]
    fn the_type_byte_is_the_descriptors_second_byte() {
        let code = code_descriptor(0);
        assert_eq!((code >> 40) & 0xFF, 0x9A, "present, DPL 0, code, S = 1");
        assert_eq!(
            (code >> 8) & 0xFF,
            0xFF,
            "the limit's low half is the boot's, not the type byte's"
        );

        let data = data_descriptor(0);
        assert_eq!((data >> 40) & 0xFF, 0x92, "present, DPL 0, data, S = 1");
        assert_eq!((data >> 8) & 0xFF, 0xFF, "and the same here");
    }

    /// The user descriptors say ring 3, and the kernel's say ring 0.
    ///
    /// The DPL is bits 45..46.  This is the descriptor the first `iretq` into a
    /// program checks: a DPL-0 user code segment is a general protection fault
    /// at the `iretq`, with the frame's selectors already popped.
    #[test]
    fn the_user_segments_are_ring_three_and_the_kernels_are_not() {
        let user_code = code_descriptor(3);
        let user_data = data_descriptor(3);
        let kernel_code = code_descriptor(0);

        assert_eq!((user_code >> 45) & 0b11, 3, "the user code segment's DPL");
        assert_eq!((user_data >> 45) & 0b11, 3, "the user data segment's DPL");
        assert_eq!((kernel_code >> 45) & 0b11, 0, "and the kernel's stays 0");

        // Present, S = 1, and the type field.  A descriptor missing `P` is one
        // the processor refuses to load — which is what happened.
        for descriptor in [user_code, user_data, kernel_code] {
            assert_ne!(descriptor & (1 << 47), 0, "present");
            assert_ne!(descriptor & (1 << 44), 0, "S: a code or data descriptor");
        }
        assert_eq!((user_code >> 40) & 0xF, 0xA, "code, execute/read");
        assert_eq!((user_data >> 40) & 0xF, 0x2, "data, read/write");
    }

    /// A 64-bit code segment sets `L`, and `D` is clear beside it.
    ///
    /// `L` (bit 53) is what makes a code segment a 64-bit one, and the
    /// processor refuses to enter a long-mode code segment without it.  `D`
    /// (bit 54) must be zero whenever `L` is set; a descriptor with both is an
    /// invalid one.
    ///
    /// The data descriptor carries the boot's flags nibble unchanged, `L`
    /// included.  On a data segment that bit is reserved and ignored, so it is
    /// left as the boot wrote it rather than cleared: this table has to agree
    /// with the table the processor is already running in, and "agrees with the
    /// boot" is the property that keeps the first segment reload from faulting.
    #[test]
    fn the_code_segment_is_a_long_mode_segment() {
        assert_ne!(code_descriptor(0) & (1 << 53), 0, "L is set on code");
        assert_eq!(
            code_descriptor(0) & (1 << 54),
            0,
            "D is clear on a 64-bit code segment"
        );
        assert_eq!(
            (data_descriptor(0) >> 52) & 0xF,
            (0x00AF_9200_0000_FFFFu64 >> 52) & 0xF,
            "and the data segment's flags are the boot's"
        );
    }

    /// The selectors are their indices times eight, and the TSS is last.
    #[test]
    fn the_selectors_are_the_indices_times_eight() {
        assert_eq!(USER_DATA_SELECTOR, 0x18);
        assert_eq!(USER_CODE_SELECTOR, 0x20);
        assert_eq!(TSS_SELECTOR, 0x28);
        assert_eq!(USER_DATA_SELECTOR as usize, super::USER_DATA_INDEX * 8);
        assert_eq!(TSS_SELECTOR as usize, super::TSS_INDEX * 8);
    }

    /// The `RSP0` sits at offset four, which is where the processor reads it.
    ///
    /// The structure is padded exactly as the hardware's layout says: a 32-bit
    /// reserved word, then three 64-bit stack pointers.  A structure that
    /// omitted the reserved word would put `RSP0` at zero and the processor
    /// would load a stack pointer from the reserved field.
    #[test]
    fn the_stack_pointer_is_where_the_processor_reads_it() {
        assert_eq!(
            core::mem::offset_of!(super::TaskStateSegment, privilege_stack_table),
            4
        );
        assert_eq!(TSS_SIZE, 104, "the layout long mode defines");
    }

    /// The TSS descriptor is sixteen bytes: limit, base, type, and the base's
    /// upper half.
    ///
    /// It occupies two of the table's eight-byte words, which is why the table
    /// has seven words for five descriptors.
    #[test]
    fn the_tss_descriptor_occupies_two_words() {
        let words = table_words(0x1234_5678_9ABC_DEF0);
        assert_eq!(words.len(), TABLE_WORDS);
        assert_eq!(super::TSS_INDEX + 2, TABLE_WORDS);

        let low = words[super::TSS_INDEX];
        let high = words[super::TSS_INDEX + 1];
        // A type of `0b1001` — available 64-bit TSS.  `0b1011` is *busy*, and
        // `ltr` faults on a busy TSS, which is the mistake this pins.
        assert_eq!((low >> 40) & 0xF, 0b1001, "available, not busy");
        assert_eq!((low >> 45) & 0b11, 0, "DPL 0: only the kernel loads a TSS");
        assert_ne!(low & (1 << 47), 0, "present");
        assert_eq!(high, 0x1234_5678, "the base's upper half");
    }

    /// The TSS descriptor's limit is the structure's size minus one.
    #[test]
    fn the_limit_is_the_size_minus_one() {
        let words = table_words(0x1000);
        let low = words[super::TSS_INDEX];
        let limit_low = low & 0xFFFF;
        let limit_high = (low >> 48) & 0xF;
        assert_eq!((limit_high << 16) | limit_low, (TSS_SIZE - 1) as u64);
    }

    /// A TSS with no stack set says so, and one that was set reports what it
    /// was given.
    ///
    /// The I/O map base is the part that matters beyond `RSP0`: a base of zero
    /// would have the processor read the beginning of this structure as a port
    /// permission bitmap, which is a bitmap of the `RSP0` value.
    #[test]
    fn a_tss_denies_ports_until_its_stack_is_set() {
        let mut tss = super::TaskStateSegment::new();
        assert!(tss.denies_ports(), "no ports without a bitmap");
        assert_eq!(tss.rsp0(), 0, "a fresh TSS has no stack");

        tss.set_rsp0(0x80_0000_3000);
        assert_eq!(tss.rsp0(), 0x80_0000_3000);
    }
}
