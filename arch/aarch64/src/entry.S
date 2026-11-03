/* File: arch/aarch64/src/entry.S */
/* Purpose: Where a bootloader or QEMU's -kernel puts an aarch64 image, and the
   three things a Rust `no_std` target needs done before it can run.

   ## What the firmware guarantees

   QEMU's `virt` machine with `-kernel` enters at the image's first byte, at
   EL1, with the MMU off and the caches off.  `%x0` holds the device tree's
   address — the one thing a device-tree machine hands over — and the rest of
   the registers are undefined.

   There is no handshake to check: a multiboot2 loader passes a magic and a
   kernel that did not receive one refuses to run, but a device-tree machine
   either loaded you or it did not.  So this does not test anything; it sets up
   and calls.

   ## What has to happen first

   1. **A stack.**  Nothing can be called without one, and the firmware leaves
      `SP` undefined at EL1.
   2. **The bss cleared.**  A `no_std` image is loaded from a file; the bytes
      the linker reserved for `.bss` are not in it, and a boot that assumed
      they were zero would find whatever the firmware left.
   3. **The exception level checked.**  This kernel runs at EL1.  A boot that
      arrived at EL2 — a hypervisor's guest — has to drop, and one that arrived
      at EL3 has to drop twice.  Doing that here is simpler than trusting the
      firmware.

   The code reads the current EL from `CurrentEL`, and drops to EL1 from EL2 if
   it has to.  EL3 is not handled: no machine this tree targets enters there,
   and a boot that did would be one whose firmware did something unusual. */

.section .text.boot, "ax"
.global _start
_start:
    /* Step 3 first, because a drop to EL1 discards what the registers hold and
       a boot at EL2 would otherwise set up a stack it cannot use. */
    mrs x1, CurrentEL
    lsr x1, x1, #2
    cmp x1, #2
    b.eq 1f
    cmp x1, #1
    b.eq 2f
    /* EL3 or EL0: not a state this kernel can start in. */
    b 3f

1:  /* At EL2: configure and drop to EL1. */
    mov x1, #(1 << 31)              /* HCR_EL2.RW: EL1 is AArch64 */
    msr hcr_el2, x1
    mov x1, #0x3c5                  /* SPSR_EL2: EL1h, DAIF masked */
    msr spsr_el2, x1
    adr x1, 2f
    msr elr_el2, x1
    eret

2:  /* At EL1: set up the stack, clear .bss, and call into Rust. */
    ldr x1, =_stack_top
    mov sp, x1

    /* FP/SIMD, before the first Rust instruction runs.
     *
     * `CPACR_EL1.FPEN` (bits 21:20) resets to zero, which traps every FP and
     * Advanced-SIMD instruction to EL1 — *from EL1 as well as from EL0*.  That
     * is not theoretical here: this boot printed four lines and stopped, and
     * the cause was `ESR_EL1.EC` = 7 at a `0x0E01...` word, a NEON instruction
     * LLVM emitted for the `memcpy` that builds the PyroFS image.  Everything
     * before it was scalar.
     *
     * `0b11` permits EL1 and EL0.  EL0 is set now rather than when user mode
     * arrives, because the value is a permission and a kernel that will hand a
     * program an FP register has already decided it may: a user process faults
     * on its first `fmov` under any narrower setting. */
    mrs x1, cpacr_el1
    orr x1, x1, #(0b11 << 20)
    msr cpacr_el1, x1
    isb

    /* `x0` still holds the device tree pointer, which is what the kernel's
       `boot_info` reads.  `x19` is callee-saved, so it survives the clear. */
    mov x19, x0

    ldr x1, =__bss_start
    ldr x2, =__bss_end
4:  cmp x1, x2
    b.hs 5f
    str xzr, [x1], #8
    b 4b
5:
    /* The vector table, before anything that could fault. */
    ldr x1, =exception_vectors
    msr vbar_el1, x1
    isb

    /* The device tree pointer, recorded before anything reads it.
     *
     * `protofire_entry` takes no arguments: `bootloader` is the protocol and it
     * must not learn which register held what.  So the machine keeps the value
     * and the module above asks for it — the same arrangement the trap sink
     * uses, and for the same reason.
     *
     * `x19` holds what `x0` did on entry; the clear of `.bss` above did not
     * touch it because it is callee-saved. */
    mov x0, x19
    bl aarch64_set_device_tree

    /* The protocol's entry, not the kernel's: `bootloader` is where "a loader
       put us here, so start the kernel" lives, and this file is the machine.
       The two meet at a symbol rather than at a crate edge, because `arch` is
       below `bootloader` and an upward import is the one thing the layering
       gate forbids. */
    bl protofire_entry

3:  /* Nowhere left to go. */
    wfe
    b 3b

/* The exception vector table: sixteen entries, 128 bytes each, 2 KiB aligned,
   as `VBAR_EL1` requires.

   ## Why each entry sets a number and branches

   The architecture gives each entry 128 bytes — thirty-two instructions — so a
   handler can save what it needs before branching.  The sixteen entries differ
   only in *which* exception they are, so each one records its own index in
   `x16` and branches to the one path that does the work.  `x16` is the
   platform's intra-procedure register, so an entry may use it before anything
   is saved.

   The number is the entry's position, which is the architecture's own layout:
   `(group * 4) + kind`, where the group is where the exception came from and
   the kind is the fourth of that group it belongs to.  Rust reads it back as
   [`crate::trap::ExceptionFrame::vector`], which is why it is a register and
   not a convention to guess at.

   The table is 2 KiB and the alignment is the same number: the register's low
   eleven bits are reserved, so a table that did not respect them is one the
   machine reads from a shifted base. */

.section .text.vectors, "ax"
.balign 2048
.global exception_vectors
exception_vectors:
    /* Current EL with SP_EL0: 0..3. */
    mov x16, #0
    b exception_entry
    .balign 128
    mov x16, #1
    b exception_entry
    .balign 128
    mov x16, #2
    b exception_entry
    .balign 128
    mov x16, #3
    b exception_entry
    .balign 128
    /* Current EL with SP_ELx — what the kernel takes: 4..7. */
    mov x16, #4
    b exception_entry
    .balign 128
    mov x16, #5
    b exception_entry
    .balign 128
    mov x16, #6
    b exception_entry
    .balign 128
    mov x16, #7
    b exception_entry
    .balign 128
    /* Lower EL, AArch64: 8..11. */
    mov x16, #8
    b exception_entry
    .balign 128
    mov x16, #9
    b exception_entry
    .balign 128
    mov x16, #10
    b exception_entry
    .balign 128
    mov x16, #11
    b exception_entry
    .balign 128
    /* Lower EL, AArch32: 12..15.  Not supported, and reported as such. */
    mov x16, #12
    b exception_entry
    .balign 128
    mov x16, #13
    b exception_entry
    .balign 128
    mov x16, #14
    b exception_entry
    .balign 128
    mov x16, #15
    b exception_entry

/* The one path every entry reaches.

   ## What it saves, and why all of it

   Every general register `x0`..`x30`, the four system registers that say where
   the exception came from (`ELR_EL1`, `SPSR_EL1`) and what it was (`ESR_EL1`,
   `FAR_EL1`), and every FP/SIMD register `q0`..`q31`.

   The SIMD half is not caution.  `CPACR_EL1.FPEN` is open (the entry code
   opens it), so the compiler emits NEON for a `memcpy` — which is how this
   boot found the trap in the first place.  A handler that saved only the
   general registers would return to SIMD code whose operands it had destroyed,
   and the corruption would appear wherever the interrupted `memcpy` finished.

   ## The stack

   An exception from the kernel runs on `SP_EL1`, which is the stack this path
   uses.  An exception from a lower EL is taken with `PSTATE.SP` set to 1, so it
   is also on `SP_EL1`, which is what makes one path serve all sixteen entries.
   A kernel that shared a stack with user mode would have to switch here instead.

   ## The frame's layout

   The offsets below are [`crate::trap::ExceptionFrame`]'s, field for field:

   | offset | what |
   |---|---|
   | 0..240 | `x0`..`x29`, in pairs |
   | 240 | `x30`, the link register |
   | 248 | `ELR_EL1` — where to return |
   | 256 | `SPSR_EL1` — the state to return to |
   | 264 | `ESR_EL1` — what the exception was |
   | 272 | `FAR_EL1` — the address it named |
   | 280 | this entry's index |
   | 288..800 | `q0`..`q31` |

   The total is 800 bytes, and that is a multiple of sixteen so the pairs stay
   aligned.  A structure and an assembly frame that disagreed about any offset
   would hand Rust a frame of the wrong shape — which is why the two are
   documented against each other rather than derived. */
exception_entry:
    sub sp, sp, #800
    /* The index first, because `x16` is saved with `x17` below. */
    str x16, [sp, #280]

    stp x0, x1, [sp, #0]
    stp x2, x3, [sp, #16]
    stp x4, x5, [sp, #32]
    stp x6, x7, [sp, #48]
    stp x8, x9, [sp, #64]
    stp x10, x11, [sp, #80]
    stp x12, x13, [sp, #96]
    stp x14, x15, [sp, #112]
    stp x16, x17, [sp, #128]
    stp x18, x19, [sp, #144]
    stp x20, x21, [sp, #160]
    stp x22, x23, [sp, #176]
    stp x24, x25, [sp, #192]
    stp x26, x27, [sp, #208]
    stp x28, x29, [sp, #224]
    str x30, [sp, #240]

    mrs x0, elr_el1
    str x0, [sp, #248]
    mrs x0, spsr_el1
    str x0, [sp, #256]
    mrs x0, esr_el1
    str x0, [sp, #264]
    mrs x0, far_el1
    str x0, [sp, #272]

    stp q0, q1, [sp, #288]
    stp q2, q3, [sp, #320]
    stp q4, q5, [sp, #352]
    stp q6, q7, [sp, #384]
    stp q8, q9, [sp, #416]
    stp q10, q11, [sp, #448]
    stp q12, q13, [sp, #480]
    stp q14, q15, [sp, #512]
    stp q16, q17, [sp, #544]
    stp q18, q19, [sp, #576]
    stp q20, q21, [sp, #608]
    stp q22, q23, [sp, #640]
    stp q24, q25, [sp, #672]
    stp q26, q27, [sp, #704]
    stp q28, q29, [sp, #736]
    stp q30, q31, [sp, #768]

    mov x0, sp
    bl aarch64_exception_dispatch

    /* Restore in the reverse order, and restore `ELR_EL1`/`SPSR_EL1` before the
       general registers: the two loads that do it need somewhere to put what
       they read, and using `x0`/`x1` for that is only safe while the values
       they held are still on the stack.

       `ESR_EL1` and `FAR_EL1` are not restored.  They describe the exception,
       and an `eret` does not read them; a handler that wants them has them in
       the frame it was given. */
    ldr x0, [sp, #248]
    msr elr_el1, x0
    ldr x0, [sp, #256]
    msr spsr_el1, x0

    ldp q0, q1, [sp, #288]
    ldp q2, q3, [sp, #320]
    ldp q4, q5, [sp, #352]
    ldp q6, q7, [sp, #384]
    ldp q8, q9, [sp, #416]
    ldp q10, q11, [sp, #448]
    ldp q12, q13, [sp, #480]
    ldp q14, q15, [sp, #512]
    ldp q16, q17, [sp, #544]
    ldp q18, q19, [sp, #576]
    ldp q20, q21, [sp, #608]
    ldp q22, q23, [sp, #640]
    ldp q24, q25, [sp, #672]
    ldp q26, q27, [sp, #704]
    ldp q28, q29, [sp, #736]
    ldp q30, q31, [sp, #768]

    ldp x0, x1, [sp, #0]
    ldp x2, x3, [sp, #16]
    ldp x4, x5, [sp, #32]
    ldp x6, x7, [sp, #48]
    ldp x8, x9, [sp, #64]
    ldp x10, x11, [sp, #80]
    ldp x12, x13, [sp, #96]
    ldp x14, x15, [sp, #112]
    ldp x16, x17, [sp, #128]
    ldp x18, x19, [sp, #144]
    ldp x20, x21, [sp, #160]
    ldp x22, x23, [sp, #176]
    ldp x24, x25, [sp, #192]
    ldp x26, x27, [sp, #208]
    ldp x28, x29, [sp, #224]
    ldr x30, [sp, #240]

    add sp, sp, #800
    eret

.section .bss.stack, "aw", @nobits
.balign 4096
_stack_bottom:
    .skip 65536
_stack_top:
