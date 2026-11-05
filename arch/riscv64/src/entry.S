/* File: arch/riscv64/src/entry.S */
/* Purpose: Where OpenSBI hands an S-mode image over, and the things a Rust
   `no_std` target needs done before it can run.

   ## What the firmware guarantees

   `qemu-system-riscv64 -machine virt -kernel image.elf` runs OpenSBI first;
   OpenSBI jumps to this image's entry in **S-mode** with `a0` holding the hart
   id and `a1` a pointer to a flattened device tree.  The MMU is off — `satp`
   is zero, so every address is its own physical address — and there is no
   handshake to check: a device-tree machine either loaded us or it did not.

   The hart id is dropped.  This tree boots one hart (`-smp 1` is how the gate
   runs the machine), and a second hart would need a stack per hart before it
   needed anything else.  The tree pointer is the one thing kept.

   ## What has to happen first

   1. **The global pointer.**  RISC-V addresses small data relative to `gp`,
      and the linker relaxes absolute references into `gp`-relative ones.  A
      `gp` that was never loaded makes the first relaxed access read whatever
      register reset to — and the relaxation happens *inside* this sequence,
      which is why the assembler is told not to relax the very instruction
      that computes it.
   2. **A stack.**  Nothing can be called without one, and OpenSBI's stack is
      OpenSBI's.
   3. **`sscratch` zeroed.**  The trap entry swaps `sp` with `sscratch` to move
      a program onto the kernel stack, and it tells "a program's trap" from
      "the kernel's own" by whether the swap produced a valid stack.  A
      register that still held OpenSBI's scratch would make the first kernel
      trap look like a program's.
   4. **The bss cleared.**  A `no_std` image is loaded from a file; the bytes
      the linker reserved for `.bss` are not in it, and a boot that assumed
      they were zero would find whatever OpenSBI left.
   5. **`SUM` set.**  A RISC-V page with the `U` bit is off-limits to S-mode
      *unless* `sstatus.SUM` says otherwise — the reverse of x86_64, where a
      supervisor may reach user pages unless `SMAP` was switched on.  The pipe
      handlers read and write a program's buffer through the program's own
      root, so the bit is a permission the boot grants once rather than a
      fault every handler re-learns.

   The FPU is left off (`sstatus.FS` is cleared): no f-register is saved in a
   trap frame, which is the same answer x86_64 gives for the SSE state, and a
   kernel that used one would fault loudly instead of corrupting a program's
   float silently.  Nothing in this tree emits float code. */

.section .text.boot, "ax"
.global _start
_start:
    /* The global pointer, before any gp-relative reference can execute. */
    .option push
    .option norelax
    lla gp, __global_pointer$
    .option pop

    lla sp, _stack_top

    /* No program is running, so no trap is a program's yet. */
    csrw sscratch, x0

    /* The CPU's own slot, which is what a trap reads to learn where it is.
       This is the hart the firmware cold-booted, and it is slot zero by the
       kernel's own numbering — the machine's hart id, which is a different
       number, is recorded separately.  A `tp` left as firmware left it would
       make the boot CPU read as whichever slot the garbage happened to name,
       and the first trap would split the scheduling half the wrong way. */
    mv tp, x0

    /* SUM: S-mode may reach a page whose `U` bit is set.  Bit 18. */
    li t0, (1 << 18)
    csrs sstatus, t0

    /* And the FPU off, which is the reset state made explicit.  Bits 14..15
       are `FS`; a two-bit clear, because "off" is the field's zero. */
    li t0, (3 << 14)
    csrc sstatus, t0

    /* `a1` still holds the device tree pointer, which is what the kernel's
       `boot_info` reads.  `a0` holds the hart the firmware cold-booted, and
       neither is a register the bss clear can be trusted to keep — `s1` and
       `s2` are callee-saved, so they survive it. */
    mv s1, a1
    mv s2, a0

    lla t0, __bss_start
    lla t1, __bss_end
1:  bgeu t0, t1, 2f
    sd x0, 0(t0)
    addi t0, t0, 8
    j 1b
2:
    /* The device tree pointer, recorded before anything reads it.  The same
       arrangement the aarch64 entry uses: `protofire_entry` takes no
       arguments because `bootloader` is the protocol, so the machine keeps
       the value and the module above asks for it. */
    mv a0, s1
    call riscv64_set_device_tree

    /* The boot hart, recorded for the same reason: which hart the firmware
       chose is a fact of this entry, and the list of harts to start is the
       machine's minus this one. */
    mv a0, s2
    call riscv64_set_boot_hart

    /* The protocol's entry, not the kernel's: `bootloader` is where "a loader
       put us here, so start the kernel" lives, and this file is the machine. */
    call protofire_entry

3:  /* Nowhere left to go. */
    wfi
    j 3b

/* The one trap path every trap reaches.

   ## The swap

   RISC-V pushes nothing on a trap and switches no stack: the handler starts on
   whatever `sp` the interrupted code held, which for a program is a stack the
   kernel must not build a frame on.  So the first instruction exchanges `sp`
   with `sscratch` — which holds the kernel stack while a program runs, and
   zero while the kernel does.  The exchange yields zero for the kernel's own
   trap (which then puts its stack back), and the kernel stack for a program's.

   The distinction survives because of a rule the Rust side keeps: `sscratch`
   is zeroed for the whole of any kernel window that can take a trap with
   interrupts enabled — the boot before any program, and the idle's wait.  A
   parked user `sp` is only ever in `sscratch` while the hart is in U-mode or
   inside a handler running masked.

   ## The frame's layout

   The offsets below are [`crate::trap::ExceptionFrame`]'s, field for field,
   and the structure asserts them with `offset_of!` rather than trusting this
   table:

   | offset | what |
   |---|---|
   | 0..256 | `x0`..`x31`, eight bytes each; `x0` stored as the zero it reads |
   | 256 | `sepc` — where to return; for a call, the `ecall` itself |
   | 264 | `sstatus` — the state to return to |
   | 272 | `scause` — what the trap was |
   | 280 | `stval` — the address a fault named |

   The total is 288 bytes.  `x2` — the stack pointer — is saved last and in a
   place of its own decision: the interrupted `sp` is the user's when the trap
   came from a program and the frame's own top when it came from the kernel,
   and `sstatus.SPP`, set by the hardware before the first instruction here,
   is what tells the two apart. */

.section .text.trap, "ax"
.balign 4
.global trap_entry
trap_entry:
    csrrw sp, sscratch, sp
    bnez sp, 1f
    csrrw sp, sscratch, x0
1:
    addi sp, sp, -288

    /* Everything but `x2`, before anything is clobbered: the two scratch
       registers the code below needs are ordinary slots by the time their
       registers are used. */
    sd x0, 0(sp)
    sd x1, 8(sp)
    sd x3, 24(sp)
    sd x4, 32(sp)
    sd x5, 40(sp)
    sd x6, 48(sp)
    sd x7, 56(sp)
    sd x8, 64(sp)
    sd x9, 72(sp)
    sd x10, 80(sp)
    sd x11, 88(sp)
    sd x12, 96(sp)
    sd x13, 104(sp)
    sd x14, 112(sp)
    sd x15, 120(sp)
    sd x16, 128(sp)
    sd x17, 136(sp)
    sd x18, 144(sp)
    sd x19, 152(sp)
    sd x20, 160(sp)
    sd x21, 168(sp)
    sd x22, 176(sp)
    sd x23, 184(sp)
    sd x24, 192(sp)
    sd x25, 200(sp)
    sd x26, 208(sp)
    sd x27, 216(sp)
    sd x28, 224(sp)
    sd x29, 232(sp)
    sd x30, 240(sp)
    sd x31, 248(sp)

    /* The interrupted stack pointer. */
    csrr t0, sstatus
    andi t0, t0, 256             /* SPP: set means the trap came from S-mode */
    beqz t0, 2f
    addi t0, sp, 288             /* the kernel's own `sp`, at the frame's top */
    j 3f
2:  csrr t0, sscratch            /* the program's, parked by the swap */
3:  sd t0, 16(sp)

    csrr t0, sepc
    sd t0, 256(sp)
    csrr t0, sstatus
    sd t0, 264(sp)
    csrr t0, scause
    sd t0, 272(sp)
    csrr t0, stval
    sd t0, 280(sp)

    mv a0, sp
    call riscv64_trap_dispatch

    /* The restore.  Every register comes home from the frame before the two
       scratch registers are spent on the return itself: `sepc` and `sstatus`
       go back to the machine, then the frame's `x2` decides where `sret` runs,
       and the `SPP` it carries decides what `sscratch` holds afterwards — the
       kernel stack, for the next program's trap, or zero, for the kernel's
       own.  `ESR` has no counterpart here to skip: `scause` and `stval`
       describe the trap, and an `sret` reads neither. */
    ld x1, 8(sp)
    ld x3, 24(sp)
    ld x4, 32(sp)
    ld x5, 40(sp)
    ld x6, 48(sp)
    ld x7, 56(sp)
    ld x8, 64(sp)
    ld x9, 72(sp)
    ld x10, 80(sp)
    ld x11, 88(sp)
    ld x12, 96(sp)
    ld x13, 104(sp)
    ld x14, 112(sp)
    ld x15, 120(sp)
    ld x16, 128(sp)
    ld x17, 136(sp)
    ld x18, 144(sp)
    ld x19, 152(sp)
    ld x20, 160(sp)
    ld x21, 168(sp)
    ld x22, 176(sp)
    ld x23, 184(sp)
    ld x24, 192(sp)
    ld x25, 200(sp)
    ld x26, 208(sp)
    ld x27, 216(sp)
    ld x28, 224(sp)
    ld x29, 232(sp)
    ld x30, 240(sp)
    ld x31, 248(sp)

    ld t0, 256(sp)
    csrw sepc, t0
    ld t0, 264(sp)
    csrw sstatus, t0
    ld t0, 16(sp)
    addi sp, sp, 288

    csrr t1, sstatus
    andi t1, t1, 256
    bnez t1, 4f
    csrw sscratch, sp
    mv sp, t0
    sret
4:  csrw sscratch, x0
    mv sp, t0
    sret

/* The kernel's stack: what the trap entry swaps in for a program's `sp`, and
   the stack the boot itself runs on.  A page-aligned page of it, like the
   aarch64 entry's. */
.section .bss.stack, "aw", @nobits
.balign 4096
_stack_bottom:
    .skip 65536
_stack_top:

/* The other harts' entry, which the boot hart names in the firmware's start
   call.  The firmware enters here in S-mode with `a0` = the hart's own id and
   `a1` = the slot the boot hart chose — an index into the stacks below and
   the flags the Rust side owns.

   ## What it does, and what it does not

   This is the boot entry's list, minus what the boot hart has already done by
   the time it asks the firmware for anyone: the bss is clear, the device tree
   is recorded, and there is nothing here to hand `protofire_entry`.  What
   remains is the global pointer — the same first instruction the boot entry
   runs, for the same reason — a stack of the hart's own, `sscratch`, `SUM`,
   the FPU off, and the trap vector.

   Then one flag and a park.  The hart does not run the scheduler (one
   structure, two harts, nothing locks) and does not take interrupts (`SIE`
   stays clear, so the park is a park and not a second CPU feeding ticks into
   code that assumes one hart); what it does is prove it came up. */

.section .text.secondary, "ax"
.balign 4
.global secondary_entry
secondary_entry:
    .option push
    .option norelax
    lla gp, __global_pointer$
    .option pop

    /* The slot indexes the stacks below.  The boot hart only ever hands out
       slots the reservation holds — the count it starts is bounded by the
       same constant the reservation is sized from — and the multiplication
       is a real multiply, not a shift, so the size stays one fact. */
    li t0, {SECONDARY_STACK_BYTES}
    mul t0, a1, t0
    lla sp, secondary_stacks
    add sp, sp, t0

    csrw sscratch, x0

    li t0, (1 << 18)
    csrs sstatus, t0
    li t0, (3 << 14)
    csrc sstatus, t0

    lla t0, trap_entry
    csrw stvec, t0

    call riscv64_secondary_main

1:  /* The Rust side parks; this is the road back if it ever returns. */
    wfi
    j 1b

/* One stack per hart the boot may start, indexed by the slot the boot hart
   handed the firmware.  The size is the boot stack's, and the count is the
   constant `smp` owns — both interpolated, so neither is written here a
   second time. */
.section .bss.secondary, "aw", @nobits
.balign 4096
secondary_stacks:
    .skip {SECONDARY_STACK_BYTES}
