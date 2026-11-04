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

    /* SUM: S-mode may reach a page whose `U` bit is set.  Bit 18. */
    li t0, (1 << 18)
    csrs sstatus, t0

    /* And the FPU off, which is the reset state made explicit.  Bits 14..15
       are `FS`; a two-bit clear, because "off" is the field's zero. */
    li t0, (3 << 14)
    csrc sstatus, t0

    /* `a1` still holds the device tree pointer, which is what the kernel's
       `boot_info` reads.  `s1` is callee-saved, so it survives the clear. */
    mv s1, a1

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

    /* The protocol's entry, not the kernel's: `bootloader` is where "a loader
       put us here, so start the kernel" lives, and this file is the machine. */
    call protofire_entry

3:  /* Nowhere left to go. */
    wfi
    j 3b

/* The kernel's stack: what the trap entry swaps in for a program's `sp`, and
   the stack the boot itself runs on.  A page-aligned page of it, like the
   aarch64 entry's. */
.section .bss.stack, "aw", @nobits
.balign 4096
_stack_bottom:
    .skip 65536
_stack_top:
