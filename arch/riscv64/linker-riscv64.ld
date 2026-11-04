/* File: arch/riscv64/linker-riscv64.ld */
/* Purpose: Place the riscv64 image where OpenSBI jumps to it.

   ## What the loader reads

   The image stays an **ELF**: `qemu-system-riscv64 -kernel image.elf` loads
   the ELF's segments at their physical addresses and hands OpenSBI the entry
   point, and OpenSBI jumps there in S-mode.  A raw binary would work too —
   aarch64's loader wants one — but the ELF's entry point is what this loader
   is given, and a file whose first byte must be an instruction has no place
   to carry one.

   `0x8020_0000` is the conventional address two megabytes into RAM: OpenSBI
   keeps itself, its heap and its own tables in the first two megabytes below,
   and jumping to anything inside them is how a kernel opens firmware memory.
   The convention is the loader's, not a constant this tree invented — which
   is why the script states it rather than deriving it.

   ## Why the bss is marked as not loaded

   The image is a file.  The `.bss` here carries the kernel's page tables —
   eight megabytes of them — and a file with those bytes in it would be a
   loader reading eight megabytes of nothing.  `(NOLOAD)` reserves the
   address space; the entry assembly's clear is what makes the region zeros. */

OUTPUT_ARCH(riscv)
ENTRY(_start)

/* The frame pool's span.  64 MiB of *address space*: see `__pool_start`. */
POOL_SIZE = 64M;

SECTIONS
{
    . = 0x80200000;
    __kernel_start = .;

    /* First, because an ELF's entry point is an address and this one is the
       image's first instruction. */
    __text_start = .;
    .text : {
        KEEP(*(.text.boot))
        *(.text .text.*)
    }
    __text_end = .;

    . = ALIGN(4096);
    __rodata_start = .;
    .rodata : {
        *(.srodata .srodata.*)
        *(.rodata .rodata.*)
    }
    __rodata_end = .;

    . = ALIGN(4096);
    __data_start = .;
    .data : {
        /* Small data is addressed through `gp`, and the linker's relaxation
           needs the symbol to relax against.  The eight-kilobyte offset is
           the convention: it keeps every gp-relative reference within the
           signed twelve-bit immediate the instruction format has. */
        __global_pointer$ = . + 0x800;
        *(.sdata .sdata.*)
        *(.data .data.*)
    }
    __data_end = .;

    . = ALIGN(4096);
    __bss_start = .;
    .bss (NOLOAD) : {
        *(.sbss .sbss.*)
        *(.bss .bss.*)
        *(.bss.stack)
        *(COMMON)
    }
    __bss_end = .;

    /* The pool's span: reserved address space, not storage.  The symbols
       exist because `memory/src/frame.rs` names them on every bare-metal
       build, and the machine's own answer — the device tree's memory — is
       the ceiling the allocator clamps the span to. */
    . = ALIGN(4096);
    __pool_start = .;
    .pool (NOLOAD) : {
        . += POOL_SIZE;
    }
    __pool_end = .;

    __kernel_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame*)
        *(.note .note.*)
    }
}
