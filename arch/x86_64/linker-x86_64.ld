/* File: arch/x86_64/linker-x86_64.ld */
/* Purpose: Place the x86_64 image where a multiboot2 loader looks for it.

   The script lives beside the entry assembly rather than with the protocol
   crate: the load address, the header's alignment and the note's placement are
   all facts about this machine's loaders, and a machine that loads differently
   writes its own script. */

OUTPUT_FORMAT(elf64-x86-64)
OUTPUT_ARCH(i386:x86-64)
ENTRY(_start)

/* The lowest address a multiboot2 loader is required to accept, which is where
   the previous tree's image also sat: a fixed base keeps the identity map the
   boot assembly builds simple, and a loader that honours the header has no
   reason to move us. */
KERNEL_LOAD_ADDRESS = 0x100000;

/* The frame pool's span.  512 MiB of *address space*: see `__pool_start`. */
POOL_SIZE = 512M;

SECTIONS
{
    . = KERNEL_LOAD_ADDRESS;
    __kernel_start = .;

    /* The multiboot2 header must lie inside the image's first 32 KiB and be
       8-byte aligned.  It is placed first so the offset is a fact rather than
       a coincidence. */
    . = ALIGN(8);
    __text_start = .;
    /* The PVH note goes in the same segment as `.text` and just before it.
       QEMU finds it through a `PT_NOTE` program header; keeping it adjacent to
       `.text` rather than in a segment of its own avoids the tiny read-only
       segment a loader may refuse. */
    .notes : {
        KEEP(*(.note.Xen))
    }
    .text : {
        KEEP(*(.multiboot_header))
        *(.text .text.*)
    }
    __text_end = .;

    . = ALIGN(4K);
    __rodata_start = .;
    .rodata : {
        *(.rodata .rodata.*)
        KEEP(*(.trampoline))
    }
    __rodata_end = .;

    . = ALIGN(4K);
    __data_start = .;
    .data : {
        *(.data .data.*)
    }
    __data_end = .;

    . = ALIGN(4K);
    __bss_start = .;
    .bss : {
        *(.bss .bss.*)
        *(COMMON)
    }
    __bss_end = .;

    __image_end = .;
    __kernel_end = .;

    /* The physical frame pool: reserved address space, not storage.
       Nothing is loaded here and no boot clears it — the allocator zeroes a
       frame when it hands one out, which is the guarantee that is actually
       needed.  Reserving it in the image rather than declaring an array in
       `.bss` is what keeps a boot from writing past the end of RAM on a small
       machine: a 512 MiB array in `.bss` made a 528 MiB machine print nothing
       at all, because the boot's clear of it landed outside RAM.

       The span is a ceiling: the manager hands the allocator the machine's
       own answer clamped to it, so a machine whose RAM ends inside the span
       manages only the frames that are really there. */
    . = ALIGN(4K);
    __pool_start = .;
    /* `NOLOAD` is what keeps the span out of the image's file contents: the
       section occupies address space and nothing is written for it.  Without
       it the ELF grows by the pool's size — a 5 MiB image for a 512 MiB
       reservation — and a loader spends that long reading zeros. */
    .pool (NOLOAD) : {
        . += POOL_SIZE;
    }
    __pool_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame*)
        *(.note .note.*)
    }
}
