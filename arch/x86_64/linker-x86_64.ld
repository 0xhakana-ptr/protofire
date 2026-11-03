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

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame*)
        *(.note .note.*)
    }
}
