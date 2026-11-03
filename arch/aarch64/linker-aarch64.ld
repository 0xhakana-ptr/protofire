/* File: arch/aarch64/linker-aarch64.ld */
/* Purpose: Place the aarch64 image where a loader expects it.

   ## What QEMU's -kernel reads

   `qemu-system-aarch64 -kernel` reads a **raw binary**, not an ELF: it loads the
   file's bytes at the address it chose and jumps to them.  The `virt` machine
   puts RAM at `0x40000000`, and a kernel is conventionally loaded at
   `0x40080000` — eight hundred kilobytes in, past the region firmware uses for
   its own structures.

   A raw image has no program headers and no entry point, so the first byte of
   the file is the first instruction and everything before `.text.boot` must be
   nothing.  That is why `_start`'s section comes first and nothing is allowed
   above it.

   ## Why the bss is marked as not loaded

   The image is a file.  A `.bss` of a megabyte would be a megabyte of zeros in
   it — a loader spends that long reading nothing, and the bytes are not the
   ones the kernel will actually use.  `(NOLOAD)` reserves the address space and
   writes nothing, which is also what the entry assembly's clear expects: the
   region exists and it is not the firmware's memory. */

ENTRY(_start)

SECTIONS
{
    . = 0x40080000;
    __kernel_start = .;

    /* First, because a raw image's first byte is its entry. */
    __text_start = .;
    .text.boot : {
        KEEP(*(.text.boot))
    }

    .text : {
        *(.text .text.*)
    }

    /* The vector table is its own section so its alignment is the section's,
       not something the assembler hopes the linker honours: `VBAR_EL1`'s low
       eleven bits are reserved, so the table must start on a 2 KiB boundary and
       no other input section may share it. */
    . = ALIGN(2048);
    .vectors : {
        KEEP(*(.text.vectors))
    }
    __text_end = .;

    . = ALIGN(4096);
    __rodata_start = .;
    .rodata : {
        *(.rodata .rodata.*)
    }
    __rodata_end = .;

    . = ALIGN(4096);
    __data_start = .;
    .data : {
        *(.data .data.*)
    }
    __data_end = .;

    . = ALIGN(4096);
    __bss_start = .;
    .bss (NOLOAD) : {
        *(.bss .bss.*)
        *(.bss.stack)
        *(COMMON)
    }
    __bss_end = .;

    /* The pool's span: reserved address space, not storage.  There is no frame
       allocator on this machine yet, and the symbols exist because
       `memory/src/frame.rs` names them on every bare-metal build. */
    . = ALIGN(4096);
    __pool_start = .;
    .pool (NOLOAD) : {
        . += 64M;
    }
    __pool_end = .;

    __kernel_end = .;

    /DISCARD/ : {
        *(.comment)
        *(.eh_frame*)
        *(.note .note.*)
    }
}
