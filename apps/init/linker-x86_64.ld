/* File: apps/init/linker-x86_64.ld */
/* Purpose: Link the x86_64 `init` at the base of its own user window.

   A ring-3 program's load address is its window's base, the same arithmetic
   `process::program_base` names, and the loader maps the segments at the
   addresses this script fixes.  The kernel's own script is not inherited: its
   frame pool and boot tables are kernel facts, and a program has none of
   them. */

OUTPUT_FORMAT(elf64-x86-64)
ENTRY(_start)

BASE_ADDRESS = 0x8040000000;

SECTIONS
{
    . = BASE_ADDRESS;

    .text : ALIGN(4096)
    {
        *(.text .text.*)
    }

    .rodata : ALIGN(4096)
    {
        *(.rodata .rodata.*)
    }

    .data : ALIGN(4096)
    {
        *(.data .data.*)
    }

    .bss : ALIGN(4096)
    {
        *(.bss .bss.*)
        *(COMMON)
    }

    /DISCARD/ :
    {
        *(.eh_frame .eh_frame.*)
        *(.comment)
        *(.note .note.*)
        *(.debug*)
    }
}
