/* File: apps/init/linker-aarch64.ld */
/* Purpose: Link the aarch64 `init` at the base of its own user window.

   See the x86_64 script: the load address is the window's base, and the
   kernel's script is not inherited because its sections are kernel facts. */

OUTPUT_FORMAT(elf64-littleaarch64)
OUTPUT_ARCH(aarch64)
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
