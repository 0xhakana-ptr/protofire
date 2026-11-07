/* File: apps/init/linker-riscv64.ld */
/* Purpose: Link the riscv64 `init` at the base of its own user window.

   See the x86_64 script: the load address is the window's base, and the
   kernel's script is not inherited because its sections are kernel facts. */

OUTPUT_FORMAT(elf64-littleriscv)
OUTPUT_ARCH(riscv)
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
        *(.sdata .sdata.*)
    }

    .bss : ALIGN(4096)
    {
        *(.bss .bss.*)
        *(.sbss .sbss.*)
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
