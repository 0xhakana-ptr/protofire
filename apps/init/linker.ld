/* File: apps/init/linker.ld */
/* Purpose: Link a program at the base of its own user window.

   ## Why this script is neutral, and not under `arch/`

   The kernel's scripts live in `arch/<machine>/`, and that is right for
   them: their load addresses are the machines' loader conventions (a
   multiboot2 header here, a raw `Image` there, OpenSBI's entry point on the
   third) and each carries the sections its loader reads.  This script has
   none of those facts.  Its base is `USER_BASE + USER_WINDOW`, arithmetic
   the kernel owns (`process::program_base`), the same on every machine; the
   container is the target triple's to choose, which is what an absent
   `OUTPUT_FORMAT` means; and the section list is the same list on all
   three.  Three per-machine copies existed and a build with one neutral
   script was byte-identical to each of them, which is the measurement this
   file replaces.

   What the program's own layout decides, and the kernel then honours: the
   loader maps each segment at the addresses this script fixes, so a
   relocation that reaches outside them is a link error rather than a
   runtime surprise.  `ENTRY(_start)` names the symbol `apps/init` defines.

   `.sdata`/`.sbss` are listed although x86_64 and aarch64 never emit them:
   riscv64's small-data model puts objects there, and a section left
   unmatched would be placed by the default rule somewhere the loader's
   segment map does not expect.  Listing a section a machine never emits
   costs nothing; missing one it does emit costs a program. */

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
