/* File: arch/x86_64/src/ap-start.S */
/* Purpose: The bytes a started CPU is entered at, and the kernel stacks the
   started CPUs run on.

   A SIPI names a page by its vector, and vector 8 is 0x8000: the firmware
   enters an application processor there in 16-bit real mode with every
   register at its reset value, at the page's first byte.  What the page does
   is the shortest road to 64 bit: a GDT of its own, `PAE`, `EFER.LME`, the
   boot page table in `cr3`, and paging on.  That table maps the first four
   gigabytes identity with two-megabyte pages, so the page, the kernel image
   and the handoff stack are all at the addresses they are linked at.  From
   64 bit the page reads the handoff words the boot CPU wrote and jumps to the
   Rust entry with the slot in the first argument register.

   ## Why the bytes are carried in the image and copied down

   The section is linked inside the image like any other, and every address
   the code uses is spelled as its offset from the page's base plus 0x8000:
   a difference of two symbols is a constant at link time, so the bytes carry
   no relocation and mean the same thing wherever the image puts them.  The
   boot CPU copies them to 0x8000 before the first start, through the window
   the kernel maps for the page, because the loader's own placement of a page
   this low does not survive the firmware's use of the first megabyte.

   ## The layout, and why the jump comes first

   The first byte is the first instruction the CPU executes, and the handoff
   words it must not execute are bytes too.  So the page opens with one jump
   over them, the handoff sits at the offsets below, and the code follows.
   The offsets are `arch/x86_64/src/smp.rs`'s handoff constants, and the two
   are one layout: the assembly fixes them, the Rust writes through them.

   The CPU enters with `DS` at zero after the second instruction, so a 16-bit
   displacement on a memory operand is the whole linear address, which is why
   the operands below are the page's own 0x8000-based addresses.  The far jump
   into 64 bit is spelled as its bytes: in 16-bit code an `ljmp` encodes a
   16-bit offset, and the target is the 32-bit linear address of the 64-bit
   half of the page, which is what the operand-size prefix is for. */

.section .trampoline, "a"
.global __trampoline_image_start
__trampoline_image_start:
.balign 16
.global ap_trampoline
ap_trampoline:
    .byte 0xE9                       /* jmp rel16: over the handoff, to the code */
    .word ap_trampoline_code16 - ap_trampoline - 3

.org ap_trampoline + 16
handoff_entry:
    .long 0                          /* handoff: the 64-bit Rust entry */
handoff_stack:
    .long 0                          /* handoff: this CPU's stack top */
handoff_slot:
    .long 0                          /* handoff: the slot among started */
handoff_cr3:
    .long boot_pml4                  /* the boot page table, at link time */

.balign 16
trampoline_gdt:
    .quad 0                          /* null */
    .quad 0x00AF9A000000FFFF         /* 64-bit code, the boot's own word */
    .quad 0x00AF92000000FFFF         /* data, the boot's own word */
trampoline_gdt_end:
trampoline_gdtr:
    .word trampoline_gdt_end - trampoline_gdt - 1
    .long trampoline_gdt - ap_trampoline + 0x8000
    .word 0

.global ap_trampoline_code16
ap_trampoline_code16:
    .code16
    cli
    xor ax, ax
    mov ds, ax
    mov ss, ax
    /* lgdt, from the pointer's own 0x8000-based address.  The bytes are
       spelled rather than written: `0F 01 /2` is the group's second, which
       modrm 0x16 names, and 0x2e is the group's reserved fifth, the one that
       raises #UD, which is what the first version executed. */
    .byte 0x0F, 0x01, 0x16
    .word trampoline_gdtr - ap_trampoline + 0x8000
    mov eax, cr4
    or eax, (1 << 5)                 /* PAE: four-level paging is what long mode walks */
    mov cr4, eax
    mov ecx, 0xC0000080              /* EFER */
    rdmsr
    or eax, (1 << 8) | (1 << 11)     /* LME, and NXE: the kernel root's data
                                        entries carry the NX bit, and without
                                        NXE the walk reads that bit as
                                        reserved and faults the very store the
                                        long-mode half is about to make */
    wrmsr
    /* mov eax, the handoff's cr3 word, from its 0x8000-based address. */
    .byte 0x66, 0xA1
    .word handoff_cr3 - ap_trampoline + 0x8000
    mov cr3, eax
    mov eax, cr0
    or eax, 0x80000001               /* PG | PE: with LME set, this is IA-32e mode */
    mov cr0, eax
    /* The far jump into 64 bit: operand-size prefix, opcode EA, offset 32,
       selector 16.  The selector names the trampoline GDT's 64-bit code
       entry, and the offset is the linear address of the half below. */
    .byte 0x66, 0xEA
    .long trampoline_code64 - ap_trampoline + 0x8000
    .word 0x08

trampoline_code64:
    .code64
    xor ebp, ebp
    /* The handoff words are 32-bit, at their 0x8000-based addresses; loading
       them into the 32-bit names here is what zero-extension is for.  The
       three are spelled as their bytes, and the SIB byte is what makes the
       displacement absolute: in 64-bit mode `mod 00, rm 101` without one is
       `RIP`-relative, and the instruction would read whatever the image keeps
       a page past its own instruction. */
    .byte 0x8B, 0x24, 0x25            /* mov esp, [disp32], SIB base-none */
    .long handoff_stack - ap_trampoline + 0x8000
    .byte 0x8B, 0x3C, 0x25            /* mov edi, [disp32] */
    .long handoff_slot - ap_trampoline + 0x8000
    .byte 0x8B, 0x04, 0x25            /* mov eax, [disp32] */
    .long handoff_entry - ap_trampoline + 0x8000
    jmp rax

.global __trampoline_image_end
__trampoline_image_end:

/* One kernel stack per CPU slot, indexed by the slot the kernel numbered the
   CPU with: the boot CPU keeps the boot stack it is already running on, and
   the CPU started into slot `s` runs on slice `s + 1`, whose top is what the
   boot CPU wrote into the handoff.  The reservation is the cap plus one for
   the same reason the other machines' is: the boot's slice is one of them,
   and a count that omitted it leaves the last slice past the end. */
.section .bss.stack, "aw", @nobits
.balign 4096
.global kernel_stacks
kernel_stacks:
    .skip {SECONDARY_STACK_RESERVATION}
