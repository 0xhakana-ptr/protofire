/* File: arch/x86_64/src/boot-x86-64.S */
/* Purpose: The x86_64 entry: the two loader handshakes, long mode, and the
   jump into the protocol's own entry.  It lives here rather than in
   `bootloader` because every instruction below is a fact about this machine. */

/* The header is what a loader reads before it loads anything, so it is written
   to the section the linker script places first.  `checksum` is the value that
   makes the four 32-bit words sum to zero: the loader recomputes it and
   refuses an image whose arithmetic does not. */
.section .multiboot_header, "a"
.align 8
multiboot_header_start:
    .long 0xE85250D6                /* magic */
    .long 0                         /* architecture: i386 protected mode */
    .long multiboot_header_end - multiboot_header_start
    .long -(0xE85250D6 + 0 + (multiboot_header_end - multiboot_header_start))

    /* End tag: type 0, flags 0, size 8.  A loader that needs tag sizes reads
       this terminator to know the header stopped. */
    .align 8
    .short 0
    .short 0
    .long 8
multiboot_header_end:

/* A second handshake for a second loader.  QEMU's `-kernel` does not read a
   multiboot2 header: it reads the PVH ELF note and refuses an image without
   one ("Error loading uncompressed kernel without PVH ELF Note"), while GRUB
   reads the header above and ignores this.  Shipping both is what lets one
   image boot either way, and it is what the previous tree's `boot.asm` does
   for the same reason.

   Type 18 is `XEN_ELFNOTE_PHYS32_ENTRY`, and the value is `pvh_entry` rather
   than `_start`: a PVH loader enters with `%ebx` holding the device tree
   address and **no multiboot handshake in `%eax`**, so the common `_start`
   would see a magic of zero and refuse.  The note's layout is the generic ELF
   note convention: namesz, descsz, type, then the name padded to four bytes
   and the descriptor. */
.pushsection .note.Xen, "a", @note
.balign 4
.long 2f - 1f                   /* namesz: "Xen" and its NUL */
.long 3f - 2f                   /* descsz: one 32-bit address */
.long 18                        /* XEN_ELFNOTE_PHYS32_ENTRY */
1:  .asciz "Xen"
2:  .balign 4
3:  .long pvh_entry
.popsection

/* A PVH loader enters here, in 32-bit protected mode, with the device tree's
   address in `%ebx` and nothing in `%eax`.  It is the same path from here on,
   but the handshake has to be recorded as "PVH" rather than as a multiboot2
   magic of zero: the difference between a loader that did not use our header
   and a loader that used our other one. */
.code32
.global pvh_entry
pvh_entry:
    cli
    /* `0xFFFF_FFFF` is the sentinel `kernel_main` reads as "PVH", so the boot
       can say which loader brought it up.  A multiboot2 magic is never this
       value. */
    mov dword ptr [multiboot_magic], 0xFFFFFFFF
    mov dword ptr [multiboot_info], ebx

    lea esp, [boot_stack_top]
    xor ebp, ebp

    call setup_page_tables
    call enable_long_mode

    lgdt [gdt64_descriptor]
    push 0x08
    lea eax, [long_mode_start]
    push eax
    retf

/* The loader enters here in 32-bit protected mode with paging off.  The first
   job is a stack, because nothing else can be called without one; the second
   is long mode, because this kernel is 64-bit. */
.section .text
.code32
.global _start
_start:
    cli
    /* The multiboot2 handshake arrives in the two registers the spec names,
       and they are saved before anything can clobber them: `eax` is the magic
       and `ebx` the information structure's address. */
    mov dword ptr [multiboot_magic], eax
    mov dword ptr [multiboot_info], ebx

    lea esp, [boot_stack_top]
    xor ebp, ebp

    call setup_page_tables
    call enable_long_mode

    lgdt [gdt64_descriptor]
    push 0x08
    lea eax, [long_mode_start]
    push eax
    /* `retf` is a far return: it pops the selector and the offset, which is
       how a 32-bit segment moves into a 64-bit one. */
    retf

/* Identity-map the first gigabyte with 2 MiB pages.  A gigabyte is the whole
   of what this boot touches before the Rust side builds its own tables: the
   image, its stack, its `.bss` and whatever the loader left below 1 GiB.
   Four page directories of 512 entries each, indexed as one array. */
.code32
setup_page_tables:
    lea eax, [boot_pdpt]
    or eax, 0x03                    /* present | writable */
    mov dword ptr [boot_pml4], eax
    mov dword ptr [boot_pml4 + 4], 0

    xor ecx, ecx
fill_pdpt_loop:
    lea eax, [boot_pd]
    mov edx, ecx
    shl edx, 12                     /* each page directory is 4096 bytes */
    add eax, edx
    or eax, 0x03
    mov edx, ecx
    shl edx, 3                      /* PDPT entries are 8 bytes apart */
    mov dword ptr [boot_pdpt + edx], eax
    mov dword ptr [boot_pdpt + edx + 4], 0
    inc ecx
    cmp ecx, 4
    jne fill_pdpt_loop

    xor ecx, ecx
fill_pd_loop:
    mov eax, ecx
    shl eax, 21                     /* 2 MiB per entry */
    or eax, 0x83                    /* present | writable | huge */
    mov dword ptr [boot_pd + ecx * 8], eax
    mov dword ptr [boot_pd + ecx * 8 + 4], 0
    inc ecx
    cmp ecx, 2048
    jne fill_pd_loop

    ret

.code32
enable_long_mode:
    lea eax, [boot_pml4]
    mov cr3, eax

    mov eax, cr4
    or eax, 1 << 5                  /* PAE */
    mov cr4, eax

    mov ecx, 0xC0000080             /* EFER */
    rdmsr
    or eax, (1 << 8) | (1 << 11)    /* long mode | no-execute */
    wrmsr

    mov eax, cr0
    or eax, 1 << 31                 /* paging */
    mov cr0, eax
    ret

.align 8
gdt64:
    .quad 0x0000000000000000
    .quad 0x00AF9A000000FFFF        /* ring 0 code, 64-bit */
    .quad 0x00AF92000000FFFF        /* ring 0 data */
gdt64_end:

gdt64_descriptor:
    .word gdt64_end - gdt64 - 1
    .long gdt64

.code64
long_mode_start:
    mov ax, 0x10
    mov ds, ax
    mov es, ax
    mov ss, ax
    xor eax, eax
    mov fs, ax
    mov gs, ax

    lea rsp, [rip + boot_stack_top]
    xor rbp, rbp

    /* The handshake goes to the machine's own record, in 64-bit mode and with
       the stack this file built: the state was saved into the `.bss` slot while
       still in 32-bit mode, and this is the first point at which a Rust calling
       convention exists to hand it over with. */
    mov edi, dword ptr [rip + multiboot_magic]
    call record_handshake

    /* Then the protocol's entry.  The name is neutral on purpose: this file
       knows how the machine is entered, `bootloader` knows what to do once it
       is, and the two meet at a symbol rather than at a crate edge: `arch` is
       below `bootloader`, and an upward import would be the one thing this
       tree's layering forbids. */
    call protofire_entry

halt_forever:
    cli
    hlt
    jmp halt_forever

.section .bss.boot, "aw", @nobits
.align 16
multiboot_magic:
    .skip 4
multiboot_info:
    .skip 4

.align 4096
boot_pml4:
    .skip 4096
boot_pdpt:
    .skip 4096
boot_pd:
    .skip 16384

.align 16
boot_stack_bottom:
    .skip 65536
/* The kernel stack's top, published: the TSS names it as `RSP0`, so every
   interrupt from ring 3 lands on this stack.  A local label would have left
   `gdt.rs` unable to name it, and a second stack declared there would be a
   second stack, one the boot is not running on, whose contents nothing
   unwinds. */
.global kstack_top
kstack_top:
boot_stack_top:
