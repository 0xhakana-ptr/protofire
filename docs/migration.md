# What has moved in, and what has not

This tree replaces a single crate of 312,000 lines.  The migration is not a
rewrite and not a copy: each subsystem moves in as a crate of its own, with its
tests, once it can be built and exercised on its own.  This document is the
count.

**The number that matters: about 14% of the previous tree is here.**  What is
here is the part that proves the architecture — a boot, a heap, a bus, a driver,
a filesystem and a syscall — and the rest is being moved a crate at a time.

## The table

| Subsystem | Previous tree | Here | What is in |
|---|---:|---:|---|
| `abi` | 4,725 | 3,479 | the whole wire format, and the syscall numbering |
| `arch` | 95,361 | 7,657 | boot, interrupts, serial, port I/O, page tables, the exception path, IDT, the 8259, the PL011 — eight of a hundred |
| `crypto` | 4,606 | 4,850 | all of it, one module per algorithm — counted under `libs` below |
| `fs` | 68,494 | 14,683 | PyroFS, tmpfs, ISO 9660, the mount table and the VFS contract; eight filesystems are not here |
| `kernel` | 39,704 | 1,536 | the boot sequence, the syscall table, device discovery |
| `memory` | 9,649 | 1,865 | the frame pool and the region pools |
| `network` | 39,240 | 1 | nothing |
| `drivers` | 18,828 | 3,772 | PCI, and virtio block |
| `syscall` | 15,647 | 253 | the context, the validators, three handlers |
| `user` | 19,145 | — | nothing; `apps/` holds three skeletons |
| `libs` | — | 14,625 | allocator, audit, cell, crypto, irq, paging, profiler, rights, sync, unicode |
| **total** | **312,131** | **~51,000** | |

The `libs` crates have no previous-tree column because most of them were modules
under `src/kernel/` or `src/memory/` there; their lines are counted in those
rows.

## Filesystems

`fs` is the largest subsystem and one of its thirteen filesystems is here.

| Filesystem | Lines | Here |
|---|---:|---|
| NTFS | 14,643 | no |
| PyroFS | 7,260 | **yes** |
| ISO 9660 | 5,928 | **yes**, read-only — rewritten, not moved |
| ext4 | 3,436 | no |
| F2FS | 3,285 | no |
| FAT32 | 2,732 | no |
| exFAT | 2,345 | no |
| btrfs | 2,108 | no |
| squashfs | 1,849 | no |
| the VFS layer | 1,723 | contract only — see below |
| tmpfs | 1,072 | **yes** |
| FUSE | 876 | no |

**The VFS row has moved.**  `fs/src/vnode.rs` and `fs/src/filesystem.rs` carry
the *contract* — what a node is, what a filesystem answers — and the namespace
is now `fs/src/mount.rs` and `fs/src/path.rs`: a mount table, longest-prefix
resolution, and path normalization.  What is still not here is the *handle
table*, which arrives with the process layer because a handle belongs to a
process.

Three filesystems are mounted on a boot: PyroFS at `/`, tmpfs at `/tmp` and an
ISO 9660 disc at `/cdrom`.  The second is what proved the namespace — a table
with one entry has never resolved anything — and the third is what proved it
goes both ways, because a disc cannot be written and so what comes out of it
came from the image.

**ISO 9660 was rewritten rather than moved**, and that is the pattern for the
rest: the previous tree's 5,928 lines are 1,105 of a reader and 800 of a
*writer* — a writer for a writable ISO image, which was a requirement of that
kernel rather than of the format.  The rewrite is the reader, at 1,700 lines,
with the field offsets named and tested instead of being a packed struct cast
from a sector.  See [`fs/src/iso9660/mod.rs`](../fs/src/iso9660/mod.rs).

The order the rest come in is by what they prove rather than by size: the FAT
family next (shared structure, three formats), then the read-only formats, then
NTFS and ext4, which are where a mistake costs data.

## Network

Nothing.  `net` is a one-line crate so the layer exists and the boundary is
declared before there is code to put behind it.

The previous tree's network subsystem is 39,240 lines: TCP, TLS, SCTP, DCCP,
IPsec, WireGuard, DNS, mDNS, DHCP, NTP, PPP/PPPoE, multicast routing, a packet
filter and raw sockets.  The order it comes in is bottom-up — link, then
internet, then the transports — because each layer's tests need the one below it.

## Architecture

Eight modules out of a hundred, on each machine.  The previous tree's `arch` is
95,361 lines across `x86_64` (49 files), `aarch64` (25) and `riscv64` (22), plus
`pci`, `fdt`, `trap`, `mmu`, `percpu`, `smp`, `thread`, `user_access`,
`syscall_trap`, `ptrace` and more.

What is here is what a boot needs before anything else: the entry, the console,
the interrupt flag, the page-table encoding, the exception path, and — on
x86_64 — the port I/O the PCI bus is reached through.  What comes next is the
device-tree parse, which is what would give aarch64 a PCI bus and a PL011
address that is not a constant.

### Translation is on, and how it was found not to be

Until this change `arch_aarch64::paging::install` wrote `MAIR_EL1` and
`TTBR0_EL1` and returned `true`, and the boot printed "page table built and
installed, 4 KiB granule" about a table no access went through: `SCTLR_EL1.M`
was never set.  That is the defect this file keeps recording — written, wired,
never executed — and it was found by reading the function rather than by a
gate, because the line it printed was true about the register and false about
the machine.

Turning translation on took three fixes, and each was found by QEMU's exception
log rather than by reasoning:

1. **The table descriptors carried leaf fields.**  `encode_at` set `AF`, `AP`,
   the attribute index and `UXN`/`PXN` on every descriptor; the architecture
   calls those bits Ignored in a table descriptor.  Invisible while nothing read
   a descriptor.  A table descriptor is now its address and its type.
2. **`EntryEncoding::encode` had no level.**  aarch64 writes a 4 KiB page
   descriptor and a 1 GiB block descriptor with different low bits, so the
   implementation hard-coded `Level::Third` — and the kernel builds four
   levels, so every page became a block.  The trait takes a level in both
   directions now, and the other two machines accept and ignore it with the
   reason written down.
3. **`TCR_EL1.T0SZ` was 25.**  That is a 39-bit space, which is a three-level
   table; this kernel's root is a level 0 table and needs 16 (48 bits).  With
   25, the machine indexed `TTBR0_EL1` as a level 1 table, never read entry 0,
   and the first fetch faulted with `DFSC = 0b000101`,
   *translation fault, level 1* — the log line that named the constant.

The aarch64 boot now prints the same nine lines with the MMU on.  Setting
`TCR_T0SZ` back to 25 stops it after `protofire: page table`, so those lines are
evidence that translation is in use rather than a coincidence.  A test,
`the_address_size_matches_the_table_depth`, derives the required value from
`Level::Root::shift()` instead of restating it.

### Device windows

Turning the MMU on changes what an unruled address *means*.  With translation
off every access is device-like; with it on, an address with no rule is Normal
memory — cached and prefetchable — and the PL011's status register read from a
stale cache line is a console that prints nothing for a reason that looks like a
dead UART.

`arch::paging::device_windows()` is the machine's answer: aarch64 returns
`0x0000_0000..0x4000_0000` — everything below `virt`'s RAM — and x86_64 returns
an empty slice, because it learns its device addresses from a bus and re-maps
them one BAR at a time.  `kernel::address_space` turns that answer into a
permission, which is the division the tree already has: `arch` says what the
machine is, the kernel says what to do about it.

The aarch64 range is a constant of `qemu-system-aarch64 -machine virt`.  It is
the honest form of "this is the machine the boot gates run on", and the parse of
the device tree is what turns it into a query.

### The aarch64 boot, and what it cost

`entry.S` does four things before Rust: a stack, the bss clear, the drop from
EL2 to EL1, and `CPACR_EL1.FPEN`.  The last one is there because the boot that
did not do it **printed four lines and stopped**, and the reason took a QEMU
exception log to find: `ESR_EL1.EC` = 7 at a `0x0E01...` word, which is a NEON
instruction LLVM emitted for the `memcpy` inside `PyroFS::build_image`.  Every
line before that was scalar code, which is why the failure looked like a
filesystem problem.

The lesson is the one this file keeps recording: a machine's boot is exercised
or it is not, and building an image is not exercising it.  `scripts/verify.sh`
now boots **every** machine with an image, so the next boot that stops early is
a red gate rather than a line someone happened to notice.

The trap path is real: `entry.S` saves `x0`..`x30`, `ELR_EL1`, `SPSR_EL1`,
`ESR_EL1`, `FAR_EL1` and `q0`..`q31` into an 800-byte frame, calls
`aarch64_exception_dispatch`, and `eret`s.  `install_interrupt_table` does not
report success from writing `VBAR_EL1` — it raises a supervisor call first and
answers `true` only if the call arrived at entry 4 and returned.  A probe that
cannot fail is not evidence, so the probe was mutated (the expected vector
changed to 8) and the boot line went back to "not installed".


## Kernel

The boot sequence, the syscall table and device discovery.  Not here:

| Module | Lines | Why it is not here yet |
|---|---:|---|
| the scheduler | — | nothing to schedule; a process layer needs address spaces |
| the process layer | — | the same |
| the network stack | — | see above |
| audit, security policy, service manager, procfs, shm | — | each arrives with the subsystem it observes |

The previous tree's `kernel` is 39,704 lines.  Most of it is the process layer
and the scheduler, and they are the last to arrive because every other subsystem
has to have somewhere to put a per-process value before a process is worth
having.

## `user` and `apps`

The previous tree's `src/user/` is 19,145 lines: a user-space runtime, syscall
wrappers, a demo renderer, the shell's commands and the programs themselves.

`apps/` holds `init`, `shell` and `service_manager` as skeletons — each has the
shape a program must have and no body, because the syscall that starts a process
is served as `NotImplemented` and a body that pretended to work would be a claim
the tree cannot back.

## How a crate arrives

1. It moves in with its tests, and `cargo test -p <crate>` runs them on the host.
2. Its layer is argued in `scripts/layering.txt` before it is added to the
   workspace — a crate with no layer is the one crate nobody checks.
3. Its test count is recorded in `scripts/crate-tests-baseline.txt`, which is a
   ratchet: the count may rise freely and may not fall.
4. `docs/architecture.md` gains a paragraph if the crate's placement was a
   decision, and this table moves a row.

A filesystem has one more condition, and it is the user's: it arrives only after
a mount has been verified on a machine.
