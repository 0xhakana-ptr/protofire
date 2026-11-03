# What has moved in, and what has not

This tree replaces a single crate of 312,000 lines.  The migration is not a
rewrite and not a copy: each subsystem moves in as a crate of its own, with its
tests, once it can be built and exercised on its own.  This document is the
count.

**The number that matters: about 13% of the previous tree is here.**  What is
here is the part that proves the architecture — a boot, a heap, a bus, a driver,
a filesystem and a syscall — and the rest is being moved a crate at a time.

## The table

| Subsystem | Previous tree | Here | What is in |
|---|---:|---:|---|
| `abi` | 4,725 | 3,479 | the whole wire format, and the syscall numbering |
| `arch` | 95,361 | 2,479 | boot, interrupts, serial, port I/O, page-table encoding — five of a hundred |
| `crypto` | 4,606 | 4,832 | all of it, one module per algorithm |
| `fs` | 68,494 | 14,683 | PyroFS, tmpfs, ISO 9660, the mount table and the VFS contract; eight filesystems are not here |
| `kernel` | 39,704 | 1,157 | the boot sequence, the syscall table, device discovery |
| `memory` | 9,649 | 1,865 | the frame pool and the region pools |
| `network` | 39,240 | 1 | nothing |
| `drivers` | 18,828 | 3,772 | PCI, and virtio block |
| `syscall` | 15,647 | 253 | the context, the validators, three handlers |
| `user` | 19,145 | — | nothing; `apps/` holds three skeletons |
| `libs` | — | 8,442 | allocator, audit, block, cell, profiler, rights, sync, unicode |
| **total** | **312,131** | **~42,000** | |

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

Four modules out of a hundred, on each machine.  The previous tree's `arch` is
95,361 lines across `x86_64` (49 files), `aarch64` (25) and `riscv64` (22), plus
`pci`, `fdt`, `trap`, `mmu`, `percpu`, `smp`, `thread`, `user_access`,
`syscall_trap`, `ptrace` and more.

What is here is what a boot needs before anything else: the entry, the console,
the interrupt flag, and — on x86_64 — the port I/O the PCI bus is reached
through.  What comes next is the memory-management unit, because a driver that
maps a BAR needs it and a kernel that faults needs it more.

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
