# Roadmap

What the tree can do, what it cannot, and which gap blocks which.  This file
exists because the answer was being re-derived by hand every time somebody asked
"what is left", and a number found by hand is a number that will be wrong the
next time it is asked.

`docs/status.md` is the per-machine census: what runs, on which machine, with
the boot line that proves it.  This file is the other axis — what is missing,
and in what order the missing pieces depend on each other.

## The measurement, and when it was taken

Everything below is measured, not remembered.  The counts are cheap to re-take:

```sh
# Which syscall numbers have a handler
grep -oE 'if number == SyscallNumber::\w+' kernel/src/process.rs
grep -A1 'table.register' kernel/src/boot.rs

# The ABI's own list
grep -cE '^\s{4}[A-Z][A-Za-z0-9]* = [0-9]+,' abi/src/number.rs

# Crate sizes and layers
grep -E '^[0-9]+ ' scripts/layering.txt
```

As of the commit that added this file: **39 crates, 87,492 lines, 832 tests**,
four machines booting, and **22 of 195 syscall numbers served**.

---

## What exists

### The foundation

| crate | lines | what it is |
|---|---|---|
| `cell` | 325 | a `Sync`-capable `UnsafeCell` |
| `profiler` | 310 | operation counters, compiled out when off |
| `unicode` | 4,619 | character conversion and normalisation |
| `rights` | 76 | two constants and **no consumer** |
| `audit` | 601 | an audit record and its ring |
| `abi` | 3,524 | error codes, the 195 syscall numbers, boot information |

### Tools a host can test

| crate | lines | what it is |
|---|---|---|
| `crypto` | 4,895 | SHA-256/512, CRC, ChaCha20, Poly1305, AES, GCM, XTS, HMAC, HKDF, PBKDF2, X25519, ECDSA, RSA |
| `fdt` | 1,663 | the flattened device tree |
| `paging` | 776 | a page table and the arithmetic that walks one |
| `irq` | 460 | the handler table |
| `ipc` | 342 | the pipe's ring buffer |
| `power` | 322 | a frequency governor |
| `async_io` | 1,539 | the request/completion model — **parked**, see `docs/async_io.md` |

### The machines

| crate | lines | what it is |
|---|---|---|
| `arch_x86_64`, `arch_aarch64`, `arch_riscv64` | 20,526 total | three real ports: boot, traps, timers, SMP, ring 3 |
| `arch` | — | the route between them |
| `block` | 1,217 | `BlockDevice` and `QueuedBlockDevice` |
| `memory` | 2,285 | the frame pool and the region pools |

### The subsystems

| crate | lines | what it is |
|---|---|---|
| `pci` | 2,590 | ECAM and ports, capability walks, BARs, MSI-X |
| `sync` | 353 | a spinlock that masks interrupts |
| `syscall` | 289 | numbering, the call context, the validators — **no handlers** |
| `security` | 1,272 | the MAC policy: rules, types, denials |
| `virtio_core` | 1,989 | queue, feature negotiation, the PCI modern transport |
| `fs` | 14,706 | the VFS, PyroFS, tmpfs, ISO 9660 |
| `virtio_block` | 1,249 | the block driver |
| `virtio_net` | 1,832 | the network card: two queues, ARP in and out |
| `service_table` | 562 | a name-to-service table — **parked** |
| `allocator` | 2,502 | the TLSF heap |
| `net`, `sound`, `virt`, `e1000` | 6 / 6 / 54 / 6 | **empty placeholders** |

### The kernel and the image

| crate | lines | what it is |
|---|---|---|
| `kernel` | 14,112 | boot, scheduler, processes, COW, pipes, the address space, device discovery |
| `bootloader` | 112 | the image entry |
| `init` | 291 | the one real program: reads a greeting, exits with its first byte |
| `service_manager`, `shell` | 60 / 59 | **empty shells** |
| `xtask` | 1,870 | the build and the gate |

---

## What is missing

### The distinction that matters most

Many gaps are **not** missing capabilities.  They are capabilities the kernel has
and user space cannot reach.  That difference decides how hard the work is: a
missing capability is design and code, a missing syscall is wiring.

| capability | in the kernel | reachable from a program |
|---|---|---|
| open, read, close a file | yes | yes — `Open`, `Read`, `Close` |
| **write a file** | yes, `VNode::write` | **no** — `Write` prints to the console |
| **create, remove, rename** | yes, PyroFS has all of it | **no** — no syscall at all |
| **list a directory, stat** | yes | **no** |
| allocate memory | yes, the heap | **yes** — `Mmap`, `Munmap`, `Brk`, `ReclaimPages` |
| start a process | yes | only the boot's own `ExecProcess` |
| fork, wait, pipe | yes | yes |
| **signals** | no | no — five numbers, all empty |
| **threads** | no | no |
| **time, randomness** | yes, the counter and `crypto` | **no** — nine numbers, all empty |
| **network** | ARP only | no — fourteen numbers, all empty |
| **shared memory** | no | no — `ShmGet` and friends are unimplemented |
| **pass a handle to another process** | no — `Descriptor` has two variants | no |

### The syscall census, by family

Of 195 numbers, 18 are served.  The unserved 177 fall into these groups; the
count is the number of numbers in the group, not the work involved.

| family | numbers | in the kernel today |
|---|---|---|
| filesystem metadata and mutation (`Stat`, `ReadDir`, `CreateDir`, `RemovePath`, `Rename`, the `*At` forms, `SetLength`, `Fsync`, `Fallocate`, xattrs, file flags) | 28 | **all of it** — PyroFS implements every operation |
| sockets and the network stack (TCP, UDP, raw, local domain, DCCP, IPsec, MRT) | 32 | ARP only |
| process, signal and scheduling (`SpawnProcess`, `SendSignal`, `WaitSignal`, `*SignalHandler`, `Futex`, `SchedSetAffinity`, `Ptrace`, `Seccomp`, `Prctl`, introspection) | 23 | fork/exit/wait/pid only |
| shared memory and synchronisation primitives (`Shm*`, `EventFd`, `TimerFd`, `SignalFd`, `Mq*`, `Epoll*`, `Timer*`) | 20 | none |
| GPU | 9 | none |
| mounts and volumes (`Mount`, `Umount`, `ListMounts`, `RepairVolume`, `FuseMount`) | 5 | the mount table exists |
| time, randomness, system information (`GetTimeOfDay`, `GetRandom`, `SystemInfo`, `AbiInfo`) | 4 | the counter and `crypto` |
| **the rest** — memory (`Brk`, `Mmap`, `Munmap`, `ReclaimPages`), descriptors (`Dup`, `Seek`, `Fcntl`, `Poll`), identity (`GetUid`, `GetGid`, users), power, audit, io_uring, service, and the app's own argv/env/path calls | 56 | assorted |

The groups overlap at the edges — `SigReturn` is a signal number, `ListThreads`
is process introspection, `GetHostName` is identity and network — so the column
does not sum to a clean total.  The counts were taken by matching the enum's
names, which is how they can be re-taken; the code block at the top of this file
shows the command.

---

## The order

Each level depends on the one above it.  Nothing here is scheduled; the order is
what the dependencies say, not a plan of work.

### Level 1 — memory — **done**

`Mmap`, `Munmap`, `Brk` and `ReclaimPages` are served, and a program maps a page,
writes into it and reads its own break back.  `docs/status.md` carries the boot
lines; the two facts worth keeping here are that reservations count down from the
window's top (the image and its stack own the bottom) and that raising the
ownership bound needed two stack arrays resized with it, which is what the first
attempt to raise it discovered.

What is still not here: **shared memory**.  `ShmGet` and its three siblings are
separate numbers and a separate problem — two processes naming one region — and
they are not part of what this level promised.

### Level 2 — the filesystem interface

`Write` (so a program can write a file and not only print), then `Stat`,
`ReadDir`, `CreateDir`, `RemovePath`, `Rename`, and the `*At` variants.  The
kernel capability exists for all of it; the work is wiring and the descriptor
bookkeeping each one needs.

**This level is the cheapest.**  PyroFS implements every operation, the VFS
declares them, and the syscall table already has the pattern: `open` in
`kernel/src/syscall/handlers.rs` is the model to follow.

### Level 3 — the process model

`SpawnProcess` (a supervisor cannot supervise what it cannot start), then
signals: `SendSignal`, `WaitSignal`, `SetSignalHandler`, `SetSignalMask`,
`SigReturn`, `SigSuspend`.  The scheduler has the waits already —
`block_unless`, `wake_blocked` — which is what a signal delivery needs.

Threads are in this level if they are wanted, and they are a different decision:
the tree has one task per process today, and a thread brings shared address
spaces.

### Level 4 — time and randomness

`GetTimeOfDay`, `GetRandom`, and the system-information calls beside them.
`arch::timer_counter` and `crypto`'s generators are the sources; the work is the
syscall and the ABI shape of a time value.

### Level 5 — the network

A stack, not a driver: IPv4, then UDP, then TCP.  `virtio_net` moves frames and
stops there on purpose.  This is the largest single level and the one with the
least existing code to build on — fourteen numbers and not one line of protocol
above the frame.

### In parallel — the drivers

`e1000`, `sound` and `virt` are placeholders.  None of them blocks a level above;
each is an independent piece of work with its own gate line.

---

## What this file is not

Not a schedule.  Not a claim that the levels are the only order — a driver could
come first, or the filesystem interface before memory if `Write` were wired to a
buffered file.  It is the order the dependencies impose, which is the part that
cannot be chosen.

Not a census.  When a level lands, its line moves to `docs/status.md` with the
boot line that proves it, and this file loses the entry — the same rule
`docs/status.md` states about itself, one document over.
