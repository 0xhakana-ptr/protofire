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

Four machines boot, and **43 of the 195 numbers are served**, after the memory,
filesystem, process and time levels.  That is the number the census command
above answers, and it is the one to re-take rather than trust.

The boot's own line, `syscall table installed, 25 number(s) served`, counts
only the registry's half — the numbers whose handler functions live in
`boot.rs`'s table.  The rest are the ones `process.rs` serves itself: the
scheduler's, the pipe's, and the ones that need a ring-3 address turned into a
borrow before a handler can see it.  A number reachable from a program needs
**both** a registry entry and a branch in `process.rs`, which is the division
that cost the `*At` calls a boot to learn.

---

## What exists

The inventory, by what a crate is for.  **No line counts here**: a table of
sizes maintained by hand is wrong within a month, and this one was.  It listed
29 crates where the workspace has 40 — `userland`, the four architecture crates
and all four placeholders were missing — and it named `init` as "reads a
greeting, exits with its first byte" long after that program had grown the whole
filesystem, memory and signal demo.

Two commands answer what it used to:

```sh
sh scripts/check-crate-tests.sh            # every crate, its lines, its tests
sh scripts/check-layering.sh               # the crates and their layers
```

The tree is **94,084 lines of Rust across 40 crates**, which is
`find . -name '*.rs' -not -path './target/*' | xargs cat | wc -l` and not the
census's sum: that one walks each crate's directory and so counts the three
machine crates twice, inside `arch/` and on their own.

### The foundation

| crate | what it is |
|---|---|
| `cell` | a `Sync`-capable `UnsafeCell` |
| `profiler` | operation counters, compiled out when off |
| `unicode` | character conversion and normalisation |
| `rights` | two constants and **no consumer** |
| `audit` | an audit record and its ring |
| `abi` | error codes, the 195 syscall numbers, the wire records, boot information |

### Tools a host can test

| crate | what it is |
|---|---|
| `crypto` | SHA-256/512, CRC, ChaCha20, Poly1305, AES, GCM, XTS, HMAC, HKDF, PBKDF2, X25519, ECDSA, RSA |
| `fdt` | the flattened device tree |
| `paging` | a page table and the arithmetic that walks one |
| `irq` | the handler table |
| `ipc` | the pipe's ring buffer |
| `power` | a frequency governor |
| `async_io` | the request/completion model — **parked**, see `docs/async_io.md` |
| `userland` | the ring-3 side of the ABI: the numbering, one call gate per machine, the wrappers |

### The machines

| crate | what it is |
|---|---|
| `arch_x86_64`, `arch_aarch64`, `arch_riscv64` | three real ports: boot, traps, timers, SMP, ring 3 |
| `arch` | the route between them |
| `block` | `BlockDevice` and `QueuedBlockDevice` |
| `memory` | the frame pool and the region pools |

### The subsystems

| crate | what it is |
|---|---|
| `pci` | ECAM and ports, capability walks, BARs, MSI-X |
| `sync` | a spinlock that masks interrupts |
| `syscall` | numbering, the call context, the validators |
| `security` | the MAC policy: rules, types, denials |
| `virtio_core` | queue, feature negotiation, the PCI modern transport |
| `fs` | the VFS, PyroFS, tmpfs, ISO 9660 |
| `virtio_block` | the block driver |
| `virtio_net` | the network card: two queues, ARP in and out |
| `service_table` | a name-to-service table — **parked** |
| `allocator` | the TLSF heap |
| `net`, `sound`, `virt`, `e1000` | **empty placeholders**: a protocol stack, audio, virtualisation, and a card this tree does not boot with |

### The kernel and the image

| crate | what it is |
|---|---|
| `kernel` | boot, scheduler, processes, COW, pipes, the address space, the syscall registry, device discovery |
| `bootloader` | the image entry: one symbol, a panic handler, and `kernel_main` |
| `init` | the first program: the filesystem interface, memory, spawn, signals, the clock and the two records |
| `shell` | the second program: reads the greeting, arms a handler, announces itself to its parent |
| `service_manager` | **an empty shell**: supervising needs a service model, not just spawn |
| `xtask` | the build and the gate |

---

## What is missing

### The distinction that matters most

Many gaps are **not** missing capabilities.  They are capabilities the kernel has
and user space cannot reach.  That difference decides how hard the work is: a
missing capability is design and code, a missing syscall is wiring.

The rows below are the ones left.  The four levels that landed — memory, the
filesystem interface, the process model, time and randomness — took every row
whose "reachable" column used to say no, which is why this table is now short.

| capability | in the kernel | reachable from a program |
|---|---|---|
| shorten a file, `SetLength` and truncate | yes, `VNode::set_len` | **no** — one handler and one registration |
| stat or list by descriptor, `StatFd`/`ReadDirFd` | yes | **no** — the descriptor carries `path`, so the anchor exists |
| seek, duplicate, poll a descriptor | the offset is per descriptor | **no** |
| **the network** | frames and ARP only | no — 32 socket numbers, all empty |
| **shared memory** | no | no — `ShmGet` and its three siblings |
| **threads** | no — one task per process | no |
| **pass a handle to another process** | no — `Descriptor` has two variants | no |
| mount, unmount, list mounts | the table exists | **no** — five numbers |
| identity: uid, gid, users | no | no |
| power, audit, io_uring, GPU, seccomp | `power`'s governors and `audit`'s ring exist, the rest do not | no |

### The syscall census, by family

Of 195 numbers, **43 are served**.  The 152 that are not fall into these
groups; the count is the number of numbers in the group, not the work involved.

| family | numbers | in the kernel today |
|---|---|---|
| filesystem metadata and mutation still unserved (`SetLength`, `StatFd`, `ReadDirFd`, `Fsync`, `Fallocate`, xattrs, file flags, the access and permission queries) | 18 | **all of it** — the filesystem implements every operation |
| sockets and the network stack (TCP, UDP, raw, local domain, DCCP, IPsec, MRT, and the host-name and address calls beside them) | 34 | ARP only |
| process, signal and scheduling still unserved (`Futex`, `SchedSetAffinity`, `Ptrace`, `Seccomp`, `Prctl`, the introspection calls) | 10 | fork/exit/wait/pid/signals landed; these did not |
| shared memory and synchronisation primitives (`Shm*`, `EventFd`, `TimerFd`, `SignalFd`, `Mq*`, `Epoll*`, `Timer*`) | 20 | none |
| GPU | 9 | none |
| mounts and volumes (`Mount`, `Umount`, `ListMounts`, `RepairVolume`, `FuseMount`) | 5 | the mount table exists |
| **the rest** — descriptors (`Dup`, `Dup2`, `Seek`, `Fcntl`, `Poll`), identity (`GetUid`, `GetGid`, users), power, audit, io_uring, service, and the app's own argv/env/path calls | 56 | assorted |

The seven rows sum to exactly 152, because each number is assigned to one row by
name — the edges between families (`GetHostName` is identity *and* network,
`ListThreads` is process introspection) are settled by where the row's handler
would live, and that assignment is the census's one judgement call.  The counts
come from matching the enum's names, which is how they can be re-taken; the code
block at the top of this file shows the command.

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

### Level 2 — the filesystem interface — **done**

`Write` writes a file, `Stat` answers a sixteen-byte record, `ReadDir` lists a
directory by index, `CreateDir`, `RemovePath` and `Rename` change the
namespace, and all five `*At` forms anchor on a directory descriptor — eleven
numbers, every one reachable from ring 3, with a program that does the whole
of it and boot lines beside each call.  `docs/status.md` carries the evidence
and the two defects the first ring-3 exercise found (an unregistered handler
and an unapplied GOT relocation), which is the part a green gate could not
have said on its own.

What the level did **not** promise: `StatFd` and `ReadDirFd` (30, 31) — a
descriptor's own stat needs the descriptor to know what it names beyond the
node, and the listing-by-descriptor is the same gap; both are separate
numbers.  `SetLength` (20) and the truncate side of `write` are one decision
the filesystem already implements (`VNode::set_len`) and the ABI has not been
given yet.  And nothing here is about *which* filesystem answers — the mount
table routes every call the same way, which is why the tmpfs and the PyroFS
volume both served the level without the handlers changing.

### Level 3 — the process model — **done**

`SpawnProcess` starts a program from a file as a child the caller can wait
for by pid, and all six signal numbers serve: `SendSignal` queues on the
target's own ring, `WaitSignal` parks on it, `SetSignalMask` blocks and
`SigSuspend` runs the ring under a mask with the caller's own put back, and
a handled signal is **delivered** — the target's context redirected to the
program's own handler at its next install, `SigReturn` putting the whole
interrupted context back.  `docs/status.md` carries the exchange and the
three defects the first boot of it found, one of them in the riscv64 trap
path itself.

What the level did **not** promise: **threads** — the tree has one task per
process, and a thread brings shared address spaces, which is a decision and
not wiring.  Nor a wait that names a timeout: the tree's waits park until
the thing they name happens, and a timed park is a scheduler feature the
level did not need.

### Level 4 — time and randomness — **done**

`GetTimeOfDay` (70), `GetRandom` (75), `SystemInfo` (53) and `AbiInfo` (39) are
served and reachable from ring 3, and `init` reads the clock twice, draws two
blocks of randomness that must differ, and reads both records back.  The
sources are what this file said they were: the machine's counter divided by the
rate it reports, and a ChaCha20 stream over that.  `docs/status.md` carries the
lines.

What the ABI grew, and why: a `TimeRecord` of two words — seconds and
nanoseconds — because a counter reading is a number whose rate is the machine's
and a program has no way to divide it; a `SystemInfo` of eight counters under
one selector, refused for a selector this build does not serve rather than
answered with zeros; and an `AbiInfo` of three constants, which is the one call
a program can make before it trusts any other.

What this level did **not** promise:

- **Wall time.**  `CLOCK_REALTIME` is defined and answers `Unsupported`.  It
  needs a real-time clock driver and this kernel has none; the old tree read
  one from an RTC, and a number nobody read is worse than an error.
- **Entropy that is not the clock.**  There is no `RDRAND`/`RDR`/`RDSEED`
  probe, so the generator's seed is timing, and the bytes are fit for a nonce,
  a salt or a shuffle rather than for a key an attacker is motivated to
  recover.  A hardware source is its own level, and the generator is written so
  that adding one changes `random::seed` and nothing else.
- `Sleep`'s timed parks, `TimerFd`, `TimerCreate`, `ClockGetRes`: separate
  numbers, and the first of them is a scheduler feature rather than a source.

**Open, and not part of this level:** aarch64 stops on some boots between a
signal and the wait that follows it.  `docs/status.md` has the measurement, the
state QEMU's monitor shows, and the six explanations that were ruled out — two
of them real defects that are now fixed and were not the whole of it.

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
