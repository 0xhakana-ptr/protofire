# Roadmap

What the tree can do, what it cannot, and which gap blocks which.  This file
exists because the answer was being re-derived by hand every time somebody asked
"what is left", and a number found by hand is a number that will be wrong the
next time it is asked.

`docs/status.md` is the per-machine census: what runs, on which machine, with
the boot line that proves it.  This file is the other axis, what is missing,
and in what order the missing pieces depend on each other.

## The measurement, and when it was taken

Everything below is measured, not remembered.  The counts are cheap to re-take:

```sh
# Which syscall numbers are served: a branch in `process/`, or a registry entry.
# Both halves are needed for different calls, so the set is their union, and
# the sort is byte order because `comm` requires both sides in the same one.
grep -rhoE 'SyscallNumber::\w+' kernel/src/process/ kernel/src/boot.rs \
  | sed 's/.*:://' | LC_ALL=C sort -u > /tmp/served.txt

# The ABI's own list, in the same order, so `comm` can compare them.
grep -oE '^[[:space:]]{4}[A-Z][A-Za-z0-9]*[[:space:]]*=[[:space:]]*[0-9]+' \
  abi/src/number.rs | sed 's/[[:space:]]*=.*//; s/^[[:space:]]*//' \
  | LC_ALL=C sort -u > /tmp/declared.txt

echo "declared $(wc -l < /tmp/declared.txt)"
echo "served   $(comm -12 /tmp/served.txt /tmp/declared.txt | wc -l)"
echo "missing  $(comm -13 /tmp/served.txt /tmp/declared.txt | wc -l)"

# Crate sizes and layers
grep -E '^[0-9]+ ' scripts/layering.txt
```

Four machines boot, and **109 of the 196 numbers are served**, after the memory,
filesystem, process, time, network and driver levels.  That is the number the
census command above answers, and it is the one to re-take rather than trust:
it was 102 before the descriptor and attribute calls landed, and the three
numbers of drift are the reason this paragraph names its command.

The boot's own line, `syscall table installed, 88 number(s) served`, counts
only the registry's half, the numbers whose handler functions live in
`boot.rs`'s table.  The rest are the ones `process/` serves itself: the
scheduler's, the pipe's, and the ones that need a ring-3 address turned into a
borrow before a handler can see it.  The two halves are not nested, and the
numbers are in the census command's three answers rather than restated here,
which is what keeps this paragraph from drifting the way it did before.

---

## What exists

The inventory, by what a crate is for.  **No line counts here**: a table of
sizes maintained by hand is wrong within a month, and this one was.  It listed
29 crates where the workspace has 40, `user_abi`, the four architecture crates
and all four placeholders were missing, and it named `init` as "reads a
greeting, exits with its first byte" long after that program had grown the whole
filesystem, memory and signal demo.

Two commands answer what it used to:

```sh
sh scripts/check-crate-tests.sh            # every crate, its lines, its tests
sh scripts/check-layering.sh               # the crates and their layers
```

The tree is **194,870 lines of Rust across 47 crates**, which is
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
| `abi` | error codes, the 196 syscall numbers, the wire records, boot information |

### Tools a host can test

| crate | what it is |
|---|---|
| `crypto` | SHA-256/512, CRC, ChaCha20, Poly1305, AES, GCM, XTS, HMAC, HKDF, PBKDF2, X25519, ECDSA, RSA |
| `fdt` | the flattened device tree |
| `paging` | a page table and the arithmetic that walks one |
| `irq` | the handler table |
| `ipc` | the pipe's ring buffer |
| `power` | a frequency governor |
| `async_io` | the request/completion model, **parked**, see `docs/async_io.md` |
| `user_abi` | the ring-3 side of the ABI: the numbering, one call gate per machine, the wrappers |

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
| `fs` | the VFS, PyroFS, tmpfs, and the ten Level 6 formats |
| `virtio_block` | the block driver |
| `virtio_net` | the network card: two queues, ARP in and out |
| `kernel/src/service/table.rs` | a name-to-service table, **parked** |
| `allocator` | the TLSF heap |
| `net`, `sound`, `e1000` | **empty placeholders**: a protocol stack, audio, and a card this tree does not boot with |
| `virt` | a header and no code: which half of the guest/host question comes first, and why neither is written |

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

The rows below are the ones left.  The four levels that landed, memory, the
filesystem interface, the process model, time and randomness, took every row
whose "reachable" column used to say no, which is why this table is now short.

| capability | in the kernel | reachable from a program |
|---|---|---|
| duplicate or poll a descriptor | the descriptor holds the handle and the rights | **no** |
| **the network** | the stack, IPv4, IPv6, ICMP, ICMPv6, NDP, UDP, TCP, and all 43 of its numbers served | **yes**, every one of them, the socket and address calls, the two status calls, the datagram, stream and local-domain calls, and the six protocols this level keeps behind a stated limit |
| **shared memory** | no | no, `ShmGet` and its three siblings |
| **threads** | no, one task per process | no |
| **pass a handle to another process** | no, `Descriptor` has two variants | no |
| mount, unmount, list mounts | the table exists | **no**, five numbers |
| identity: uid, gid, users | no | no |
| power, audit, io_uring, GPU, seccomp | `power`'s governors and `audit`'s ring exist, the rest do not | no |

### The syscall census, by family

Of 196 numbers, **102 are served**.  The 94 that are not fall into these
groups; the count is the number of numbers in the group, not the work involved.
The network has no row, which is the change since this table was first taken:
each of its 43 numbers is served, so nothing from it is left to list.

| family | numbers | in the kernel today |
|---|---|---|
| filesystem metadata and mutation (`SetFdFlags`, the access and permission queries) | 7 | the access machinery exists and nothing has given it an identity to check |
| descriptors (`Dup`, `Dup2`, `Fcntl`, `Poll`) | 4 | the descriptor holds the handle and the rights; what is missing is a way to copy one, and a readiness question for `Poll` |
| shared memory, timers, multiplexing and queues (`Shm*`, `Futex`, `EventFd`, `TimerFd`, `SignalFd`, `Mq*`, `Epoll*`, `Timer*`) | 21 | none, and each is one mechanism rather than one call |
| identity (`GetUid`, `GetGid`, `AddUser`, `RemoveUser`, `SetUserPassword`, `SetSecurityDescriptor`) | 6 | `security` has the types and nothing has asked them |
| introspection and scheduling (`ListProcesses`, `ListThreads`, `ListProcessFaults`, `KernelLog`, `Prctl`, `Ptrace`, `Seccomp`, `SchedSetAffinity`, `SchedGetAffinity`) | 9 | the scheduler exists; these report on it or move a task |
| the app and the machine (`ArgCount`, `ArgValue`, `EnvCount`, `EnvValue`, `CurrentDir`, `SetCurrentDir`, `AppId`, `AppVersion`, `ImagePath`, `ManifestPath`, `Yield`, `RestartSyscall`, `CompactMemory`, `Mlock`, `Munlock`, `Madvise`) | 16 | assorted, and most are a record a program reads |
| io_uring (`IoUringSetup`, `IoUringEnter`) | 2 | none, and it is a second way to do what the calls above already do |
| GPU (`GpuCtxCreate`, `GpuCtxDestroy`, `GpuDeviceInfo`, `GpuResCreate3d`, `GpuResUnref`, `GpuSetScanout`, `GpuSubmit3d`, `GpuTransferFromHost3d`, `GpuTransferToHost3d`) | 9 | none, a VIRGL context over a device this tree does not have |
| mounts and volumes (`Mount`, `Umount`, `ListMounts`, `RepairVolume`, `FuseMount`) | 5 | the mount table exists |
| extended attributes (`SetXattr`, `GetXattr`, `ListXattr`, `RemoveXattr`) | 4 | every filesystem that has them implements them; what is missing is the wire format for a packed list |
| power, audit, policy and packages (`Cpufreq*`, `Audit*`, `MacSetPathType`, `ServiceDeclare`, `ServiceStartAll`, `InstallPackage`) | 11 | `power`'s governors and `audit`'s ring exist; the calls do not |

The twelve rows sum to exactly 94, because each number is assigned to one row by
name, the edges between families (`ListThreads` is process introspection *and*
scheduling) are settled by where the row's handler would live, and that
assignment is the census's one judgement call.  The counts come from matching
the enum's names, which is how they can be re-taken; the code block at the top
of this file shows the command.

Two of those rows were wrong when this table was first taken, and the error is
worth keeping: the network row said 34 while the enum has **43** names that are
network, seven `Dccp*`, five `Ipsec*`, six `Mrt*`, four `Filter*` and
`TlsConnect` were not counted in the parenthetical, and the "rest" row
absorbed the difference at 56.  One row's undercount is invisible in a total
that another row's overcount fills, which is why the rows are asserted to sum
rather than the total alone.

The table then went stale rather than wrong: it kept saying 51 served while the
network level served all 43 of its numbers and the rest stood still.  That is
the same defect as a remembered count, so the check is mechanical now, the
groups are asserted to partition the unserved set, and the numbers above are
what the command block at the top prints.

---

## The order

Most levels depend on the one above them, and where that is true the dependency
is the reason for the position.  Where it is not true, the position is a
choice, and this file says so rather than pretending otherwise.

**Levels 5 and 6 do not depend on each other.**  `net`'s manifest names no
crate and nothing in `fs/src/` mentions it; a filesystem needs `block`, and a
network stack needs `virtio_net`.  The network is first because it is smaller
and because the four layers it starts with are proved on the host without a
syscall, not because a filesystem would be wrong to come first.

### Level 1, memory, **done**

`Mmap`, `Munmap`, `Brk` and `ReclaimPages` are served, and a program maps a page,
writes into it and reads its own break back.  `docs/status.md` carries the boot
lines; the two facts worth keeping here are that reservations count down from the
window's top (the image and its stack own the bottom) and that raising the
ownership bound needed two stack arrays resized with it, which is what the first
attempt to raise it discovered.

What is still not here: **shared memory**.  `ShmGet` and its three siblings are
separate numbers and a separate problem, two processes naming one region, and
they are not part of what this level promised.

### Level 2, the filesystem interface, **done**

`Write` writes a file, `Stat` answers a sixteen-byte record, `ReadDir` lists a
directory by index, `CreateDir`, `RemovePath` and `Rename` change the
namespace, and all five `*At` forms anchor on a directory descriptor, eleven
numbers, every one reachable from ring 3, with a program that does the whole
of it and boot lines beside each call.  `docs/status.md` carries the evidence
and the two defects the first ring-3 exercise found (an unregistered handler
and an unapplied GOT relocation), which is the part a green gate could not
have said on its own.

What the level did **not** promise: `StatFd` and `ReadDirFd` (30, 31), a
descriptor's own stat needs the descriptor to know what it names beyond the
node, and the listing-by-descriptor is the same gap; both are separate
numbers.  And nothing here is about *which* filesystem answers, the mount
table routes every call the same way, which is why the tmpfs and the PyroFS
volume both served the level without the handlers changing.

Both of those came off the list later, in one change, because they are one
gap: `Descriptor::File` already records the path it resolved to, its own field
comment saying that is what the `*At` calls anchor on, and the two readings
were the calls that needed the same fact and nothing else.  `SyscallTable::path_of`
is the one new piece; `StatFd` and `ReadDirFd` then reuse `stat_resolved` and
`read_dir_resolved` unchanged, which is why the pair cost less than either
alone.

The evidence is that the two anchors agree, and the boot prints both:

```
protofire: process 1 stat'd descriptor 1
protofire: process 1 listed descriptor 1
```

`init` compares each descriptor answer against the path form's for the same
directory, so a call that resolved a different anchor fails its own exit status
rather than passing on a plausible record.  Four host tests, mutation-tested:
a `path_of` that answers `/` for every descriptor fails three of them, and one
that lets a pipe end answer a path fails the fourth.

`Seek` (9) came with them, and it is the one call of the group with an
arithmetic rather than a lookup.  Three things it decides, each because the
alternative is a failure that looks like success:

- **The offset is signed.**  A backward step from the current position is a
  negative distance, and reading the word unsigned turns `-1` into
  eighteen quintillion and refuses a call that asked to step back one byte.
- **A position past the end is legal and stays.**  The read path already treats
  a position past the end as end of file, and refusing it at the seek would be
  a rule the seek keeps and the read does not.
- **`SEEK_DATA` and `SEEK_HOLE` are not distances.**  Their offset is absolute,
  their answer is the node's, and the position moves to the answer.  `VNode::next_extent`
  already had the mechanism, so the call is a reader of it.

Writing it produced one lesson worth keeping: the first version had a
`if next < 0` check before the `u64::try_from` that follows, and **deleting the
check changed no test**, because the conversion already refuses both ends.  The
check is gone, and the comment where it was now says so.  A refusal no test can
remove is a refusal nobody can tell is there.

`Fsync` (54) and `Fdatasync` (55) came next, and they are the reverse problem:
their success leaves no trace on the file, so every test that reads the status
word passes a handler that answered without reaching the node.  The test that
holds them inserts a node that **counts** its two flush entry points, and the
assertions are on those counts: `Fsync` calls `sync` once and not `sync_data`,
`Fdatasync` the other way round, and a read-only descriptor reaches neither.
That is the cheap version of the rule this tree keeps relearning, a call that is
written, wired and never executed looks exactly like one that works.

`Fallocate` (193), `GetFileFlags` (156) and `SetFileFlags` (155) closed the
group, and the boot's first honest run of them turned up a Level 7 gap that
this level had been quietly assuming away.

**The driver never negotiated `VIRTIO_BLK_F_FLUSH`.**  It offered
`VIRTIO_F_VERSION_1 | VIRTIO_F_RING_EVENT_IDX` and nothing else, so a `Flush`
request went out to a card that was never told the driver would send one, and
`wait` spun to its 50-million-iteration limit before answering `TimedOut`.  A
`Fsync` on the root volume took seconds and failed, and the first boot of this
group demonstrated it by hanging until the gate's own timeout rather than by
printing anything.

Level 7 fixed it, and the fix was two defects rather than one.  Negotiating the
bit is the first: `virtio_block::features` now asks for it and `VirtioBlock`
remembers whether it got it, so a device without the bit answers
`NotImplemented` at once instead of submitting into a request it will ignore.

The second is the one the first exposed.  `submit` allocated three descriptors
unconditionally, so a flush went out as `header -> {address 0, length 0} ->
status`; the specification says a flush is two (5.2.6.1), and a device that
trusts the specification never completes the third.  **Twenty-three host tests
could not see it**, because the fake device read the chain with the same
three-descriptor assumption the driver wrote with: the two agreed, and both were
wrong.  The fake device now walks the chain to its end and records how many
links it walked, which is how the shape became assertable at all.

The boot says what it negotiated, because a bit's absence is invisible any
other way:

```
protofire: virtio-blk negotiated flush=yes
protofire: process 1 flushed descriptor 6
```

The second line is a flush on the PyroFS root, which is the case that used to
hang.

The two refusals that *are* exercised are both properties of this machine and
both recorded as such, with the program asserting the refusal rather than
success:

- **`Fallocate` refuses on the root**, because only the NTFS volume implements
  `VNode::punch_hole` and the root is PyroFS.
- **`SetFileFlags` refuses on the root**, because PyroFS persists the flags byte
  only in its V4 format and the boot image is not V4.  The volume answers
  `Unsupported` rather than writing into a field a remount would drop, which is
  the reading this tree prefers to a call that reports success and loses the
  value.

`GetFileFlags` is the one that answers, and its line carries the word the
program read back:

```
protofire: process 1 asked for the flags of descriptor 6, answered 0
protofire: process 1 was refused a call on descriptor 6
```

`SetLength` (20) was on that list and has come off it.  The filesystem already
implemented it, `VNode::set_len`, and what was missing was a table method, a
handler, a registration and a ring-3 branch: the level's own gap stated as
wiring.  `init` truncates the file it wrote, and the boot proves the file
actually shrank rather than the call answering zero:

```
protofire: process 1 stat'd at.txt via descriptor 1, kind file, size 4
protofire: process 1 set descriptor 6 to 2 byte(s)
protofire: process 1 stat'd at.txt via descriptor 1, kind file, size 2
```

The descriptor's position does not move, which is the one design decision
inside it: a caller that writes, truncates and writes again appends, and a
truncate that rewound the position would make the third call overwrite the
first.  Four host tests hold it, one per claim, and each was mutation-tested:
a `set_len_at` that answers without reaching the node, a missing write-right
check, and an offset that moves all fail the test that names them.

### Level 3, the process model, **done**

`SpawnProcess` starts a program from a file as a child the caller can wait
for by pid, and all six signal numbers serve: `SendSignal` queues on the
target's own ring, `WaitSignal` parks on it, `SetSignalMask` blocks and
`SigSuspend` runs the ring under a mask with the caller's own put back, and
a handled signal is **delivered**, the target's context redirected to the
program's own handler at its next install, `SigReturn` putting the whole
interrupted context back.  `docs/status.md` carries the exchange and the
three defects the first boot of it found, one of them in the riscv64 trap
path itself.

What the level did **not** promise: **threads**, the tree has one task per
process, and a thread brings shared address spaces, which is a decision and
not wiring.  Nor a wait that names a timeout: the tree's waits park until
the thing they name happens, and a timed park is a scheduler feature the
level did not need.

### Level 4, time and randomness, **done**

`GetTimeOfDay` (70), `GetRandom` (75), `SystemInfo` (53) and `AbiInfo` (39) are
served and reachable from ring 3, and `init` reads the clock twice, draws two
blocks of randomness that must differ, and reads both records back.  The
sources are what this file said they were: the machine's counter divided by the
rate it reports, and a ChaCha20 stream over that.  `docs/status.md` carries the
lines.

What the ABI grew, and why: a `TimeRecord` of two words, seconds and
nanoseconds, because a counter reading is a number whose rate is the machine's
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

**The aarch64 stop that used to shadow this level is fixed.**  It looked like a
started core's timer going silent; it was a software interrupt at the GIC's
reset priority blocking that core's whole interrupt path.  `docs/status.md`
carries the trace and the 30-of-30 measurement.

### Level 5, the network, **done**

A stack, not a driver: IPv4, then UDP, then TCP, and then IPv6, which started
as "the other address family" and turned out to bring its own discovery
protocol with it.  `virtio_net` moves frames and stops there on purpose.  This
was the largest single level and the one with the least existing code to build
on, **43 numbers** and no line of protocol above the frame when it started.

All 43 are served now, and the census above has no network row because of it.
The rest of this section is the record of what the level decided, which is
worth keeping: two of the limits it states are properties of this machine
rather than gaps, and a later change that "fixes" one of them is undoing a
measurement.

What those 43 are, because the shape decides the order: 20 of them are the
socket and address calls a program makes (`NetworkStatus`, `ConnectTcp`,
`ListenTcp`, `AcceptTcp`, `BindUdp`, `SendToUdp`, `RecvFromUdp`, the three
name lookups, `GetSockName`/`GetPeerName`, the four raw-socket calls, the two
`SockOpt` calls and the three local-domain ones); the other 23 are protocols
the level planned not to promise, seven `Dccp*`, five `Ipsec*`, six `Mrt*`,
four `Filter*`, and `TlsConnect`.  All 23 landed anyway, which is the second
thing this section records.

The dependencies, in order, as they were planned:

1. **`net`** was 6 lines when this was written, a `#![no_std]` and a comment.
   It grew the frame's layers, and each one is a host-testable unit with no
   device in it: IPv4 header parse and build plus its checksum, an ARP cache
   (the card answers one ARP question and remembers nothing), ICMP as far as
   "port unreachable" needs, UDP with its checksum, then TCP's state machine.
2. **The kernel** grows a socket table and the dispatch.  A socket is a handle
   a program holds, and `Descriptor` in `kernel/src/syscall/table/mod.rs` has two
   variants, `File` and `Pipe`, so this is where a third arrives.  The
   scheduler's parking machinery is already the right shape for a blocking
   `accept` and a blocking `recv`; nothing about it needs to change.
3. **The gate** grows a line per layer.  `virtio_net` already proves both
   queues with the ARP exchange, and QEMU's user-mode network answers a ping
   and a UDP echo, so a layer's evidence can be a real exchange rather than a
   packet built and thrown away.

`virtio_net` needs no change to carry this: `submit_frame`, `post_receive_buffer`
and `receive_frame` are already the raw interface a stack wants, and the card
already owns both queues.  What it has never had is a *caller that is not the
boot's ARP probe*, and that is what a stack becomes.

#### The order inside Level 5, and why each step is worth landing

Each step is one commit with its own host tests and its own boot line, and each
is useful before the next exists.

| step | what it adds | how it is proved |
|---|---|---|
| **5.1** IPv4 | header parse/build, checksum, a frame this host can construct and re-read | host tests over hand-built bytes; round-trip |
| **5.2** ARP cache | a table from an address to a MAC, an unanswered question asked once | host tests; a boot that asks once and reuses the answer |
| **5.3** ICMP echo | a reply to a ping the boot sends | QEMU's user-mode network answers `10.0.2.2` |
| **5.4** UDP | a datagram out and back, the checksum that may be zero | a boot that sends and parses the echo |
| **5.5** `NetworkStatus` (37) | one number: is a card up, and what is its address | the first syscall of the level, and the smallest |
| **5.6** `BindUdp`/`SendToUdp`/`RecvFromUdp` (58–60) | the three calls a datagram needs | `init` sends and receives through ring 3 |
| **5.7** TCP | a handshake, a segment, an acknowledgement, an orderly close | QEMU's user-mode network is a real peer here |
| **5.8** `ConnectTcp`/`ListenTcp`/`AcceptTcp` (38, 56, 57) | the three calls a stream needs | two programs on one machine, one listening and one connecting |

5.1 to 5.4 are `net`-only: no syscall, no kernel change, and every test runs on
the host.  That is deliberate, the largest and least certain part of the level
lands before anything in the kernel depends on it.

#### What the level serves with a stated limit

Stated as limits rather than as gaps, because in each case the mechanism is
there and the machine is what is missing.  A later change that removes one of
these is a change to a measurement, and the measurement is in the sentence.

- **All 23 protocol numbers are served, and two of them are served with a
  stated limit.**  `Filter*` (122-125), `Mrt*` (169-174), `Ipsec*` (164-168) and
  `Dccp*` (157-163) each have a mechanism the boot observes end to end: a rule
  either keeps a packet out or it does not, a forwarded frame either leaves the
  card with a spent hop or it does not, an ESP payload either carries no
  plaintext or it does, and a DCCP connection either reaches `Open` or it does
  not.  `TlsConnect` (121) is served as far as this machine allows and **refuses
  with `Unsupported`** after sending its hello, because there is no TLS server
  here to answer it; `net::tls` has the record layer, the key schedule and the
  handshake, and the boot proves both sides of a handshake agree.  No X.509
  parser exists, so a chain is carried opaque.  `docs/status.md` records all
  three limits where the call is.  `TrustAnchorAdd` (194) and
  `TrustAnchorRemove` (195) are served as well, over `net::x509`, which parses a
  real certificate chain, verifies its signatures and matches its names; that is
  13 host tests against DER openssl wrote, and no boot probe, because the chain
  check faults in this tree's ECDSA on aarch64 and that defect is its own
  change.
- **Routing.**  One interface, one address, one gateway.  A routing table is a
  decision for a tree with two networks.
- **DNS beyond the literal.**  `ResolveHostname` (93) can answer from a hosts
  table the boot installs; a resolver that asks a server is a protocol on top of
  the UDP that lands at 5.4, and it is its own step.
- **Any guarantee about the card's message.**  `docs/status.md` records that the
  receive wait has never executed on QEMU's user-mode network, because the reply
  is already in the ring when the doorbell returns.  A stack that blocks on a
  receive is the first caller that could exercise it, and it may still not on
  this machine.

#### IPv6, which is a second family and not a longer address

The level landed IPv4 first and stopped there, and that is where the stack was
when this was written down.  IPv6 is not "IPv4 with sixteen-byte addresses": it
moves the checksum into a pseudo-header, deletes the header sum that IPv4
recomputes at every hop, and, the part that decides whether the thing works at
all, **deletes ARP**.  A MAC address comes from Neighbor Discovery, which is
ICMPv6, so a stack with ICMPv6 echo and no NDP can answer a ping from nowhere
and send to nowhere.

What landed, in the order a packet needs it:

| layer | where | what it does |
|---|---|---|
| the packet | `net/src/internet/ipv6.rs` | the fixed header, the extension-header chain walked to the first consumer, the fragment header reported rather than reassembled, and the forty-byte pseudo-header sum |
| the messages | `net/src/internet/icmpv6.rs` | echo, the error types a sender reacts to, and the four NDP messages, neighbour and router, solicitation and advertisement, with the option walk |
| what is remembered | `net/src/internet/ndp.rs` | a neighbour cache with three states, the duplicate-address check, and the two addresses a host computes rather than asks for |
| the transports | `net/src/transport/udp.rs`, `net/src/transport/tcp/mod.rs`, `net/src/address.rs` | an IPv6 writer and reader each, a **second function** rather than the IPv4 one with a flag, and an address type that carries its family so a socket and a connection can be keyed on either |
| the interface | `kernel/src/net/mod.rs` | a link-local address derived at install, the groups joined, the cache, and a demux branch that walks the chain before it reads a transport |
| the program's view | `AbiInfo`-shaped record in `abi/src/network.rs` | `Ipv6Status` (197), a new number above the frozen boundary, because `NetworkStatus`'s fourteen address bytes are IPv4's |

**Three things this level had to decide, and did:**

- **The IPv6 addresses do not fit `NetworkStatus`, so they get their own
  call.**  Numbers at or below 120 are frozen and their record layouts with
  them; a sixteen-byte address in a record whose address field is four bytes is
  a change to a contract programs were built against.  `Ipv6Status` is 197
  above the boundary, additive by construction, and `NetworkStatus` is
  untouched for the programs that already call it.
- **A zero UDP checksum is refused over IPv6.**  IPv4's zero means "not
  computed"; IPv6 has no such value, so a datagram that arrives with one is a
  datagram to drop rather than sum.
- **The pseudo-header sum is commutative, so it proves the pair and not the
  direction.**  Swapping the source and the destination does not break a
  checksum, the test says so and says why, so a later change that "fixes"
  the pseudo-header's order fails a test that explains the invariant.

**What the boot proves, and what it does not.**  Two exchanges, both through
`demux_ipv6`, the path a frame off the wire takes, and both loopbacks:

```
protofire: ipv6 neighbour answered for fe80:0000:0000:0000:5054:00ff:fe12:3456, peer fe80:0000:0000:0000:5055:0aff:fe00:0202 is 52:55:0a:00:02:02
protofire: ipv6 echo reply to fe80:0000:0000:0000:5055:0aff:fe00:0202, identifier 7, sequence 1, 8 byte(s)
protofire: process 1 asked the ipv6 side, 56 byte(s)
```

The third line is ring 3 reading the record and checking the link-local address
against the MAC it was told about, `fe80::` plus the modified EUI-64, which is
the one fact a program can verify without the wire.

QEMU's user-mode network was **measured and refused** for this: `ipv6=on` makes
slirp stop answering IPv4 ARP, so enabling it costs the boot's four IPv4
exchanges to reach a neighbour that does not answer NDP either.  The
measurement is in `tools/xtask/src/machine.rs` beside the option that is
deliberately absent, so the next reader does not make it again.

**UDP and TCP carry over IPv6.**  The state that could not describe them, a
socket keyed on four bytes, a connection keyed on four bytes, is keyed on
`net::address::Address` now, which carries its family with its bytes, and the
receive path routes `NEXT_UDP` and `NEXT_TCP` as well as `NEXT_ICMPv6`.  Two
lines prove it, on every machine:

```
protofire: ipv6 udp received 10 byte(s) from this machine
protofire: ipv6 tcp echoed 2 byte(s) of 2, round trip
```

Each is a loopback through the demux rather than a claim about code: a
datagram written with an IPv6 address, framed, parsed back and read off the
socket the address names, and a stream that opens, carries, echoes and closes.
The datagram's line names the sender it read out of the record, so a demux
that routed by the wrong address would print the refusal instead.

**The boundary cost no numbers.**  `SendToUdp` (59), `ConnectTcp` (38) and
`RecvFromUdp` (60) all sit below the frozen line and all three had a reserved
word that must be zero.  That word is a flags word now, and its one bit says
the address slot is a pointer to sixteen bytes rather than a packed word.  A
caller passing zero is unchanged, which is what §3.2's "additive *optional*
behaviour" permits in the frozen range; `docs/fmts/syscall-abi.md` states the
reading per call.  A second number per call would have spent
experimental-range numbers to say something the flags word had room for.

**Fragments are reassembled, and a closed port is told.**  Both were
correctness gaps rather than missing features: a fragmented datagram used to be
dropped piece by piece (IPv4 kept no pieces at all; IPv6 refused the fragment
header), and a datagram for a port nothing owned vanished without the
port-unreachable report its sender is owed.

`net::reassembly::Cache` holds the pieces, bounded in every direction a sender
controls, a payload ceiling, an entry count, an expiry on the caller's clock,
and [RFC 5722]'s rule that an overlapping piece takes the whole datagram with
it.  The boot proves it on every machine:

```
protofire: fragments reassembled 20 byte(s), intact
```

The ICMP error path is `net::icmp::write_destination_unreachable`, and its
evidence is a host test rather than a boot line, because a report only goes to
a sender that sent something and this stack's own senders are the loopback:
the test builds the frame the kernel would send and reads the sender's own
ports back out of the quote.  `deliver_udp` answers `Delivery::Unbound` now,
which is the distinction the error needs, "nobody was waiting" and "nobody
owns the port" used to be the same `Ok(0)`.

[RFC 5722]: https://www.rfc-editor.org/rfc/rfc5722

**The machine configures itself.**  Three protocols landed together because
they answer one question, what this machine's network is:

| protocol | what it settles | the line |
|---|---|---|
| DHCP | the IPv4 address, the router, the name server | `dhcp leased 10.0.2.15 from 10.0.2.2, router 10.0.2.2` |
| DNS | a name, asked of the server the lease named | `dns resolved example.com to 104.20.23.154` |
| SLAAC | a global IPv6 address, from a router's prefix | `slaac configured 2001:0db8:…:5054:00ff:fe12:3456` |

Before this the first three numbers were constants in `device.rs`, named
because QEMU's user-mode network happens to use them, so a machine that was not
QEMU's could not join a network at all.

Two of the three are gate lines and the second is not: a CI machine may have no
resolver, and a gate that fails for a reason the tree cannot fix is a gate
nobody relies on.  The name's evidence is the boot's line and the parser's own
tests, which cover a compression pointer that does not point backwards, an
answer for another transaction, and a record whose length is not its type's.

SLAAC was reachable in theory and not in fact: `net/src/internet/ndp.rs` had the prefix
arithmetic and `handle_icmpv6` had no branch for a router advertisement, so no
advertisement could ever reach it.  The branch is the change, and the boot's
probe sends its advertisement through the same receive path a real one takes.

What is **not** here, and is its own step: rebinding, which is the broadcast
any server may answer and which `Lease::duty` names but no caller sends; and
DHCPv6, a different protocol with a different message set.  Congestion control
is no longer on the list: a stream slow-starts, avoids, and retransmits on three
duplicate acknowledgements.  What it still does not do is measure a round trip,
so its timeout is a constant.  Two things came off
this list: out-of-order receive, because a segment ahead of the expected
position is held and delivered in sequence order when the gap closes, and
path-MTU discovery in both families, because a fragmentation-needed or
packet-too-big report now shrinks the stream it quotes, and IPv6's default route,
because a router advertisement is now read for the route as well as the
prefix.  The window is off the
list too: a stream advertises the room it has and refuses a byte past it.

### The rest of the road: rewriting what the previous kernel had

The previous kernel was 301,718 lines across nine module trees; this one is
194,870 across 47 crates.  The difference is not lost work, it is work the new
architecture has to **do again, in its own shape**, and that word is the
important one.

**This is a rewrite, not a migration.**  The two trees do not share an
architecture: the old one was one binary with module trees and a `shared` crate;
this one is 47 crates with a layering a gate enforces, a different error type, a
different syscall dispatch, and a rule that no crate outside `arch/` may name a
machine.  Code carried across unchanged would either fail those gates or, worse,
pass them and leave a layer inverted.  So every row below is read as *"what does
this have to do here"*, with the old module open beside it for its arithmetic
never pasted, and often not recognisable afterwards.

The measurements, taken from `16b5ef8` (the previous kernel's last commit):

| old module | lines | state now |
|---|---|---|
| `arch` | 95,361 | **done**, three ports, trap paths, timers, SMP, ring 3 (20,645 lines here, a third of the size) |
| `fs` | 68,494 | **moved**, PyroFS, tmpfs and the ten Level 6 formats; four of them are readers, which the old tree's were too |
| `kernel` | 39,704 | **mostly done**, scheduler, processes, COW, pipes, signals, memory |
| `network` | 39,240 | **done**, the stack is one tenth of it: IPv4, IPv6, ICMP, ICMPv6, NDP, UDP, TCP, DHCP, DNS, SLAAC and the six protocols below it, with all 43 calls a program reaches |
| `drivers` | 18,828 | **partial**, virtio-blk, virtio-net, the display, the NVMe controller and the AHCI controller; Level 7 states the order, and its first three items have landed |
| `user` | 19,145 | **partial**, three programs; the old shell's body and command set are not here |
| `syscall` | 15,647 | **partial**, 102 of 196 numbers |
| `abi` | 4,725 | **done**, the numbering, the records, the boot information |
| `util` | 574 | folded into the crates that use it |

The nine rows sum to 301,718; the remaining 764 lines are that tree's two root
files, the entry and the library root.

Where it is written down: each of the levels below is one subject, because that
is the unit a commit and a gate can check.  They are ordered by dependency, and
the order is the part that cannot be chosen.

#### The syscall gap is the whole of the old tree's coverage

Measured: the previous kernel's enum held **194** numbers, 0 through 195 with
141 and 142 retired, and **every one of them had a registered handler**.  That
is what "the old tree served everything it declared" means, and it is worth
stating precisely because "served" there was not "works": a handler was allowed
to answer `Error::Unsupported` for a shape it did not implement, and reading the
number's presence as a capability is the mistake this tree's `Handler::Unimplemented`
exists to avoid.

This tree declares **196**, the same 194 plus `WaitProcessOf` (196) and
`Ipv6Status` (197), with the same two retirements, and serves **102** of them.
The other 94 are what the levels below are about.

That single number is the clearest statement of what is left.  The old tree's
15,647-line syscall tree is the work list, and its modules are named by what
answers them, epoll, eventfd, futex, io_uring, message queues, POSIX timers,
ptrace, seccomp, scheduler affinity, TLS, IPsec, multicast routing, the GPU
calls, shared memory, extended attributes, and the network calls.

The gap is not 152 independent pieces of wiring: it is roughly twenty
mechanisms, each of which brings its numbers with it.  A futex is one number and
one mechanism; shared memory is four numbers and one.  That is why the levels
below are named after mechanisms and not after syscall families.

### Level 6, the filesystems

Ten filesystems the old tree has and this one did not: `ext4`, `fat32`,
`exfat`, `ntfs`, `btrfs`, `xfs`, `f2fs`, `erofs`, `squashfs`, and the old
`fuse` client.  **All ten are here.**  This level was about moving them, not
about completing them, and what each one can do is the old tree's answer
carried over and, where a write path was missing, built:

| format | here | what it does |
|---|---|---|
| `ext4` | `fs/src/ext4/` | reads and writes; extent tree, an indirect fallback, and the JBD2 journal replayed and written |
| `f2fs` | `fs/src/f2fs/` | reads and writes; log-structured appends, NAT/SIT caches, two checkpoint copies |
| `xfs` | `fs/src/xfs/` | **read-only**; B+tree extent and directory readers, journal replay, and every mutation refused in its own `FileSystem` impl |
| `fat32` | `fs/src/fat32/` | reads and writes; FAT12 12-bit packing, FSInfo, LFN sets |
| `exfat` | `fs/src/exfat/` | reads and writes; the checksummed boot region, 32-bit FAT plus allocation bitmap, NoFatChain streams |
| `iso9660` | `fs/src/iso9660/` | reads and writes; RFC 0011's whole write path, data, length, space from a block map, records, directories, rename, with path tables rebuilt from the tree |
| `ntfs` | `fs/src/ntfs/` | reads and writes; MFT and attribute lists, index trees split and merged, the cluster bitmap, LZNT1 streams, and a harness judging it against a volume `mkntfs` made |
| `squashfs` | `fs/src/squashfs/` | **read-only**; LZ4 and ZSTD metadata and data blocks, fragments |
| `erofs` | `fs/src/erofs/` | **read-only**; compact inodes, flat block mapping, 16-byte fast symlinks |
| `btrfs` | `fs/src/btrfs/` | **read-only**; superblock, chunk map, checksummed trees |
| `fuse` client | `fs/src/fuse/` | reads and writes through the protocol; each VFS operation is a request, so what it can do is what the program on the other side does |

**The goal was that all ten can write, and four of the formats cannot.**  That
is the honest state and it is recorded here rather than in a footnote: the old
tree's `xfs` answered `PermissionDenied` to every mutation too, its "21 write
operations" were reads over structures a writer would need, and the three
compressed formats, `squashfs`, `erofs` and `btrfs`, have no write path in
either tree.  (The FUSE client is a fifth writer in a different sense: a
mutation is a request to the program on the other side, so its writes are its
server's.)  What the port promised is that the *code* moved and the *evidence*
moved with it; what it did not promise is that a reader becomes a writer by
being ported.  A write path for any of the four is its own RFC.

The three batches this level was ordered by, and where each ended:

| batch | formats | outcome |
|---|---|---|
| **already writable** | `ext4`, `f2fs`, `xfs` | `ext4` and `f2fs` port whole, journal and checkpoint copies included; `xfs` ports as the read-only driver it always was |
| **designed, partly built** | `iso9660`, `ntfs` | both port whole: RFC 0011's write path lands in full, and RFC 0012's fixture comes with NTFS's write path |
| **read-only** | `fat32`, `exfat`, `btrfs`, `squashfs`, `erofs` | `fat32` and `exfat` gained write paths; `btrfs`, `squashfs` and `erofs` port as readers |

`ReadOnlyFileSystem` in `fs/src/filesystem.rs` is the blanket impl a read-only
format gets for free: it supplies every mutation as `PermissionDenied`, so a
view has nowhere to declare one.  It is the right shape for a view over kernel
state; it is the *wrong* final shape for a storage format, which is why
`fat32`, `exfat`, `iso9660` and `ntfs` implement `FileSystem` directly instead
, and why the four that stayed readers say so in their own documentation
rather than hiding behind the blanket.

This was one level and not ten, because they share one thing worth deciding
once: **a filesystem in this tree is a module inside `fs` that implements
`VNode` and `FileSystem`** (`fs/src/filesystem.rs`, `fs/src/vnode.rs`) and
brings its own on-disk parser.  `fs/src/pyrofs/` is the shape, 18 files, its
own `format_io`, `superblock`, `dir_ops`, `file_io`, `tests`, and the ten
ports follow it: `types` for the on-disk shapes, `fs` for the volume's low
level, `vfs` (or `volume`) for the mount, and `tests` for a fixture the test
builds and a second mount reads back through.

What this level did not promise, and does not claim: **compression codecs as a
shared abstraction**, `squashfs`'s LZ4 and ZSTD and `btrfs`'s use of them
belong to their modules until a third user appears; and **a journal for the
formats that need none**.  `ext4`'s journal is the template because it is the
hardest case, not because every filesystem has to grow one.

### Level 7, the drivers

The old tree's `drivers/` was 18,828 lines and this tree has virtio-blk and
virtio-net.  The migration is **six bodies of work plus what the old tree did
not have**, and the order below is by what each one unblocks rather than by
size.

**Landed.**

- **7.1, the flush.**  `VIRTIO_BLK_F_FLUSH` is negotiated, and a flush goes out
  as the two descriptors the specification names.  Found by a Level 2 `Fsync`
  that was served and unusable; see that level for the two defects it turned
  out to be.
- **7.2b, the console.**  A character grid over that framebuffer, and the sink
  that makes a kernel line and a program's line reach it.  `drivers/display/text`
  is the font, the control characters and the scroll, and it names nothing of
  this tree: eighteen host tests drive the grid against a recording surface.
  The kernel's half is the surface that writes pixels and the hook in `arch`'s
  console, which every byte already passes through.
  **It brought two numbers with it**: `WriteDebug` (1), a program's bytes into
  the kernel's own log, and `ReadConsole` (4), served as zero rather than
  `NotImplemented` because this machine has no keyboard driver and "nothing yet"
  is a word a shell can loop on.

  One defect it found in itself, worth keeping: the first version repainted the
  whole screen on every byte, and the boot **stopped inside the network probe**
  because 1024x768 pixels times a few thousand bytes is four hundred million
  framebuffer writes.  A line is the unit a reader sees, so a line is the unit a
  repaint waits for.
- **7.2a, the display.**  `drivers/display/vga` is the bochs-display's register
  block and mode-set sequence, and it names nothing of this tree, so a host
  test drives the whole sequence against an array.  The probe is the kernel's,
  because reaching a BAR is.  The boot finds the device, reads `VBE 0xb0c5`
  back from its `ID` register, sets 1024x768 at 32 bits, and prints the mode the
  **device** reports rather than the one it asked for.

  That is the first time this machine's screen has said anything:
  ```
  protofire: display at 0xfd000000, registers at 0xfeb90000
  protofire: display answered VBE 0xb0c5
  protofire: display mode 1024x768 at 32 bpp, 4096 byte(s) per line
  ```

  One thing this had to correct on the way: the `tlb shootdown` gate line
  asserted an exact count of three, on the argument that the machine's
  remapping is deterministic.  It is, and the count is "how many shared windows
  the boot changed after the second CPU came up", so mapping two display BARs
  made it four.  The number is still exact and the comment now says what it
  counts.

**What is left, in the order it matters:**

1. **The framebuffer console.**  This is the one that changes what the machine
   *is*.  Today a boot has a serial port and nothing else, so every
   demonstration this tree has is a log rather than a screen.  The old tree's
   half is `framebuffer` (199 lines), `framebuffer_protocol` (147) and
   `framebuffer_console` (726), and the split is worth keeping: the protocol is
   a description that compiles everywhere, the probe is the machine's, and the
   console is neither.
   It is first because it is the smallest of the six and because it changes the
   shape of every later demonstration.  It is also the one with a real
   decision: this tree's output goes through `arch::serial`, which 767 call
   sites name, so a console has to be a **second sink beside** that one, not a
   rewrite of it.
2. **`nvme`.**  A modern machine's disk, and what makes a boot from real
   hardware plausible.  The old tree's `nvme` (1,125) and `nvme_protocol` (459)
   split along the line this tree already draws for virtio: the wire format
   compiles everywhere and the controller is the machine's.

   **The format has landed** as `drivers/storage/nvme`: BAR0's registers, the
   two queue entries, and the identify structures, with twenty host tests.  It
   names nothing, so every offset and size is asserted rather than assumed, and
   that is what caught the defect the old tree carried.  Its `IdentifyController`
   was a 99-byte structure whose namespace count sat at offset 95 while NVMe 1.0
   puts `NN` at **516**: the driver read the serial number and called it a
   namespace count.  The old structure declared its fields in a run with no
   regard for the specification's reserved gaps and nothing checked an offset,
   which is why it survived.  This module declares only the fields a driver
   reads, at the offsets the specification names, and the geometry reads the LBA
   format table row the namespace selects instead of answering 512 from a
   constant.  The controller half, mapping BAR0, driving the queues and claiming
   a message, is what is left.

   **Two numbers came with the device list**, as this tree's rule asks when a
   change touches them:

   - `ListBlockDevices` (79), one disk the boot found, by index.  The list is
     `kernel/block_devices`, a fixed array the boot fills as it attaches each
     device: the ABI's index is "which of the devices this boot found", and a
     fixed array makes "the list is full" a state the code names rather than a
     silent drop.  It answers the **devices**, not the filesystems, so a disk
     nobody mounted still has a name and a size.
   - `Sync` (72), every mounted filesystem flushed in one call.  It is the
     whole-machine half of durability where a descriptor's `Fsync` is the
     per-file half, and the mount table grew `sync_all` for it.

   **The controller was attempted and is not finished.**  Admin commands work:
   the controller comes up, `Identify Controller` and `Identify Namespace` both
   answer, and the namespace's size and block size are read from a real device.
   I/O submissions do not: a read or write is put in the submission ring, the
   doorbell is rung, and no completion arrives.  Three specification errors were
   found and fixed on the way, and each is worth recording so the next attempt
   does not rediscover them:

   1. **A queue's base address must be page aligned.**  The first version handed
      the controller addresses from a `Vec`, which has alignment one: the boot
      printed `admin queues at 0xa7d810, 0xa7e830` and the controller answered
      `CSTS = 0x2`, `CFS` -- "I am fatal" -- and never started.  A page-aligned
      allocation fixed it, and `CSTS` is the register that says so.
   2. **A claim that `Create I/O Submission Queue` needs `DW11` bit 1, `EN`,
      was wrong.**  This entry used to say the bit was required, on the evidence
      that setting it made a queue appear to work.  There is no enable bit in
      that command: NVMe 1.0 §5.4 gives `DW11` bit 0 as `PC`, bits 2:1 as
      `QPRIO`, and bits 31:16 as the completion queue id.  Bit 1 is `QPRIO`'s low
      bit, so setting it made the queue *urgent*, and QEMU's `nvme_create_sq`
      validates only `PC` and never reads bits 2:1 at all.  The bit changed
      nothing; the real defect was the doorbell below, and it outlived this fix.
      The builder no longer sets the bit and its host test asserts bits 2:1 are
      zero.  Kept here because a wrong entry that is quietly deleted is one the
      next attempt rediscovers.
   3. **The completion queue's doorbell must be written after the queue is
      created**, telling the controller where the host will start reading.

   What is left is the fourth question: why a submission on an enabled, aligned,
   correctly-belled I/O queue still gets no completion.  The next step is not
   more guessing -- three of those three errors were each found by printing one
   more register -- but QEMU's own NVMe trace, which says what the device did
   with the command rather than what the driver expected.

   **That fourth answer was the doorbell address, and it was wrong here rather
   than in the controller.**  `nvme::doorbell` laid the array out as "every
   submission queue's, then every completion queue's", which puts queue 1's
   submission tail exactly where queue 0's completion head is: the driver rang
   `0x1004` when it meant to submit on queue 1, the controller read that as
   completion queue 0's head advancing -- a completion nobody was waiting for --
   and the command sat in a ring nothing would look at.  A defect that produces
   a timeout and names nothing, which is why three rounds of printing registers
   did not find it.

   NVMe 1.0 §3.1.9 **interleaves** the two:
   `SQ y Tail = 0x1000 + 2y*(4 << DSTRD)`, `CQ y Head = 0x1000 + (2y+1)*(4 <<
   DSTRD)`.  That was checked against two independent implementations rather
   than against one reading of the specification: QEMU dispatches a submission
   doorbell as `(addr - 0x1000) >> 3` and a completion as
   `(addr - 0x1004) >> 3`, and Linux's driver computes
   `q_db = &dbs[qid * 2 * db_stride]` for a submission queue and writes the
   completion head at `q_db + db_stride`.  Both are this formula at `DSTRD`
   zero.

   The helper had taken the queue **count** as its stride on the belief that the
   two groups were laid out one after the other, and its test asserted that
   layout as four literals -- a test that pins a wrong formula is one that makes
   the wrong formula look measured.  The replacement asserts the invariant
   instead: no submission doorbell of any queue in `0..64` equals any completion
   doorbell, and the stride is `CAP`'s own bits 35:32.

   **The controller now completes a read, the namespace is a block device, and
   the namespace is mounted.**  `kernel/src/nvme.rs` finds the function on the
   bus, maps BAR0, resets the controller, points it at an admin pair,
   identifies the controller and the namespace, creates an I/O pair, and wraps
   the namespace in `NvmeBlockDevice`, a device of depth one.
   `kernel/src/volume.rs` mounts that device at `/data` beside the boot's
   three, and the boot's evidence is the lines each step answers:

   ```
   protofire: nvme capability 0x4008200f0107ff, version 1024, queues up to 2048 entr(ies), stride 0
   protofire: nvme namespace 1, 32768 block(s) of 512 byte(s)
   protofire: nvme I/O queue pair up, 64 entr(ies)
   protofire: nvme0n1 far block answers PFNVME01
   protofire: nvme0n1 wrote and read back sector 32766
   protofire: nvme0n1 recorded as block device 0
   protofire: namespace: pyrofs on / (protofire), tmpfs on /tmp (memory), iso9660 on /cdrom (bootdisc), pyrofs on /data (nvme0n1)
   protofire: /data/note.txt reads back over nvme
   ```

   The fourth line reads bytes **only the host wrote** -- the disk's far block
   says `PFNVME01` because `xtask` put it there before the machine ran, at the
   far end because block zero of a filesystem is its superblock, so no part of
   this boot could have satisfied it.  The fifth is the write path, through the
   block interface a filesystem will use rather than through a raw command, so
   the code that is proven is the code a caller runs.  The last is the end the
   whole path exists for: a file the host wrote, read back through the mount
   table, where no part of the boot could have written it.  All are required
   lines of the x86_64 gate, and only x86_64's: `q35` carries an `nvme`
   function and the other two machines' trees describe a bus this controller is
   not on.

   Every transfer rides one page-aligned frame the controller owns, because a
   caller's buffer is neither page-aligned nor inside one page and this driver's
   PRP arithmetic is `PRP1` alone.  A namespace whose blocks are bigger than the
   frame is refused at probe rather than driven badly.

   The controller is brought up **before** the mount, because a namespace
   mounted over it has to find the device already there; and a second volume
   that fails to open is skipped rather than fatal, because the boot volume is
   the one a machine cannot boot without and the second disk is a machine fact
   the host may have left empty.  The volume mounts as the table's fourth
   entry, which makes this boot the first with two disks: the device list
   answers two, and init's exercise reads the second record from ring 3
   (`process 1 listed block device 1`), where it used to assert that a second
   device must be refused.

   The record's layout had a defect of its own to avoid: `#[repr(C)]` pads the
   three 64-bit words to the name field's **aligned** end, which for a 63-byte
   name is offset 64 and not 63.  A handler that added 63 would put every word
   one byte early and no field would read as the number it was given, so the
   offsets come from the type's own layout rather than from the field order.
3. **`ahci`.**  Worth stating precisely, because the roadmap used to imply it
   was a driver crate like the others: **the old tree had no `drivers/ahci`.**
   Its AHCI driver was 1,085 lines inside the x86_64 architecture crate (its
   ATA PIO sibling 1,144 beside it), which is exactly the inversion this
   tree's `check-arch-fanout` refuses.  So the work was not a port but a
   **relocation**, and it has landed: the specification's half is
   `drivers/storage/ahci` at layer 0, twenty-four host tests asserting the
   offsets, the structures and the identify parse; the machine's half is
   `kernel/src/ahci.rs`, which finds the controller, finds the port the disk
   is on, starts the engine, and drives the disk as a block device.  The
   boot's evidence, all required lines of the x86_64 gate:

   ```
   protofire: ahci at 0xfebda000, 4096 byte(s)
   protofire: ahci ports implemented 0x3f
   protofire: ahci disk on port 0
   protofire: ahci port 0, 65536 block(s) of 512 byte(s), model QEMU HARDDISK
   protofire: ahci0 far block answers PFATAH01
   protofire: ahci0 wrote and read back sector 65534
   protofire: ahci0 recorded as block device 1
   ```

   The far block and the round trip are the same two proofs the NVMe device
   makes, and for the same reasons: the magic is bytes only the host wrote,
   and the round trip is the write path through the interface a filesystem
   will use.  The disk is a third one, 32 MiB against NVMe's 16, so the two
   identify lines cannot be confused.

   The relocation corrected three defects the old driver carried, each one a
   reason it had never executed a command:

   - The command header's `CFL` was left zero, and a controller is entitled
     to refuse that: QEMU's `handle_cmd` rejects a length below two dwords
     with no message a driver reads.
   - The command table's address sat in the header's fourth and fifth dwords
     where the layout has it at the third and fourth; the controller then
     took its command table from bytes 8 to 15 -- zeros -- which is physical
     address zero, the interrupt vector table.  QEMU's trace printed the
     vector table as the command it was asked to run, and that dump settled
     the layout for both the old tree and this crate's first builder.
   - The write FIS set byte 1's bit 6 "for a write", where the layout has
     only `C` at bit 7 and **reserved** at bits 6:4.  QEMU's controller
     checks the reserved mask and drops the FIS without executing it -- the
     same silence a wrong doorbell produces, and this time the dump that
     found the address was already in place before it mattered.

   The port itself was never found in the old driver: it hardcoded port zero
   with a comment promising to find the real one later.  This one reads `PI`,
   walks the implemented ports, and takes the first whose `PxSSTS.DET` reads
   three, because present-but-dead and absent are two states a driver that
   only checked "non-zero" would send IDENTIFY into.

   The devices past the first are now three, and init's exercise walks them:
   it lists past the first until the table refuses, and every record named on
   the way must be as well-formed as the first.
4. **`xhci`** and USB HID/MSD.  The largest of the six by far, the old tree's
   at 3,451 + 1,177 + 642 + 545.  A keyboard, a mouse and a stick.

   **It has landed**, in two rounds: the wire format as `drivers/usb/xhci` at
   layer 0 with twenty-four host tests, and the machine's half as four kernel
   files -- the controller, `usb_hid`, `usb_msd` and `usb_mouse`.  The boot
   enumerates the bus, finds a mass-storage device and a keyboard, moves a real
   SCSI exchange (INQUIRY, a capacity read, a sector read) over the bulk
   endpoints, records the disk as a third block device, and reads the
   keyboard's interrupt endpoint into a report whose bytes are a PS/2 Set 1
   scancode.  Its evidence, all required lines of the x86_64 gate:

   ```
   [xhci  ] controller initialised and running
   [xhci  ] mass storage initialised at slot 1
   [usbmsd] INQUIRY: vendor='QEMU' product='QEMU HARDDISK'
   [usbmsd] USB mass storage: 16384 blocks x 512 bytes = 8 MiB
   [usbmsd] recorded as block device 2
   [xhci  ] HID keyboard ready at slot 2
   [hid  ] keyboard report: modifiers=0x00 keys=[04,00,00,00,00,00]
   ```

   The `[hid  ]` line is a key the host typed: `xtask` writes `sendkey a` to
   QEMU's monitor once the boot is past its `ReadConsole` exercise, and `04` is
   the HID usage for `a`, which the report prints as the device sent it.

   Three defects the relocation had to fix, each one a reason the old tree's
   controller never enumerated anything:

   - The controller's MMIO base was mapped a second time: the bus scan had
     already mapped it, and `map_device` answers false for a window it holds,
     so the bring-up took the failure and skipped the controller entirely.
   - Every log line was written with `write!` where the sink needed a newline,
     so sixty-seven fragments arrived as one line and three gate lines matched
     nothing.  The macro writes a whole line now.
   - The keyboard's `Interval` field is the **exponent** of the period, not the
     period, so a report interval of 8 became 256 frames; and a hub port reset
     is `PORTSC`'s selector 4 with the change bit 20, where clearing bit 21
     stalls the port rather than acknowledging the reset.
5. **`virtio_gpu`** and **`virtio_input`.**  The same two devices on the
   emulator this tree is developed on, which is the cheaper way to prove the
   input path before the USB one.  They come after the framebuffer console
   because that console is what they draw into.

   **Both have landed.**  The input device is `drivers/virtio/input` at layer
   7: one event queue whose buffers
   the driver keeps posted, the eight-byte event the specification defines
   (`type: le16`, `code: le16`, `value: le32`), and a `drain` that hands the
   caller the event rather than a meaning.  What an evdev code means to a
   console is this boot's decision, so `kernel/src/virtio_input.rs` is the file
   that translates, through the same table `usb_hid` already carries.  Its
   evidence, required lines of the x86_64 gate:

   ```
   protofire: virtio-input up, event queue posted
   [vioin] device event: kind=1, code=48, value=1
   ```

   The two keyboards are typed through two channels because QEMU's input layer
   delivers a key to **one** handler, not to every device that takes input:
   `qemu_input_find_handler` walks its list and returns the first match, and
   `qemu_input_event_send_impl` calls exactly that one.  Measured, adding this
   device made the USB keyboard's `[hid  ]` line vanish while the virtio one's
   arrived, which is the unicast seen from the other side.  So the virtio
   keyboard is bound to a console of its own (`VGA,id=disp0`, with `-vga none`
   so the machine still has exactly one display for the kernel's probe), the
   monitor's `sendkey` -- which names no console and reaches the USB keyboard
   -- types to that one, and QMP's `input-send-event` names this console and
   reaches the virtio one.  `input-send-event`'s `device` argument is a
   **console** and not a device: a version that passed a keyboard's id made
   QEMU abort with `Property 'qemu-fixed-text-console.device' not found`.

   The GPU is `drivers/display/virtio_gpu` at layer 0, holding the wire format
   and nothing else: the 24-byte control header, the command and response
   numbers, the 2D bodies, the 3D bodies, and the display-info answer.  The
   machine's half is `kernel/src/virtio_gpu.rs`, which finds the function,
   walks the status sequence, posts control commands, owns a page-aligned
   backing for the scanout, and paints and presents a band.  Its evidence,
   required lines of the x86_64 gate:

   ```
   protofire: virtio-gpu display 1280x800 at 0,0, resource 1 on scanout 0
   protofire: virtio-gpu scanout 1280x800, 16 row(s) of 0x2080e0 presented
   ```

   **The screen is checked from outside the guest**, and that half is the
   point.  A serial line is the driver's claim; a screendump is the host's
   image of the scanout, and only it can say a pixel reached a display.  So the
   gate asks QEMU for one over QMP once the presented line appears, parses the
   PPM, and requires that every pixel of the band's sixteen rows is the colour
   the boot named and that row sixteen is not.  Both halves were measured to
   fail on their own: a changed colour fails the serial line, and a gate that
   expected twelve rows where the guest painted sixteen failed with
   `the band runs past its 12 rows; the pixel at row 12 reads [32, 128, 224]`,
   which is the real pixel the device was showing.

   Six wire errors the previous tree carried, every one of them a reason its
   3D path could never have worked, and all six caught by this crate's host
   tests before a boot:

   - `CTX_CREATE` was `0x0201` where the specification's enum makes it
     `0x0200`, and `CTX_DESTROY` was `0x0202` where it is `0x0201`: the two
     were each one past where they belong.
   - `SUBMIT_3D` was `0x0208` where it is `0x0207`, the first number past the
     3D group's last member.
   - `RESOURCE_CREATE_3D` named its last three words `levels`, `num_samples`
     and `stride` where the specification has `last_level`, `nr_samples` and
     `flags`, and dropped the padding word the struct ends with.
   - `TRANSFER_HOST_3D` put `resource_id` first, after the header, where the
     layout has a box of six words, then a 64-bit offset, and only then the
     resource id -- so the device read the box's `x` as a resource.
   - `RESOURCE_CREATE_2D` and `RESOURCE_FLUSH` were sized from a reader's
     count of their words rather than from their structs, so both bodies were
     one field short.
   - `TRANSFER_TO_HOST_2D` declared its `resource_id` before the offset and
     the rectangle, which makes QEMU answer `RESP_ERR_INVALID_RESOURCE_ID` --
     a message that names the wrong field.

   What this round deliberately does not land is the nine GPU syscalls
   (`181..=189`, VIRGL 3D): they need a guest-owned resource table, a DMA
   mapping path from a user buffer, and a host with OpenGL for the emulator to
   offer `VIRTIO_GPU_F_VIRGL` at all.  This machine's `virtio-gpu-pci` reports
   no VIRGL, and `virtio-gpu-gl-pci` refuses to start without an OpenGL display
   backend, so a syscall with a device behind it is the change that needs a
   machine this host can configure rather than a driver this tree can write.
6. **`pcspkr`**, last: one line of value, and it needs a timer nobody has
   asked for.

   **It has landed**, as `kernel/src/pcspkr.rs`: PIT channel 2 in mode 3 off
   the fixed 1.193182 MHz clock, and port 0x61's low two bits opening the PIT
   gate and the speaker's own.  The boot plays 1000 Hz and silences it, and
   `protofire: pcspkr played 1000 Hz, then silenced` is a required line of the
   x86_64 gate.  What a serial line cannot carry is what a listener hears, so
   the out-of-band check is QEMU's traces: the command word `0xB6`, the divisor
   `0xa9`/`0x04` -- 1193, which is 1000 Hz -- and a gate transition on 0x61,
   landing on the hardware the specification names.

**What the old tree had and this list does not:** `hda` (857 lines) and its
protocol (751).  It is not on the list because nothing in this tree has a
caller for audio, and `sound` is a crate with no code.  It is the one place
this level does not aim at parity, and the reason is stated here rather than
left as an omission.

What this level does not promise: a driver *framework*.  `block`'s two traits
are the only abstraction this tree has and they are enough for a disk; a
display and an input device do not obviously want the same shape, and inventing
one before the second driver exists is how a framework becomes a constraint.
The framebuffer console is the first place that question gets asked for real,
and the answer it gives is the one the later drivers inherit.

### Level 8, the mechanisms the numbers name

The syscall gap restated as work: roughly twenty mechanisms, ordered by what
each unblocks rather than by size.

1. **Descriptors and the file interface.  Done.**  `Dup`, `Dup2`, `Fcntl`,
   `Poll`, `SetFdFlags`, `SetXattr`, `GetXattr`, `ListXattr`, `RemoveXattr`,
   `SetFileFlags`, `GetFileFlags`, `AccessQuery`, `AccessQueryAt`,
   `AccessQueryFd`, `PermissionMetadata`, `PermissionMetadataAt` and
   `PermissionMetadataFd` are all served.  These were the leftover of Level 2
   and the cheapest row on this page: the filesystem already implemented every
   operation.

   **`Dup` and `Dup2` have landed**, and they were the two on this row that
   needed something no filesystem has: a second **handle** on one thing.
   `Descriptor::for_owner` already existed for `fork`, and a duplicate is the
   same operation on the table with a different owner, so the change was two
   table methods and two handlers rather than a new mechanism.  The two calls
   differ in exactly the ways that matter: `Dup` answers the lowest free slot,
   `Dup2` places the copy on a number the caller names and closes what that
   number held first, and `Dup2` onto its own source answers the source and
   changes nothing.

   The evidence is two exact gate lines, `duplicated descriptor 6 as 7` and
   `placed descriptor 6 on 12`, and both are exact rather than prefixes because
   `as 6` is what a duplicate that answered its source would print.  Measured,
   that defect made the boot stop: the program's own `duplicate == held` check
   exited 251 before the lines after it could run.

   **`Fcntl` has landed too**, as one number carrying seven commands.  Three
   of them needed state this tree did not have in a descriptor: `F_GETFL`
   reports the descriptor's access mode beside the node's non-blocking bit,
   `F_SETFL` writes that bit, and the two pipe-capacity commands read and resize
   the ring `kernel/src/pipe.rs` owns -- which is why ``F_GETPIPE_SZ`` answers
   from the pipe and not from a `VNode`, whose `pipe_capacity` exists for
   filesystems that model a pipe as a file and which no filesystem here
   overrides.  `F_GETFD` and `F_SETFD` are served as "this build has no
   per-descriptor flags": `FD_CLOEXEC` is about what an `exec` closes, and this
   tree's `exec` replaces the image and keeps every descriptor, so accepting the
   bit would record a promise nothing keeps.

   **The four extended-attribute calls have landed**, and the shape they
   needed is `fs_abi::XattrEntryRecord`: a fixed header with the name's and the
   value's lengths and offsets, then the variable bytes, with both offsets
   measured from the record's own start so a caller can walk a buffer it did not
   write.  It mirrors `DirectoryEntryRecord` deliberately.  Every filesystem that
   has extended attributes already implemented them, so what this change added
   is the encoding and the three branches over a path, plus the one branch that
   names two user buffers.

   **The six access and permission calls have landed**, in both forms: three
   that read a path's owner and mode, and three that ask whether the caller may
   do something with it.  The reads were wiring.  The queries needed one new
   thing, `SecurityToken::for_mac_type`, because the dispatcher carries a MAC
   label and not a full identity, and the token that label builds must not be a
   kernel one: a kernel token bypasses the discretionary check, and an access
   query computed from one answers "allowed" for every file in the tree.

   **`Poll` and `SetFdFlags` landed last**, and together for the reason the
   paragraph that stood here gave: both needed a wire format, and `SetFdFlags`
   overlaps `Fcntl`'s `F_SETFD` closely enough that deciding them apart would
   have decided the same thing twice.  `Poll` took `PollFd`, eight bytes of
   `fd`, `events` and `revents`, four event bits, and a readiness question
   answered from the table: a file is always ready, a pipe answers from its
   ends and its writer count, and everything else answers `POLL_ERR`.  It does
   not block, because parking needs the scheduler and the handler holds the
   registry's lock, which the handler's own comment states rather than implies.
   `SetFdFlags` gave `FD_CLOEXEC` a place to live, a parallel
   `[u8; MAX_DESCRIPTORS]` array beside the table's slots, and `exec` closes
   what it marks, which is the promise `F_SETFD` had been refusing to make.
   Three exact gate lines carry the evidence, `set descriptor 6 flags to 1`,
   `to 0` and `polled 1 descriptor(s), 1 ready`.
2. **Shared memory**, `ShmGet`, `ShmAt`, `ShmDt`, `ShmCtl`.  Two processes
   naming one region, which is a decision about the address space and not
   wiring.
3. **Synchronisation**, `Futex`.  One number, and the wrong shape for a kernel
   with a scheduler that already parks.
4. **Timers and notifications**, `TimerFd`, `SignalFd`, `EventFd`,
   `TimerCreate`, `TimerSetTime`, `TimerGetTime`, `TimerDelete`.
5. **Multiplexing**, `EpollCreate`, `EpollCtl`, `EpollWait`.
6. **Message queues**, `MqOpen`, `MqClose`, `MqSend`, `MqReceive`, `MqNotify`,
   `MqUnlink`.
7. **Identity**, `GetUid`, `GetGid`, `AddUser`, `RemoveUser`,
   `SetUserPassword`, `SetSecurityDescriptor`.  `security` has the types and
   nothing has asked them.
8. **Introspection**, `ListProcesses`, `ListThreads`, `ListProcessFaults`,
   `KernelLog`, `Prctl`, `Ptrace`, `Seccomp`, `SchedSetAffinity`,
   `SchedGetAffinity`.
9. **The app's own calls**, `ArgCount`, `ArgValue`, `EnvCount`, `EnvValue`,
   `CurrentDir`, `SetCurrentDir`, `AppId`, `AppVersion`, `ImagePath`,
   `ManifestPath`, `Yield`, `ListBlockDevices`, `ListMounts`, `Mount`,
   `Umount`, `RepairVolume`, `FuseMount`, `Sync`, `RestartSyscall`,
   `CompactMemory`, `Mlock`, `Munlock`, `Madvise`.  `WriteDebug` and
   `ReadConsole` were on this row and came off it with Level 7's console.
10. **io_uring**, `IoUringSetup`, `IoUringEnter`.  Last because it is a second
    way to do what every call above already does, and nothing needs it.
11. **Power, audit, the policy's path rule, the service table and packages**,
    `CpufreqGet`, `CpufreqSet`, `CpufreqGetRange`, `CpufreqSetGovernor`,
    `CpufreqGetTemp`, `AuditSetEnable`, `AuditReadLog`, `MacSetPathType`,
    `ServiceDeclare`, `ServiceStartAll`, `InstallPackage`.  Seven of these were
    not on this list at all until it was re-taken against the enum, which is
    the drift the census command above exists to catch.  `power` and `audit`
    both have their mechanism; `ServiceDeclare` and `ServiceStartAll` are the
    two numbers the parked service table would need (`docs/status.md` records
    why that direction is unscheduled), and `InstallPackage` names a package
    format this tree does not have.

The network is no longer on this list.  It was item 11, `ResolveHostname`
beyond a hosts table, `TlsConnect`, `Ipsec*`, `Mrt*`, `Filter*`, `Dccp*`; all
43 of the level's numbers are served, so the row is gone rather than shrunk.

What this level does not promise: **the GPU calls**, all nine of them,
`GpuCtxCreate`, `GpuCtxDestroy`, `GpuDeviceInfo`, `GpuResCreate3d`,
`GpuResUnref`, `GpuSetScanout`, `GpuSubmit3d`, `GpuTransferFromHost3d` and
`GpuTransferToHost3d`.  They describe a VIRGL context, which is a device this
tree does not have and a protocol above it, and they belong with Level 7's
`virtio_gpu` if that ever lands, not here.  They are named one by one because
"and its eight siblings" is what let them fall off this list the first time.

### Level 7.5, the defects a contributor found

A contributor read this tree and reported five kernel defects and three
engineering ones.  All of them were real, and every one was a case the gates
could not see: the boot is short, the programs are this tree's own, and nothing
in it ever passed the kernel a pointer, an ELF or a fault it did not mean.  They
are recorded here with their evidence and with what closed each one, in the
order they landed: by what a program could do with them rather than by how hard
they were to fix.

Every one is fixed except the retired-space bound, and that is not a defect but
a decision this file now argues: the array is deliberate and documented at the
field.  The rule this level leaves behind is the one its last item states: a
test that fails without the fix is the only thing that makes a green gate mean
the defect is gone.

**1. A user pointer's *value* is checked and its *mapping* is not.  P0.
Fixed.**

`address_space::is_user_range` was the whole validation most call sites did, and
its own doc comment said what it did not check: "what it does **not** check is
that the pages are mapped".  Then `copy_user_path` and the `from_raw_parts`
calls below it dereferenced the address.  A program that passed a number inside
the window and outside its mappings faulted **in the kernel**, and
`interrupts::handle` has no kernel-mode arm: it tried the write fault as
copy-on-write, then `describe_fault`, then answered `false` and the machine
stopped.

The fix took the first of the two shapes named here.  `address_space::user_range`
keeps the window arithmetic and then walks **the running task's own root** one
page at a time, through `table::range_allowed`, which shares the leaf walk with
`permissions_of` so the validator and the fault handler cannot disagree about a
page.  A write is admitted on a page the table marks writable **and** on one the
pool marks copy-on-write, because refusing the second would break every program
that forked, whose pages are read-only in the table by design.  Every
buffer-taking call site now goes through it, including the two `copy_user_*`
helpers, and `copy_user_path` grew a `checked_add` because the loop's own
`path_ptr + length` was the second unchecked addition in the same file.

The evidence, and it is two-sided.  `/bin/init` calls `open` with an address one
page past its own mapping: the boot prints
`protofire: refused a pointer to an unmapped page at 0x8080000000, for a read`
and the program asserts the answer is `InvalidArgument` (exit 232 on anything
else; it exits 116, the greeting's first byte).  With the walk short-circuited
the same boot takes **1,737** `fault at 0x8080000000, read, not mapped` lines at
`rip 0x136534` and never reaches its exit.  The gate requires the refusal line on
all three machines, so a boot that stops walking the root fails there.

**2. W^X is declared and bypassed in two places.  P0.  Fixed.**

`SECURITY.md` states that a segment both writable and executable is refused,
and `loader::checked` does refuse it.  Three paths re-opened it afterwards.

`AddressSpace::map` took a `writable` flag and hardcoded `executable: true`,
and the fork path called `child.map(va, phys, false)` for every page, so a
child's data and stack were executable.  The copy-on-write resolver widened with
`Permissions { writable: true, ..entry.permissions }`, which keeps `executable`.
And `build_image_space` merged two segments sharing a page with `|=` on both
bits, which is exactly the pair the loader refuses arrived at from two legal
segments.

The fix removes the place a wrapper could invent a permission.  `map` now takes
a `Permissions` and each of its callers states what it means: the loaded image's
page is read-execute, its stack read-write, and the boot's own two pages the
same pair.  `MappedPage` grew an `executable` field so a fork can carry the
parent's permissions across with one change, the demotion, instead of
re-deriving them from a boolean; the resolver refuses a page that would end up
writable and executable rather than quietly promoting it; and the segment merge
refuses the image whose shared page needs both.  `map_user_page` was a fourth
path: a `pub` helper with no callers at all, mapping into the kernel's own root
with both bits set.  It is deleted rather than fixed, because a function no gate
can reach is not a function.

The evidence is a measurement, and it took two attempts.  The first version
counted the **child's** pages after the fork, which reads zero by construction
because the fork has just demoted them all read-only; a probe that put the
hardcoded execute bit back still read zero, which is what a probe reading zero
information looks like.  The line that means something counts the **parent's**
pages before the fork:
`protofire: the parent has 0 writable-executable page(s)`, printed on every
fork, and with the probe restoring the old stack mapping the same line read `1`.
The gate requires the zero on all three machines.  A host test pins the count's
conjunction, so a counter that tested either bit alone fails without a boot.

**3. A fault handler is never withdrawn, so it can re-enter for ever.  P1.
Fixed.**

`install_exception_handler`'s doc comment said a handler that faults is
"withdrawn, so the second fault kills it instead of looping".
`hand_the_fault_to_the_program` read `task.handler` and never wrote it back, so
the second fault re-entered the handler, and a handler whose own address was
unmapped looped until the stack ran out, printing one `handled its own fault`
line per level.

The read is now a `take`.  One lock acquisition answers "was a handler
installed" and clears it, because those are one decision and two acquisitions
would leave a window in which two CPUs both answered "yes" to the same handler.
Taking it is not a latch: a program that survives a fault through
`ReturnFromException` can arm another, which is why there are two host tests and
not one, and the second test exists to fail a version that set a "has faulted"
flag instead.  The boot's own handler still runs: `process 3 handled its own
fault at 0x80c0000000 (vector 14)` appears once, as it did before.

**4. The ELF loader has unchecked additions.  P1.  Fixed.**

`loader::checked` bounded a segment with `segment.file_offset + segment.file_size
> bytes.len()`, and the dynamic-section check with `p_offset + p_filesz <= end`.
Neither used `checked_add`, and the comment beside the first claimed the window
check was also the overflow check.  It was not: `is_user_range` covers
`vaddr + memsz`, and these two sums are file offsets, which the file chooses.  A
program that wrote a shaped ELF into the filesystem and called `ExecProcess`
overflowsed the debug build's bounds check, a panic in the kernel, and could
wrap past the range test in the release one.

Both sums are `checked_add` now, and the header walk's `e_phoff + header *
size` is too.  The paragraph beside the remaining plain additions (`pages`,
`overlaps`, the entry range, the dynamic containment test's `segment.file_offset
+ segment.file_size`) says what they rest on: `checked` admitted the segment, and
its window test is what proves `vaddr + memsz` did not wrap, so those four run
on numbers that already passed.  A caller that built a `Segment` some other way
would not get that guarantee, which is the reason the paragraph exists.

The tests found their own first version wrong twice, and both are worth the
space.  A segment naming `u64::MAX` as its file offset is refused by the **page
congruence** test, before the sum is reached, so a probe replacing `checked_add`
with `wrapping_add` still passed; the offset has to be congruent to the virtual
address for the sum to be what refuses it.  And a dynamic header naming
`u64::MAX` is refused by the containment test whether the sum is checked or not;
the pair has to be one whose **wrapped** sum lands inside the segment, so that
the containment test reads the wrap as yes.  Both tests now do that, and a probe
returned `Ok(Image)` under each before the fix was restored.

**5. Process lifecycle does not reset between images.  P1.  Half fixed.**

`exec_current` replaced `space` and `context` and nothing else: `handler`, the
signal mask, the pending-signal ring, the per-signal handlers and a delivery
mid-flight all survived into the new image, so a program inherited the previous
image's fault handler and undelivered signals.  A space and a context are only
half of what a process is, and the other half belonged to the image being
replaced.

`Task::clear_image_state` clears the six fields now, and `exec_current` calls it
after the space is swapped.  What it does **not** clear is stated at the method:
the pid and parent, because the process is the same one afterwards; the
descriptors, because `close_on_exec` closes the marked ones under its own rule;
and `last_cpu`, because that is the scheduler's record of the *task* and not the
program's.  Two host tests pin it, one setting every field and asserting none
survives, the other asserting the clear can be repeated in case an exec is
retried.

**The retired-space array is still the leak it was, and deliberately so.**  Its
documentation says what it is: `exec` runs with the scheduler's lock held, and
growing a `Vec` there would allocate from the kernel heap while another CPU may
be spinning on that lock, so the array is fixed and a boot that execs more than
eight times keeps the last ones alive.  That is a bound this tree chose, not a
defect it overlooked, and changing it means re-arguing *when* a retired root may
be freed, which is the address-space activation path.  The shape that would work
is a release after `shootdown::invalidate_others()`, but an acknowledgement
proves the *TLB* was flushed and not that another CPU is out of its trap path,
and the boot's own log shows tasks migrating.  Nothing in this tree execs eight
times: the boot execs once.  This moves to Level 9, where a shell that runs
commands makes repeated exec real and makes the argument testable.

**The engineering problems, which are not kernel defects and are not smaller.**

- **`cargo --offline` cannot work on a fresh clone.  Fixed.**  There was no
  `vendor/`, and 25 of the lockfile's packages come from the registry, so the
  gates' `--offline` passed on a machine whose `~/.cargo` cache was warm and
  failed on one that had never built this tree: `attempting to make an HTTP
  request, but --offline was specified`, at the first resolve.  The tree now
  carries `vendor/` (27 MiB, 25 crate sources) and `.cargo/config.toml` replaces
  `crates.io` with it, which is verified the way the finding was made: with
  `CARGO_HOME` pointed at an empty directory and no network, `cargo metadata
  --offline` resolves and `cargo build --offline --workspace` builds.

  The `.gitignore` found this one, and that is worth recording.  `.*` hides
  every dotfile, `cargo vendor` writes `.cargo-checksum.json` beside every
  crate, and the vendor directory was untracked, so `git add -A` would have
  committed 953 files that did not include any checksum; `cargo` then refuses
  the sources it cannot verify, and the directory would have been present and
  useless.  `check-ignored-files.sh` names exactly this case in its own header.
- **Two documents had drifted, and `check-docs.sh` cannot see it.  Fixed.**
  `kernel/src/syscall/mod.rs` said "Thirty-one numbers" where the boot
  registers 88, and this file said "147,731 lines of Rust across 40 crates"
  where the workspace has 47.  Both were corrected when the finding landed.  The
  finding itself stands and is not repaired by correcting two numbers: the gate
  checks that a cited **path** exists, which is a different claim from a number
  in prose being true, so "the docs gate passed" is still not evidence that a
  document is accurate.  The census in this file carries the command that
  re-takes it, which is the answer available.
- **The gates run only what this tree wrote, and that is what let all five
  defects through.**  Each fix above carries a test or a boot line that fails
  without it, which is the repair for the five.  What is not repaired is the
  class: a program handing the kernel a bad pointer, a shaped ELF or a fault
  handler that faults was not something any gate exercised, and the tests added
  here are host tests and one boot probe rather than a fuzz or a hostile-program
  suite.  That suite is the durable answer, it needs a way to build a program
  this tree does not ship, and it is the one item on this level with no commit
  behind it.

The order they landed is the order they were listed: 1 and 2 first, because they
turned a program's mistake into a kernel stop and into a page a program could
rewrite; then 3 and 4, which were each a loop or a panic from one syscall's
worth of input; then 5, which was a channel between two images rather than a
fault.  The offline build was separate and did not wait for any of them, which
is why it is the commit after all five.

### Level 9, the programs

The old tree's shell was 2,639 lines and its command set 528 more, across
`env`, `gpu`, `network`, `process` and `user`.  This tree's shell reads the
greeting and announces itself, which is the smallest program whose exit status
proves the kernel loaded and ran a second image.

What this level is: a shell a person can use.  It needs the mechanisms above
a console to read from, a command set to run, an environment to read, so it is
last by dependency and not by importance.  `service_manager` grows a body in the
same level, because supervising is the other half of what a program with the
process calls can do.

### Level 10, the device model, and what "everything is a service" would mean

**Deliberately last.**  A handle a program can give away is a design decision
about what a descriptor *is*, and making it before the filesystems, the drivers
and the mechanisms have landed would decide it against an incomplete set of
things a descriptor has to name.  It is also the one level whose *size* is small
and whose *consequence* is large: `abi` would grow a wire record and a
numbering, `kernel` the transfer itself and nothing about what is transferred,
and everything above it, what a service is and how it is found, is user space.
That is tens of lines of kernel and an architecture of user space, which is why
building it now would decide a descriptor's third variant against one service
and no device.

Every other level on this page is code.  This one is a decision.  Today a
`Descriptor` is a `File` or a `Pipe`, both of which are things the kernel
implements; a service handle is a third thing the kernel only has to *route*.

What the level would have to decide, in the order the decisions depend:

1. **What a handle names.**  A service, a capability, or a right over an object
   the kernel already has.  `rights` is a crate with two constants and no
   consumer; it was put at layer 0 for exactly this, and this is the change that
   would give it one.
2. **How a handle crosses a process boundary.**  The same call that makes
   `Fork` copy descriptors is the one that would have to *transfer* one, and the
   difference between copying and transferring is what `Descriptor::for_owner`
   is written by hand to get right today.
3. **What the kernel guarantees about a handle it did not create.**  This is the
   part that decides whether the tree stays a monolithic kernel or grows a
   distributed one.  `docs/async_io.md` argues the position: the kernel supplies
   mechanism, a name-to-service table and a submit/complete queue, and the
   *policy* of what services exist stays in user space, where a service that
   crashes can be restarted.  A kernel that grew "discovery", "migration" and
   "shared state" of its own would be the bloat the same document warns about
   every device type adds kernel code, and the set of device types has no bound.

So the intended shape of Level 10 is **not** a distributed bus in the kernel.
It is: `abi` grows wire records and a numbering for capability transfer;
`kernel` grows the transfer itself and nothing about what is transferred;
the kernel's service table gains its first real consumer; `apps/service_manager` grows a
body.  Whether a *distributed* layer ever exists on top of that is a later
question, and the test of whether it can is whether `abi`'s records are stable
enough that two implementations of them can talk, which is the same test the
syscall numbering already passes.

**Nothing in Level 10 is scheduled, and no work on the service layer should
start before the four questions above are answered in writing.**  The levels
before it do not depend on it; it is listed last because it is the only one
whose first step is a decision rather than a file.

### In parallel, the drivers

`e1000` and `sound` are 7-line placeholders.  `virt` is not: it is a 61-line
header that states the guest/host question and which half comes first, and it
has no code because nothing has needed one.  None of the three blocks a level
above; each is an independent piece of work with its own gate line.

---

## What this file is not

Not a schedule.  Not a claim that the levels are the only order, a driver could
come first, or the filesystem interface before memory if `Write` were wired to a
buffered file.  It is the order the dependencies impose, which is the part that
cannot be chosen.

Not a census.  When a level lands, its line moves to `docs/status.md` with the
boot line that proves it, and this file loses the entry, the same rule
`docs/status.md` states about itself, one document over.
