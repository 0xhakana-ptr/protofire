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
# Which syscall numbers have a handler
grep -oE 'if number == SyscallNumber::\w+' kernel/src/process.rs
grep -A1 'table.register' kernel/src/boot.rs

# The ABI's own list
grep -cE '^\s{4}[A-Z][A-Za-z0-9]* = [0-9]+,' abi/src/number.rs

# Crate sizes and layers
grep -E '^[0-9]+ ' scripts/layering.txt
```

Four machines boot, and **51 of the 196 numbers are served**, after the memory,
filesystem, process, time and network levels.  That is the number the census
command above answers, and it is the one to re-take rather than trust.

The boot's own line, `syscall table installed, 31 number(s) served`, counts
only the registry's half, the numbers whose handler functions live in
`boot.rs`'s table.  The rest are the ones `process.rs` serves itself: the
scheduler's, the pipe's, and the ones that need a ring-3 address turned into a
borrow before a handler can see it.  A number reachable from a program needs
**both** a registry entry and a branch in `process.rs`, which is the division
that cost the `*At` calls a boot to learn.

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

The tree is **147,731 lines of Rust across 40 crates**, which is
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
| shorten a file, `SetLength` and truncate | yes, `VNode::set_len` | **no**, one handler and one registration |
| stat or list by descriptor, `StatFd`/`ReadDirFd` | yes | **no**, the descriptor carries `path`, so the anchor exists |
| seek, duplicate, poll a descriptor | the offset is per descriptor | **no** |
| **the network** | the stack, IPv4, IPv6, ICMP, ICMPv6, NDP, UDP, TCP, and 8 of its numbers served | **yes** for 8, the two status calls, the three datagram calls, the three stream calls; 36 socket and protocol numbers still answer `NotImplemented` |
| **shared memory** | no | no, `ShmGet` and its three siblings |
| **threads** | no, one task per process | no |
| **pass a handle to another process** | no, `Descriptor` has two variants | no |
| mount, unmount, list mounts | the table exists | **no**, five numbers |
| identity: uid, gid, users | no | no |
| power, audit, io_uring, GPU, seccomp | `power`'s governors and `audit`'s ring exist, the rest do not | no |

### The syscall census, by family

Of 196 numbers, **51 are served**.  The 145 that are not fall into these
groups; the count is the number of numbers in the group, not the work involved.
The unserved count is the same 145 it was before the IPv6 side landed, because
that change added a number and served it: `Ipv6Status` (197) is the one row here
the network level did not have when this table was first taken.

| family | numbers | in the kernel today |
|---|---|---|
| filesystem metadata and mutation still unserved (`SetLength`, `StatFd`, `ReadDirFd`, `Fsync`, `Fallocate`, xattrs, file flags, the access and permission queries) | 19 | **all of it**, the filesystem implements every operation |
| sockets and the network stack still unserved (raw, local domain, DCCP, TLS, IPsec, MRT, the packet filter, the host-name and address calls beside them, and the rest of the stream and datagram surface) | 36 | **the eight the network level serves**, the two status calls, the three datagram calls, the three stream calls |
| process, signal and scheduling still unserved (`Futex`, `SchedSetAffinity`, `Ptrace`, `Seccomp`, `Prctl`, the introspection calls) | 10 | fork/exit/wait/pid/signals landed; these did not |
| shared memory and synchronisation primitives (`Shm*`, `EventFd`, `TimerFd`, `SignalFd`, `Mq*`, `Epoll*`, `Timer*`) | 20 | none |
| GPU | 9 | none |
| mounts and volumes (`Mount`, `Umount`, `ListMounts`, `RepairVolume`, `FuseMount`) | 5 | the mount table exists |
| **the rest**, descriptors (`Dup`, `Dup2`, `Seek`, `Fcntl`, `Poll`), identity (`GetUid`, `GetGid`, users), power, audit, io_uring, service, locking, and the app's own argv/env/path/debug calls | 46 | assorted |

The seven rows sum to exactly 145, because each number is assigned to one row by
name, the edges between families (`GetHostName` is identity *and* network,
`ListThreads` is process introspection) are settled by where the row's handler
would live, and that assignment is the census's one judgement call.  The counts
come from matching the enum's names, which is how they can be re-taken; the code
block at the top of this file shows the command.

Two of those rows were wrong until this was re-taken, and the error is worth
keeping: the network row said 34 while the enum has **43** names that are
network, seven `Dccp*`, five `Ipsec*`, six `Mrt*`, four `Filter*` and
`TlsConnect` were not counted in the parenthetical, and the "rest" row
absorbed the difference at 56.  One row's undercount is invisible in a total
that another row's overcount fills, which is why the rows are asserted to sum
rather than the total alone.

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
numbers.  `SetLength` (20) and the truncate side of `write` are one decision
the filesystem already implements (`VNode::set_len`) and the ABI has not been
given yet.  And nothing here is about *which* filesystem answers, the mount
table routes every call the same way, which is why the tmpfs and the PyroFS
volume both served the level without the handlers changing.

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

### Level 5, the network

A stack, not a driver: IPv4, then UDP, then TCP, and then IPv6, which started
as "the other address family" and turned out to bring its own discovery
protocol with it.  `virtio_net` moves frames and stops there on purpose.  This
is the largest single level and the one with the least existing code to build
on, **43 numbers** and not one line of protocol above the frame.

What those 43 are, because the shape decides the order: 20 of them are the
socket and address calls a program makes (`NetworkStatus`, `ConnectTcp`,
`ListenTcp`, `AcceptTcp`, `BindUdp`, `SendToUdp`, `RecvFromUdp`, the three
name lookups, `GetSockName`/`GetPeerName`, the four raw-socket calls, the two
`SockOpt` calls and the three local-domain ones); the other 23 are protocols
this level does not promise, seven `Dccp*`, five `Ipsec*`, six `Mrt*`, four
`Filter*`, and `TlsConnect`.

The dependencies, in order:

1. **`net`** is 6 lines today, a `#![no_std]` and a comment.  It grows the
   frame's layers, and each one is a host-testable unit with no device in it:
   IPv4 header parse and build plus its checksum, an ARP cache (the card
   answers one ARP question and remembers nothing), ICMP as far as "port
   unreachable" needs, UDP with its checksum, then TCP's state machine.
2. **The kernel** grows a socket table and the dispatch.  A socket is a handle
   a program holds, and `Descriptor` in `kernel/src/syscall/table.rs` has two
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

#### What Level 5 does not promise

- **The 23 protocol numbers this level leaves alone.**  `Dccp*`, `Ipsec*`,
  `Mrt*`, `Filter*` and `TlsConnect` are named in the ABI and stay unserved.
  They are separate mechanisms, not more calls on this stack.
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
| the transports | `net/src/transport/udp.rs`, `net/src/transport/tcp.rs`, `net/src/address.rs` | an IPv6 writer and reader each, a **second function** rather than the IPv4 one with a flag, and an address type that carries its family so a socket and a connection can be keyed on either |
| the interface | `kernel/src/net.rs` | a link-local address derived at install, the groups joined, the cache, and a demux branch that walks the chain before it reads a transport |
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
147,731 across 40 crates.  The difference is not lost work, it is work the new
architecture has to **do again, in its own shape**, and that word is the
important one.

**This is a rewrite, not a migration.**  The two trees do not share an
architecture: the old one was one binary with module trees and a `shared` crate;
this one is 40 crates with a layering a gate enforces, a different error type, a
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
| `network` | 39,240 | **partial**, the stack is one tenth of it: IPv4, IPv6, ICMP, ICMPv6, NDP, UDP and TCP, and the eight calls a program reaches |
| `drivers` | 18,828 | **partial**, virtio-blk and virtio-net; the rest are not here |
| `user` | 19,145 | **partial**, three programs; the old shell's body and command set are not here |
| `syscall` | 15,647 | **partial**, 51 of 196 numbers |
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
`Ipv6Status` (197), with the same two retirements, and serves **51** of them.
The other 145 are what the levels below are about.

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
virtio-net.  What is missing, in the order it matters:

1. **`nvme`**, a modern machine's disk, and the one that makes a boot from
   real hardware plausible.
2. **`ahci`**, the SATA controller, for a machine without NVMe.
3. **The framebuffer console**, this is the one that changes what the machine
   *is*: today a boot has a serial port and nothing else, which is why every
   demonstration is a log rather than a screen.
4. **`xhci`** and USB HID/MSD, a keyboard, a mouse, a stick.
5. **`virtio_gpu`** and **`virtio_input`**, the same two, on the emulator this
   tree is developed on, which is the cheaper way to prove the input path.
6. **`pcspkr`** last: one line of value, and it needs a timer nobody has asked
   for.

What this level does not promise: a driver *framework*.  `block`'s two traits
are the only abstraction this tree has and they are enough for a disk; a
display and an input device do not obviously want the same shape, and inventing
one before the second driver exists is how a framework becomes a constraint.

### Level 8, the mechanisms the numbers name

The syscall gap restated as work: roughly twenty mechanisms, ordered by what
each unblocks rather than by size.

1. **Descriptors and the file interface**, `SetLength`, `StatFd`, `ReadDirFd`,
   `Dup`, `Dup2`, `Seek`, `Fcntl`, `Poll`, `Fsync`, `Fallocate`.  These are the
   leftover of Level 2 and the cheapest row on this page: the filesystem already
   implements every operation.
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
   `ManifestPath`, `Yield`, `WriteDebug`, `ReadConsole`, `ListBlockDevices`,
   `ListMounts`, `Mount`, `Umount`, `Sync`, `RestartSyscall`, `CompactMemory`,
   `Mlock`, `Munlock`, `Madvise`.
10. **io_uring**, `IoUringSetup`, `IoUringEnter`.  Last because it is a second
    way to do what every call above already does, and nothing needs it.
11. **The rest of the network**, `ResolveHostname` beyond a hosts table, the
    raw socket calls, `TlsConnect`, `Ipsec*`, `Mrt*`, `Filter*`, `Dccp*`.
    `GetSockName`/`GetPeerName`, `SetSockOpt`/`GetSockOpt` and the three
    local-domain calls were on this row and have moved off it.

What this level does not promise: **the GPU calls**.  `GpuCtxCreate` and its
eight siblings describe a VIRGL context, which is a device this tree does not
have and a protocol above it, and they belong with Level 7's `virtio_gpu` if
that ever lands, not here.

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
