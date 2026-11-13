# Status

This document is the per-machine census: for each of the three machines, what
the code does today and what it does not do yet.  It deliberately carries no
line counts, file counts, test counts, or completion percentages, those change
with every commit, and a number maintained by hand is a number that will
eventually be wrong.  The tree is the authority for how much code there is;
this document is the authority for what that code does.

Two words are used strictly below:

- **implemented** means the code path exists and is reachable.
- **verified** means a gate boots it or a test pins it.

Where a machine's entry says nothing about a gap, no gap is known and recorded
here — which is not the same as the machine having none.  Where this document
and the tree disagree, the tree is right and this document is the bug;
`scripts/check-docs.sh` enforces the part of that a machine can check: every
path named here has to exist.

## What every machine does

The three machines are one kernel.  A boot installs the same frame pool and
heap, mounts PyroFS at `/`, tmpfs at `/tmp` and an ISO 9660 disc at `/cdrom`,
installs the syscall table, asks the MAC policy both ways, and starts three
ring-3 programs: one that sleeps and maps memory, one blocked on a pipe, and one
writing to it.  The sleeping one is `/bin/init`, which then does the rest of the
boot's demonstration itself — it forks, spawns `/bin/shell` twice, exchanges
signals with each child, and reads the clock and two ABI records — so the boot's
`every program exited` counts **six** exits from the three tasks it started.
The four parts below are the same on all three machines, so they are stated
once.  A machine's own section carries only what differs.

**Scheduler.**  Preemption, sleeping with a deadline, and a read blocked on a
pipe and woken by a write.  Each task carries a pid, a parent, and the status
it exited with.  `Fork` shares the running process's pages with its child and
hands its context down, writable pages demoted read-only and copied only when a
write faults, once per page that is actually written.  `ExecProcess` rebuilds
the running task around the **file its argument names** — a NUL-terminated path
read through the registry's namespace, parsed by the kernel's ELF64 loader, and
mapped segment by segment at the addresses the loader accepted, with a
writable-executable segment refused by name.  The task keeps its pid, and the
exec'd program opens the boot's own file through `Open`/`Read`/`Close` and
exits with the first byte it read, `116`, the `t` of "the quick brown pyrofox".
Pipes and files share one descriptor numbering, and a descriptor belongs to
the process that holds it: its exit releases every slot it owned, which for a
pipe end is the close that ends a reader's wait.  Every operation checks the
owner, so another process's number is `InvalidArgument` — the same answer as a
number that names nothing, because "denied" would tell a caller which slots
exist.  A `fork` copies the parent's descriptors to the child, owned by the
child; a pipe end copies as a **handle**, so the pipe's count rises and
end-of-file waits for both processes.  The boot's own programs remain
machine code, and `/bin/init` is the workspace's first compiled ring-3 program.

Verified by `the timer preempted, `, `a write woke `,
`forked a process, child pid 4`, `copy-on-write copy at `,
`copy-on-write promote at `, `loaded /bin/init, `, `process 1 exec'd /bin/init`,
`process 1 opened /greeting.txt`, and `exit statuses 1 -> 116`.

The pipe's reader also calls `WaitProcess` after its end-of-file read, and the
gate requires the kernel's own `a wait answered status ` line on all three
machines: the guard, the park's retry contract and the exit's wake are on a
path every boot runs.

A park saves its resume **at the call**, not after it: a trap leaves `ELR_EL1`
past the instruction, which is what an answered call wants, and a parked call
has no answer, so resuming past it would skip the handler and leave the
program reading whatever its register held from the call before.  The rewind
lives in `block` (each machine's `arch` answers the call's width — four bytes
for `svc` and `ecall`, two for `int 0x80`), and a host test requires it.

Two things a wait does not promise, one of which is now answered:

- **`WaitProcess` answers about *some* process, not the one asked for.**  The
  boot has four, and the forked child exits first, so the status that call
  receives can be `139`, that child's fault status, not the writer's `0`.
  `WaitProcessOf(pid)` (#196) is the answer and the boot's programs use it now:
  it names the process, parks a caller whose pid has not exited, wakes it from
  that exit, and answers `NotFound` for a pid no task has.  `WaitProcess`
  remains for the caller that genuinely wants "whichever finished first".
- **The reader's payload and its end-of-file are one call apart.**  The first
  read blocks and a retry returns the writer's four bytes; only the read after
  that sees the closed end.  That is a short read working as the contract says,
  but an image that wants both in one call needs a loop, and this one has none.

A wake reports its count whether or not it woke anyone, because zero is a fact
— a reader already awake is still a reader the bytes reached — and a line that
printed only the non-zero case made the gate depend on an interleaving.
Measured: 120 aarch64 boots with the wake line required, and 60 more with the
wait line required as well, all clean.

**Faults.**  A fault reaches the kernel with its direction and with the
faulting CPU's own table asked what the address is mapped as.  A write to a
page a fork demoted is the copy-on-write event the resolver answers.  A fault
no resolver answers is reported, the task goes `Finished` with the kernel's
status 139, and the next task runs.

A program may answer its own faults: `InstallExceptionHandler` records an
address in the task, a fault is then resumed there with the vector, the
address and the direction in the argument registers, and
`ReturnFromException` resumes the **instruction after the one that faulted**
with the handler's value as the call's answer.  The resume position is held in
the task rather than the frame, because entering the handler replaces the
frame that described the fault.

Verified by `fault at `, `process 4 died from a fault at `,
`exit statuses ... 4 -> 139`, and on every machine `process 3 installed a
fault handler at ` and `process 3 handled its own fault at `: the pipe's reader
stores into its own read-execute code page and the kernel resumes it at the
handler rather than killing it.

The handler receives the faulting instruction's address in the **fifth**
argument register, not the fourth: x86_64's fourth is `rcx`, which `int 0x80`
uses for its return address.  It answers `ReturnFromException(resume, value)`
with the address to continue at, because an instruction's length is the
program's fact and not the kernel's — x86_64's vary.

**Devices.**  The PCI scan, BARs assigned by the boot, and virtio-blk
attached.  Verified by `block device from virtio-blk on pci` and
`virtio-blk wrote and read back sector `.

The virtio network card is **attached on all four boots**.  `virtio_net` brings
a card up — the same status sequence the block device runs, the address read
from the configuration region under `VIRTIO_NET_F_MAC`, and both queues,
receive 0 and transmit 1 — and then moves a frame in each direction.  The
exchange is an ARP request for QEMU's user-mode gateway and the reply:
`qemu_arguments` gives every bootable machine `-netdev user` and a
`virtio-net-pci`, and the gate requires `protofire: virtio-net arp reply ` on
all four.  Measured on x86_64:

```
protofire: virtio-net up, address 52:54:00:12:34:56, receive queue 256, transmit queue 256
protofire: virtio-net arp reply 52:55:0a:00:02:02 holds 10.0.2.2, asked by 52:54:00:12:34:56 for 10.0.2.15
protofire: arp cache holds 10.0.2.2 at 52:55:0a:00:02:02, the wire asked 1 time(s)
protofire: arp cache answered 10.0.2.2 again without the wire
```

The driver's reads of the reply are checked against the request it sent — the
reply has to name this card's address and the address this boot asked about —
so the line is evidence that a frame left, a frame arrived, and the frame that
arrived answers the question.  The two lines after it are the answer's second
half: the reply goes into `net`'s ARP cache, and the same question read back
answers from the table — which is why every later consumer of the gateway's
address resolves there first and the wire's ask count stays at one for the
whole boot.  The gate requires both lines on all four machines, the second
exact, because its tail is the one fact a lookup could not vary.

Three defects were found by booting, and all three are recorded where they were
found because each was invisible to a host test and to every register read-back:

- **The notify region's multiplier was read from its `length`.**  Section
  4.1.4.4.1 makes the multiplier the dword appended *after* the capability
  structure; `length` is the region's size, as it is for the other two.  With
  the multiplier taken from `length` (0x1000 on QEMU's card) a doorbell landed
  at `off * 0x1000`, past the mapped BAR, and the boot died with
  `write past the mapped BAR` on its first transmit.
- **The header is twelve bytes, not ten.**  A probe that filled the frame with
  its own byte indices had the wire carry `2, 3, 4, …`: the card skipped twelve
  bytes of a buffer whose header the driver wrote as ten.  Two more probes
  pinned the number — a header descriptor declaring eight bytes shifted the
  frame to `4, 5, 6, …`, and a single buffer with twelve leading zeros
  delivered it whole.  The driver writes twelve now, and
  `drivers/virtio/net/src/header.rs` records which measurement decided it.
- **The receive path stripped the wrong header.**  With the card writing twelve
  bytes and the driver reading ten, the reply was on the wire — captured with
  QEMU's `filter-dump` — while the driver parsed the frame four bytes into its
  own ARP message and reported it as not an ARP.

**The card's receive queue has its own message, and it is the second identity in
the same table.**  On `riscv64-aia` both devices wire a queue to an IMSIC
identity — the block device's transmit queue to 200, the card's receive queue to
201 — and the boot reports each device's count on its own line:

```
protofire: block message wired to imsic page 0x28000000, identity 200, vector 2, queue 0
protofire: net message wired to imsic page 0x28000000, identity 201, vector 2, queue 0
protofire: block completion message(s) taken = 2
protofire: network message(s) taken = 1
```

Two counts rather than one total is the claim: a sum would say a message
arrived without saying which device sent it.  The gate requires both lines
non-zero on this machine, so a boot that took one device's message and not the
other's fails rather than passing on a total.

**The wiring is one function for both devices now.**  It was a block-device
function that named identity 200, vector 2 and queue 0 in its body; the card
would have been a second copy of the table arithmetic, and a second copy is a
second place the same bug can hide.  `MessagePlan` carries the three numbers and
a name, `wire_device_message` carries the mechanism, and each device names its
own handler — a function pointer, because the registry stores one and the trap
path hands it the identity.  The compile-time assertions moved onto the list of
plans, which is also the only place a **pair** of devices can be checked for
sharing an identity: a per-device pair of assertions could not see the
collision.

**The independence was measured, not assumed.**  With the card's queue vector
left unset — a control that leaves the block device's wiring untouched — the
boot printed `net message wiring refused: ..., queue vector cleared, identity
enabled` and `network message(s) taken = 0`, while `block completion message(s)
taken = 2` did not move.  That is the evidence that the card's 1 is its own
queue's message, and not the block device's count reaching a second counter by
accident.  A first attempt at this control moved the card's *vector number*
instead of failing the write, and the count stayed at 1 — a vector a device is
told about is a vector it sends to, whatever number it is, so the control had
not disconnected anything.

**The receive wait is bounded by the timer, and the wait itself has never run.**
The ARP exchange used to spin: a `spin_loop` poll with a turn count.  It now
checks the ring and, when it is empty, arms the machine's timer for a slice and
stops the core until an interrupt arrives — the card's message is one of the two
that can end it, and the timer's is the other.

Two things were measured about that loop, and only two:

- **The bound is real.**  With no receive buffer posted, the card has nowhere to
  put the reply and the loop exhausts its turns: the boot prints `virtio-net
  arp request went unanswered after 41 turn(s)` and **continues**, rather than
  stopping in a wait.  That is the difference between a bound and a count that
  can never be reached — the first version of this change counted turns and was
  killed by the checker's timeout instead, because `wait_for_a_wakeup` does not
  return without an interrupt.
- **The wait branch does not execute on this machine.**  The boot prints
  `virtio-net waited 0 time(s) for the reply`: QEMU puts the reply in the
  receive ring inside the doorbell write, so the ring is already populated when
  the loop first looks.  A frame's arrival does not depend on the message at
  all — measured by removing the card's queue vector, after which the reply
  still arrived and `network message(s) taken` read 0.

So the card's message is **delivered and counted, and the driver does not yet
wait on it in any boot this gate runs**.  That is "implemented", not "verified",
and it stays a gap rather than a claim: making the wait execute needs a machine
whose device completes asynchronously, which QEMU's user-mode network is not.
The count is what the message's own mechanism has for evidence, and it is
required non-zero on the AIA machine.

A network stack above this is under construction: `net` carries Ethernet, ARP
with its cache, and IPv4, and `docs/roadmap.md` Level 5 carries the steps and
what each is proved by.

**Services — built, and deliberately parked.**  A table from a name to a
service, installed during boot and frozen before anything looks one up; a caller
asks for a name and drives what it gets through one trait, without knowing which
crate implements it.  The first
service in it is the clock, whose answer is the machine's own counter — so the
boot shows the shape working end to end rather than only in host tests:

```
protofire: services installed = 1, frozen
protofire: clock service answered 0x212ae78a through the table
```

The reading is hardware and not a constant: three boots answered `0x2167a7ec`,
`0x22a11df2` and `0x2134f3b4`.

Two defects were found building it, both in `async_io` and both by writing the
test first:

- **An interleaved submission lost its completion.**  `submit` counted only the
  completions already in the queue, not the ones pending requests would produce,
  so submitting after a poll could spend a slot twice; the transfer ran, the
  device did the work, and `poll` dropped the completion with `let _ =`.  The
  check is `completions + pending` now, and the two pushes that follow assert
  their result instead of discarding it.
- **The trait could not hand a completion back.**  `poll` answered `bool` and
  each service kept its queue in a private field, so a `&mut dyn Service` could
  be driven and never read.  `Service::take_completion` is the fourth method,
  and the test for it is written over the trait object rather than a concrete
  type — a generic bound would have passed without the trait being usable.

Two halves of one crate and one ring-3 program answer to the word "service",
and they are not the same thing:

- **`kernel/src/service/table.rs`** is the table: `install`, `lookup`, `freeze`,
  and a value type so a test can build its own.  It knows how to hold a service
  and nothing about which services exist.  It was a crate of its own (layer 7)
  until its only consumer turned out to be the kernel module beside it, which
  is why it is a module now.
- **`kernel/src/service/` around it** is what this boot installs: `install_all`
  names the clock, `clock.rs` implements it.  A kernel with a second service
  changes this directory and not the table.
- **`apps/service_manager`** is a ring-3 program, and it is where "everything is
  a service" is meant to end up: it supervises processes with lifecycle policies.
  Its own header still says it is a shell because supervising needs a restart
  policy — the spawn, wait and signal calls it was waiting on have since landed,
  so what is missing now is the policy and not the mechanism.

The first two split for a reason worth keeping: the table is a mechanism, the
list is this boot's content, the same division as `fs`'s `MountTable` and
`kernel`'s `volume` module — one the merge made a division inside the crate
rather than between crates.

What a service is **not**, yet: a device.  Every driver still submits through
`block`'s `QueuedBlockDevice`, and the clock answers in the call and has no
queue, so nothing in a boot exercises the *pending* half of the model.

**This is parked on purpose, not half-finished in the way.**  "Everything is a
service" is a direction for later, and the work above exists so the direction has
a base when it is reached — not because it is the next thing to build.  It landed
early: `async_io` was being reviewed for whether it should exist at all with no
caller, and the answer "keep it, and here is the layer it is missing" turned into
building that layer.  The reasoning was sound and the result is gate-green, but
the *timing* was not the plan.

So: nothing below is scheduled, and no further work on the service layer should
be started without deciding it is time.  In particular:

- **No driver implements `Service`.**  `VirtioBlock` stays on
  `QueuedBlockDevice`, which works and has a caller.
- **No syscall reaches the table.**  No number names a service; 197 stays
  unassigned, and the 43 numbers that are served are the memory, filesystem,
  process, time and descriptor calls.
- **`apps/service_manager` stays a shell.**  It is the ring-3 half, and it is the
  half that matters when this direction is picked up.

The four items this section lists below are the prerequisites for that half, and
they are prerequisites for a userland of any shape — which is why they are worth
reading whether or not this direction is taken.

### What the user-space half needed, and what it got

"Everything is a service" is a direction, and the user side is the larger half
of it.  When this section was written it listed four prerequisites, in the order
they blocked each other.  Three have landed; this is the honest scorecard rather
than the list.

| prerequisite | state | evidence |
|---|---|---|
| the memory layer | **done** — `Mmap`, `Munmap`, `Brk`, `ReclaimPages` served | the `program memory call` lines below |
| a process a program can start | **done** — `SpawnProcess` plus the six signal calls | `process 1 spawned /bin/shell as pid 5` |
| a way to reach the table from ring 3 | **done** — 43 numbers reachable, the registry holding 25 of them | `syscall table installed, 25 number(s) served` |
| **a handle that can be given away** | **not started** | `Descriptor` still has two variants, `File` and `Pipe` |

The last one is the one that matters now, and the fourth line of the old list
explains why it waited: a service handle is a `Descriptor` variant carrying the
rights it was granted, and passing one between processes is the change that
makes the service table a thing programs use rather than a thing the boot fills.

What has **not** been done is the service layer itself.  `service_manager` is
still an entry point and a panic handler, and the reason is in its own header:
supervising needs a restart policy, and a manager of processes and a manager of
services are the same code until something needs one.

**Memory.**  A program can ask for memory and get it.  `Mmap`, `Munmap`, `Brk`
and `ReclaimPages` are served from ring 3 — four numbers that had none — and the
boot shows a program using two of them:

```
protofire: program memory call 67 answered 0x807ffff000
protofire: program memory call 92 answered 0x8040003000
```

`67` is `Mmap` and `92` is `Brk`.  The mapping's base is the last page of init's
own window — reservations count **down** from the top, because the image starts
at the window's base, its stack is one page above the image, and `Brk` grows up
from the stack; growing mappings down from the top keeps the two ends apart.  The
break is one page past that stack.  Both are addresses the kernel computed from
the program's own layout, and a kernel that had mapped nothing could not name
either — which is why the two lines are the evidence and not the fact that the
call returned.

The store is the other half: init writes a byte into the page it was given, and
the boot reaches its exit status.  A mapping the kernel reported but did not make
would fault there instead.

`AddressSpace` changed to make room: the frame list was a fixed array sized by
what an **image** may weigh, and a heap has nothing to do with an image's size.
It is a `Vec` now and the bounds are two — `MAX_IMAGE_FRAMES` (65) for the
loader's budget and `MAX_OWNED_FRAMES` (4096) for what one space may hold.

**Raising that bound was not enough to raise it.**  Two stack arrays had been
sized by it while it was 65: `fork_from`'s page list (98 KiB at 4096) and the
exec path's (32 KiB).  The kernel stack has neither, and every riscv64 boot died
with a store page fault three frames below `USER_BASE` — reported as
`unhandled exception ... on cpu 4294967295`, because the fault had already
destroyed the register that names the CPU.  Both are sized by the image bound
now, which is the set of pages each actually describes.

**The file interface.**  A program can write, measure, list, move and remove.
Eleven numbers serve the filesystem now — `Write` (6), `CreateDir` (19),
`RemovePath` (21), `Stat` (27), `ReadDir` (28), `Rename` (29) and the five
`*At` forms (32–36) — where a program could previously only open, read and
close, and `Write` printed a fixed line instead of writing anything.  The boot
execs a program that does the whole of it against the tmpfs and shows each
answer beside the call that produced it:

```
protofire: process 1 opened note.txt via descriptor 0
protofire: process 1 wrote 19 byte(s) to a file
protofire: process 1 opened note.txt via descriptor 0
protofire: process 1 stat'd note.txt via descriptor 0, kind file, size 19
protofire: process 1 created directory notes via descriptor 0
protofire: process 1 opened at.txt via descriptor 5
protofire: process 1 wrote 4 byte(s) to a file
protofire: process 1 stat'd at.txt via descriptor 5, kind file, size 4
protofire: process 1 read /tmp/notes entry 0
protofire: process 1 renamed note.txt via descriptor 0 to kept.txt via descriptor 0
protofire: process 1 stat'd /tmp/kept.txt, kind file, size 19
protofire: process 1 removed scratch.txt via descriptor 0
```

The descriptor number on those lines is the table's, not the program's, which
is why the gate takes them as prefixes.  The checks the program makes on its
own are stricter than the lines: it compares the read-back bytes, the stat
record's kind and size, and the listed name against what it wrote, and exits
with a status that is not the greeting's byte when any of them disagrees —
so the boot's `exit statuses 1 -> 116` is the whole program's claim, and a
broken step turns the gate red rather than printing something plausible.

The rights a descriptor holds are the open's: a `writable` flag recorded
beside `readable`, refused with `PermissionDenied` on a descriptor that did
not ask.  A create is the volume's own refusal when the volume cannot create,
not the lookup's miss that prompted it.  A rename whose two names resolve to
different filesystems is refused outright — the alternative is a copy and a
delete, whose halfway failure is the one outcome a rename exists to make
impossible.

The `*At` forms anchor on a descriptor, and the anchor is the descriptor's
record: every open now records the path it resolved to, because a node knows
its own last component and nothing of the namespace above it.  An absolute
path bypasses the anchor; the `AT_FDCWD` sentinel anchors at `/`, the one
base every process shares, because there is no per-process current directory
yet; anything else resolves against the directory the descriptor was opened
from.  A file, a pipe end, or another process's descriptor is not an anchor.

Two defects the first ring-3 exercise found, both recorded because a gate
that had never called these numbers was green through both:

- The five `*At` handlers were wired but **never registered** in the boot's
  table — a silent python replacement in the change that added them skipped
  `boot.rs` and nothing in that change's gate called the numbers.  The first
  program to call one got `NotImplemented`, and the probe that found it is
  the reason the registrations carry a comment.
- A program linked as PIE routes calls to its own library symbols through a
  GOT whose slots are filled by `R_X86_64_RELATIVE` relocations the loader
  does not apply.  The first image big enough to make the linker route a
  `bcmp` that way died jumping to address 0.  init now links `-no-pie`, which
  resolves those slots at link time — honest for an image whose load address
  the linker script fixes — and the flag lives in the command that builds
  init, not in the target's config, so the kernel's own relocatable build is
  untouched.

One entry-assembly defect fell out of the same exercise, on the memory side
of the boundary: x86_64's `iretq`-into-ring-3 left the kernel's own selector,
flags and hand-over pointer in the three registers a program's arguments
travel in (`rdi`, `rdx`, `rcx`, measured), because `iretq` changes rings and
touches no general register.  Every program's first `Write` therefore carried
a length the kernel was right to refuse.  The entry zeroes the program's
registers now, the same clean slate `Context::user` builds and the trap
epilogue restores everywhere else.

The boot's policy grew the permission these calls are policed by: the system
label may read and write unlabelled files **and** the scratch zone, because
`/tmp` is not unlabelled — the layout resolves it to `MAC_TYPE_TMP`, and the
scratch zone is the one the boot mounts for its programs.  The rule's
permission field is a set, which is what makes read and write one rule per
object; two `add_rule` calls with `replace` on would have displaced each
other, and the first attempt did exactly that — the boot's own allow probe
printed `MISPOLICED`, which is what caught it.

**The process model.**  A program can start a program, and processes can
signal each other.  Seven numbers serve the level — `SpawnProcess` (25) and
the six signal calls (`SendSignal` 40, `WaitSignal` 41, `SetSignalHandler`
104, `SetSignalMask` 94, `SigReturn` 134, `SigSuspend` 135) — and the boot's
`init` runs the whole of it: it starts `/bin/shell`, the child announces
itself with a signal, the parent delivers one to the child's **own handler**,
and each child exits with the greeting's length.

```
protofire: process 1 spawned /bin/shell as pid 5
protofire: process 5 sent signal 10 to process 1
protofire: a signal wait answered signal 10 from process 5
protofire: a suspend answered signal 10 from process 6, mask put back
protofire: every program exited, 6 exit(s), 429 tick(s), 32 switch(es), 2 signal delivery(ies)
```

The spawn shares one image construction with `exec` — read, parse, map,
stack, exec block — and the child inherits nothing: a fresh process opens
its own files.  The signal's ring is the target's own, eight deep, FIFO,
carrying the sender **with** the signal; a masked signal stays queued and a
wait skips it, which is what a mask means.  A handled, unmasked signal is
**delivered** — the target's context redirected to the program's handler at
the one moment the kernel owns the frame — with the whole displaced context
kept for the handler's `SigReturn`, because a delivery that is not
transparent is a corruption: the measured case was a resumed flow reading
through a base register the handler's own `ecall` had overwritten, one
instruction past an address computation the delivery's resume had skipped.

Two defects the first boot of this found, both in code the signal demo was
the first to exercise:

- The riscv64 trap path destroyed the program's `x5` and `x6` **twice
  over** — the head computed the hart id in `t0`/`t1` before saving them,
  and the epilogue spent the same registers on its own return after
  restoring them.  Every `ecall` cost the program two registers, and
  nothing noticed while the only programs were machine code that reloaded
  before every call.  The shell's compiler kept a value in `t0` across one.
- `preempt` declined to switch when no other task was runnable, and a
  delivery rode the switch — an armed child spinning as the only runnable
  task never got its delivery, and the boot hung with both processes
  waiting for each other.  The delivery now moves without a switch, which
  is what it is: the signal's arrival, not a scheduling decision.

The `user_abi` crate is the other structural fact of the level: the
wrappers every program compiles against, with the numbering derived from
the ABI's own enum — a number that moves in `abi` breaks the program
side's build rather than drifting until a host test notices.

Verified by the lines above on every machine, by the gate's required lines
for the spawn, the two waits and the suspend, and by `protofire: syscall
table installed, 25 number(s) served` with the census at **43 of 195**
reachable from ring 3.

**The clock and the generator.**  `GetTimeOfDay` (70), `GetRandom` (75),
`SystemInfo` (53) and `AbiInfo` (39) answer from three different places, and
the boot says which of them it has: the machine's counter divided by the rate
the machine reported, a ChaCha20 stream seeded from that counter, and the
scheduler's own counts.  `init` reads the clock twice — a reading, then
another after work, and the pair must not go backwards — draws two blocks of
randomness that must differ, and reads both records back against the ABI's own
constants.

```
protofire: time origin 0x22d9e808 at 2611 MHz
protofire: random seeded, two reads differ
protofire: process 1 read the clock, 16 byte(s)
protofire: process 1 drew random bytes, 16 byte(s)
protofire: process 1 asked the ABI, 24 byte(s)
protofire: process 1 asked the system, 64 byte(s)
```

The time is an interval and not a date: the origin is the reading the boot
saw, recorded once, and every answer is measured from it.  `CLOCK_REALTIME` is
defined and refused with `Unsupported`, because a real-time clock needs a
device driver this kernel does not have and a plausible timestamp nobody read
is worse than an error a caller can act on.

The generator's seed is **timing**, and `docs/roadmap.md` carries the honest
sentence: there is no `RDRAND`/`RDR` probe here, so the bytes are fit for a
nonce, a salt or a shuffle and not for a long-lived key an attacker is
motivated to recover.  Six readings with a spin between them, hashed with the
origin on the end; the stream re-keys from its own state every 1024 blocks, so
an early output does not yield the later ones.

Two defects the first ring-3 boot of this found:

- `AbiInfo` names its record in `a0`, and the intercept read the record and
  length from `a1`/`a2` — the pair every other call in the group uses because
  they have a selector in front.  The length word was validated as an address,
  the range check refused it, and the program exited 200, which is the status
  `insist` uses for a refused call: indistinguishable in the log from a kernel
  that serves nothing.  The refusal prints its own line now.
- The `crypto` dependency the generator needs was absent from `kernel`'s
  manifest, so the module compiled on the host — where `fill` is never called —
  and failed only for a target.

Verified by the six lines above on every machine, by the gate's required lines
for all four calls, and by `protofire: syscall table installed, 25 number(s)
served` with the census at **43 of 195**.

**The second CPU.**  A task is not pinned, so one that is preempted or woken
is placed again, and the boot counts and names the placement.  Placement
follows a rule rather than the rotation: a task the asking CPU last ran is
offered back to it first, a task no CPU has run comes next, and a task another
CPU ran is taken only when neither exists — the **steal**, which is the one
placement that migrates.  Measured on the same image: `task migrations` read 6,
9, 9, 7, 7 and 16 on six boots before the rule, and 1, 1, 2, 3, 3 and 3 after
it, against 12 to 16 `task placings home` — which is the rule's preferred arm
running, not merely a lower number.

Verified by `hart 1 online`, `ipi to 1 other cpu(s), taken`, `cpu 1 runs process `,
`program ended on cpu 1`, `parallel, programs ended on `, `task migrations `,
`task placings home `, `address spaces reaped 6, `, and `tlb shootdown `.

**A queue per CPU is not a gap, and the measurement says so.**  The offer of
work is still the lock's: every CPU scans the same list rather than taking from
a queue a shard filled toward it.  That is a shape worth changing only if the
scan costs something, so it was measured rather than assumed.  Counting every
candidate the two rotation scans look at, over six boots of the same image:

| boot | switches | candidates scanned | steals |
|---|---|---|---|
| 1 | 23 | 155 | 3 |
| 2 | 24 | 120 | 1 |
| 3 | 29 | 124 | 2 |
| 4 | 24 | 110 | 2 |
| 5 | 28 | 147 | 2 |
| 6 | 23 | 155 | 3 |

Five to seven candidates per placement, with four tasks in the machine and a
hard ceiling of eight: the scan is two linear passes over an array that fits in
a cache line.  Sharding would move that cost, not remove it, and would add a
steal path between queues — the same migration, one indirection further away.
What would change the arithmetic is a machine with many more runnable tasks than
CPUs, and nothing here has that yet.  So the shape stays, and the number is
recorded so the next reader can see it was measured.

Exited programs' spaces are released at the boot's end rather than at each exit,
because releasing one while the other CPU was still installed on its root
faulted 186 times in six boots of eight.  `docs/migration.md` has the per-step
cost of more CPUs.

## x86_64

**Boot.**  Multiboot2 or PVH handoff; the entry assembly's 2 MiB identity map.
Verified by the gate's `entered via pvh` line.

**Console.**  COM1, reached through the port pair.  Every line the gate reads
comes through it.

**Page table.**  The kernel's own 4 KiB-granule table replacing the boot's;
text read-execute, read-only data read, device windows uncached.  Verified by
`page table built and installed, 4 KiB granule`.

**Interrupts.**  The local APIC; the 8259 masked rather than remapped; the
self-test raises the inter-processor interrupt's vector, which the controller
delivers and the kernel counts.  Verified by `interrupt delivered to its handler`.

**Timer and clock.**  The APIC timer, calibrated once against the PIT, and the
TSC as the monotonic clock, calibrated separately.  The two rates differ and
the boot proves both.  Verified by `timer armed at ` and `timer counter `.  That
second line carries a count between its two fragments —
`timer counter 5395 ticks apart` — which is why the gate asserts the prefix
rather than a whole line.

**Ring 3.**  A GDT with DPL-3 code and data segments, a TSS whose `RSP0` names
the stack every ring-3 interrupt lands on, a call gate at DPL 3, and an `iretq`
out.  Verified by `descriptor tables installed, TSS loaded` and `entering ring 3`.

**Fault direction.**  From the page-fault error code's `W/R` bit, on vector 14
alone.

**Second CPU.**  The machine's CPU count read from `fw_cfg`, each started
through INIT-SIPI into a copied-down real-mode-to-long-mode page.  A started
CPU loads its own GDT and TSS, its own `IDTR`, its own local APIC and its own
timer, records that it is online, takes its clock, an inter-processor
interrupt and a task from the shared scheduler, and enters ring 3 on it.
Shared-table changes are broadcast and acknowledged.

## AArch64

**Boot.**  QEMU's `-kernel` raw image at EL1; the device-tree pointer recorded
by the entry.  Verified by the gate's `entered via dtb` line.

**Console.**  The PL011, at the address the tree names.

**Page table.**  The kernel's own 4 KiB table; `TCR_EL1` sized for the full
48-bit walk; the tree's device windows uncached.  Verified by
`page table built and installed, 4 KiB granule`.

**Interrupts.**  The GIC; the self-test raises a software interrupt the
controller delivers.  Verified by `interrupt delivered to its handler`.

**Timer and clock.**  The generic timer, one clock for both the deadline and
the counter.  Its private interrupt is configured **level**-triggered, which is
what `CNTP_CTL_EL0.ISTATUS` staying set until reprogramming makes it, and the
started core's own clock fires from it.  Verified by `timer armed at ` and
`cpu 1 id 1, ticking, `.

**Idle.**  A CPU with nothing to run parks in `wfe` and is woken by the event
the kernel's inter-CPU wake issues.  The mechanism is the **event**, not the
interrupt: `wfe` returns for a `sev` from any core and is untouched by the
controller, so a park ends on a call this kernel makes rather than on a line it
hopes the controller delivers.  Measured: a `wfi` in the idle left a started
core parked in **22 boots of 40**, and the boot ended `ended without
confirmation`; `wfe` beside a `sev` from `send_ipi_to_others` ended clean in
**100 of 100**, and in 40 more with the bounded spin behind the hint removed,
which is what shows the event — not the spin — is what ends the wait.  Verified
by the absence of the confirmation line across those 100 boots and by the
started core's own record (`cpu 1 id 1, ticking, ` with a non-zero tick count).

The mask is not the cause and was ruled out: clearing every bit
(`DAIFClr, #0xf`) and halting still left that core's second `wfi` never
returning.  With `wfe` there is no bound behind it: a core whose event never
comes stays parked, and the boot's own reaping side reports the CPUs that never
confirmed rather than waiting for ever.

The reason a `wfi` there never returned was found later and is not a defect in
this wait: an SGI at the reset priority of zero outranked the timer and, once
acknowledged without a finish, blocked the core's whole interrupt path.  See the
"Fixed" entry below for the trace and the measurement.

**Ring 3.**  `eret` to EL0t, `SP_EL0` carried in the trap frame, FP/SIMD saved
because the compiler provably emits them.  Verified by `entering ring 3`.

**Fault direction.**  From `ESR_EL1`'s WnR bit, on the two data-abort classes.

**Second CPU.**  The tree's cores minus the one firmware cold-booted, started
through PSCI `CPU_ON`.  A started core installs its own vectors and
`TTBR0_EL1`, arms its own timer, records that it is online, takes its clock, an
inter-processor interrupt and a task from the shared scheduler, and enters EL0
on it.  Shared-table changes are broadcast and acknowledged.

Missing: about two boots in a hundred used to end wrong; fixed by masking the
trap entry's restore.  The boot's last exit printed `program ended on cpu 1`
and then the machine either took a data abort one byte past the RAM's top —
`fault at 0x60000000, read, mapped read-write, supervisor`, PC in
`exception_entry`'s first `ldp` of a restore — or wedged before `every
program exited`, the reaping side waiting in `send_ipi_to_others` for a core
that halted in the unhandled path.  Measured 2 in 100 and 1 in 60 on the
pre-session baseline, never on x86_64 (80 boots) or riscv64 (20).

The cause was a trap taken during the restore.  The handler **deliberately
unmasks** — a park or a wait clears `I` so the wake can arrive — and returned
with `I` clear, so the restore that writes `ELR_EL1`/`SPSR_EL1`/`SP_EL0` and
reloads 32 SIMD registers ran interruptible.  An IRQ taken there entered the
vector with `SP_EL1` still at the frame, built a second frame over the first
one's, and its `eret` resumed the first restore with a `sp` that a temporary
trap-entry probe showed landing on a **frame-pool page** (`0x449a7000`,
`0x449913c0`) rather than the RAM's top — a saved slot the second frame had
overwritten.  Masking the entry alone was not enough and measured 3 in 200;
masking again after the dispatch, before the restore, measured **200 of 200
clean**.  `eret` reloads `DAIF` from `SPSR_EL1`, so neither mask needs an
unmask.

**Fixed: a boot that stopped between a signal and the wait that follows it.**
With two CPUs and the signal exchange `init` runs — `SpawnProcess`, the child's
announcement, the parent's delivery, the parent's `WaitProcessOf` — a boot
sometimes stopped after `a program waits for process N` and never reached
`every program exited`.  Measured at 4 boots in 10 on the machine the gate
boots.  The scheduler was never at fault: its state read correctly throughout.

**The cause was an interrupt priority, not a lost interrupt.**  This entry said
for two sessions that the started core's private timer line stopped arriving,
because `GICD_ISPENDR0` showed no bit 30 while `CNTP_CTL_EL0.ISTATUS` was set.
That was a symptom read as a cause.  QEMU's `-d int` exception log and its
`gic_*` trace events, from **one** stalled boot, show what actually happened:

- The started core's last acknowledge was `irq 0`, a software interrupt, and
  **no `EOIR` write for it followed** — the SGI stayed active.
- Every later `gic_update_bestirq` for that core read
  `irq 30 priority 128 cpu priority mask 255 cpu running priority 0`: the
  distributor had the timer pending and could not forward it, because a
  priority-128 line cannot preempt a running priority of 0.
- The exception log then recorded **no exception at all** on that core while
  its program kept executing in ring 3 with `IRQs` unmasked — 507 IRQs taken
  and then none, over the remaining twelve million lines of log.

A running priority of 0 is the SGI's, and nothing in this tree ever wrote one.
`GICD_IPRIORITYR` resets to **zero**, zero is the *highest* priority a GIC has,
and `enable_interrupt` never routes an SGI — its enable bits are read-only — so
every inter-processor interrupt outranked the timer's `0x80`.  One un-finished
SGI then blocked that core's entire interrupt path.

`arch/aarch64/src/gic.rs` now writes every software interrupt at
`SOFTWARE_PRIORITY` (`0xA0`, below the device priority) when the controller is
enabled, and a `const` assertion fails the build if the ordering is ever
inverted.  The fix was measured against a control rather than assumed:

| image | boots completed |
|---|---|
| before the change | 4 of 10 |
| with the priority write removed (control) | 2 of 10 |
| with the priority write | **30 of 30** |

The three repairs tried before this one all made the boot worse, which is
consistent with the cause being outside the timer path altogether:

| repair | boots completed |
|---|---|
| none (before the attempts) | 6 of 14 |
| `preempt` waits when it finds an unowned user frame | 4 of 14 |
| `CNTP_CVAL_EL0` accumulated by the handler | 4 of 14 |
| boot core pings the others on every one of its ticks | 4 of 14 |

`wait_for_a_wakeup` still waits on the `sev` **event**, and that is no longer a
workaround for a broken timer: a park should end on a call this kernel makes
rather than on a line it hopes the controller delivers.  The design those three
failed repairs pointed at — "the boot core's tick drives every core" — was
never implemented, and this measurement shows it was aimed at the wrong module.

Also ruled out along the way, each by measuring rather than by argument: the
machine's CPU model (cortex-a57 7 in 10, `max` 6 in 10 — the same defect); the
GIC version (`virt,gic-version=2` 6 in 10, and `gic-version=3` 0 in 10 because
this tree implements the v2 register interface only); a missing `sev` after the
exit wake (real, fixed, not the whole of it); the order of `idle_until_woken`
and `switch_without_saving` (removing the idle call made it worse, 5 in 6); and
an exit whose `running[cpu]` was already clear (the probe for it never fired);
a stalled global clock (the global `TIMER_TICKS` keeps climbing at a stopped
boot — it is the started core's own count that stops, which is why the per-CPU
census is the number to read); and the `has_runnable`-counts-blocked reading
(the scheduler's state was correct throughout).

Three measurement details are worth keeping, because each cost a wrong
conclusion:

1. An early attempt booted **one** CPU against a disk formatted by the kernel's
   own built-in image — the one that carries the greeting and no init image —
   and every such boot stopped five times in five.  That stop was
   `ExecProcess` failing on a file the disk did not have.  Any future
   measurement here has to name which disk it booted.
2. Reading GIC memory through a gdb stub's `x` command **kills the
   connection** on this machine; it is device memory and the stub's translation
   does not carry it.  QEMU's monitor (`xp`) reads it and survives.
3. Four QEMU processes were once left running at the same time, one of them
   holding the gdb port, so "the stalled machine" a later session attached to
   was not the one whose log it read.  The numbers in this entry come from
   single-process runs, sampled twice with the guest executing between the
   samples.

None of this was in the level-4 calls: the same boot stopped at the same line
on the commit before them.

## RISC-V 64

**Boot.**  OpenSBI hands the entry S-mode with the device tree in `a1`; the
image is an ELF at the loader's conventional address.  Verified by the gate's
`entered via dtb` line.

**Console.**  The NS16550A, at the emulated platform's address.

**Page table.**  Sv48, the mode whose four-level walk is the shape the kernel's
shared arithmetic defines; `satp`'s page number at the register's own bits.
Verified by `page table built and installed, 4 KiB granule`.

**Interrupts.**  Four lines, all bits in `sie`: the timer's, the software one
the machine raises on itself, and the external one a PLIC source arrives on.
The PLIC is programmed and the console's UART is claimed as a real source —
enabled at the controller, asked for one transmitter interrupt, acknowledged at
the device before the source is completed.  Verified by
`interrupt delivered to its handler`, `external controller at `, and
`console interrupt(s) taken = 1`.

**A delivery the device does not own is not counted as an interrupt.**  The
controller can hand this source over once more after the handler silenced the
UART: the line was asserted when the source became pending, and the controller
delivers what it latched although the device has nothing to say by the time it
is read.  Measured on both the PLIC and the APLIC, six boots each: exactly one
delivery whose `IIR` read says "mine" and exactly one whose read says "not
mine", every time.  The trap path completes the second and returns without
handing it to the sink, so the count describes interrupts rather than
deliveries.  A probe is what found it — without one, the same boot printed
`taken = 1` or `taken = 2` depending on where the print landed.

The AIA's APLIC is driven in **direct delivery mode**: the machine is
described with `riscv,numsource` and `riscv,aplic`, its sources are configured
level-high with a per-source target, and a hart's delivery block claims and
completes.  The boot finds the APLIC before the PLIC, because a machine that
describes one is an AIA machine and the older node beside it is the one the
firmware left for a kernel that does not know the new one.  Measured on
`-machine virt,aia=aplic`: `external controller at 0xd000000, context 0, 96
source(s)` and `console interrupt(s) taken = 2`, with the boot completing in
4 of 4 runs.

**The IMSIC is driven, and the boot walks its message path.**  When the tree
names a supervisor IMSIC — the node whose `interrupts-extended` pairs carry
cause 9; the one carrying 11 is machine mode and is not this kernel's — the boot
reads the group's base, stride and `riscv,num-ids`, enables this hart's file
(`eithreshold` zero, `eidelivery` on), and then proves the path with no device
attached: it enables the file's **highest** identity — one past any a device
could be given — writes that identity into **this hart's own MSI page** exactly
as an MSI-X table entry would, and reads it back with the `stopei` claim.

    protofire: imsic at 0x28000000, hart file 0, 255 identit(ies), self-test identity 254 delivered and claimed

That line is the evidence: the page's address, the bare-identity data word, the
pending bit, the enable bit and the claim were all executed. QEMU's `virt` with
`-machine virt,aia=aplic-imsic` is where it runs — `cargo xtask check --machine
riscv64-aia`, which is part of `sh scripts/verify.sh p1` and therefore of every
tier above it.  It is a **gate machine**, not a measurement made by hand: the
same image the PLIC machine boots, on a tree that names an APLIC and an IMSIC,
with its own required lines.  The default machine and `virt,aia=aplic` print no
such line because their trees name no IMSIC, and the code that would touch
`siselect`/`sireg` is not reached — which is load-bearing rather than tidy,
because on those machines the pair is an **illegal instruction**.  Measured:
`virt` and `virt,aia=aplic` both stop with `unhandled exception 2 (illegal
instruction), address 0x15051073` if the CSRs are read unconditionally, and both
boot to completion when the read is gated on the tree as it now is.

The gate's four kinds of assertion cover what a single boot line cannot, and
each was mutation-tested by breaking the kernel it guards:

| assertion | what it refuses | what broke it |
|---|---|---|
| a required line | the boot never reached this step | an absent line fails |
| paired fragments on one line | two lines that say different things | text change on the IMSIC line fails |
| a count above zero | a wiring that armed every register and took nothing | the pre-reset wiring reads `= 0` and fails |
| text that must not appear | a failure whose words contain its own success | the self-test's failure text fails |

**The APLIC's message mode delivers to the IMSIC, and each source's message
carries its own number.**  On `-machine virt,aia=aplic-imsic` the APLIC is
locked in message mode (`domaincfg` reads `0x80000104`, `DM` set and
read-only), so a wired source becomes a message into the IMSIC.  Each source's
target word names the hart and **the source's own number as the identity** —
measured, a constant there put every wired source's message onto identity 1,
which is also the firmware's inter-processor identity (`eie` reads `0x2` at hart
start, set by the firmware), and a trap that claimed identity 1 could not tell
the console's level wire from an IPI: the wire stayed high and the APLIC
re-sent for ever, 16,052 claims in six seconds.  With the identity as the
source's own, the file's enable is the **filter** — only the sources a driver
claims get one, because enabling the whole range turned every wired line with
nobody to answer it into a storm (41,201 deliveries in ten seconds from one
source, silenced at its controller once the trap path stopped re-arming it).
Those boots finish, with `console interrupt(s) taken = 1` — the console's own
message, delivered through the APLIC, claimed as its source's identity, and
acknowledged at the UART.

**That one was an off-by-one in the source arrays, and no register the driver
read could show it.**  The APLIC's `sourcecfg` and `target` arrays are indexed
by **source number, which starts at one**: source `N`'s word is at the array's
base plus `(N - 1) * 4`.  The driver wrote `number * 4`, so every word landed one
source too high.  The console's source 10 therefore carried the target written
for source 9 — identity 9 — and the APLIC delivered every console message to
identity 9 while the kernel had enabled and was waiting on identity 10.  Every
register read back correctly, because the driver read its own wrong offsets;
`CLRIP` showed the wire asserted at source 10, `SETIE` showed it enabled, and the
file showed identity 10 enabled.  The message was sent and claimed and simply
never recognised.

What found it was QEMU's own MMIO trace, which is external to the guest:

    qemu-system-riscv64 -trace memory_region_ops_write ...
    memory_region_ops_write ... addr 0x28000000 value 0x9 size 4 name 'riscv.imsic'

Identity **9** arriving at the file, written for a kernel waiting on 10, is the
whole of the defect in one line.  After the fix the same trace reads `value 0xa`,
and the count is one on **6 of 6** boots — the same number the PLIC machine has
reached by a different mechanism.  `check --machine riscv64-aia` requires that
one, and reverting the `- 1` makes the gate fail on exactly that line.

**A PCI device's MSI-X reaches the IMSIC, and the reason it once did not is the
order the wiring ran in.**  The block device's queue is mapped to a message: an
MSI-X table entry naming this hart's file page and the bare identity 200,
MSI-X enabled, the queue's vector set, and the identity enabled in the file —
every step read back from the device, then the handler registered under the
identity.  Measured on `-machine virt,aia=aplic-imsic`: **8 of 8 boots** take
the completion message, and the census line reports it:

    protofire: block message wired to imsic page 0x28000000, identity 200, vector 2
    protofire: block completion message(s) taken = 2

The count is 2 and not one per completion because an IMSIC file holds **one
pending bit per identity**: completions that arrive before the first is claimed
share the bit, and the number is how many times the trap ran.  Twelve
`virtio_notify` events in QEMU's own trace against two trap deliveries is that
shape, and it is why the count is reported beside the programs rather than
taken to be the device's request count.

The wiring has to run **after** the driver is constructed, and that is the whole
of the defect the previous session could not reproduce: the driver's first step
is a device reset (`write_status(0)`), and a reset is the device forgetting
every queue's interrupt state.  Armed before it, the table entry and the queue
vector are both discarded and the transport drops every completion silently —
QEMU's trace records the notifications, and no `virtio_pci_notify` follows
because the queue's vector is `VIRTIO_NO_VECTOR` again.  The same code at the
two positions, one variable apart: **0 of 4** boots before the reset, **8 of 8**
after, with the wiring's own line reading back identically in both runs.  The
one boot that "worked" last session was a race it won, not a mechanism.

Also corrected: the previous note that this file refuses identity 128 was a
measurement of the same defect, not of the identity range.  QEMU's
`riscv_imsic_write` accepts any identity in `1..num_irqs` (255 on this machine),
and writes 20, 128 and 200 all arrived once the wiring ran in the right place.

One limit remains, measured:

- **Only one device's message is claimed.**  The identity is the boot's to hand
  out and the handler table is per identity, so a second device is a second
  identity and a second handler rather than a controller change; what is
  missing is a driver per device, not a message path.  The APLIC's wired sources
  are claimed too — each delivers as its own identity — and the console's is
  both delivered and taken, which the line above records as `taken = 1`.

**Timer and clock.**  The SBI's legacy `set_timer`; arming is a trap into
M-mode, with every clobbered register declared.  The counter's rate comes from
the tree, there being no register that states it.  Verified by `timer armed at 10000 ticks/ms`.

**Scheduler, in addition.**  A sleep is bounded by the largest duration one
`addi` immediate can express, which is the machine's own limit rather than the
scheduler's.

**Ring 3.**  `sret` to U-mode, `sscratch` holding the kernel stack for the trap
back, `sepc` advanced before a handler can park the frame, `SUM` granted once at
the entry.  Verified by `entering ring 3`.

**Fault direction.**  From `scause`, where store and load page faults are two
different numbers.

**Second CPU.**  The tree's hart list minus the hart the firmware cold-booted,
started through the HSM call.  A started hart takes its own stack, its own
`satp`, its own timer and the trap vector, records that it is online, takes its
clock, an inter-processor interrupt and a task from the shared scheduler, and
enters U-mode on it.  Which hart the firmware cold-boots is the firmware's
choice, so the census names the slot the kernel numbered rather than a hart id.

This machine broadcasts no shared-table change, and that is a fact rather than
a gap: its ECAM window is inside the identity map, so nothing is remapped after
the second hart is up.
