# What has moved in, and what has not

This tree replaces a single crate.  The migration is not a rewrite and not a
copy: each subsystem moves in as a crate of its own, with its tests, once it
can be built and exercised on its own.  This document is what has moved, and
what each of those pieces decided about the shape it landed in.

There is deliberately no size column.  A line count is wrong the moment the
next change lands, and a document that is wrong is a bug in this tree, where a
number would be, the table says what is here, and that is the claim worth
keeping true.

## What this document is not

It is not a changelog.  Every defect a subsystem cost on its way in is in the
commit that fixed it — the message says what broke, what the wrong version
did, and what the measurement was — and repeating that here was the larger
half of this file for a while.  A record that grows one story per fixed bug is
a record nobody reads to the end, and the parts worth re-reading (why the
scheduler is one lock, what a second CPU costs, what is deliberately absent)
were buried in it.

What stays here is the part git history cannot answer: the shape of the tree
as it is now, and the reasons that are still load-bearing.  A reason that stops
being true is deleted with the code it argued for, in the same commit.

## The table

| Subsystem | What is in |
|---|---|
| `abi` | the whole wire format, and the syscall numbering |
| `arch` | boot, interrupts, serial, port I/O, page tables, the exception path, IDT, the GDT and TSS, the local APIC and its timer, the 8259, the PL011, the NS16550A, the device-tree handshake, the GIC, the OpenSBI handoff, ring 3 on all three bootable machines |
| `crypto` | all of it, one module per algorithm, it is a `libs` crate, like `unicode` |
| `fs` | PyroFS, tmpfs, ISO 9660, the mount table and the VFS contract; most of the names in the next table are not |
| `kernel` | the boot sequence, the syscall table, the scheduler, device discovery |
| `memory` | the frame pool and the region pools |
| `network` | nothing |
| `drivers` | PCI (ports, ECAM, BAR enumeration, MSI-X), and virtio block |
| `syscall` | the context, the validators, a handful of handlers |
| `user` | nothing; `apps/` holds skeletons |
| `libs` | allocator, audit, cell, crypto, fdt, irq, paging, profiler, rights, sync, unicode |

The `libs` crates have no separate row of their own for the previous tree
because most of them were modules under that crate's `kernel` or `memory`; what
they are now is a crate each.

## Filesystems

A filesystem is the largest kind of subsystem in the previous tree.  What is
here is PyroFS, tmpfs and a read-only ISO 9660; the rest are listed by name,
because the plan is a list of what to do and not a score.

| Filesystem | Here |
|---|---|
| NTFS | no |
| PyroFS | **yes** |
| ISO 9660 | **yes**, read-only, rewritten, not moved |
| ext4 | no |
| F2FS | no |
| FAT32 | no |
| exFAT | no |
| btrfs | no |
| squashfs | no |
| the VFS layer | contract only, see below |
| tmpfs | **yes** |
| FUSE | no |

**The VFS row has moved.**  `fs/src/vnode.rs` and `fs/src/filesystem.rs` carry
the *contract*, what a node is, what a filesystem answers, and the namespace
is now `fs/src/mount/mod.rs` and `fs/src/path.rs`: a mount table, longest-prefix
resolution, and path normalization.  What is still not here is the *handle
table*, which arrives with the process layer because a handle belongs to a
process.

Three filesystems are mounted on a boot: PyroFS at `/`, tmpfs at `/tmp` and an
ISO 9660 disc at `/cdrom`.  The second is what proved the namespace, a table
with one entry has never resolved anything, and the third is what proved it
goes both ways, because a disc cannot be written and so what comes out of it
came from the image.

**ISO 9660 was rewritten rather than moved**, and that is the pattern for the
rest.  The previous tree had a reader and a *writer*, a writer for a writable
ISO image, which was a requirement of that kernel rather than of the format.
This tree has the reader, with the field offsets named and tested instead of
being a packed struct cast from a sector.  See
[`fs/src/iso9660/mod.rs`](../fs/src/iso9660/mod.rs).

The order the rest come in is by what they prove rather than by size: the FAT
family next (shared structure, three formats), then the read-only formats, then
NTFS and ext4, which are where a mistake costs data.

## Network

Nothing.  `net` is a one-line crate so the layer exists and the boundary is
declared before there is code to put behind it.

What the previous tree's network subsystem held: TCP, TLS, SCTP, DCCP, IPsec,
WireGuard, DNS, mDNS, DHCP, NTP, PPP/PPPoE, multicast routing, a packet filter
and raw sockets.  The order it comes in is bottom-up, link, then internet,
then the transports, because each layer's tests need the one below it.

## Architecture

A handful of modules out of the many a machine's support actually needs.  The
previous tree's `arch` had `pci`, `fdt`, `trap`, `mmu`, `percpu`, `smp`,
`thread`, `user_access`, `syscall_trap`, `ptrace` and more.

What is here is what a boot needs before anything else: the entry, the console,
the interrupt flag, the page-table encoding, the exception path, the port I/O
the PCI bus is reached through, and, on all three bootable machines, ring 3,
a timer and a preempting scheduler.

Both machines now reach a program at ring 3, and the two halves differ enough
to say where.  x86_64 needed a descriptor table with a DPL-3 code and data
segment, a task state segment whose `RSP0` names the stack every ring-3
interrupt lands on, a call gate at `DPL` 3, and a `cr3` write to switch
address spaces.  Its timer is the local APIC's, calibrated against the PIT, and
its monotonic clock is the TSC, the APIC's own count runs *down* and reloads,
which is not a deadline and cost a boot its wakes.

The blocking `read` is in on all three machines: a pipe parks a reader, which
`sleep` could not, `sleep` has a deadline and a wake, and a pipe has a writer
and no clock.  The third machine took every seam the first two had left and
kept it, which is the argument that the seams are design rather than two
machines' coincidence.

## What the second CPU is allowed to do

The first attempt gave the started hart its own timer and nothing else, and it
produced two faults that are worth recording because both were far from their
cause: a store page fault inside the device tree, and a store to address three.
What was missing was not a lock.  It was three things the hart had never been
given, and each of them is a register the firmware leaves alone:

- **`satp`.**  The page table is installed on the hart that builds it.  A
  started hart is entered with `satp` clear, so it ran untranslated while the
  boot hart ran through a table.  The addresses still resolve, because the
  kernel is identity mapped, which is exactly what made the omission invisible:
  what would not have held is every permission the table encodes.
- **A deadline.**  Arming the timer is a firmware call, and the firmware keeps
  one deadline per hart.  The boot hart arming its own left the started hart
  with a line enabled and nothing to fire it.
- **`SIE`.**  The firmware enters a started hart with supervisor interrupts
  masked, and nothing had set them.

There was a smaller defect on the way, and it is the one that made the first
version confusing: the started hart wrote its own slot index into `tp`, and slot
zero is the boot CPU's, so the first started hart read as the CPU that owns the
scheduler, and it ran `wake_expired` while the boot hart was still building the
scheduler.  Slots are now one past the index among started harts, and the boot
hart writes its own zero at entry rather than trusting what firmware left in
the register.

## The line the trap entry draws, and where it moved

The gate that stopped a second hart was a single `return` at the top of the
dispatch: a CPU that was not the boot CPU acknowledged its software line and
returned before the sink.  Removing it was safe because the split it stood in
for already exists further in, on state that says what it means:

- `interrupts::handle` counts the tick on whichever CPU took it and re-arms that
  CPU's own clock, then returns early for any CPU that is not the scheduler's
  owner.
- `scheduler::preempt` refuses a frame that is not a program's, and a CPU that
  never enters U-mode never holds one.

So a started hart takes its clock and its inter-processor interrupt, hands both
to the sink, and touches no task.  What it must not do is claim an external
source: the `Plic` the boot installed carries the boot hart's context, so a
claim through it from another hart completes a source nobody finishes.  That
line stays disabled on a started hart, and if a machine ever enables it the
dispatch says so rather than claiming through the wrong context.

The boot proves the whole path rather than describing it.  After the started
hart records that it is online, the boot hart sends one inter-processor
interrupt through the firmware and waits, bounded, for the count:

    protofire: cpus online = 2
    protofire: ipi to 1 other cpu(s), taken
    protofire: cpu 0 id 0, scheduler owner, 5 tick(s)
    protofire: cpu 1 id 1, ticking, 1 ipi(s), 756 tick(s)

The counts are the evidence the start alone cannot give: a hart that stored its
flag and then stopped prints `not taken` and a tick count of zero.  A taken IPI
means the firmware delivered, `stvec` was where this hart reads it, the trap
entry built a frame on this hart's own stack, and the kernel's handler ran far
enough to count.

Four defects came out of the change, and all four are fixed in what this
document describes:

- **The per-hart stack reservation held one slot.**  The entry multiplied the
  hart's slot by the stack size to pick a stack, so slot 1 pointed past the end
  of the buffer.  It went unnoticed while the started hart only parked, and the
  moment it took a trap it ran on whatever followed the reservation.
- **The stack pointer started at the stack's base.**  A downward-growing frame
  written from there is a frame below the reservation, which is what slot zero
  did on the very first trap.
- **A CPU that never came up was still registered as online**, so the activity
  line could count a CPU the line above it had just called a failure.
- **The boot CPU's recorded `id` was its slot**, not the hart the machine
  named.  The two coincide on a machine whose firmware cold-boots hart zero,
  which is why it looked right.

What is still not done is the reason this stopped here.  A started CPU draws no
task, because a task switch writes the scheduler, and the scheduler is one
structure with one owner.  Nothing in this kernel has parallel work to give it:
there is no SMP scheduler, no parallel driver and no load.  When there is work
for it, the change that gives it that work is also the change that decides how
the scheduler becomes per-CPU or locked, and `docs/status.md` records the gap
rather than implying it here.

## Kernel

The boot sequence, the syscall table, the scheduler and device discovery.

The scheduler and the process layer are here: a round-robin rotation over tasks
whose saved context is the trap frame, with a timer that preempts and a sleep
that parks a task on a deadline.  What they do not have is the part of a process
layer that needs the other subsystems, a handle table belongs to a process and
needs the filesystem, and a signal belongs to a process and needs a signal to be
sent by something.

Not here:

| Module | Why it is not here yet |
|---|---|
| the network stack | see above |
| audit, security policy, service manager, procfs, shm | each arrives with the subsystem it observes |

## `user` and `apps`

The previous tree's `src/user/` held a user-space runtime, syscall wrappers, a
demo renderer, the shell's commands and the programs themselves.

`apps/` holds `init`, `shell` and `service_manager` as skeletons, each has the
shape a program must have and no body, because the syscall that starts a process
is served as `NotImplemented` and a body that pretended to work would be a claim
the tree cannot back.

## How a crate arrives

1. It moves in with its tests, and `cargo test -p <crate>` runs them on the host.
2. Its layer is argued in `scripts/layering.txt` before it is added to the
   workspace, a crate with no layer is the one crate nobody checks.
3. Its test count is recorded in `scripts/crate-tests-baseline.txt`, which is a
   ratchet: the count may rise freely and may not fall.
4. `docs/architecture.md` gains a paragraph if the crate's placement was a
   decision, and this table moves a row.

A filesystem has one more condition, and it is the user's: it arrives only after
a mount has been verified on a machine.

## Releasing an exited program's pages

`scheduler::reap` existed and had **no callers** for as long as it existed,
which meant every exit leaked its two image frames, its stack and its page
tables for the length of the boot.  Four programs is small enough that the leak
was invisible, and a program that forked twice would have found the pool
smaller than it was.

The first version of the fix released a task's space at the exit that finished
it, on the argument that the switch that leaves a task clears its slot, so no
CPU is running it.  That argument is wrong, and the boot showed it: **186 page
faults at `0x8080000030`, program 2's stack, in six boots of eight.**  Clearing
the slot is not leaving the root.  The CPU that finds no next task keeps the
finished program's table in its register while it waits, and it can be in its
own trap path with the scheduler's lock not held, so a reaper on the other CPU
sees "no CPU holds this task" and frees a table the first CPU is still walking.

A per-CPU record of the installed root made it worse rather than better: the
window between the record and the register write decides whether a frame is
freed under a live walk, and records written on both sides of that window
produced the same faults at the same address in the same six boots of eight.

So the release is **deferred to the one moment the machine is quiescent**: every
task is `Finished`, and no CPU can still be walking one of those tables.  A
finished task's pages are not needed for it to stay finished, so holding them
costs nothing, and the race is removed rather than narrowed.  The pool goes from
131072 frames free at boot to 131068 after four programs' spaces come back, and
the line is required on all three machines.

**"No CPU can still be walking one" had to be made true rather than assumed.**
The flag that says the boot is over is a request, and a CPU can hold it while
still restoring a trap frame or one instruction from reading a user address;
releasing there returned live frames to the pool, and the machine died inside
its own allocator.  Each CPU now records that it has parked — on the path out,
never on the way in — and the reaping side waits for every online CPU to have
done so, waking a CPU asleep in `wfi` with the inter-processor line because
nothing else will.  `exec` takes the same road: the space it replaces is retired
rather than freed, and goes back here with the rest.

That was measured, not argued: ten crashes in thirty two-CPU boots before, none
in forty after, and never a crash on one CPU in either version.

## What it takes to run on more than two CPUs

The path from one CPU to two is behind us, and the path from two to four is
mostly arithmetic.  This section says what each step costs, in the order the cost
grows, because "does it scale" has three different answers depending on how far
the question is asking.

### Two to four: constants, and one gate

Nothing in the kernel assumes two CPUs.  The start loop is
`for slot in 0..started`, the scheduler's `running` array is one slot per CPU,
`per_cpu::CPUS` is one record per slot, and each machine's trap path answers
"which CPU am I" from the machine's own register: riscv64 derives the slot from
the kernel stack in the trap entry, aarch64 keeps it in `TPIDR_EL1`, and
x86_64 in its `GS` base.  The limits are constants:

| Where | What | Why it is that number |
|---|---|---|
| `arch/riscv64/src/smp.rs`, `arch/aarch64/src/smp.rs`, `arch/x86_64/src/smp.rs` | `MAX_SECONDARY_HARTS = 4` | each machine's `kernel_stacks` reservation is sized from it, and each entry assembly indexes that array by slot |
| `kernel/src/per_cpu.rs` | `MAX_SECONDARY_CPUS = arch::MAX_SECONDARY_HARTS` | the kernel asks the machine rather than copying the number, so the two cannot disagree |
| `kernel/src/per_cpu.rs` | `MAX_CPUS = 1 + MAX_SECONDARY_CPUS` | slot zero is the boot CPU's |
| `kernel/src/scheduler/core/mod.rs` | `running: [Option<usize>; MAX_CPUS]` | one current task per CPU |
| `arch/*/src/serial.rs` | `LINE_SLOTS` | one console line buffer per CPU, on every machine |
| `arch/riscv64/src/boot.rs` | `MAX_HART_NODES = 8` | how many `/cpus` children the tree walk reads |
| `tools/xtask/src/main.rs` | `-smp 2` | the gate's machines, not a kernel limit: all three boot with two |

The numbers that matter are the first three rows: the machine's cap and the
kernel's copy of it are one derivation, and the defect two-CPU support cost the
most to find was exactly a disagreement between them.
`MAX_CPUS` here was four while the slots a boot uses are 1..=4, so the fourth CPU
shared the boot CPU's arrays, and the symptom was a task resumed with another
CPU's context.  The guard that defect deserved is now in place: the kernel's
constant is derived from the machine's, so a machine that raises its cap moves
the kernel's with it, and the `panic` in `per_cpu::cpu` is the belt for a slot
that comes from outside the derivation, such as a register.

The cost of raising the cap is memory, and it is small here: the stack
reservation is `(MAX_SECONDARY_HARTS + 1) * 64 KiB`, so four secondaries are
320 KiB of `.bss` and eight are 576 KiB, against a `.bss` that is already
sixty-four megabytes.  The line buffers are 512 bytes per CPU.

What four CPUs would actually exercise, and what a `-smp 4` gate variant is
worth: the start loop's bound, the stack indexing for slots 2 and 3, and the
scheduler's `running` array under three concurrent claims.  Those are the paths
a two-CPU machine never reaches, and the ones a hard-coded two would break.

### Past eight: the hart list, and the interrupt mask

Two limits change shape rather than size:

- **`MAX_HART_NODES = 8`** is a fixed array the device-tree walk fills.  A
  machine with more harts needs a larger array or a walk that yields rather than
  copies, and the choice is the same one this tree made for the frame pool: a
  fixed bound with a report, or an allocator that does not exist yet at the
  point the tree is read.
- **The inter-processor interrupt's hart mask is a `u64`.**  SBI names harts by
  a bit per hart id, so an id at or past 64 cannot be addressed by one call.
  `started_harts_mask` already skips those rather than truncating, which is the
  honest failure, but a machine with such an id needs a second SBI mechanism or
  a different interrupt.  That is a fact about SBI, not a limit this tree chose.

Neither is hard.  Both are the kind of change that is cheap to make when the
machine that needs it exists, and expensive to guess at before.

### The real threshold: one scheduler, one lock

Past four or eight CPUs the limit stops being a constant and becomes a shape.
Everything above scales because every CPU shares one scheduler behind one
`sync::Mutex`.  That is correct, and it is what made two CPUs landable: a task a
CPU holds is excluded from every other CPU, and nobody had to decide what happens
when a task moves.

The cost it pays is contention.  Every tick, on every CPU, takes the same lock to
walk the same task list looking for expired sleepers.  With two CPUs and a
handful of tasks that is invisible; with sixteen CPUs and a hundred tasks it is a
queue, and the fix is not a bigger lock.

What a sharded scheduler needs, in the order it becomes necessary:

1. **One run queue per CPU**, with a task staying where it was queued.  This
   alone removes the contention and is the smallest version of the change: the
   global lock becomes per-queue, and the questions that cross queues (who may be
   woken, who may be stolen) are the next two.
2. **A migration rule.**  A CPU with an empty queue takes a task from another,
   or the machine idles one CPU while another has work.  A task is already free
   to be placed anywhere — nothing pins one to a CPU — so what a rule adds is a
   *decision* about where, not the permission.  What it costs is not a
   shootdown: see below.
3. **A TLB shootdown.**  Not for migration: a root switch is a whole-TLB flush
   on all three machines, so a migrated task pays one flush and needs no
   broadcast.  What needs the broadcast is any change to the **shared** tables
   every root copies, and that mechanism exists now (`kernel/src/shootdown.rs`):
   an epoch, a per-CPU acknowledgement, and a bounded wait, driven by the same
   inter-processor interrupt the waker already uses, with `tlb shootdown N sent,
   M acknowledged, 0 timed out` on the console.  A sharded scheduler that later
   changes a shared table on a CPU other than the boot one sends through it; one
   that only moves tasks does not.

The order matters less than it looks.  Sharding without migration is a safe
intermediate that buys the contention away and changes no semantics.  Migration
without a shootdown is **not** a use-after-free here, because the flush is part
of every root switch; what would make it one is an address-space identifier or a
switch that skipped its flush.  Releasing a space without knowing no CPU walks
it *is* a use-after-free, and that one has been measured — 186 faults at a
program's stack address in six boots of eight — which is why the release waits
for every CPU to say it has parked.

### What this tree should not do yet

Add CPUs to the machine before adding work for them.  The boot's programs are
three, plus one forked child, and two CPUs already leave one idle for part of the
run; four would leave two idle.  A sharded scheduler written against a machine
with nothing to shard it for would be a design argued from a diagram rather than
from a boot, which is the argument this document makes in the other direction
everywhere else.

So the order is: raise the cap to four and gate `-smp 4` when there is a reason
to, shard when a tick's lock contention is measurable, and migrate when there is
load to balance.  Each step is a change with a measurement in front of it rather
than a preparation for a load no boot in this tree produces.
