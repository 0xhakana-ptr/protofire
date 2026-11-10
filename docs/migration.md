# What is here, and why it is shaped this way

This tree replaces a single crate.  Each subsystem arrived as a crate of its
own, with its tests, once it could be built and exercised on its own.  What
this document keeps is the part git history cannot answer: **the shape the tree
has now, and the reasons behind it that are still load-bearing.**  A reason
that stops being true is deleted with the code it argued for, in the same
commit.

It is deliberately not a changelog.  Every defect a subsystem cost on its way
in is in the commit that fixed it — the message says what broke, what the wrong
version did, and what the measurement was.  It is also not an inventory of the
tree it replaced: what that tree had and this one does not is a list that goes
stale the moment it is written, and it answers a question no reader of this
tree needs.  Where a subsystem is *absent* rather than unfinished, the section
says so and says what it would take.

## The crates

- **`abi`** — the whole wire format, and the syscall numbering.
- **`arch`** — boot, interrupts, serial, port I/O, page tables, the exception
  path, the IDT, the GDT and TSS, the local APIC and its timer, the 8259, the
  PL011, the NS16550A, the device-tree handshake, the GIC, the OpenSBI handoff,
  and ring 3 on all three bootable machines.
- **`fs`** — PyroFS, tmpfs, ISO 9660, the mount table and the VFS contract.
- **`kernel`** — the boot sequence, the syscall table, the scheduler, device
  discovery.
- **`memory`** — the frame pool and the region pools.
- **`drivers`** — PCI (ports, ECAM, BAR enumeration, MSI-X) and virtio block.
- **`syscall`** — the context, the validators, and a handful of handlers.
- **`libs`** — allocator, audit, cell, crypto, fdt, irq, paging, profiler,
  rights, sync, unicode.  Each is a crate rather than a module under `kernel`
  or `memory` as it once was, because a crate is what can be tested on a host
  without the kernel it belongs to.
- **`network`** — nothing.  The crate is one line so the layer exists and the
  boundary is declared before there is code to put behind it.
- **`apps`** — `init`, `shell` and `service_manager`, each with the shape a
  program must have and no body, because the syscall that starts a process is
  served as `NotImplemented` and a body that pretended to work would be a claim
  the tree cannot back.

## Filesystems

Three are mounted on a boot: PyroFS at `/`, tmpfs at `/tmp`, and an ISO 9660
disc at `/cdrom`.  The second is what proved the namespace — a table with one
entry has never resolved anything — and the third is what proved it goes both
ways, because a disc cannot be written and so what comes out of it came from
the image.

`fs/src/vnode.rs` and `fs/src/filesystem.rs` carry the *contract*: what a node
is and what a filesystem answers.  The namespace is `fs/src/mount.rs` and
`fs/src/path.rs` — a mount table, longest-prefix resolution, path
normalization.  What is not here is the *handle table*, which belongs to the
process layer because a handle belongs to a process.

ISO 9660 is the pattern for how the rest arrive: it is a **reader**, with field
offsets named and tested rather than a packed struct cast from a sector.  A
writer is a requirement of a kernel that wants a writable disc, not of the
format.

The order the rest come in is by what they prove rather than by size: the FAT
family next (one structure, three formats), then the read-only formats, then
NTFS and ext4, which are where a mistake costs data.

## What the second CPU is allowed to do

The first attempt gave the started hart its own timer and nothing else, and it
produced two faults far from their cause: a store page fault inside the device
tree, and a store to address three.  What was missing was not a lock.  It was
three things the hart had never been given, each a register the firmware leaves
alone:

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

## The line the trap entry draws

The gate that stopped a second hart was a single `return` at the top of the
dispatch: a CPU that was not the boot CPU acknowledged its software line and
returned before the sink.  Removing it was safe because the split it stood in
for already exists further in, on state that says what it means:

- `interrupts::handle` counts the tick on whichever CPU took it and re-arms
  that CPU's own clock, then returns early for any CPU that is not the
  scheduler's owner.
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

So the release is **deferred to the one moment the machine is quiescent**:
every task is `Finished`, and no CPU can still be walking one of those tables.
A finished task's pages are not needed for it to stay finished, so holding them
costs nothing, and the race is removed rather than narrowed.  The pool goes
from 131072 frames free at boot to 131068 after four programs' spaces come back,
and the line is required on all three machines.

The wait for that quiescence is bounded, and a boot that gives up says so on
the line after the report rather than ending silently.  What a machine has to
do for a CPU to *reach* the point of recording that it stopped is a property of
its interrupt controller, and `docs/status.md` carries that per machine.

## How a crate arrives

1. It moves in with its tests, and `cargo test -p <crate>` runs them on the
   host.
2. Its layer is argued in `scripts/layering.txt` before it is added to the
   workspace; a crate with no layer is the one crate nobody checks.
3. Its test count is recorded in `scripts/crate-tests-baseline.txt`, which is a
   ratchet: the count may rise freely and may not fall.
4. `docs/architecture.md` gains a paragraph if the crate's placement was a
   decision.

A filesystem has one more condition, and it is the user's: it arrives only
after a mount has been verified on a machine.

## What it takes to run on more than two CPUs

### Two to four: constants, and one gate

`MAX_CPUS` in `kernel/src/per_cpu.rs` is what the per-CPU arrays are sized
from; it derives from the machine's own `MAX_SECONDARY_HARTS` rather than being
written a second time.  Raising it is a constant and a boot that starts more
cores — and, on aarch64, one slice of kernel stack per core, which
`kernel_stack_reservation` computes from the same cap.

### Past eight: the hart list, and the interrupt mask

The slot table and the per-CPU records scale with the constant.  What does not
is anything that names a CPU in a **bitmask**: a `GICD_SGIR` target list has
eight bits, and past that a machine needs the affinity-routed interface rather
than the list.

### The real threshold: one scheduler, one lock

Every entry takes one global lock.  A task is not pinned to a CPU: nothing says
where it may run, so the lock is what keeps two CPUs from being handed one
task, and placement is `next_runnable`'s rule — a task the asking CPU last ran,
then a task no CPU has run, then a steal from another CPU.  A per-CPU queue
would shard the contention and would not change what a task is allowed to do;
what it would change is that an idle CPU's work is *nearer* it, which the rule
now approaches from the other side by preferring not to move a task at all.

The measurement is in `docs/status.md`: six boots of the same image read 6, 9,
9, 7, 7 and 16 migrations before the rule and 1, 1, 2, 3, 3 and 3 after it.  A
rule that refused the steal would take that to zero and leave a core idle with
work in the queue, which is why the steal stays.
