# The tree, grouped

What each directory of this tree is, laid out by what it is for rather than
sorted by name.  The map below is the whole tree at a glance; the sections
after it say what each group is and why it is a group.

One distinction underlies the layout, and it comes first.

## Shelf or crate

**A crate** is a compilation unit and a layer.  It has a manifest, it owns
the name cargo resolves, and `scripts/layering.txt` gives it a number saying
what it may depend on.  The layering gate walks crates; it cannot see
directories.

**A shelf** is a directory that groups crates of one kind.  It has no
manifest, compiles nothing, and means nothing to the gates.  `drivers/` is
five crates; `libs/` is twelve; `apps/` is three; `arch/` is four.  Moving a
crate between shelves changes addresses and nothing else — which is how
`devices/` appeared and `ipc` joined `libs/` without a gate noticing anything
but the file headers.

The shelves answer *where would I look*; the crates answer *what may name
what*.  A small crate standing on no shelf reads like a subsystem, and that
was worth fixing twice: `service_table` became a module of the kernel, and
`ipc` took its place on the `libs/` shelf, both because the name suggested
more than the contents held.

## The map

```text
protofire/
├── abi/             the wire format: numbers, records, errors
├── user_abi/        the program's half of the ABI: one gate per machine,
│                    the wrappers, the call-site names
├── syscall/         what a call carries: the context, the argument
│                    validators, the actions
│
│   ── the kernel and its machine ─────────────────────────────────────
├── kernel/          the core: scheduling, processes, address spaces,
│                    the syscalls, the service table
├── bootloader/      the image's entry: what a boot does once the machine
│                    runs Rust
├── arch/            shelf: the machines — x86_64/, aarch64/, riscv64/
├── memory/          the frame pool and the numbered regions
├── async_io/        the request/completion model
│
│   ── the subsystems ─────────────────────────────────────────────────
├── fs/              the VFS: PyroFS, tmpfs, ISO 9660
├── net/             the protocol stack: Ethernet and ARP today
├── power/           the frequency governor policy
├── security/        identities, tokens, the MAC policy
├── sound/           reserved: audio, filled when a machine has a device
│                    worth driving
├── virt/            reserved: virtualisation, argued and no code yet
│
│   ── devices: the traits, then the drivers ──────────────────────────
├── devices/         shelf: what a device is — the traits a driver
│   ├── block/       implements: a disk,
│   └── netdev/      and a network card
├── drivers/         shelf: who drives one — bus/pci/, virtio/ (core,
│                    block, net), net/e1000/ (reserved)
│
│   ── infrastructure: the shelf of pure tools ────────────────────────
├── libs/            allocator, audit, cell, crypto, fdt, ipc, irq,
│                    paging, profiler, rights, sync, unicode
│
│   ── ring 3 ─────────────────────────────────────────────────────────
├── apps/            shelf: init/, shell/, service_manager/
│
│   ── the tree's own operations ──────────────────────────────────────
├── docs/            the documents: status, roadmap, architecture,
│                    migration, async_io, fmts/, this file
├── scripts/         the gates: verify.sh, the checks, the baselines
├── tools/           xtask, the build tool
├── certs/           trust anchors
└── LICENSES/
```

The three crates above the first divider are one conversation seen from
three sides, and they sit alone because every other group is *behind* the
boundary they define.

## The groups

### The contract — abi, user_abi, syscall

`abi` is the wire: the numbers, the `#[repr(C)]` records, the error
encoding — the one thing both sides of the privilege boundary name, and
therefore the frozen surface a change argues before it touches.
`user_abi` is the program's half: one call gate per machine and the
wrappers that pack arguments, every constant derived from `abi`'s own
value, so a number that moves there breaks the program side's build
instead of drifting.  `syscall` is what a call carries on the kernel's
side: the context a handler reads and the validators that refuse a
malformed argument before a handler ever sees it.  The handlers themselves
live in the kernel — `kernel/src/syscall/` is where a number becomes work —
because a handler needs everything the kernel has, and what this crate
holds is what a host test can check without one.

### The kernel and its machine — kernel, bootloader, arch, memory, async_io

`kernel` is what the rest of the tree is for: the scheduler, the
processes, the address spaces, the syscall handlers, the service table.
`bootloader` is the entry the image boots through, a protocol rather than
a driver.  `arch/` is a shelf of three machines behind one router, so a
caller names "the machine" and the target decides which implementation
answers.  `memory` is the frame pool and the region pools — physical
memory before anyone has a heap.  `async_io` is the request/completion
model and its `Service` trait, parked: built, tested, and waiting for a
device to get behind it.

### The subsystems — fs, net, power, security, sound, virt

The large things a kernel exists to do, one directory each.  `fs` holds
the VFS and the three filesystems behind it.  `net` is the protocol stack,
which today means Ethernet and ARP, sent through the trait in
`devices/netdev`.  `power` is the governor policy: a load sample and a
frequency range in, a target frequency out.  `security` labels subjects
and objects and refuses what the policy refuses.  `sound` and `virt` are
the two honest placeholders — reserved plots, with `virt`'s header
carrying the guest/host argument for the day it is filled.

### Devices — devices, drivers

Two shelves, one relationship.  `devices/` holds what a device *is*: the
traits a driver implements and a subsystem above reads through.
`drivers/` holds who drives one: the PCI bus, the virtio framework and the
two devices on it, and the reserved slot for a card this tree does not
boot with.  A driver names a trait and never a stack; a stack names a
trait and never a driver; the kernel is the only crate that names both,
which is the whole reason the traits live on a shelf of their own.

### Infrastructure — libs

The shelf of pure tools: a heap, a record format, an `UnsafeCell`,
ciphers, a device-tree parser, a ring, a handler table, page-table
arithmetic, counters, two flag constants, a spinlock and Unicode.  What
they share is not a topic but a discipline: each names nothing above
itself, which is what lets each be tested on a host in seconds rather
than only during a boot.

### Ring 3 — apps

Three programs compiled by the same workspace and shipped inside the
image, reaching the kernel through `user_abi` and nothing else.  `init` is
the first: exec'd from the kernel's own filesystem, it spawns the shell
and supervises it.  `shell` is the first program something other than the
boot can start.  `service_manager` is a shell headed for service
supervision — the mechanism it waited on has landed, and what is missing
is the policy.

### The tree's own operations — docs, scripts, tools, certs, LICENSES

The parts that exist for the tree rather than in it.  `docs/` carries what
is true and why: the status census, the roadmap, the architecture
argument, the migration record, the async_io review, and `fmts/` — the
formats other code is written against.  `scripts/` carries the gates, and
`tools/xtask` is the build tool that drives them.  `certs/` holds the
trust anchors; `LICENSES/` the licence texts.

## Where the truth goes from here

This file says what lives where.  It does not say what may depend on what
— [`scripts/layering.txt`](../scripts/layering.txt) is that spec, and
`scripts/verify.sh` is what enforces it.  It does not say what works on
which machine ([`status.md`](status.md)), why the tree is shaped this way
([`architecture.md`](architecture.md)), how it got here
([`migration.md`](migration.md)), or what a contributor's change must
satisfy ([`fmts/`](fmts/), from its README).  Where this file and the tree
disagree, the tree is right and this file is the bug.
