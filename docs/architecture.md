# The architecture of this tree

This document says why the crates are arranged the way they are.  The arrangement
itself is `scripts/layering.txt`, which `scripts/check-layering.sh` enforces; what
follows is the argument, and it is the part a new crate has to be placed against.

## The one rule

**A crate may depend on a crate in a lower layer, and on nothing else.**

That is not the same rule as "no cycles", and the difference is the reason this
document exists.  A graph can be perfectly acyclic and still wrong: a filesystem
that depends on the scheduler closes no loop and is exactly the edge that makes
neither side auditable — the filesystem now has to know what a thread is in order
to answer a read.  Layering refuses that edge on the day it is written, instead
of at the point where unwinding it costs a month.

Two crates in one layer may not depend on each other either.  If they must, one
of them is in the wrong layer — or there is a type both need that has not been
extracted yet.

## The layers

```
  9-10   integration_tests, protofire (root), xtask     not shipped
     8   bootloader                                    the image
     7   kernel                                        the core
   5-6   syscall, pci, virtio_block, e1000, sound, virt, fs, net,
         security, allocator
     4   arch, block, virtio_core                      the route, the disk interface,
                                                       and the virtio framework
     3   arch_x86_64, arch_aarch64, arch_riscv64       the machines
     2   crypto, async_io, power, ipc                  algorithms and rings
     1   abi                                           the wire format
     0   cell, profiler, unicode, rights, audit        core and alloc only
```

`ipc` and `power` sit at layer 2 with the algorithms, not with the kernel, and
that placement is a decision with an argument.  A pipe's ring buffer is a
buffer, two cursors and a count; a frequency governor is arithmetic over a load
sample and a range.  Neither needs a machine, a scheduler or a thread — which is
exactly why both can be tested on a host, and why they are crates whose contents
run in a third of a second rather than only during a boot.

What belongs to the kernel is the half that does need those things: the pipe's
endpoints, which park a reader and so need a wait queue, and the `cpufreq`
dispatchers, which touch an MSR or a device tree.  Those halves live in the
kernel and call into these crates; the crates never learn what a thread is.  The
test of the placement is that `scripts/check-layering.sh` would refuse the
opposite arrangement, where a ring's arithmetic reached up for the scheduler.

The numbers are not aesthetic.  Each is the answer to "what does a reader have to
understand before this crate makes sense?"

### Layer 0 — nothing of this tree

A crate here names `core`, and `alloc` where a value is a collection.  Nothing
else.  Everything above may name a layer-0 crate, so anything added here is a
cost the whole tree pays.

`cell` is a `Sync`-capable `UnsafeCell`: four lines and a safety argument, needed
by the heap, by an architecture crate and by the kernel.  `profiler` is operation
counters whose whole design is that they cost nothing when off — a claim checked
by a test rather than stated.  `unicode` is character conversion and
normalisation; `rights` is two constants four layers name; `audit` is the record
and its ring buffer.

`rights` deserves a sentence because sixteen lines is an odd size for a crate.
The flags are read by the filesystem, by device descriptors, by the audit log and
by the handle table.  As a module under any one of them, the other three would
have to depend on it.  As a crate at layer 0, they all depend on a leaf.

### Layer 1 — the wire format

`abi` is what the kernel and a program both compile against: the error type and
its discriminants, the syscall status encoding, the boot information.

It is one layer above the leaves rather than beside them because it is the one
value in the tree that is *shared* rather than owned.  A type both sides of a
privilege boundary name cannot be a private detail of either side.

The rule for this crate is that nothing may be added that needs `alloc`: a
program's ABI is a word.  Where that is inconvenient, the type does not belong
here.

**What this crate replaces.**  The previous tree carried the ABI twice — the
kernel's copy and a vendored copy for the user side — kept identical below the
header by a census script with a baseline of recorded differences.  The copy
existed because a payload is compiled separately and could not `use` the kernel's
crate.  A crate both sides depend on removes the reason, and the script that
compared two copies is not needed.

### Layer 2 — algorithms over the ABI's types

`crypto` and `async_io` name `abi` for the error type.  A cipher that returned
`Result` without sharing the tree's `Error` would force every caller to
translate, and translation tables are how two error vocabularies drift apart.

Both are testable on a host, which is the property that justifies them being
crates: a hash has published vectors, and a request/completion queue has a state
machine that can be driven without an emulator.

`crypto` is one module per algorithm — `sha256`, `crc`, `chacha20`, `poly1305`,
`aes`, `gcm`, `xts`, `hmac`, `hkdf`, `pbkdf2`, `x25519`, `ecdsa`, `rsa`, and the
two that are not algorithms at all — `constant_time` and `salt`.  The split is
the crate argument applied one level down: a primitive is added or removed one
at a time, and the `use` lines between the modules are the dependency graph.  A
mode names the block cipher it wraps (`gcm` and `xts` import `aes`), a
construction names its hash (`hmac` imports `sha256`, `hkdf` and `pbkdf2` import
`hmac`).  Nothing is re-exported through an intermediate module, so there is one
place each function can be found.

### Layer 3 — the machines

`arch_x86_64`, `arch_aarch64` and `arch_riscv64` are three crates, not one crate
with three `#[cfg]` arms.  The difference shows when an operation is missing: with
three arms, a machine whose arm was never written still compiles, because the arm
for another machine was.  With three crates, the build fails for the machine that
is missing the operation, and names it.

That happened in this tree.  The spinlock closes the interrupt window by
disabling local interrupts, and only x86_64 had a crate that could; the other two
got their `interrupts` module in the change that first asked them for one.

### Layer 4 — the route

`arch` selects between the three by `cfg(target_arch)` in its own manifest.

Not by a feature, and that is deliberate.  A feature would be a second place the
machine is named, and a build could select the one that disagrees with
`--target`: `--target aarch64-unknown-none --features x86_64` would compile
x86_64's `out`/`in` instructions into an aarch64 image, and the only thing that
would notice is the assembler, if it did.

Cargo evaluates the `cfg(target_arch)` tables against the target being built, so
the choice is made once and cannot be overridden.  Selecting none is not
expressible: a target no table names gets no implementation, and the re-exports
then name crates that are not there — an error that says the architecture has no
implementation, which is the true statement.

**The promise this layer makes** is that nothing above it learns which machine it
runs on.  `scripts/check-arch-fanout.sh` holds it: every `target_arch` name
outside `arch/` is counted, each file in the census carries a reason, and the
number is expected to reach zero.

**It is now zero.**  The census's first honest reading was one row —
`bootloader/src/main.rs`, five occurrences — and the reason on it said the entry
symbol and the panic handler are things only a binary can define.  That was true
and it was not the question: the *symbol* is a binary's, but the *instruction* it
reaches for is the machine's.  Five `target_arch` gates meant five places
`bootloader` named a machine, in the crate that is not the machine.

The distinction the row was missing is the one this tree now states explicitly:

| | |
|---|---|
| **`bootloader` is a protocol** | a loader put us here, so record what it said, take over the console, start the kernel |
| **`arch` is the machine** | the state arrived in `%eax`, the stack is at this symbol, an image links at this address |

A new loader changes the first; a new machine changes the second.  So the
machine's entry assembly, its linker script and its stop instruction all live in
`arch/<machine>/`, and `bootloader` defines one neutral symbol —
`protofire_entry` — that every machine's assembly calls.  The kernel's own four
gates went the same way: the handshake is the architecture's to parse and the
kernel takes no arguments.

That last sentence is a link-time reference in one direction, not a crate edge:
`arch` sits *below* `bootloader`, so `arch`'s assembly cannot name it, and the
symbol is what the two sides agree on.  An upward `use` would have been the one
thing the layer gate forbids; a symbol with no type attached is not a dependency.

### The quiet exception: `sync` above `arch`

`sync` names `arch`, and that upward edge is a decision with a cost.

A spinlock that only spins is safe between CPUs and unsafe against itself: an
interrupt taken while the lock is held, whose handler takes the same lock, spins
forever on a CPU that cannot make progress.  Closing that window needs the
interrupt flag, the flag is the machine's, and putting it behind a trait would add
an indirect call on the hottest path in the kernel.  That was measured in the
previous tree and declined.

So everything that wants a lock carries the machine layer with it.  That is the
price, it is cheaper than the alternative, and it is written down because an
exception nobody argues for is what the gate is for.

`memory` is at a lower layer and does *not* name `arch`: the frame pool is a range
and a bitmap, and the one place it needs the machine — "make this range writable"
— is an injected function.  That is what keeps the page table out of a data
structure, and it is why the frame pool's arithmetic can be tested on a host.

### `virtio_core`: a framework below the drivers

`virtio_core` is the virtio framework — one split virtqueue, the feature
negotiation, the status state machine a device goes through, and a `Transport`
trait with the PCI modern register offsets.  `virtio_block` is the block device
on top of it: a request header, a data buffer, a status byte, and the two block
traits over them.

They are two crates and not one because virtio is a protocol with several
devices behind it.  A network driver and a GPU driver submit through the same
queue and negotiate features the same way; a `virtio` crate that also held the
block driver would make them depend on block code to reach a queue.

**The framework sits at layer 4, with `block` and `arch`.**  A framework is
named by the drivers, so it has to be under them — the same argument that put
`block` there.  `virtio_block` stays at layer 5 with the other drivers.

**What is testable on a host, and what is not.**  A virtqueue is arithmetic over
three rings in memory, so a host test builds one over a `Vec` and stands in for
the device by writing into the used ring.  A transport is register accesses at
addresses a machine chose, so its host arm reports "no device" rather than
pretending.  The block driver is written against `Transport` rather than against
PCI, which is what lets a host test drive the whole of it — initialisation,
request encoding, the descriptor chain, the doorbell, the used ring — with a
fake device that behaves like one.

That last point is the reason the trait exists.  Without it the driver would be
tested by booting, and a boot tells you that it failed, not which of the forty
things it did was wrong.

### `block`: an interface at the drivers' layer

`block` is at layer 4, below the drivers that implement it, and it is in the
root rather than under `libs/`.  Both facts are the same argument.

A crate under `libs/` is a tool with no client shape: a cell, a set of flags,
a `Vec`-with-a-lock, an allocator.  `block` defines a *role* — what a disk
driver is — and a role is the thing `drivers/` and `fs/` share rather than
something either one owns.  That is the position `abi` and `fs` are in, which
is why they are siblings of it; filing `block` under `libs/` made the tree say
it was a toolbox when it was a contract.

It sits at layer 4 because the drivers have to name it to implement it.  With
`block` at layer 6 and `virtio` at layer 5, the trait was one no driver could
implement — an upward edge — and that is why `drivers/block/virtio` was an
empty file for as long as it was.  The layer was wrong, not the driver.

The price of layer 4 is that `block` cannot name `sync`, which is at layer 5
because closing a spinlock's interrupt window needs the machine.  So `block`
holds a `spin` lock, and the argument is in its header: the devices there are
in-memory ones touched from ordinary context, and a real driver takes its own
lock where the interrupt question is its own.

The crate holds two traits.  `BlockDevice` is what every device is;
`QueuedBlockDevice` is what a device that can be ahead of its caller is.  They
are separate because `submit_read` is `unsafe` — the caller's buffer has to
stay put until the device is done — and an interface every device implements
should not carry a borrow contract only some of them need.

### The subsystems and the core

`security` sits below both the filesystem and the process layer, because both
must ask it and neither may name the other to do so.  A denial goes through a
sink rather than into an audit record: finding the current process is the audit
layer's business, and a security decision should not have to know how to do it in
order to say that it denied something.

`allocator` is the heap, above `sync` because the heap is shared by every CPU and
by interrupt handlers.

The drivers are one crate each so that a machine without a device does not carry
its code.

`kernel` names everything below it and nothing in its own layer.  `bootloader` is
the only crate that links an image.  `integration_tests`, `protofire` and `xtask`
are not shipped: nothing depends on them, and they may name anything, which is
expressible as the top layer rather than as an exception.

## What a crate split buys, measured

The reason for this arrangement is that a crate can be built and tested on its
own.  That is checkable, and these are the numbers from this tree:

| | |
|---|---|
| a test run for one crate | `cargo test -p crypto` — 64 tests, 0.5 s |
| lines moved with two import changes | 4,606 (`crypto`, from the previous tree) |
| lines moved with no source change | 4,596 (`unicode`) |

The second row is the experiment that justified the exercise: the previous tree's
`crypto` is 4,606 lines and 64 tests, and it crossed the boundary with
`use crate::Error` becoming `use abi::Error`.  The tests are the same tests, they
run on a host instead of needing a boot, and they still fail when the code is
wrong — flipping one SHA-256 initial constant turns five of them red.

## What the gates hold

| Gate | Question |
|---|---|
| `check-layering.sh` | does every dependency point downward? |
| `check-arch-fanout.sh` | does anything outside `arch/` know which machine it is? |
| `check-crate-tests.sh` | does every crate with code have tests, and has none lost any? |
| `xtask check` | does the image reach its console, its heap, and a file read through the syscalls? |

The first three are censuses: each records a number, refuses growth, and refuses a
stale row.  A ratchet moves in the change that moves it, with its argument in the
baseline's own prose — which is why `scripts/layering.txt` is longer than the list
of crates it describes.

## Two failures this arrangement was built against

**A crate boundary can hide a gate.**  The architecture census counted
`target_arch` names in `src/`, and when the shared tree became a crate at
`shared/` its ten gates moved out of the census with it; the baseline then read
as "these shrank to zero" rather than "the gate stopped looking there".  Every
census here now walks the whole tree, and a row whose file no longer exists fails.

**A gate that makes a build succeed can hide the code.**  Two architecture crates
carried `#![cfg(target_arch = "…")]` at the crate root so a host build would not
assemble `wfi` into an x86 binary.  It also made both crates entirely empty on a
host, *including their tests* — which reported zero, and had never been compiled
once.  The gate was removed; the modules keep their own `cfg(target_os)` arms, and
the host arms do something testable rather than nothing.

## Adding a crate

1. Pick the layer by what the crate *is*, not by what it happens to need.  If it
   needs something above it, either the layer is wrong or the dependency is.
2. Add it to `scripts/layering.txt` with the argument.  The gate refuses a crate
   the spec does not name.
3. Give it a test.  The gate refuses a crate above a small size with none, unless
   its row says why it cannot have one.
4. Add it to `scripts/crate-tests-baseline.txt` with `--record`, in the same
   change.
