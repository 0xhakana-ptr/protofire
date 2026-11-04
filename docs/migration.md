# What has moved in, and what has not

This tree replaces a single crate.  The migration is not a rewrite and not a
copy: each subsystem moves in as a crate of its own, with its tests, once it
can be built and exercised on its own.  This document is what has moved.

There is deliberately no size column.  A line count is wrong the moment the
next change lands, and a document that is wrong is a bug in this tree — where a
number would be, the table says what is here, and that is the claim worth
keeping true.

## The table

| Subsystem | What is in |
|---|---|
| `abi` | the whole wire format, and the syscall numbering |
| `arch` | boot, interrupts, serial, port I/O, page tables, the exception path, IDT, the GDT and TSS, the local APIC and its timer, the 8259, the PL011, the device-tree handshake, the GIC, ring 3 on both bootable machines |
| `crypto` | all of it, one module per algorithm — it is a `libs` crate, like `unicode` |
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
| ISO 9660 | **yes**, read-only — rewritten, not moved |
| ext4 | no |
| F2FS | no |
| FAT32 | no |
| exFAT | no |
| btrfs | no |
| squashfs | no |
| the VFS layer | contract only — see below |
| tmpfs | **yes** |
| FUSE | no |

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
rest.  The previous tree had a reader and a *writer* — a writer for a writable
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
and raw sockets.  The order it comes in is bottom-up — link, then internet,
then the transports — because each layer's tests need the one below it.

## Architecture

A handful of modules out of the many a machine's support actually needs.  The
previous tree's `arch` had `pci`, `fdt`, `trap`, `mmu`, `percpu`, `smp`,
`thread`, `user_access`, `syscall_trap`, `ptrace` and more.

What is here is what a boot needs before anything else: the entry, the console,
the interrupt flag, the page-table encoding, the exception path, the port I/O
the PCI bus is reached through, and — on both bootable machines — ring 3, a
timer and a preempting scheduler.

Both machines now reach a program at ring 3, and the two halves differ enough
to say where.  x86_64 needed a descriptor table with a DPL-3 code and data
segment, a task state segment whose `RSP0` names the stack every ring-3
interrupt lands on, a call gate at `DPL` 3, and a `cr3` write to switch
address spaces.  Its timer is the local APIC's, calibrated against the PIT, and
its monotonic clock is the TSC — the APIC's own count runs *down* and reloads,
which is not a deadline and cost a boot its wakes.

What comes next is the blocking `read`, which needs a pipe to park a reader on
that `sleep` does not — `sleep` has a deadline and a wake, and a pipe has a
writer and no clock.

### The timer, and three reasons it looked broken

    protofire: timer armed at 1000000 ticks/ms
    protofire: every program exited, 2 exit(s), 5 tick(s), 5 switch(es)
    protofire: the timer preempted, 4 switch(es) from ticks

`arch/aarch64/src/timer.rs` is the generic timer: `CNTFRQ_EL0` for the
frequency, `CNTPCT_EL0` for the counter, `CNTP_TVAL_EL0` for a countdown.  The
countdown and not the compare value, because a deadline computed from a counter
read that arrived one tick late is a deadline in the past — which fires
immediately and looks like a timer that ignores its interval.

Four things were wrong before it worked, and each looked like the previous one's
symptom:

1. **The interrupt was in group 1 and QEMU did not deliver it.**  Every register
   read back correct — enabled, group 1, priority `0x80`, edge-triggered, both
   CPU-interface groups on, `PMR = 0xff` — and `GICD_ISPENDR0` showed bit 30
   **pending** while `GICC_IAR` answered `1022` (spurious) forever.  The same
   interrupt in group 0 delivers.  That is written down in `gic.rs` at the
   place it is decided, because a reader who finds a PPI in group 0 will want
   to know it is not an oversight.

2. **`SPSR_EL1` masked IRQ at EL0.**  The constant was `0x3C0`, which sets
   `D`, `A`, `I` and `F`; a program running with `I` set never takes a tick, so
   preemption would have been a scheduler the kernel believes in and the
   machine never invokes.  It is `0x340` — the same three masks and `I` clear.

3. **The timer was armed before the boot finished.**  Every tick during the
   remaining EL1 setup took a full 800-byte trap, and the boot stopped in the
   middle of a console line: `program 1 mappe`.  It is armed at the last moment
   before `eret` into EL0.

4. **A console write was not atomic.**  `write_str` is dozens of byte writes and
   a tick between two of them ran another program that printed — so one line
   came out interleaved with another's.  It now masks IRQs for its duration and
   restores what was there, which is what `sync` already does for every other
   piece of kernel state.

**The first check could not fail, twice.**  The timer's line was reported as
firing from a counter the boot incremented itself; it now counts what the
handler sees.  And the boot's total said `1 switch(es)` — one, from the first
exit — whatever the timer did, so a scheduler that never preempted printed
exactly what one that did printed.  The boot now says which happened: with the
preemption sink removed it prints `the timer did not preempt`, and the gate
requires the other line.

Three mutations were run and all three are visible in a boot: removing the
preempt sink leaves the ticks and drops the switches to one; masking IRQ at EL0
drops the ticks; and the program's busy loop had to be lengthened because one
register's 16-bit immediate is twelve microseconds, which is shorter than a
slice.

### Two programs, two address spaces

    protofire: program 1 mapped at 0x8040000000
    protofire: program 2 mapped at 0x8080000000
    protofire: entering ring 3
    program 1 says hello
    program 2 says hello
    protofire: every program exited, 1 switch(es), 2 exit(s)

A program's pages live above `0x80_0000_0000`, which is root entry 1 — one entry
past this kernel's identity map.  So a program's root table holds the kernel's
entry 0 unchanged, and every kernel address translates identically in every
space.  That is the whole economy of it: a root that copied the identity map
instead would spend a hundred and thirty thousand frames per program to share
what is already shared.

A task switch is therefore two copies and one system register — save the frame
into the running task, copy the next one's over it, write `TTBR0_EL1` if the
space changed.  There is no assembly, because the assembly that matters is the
epilogue every trap already runs through: it restores whatever frame it finds
and `eret`s, including the exception level.

`eret` carries no address-space identifier.  An ASID would let two roots'
translations coexist in the TLB and remove the flush; it also has to be
allocated, kept unique and cleared at the right moment, and this kernel has one
CPU and a switch per program exit.  The flush is the cheap correct answer.

**A `Write` that switched the task was the first version, and it was wrong in a
way the log did not show.**  Both programs printed their lines, so it looked
right.  Underneath, `advance` replaced the frame with the other task's context
and then the handler wrote *its own* answer into that context's `x0` and
answered `Return` — so the program resumed was the other one, with its `x0`
overwritten by a value meant for this one, and the exit never happened.  Only
`Exit` switches now, which is also the honest policy: a program that made a call
and got its answer has no reason to lose the CPU.

Two mutations were run and both stop the boot, which is what makes the switch
real rather than nominal.  Deleting the `TTBR0_EL1` write leaves program 2's
entry unmapped in program 1's space, and the boot stops at
`instruction abort at 0x8080000000`.  Deleting the context restore resumes
program 1 — at `0x8040000018`, after its `mov` — inside program 2's space, and
the boot stops at `instruction abort at 0x8040000018`.  Neither program can
reach the other's memory, and both can reach the kernel's.

### A program at EL0

    protofire: entering ring 3
    protofire: program mapped 1
    hello from ring 3
    protofire: program exited with 0

Thirty-two bytes of AArch64, mapped `user`, entered with an `eret` that names
EL0, and its `svc` served and resumed.  It is the first thing in this tree that
does not run at EL1.

The program is written as words with a table of what each one encodes, and the
bytes were disassembled by `llvm-objdump` before they were written down — a
program encoded by hand is one the machine fetches as different instructions,
and the failure would be a trap at a plausible address rather than a message.

**The first version of it could not fail.**  It called `Write`, ignored the
answer, and exited zero.  Deleting the trap path's write-back of `x0` changed no
output at all: the boot printed the same three lines.  The program now compares
`x0` against what `Write` answered — seventeen, the length of the line — and
exits two when the comparison fails.  Deleting the write-back makes it exit two,
and the gate requires the exit status exactly.

Two mutations were run against the entry path and both failed as they should.
Setting `SPSR_EL1` to EL1h instead of EL0t leaves the program's page mapped
`user` with no EL1 execute permission, and the boot stops at
`instruction abort at 0x1000000` — which is the `user` bit being real rather
than decorative.

What is not here: a second program.  `enter_user` does not return and `Exit`
stops the machine, because there is no scheduler to run next and no address
space to switch to.  The page is in the kernel's own table with `user: true`;
that protects the kernel from the program and does not protect one program from
another.

### x86_64 at ring 3, and the four pieces it needed

    protofire: descriptor tables installed, TSS loaded
    protofire: interrupt from the controller delivered to the timer's handler
    protofire: program 1 mapped at 0x8040000000
    protofire: program 2 mapped at 0x8080000000
    protofire: entering ring 3
    program 1 says hello
    program 2 says hello
    protofire: every program exited, 2 exit(s), 6 tick(s), 3 switch(es)
    protofire: the timer preempted, 2 switch(es) from ticks

`enter_user` was `unreachable!` and its comment named what was missing: a TSS
with an `RSP0`, a DPL-3 segment and a DPL-3 gate.  Each is a separate thing and
each failed differently before it was right.

**The descriptor bits were in the wrong half of the word.**  The type byte,
`S`, the DPL and `P` are the descriptor's second byte as the processor reads
it — bits 40..47 — and the first version wrote them at bits 8..15, which is the
limit's low half.  The processor refused the first `mov ds` with a general
protection fault carrying selector index 2.  What found it was `-d int`: the
fault was `v=0d e=0010` at the `mov %ax,%ds` one instruction after a `lgdt`
that had *already succeeded*, which is only possible if the table loaded and
the descriptor in it was wrong.  The table's words are now asserted against the
boot's own literals, which is the oracle that was missing.

**The gate's DPL was 0 on every vector.**  A gate at DPL 0 refuses `int $0x80`
from ring 3 with a protection fault.  The system call vector is now the one
gate at DPL 3, and the boot raises it from ring 0 to prove the stub and the
frame before any program runs.

**The frame held nine registers.**  The nine a Rust function may clobber is all
a *handler* needs; a *switch* needs every register, because the frame is copied
and the callee-saved eight are what a compiled program keeps its locals in.
The stub now saves fifteen, and `context.rs` asserts the fifteen offsets
against the assembly.

**The timer's count is not a clock.**  x86_64's first `sleep` never woke:
`timer_counter()` answered the APIC's current count, which runs *down* and
reloads on every fire, so `now >= deadline` was never true.  It is the TSC now,
which counts up and never resets, like the register aarch64 reads.

The rate and the countdown are separate questions, so they are separate
functions: `clock_frequency` is how fast the counter counts and
`timer_frequency` is how fast the timer counts down.  Measured on one boot they
are not the same number — the counter runs at about 2.6 GHz and the APIC's
countdown at about 1 GHz — so a duration converted with the wrong one is a
deadline that is short by that ratio.  A twenty-millisecond sleep absorbed it
and a boot passed either way, which is why the split is a signature that says
what it means rather than a defect this found.

### A race in `enter_user`, found at four thousand ticks a second

A short time slice — twenty microseconds instead of a hundred — made aarch64
fail about one boot in three, at a kernel address, from EL0, with `spsr 0x340`.
The baseline at that commit failed six times in fifteen, so the defect predated
the change that exposed it.

The address was inside `enter_user`'s own asm block, and that is the whole
explanation.  The three `msr`s and the `eret` are one transaction, and
`enter_user` ran with interrupts enabled.  A tick in that window is taken at
EL1, so `entry.S` saves the interrupted `ELR_EL1`/`SPSR_EL1` **and restores them
on the way out** — clobbering the entry that had just been written.  The `eret`
then returned to whatever the tick interrupted, which is inside `enter_user`,
at EL0, because the `spsr` had been rewritten to EL0t again.

`daifset #2` around the window is the fix, and `eret` needs no matching unmask:
it loads PSTATE from `SPSR_EL1`, which names EL0t with `I` clear.  Fifteen
boots at the same slice after the fix, zero failures.

x86_64's entry has the same shape — five pushes and an `iretq` — but it was
**not** given the same treatment, because the reasoning does not carry over and
the measurement said so.  An x86_64 exception pushes and restores
`RFLAGS` through the frame the stub builds, and that frame is the one the
kernel's own `int $0x80` handler already owns, so a tick in the window would be
served and returned rather than clobber the entry.  A `cli` was added there
while chasing the sleep fault and removed when a mutation showed the boot
takes its ticks with or without it.

### Sleeping, and the two ways to be not-runnable

    protofire: a program sleeps until counter 632293560
    protofire: a program sleeps until counter 633478228
    protofire: every program is asleep, waiting
    program 2 says hello
    protofire: a program woke, 1 of them
    program 1 says hello

A task now has three states rather than a `finished` flag: runnable, sleeping
until a counter reading, finished.  The third is not "finished with a
timestamp" — a sleeping task is runnable *later*, and a scheduler that could
not tell the two apart would either wake a dead program or never wake a live
one.

`Sleep` is the first call that does not answer immediately, and its handler is
the only place the two meanings of `Exit` are distinguished.  `advance` answers
`Exit` when nothing is selectable, which happens both when every task has
finished and when every task is asleep; the first means stop the machine and
the second means wait for a tick.  So the handler asks `has_other_runnable` and
`has_sleeping`, and the waiting case idles in `wfi`/`sti;hlt` until the timer
turns a deadline into a runnable task.

The deadline is a counter reading, not a duration, and it is the same counter
`wake_expired` compares — which is why the platform with a countdown timer
needed the TSC.  The wake check runs in the timer's handler **before** the
preemption hook, because a task that has finished sleeping is runnable now and
a pass that ran first would find nothing and stop the machine with work left.

**The frame is saved by `sleep_until` itself, and that is the one change this
needed.**  Leaving it to whichever scheduling call happened next was correct
only while a call always happened; with every task asleep the boot idles
instead, and the sleeper then resumed at whatever position its context last
held — which was the `Sleep` call.  The log showed program 2 printing its line,
sleeping, waking, and printing the same line again, for ever.

Everything else in this area was diagnosis, and a mutation says so: reverting
the end-of-interrupt predicate to "the timer's vector only" passes the gate,
reverting `switch_without_saving` to `advance` passes it, and so does an idle
loop that asks `has_runnable`.  Each of those was a change made while chasing
the fault and each turned out to be unnecessary once the frame was saved where
it belonged.  They are kept because they are the more honest statements of what
the code means — an APIC ends every vector it delivered, not just the timer's,
and a boot's idle does not own a frame to save — and not because a boot fails
without them.

### The frame allocator, and the loop it breaks

`memory/src/frame.rs` tracked free ranges in a `BTreeMap`.  That is the right
shape for an unbounded set and the wrong one here for a reason that is not about
speed: **this allocator hands out the frames a page table is built from, and a
page table has to exist before the heap does.**  A free list that needed `alloc`
could not run when it was most needed, and the way that showed was the kernel
working around it — building its tables in a `static` array with a bound nobody
had justified.

The free list was replaced twice, and the second attempt is the instructive one.
A sorted array of a fixed number of ranges dropped `alloc` and **broke a test
that existed to say why the map was there**: freeing every other frame of two
hundred leaves a hundred separate holes, and a `deallocate` with nowhere to put
one answers `false` and loses the frame.  A free list that drops memory under
fragmentation is worse than one that cannot be built.

One bit per frame is the shape that is both fixed-size and unbounded in
fragmentation: sixteen kilobytes for the pool, no heap, and the number of holes
is the pool's size rather than a constant somebody picked.  `MAX_NODES` was in
the file and unused, which is what a bound looks like when the implementation
stops honouring it.

`arch::managed_pool_bytes` was named by that file's own documentation and
implemented by no machine.  It is now: aarch64 sums the device tree's memory
regions, x86_64 answers `None` because its boot does not parse the multiboot2
memory map, and riscv64 answers `None` because it has no entry.

`address_space` takes a table from the pool once its two spare tables are used.
That branch has not run on this machine, and the boot says so — `0 in page
tables` — rather than letting a zero read as a success.  The allocator itself is
exercised: the boot allocates a frame, checks it is zeroed, releases it, and
compares the free count before and after.  Deleting the release makes it print
`pool check FAILED`, which the gate refuses.

### MSI-X: the encoding, and the hop that does not arrive

`drivers/bus/pci/src/msix.rs` is the MSI-X capability and table: the three
structures, the entry layout, and the two bits in message control that are
different — 15 enables the feature and 14 says the function must not fall back
to its INTx pin.  An entry's mask bit is set-means-masked, the opposite of every
other enable bit in PCI.  The table size register holds the count *minus one*.

Five defects were fixed while writing it, and four were in the test fake:

- The message control register is the **high half** of the dword at the
  capability's offset; its low half is `cap_id` and `cap_next`, which are
  read-only.  Writing the control into the low half corrupts the capability id
  and leaves the enable bit where the device is not looking.
- The table size register was read as a count rather than a count minus one.
- The fake's register file was too small for offset `0x98`.
- The fake wrote `1` into the size field to mean "one entry", which is two.

`arch/aarch64/src/gicv2m.rs` is the frame: `MSI_TYPER` holds two ten-bit fields
— the first interrupt and the count — and `MSI_SET_SPI` is an array where the
**address** selects which interrupt a write raises, not the payload.  The boot
reads `MSI_TYPER` and reports what it found: `msi frame raises 80 interrupt(s)
from 64`, which is `0x0050_0040` decoded and not assumed.

**A write to `MSI_SET_SPI` does not raise an interrupt on this machine.**  The
frame is real, its registers read, and QEMU reports it as `arm-gicv2m` with 64
interrupts from SPI 48.  Every prerequisite was then checked, and each was
either already correct or irrelevant:

| checked | how | result |
|---|---|---|
| the window is mapped | `MSI_TYPER` reads `0x0050_0040` | mapped, readable |
| the line is enabled | `GICD_ISENABLER0+8` bit 0 | set |
| the line is group 1 | `GICD_IGROUPR0+8` bit 0 | set |
| the line is edge-triggered | `GICD_ICFGR2` bit 1 | set |
| the distributor is on | `GICD_CTLR` | `0x3`, both groups |
| the CPU interface is on | `GICC_CTLR`, `GICC_PMR` | `0x1`, `0xff` |
| interrupts are masked | `DAIF` | clear |
| the controller is GICv2 | `GICD_PIDR2` bits 7..4 | `2` |
| the secure alias was the problem | wrote `0x0040` instead of `0x0000` | neither acts |
| the number was wrong | enabled 64, and 48 and 80 from `base-spi` | none arrives |
| the write is what does it | wrote the same address from QEMU's monitor | nothing |

`ISPENDR` stays zero throughout, so **the frame produces nothing at all** — this
is not a delivery problem and no amount of distributor configuration reaches it.
QEMU's frame also answers zero to every identification register (`PIDR2` at
`0xfe8` reads `0`), which a real GICv2m would not.

The honest conclusion is that this QEMU build's `arm-gicv2m` does not act on the
write, and the reason was not found.  The boot test was removed rather than left
passing vacuously, and the two crates stay: they are arithmetic over a
specification and that half is tested.  A driver built on a mechanism that has
never been seen to work would be the defect this file keeps recording.

The GIC itself is not in question: the software-generated interrupt above
travels the whole path, and that is the half MSI-X shares.

### The interrupt controller, and the probe that could not fail

An aarch64 boot now takes an interrupt:

```
protofire: interrupt table installed, interrupts on
protofire: interrupt delivered to its handler
```

`arch/aarch64/src/gic.rs` is the GICv2 register layer: the distributor decides
which lines exist and which CPU they go to, the CPU interface is what this core
acknowledges and finishes through, and the two are different windows.  The
arithmetic is the specification's, and the two arrays a driver must reach do not
share a divisor — `ISENABLER` holds 32 interrupts per register and `IPRIORITYR`
holds **four** — so a driver that used 32 for both enables the right line and
sets the priority of a different one.

The dispatcher now tells an IRQ from a fault: the vector is `(group * 4) +
kind`, so `vector % 4 == 1` is an IRQ whatever its group, and that path
acknowledges, hands the number to the sink, and finishes.  Returning without the
finish leaves the line active and the machine taking exactly one interrupt —
which is why the finish is not on the handler's honour.

**The probe could not fail, and that is the defect worth recording.**  The boot
raises an interrupt from the controller and a handler counts it.  The first
version raised interrupt **zero** and initialised its counter to **zero**, so a
boot that raised nothing printed exactly what a boot that raised something
printed.  Deleting the write that raises it changed no output at all.  The
counter now starts at `usize::MAX`, and deleting the write prints
`raised but not delivered`.

Two things were learned from the controller's own behaviour while doing this:

- **`GICD_SGIR` raises only interrupts 0..16.**  It has no field for a device
  line, because a device raises its own.  The first version asked it for
  interrupt 40, wrote an SGI id the distributor did not route, and then had to
  reconcile "the path works" — an unclaimed PPI arrived on its own and was
  reported — with "my interrupt never came".  The path an SGI takes is the same
  one a device's takes, so it is the right instrument and the only one.

- **A PCIe `interrupt-map` did not resolve, and was left out rather than
  guessed at.**  The entries are `key + phandle + parent specifier`, and QEMU's
  `virt` writes a parent specifier wider than the GIC's declared
  `#interrupt-cells` — five cells against three.  A parser that assumed three
  read the next entry's key as part of the controller's number.  Rather than
  ship a table that resolved one pin out of four, the function was removed; the
  number a PCI function raises is still an open question, and the answer is the
  one the map states.

### PCI enumeration, and the six defects that were hiding behind "not mapped"

QEMU's `virt` has a PCIe host bridge and no firmware, so every BAR comes up
unaddressed.  Reading a capability was possible after the device tree arrived;
reaching the device behind it needed the assignment pass a firmware would have
run — size each BAR, allocate from the bridge's `ranges` window, write it back,
verify.

The aarch64 boot now writes a sector and reads it back:

```
protofire: pci bars assigned 4, kept 0, no room 0, refused 0
protofire: block device from virtio-blk on pci
protofire: virtio-blk wrote and read back sector 63
```

Six things were wrong, and only one of them was the feature:

1. **`bar::size` treated a zero register as "no BAR".**  An unaddressed BAR
   reads zero.  On a machine with firmware that is unusual; on a device-tree
   machine it is the *normal* state, so the early return turned every device
   into no device.  The current value cannot answer whether a BAR exists — only
   the device can, and the way to ask is a sizing write.

2. **The 32-bit mask was not widened.**  A 32-bit BAR's mask came out as
   `0x0000_0000_FFFF_F000`, whose complement plus one is
   `0xFFFF_FFFF_0000_1000` — not a power of two, so every 32-bit BAR sized as
   absent.  The mechanism's answer is a 64-bit mask whatever the BAR's width.

3. **The type bits were read from the register, not the mask.**  Those bits are
   wires: they survive a sizing write and do not survive an address write.  A
   decoder that used the current value called every unassigned 64-bit BAR 32-bit
   and tried to place it below four gigabytes.

4. **Nothing above four gigabytes was mappable.**  The identity map stopped
   there, so a PCIe ECAM window at `0x40_1000_0000` had nowhere to go.
   `map_region` now creates a 2 MiB block table for a region above the limit.

5. **A mapping was made and the TLB was not told.**  `flush_translation` is now
   part of `map_region`, and each machine spells it: `tlbi vmalle1` on aarch64,
   a `cr3` rewrite on x86_64, `sfence.vma` on riscv64.

6. **The transport was built on a `PortConfig` while the scan ran over ECAM.**
   A port that does not exist answers `0xFFFF_FFFF`, so the capability walk
   visited forty-eight structures whose type was `0xFF` and reported the device
   as having no `Common` capability.  The scan and the transport must agree
   about the mechanism, and now they are handed the same one.

The sixth is the one worth keeping: it was introduced by *this* change, in the
same function that added the mechanism choice.  A diagnostic line — `the walk
saw 48 structure(s), types 255 255 …` — is what named it, and that line is now
part of the error rather than a probe.

Two smaller things fell out.  `Device::bars` returns **slots**, and a PCI
capability's `bar` field counts **registers**; a 64-bit BAR occupies one slot
and two register numbers, so indexing the slot array with a register number
reaches the wrong window.  `Device::bar_register` is the lookup that matches.
And a capability's `bar` field is at `+4`, `offset` at `+8`, `length` at `+12` —
the previous version read them one dword too far.

### The device tree, and the four bugs it exposed

`libs/fdt` is the format — header, structure block, strings block, and the walks
over them — and `arch/aarch64` is what records the pointer firmware left in
`x0`.  The split is the tree's own rule: a format is not a machine, and the same
bytes are read by a host test that has neither.

Parsing it turned four things from constants into questions, and each question
found a defect:

1. **The console's address.**  `serial` now asks the tree for
   `arm,pl011` and falls back to `0x0900_0000` for a boot whose blob did not
   parse.  The boot line says which path ran, which is how the two states are
   told apart in a log.

2. **The device windows.**  `paging::device_windows` was a constant range.  It
   now asks the tree where **memory** is and treats everything else as a
   device — the complement, not a list, because a list has to grow before the
   device it is missing can work and its failure is an intermittently stale
   register read.

3. **The PCIe ECAM window.**  `pci::EcamConfig` is a second `ConfigSpace`: the
   port mechanism is x86_64's and a device-tree machine has a memory window
   instead.  Everything above — enumeration, capability walks, BAR decoding —
   is unchanged, which is what the trait was for.

4. **`TCR_EL1.IPS`.**  `ips_for_parange` mapped `PARange` to `IPS` as if the two
   registers numbered sizes differently.  They do not: the encoding is the
   identity.  A machine reporting 40 bits was programmed with 36, and the first
   access to a PCIe ECAM window at `0x40_1000_0000` — 275 GiB — faulted with
   `DFSC = 0b000010`, *address size fault, level 2*.  The test that had been
   asserting the wrong mapping is now the table a reader can check.

Five more defects fell out of making the machine reach further, and none of them
was the device tree's:

- **`all_compatible` used a fixed stack of 32.** QEMU's tree has 51 children
  under its root, so it found 28 of the 32 `virtio,mmio` transports and every
  fixture-based test passed.  The walk is a cursor over the structure block now,
  which is the order the format already stores, with a depth stack only for the
  cell widths.
- **A node's `#address-cells` governs its children, not itself.**  Its own `reg`
  is decoded with its parent's.  The first version got this backwards and read
  the PCIe bridge's `reg` as three cells: `0x0040_1000_0000_0000`, a number, so
  nothing failed.
- **Capability structures were read one dword too far.**  `bar` is at `+4`,
  `offset` at `+8`, `length` at `+12`; the first version read them from `+4`,
  `+8` and `+12` as if `bar` were a dword of its own.
- **`(word >> (shift + 8))` overflowed at `shift = 24`**, which panicked the boot
  on a capability structure at offset `0x1C`.
- **A panic printed nothing.**  `bootloader`'s handler called `arch::halt()` and
  stopped.  A boot that ended mid-log looked identical to one that finished, and
  this cost a session: the shift-overflow panic above happened after the scan
  line with no message at all.  The handler now prints.

`qemu-virt.dtb` in the parser's test assets is firmware's own bytes, not `dtc`'s
rendering of a source file — a generator and a parser written from one reading
of a specification agree with each other, and only firmware disagrees when that
reading is wrong.  It is what caught the stack bound.

### Translation is on, and how it was found not to be

Until this change `arch_aarch64::paging::install` wrote `MAIR_EL1` and
`TTBR0_EL1` and returned `true`, and the boot printed "page table built and
installed, 4 KiB granule" about a table no access went through: `SCTLR_EL1.M`
was never set.  That is the defect this file keeps recording — written, wired,
never executed — and it was found by reading the function rather than by a
gate, because the line it printed was true about the register and false about
the machine.

Turning translation on took three fixes, and each was found by QEMU's exception
log rather than by reasoning:

1. **The table descriptors carried leaf fields.**  `encode_at` set `AF`, `AP`,
   the attribute index and `UXN`/`PXN` on every descriptor; the architecture
   calls those bits Ignored in a table descriptor.  Invisible while nothing read
   a descriptor.  A table descriptor is now its address and its type.
2. **`EntryEncoding::encode` had no level.**  aarch64 writes a 4 KiB page
   descriptor and a 1 GiB block descriptor with different low bits, so the
   implementation hard-coded `Level::Third` — and the kernel builds four
   levels, so every page became a block.  The trait takes a level in both
   directions now, and the other two machines accept and ignore it with the
   reason written down.
3. **`TCR_EL1.T0SZ` was 25.**  That is a 39-bit space, which is a three-level
   table; this kernel's root is a level 0 table and needs 16 (48 bits).  With
   25, the machine indexed `TTBR0_EL1` as a level 1 table, never read entry 0,
   and the first fetch faulted with `DFSC = 0b000101`,
   *translation fault, level 1* — the log line that named the constant.

The aarch64 boot now prints the same nine lines with the MMU on.  Setting
`TCR_T0SZ` back to 25 stops it after `protofire: page table`, so those lines are
evidence that translation is in use rather than a coincidence.  A test,
`the_address_size_matches_the_table_depth`, derives the required value from
`Level::Root::shift()` instead of restating it.

### Device windows

Turning the MMU on changes what an unruled address *means*.  With translation
off every access is device-like; with it on, an address with no rule is Normal
memory — cached and prefetchable — and the PL011's status register read from a
stale cache line is a console that prints nothing for a reason that looks like a
dead UART.

`arch::paging::device_windows()` is the machine's answer: aarch64 returns
`0x0000_0000..0x4000_0000` — everything below `virt`'s RAM — and x86_64 returns
an empty slice, because it learns its device addresses from a bus and re-maps
them one BAR at a time.  `kernel::address_space` turns that answer into a
permission, which is the division the tree already has: `arch` says what the
machine is, the kernel says what to do about it.

The aarch64 range is a constant of `qemu-system-aarch64 -machine virt`.  It is
the honest form of "this is the machine the boot gates run on", and the parse of
the device tree is what turns it into a query.

### The aarch64 boot, and what it cost

`entry.S` does four things before Rust: a stack, the bss clear, the drop from
EL2 to EL1, and `CPACR_EL1.FPEN`.  The last one is there because the boot that
did not do it **printed four lines and stopped**, and the reason took a QEMU
exception log to find: `ESR_EL1.EC` = 7 at a `0x0E01...` word, which is a NEON
instruction LLVM emitted for the `memcpy` inside `PyroFS::build_image`.  Every
line before that was scalar code, which is why the failure looked like a
filesystem problem.

The lesson is the one this file keeps recording: a machine's boot is exercised
or it is not, and building an image is not exercising it.  `scripts/verify.sh`
now boots **every** machine with an image, so the next boot that stops early is
a red gate rather than a line someone happened to notice.

The trap path is real: `entry.S` saves `x0`..`x30`, `ELR_EL1`, `SPSR_EL1`,
`ESR_EL1`, `FAR_EL1` and `q0`..`q31` into an 800-byte frame, calls
`aarch64_exception_dispatch`, and `eret`s.  `install_interrupt_table` does not
report success from writing `VBAR_EL1` — it raises a supervisor call first and
answers `true` only if the call arrived at entry 4 and returned.  A probe that
cannot fail is not evidence, so the probe was mutated (the expected vector
changed to 8) and the boot line went back to "not installed".


## Kernel

The boot sequence, the syscall table, the scheduler and device discovery.

The scheduler and the process layer are here: a round-robin rotation over tasks
whose saved context is the trap frame, with a timer that preempts and a sleep
that parks a task on a deadline.  What they do not have is the part of a process
layer that needs the other subsystems — a handle table belongs to a process and
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
