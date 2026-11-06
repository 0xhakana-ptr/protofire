# What has moved in, and what has not

This tree replaces a single crate.  The migration is not a rewrite and not a
copy: each subsystem moves in as a crate of its own, with its tests, once it
can be built and exercised on its own.  This document is what has moved.

There is deliberately no size column.  A line count is wrong the moment the
next change lands, and a document that is wrong is a bug in this tree, where a
number would be, the table says what is here, and that is the claim worth
keeping true.

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

### The timer, and three reasons it looked broken

    protofire: timer armed at 1000000 ticks/ms
    protofire: every program exited, 2 exit(s), 5 tick(s), 5 switch(es)
    protofire: the timer preempted, 4 switch(es) from ticks

`arch/aarch64/src/timer.rs` is the generic timer: `CNTFRQ_EL0` for the
frequency, `CNTPCT_EL0` for the counter, `CNTP_TVAL_EL0` for a countdown.  The
countdown and not the compare value, because a deadline computed from a counter
read that arrived one tick late is a deadline in the past, which fires
immediately and looks like a timer that ignores its interval.

Four things were wrong before it worked, and each looked like the previous one's
symptom:

1. **The interrupt was in group 1 and QEMU did not deliver it.**  Every register
   read back correct, enabled, group 1, priority `0x80`, edge-triggered, both
   CPU-interface groups on, `PMR = 0xff`, and `GICD_ISPENDR0` showed bit 30
   **pending** while `GICC_IAR` answered `1022` (spurious) forever.  The same
   interrupt in group 0 delivers.  That is written down in `gic.rs` at the
   place it is decided, because a reader who finds a PPI in group 0 will want
   to know it is not an oversight.

2. **`SPSR_EL1` masked IRQ at EL0.**  The constant was `0x3C0`, which sets
   `D`, `A`, `I` and `F`; a program running with `I` set never takes a tick, so
   preemption would have been a scheduler the kernel believes in and the
   machine never invokes.  It is `0x340`, the same three masks and `I` clear.

3. **The timer was armed before the boot finished.**  Every tick during the
   remaining EL1 setup took a full 800-byte trap, and the boot stopped in the
   middle of a console line: `program 1 mappe`.  It is armed at the last moment
   before `eret` into EL0.

4. **A console write was not atomic.**  `write_str` is dozens of byte writes and
   a tick between two of them ran another program that printed, so one line
   came out interleaved with another's.  It now masks IRQs for its duration and
   restores what was there, which is what `sync` already does for every other
   piece of kernel state.

**The first check could not fail, twice.**  The timer's line was reported as
firing from a counter the boot incremented itself; it now counts what the
handler sees.  And the boot's total said `1 switch(es)`, one, from the first
exit, whatever the timer did, so a scheduler that never preempted printed
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

A program's pages live above `0x80_0000_0000`, which is root entry 1, one entry
past this kernel's identity map.  So a program's root table holds the kernel's
entry 0 unchanged, and every kernel address translates identically in every
space.  That is the whole economy of it: a root that copied the identity map
instead would spend a hundred and thirty thousand frames per program to share
what is already shared.

A task switch is therefore two copies and one system register, save the frame
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
answered `Return`, so the program resumed was the other one, with its `x0`
overwritten by a value meant for this one, and the exit never happened.  Only
`Exit` switches now, which is also the honest policy: a program that made a call
and got its answer has no reason to lose the CPU.

Two mutations were run and both stop the boot, which is what makes the switch
real rather than nominal.  Deleting the `TTBR0_EL1` write leaves program 2's
entry unmapped in program 1's space, and the boot stops at
`instruction abort at 0x8080000000`.  Deleting the context restore resumes
program 1, at `0x8040000018`, after its `mov`, inside program 2's space, and
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
bytes were disassembled by `llvm-objdump` before they were written down, a
program encoded by hand is one the machine fetches as different instructions,
and the failure would be a trap at a plausible address rather than a message.

**The first version of it could not fail.**  It called `Write`, ignored the
answer, and exited zero.  Deleting the trap path's write-back of `x0` changed no
output at all: the boot printed the same three lines.  The program now compares
`x0` against what `Write` answered, seventeen, the length of the line, and
exits two when the comparison fails.  Deleting the write-back makes it exit two,
and the gate requires the exit status exactly.

Two mutations were run against the entry path and both failed as they should.
Setting `SPSR_EL1` to EL1h instead of EL0t leaves the program's page mapped
`user` with no EL1 execute permission, and the boot stops at
`instruction abort at 0x1000000`, which is the `user` bit being real rather
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
it, bits 40..47, and the first version wrote them at bits 8..15, which is the
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
are not the same number, the counter runs at about 2.6 GHz and the APIC's
countdown at about 1 GHz, so a duration converted with the wrong one is a
deadline that is short by that ratio.  A twenty-millisecond sleep absorbed it
and a boot passed either way, which is why the split is a signature that says
what it means rather than a defect this found.

### A race in `enter_user`, found at four thousand ticks a second

A short time slice, twenty microseconds instead of a hundred, made aarch64
fail about one boot in three, at a kernel address, from EL0, with `spsr 0x340`.
The baseline at that commit failed six times in fifteen, so the defect predated
the change that exposed it.

The address was inside `enter_user`'s own asm block, and that is the whole
explanation.  The three `msr`s and the `eret` are one transaction, and
`enter_user` ran with interrupts enabled.  A tick in that window is taken at
EL1, so `entry.S` saves the interrupted `ELR_EL1`/`SPSR_EL1` **and restores them
on the way out**, clobbering the entry that had just been written.  The `eret`
then returned to whatever the tick interrupted, which is inside `enter_user`,
at EL0, because the `spsr` had been rewritten to EL0t again.

`daifset #2` around the window is the fix, and `eret` needs no matching unmask:
it loads PSTATE from `SPSR_EL1`, which names EL0t with `I` clear.  Fifteen
boots at the same slice after the fix, zero failures.

### Sleeping, and the two ways to be not-runnable

    protofire: a program sleeps until counter 632293560
    protofire: a program sleeps until counter 633478228
    protofire: every program is asleep, waiting
    program 2 says hello
    protofire: a program woke, 1 of them
    program 1 says hello

A task now has three states rather than a `finished` flag: runnable, sleeping
until a counter reading, finished.  The third is not "finished with a
timestamp", a sleeping task is runnable *later*, and a scheduler that could
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
`wake_expired` compares, which is why the platform with a countdown timer
needed the TSC.  The wake check runs in the timer's handler **before** the
preemption hook, because a task that has finished sleeping is runnable now and
a pass that ran first would find nothing and stop the machine with work left.

**The frame is saved by `sleep_until` itself, and that is the one change this
needed.**  Leaving it to whichever scheduling call happened next was correct
only while a call always happened; with every task asleep the boot idles
instead, and the sleeper then resumed at whatever position its context last
held, which was the `Sleep` call.  The log showed program 2 printing its line,
sleeping, waking, and printing the same line again, for ever.

Everything else in this area was diagnosis, and a mutation says so: reverting
the end-of-interrupt predicate to "the timer's vector only" passes the gate,
reverting `switch_without_saving` to `advance` passes it, and so does an idle
loop that asks `has_runnable`.  Each of those was a change made while chasing
the fault and each turned out to be unnecessary once the frame was saved where
it belonged.  They are kept because they are the more honest statements of what
the code means, an APIC ends every vector it delivered, not just the timer's,
and a boot's idle does not own a frame to save, and not because a boot fails
without them.

### A pipe, and the first read that waits for a task

A `sleep` waits for a clock.  A pipe waits for *another task*, and the two are
different in every way that matters: there is no deadline to compare, the wake
comes from a syscall rather than from the timer, and the wait ends in three
ways rather than one, bytes arrived, the write end closed, or the wait was
interrupted.  The third is not implemented.

The split is the one `scripts/layering.txt` already described: `ipc::ByteRing`
is the arithmetic and is tested on a host, and the endpoints that park a task
are the kernel's because parking needs the scheduler.  `kernel/src/pipe/mod.rs`
holds the second half and hands bytes to the first.

A task now has a third state.  `Sleeping { until }` ends when the clock passes
a reading; `Blocked` ends when another task says so.  A scheduler that folded
the two together would have to invent a deadline for a wait that has none, and
any number it invented would be a read that gives up early.

**A pointer from ring 3 is a number until something checks it**, and this is
the first call that takes one.  `address_space::is_user_range` asks three
things: the range is in the user window, it does not wrap, and its *end* is in
the window and not merely its start.  What it does not ask is whether the pages
are mapped, a fault is the machine's answer to that, and a walk of the page
tables to know in advance would be the kernel doing what the MMU already does.

**`SP_EL0` was never in aarch64's trap frame**, and that is what the pipe reader
found.  The hardware does not push a stack pointer, so a switch carried every
register but that one, and a program that used its stack resumed with the
previous task's, taking a data abort inside another program's memory.  It was
invisible for as long as no program touched its stack: the announcing programs
call `svc` and never `push`.  The frame is 816 bytes now, with `sp_el0` at the
end so every `q` pair keeps its offset.

The same fault was in `starting_context`, which carried the stack pointer in
`x0`, a register a program overwrites with its first argument.  It is a field
of its own now, and `stack_pointer` reads it.

**`Write` had two meanings under one number.**  The announcing call names a
program in `esi` and has no length; a pipe write names a descriptor in `edi`
and a length in `edx`.  Recognising a pipe by the descriptor alone was wrong
twice: a program's `edi` holds whatever the boot left, zero, and zero is a
valid descriptor once a pipe exists, so the announcement was served as a pipe
write and printed nothing.  A length is what one call genuinely lacks and the
other genuinely has, and that is the test now.

### The idle that could not take a tick

Both machines park a boot in an idle loop when every task is asleep, and both
had to unmask interrupts to do it: `sti` before `hlt` on x86_64, and
`msr daifclr, #2` before `wfi` on aarch64.  A supervisor call arrives through
an interrupt gate, which clears the flag on entry, so the kernel serves the
whole call with interrupts off, and a wait in that window waits for a tick
that cannot be delivered.

aarch64's half was missing and this is how it showed: two programs slept, the
boot printed `every program is asleep, waiting`, and `wfi` returned two hundred
thousand times without a single tick reaching the timer's handler.  The counter
line above it read `187081226` and never moved.

### The frame allocator, and the loop it breaks

`memory/src/frame/mod.rs` tracked free ranges in a `BTreeMap`.  That is the right
shape for an unbounded set and the wrong one here for a reason that is not about
speed: **this allocator hands out the frames a page table is built from, and a
page table has to exist before the heap does.**  A free list that needed `alloc`
could not run when it was most needed, and the way that showed was the kernel
working around it, building its tables in a `static` array with a bound nobody
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
That branch has not run on this machine, and the boot says so, `0 in page
tables`, rather than letting a zero read as a success.  The allocator itself is
exercised: the boot allocates a frame, checks it is zeroed, releases it, and
compares the free count before and after.  Deleting the release makes it print
`pool check FAILED`, which the gate refuses.

### MSI-X: the encoding, and the hop that does not arrive

`drivers/bus/pci/src/msix/mod.rs` is the MSI-X capability and table: the three
structures, the entry layout, and the two bits in message control that are
different, 15 enables the feature and 14 says the function must not fall back
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

`arch/aarch64/src/gicv2m/mod.rs` is the frame: `MSI_TYPER` holds two ten-bit fields, the first interrupt and the count, and `MSI_SET_SPI` is an array where the
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

`ISPENDR` stays zero throughout, so **the frame produces nothing at all**, this
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
share a divisor, `ISENABLER` holds 32 interrupts per register and `IPRIORITYR`
holds **four**, so a driver that used 32 for both enables the right line and
sets the priority of a different one.

The dispatcher now tells an IRQ from a fault: the vector is `(group * 4) +
kind`, so `vector % 4 == 1` is an IRQ whatever its group, and that path
acknowledges, hands the number to the sink, and finishes.  Returning without the
finish leaves the line active and the machine taking exactly one interrupt, which is why the finish is not on the handler's honour.

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
  reconcile "the path works", an unclaimed PPI arrived on its own and was
  reported, with "my interrupt never came".  The path an SGI takes is the same
  one a device's takes, so it is the right instrument and the only one.

- **A PCIe `interrupt-map` did not resolve, and was left out rather than
  guessed at.**  The entries are `key + phandle + parent specifier`, and QEMU's
  `virt` writes a parent specifier wider than the GIC's declared
  `#interrupt-cells`, five cells against three.  A parser that assumed three
  read the next entry's key as part of the controller's number.  Rather than
  ship a table that resolved one pin out of four, the function was removed; the
  number a PCI function raises is still an open question, and the answer is the
  one the map states.

### PCI enumeration, and the six defects that were hiding behind "not mapped"

QEMU's `virt` has a PCIe host bridge and no firmware, so every BAR comes up
unaddressed.  Reading a capability was possible after the device tree arrived;
reaching the device behind it needed the assignment pass a firmware would have
run, size each BAR, allocate from the bridge's `ranges` window, write it back,
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
   into no device.  The current value cannot answer whether a BAR exists, only
   the device can, and the way to ask is a sizing write.

2. **The 32-bit mask was not widened.**  A 32-bit BAR's mask came out as
   `0x0000_0000_FFFF_F000`, whose complement plus one is
   `0xFFFF_FFFF_0000_1000`, not a power of two, so every 32-bit BAR sized as
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
same function that added the mechanism choice.  A diagnostic line, `the walk
saw 48 structure(s), types 255 255 …`, is what named it, and that line is now
part of the error rather than a probe.

Two smaller things fell out.  `Device::bars` returns **slots**, and a PCI
capability's `bar` field counts **registers**; a 64-bit BAR occupies one slot
and two register numbers, so indexing the slot array with a register number
reaches the wrong window.  `Device::bar_register` is the lookup that matches.
And a capability's `bar` field is at `+4`, `offset` at `+8`, `length` at `+12`, the previous version read them one dword too far.

### The device tree, and the four bugs it exposed

`libs/fdt` is the format, header, structure block, strings block, and the walks
over them, and `arch/aarch64` is what records the pointer firmware left in
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
   device, the complement, not a list, because a list has to grow before the
   device it is missing can work and its failure is an intermittently stale
   register read.

3. **The PCIe ECAM window.**  `pci::EcamConfig` is a second `ConfigSpace`: the
   port mechanism is x86_64's and a device-tree machine has a memory window
   instead.  Everything above, enumeration, capability walks, BAR decoding, is unchanged, which is what the trait was for.

4. **`TCR_EL1.IPS`.**  `ips_for_parange` mapped `PARange` to `IPS` as if the two
   registers numbered sizes differently.  They do not: the encoding is the
   identity.  A machine reporting 40 bits was programmed with 36, and the first
   access to a PCIe ECAM window at `0x40_1000_0000`, 275 GiB, faulted with
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
rendering of a source file, a generator and a parser written from one reading
of a specification agree with each other, and only firmware disagrees when that
reading is wrong.  It is what caught the stack bound.

### Translation is on, and how it was found not to be

Until this change `arch_aarch64::paging::install` wrote `MAIR_EL1` and
`TTBR0_EL1` and returned `true`, and the boot printed "page table built and
installed, 4 KiB granule" about a table no access went through: `SCTLR_EL1.M`
was never set.  That is the defect this file keeps recording, written, wired,
never executed, and it was found by reading the function rather than by a
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
   implementation hard-coded `Level::Third`, and the kernel builds four
   levels, so every page became a block.  The trait takes a level in both
   directions now, and the other two machines accept and ignore it with the
   reason written down.
3. **`TCR_EL1.T0SZ` was 25.**  That is a 39-bit space, which is a three-level
   table; this kernel's root is a level 0 table and needs 16 (48 bits).  With
   25, the machine indexed `TTBR0_EL1` as a level 1 table, never read entry 0,
   and the first fetch faulted with `DFSC = 0b000101`,
   *translation fault, level 1*, the log line that named the constant.

The aarch64 boot now prints the same nine lines with the MMU on.  Setting
`TCR_T0SZ` back to 25 stops it after `protofire: page table`, so those lines are
evidence that translation is in use rather than a coincidence.  A test,
`the_address_size_matches_the_table_depth`, derives the required value from
`Level::Root::shift()` instead of restating it.

### Device windows

Turning the MMU on changes what an unruled address *means*.  With translation
off every access is device-like; with it on, an address with no rule is Normal
memory, cached and prefetchable, and the PL011's status register read from a
stale cache line is a console that prints nothing for a reason that looks like a
dead UART.

`arch::paging::device_windows()` is the machine's answer: aarch64 returns
`0x0000_0000..0x4000_0000`, everything below `virt`'s RAM, and x86_64 returns
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
report success from writing `VBAR_EL1`, it raises a supervisor call first and
answers `true` only if the call arrived at entry 4 and returned.  A probe that
cannot fail is not evidence, so the probe was mutated (the expected vector
changed to 8) and the boot line went back to "not installed".

### The riscv64 boot, and the two shifts that look alike

    protofire 0.1.0: entered via dtb, console up, stage 1
    protofire: device tree v17, 1 memory region(s), uart at 0x10000000
    protofire: page table built and installed, 4 KiB granule
    protofire: frame pool 16384 frame(s), 16384 free, 0 in page tables, pool check ok
    protofire: block device from virtio-blk on pci

The third machine boots through the whole of the machine-neutral kernel, device tree, page table, frame pool, heap, the PCI scan, virtio-blk, the
namespace and the MAC policy, on the strength of work that never named it.  What
it needed was an entry, a linker script and the boot's own answers.

OpenSBI hands the image over in S-mode with the tree in `a1` and the MMU off.
The entry sets `gp` before anything gp-relative can run (and tells the assembler
not to relax the very instruction that loads it, or the relaxation would read
`gp` before it exists), clears `sscratch`, sets `SUM`, and clears the bss.
`SUM` is the bit x86_64 does not have an analogue of: on RISC-V a page marked
`U` is off-limits to the supervisor *unless* it is set, where x86_64 lets the
kernel reach user pages unless `SMAP` was switched on.  The pipe handlers read
and write a program's buffer, so the permission is granted once at entry rather
than re-learned at every fault.  The FPU is left off, which is the same answer
x86_64 gives for SSE state: no f-register is saved in a frame, and a kernel that
used one would fault loudly instead of corrupting a program's float silently.

The image stays an ELF at `0x8020_0000`, because that loader reads an entry
point rather than a first byte, and two megabytes in is where OpenSBI's own
memory ends.

**The first boot died at the instruction after the `satp` write, and the two
faults it left are a lesson about shifts.**  A page-table **entry** keeps its
page number above the flag bits, at 10..53.  The `satp` **register** keeps its
page number at 0..43, and nothing above it but the ASID.  The install that was
written before any boot existed used the entry's shift, so the root's number
landed mostly in the ASID field and the walk started from a root made of an
address's middle bits; the first fetch faulted, the trap vector named nothing,
and the machine spun at its own entry.  QEMU's exception log said
`exec_page_fault` at exactly the next instruction's address, which is the whole
diagnosis: translation was on and the table it was handed was not the table that
was built.

**The mode is Sv48, and the reason is the walk's shape, not reach.**  The
kernel's page-table arithmetic is four levels of nine bits, the shape the two
machines with a ring 3 already share.  Sv48's walk is exactly that shape;
Sv39's three levels would put the user window at an index the four-level
arithmetic cannot name, and the price of insisting on Sv39 is a machine
conditional in code that is machine-neutral today.  A machine that answers the
mode whose walk matches the shared arithmetic is a machine the kernel never
learns the name of.

The boot's own answers came from the tree OpenSBI hands over: the console's
address, the memory the frame pool clamps to, the PCIe ECAM window and the BAR
window the enumeration pass assigns from, and the timer's rate, which RISC-V
reports nowhere but `/cpus`'s `timebase-frequency`, there being no register on
this machine that says how fast `time` runs.

### A trap on the third machine, and a timer the firmware owns

    protofire: interrupt table installed, interrupts on
    protofire: interrupt delivered to its handler
    protofire: timer line enabled = 1
    protofire: timer armed at 10000 ticks/ms

One entry serves every trap, because `stvec` names one address and the cause
read there is the whole of what arrived.  The entry has one trick worth
writing down: RISC-V pushes nothing on a trap and switches no stack, so the
first instruction exchanges `sp` with `sscratch`, which holds the kernel
stack while a program runs and zero while the kernel does, and the exchange
yielding zero is how the kernel's own traps find their way home.  Which stack
the interrupted `sp` was is decided by `sstatus.SPP`, the bit the hardware set
before the first instruction of the handler ran.

The frame is 288 bytes: all thirty-two integer registers, `sepc`, `sstatus`,
`scause` and `stval`.  No float registers, because `sstatus.FS` is left off
from the entry onward, the same answer x86_64's frame gives for SSE, and a
kernel that used a float would fault loudly instead of corrupting a program's
state silently.  aarch64's frame saves its vector registers because that
machine's compiler provably emits them; this one's does not.

There is no self-test `ecall` in the install, and the absence is not an
omission the way it was on aarch64: an `ecall` from S-mode is the **firmware's**
door, the same instruction that arms the timer, so raising one as a probe
would be a request to OpenSBI.  The line this machine can be asked for is the
supervisor software interrupt, whose pending bit S-mode may set on itself; the
boot raises it the moment the register is written, and silences the source
before the handler sees it, because a pending bit that stays set takes the
same interrupt again the moment interrupts are enabled.

The timer is an SBI call, and the call is a trap: arming is an `ecall` into
M-mode, which clobbers the argument registers, the previous tree's timer did
not declare them, and every tick it reported was tick 1.  Every register the
call can reach is declared at the call site, which is the one place a reader
can check it.

**The first storm came from the disarm, and it was arithmetic.**  There is no
disable bit this mode owns, so "off" is a deadline the counter will not reach.
The first version computed that deadline by adding the counter's full range, which **wraps** to one tick in the past.  The boot disarmed its timer and
instantly armed it for an immediate fire, whose handler re-armed the real
slice: four thousand traps a second through a phase of the boot that should
have been quiet, and two panics a long way from the cause, a hex printer whose
loop counter overflowed a multiply, and a `copy_nonoverlapping` that saw
pointers nothing in this tree had made.  "Off" is now half the counter's range,
which no boot waits out and nothing wraps past.

### A program in U-mode, and the instruction the machine does not advance

    protofire: entering ring 3
    program 3 says hello
    program 1 says hello
    program 2 says hello
    protofire: a program blocks on a pipe
    protofire: every program is asleep, waiting
    protofire: a write woke 1 blocked task(s)
    protofire: every program exited, 3 exit(s), 23 tick(s), 13 switch(es)
    protofire: the timer preempted, 12 switch(es) from ticks

The programs are this machine's machine code: `ecall` is the call, `a7`
carries the number, and the helpers that encode them are checked by decoding
what they encoded.  The sleep travels in an `addi` immediate, whose twelve
signed bits reach two thousand and forty-seven, the aarch64 program's twenty
thousand needs the sixteen bits a `movz` has, so this machine's programs sleep
two milliseconds, which is twenty slices, which is what the duration is for.

**The first sleeper slept forever, and the cause is the instruction the
machine does not advance.**  aarch64's `ELR` and x86_64's saved `rip` name the
instruction *after* the call before any handler exists; RISC-V's `sepc` names
the `ecall` itself, and nothing moves it.  The dispatcher's first advance was
placed after the handler answered, which repairs a call that returned
immediately, and does nothing for one that parked its frame: the sleep handler
saves the frame with a deadline, the wake resumed the frame as it was parked,
and the program executed the same `ecall` again.  The log counted it: a sleep,
a wake, and the same sleep, every two milliseconds, forever.  The advance now
happens **before** the handler runs, because a frame a handler parks has to
park a resume past the call.

**The first program could not read its own stack, and the cause is a
permission the other two machines cannot express.**  The encoder had given
every executable page `X` without `R`, the specification's execute-only form, but the permissions this kernel names carry no "read" flag: on x86_64 and
aarch64 a present page is readable, and `executable` adds to that rather than
replacing it.  The reader program's first load, from the descriptor the boot
handed it, was the machine refusing what the mapping said.  A present leaf on
this machine is readable now, because nothing above the encoder asks for
execute-only and an encoder that invents it breaks the callers it has.

Two further differences from the machines that came first are in the entry,
not the trap.  `SUM` is set once at boot, because a RISC-V page marked `U` is
off-limits to the supervisor *unless* it says otherwise, the reverse of
x86_64, where the kernel reaches user pages unless `SMAP` was switched on, and the pipe handlers read a program's buffer.  And the entry masks
interrupts across its three CSR writes and its `sret`, which is the aarch64
entry race in this machine's registers: a tick between the writes restores the
`sepc` it saved, and the `sret` returns to a kernel address in U-mode.

The return path decides what `sscratch` holds next from the `sstatus` it is
about to restore: back to a program, it re-arms the kernel stack for the next
trap; back to the kernel, it zeroes it.  The idle's wait zeroes it too, before
unmasking, a tick inside that window is the kernel's own trap, and a parked
user `sp` would misroute it onto a program's stack.

### A second hart, started and counted

    protofire: interrupt delivered to its handler
    protofire: hart 1 online
    protofire: timer line enabled = 1

The machine's hart list comes from the tree, `/cpus`'s `cpu@` children, each
`reg` naming its hart id and `status` saying whether firmware means to use it, and the boot hart is not assumed to be any of them: it is whichever hart the
firmware cold-booted, recorded by the entry in the same kind of static the
device-tree pointer reaches.  The list to start is the machine's minus that
one.

Starting is an ask, not a register write.  A hart that is not running is parked
in M-mode, and S-mode cannot wake it, the HSM extension is the firmware's
door, and the ask names an entry address and carries one opaque word.  The
word is the slot: it chooses which stack the hart lands on and which flag it
stores, and the boot hart only ever hands out slots the reservation holds.
The reservation is one fact, the constant `smp` owns is interpolated into the
assembly, so the count the boot bounds and the bytes it reserves cannot
disagree.

What a started hart does is deliberately small: its own stack, the global
pointer, `sscratch`, `SUM`, the trap vector, the kernel's page table in its own
`satp`, its own timer, the two lines it answers, one flag stored, and a wait.

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

### The PLIC, and the report that proved nothing

    protofire: external controller at 0xc000000, context 1, 95 source(s), hart line on

The third machine now has an external interrupt path: the PLIC the tree names
is programmed (every source's priority above the threshold, this hart's context
bank cleared, the threshold open), the hart's external line is enabled, and the
trap path claims a source, hands its number to the sink, and completes it.

**The first version of the line it printed was not evidence.**  It was built
from the device tree, base, source count, and a context computed from the hart
id, so a boot with the controller's `enable` deleted printed the identical
words.  The mutation is what found it: the install was made to return before
setting the controller, and the gate stayed green.  The report now reads the
controller the trap path actually holds, and the same mutation turns the gate
red.

Two defects in the driver were found the same way.  The window reader asked for
**two** regions, because that is a GIC's shape, and answered `None` for a PLIC
that was right there, its `reg` is one window and everything is an offset
inside it.  And the source count came from the tree while the driver was
programming `min(declared, 128)`; those are one number now, and the line reports
the one the driver used.

### A process, and the register two machines disagree about

    protofire: exit statuses 1 -> 1, 2 -> 0, 3 -> 0

The process layer this tree has is the part that can be honest without
`fork`.  A task carries a pid, the parent that started it, and the status it
exited with; `GetPid`, `GetPpid` and `WaitProcess` are served; and the boot's
three programs are three processes, each a child of the boot because nothing
here creates a process.

The evidence is a status that is the program's own number: the announcing
program asks `GetPid` and then exits with the answer, so `1 -> 1` says the
identity call ran and the status carried its answer.  A constant the kernel
invented would be the same number for every program, and the gate would still
see a status.

**`Exit`'s status and a call's answer are not always the same register, and the
first version read one for the other.**  On aarch64 and riscv64 the answer to
`GetPid` and `Exit`'s first argument are both `x0`/`a0`, so the program could
exit with the pid by leaving it where the answer arrived.  On x86_64 they are
`rax` and `edi`: the boot printed `1 -> 20000`, because `edi` still held the
sleep's duration from three calls earlier.  The program now moves the answer
into the argument register, and the scheduler is **told** the status rather
than reading a register through a machine-neutral accessor that would be right
on two machines and wrong on the third.

The pipe's two programs have no identity call, so their status is whatever
their last call left in the register.  The boot reports it as it is: a status
the kernel tidied up to look like a pid would be exactly the invented answer
this file keeps warning about.

### A fork, and the frame that has to be the live one

    protofire: forked a process, child pid 4
    protofire: exit statuses 1 -> 4, 2 -> 0, 3 -> 0, 4 -> 0

`Fork` copies the running process, every page it maps, and the context it is
in, into a task of its own.  Both resume at the instruction after the call;
what tells them apart is the answer, and it is the only difference: the parent
learns the child's pid, the child learns zero.

**The first version forked once and produced seven children, because it copied
the wrong frame.**  A task's saved context is the one its last switch wrote, from *before* the call that is running.  A child resuming there re-executes its
parent's whole path from that switch, including the `fork` that created it, and
the boot showed exactly that in the log: one `forked a process` line, then
seven.  What a child inherits is the frame the trap path is holding, whose
program counter already names the instruction after the call.

**The second version copied every page and still answered the wrong status,
because the answer and the status are different registers.**  `Fork`'s answer
arrives in the return register; `Exit`'s status is read from the first argument.
On aarch64 and riscv64 those are both `x0`/`a0`, and on x86_64 they are `rax`
and `edi`.  The boot printed `1 -> 21`, 21 is what `Write` answers, because
the `Write` between the fork and the exit had overwritten the answer.  Both
programs now keep the answer in a register no call in this program writes, and
the status the boot reports is the fork's own answer.

What is not here: copy-on-write.  Every page a fork copies is copied whole,
which is correct and slower than it needs to be; a COW fork needs a write fault
this kernel does not handle.  And `exec`: a child that wants a different program
than its parent has no call for it.

### Two CPUs running programs

The started hart comes up, installs the kernel's page table in its own `satp`,
arms its own timer, enables its own clock and inter-processor lines, records
that it is online, and then asks the kernel for a task.  The four defects found
bringing it that far are recorded in the section above.

The scheduler, the page tables, the pipes, the syscall registry and the console
are concurrent-safe, `running` gives each CPU its own current task, and a
started hart claims a task and enters U-mode on it.  A boot prints

    protofire: cpu 1 runs process 2
    protofire: program ended on cpu 1
    protofire: every program exited, 4 exit(s), 62 tick(s), 15 switch(es)
    protofire: exit statuses 1 -> 4, 2 -> 0, 3 -> 0, 4 -> 0
    protofire: parallel, programs ended on 2 non-boot cpu(s)

One to three of the four programs end on a CPU other than the boot's, and every
exit status is the one the single-CPU boot produces.  Five consecutive runs
after the last fix had no fault and exactly one report line; the same build
before it faulted in three runs of five, which is the measurement this section
is written from.

**The identity defect is the one a single CPU could not show.**  The trap entry
asked `tp` which CPU it was on.  `starting_context` zeroes every register a
program begins with, so a program's `tp` is zero, and a second CPU running a
program reported itself as CPU 0: both CPUs wrote slot zero and each was handed
the task the other was running.  The two faults named each other's program.  The
trap entry now derives the slot from the kernel stack it just switched to, the
one register an interrupted program cannot have written, and restores the
program's `tp` from the frame like every other register.  `tp` at boot is a
starting value for the window before a program exists, and nothing more.

**Three rules had to be stated, and each was mistaken for a fourth bug.**

- **`Exit` answered two states with one value.**  "The next task's context is
  in this frame" and "this CPU has nothing to run" are different, and the trap
  path cannot tell them apart from the word alone.  On the second it would
  `sret` to the instruction after the finished program's last one, which is
  past the end of its image.  On this machine that word is zero, and the fault
  was `illegal instruction` at offset 21 words: exactly one word past the pipe
  reader's probe image.  `advance_with_status` now installs a task or waits for
  one, and never returns a frame no task owns.
- **`halt` stops one CPU, and the boot's end was spelled with it.**  A CPU that
  found nothing in its own queue set the boot-finished flag and stopped the
  machine, so a boot ended with programs that had not run.  `finish_and_halt`
  and `idle_this_cpu` are two statements now: a CPU with nothing waits for the
  work another CPU may create, and only "nothing is runnable anywhere" finishes
  the machine.
- **The report ran wherever the last exit happened.**  Both CPUs can see that
  the machine is finished, so `every program exited` was printed twice.  One
  atomic exchange owns the report, and the CPU that loses it stops without
  printing.

What is not here, and is named in `docs/status.md` rather than implied: there
is no load balancing.  A task is not pinned to a CPU — the only binding is the
scheduler's `running` array, and leaving it is what every switch does — so a
task that was preempted, woken or blocked resumes wherever it is next selected,
and on this boot that happens.  A boot prints

    protofire: task migrations 4, last process 2 from cpu 1 to cpu 0
    protofire: address spaces reaped 4, 16370 frame(s) free
    protofire: tlb shootdown 3 sent, 3 acknowledged, 0 timed out

and the middle line is the one that says placement moved rather than merely
being allowed to.

**A migration does not need a TLB shootdown, and the earlier version of this
section said it did.**  The claim was that a task's pages have to be reachable
from the new CPU and that every CPU which ever translated through that address
space may hold a stale translation.  The second half is true and the first half
is the reason it does not matter: every machine's `switch_address_space` is a
**whole-TLB** operation — x86_64 rewrites `cr3`, aarch64 runs `tlbi vmalle1`,
riscv64 runs `sfence.vma` — so the CPU that stops running a task has already
discarded every translation into it, and the CPU that starts one discards
whatever it had before its first fetch through the new root.  There is no
window in which a CPU holds a translation for a root it is not installed on.
A migration that reused address-space identifiers, or that switched roots
without a flush, would need the shootdown; this tree does neither.

What a shootdown **is** needed for is the other table: the kernel's own.  Every
program root copies the kernel root's entry 0, so the identity map and the
device windows are one set of tables every CPU walks, and a change made from one
CPU is invisible to the others.  The boot has the live case — the second CPU is
online before the first one remaps a device window uncached — and that is what
`kernel/src/shootdown.rs` is for and what the `tlb shootdown` line reports.
`x86_64` sends three and `aarch64` one; `riscv64` sends none, and that is a fact
about the machine rather than a gap: its ECAM window sits inside the identity
map, so the boot re-maps nothing after the second hart is up and there is
nothing to broadcast.

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
task is `Finished`, and `report_and_finish`'s atomic exchange has told every
other CPU the boot is over.  A finished task's pages are not needed for it to
stay finished, so holding them costs nothing, and the race is removed rather
than narrowed.  The pool goes from 131072 frames free at boot to 131068 after
four programs' spaces come back, and the line is required on all three
machines.

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
3. **A TLB shootdown.**  Not for migration, which is the correction the section
   above records: a root switch is a whole-TLB flush on all three machines, so a
   migrated task pays one flush and needs no broadcast.  What needs the
   broadcast is any change to the **shared** tables every root copies, and that
   mechanism exists now (`kernel/src/shootdown.rs`): an epoch, a per-CPU
   acknowledgement, and a bounded wait, driven by the same inter-processor
   interrupt the waker already uses, with `tlb shootdown N sent, M acknowledged,
   0 timed out` on the console.  A sharded scheduler that later changes a shared
   table on a CPU other than the boot one sends through it; one that only moves
   tasks does not.

The order matters, but less than the previous version of this paragraph said.
Sharding without migration is a safe intermediate that buys the contention away
and changes no semantics.  Migration without a shootdown is **not** a
use-after-free here, because the flush is part of every root switch; what would
make it one is an address-space identifier or a switch that skipped its flush.
Releasing a space without knowing no CPU walks it *is* a use-after-free, and
that one has been measured — 186 faults at a program's stack address in six
boots of eight — which is why the release is deferred to the machine's end
rather than narrowed.

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

### The first device that raised the line

    protofire: console source 10 enabled at the controller
    protofire: console interrupt(s) taken = 1

The PLIC had been programmed and its claim path had never carried a
device: every source was disabled, so the external line was a path the machine
could take and nothing ever made it.  The console's UART is the device this boot
has, and its transmitter raises the line on its own once asked, so the claim
path is now something a boot runs.

**Two orderings had to be right, and the first one showed itself as a storm.**
A 16550 keeps its line raised until something reads `IIR`, so a source completed
at the controller but not at the device arrives again the moment interrupts are
unmasked; the first boot printed `unhandled external interrupt 10` without end.
The device is acknowledged first now, and only then is the source completed.

**The second showed itself as a panic inside the hex printer.**  A transmitter
interrupt fires whenever the holding register is empty, which is nearly always,
so leaving the device enabled turns every printed byte into a trap inside the
print that is trying to report it.  The boot asks for one interrupt and silences
the device in the handler, which is why the count is one rather than one per
byte.

Both mutations turn the gate red: never enabling the source loses the
`console source 10 enabled` line, and a sink that does not claim the number
loses the count.

### The write fault that became a fork's answer

    protofire: forked a process, child pid 4
    protofire: copy-on-write copy at 0x8040001ff8 from frame 0x4a1f000 to frame 0x4a33000
    protofire: copy-on-write promote at 0x8040001ff8 on frame 0x4a1f000

`Fork` used to copy every page whole, and the reason it gave was that a write to
a read-only page was a fault nobody handled.  That reason stopped being true the
day the fault path learned two things every machine was already carrying and the
kernel was dropping at the trap boundary: **which direction** the faulting access
went, and **what the page table says** about the address.  x86_64 keeps the
direction in the page-fault error code's `W/R` bit — and in no other exception's,
which is why the bit is trusted only on vector 14 — aarch64 in `ESR_EL1`'s `WnR`
for the two data-abort classes, riscv64 in `scause` itself, where a store page
fault and a load page fault are two different numbers and an instruction fetch is
neither a read nor a write.  The shared frame carries it as `write: Option<bool>`,
`None` being a device's line, which has no direction because it had no access.

With the direction in hand, `fork_from` stopped copying and started sharing.  A
writable page is demoted first — the parent's entry rewritten read-only and the
frame marked in the pool — and both spaces map the same frame; a read-only page
is shared as it stands, because it was never writable and a write to it is the
program faulting on its own code, which is a real fault and stays one.  The
demotion and the mark are one pool critical section, because they are one fact:
a demotion whose mark landed later would leave a window where the parent faults
and the handler has nothing to read.  The count is a byte per frame in the
allocator, beside the free bitmap, and `deallocate` refuses a frame whose count
is above zero, which is the premature free the count can see.

The fault handler's answer depends on the same count.  Co-owners remain, the
faulting space gets a private copy and its claim on the shared frame goes with
it — `replace_owned` swaps the record, so the bound does not move and the count
stays honest.  No co-owners, the frame is promoted in place: the mark clears and
the entry turns writable, nothing copied, because nobody else will ever read the
old bytes.  The boot log shows both answers on one page, and the promote's frame
is the copy's source frame, which is the pair reading itself.

Three arguments the change had to make, and where each is checked:

- **One local flush is the whole invalidation.**  The demotion happens on the
  CPU serving the fork, which is the parent's own; every machine's root switch
  is a whole-TLB flush, so no other CPU holds a translation for the parent's
  pages; and the parent cannot write between the demotion and the share because
  it is suspended inside its own syscall.  The shootdown broadcast is for the
  *shared kernel tables*, which this does not touch.
- **The demotions a failed fork leaves behind need no repair.**  The state is
  correct on its own: the next write faults, the handler reads the count, and
  the parent continues.  A failed fork costs copies that would have been paid
  on the first writes anyway.
- **The resolver's lock order is the scheduler's and then the pool's**, the
  only order any code in this kernel takes the two, taken because the fault
  arrives with no task named and the task it belongs to is the one the CPU
  marked as running.

The mutation: with the resolver unwired from the fault path, both processes'
stack writes print `fault at 0x8040001ff8, write, mapped read-execute, user, not
writable` and stop the machine, and all three machines' gates go red.  With it
wired, the same write is the two lines above, and the boot reports four exits
whose statuses are unchanged — the fork's contract, kept by cheaper means.

### Exec, and the window it kept

    protofire: process 1 exec'd image 4
    protofire: exit statuses 1 -> 1, 2 -> 1, 3 -> 0, 4 -> 0

`ExecProcess` was a number in the frozen range that no boot served.  Serving it
is one function with one ordering decision in it, and the ordering is the whole
of the change: the old root is installed on the CPU serving the call, and
freeing a root the machine is translating through is a fault on the next
instruction — the same lesson the exit-time release learned, at 186 faults.
So `exec` builds the new space whole **before** touching the task, then swaps
the task onto it, installs the new root, and releases the old space only after
the switch — and every machine's switch is a whole-TLB flush, which is what
makes the release safe at that point rather than a promise about it: no CPU
translates through the old root any more, because this one just flushed and
switched, the task is marked running here and nowhere else, and no other CPU
ever held it.

Two things carry over and two do not.  The **window** carries over: the new
image maps at the virtual addresses the task already owned, read from its own
table rather than remembered anywhere, because the table is the truth and a
second record of it is the first thing to diverge.  The **identity** carries
over: same task, same pid, same parent, which is what separates `exec` from a
new process.  What does not is the image behind the window and the context — a
program that asked to become another does not resume where it was.

The boot proves the identity with the image it execs into: it announces, asks
the kernel who it is, and exits with the answer, so the pair — `process 1
exec'd image 4`, then `1 -> 1` — is a fact the exec'd task itself reports, and
a process that lost its identity in the change could not print it.  The
mutation — installing no new frame, leaving the trap path to resume the
program it replaced — faults the machine before it can print the line, and the
gate goes red.
